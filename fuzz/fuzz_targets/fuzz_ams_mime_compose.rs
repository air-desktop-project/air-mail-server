// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : le message qui porte un rapport** — ses en-têtes, son découpage en
//! parties, et sa pièce jointe.
//!
//! # Ce qui entre ici ne vient pas toujours de nous
//!
//! L'adresse du destinataire d'un rapport est publiée par le domaine qu'on
//! rapporte — c'est-à-dire, quand cela compte, par celui qui usurpe. Le nom du
//! fichier joint est composé à partir de ce même domaine. Un message qu'on
//! compose soi-même et qu'on remet soi-même est le dernier endroit où une
//! injection passerait inaperçue.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **UN MESSAGE COMPOSÉ N'A QUE LES EN-TÊTES QU'ON A ÉCRITS** : on les
//!    compte. Un `CRLF` glissé dans une adresse en ajouterait un.
//! 3. **Le délimiteur figure exactement trois fois** — deux ouvertures et une
//!    clôture. Ni plus, ni moins : un `multipart` qui se découpe ailleurs se lit
//!    autrement que ce qu'on a écrit.
//! 4. **LE BASE64 SE RELIT** : la pièce jointe décodée est exactement celle
//!    qu'on a donnée. Le décodeur est écrit ici, dans la cible, pour qu'une
//!    erreur symétrique ne passe pas inaperçue.
//! 5. **Une date s'écrit toujours**, et tient dans ce qu'elle annonce.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_mime::{DATE_MAX, ReportMail, report_mail_max, write_date, write_report_mail};

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    from: &'a [u8],
    to: &'a [u8],
    subject: &'a [u8],
    message_id: &'a [u8],
    boundary: &'a [u8],
    text: &'a [u8],
    filename: &'a [u8],
    attachment: &'a [u8],
    date: u64,
}

/// Un décodeur base64 écrit ICI, et volontairement séparé de l'encodeur.
///
/// Réencoder avec le code qu'on éprouve prouverait seulement qu'il est
/// d'accord avec lui-même.
fn decoder(texte: &[u8]) -> Option<Vec<u8>> {
    let mut sortie = Vec::new();
    let mut accumulateur = 0_u32;
    let mut bits = 0_u32;
    for octet in texte {
        if matches!(octet, b'\r' | b'\n') {
            continue;
        }
        if *octet == b'=' {
            break;
        }
        let valeur = match octet {
            b'A'..=b'Z' => u32::from(octet - b'A'),
            b'a'..=b'z' => u32::from(octet - b'a') + 26,
            b'0'..=b'9' => u32::from(octet - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        accumulateur = (accumulateur << 6) | valeur;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            sortie.push(u8::try_from((accumulateur >> bits) & 0xFF).ok()?);
        }
    }
    Some(sortie)
}

fuzz_target!(|entree: Entree<'_>| {
    // ── La date s'écrit toujours ────────────────────────────────────────────
    let mut place = [0_u8; DATE_MAX];
    let date = write_date(entree.date, &mut place).expect("DATE_MAX suffit toujours");
    assert!(date.len() <= DATE_MAX);
    assert!(date.ends_with(b" +0000"));

    // ── Le message ──────────────────────────────────────────────────────────
    let courrier = ReportMail {
        from: entree.from,
        to: entree.to,
        subject: entree.subject,
        message_id: entree.message_id,
        date: entree.date,
        boundary: entree.boundary,
        text: entree.text,
        filename: entree.filename,
        attachment: entree.attachment,
    };
    let mut sortie = vec![0_u8; report_mail_max(&courrier)];
    let Ok(message) = write_report_mail(&mut sortie, &courrier) else {
        return;
    };

    let compter = |motif: &[u8]| {
        message
            .windows(motif.len())
            .filter(|fenetre| *fenetre == motif)
            .count()
    };
    // PROPRIÉTÉ 2 : les en-têtes sont ceux qu'on a écrits, et pas un de plus.
    //
    // On ne compte QUE DANS LE BLOC D'EN-TÊTE. Un corps `text/plain` a le droit
    // de contenir « From: » — c'est du texte — et confondre les deux ferait
    // crier cette cible sur un message parfaitement correct.
    let fin_des_entetes = message
        .windows(4)
        .position(|f| f == b"\r\n\r\n")
        .expect("la ligne vide qui ferme le bloc d'en-tête");
    let entetes = &message[..fin_des_entetes];
    let compter_entete = |motif: &[u8]| {
        entetes
            .windows(motif.len())
            .filter(|fenetre| *fenetre == motif)
            .count()
    };
    for entete in [
        &b"\r\nTo: "[..],
        b"\r\nSubject: ",
        b"\r\nDate: ",
        b"\r\nMessage-ID: ",
        b"\r\nMIME-Version: ",
        b"\r\nContent-Type: multipart/mixed;",
    ] {
        assert_eq!(
            compter_entete(entete),
            1,
            "en-tête {entete:?} en double ou absent"
        );
    }
    assert!(message.starts_with(b"From: <"));
    assert_eq!(
        compter_entete(b"\r\nFrom: "),
        0,
        "un second `From:` a été injecté"
    );

    // PROPRIÉTÉ 3 : le délimiteur, deux fois ouvert et une fois clos.
    let mut delimiteur = Vec::from(&b"\r\n--"[..]);
    delimiteur.extend_from_slice(entree.boundary);
    assert_eq!(
        compter(&delimiteur),
        3,
        "le message ne se découpe pas là où on l'a écrit"
    );
    assert!(message.ends_with(b"--\r\n"));

    // PROPRIÉTÉ 4 : la pièce jointe se relit.
    //
    // On ne cherche pas un en-tête en particulier — l'ordre des en-têtes d'une
    // partie MIME n'est pas garanti par la RFC, et une cible qui en dépendrait
    // éprouverait la mise en page plutôt que le contenu. On repère la SECONDE
    // ouverture de partie, puis sa ligne vide.
    let ouvertures: Vec<usize> = message
        .windows(delimiteur.len())
        .enumerate()
        .filter(|(_, fenetre)| *fenetre == delimiteur)
        .map(|(rang, _)| rang)
        .collect();
    let seconde = ouvertures[1] + delimiteur.len();
    let partie = &message[seconde..];
    let corps = partie
        .windows(4)
        .position(|f| f == b"\r\n\r\n")
        .expect("la ligne vide qui ouvre le corps de la partie")
        + 4;
    let reste = &partie[corps..];
    let fin = reste
        .windows(delimiteur.len())
        .position(|f| f == delimiteur)
        .expect("la clôture de la partie");
    let relu = decoder(&reste[..fin]).expect("du base64 et rien d'autre");
    assert_eq!(relu, entree.attachment, "la pièce jointe a été abîmée");
});
