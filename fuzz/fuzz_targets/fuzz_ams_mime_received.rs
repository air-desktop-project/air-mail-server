// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : les deux en-têtes de §4.4** — la trace `Received:` que ce serveur
//! pose sur chaque message qu'il accepte, et le `Return-Path:` que la remise
//! finale pose au-dessus d'elle.
//!
//! # L'ENTRÉE HOSTILE EST CE QUE LE PAIR A DIT DE LUI-MÊME
//!
//! Le nom du `HELO` et le chemin de retour viennent tous deux du pair, avant
//! toute authentification, et finissent recopiés EN TÊTE du message — là où un
//! lecteur croira que c'est nous qui parlons. Un `CRLF` glissé dans l'un ou
//! l'autre écrirait un en-tête entier sous notre nom, au-dessus de tous les
//! autres.
//!
//! **Le chemin de retour est le plus exposé des deux** : il est écrit tout en
//! haut, avant même la trace.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets et l'instant.
//! 2. **RIEN N'EST ÉCRIT AU-DELÀ DU TAMPON** : ce qui borde ne bouge pas.
//! 3. **IL N'Y A QU'UN CHAMP** : une seule ligne ne commence pas par un blanc,
//!    et c'est la première. Toute autre serait un en-tête que le pair aurait
//!    écrit à travers nous.
//! 4. **TOUT CE QUI SORT EST ÉMETTABLE** : de l'ASCII imprimable, des
//!    tabulations, et des fins de ligne COMPLÈTES.
//! 5. **AUCUNE LIGNE NE DÉPASSE 998 OCTETS** (§2.1.1 de RFC 5322). Au-delà, les
//!    analyseurs en aval coupent où ils veulent, et ce qu'ils lisent n'est plus
//!    ce qu'on a écrit.
//! 6. **AUCUN DESTINATAIRE N'Y EST NOMMÉ** : ce serveur n'écrit jamais de clause
//!    `for`, et l'en-tête voyage avec le message.
//! 7. **LE `Return-Path:` EST UNE LIGNE, ET UNE SEULE**, close par un `CRLF`, et
//!    ce qu'elle porte est exactement ce qu'on lui a donné — ni tronqué, ni
//!    complété. Un chemin coupé désignerait quelqu'un d'autre.
//! 8. **CE QU'UNE SOUMISSION FAIT COMPLÉTER SE COMPTE** (RFC 6409 §8) : autant
//!    de champs écrits que de champs déclarés manquants, pas un de plus, et
//!    chacun clos par son `CRLF`.
//!
//! Harnais **pur** : aucune entrée-sortie (C1).

#![no_main]

use ams_mime::{
    Missing, RECEIVED_MAX, RETURN_PATH_MAX, Received, SUBMISSION_FIELDS_MAX, Transport,
    write_received, write_return_path, write_submission_fields,
};
use arbitrary::Arbitrary;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use libfuzzer_sys::fuzz_target;

/// Ce qui borde le tampon, pour voir si l'on écrit au-delà.
const GARDE: u8 = 0xa5;

#[derive(Debug, Arbitrary)]
struct Entree {
    helo: Vec<u8>,
    receiver: Vec<u8>,
    /// Une adresse, v4 ou v6 selon le premier octet.
    six: bool,
    adresse: [u8; 16],
    transport: u8,
    date: u64,
    /// Le chemin de retour, tel que le pair l'a écrit. **VIENT DE LUI.**
    chemin: Vec<u8>,
    /// Ce qui manque à une soumission (RFC 6409 §8), et de quoi le compléter.
    sans_date: bool,
    sans_identifiant: bool,
    unique: Vec<u8>,
    domaine_du_de: Vec<u8>,
    /// La place qu'on donne, bornée par ce que le produit réserve.
    place: u16,
}

fuzz_target!(|entree: Entree| {
    let client = if entree.six {
        IpAddr::V6(Ipv6Addr::from(entree.adresse))
    } else {
        let [a, b, c, d, ..] = entree.adresse;
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    };
    let champ = Received {
        helo: &entree.helo,
        client,
        receiver: &entree.receiver,
        with: match entree.transport % 4 {
            0 => Transport::Smtp,
            1 => Transport::Esmtp,
            2 => Transport::Esmtps,
            _ => Transport::EsmtpsA,
        },
        date: entree.date,
    };

    let place = usize::from(entree.place) % (RECEIVED_MAX + 1);
    let mut tampon = vec![GARDE; place.saturating_add(64)];
    let issue = {
        let dedans = &mut tampon[..place];
        write_received(dedans, &champ).map(<[u8]>::len)
    };

    // 2. RIEN N'EST ÉCRIT AU-DELÀ.
    assert!(
        tampon[place..].iter().all(|octet| *octet == GARDE),
        "écrit au-delà de la place donnée"
    );

    let Ok(combien) = issue else {
        return;
    };
    let ecrit = &tampon[..combien];

    // 4. TOUT CE QUI SORT EST ÉMETTABLE.
    assert!(
        emettable(ecrit),
        "un octet qu'on ne peut pas mettre sur le fil"
    );
    assert!(
        ecrit.starts_with(b"Received: from "),
        "le champ n'est pas celui qu'on annonce"
    );
    assert!(ecrit.ends_with(b"\r\n"), "le champ ne se termine pas");

    // 3. IL N'Y A QU'UN CHAMP, et 5. AUCUNE LIGNE NE DÉPASSE 998 OCTETS.
    for (rang, ligne) in ecrit.split(|octet| *octet == b'\n').enumerate() {
        let ligne = ligne.strip_suffix(b"\r").unwrap_or(ligne);
        if ligne.is_empty() {
            continue;
        }
        assert!(
            rang == 0 || matches!(ligne.first(), Some(b' ' | b'\t')),
            "une seconde ligne d'en-tête est apparue"
        );
        assert!(ligne.len() <= 998, "ligne de plus de 998 octets");
    }

    // 6. AUCUN DESTINATAIRE N'Y EST NOMMÉ.
    assert!(
        !contient(ecrit, b" for "),
        "une clause `for` est apparue : elle nommerait un destinataire"
    );

    // ── 7. LE `Return-Path:` DE LA REMISE FINALE ────────────────────────────
    //
    // Il s'écrit AU-DESSUS de la trace : c'est la première chose qu'un lecteur
    // voit, et donc la plus exposée.
    let mut chemin = vec![GARDE; RETURN_PATH_MAX.saturating_add(64)];
    let issue = {
        let dedans = chemin
            .get_mut(..RETURN_PATH_MAX)
            .expect("le tampon fait au moins la borne annoncée");
        write_return_path(dedans, &entree.chemin).map(<[u8]>::len)
    };
    assert!(
        chemin
            .get(RETURN_PATH_MAX..)
            .is_some_and(|bord| bord.iter().all(|octet| *octet == GARDE)),
        "écrit au-delà de la place donnée"
    );
    let Ok(combien) = issue else {
        return;
    };
    let ecrit = chemin.get(..combien).unwrap_or_default();
    assert!(
        emettable(ecrit),
        "un octet qu'on ne peut pas mettre sur le fil"
    );
    // UNE LIGNE, ET UNE SEULE : un `CRLF` au milieu ouvrirait un en-tête que le
    // pair aurait écrit à travers nous, tout en haut du message.
    assert!(ecrit.ends_with(b"\r\n"), "la ligne ne se ferme pas");
    let corps = ecrit.get(..combien.saturating_sub(2)).unwrap_or_default();
    assert!(
        !corps.contains(&b'\r') && !corps.contains(&b'\n'),
        "une fin de ligne PRÉMATURÉE"
    );
    // **CE QUI SORT EST EXACTEMENT CE QU'ON A DONNÉ**, entre les chevrons : ni
    // tronqué, ni complété. Un chemin coupé désignerait quelqu'un d'autre.
    assert_eq!(
        corps,
        [&b"Return-Path: <"[..], &entree.chemin, b">"].concat(),
        "le chemin a changé en route"
    );

    // ── 8. LES CHAMPS D'UNE SOUMISSION (RFC 6409 §8) ────────────────────────
    //
    // Ils s'écrivent à la fin du bloc d'en-tête d'un message qu'un de nos
    // comptes nous confie. Un `CRLF` de trop y ouvrirait un champ que personne
    // n'a demandé, au milieu de l'en-tête de quelqu'un d'autre.
    let manquants = Missing {
        date: entree.sans_date,
        message_id: entree.sans_identifiant,
    };
    let mut champs = vec![GARDE; SUBMISSION_FIELDS_MAX.saturating_add(64)];
    let issue = {
        let dedans = champs
            .get_mut(..SUBMISSION_FIELDS_MAX)
            .expect("le tampon fait au moins la borne annoncée");
        write_submission_fields(
            dedans,
            manquants,
            entree.date,
            &entree.unique,
            &entree.domaine_du_de,
        )
        .map(<[u8]>::len)
    };
    assert!(
        champs
            .get(SUBMISSION_FIELDS_MAX..)
            .is_some_and(|bord| bord.iter().all(|octet| *octet == GARDE)),
        "écrit au-delà de la place donnée"
    );
    let Ok(combien) = issue else {
        return;
    };
    let ecrit = champs.get(..combien).unwrap_or_default();
    assert!(
        emettable(ecrit),
        "un octet qu'on ne peut pas mettre sur le fil"
    );
    // **AUTANT DE LIGNES QUE DE CHAMPS DÉCLARÉS MANQUANTS**, pas une de plus :
    // c'est ce qui interdit à une valeur d'ouvrir un champ à notre place.
    let attendues = usize::from(manquants.date) + usize::from(manquants.message_id);
    let lignes = ecrit.windows(2).filter(|paire| *paire == b"\r\n").count();
    assert_eq!(lignes, attendues, "un champ est apparu ou a disparu");
    // Et chacune se ferme : rien ne traîne sans son `CRLF`.
    assert!(
        ecrit.is_empty() || ecrit.ends_with(b"\r\n"),
        "une ligne ouverte"
    );
});

/// `botte` porte-t-elle `aiguille` ?
fn contient(botte: &[u8], aiguille: &[u8]) -> bool {
    botte
        .windows(aiguille.len())
        .any(|fenetre| fenetre == aiguille)
}

/// Ces octets peuvent-ils passer sur le fil tels quels ?
///
/// De l'ASCII imprimable, des tabulations, et des fins de ligne COMPLÈTES.
fn emettable(octets: &[u8]) -> bool {
    let mut attend_lf = false;
    for octet in octets {
        if attend_lf {
            if *octet != b'\n' {
                return false;
            }
            attend_lf = false;
            continue;
        }
        match *octet {
            b'\r' => attend_lf = true,
            b'\n' => return false,
            b'\t' => {}
            autre if autre.is_ascii_graphic() || autre == b' ' => {}
            _ => return false,
        }
    }
    !attend_lf
}
