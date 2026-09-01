// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : la réponse HTTP lue par le client** — la contrebande, dans l'autre
//! sens.
//!
//! # CE QUI EST HOSTILE ICI
//!
//! Ce serveur ne parle HTTP en client que pour aller chercher une politique
//! MTA-STS, et **le serveur est désigné par le domaine qu'on interroge** —
//! c'est-à-dire, quand cela compte, par celui qui usurpe. Ce qui revient est
//! une entrée hostile comme une autre.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **UNE TÊTE ACCEPTÉE TIENT DANS CE QU'ON A LU**, et se termine par une
//!    ligne vide.
//! 3. **AUCUN `CR` NI `LF` ISOLÉ N'EST PASSÉ.** C'est la contrebande : un
//!    message qu'un intermédiaire découpe autrement que nous en laisse passer un
//!    second.
//! 4. **`Content-Length` ET `Transfer-Encoding` NE COEXISTENT JAMAIS** dans une
//!    tête acceptée (§11.2 de RFC 9112).
//! 5. **LIRE PLUS TÔT NE DIT PAS AUTRE CHOSE** : ce qu'on rend sur un préfixe
//!    est « pas encore », jamais un autre verdict.

#![no_main]

use ams_proto_http::{Body, parse_response};
use libfuzzer_sys::fuzz_target;

/// La borne de tête qu'un appelant impose.
const TETE_MAX: usize = 8192;

fuzz_target!(|octets: &[u8]| {
    let Ok(Some(tete)) = parse_response(octets, TETE_MAX) else {
        return;
    };

    // 2. LA TÊTE TIENT DANS CE QU'ON A LU, ET FINIT PAR UNE LIGNE VIDE.
    assert!(
        tete.length() <= octets.len(),
        "la tête dépasse ce qu'on a lu"
    );
    let lue = &octets[..tete.length()];
    assert!(lue.ends_with(b"\r\n\r\n"), "la tête ne se termine pas");

    // 3. AUCUN `CR` NI `LF` ISOLÉ.
    //
    // Tout `\r` est suivi d'un `\n`, et tout `\n` est précédé d'un `\r` : c'est
    // ce qui garantit qu'un autre lecteur découpera cette tête comme nous.
    let mut attend_lf = false;
    for (rang, octet) in lue.iter().enumerate() {
        if attend_lf {
            assert_eq!(*octet, b'\n', "un CR isolé au rang {rang}");
            attend_lf = false;
            continue;
        }
        match *octet {
            b'\r' => attend_lf = true,
            b'\n' => panic!("un LF isolé au rang {rang}"),
            _ => {}
        }
    }
    assert!(!attend_lf, "un CR en fin de tête");

    // 4. LES DEUX DÉLIMITATIONS NE COEXISTENT PAS.
    //
    // On le vérifie sur les octets, sans faire confiance à ce que le décodeur a
    // conclu : c'est le décodeur qu'on éprouve.
    let porte = |aiguille: &[u8]| {
        lue.windows(aiguille.len())
            .any(|fenetre| fenetre.eq_ignore_ascii_case(aiguille))
    };
    if porte(b"\r\ncontent-length:") && porte(b"\r\ntransfer-encoding:") {
        panic!("les deux délimitations ont été acceptées ensemble");
    }
    // Et ce que le décodeur a conclu s'accorde avec ce qu'il a lu.
    match tete.body() {
        Body::Chunked => assert!(porte(b"\r\ntransfer-encoding:")),
        Body::Length(_) => assert!(porte(b"\r\ncontent-length:")),
        Body::UntilClose => {}
    }

    // 5. LIRE PLUS TÔT NE DIT PAS AUTRE CHOSE.
    for combien in 0..tete.length() {
        let prefixe = &octets[..combien];
        match parse_response(prefixe, TETE_MAX) {
            // « Pas encore » : c'est la seule bonne réponse sur un préfixe.
            Ok(None) => {}
            // Un refus est licite : le préfixe peut porter une faute que la
            // suite n'aurait pas réparée.
            Err(_) => {}
            Ok(Some(autre)) => panic!(
                "un préfixe de {combien} octets a rendu une tête de {} octets",
                autre.length()
            ),
        }
    }
});
