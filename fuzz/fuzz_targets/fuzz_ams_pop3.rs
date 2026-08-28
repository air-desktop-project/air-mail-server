// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : la ligne de commande POP3, avant toute ouverture de session.**
//!
//! C'est ce qu'un inconnu envoie en premier, exactement comme en SMTP — et pour
//! la même raison, une panique y serait un déni de service offert à qui sait
//! écrire quinze octets.
//!
//! # Les quatre propriétés
//!
//! 1. **Rien ne panique**, quelles que soient les bornes.
//! 2. **Ce qui est lu se relit** : une commande acceptée a un `CRLF` à la fin et
//!    n'en contient pas ailleurs. Le contrebandage se joue là.
//! 3. **Une réponse encodée tient dans ce que `encoded_len` annonce**, et jamais
//!    un octet de plus (C3).
//! 4. **Le doublement du point est TOTAL** : toute ligne rendue par `stuff_line`
//!    qui commence par un point en porte deux, sans quoi elle serait prise pour
//!    le terminateur et le message finirait au milieu.

#![no_main]

use libfuzzer_sys::fuzz_target;

use ams_proto_pop3::{Command, Limits, Status, encode, encoded_len, stuff_line, stuffed_len};
use arbitrary::Arbitrary;

#[derive(Debug, Arbitrary)]
struct Entree<'a> {
    /// La ligne de commande, telle qu'un pair l'enverrait.
    ligne: &'a [u8],
    /// Les bornes — LIBREMENT ABSURDES : elles viennent de la configuration,
    /// donc d'un administrateur qui peut y écrire trois.
    bornes: [u32; 3],
    /// Le texte d'une réponse.
    texte: &'a [u8],
    /// Une ligne de corps à doubler.
    corps: &'a [u8],
}

fuzz_target!(|entree: Entree| {
    let bornes = Limits {
        max_command_octets: entree.bornes[0] as usize,
        max_reply_octets: entree.bornes[1] as usize,
        max_argument_octets: entree.bornes[2] as usize,
    };

    // ── 1 et 2. LA COMMANDE ─────────────────────────────────────────────────
    if Command::parse(entree.ligne, &bornes).is_ok() {
        assert!(
            entree.ligne.ends_with(b"\r\n"),
            "une commande acceptée sans CRLF final"
        );
        let corps = &entree.ligne[..entree.ligne.len() - 2];
        assert!(
            !corps.iter().any(|&octet| octet == b'\r' || octet == b'\n'),
            "une commande acceptée porte un CR ou un LF isolé"
        );
        assert!(entree.ligne.len() <= bornes.max_command_octets);
    }
    // Et avec les bornes du produit, qui sont celles qui serviront.
    let _ = Command::parse(entree.ligne, &Limits::DEFAULT);

    // ── 3. LA RÉPONSE ───────────────────────────────────────────────────────
    let mut tampon = [0_u8; 2048];
    for status in [Status::Ok, Status::Err] {
        match encoded_len(status, entree.texte, &bornes) {
            Ok(annonce) => {
                assert!(
                    annonce <= bornes.max_reply_octets,
                    "l'annonce dépasse la borne"
                );
                if let Ok(ecrit) = encode(&mut tampon, status, entree.texte, &bornes) {
                    assert_eq!(
                        ecrit.len(),
                        annonce,
                        "l'écrit ne fait pas la taille annoncée"
                    );
                    assert!(ecrit.starts_with(status.as_bytes()));
                    assert!(ecrit.ends_with(b"\r\n"));
                }
            }
            // Refusée : texte trop long, saut de ligne dedans, ou borne plus
            // petite que l'enveloppe. `encode` doit refuser de même.
            Err(_) => {
                assert!(encode(&mut tampon, status, entree.texte, &bornes).is_err());
            }
        }
    }

    // ── 4. LE DOUBLEMENT DU POINT ───────────────────────────────────────────
    let mut sortie = [0_u8; 2048];
    if let Ok(double) = stuff_line(&mut sortie, entree.corps) {
        assert_eq!(double.len(), stuffed_len(entree.corps));
        assert!(double.ends_with(b"\r\n"));
        if entree.corps.first() == Some(&b'.') {
            assert!(
                double.starts_with(b".."),
                "un point en tête n'a pas été doublé : la ligne serait prise pour le terminateur"
            );
        }
        // Et une ligne doublée n'est JAMAIS le terminateur.
        assert_ne!(double, b".\r\n");
    }
});
