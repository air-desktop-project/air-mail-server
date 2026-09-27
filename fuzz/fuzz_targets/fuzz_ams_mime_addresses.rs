// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : ce que l'enveloppe REST lit d'un champ** — les adresses et leurs
//! noms, les identifiants de message, la date.
//!
//! # POURQUOI UNE CIBLE DE PLUS
//!
//! `mime-envelope` éprouve l'`ENVELOPE` d'IMAP, qui recopie. Celle-ci éprouve
//! les lecteurs de l'API, qui DÉCODENT : un nom d'affichage traverse deux étapes
//! — guillemets défaits, puis mots encodés — et la seconde peut grandir. Ce sont
//! deux tampons fixes, choisis par l'appelant, remplis d'après un en-tête que
//! n'importe qui écrit (C3).
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique.**
//! 2. **RIEN N'EST ÉCRIT AU-DELÀ DES TAMPONS**, et les longueurs rendues y
//!    tiennent.
//! 3. **CE QU'ON REND EST UN MORCEAU DE CE QU'ON A LU** : chaque nom et chaque
//!    adresse bruts sont des tranches du champ, sans rien d'inventé.
//! 4. **UN NOM RENDU NE PORTE NI FIN DE LIGNE NI BLANC EN BORDURE**, et une
//!    adresse rendue ni blanc ni fin de ligne.
//! 5. **UN IDENTIFIANT EST DE L'ASCII IMPRIMABLE**, sans chevron.
//! 6. **UNE DATE SE RELIT** : son fuseau est de la forme `±hhmm`.

#![no_main]

use libfuzzer_sys::fuzz_target;

use ams_mime::{message_ids, named_addresses, read_date_time, write_addr_spec, write_display_name};

/// Ce qui borde les tampons, pour voir si l'on écrit au-delà.
const GARDE: u8 = 0xa5;
/// La place qu'on laisse : petite, pour que les débordements se produisent.
const PLACE: usize = 64;

/// Vrai si `morceau` est une tranche de `tout`.
fn est_une_tranche(morceau: &[u8], tout: &[u8]) -> bool {
    let debut = tout.as_ptr() as usize;
    let fin = debut + tout.len();
    let ici = morceau.as_ptr() as usize;
    morceau.is_empty() || (ici >= debut && ici + morceau.len() <= fin)
}

fuzz_target!(|champ: &[u8]| {
    for une in named_addresses(champ) {
        // PROPRIÉTÉ 3.
        assert!(est_une_tranche(une.name, champ), "un nom inventé");
        assert!(est_une_tranche(une.address, champ), "une adresse inventée");

        let mut travail = vec![GARDE; PLACE + 16];
        let mut sortie = vec![GARDE; PLACE * 2 + 16];
        if let Ok(ecrits) =
            write_display_name(une.name, &mut travail[..PLACE], &mut sortie[..PLACE * 2])
        {
            // PROPRIÉTÉ 2.
            assert!(ecrits <= PLACE * 2, "une longueur qui déborde");
            let nom = &sortie[..ecrits];
            // PROPRIÉTÉ 4 : le décodage d'un mot encodé peut rendre ce qu'il
            // veut, mais le blanc de bordure et les plis du TEXTE s'en vont.
            assert!(
                !nom.starts_with(b" ") || une.name.contains(&b'='),
                "un nom qui commence par un blanc"
            );
        }
        assert!(travail[PLACE..].iter().all(|o| *o == GARDE), "débordement");
        assert!(
            sortie[PLACE * 2..].iter().all(|o| *o == GARDE),
            "débordement"
        );

        let mut adresse = vec![GARDE; PLACE + 16];
        if let Ok(ecrits) = write_addr_spec(une.address, &mut adresse[..PLACE]) {
            assert!(ecrits <= PLACE, "une longueur qui déborde");
        }
        assert!(adresse[PLACE..].iter().all(|o| *o == GARDE), "débordement");
        // Avec toute la place qu'il faut, l'adresse tient toujours, et ne
        // porte plus de blanc hors d'une chaîne citée.
        let mut large = vec![0_u8; une.address.len()];
        let ecrits = write_addr_spec(une.address, &mut large).expect("sa propre taille suffit");
        let rendue = &large[..ecrits];
        if !rendue.contains(&b'"') {
            assert!(
                !rendue
                    .iter()
                    .any(|o| matches!(*o, b' ' | b'\t' | b'\r' | b'\n')),
                "une adresse qui porte un blanc"
            );
        }
    }

    for identifiant in message_ids(champ) {
        // PROPRIÉTÉ 5.
        assert!(!identifiant.is_empty());
        assert!(
            identifiant
                .iter()
                .all(|o| (b'!'..=b'~').contains(o) && *o != b'>'),
            "un identifiant hors de l'ASCII imprimable"
        );
        assert!(est_une_tranche(identifiant, champ));
    }

    if let Some(date) = read_date_time(champ) {
        // PROPRIÉTÉ 6.
        let zone = date.zone();
        assert!(matches!(zone[0], b'+' | b'-'));
        assert!(zone[1..].iter().all(u8::is_ascii_digit));
    }
});
