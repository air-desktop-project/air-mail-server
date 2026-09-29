// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : le registre de réception** (0.2.44) — un fichier quelconque, tel
//! qu'un disque abîmé ou une archive retouchée le rendrait, et un bloc
//! d'en-tête quelconque, tel qu'un pair l'enverrait.
//!
//! Les graines sont un fichier scellé et un bloc d'en-tête ordinaires : le fuzz
//! part de ce qui se lit, et l'altère.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **UNE TRAME LUE SE RÉÉCRIT, ET SE RELIT À L'IDENTIQUE** : ce que le
//!    lecteur accepte, l'écrivain sait le reproduire.
//! 3. **UN FICHIER VÉRIFIÉ A UN ENTÊTE, ET SON SCEAU PORTE LE BON COMPTE.**
//! 4. **LES TRAMES ENTIÈRES NE DÉBORDENT PAS LE FICHIER.**
//! 5. **LES EN-TÊTES D'UN PAIR SE LISENT SANS PANIQUE**, et chaque valeur
//!    retenue est bornée.

#![no_main]

use ams_config::registre::{
    TEXTE_MAX, en_json, en_tetes, lire_trame, trame, trames_entieres, verifier,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|octets: &[u8]| {
    // 2. Chaque trame lue se réécrit, et se relit à l'identique.
    let mut debut = 0;
    while let Ok((quoi, apres)) = lire_trame(octets, debut) {
        assert!(apres > debut && apres <= octets.len());
        let _ = en_json(&quoi);
        let reecrite = trame(&quoi).expect("ce qui se lit se réécrit");
        let (relue, _) = lire_trame(&reecrite, 0).expect("ce qui s'écrit se relit");
        assert_eq!(relue, quoi);
        debut = apres;
    }
    // 3. Un fichier vérifié.
    if let Ok(bilan) = verifier(octets) {
        assert!(bilan.enregistrements >= 1);
        if let Some(sceau) = bilan.sceau {
            assert_eq!(sceau.enregistrements, bilan.enregistrements);
        }
    }
    // 4. Les trames entières.
    let (entier, _) = trames_entieres(octets);
    assert!(entier <= octets.len());
    // 5. Les en-têtes d'un pair.
    let vus = en_tetes(octets);
    for valeur in [
        &vus.message_id,
        &vus.date,
        &vus.from,
        &vus.sender,
        &vus.reply_to,
        &vus.list_id,
    ] {
        assert!(valeur.len() <= TEXTE_MAX);
    }
});
