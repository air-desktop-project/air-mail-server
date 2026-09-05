// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : l'UTF-7 modifié de RFC 3501 §5.1.3**, dans les deux sens.
//!
//! # POURQUOI CE CODEC MÉRITE UNE CIBLE
//!
//! Un nom de boîte vient du réseau et finit **dans un nom de répertoire**. Ce
//! codec est donc traversé par des octets choisis par un pair, avant toute
//! vérification de forme — et il fait ce qu'un décodeur fait de plus délicat :
//! accumuler des bits, apparier des demi-substituts, écrire dans un tampon
//! borné.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets, dans les deux sens et
//!    quelle que soit la place offerte.
//! 2. **CE QUI EST ÉCRIT TIENT DANS CE QU'ON A DONNÉ.** Une longueur rendue
//!    plus grande que le tampon ferait lire à l'appelant des octets qui ne sont
//!    pas à lui.
//! 3. **UN DÉCODAGE RÉUSSI REND DE L'UTF-8 VALIDE.** C'est la seule chose que
//!    l'appelant a le droit de supposer : le nom descend vers le magasin, et un
//!    nom mal formé y deviendrait un répertoire qu'on ne saurait plus relire.
//! 4. **L'ALLER-RETOUR EST L'IDENTITÉ**, sur ce qui se décode. Un nom qui
//!    reviendrait différent désignerait une AUTRE boîte — c'est la propriété
//!    dont dépend le fait qu'un client rev1 et un client rev2 parlent bien de
//!    la même.
//! 5. **UNE PLACE INSUFFISANTE SE DIT**, elle ne tronque pas. Un nom tronqué
//!    est un autre nom, et l'appelant ne pourrait pas s'en apercevoir.

#![no_main]

use libfuzzer_sys::fuzz_target;

/// De quoi transcrire tout nom que la grammaire admet, et bien au-delà.
const ASSEZ: usize = 4096;

fuzz_target!(|donnees: &[u8]| {
    // Le premier octet choisit la place offerte : c'est ainsi que les chemins
    // « la place manque » se prennent, et ils sont la moitié de ce code.
    let (place, entree) = match donnees.split_first() {
        Some((tete, reste)) => (usize::from(*tete), reste),
        None => return,
    };

    // ── DÉCODER ────────────────────────────────────────────────────────────
    let mut sortie = [0_u8; ASSEZ];
    let borne = place.min(ASSEZ);
    if let Ok(ecrits) = ams_proto_imap::utf7_decode(entree, &mut sortie[..borne]) {
        // 2. Ce qui est écrit tient dans ce qu'on a donné.
        assert!(ecrits <= borne, "{ecrits} octets écrits dans {borne}");
        let decode = &sortie[..ecrits];
        // 3. Un décodage réussi rend de l'UTF-8 valide.
        let texte = core::str::from_utf8(decode).expect("un décodage rend de l'UTF-8");

        // 4. L'aller-retour est l'identité.
        let mut retour = [0_u8; ASSEZ];
        let combien = ams_proto_imap::utf7_encode(texte.as_bytes(), &mut retour)
            .expect("ce qui s'est décodé se réencode");
        let mut encore = [0_u8; ASSEZ];
        let refait = ams_proto_imap::utf7_decode(&retour[..combien], &mut encore)
            .expect("ce qui s'est encodé se redécode");
        assert_eq!(
            &encore[..refait],
            decode,
            "l'aller-retour a changé le nom : {texte:?}"
        );
    }

    // ── ENCODER ────────────────────────────────────────────────────────────
    //
    // On n'encode que de l'UTF-8 valide : c'est le contrat, et l'entrée du
    // fuzzeur ne l'est pas toujours. Ce qui est éprouvé ici est la BORNE.
    if let Ok(texte) = core::str::from_utf8(entree) {
        let mut serre = [0_u8; ASSEZ];
        let borne = place.min(ASSEZ);
        match ams_proto_imap::utf7_encode(texte.as_bytes(), &mut serre[..borne]) {
            Ok(ecrits) => {
                assert!(ecrits <= borne, "{ecrits} octets écrits dans {borne}");
                // 5. Ce qui est rendu se relit, et redonne le même texte.
                let mut relu = [0_u8; ASSEZ];
                let refait = ams_proto_imap::utf7_decode(&serre[..ecrits], &mut relu)
                    .expect("ce qui s'est encodé se redécode");
                assert_eq!(
                    &relu[..refait],
                    texte.as_bytes(),
                    "l'encodage a changé le nom : {texte:?}"
                );
            }
            // La place manque : c'est une réponse, pas un défaut.
            Err(_) => {}
        }
    }
});
