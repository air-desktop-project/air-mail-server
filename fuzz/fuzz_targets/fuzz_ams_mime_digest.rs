// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : le résumé d'un message** — sujet et expéditeur, pour une liste.
//!
//! # POURQUOI CELLE-CI, ALORS QUE `mime-envelope` EXISTE
//!
//! L'enveloppe rend les octets de l'en-tête TELS QUELS. Le résumé, lui, DÉCODE :
//! il défait des mots encodés (RFC 2047), efface des plis, et dégage une adresse
//! de ce qui l'entoure. **Décoder peut grandir** — quatre caractères de base64
//! rendent trois octets `iso-8859-1`, qui font jusqu'à six octets d'UTF-8 —, et
//! c'est exactement le genre de calcul où une borne s'oublie.
//!
//! Ce qu'il écrit va dans deux tampons de taille FIXE, choisis d'avance par
//! l'appelant, à partir d'un en-tête que n'importe qui peut écrire (C3).
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets de l'en-tête.
//! 2. **RIEN N'EST ÉCRIT AU-DELÀ DES TAMPONS** : les longueurs rendues tiennent
//!    dans ce qu'on a donné, et les octets qui suivent ne bougent pas.
//! 3. **UN TEXTE RENDU NE PORTE PAS DE FIN DE LIGNE.** C'est la règle qui, en
//!    IMAP, empêche une désynchronisation ; ici le rendu est du JSON, mais un pli
//!    reste un artefact de transport qu'on ne montre pas.
//! 4. **UNE ADRESSE EST UNE ADRESSE** : ce qu'on rend porte une arobase, et
//!    aucun des octets qui ne peuvent qu'entourer une adresse — blanc,
//!    commentaire, chevron, virgule.
//! 5. **LE RÉSULTAT NE DÉPEND PAS DE LA PLACE QU'ON LAISSE** : avec des tampons
//!    plus grands, on rend la même chose ou davantage, jamais autre chose.

#![no_main]

use libfuzzer_sys::fuzz_target;

use ams_mime::{DIGEST_FROM_MAX, DIGEST_SUBJECT_MAX, Limits, write_digest};

/// Ce qui borde les tampons, pour voir si l'on écrit au-delà.
const GARDE: u8 = 0xa5;

/// Vérifie qu'on n'a rien écrit au-delà de `combien`, et rend ce qui est écrit.
fn ecrit(tampon: &[u8], combien: Option<usize>, borne: usize) -> Option<&[u8]> {
    assert!(
        tampon
            .get(borne..)
            .is_some_and(|apres| apres.iter().all(|octet| *octet == GARDE)),
        "on a écrit au-delà du tampon"
    );
    let combien = combien?;
    // PROPRIÉTÉ 2 : la longueur rendue tient dans ce qu'on a donné.
    assert!(combien <= borne, "une longueur qui déborde le tampon");
    tampon.get(..combien)
}

fuzz_target!(|entete: &[u8]| {
    let bornes = Limits::DEFAULT;
    let mut sujet = vec![GARDE; DIGEST_SUBJECT_MAX + 64];
    let mut expediteur = vec![GARDE; DIGEST_FROM_MAX + 64];

    let vu = write_digest(
        entete,
        &mut sujet[..DIGEST_SUBJECT_MAX],
        &mut expediteur[..DIGEST_FROM_MAX],
        &bornes,
    );

    if let Some(texte) = ecrit(&sujet, vu.subject, DIGEST_SUBJECT_MAX) {
        // PROPRIÉTÉ 3.
        assert!(
            !texte.contains(&b'\r') && !texte.contains(&b'\n'),
            "un sujet qui porte une fin de ligne"
        );
    }

    if let Some(adresse) = ecrit(&expediteur, vu.from, DIGEST_FROM_MAX) {
        // PROPRIÉTÉ 4.
        assert!(adresse.contains(&b'@'), "une adresse sans arobase");
        assert!(
            !adresse.iter().any(|octet| matches!(
                *octet,
                b' ' | b'\t' | b'\r' | b'\n' | b'(' | b')' | b'<' | b'>' | b','
            )),
            "une adresse qui porte ce qui ne fait que l'entourer"
        );
    }

    // PROPRIÉTÉ 5 : de la place en plus ne change pas ce qu'on rend.
    let mut large_sujet = vec![0_u8; DIGEST_SUBJECT_MAX * 2];
    let mut large_expediteur = vec![0_u8; DIGEST_FROM_MAX * 2];
    let encore = write_digest(entete, &mut large_sujet, &mut large_expediteur, &bornes);
    if let Some(combien) = vu.subject {
        assert_eq!(
            encore.subject,
            Some(combien),
            "un tampon plus grand a changé le sujet"
        );
        assert_eq!(large_sujet.get(..combien), sujet.get(..combien));
    }
    if let Some(combien) = vu.from {
        assert_eq!(
            encore.from,
            Some(combien),
            "un tampon plus grand a changé l'expéditeur"
        );
        assert_eq!(large_expediteur.get(..combien), expediteur.get(..combien));
    }
});
