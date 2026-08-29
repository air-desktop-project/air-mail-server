// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : l'`ENVELOPE` d'un message** (RFC 9051 §7.5.2).
//!
//! # CE QU'ELLE ÉCRIT PART SUR LE FIL
//!
//! L'enveloppe est composée à partir d'un EN-TÊTE, c'est-à-dire de ce que
//! n'importe qui peut écrire, et elle est recopiée telle quelle dans une réponse
//! IMAP. Une enveloppe mal formée — une parenthèse en trop, un guillemet non
//! échappé — ne fait pas seulement une réponse illisible : elle désynchronise le
//! client, qui lira la suite du dialogue comme la fin de la réponse.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets de l'en-tête.
//! 2. **CE QUI EST ÉCRIT EST BIEN FORMÉ** : les parenthèses s'équilibrent, les
//!    chaînes se ferment, et aucun guillemet ne s'échappe d'une chaîne sans être
//!    précédé d'un antislash. C'est la propriété qui empêche la
//!    désynchronisation.
//! 3. **L'ENVELOPPE A DIX CHAMPS**, ni plus ni moins : c'est la forme que la
//!    grammaire de §7.5.2 impose, et un champ de moins ferait lire au client le
//!    suivant à la place.
//! 4. **RIEN N'EST ÉCRIT AU-DELÀ DE CE QU'ON DONNE** : la longueur rendue ne
//!    dépasse jamais le tampon, et un tampon trop court le dit au lieu d'écrire
//!    une enveloppe à moitié.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_mime::{Error, Limits, write_envelope};

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// Le bloc d'en-tête, tel qu'il arriverait d'un message.
    entete: &'a [u8],
    /// La place qu'on laisse, pour éprouver le manque.
    place: u16,
}

/// Vérifie qu'un texte est une enveloppe bien formée, et rend son nombre de
/// champs au premier niveau.
///
/// Les champs se comptent par les espaces qui les séparent au premier niveau :
/// neuf séparateurs pour dix champs.
fn champs_de(texte: &[u8]) -> usize {
    assert!(
        texte.first() == Some(&b'(') && texte.last() == Some(&b')'),
        "une enveloppe s'ouvre et se ferme"
    );
    let mut profondeur = 0_usize;
    let mut separateurs = 0_usize;
    let mut dans_une_chaine = false;
    let mut i = 0_usize;
    while i < texte.len() {
        let octet = texte[i];
        if dans_une_chaine {
            match octet {
                // Un octet échappé ne compte pas : c'est ce qui distingue un
                // guillemet de fin d'un guillemet du texte.
                b'\\' => i = i.saturating_add(1),
                b'"' => dans_une_chaine = false,
                // UNE CHAÎNE NE PORTE PAS DE FIN DE LIGNE : elle ferait de la
                // réponse deux réponses, et le client lirait la seconde comme
                // du protocole.
                b'\r' | b'\n' => panic!("une fin de ligne dans une chaîne"),
                _ => {}
            }
            i = i.saturating_add(1);
            continue;
        }
        match octet {
            b'"' => dans_une_chaine = true,
            b'(' => profondeur = profondeur.saturating_add(1),
            b')' => {
                assert!(profondeur > 0, "une parenthèse fermante de trop");
                profondeur = profondeur.saturating_sub(1);
            }
            b' ' if profondeur == 1 => separateurs = separateurs.saturating_add(1),
            _ => {}
        }
        i = i.saturating_add(1);
    }
    assert!(!dans_une_chaine, "une chaîne qui ne se ferme pas");
    assert_eq!(profondeur, 0, "des parenthèses qui ne s'équilibrent pas");
    separateurs.saturating_add(1)
}

fuzz_target!(|entree: Entree<'_>| {
    let bornes = Limits::DEFAULT;
    let mut grand = vec![0_u8; 256 * 1024];

    if let Ok(ecrits) = write_envelope(entree.entete, &mut grand, &bornes) {
        // PROPRIÉTÉ 4 : rien au-delà de ce qu'on donne.
        assert!(ecrits <= grand.len());
        let compose = grand.get(..ecrits).unwrap_or_default();
        // PROPRIÉTÉS 2 et 3.
        assert_eq!(
            champs_de(compose),
            10,
            "une enveloppe a dix champs : {:?}",
            core::str::from_utf8(compose)
        );

        // Un tampon plus court ne rend jamais une enveloppe à moitié.
        let court = usize::from(entree.place).min(ecrits);
        let mut petit = vec![0_u8; court];
        match write_envelope(entree.entete, &mut petit, &bornes) {
            Ok(refait) => {
                assert_eq!(
                    refait, ecrits,
                    "deux compositions du même en-tête diffèrent"
                );
                assert_eq!(petit.get(..refait), Some(compose));
            }
            Err(erreur) => assert_eq!(erreur, Error::BufferTooSmall),
        }
    }
});
