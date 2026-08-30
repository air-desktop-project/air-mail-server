// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un entier à préfixe a le droit d'être.

use super::{decode_integer, encode_integer};
use crate::error::Fault;

/// Les trois exemples de l'annexe C.1 de RFC 7541.
#[test]
fn les_exemples_de_la_rfc_se_lisent() {
    // C.1.1 : dix sur un préfixe de cinq bits.
    assert_eq!(decode_integer(&[0b1010_1010], 5), Ok((10, 1)));
    // C.1.2 : mille trois cent trente-sept sur cinq bits.
    assert_eq!(
        decode_integer(&[0b0011_1111, 0b1001_1010, 0b0000_1010], 5),
        Ok((1337, 3))
    );
    // C.1.3 : quarante-deux, aligné sur un octet.
    assert_eq!(decode_integer(&[42], 8), Ok((42, 1)));
}

/// Ce qu'on écrit se relit, sur tous les préfixes.
#[test]
fn ce_qu_on_ecrit_se_relit() {
    for bits in 1..=8_u32 {
        for valeur in [
            0_u32,
            1,
            30,
            31,
            127,
            128,
            255,
            256,
            16_383,
            16_384,
            1_337,
            u32::MAX.saturating_sub(1),
            u32::MAX,
        ] {
            let mut sortie = [0_u8; 8];
            let ecrits = encode_integer(valeur, bits, 0, &mut sortie).expect("écrivable");
            assert_eq!(
                decode_integer(sortie.get(..ecrits).unwrap_or_default(), bits),
                Ok((valeur, ecrits)),
                "{valeur} sur {bits} bits"
            );
        }
    }
}

/// **LES BITS DE TÊTE SONT PRÉSERVÉS** : ils portent le type de la
/// représentation, et les écraser changerait le sens de la ligne.
#[test]
fn les_bits_de_tete_sont_preserves() {
    let mut sortie = [0_u8; 8];
    let ecrits = encode_integer(2, 6, 0b1100_0000, &mut sortie).expect("écrivable");
    assert_eq!(sortie.first(), Some(&0b1100_0010));
    assert_eq!(ecrits, 1);
    // Et la lecture les ignore.
    assert_eq!(decode_integer(&sortie, 6), Ok((2, 1)));
}

/// **UN ENTIER QUI DÉBORDE N'EST PAS UN GRAND ENTIER.**
#[test]
fn un_entier_qui_deborde_se_refuse() {
    for octets in [
        // Une continuation infinie.
        &[0xff_u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff][..],
        // Ce qui dépasse `u32::MAX`.
        &[0xff, 0x80, 0x80, 0x80, 0x80, 0x10],
        &[0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
    ] {
        let issue = decode_integer(octets, 8).expect_err("refusé");
        assert_eq!(issue.fault(), Fault::BadInteger, "{octets:?}");
    }
}

/// **UN ENTIER QUI NE SE TERMINE PAS N'EN EST PAS UN**, et un tampon vide non
/// plus.
#[test]
fn un_entier_inacheve_se_refuse() {
    for octets in [&[][..], &[0x1f], &[0x1f, 0x80], &[0x1f, 0x80, 0x80]] {
        let issue = decode_integer(octets, 5).expect_err("refusé");
        assert_eq!(issue.fault(), Fault::BadInteger, "{octets:?}");
    }
}

/// **UN MULTIPLICATEUR, ET NON UN DÉCALAGE**, et voici pourquoi : ces six
/// octets-là se lisaient comme la valeur 255. `127u32.checked_shl(28)` rend
/// `Some` et jette les bits qui débordent — le décalage ne dépasse pas la
/// largeur du type, seule la valeur le fait.
///
/// Défaut écrit puis trouvé par ce test, en une heure.
#[test]
fn un_decalage_ne_suffit_pas_a_voir_le_debordement() {
    let issue = decode_integer(&[0xff, 0xff, 0xff, 0xff, 0xff, 0x7f], 8).expect_err("refusé");
    assert_eq!(issue.fault(), Fault::BadInteger);
}

/// **UNE ÉCRITURE NON CANONIQUE SE REFUSE** : `0x80` ajoute sept bits nuls, donc
/// rien, et une suite de continuations vides fait un entier arbitrairement long
/// qui vaut zéro.
#[test]
fn une_ecriture_trop_longue_se_refuse() {
    // Cinq octets de continuation, c'est le maximum d'un `u32`.
    assert!(decode_integer(&[0xff, 0x80, 0x80, 0x80, 0x80, 0x00], 8).is_ok());
    // Six, c'est un de trop.
    let issue = decode_integer(&[0xff, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00], 8).expect_err("refusé");
    assert_eq!(issue.fault(), Fault::BadInteger);
}

/// Un tampon trop court pour écrire le dit.
#[test]
fn un_tampon_trop_court_pour_ecrire_le_dit() {
    for taille in 0..3_usize {
        let mut petit = std::vec![0_u8; taille];
        let issue = encode_integer(1337, 5, 0, &mut petit).expect_err("refusé");
        assert_eq!(issue.fault(), Fault::BufferTooSmall, "{taille}");
    }
    // Un seul octet suffit pour ce qui tient dans le préfixe.
    let mut un = [0_u8; 1];
    assert_eq!(encode_integer(10, 5, 0, &mut un), Ok(1));
    let mut zero: [u8; 0] = [];
    assert!(encode_integer(10, 5, 0, &mut zero).is_err());
}
