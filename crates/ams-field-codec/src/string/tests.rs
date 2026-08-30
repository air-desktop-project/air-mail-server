// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une chaîne littérale a le droit d'être.

use super::{decode_string, encode_string};
use crate::error::Fault;

/// Écrit puis relit.
fn aller_retour(clair: &[u8]) -> (std::vec::Vec<u8>, usize) {
    let mut ecrit = std::vec![0_u8; clair.len().saturating_mul(4).saturating_add(16)];
    let ecrits = encode_string(clair, &mut ecrit).expect("écrivable");
    ecrit.truncate(ecrits);
    let mut relu = std::vec![0_u8; clair.len().saturating_add(16)];
    let (texte, lus) = decode_string(&ecrit, &mut relu).expect("relisible");
    assert_eq!(lus, ecrits, "on relit ce qu'on a écrit, ni plus ni moins");
    (texte.to_vec(), ecrits)
}

/// Ce qu'on écrit se relit, comprimé ou non.
#[test]
fn ce_qu_on_ecrit_se_relit() {
    for clair in [
        &b""[..],
        b"a",
        b"www.example.com",
        b"custom-key",
        b"application/json",
        b"\x00\xff",
    ] {
        let (relu, _) = aller_retour(clair);
        assert_eq!(relu, clair, "{clair:?}");
    }
}

/// **ON COMPRIME QUAND CELA RACCOURCIT, ET PAS AUTREMENT.**
#[test]
fn on_comprime_quand_cela_raccourcit() {
    // `www.example.com` : quinze octets en clair, douze comprimés.
    let mut sortie = [0_u8; 64];
    let ecrits = encode_string(b"www.example.com", &mut sortie).expect("écrivable");
    assert_eq!(sortie.first().map(|octet| octet & 0x80), Some(0x80));
    assert_eq!(ecrits, 13, "un octet de longueur, douze de contenu");

    // Des octets que Huffman allonge : chacun coûte plus de huit bits.
    let long = [0x00_u8, 0x01, 0x02, 0x03];
    let ecrits = encode_string(&long, &mut sortie).expect("écrivable");
    assert_eq!(
        sortie.first().map(|octet| octet & 0x80),
        Some(0x00),
        "en clair"
    );
    assert_eq!(ecrits, 5);
}

/// **LA LONGUEUR VIENT DU RÉSEAU, ET ELLE EST VÉRIFIÉE AVANT D'ÊTRE CRUE.** Un
/// décodeur qui découpe sans vérifier lirait la suite du bloc comme du contenu.
#[test]
fn une_longueur_qui_deborde_se_refuse() {
    let mut relu = [0_u8; 64];
    for entree in [
        // Annonce dix octets, en porte trois.
        &[0x0a_u8, b'a', b'b', b'c'][..],
        // Annonce un octet, n'en porte aucun.
        &[0x01],
        // Comprimée, et débordante.
        &[0x8a, 0xff],
        // Vide : il n'y a même pas de longueur.
        &[],
    ] {
        let issue = decode_string(entree, &mut relu).expect_err("refusé");
        assert!(
            matches!(issue.fault(), Fault::BadString | Fault::BadInteger),
            "{entree:?} : {issue:?}"
        );
    }
}

/// Un tampon de sortie trop court le dit.
#[test]
fn un_tampon_trop_court_le_dit() {
    let entree = [0x03_u8, b'a', b'b', b'c'];
    for taille in 0..3_usize {
        let mut petit = std::vec![0_u8; taille];
        let issue = decode_string(&entree, &mut petit).expect_err("refusé");
        assert_eq!(issue.fault(), Fault::BufferTooSmall, "{taille}");
    }
    // `abc` tient en trois octets une fois comprimé — un de longueur, deux de
    // contenu —, et c'est donc à deux que la place manque.
    for taille in 0..3_usize {
        let mut petit = std::vec![0_u8; taille];
        let issue = encode_string(b"abc", &mut petit).expect_err("refusé");
        assert_eq!(issue.fault(), Fault::BufferTooSmall, "{taille}");
    }
    assert_eq!(encode_string(b"abc", &mut [0_u8; 3]), Ok(3));

    // Une chaîne que Huffman ALLONGE s'écrit en clair, et manque de place au
    // même endroit : c'est l'autre branche de l'écriture du corps.
    let long = std::vec![0x00_u8; 32];
    for taille in 0..33_usize {
        let mut petit = std::vec![0_u8; taille];
        let issue = encode_string(&long, &mut petit).expect_err("refusé");
        assert_eq!(issue.fault(), Fault::BufferTooSmall, "{taille}");
    }
    assert!(encode_string(&long, &mut [0_u8; 33]).is_ok());
}

/// **UN CORPS COMPRIMÉ FAUTIF FAIT ÉCHOUER LA CHAÎNE**, et la faute qui remonte
/// est celle de Huffman : c'est elle qui dit ce qui cloche.
#[test]
fn un_corps_comprime_fautif_remonte() {
    let mut relu = [0_u8; 64];
    // Comprimée, un octet : `0x00` termine sur un remplissage qui n'est pas
    // fait de un.
    let issue = decode_string(&[0x81, 0x00], &mut relu).expect_err("refusé");
    assert_eq!(issue.fault(), Fault::BadHuffman);
}

/// Une chaîne littérale non comprimée se lit telle quelle.
#[test]
fn une_chaine_en_clair_se_lit_telle_quelle() {
    let mut relu = [0_u8; 64];
    let (texte, lus) = decode_string(&[0x03, b'a', b'b', b'c'], &mut relu).expect("lisible");
    assert_eq!(texte, b"abc");
    assert_eq!(lus, 4);
    // Une chaîne vide est licite.
    let (vide, lus) = decode_string(&[0x00], &mut relu).expect("lisible");
    assert_eq!(vide, b"");
    assert_eq!(lus, 1);
}
