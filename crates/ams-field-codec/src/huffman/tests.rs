// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une chaîne comprimée a le droit d'être.

use super::{decode_huffman, encode_huffman, encoded_huffman_len};
use crate::error::Fault;

/// Comprime, et rend les octets.
fn comprime(clair: &[u8]) -> std::vec::Vec<u8> {
    let mut sortie = std::vec![0_u8; clair.len().saturating_mul(4).saturating_add(8)];
    let ecrits = encode_huffman(clair, &mut sortie).expect("comprimable");
    assert_eq!(ecrits, encoded_huffman_len(clair), "la longueur annoncée");
    sortie.truncate(ecrits);
    sortie
}

/// Décomprime, et rend les octets.
fn decomprime(brut: &[u8]) -> std::vec::Vec<u8> {
    let mut sortie = std::vec![0_u8; brut.len().saturating_mul(8).saturating_add(8)];
    let ecrits = decode_huffman(brut, &mut sortie).expect("décomprimable");
    sortie.truncate(ecrits);
    sortie
}

/// Les exemples de l'annexe C.4 de RFC 7541.
#[test]
fn les_exemples_de_la_rfc_se_compriment() {
    for (clair, attendu) in [
        (
            &b"www.example.com"[..],
            &[
                0xf1_u8, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
            ][..],
        ),
        (b"no-cache", &[0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf]),
        (
            b"custom-key",
            &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f],
        ),
        (
            b"custom-value",
            &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf],
        ),
    ] {
        assert_eq!(comprime(clair), attendu, "{clair:?}");
        assert_eq!(decomprime(attendu), clair, "{attendu:?}");
    }
}

/// Ce qu'on comprime se décomprime à l'identique, pour tout octet.
#[test]
fn ce_qu_on_comprime_se_decomprime() {
    // Chaque octet seul.
    for octet in 0..=255_u8 {
        let clair = [octet];
        assert_eq!(decomprime(&comprime(&clair)), clair, "{octet}");
    }
    // Et quelques chaînes.
    for clair in [
        &b""[..],
        b"a",
        b"content-type",
        b"application/json; charset=utf-8",
        b"\x00\x01\x02\xfd\xfe\xff",
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        assert_eq!(decomprime(&comprime(clair)), clair, "{clair:?}");
    }
    // La chaîne vide ne produit aucun octet.
    assert_eq!(comprime(b""), std::vec::Vec::<u8>::new());
    assert_eq!(encoded_huffman_len(b""), 0);
}

/// **LE REMPLISSAGE : AU PLUS SEPT BITS, ET TOUS À UN** (§5.2). Sans cela, il y
/// aurait deux écritures d'une même chaîne — et deux implémentations qui ne
/// s'accordent pas sur laquelle est valide.
#[test]
fn un_remplissage_fautif_se_refuse() {
    let mut sortie = [0_u8; 64];
    // `0x00` : le code de `0` fait cinq bits (`00000`), suivi de trois bits
    // nuls — un remplissage qui n'est pas fait de un.
    let issue = decode_huffman(&[0x00], &mut sortie).expect_err("refusé");
    assert_eq!(issue.fault(), Fault::BadHuffman);

    // Un octet entier de remplissage : huit bits, c'est un symbole omis.
    // `0xff` seul ne complète aucun code court : ce sont les bits de tête de
    // codes longs, et huit bits en attente sont refusés.
    let issue = decode_huffman(&[0xff], &mut sortie).expect_err("refusé");
    assert_eq!(issue.fault(), Fault::BadHuffman);

    // Un remplissage de un, mais trop long : deux octets de `0xff` après un
    // symbole complet.
    let mut trop = comprime(b"a");
    trop.push(0xff);
    assert!(decode_huffman(&trop, &mut sortie).is_err());
}

/// **`EOS` DANS UNE CHAÎNE EST UNE FAUTE** (§5.2) : il ne termine rien ici, la
/// longueur le fait — et le tolérer donnerait deux écritures du même texte.
#[test]
fn eos_dans_une_chaine_se_refuse() {
    // Le code d'`EOS` fait trente bits à un ; quatre octets de `0xff` puis deux
    // bits de remplissage.
    let mut sortie = [0_u8; 64];
    let issue = decode_huffman(&[0xff, 0xff, 0xff, 0xff], &mut sortie).expect_err("refusé");
    assert_eq!(issue.fault(), Fault::BadHuffman);
}

/// Un code qui n'existe pas se refuse, sans boucler.
#[test]
fn un_code_inconnu_se_refuse() {
    let mut sortie = [0_u8; 64];
    // Trente et un bits à un : au-delà du plus long code, et ce n'est pas
    // `EOS`.
    let issue = decode_huffman(&[0xff, 0xff, 0xff, 0xff, 0xfe], &mut sortie).expect_err("refusé");
    assert_eq!(issue.fault(), Fault::BadHuffman);
}

/// Un tampon trop court le dit, dans les deux sens.
#[test]
fn un_tampon_trop_court_le_dit() {
    let brut = comprime(b"www.example.com");
    for taille in 0..15_usize {
        let mut petit = std::vec![0_u8; taille];
        let issue = decode_huffman(&brut, &mut petit).expect_err("refusé");
        assert_eq!(issue.fault(), Fault::BufferTooSmall, "{taille}");
    }
    for taille in 0..brut.len() {
        let mut petit = std::vec![0_u8; taille];
        let issue = encode_huffman(b"www.example.com", &mut petit).expect_err("refusé");
        assert_eq!(issue.fault(), Fault::BufferTooSmall, "{taille}");
    }
}
