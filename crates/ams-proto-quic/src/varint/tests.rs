// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un entier de §16 a le droit d'être.

use super::{VARINT_MAX, decode, encode, encoded_len};
use crate::error::{Reason, TransportError};

/// **LES QUATRE EXEMPLES DE L'ANNEXE A.1**, pris à la lettre. Le quatrième est
/// le même nombre que le troisième, écrit plus long : §16 dit que l'écriture
/// n'est pas canonique, et le décodeur ne s'en offusque pas.
#[test]
fn les_exemples_de_la_rfc_se_lisent() {
    let cas: [(&[u8], u64, usize); 5] = [
        (
            &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
            151_288_809_941_952_652,
            8,
        ),
        (&[0x9d, 0x7f, 0x3e, 0x7d], 494_878_333, 4),
        (&[0x7b, 0xbd], 15_293, 2),
        (&[0x25], 37, 1),
        // **LE MÊME TRENTE-SEPT, SUR DEUX OCTETS.** L'annexe A.1 le donne
        // exprès : une écriture longue est valide, et la refuser refuserait des
        // paquets conformes.
        (&[0x40, 0x25], 37, 2),
    ];
    for (octets, attendue, longueur) in cas {
        let (valeur, lus) = decode(octets).expect("lisible");
        assert_eq!(valeur, attendue, "{octets:02x?}");
        assert_eq!(lus, longueur, "{octets:02x?}");
    }
}

/// Ce qu'on écrit se relit, et se réécrit pareil.
#[test]
fn ce_qu_on_ecrit_se_relit() {
    for valeur in [
        0_u64,
        1,
        63,
        64,
        16_383,
        16_384,
        1_073_741_823,
        1_073_741_824,
        VARINT_MAX,
    ] {
        let mut octets = [0_u8; 8];
        let ecrits = encode(valeur, &mut octets).expect("écrivable");
        assert_eq!(ecrits, encoded_len(valeur).expect("mesurable"), "{valeur}");
        let (relue, lus) = decode(&octets).expect("relisible");
        assert_eq!(relue, valeur, "{valeur}");
        assert_eq!(lus, ecrits, "{valeur}");
    }
}

/// **ON ÉCRIT AU PLUS COURT**, et les quatre bornes sont exactement celles de
/// §16 : soixante-trois, seize mille trois cent quatre-vingt-trois, un milliard
/// soixante-treize millions sept cent quarante et un mille huit cent
/// vingt-trois.
#[test]
fn on_ecrit_au_plus_court() {
    for (valeur, longueur) in [
        (0_u64, 1_usize),
        (63, 1),
        (64, 2),
        (16_383, 2),
        (16_384, 4),
        (1_073_741_823, 4),
        (1_073_741_824, 8),
        (VARINT_MAX, 8),
    ] {
        assert_eq!(
            encoded_len(valeur).expect("mesurable"),
            longueur,
            "{valeur}"
        );
    }
}

/// **AU-DELÀ DE 2^62 - 1, §16 NE SAIT PAS ÉCRIRE**, et c'est notre faute si on
/// le lui demande : le pair n'a rien fait.
#[test]
fn au_dela_de_deux_puissance_soixante_deux_on_refuse() {
    for valeur in [VARINT_MAX.saturating_add(1), u64::MAX] {
        let issue = encoded_len(valeur).expect_err("hors borne");
        assert_eq!(issue.reason(), Reason::VarintTooLarge);
        assert_eq!(issue.code(), TransportError::InternalError);
        assert_eq!(
            encode(valeur, &mut [0_u8; 8])
                .expect_err("hors borne")
                .reason(),
            Reason::VarintTooLarge
        );
    }
}

/// Un tampon qui ne porte pas les octets annoncés, et un tampon vide.
#[test]
fn un_entier_tronque_se_refuse() {
    // Le premier octet annonce huit, il n'y en a que trois.
    for octets in [
        [0_u8; 0].as_slice(),
        &[0xc2],
        &[0xc2, 0x19, 0x7c],
        &[0x9d, 0x7f],
        &[0x7b],
    ] {
        let issue = decode(octets).expect_err("tronqué");
        assert_eq!(issue.reason(), Reason::Truncated, "{octets:02x?}");
        assert_eq!(issue.code(), TransportError::FrameEncodingError);
    }
}

/// La place manque à l'écriture, et c'est notre tampon.
#[test]
fn l_ecriture_veut_de_la_place() {
    for (valeur, taille) in [(0_u64, 0_usize), (64, 1), (16_384, 3), (VARINT_MAX, 7)] {
        let mut court = [0_u8; 8];
        let issue = encode(valeur, court.get_mut(..taille).expect("assez court"))
            .expect_err("la place manque");
        assert_eq!(issue.reason(), Reason::BufferTooSmall, "{valeur}");
        assert_eq!(issue.code(), TransportError::InternalError);
    }
}

/// **LES QUATRE ÉCRITURES D'UN MÊME NOMBRE SE LISENT TOUTES PAREIL.** C'est le
/// contraire de HPACK, où une écriture non canonique est une attaque — et la
/// différence tient à ce qu'ici la longueur est ANNONCÉE et BORNÉE.
#[test]
fn les_ecritures_longues_disent_la_meme_chose() {
    let ecritures: [&[u8]; 4] = [
        &[0x25],
        &[0x40, 0x25],
        &[0x80, 0x00, 0x00, 0x25],
        &[0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25],
    ];
    for octets in ecritures {
        let (valeur, lus) = decode(octets).expect("lisible");
        assert_eq!(valeur, 37, "{octets:02x?}");
        assert_eq!(lus, octets.len(), "{octets:02x?}");
    }
}
