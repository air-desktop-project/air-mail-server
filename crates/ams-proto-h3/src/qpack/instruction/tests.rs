// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que les deux flux QPACK ont le droit de porter.

use super::{
    DecoderInstruction, EncoderInstruction, check_encoder_instruction, read_decoder_instruction,
    read_encoder_instruction, write_decoder_instruction,
};
use crate::error::{H3Error, Reason};
use crate::qpack::representation::Table;

/// Lit une instruction d'encodeur dans un tampon qui vit assez longtemps.
fn lire(octets: &[u8]) -> Result<(EncoderInstruction<'static>, usize), crate::error::Error> {
    let place: &'static mut [u8] = std::boxed::Box::leak(std::boxed::Box::new([0_u8; 256]));
    let decode = read_encoder_instruction(octets, place)?;
    Ok((decode.instruction, decode.read))
}

/// **§4.3.1 : `001xxxxx`** — le pair change la taille de sa table.
#[test]
fn un_changement_de_capacite_se_lit() {
    let (instruction, lus) = lire(&[0b0011_1111, 0x21]).expect("lisible");
    assert_eq!(
        instruction,
        EncoderInstruction::SetCapacity { capacity: 64 }
    );
    assert_eq!(lus, 2);

    let (instruction, lus) = lire(&[0b0010_0000]).expect("lisible");
    assert_eq!(instruction, EncoderInstruction::SetCapacity { capacity: 0 });
    assert_eq!(lus, 1);
}

/// **§4.3.2 : `1Txxxxxx`** — insertion avec un nom indexé.
#[test]
fn une_insertion_avec_nom_indexe_se_lit() {
    let (instruction, lus) = lire(&[0b1100_0011, 0x02, b'/', b'a']).expect("lisible");
    assert_eq!(
        instruction,
        EncoderInstruction::InsertWithNameRef {
            index: 3,
            table: Table::Static,
            value: b"/a",
        }
    );
    assert_eq!(lus, 4);

    // `T=0` désigne la table dynamique.
    let (instruction, _) = lire(&[0b1000_0011, 0x00]).expect("lisible");
    assert_eq!(
        instruction,
        EncoderInstruction::InsertWithNameRef {
            index: 3,
            table: Table::Dynamic,
            value: b"",
        }
    );
}

/// **§4.3.3 : `01Hxxxxx`** — insertion avec un nom écrit, dont le fanion de
/// Huffman partage le premier octet avec les bits de type.
#[test]
fn une_insertion_avec_nom_ecrit_se_lit() {
    let brut = [0b0100_0011, b'a', b'b', b'c', 0x02, b'x', b'y'];
    let (instruction, lus) = lire(&brut).expect("lisible");
    assert_eq!(
        instruction,
        EncoderInstruction::InsertWithLiteralName {
            name: b"abc",
            value: b"xy",
        }
    );
    assert_eq!(lus, brut.len());

    // Le nom comprimé se lit aussi.
    let mut serre = [0_u8; 16];
    let ecrits = ams_field_codec::encode_huffman(b"cookie", &mut serre).expect("comprimable");
    let mut brut = std::vec::Vec::new();
    brut.push(0b0110_0000 | u8::try_from(ecrits).expect("court"));
    brut.extend_from_slice(serre.get(..ecrits).expect("écrit"));
    brut.push(0x00);
    let (instruction, _) = lire(&brut).expect("lisible");
    assert_eq!(
        instruction,
        EncoderInstruction::InsertWithLiteralName {
            name: b"cookie",
            value: b"",
        }
    );
}

/// **§4.3.4 : `000xxxxx`** — recopie une entrée en tête de table.
#[test]
fn une_duplication_se_lit() {
    let (instruction, lus) = lire(&[0b0000_0111]).expect("lisible");
    assert_eq!(instruction, EncoderInstruction::Duplicate { index: 7 });
    assert_eq!(lus, 1);
}

/// **LES QUATRE MOTIFS NE SE CONFONDENT PAS**, et le classement va du plus long
/// au plus court.
#[test]
fn les_quatre_motifs_ne_se_confondent_pas() {
    let cas: [(u8, &str); 4] = [
        (0b1000_0000, "nom indexé"),
        (0b0100_0000, "nom écrit"),
        (0b0010_0000, "capacité"),
        (0b0000_0000, "duplication"),
    ];
    for (premier, quoi) in cas {
        let brut = [premier, 0x00, 0x00];
        let (instruction, _) = lire(&brut).unwrap_or_else(|e| panic!("{quoi} : {e:?}"));
        let nom = match instruction {
            EncoderInstruction::InsertWithNameRef { .. } => "nom indexé",
            EncoderInstruction::InsertWithLiteralName { .. } => "nom écrit",
            EncoderInstruction::SetCapacity { .. } => "capacité",
            EncoderInstruction::Duplicate { .. } => "duplication",
        };
        assert_eq!(nom, quoi, "motif {premier:#010b}");
    }
}

/// **SANS TABLE, AUCUNE INSERTION N'EST LICITE** (§3.2.3). C'est ce qui ferme
/// d'un coup le blocage de compression, CRIME à la réception, et tout un étage
/// de code.
#[test]
fn sans_table_aucune_insertion_n_est_licite() {
    let insertions = [
        EncoderInstruction::InsertWithNameRef {
            index: 3,
            table: Table::Static,
            value: b"/a",
        },
        EncoderInstruction::InsertWithLiteralName {
            name: b"a",
            value: b"b",
        },
        EncoderInstruction::Duplicate { index: 0 },
    ];
    for instruction in insertions {
        let issue = check_encoder_instruction(instruction, 0).expect_err("sans table");
        assert_eq!(
            issue.reason(),
            Reason::DynamicTableRefused,
            "{instruction:?}"
        );
        assert_eq!(issue.code(), H3Error::QpackEncoderStreamError);
        // Avec une table, en revanche, elles passent.
        assert!(check_encoder_instruction(instruction, 4_096).is_ok());
    }
}

/// **ZÉRO EST LICITE, ET TOUT LE RESTE NE L'EST PAS QUAND ON ANNONCE ZÉRO**
/// (§3.2.3) : la capacité demandée ne peut pas dépasser ce qu'on a annoncé.
#[test]
fn une_capacite_au_dela_de_ce_qu_on_annonce_se_refuse() {
    assert!(check_encoder_instruction(EncoderInstruction::SetCapacity { capacity: 0 }, 0).is_ok());
    let issue = check_encoder_instruction(EncoderInstruction::SetCapacity { capacity: 1 }, 0)
        .expect_err("au-delà");
    assert_eq!(issue.reason(), Reason::DynamicTableRefused);

    // Et avec une table de quatre kibioctets, la borne est là.
    assert!(
        check_encoder_instruction(EncoderInstruction::SetCapacity { capacity: 4_096 }, 4_096)
            .is_ok()
    );
    assert!(
        check_encoder_instruction(EncoderInstruction::SetCapacity { capacity: 4_097 }, 4_096)
            .is_err()
    );
}

/// Une instruction d'encodeur mal formée se refuse.
#[test]
fn une_instruction_d_encodeur_mal_formee_se_refuse() {
    let issue = lire(&[]).expect_err("vide");
    assert_eq!(issue.reason(), Reason::Truncated);

    // Une valeur qui annonce plus que l'instruction ne porte.
    let issue = lire(&[0b1100_0011, 0x05, b'/']).expect_err("elle ment");
    assert_eq!(issue.reason(), Reason::BadEncoderInstruction);
    assert_eq!(issue.code(), H3Error::QpackEncoderStreamError);

    // Un nom écrit qui ment sur sa taille.
    let issue = lire(&[0b0100_0111, b'a']).expect_err("il ment");
    assert_eq!(issue.reason(), Reason::BadEncoderInstruction);

    // Une valeur qui manque derrière un nom écrit.
    let issue = lire(&[0b0100_0001, b'a']).expect_err("il manque la valeur");
    assert_eq!(issue.reason(), Reason::BadEncoderInstruction);

    // Des entiers qui annoncent une continuation sans la porter.
    for octets in [[0b1111_1111_u8].as_slice(), &[0b0011_1111], &[0b0001_1111]] {
        let issue = lire(octets).expect_err("tronqué");
        assert_eq!(issue.reason(), Reason::Truncated, "{octets:02x?}");
    }
}

/// **LES TROIS INSTRUCTIONS DE DÉCODEUR FONT UN ALLER-RETOUR** : ce qu'on écrit
/// se relit, et se relit comme la même chose.
#[test]
fn les_instructions_de_decodeur_font_un_aller_retour() {
    let cas = [
        DecoderInstruction::SectionAck { stream: 0 },
        DecoderInstruction::SectionAck { stream: 126 },
        DecoderInstruction::SectionAck { stream: 1_000_000 },
        DecoderInstruction::StreamCancellation { stream: 0 },
        DecoderInstruction::StreamCancellation { stream: 62 },
        DecoderInstruction::StreamCancellation { stream: 9_999 },
        DecoderInstruction::InsertCountIncrement { increment: 0 },
        DecoderInstruction::InsertCountIncrement { increment: 62 },
        DecoderInstruction::InsertCountIncrement { increment: 100_000 },
    ];
    for instruction in cas {
        let mut place = [0_u8; 16];
        let ecrits = write_decoder_instruction(instruction, &mut place).expect("écrivable");
        let (relue, lus) =
            read_decoder_instruction(place.get(..ecrits).expect("écrit")).expect("relisible");
        assert_eq!(relue, instruction, "un aller-retour a changé l'instruction");
        assert_eq!(lus, ecrits, "{instruction:?}");
    }
}

/// **LES TROIS MOTIFS DE §4.4 NE SE CONFONDENT PAS.**
#[test]
fn les_trois_motifs_de_decodeur_ne_se_confondent_pas() {
    let cas: [(u8, &str); 3] = [
        (0b1000_0000, "accusé"),
        (0b0100_0000, "annulation"),
        (0b0000_0000, "incrément"),
    ];
    for (premier, quoi) in cas {
        let (instruction, _) = read_decoder_instruction(&[premier]).expect("lisible");
        let nom = match instruction {
            DecoderInstruction::SectionAck { .. } => "accusé",
            DecoderInstruction::StreamCancellation { .. } => "annulation",
            DecoderInstruction::InsertCountIncrement { .. } => "incrément",
        };
        assert_eq!(nom, quoi, "motif {premier:#010b}");
    }
}

/// **LA BORNE EST CELLE DE LA REPRÉSENTATION, ET NON CELLE DU PROTOCOLE** : les
/// entiers à préfixe de RFC 7541 s'arrêtent à 2^32-1, un numéro de flux QUIC va
/// jusqu'à 2^62-1. On le dit plutôt que de tronquer.
#[test]
fn un_numero_hors_de_la_representation_se_dit() {
    let trop = u64::from(u32::MAX).saturating_add(1);
    for instruction in [
        DecoderInstruction::SectionAck { stream: trop },
        DecoderInstruction::StreamCancellation { stream: trop },
        DecoderInstruction::InsertCountIncrement { increment: trop },
    ] {
        let issue =
            write_decoder_instruction(instruction, &mut [0_u8; 16]).expect_err("hors borne");
        assert_eq!(
            issue.reason(),
            Reason::BadDecoderInstruction,
            "{instruction:?}"
        );
        assert_eq!(issue.code(), H3Error::QpackDecoderStreamError);
    }
}

/// Une instruction de décodeur tronquée, et un tampon qui ne suffit pas.
#[test]
fn une_instruction_de_decodeur_mal_formee_se_refuse() {
    let issue = read_decoder_instruction(&[]).expect_err("vide");
    assert_eq!(issue.reason(), Reason::Truncated);
    for octets in [[0b1111_1111_u8].as_slice(), &[0b0111_1111], &[0b0011_1111]] {
        let issue = read_decoder_instruction(octets).expect_err("tronquée");
        assert_eq!(issue.reason(), Reason::Truncated, "{octets:02x?}");
    }

    let issue =
        write_decoder_instruction(DecoderInstruction::SectionAck { stream: 1_000 }, &mut [])
            .expect_err("pas la place");
    assert_eq!(issue.reason(), Reason::BufferTooSmall);
    assert_eq!(issue.code(), H3Error::InternalError);
}
