// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une ligne de champ a le droit d'être.

use super::{FieldLine, Table, read_field_line};
use crate::error::{H3Error, Reason};

/// Lit une ligne dans un tampon neuf, et rend ce qu'elle dit.
fn lire(octets: &[u8]) -> Result<(FieldLine<'static>, usize), crate::error::Error> {
    // Le tampon vit aussi longtemps que le test : on le fuit exprès, pour que
    // la ligne rendue puisse être comparée sans emprunt qui traîne.
    let place: &'static mut [u8] = std::boxed::Box::leak(std::boxed::Box::new([0_u8; 256]));
    let decode = read_field_line(octets, place)?;
    Ok((decode.line, decode.read))
}

/// **§4.5.2 : `1Txxxxxx`** — nom et valeur d'un coup, et le bit `T` dit de
/// quelle table.
#[test]
fn un_index_designe_une_table_ou_l_autre() {
    // `1` + `T=1` (statique) + index 17 : `0b1101_0001`.
    let (ligne, lus) = lire(&[0b1101_0001]).expect("lisible");
    assert_eq!(
        ligne,
        FieldLine::Indexed {
            index: 17,
            table: Table::Static
        }
    );
    assert_eq!(lus, 1);

    // `1` + `T=0` (dynamique) + index 3 : `0b1000_0011`.
    let (ligne, _) = lire(&[0b1000_0011]).expect("lisible");
    assert_eq!(
        ligne,
        FieldLine::Indexed {
            index: 3,
            table: Table::Dynamic
        }
    );

    // Un index qui déborde le préfixe se poursuit sur l'octet suivant.
    let (ligne, lus) = lire(&[0b1111_1111, 0x0a]).expect("lisible");
    assert_eq!(
        ligne,
        FieldLine::Indexed {
            index: 73,
            table: Table::Static
        }
    );
    assert_eq!(lus, 2);
}

/// **§4.5.3 : `0001xxxx`** — un index compté APRÈS le rang de la section. Sans
/// ce mode, un encodeur qui insère pendant qu'il écrit devrait refaire son
/// préfixe après coup.
#[test]
fn un_index_apres_le_rang_se_lit() {
    let (ligne, lus) = lire(&[0b0001_0101]).expect("lisible");
    assert_eq!(ligne, FieldLine::IndexedPostBase { index: 5 });
    assert_eq!(lus, 1);
}

/// **§4.5.4 : `01NTxxxx`** — le nom vient d'une table, la valeur est écrite.
#[test]
fn un_nom_indexe_avec_une_valeur_ecrite() {
    // `01` + `N=0` + `T=1` (statique) + index 3, puis « /a » en clair.
    let (ligne, lus) = lire(&[0b0101_0011, 0x02, b'/', b'a']).expect("lisible");
    assert_eq!(
        ligne,
        FieldLine::LiteralWithName {
            index: 3,
            table: Table::Static,
            value: b"/a",
            never: false,
        }
    );
    assert_eq!(lus, 4);

    // **LE BIT `N` N'EST PAS UNE SUGGESTION** : le perdre au passage, c'est
    // indexer le secret chez l'intermédiaire suivant.
    let (ligne, _) = lire(&[0b0111_0011, 0x02, b'/', b'a']).expect("lisible");
    assert_eq!(
        ligne,
        FieldLine::LiteralWithName {
            index: 3,
            table: Table::Static,
            value: b"/a",
            never: true,
        }
    );

    // Et `T=0` désigne la table dynamique.
    let (ligne, _) = lire(&[0b0100_0011, 0x00]).expect("lisible");
    assert_eq!(
        ligne,
        FieldLine::LiteralWithName {
            index: 3,
            table: Table::Dynamic,
            value: b"",
            never: false,
        }
    );
}

/// **§4.5.5 : `0000Nxxx`** — le nom vient de la table dynamique, après le rang.
#[test]
fn un_nom_apres_le_rang_avec_une_valeur_ecrite() {
    let (ligne, lus) = lire(&[0b0000_0010, 0x01, b'x']).expect("lisible");
    assert_eq!(
        ligne,
        FieldLine::LiteralWithPostBaseName {
            index: 2,
            value: b"x",
            never: false,
        }
    );
    assert_eq!(lus, 3);

    // Avec le bit `N`.
    let (ligne, _) = lire(&[0b0000_1010, 0x01, b'x']).expect("lisible");
    assert_eq!(
        ligne,
        FieldLine::LiteralWithPostBaseName {
            index: 2,
            value: b"x",
            never: true,
        }
    );
}

/// **§4.5.6 : `001NHxxx`** — le nom ET la valeur sont écrits, et le fanion de
/// Huffman du NOM vit dans ce premier octet. Lire la longueur avec un préfixe de
/// sept bits, comme le ferait une chaîne ordinaire, la lirait de travers.
#[test]
fn un_nom_et_une_valeur_ecrits_tous_les_deux() {
    // `001` + `N=0` + `H=0` + longueur 3 : `0b0010_0011`, puis « abc », puis
    // une valeur de deux octets.
    let brut = [0b0010_0011, b'a', b'b', b'c', 0x02, b'x', b'y'];
    let (ligne, lus) = lire(&brut).expect("lisible");
    assert_eq!(
        ligne,
        FieldLine::Literal {
            name: b"abc",
            value: b"xy",
            never: false,
        }
    );
    assert_eq!(lus, brut.len());

    // Avec le bit `N`.
    let brut = [0b0011_0011, b'a', b'b', b'c', 0x00];
    let (ligne, _) = lire(&brut).expect("lisible");
    assert_eq!(
        ligne,
        FieldLine::Literal {
            name: b"abc",
            value: b"",
            never: true,
        }
    );
}

/// Un nom comprimé par Huffman se lit aussi, et c'est le bit `H` du premier
/// octet qui le dit.
#[test]
fn un_nom_comprime_se_lit() {
    // « :path » comprimé par Huffman fait quatre octets.
    let mut serre = [0_u8; 16];
    let ecrits = ams_field_codec::encode_huffman(b":path", &mut serre).expect("comprimable");
    let mut brut = std::vec::Vec::new();
    // `001` + `N=0` + `H=1` + la longueur comprimée sur trois bits.
    brut.push(0b0010_1000 | u8::try_from(ecrits).expect("court"));
    brut.extend_from_slice(serre.get(..ecrits).expect("écrit"));
    brut.push(0x00);
    let (ligne, lus) = lire(&brut).expect("lisible");
    assert_eq!(
        ligne,
        FieldLine::Literal {
            name: b":path",
            value: b"",
            never: false,
        }
    );
    assert_eq!(lus, brut.len());
}

/// **LE CLASSEMENT SE FAIT DU PLUS LONG MOTIF AU PLUS COURT** : les cinq motifs
/// se recouvrent, et tester le plus court d'abord ferait lire une représentation
/// pour une autre.
#[test]
fn les_cinq_motifs_ne_se_confondent_pas() {
    let cas: [(u8, &str); 5] = [
        (0b1000_0000, "indexé"),
        (0b0100_0000, "nom indexé"),
        (0b0010_0000, "littéral"),
        (0b0001_0000, "indexé après le rang"),
        (0b0000_0000, "nom après le rang"),
    ];
    let mut vus = std::vec::Vec::new();
    for (premier, quoi) in cas {
        let brut = [premier, 0x00, 0x00];
        let (ligne, _) = lire(&brut).unwrap_or_else(|e| panic!("{quoi} : {e:?}"));
        let nom = match ligne {
            FieldLine::Indexed { .. } => "indexé",
            FieldLine::LiteralWithName { .. } => "nom indexé",
            FieldLine::Literal { .. } => "littéral",
            FieldLine::IndexedPostBase { .. } => "indexé après le rang",
            FieldLine::LiteralWithPostBaseName { .. } => "nom après le rang",
        };
        assert_eq!(nom, quoi, "motif {premier:#010b}");
        vus.push(nom);
    }
    assert_eq!(vus.len(), 5, "les cinq motifs sont distincts");
}

/// Une ligne tronquée, et un tampon qui ne suffit pas.
#[test]
fn une_ligne_mal_formee_se_refuse() {
    // Vide.
    let issue = lire(&[]).expect_err("vide");
    assert_eq!(issue.reason(), Reason::Truncated);
    assert_eq!(issue.code(), H3Error::FrameError);

    // Une valeur qui annonce plus que la ligne ne porte.
    let issue = lire(&[0b0101_0011, 0x05, b'/']).expect_err("elle ment");
    assert_eq!(issue.reason(), Reason::BadFieldLine);
    assert_eq!(issue.code(), H3Error::QpackDecompressionFailed);

    // Un nom littéral qui annonce plus que la ligne ne porte.
    let issue = lire(&[0b0010_0111, b'a']).expect_err("il ment");
    assert_eq!(issue.reason(), Reason::BadFieldLine);

    // Un index qui annonce une continuation sans la porter.
    let issue = lire(&[0b1111_1111]).expect_err("tronqué");
    assert_eq!(issue.reason(), Reason::Truncated);
    let issue = lire(&[0b0101_1111]).expect_err("tronqué");
    assert_eq!(issue.reason(), Reason::Truncated);
    let issue = lire(&[0b0001_1111]).expect_err("tronqué");
    assert_eq!(issue.reason(), Reason::Truncated);
    let issue = lire(&[0b0000_0111]).expect_err("tronqué");
    assert_eq!(issue.reason(), Reason::Truncated);
    let issue = lire(&[0b0010_0111]).expect_err("tronqué");
    assert_eq!(issue.reason(), Reason::BadFieldLine);
}

/// **UN SEUL TAMPON POUR TOUTE LA SECTION** : le décodeur rend ce qu'il n'a pas
/// employé, sans quoi chaque ligne voudrait le sien.
#[test]
fn un_seul_tampon_sert_a_toute_la_section() {
    let brut = [
        0b0010_0011,
        b'u',
        b'n',
        b'e',
        0x02,
        b'x',
        b'y',
        0b0010_0100,
        b'd',
        b'e',
        b'u',
        b'x',
        0x01,
        b'z',
    ];
    let mut place = [0_u8; 64];
    let mut libre = place.as_mut_slice();
    let mut reste = brut.as_slice();
    let mut recoltees = std::vec::Vec::new();
    while !reste.is_empty() {
        let decode = read_field_line(reste, libre).expect("lisible");
        if let FieldLine::Literal { name, value, .. } = decode.line {
            recoltees.push((name.to_vec(), value.to_vec()));
        }
        reste = reste.get(decode.read..).unwrap_or_default();
        libre = decode.rest;
    }
    assert_eq!(recoltees.len(), 2);
    assert_eq!(recoltees[0], (b"une".to_vec(), b"xy".to_vec()));
    assert_eq!(recoltees[1], (b"deux".to_vec(), b"z".to_vec()));
}

/// Le tampon de sortie ne suffit pas.
#[test]
fn le_decodage_veut_de_la_place() {
    // Le nom fait trois octets, la valeur deux : cinq suffisent PILE, et
    // quatre ne suffisent pas. La borne exacte est ce qui compte — un décodeur
    // qui demanderait davantage refuserait des sections parfaitement lisibles.
    let brut = [0b0010_0011, b'a', b'b', b'c', 0x02, b'x', b'y'];
    for taille in 0..5_usize {
        let mut petit = [0_u8; 8];
        let issue = read_field_line(&brut, petit.get_mut(..taille).expect("court"))
            .expect_err("pas la place");
        assert_eq!(issue.reason(), Reason::BadFieldLine, "{taille}");
    }
    let mut juste = [0_u8; 5];
    assert!(
        read_field_line(&brut, &mut juste).is_ok(),
        "cinq octets suffisent, et pas un de plus"
    );
}

/// **UNE VALEUR ILLISIBLE DANS CHAQUE REPRÉSENTATION QUI EN PORTE UNE.** Une
/// seule oubliée laisserait une section se lire à moitié.
#[test]
fn chaque_representation_refuse_une_valeur_illisible() {
    // §4.5.4 : nom indexé, valeur qui annonce cinq octets et n'en porte qu'un.
    let issue = lire(&[0b0101_0011, 0x05, b'/']).expect_err("elle ment");
    assert_eq!(issue.reason(), Reason::BadFieldLine);

    // §4.5.5 : nom après le rang, même mensonge.
    let issue = lire(&[0b0000_0010, 0x05, b'/']).expect_err("elle ment");
    assert_eq!(issue.reason(), Reason::BadFieldLine);

    // §4.5.6 : nom littéral, valeur qui ment.
    let issue = lire(&[0b0010_0001, b'a', 0x05, b'/']).expect_err("elle ment");
    assert_eq!(issue.reason(), Reason::BadFieldLine);
}

/// **UN NOM COMPRIMÉ PAR UN CODE QU'AUCUN SYMBOLE N'EMPLOIE** se refuse : la
/// compression du NOM passe par un chemin à part, et il faut l'éprouver
/// séparément de celle des valeurs.
#[test]
fn un_nom_comprime_illisible_se_refuse() {
    // `001` + `H=1` + longueur 2, puis deux octets tout à un : c'est le code
    // `EOS`, que §5.2 de RFC 7541 interdit dans une chaîne.
    let issue = lire(&[0b0010_1010, 0xff, 0xff]).expect_err("un code impossible");
    assert_eq!(issue.reason(), Reason::BadFieldLine);
    assert_eq!(issue.code(), H3Error::QpackDecompressionFailed);
}
