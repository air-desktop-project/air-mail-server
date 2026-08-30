// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un bloc écrit contient — et ce qu'il ne contient jamais.

use super::{encode_field, encode_status};
use crate::error::Cause;
use crate::hpack::Decoder;

/// Écrit un champ, puis le relit avec un décodeur neuf.
fn aller_retour(nom: &[u8], valeur: &[u8]) -> (usize, std::vec::Vec<u8>, std::vec::Vec<u8>) {
    let mut ecrit = [0_u8; 1024];
    let ecrits = encode_field(nom, valeur, &mut ecrit).expect("écrivable");
    let mut decodeur = Decoder::new();
    decodeur.begin_block();
    let mut place = [0_u8; 1024];
    let decode = decodeur
        .next(ecrit.get(..ecrits).unwrap_or_default(), &mut place)
        .expect("relisible")
        .expect("un champ");
    let champ = decode.field;
    assert_eq!(decode.read, ecrits, "on relit exactement ce qu'on a écrit");
    // **LA TABLE RESTE VIDE CHEZ LE LECTEUR AUSSI** : on n'indexe jamais.
    assert!(
        decodeur.table().is_empty(),
        "un champ écrit ne doit pas entrer en table"
    );
    (ecrits, champ.name.to_vec(), champ.value.to_vec())
}

/// **CE QU'ON ÉCRIT SE RELIT**, sur les trois écritures.
#[test]
fn ce_qu_on_ecrit_se_relit() {
    for (nom, valeur) in [
        // Nom ET valeur dans la table statique.
        (&b":status"[..], &b"200"[..]),
        (b":method", b"GET"),
        (b":scheme", b"https"),
        // Nom seul dans la table.
        (b":status", b"418"),
        (b"content-type", b"application/json"),
        (b"etag", b"\"abc\""),
        // Ni l'un ni l'autre.
        (b"x-chose", b"oui"),
        (b"x-vide", b""),
        // Des octets quelconques.
        (b"x-brut", b"\x00\x01\xfe\xff"),
    ] {
        let (_, relu_nom, relu_valeur) = aller_retour(nom, valeur);
        assert_eq!(relu_nom, nom, "{nom:?}");
        assert_eq!(relu_valeur, valeur, "{nom:?}");
    }
}

/// **LA TABLE STATIQUE SERT, ET ELLE SEULE** : `:status 200` tient en un octet.
#[test]
fn la_table_statique_raccourcit_ce_qu_elle_peut() {
    let (un_octet, _, _) = aller_retour(b":status", b"200");
    assert_eq!(un_octet, 1, "l'index suffit");

    // Nom connu, valeur inconnue : un octet d'index, puis la valeur écrite en
    // clair — Huffman n'abrège pas `418`, dont deux chiffres coûtent six bits.
    let (avec_nom, _, _) = aller_retour(b":status", b"418");
    assert_eq!(avec_nom, 5, "index du nom, longueur, trois chiffres");

    // Rien de connu : les deux littéraux.
    let (tout, _, _) = aller_retour(b"x-chose", b"oui");
    assert!(tout > avec_nom, "les deux littéraux coûtent plus");
}

/// **RIEN N'EST JAMAIS INDEXÉ**, et c'est ce qui ferme CRIME et BREACH : la
/// taille du bloc ne dit rien d'un secret qu'il porterait.
#[test]
fn rien_n_est_jamais_indexe() {
    let mut ecrit = [0_u8; 1024];
    let mut decodeur = Decoder::new();
    let mut place = [0_u8; 1024];
    // Cent champs, dont un « secret » répété : la table doit rester vide.
    for tour in 0..100_u32 {
        let valeur = std::format!("secret-{tour}");
        let ecrits =
            encode_field(b"authorization", valeur.as_bytes(), &mut ecrit).expect("écrivable");
        decodeur.begin_block();
        decodeur
            .next(ecrit.get(..ecrits).unwrap_or_default(), &mut place)
            .expect("relisible")
            .expect("un champ");
        assert!(decodeur.table().is_empty(), "tour {tour}");
    }
    assert_eq!(decodeur.table().size(), 0);
}

/// **LA PREMIÈRE ENTRÉE DU NOM, PAS N'IMPORTE LAQUELLE** : `:status` en a huit,
/// et un choix stable rend deux encodages du même en-tête identiques.
#[test]
fn le_choix_de_l_index_est_stable() {
    let mut premier = [0_u8; 64];
    let mut second = [0_u8; 64];
    let a = encode_field(b":status", b"418", &mut premier).expect("écrivable");
    let b = encode_field(b":status", b"418", &mut second).expect("écrivable");
    assert_eq!(a, b);
    assert_eq!(premier.get(..a), second.get(..b));
    // `:status` commence à l'index huit dans la table statique.
    assert_eq!(premier.first(), Some(&0x08));
}

/// Un `:status` s'écrit depuis son nombre, et se refuse hors de la plage.
#[test]
fn un_status_s_ecrit_depuis_son_nombre() {
    let mut ecrit = [0_u8; 64];
    let ecrits = encode_status(200, &mut ecrit).expect("écrivable");
    assert_eq!(ecrits, 1, "l'index de `:status 200`");

    let ecrits = encode_status(418, &mut ecrit).expect("écrivable");
    assert_eq!(ecrits, 5);

    for hors in [0_u16, 99, 600, u16::MAX] {
        let issue = encode_status(hors, &mut ecrit).expect_err("refusé");
        assert_eq!(issue.cause(), Cause::BufferTooSmall, "{hors}");
    }
}

/// Un tampon trop court le dit, sur chacun des trois chemins.
#[test]
fn un_tampon_trop_court_le_dit() {
    for (nom, valeur) in [
        (&b":status"[..], &b"200"[..]),
        (b":status", b"418"),
        (b"x-chose", b"oui"),
    ] {
        // Ce que le champ occupe, mesuré plutôt que deviné : la compression de
        // Huffman ne s'applique que là où elle abrège, et le compter de tête est
        // le meilleur moyen de se tromper.
        let mut assez = [0_u8; 64];
        let tenu = encode_field(nom, valeur, &mut assez).expect("écrivable");
        for taille in 0..tenu {
            let mut petit = std::vec![0_u8; taille];
            let issue = encode_field(nom, valeur, &mut petit).expect_err("refusé");
            assert_eq!(issue.cause(), Cause::BufferTooSmall, "{nom:?} {taille}");
        }
        let mut juste = std::vec![0_u8; tenu];
        assert_eq!(encode_field(nom, valeur, &mut juste), Ok(tenu), "{nom:?}");
    }
    // Et `encode_status` remonte la même faute.
    let mut petit = [0_u8; 0];
    assert_eq!(
        encode_status(200, &mut petit).expect_err("refusé").cause(),
        Cause::BufferTooSmall
    );
}
