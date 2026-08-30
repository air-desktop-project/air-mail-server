// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que la table statique de QPACK doit être.

use super::{STATIQUE, STATIQUE_LEN, entree_statique};

/// **QUATRE-VINGT-DIX-NEUF ENTRÉES**, et l'appendice A n'en donne pas d'autres.
#[test]
fn la_table_a_la_taille_que_la_rfc_lui_donne() {
    assert_eq!(STATIQUE_LEN, 99);
    assert_eq!(STATIQUE.len(), 99);
}

/// **ELLE COMMENCE À ZÉRO**, là où celle de HPACK commençait à un. Un décodeur
/// qui garderait l'habitude de HPACK décalerait toute la table d'un rang.
#[test]
fn elle_commence_a_zero() {
    assert_eq!(
        entree_statique(0),
        Some((b":authority".as_slice(), b"".as_slice()))
    );
    assert_eq!(
        entree_statique(1),
        Some((b":path".as_slice(), b"/".as_slice()))
    );
    // La dernière est à quatre-vingt-dix-huit, et il n'y a rien après.
    assert_eq!(
        entree_statique(98),
        Some((b"x-frame-options".as_slice(), b"sameorigin".as_slice()))
    );
    assert_eq!(entree_statique(99), None);
    assert_eq!(entree_statique(u64::MAX), None);
}

/// Quelques entrées prises à la lettre dans l'appendice A, dont celles que la
/// mise en page de la RFC coupe en deux — c'est exactement là qu'une
/// transcription à la main se serait trompée.
#[test]
fn les_entrees_coupees_par_la_mise_en_page_sont_entieres() {
    let cas: [(u64, &[u8], &[u8]); 10] = [
        (15, b":method", b"CONNECT"),
        (17, b":method", b"GET"),
        (30, b"accept", b"application/dns-message"),
        (41, b"cache-control", b"public, max-age=31536000"),
        (45, b"content-type", b"application/javascript"),
        (47, b"content-type", b"application/x-www-form-urlencoded"),
        (52, b"content-type", b"text/html; charset=utf-8"),
        (54, b"content-type", b"text/plain;charset=utf-8"),
        (
            58,
            b"strict-transport-security",
            b"max-age=31536000; includesubdomains; preload",
        ),
        (
            85,
            b"content-security-policy",
            b"script-src 'none'; object-src 'none'; base-uri 'none'",
        ),
    ];
    for (index, nom, valeur) in cas {
        assert_eq!(entree_statique(index), Some((nom, valeur)), "index {index}");
    }
}

/// **LES ENTRÉES SE RÉPÈTENT, ET CE N'EST PAS UNE ERREUR** : l'appendice A le
/// dit. Un décodeur qui s'attendrait à des noms uniques se tromperait.
#[test]
fn les_noms_se_repetent_et_c_est_normal() {
    let mut types = 0_usize;
    let mut statuts = 0_usize;
    for (nom, _) in STATIQUE {
        if nom == b"content-type" {
            types = types.saturating_add(1);
        }
        if nom == b":status" {
            statuts = statuts.saturating_add(1);
        }
    }
    assert!(types > 1, "content-type devrait apparaître plusieurs fois");
    assert!(statuts > 1, ":status devrait apparaître plusieurs fois");
}

/// **AUCUN NOM N'EST VIDE**, et tous sont en minuscules : §4.1.1 de RFC 9114 le
/// veut, et une entrée fautive ferait écrire un champ qu'un pair refuserait.
#[test]
fn chaque_nom_est_recevable() {
    for (rang, (nom, valeur)) in STATIQUE.iter().enumerate() {
        assert!(!nom.is_empty(), "l'entrée {rang} n'a pas de nom");
        for octet in nom.iter() {
            assert!(
                !octet.is_ascii_uppercase(),
                "l'entrée {rang} porte une majuscule"
            );
        }
        // Une valeur peut être vide — c'est le cas des noms qu'on emploie avec
        // une valeur littérale — mais jamais porter de fin de ligne.
        for octet in valeur.iter() {
            assert!(
                *octet != b'\r' && *octet != b'\n' && *octet != 0,
                "l'entrée {rang} porte un octet interdit"
            );
        }
    }
}

/// **LA TABLE DE QPACK N'EST PAS CELLE DE HPACK.** Elles se ressemblent assez
/// pour qu'on les confonde, et diffèrent assez pour que la confusion soit
/// indétectable : un index qui désigne une chose dans l'une en désigne une autre
/// dans l'autre.
#[test]
fn elle_n_est_pas_celle_de_hpack() {
    // Dans HPACK, l'index 2 est `:method GET` ; ici, c'est `age 0`.
    assert_eq!(
        entree_statique(2),
        Some((b"age".as_slice(), b"0".as_slice()))
    );
    // Dans HPACK, l'index 8 est `:status 200` ; ici, c'est `if-modified-since`.
    assert_eq!(
        entree_statique(8),
        Some((b"if-modified-since".as_slice(), b"".as_slice()))
    );
}
