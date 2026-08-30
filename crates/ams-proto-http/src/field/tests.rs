// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un champ a le droit d'être.

use super::{
    FieldKind, field_kind, field_name_is_valid, field_value_is_valid, is_connection_specific,
};

/// Les noms ordinaires passent.
#[test]
fn les_noms_ordinaires_passent() {
    for nom in [
        &b"content-length"[..],
        b"content-type",
        b"authorization",
        b"x-chose",
        b"a",
        b"0",
        b"!#$%&'*+-.^_`|~",
        b"if-none-match",
    ] {
        assert!(field_name_is_valid(nom), "{nom:?}");
        assert_eq!(field_kind(nom), FieldKind::Ordinary, "{nom:?}");
    }
}

/// **UN NOM EN MAJUSCULES EST MAL FORMÉ, PAS CORRIGÉ** (§8.2.1). Le normaliser
/// laisserait passer deux écritures du même nom là où un intermédiaire n'en
/// accepte qu'une — et deux analyseurs qui ne s'accordent pas, c'est la faille.
#[test]
fn un_nom_en_majuscules_est_mal_forme() {
    for nom in [
        &b"Content-Length"[..],
        b"CONTENT-LENGTH",
        b"contentLength",
        b"A",
    ] {
        assert!(!field_name_is_valid(nom), "{nom:?}");
        assert_eq!(field_kind(nom), FieldKind::Invalid, "{nom:?}");
    }
}

/// Ce qui n'est pas un `tchar` ne passe pas — l'espace, le `:` intérieur, les
/// séparateurs, et les octets de structure.
#[test]
fn ce_qui_n_est_pas_un_jeton_se_refuse() {
    for nom in [
        &b""[..],
        b"content length",
        b"content\tlength",
        b"content:length",
        b"content;length",
        b"content,length",
        b"content/length",
        b"content(length)",
        b"content\"length\"",
        b"content\rlength",
        b"content\nlength",
        b"content\0length",
        b"cl\x80",
        b"\x7f",
    ] {
        assert!(!field_name_is_valid(nom), "{nom:?}");
    }
}

/// Les valeurs ordinaires passent, la vide comprise.
#[test]
fn les_valeurs_ordinaires_passent() {
    for valeur in [
        &b""[..],
        b"0",
        b"application/json",
        b"Bearer eyJhbGci",
        b"a b c",
        b"a\tb",
        // `obs-text` est admis par §5.5 : le refuser casserait des valeurs que
        // d'autres serveurs acceptent.
        b"caf\xc3\xa9",
        b"\x80\xff",
    ] {
        assert!(field_value_is_valid(valeur), "{valeur:?}");
    }
}

/// **`NUL`, `CR` ET `LF` SONT LES OCTETS QUI FABRIQUENT UNE LIGNE**, et c'est
/// pourquoi ils sont interdits. Un intermédiaire qui réécrirait la requête en
/// HTTP/1.1 en ferait une coupure, et la moitié de la valeur deviendrait une
/// requête que personne n'a envoyée.
#[test]
fn les_octets_de_structure_ne_passent_pas_dans_une_valeur() {
    for valeur in [
        &b"a\rb"[..],
        b"a\nb",
        b"a\r\nb",
        b"a\0b",
        b"\r",
        b"\n",
        b"\0",
        b"fin\r\nx-injecte: oui",
    ] {
        assert!(!field_value_is_valid(valeur), "{valeur:?}");
    }
}

/// **NI ESPACE NI TABULATION AU BORD** : c'est ainsi que s'écrivait le
/// repliement d'en-tête d'HTTP/1.1, qu'un intermédiaire reconstituerait.
#[test]
fn une_espace_au_bord_ne_passe_pas() {
    for valeur in [&b" a"[..], b"a ", b"\ta", b"a\t", b" ", b"\t", b"  a  "] {
        assert!(!field_value_is_valid(valeur), "{valeur:?}");
    }
    // Au MILIEU, elles passent : c'est du texte.
    assert!(field_value_is_valid(b"a b"));
    assert!(field_value_is_valid(b"a\tb"));
}

/// Les cinq champs de §8.2.2 se reconnaissent, et rien d'autre.
#[test]
fn les_champs_propres_a_la_connexion_se_reconnaissent() {
    for nom in [
        &b"connection"[..],
        b"proxy-connection",
        b"keep-alive",
        b"transfer-encoding",
        b"upgrade",
    ] {
        assert!(is_connection_specific(nom), "{nom:?}");
    }
    for nom in [
        &b"content-length"[..],
        b"te",
        b"connexion",
        b"connection2",
        b"",
    ] {
        assert!(!is_connection_specific(nom), "{nom:?}");
    }
}

/// **LE `:` SÉPARE LES DEUX MONDES**, et un pseudo-en-tête inconnu reste un
/// pseudo-en-tête : le prendre pour un champ mal formé rendrait la mauvaise
/// faute.
#[test]
fn le_deux_points_separe_les_deux_mondes() {
    for nom in [&b":method"[..], b":path", b":chose", b":a"] {
        assert_eq!(field_kind(nom), FieldKind::Pseudo, "{nom:?}");
    }
    for nom in [&b":"[..], b"::method", b":Method", b":met hod"] {
        assert_eq!(field_kind(nom), FieldKind::Invalid, "{nom:?}");
    }
    assert_eq!(field_kind(b""), FieldKind::Invalid);
    assert!(std::format!("{:?}", FieldKind::Pseudo).contains("Pseudo"));
}
