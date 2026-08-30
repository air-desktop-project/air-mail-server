// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un code d'état a le droit d'être.

use super::StatusCode;
use crate::Error;

fn rendu(code: StatusCode) -> std::string::String {
    let mut sortie = [0_u8; StatusCode::OCTETS];
    let ecrit = code.write(&mut sortie).expect("écrivable");
    std::string::String::from_utf8(ecrit.to_vec()).expect("des chiffres")
}

/// Les trois chiffres s'écrivent, et se relisent à l'identique.
#[test]
fn les_codes_s_ecrivent_et_se_relisent() {
    for valeur in [100_u16, 200, 204, 304, 404, 500, 599] {
        let code = StatusCode::new(valeur).expect("valide");
        assert_eq!(code.value(), valeur);
        let texte = rendu(code);
        assert_eq!(texte.len(), 3, "{valeur}");
        assert_eq!(
            StatusCode::parse(texte.as_bytes()),
            Ok(code),
            "{valeur} relu"
        );
    }
    // Les constantes du produit valent ce qu'elles disent.
    assert_eq!(StatusCode::OK.value(), 200);
    assert_eq!(StatusCode::NOT_FOUND.value(), 404);
    assert_eq!(StatusCode::HEADER_FIELDS_TOO_LARGE.value(), 431);
}

/// **HORS DE `100..=599`, CE N'EST PAS UN CODE D'ÉTAT** : §15 n'en définit pas
/// d'autre, et un `042` ferait écrire trois chiffres qu'aucun client ne saurait
/// classer.
#[test]
fn ce_qui_n_est_pas_un_code_se_refuse() {
    for valeur in [0_u16, 1, 99, 600, 999, u16::MAX] {
        assert_eq!(
            StatusCode::new(valeur),
            Err(Error::MalformedFieldValue),
            "{valeur}"
        );
    }
}

/// **EXACTEMENT TROIS CHIFFRES** (§8.3.2) : `0200` se lirait sinon comme `200`
/// par ce serveur et comme une faute par le suivant.
#[test]
fn un_status_se_lit_sur_trois_chiffres_exactement() {
    for texte in [
        &b""[..],
        b"2",
        b"20",
        b"0200",
        b"2000",
        b"20x",
        b"x00",
        b"2 0",
        b" 200",
        b"200 ",
        b"+200",
        b"099",
    ] {
        assert_eq!(
            StatusCode::parse(texte),
            Err(Error::MalformedFieldValue),
            "{texte:?}"
        );
    }
}

/// **`204` ET `304` NE PORTENT JAMAIS DE CORPS**, ni les `1xx` : en écrire un
/// ferait lire ce corps comme le message suivant.
#[test]
fn ce_qui_ne_porte_pas_de_corps_le_dit() {
    for valeur in [100_u16, 101, 199, 204, 304] {
        let code = StatusCode::new(valeur).expect("valide");
        assert!(!code.allows_body(), "{valeur}");
    }
    for valeur in [200_u16, 201, 203, 205, 206, 301, 400, 404, 500] {
        let code = StatusCode::new(valeur).expect("valide");
        assert!(code.allows_body(), "{valeur}");
    }
}

/// La classe se lit, et sert à décider sans comparer dix valeurs.
#[test]
fn la_classe_se_lit() {
    assert_eq!(StatusCode::OK.class(), 2);
    assert_eq!(StatusCode::NOT_FOUND.class(), 4);
    assert_eq!(StatusCode::INTERNAL_SERVER_ERROR.class(), 5);
    // Les codes s'ordonnent, ce qui sert à choisir le pire d'un lot.
    assert!(StatusCode::BAD_REQUEST < StatusCode::INTERNAL_SERVER_ERROR);
    assert!(std::format!("{:?}", StatusCode::OK).contains("200"));
}

/// Un tampon trop court le dit.
#[test]
fn un_tampon_trop_court_le_dit() {
    for taille in 0..StatusCode::OCTETS {
        let mut petit = std::vec![0_u8; taille];
        assert_eq!(
            StatusCode::OK.write(&mut petit),
            Err(Error::BufferTooSmall { needed: 3 }),
            "{taille}"
        );
    }
}
