// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une méthode a le droit d'être.

use super::{CONNUES, Method};

/// Les sept se lisent, et se réécrivent à l'identique.
#[test]
fn les_methodes_servies_se_lisent_et_se_reecrivent() {
    for (nom, attendue) in CONNUES {
        assert_eq!(Method::parse(nom), Some(attendue), "{nom:?}");
        assert_eq!(attendue.as_bytes(), nom, "{nom:?}");
    }
}

/// **`CONNECT` ET `TRACE` SE REFUSENT**, et pour deux raisons différentes :
/// l'un demande un tunnel, l'autre est un miroir à jetons.
#[test]
fn ce_qu_on_ne_sert_pas_se_refuse() {
    for nom in [
        &b"CONNECT"[..],
        b"TRACE",
        // La casse compte (§9.1).
        b"get",
        b"Get",
        b"POSt",
        // Ce qui n'est pas une méthode du tout.
        b"",
        b"GET ",
        b" GET",
        b"BREW",
        b"GETGET",
    ] {
        assert_eq!(Method::parse(nom), None, "{nom:?}");
    }
}

/// **LA RÉPONSE À `HEAD` NE PORTE JAMAIS DE CORPS** (§9.3.2), quel que soit ce
/// que `content-length` annonce. En écrire un ferait lire ce corps comme la
/// réponse suivante.
#[test]
fn head_seule_ne_porte_pas_de_corps() {
    assert!(!Method::Head.allows_response_body());
    for methode in [
        Method::Get,
        Method::Post,
        Method::Put,
        Method::Delete,
        Method::Patch,
        Method::Options,
    ] {
        assert!(methode.allows_response_body(), "{methode:?}");
    }
}

/// Ce qu'on lit se montre et se compare.
#[test]
fn une_methode_se_montre() {
    assert_eq!(Method::Get, Method::Get);
    assert_ne!(Method::Get, Method::Post);
    assert!(std::format!("{:?}", Method::Patch).contains("Patch"));
}
