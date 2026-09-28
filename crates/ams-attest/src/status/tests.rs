// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::read_status_list;
use crate::Refusal;
use std::vec::Vec;

fn lire(json: &[u8]) -> Result<Vec<u128>, Refusal> {
    let mut vus = Vec::new();
    let combien = read_status_list(json, &mut |serie| vus.push(serie))?;
    assert_eq!(combien, vus.len());
    Ok(vus)
}

/// **LA VRAIE LISTE SE LIT ENTIÈRE** — celle que Google publiait le
/// 2026-09-28 : 1 757 entrées, toutes révoquées.
#[test]
fn la_liste_de_google_se_lit() {
    let vus = lire(include_bytes!("../vecteurs/google/status-2026-09-28.json")).expect("lisible");
    assert_eq!(vus.len(), 1757);
    // Une entrée décimale-d'apparence, une de trente-deux chiffres.
    assert!(vus.contains(&0x668_1152_6592_0522_5093));
    assert!(vus.contains(&0xc357_47a0_8447_0c31_35ae_efe2_b8d4_0cd6));
}

/// **L'EXEMPLE DE GOOGLE, ET SON ENTRÉE SUSPENDUE** : toute entrée compte.
#[test]
fn une_entree_suspendue_compte_aussi() {
    let vus = lire(include_bytes!("../vecteurs/google/status-exemple.json")).expect("lisible");
    assert_eq!(vus.len(), 5);
    assert!(vus.contains(&0xcc66_e9a9_3713_b6e6_43b2_6c15_8797_86f7));
}

#[test]
fn les_formes_admises_se_lisent() {
    assert_eq!(lire(b"{}"), Ok(Vec::new()));
    assert_eq!(lire(br#" { "entries" : { } } "#), Ok(Vec::new()));
    // Des champs inconnus, de toutes les formes, autour et dedans.
    let json = br#"{"avant":[1,-2.5e3,true,false,null,"x\"y",[],{}],
        "entries":{"a1":{"status":"REVOKED","expires":"2030-01-01","n":[{"p":1}]},
                   "ffffffffffffffffffffffffffffffff":{}},
        "apres":{}}"#;
    assert_eq!(lire(json), Ok(std::vec![0xa1, u128::MAX]));
}

/// **UNE LISTE MAL FORMÉE SE REFUSE ENTIÈRE** — y compris un numéro qui n'est
/// pas de l'hexadécimal minuscule sans zéro de tête, ou trop long.
#[test]
fn une_liste_mal_formee_se_refuse_entiere() {
    for faux in [
        &b""[..],
        b"[]",
        b"{",
        b"{\"entries\"}",
        b"{\"entries\":{}",
        b"{\"entries\":{} x",
        b"{\"entries\":{}}x",
        b"{\"entries\":{},}",
        b"{\"entries\":{\"a1\":{}\"b2\":{}}}",
        b"{\"entries\":[]}",
        b"{\"entries\":{\"A1\":{}}}",
        b"{\"entries\":{\"0a\":{}}}",
        b"{\"entries\":{\"\":{}}}",
        b"{\"entries\":{\"g1\":{}}}",
        b"{\"entries\":{\"1ffffffffffffffffffffffffffffffff\":{}}}",
        b"{\"entries\":{\"a1\" {}}}",
        b"{\"entries\":{\"a1\":}}",
        b"{\"entries\":{\"a1\":{\"s\":\"x}}}",
        b"{\"entries\":{\"a1\":{\"s\":\"\x01\"}}}",
        b"{\"entries\":{\"a1\":{\"s\" 1}}}",
        b"{\"entries\":{\"a1\":{\"s\":1 \"t\":2}}}",
        b"{\"entries\":{\"a1\":[1 2]}}",
        b"{\"entries\":{\"a1\":[1,]}}",
        b"{\"entries\":{\"a1\":@}}",
        b"{\"x\":",
        b"{\"x\":[",
        b"{\"x\":{",
        b"{\"x\":[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]}",
        b"{\"x\" 1}",
        b"{\"x\":1 \"y\":2}",
        b"{\"x\":1",
        b"{x:1}",
        // Tronquées là où l'on attend une fermeture, ou un nom.
        b"{\"entries\":{",
        b"{\"entries\":{\"a1\":{}",
        b"{\"entries\":{1:{}}}",
        b"{\"x\":{\"a\":1",
        b"{\"x\":{1:2}}",
        b"{\"x\":[1",
    ] {
        assert_eq!(
            lire(faux),
            Err(Refusal::Malformed),
            "{}",
            std::string::String::from_utf8_lossy(faux)
        );
    }
    // Seize niveaux passent ; dix-huit, non.
    let profond = std::format!("{{\"x\":{}1{}}}", "[".repeat(16), "]".repeat(16));
    assert!(lire(profond.as_bytes()).is_ok());
}
