// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un document d'erreur dit, et ce qu'il ne dit pas.

use std::string::{String, ToString};

use super::{JSON_MEDIA_TYPE, PROBLEM_MEDIA_TYPE, problem};
use crate::error::Reason;

/// Toutes les raisons, pour que chaque essai les parcoure toutes.
const TOUTES: [Reason; 9] = [
    Reason::BadPath,
    Reason::PathTooLong,
    Reason::NoSuchResource,
    Reason::MethodNotAllowed,
    Reason::Forbidden,
    Reason::BadToken,
    Reason::TokenExpired,
    Reason::BadKey,
    Reason::BufferTooSmall,
];

/// Rend le document écrit pour cette faute.
fn document(reason: Reason) -> String {
    let mut place = [0_u8; 256];
    let ecrit = problem(reason, &mut place).expect("écrivable");
    core::str::from_utf8(ecrit).expect("de l'UTF-8").to_string()
}

/// Un document d'erreur porte les trois membres de §3.1 de RFC 9457.
#[test]
fn le_document_porte_les_trois_membres() {
    let dit = document(Reason::NoSuchResource);
    assert_eq!(
        dit,
        "{\"type\":\"/problems/not-found\",\"title\":\"aucune ressource ici\",\"status\":404}"
    );
}

/// Chaque raison écrit un document lisible, avec son code.
#[test]
fn chaque_raison_ecrit_son_document() {
    for reason in TOUTES {
        let dit = document(reason);
        assert!(
            dit.starts_with("{\"type\":\"/problems/"),
            "{reason:?} : {dit}"
        );
        assert!(dit.contains("\"title\":\""), "{reason:?}");
        assert!(
            dit.contains(&std::format!("\"status\":{}", reason.status().value())),
            "{reason:?} : {dit}"
        );
        assert!(dit.ends_with('}'), "{reason:?}");
    }
}

/// **LE TYPE VIENT DU CODE D'ÉTAT, ET NON DE LA RAISON** : deux raisons qui
/// partagent un code sont indiscernables, jusque dans le document d'erreur.
///
/// Sans cette règle, le `type` rendrait immédiatement la distinction que le code
/// 404 venait d'effacer — et le document défferait le travail du code d'état.
#[test]
fn l_absence_et_l_interdit_ecrivent_le_meme_document() {
    assert_eq!(
        document(Reason::NoSuchResource),
        document(Reason::Forbidden),
        "les deux documents doivent être indiscernables, octet pour octet"
    );
}

/// **CE QUI EST NÔTRE SE DIT D'UNE SEULE FAÇON** : le détailler dirait ce que
/// notre code a fait de travers.
#[test]
fn nos_propres_fautes_se_disent_pareil() {
    for reason in TOUTES {
        if reason.status().class() != 5 {
            continue;
        }
        assert!(
            document(reason).contains("/problems/internal"),
            "{reason:?} nomme autre chose"
        );
    }
}

/// **LE TYPE DE MÉDIA N'EST PAS `application/json`** (§3 de RFC 9457) : un
/// intermédiaire peut reconnaître une erreur sans lire le corps.
#[test]
fn le_type_de_media_distingue_une_erreur() {
    assert_eq!(PROBLEM_MEDIA_TYPE, "application/problem+json");
    assert_eq!(JSON_MEDIA_TYPE, "application/json");
    assert_ne!(PROBLEM_MEDIA_TYPE, JSON_MEDIA_TYPE);
}

/// **NOTRE TAMPON, NOTRE FAUTE.**
#[test]
fn un_tampon_trop_court_est_notre_faute() {
    for taille in 0..document(Reason::NoSuchResource).len() {
        let mut petit = std::vec![0_u8; taille];
        let faute = problem(Reason::NoSuchResource, &mut petit).expect_err("trop court");
        assert_eq!(faute.reason(), Reason::BufferTooSmall, "{taille}");
    }
}
