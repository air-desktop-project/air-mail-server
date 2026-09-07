// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un document d'erreur dit, et ce qu'il ne dit pas.

use std::string::{String, ToString};

use super::{JSON_MEDIA_TYPE, PROBLEM_MEDIA_TYPE, problem};
use crate::error::Reason;

/// Toutes les raisons, pour que chaque essai les parcoure toutes.
const TOUTES: [Reason; 10] = [
    Reason::BadPath,
    Reason::PathTooLong,
    Reason::NoSuchResource,
    Reason::MethodNotAllowed,
    Reason::Forbidden,
    Reason::BadPassword,
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

/// **UN MOT DE PASSE ACTUEL FAUX SE DIT 403, ET NON 404 NI 401.**
///
/// Les trois codes racontent trois choses différentes, et le client agit
/// différemment sur chacun : 404 le ferait chercher une route disparue, 401 lui
/// ferait recommencer une authentification qui a réussi, 403 lui dit ce qui est
/// vrai — la requête est comprise, et refusée.
///
/// L'essai tient aussi le `type`, parce qu'il vient du CODE : un 403 qui
/// retomberait sur `/problems/internal` accuserait le serveur d'une faute qui
/// est celle de qui tape son ancien mot de passe.
#[test]
fn un_mot_de_passe_actuel_faux_se_dit_403() {
    assert_eq!(Reason::BadPassword.status().value(), 403);
    assert_eq!(
        document(Reason::BadPassword),
        "{\"type\":\"/problems/forbidden\",\"title\":\"le mot de passe actuel ne \
         correspond pas\",\"status\":403}"
    );

    // Et il ne se confond avec aucun des deux voisins.
    assert_ne!(
        Reason::BadPassword.status(),
        Reason::Forbidden.status(),
        "une portée refusée se cache derrière un 404 ; celui-ci n'a rien à cacher"
    );
    assert_ne!(Reason::BadPassword.status(), Reason::BadToken.status());
}
