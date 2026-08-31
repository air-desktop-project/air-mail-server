// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une faute d'API dit au client.

use ams_proto_http::StatusCode;

use super::{Error, Reason};

/// Chaque raison a son code, et son message.
#[test]
fn chaque_raison_a_son_code_et_son_message() {
    let cas = [
        (
            Reason::BadPath,
            StatusCode::BAD_REQUEST,
            "chemin est refusé",
        ),
        (Reason::PathTooLong, StatusCode::URI_TOO_LONG, "trop long"),
        (
            Reason::NoSuchResource,
            StatusCode::NOT_FOUND,
            "aucune ressource",
        ),
        (
            Reason::MethodNotAllowed,
            StatusCode::METHOD_NOT_ALLOWED,
            "méthode",
        ),
        (Reason::Forbidden, StatusCode::NOT_FOUND, "aucune ressource"),
        (
            Reason::BadToken,
            StatusCode::UNAUTHORIZED,
            "n'est pas recevable",
        ),
        (Reason::TokenExpired, StatusCode::UNAUTHORIZED, "a expiré"),
        (
            Reason::BadKey,
            StatusCode::INTERNAL_SERVER_ERROR,
            "n'a pas pu authentifier",
        ),
        (
            Reason::BufferTooSmall,
            StatusCode::INTERNAL_SERVER_ERROR,
            "n'a pas pu écrire",
        ),
    ];
    for (raison, code, morceau) in cas {
        let faute = Error::new(raison);
        assert_eq!(faute.reason(), raison);
        assert_eq!(faute.status(), code, "{raison:?}");
        assert_eq!(raison.status(), code);
        let dit = std::format!("{faute}");
        assert!(dit.contains(morceau), "{raison:?} dit « {dit} »");
        assert!(
            dit.contains(&std::format!("{}", code.value())),
            "{raison:?} ne dit pas son code"
        );
    }
}

/// **LA MÊME RÉPONSE POUR « CELA N'EXISTE PAS » ET « VOUS N'AVEZ PAS LE DROIT DE
/// SAVOIR »** : la différence entre les deux serait l'information elle-même, et
/// un client sans aucun droit pourrait la collecter en balayant.
#[test]
fn l_absence_et_l_interdit_ne_se_distinguent_pas() {
    assert_eq!(
        Reason::NoSuchResource.status(),
        Reason::Forbidden.status(),
        "les deux codes doivent être indiscernables"
    );
    assert_eq!(
        Reason::NoSuchResource.message(),
        Reason::Forbidden.message(),
        "les deux messages doivent être indiscernables"
    );
}

/// **ON NE DIT JAMAIS CE QU'ON A REFUSÉ PRÉCISÉMENT** : la formulation précise
/// apprendrait à qui sonde quelle règle il a touchée, et donc laquelle
/// contourner.
#[test]
fn le_message_ne_nomme_aucune_regle() {
    for raison in [
        Reason::BadPath,
        Reason::PathTooLong,
        Reason::NoSuchResource,
        Reason::Forbidden,
        Reason::BadToken,
        Reason::TokenExpired,
    ] {
        let dit = raison.message();
        for indice in ["segment", "..", "%", "UTF-8", "portée", "sceau", "clé"] {
            assert!(
                !dit.contains(indice),
                "« {dit} » nomme « {indice} », ce qui apprend où appuyer"
            );
        }
    }
}
