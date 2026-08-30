// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un `STATUS` a le droit de demander.

use super::*;

/// Les six éléments se lisent, et sortent dans l'ordre de la demande.
#[test]
fn les_six_elements_se_lisent_dans_l_ordre() {
    let lu =
        StatusItems::parse(b"(SIZE MESSAGES UNSEEN DELETED UIDNEXT UIDVALIDITY)").expect("lisible");
    assert_eq!(
        lu.items(),
        [
            StatusAtt::Size,
            StatusAtt::Messages,
            StatusAtt::Unseen,
            StatusAtt::Deleted,
            StatusAtt::UidNext,
            StatusAtt::UidValidity,
        ]
    );
    assert!(lu.wants(StatusAtt::Unseen));

    // La casse ne compte pas, et les espaces surnuméraires non plus.
    let casse = StatusItems::parse(b"(  messages   uidnext  )").expect("lisible");
    assert_eq!(casse.items(), [StatusAtt::Messages, StatusAtt::UidNext]);
    assert!(!casse.wants(StatusAtt::Size));
}

/// **UN DOUBLON NE DEMANDE RIEN DE PLUS**, et n'est pas une faute.
#[test]
fn un_doublon_ne_demande_rien_de_plus() {
    let lu = StatusItems::parse(b"(MESSAGES MESSAGES messages)").expect("lisible");
    assert_eq!(lu.items(), [StatusAtt::Messages]);

    // Et l'on ne peut pas faire déborder le tableau en répétant.
    let mut beaucoup = std::vec::Vec::from(&b"("[..]);
    for _ in 0..50 {
        beaucoup.extend_from_slice(b"MESSAGES UNSEEN ");
    }
    beaucoup.extend_from_slice(b")");
    let repete = StatusItems::parse(&beaucoup).expect("lisible");
    assert_eq!(repete.items(), [StatusAtt::Messages, StatusAtt::Unseen]);
    assert!(repete.items().len() <= STATUS_ATTS_MAX);
}

/// **`RECENT` A DISPARU DE rev2**, et se refuse plutôt que de rendre zéro.
#[test]
fn recent_a_disparu_et_se_refuse() {
    assert_eq!(StatusItems::parse(b"(RECENT)"), Err(Error::MalformedStatus));
    assert_eq!(
        StatusItems::parse(b"(MESSAGES RECENT)"),
        Err(Error::MalformedStatus)
    );
}

/// Ce qui n'a pas la forme de §6.3.11 se refuse.
#[test]
fn ce_qui_n_a_pas_la_forme_se_refuse() {
    for arguments in [
        // Rien du tout, ou une liste vide : §9 en veut au moins un.
        &b""[..],
        b"()",
        b"(   )",
        // Sans parenthèses.
        b"MESSAGES",
        // Une parenthèse d'un seul côté.
        b"(MESSAGES",
        b"MESSAGES)",
        // Un mot qui n'est pas un élément.
        b"(TAILLE)",
        b"(MESSAGESS)",
    ] {
        assert_eq!(
            StatusItems::parse(arguments),
            Err(Error::MalformedStatus),
            "{arguments:?}"
        );
    }
}

/// Ce qui est lu se montre et se compare.
#[test]
fn ce_qui_est_lu_se_montre() {
    let lu = StatusItems::parse(b"(MESSAGES)").expect("lisible");
    assert_eq!(lu, lu);
    assert!(std::format!("{lu:?}").contains("Messages"));
    let texte = std::format!("{}", Error::MalformedStatus);
    assert!(texte.contains("`STATUS`"), "{texte}");
}
