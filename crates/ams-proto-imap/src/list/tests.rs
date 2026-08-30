// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un `LIST` a le droit d'être.

use super::*;

/// La forme que tout le monde envoie : deux mots, et rien d'autre.
#[test]
fn la_forme_ordinaire_se_lit() {
    let lu = List::parse(b"\"\" *").expect("lisible");
    assert_eq!(lu.patterns(), [&b"*"[..]]);
    assert!(!lu.subscribed_only());
    assert!(!lu.report_subscribed());

    // La référence est lue et jetée, quelle qu'elle soit.
    let autre = List::parse(b"\"#news.\" comp.*").expect("lisible");
    assert_eq!(autre.patterns(), [&b"comp.*"[..]]);

    // Sans guillemets non plus ce n'est pas une faute : §9 admet l'atome.
    let nu = List::parse(b"x INBOX").expect("lisible");
    assert_eq!(nu.patterns(), [&b"INBOX"[..]]);
}

/// **DEVANT C'EST UN FILTRE, DERRIÈRE C'EST UN RENSEIGNEMENT**, et le même mot
/// ne dit pas la même chose aux deux places.
#[test]
fn le_meme_mot_ne_dit_pas_la_meme_chose_aux_deux_places() {
    let filtre = List::parse(b"(SUBSCRIBED) \"\" *").expect("lisible");
    assert!(filtre.subscribed_only());
    assert!(!filtre.report_subscribed());

    let renseignement = List::parse(b"\"\" * RETURN (SUBSCRIBED)").expect("lisible");
    assert!(!renseignement.subscribed_only());
    assert!(renseignement.report_subscribed());

    // Et les deux ensemble.
    let deux = List::parse(b"(SUBSCRIBED) \"\" * RETURN (SUBSCRIBED)").expect("lisible");
    assert!(deux.subscribed_only());
    assert!(deux.report_subscribed());

    // La casse ne compte pas.
    let casse = List::parse(b"(subscribed) \"\" * return (children)").expect("lisible");
    assert!(casse.subscribed_only());
    assert!(!casse.report_subscribed());
}

/// **UNE OPTION QU'ON NE SERT PAS SE REFUSE** : l'ignorer rendrait une liste que
/// le client croirait filtrée.
#[test]
fn une_option_qu_on_ne_sert_pas_se_refuse() {
    for arguments in [
        &b"(REMOTE) \"\" *"[..],
        b"(RECURSIVEMATCH) \"\" *",
        b"(SUBSCRIBED REMOTE) \"\" *",
        b"\"\" * RETURN (STATUS (MESSAGES))",
        b"\"\" * RETURN (SPECIAL-USE)",
    ] {
        assert_eq!(
            List::parse(arguments),
            Err(Error::MalformedList),
            "{arguments:?}"
        );
    }
}

/// `CHILDREN` est admis SANS RIEN CHANGER : la réponse le porte déjà.
#[test]
fn children_est_admis_sans_rien_changer() {
    let lu = List::parse(b"\"\" * RETURN (CHILDREN SUBSCRIBED)").expect("lisible");
    assert!(lu.report_subscribed());
    let seul = List::parse(b"\"\" * RETURN (CHILDREN)").expect("lisible");
    assert!(!seul.report_subscribed());
    // Une liste de retour VIDE ne demande rien, et n'est pas une faute.
    let vide = List::parse(b"\"\" * RETURN ()").expect("lisible");
    assert!(!vide.report_subscribed());
    // Une liste de sélection vide non plus : `()` ne filtre rien.
    let sans = List::parse(b"() \"\" *").expect("lisible");
    assert!(!sans.subscribed_only());
}

/// **PLUSIEURS MOTIFS SE DEMANDENT EN UNE FOIS**, ce que §9 admet.
#[test]
fn plusieurs_motifs_se_demandent_en_une_fois() {
    let lu = List::parse(b"\"\" (\"INBOX\" \"Travail/%\")").expect("lisible");
    assert_eq!(lu.patterns(), [&b"INBOX"[..], &b"Travail/%"[..]]);

    // Une liste de motifs VIDE ne demande rien : §6.3.9 rend alors une réponse
    // vide, et non une faute.
    let rien = List::parse(b"\"\" ()").expect("lisible");
    assert!(rien.patterns().is_empty());

    // Et le `RETURN` suit toujours.
    let avec = List::parse(b"\"\" (\"a\" \"b\") RETURN (SUBSCRIBED)").expect("lisible");
    assert_eq!(avec.patterns(), [&b"a"[..], &b"b"[..]]);
    assert!(avec.report_subscribed());
}

/// **LA BORNE EST CELLE DU TRAVAIL DEMANDÉ**, pas celle de la grammaire :
/// chaque motif fait un parcours de plus sur toutes les boîtes du compte.
#[test]
fn trop_de_motifs_se_refuse() {
    let mut trop = std::vec::Vec::from(&b"\"\" ("[..]);
    for _ in 0..=LIST_PATTERNS_MAX {
        trop.extend_from_slice(b"\"a\" ");
    }
    trop.extend_from_slice(b")");
    assert_eq!(List::parse(&trop), Err(Error::MalformedList));

    // Juste ce qu'il faut passe.
    let mut assez = std::vec::Vec::from(&b"\"\" ("[..]);
    for _ in 0..LIST_PATTERNS_MAX {
        assez.extend_from_slice(b"\"a\" ");
    }
    assez.extend_from_slice(b")");
    let lu = List::parse(&assez).expect("lisible");
    assert_eq!(lu.patterns().len(), LIST_PATTERNS_MAX);
}

/// **UN MOTIF PLUS LONG QUE LE PLUS LONG NOM DE BOÎTE NE DÉSIGNE RIEN**, et se
/// refuse plutôt que de faire parcourir toutes les boîtes pour rien.
#[test]
fn un_motif_demesure_se_refuse() {
    let mut long = std::vec::Vec::from(&b"\"\" "[..]);
    long.resize(long.len() + MAILBOX_NAME_MAX + 1, b'x');
    assert_eq!(List::parse(&long), Err(Error::MalformedList));

    let mut entre = std::vec::Vec::from(&b"\"\" (\""[..]);
    entre.resize(entre.len() + MAILBOX_NAME_MAX + 1, b'x');
    entre.extend_from_slice(b"\")");
    assert_eq!(List::parse(&entre), Err(Error::MalformedList));

    // Juste ce qu'il faut passe.
    let mut juste = std::vec::Vec::from(&b"\"\" "[..]);
    juste.resize(juste.len() + MAILBOX_NAME_MAX, b'x');
    assert!(List::parse(&juste).is_ok());
}

/// Ce qui n'a pas la forme de §6.3.9 se refuse, et le dit.
#[test]
fn ce_qui_n_a_pas_la_forme_se_refuse() {
    for arguments in [
        // Rien du tout.
        &b""[..],
        // Une référence sans motif.
        b"\"\"",
        // Une parenthèse qui ne se ferme pas.
        b"(SUBSCRIBED \"\" *",
        b"\"\" (\"a\"",
        b"\"\" * RETURN (SUBSCRIBED",
        // Des parenthèses emboîtées, qui ne voudraient rien dire.
        b"((SUBSCRIBED)) \"\" *",
        // Un guillemet qui ne se ferme pas, à chacune de ses places.
        b"\"\" \"abc",
        b"\"\" * \"abc",
        b"\"\" (\"abc)",
        // Ce qui suit le motif n'est pas un `RETURN`.
        b"\"\" * SUBSCRIBED",
        b"\"\" * RETURN (SUBSCRIBED) et-puis-quoi",
        // Un `RETURN` sans sa liste.
        b"\"\" * RETURN",
        b"\"\" * RETURN SUBSCRIBED",
    ] {
        assert_eq!(
            List::parse(arguments),
            Err(Error::MalformedList),
            "{arguments:?}"
        );
    }
}

/// Ce que le module rend se lit — la dérive de `Debug` sert au fuzz et aux
/// messages d'échec.
#[test]
fn ce_qui_est_lu_se_montre() {
    let lu = List::parse(b"\"\" *").expect("lisible");
    let texte = std::format!("{lu:?}");
    assert!(texte.contains("subscribed_only"), "{texte}");
    assert_eq!(lu, lu.clone());
}

/// Le texte d'une faute de `LIST` se lit : c'est ce que le journal en dira.
#[test]
fn la_faute_se_dit() {
    let texte = std::format!("{}", Error::MalformedList);
    assert!(texte.contains("`LIST`"), "{texte}");
}
