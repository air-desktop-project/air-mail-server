//! Ce qu'un `TXT` de politique dit, et ce qu'on refuse d'y lire.

use super::parse_id;

#[test]
fn un_txt_ordinaire_rend_son_identifiant() {
    assert_eq!(
        parse_id("v=STSv1; id=20160831085700Z;"),
        Some("20160831085700Z")
    );
    // Sans point-virgule final, et sans espaces.
    assert_eq!(parse_id("v=STSv1;id=abc123"), Some("abc123"));
    // Des blancs autour des champs : §3.1 en tolère après le point-virgule, et
    // l'on est indulgent des deux côtés.
    assert_eq!(parse_id("v=STSv1 ;  id=abc "), Some("abc"));
    // Mais PAS autour du signe égal : `sts-id = "id" "=" 1*32(ALPHA / DIGIT)`
    // ne laisse rien entre les trois, et l'inventer ferait lire un champ qui
    // n'existe pas.
    assert_eq!(parse_id("v=STSv1; id = abc"), None);
}

/// **§3.1 : `v=STSv1` VIENT EN PREMIER.**
///
/// Accepter l'inverse ferait lire comme une politique un enregistrement du
/// domaine qui parle d'autre chose.
#[test]
fn la_version_doit_venir_en_premier() {
    assert_eq!(parse_id("id=abc; v=STSv1"), None);
    assert_eq!(parse_id("v=STSv2; id=abc"), None);
    assert_eq!(parse_id("v=stsv1; id=abc"), None);
    assert_eq!(parse_id("id=abc"), None);
    assert_eq!(parse_id(""), None);
    // Un `TXT` du domaine qui parle d'autre chose.
    assert_eq!(parse_id("v=spf1 include:example.com -all"), None);
}

#[test]
fn un_txt_sans_identifiant_ne_rend_rien() {
    assert_eq!(parse_id("v=STSv1"), None);
    assert_eq!(parse_id("v=STSv1; autre=chose"), None);
}

/// L'identifiant est fait de lettres et de chiffres, de un à trente-deux.
#[test]
fn un_identifiant_qui_n_en_est_pas_un_est_refuse() {
    for mauvais in ["", " ", "abc-def", "abc.def", "abc/def", "abc def", "é"] {
        let txt = std::format!("v=STSv1; id={mauvais}");
        assert_eq!(parse_id(&txt), None, "« {mauvais} »");
    }
    // Trente-deux passent ; trente-trois, non.
    let juste = "a".repeat(32);
    assert_eq!(
        parse_id(&std::format!("v=STSv1; id={juste}")),
        Some(juste.as_str())
    );
    let trop = "a".repeat(33);
    assert_eq!(parse_id(&std::format!("v=STSv1; id={trop}")), None);
}

/// **LE PREMIER `id=` L'EMPORTE**, et les suivants ne le remplacent pas : un
/// enregistrement qui en porte deux est ambigu, et prendre le dernier laisserait
/// un tiers ajouter le sien à la fin.
#[test]
fn le_premier_identifiant_l_emporte() {
    assert_eq!(parse_id("v=STSv1; id=premier; id=second"), Some("premier"));
}
