//! Ce qu'une politique dit, et ce qu'on refuse d'y lire.

use super::{MX_MAX, Mode, parse_policy};
use crate::Error;

/// Une politique bien formée, dont chaque essai change une pièce.
const ENFORCE: &str = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n";

#[test]
fn une_politique_ordinaire_se_lit() {
    let mut place = [""; 8];
    let politique = parse_policy(ENFORCE, &mut place).expect("lisible");
    assert_eq!(politique.mode(), Mode::Enforce);
    assert_eq!(politique.mx(), ["mail.example.com"]);
    assert_eq!(politique.max_age(), 604_800);
}

/// **§3.2 : LES LIGNES SE TERMINENT PAR `CRLF` OU PAR `LF`.**
#[test]
fn les_deux_fins_de_ligne_se_lisent() {
    let mut place = [""; 8];
    let crlf = ENFORCE.replace('\n', "\r\n");
    let politique = parse_policy(&crlf, &mut place).expect("lisible");
    assert_eq!(politique.mode(), Mode::Enforce);
    assert_eq!(politique.mx(), ["mail.example.com"]);
}

#[test]
fn les_trois_modes_se_distinguent() {
    for (mot, attendu) in [
        ("enforce", Mode::Enforce),
        ("testing", Mode::Testing),
        ("none", Mode::None),
    ] {
        let texte = ENFORCE.replace("enforce", mot);
        let mut place = [""; 8];
        assert_eq!(
            parse_policy(&texte, &mut place).expect("lisible").mode(),
            attendu,
            "« {mot} »"
        );
    }
    // Et rien d'autre.
    let texte = ENFORCE.replace("enforce", "peut-être");
    let mut place = [""; 8];
    assert_eq!(parse_policy(&texte, &mut place), Err(Error::BadMode));
}

/// **UNE POLITIQUE `none` N'A PAS BESOIN DE `mx`.**
///
/// C'est la façon de dire « oubliez celle que vous aviez », et exiger un serveur
/// pour la lire rendrait le retrait impossible.
#[test]
fn une_politique_none_sans_mx_se_lit() {
    let texte = "version: STSv1\nmode: none\nmax_age: 1\n";
    let mut place = [""; 8];
    let politique = parse_policy(texte, &mut place).expect("lisible");
    assert_eq!(politique.mode(), Mode::None);
    assert!(politique.mx().is_empty());
    // Mais `enforce` sans `mx` ne veut rien dire.
    let texte = "version: STSv1\nmode: enforce\nmax_age: 1\n";
    let mut place = [""; 8];
    assert_eq!(parse_policy(texte, &mut place), Err(Error::BadMx));
}

/// **UNE VERSION QU'ON NE CONNAÎT PAS SE REFUSE**, et ne se devine pas.
#[test]
fn une_version_absente_ou_inconnue_est_refusee() {
    for texte in [
        "mode: enforce\nmx: a.test\nmax_age: 1\n",
        "version: STSv2\nmode: enforce\nmx: a.test\nmax_age: 1\n",
        "version: stsv1\nmode: enforce\nmx: a.test\nmax_age: 1\n",
        "",
    ] {
        let mut place = [""; 8];
        assert_eq!(
            parse_policy(texte, &mut place),
            Err(Error::BadVersion),
            "« {texte} »"
        );
    }
}

#[test]
fn un_mode_ou_un_age_absent_est_refuse() {
    let mut place = [""; 8];
    assert_eq!(
        parse_policy("version: STSv1\nmx: a.test\nmax_age: 1\n", &mut place),
        Err(Error::BadMode)
    );
    let mut place = [""; 8];
    assert_eq!(
        parse_policy("version: STSv1\nmode: enforce\nmx: a.test\n", &mut place),
        Err(Error::BadMaxAge)
    );
}

/// §3.2 borne `max_age` à un peu plus d'un an, et zéro n'a pas de sens.
#[test]
fn un_age_hors_bornes_est_refuse() {
    for valeur in [
        "0",
        "31557601",
        "-1",
        "beaucoup",
        "",
        "99999999999999999999",
    ] {
        let texte = ENFORCE.replace("604800", valeur);
        let mut place = [""; 8];
        assert_eq!(
            parse_policy(&texte, &mut place),
            Err(Error::BadMaxAge),
            "« {valeur} »"
        );
    }
    // Les deux bornes elles-mêmes passent.
    for valeur in ["1", "31557600"] {
        let texte = ENFORCE.replace("604800", valeur);
        let mut place = [""; 8];
        assert!(parse_policy(&texte, &mut place).is_ok(), "« {valeur} »");
    }
}

/// **LE JOKER COUVRE EXACTEMENT UNE ÉTIQUETTE** (§4.1, et §6.4.3 de RFC 6125).
///
/// Le laisser couvrir davantage reviendrait à laisser un sous-domaine délégué à
/// un tiers recevoir le courrier du domaine entier.
#[test]
fn le_joker_couvre_exactement_une_etiquette() {
    let texte = "version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 1\n";
    let mut place = [""; 8];
    let politique = parse_policy(texte, &mut place).expect("lisible");

    assert!(politique.allows("mx1.example.com"));
    assert!(
        politique.allows("MX1.EXAMPLE.COM"),
        "la casse ne compte pas"
    );
    // Deux étiquettes : non.
    assert!(!politique.allows("a.b.example.com"));
    // Zéro étiquette : non plus.
    assert!(!politique.allows("example.com"));
    // Et un autre domaine, évidemment.
    assert!(!politique.allows("mx1.ailleurs.test"));
    assert!(!politique.allows(""));
}

#[test]
fn un_motif_sans_joker_se_compare_entier() {
    let mut place = [""; 8];
    let politique = parse_policy(ENFORCE, &mut place).expect("lisible");
    assert!(politique.allows("mail.example.com"));
    assert!(politique.allows("MAIL.example.COM"));
    assert!(!politique.allows("autre.example.com"));
    assert!(!politique.allows("mail.example.com.evil.test"));
    assert!(!politique.allows("x.mail.example.com"));
}

/// **LE JOKER N'EST PERMIS QU'EN TÊTE**, et doit couvrir une étiquette entière.
#[test]
fn un_motif_qui_n_en_est_pas_un_est_refuse() {
    for motif in [
        "",
        ".example.com",
        "example.com.",
        "mail example.com",
        "mail@example.com",
        "mail_example.com",
        "*",
    ] {
        let texte = ENFORCE.replace("mail.example.com", motif);
        let mut place = [""; 8];
        assert_eq!(
            parse_policy(&texte, &mut place),
            Err(Error::BadMx),
            "« {motif} »"
        );
    }
    // `m*.example.com` n'est pas un joker : il est lu comme un nom littéral, et
    // l'astérisque n'a rien à y faire.
    let texte = ENFORCE.replace("mail.example.com", "m*.example.com");
    let mut place = [""; 8];
    assert_eq!(parse_policy(&texte, &mut place), Err(Error::BadMx));
}

/// **UNE POLITIQUE PLUS GARNIE QUE LA PLACE EST REFUSÉE, PAS TRONQUÉE.**
///
/// Une politique amputée d'un de ses serveurs ferait refuser une remise
/// parfaitement légitime.
#[test]
fn une_politique_plus_garnie_que_la_place_est_refusee() {
    let mut texte = std::string::String::from("version: STSv1\nmode: enforce\nmax_age: 1\n");
    for rang in 0..5 {
        texte.push_str(&std::format!("mx: mx{rang}.example.com\n"));
    }
    let mut trop_petite = [""; 4];
    assert_eq!(parse_policy(&texte, &mut trop_petite), Err(Error::BadMx));
    let mut juste = [""; 5];
    assert_eq!(
        parse_policy(&texte, &mut juste)
            .expect("lisible")
            .mx()
            .len(),
        5
    );
}

/// **LA BORNE DE C3 EST CELLE DE LA CRATE**, et non celle de l'appelant : une
/// place démesurée ne doit pas permettre une politique démesurée.
#[test]
fn plus_de_motifs_que_la_borne_est_refuse() {
    let mut texte = std::string::String::from("version: STSv1\nmode: enforce\nmax_age: 1\n");
    for rang in 0..=MX_MAX {
        texte.push_str(&std::format!("mx: mx{rang}.example.com\n"));
    }
    let mut place = std::vec![""; MX_MAX * 2];
    assert_eq!(parse_policy(&texte, &mut place), Err(Error::BadMx));
}

/// **UNE CLEF QU'ON NE CONNAÎT PAS SE SAUTE.**
///
/// §3.2 réserve l'extension : un champ de demain ne doit pas arrêter le courrier
/// d'aujourd'hui.
#[test]
fn une_clef_inconnue_se_saute() {
    let texte = "version: STSv1\nmode: enforce\nmx: a.test\nmax_age: 1\nfuture: 42\n";
    let mut place = [""; 8];
    assert!(parse_policy(texte, &mut place).is_ok());
}

#[test]
fn une_ligne_qui_n_est_pas_une_paire_est_refusee() {
    let texte = "version: STSv1\nmode: enforce\nsans-deux-points\nmx: a.test\nmax_age: 1\n";
    let mut place = [""; 8];
    assert_eq!(parse_policy(texte, &mut place), Err(Error::Malformed));
    // Les lignes vides, en revanche, se sautent.
    let texte = "\n\nversion: STSv1\n\nmode: enforce\n\nmx: a.test\nmax_age: 1\n\n";
    let mut place = [""; 8];
    assert!(parse_policy(texte, &mut place).is_ok());
}

/// **UNE LIGNE DÉMESURÉE SE REFUSE.** Le texte vient d'un serveur qu'on ne
/// choisit pas.
#[test]
fn une_ligne_demesuree_est_refusee() {
    let longue = "a".repeat(600);
    let texte =
        std::format!("version: STSv1\nmode: enforce\nmx: a.test\nmax_age: 1\nx: {longue}\n");
    let mut place = [""; 8];
    assert_eq!(parse_policy(&texte, &mut place), Err(Error::Malformed));
}

#[test]
fn les_types_se_copient_et_se_deboguent() {
    let mut place = [""; 8];
    let politique = parse_policy(ENFORCE, &mut place).expect("lisible");
    let copie = politique;
    assert_eq!(copie, politique);
    assert!(!std::format!("{politique:?}").is_empty());
    assert!(!std::format!("{:?}", Mode::Testing).is_empty());
    assert_ne!(Mode::Enforce, Mode::Testing);
    assert_ne!(Mode::None, Mode::Testing);
    assert!(!std::format!("{:?}", Error::BadMx).is_empty());
    assert_ne!(Error::BadMx, Error::BadMode);
}
