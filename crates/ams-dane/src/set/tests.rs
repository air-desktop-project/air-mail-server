//! Ce qu'un jeu de `TLSA` engage, et ce qu'il n'engage pas.

use super::Set;
use crate::record::tests::{AUTORITE, FEUILLE, rdata};
use crate::record::{Match, Tlsa};
use sha2::{Digest as _, Sha256};

/// La clef de la feuille, telle qu'un `TLSA` la désigne.
fn clef_de_la_feuille() -> std::vec::Vec<u8> {
    let clef = crate::subject_public_key_info(FEUILLE).expect("une clef");
    Sha256::digest(clef).to_vec()
}

/// **LE BIT `AD` DÉCIDE, ET LUI SEUL.**
///
/// Un `TLSA` lu dans une réponse non authentifiée ne vaut rien : un tiers qui
/// détourne la résolution le RETIRE, et l'on retomberait sur le chiffrement
/// opportuniste en croyant être protégé.
#[test]
fn un_jeu_non_authentifie_n_engage_a_rien() {
    let octets = rdata(3, 1, 1, &clef_de_la_feuille());
    let record = Tlsa::parse(&octets).expect("bien formé");

    assert!(Set::from_records(std::vec![record], true).engage());
    assert!(!Set::from_records(std::vec![record], false).engage());

    // Et il ne prétend pas non plus être authentifié.
    assert!(Set::from_records(std::vec![record], true).authentic());
    assert!(!Set::from_records(std::vec![record], false).authentic());
}

/// **UN JEU ENTIÈREMENT INUTILISABLE SE TRAITE COMME UN JEU VIDE.**
///
/// §2.2 de RFC 7672. C'est la bonne façon d'échouer : un domaine qui publie un
/// usage ou un algorithme qu'on ne sait pas traiter ne doit pas voir son courrier
/// s'arrêter.
#[test]
fn un_jeu_entierement_inutilisable_n_engage_a_rien() {
    let pkix = rdata(1, 1, 1, &clef_de_la_feuille());
    let futur = rdata(3, 1, 9, &[0xab; 32]);
    let records = std::vec![
        Tlsa::parse(&pkix).expect("bien formé"),
        Tlsa::parse(&futur).expect("bien formé"),
    ];
    let jeu = Set::from_records(records, true);
    assert!(!jeu.engage());
    assert_eq!(jeu.usable().count(), 0);
    // Il est authentifié, et il n'engage pourtant à rien : les deux ne sont pas
    // la même chose.
    assert!(jeu.authentic());
}

/// **UN SEUL UTILISABLE SUFFIT À ENGAGER.**
///
/// Le jeu que le domaine publie peut porter n'importe quoi ; ce qui compte est
/// qu'il ait dit AU MOINS une chose qu'on sait vérifier.
#[test]
fn un_seul_utilisable_suffit_a_engager() {
    let pkix = rdata(0, 0, 1, &Sha256::digest(FEUILLE));
    let bon = rdata(3, 1, 1, &clef_de_la_feuille());
    let records = std::vec![
        Tlsa::parse(&pkix).expect("bien formé"),
        Tlsa::parse(&bon).expect("bien formé"),
    ];
    let jeu = Set::from_records(records, true);
    assert!(jeu.engage());
    assert_eq!(jeu.usable().count(), 1);
}

/// **LE JEU EST UNE DISJONCTION** (§2.1 de RFC 7671).
///
/// Un domaine qui renouvelle publie l'ancienne et la nouvelle empreinte en même
/// temps ; exiger les deux rendrait tout renouvellement impossible.
#[test]
fn un_seul_enregistrement_satisfait_suffit() {
    let ancien = rdata(3, 1, 1, &[0x11; 32]);
    let nouveau = rdata(3, 1, 1, &clef_de_la_feuille());
    let records = std::vec![
        Tlsa::parse(&ancien).expect("bien formé"),
        Tlsa::parse(&nouveau).expect("bien formé"),
    ];
    let jeu = Set::from_records(records, true);
    assert_eq!(jeu.matching(FEUILLE), Some(Match::LeafOnly));
    // Et un certificat qui n'est ni l'un ni l'autre ne satisfait rien.
    assert_eq!(jeu.matching(AUTORITE), None);
}

/// **L'ENTITÉ FINALE L'EMPORTE SUR L'AUTORITÉ.**
///
/// Elle ne demande ni chaîne, ni nom, ni date. Prendre l'autorité en premier
/// ferait vérifier un nom là où le domaine avait nommé un certificat exact.
#[test]
fn l_entite_finale_l_emporte_sur_l_autorite() {
    let ancre = rdata(2, 1, 1, &clef_de_la_feuille());
    let feuille = rdata(3, 1, 1, &clef_de_la_feuille());
    // Dans les deux ordres : le résultat ne dépend pas de celui du DNS.
    for records in [
        std::vec![
            Tlsa::parse(&ancre).expect("bien formé"),
            Tlsa::parse(&feuille).expect("bien formé"),
        ],
        std::vec![
            Tlsa::parse(&feuille).expect("bien formé"),
            Tlsa::parse(&ancre).expect("bien formé"),
        ],
    ] {
        let jeu = Set::from_records(records, true);
        assert_eq!(jeu.matching(FEUILLE), Some(Match::LeafOnly));
    }
}

/// Une autorité seule reste une autorité : le nom devra être vérifié.
#[test]
fn une_autorite_seule_demande_une_chaine() {
    let ancre = rdata(2, 0, 1, &Sha256::digest(AUTORITE));
    let jeu = Set::from_records(std::vec![Tlsa::parse(&ancre).expect("bien formé")], true);
    assert!(jeu.engage());
    assert_eq!(jeu.matching(AUTORITE), Some(Match::Anchor));
}

/// **UN ENREGISTREMENT INUTILISABLE NE SATISFAIT RIEN**, même quand ses octets
/// correspondent.
#[test]
fn un_inutilisable_ne_satisfait_rien() {
    // Un `PKIX-EE(1)` dont l'empreinte est pourtant la bonne.
    let pkix = rdata(1, 1, 1, &clef_de_la_feuille());
    let jeu = Set::from_records(std::vec![Tlsa::parse(&pkix).expect("bien formé")], true);
    assert_eq!(jeu.matching(FEUILLE), None);
}

#[test]
fn un_jeu_vide_n_engage_a_rien() {
    let vide = Set::none();
    assert!(!vide.engage());
    assert!(!vide.authentic());
    assert_eq!(vide.usable().count(), 0);
    assert_eq!(vide.matching(FEUILLE), None);
    // Le défaut est le jeu vide : une politique qui ne dit rien n'ouvre rien.
    assert!(!Set::default().engage());
    // Et un jeu authentifié mais SANS enregistrement non plus.
    assert!(!Set::from_records(std::vec![], true).engage());
}

#[test]
fn un_jeu_se_clone_et_se_debogue() {
    let octets = rdata(3, 1, 1, &clef_de_la_feuille());
    let jeu = Set::from_records(std::vec![Tlsa::parse(&octets).expect("bien formé")], true);
    let copie = jeu.clone();
    assert_eq!(copie.engage(), jeu.engage());
    assert!(!std::format!("{jeu:?}").is_empty());
}
