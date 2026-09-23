//! Ce que le registre des sessions garantit, et ce qu'il oublie.

use super::{PAR_COMPTE, Sessions};

/// Une microseconde d'horloge, pour que les essais se lisent.
const SECONDE: u64 = 1_000_000;

/// **UNE SESSION OUVERTE EST OUVERTE, ET ELLE SEULE.**
#[test]
fn une_session_ouverte_se_reconnait() {
    let registre = Sessions::new();
    registre.ouvrir("marie", 7, 100 * SECONDE, 0);
    assert!(registre.ouverte("marie", 7, 0));
    // Ni un autre identifiant du même compte…
    assert!(!registre.ouverte("marie", 8, 0));
    // …ni le même identifiant d'un autre compte.
    assert!(!registre.ouverte("jean", 7, 0));
}

/// **FERMER, C'EST FERMER.** C'est la propriété que ce registre existe pour
/// donner : sans lui, un jeton volé valait jusqu'à son expiration.
#[test]
fn une_session_fermee_ne_s_ouvre_plus() {
    let registre = Sessions::new();
    registre.ouvrir("marie", 7, 100 * SECONDE, 0);
    assert!(registre.fermer("marie", 7));
    assert!(!registre.ouverte("marie", 7, 0));
    // Et la fermer deux fois dit qu'il n'y avait plus rien à fermer.
    assert!(!registre.fermer("marie", 7));
}

/// **L'EXPIRATION SE REVÉRIFIE À LA LECTURE**, et pas seulement à la purge :
/// une entrée périmée que personne n'a balayée ne doit pas ouvrir une porte que
/// le jeton fermait.
#[test]
fn une_session_perimee_est_close_meme_sans_purge() {
    let registre = Sessions::new();
    registre.ouvrir("marie", 7, 10 * SECONDE, 0);
    assert!(registre.ouverte("marie", 7, 9 * SECONDE));
    assert!(!registre.ouverte("marie", 7, 10 * SECONDE));
    assert!(!registre.ouverte("marie", 7, 11 * SECONDE));
}

/// **LE PLAFOND TIENT, ET C'EST LA PLUS ANCIENNE QUI CÈDE.**
///
/// Refuser l'ouverture enfermerait dehors quelqu'un qui a ses identifiants —
/// exactement ce qu'un attaquant chercherait à provoquer en ouvrant des
/// sessions jusqu'au plafond.
#[test]
fn au_dela_du_plafond_la_plus_ancienne_cede() {
    let registre = Sessions::new();
    for rang in 0..u64::try_from(PAR_COMPTE).expect("tient") {
        registre.ouvrir("marie", rang, 100 * SECONDE, 0);
    }
    assert_eq!(registre.combien("marie", 0), PAR_COMPTE);
    assert!(registre.ouverte("marie", 0, 0), "la première est là");

    // Une de plus : la plus ancienne s'en va, la nouvelle entre.
    registre.ouvrir("marie", 999, 100 * SECONDE, 0);
    assert_eq!(registre.combien("marie", 0), PAR_COMPTE, "le plafond tient");
    assert!(!registre.ouverte("marie", 0, 0), "la plus ancienne a cédé");
    assert!(registre.ouverte("marie", 999, 0), "la nouvelle est entrée");
    assert!(registre.ouverte("marie", 1, 0), "et la suivante demeure");
}

/// **LA PURGE A LIEU À L'INSERTION**, et elle ne compte pas les périmées dans
/// le plafond : sans cela, un compte actif se retrouverait plafonné par des
/// sessions mortes.
#[test]
fn les_perimees_ne_tiennent_pas_de_place() {
    let registre = Sessions::new();
    for rang in 0..u64::try_from(PAR_COMPTE).expect("tient") {
        registre.ouvrir("marie", rang, 10 * SECONDE, 0);
    }
    // Toutes ont expiré : la suivante les balaie, et rien n'a cédé de force.
    registre.ouvrir("marie", 999, 100 * SECONDE, 20 * SECONDE);
    assert_eq!(registre.combien("marie", 20 * SECONDE), 1);
    assert!(registre.ouverte("marie", 999, 20 * SECONDE));
}

/// **UN COMPTE SANS SESSION NE LAISSE PAS D'ENTRÉE.**
///
/// Sans ce ménage, la table retiendrait le nom de tous les comptes s'étant
/// connectés un jour — un annuaire que personne n'a demandé.
#[test]
fn un_compte_vide_disparait_de_la_table() {
    let registre = Sessions::new();
    registre.ouvrir("marie", 7, 100 * SECONDE, 0);
    assert_eq!(registre.combien("marie", 0), 1);
    registre.fermer("marie", 7);
    assert_eq!(registre.combien("marie", 0), 0);
    // Et fermer sur un compte inconnu ne fabrique pas d'entrée.
    assert!(!registre.fermer("personne", 1));
    assert_eq!(registre.combien("personne", 0), 0);
}

/// Les comptes ne se mélangent pas, même au plafond.
#[test]
fn le_plafond_est_par_compte() {
    let registre = Sessions::new();
    for rang in 0..u64::try_from(PAR_COMPTE).expect("tient") {
        registre.ouvrir("marie", rang, 100 * SECONDE, 0);
        registre.ouvrir("jean", rang, 100 * SECONDE, 0);
    }
    assert_eq!(registre.combien("marie", 0), PAR_COMPTE);
    assert_eq!(registre.combien("jean", 0), PAR_COMPTE);
    registre.ouvrir("marie", 999, 100 * SECONDE, 0);
    assert!(!registre.ouverte("marie", 0, 0), "marie a perdu la sienne");
    assert!(registre.ouverte("jean", 0, 0), "jean n'a rien perdu");
}
