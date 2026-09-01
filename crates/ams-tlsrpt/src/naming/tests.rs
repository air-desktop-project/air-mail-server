//! Ce qu'un rapport s'appelle, et comment son message s'annonce.

use super::{FILENAME_MAX, SUBJECT_MAX, filename, subject};
use crate::Error;

#[test]
fn le_nom_est_celui_que_la_rfc_impose() {
    let mut place = [0_u8; FILENAME_MAX];
    let nom = filename(
        "mail.nous.test",
        "example.com",
        1_700_000_000,
        1_700_086_400,
        &mut place,
    )
    .expect("nommable");
    assert_eq!(
        nom,
        "mail.nous.test!example.com!1700000000!1700086400.json.gz"
    );
}

#[test]
fn le_sujet_est_celui_que_la_rfc_impose() {
    let mut place = [0_u8; SUBJECT_MAX];
    let sujet =
        subject("example.com", "mail.nous.test", "abc-123", &mut place).expect("composable");
    assert_eq!(
        sujet,
        "Report Domain: example.com Submitter: mail.nous.test Report-ID: abc-123"
    );
}

/// **UN `!` OU UN `/` CASSERAIT LE NOM.**
#[test]
fn un_domaine_qui_n_en_est_pas_un_est_refuse() {
    let mut place = [0_u8; FILENAME_MAX];
    for mauvais in ["", ".example.com", "a!b", "a/b", "a b", "é", "../ailleurs"] {
        assert_eq!(
            filename(mauvais, "x.test", 1, 2, &mut place),
            Err(Error::NotPrintable),
            "émetteur « {mauvais} »"
        );
        assert_eq!(
            filename("x.test", mauvais, 1, 2, &mut place),
            Err(Error::NotPrintable),
            "rapporté « {mauvais} »"
        );
    }
}

/// **UN `CRLF` DANS L'IDENTIFIANT ÉCRIRAIT DES EN-TÊTES À NOTRE PLACE.**
#[test]
fn un_identifiant_qui_ecrirait_un_entete_est_refuse() {
    let mut place = [0_u8; SUBJECT_MAX];
    for mauvais in ["", "a b", "a\r\nX: y", "a\nb", "\t"] {
        assert_eq!(
            subject("x.test", "y.test", mauvais, &mut place),
            Err(Error::NotPrintable),
            "« {mauvais} »"
        );
    }
    let long = "a".repeat(129);
    assert_eq!(
        subject("x.test", "y.test", &long, &mut place),
        Err(Error::NotPrintable)
    );
}

#[test]
fn un_tampon_trop_court_est_une_erreur_pas_un_nom_tronque() {
    let entier = "a.test!b.test!1!2.json.gz";
    for taille in 0..entier.len() {
        let mut place = std::vec![0_u8; taille];
        assert_eq!(
            filename("a.test", "b.test", 1, 2, &mut place),
            Err(Error::BufferTooSmall),
            "à {taille} octets"
        );
    }
    let entier = "Report Domain: a.test Submitter: b.test Report-ID: x";
    for taille in 0..entier.len() {
        let mut place = std::vec![0_u8; taille];
        assert_eq!(
            subject("a.test", "b.test", "x", &mut place),
            Err(Error::BufferTooSmall),
            "à {taille} octets"
        );
    }
}

#[test]
fn un_instant_a_zero_ou_demesure_s_ecrit() {
    let mut place = [0_u8; FILENAME_MAX];
    let nom = filename("a.test", "b.test", 0, u64::MAX, &mut place).expect("nommable");
    assert_eq!(nom, "a.test!b.test!0!18446744073709551615.json.gz");
}
