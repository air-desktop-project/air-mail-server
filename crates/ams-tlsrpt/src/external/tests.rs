//! Ce qui autorise un rapport à partir chez un tiers.

use super::{VERIFICATION_MAX, authorizes, needs_verification, verification_name};
use crate::Error;

/// **UN DOMAINE SE RAPPORTE À SOI SANS SE DONNER D'AUTORISATION.**
#[test]
fn le_domaine_lui_meme_ne_demande_rien() {
    assert!(!needs_verification("example.com", "example.com"));
    assert!(!needs_verification("example.com", "EXAMPLE.COM"));
    // Et un sous-domaine non plus.
    assert!(!needs_verification("example.com", "reports.example.com"));
    assert!(!needs_verification("example.com", "a.b.example.com"));
}

/// **LA COMPARAISON EST SUR LES ÉTIQUETTES, PAS SUR LES OCTETS.**
///
/// `mauvaisexample.com` se termine par `example.com` sans en être un
/// sous-domaine : le lire ainsi laisserait n'importe qui se dispenser de la
/// vérification en achetant le bon nom.
#[test]
fn un_suffixe_qui_n_est_pas_un_sous_domaine_demande_une_verification() {
    assert!(needs_verification("example.com", "mauvaisexample.com"));
    assert!(needs_verification("example.com", "ailleurs.test"));
    // Et l'inverse : le domaine rapporté n'est pas un sous-domaine de la
    // destination.
    assert!(needs_verification("reports.example.com", "example.com"));
    assert!(needs_verification("example.com", "com"));
}

#[test]
fn le_nom_de_verification_est_celui_de_la_rfc() {
    let mut place = [0_u8; VERIFICATION_MAX];
    let nom =
        verification_name("example.com", "reports.example.net", &mut place).expect("nommable");
    assert_eq!(nom, "example.com._report._smtp._tls.reports.example.net");
}

#[test]
fn un_nom_qui_n_en_est_pas_un_est_refuse() {
    let mut place = [0_u8; VERIFICATION_MAX];
    for mauvais in ["", ".example.com", "example.com.", "a b", "a/b", "é"] {
        assert_eq!(
            verification_name(mauvais, "x.test", &mut place),
            Err(Error::NotPrintable),
            "rapporté « {mauvais} »"
        );
        assert_eq!(
            verification_name("x.test", mauvais, &mut place),
            Err(Error::NotPrintable),
            "destination « {mauvais} »"
        );
    }
}

#[test]
fn un_tampon_trop_court_est_une_erreur() {
    let entier = "example.com._report._smtp._tls.reports.example.net";
    for taille in 0..entier.len() {
        let mut place = std::vec![0_u8; taille];
        assert_eq!(
            verification_name("example.com", "reports.example.net", &mut place),
            Err(Error::BufferTooSmall),
            "à {taille} octets"
        );
    }
}

/// **§3 : LA RÉPONSE DOIT PORTER `v=TLSRPTv1`.**
///
/// Rien d'autre n'est exigé, et rien d'autre n'est lu : un `rua=` dans une
/// réponse de vérification ne redirige pas le rapport ailleurs.
#[test]
fn seule_la_version_autorise() {
    assert!(authorizes("v=TLSRPTv1"));
    assert!(authorizes("v=TLSRPTv1;"));
    assert!(authorizes(" v=TLSRPTv1 ; rua=mailto:ignore@x.test"));
    for refuse in [
        "",
        "v=TLSRPTv2",
        "v=tlsrptv1",
        "rua=mailto:a@x.test; v=TLSRPTv1",
        "v=spf1 -all",
        "v=DMARC1",
    ] {
        assert!(!authorizes(refuse), "« {refuse} »");
    }
}
