//! Ce qui sépare un rapport d'une nuisance.

use super::{VERIFICATION_NAME_MAX, authorizes, needs_verification, verification_name};
use crate::Error;

#[test]
fn une_destination_chez_soi_ne_demande_rien() {
    assert!(!needs_verification(b"example.com", b"example.com"));
    assert!(!needs_verification(b"example.com", b"EXAMPLE.COM"));
}

/// **On compare les domaines, pas leurs domaines organisationnels.** Se tromper
/// dans le sens strict coûte une interrogation ; se tromper dans l'autre
/// autorise un envoi que personne n'a accepté.
#[test]
fn un_sous_domaine_est_une_destination_externe() {
    assert!(needs_verification(b"example.com", b"rapports.example.com"));
    assert!(needs_verification(b"example.com", b"autre.test"));
}

#[test]
fn le_nom_a_interroger_est_sous_le_domaine_de_la_destination() {
    let mut tampon = [0_u8; VERIFICATION_NAME_MAX];
    let nom = verification_name(b"appat.example", b"banque.test", &mut tampon).expect("nommable");
    assert_eq!(nom, b"appat.example._report._dmarc.banque.test");
}

/// C'est tout le mécanisme : ce nom-là, l'attaquant ne peut pas le publier.
#[test]
fn c_est_ce_nom_que_l_attaquant_ne_peut_pas_publier() {
    let mut tampon = [0_u8; VERIFICATION_NAME_MAX];
    let nom = verification_name(b"appat.example", b"banque.test", &mut tampon).expect("nommable");
    let suffixe = b"banque.test";
    assert!(
        nom.ends_with(suffixe),
        "le nom doit être dans la zone de la victime, pas dans celle de l'attaquant"
    );
}

#[test]
fn un_domaine_trop_long_ne_se_nomme_pas() {
    let long = [b'a'; 256];
    let mut tampon = [0_u8; VERIFICATION_NAME_MAX];
    assert_eq!(
        verification_name(&long, b"x.test", &mut tampon),
        Err(Error::DomainTooLong)
    );
    assert_eq!(
        verification_name(b"x.test", &long, &mut tampon),
        Err(Error::DomainTooLong)
    );
}

#[test]
fn un_tampon_trop_court_le_dit() {
    let mut tampon = [0_u8; 8];
    assert_eq!(
        verification_name(b"a.test", b"b.test", &mut tampon),
        Err(Error::BufferTooSmall)
    );
}

/// §7.1 : l'enregistrement de consentement n'a pas à porter de politique. Le
/// passer à `Record::parse` le ferait écarter pour `p=` manquant, et le
/// consentement d'un domaine correctement configuré serait lu comme un refus.
#[test]
fn la_version_seule_suffit_a_consentir() {
    assert!(authorizes(b"v=DMARC1"));
    assert!(authorizes(b"v=DMARC1;"));
    assert!(authorizes(b"v=dmarc1; rua=mailto:ailleurs@x.test"));
    assert!(authorizes(b" V = DMARC1 "));
    assert!(crate::Record::parse(b"v=DMARC1").is_err());
}

#[test]
fn ce_qui_n_est_pas_un_consentement_n_en_est_pas_un() {
    for texte in [
        &b""[..],
        b"v=DMARC2",
        b"v=spf1 -all",
        b"p=none; v=DMARC1",
        b"pas une liste",
        b"=DMARC1",
    ] {
        assert!(!authorizes(texte), "{texte:?}");
    }
}
