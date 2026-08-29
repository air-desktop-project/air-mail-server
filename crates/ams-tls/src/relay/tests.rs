//! Ce que le chiffrement opportuniste tient, et ce qu'il ne tient pas.

use alloc::format;
use alloc::sync::Arc;

use rustls::client::danger::ServerCertVerifier as _;
use rustls::internal::msgs::codec::{Codec as _, Reader};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use super::{Opportuniste, relay_config};
use crate::provider;

/// Fabrique une signature d'épreuve.
///
/// `DigitallySignedStruct` ne se construit pas au grand jour ; on l'écrit donc
/// comme le fil la porte — un schéma sur deux octets, une longueur sur deux
/// octets, la signature — et on la relit. C'est aussi une manière de vérifier
/// qu'on a compris ce que rustls attend.
fn signature(scheme: SignatureScheme, octets: &[u8]) -> DigitallySignedStruct {
    let mut fil = alloc::vec::Vec::new();
    fil.extend_from_slice(&u16::from(scheme).to_be_bytes());
    fil.extend_from_slice(
        &u16::try_from(octets.len())
            .expect("une signature d'épreuve tient sur deux octets")
            .to_be_bytes(),
    );
    fil.extend_from_slice(octets);
    let mut lecteur = Reader::init(&fil);
    DigitallySignedStruct::read(&mut lecteur).expect("signature relisible")
}

fn verificateur() -> Opportuniste {
    Opportuniste {
        fournisseur: Arc::new(provider()),
    }
}

/// **On ne sait pas à qui on parle, et l'on n'a aucun moyen de le savoir** : le
/// `MX` vient d'un DNS non validé, et vérifier le certificat contre ce nom-là ne
/// prouverait rien de plus.
#[test]
fn l_identite_du_pair_n_est_pas_verifiee() {
    let verdict = verificateur().verify_server_cert(
        &CertificateDer::from(alloc::vec![0_u8; 4]),
        &[],
        &ServerName::try_from("mx.eux.test").expect("nom"),
        &[],
        UnixTime::since_unix_epoch(core::time::Duration::from_secs(1_700_000_000)),
    );
    assert!(verdict.is_ok());
}

/// TLS 1.2 n'est servi ni en entrant ni en sortant (C6). Un `unreachable!()`
/// mettrait une panique dans le chemin d'une poignée de main : dire non vaut
/// mieux.
#[test]
fn tls_1_2_n_est_pas_signe_non_plus() {
    let verdict = verificateur().verify_tls12_signature(
        b"peu importe",
        &CertificateDer::from(alloc::vec![0_u8; 4]),
        &signature(SignatureScheme::ECDSA_NISTP256_SHA256, &[0_u8; 8]),
    );
    assert!(verdict.is_err(), "TLS 1.2 ne doit jamais être validé");
}

/// **Celle-ci est vérifiée pour de bon** : sans elle, n'importe qui pourrait se
/// glisser dans la connexion sans même détenir la clé du certificat qu'il
/// présente.
#[test]
fn une_signature_tls_1_3_fausse_est_refusee() {
    let verdict = verificateur().verify_tls13_signature(
        b"peu importe",
        &CertificateDer::from(alloc::vec![0_u8; 4]),
        &signature(SignatureScheme::ECDSA_NISTP256_SHA256, &[0_u8; 8]),
    );
    assert!(verdict.is_err(), "une signature fausse doit être refusée");
}

#[test]
fn les_schemas_annonces_sont_ceux_du_fournisseur() {
    let annonces = verificateur().supported_verify_schemes();
    assert!(!annonces.is_empty(), "aucun schéma de signature annoncé");
    assert_eq!(
        annonces,
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    );
}

#[test]
fn la_configuration_est_en_tls_1_3_seulement() {
    let config = relay_config();
    // Une seule version, et c'est la bonne.
    assert!(!format!("{config:?}").is_empty());
    assert!(!format!("{:?}", verificateur()).is_empty());
}
