// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le banc du vérificateur d'identité.
//!
//! # LES CERTIFICATS SONT DE VRAIS CERTIFICATS
//!
//! `asl_cle::certificat_d_identite` est ce qu'un annuaire présente vraiment —
//! la même fonction, la même forme. Un certificat fabriqué ici à la main
//! éprouverait ce que nous croyons qu'un annuaire envoie.

use alloc::string::ToString as _;
use alloc::sync::Arc;
use alloc::vec::Vec;

use asl_cle::CleSecrete;
use rustls::client::danger::ServerCertVerifier as _;
use rustls::internal::msgs::codec::{Codec as _, Reader};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use super::{Asl, asl_config, nom_de_serveur};

/// Fabrique un `DigitallySignedStruct` à partir de sa forme sur le fil.
///
/// **SON CONSTRUCTEUR EST PRIVÉ** dans `rustls`, et la seule porte publique est
/// la lecture : on écrit les octets que TLS mettrait sur le fil — le schéma sur
/// deux octets, la longueur sur deux, la signature —, et on les relit. C'est la
/// même astuce, pour la même raison, que dans `relay/tests.rs`.
fn signature(scheme: SignatureScheme, octets: &[u8]) -> DigitallySignedStruct {
    let mut fil = Vec::new();
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

/// Un vérificateur qui n'accepte que ces clés.
fn monter(acceptees: &[&CleSecrete]) -> Asl {
    Asl {
        identites: acceptees
            .iter()
            .map(|cle| asl_cle::identifiant_de_racine(&cle.publique()))
            .collect(),
        fournisseur: Arc::new(crate::provider_quic()),
    }
}

/// Soumet cette chaîne au vérificateur. La tête d'abord, le reste en
/// intermédiaires.
fn juger(verificateur: &Asl, chaine: &[Vec<u8>]) -> bool {
    let (tete, suite) = chaine.split_first().expect("une tête");
    let suite: Vec<CertificateDer<'_>> = suite
        .iter()
        .map(|der| CertificateDer::from(der.as_slice()))
        .collect();
    verificateur
        .verify_server_cert(
            &CertificateDer::from(tete.as_slice()),
            &suite,
            &ServerName::try_from("127.0.0.1").expect("une adresse"),
            &[],
            UnixTime::now(),
        )
        .is_ok()
}

/// **LA CLÉ ATTENDUE PASSE.**
#[test]
fn la_cle_attendue_passe() {
    let racine = CleSecrete::depuis_entropie([0x61; 32]);
    let certificat = asl_cle::certificat_d_identite(&racine).to_vec();
    assert!(juger(
        &monter(&[&racine]),
        core::slice::from_ref(&certificat)
    ));
}

/// **N'IMPORTE LAQUELLE DE LA LISTE PASSE, ET PAS SEULEMENT LA PREMIÈRE.**
///
/// C'est le cas de `GET /v1/racines`, qui se vérifie contre toutes les racines
/// embarquées à la fois. Un vérificateur qui ne jugerait que la tête de la
/// liste accepterait une racine sur deux, et l'échec serait intermittent.
#[test]
fn n_importe_laquelle_de_la_liste_passe() {
    let une = CleSecrete::depuis_entropie([0x62; 32]);
    let autre = CleSecrete::depuis_entropie([0x63; 32]);
    let verificateur = monter(&[&une, &autre]);

    for cle in [&une, &autre] {
        let certificat = asl_cle::certificat_d_identite(cle).to_vec();
        assert!(juger(&verificateur, core::slice::from_ref(&certificat)));
    }
}

/// **UNE CLÉ INATTENDUE EST REFUSÉE.**
///
/// C'est tout ce que cette confiance fait : un certificat parfaitement valide,
/// émis par qui l'on veut, ne passe pas si sa clé ne rend pas l'identifiant
/// attendu.
#[test]
fn une_cle_inattendue_est_refusee() {
    let nous = CleSecrete::depuis_entropie([0x64; 32]);
    let inconnue = CleSecrete::depuis_entropie([0x65; 32]);
    let certificat = asl_cle::certificat_d_identite(&inconnue).to_vec();
    assert!(!juger(
        &monter(&[&nous]),
        core::slice::from_ref(&certificat)
    ));
}

/// **UNE CHAÎNE DE DEUX N'EST PAS UN CERTIFICAT D'IDENTITÉ**, même si sa tête
/// en porte un.
///
/// Accepter la tête d'une chaîne reviendrait à croire que quelqu'un d'autre
/// l'a émise — exactement ce que cette confiance refuse de consulter.
#[test]
fn une_chaine_de_deux_n_est_pas_un_certificat_d_identite() {
    let racine = CleSecrete::depuis_entropie([0x66; 32]);
    let certificat = asl_cle::certificat_d_identite(&racine).to_vec();
    assert!(!juger(
        &monter(&[&racine]),
        &[certificat.clone(), certificat]
    ));
}

/// **UNE LISTE VIDE NE SE MONTE PAS.**
///
/// Elle se monterait très bien et refuserait ensuite tout certificat : une
/// connexion qui ne peut pas aboutir, dont la cause serait cherchée dans le
/// réseau.
#[test]
fn rien_a_croire_ne_se_monte_pas() {
    let faute = asl_config(&[]).expect_err("rien à croire se refuse");
    assert!(
        matches!(faute, crate::MaterialError::SansIdentite),
        "la cause est nommée, non empruntée à une autre : {faute:?}"
    );
    assert!(
        faute.to_string().contains("cherchée dans le réseau"),
        "le refus dit ce qu'il évite de faire chercher : {faute}"
    );
}

/// **LA CONFIGURATION MONTÉE ANNONCE `h3`, ET RIEN D'AUTRE.**
///
/// §3.1 de RFC 9114 : sans cette ALPN, un serveur qui ne sert que HTTP/3
/// refuse la poignée de main. L'oublier se verrait à la première connexion, et
/// pas avant.
#[test]
fn la_configuration_annonce_h3() {
    let racine = CleSecrete::depuis_entropie([0x67; 32]);
    let identite = asl_cle::identifiant_de_racine(&racine.publique());

    let config = asl_config(&[identite]).expect("elle se monte");
    assert_eq!(config.alpn_protocols, crate::alpn_h3());
}

/// **TLS 1.2 EST REFUSÉ, ET LE REFUS NOMME SA CAUSE.**
///
/// QUIC n'existe qu'en TLS 1.3 (RFC 9001 §4.2). Une erreur générique
/// enverrait chercher une clé fausse là où il n'y a qu'une version de
/// protocole.
#[test]
fn tls12_est_refuse_en_nommant_quic() {
    let racine = CleSecrete::depuis_entropie([0x68; 32]);
    let certificat = asl_cle::certificat_d_identite(&racine).to_vec();
    let verificateur = monter(&[&racine]);

    let faute = verificateur
        .verify_tls12_signature(
            b"peu importe",
            &CertificateDer::from(certificat.as_slice()),
            &signature(SignatureScheme::ED25519, &[]),
        )
        .expect_err("TLS 1.2 n'a pas cours ici");
    assert!(
        matches!(faute, rustls::Error::PeerIncompatible(_)),
        "le refus doit nommer l'incompatibilité : {faute:?}"
    );
}

/// **LA PREUVE DE POSSESSION EST EXIGÉE, ET UNE FAUSSE SIGNATURE TOMBE.**
///
/// Reconnaître la clé ne suffit pas : n'importe qui peut rejouer un certificat
/// public. C'est la signature de la poignée de main, vérifiée contre cette
/// même clé, qui prouve qu'on parle au détenteur.
#[test]
fn une_signature_de_poignee_de_main_fausse_est_refusee() {
    let racine = CleSecrete::depuis_entropie([0x69; 32]);
    let certificat = asl_cle::certificat_d_identite(&racine).to_vec();
    let verificateur = monter(&[&racine]);

    assert!(
        verificateur
            .verify_tls13_signature(
                b"ce que la poignee de main couvre",
                &CertificateDer::from(certificat.as_slice()),
                &signature(SignatureScheme::ED25519, &[0_u8; 64]),
            )
            .is_err(),
        "soixante-quatre zéros ne sont pas une signature"
    );

    // **ET LES SCHÉMAS ANNONCÉS SONT CEUX DU FOURNISSEUR**, non une liste
    // écrite à la main qui divergerait de ce qu'il sait vérifier.
    assert!(
        verificateur
            .supported_verify_schemes()
            .contains(&SignatureScheme::ED25519),
        "un annuaire signe en Ed25519 : ce schéma doit être annoncé"
    );
}

/// **LE NOM DE SERVEUR EST UNE ADRESSE, JAMAIS UN NOM** (C20).
///
/// Envoyer un nom dans le SNI ferait voyager une information qu'ASL interdit
/// de produire — et que personne, au bout, ne vérifierait.
#[test]
fn le_nom_de_serveur_est_une_adresse() {
    for texte in ["192.0.2.9:6630", "[2001:db8::1dd4]:6630"] {
        let cible: core::net::SocketAddr = texte.parse().expect("une adresse");
        assert!(
            matches!(nom_de_serveur(cible), ServerName::IpAddress(_)),
            "sur {texte}"
        );
    }
}
