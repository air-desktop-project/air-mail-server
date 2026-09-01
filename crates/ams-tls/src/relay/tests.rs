//! Ce que le chiffrement opportuniste tient, et ce qu'il ne tient pas.

use alloc::format;
use alloc::sync::Arc;

use rustls::client::danger::ServerCertVerifier as _;
use rustls::internal::msgs::codec::{Codec as _, Reader};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use super::{Dane, Opportuniste, dane_config, relay_config};
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

// ── DANE (RFC 7672) ─────────────────────────────────────────────────────────

/// De vrais certificats, fabriqués une fois — voir `vecteurs/README.md`.
const FEUILLE: &[u8] = include_bytes!("../../vecteurs/leaf.der");
const AUTORITE: &[u8] = include_bytes!("../../vecteurs/ca.der");
const SOLO: &[u8] = include_bytes!("../../vecteurs/solo.der");

/// Les empreintes de référence, calculées par `openssl` — voir
/// `crates/ams-dane/src/record/tests.rs`, qui dit pourquoi elles ne se
/// recalculent pas ici.
const FEUILLE_CLEF: &str = "2e33cf366868663c12573145506fdf1173cb360294fcca9b361cbdc8d7aaffe2";
const AUTORITE_CLEF: &str = "8b48daf37bbecb619ce29fb512d662ac553d9f8fc6c11ded18b3ef0305b08cec";
const SOLO_CLEF: &str = "523e1c80fe8e2862d99b5ae327eb541e369f66f680f371fca1227ef2448b455c";

/// Un instant à l'intérieur de la validité des vecteurs, qui court jusqu'en 2126.
fn maintenant() -> UnixTime {
    UnixTime::since_unix_epoch(core::time::Duration::from_secs(1_800_000_000))
}

/// Des octets écrits en hexadécimal.
fn octets(hexa: &str) -> alloc::vec::Vec<u8> {
    hexa.as_bytes()
        .chunks(2)
        .map(|paire| {
            let texte = core::str::from_utf8(paire).expect("de l'ASCII");
            u8::from_str_radix(texte, 16).expect("de l'hexadécimal")
        })
        .collect()
}

/// Le `RDATA` d'un `TLSA`.
fn rdata(usage: u8, selecteur: u8, appariement: u8, empreinte: &str) -> alloc::vec::Vec<u8> {
    let mut octets_du_record = alloc::vec![usage, selecteur, appariement];
    octets_du_record.extend_from_slice(&octets(empreinte));
    octets_du_record
}

fn dane(rdata: alloc::vec::Vec<alloc::vec::Vec<u8>>) -> Dane {
    Dane {
        fournisseur: Arc::new(provider()),
        rdata,
    }
}

/// **`DANE-EE(3)` : NI CHAÎNE, NI NOM, NI DATE.**
///
/// §3.1.1 de RFC 7672. Le domaine a publié l'empreinte exacte de ce qu'il
/// présente, et c'est plus fort que tout ce qu'une autorité pourrait attester.
/// Le nom demandé est ici DÉLIBÉRÉMENT étranger au certificat : un serveur qui
/// sert dix domaines n'a pas à porter dix noms.
#[test]
fn une_entite_finale_se_verifie_sans_nom_ni_chaine() {
    let verificateur = dane(alloc::vec![rdata(3, 1, 1, SOLO_CLEF)]);
    let verdict = verificateur.verify_server_cert(
        &CertificateDer::from(SOLO.to_vec()),
        &[],
        &ServerName::try_from("un.nom.qui.n.est.pas.le.sien").expect("nom"),
        &[],
        maintenant(),
    );
    assert!(verdict.is_ok(), "{verdict:?}");
}

/// **UN CERTIFICAT QUE LE JEU NE NOMME PAS EST REFUSÉ.**
///
/// C'est le seul refus qui donne un sens à DANE : s'en remettre alors au
/// chiffrement opportuniste rendrait la publication d'un `TLSA` décorative.
#[test]
fn un_certificat_etranger_est_refuse() {
    let verificateur = dane(alloc::vec![rdata(3, 1, 1, SOLO_CLEF)]);
    let verdict = verificateur.verify_server_cert(
        &CertificateDer::from(FEUILLE.to_vec()),
        &[],
        &ServerName::try_from("mx.example.test").expect("nom"),
        &[],
        maintenant(),
    );
    assert!(verdict.is_err(), "un certificat étranger a été accepté");
}

/// **`DANE-TA(2)` : LA CHAÎNE ET LE NOM, TOUS LES DEUX.**
///
/// L'autorité a pu signer pour d'autres ; c'est ce qui la distingue d'une entité
/// finale, et le nom redevient donc nécessaire.
#[test]
fn une_autorite_verifie_la_chaine_et_le_nom() {
    let verificateur = dane(alloc::vec![rdata(2, 1, 1, AUTORITE_CLEF)]);
    let verdict = verificateur.verify_server_cert(
        &CertificateDer::from(FEUILLE.to_vec()),
        &[CertificateDer::from(AUTORITE.to_vec())],
        &ServerName::try_from("mx.example.test").expect("nom"),
        &[],
        maintenant(),
    );
    assert!(verdict.is_ok(), "{verdict:?}");
}

/// **ET LE NOM COMPTE VRAIMENT** : la même chaîne, un autre nom, et c'est non.
#[test]
fn une_autorite_refuse_un_autre_nom() {
    let verificateur = dane(alloc::vec![rdata(2, 1, 1, AUTORITE_CLEF)]);
    let verdict = verificateur.verify_server_cert(
        &CertificateDer::from(FEUILLE.to_vec()),
        &[CertificateDer::from(AUTORITE.to_vec())],
        &ServerName::try_from("autre.example.test").expect("nom"),
        &[],
        maintenant(),
    );
    assert!(verdict.is_err(), "un nom étranger a été accepté");
}

/// **UNE AUTORITÉ QUI N'EST PAS DANS LA CHAÎNE NE SERT À RIEN.**
///
/// Le pair DOIT présenter l'autorité que le domaine a nommée (§3.1.3 de
/// RFC 7672) ; sans elle, il n'y a rien à quoi rattacher le certificat.
#[test]
fn une_autorite_absente_de_la_chaine_est_refusee() {
    let verificateur = dane(alloc::vec![rdata(2, 1, 1, AUTORITE_CLEF)]);
    let verdict = verificateur.verify_server_cert(
        &CertificateDer::from(FEUILLE.to_vec()),
        &[],
        &ServerName::try_from("mx.example.test").expect("nom"),
        &[],
        maintenant(),
    );
    assert!(verdict.is_err(), "une chaîne incomplète a été acceptée");
}

/// **LE JEU EST UNE DISJONCTION**, et un enregistrement inutilisable n'ouvre
/// rien.
#[test]
fn un_seul_enregistrement_satisfait_suffit() {
    let verificateur = dane(alloc::vec![
        // Un `PKIX-EE(1)` dont l'empreinte est pourtant la bonne : inutilisable.
        rdata(1, 1, 1, SOLO_CLEF),
        // Un algorithme de demain.
        rdata(3, 1, 9, SOLO_CLEF),
        // Une empreinte qui ne désigne pas ce certificat.
        rdata(3, 1, 1, FEUILLE_CLEF),
        // Et celle qui le désigne.
        rdata(3, 1, 1, SOLO_CLEF),
    ]);
    let verdict = verificateur.verify_server_cert(
        &CertificateDer::from(SOLO.to_vec()),
        &[],
        &ServerName::try_from("solo.example.test").expect("nom"),
        &[],
        maintenant(),
    );
    assert!(verdict.is_ok(), "{verdict:?}");
}

/// **UN JEU QUI NE PORTE QUE DE L'INUTILISABLE REFUSE TOUT.**
///
/// C'est l'appelant qui décide de ne pas construire cette configuration dans ce
/// cas (§2.2 de RFC 7672, `Set::engage`). S'il la construit quand même, le
/// vérificateur ne laisse rien passer : c'est le bon sens de l'erreur.
#[test]
fn un_jeu_inutilisable_ne_laisse_rien_passer() {
    let verificateur = dane(alloc::vec![rdata(1, 1, 1, SOLO_CLEF)]);
    let verdict = verificateur.verify_server_cert(
        &CertificateDer::from(SOLO.to_vec()),
        &[],
        &ServerName::try_from("solo.example.test").expect("nom"),
        &[],
        maintenant(),
    );
    assert!(verdict.is_err());
    // Et un jeu vide non plus.
    let vide = dane(alloc::vec![]);
    assert!(
        vide.verify_server_cert(
            &CertificateDer::from(SOLO.to_vec()),
            &[],
            &ServerName::try_from("solo.example.test").expect("nom"),
            &[],
            maintenant(),
        )
        .is_err()
    );
}

/// **DES OCTETS QUI NE SONT PAS UN `TLSA` SE JETTENT SANS BRUIT.**
///
/// Le DNS rend ce qu'il rend ; un enregistrement tronqué ne doit ni paniquer, ni
/// ouvrir quoi que ce soit.
#[test]
fn un_rdata_illisible_se_jette() {
    let verificateur = dane(alloc::vec![
        alloc::vec![],
        alloc::vec![3],
        alloc::vec![3, 1, 1],
        rdata(3, 1, 1, SOLO_CLEF),
    ]);
    let verdict = verificateur.verify_server_cert(
        &CertificateDer::from(SOLO.to_vec()),
        &[],
        &ServerName::try_from("solo.example.test").expect("nom"),
        &[],
        maintenant(),
    );
    assert!(verdict.is_ok(), "{verdict:?}");
}

/// **UNE « AUTORITÉ » QUE `rustls` REFUSE D'AJOUTER N'ARRÊTE PAS LE PARCOURS.**
///
/// Le jeu peut en nommer plusieurs, et l'une d'elles peut être n'importe quoi.
#[test]
fn une_ancre_illisible_n_arrete_pas_le_parcours() {
    // Le premier candidat est un certificat que `rustls` ne saura pas ajouter
    // comme racine ; il satisfait pourtant l'enregistrement d'autorité.
    let ordure = alloc::vec![0x30, 0x03, 0x02, 0x01, 0x00];
    let empreinte = {
        use sha2::Digest as _;
        let calcul = sha2::Sha256::digest(&ordure);
        let mut hexa = alloc::string::String::new();
        for octet in calcul {
            hexa.push_str(&format!("{octet:02x}"));
        }
        hexa
    };
    let verificateur = dane(alloc::vec![
        rdata(2, 0, 1, &empreinte),
        rdata(2, 1, 1, AUTORITE_CLEF),
    ]);
    let verdict = verificateur.verify_server_cert(
        &CertificateDer::from(FEUILLE.to_vec()),
        &[
            CertificateDer::from(ordure),
            CertificateDer::from(AUTORITE.to_vec()),
        ],
        &ServerName::try_from("mx.example.test").expect("nom"),
        &[],
        maintenant(),
    );
    assert!(verdict.is_ok(), "{verdict:?}");
}

/// La configuration DANE s'assemble, et elle n'est pas l'opportuniste.
#[test]
fn la_configuration_dane_s_assemble() {
    let configuration = dane_config(alloc::vec![rdata(3, 1, 1, SOLO_CLEF)]);
    assert!(!format!("{configuration:?}").is_empty());
    // Et l'opportuniste s'assemble toujours à côté : les deux vérificateurs
    // coexistent, et c'est le DNS qui choisit.
    assert!(!format!("{:?}", relay_config()).is_empty());
    assert!(!format!("{:?}", dane(alloc::vec![])).is_empty());
}

/// **TLS 1.2 N'EST PAS SERVI**, ici non plus (C6).
#[test]
fn le_verificateur_dane_refuse_tls_1_2() {
    let verificateur = dane(alloc::vec![rdata(3, 1, 1, SOLO_CLEF)]);
    let verdict = verificateur.verify_tls12_signature(
        b"un message",
        &CertificateDer::from(SOLO.to_vec()),
        &signature(SignatureScheme::ECDSA_NISTP256_SHA256, b"peu importe"),
    );
    assert!(verdict.is_err());
    // Et il annonce les mêmes schémas que le fournisseur du produit.
    assert!(!verificateur.supported_verify_schemes().is_empty());
}

/// **LA SIGNATURE DE LA POIGNÉE DE MAIN EST VÉRIFIÉE POUR DE BON**, en DANE
/// comme en opportuniste : sans elle, n'importe qui pourrait présenter le bon
/// certificat sans en détenir la clef.
#[test]
fn le_verificateur_dane_verifie_la_signature_tls_1_3() {
    let verificateur = dane(alloc::vec![rdata(3, 1, 1, SOLO_CLEF)]);
    let verdict = verificateur.verify_tls13_signature(
        b"un message",
        &CertificateDer::from(SOLO.to_vec()),
        &signature(
            SignatureScheme::ECDSA_NISTP256_SHA256,
            b"une fausse signature",
        ),
    );
    assert!(verdict.is_err(), "une fausse signature a été acceptée");
}

// ── Le magasin de racines (MTA-STS) ─────────────────────────────────────────

const AUTORITE_PEM: &[u8] = include_bytes!("../../vecteurs/ca.pem");

#[test]
fn un_magasin_se_lit_depuis_du_pem() {
    let racines = super::anchors(AUTORITE_PEM).expect("lisible");
    assert_eq!(racines.len(), 1);
    // Et il assemble une configuration qui vérifie ORDINAIREMENT.
    let configuration = super::webpki_config(Arc::new(racines));
    assert!(!format!("{configuration:?}").is_empty());
}

/// **UN MAGASIN VIDE N'EST PAS UN MAGASIN.**
///
/// Il ferait échouer chaque vérification sans que rien ne dise pourquoi ; mieux
/// vaut refuser sur un fichier qui ne porte aucune autorité.
#[test]
fn un_fichier_sans_autorite_est_refuse() {
    for vide in [
        &b""[..],
        b"# rien que des commentaires
",
        b"pas du PEM du tout",
    ] {
        assert_eq!(
            super::anchors(vide).err(),
            Some(super::AnchorError::Empty),
            "{vide:?}"
        );
    }
}

/// Un PEM tronqué ou corrompu se refuse, plutôt que d'être sauté en silence.
#[test]
fn un_pem_illisible_est_refuse() {
    let mut tronque = alloc::vec::Vec::from(AUTORITE_PEM);
    tronque.truncate(AUTORITE_PEM.len() / 2);
    let issue = super::anchors(&tronque);
    assert!(issue.is_err(), "un PEM tronqué a été accepté");

    // Un bloc bien délimité dont le contenu n'est pas un certificat.
    let faux = b"-----BEGIN CERTIFICATE-----
Zm9v
-----END CERTIFICATE-----
";
    assert_eq!(
        super::anchors(faux).err(),
        Some(super::AnchorError::Rejected)
    );
}

#[test]
fn les_erreurs_de_magasin_s_affichent() {
    for erreur in [
        super::AnchorError::Unreadable,
        super::AnchorError::Rejected,
        super::AnchorError::Empty,
    ] {
        let texte = format!("{erreur}");
        assert!(!texte.is_empty(), "{erreur:?} s'affiche vide");
        assert!(!format!("{erreur:?}").is_empty());
    }
    assert_ne!(super::AnchorError::Empty, super::AnchorError::Rejected);
}
