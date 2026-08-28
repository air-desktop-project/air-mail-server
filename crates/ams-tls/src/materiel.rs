//! Du PEM vers un `ServerConfig` : le seul endroit qui assemble TLS.
//!
//! # Pourquoi cette fonction existe plutôt que six lignes recopiées
//!
//! Assembler un `ServerConfig` tient en six lignes, et c'est exactement le
//! problème : six lignes se recopient, et la copie qui oublie
//! `with_protocol_versions(&[&TLS13])` sert du TLS 1.2 sans que personne ne s'en
//! aperçoive. C4 vaut mieux qu'un copier-coller discipliné.
//!
//! Le matériel arrive en **octets**, pas en chemins : lire un fichier est une
//! entrée-sortie, et C1 l'interdit ici. C'est l'appelant qui lit, et c'est aussi
//! lui qui décide ce qu'il refuse — les permissions d'une clé privée, par
//! exemple, ne se jugent pas sans système de fichiers.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use rustls::ServerConfig;
use rustls::pki_types::pem::{self, PemObject as _};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::provider;

/// Ce qui rend un matériel TLS inutilisable.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// La chaîne de certificats ne se lit pas, ou ne contient rien.
    Certificate(pem::Error),
    /// La clé privée ne se lit pas.
    PrivateKey(pem::Error),
    /// Le fournisseur n'a pas su charger la clé.
    ///
    /// # Ce que ce contrôle N'ATTRAPE PAS, et il faut le savoir
    ///
    /// `rustls` documente que `with_single_cert` échoue « si la clé publique de
    /// la clé privée ne correspond pas au certificat de tête ». **Ce n'est pas
    /// vrai avec `rustls-rustcrypto`** : sa clé de signature ne sait pas rendre
    /// sa clé publique, si bien que la comparaison est silencieusement sautée.
    /// Mesuré, pas supposé — voir `tests/materiel.rs`.
    ///
    /// La conséquence est opérationnelle : un renouvellement qui remplace le
    /// certificat sans la clé (ou l'inverse) donne un serveur **qui démarre** et
    /// dont **toutes** les poignées de main échouent. Le symptôme est alors très
    /// loin de la cause. C'est un des prix du fournisseur pur Rust, et il est
    /// consigné dans le registre des contraintes plutôt que découvert un jour de
    /// renouvellement.
    Rejected(rustls::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Certificate(cause) => write!(f, "chaîne de certificats illisible : {cause}"),
            Error::PrivateKey(cause) => write!(f, "clé privée illisible : {cause}"),
            Error::Rejected(cause) => write!(
                f,
                "clé refusée par le fournisseur cryptographique : {cause}                  (une clé valide mais ÉTRANGÈRE au certificat, elle, n'est PAS                  détectée ici — voir la documentation de cette variante)"
            ),
        }
    }
}

impl core::error::Error for Error {}

/// Assemble un `ServerConfig` à partir d'une chaîne et d'une clé, en PEM.
///
/// La configuration rendue est **TLS 1.3 uniquement** (C4) et offre
/// `X25519MLKEM768` en tête (C14) : c'est [`provider`] qui le garantit, et
/// `with_protocol_versions` qui le redit.
///
/// # Errors
///
/// [`Error`] — chaîne illisible ou vide, clé illisible, ou clé qui ne
/// correspond pas au certificat de tête.
pub fn server_config(chain_pem: &[u8], key_pem: &[u8]) -> Result<ServerConfig, Error> {
    let chaine: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(chain_pem)
        .collect::<Result<_, _>>()
        .map_err(Error::Certificate)?;
    // Un fichier sans le moindre bloc `CERTIFICATE` passe l'itération sans rien
    // rendre. Le laisser filer donnerait un serveur sans certificat, qui
    // échouerait à la première poignée de main au lieu de refuser de démarrer.
    if chaine.is_empty() {
        return Err(Error::Certificate(pem::Error::NoItemsFound));
    }

    let cle = PrivateKeyDer::from_pem_slice(key_pem).map_err(Error::PrivateKey)?;

    ServerConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        // Ce `expect` ne peut pas se déclencher : il faudrait que le fournisseur
        // n'offre AUCUNE suite TLS 1.3, ce qu'un test de `provider` interdit
        // explicitement. Un `?` ouvrirait ici une branche qu'aucun test ne peut
        // atteindre — et C2 refuse les gardes inatteignables, qui ne sont pas
        // des gardes mais des affirmations non vérifiées.
        .expect("le fournisseur n'offre que des suites TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(chaine, cle)
        .map_err(Error::Rejected)
}

#[cfg(test)]
mod tests {
    use super::{Error, server_config};
    use alloc::format;

    /// Un bloc PEM bien formé qui ne contient pas ce qu'il annonce.
    const CERT_BIDON: &[u8] = b"-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n";

    /// Le genre d'une erreur, en TOTAL : chaque variante a son bras, et chacun
    /// est emprunté par un test. Un `matches!` dans une assertion laisserait au
    /// contraire un bras `_ => false` que rien n'atteint jamais, puisque
    /// l'assertion réussit — un trou de couverture né du test lui-même.
    fn genre(erreur: &Error) -> &'static str {
        match erreur {
            Error::Certificate(_) => "chaîne",
            Error::PrivateKey(_) => "clé",
            Error::Rejected(_) => "refus",
        }
    }

    #[test]
    fn une_chaine_illisible_est_refusee() {
        // ATTENTION À CE QUE CE TEST MESURE : du texte sans bloc `BEGIN` ne
        // produit aucune erreur d'analyse, il produit ZÉRO élément — et c'est le
        // contrôle de chaîne vide qui répond. Le vrai échec d'analyse a son
        // propre test ci-dessous.
        let erreur = server_config(b"ceci n'est pas du PEM", CERT_BIDON).expect_err("refusée");
        assert_eq!(genre(&erreur), "chaîne", "{erreur:?}");
        assert!(format!("{erreur}").contains("chaîne"));
    }

    #[test]
    fn une_chaine_vide_est_refusee_au_demarrage() {
        // Un fichier lisible mais sans certificat : le serveur qui l'accepterait
        // échouerait à la première poignée de main, loin de la cause.
        let erreur = server_config(b"", b"").expect_err("refusée");
        assert_eq!(genre(&erreur), "chaîne", "{erreur:?}");
    }

    #[test]
    fn un_bloc_de_certificat_illisible_est_refuse() {
        // Celui-ci, lui, échoue À L'ANALYSE : le bloc est annoncé, son contenu
        // n'est pas du base64.
        let casse: &[u8] = b"-----BEGIN CERTIFICATE-----\n@@@@\n-----END CERTIFICATE-----\n";
        let erreur = server_config(casse, CERT_BIDON).expect_err("refusée");
        assert_eq!(genre(&erreur), "chaîne", "{erreur:?}");
    }

    #[test]
    fn une_cle_illisible_est_refusee() {
        let erreur = server_config(CERT_BIDON, b"pas de clef ici").expect_err("refusée");
        assert_eq!(genre(&erreur), "clé", "{erreur:?}");
        assert!(format!("{erreur}").contains("clé privée"));
    }

    #[test]
    fn une_cle_que_le_fournisseur_ne_sait_pas_charger_est_refusee() {
        // Le bloc est du PEM bien formé, son contenu n'est pas une clé.
        let cle_bidon = b"-----BEGIN PRIVATE KEY-----\naGVsbG8=\n-----END PRIVATE KEY-----\n";
        let erreur = server_config(CERT_BIDON, cle_bidon).expect_err("refusée");
        assert_eq!(genre(&erreur), "refus", "{erreur:?}");
        assert!(format!("{erreur}").contains("refusée par le fournisseur"));
    }
}
