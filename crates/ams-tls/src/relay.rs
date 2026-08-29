//! Le matériel TLS pour **émettre** : le chiffrement opportuniste (RFC 7435).
//!
//! # CE CHIFFREMENT N'AUTHENTIFIE PERSONNE, ET C'EST DIT ICI
//!
//! Quand ce serveur remet du courrier à un autre, il chiffre s'il le peut. Il ne
//! **vérifie pas** le certificat du pair, et il faut comprendre exactement
//! pourquoi avant de crier au scandale.
//!
//! Le serveur auquel on remet est désigné par un enregistrement `MX`, lu dans un
//! DNS **qui n'est pas validé** (pas de DNSSEC ici). Un tiers qui peut détourner
//! cette résolution peut aussi bien se présenter avec un certificat parfaitement
//! valide pour le nom qu'il vient de fabriquer. **Vérifier le certificat contre
//! le nom `MX` ne prouve donc rien de plus que de ne pas le vérifier** : la
//! chaîne de confiance s'arrête un cran plus tôt, dans le DNS.
//!
//! Ce qu'il faudrait pour authentifier vraiment, ce sont DANE (RFC 7672, qui
//! demande DNSSEC) ou MTA-STS (RFC 8461, qui demande HTTPS et une politique
//! publiée). **Aucun des deux n'est ici**, et les nommer vaut mieux que de
//! laisser croire à une protection qui n'existe pas.
//!
//! # Alors à quoi sert-il ?
//!
//! À la même chose que partout : **passer d'un espion passif à un attaquant
//! actif**. Lire le courrier de tout le monde sur un lien devient impossible ;
//! il faut désormais s'insérer dans chaque connexion, ce qui se voit et ce qui
//! coûte. C'est la thèse de la RFC 7435 — « une protection imparfaite vaut mieux
//! que pas de protection » — et c'est aussi pourquoi elle ne doit **jamais** être
//! présentée comme une authentification.
//!
//! # Ce qui n'est PAS opportuniste ici
//!
//! **Le repli.** Un serveur qui annonce `STARTTLS` puis refuse la poignée de
//! main ne nous fera pas parler en clair : c'est exactement le levier d'une
//! attaque par déclassement, et il est fermé dans `ams-session`. De même, TLS
//! 1.3 reste le plancher (C6) — un pair qui ne sait pas le faire n'est pas servi,
//! fût-ce au prix de quelques remises manquées.

use alloc::sync::Arc;
use alloc::vec::Vec;

use rustls::ClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, PeerIncompatible, SignatureScheme};

use crate::provider;

/// Assemble un `ClientConfig` pour remettre du courrier.
///
/// **TLS 1.3 uniquement** (C4), `X25519MLKEM768` en tête (C14), et **aucune
/// authentification du pair** — voir la documentation du module, qui dit
/// pourquoi et ce que cela ne protège pas.
#[must_use]
pub fn relay_config() -> ClientConfig {
    let fournisseur = Arc::new(provider());
    ClientConfig::builder_with_provider(Arc::clone(&fournisseur))
        .with_protocol_versions(&[&rustls::version::TLS13])
        // Ce `expect` ne peut pas se déclencher : il faudrait que le fournisseur
        // n'offre AUCUNE suite TLS 1.3, ce qu'un test de `provider` interdit
        // explicitement. Un `?` ouvrirait ici une branche qu'aucun test ne peut
        // atteindre, et C2 refuse les gardes inatteignables.
        .expect("le fournisseur n'offre que des suites TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Opportuniste { fournisseur }))
        .with_no_client_auth()
}

/// Le vérificateur qui **ne vérifie pas l'identité**, et vérifie tout le reste.
///
/// La distinction est celle qui compte : la signature de la poignée de main est
/// contrôlée — sans quoi le chiffrement ne tiendrait devant personne — et seule
/// la question « ce certificat est-il celui de ce nom-là ? » est laissée sans
/// réponse, faute d'une chaîne de confiance pour y répondre.
#[derive(Debug)]
struct Opportuniste {
    fournisseur: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Opportuniste {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // On ne sait pas à qui on parle, et l'on n'a aucun moyen de le savoir.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // TLS 1.2 N'EST PAS SERVI (C6), ni en entrant ni en sortant. rustls ne
        // devrait jamais appeler ceci, la version étant déjà refusée à la
        // négociation ; un `unreachable!()` mettrait une panique dans le chemin
        // d'une poignée de main, ce qui est pire que de dire non.
        Err(rustls::Error::PeerIncompatible(
            PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // CELLE-CI EST VÉRIFIÉE POUR DE BON. Sans elle, n'importe qui pourrait
        // se glisser dans la connexion sans même détenir la clé du certificat
        // qu'il présente, et le chiffrement ne vaudrait plus rien du tout.
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.fournisseur.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.fournisseur
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests;
