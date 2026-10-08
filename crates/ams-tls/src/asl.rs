// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La confiance d'`air-service-locator` : **ni autorité, ni nom — une clé**.
//!
//! # LE TROISIÈME VÉRIFICATEUR DE CE DÉPÔT, ET LE PLUS ÉTROIT
//!
//! [`relay_config`](crate::relay_config) croit le magasin du système,
//! [`dane_config`](crate::dane_config) croit un `TLSA` publié dans le DNS, et
//! celui-ci ne croit **rien de tout cela**. Un annuaire présente un certificat
//! **auto-signé**, et la seule question posée est : la clé de ce certificat se
//! déduit-elle en l'identifiant `n-…` que l'on attendait ?
//!
//! Ni nom, ni date, ni émetteur ne sont lus. C'est la contrainte C20 du dépôt
//! `air-service-locator` — **ASL fonctionne sans DNS** : les racines sont
//! embarquées dans la bibliothèque par leur identité et leurs adresses, et
//! aucun nom n'est résolu ni envoyé comme preuve. Un vérificateur qui
//! exigerait un nom rendrait cette propriété inatteignable.
//!
//! # LA MOITIÉ PURE VIENT DE LÀ-BAS, ET C'EST VOULU
//!
//! `asl_racines::identite_attendue` est la règle elle-même, écrite une fois
//! pour les deux dépôts, couverte et éprouvée chez elle. Sa documentation dit
//! exactement ce qui reste à faire ici : « c'est la moitié pure du
//! vérificateur : l'étage 3 y ajoute la preuve de possession (la signature de
//! la poignée de main contre cette même clé) ».
//!
//! Ce fichier ne fait donc que deux choses — reconnaître, puis exiger la
//! preuve — et c'est `rustls` qui fournit la seconde.
//!
//! # RECONNAÎTRE N'EST PAS CROIRE
//!
//! Un certificat dont la clé rend la bonne identité ne prouve encore rien :
//! n'importe qui peut rejouer un certificat public. Ce qui prouve la
//! possession est la **signature de la poignée de main**, vérifiée contre
//! cette même clé — et c'est pourquoi [`Asl::verify_tls13_signature`] n'est
//! pas un passe-droit mais la seconde moitié du jugement. Les deux séparées
//! laisseraient croire qu'une seule suffit.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::net::SocketAddr;

use asl_id::Identifiant;
use rustls::DigitallySignedStruct;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, SignatureScheme};

/// Monte la configuration TLS cliente qui ne croit que ces identités.
///
/// # IL N'Y A AUCUN TÉMOIN DE CE QUI A ÉTÉ JUGÉ, ET C'EST DÉLIBÉRÉ
///
/// La première écriture en portait un — un `Mutex` où le vérificateur
/// déposait l'identité reconnue. Deux raisons l'ont fait retirer, et la
/// seconde seule aurait suffi.
///
/// **Personne ne le lirait.** Un appelant joint UNE adresse en attendant UNE
/// identité : c'est la tournée qui essaie les annuaires l'un après l'autre, et
/// elle sait déjà lequel elle vient de composer. La liste est plurielle parce
/// que `GET /v1/racines` se vérifie contre toutes les racines embarquées à la
/// fois, et ce cas-là ne demande pas de savoir laquelle a répondu.
///
/// **Et il coûterait une dépendance.** Cette crate est `#![no_std]` : il n'y a
/// pas de `Mutex`, et `rustls` exige un vérificateur `Sync`. Il faudrait donc
/// faire entrer un verrou tiers dans la crate qui porte TOUT le TLS de ce
/// serveur — pour une information que personne ne consulte.
///
/// # L'ALPN EST POSÉE ICI, ET PAS AILLEURS
///
/// §3.1 de RFC 9114 : un client qui n'annonce pas `h3` voit sa poignée de main
/// refusée par un serveur qui ne sert que cela. La poser ici rend l'oubli
/// impossible — c'est la même raison qui met `alpn_h3` dans
/// [`quic_server_config`](crate::quic_server_config).
///
/// # UNE LISTE VIDE EST REFUSÉE
///
/// Elle se monterait très bien, et refuserait ensuite **tout** certificat : une
/// connexion qui ne peut pas aboutir, dont la cause serait cherchée dans le
/// réseau. Le refus est rendu à qui a écrit la configuration, dans sa main.
///
/// # Errors
///
/// [`crate::MaterialError::SansIdentite`], et elle seule : TLS 1.3 ne peut pas
/// être refusé par notre propre fournisseur, qui n'offre que cela.
pub fn asl_config(identites: &[Identifiant]) -> Result<Arc<ClientConfig>, crate::materiel::Error> {
    if identites.is_empty() {
        return Err(crate::materiel::Error::SansIdentite);
    }

    let fournisseur = Arc::new(crate::provider_quic());
    let verificateur = Asl {
        identites: identites.to_vec(),
        fournisseur: Arc::clone(&fournisseur),
    };

    let mut config = ClientConfig::builder_with_provider(fournisseur)
        .with_protocol_versions(&[&rustls::version::TLS13])
        // Ce `expect` ne peut pas se déclencher, pour la même raison que dans
        // `dane_config` : un essai de `provider` interdit qu'il n'offre aucune
        // suite TLS 1.3. Un `?` ouvrirait ici une branche que rien ne peut
        // emprunter, et le 100 % de couverture (C2) l'a dit.
        .expect("le fournisseur n'offre que des suites TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verificateur))
        .with_no_client_auth();
    config.alpn_protocols = crate::alpn_h3();
    Ok(Arc::new(config))
}

/// Le nom de serveur à donner à la poignée de main : **l'adresse, jamais un
/// nom**.
///
/// Un annuaire rend son certificat d'identité à qui vise une adresse, et c'est
/// ce certificat qu'on juge. Envoyer un nom dans le SNI ferait voyager une
/// information que C20 interdit de produire — et que personne, au bout, ne
/// vérifierait.
#[must_use]
pub fn nom_de_serveur(cible: SocketAddr) -> ServerName<'static> {
    ServerName::IpAddress(cible.ip().into())
}

/// Le vérificateur : un seul maillon, dont la clé est une identité attendue.
#[derive(Debug)]
struct Asl {
    /// Les identités qu'on accepte de trouver au bout.
    identites: Vec<Identifiant>,
    /// Le fournisseur, pour vérifier la signature de la poignée de main.
    fournisseur: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Asl {
    fn verify_server_cert(
        &self,
        certificat: &CertificateDer<'_>,
        intermediaires: &[CertificateDer<'_>],
        _nom: &ServerName<'_>,
        _ocsp: &[u8],
        _maintenant: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // **UN SEUL MAILLON, ET SA CLÉ EST L'IDENTITÉ.** Une chaîne de deux
        // n'est pas un certificat d'identité, même si sa tête en porte un :
        // accepter la tête d'une chaîne reviendrait à croire que quelqu'un
        // d'autre l'a émise, ce qui est exactement ce que cette confiance-ci
        // refuse de consulter.
        let maillons = intermediaires.len().saturating_add(1);
        if asl_racines::identite_attendue(maillons, certificat, &self.identites).is_none() {
            // **PAS DE DÉTAIL DANS LE REFUS.** `rustls` le rend au pair, et
            // distinguer « clé inconnue » de « chaîne trop longue » lui dirait
            // quelles identités nous attendons.
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _certificat: &CertificateDer<'_>,
        _signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // QUIC n'existe qu'en TLS 1.3 (RFC 9001 §4.2), et ce vérificateur ne
        // sert que QUIC. Le refus nomme la cause plutôt que de rendre une
        // erreur générique.
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls13RequiredForQuic,
        ))
    }

    /// **LA PREUVE DE POSSESSION**, et la seconde moitié du jugement.
    ///
    /// La signature de la poignée de main, vérifiée contre la clé du
    /// certificat — celle qu'on vient de reconnaître. Sans elle, un certificat
    /// public rejoué suffirait à se faire passer pour un annuaire.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificat: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            certificat,
            signature,
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
