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
//! # DANE REPREND LA CHAÎNE LÀ OÙ ELLE S'ARRÊTE
//!
//! Depuis le 2026-09-01, ce module offre un SECOND vérificateur :
//! [`dane_config`], pour les domaines qui publient un `TLSA` dans un DNS signé.
//! Le domaine dit lui-même quel certificat il présentera ; il n'y a plus de
//! tiers à croire, et le nom `MX` cesse d'être le maillon faible.
//!
//! **Les deux vérificateurs coexistent, et c'est le DNS qui choisit.** Un
//! domaine qui ne publie rien continue d'être servi en opportuniste ; un domaine
//! qui publie ENGAGE, et la remise est alors authentifiée ou n'a pas lieu
//! (§2.2 de RFC 7672). C'est l'appelant qui tranche — il est le seul à savoir si
//! la réponse DNS était authentifiée.
//!
//! MTA-STS (RFC 8461) reste à faire, et le nommer vaut mieux que de laisser
//! croire qu'il est là.
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

use ams_dane::{Match, Set, Tlsa};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, RootCertStore};
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

/// Assemble un `ClientConfig` qui EXIGE que le pair satisfasse ces `TLSA`.
///
/// `rdata` porte les `RDATA` bruts, tels que le DNS les a rendus. **C'est
/// l'appelant qui garantit qu'ils sont authentiques** — le bit `AD` d'un
/// résolveur valideur — et qui ne construit cette configuration que dans ce cas.
///
/// # POURQUOI LES OCTETS BRUTS, ET NON UN `Set` DÉJÀ DÉCODÉ
///
/// Un `ams_dane::Set` emprunte les octets qu'il décode. Ce vérificateur, lui,
/// vit dans un `Arc` à l'intérieur d'une configuration rustls, aussi longtemps
/// qu'elle : il ne peut rien emprunter. Il garde donc les octets, et redécode à
/// chaque poignée de main — quelques dizaines d'octets par connexion, contre une
/// structure qui se référencerait elle-même.
///
/// # CE QUI N'EST PLUS OPPORTUNISTE
///
/// Tout. Un pair qui ne satisfait aucun enregistrement voit sa poignée de main
/// REFUSÉE, et la remise est ajournée : le message reste en file et repartira
/// plus tard. §2.2 de RFC 7672 ne laisse pas le choix, et il n'y a **aucun
/// réglage** pour l'affaiblir — la même discipline que le refus de repli en
/// clair après un `STARTTLS` annoncé.
#[must_use]
pub fn dane_config(rdata: Vec<Vec<u8>>) -> ClientConfig {
    let fournisseur = Arc::new(provider());
    ClientConfig::builder_with_provider(Arc::clone(&fournisseur))
        .with_protocol_versions(&[&rustls::version::TLS13])
        // Ce `expect` ne peut pas se déclencher, pour la même raison que dans
        // `relay_config` : un test de `provider` interdit qu'il n'offre aucune
        // suite TLS 1.3.
        .expect("le fournisseur n'offre que des suites TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Dane { fournisseur, rdata }))
        .with_no_client_auth()
}

/// Le vérificateur qui exige un `TLSA`.
#[derive(Debug)]
struct Dane {
    fournisseur: Arc<CryptoProvider>,
    /// Les `RDATA` bruts, gardés parce qu'un `Set` emprunterait.
    rdata: Vec<Vec<u8>>,
}

impl Dane {
    /// Le jeu, redécodé pour cette poignée de main.
    ///
    /// **`true` en second argument, et ce n'est pas une négligence** :
    /// [`dane_config`] n'est construit QUE sur des enregistrements
    /// authentiques, et c'est écrit dans sa documentation. Redemander ici ferait
    /// deux endroits où l'on décide de la même chose.
    fn jeu(&self) -> Set<'_> {
        let records = self
            .rdata
            .iter()
            .filter_map(|octets| Tlsa::parse(octets))
            .collect();
        Set::from_records(records, true)
    }
}

impl Dane {
    /// Ce candidat, pris pour SEULE racine.
    ///
    /// # LES DEUX ÉCHECS N'EN FONT QU'UN
    ///
    /// `add` refuse un certificat que `rustls` ne sait pas lire ; `build` refuse
    /// un magasin vide — ce qui ne peut arriver qu'après le premier. Les séparer
    /// donnerait deux bras dont un que rien ne pourrait atteindre, et une garde
    /// inatteignable n'est pas une garde.
    fn en_verificateur(&self, candidat: &CertificateDer<'_>) -> Option<Arc<WebPkiServerVerifier>> {
        let mut racines = RootCertStore::empty();
        racines.add(candidat.clone()).ok()?;
        WebPkiServerVerifier::builder_with_provider(
            Arc::new(racines),
            Arc::clone(&self.fournisseur),
        )
        .build()
        .ok()
    }
}

impl ServerCertVerifier for Dane {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let jeu = self.jeu();

        // ── `DANE-EE(3)` : le domaine a nommé CE certificat ─────────────────
        //
        // §3.1.1 de RFC 7672 : ni chaîne, ni nom, ni date. Le domaine a publié
        // dans son DNS signé l'empreinte exacte de ce qu'il présente, et c'est
        // plus fort que tout ce qu'une autorité pourrait attester. Les
        // vérifications de nom NE DOIVENT PAS être faites — un serveur qui sert
        // dix domaines n'a pas à porter dix noms.
        //
        // La date est ignorée pour la même raison (§5.1 de RFC 7671) : un
        // certificat expiré dont le domaine dit aujourd'hui qu'il est le sien
        // est le sien. Refuser sur la date reviendrait à faire confiance à une
        // horloge plutôt qu'au domaine.
        if jeu.matching(end_entity) == Some(Match::LeafOnly) {
            return Ok(ServerCertVerified::assertion());
        }

        // ── `DANE-TA(2)` : le domaine a nommé son AUTORITÉ ──────────────────
        //
        // Il faut alors deux choses de plus, et aucune n'est facultative : que
        // le certificat du pair se rattache à cette autorité, et que son NOM
        // corresponde (§3.1.1). L'autorité a pu signer pour d'autres.
        //
        // La chaîne se vérifie par `rustls`, avec l'autorité trouvée pour seule
        // racine. **On n'écrit pas de validation X.509 ici** : un second
        // vérificateur de chaîne dans ce dépôt finirait par diverger de celui
        // qui sert partout ailleurs, et c'est exactement le genre d'écart qu'on
        // ne remarque qu'après.
        for candidat in core::iter::once(end_entity).chain(intermediates) {
            if jeu.matching(candidat) != Some(Match::Anchor) {
                continue;
            }
            // Une « autorité » dont `rustls` ne veut pas n'en est pas une. On
            // essaie les suivantes plutôt que de renoncer : le jeu peut en
            // nommer plusieurs.
            let Some(verificateur) = self.en_verificateur(candidat) else {
                continue;
            };
            if verificateur
                .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
                .is_ok()
            {
                return Ok(ServerCertVerified::assertion());
            }
        }

        // **AUCUN ENREGISTREMENT SATISFAIT : ON NE PARLE PAS.**
        //
        // C'est le seul refus qui donne un sens à DANE. S'en remettre alors au
        // chiffrement opportuniste rendrait la publication d'un `TLSA` purement
        // décorative, et un attaquant n'aurait qu'à présenter n'importe quoi.
        Err(rustls::Error::InvalidCertificate(
            CertificateError::ApplicationVerificationFailure,
        ))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // TLS 1.2 n'est pas servi (C6) — la même raison qu'au-dessus.
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
