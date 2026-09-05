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
use rustls::sign::CertifiedKey;

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
    /// **CE CONTRÔLE-CI N'ATTRAPE PAS UNE PAIRE DÉPAREILLÉE**, et c'est
    /// [`Error::Mismatched`] qui s'en charge désormais — voir sa documentation
    /// pour le pourquoi.
    Rejected(rustls::Error),

    /// La clé est valable, et **elle n'est pas celle de ce certificat**.
    ///
    /// # POURQUOI CETTE VARIANTE A DÛ ÊTRE ÉCRITE
    ///
    /// `rustls` documente que `with_single_cert` échoue « si la clé publique de
    /// la clé privée ne correspond pas au certificat de tête ». **Ce n'est pas
    /// vrai avec `rustls-rustcrypto`** : sa clé de signature n'implémente pas
    /// `public_key`, si bien que `keys_match` rend `Unknown` — que `from_der`
    /// traite comme un succès.
    ///
    /// Ce défaut était CONNU et consigné comme une limite acceptée. Il est
    /// désormais fermé : on signe quelques octets avec la clé, et l'on vérifie
    /// la signature contre le certificat, exactement comme une poignée de main
    /// TLS 1.3 le ferait.
    ///
    /// **Ce que cela coûtait** (mesuré le 2026-09-05, pas supposé) : une chaîne
    /// neuve avec une clé ancienne — l'état d'un renouvellement surpris à
    /// mi-chemin — était acceptée, le serveur démarrait, et TOUTES ses poignées
    /// de main échouaient ensuite sur « bad signature ». Le symptôme était très
    /// loin de la cause.
    Mismatched,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Certificate(cause) => write!(f, "chaîne de certificats illisible : {cause}"),
            Error::PrivateKey(cause) => write!(f, "clé privée illisible : {cause}"),
            Error::Rejected(cause) => {
                write!(
                    f,
                    "clé refusée par le fournisseur cryptographique : {cause}"
                )
            }
            Error::Mismatched => f.write_str(
                "la clé privée est valable, mais elle n'est PAS celle de ce certificat \
                 (un renouvellement à moitié écrit donne exactement cela)",
            ),
        }
    }
}

impl core::error::Error for Error {}

/// Le seul protocole applicatif que ce serveur annonce sur TLS.
///
/// **`h2`, ET RIEN D'AUTRE.** HTTP/1.1 n'est pas servi (C6) : son cadrage est
/// textuel et sa longueur se déduit de deux champs qui peuvent se contredire,
/// d'où toute la famille des attaques par contrebande de requête.
pub const ALPN_H2: &[u8] = b"h2";

/// Les protocoles qu'on annonce, dans l'ordre de préférence.
///
/// # POURQUOI UNE FONCTION, ET NON UN PARAMÈTRE DE [`server_config`]
///
/// Une liste passée par l'appelant se remplirait un jour de `http/1.1` — « juste
/// pour un client ancien ». Or annoncer un protocole qu'on refuse de servir est
/// pire que de ne pas l'annoncer : le client le négocie, croit avoir accordé, et
/// se voit refuser après la poignée de main.
///
/// **IL N'Y A DONC QU'UNE SEULE LISTE SANCTIONNÉE**, et c'est celle-ci.
///
/// # ET POURQUOI L'ASSEMBLAGE N'EST PAS ICI
///
/// Poser cette liste sur une configuration demande une configuration, donc un
/// certificat — que cette crate ne peut pas fabriquer sans matériel, et qu'on ne
/// versionne pas. L'assemblage vit donc là où un certificat existe : dans
/// l'écoute qui s'en sert.
///
/// La découpe suit ce que chaque morceau peut prouver seul : ce qu'on annonce se
/// vérifie sans rien, l'assemblage demande de quoi assembler.
#[must_use]
pub fn alpn() -> Vec<Vec<u8>> {
    alloc::vec![ALPN_H2.to_vec()]
}

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
    assembler(chain_pem, key_pem, provider())
}

/// Lit une chaîne et une clé PEM, et rend le matériel qu'une poignée de main
/// présente.
///
/// # POURQUOI CETTE FONCTION EXISTE, ALORS QUE `server_config` FAIT DÉJÀ CELA
///
/// Un certificat Let's Encrypt vit trois mois, et se renouvelle tous les deux.
/// Un serveur qui lit son matériel au démarrage et jamais plus **cesse de servir
/// le TLS quatre-vingt-dix jours après son installation** — silencieusement,
/// puisque rien dans son fonctionnement ne change jusqu'à l'expiration.
///
/// Recharger demande de pouvoir REMPLACER le matériel sans reconstruire la
/// configuration : `ServerConfig` est immuable une fois bâtie, et la remplacer
/// obligerait chaque écoute, chaque connexion en cours et chaque tampon à voir
/// le changement. `ResolvesServerCert` résout cela — la configuration reste UN
/// objet, et ce qu'elle présente change dessous.
///
/// **Cette crate rend le matériel ; elle ne le tient pas.** Elle est `no_std` et
/// sans entrée-sortie : ni verrou, ni fichier, ni horloge. Ce qui GARDE le
/// matériel courant et le remplace vit dans la boucle, avec ce qui sait lire un
/// fichier et regarder sa date.
///
/// # Errors
///
/// [`Error`] — chaîne illisible ou vide, clé illisible, ou clé qui ne
/// correspond pas au certificat de tête. **Les mêmes refus que
/// [`server_config`]**, et c'est voulu : un matériel qu'on rechargerait sous des
/// règles plus souples que celles du démarrage serait un moyen de contourner
/// celles-ci.
pub fn certified_key(chain_pem: &[u8], key_pem: &[u8]) -> Result<CertifiedKey, Error> {
    let lu = lire(chain_pem, key_pem)?;
    let materiel =
        CertifiedKey::from_der(lu.chaine, lu.cle, &provider()).map_err(Error::Rejected)?;
    accorder(&lu.tete, &*materiel.key)?;
    Ok(materiel)
}

/// La clé signe-t-elle vraiment pour ce certificat ?
///
/// # POURQUOI CE CONTRÔLE EXISTE, ALORS QUE `rustls` EN A UN
///
/// `CertifiedKey::from_der` appelle `keys_match`, qui compare la clé publique de
/// la clé privée à celle du certificat. **Mais il n'échoue que s'il PEUT
/// comparer** : quand la clé ne sait pas rendre sa partie publique, il rend
/// `InconsistentKeys::Unknown`, que `from_der` traite comme un succès.
///
/// C'est exactement notre cas : `rustls-rustcrypto` n'implémente pas
/// `SigningKey::public_key`. **Toute paire dépareillée passait donc.** Mesuré le
/// 2026-09-05 : une chaîne neuve avec une clé ancienne était acceptée, installée,
/// et TOUTES les poignées de main échouaient ensuite sur « bad signature ».
///
/// # ON SIGNE, ET ON VÉRIFIE
///
/// Comparer des clés publiques est impossible ici ; signer ne l'est pas. On
/// signe donc quelques octets avec la clé privée, et l'on vérifie la signature
/// **contre le certificat** — ce que fait exactement une poignée de main
/// TLS 1.3 (§4.4.3 de RFC 8446), avec les mêmes algorithmes.
///
/// C'est plus lent qu'une comparaison, et c'est payé **une fois par
/// chargement** : au démarrage, et à chaque renouvellement. Deux fois en trois
/// mois.
fn accorder(
    certificat: &CertificateDer<'_>,
    cle: &dyn rustls::sign::SigningKey,
) -> Result<(), Error> {
    let fournisseur = provider();
    // §4.4.3 : ce que le serveur signe est un préfixe fixe, un séparateur, puis
    // le condensat de la transcription. Ici les octets n'ont aucune importance —
    // seul compte que la signature se vérifie —, mais les prendre de la RFC
    // évite d'inventer un format qui ressemblerait à autre chose.
    const A_SIGNER: &[u8] = b"air-mail-server : accord de la cle et du certificat";

    let verifiables = &fournisseur.signature_verification_algorithms;

    // **AUCUNE FERMETURE ICI, ET C'EST UNE CONTRAINTE DE MESURE.** Cette crate
    // est compilée DEUX FOIS — une fois pour ses propres essais, une fois comme
    // dépendance — et les fermetures ne s'y instancient pas de la même façon.
    // Une fermeture présente dans l'une et absente de l'autre ne peut pas être
    // appariée : elle compte comme non couverte à jamais, quoi qu'on éprouve.
    // Des boucles explicites n'ont pas ce défaut.
    let Some(signataire) = cle.choose_scheme(&verifiables.supported_schemes()) else {
        return Err(Error::Mismatched);
    };
    let Ok(signature) = signataire.sign(A_SIGNER) else {
        return Err(Error::Mismatched);
    };
    // Un bloc PEM bien formé dont le contenu n'est pas un certificat arrive
    // JUSQU'ICI : `keys_match` rend `Unknown` avant même de l'analyser, puisque
    // la clé ne sait pas rendre sa partie publique.
    let Ok(lu) = webpki::EndEntityCert::try_from(certificat) else {
        return Err(Error::Mismatched);
    };

    // **ON ESSAIE TOUS LES ALGORITHMES DU SCHÉMA**, plutôt que d'en chercher un.
    // Un schéma peut en avoir plusieurs — la même signature acceptée par deux
    // implémentations — et il suffit que l'un la reconnaisse.
    let schema = signataire.scheme();
    for (connu, algorithmes) in verifiables.mapping {
        if *connu != schema {
            continue;
        }
        for algorithme in *algorithmes {
            if lu
                .verify_signature(*algorithme, A_SIGNER, &signature)
                .is_ok()
            {
                return Ok(());
            }
        }
    }
    Err(Error::Mismatched)
}

/// Assemble un `ServerConfig` qui demande son matériel à `resolveur`.
///
/// Mêmes garanties que [`server_config`] — TLS 1.3 seul, `X25519MLKEM768` en
/// tête —, mais **le certificat présenté peut changer** d'une poignée de main à
/// l'autre. Voir [`certified_key`].
#[must_use]
pub fn server_config_resolving(
    resolveur: Arc<dyn rustls::server::ResolvesServerCert>,
) -> ServerConfig {
    ServerConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        // Ce `expect` ne peut pas se déclencher, et pour la raison écrite dans
        // `assembler` : il faudrait que le fournisseur n'offre aucune suite
        // TLS 1.3, ce qu'un test de `provider` interdit explicitement.
        .expect("le fournisseur n'offre que des suites TLS 1.3")
        .with_no_client_auth()
        .with_cert_resolver(resolveur)
}

/// Ce qu'un fichier de chaîne et un fichier de clé donnent, une fois lus.
///
/// **LA TÊTE EST RENDUE À PART, ET CE N'EST PAS UNE COMMODITÉ.** C'est elle qui
/// porte la clé publique, donc elle que tout accord regarde. La tirer ici, où
/// l'on vérifie déjà que la chaîne n'est pas vide, ÉVITE UNE SECONDE GARDE plus
/// loin — une garde qu'aucune entrée ne pourrait faire céder, puisque celle-ci
/// l'a déjà exclue.
struct Materiel {
    tete: CertificateDer<'static>,
    chaine: Vec<CertificateDer<'static>>,
    cle: PrivateKeyDer<'static>,
}

fn lire(chain_pem: &[u8], key_pem: &[u8]) -> Result<Materiel, Error> {
    let chaine: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(chain_pem)
        .collect::<Result<_, _>>()
        .map_err(Error::Certificate)?;
    // Un fichier sans le moindre bloc `CERTIFICATE` passe l'itération sans rien
    // rendre. Le laisser filer donnerait un serveur sans certificat, qui
    // échouerait à la première poignée de main au lieu de refuser de démarrer.
    let Some(tete) = chaine.first().cloned() else {
        return Err(Error::Certificate(pem::Error::NoItemsFound));
    };
    let cle = PrivateKeyDer::from_pem_slice(key_pem).map_err(Error::PrivateKey)?;
    Ok(Materiel { tete, chaine, cle })
}

/// La même chose, mais capable de conduire une poignée de main QUIC.
///
/// # POURQUOI DEUX FONCTIONS PLUTÔT QU'UN PARAMÈTRE
///
/// Un paramètre « quel fournisseur » se renseignerait mal un jour. **Une
/// configuration QUIC montée sur le fournisseur ordinaire ne se voit pas** :
/// elle se construit, elle démarre, et `rustls::quic::ServerConnection` refuse
/// ensuite avec « at least one ciphersuite must support QUIC » — au montage de
/// la première connexion, loin du fichier où le choix a été fait.
///
/// Ici, le nom de la fonction EST le choix, et il n'y a rien à renseigner. C'est
/// la même règle que pour l'ALPN : ce qu'on ne peut pas exprimer ne peut pas
/// être faux.
///
/// L'ALPN, elle, reste à la charge de l'appelant : cette configuration sert la
/// poignée de main, et le protocole applicatif est une décision de la couche du
/// dessus. Voir [`alpn_h3`](crate::alpn_h3).
///
/// # Errors
///
/// [`Error`] — chaîne illisible ou vide, clé illisible, ou clé qui ne
/// correspond pas au certificat de tête.
pub fn quic_server_config(chain_pem: &[u8], key_pem: &[u8]) -> Result<ServerConfig, Error> {
    assembler(chain_pem, key_pem, crate::provider_quic())
}

/// Le corps commun des deux : les mêmes refus, le même TLS 1.3, un fournisseur
/// qui change.
fn assembler(
    chain_pem: &[u8],
    key_pem: &[u8],
    fournisseur: rustls::crypto::CryptoProvider,
) -> Result<ServerConfig, Error> {
    let lu = lire(chain_pem, key_pem)?;

    // **LE DÉMARRAGE SUBIT LE MÊME CONTRÔLE QUE LE RECHARGEMENT.** Sans cela, un
    // serveur pourrait démarrer sur une paire dépareillée et échouer à chaque
    // poignée de main — ce qui était le cas jusqu'ici. Voir `accorder`.
    let signataire = provider()
        .key_provider
        .load_private_key(lu.cle.clone_key())
        .map_err(Error::Rejected)?;
    accorder(&lu.tete, &*signataire)?;

    ServerConfig::builder_with_provider(Arc::new(fournisseur))
        .with_protocol_versions(&[&rustls::version::TLS13])
        // Ce `expect` ne peut pas se déclencher : il faudrait que le fournisseur
        // n'offre AUCUNE suite TLS 1.3, ce qu'un test de `provider` interdit
        // explicitement. Un `?` ouvrirait ici une branche qu'aucun test ne peut
        // atteindre — et C2 refuse les gardes inatteignables, qui ne sont pas
        // des gardes mais des affirmations non vérifiées.
        .expect("le fournisseur n'offre que des suites TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(lu.chaine, lu.cle)
        .map_err(Error::Rejected)
}

#[cfg(test)]
mod tests {
    use super::{Error, server_config};
    use alloc::format;
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    /// **UNE PAIRE D'ESSAI, VERSÉE DANS LE DÉPÔT.**
    ///
    /// # POURQUOI ELLE EXISTE, ET POURQUOI ELLE EST SANS DANGER
    ///
    /// Cette crate est compilée DEUX FOIS — une fois pour ses propres essais
    /// unitaires, une fois comme dépendance — et la couverture les compte
    /// séparément. Une fonction qu'un essai d'INTÉGRATION seul exerce laisse
    /// donc l'autre compilation à découvert, quoi qu'on fasse.
    ///
    /// Les essais unitaires n'avaient aucun matériel valable : ils ne pouvaient
    /// éprouver que des refus. Cette paire-ci leur donne le chemin nominal.
    ///
    /// **SA CLÉ PRIVÉE EST PUBLIQUE, ET C'EST SANS CONSÉQUENCE** : elle ne
    /// certifie rien — son nom est `materiel-d-essai.invalid`, un domaine que
    /// RFC 2606 §2 réserve pour qu'il n'existe jamais — et aucune autorité ne
    /// l'a signée. La connaître ne donne accès à rien.
    const CERT_ESSAI: &[u8] = include_bytes!("materiel/essai-cert.pem");
    /// La clé de [`CERT_ESSAI`]. Voir sa documentation.
    const CLE_ESSAI: &[u8] = include_bytes!("materiel/essai-cle.pem");
    /// **UNE SECONDE CLÉ, ÉTRANGÈRE AU CERTIFICAT D'ESSAI.**
    ///
    /// Elle sert à un seul cas, et il est le plus important de ce module : une
    /// paire VALABLE des deux côtés, et dépareillée. C'est l'état exact d'un
    /// renouvellement dont un seul des deux fichiers a été remplacé — et le
    /// seul que `keys_match` ne sait pas voir avec ce fournisseur.
    ///
    /// Sans elle, on n'éprouve que des refus qui tombent PLUS TÔT — un PEM
    /// illisible, un certificat qui ne s'analyse pas — et jamais celui qui
    /// compte : la signature qui ne se vérifie pas.
    const CLE_ETRANGERE: &[u8] = include_bytes!("materiel/essai-autre-cle.pem");

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
            Error::Mismatched => "dépareillée",
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

    /// **`h2`, ET RIEN D'AUTRE** : annoncer un protocole qu'on refuse de servir
    /// est pire que de ne pas l'annoncer, puisque le client le négocie et croit
    /// avoir accordé.
    #[test]
    fn on_n_annonce_que_http2() {
        let dits = super::alpn();
        assert_eq!(dits.len(), 1, "{dits:?}");
        assert_eq!(dits.first().map(Vec::as_slice), Some(super::ALPN_H2));
        assert_eq!(super::ALPN_H2, b"h2");
        // Rien qui ressemble à HTTP/1.1 : ni le nom, ni une variante.
        for refuse in [&b"http/1.1"[..], b"http/1.0", b"h2c", b"http/0.9"] {
            assert!(
                !dits.iter().any(|dit| dit.as_slice() == refuse),
                "{refuse:?} est annoncé"
            );
        }
    }

    #[test]
    fn une_cle_que_le_fournisseur_ne_sait_pas_charger_est_refusee() {
        // Le bloc est du PEM bien formé, son contenu n'est pas une clé.
        let cle_bidon = b"-----BEGIN PRIVATE KEY-----\naGVsbG8=\n-----END PRIVATE KEY-----\n";
        let erreur = server_config(CERT_BIDON, cle_bidon).expect_err("refusée");
        assert_eq!(genre(&erreur), "refus", "{erreur:?}");
        assert!(format!("{erreur}").contains("refusée par le fournisseur"));
    }

    /// **UN RECHARGEMENT NE PASSE PAS SOUS DES RÈGLES PLUS SOUPLES QUE LE
    /// DÉMARRAGE.**
    ///
    /// `certified_key` sert à remplacer le matériel d'un serveur qui tourne. S'il
    /// acceptait ce que `server_config` refuse, il serait un moyen de contourner
    /// les refus du démarrage — et c'est exactement le genre de porte qu'on
    /// n'ouvre pas.
    /// **UNE CLÉ QUI NE SAIT PAS SIGNER NE S'ACCORDE À RIEN.**
    ///
    /// Deux façons d'échouer, et le même verdict : aucun schéma ne convient, ou
    /// la signature est refusée. Distinguer ces causes n'apprendrait rien à qui
    /// doit simplement remettre les deux bons fichiers.
    ///
    /// **Ces deux chemins ne s'atteignent QUE d'ici** : un fournisseur qui
    /// charge une clé sait toujours signer avec. Les laisser non éprouvés en
    /// ferait des affirmations plutôt que des gardes.
    #[test]
    fn une_cle_qui_ne_sait_pas_signer_ne_s_accorde_a_rien() {
        /// Une clé qui ne choisit aucun schéma.
        #[derive(Debug)]
        struct SansSchema;

        /// Une clé qui choisit un schéma, puis refuse de signer.
        #[derive(Debug)]
        struct SansSignature;

        /// Le signataire de la précédente : il refuse.
        #[derive(Debug)]
        struct Refuse;

        impl rustls::sign::SigningKey for SansSchema {
            fn choose_scheme(
                &self,
                _offerts: &[rustls::SignatureScheme],
            ) -> Option<alloc::boxed::Box<dyn rustls::sign::Signer>> {
                None
            }
            fn algorithm(&self) -> rustls::SignatureAlgorithm {
                rustls::SignatureAlgorithm::ED25519
            }
        }

        impl rustls::sign::Signer for Refuse {
            fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
                Err(rustls::Error::General(alloc::string::String::from("non")))
            }
            fn scheme(&self) -> rustls::SignatureScheme {
                rustls::SignatureScheme::ED25519
            }
        }

        impl rustls::sign::SigningKey for SansSignature {
            fn choose_scheme(
                &self,
                _offerts: &[rustls::SignatureScheme],
            ) -> Option<alloc::boxed::Box<dyn rustls::sign::Signer>> {
                Some(alloc::boxed::Box::new(Refuse))
            }
            fn algorithm(&self) -> rustls::SignatureAlgorithm {
                rustls::SignatureAlgorithm::ED25519
            }
        }

        // **LE CERTIFICAT N'A AUCUNE IMPORTANCE ICI** : on n'arrive jamais
        // jusqu'à lui, puisque la clé échoue avant. C'est exactement ce que
        // l'ordre des contrôles achète.
        let certificat = rustls::pki_types::CertificateDer::from(alloc::vec![0_u8]);
        for (nom, cle) in [
            ("aucun schéma", &SansSchema as &dyn rustls::sign::SigningKey),
            ("refuse de signer", &SansSignature),
        ] {
            let refus = super::accorder(&certificat, cle).expect_err(nom);
            assert_eq!(genre(&refus), "dépareillée", "{nom} : {refus:?}");
            // **UNE DOUBLURE DOIT ÊTRE COMPLÈTE**, et `accorder` n'appelle ni
            // `algorithm`, ni `scheme` sur une clé qui refuse de signer. Les
            // laisser sans emploi en ferait des trous de couverture nés du banc
            // d'essai, et non du code éprouvé.
            assert_eq!(
                cle.algorithm(),
                rustls::SignatureAlgorithm::ED25519,
                "{nom}"
            );
            if let Some(signataire) = cle.choose_scheme(&[rustls::SignatureScheme::ED25519]) {
                assert_eq!(
                    signataire.scheme(),
                    rustls::SignatureScheme::ED25519,
                    "{nom}"
                );
            }
        }
    }

    /// Une configuration qui demande son matériel à un résolveur se monte, et
    /// **reste TLS 1.3 seule** : elle se bâtit par un autre chemin que
    /// [`server_config`], et C4 vaut pour les deux.
    ///
    /// **LE RÉSOLVEUR VIENT DE `rustls`**, et non d'une doublure écrite ici :
    /// une doublure devrait implémenter `resolve`, que ce test n'appelle pas —
    /// et une méthode sans emploi serait un trou de couverture né du banc
    /// d'essai. `ResolvesServerCertUsingSni` est vide et public ; elle suffit.
    #[test]
    fn une_configuration_a_resolveur_reste_en_tls13() {
        let vide = rustls::server::ResolvesServerCertUsingSni::new();
        let config = super::server_config_resolving(Arc::new(vide));
        assert!(
            config.alpn_protocols.is_empty(),
            "l'ALPN reste à l'appelant"
        );
        let suites = config.crypto_provider().cipher_suites.clone();
        assert!(!suites.is_empty(), "au moins une suite est offerte");
        for suite in &suites {
            assert_eq!(
                suite.version().version,
                rustls::ProtocolVersion::TLSv1_3,
                "{suite:?} n'est pas en TLS 1.3"
            );
        }
    }

    /// **LE CHEMIN NOMINAL, ÉPROUVÉ ICI AUSSI.**
    ///
    /// Les refus se mesuraient déjà ; l'ACCEPTATION ne l'était que par les
    /// essais d'intégration, donc dans une seule des deux compilations de cette
    /// crate. Voir [`CERT_ESSAI`].
    #[test]
    fn une_paire_accordee_passe_les_deux_portes() {
        assert!(
            server_config(CERT_ESSAI, CLE_ESSAI).is_ok(),
            "la porte du démarrage"
        );
        assert!(
            super::certified_key(CERT_ESSAI, CLE_ESSAI).is_ok(),
            "la porte du rechargement"
        );
        assert!(
            super::quic_server_config(CERT_ESSAI, CLE_ESSAI).is_ok(),
            "et celle de QUIC, qui passe par le même accord"
        );
    }

    /// **UNE PAIRE DÉPAREILLÉE EST REFUSÉE**, et c'est ce que `keys_match` ne
    /// sait pas faire avec ce fournisseur.
    #[test]
    fn une_paire_depareillee_est_refusee_aux_deux_portes() {
        // **DEUX MATÉRIELS VALABLES, ET QUI NE VONT PAS ENSEMBLE.** C'est le cas
        // qui compte : la signature se produit, et le certificat ne la reconnaît
        // pas. Un certificat illisible échouerait plus tôt, et n'éprouverait
        // donc pas ce chemin-là.
        let erreur = server_config(CERT_ESSAI, CLE_ETRANGERE).expect_err("refusée");
        assert_eq!(genre(&erreur), "dépareillée", "{erreur:?}");
        let erreur = super::certified_key(CERT_ESSAI, CLE_ETRANGERE).expect_err("refusée");
        assert_eq!(genre(&erreur), "dépareillée", "{erreur:?}");

        // Et un certificat qui ne s'analyse pas échoue AUSSI, plus tôt.
        let erreur = super::certified_key(CERT_BIDON, CLE_ESSAI).expect_err("refusée");
        assert_eq!(genre(&erreur), "dépareillée", "{erreur:?}");
    }

    /// **CHAQUE VARIANTE S'AFFICHE, ET DIT QUELQUE CHOSE.**
    ///
    /// `Mismatched` n'a pas de cause à porter — c'est un verdict, pas un relais.
    /// Son texte est donc la seule chose qu'un exploitant lira, et il doit
    /// nommer le problème plutôt que le genre du problème.
    #[test]
    fn une_paire_depareillee_se_dit_en_toutes_lettres() {
        assert_eq!(genre(&Error::Mismatched), "dépareillée");
        let texte = format!("{}", Error::Mismatched);
        assert!(
            texte.contains("n'est PAS celle de ce certificat"),
            "{texte}"
        );
        assert!(texte.contains("renouvellement"), "{texte}");
    }

    #[test]
    fn le_rechargement_refuse_ce_que_le_demarrage_refuse() {
        let cle_bidon = b"-----BEGIN PRIVATE KEY-----\naGVsbG8=\n-----END PRIVATE KEY-----\n";
        for (chaine, cle) in [
            (&b"ceci n'est pas du PEM"[..], CERT_BIDON),
            (b"", CERT_BIDON),
            (CERT_BIDON, cle_bidon),
        ] {
            let au_demarrage = server_config(chaine, cle).expect_err("refusée");
            let au_rechargement = super::certified_key(chaine, cle).expect_err("refusée");
            assert_eq!(
                genre(&au_demarrage),
                genre(&au_rechargement),
                "les deux doivent refuser DE LA MÊME FAÇON : {au_demarrage:?} contre \
                 {au_rechargement:?}"
            );
        }
    }
}
