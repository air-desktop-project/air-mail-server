//! Le fournisseur cryptographique : TLS 1.3, pur Rust, post-quantique d'abord.

use alloc::vec::Vec;

use rustls::SupportedCipherSuite;
use rustls::crypto::{CryptoProvider, SupportedKxGroup};

use crate::kx::X25519MlKem768;

/// Le groupe hybride, **construit à la compilation**.
///
/// `kx_groups` exige du `&'static`. La première version l'obtenait par
/// `Box::leak`, en s'appuyant sur un commentaire qui disait « un fournisseur se
/// construit une fois au démarrage » : une consigne d'usage, que rien n'imposait.
/// **LeakSanitizer l'a démontrée fausse dès la première campagne de fuzzing** —
/// appelée en boucle, `provider()` fuyait sans borne.
///
/// Un `static` supprime la question au lieu de la déplacer : aucune allocation,
/// aucune initialisation paresseuse, aucun verrou, et le `'static` devient une
/// propriété du code plutôt qu'une promesse faite dans un commentaire. C'est
/// aussi la seule forme qui reste vraie en `no_std` sans `OnceLock`.
static HYBRIDE: X25519MlKem768 = X25519MlKem768::new(&rustls_rustcrypto::Provider);

/// Construit le fournisseur.
///
/// # Ce qu'il garantit, et ce que chaque garantie coûterait autrement
///
/// - **TLS 1.3 et rien d'autre.** La feature `tls12` de `rustls-rustcrypto` est
///   ACTIVE depuis le 2026-09-22 — [`provider_tls12`] en a besoin —, et ce
///   fournisseur-ci **filtre** ses suites : seules celles de version 1.3
///   restent. Ce n'était plus une absence, c'est devenu un choix, et un essai
///   le tient. C'est ce fournisseur que prennent le relais de sortie, l'API,
///   QUIC et la lecture des politiques MTA-STS — tout ce qui parle à des
///   machines modernes.
/// - **Pas une ligne de C.** `aws-lc-rs` et `ring` en embarquent ; le portage
///   vers Air ne peut pas payer ce prix (C4).
/// - **`X25519MLKEM768` EN PREMIER.** rustls essaie les groupes dans l'ordre :
///   le placer en tête, c'est le faire préférer. **La liste amont reste derrière,
///   entière** — `X25519`, `secp256r1`, `secp384r1` —, pour les pairs dont la
///   pile ne sait pas encore faire de post-quantique (C14). Ce commentaire ne
///   nommait que `X25519` : vrai du deuxième, muet sur les deux suivants.
///
/// # Le résidu, nommé
///
/// Un pair sans post-quantique obtient l'un des trois groupes classiques, et
/// **cette connexion-là n'est pas protégée** contre « intercepter aujourd'hui,
/// déchiffrer demain ». C'est
/// le prix de l'interopérabilité ; on ne dira donc jamais que ce serveur est
/// post-quantique sans ajouter « quand le pair le veut bien ».
#[must_use]
pub fn provider() -> CryptoProvider {
    let base = avec_le_groupe_hybride(rustls_rustcrypto::provider());
    let cipher_suites = base
        .cipher_suites
        .iter()
        .copied()
        .filter(|suite| matches!(suite, SupportedCipherSuite::Tls13(_)))
        .collect();
    CryptoProvider {
        cipher_suites,
        ..base
    }
}

/// Le fournisseur des ÉCOUTES DE COURRIER : TLS 1.3 d'abord, TLS 1.2 accepté.
///
/// # POURQUOI CE FOURNISSEUR EXISTE, ALORS QUE C4 DISAIT « RIEN EN DESSOUS »
///
/// Le 2026-09-22, `mail.narro.ch` a basculé sur ce serveur et y est resté
/// quatre heures : **Apple Mail — sur Mac comme sur iPhone — ne parle que
/// TLS 1.2.** Capturé sur la machine, son `ClientHello` vers le 993 n'a pas
/// d'extension `supported_versions`, propose `secp256r1/384/521` et vingt-deux
/// suites 1.2. Le serveur répondait « alert protocol version », et aucun
/// réglage du client n'y pouvait rien : c'est sa pile IMAP/SMTP, pas une
/// option. Tous les contrôles de la bascule venaient d'OpenSSL ou de Python,
/// qui font du 1.3 — ils ne prouvaient rien sur le client que les cinq
/// comptes emploient. Retour à Postfix en 36 secondes.
///
/// C4 est donc AMENDÉE, et non abandonnée : TLS 1.3 reste ce qu'on préfère et
/// ce qu'on obtient de tout pair qui sait le faire — rustls choisit la version
/// la plus haute que le client propose —, et TLS 1.2 n'est accepté que là où
/// des humains branchent des clients qu'ils ne choisissent pas : **les
/// écoutes SMTP, submission et IMAP**. Le relais de sortie, l'API, QUIC et
/// MTA-STS gardent [`provider`], et TLS 1.3 seul.
///
/// # Ce que le 1.2 apporte, et ce qu'il n'apporte pas
///
/// Six suites, toutes ECDHE avec un AEAD — `AES-GCM` ou `ChaCha20-Poly1305`,
/// signées ECDSA ou RSA. **Aucune suite CBC, aucun RSA statique, aucun
/// SHA-1** : c'est l'amont qui ne les fournit pas, et c'est heureux. Ce qui
/// manque au 1.2 face au 1.3 est structurel — pas de secret avant la poignée
/// de main, une négociation en clair — et ne se corrige pas par une suite.
///
/// Et **le groupe hybride est en tête ici aussi**, pour que le pair qui sait
/// faire du post-quantique en fasse, même sur une écoute qui tolère l'ancien.
#[must_use]
pub fn provider_tls12() -> CryptoProvider {
    avec_le_groupe_hybride(rustls_rustcrypto::provider())
}

/// Place `X25519MLKEM768` en tête des groupes de l'amont, sans en retirer.
fn avec_le_groupe_hybride(base: CryptoProvider) -> CryptoProvider {
    let hybride: &'static dyn SupportedKxGroup = &HYBRIDE;
    let mut kx_groups: Vec<&'static dyn SupportedKxGroup> =
        Vec::with_capacity(base.kx_groups.len().saturating_add(1));
    kx_groups.push(hybride);
    kx_groups.extend_from_slice(&base.kx_groups);
    CryptoProvider { kx_groups, ..base }
}

#[cfg(test)]
mod tests {
    /// Le `static` ci-dessus **nomme** la source d'aléa de l'amont au lieu de la
    /// lire dans `base.secure_random` : c'est le prix d'une construction en
    /// contexte constant. Si l'amont changeait de source, notre groupe hybride
    /// garderait l'ancienne en silence — et le silence est exactement ce qu'on
    /// refuse ailleurs. Ce test est le grelot : il échoue au prochain SHA qui
    /// remplacerait `Provider`.
    #[test]
    fn la_source_d_alea_de_l_amont_est_bien_celle_que_le_static_nomme() {
        let amont = alloc::format!("{:?}", rustls_rustcrypto::provider().secure_random);
        assert_eq!(amont, "Provider", "l'amont a changé de source d'aléa");
    }

    use super::{provider, provider_tls12};
    use rustls::NamedGroup;

    #[test]
    fn le_fournisseur_n_offre_que_du_tls_1_3() {
        // **C'ÉTAIT UNE ABSENCE, C'EST DEVENU UN FILTRE** : la feature `tls12`
        // est active depuis le 2026-09-22 pour les écoutes de courrier, et ce
        // fournisseur-ci doit continuer d'écarter ce qu'elle apporte. Si ce
        // nombre passe à neuf, le filtre a sauté — et le relais, l'API et QUIC
        // se mettraient à négocier du 1.2 sans que rien ne le dise.
        let fournisseur = provider();
        assert_eq!(fournisseur.cipher_suites.len(), 3);
        for suite in &fournisseur.cipher_suites {
            // Le nom est LIÉ avant l'assertion : l'appeler dans le message
            // d'échec le rendrait paresseux, donc jamais évalué — et le 100 % de
            // C2 compterait cette évaluation à jamais découverte.
            let nom = suite.suite();
            let version = suite.version().version;
            assert_eq!(
                version,
                rustls::ProtocolVersion::TLSv1_3,
                "{nom:?} n'est pas une suite TLS 1.3"
            );
        }
    }

    /// Les écoutes de courrier acceptent TLS 1.2 — pour Apple Mail, qui ne
    /// sait rien faire d'autre —, et l'on vérifie EXACTEMENT ce qui entre.
    #[test]
    fn le_fournisseur_des_ecoutes_offre_du_1_2_derriere_le_1_3() {
        let fournisseur = provider_tls12();
        let versions: std::vec::Vec<rustls::ProtocolVersion> = fournisseur
            .cipher_suites
            .iter()
            .map(|suite| suite.version().version)
            .collect();
        // Six suites 1.2 puis trois suites 1.3 — celles de l'amont, dans SON
        // ordre : rustls choisit la version sur `supported_versions`, pas sur
        // le rang des suites, et l'ordre ne décide donc que dans une version.
        // Un changement de l'amont doit faire échouer cet essai : la liste est
        // DÉCRITE dans C4, et ce qui décrit sans épingler vieillit.
        let attendu: std::vec::Vec<rustls::ProtocolVersion> =
            core::iter::repeat_n(rustls::ProtocolVersion::TLSv1_2, 6)
                .chain(core::iter::repeat_n(rustls::ProtocolVersion::TLSv1_3, 3))
                .collect();
        assert_eq!(
            versions, attendu,
            "les suites des écoutes ne sont plus celles que C4 décrit"
        );
        // **RIEN QUE DE L'ECDHE AVEC UN AEAD** : ni CBC, ni RSA statique, ni
        // SHA-1. Le nom de chaque suite 1.2 le porte, et on le lit.
        for suite in &fournisseur.cipher_suites {
            if suite.version().version != rustls::ProtocolVersion::TLSv1_2 {
                continue;
            }
            let nom = alloc::format!("{:?}", suite.suite());
            assert!(
                nom.starts_with("TLS_ECDHE_"),
                "{nom} n'est pas une suite ECDHE"
            );
            assert!(
                nom.contains("_GCM_") || nom.contains("CHACHA20_POLY1305"),
                "{nom} n'est pas un AEAD"
            );
        }
        // Le groupe hybride reste en tête, même sur une écoute tolérante.
        assert_eq!(
            fournisseur.kx_groups.first().map(|groupe| groupe.name()),
            Some(NamedGroup::X25519MLKEM768)
        );
        // Et rustls accepte de servir les DEUX versions avec.
        let assemblage =
            rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(provider_tls12()))
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12]);
        assert!(
            assemblage.is_ok(),
            "rustls a refusé le fournisseur des écoutes"
        );
    }

    #[test]
    fn le_groupe_hybride_est_en_tete() {
        // rustls essaie les groupes DANS L'ORDRE : être en tête, c'est être
        // préféré (C14).
        let fournisseur = provider();
        let noms: std::vec::Vec<NamedGroup> = fournisseur
            .kx_groups
            .iter()
            .map(|groupe| groupe.name())
            .collect();
        // **LA LISTE EXACTE, ET NON UN MINIMUM.** Elle était éprouvée par
        // `len() >= 4`, ce qui laissait l'amont en ajouter ou en retirer sans
        // qu'on le sache — alors que C14 DÉCRIT cette liste, et qu'une entrée
        // qui décrit sans épingler vieillit. Un changement de
        // `rustls-rustcrypto` doit faire échouer cet essai, pour que la
        // contrainte soit relue plutôt que dépassée en silence.
        assert_eq!(
            noms,
            std::vec![
                NamedGroup::X25519MLKEM768,
                NamedGroup::X25519,
                NamedGroup::secp256r1,
                NamedGroup::secp384r1,
            ],
            "la liste des groupes a changé : C14 la décrit, et doit être relue"
        );
    }

    #[test]
    fn le_fournisseur_construit_bien_une_configuration_serveur() {
        // Il ne suffit pas qu'il existe : rustls doit l'accepter pour du 1.3.
        let assemblage =
            rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(provider()))
                .with_protocol_versions(&[&rustls::version::TLS13]);
        assert!(assemblage.is_ok(), "rustls a refusé le fournisseur");
    }
}
