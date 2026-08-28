//! Le fournisseur cryptographique : TLS 1.3, pur Rust, post-quantique d'abord.

use alloc::vec::Vec;

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
/// - **TLS 1.3 et rien d'autre.** `rustls-rustcrypto` est pris sans sa feature
///   `tls12` : le fournisseur n'offre alors que trois suites, toutes en 1.3.
///   Ce n'est pas une intention, c'est une absence — il n'y a pas de suite 1.2 à
///   négocier.
/// - **Pas une ligne de C.** `aws-lc-rs` et `ring` en embarquent ; le portage
///   vers Air ne peut pas payer ce prix (C4).
/// - **`X25519MLKEM768` EN PREMIER.** rustls essaie les groupes dans l'ordre :
///   le placer en tête, c'est le faire préférer. `X25519` reste derrière, pour
///   les pairs dont la pile ne sait pas encore faire de post-quantique (C14).
///
/// # Le résidu, nommé
///
/// Un pair sans post-quantique obtient `X25519`, et **cette connexion-là n'est
/// pas protégée** contre « intercepter aujourd'hui, déchiffrer demain ». C'est
/// le prix de l'interopérabilité ; on ne dira donc jamais que ce serveur est
/// post-quantique sans ajouter « quand le pair le veut bien ».
#[must_use]
pub fn provider() -> CryptoProvider {
    let base = rustls_rustcrypto::provider();

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

    use super::provider;
    use rustls::NamedGroup;

    #[test]
    fn le_fournisseur_n_offre_que_du_tls_1_3() {
        // CE N'EST PAS UNE INTENTION, C'EST UNE ABSENCE : la feature `tls12`
        // n'est pas activée, donc il n'y a aucune suite 1.2 à négocier.
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
        assert_eq!(noms.first(), Some(&NamedGroup::X25519MLKEM768));
        // `X25519` reste offert derrière, pour les pairs sans post-quantique.
        assert!(
            noms.contains(&NamedGroup::X25519),
            "X25519 devrait rester offert : {noms:?}"
        );
        assert!(
            noms.len() >= 4,
            "les groupes classiques ont disparu : {noms:?}"
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
