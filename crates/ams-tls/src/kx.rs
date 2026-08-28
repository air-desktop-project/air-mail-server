//! L'échange de clés hybride `X25519MLKEM768` (C14).
//!
//! # L'ordre des octets vient de la SPÉCIFICATION, pas de la mémoire
//!
//! Le brouillon `draft-ietf-tls-ecdhe-mlkem` §3.1 le dit, et il prévient
//! lui-même du piège :
//!
//! > *Le nom `X25519MLKEM768` ne suit pas la convention de nommage […] l'ordre
//! > des parts dans la concaténation a été inversé. Raisons historiques.*
//!
//! Autrement dit : **ML-KEM d'abord**, contrairement à `SecP256r1MLKEM768` où
//! c'est l'ECDH qui vient en tête. Reconstituer cela de mémoire donne une
//! poignée de main qui échoue en interopérabilité et **réussit contre
//! soi-même** — le pire des deux mondes, puisque tous les tests passeraient.
//!
//! | | Ordre, §3.1 |
//! | --- | --- |
//! | Part client (1216 o) | clé d'encapsulation ML-KEM (1184) ‖ X25519 (32) |
//! | Part serveur (1120 o) | chiffré ML-KEM (1088) ‖ X25519 (32) |
//! | Secret partagé (64 o) | secret ML-KEM (32) ‖ secret X25519 (32) |
//!
//! # Tout l'aléa vient du fournisseur, aucun du système
//!
//! rustls suppose que « la bibliothèque cryptographique fournit elle-même » son
//! aléa. Ici non : il vient de [`SecureRandom`], qui est un paramètre.
//!
//! Deux raisons. La première est C1 : lire l'aléa du système est une
//! entrée-sortie, et cette crate est de l'étage 2. La seconde est le portage —
//! sur la cible Air, l'aléa vient d'`AirRandom`, et une crate qui appellerait
//! `getrandom` elle-même n'y compilerait pas.
//!
//! Les API déterministes de `ml-kem` (`from_seed`, `encapsulate_deterministic`)
//! sont donc employées avec des octets tirés du fournisseur. Ce n'est pas un
//! détournement : ce sont exactement `ML-KEM.KeyGen_internal` et
//! `ML-KEM.Encaps_internal` de FIPS 203, qui prennent leur aléa en argument.

use alloc::boxed::Box;
use alloc::vec::Vec;

use ml_kem::B32;
use ml_kem::kem::{Decapsulate as _, KeyExport as _};
use ml_kem::ml_kem_768::{DecapsulationKey, EncapsulationKey};
use rustls::crypto::{
    ActiveKeyExchange, CompletedKeyExchange, SecureRandom, SharedSecret, SupportedKxGroup,
};
use rustls::{Error, NamedGroup, PeerMisbehaved};
use x25519_dalek::{PublicKey, StaticSecret};

/// Taille de la clé d'encapsulation ML-KEM-768.
const ENCAPSULATION_KEY: usize = 1184;
/// Taille d'un chiffré ML-KEM-768.
const CIPHERTEXT: usize = 1088;
/// Taille d'une part X25519.
const X25519: usize = 32;
/// Taille de la part du client : clé d'encapsulation, puis X25519.
pub const CLIENT_SHARE: usize = ENCAPSULATION_KEY + X25519;
/// Taille de la part du serveur : chiffré, puis X25519.
pub const SERVER_SHARE: usize = CIPHERTEXT + X25519;
/// Taille du secret partagé : les deux secrets, ML-KEM d'abord.
pub const SHARED_SECRET: usize = 32 + 32;

/// Le groupe `X25519MLKEM768`.
#[derive(Debug)]
pub struct X25519MlKem768 {
    random: &'static dyn SecureRandom,
}

impl X25519MlKem768 {
    /// Construit le groupe sur une source d'aléa.
    #[must_use]
    pub const fn new(random: &'static dyn SecureRandom) -> Self {
        Self { random }
    }

    /// Tire `N` octets du fournisseur.
    fn tirer<const N: usize>(&self) -> Result<[u8; N], Error> {
        let mut octets = [0_u8; N];
        self.random
            .fill(&mut octets)
            .map_err(|_| Error::FailedToGetRandomBytes)?;
        Ok(octets)
    }
}

impl SupportedKxGroup for X25519MlKem768 {
    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    /// Le rôle CLIENT : on prépare une clé d'encapsulation et une part X25519.
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        // FIPS 203 `KeyGen_internal` prend `d ‖ z`, soit soixante-quatre octets.
        let graine: [u8; 64] = self.tirer()?;
        let decapsulation = DecapsulationKey::from_seed(graine.into());
        let secret = StaticSecret::from(self.tirer::<32>()?);

        let mut part = Vec::with_capacity(CLIENT_SHARE);
        part.extend_from_slice(&decapsulation.encapsulation_key().to_bytes());
        part.extend_from_slice(PublicKey::from(&secret).as_bytes());

        Ok(Box::new(EnCours {
            decapsulation,
            secret,
            part,
        }))
    }

    /// Le rôle SERVEUR : on encapsule vers la clé du pair, en une seule fois.
    fn start_and_complete(&self, peer: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let (encapsulation, pair_x25519) = decouper_part_client(peer)?;

        // « Le serveur DOIT effectuer le contrôle de clé d'encapsulation décrit
        // en §7.2 de FIPS 203 sur la clé du client, et abandonner avec une
        // alerte `illegal_parameter` s'il échoue. » (§3.1.2 du brouillon)
        // `EncapsulationKey::new` fait ce contrôle en décodant.
        let cle = EncapsulationKey::new(&(*encapsulation).into())
            .map_err(|_| Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))?;

        // FIPS 203 `Encaps_internal` prend son aléa en argument.
        let alea: B32 = self.tirer::<32>()?.into();
        let (chiffre, secret_mlkem) = cle.encapsulate_deterministic(&alea);

        let notre_secret = StaticSecret::from(self.tirer::<32>()?);
        let secret_x25519 = notre_secret.diffie_hellman(&PublicKey::from(*pair_x25519));
        verifier_contribution(&secret_x25519)?;

        let mut part = Vec::with_capacity(SERVER_SHARE);
        part.extend_from_slice(&chiffre);
        part.extend_from_slice(PublicKey::from(&notre_secret).as_bytes());

        Ok(CompletedKeyExchange {
            group: NamedGroup::X25519MLKEM768,
            pub_key: part,
            secret: assembler(&secret_mlkem, secret_x25519.as_bytes()),
        })
    }
}

/// Un échange engagé, côté client.
struct EnCours {
    decapsulation: DecapsulationKey,
    secret: StaticSecret,
    part: Vec<u8>,
}

impl ActiveKeyExchange for EnCours {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let (chiffre, pair_x25519) = decouper_part_serveur(peer)?;

        // « Le client DOIT vérifier que la longueur du chiffré correspond au
        // groupe choisi. » (§3.1.2) — c'est ce que `decouper_part_serveur`
        // fait, et le type qu'il rend le prouve. On prend donc `decapsulate`,
        // qui est TOTAL, plutôt que `decapsulate_slice`, dont l'erreur ne
        // décrit qu'une longueur désormais impossible.
        let secret_mlkem = self.decapsulation.decapsulate(&(*chiffre).into());

        let secret_x25519 = self.secret.diffie_hellman(&PublicKey::from(*pair_x25519));
        verifier_contribution(&secret_x25519)?;

        Ok(assembler(&secret_mlkem, secret_x25519.as_bytes()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.part
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}

/// Découpe la part du client : clé d'encapsulation, puis X25519.
///
/// `split_first_chunk` rend un tableau, pas une tranche : la longueur du
/// premier morceau est portée par le *type*, et le reste du fichier n'a plus
/// à s'en assurer. Le découpage avec `split_at_checked` rendait deux tranches,
/// donc deux conversions vers tableau — dont une que rien ne pouvait faire
/// échouer, et qu'aucun test ne pouvait donc atteindre. Une garde
/// inatteignable n'est pas une garde : c'est une affirmation non vérifiée.
fn decouper_part_client(part: &[u8]) -> Result<(&[u8; ENCAPSULATION_KEY], &[u8; X25519]), Error> {
    let mauvaise = || Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);
    let (encapsulation, reste) = part
        .split_first_chunk::<ENCAPSULATION_KEY>()
        .ok_or_else(mauvaise)?;
    let x25519 = reste.try_into().map_err(|_| mauvaise())?;
    Ok((encapsulation, x25519))
}

/// Découpe la part du serveur : chiffré, puis X25519. Même raisonnement.
fn decouper_part_serveur(part: &[u8]) -> Result<(&[u8; CIPHERTEXT], &[u8; X25519]), Error> {
    let mauvaise = || Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);
    let (chiffre, reste) = part
        .split_first_chunk::<CIPHERTEXT>()
        .ok_or_else(mauvaise)?;
    let x25519 = reste.try_into().map_err(|_| mauvaise())?;
    Ok((chiffre, x25519))
}

/// « Les deux parties DOIVENT traiter la part ECDH comme décrit en §4.2.8.2 de
/// la RFC 8446, contrôles de validité COMPRIS. » (§3.1.2 du brouillon)
///
/// Le contrôle de la RFC 8446 est celui-ci : un secret X25519 entièrement nul
/// signifie que le pair a envoyé un point d'ordre faible, et que le secret ne
/// dépend donc pas de notre clé. Le poursuivre reviendrait à chiffrer avec une
/// valeur que le pair a choisie seul.
fn verifier_contribution(secret: &x25519_dalek::SharedSecret) -> Result<(), Error> {
    if secret.was_contributory() {
        Ok(())
    } else {
        Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))
    }
}

/// Assemble le secret partagé : **ML-KEM d'abord**, X25519 ensuite (§3.1.3).
fn assembler(mlkem: &[u8], x25519: &[u8]) -> SharedSecret {
    let mut secret = Vec::with_capacity(SHARED_SECRET);
    secret.extend_from_slice(mlkem);
    secret.extend_from_slice(x25519);
    // `SharedSecret` prend possession du tampon et l'efface à sa destruction :
    // rien n'en subsiste ailleurs.
    SharedSecret::from(&secret[..])
}

#[cfg(test)]
mod tests {
    use super::{
        CLIENT_SHARE, SERVER_SHARE, SHARED_SECRET, X25519MlKem768, decouper_part_client,
        decouper_part_serveur,
    };
    use alloc::boxed::Box;
    use rustls::crypto::{SecureRandom, SupportedKxGroup};
    use rustls::{Error, NamedGroup};

    /// Un aléa de test, déterministe.
    ///
    /// Il n'est PAS cryptographique, et ne prétend pas l'être : il sert à ce
    /// qu'un échec se rejoue à l'identique. Le fournisseur réel apporte le sien.
    #[derive(Debug)]
    struct AleaDeTest(core::cell::Cell<u64>);

    // SAFETY : les tests l'emploient depuis un seul fil ; `SecureRandom` exige
    // `Send + Sync`, que `Cell` n'a pas. L'état est un simple compteur, et aucun
    // test ne le partage.
    unsafe impl Sync for AleaDeTest {}

    impl SecureRandom for AleaDeTest {
        fn fill(&self, buf: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
            for octet in buf.iter_mut() {
                let mut x = self.0.get();
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0.set(x);
                *octet = u8::try_from(x & 0xFF).unwrap_or(0);
            }
            Ok(())
        }
    }

    /// L'erreur est-elle un reproche fait au pair ?
    ///
    /// TOTAL, et c'est le point : un `matches!` engendre un bras `_ => false`
    /// que rien n'emprunte quand l'assertion réussit toujours.
    fn pair_fautif(erreur: &Error) -> bool {
        matches!(erreur, Error::PeerMisbehaved(_))
    }

    /// L'erreur d'un résultat dont la valeur ne se débogue pas.
    ///
    /// `CompletedKeyExchange` et `SharedSecret` n'implémentent pas `Debug` — et
    /// c'est heureux : un secret partagé qui s'affiche est un secret qui finit
    /// dans un journal. `expect_err` leur est donc inapplicable.
    /// TOTAL : `Result::err` est un appel, pas une branche à nous. Un
    /// `match … Ok(_) => panic!()` en ouvrirait une que rien n'emprunte.
    fn erreur_de<T>(resultat: Result<T, Error>) -> Option<Error> {
        resultat.err()
    }

    fn groupe() -> &'static X25519MlKem768 {
        let alea: &'static AleaDeTest =
            Box::leak(Box::new(AleaDeTest(core::cell::Cell::new(0x2545_F491))));
        Box::leak(Box::new(X25519MlKem768::new(alea)))
    }

    // ── L'aller-retour ──────────────────────────────────────────────────────

    #[test]
    fn les_deux_roles_arrivent_au_meme_secret() {
        // C'EST LA PROPRIÉTÉ QUI COMPTE. Si l'ordre des octets était faux des
        // deux côtés, ce test passerait quand même — c'est pourquoi il ne suffit
        // pas, et pourquoi l'interopérabilité avec OpenSSL existe.
        let groupe = groupe();
        let client = groupe.start().expect("part client");
        assert_eq!(client.pub_key().len(), CLIENT_SHARE);
        assert_eq!(client.group(), NamedGroup::X25519MLKEM768);

        let part_client = client.pub_key().to_vec();
        let serveur = groupe
            .start_and_complete(&part_client)
            .expect("part serveur");
        assert_eq!(serveur.pub_key.len(), SERVER_SHARE);
        assert_eq!(serveur.group, NamedGroup::X25519MLKEM768);
        assert_eq!(serveur.secret.secret_bytes().len(), SHARED_SECRET);

        let secret_client = client.complete(&serveur.pub_key).expect("secret");
        assert_eq!(
            secret_client.secret_bytes(),
            serveur.secret.secret_bytes(),
            "les deux côtés n'arrivent pas au même secret"
        );
    }

    #[test]
    fn les_tailles_sont_celles_de_la_specification() {
        // §3.1 du brouillon : 1216, 1120, 64.
        assert_eq!(CLIENT_SHARE, 1216);
        assert_eq!(SERVER_SHARE, 1120);
        assert_eq!(SHARED_SECRET, 64);
    }

    #[test]
    fn la_part_du_client_porte_ml_kem_puis_x25519() {
        // L'ORDRE EST INVERSÉ par rapport à la convention de nommage, et c'est le
        // brouillon qui le dit. Les 1184 premiers octets doivent se relire comme
        // une clé d'encapsulation ; s'ils étaient à la fin, ils ne le pourraient
        // pas.
        let client = groupe().start().expect("part client");
        let part = client.pub_key();
        let (encapsulation, _) = decouper_part_client(part).expect("découpable");
        assert!(
            ml_kem::ml_kem_768::EncapsulationKey::new(&(*encapsulation).into()).is_ok(),
            "les 1184 premiers octets ne sont pas une clé d'encapsulation"
        );
    }

    // ── Les refus ───────────────────────────────────────────────────────────

    #[test]
    fn une_part_de_mauvaise_longueur_est_refusee() {
        let groupe = groupe();
        for longueur in [0_usize, 1, CLIENT_SHARE - 1, CLIENT_SHARE + 1] {
            let part = alloc::vec![0_u8; longueur];
            assert!(
                groupe.start_and_complete(&part).is_err(),
                "une part de {longueur} octets aurait dû être refusée"
            );
        }
    }

    #[test]
    fn une_cle_d_encapsulation_invalide_est_refusee() {
        // « Le serveur DOIT effectuer le contrôle de §7.2 de FIPS 203 » — une
        // clé dont les coefficients sortent du module est refusée.
        let part = alloc::vec![0xFF_u8; CLIENT_SHARE];
        let erreur = erreur_de(groupe().start_and_complete(&part)).expect("refusée");
        assert!(pair_fautif(&erreur), "{erreur:?}");
        // Et le prédicat rend bien `false` sur une erreur qui n'est pas cela.
        assert!(!pair_fautif(&Error::FailedToGetRandomBytes));
    }

    #[test]
    fn une_reponse_de_serveur_mal_formee_est_refusee() {
        let groupe = groupe();
        for longueur in [0_usize, SERVER_SHARE - 1, SERVER_SHARE + 1] {
            let client = groupe.start().expect("part client");
            let reponse = alloc::vec![0_u8; longueur];
            assert!(
                client.complete(&reponse).is_err(),
                "une réponse de {longueur} octets aurait dû être refusée"
            );
        }
        // Et une réponse de la bonne longueur mais sans queue de tête.
        let client = groupe.start().expect("part client");
        assert!(client.complete(&alloc::vec![0_u8; SERVER_SHARE]).is_err());
    }

    #[test]
    fn un_point_x25519_d_ordre_faible_est_refuse() {
        // RFC 8446 §4.2.8.2 : un secret X25519 nul signifie que le pair a envoyé
        // un point d'ordre faible, et que le secret ne dépend pas de notre clé.
        // Le poursuivre reviendrait à chiffrer avec une valeur qu'il a choisie
        // seul.
        let groupe = groupe();
        let client = groupe.start().expect("part client");
        let part_client = client.pub_key().to_vec();
        let mut serveur = groupe
            .start_and_complete(&part_client)
            .expect("part serveur");
        // On remplace la part X25519 du serveur par le point nul.
        let debut = SERVER_SHARE - 32;
        serveur.pub_key[debut..].fill(0);
        let erreur = erreur_de(client.complete(&serveur.pub_key)).expect("refusée");
        assert!(pair_fautif(&erreur), "{erreur:?}");
    }

    #[test]
    fn un_point_x25519_d_ordre_faible_est_refuse_cote_serveur_aussi() {
        // Le contrôle de la RFC 8446 §4.2.8.2 vaut POUR LES DEUX CÔTÉS, et le
        // brouillon le redit. Ne le faire que côté client laisserait un pair
        // choisir seul le secret d'une connexion entrante.
        let groupe = groupe();
        let mut part = groupe.start().expect("part client").pub_key().to_vec();
        let debut = CLIENT_SHARE - 32;
        part[debut..].fill(0);
        let erreur = erreur_de(groupe.start_and_complete(&part)).expect("refusée");
        assert!(pair_fautif(&erreur), "{erreur:?}");
    }

    #[test]
    fn le_decoupage_verifie_les_longueurs() {
        assert!(decouper_part_client(&[0_u8; CLIENT_SHARE]).is_ok());
        assert!(decouper_part_client(&[0_u8; 10]).is_err());
        assert!(decouper_part_serveur(&[0_u8; SERVER_SHARE]).is_ok());
        assert!(decouper_part_serveur(&[0_u8; 10]).is_err());
    }

    /// Un aléa qui rend la main `apres` fois, puis échoue.
    ///
    /// Chaque appel à la source est un endroit où l'échec doit se propager. Une
    /// source qui échoue toujours n'éprouverait que le premier.
    #[derive(Debug)]
    struct AleaDefaillant(core::cell::Cell<usize>);

    // SAFETY : même raison que pour `AleaDeTest` — usage mono-fil dans les tests.
    unsafe impl Sync for AleaDefaillant {}

    impl SecureRandom for AleaDefaillant {
        fn fill(&self, buf: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
            let restants = self.0.get();
            if restants == 0 {
                return Err(rustls::crypto::GetRandomFailed);
            }
            self.0.set(restants.saturating_sub(1));
            buf.fill(0x42);
            Ok(())
        }
    }

    fn groupe_defaillant(apres: usize) -> &'static X25519MlKem768 {
        let alea: &'static AleaDefaillant =
            Box::leak(Box::new(AleaDefaillant(core::cell::Cell::new(apres))));
        Box::leak(Box::new(X25519MlKem768::new(alea)))
    }

    #[test]
    fn un_echec_de_la_source_d_alea_se_propage_partout() {
        // UNE CLÉ TIRÉE D'UN ALÉA MANQUANT SERAIT UNE CLÉ CONNUE. Chaque site
        // d'appel doit propager l'échec, et non poursuivre avec des zéros.
        for apres in [0_usize, 1] {
            assert!(
                groupe_defaillant(apres).start().is_err(),
                "`start` a survécu à un aléa défaillant après {apres} appel(s)"
            );
        }
        // Le rôle serveur en fait trois : l'aléa d'encapsulation, puis la clé
        // X25519. Le premier échec possible arrive après le décodage de la part.
        let part = groupe().start().expect("part client").pub_key().to_vec();
        for apres in [0_usize, 1] {
            assert!(
                groupe_defaillant(apres).start_and_complete(&part).is_err(),
                "`start_and_complete` a survécu à un aléa défaillant après {apres}"
            );
        }
    }

    #[test]
    fn le_groupe_se_nomme_et_se_debogue() {
        let groupe = groupe();
        assert_eq!(groupe.name(), NamedGroup::X25519MLKEM768);
        // Le point de code de la RFC : `0x11ec`.
        assert_eq!(u16::from(NamedGroup::X25519MLKEM768), 0x11ec);
        assert!(!std::format!("{groupe:?}").is_empty());
    }
}
