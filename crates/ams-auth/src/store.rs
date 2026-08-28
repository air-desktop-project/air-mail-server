//! Les comptes, leur validation, et la vérification d'un mot de passe.

use alloc::string::{String, ToString as _};
use core::fmt;

use ams_sasl::Credentials;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher as _, PasswordVerifier as _};
use argon2::{Algorithm, Argon2, Params, Version};

/// Mémoire employée par une vérification, en kibioctets (OWASP).
pub const MEMORY_KIB: u32 = 19_456;
/// Nombre de passes (OWASP).
pub const TIME_COST: u32 = 2;
/// Voies parallèles (OWASP).
pub const PARALLELISM: u32 = 1;

/// Une empreinte de PERSONNE, aux paramètres du produit.
///
/// # À quoi sert une empreinte que personne ne peut ouvrir
///
/// À faire durer un compte inconnu **aussi longtemps** qu'un compte connu.
/// Sans elle, un nom absent du magasin répondrait tout de suite et un nom
/// présent après trente millisecondes : l'écart se mesure, se répète, et rend
/// le fichier de comptes énumérable **sans connaître un seul mot de passe**.
///
/// Ce n'est pas un secret — le mot de passe qui l'a produite n'existe nulle
/// part, et n'est pas censé être devinable ni retrouvable. Son unique rôle est
/// de consommer le même temps et la même mémoire qu'une vraie vérification.
pub const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$YWlyLW1haWwtc2VydmVyLWR1bW15\
                              $8MOaCJHIT7hh8m/QIhWKKUdSMDBDcVYQnCWWm1uXA0Y";

/// Un compte : un nom, et une empreinte au format PHC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// Le nom de compte, tel que le pair l'enverra.
    pub login: String,
    /// L'empreinte, au format PHC.
    pub hash: String,
}

/// Ce qui rend un magasin ou une empreinte irrecevable.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// L'empreinte n'est pas une chaîne PHC lisible.
    Malformed,
    /// L'algorithme n'est pas `argon2id`.
    ///
    /// `argon2i` et `argon2d` sont refusés : la RFC 9106 §4 recommande
    /// l'hybride quand on ne sait rien de l'attaquant, et c'est notre cas.
    NotArgon2id,
    /// Les paramètres de l'empreinte sont **sous le plancher** du produit.
    ///
    /// Une vérification emploie les paramètres de l'EMPREINTE. Une empreinte
    /// faible serait donc vérifiée faiblement, en silence, et le magasin
    /// paraîtrait sain.
    TooWeak,
    /// Le sel ou la sortie manque.
    Incomplete,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Malformed => f.write_str("l'empreinte n'est pas une chaîne PHC lisible"),
            Error::NotArgon2id => f.write_str("l'empreinte n'est pas de l'`argon2id`"),
            Error::TooWeak => write!(
                f,
                "les paramètres de l'empreinte sont sous le plancher du produit \
                 (m={MEMORY_KIB}, t={TIME_COST}, p={PARALLELISM}) : ce compte doit être réécrit"
            ),
            Error::Incomplete => f.write_str("l'empreinte n'a ni sel ni sortie"),
        }
    }
}

impl core::error::Error for Error {}

/// L'instance Argon2 du produit.
fn argon2() -> Argon2<'static> {
    // `Params::new` ne peut échouer que sur des valeurs hors bornes ; les
    // nôtres sont des constantes, et un test le vérifie. Un `?` ouvrirait ici
    // une branche qu'aucun test ne peut atteindre, ce que C2 refuse.
    let params = Params::new(MEMORY_KIB, TIME_COST, PARALLELISM, None)
        .expect("les paramètres du produit sont dans les bornes d'Argon2");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Calcule l'empreinte d'un mot de passe, avec **le sel qu'on lui donne**.
///
/// Le sel vient de l'appelant : cette crate est sans entrée-sortie, et n'a donc
/// pas de source d'aléa. C'est aussi ce qui rend le hachage reproductible sous
/// test. Le sel doit faire au moins seize octets et être **tiré au hasard pour
/// chaque compte** — deux comptes au même sel se cassent une seule fois.
///
/// # Errors
///
/// [`Error::Malformed`] si le sel est d'une taille qu'Argon2 refuse.
pub fn hash_password(password: &[u8], salt: &[u8]) -> Result<String, Error> {
    argon2()
        .hash_password_with_salt(password, salt)
        .map(|empreinte| empreinte.to_string())
        .map_err(|_| Error::Malformed)
}

/// Cette empreinte est-elle acceptable pour ce produit ?
///
/// # Errors
///
/// [`Error`] — illisible, mauvais algorithme, paramètres trop faibles, ou
/// incomplète.
pub fn check_stored(phc: &str) -> Result<(), Error> {
    let lue = PasswordHash::new(phc).map_err(|_| Error::Malformed)?;
    if lue.algorithm.as_str() != "argon2id" {
        return Err(Error::NotArgon2id);
    }
    // Sans sel ni sortie, il n'y a rien à comparer : `verify_password`
    // échouerait à chaque tentative, et le compte serait mort sans le dire.
    if lue.salt.is_none() || lue.hash.is_none() {
        return Err(Error::Incomplete);
    }
    let params = Params::try_from(&lue).map_err(|_| Error::Malformed)?;
    if params.m_cost() < MEMORY_KIB || params.t_cost() < TIME_COST || params.p_cost() < PARALLELISM
    {
        return Err(Error::TooWeak);
    }
    Ok(())
}

/// Ces identifiants ouvrent-ils une session ?
///
/// # Le temps que prend un refus ne dit pas POURQUOI il refuse
///
/// Un nom absent du magasin fait tout de même une vérification, contre
/// [`DUMMY_HASH`]. Sans cela, l'écart de temps entre « ce compte n'existe pas »
/// et « ce mot de passe est faux » rendrait le fichier de comptes énumérable
/// sans en connaître un seul mot de passe.
///
/// La comparaison finale, elle, est à temps constant : c'est `argon2` qui la
/// fait, et il compare des empreintes, jamais des mots de passe.
#[must_use]
pub fn authenticate(accounts: &[Account], credentials: &Credentials<'_>) -> bool {
    // RFC 4616 §2 : une identité d'autorisation VIDE veut dire « moi-même ».
    // Toute autre demande est une demande d'agir POUR QUELQU'UN D'AUTRE, et ce
    // serveur ne sait pas déléguer. L'accepter en l'ignorant serait pire que la
    // refuser : le pair croirait agir pour un tiers.
    if !credentials.authorization_identity.is_empty()
        && credentials.authorization_identity != credentials.authentication_identity
    {
        return false;
    }

    let empreinte = accounts
        .iter()
        .find(|compte| compte.login.as_bytes() == credentials.authentication_identity)
        .map_or(DUMMY_HASH, |compte| compte.hash.as_str());

    let Ok(lue) = PasswordHash::new(empreinte) else {
        // Une empreinte illisible ne peut pas ouvrir de session. `check_stored`
        // l'a normalement écartée au chargement ; ce chemin reste emprunté par
        // les magasins que personne n'a validés.
        return false;
    };
    let juste = argon2().verify_password(credentials.password, &lue).is_ok();

    // Le compte inconnu a coûté le même temps, et il refuse tout de même.
    juste
        && accounts
            .iter()
            .any(|compte| compte.login.as_bytes() == credentials.authentication_identity)
}

#[cfg(test)]
mod tests {
    use super::{
        Account, DUMMY_HASH, Error, MEMORY_KIB, PARALLELISM, TIME_COST, authenticate, check_stored,
        hash_password,
    };
    use alloc::string::{String, ToString as _};
    use alloc::{format, vec};
    use ams_sasl::Credentials;

    /// Un sel de test — fixe, parce qu'un test reproductible vaut mieux qu'un
    /// test qui échoue une fois sur mille.
    const SEL: &[u8] = b"seize octets ici";

    /// Une empreinte FAIBLE, écrite à la main : c'est exactement ce que
    /// `check_stored` doit refuser, et la fabriquer avec les vrais paramètres
    /// coûterait des secondes à chaque exécution.
    const FAIBLE: &str = "$argon2id$v=19$m=8,t=1,p=1$c2VpemUgb2N0ZXRzIGljaQ$\
                          Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm8";

    fn identifiants<'a>(compte: &'a [u8], secret: &'a [u8]) -> Credentials<'a> {
        Credentials {
            authorization_identity: b"",
            authentication_identity: compte,
            password: secret,
        }
    }

    fn magasin() -> vec::Vec<Account> {
        vec![Account {
            login: String::from("jean"),
            // Le seul hachage aux vrais paramètres de toute la suite : les
            // autres tests s'appuient sur des empreintes faibles, qui se
            // vérifient en une milliseconde au lieu de trois secondes en
            // débogage.
            hash: hash_password(b"ouvre-toi", SEL).expect("hachable"),
        }]
    }

    #[test]
    fn le_bon_mot_de_passe_ouvre_et_les_autres_non() {
        let comptes = magasin();
        assert!(authenticate(&comptes, &identifiants(b"jean", b"ouvre-toi")));
        assert!(!authenticate(&comptes, &identifiants(b"jean", b"autre")));
        assert!(!authenticate(&comptes, &identifiants(b"jean", b"")));
    }

    #[test]
    fn un_compte_inconnu_est_refuse_apres_avoir_coute_le_meme_travail() {
        // On ne peut pas mesurer un temps dans un test sans le rendre fragile.
        // Ce qu'on éprouve, c'est le CHEMIN : un nom inconnu passe par une
        // vérification (contre `DUMMY_HASH`) et refuse ensuite.
        let comptes = magasin();
        assert!(!authenticate(
            &comptes,
            &identifiants(b"paul", b"ouvre-toi")
        ));
        assert!(!authenticate(&[], &identifiants(b"jean", b"ouvre-toi")));
    }

    #[test]
    fn l_empreinte_de_personne_a_bien_les_parametres_du_produit() {
        // Si les paramètres changeaient sans que `DUMMY_HASH` suive, un compte
        // inconnu coûterait moins cher qu'un compte connu — et l'écart de temps
        // rendrait le magasin énumérable. C'est le seul lien entre les deux, et
        // il est vérifié plutôt que confié à la mémoire de quelqu'un.
        assert_eq!(check_stored(DUMMY_HASH), Ok(()));
        assert!(DUMMY_HASH.contains(&format!("m={MEMORY_KIB},t={TIME_COST},p={PARALLELISM}")));
        // Et personne ne l'ouvre.
        let comptes = vec![Account {
            login: String::from("personne"),
            hash: DUMMY_HASH.to_string(),
        }];
        for essai in [&b""[..], b"motdepasse", b"personne", DUMMY_HASH.as_bytes()] {
            assert!(!authenticate(&comptes, &identifiants(b"personne", essai)));
        }
    }

    #[test]
    fn une_identite_d_autorisation_etrangere_est_refusee() {
        // « Je suis jean, et j'agis pour postmaster » : ce serveur ne sait pas
        // déléguer, et l'ignorer ferait croire au pair qu'il agit pour un tiers.
        let comptes = magasin();
        let demande = Credentials {
            authorization_identity: b"postmaster",
            authentication_identity: b"jean",
            password: b"ouvre-toi",
        };
        assert!(!authenticate(&comptes, &demande));
        // La même identité des deux côtés, en revanche, est licite.
        let soi_meme = Credentials {
            authorization_identity: b"jean",
            authentication_identity: b"jean",
            password: b"ouvre-toi",
        };
        assert!(authenticate(&comptes, &soi_meme));
    }

    #[test]
    fn une_empreinte_illisible_n_ouvre_rien() {
        let comptes = vec![Account {
            login: String::from("jean"),
            hash: String::from("ceci n'est pas du PHC"),
        }];
        assert!(!authenticate(
            &comptes,
            &identifiants(b"jean", b"ouvre-toi")
        ));
    }

    #[test]
    fn une_empreinte_sous_le_plancher_est_refusee_au_chargement() {
        // LE PIÈGE QUE CE CONTRÔLE FERME : une vérification emploie les
        // paramètres inscrits DANS l'empreinte. Sans ce contrôle, un compte
        // haché en `m=8,t=1` serait vérifié en `m=8,t=1`, et le magasin
        // paraîtrait sain.
        assert_eq!(check_stored(FAIBLE), Err(Error::TooWeak));
    }

    #[test]
    fn des_parametres_hors_des_bornes_d_argon2_sont_refuses() {
        // `m=1` passe l'analyse PHC — c'est un entier — mais Argon2 exige au
        // moins `8 × p` kibioctets. L'empreinte n'est donc pas une empreinte
        // Argon2 du tout, et `TooWeak` mentirait sur la nature du défaut.
        let hors_bornes = FAIBLE.replace("m=8,", "m=1,");
        assert_eq!(check_stored(&hors_bornes), Err(Error::Malformed));
    }

    #[test]
    fn seul_argon2id_est_accepte() {
        let argon2i = FAIBLE.replace("argon2id", "argon2i");
        assert_eq!(check_stored(&argon2i), Err(Error::NotArgon2id));
    }

    #[test]
    fn une_empreinte_incomplete_ou_illisible_est_refusee() {
        assert_eq!(check_stored("pas du PHC"), Err(Error::Malformed));
        // Un PHC bien formé mais sans sel ni sortie : `verify_password`
        // échouerait à chaque tentative, et le compte serait mort sans le dire.
        assert_eq!(
            check_stored("$argon2id$v=19$m=19456,t=2,p=1"),
            Err(Error::Incomplete)
        );
    }

    #[test]
    fn une_empreinte_du_produit_passe_ses_propres_controles() {
        let empreinte = hash_password(b"ouvre-toi", SEL).expect("hachable");
        assert_eq!(check_stored(&empreinte), Ok(()));
        assert!(empreinte.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
    }

    #[test]
    fn un_sel_trop_court_est_refuse() {
        assert_eq!(hash_password(b"ouvre-toi", b"court"), Err(Error::Malformed));
    }

    #[test]
    fn les_erreurs_disent_quelque_chose_et_se_distinguent() {
        for erreur in [
            Error::Malformed,
            Error::NotArgon2id,
            Error::TooWeak,
            Error::Incomplete,
        ] {
            assert!(format!("{erreur}").len() > 20, "{erreur:?}");
        }
        assert_ne!(Error::Malformed, Error::TooWeak);
        assert_eq!(Error::TooWeak, Error::TooWeak);
        // Un compte se compare et se débogue : `air-mail-admin` en liste.
        let compte = Account {
            login: String::from("jean"),
            hash: String::from(DUMMY_HASH),
        };
        assert_eq!(compte, compte.clone());
        assert!(!format!("{compte:?}").is_empty());
    }
}
