//! Les comptes, leur validation, et la vérification d'un mot de passe.

use alloc::string::{String, ToString as _};
use alloc::vec::Vec;
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

/// Un compte : un nom, une empreinte, et les adresses qui lui arrivent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// Le nom de compte, tel que le pair l'enverra.
    ///
    /// **C'est aussi le nom du répertoire de sa boîte**, ce qui impose des
    /// contraintes que [`check_login`] énonce. Deux champs — un identifiant et
    /// un répertoire — auraient permis de les faire diverger.
    pub login: String,
    /// L'empreinte, au format PHC.
    pub hash: String,
    /// Les adresses d'enveloppe qui arrivent dans cette boîte.
    ///
    /// **Vide est licite** : un compte qui peut se connecter sans rien recevoir
    /// est un compte de soumission, et c'est une situation réelle. Ce n'est pas
    /// un oubli qu'il faudrait deviner.
    pub addresses: Vec<String>,
}

/// Ce qu'un nom de compte a le droit d'être.
///
/// # Il devient un nom de RÉPERTOIRE, et c'est là qu'est le danger
///
/// La boîte d'un compte est `<racine>/<login>/`. Un login de `../../etc` ferait
/// écrire hors de la racine ; un login vide ou réduit à `.` désignerait la
/// racine elle-même. Ce contrôle est donc une frontière de sécurité, pas une
/// question de goût — et il a lieu à l'ÉCRITURE du magasin comme à sa lecture,
/// parce qu'un fichier peut arriver autrement que par notre outil.
///
/// Sont refusés : le vide, tout `/`, l'octet nul, `.` et `..`, un point en tête
/// (un répertoire caché n'est pas ce qu'un administrateur croit lire), et
/// au-delà de 64 octets. Le reste est permis, **`@` et accents compris** : un
/// login est souvent une adresse, et beaucoup de gens ont un nom qui ne tient
/// pas dans l'ASCII.
///
/// # Errors
///
/// [`Error::BadLogin`].
pub fn check_login(login: &str) -> Result<(), Error> {
    let interdit = login.is_empty()
        || login.len() > 64
        || login == "."
        || login == ".."
        || login.starts_with('.')
        || login.contains('/')
        || login.contains('\0');
    if interdit {
        return Err(Error::BadLogin);
    }
    Ok(())
}

/// À quelle boîte cette adresse d'enveloppe mène-t-elle ?
///
/// # La comparaison replie la casse, ENTIÈREMENT
///
/// La RFC 5321 §2.4 réserve la casse de la partie locale à l'hôte de
/// destination. **C'est nous**, et nous choisissons de la replier : personne ne
/// retient si son adresse a une majuscule, et deux boîtes qui ne diffèrent que
/// par la casse seraient une source d'erreurs bien plus coûteuse que la nuance
/// qu'on abandonne. Le domaine, lui, est insensible à la casse par la RFC.
///
/// Le repliement est ASCII seulement : replier de l'Unicode demanderait des
/// tables, et deux formes normalisées différemment ne sont pas la même adresse.
#[must_use]
pub fn route<'a>(accounts: &'a [Account], address: &[u8]) -> Option<&'a Account> {
    accounts.iter().find(|compte| {
        compte
            .addresses
            .iter()
            .any(|connue| connue.as_bytes().eq_ignore_ascii_case(address))
    })
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
    /// Le nom de compte ne peut pas être un nom de répertoire.
    ///
    /// Voir [`check_login`] : c'est une frontière de sécurité, puisque ce nom
    /// devient un chemin.
    BadLogin,
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
            Error::BadLogin => f.write_str(
                "un nom de compte est aussi un nom de répertoire : ni vide, ni `.`, ni `..`, \
                 ni commençant par un point, sans `/` ni octet nul, et au plus 64 octets",
            ),
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
        Account, DUMMY_HASH, Error, MEMORY_KIB, PARALLELISM, TIME_COST, authenticate, check_login,
        check_stored, hash_password, route,
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
            addresses: vec![
                String::from("jean@example.com"),
                String::from("j.dupont@example.com"),
            ],
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
            addresses: vec::Vec::new(),
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
            addresses: vec::Vec::new(),
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
    fn une_adresse_mene_a_sa_boite_quelle_qu_en_soit_la_casse() {
        // Personne ne retient si son adresse a une majuscule. La RFC 5321 §2.4
        // réserve la casse de la partie locale à l'hôte de destination : c'est
        // nous, et nous la replions.
        let comptes = magasin();
        for adresse in [
            &b"jean@example.com"[..],
            b"JEAN@EXAMPLE.COM",
            b"Jean@Example.Com",
            b"j.dupont@example.com",
        ] {
            assert_eq!(
                route(&comptes, adresse).map(|compte| compte.login.as_str()),
                Some("jean"),
                "{adresse:?}"
            );
        }
    }

    #[test]
    fn une_adresse_inconnue_ne_mene_nulle_part() {
        // C'EST LA FIN DU FOURRE-TOUT : une adresse qu'aucun compte ne déclare
        // n'est pas acceptée « parce que le domaine est hébergé ». Un serveur
        // qui accepte tout ce qui passe est un piège à spam, pas une boîte.
        let comptes = magasin();
        for adresse in [
            &b"personne@example.com"[..],
            b"jean@ailleurs.example",
            b"jean",
            b"",
        ] {
            assert!(route(&comptes, adresse).is_none(), "{adresse:?}");
        }
        assert!(route(&[], b"jean@example.com").is_none());
    }

    #[test]
    fn un_nom_de_compte_est_aussi_un_nom_de_repertoire() {
        // LA FRONTIÈRE DE SÉCURITÉ : ce nom devient un chemin.
        for refuse in [
            "",           // désignerait la racine
            ".",          // idem
            "..",         // le parent de la racine
            "../../etc",  // hors de la racine, franchement
            "jean/paul",  // un sous-répertoire qu'on n'a pas demandé
            ".cache",     // un répertoire caché n'est pas ce qu'on croit lire
            "jean\0paul", // tronqué par un appel système
        ] {
            assert_eq!(check_login(refuse), Err(Error::BadLogin), "{refuse:?}");
        }
        // Et ce qui est permis l'est vraiment : `@` et accents compris, parce
        // qu'un login est souvent une adresse et que beaucoup de noms ne
        // tiennent pas dans l'ASCII.
        for permis in ["jean", "jean@example.com", "jean.dupont", "Jean-Élise", "j"] {
            assert_eq!(check_login(permis), Ok(()), "{permis:?}");
        }
        // Soixante-cinq octets, c'est un de trop.
        assert_eq!(check_login(&"a".repeat(65)), Err(Error::BadLogin));
        assert_eq!(check_login(&"a".repeat(64)), Ok(()));
    }

    #[test]
    fn les_erreurs_disent_quelque_chose_et_se_distinguent() {
        for erreur in [
            Error::Malformed,
            Error::NotArgon2id,
            Error::TooWeak,
            Error::Incomplete,
            Error::BadLogin,
        ] {
            assert!(format!("{erreur}").len() > 20, "{erreur:?}");
        }
        assert_ne!(Error::Malformed, Error::TooWeak);
        assert_eq!(Error::TooWeak, Error::TooWeak);
        // Un compte se compare et se débogue : `air-mail-admin` en liste.
        let compte = Account {
            login: String::from("jean"),
            hash: String::from(DUMMY_HASH),
            addresses: vec![String::from("jean@example.com")],
        };
        assert_eq!(compte, compte.clone());
        assert!(!format!("{compte:?}").is_empty());
    }
}
