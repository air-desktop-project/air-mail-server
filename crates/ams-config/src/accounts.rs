//! Le fichier de comptes : ce qu'il porte, et ce qu'il refuse.
//!
//! # Ce fichier ne contient AUCUN mot de passe
//!
//! Il porte des empreintes Argon2id au format PHC, d'où l'on ne remonte pas au
//! mot de passe. C'est l'unique raison d'être d'une fonction de dérivation, et
//! c'est pourquoi une fuite de ce fichier n'est pas une fuite des comptes — elle
//! reste, en revanche, un dictionnaire de noms à essayer.
//!
//! # Il est SÉPARÉ de la configuration, et pour trois raisons
//!
//! Les deux ne changent pas au même rythme ; ils ne méritent pas les mêmes
//! permissions ; et une fuite de l'un n'est pas une fuite de l'autre.

use alloc::vec::Vec;

use ams_auth::{Account, check_stored};
use capnp::message::ReaderOptions;
use capnp::serialize;

use crate::ams_accounts_capnp::accounts;
use crate::codec::{Error, TRAVERSAL_LIMIT_WORDS, texte};

/// Lit un fichier de comptes.
///
/// # Ce qui est REFUSÉ au chargement, plutôt que découvert plus tard
///
/// - un nom de compte vide — il ne peut correspondre à aucun pair ;
/// - **un nom en double** : deux empreintes pour un nom, c'est une question
///   sans réponse, et le premier arrivé l'emporterait en silence ;
/// - une empreinte que [`ams_auth::check_stored`] refuse — mauvais algorithme,
///   paramètres sous le plancher, empreinte incomplète. Une vérification emploie
///   les paramètres inscrits DANS l'empreinte : sans ce contrôle, un compte
///   haché faiblement serait vérifié faiblement, et le magasin paraîtrait sain.
///
/// # Errors
///
/// [`Error`].
pub fn decode_accounts(octets: &[u8]) -> Result<Vec<Account>, Error> {
    let mut reste = octets;
    let message = serialize::read_message_from_flat_slice(
        &mut reste,
        ReaderOptions {
            traversal_limit_in_words: Some(
                usize::try_from(TRAVERSAL_LIMIT_WORDS).unwrap_or(usize::MAX),
            ),
            nesting_limit: 8,
        },
    )?;
    let lu: accounts::Reader<'_> = message.get_root()?;

    let mut comptes: Vec<Account> = Vec::new();
    for compte in lu.get_accounts()?.iter() {
        let login = texte(compte.get_login()?)?;
        if login.is_empty() {
            return Err(Error::Empty("login"));
        }
        if comptes.iter().any(|connu| connu.login == login) {
            return Err(Error::DuplicateLogin(login));
        }
        let hash = texte(compte.get_hash()?)?;
        check_stored(&hash).map_err(|cause| Error::WeakAccount {
            login: login.clone(),
            cause,
        })?;
        comptes.push(Account { login, hash });
    }
    Ok(comptes)
}

/// Écrit un fichier de comptes.
///
/// # Errors
///
/// [`Error::Malformed`] si l'encodage échoue — ce qui n'arrive que sur un défaut
/// de la bibliothèque, jamais sur un magasin valide.
pub fn encode_accounts(comptes: &[Account]) -> Result<Vec<u8>, Error> {
    let mut message = capnp::message::Builder::new_default();
    {
        let ecrit = message.init_root::<accounts::Builder<'_>>();
        let mut liste = ecrit.init_accounts(u32::try_from(comptes.len()).unwrap_or(u32::MAX));
        for (rang, compte) in comptes.iter().enumerate() {
            let mut case = liste
                .reborrow()
                .get(u32::try_from(rang).unwrap_or(u32::MAX));
            case.set_login(&compte.login);
            case.set_hash(&compte.hash);
        }
    }
    Ok(serialize::write_message_to_words(&message))
}

#[cfg(test)]
mod tests {
    use super::{decode_accounts, encode_accounts};
    use crate::codec::Error;
    use alloc::string::{String, ToString as _};
    use alloc::vec;
    use alloc::vec::Vec;
    use ams_auth::{Account, DUMMY_HASH};

    fn compte(login: &str) -> Account {
        Account {
            login: String::from(login),
            // L'empreinte de personne fait un excellent compte de test : elle a
            // les vrais paramètres du produit, et n'ouvre rien.
            hash: DUMMY_HASH.to_string(),
        }
    }

    #[test]
    fn un_magasin_ecrit_se_relit_a_l_identique() {
        let original = vec![compte("jean"), compte("paul")];
        let relu =
            decode_accounts(&encode_accounts(&original).expect("encodable")).expect("relisible");
        assert_eq!(relu, original);
        assert_eq!(relu[0].login, "jean");
    }

    #[test]
    fn un_magasin_vide_est_licite() {
        // C'est l'état par défaut : un serveur sans comptes n'annonce pas `AUTH`.
        let vide: Vec<Account> = Vec::new();
        let relu = decode_accounts(&encode_accounts(&vide).expect("encodable")).expect("relisible");
        assert!(relu.is_empty());
    }

    #[test]
    fn un_nom_en_double_est_refuse() {
        // Deux empreintes pour un nom, c'est une question sans réponse. Le
        // premier arrivé l'emporterait en silence, et l'administrateur croirait
        // avoir changé un mot de passe.
        let octets = encode_accounts(&[compte("jean"), compte("jean")]).expect("encodable");
        let erreur = decode_accounts(&octets).expect_err("refusé");
        assert_eq!(erreur, Error::DuplicateLogin(String::from("jean")));
        // Le message NOMME le compte : sans lui, l'administrateur doit relire
        // son magasin ligne à ligne pour trouver lequel.
        let dit = alloc::format!("{erreur}");
        assert!(dit.contains("jean") && dit.contains("deux fois"), "{dit}");
    }

    #[test]
    fn un_nom_vide_est_refuse() {
        let mut mauvais = compte("jean");
        mauvais.login = String::new();
        let octets = encode_accounts(&[mauvais]).expect("encodable");
        assert_eq!(decode_accounts(&octets), Err(Error::Empty("login")));
    }

    #[test]
    fn une_empreinte_faible_est_refusee_et_le_message_nomme_le_compte() {
        // Nommer le compte n'est pas un détail : un magasin de trente lignes
        // sans nom oblige à les essayer une par une.
        let mut faible = compte("jean");
        faible.hash = String::from(
            "$argon2id$v=19$m=8,t=1,p=1$c2VpemUgb2N0ZXRzIGljaQ$\
             Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm8",
        );
        let octets = encode_accounts(&[faible]).expect("encodable");
        let erreur = decode_accounts(&octets).expect_err("refusé");
        let dit = alloc::format!("{erreur}");
        assert!(dit.contains("jean"), "{dit}");
        assert!(dit.contains("plancher"), "{dit}");
    }

    #[test]
    fn un_fichier_corrompu_ne_fait_jamais_paniquer_le_serveur() {
        // Même balayage que pour la configuration : chaque octet, trois masques.
        let sain = encode_accounts(&[compte("jean")]).expect("encodable");
        let mut refuses = 0_u32;
        let mut acceptes = 0_u32;
        for position in 0..sain.len() {
            for masque in [0xFF_u8, 0x01, 0x80] {
                let mut corrompu = sain.clone();
                corrompu[position] ^= masque;
                match decode_accounts(&corrompu) {
                    Ok(_) => acceptes = acceptes.saturating_add(1),
                    Err(_) => refuses = refuses.saturating_add(1),
                }
            }
        }
        assert!(refuses > 0, "aucune corruption n'a été détectée");
        assert!(
            acceptes > 0,
            "toutes les corruptions ont été refusées : le balayage ne traverse pas le chemin nominal"
        );
    }

    #[test]
    fn des_octets_qui_ne_sont_pas_un_message_sont_refuses() {
        assert!(decode_accounts(b"pas un message").is_err());
        assert!(decode_accounts(&[]).is_err());
    }
}
