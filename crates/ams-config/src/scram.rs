// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le magasin des vérificateurs SCRAM : ce qu'il porte, et ce qu'il refuse.
//!
//! # POURQUOI IL EST SÉPARÉ DE `comptes.bin`
//!
//! Ce n'est pas un rangement, c'est la condition à laquelle SCRAM a été
//! accepté — voir `schema/ams-scram.capnp`, qui la cite. §9 de RFC 5802 : une
//! `ServerKey` s'emploie telle quelle pour usurper le serveur, là où une
//! empreinte Argon2id demande d'abord d'être cassée. Elle ne peut donc vivre
//! ni à côté des empreintes, ni en clair.
//!
//! # CE QUE CE MODULE VÉRIFIE, ET CE QU'IL NE PEUT PAS VÉRIFIER
//!
//! Il vérifie la FORME : un login recevable, pas de doublon, des tailles
//! exactes pour le sel et le nonce, un compte d'itérations au-dessus du
//! minimum de RFC 7677. Il ne vérifie RIEN du contenu scellé — il n'a pas la
//! clé, et c'est tout l'objet du scellement. Un vérificateur qui n'ouvre pas se
//! découvre à l'ouverture de session, par [`ams_auth::scram_ouvrir`].

use alloc::vec::Vec;

use ams_auth::{NONCE_OCTETS, SEL_OCTETS, ScramVerifier, check_login};
use capnp::message::ReaderOptions;
use capnp::serialize;

use crate::ams_scram_capnp::scram_store;
use crate::codec::{Error, TRAVERSAL_LIMIT_WORDS, texte};

/// Lit un magasin de vérificateurs SCRAM.
///
/// # Ce qui est REFUSÉ au chargement, plutôt que découvert plus tard
///
/// - un login que [`ams_auth::check_login`] refuse — le même contrôle que pour
///   `comptes.bin`, et pour la même raison : ce nom désigne aussi un
///   répertoire ;
/// - **un login en double** : deux vérificateurs pour un compte, c'est une
///   question sans réponse, et le premier arrivé l'emporterait en silence ;
/// - un sel ou un nonce de mauvaise taille. **UN NONCE TRONQUÉ N'EST PAS UNE
///   MALADRESSE** : `ChaCha20-Poly1305` en veut douze octets, et un magasin qui
///   en porterait onze ferait échouer l'ouverture d'un compte au moment le plus
///   coûteux — pendant une ouverture de session, sans dire pourquoi ;
/// - un compte d'itérations sous le minimum de RFC 7677 §3.1. Le nombre est lu
///   DANS le fichier, jamais pris du code : c'est ce qui permet de le faire
///   évoluer sans invalider les comptes. Sans ce contrôle, un vérificateur posé
///   à 1 000 tours serait vérifié à 1 000 tours, et le magasin paraîtrait sain.
///
/// # Errors
///
/// [`Error`] — message illisible, login refusé ou en double, taille fausse,
/// itérations trop basses.
pub fn decode_scram(octets: &[u8]) -> Result<Vec<ScramVerifier>, Error> {
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
    let lu: scram_store::Reader<'_> = message.get_root()?;

    let mut verificateurs: Vec<ScramVerifier> = Vec::new();
    for entree in lu.get_verifiers()?.iter() {
        let login = texte(entree.get_login()?)?;
        check_login(&login).map_err(|cause| Error::WeakAccount {
            login: login.clone(),
            cause,
        })?;
        if verificateurs
            .iter()
            .any(|connu| connu.login.eq_ignore_ascii_case(&login))
        {
            return Err(Error::DuplicateLogin(login));
        }

        let sel = octets_exacts(entree.get_salt()?, "salt")?;
        let nonce = octets_exacts(entree.get_nonce()?, "nonce")?;
        let iterations = entree.get_iterations();
        if iterations < ams_sasl::ITERATIONS_MIN {
            return Err(Error::Empty("iterations"));
        }
        let scelle = entree.get_sealed()?;
        if scelle.is_empty() {
            return Err(Error::Empty("sealed"));
        }

        verificateurs.push(ScramVerifier {
            login,
            sel,
            iterations,
            nonce,
            scelle: scelle.to_vec(),
            lie: entree.get_bound(),
        });
    }
    Ok(verificateurs)
}

/// Écrit un magasin de vérificateurs SCRAM.
///
/// # Errors
///
/// [`Error`] si l'encodage échoue — ce qui n'arrive que sur un défaut de la
/// bibliothèque, jamais sur un magasin valide.
pub fn encode_scram(verificateurs: &[ScramVerifier]) -> Result<Vec<u8>, Error> {
    let mut message = capnp::message::Builder::new_default();
    {
        let ecrit = message.init_root::<scram_store::Builder<'_>>();
        let mut liste =
            ecrit.init_verifiers(u32::try_from(verificateurs.len()).unwrap_or(u32::MAX));
        for (rang, v) in verificateurs.iter().enumerate() {
            let mut case = liste
                .reborrow()
                .get(u32::try_from(rang).unwrap_or(u32::MAX));
            case.set_login(&v.login);
            case.set_salt(&v.sel);
            case.set_iterations(v.iterations);
            case.set_nonce(&v.nonce);
            case.set_sealed(&v.scelle);
            case.set_bound(v.lie);
        }
    }
    Ok(serialize::write_message_to_words(&message))
}

/// Un champ d'octets de taille EXACTE, ou l'erreur qui le dit.
///
/// Le type de retour porte la taille attendue : c'est le compilateur qui
/// l'impose aux deux appelants, et non une constante qu'on pourrait confondre.
fn octets_exacts<const N: usize>(lu: &[u8], champ: &'static str) -> Result<[u8; N], Error> {
    if lu.len() != N {
        return Err(Error::Empty(champ));
    }
    let mut sortie = [0_u8; N];
    for (place, octet) in sortie.iter_mut().zip(lu) {
        *place = *octet;
    }
    Ok(sortie)
}

/// Les deux tailles que ce module impose viennent d'`ams-auth`, et non d'ici :
/// deux vérités pour une longueur de sel finiraient par diverger.
const _: () = assert!(SEL_OCTETS == 16 && NONCE_OCTETS == 12);

#[cfg(test)]
mod tests;
