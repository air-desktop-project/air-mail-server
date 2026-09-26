// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le magasin des mots de passe applicatifs : ce qu'il range, et ce qu'il
//! refuse de relire.
//!
//! Voir `ams_auth::AppPassword` pour ce qu'un mot de passe applicatif est, et
//! `schema/ams-app-passwords.capnp` pour ce que ce fichier porte.

use alloc::vec::Vec;

use ams_auth::{APP_ID_CHIFFRES, AppPassword, check_login};
use capnp::message::ReaderOptions;
use capnp::serialize;

use crate::ams_app_passwords_capnp::app_passwords;
use crate::codec::{Error, TRAVERSAL_LIMIT_WORDS, texte};

/// Ce qu'un nom de mot de passe applicatif peut faire de long.
///
/// La même borne que pour un appareil, et pour la même raison : il ne sert
/// qu'à l'humain qui choisit lequel révoquer.
pub const APP_NOM_OCTETS_MAX: usize = 128;

/// Lit un magasin de mots de passe applicatifs.
///
/// # Ce qui est REFUSÉ au chargement, plutôt que découvert plus tard
///
/// - un compte que [`ams_auth::check_login`] refuse ;
/// - **un identifiant qui n'a pas sa forme**, ou **un condensat qui ne fait pas
///   trente-deux octets** : ni l'un ni l'autre ne pourrait jamais ouvrir, et
///   son propriétaire le croirait valable ;
/// - **un identifiant en double** : c'est lui qui trouve l'entrée, et l'une des
///   deux n'ouvrirait jamais ;
/// - un nom vide, ou plus long que sa borne.
///
/// # Errors
///
/// [`Error`].
pub fn decode_app_passwords(octets: &[u8]) -> Result<Vec<AppPassword>, Error> {
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
    let lu: app_passwords::Reader<'_> = message.get_root()?;

    let mut entrees: Vec<AppPassword> = Vec::new();
    for entree in lu.get_app_passwords()?.iter() {
        let login = texte(entree.get_login()?)?;
        check_login(&login).map_err(|cause| Error::WeakAccount {
            login: login.clone(),
            cause,
        })?;

        let id = texte(entree.get_id()?)?;
        if id.len() != APP_ID_CHIFFRES
            || !id
                .bytes()
                .all(|octet| octet.is_ascii_digit() || (b'a'..=b'f').contains(&octet))
        {
            return Err(Error::BadAppPassword(id));
        }
        if entrees.iter().any(|connue| connue.id == id) {
            return Err(Error::DuplicateAppPassword(id));
        }

        let name = texte(entree.get_name()?)?;
        if name.is_empty() {
            return Err(Error::Empty("app password name"));
        }
        if name.len() > APP_NOM_OCTETS_MAX {
            return Err(Error::TooLong("app password name"));
        }

        let lu_condensat = entree.get_digest()?;
        let mut digest = [0_u8; 32];
        if lu_condensat.len() != digest.len() {
            return Err(Error::BadAppPassword(id));
        }
        digest.copy_from_slice(lu_condensat);

        entrees.push(AppPassword {
            login,
            id,
            name,
            created: entree.get_created(),
            last_used: entree.get_last_used(),
            digest,
        });
    }
    Ok(entrees)
}

/// Écrit un magasin de mots de passe applicatifs.
///
/// # Errors
///
/// [`Error::Malformed`] si l'encodage échoue — ce qui n'arrive que sur un défaut
/// de la bibliothèque, jamais sur un magasin valide.
pub fn encode_app_passwords(entrees: &[AppPassword]) -> Result<Vec<u8>, Error> {
    let mut message = capnp::message::Builder::new_default();
    {
        let ecrit = message.init_root::<app_passwords::Builder<'_>>();
        let mut liste = ecrit.init_app_passwords(u32::try_from(entrees.len()).unwrap_or(u32::MAX));
        for (rang, entree) in entrees.iter().enumerate() {
            let mut case = liste
                .reborrow()
                .get(u32::try_from(rang).unwrap_or(u32::MAX));
            case.set_login(&entree.login);
            case.set_id(&entree.id);
            case.set_name(&entree.name);
            case.set_created(entree.created);
            case.set_last_used(entree.last_used);
            case.set_digest(&entree.digest);
        }
    }
    Ok(serialize::write_message_to_words(&message))
}

#[cfg(test)]
mod tests;
