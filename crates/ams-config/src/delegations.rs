// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les délégations : **qui atteint la boîte de qui, et pour quoi faire.**
//!
//! Voir `schema/ams-delegations.capnp` pour ce que ce fichier porte, et
//! pourquoi il n'entre jamais dans un jeton.

use alloc::string::String;
use alloc::vec::Vec;

use ams_auth::check_login;
use capnp::message::ReaderOptions;
use capnp::serialize;

use crate::ams_delegations_capnp::delegations;
use crate::codec::{Error, TRAVERSAL_LIMIT_WORDS, texte};

/// Ce qu'une délégation permet.
///
/// **TROIS DROITS, ET DEUX IMPLIQUENT LE TROISIÈME** : écrire dans une boîte
/// qu'on ne peut pas lire, ou répondre au nom d'une boîte dont on ne voit pas
/// le courrier, n'a pas de sens. Un jeu de droits qui le prétendrait ne se
/// construit pas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rights(u8);

impl Rights {
    /// Voir les boîtes et les messages.
    pub const READ: Self = Self(1);
    /// Changer les drapeaux, ranger, déplacer, supprimer — ce qui modifie la
    /// boîte.
    pub const WRITE: Self = Self(1 | 2);
    /// Soumettre un message AU NOM du titulaire : `From:` une de ses adresses.
    pub const SEND: Self = Self(1 | 4);

    /// Les bits, tels qu'ils se rangent.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Ces droits-ci couvrent-ils ceux-là ?
    #[must_use]
    pub const fn contains(self, autres: Self) -> bool {
        self.0 & autres.0 == autres.0
    }

    /// Les deux réunis.
    #[must_use]
    pub const fn with(self, autres: Self) -> Self {
        Self(self.0 | autres.0)
    }

    /// Des bits lus : **seulement les trois connus**, au moins la lecture, et
    /// la lecture dès que l'écriture ou l'envoi y est.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !7 != 0 || bits & 1 == 0 {
            return None;
        }
        Some(Self(bits))
    }

    /// Le droit que ce nom désigne : `read`, `write` ou `send`.
    #[must_use]
    pub fn from_name(nom: &str) -> Option<Self> {
        match nom {
            "read" => Some(Self::READ),
            "write" => Some(Self::WRITE),
            "send" => Some(Self::SEND),
            _ => None,
        }
    }

    /// Les noms des droits portés, dans un ordre fixe.
    #[must_use]
    pub fn names(self) -> Vec<&'static str> {
        [("read", 1_u8), ("write", 2), ("send", 4)]
            .into_iter()
            .filter(|&(_, bit)| self.0 & bit != 0)
            .map(|(nom, _)| nom)
            .collect()
    }
}

/// Une délégation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    /// Le compte qui reçoit l'accès.
    pub delegate: String,
    /// Le compte dont la boîte est atteinte.
    pub owner: String,
    /// Ce qu'il y peut faire.
    pub rights: Rights,
}

/// Lit un magasin de délégations.
///
/// # Ce qui est REFUSÉ au chargement
///
/// - un compte, délégué ou titulaire, que [`ams_auth::check_login`] refuse ;
/// - **une délégation de soi à soi** : elle ne donnerait rien, et laisserait
///   croire qu'il fallait la donner ;
/// - **deux délégations pour le même couple** : laquelle vaudrait ?
/// - des droits qui ne se construisent pas — un bit inconnu, aucun droit, ou
///   l'écriture sans la lecture.
///
/// # Errors
///
/// [`Error`].
pub fn decode_delegations(octets: &[u8]) -> Result<Vec<Delegation>, Error> {
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
    let lu: delegations::Reader<'_> = message.get_root()?;

    let mut tenues: Vec<Delegation> = Vec::new();
    for lue in lu.get_delegations()?.iter() {
        let delegate = texte(lue.get_delegate()?)?;
        let owner = texte(lue.get_owner()?)?;
        for login in [&delegate, &owner] {
            check_login(login).map_err(|cause| Error::WeakAccount {
                login: login.clone(),
                cause,
            })?;
        }
        let couple = alloc::format!("{delegate} → {owner}");
        if delegate == owner {
            return Err(Error::BadDelegation(couple));
        }
        let Some(rights) = Rights::from_bits(lue.get_rights()) else {
            return Err(Error::BadDelegation(couple));
        };
        if tenues
            .iter()
            .any(|tenue| tenue.delegate == delegate && tenue.owner == owner)
        {
            return Err(Error::DuplicateDelegation(couple));
        }
        tenues.push(Delegation {
            delegate,
            owner,
            rights,
        });
    }
    Ok(tenues)
}

/// Écrit un magasin de délégations.
///
/// # Errors
///
/// [`Error`] si l'encodage échoue — ce qui n'arrive que sur un défaut de la
/// bibliothèque.
pub fn encode_delegations(tenues: &[Delegation]) -> Result<Vec<u8>, Error> {
    let mut message = capnp::message::Builder::new_default();
    {
        let ecrit = message.init_root::<delegations::Builder<'_>>();
        let mut liste = ecrit.init_delegations(u32::try_from(tenues.len()).unwrap_or(u32::MAX));
        for (rang, tenue) in tenues.iter().enumerate() {
            let mut case = liste
                .reborrow()
                .get(u32::try_from(rang).unwrap_or(u32::MAX));
            case.set_delegate(&tenue.delegate);
            case.set_owner(&tenue.owner);
            case.set_rights(tenue.rights.bits());
        }
    }
    Ok(serialize::write_message_to_words(&message))
}

#[cfg(test)]
mod tests;
