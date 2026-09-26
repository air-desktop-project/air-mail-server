// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La chaîne de requête : ce qu'elle a le droit de dire, et rien d'autre.
//!
//! # POURQUOI ELLE SE LIT ICI, ET NON DANS LE SERVEUR
//!
//! Jusqu'en 0.2.17, elle était **jetée** : le curseur `next` que rendait la
//! liste des messages ne pouvait pas être renvoyé, et seuls les cinquante plus
//! anciens étaient atteignables. La lire dans le code sans entrée-sortie, et
//! rendre au serveur une structure déjà typée, garde la grammaire là où elle
//! est éprouvée à cent pour cent.
//!
//! # CE QUI EST REFUSÉ, PLUTÔT QU'IGNORÉ
//!
//! Un paramètre inconnu, en double, vide, sans `=`, ou dont la valeur n'est pas
//! un entier décimal écrit d'une seule façon. **Ignorer ce qu'on ne comprend
//! pas** ferait croire au client qu'il a été entendu : un `limt=10` rendrait
//! cinquante messages, et personne ne saurait pourquoi.

use crate::error::{Error, Reason};

/// Ce qu'une requête peut dire. Tout est facultatif.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Query {
    /// `before=<uid>` : les messages d'UID STRICTEMENT inférieur — le curseur
    /// pour remonter dans le temps.
    pub before: Option<u32>,
    /// `limit=<n>` : combien au plus. Zéro est refusé : ne rien demander n'est
    /// pas une requête.
    pub limit: Option<u16>,
    /// `since=<modseq>` : les changements postérieurs à ce point du journal.
    pub since: Option<u64>,
}

impl Query {
    /// Aucun paramètre n'a été donné.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.before.is_none() && self.limit.is_none() && self.since.is_none()
    }
}

/// Lit une chaîne de requête — ce qui suit le `?`, sans lui.
///
/// # Errors
///
/// [`Reason::BadQuery`] pour tout ce qui n'est pas `nom=entier` séparés par
/// `&`, avec un nom connu, une seule fois chacun.
pub fn parse_query(brut: &[u8]) -> Result<Query, Error> {
    let mauvaise = Error::new(Reason::BadQuery);
    let mut lue = Query::default();
    if brut.is_empty() {
        return Ok(lue);
    }
    for paire in brut.split(|octet| *octet == b'&') {
        let rang = paire
            .iter()
            .position(|octet| *octet == b'=')
            .ok_or(mauvaise)?;
        let (nom, valeur) = paire.split_at(rang);
        let valeur = entier(valeur.get(1..).unwrap_or_default()).ok_or(mauvaise)?;
        match nom {
            b"before" if lue.before.is_none() => {
                lue.before = Some(u32::try_from(valeur).map_err(|_| mauvaise)?);
            }
            b"limit" if lue.limit.is_none() && valeur > 0 => {
                lue.limit = Some(u16::try_from(valeur).map_err(|_| mauvaise)?);
            }
            b"since" if lue.since.is_none() => lue.since = Some(valeur),
            _ => return Err(mauvaise),
        }
    }
    Ok(lue)
}

/// Un entier décimal écrit d'UNE seule façon : des chiffres, sans zéro de tête
/// (sauf `0` lui-même), et qui tient dans un `u64`.
///
/// **UNE SEULE ÉCRITURE PAR VALEUR** : `before=007` et `before=7` désignant la
/// même chose, deux caches les verraient comme deux requêtes.
fn entier(chiffres: &[u8]) -> Option<u64> {
    if chiffres.is_empty() || (chiffres.len() > 1 && chiffres.first() == Some(&b'0')) {
        return None;
    }
    let mut valeur = 0_u64;
    for chiffre in chiffres {
        if !chiffre.is_ascii_digit() {
            return None;
        }
        valeur = valeur
            .checked_mul(10)?
            .checked_add(u64::from(chiffre.saturating_sub(b'0')))?;
    }
    Some(valeur)
}

#[cfg(test)]
mod tests;
