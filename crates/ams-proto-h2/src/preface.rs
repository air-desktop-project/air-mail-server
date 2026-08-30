// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le préambule de connexion (§3.4).

use crate::error::{Cause, Error, ErrorCode};

/// Les vingt-quatre octets qu'un client envoie avant tout le reste.
///
/// # POURQUOI CES OCTETS-LÀ, ET PAS D'AUTRES
///
/// `PRI * HTTP/2.0` est une requête HTTP/1.1 qu'aucun serveur HTTP/1.1 ne peut
/// servir : la méthode `PRI` n'existe pas. Un serveur HTTP/1.1 qui recevrait ce
/// préambule répondra `501` et fermera, au lieu de commencer à lire des cadres
/// binaires comme des lignes de texte. Ce n'est donc pas une signature
/// arbitraire — **c'est une phrase choisie pour être mal comprise proprement**.
pub const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Ce que la lecture du préambule a donné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preface {
    /// Il en manque : lire davantage, puis rappeler.
    More,
    /// Il est là, et il occupe [`PREFACE`] octets.
    Complete,
}

/// Lit le préambule dans un tampon qui ne fait que croître.
///
/// # ON REFUSE DÈS LE PREMIER OCTET QUI DIFFÈRE
///
/// Attendre les vingt-quatre octets pour comparer laisserait un pair envoyer
/// vingt-trois octets et se taire, en occupant une connexion. Comparer ce qu'on
/// a, au fur et à mesure, refuse `GET / HTTP/1.1` au quatrième octet — c'est-à-dire
/// dès qu'on sait.
///
/// # Errors
///
/// [`Cause::BadPreface`], qui condamne la connexion : sans préambule, rien de ce
/// qui suit ne peut être lu, et il n'y a aucun flux à qui imputer la faute.
pub fn read_preface(tampon: &[u8]) -> Result<Preface, Error> {
    let vus = tampon.len().min(PREFACE.len());
    let (debut, attendu) = (
        tampon.get(..vus).unwrap_or_default(),
        PREFACE.get(..vus).unwrap_or_default(),
    );
    if debut != attendu {
        return Err(Error::connection(
            ErrorCode::ProtocolError,
            Cause::BadPreface,
        ));
    }
    match vus == PREFACE.len() {
        true => Ok(Preface::Complete),
        false => Ok(Preface::More),
    }
}

#[cfg(test)]
mod tests;
