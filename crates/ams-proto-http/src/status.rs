// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Un code d'état (RFC 9110 §15).
//!
//! # NI h2 NI h3 NE TRANSPORTENT DE PHRASE DE RAISON
//!
//! `HTTP/1.1 404 Not Found` portait un texte à côté du nombre. RFC 9113 §8.3.2 et
//! RFC 9114 §4.3.2 l'ont supprimé : `:status` vaut trois chiffres, et rien
//! d'autre. C'est une bonne nouvelle — cette phrase était un endroit où écrire
//! du texte venu d'ailleurs dans une ligne de protocole.

use crate::Error;

/// Un code d'état, entre 100 et 599.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct StatusCode(u16);

impl StatusCode {
    /// `200 OK`.
    pub const OK: Self = Self(200);
    /// `201 Created`.
    pub const CREATED: Self = Self(201);
    /// `204 No Content`.
    pub const NO_CONTENT: Self = Self(204);
    /// `304 Not Modified`.
    pub const NOT_MODIFIED: Self = Self(304);
    /// `400 Bad Request`.
    pub const BAD_REQUEST: Self = Self(400);
    /// `401 Unauthorized`.
    pub const UNAUTHORIZED: Self = Self(401);
    /// `403 Forbidden`.
    pub const FORBIDDEN: Self = Self(403);
    /// `404 Not Found`.
    pub const NOT_FOUND: Self = Self(404);
    /// `405 Method Not Allowed`.
    pub const METHOD_NOT_ALLOWED: Self = Self(405);
    /// `413 Content Too Large`.
    pub const CONTENT_TOO_LARGE: Self = Self(413);
    /// `414 URI Too Long`.
    pub const URI_TOO_LONG: Self = Self(414);
    /// `415 Unsupported Media Type`.
    pub const UNSUPPORTED_MEDIA_TYPE: Self = Self(415);
    /// `429 Too Many Requests`.
    pub const TOO_MANY_REQUESTS: Self = Self(429);
    /// `431 Request Header Fields Too Large`.
    pub const HEADER_FIELDS_TOO_LARGE: Self = Self(431);
    /// `500 Internal Server Error`.
    pub const INTERNAL_SERVER_ERROR: Self = Self(500);
    /// `501 Not Implemented`.
    pub const NOT_IMPLEMENTED: Self = Self(501);
    /// `503 Service Unavailable`.
    pub const SERVICE_UNAVAILABLE: Self = Self(503);

    /// Ce qu'un `:status` occupe : trois chiffres, toujours.
    pub const OCTETS: usize = 3;

    /// Construit un code d'état.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedFieldValue`] hors de `100..=599` : §15 ne définit pas
    /// d'autre plage, et un `042` ferait écrire trois chiffres qu'aucun client
    /// ne saurait classer.
    pub const fn new(valeur: u16) -> Result<Self, Error> {
        if valeur < 100 || valeur > 599 {
            return Err(Error::MalformedFieldValue);
        }
        Ok(Self(valeur))
    }

    /// La valeur numérique.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }

    /// La classe : `2` pour `2xx`, `4` pour `4xx`…
    #[must_use]
    pub const fn class(self) -> u16 {
        self.0 / 100
    }

    /// **CETTE RÉPONSE PEUT-ELLE PORTER UN CORPS ?**
    ///
    /// §15.3.5 et §15.4.5 : `204` et `304` n'en portent JAMAIS, et une réponse
    /// informative `1xx` non plus. En écrire un ferait lire ce corps comme le
    /// message suivant — c'est la contrebande de réponse, le pendant exact de
    /// celle des requêtes.
    #[must_use]
    pub const fn allows_body(self) -> bool {
        self.0 != 204 && self.0 != 304 && self.class() != 1
    }

    /// Écrit les trois chiffres, sans phrase de raison.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] si `out` ne suffit pas.
    pub fn write(self, out: &mut [u8]) -> Result<&[u8], Error> {
        let place = out.get_mut(..Self::OCTETS).ok_or(Error::BufferTooSmall {
            needed: Self::OCTETS,
        })?;
        // TROIS CHIFFRES, ET LA VALEUR EST DÉJÀ BORNÉE : `new` a refusé tout ce
        // qui ne tient pas sur trois. Écrire une garde ici serait affirmer une
        // impossibilité sans la vérifier.
        let mut reste = self.0;
        for chiffre in place.iter_mut().rev() {
            *chiffre = b'0'.saturating_add(u8::try_from(reste % 10).unwrap_or_default());
            reste /= 10;
        }
        out.get(..Self::OCTETS).ok_or(Error::BufferTooSmall {
            needed: Self::OCTETS,
        })
    }

    /// Lit un `:status` : trois chiffres, et rien d'autre.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedFieldValue`] pour ce qui n'est pas trois chiffres
    /// décimaux, ou dont la valeur sort de `100..=599`.
    pub fn parse(texte: &[u8]) -> Result<Self, Error> {
        // **EXACTEMENT TROIS CHIFFRES** (§8.3.2) : `20` et `0200` sont l'un et
        // l'autre irrecevables. Les accepter ferait lire `0200` comme `200` par
        // ce serveur et comme une faute par le suivant.
        let chiffres = match texte {
            [a, b, c] if a.is_ascii_digit() && b.is_ascii_digit() && c.is_ascii_digit() => {
                [*a, *b, *c]
            }
            _ => return Err(Error::MalformedFieldValue),
        };
        let mut valeur = 0_u16;
        for chiffre in chiffres {
            valeur = valeur
                .saturating_mul(10)
                .saturating_add(u16::from(chiffre.wrapping_sub(b'0')));
        }
        Self::new(valeur)
    }
}

#[cfg(test)]
mod tests;
