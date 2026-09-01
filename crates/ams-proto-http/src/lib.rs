// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La SÉMANTIQUE d'HTTP (RFC 9110), **sans entrée-sortie** (C1, C3).
//!
//! # CETTE CRATE NE CADRE RIEN, ET C'EST TOUT SON OBJET
//!
//! HTTP/2 et HTTP/3 ne partagent aucun octet de cadrage : l'un compte des
//! cadres sur TCP (RFC 9113), l'autre des cadres sur QUIC (RFC 9114), et leurs
//! compressions d'en-têtes elles-mêmes diffèrent — HPACK d'un côté, QPACK de
//! l'autre. **Ce qu'ils partagent, c'est le SENS** : une méthode, une cible, des
//! champs, un code d'état, et les règles qui disent quelle liste de champs est
//! recevable.
//!
//! Ces règles-là ne sont écrites qu'ICI. Les écrire deux fois, c'est se donner
//! deux occasions de les écrire différemment — et une différence entre les deux
//! versions du même serveur est exactement ce qu'un attaquant cherche.
//!
//! # HTTP/1.1 N'EST PAS SERVI, ET CE N'EST PAS UN OUBLI
//!
//! Le cadrage d'HTTP/1.1 est TEXTUEL, et sa longueur se déduit de deux champs
//! qui peuvent se contredire — `Content-Length` et `Transfer-Encoding`. Toute la
//! famille des attaques par contrebande de requête (« request smuggling ») vit
//! dans cette contradiction, et dans les désaccords d'analyse entre deux
//! implémentations qui se relaient.
//!
//! HTTP/2 et HTTP/3 n'ont pas ce défaut : la longueur d'un cadre est un nombre,
//! écrit une fois, et `Transfer-Encoding` y est **interdit** (RFC 9113 §8.2.2).
//! C'est le même raisonnement que celui qui a fermé la contrebande SMTP dans ce
//! dépôt, et c'est ce que C6 demande : on ne sert pas ce qui affaiblit.
//!
//! La conséquence est réelle et doit être dite : un client qui ne parle QUE
//! HTTP/1.1 ne pourra pas joindre ce serveur. La négociation se fait par ALPN,
//! donc explicitement, et un client qui n'offre ni `h2` ni `h3` est refusé avant
//! la première requête plutôt qu'après.
//!
//! # Ce qui vit ici
//!
//! - [`Method`] — les méthodes servies, et celles qu'on refuse.
//! - [`StatusCode`] — un code d'état, sans phrase de raison : ni h2 ni h3 n'en
//!   transportent.
//! - [`field_name_is_valid`] / [`field_value_is_valid`] — ce qu'un champ a le
//!   droit d'être, sur le fil binaire.
//! - [`RequestHead`] — une requête décodée, et les règles de §8.3 qui disent si
//!   la liste de champs qu'on vient de décomprimer est recevable.
//! - [`Limits`] — ce qu'on refuse de retenir.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

// LES TESTS, EUX, ONT LE DROIT D'ALLOUER.
#[cfg(test)]
extern crate std;

mod error;
mod field;
mod head;
mod limits;
mod method;
mod range;
mod response;
mod status;

pub use error::Error;
pub use field::{
    FieldKind, field_kind, field_name_is_valid, field_value_is_valid, is_connection_specific,
    response_field_is_serviceable,
};
pub use head::{FIELDS_MAX, HeadBuilder, RequestHead};
pub use limits::Limits;
pub use method::Method;
pub use range::{ByteRange, RangeFault, parse_range};
pub use response::{Body, ResponseHead, parse_response};
pub use status::StatusCode;
