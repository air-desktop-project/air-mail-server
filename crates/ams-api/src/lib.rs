// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! L'API REST : **ce qu'une requête désigne, et le droit qu'elle demande**,
//! sans entrée-sortie (C1).
//!
//! # C'EST LA PREMIÈRE SURFACE DE CE SERVEUR QU'UNE RFC NE DÉCRIT PAS
//!
//! SMTP, POP3, IMAP, HTTP, QUIC : jusqu'ici, chaque octet accepté ou refusé
//! l'était parce qu'un document le disait. Ici, c'est nous qui décidons — et
//! c'est précisément pour cela que les règles doivent être écrites d'un seul
//! endroit, sous une forme qui se vérifie.
//!
//! # UN CHEMIN N'EST PAS UNE CHAÎNE, C'EST UNE DÉSIGNATION
//!
//! La quasi-totalité des fautes de sécurité d'une API vient de la distance entre
//! les deux : deux écritures d'un même chemin que le contrôle d'accès traite
//! différemment, un `%2F` qui devient un séparateur après la vérification, un
//! `..` qui remonte hors de ce qu'on croyait borner.
//!
//! Ce module ne normalise donc RIEN. **Il refuse.** Une désignation ambiguë n'a
//! pas de forme canonique à choisir : elle a un auteur à qui dire non. Voir
//! [`path`].
//!
//! # ET UN DROIT SE DEMANDE AVANT DE S'ACCORDER
//!
//! Chaque ressource dit elle-même la portée qu'elle exige ([`Resource::scope`]).
//! La liste vit à côté de la table de routage, dans le même `match` : ajouter une
//! ressource sans lui donner de portée ne compile pas.
//!
//! C'est l'inverse d'une liste de contrôle tenue à part, qui se désynchronise
//! au premier ajout — et dont le premier symptôme est une ressource servie sans
//! droit.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

// LES TESTS, EUX, ONT LE DROIT D'ALLOUER.
#[cfg(test)]
extern crate std;

mod error;
mod path;
mod route;
mod scope;

pub use error::{Error, Reason};
pub use path::{SEGMENTS_MAX, Segments, split_query};
pub use route::{Resolved, Resource, resolve};
pub use scope::{Area, Rights, Scope};
