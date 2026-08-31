// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La machine de connexion QUIC, **sans entrée-sortie** (C1).
//!
//! # C'EST ICI QUE LA GRAMMAIRE ET LE CHIFFREMENT SE RENCONTRENT
//!
//! `ams-proto-quic` sait lire des en-têtes et des trames, sans clé.
//! `ams-quic-crypto` sait chiffrer et démasquer, sans grammaire. Ni l'un ni
//! l'autre ne sait ouvrir un paquet : il faut les deux, et dans un ordre que le
//! protocole impose.
//!
//! Cette séparation n'est pas une élégance : elle suit l'ordre des opérations de
//! §5.4 de RFC 9001. Pour ôter le masque il faut la clé, pour trouver la clé il
//! faut l'identifiant de destination, pour lire l'identifiant il faut avoir lu
//! l'en-tête. **Grammaire d'abord, clés ensuite, assemblage ici.**

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

// LES TESTS, EUX, ONT LE DROIT D'ALLOUER.
#[cfg(test)]
extern crate std;

mod error;
mod receive;

pub use error::{Error, Reason};
pub use receive::{Opened, PacketKind, open_packet};
