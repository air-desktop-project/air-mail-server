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
//!
//! # ET C'EST ICI QU'UN FLUX DEVIENT UNE SUITE D'OCTETS
//!
//! Un paquet ouvert porte des trames ; une trame `STREAM` porte un morceau à un
//! décalage. Entre les deux, il faut retenir ce qui est en avance, réunir ce qui
//! se touche, et refuser ce qu'on ne peut pas retenir — c'est [`Recv`], [`Send`]
//! et [`Flow`], et c'est là que le contrôle de flux empêche un pair de commander
//! notre mémoire.
//!
//! # ET C'EST ICI QUE LA CONNEXION SAIT QUAND ELLE S'ÉTEINT
//!
//! [`Connection`] tient ce qui vaut pour la connexion entière et non pour un
//! flux : la borne d'amplification qui empêche notre serveur d'être l'arme de
//! quelqu'un d'autre, le délai d'inactivité, et les deux états où l'on n'est plus
//! là mais où l'on répond encore.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

// LES TESTS, EUX, ONT LE DROIT D'ALLOUER.
#[cfg(test)]
extern crate std;

mod connection;
mod error;
mod flow;
mod handshake;
mod plages;
mod receive;
mod recv;
mod send;

pub use connection::{AMPLIFICATION_FACTOR, CLOSING_PTOS, Connection, IDLE_PTOS, State};
pub use error::{Error, Reason};
pub use flow::{Concurrence, Concurrences, Cote, Flow};
pub use handshake::{CRYPTO_OCTETS_MAX, Handshake, Level, crypto_error};
pub use plages::HOLES_MAX;
pub use receive::{Opened, PacketKind, open_packet};
pub use recv::{Recv, RecvState};
pub use send::{Send, SendState};
