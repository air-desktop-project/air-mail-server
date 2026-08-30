// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! HTTP/3 (RFC 9114) : le cadrage et les flux, **sans entrée-sortie** (C1, C3).
//!
//! # CE QUI DISPARAÎT PAR RAPPORT À HTTP/2, ET C'EST L'ESSENTIEL
//!
//! HTTP/2 devait construire des flux au-dessus d'une connexion TCP unique :
//! numéros de flux, machine d'états par flux, contrôle de flux par flux,
//! `WINDOW_UPDATE`, `RST_STREAM`, `PRIORITY`. Tout cela est descendu dans QUIC,
//! et n'a plus à être écrit ici.
//!
//! **Ce qui disparaît avec, et qui compte davantage** : le blocage de tête de
//! ligne. En HTTP/2, un paquet perdu arrêtait TOUS les flux, parce que TCP livre
//! dans l'ordre ou ne livre pas. En HTTP/3, il n'arrête que le flux auquel il
//! appartenait.
//!
//! # CE QUI RESTE À ÉCRIRE
//!
//! Le cadrage — trois entiers et une charge —, les types de flux
//! unidirectionnels, trois réglages, et QPACK. C'est peu, et c'est voulu : ce
//! qui reste ici est ce que QUIC ne pouvait pas faire à notre place.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

// LES TESTS, EUX, ONT LE DROIT D'ALLOUER.
#[cfg(test)]
extern crate std;

mod error;
mod frame;
pub mod qpack;
mod settings;
mod stream;

pub use error::{Error, H3Error, Reason};
pub use frame::{FRAME_LENGTH_MAX, FrameHeader, FrameKind, Placement};
pub use settings::{DEFAULT_MAX_FIELD_SECTION_SIZE, Settings};
pub use stream::{StreamHead, StreamKind, accept_stream, read_stream_head};
