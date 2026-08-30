// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! HTTP/2 (RFC 9113) : le cadrage et les réglages, **sans entrée-sortie**
//! (C1, C3).
//!
//! # LE CADRAGE EST UN NOMBRE, ET C'EST TOUT L'INTÉRÊT
//!
//! Un cadre HTTP/2 commence par neuf octets : une longueur, un type, des
//! fanions, un numéro de flux. La longueur est écrite UNE FOIS, en clair, et
//! rien d'autre ne la contredit. C'est ce qui fait qu'il n'y a pas de
//! contrebande de requête en HTTP/2 — pas parce que le protocole est plus
//! récent, mais parce qu'il n'y a plus deux façons de savoir où un message
//! s'arrête.
//!
//! # CE QU'ON NE CONNAÎT PAS, ON L'IGNORE — ET C'EST UNE RÈGLE, PAS UNE
//! INDULGENCE
//!
//! §4.1 : un cadre d'un type inconnu doit être IGNORÉ, pas refusé. C'est ce qui
//! permet aux extensions d'exister sans casser les serveurs déployés. Un serveur
//! qui refuserait ce qu'il ne connaît pas serait le maillon par lequel toute
//! évolution devient impossible.
//!
//! La distinction est importante et se retrouve partout ici : **on ignore ce
//! qu'on ne connaît pas, on refuse ce qu'on connaît et qui est faux.** Un
//! réglage inconnu s'ignore ; un `SETTINGS_MAX_FRAME_SIZE` à 42 se refuse.
//!
//! # Ce qui vit ici
//!
//! - [`Preface`] — les vingt-quatre octets qui ouvrent une connexion.
//! - [`FrameHeader`] — les neuf octets, et les règles de §4.
//! - [`FrameReader`] — le découpage, sur un tampon qui ne fait que croître.
//! - [`Settings`] — les six réglages de §6.5.2.
//! - [`ErrorCode`] — les codes de §7, ceux qu'on écrit sur le fil.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

// LES TESTS, EUX, ONT LE DROIT D'ALLOUER.
#[cfg(test)]
extern crate std;

mod error;
mod frame;
mod preface;
mod settings;

pub use error::{Error, ErrorCode};
pub use frame::{
    FRAME_HEADER_OCTETS, FrameFlags, FrameHeader, FrameKind, FrameReader, Need, Padded,
};
pub use preface::{PREFACE, Preface, read_preface};
pub use settings::{SETTINGS_ENTRY_OCTETS, Setting, Settings, SettingsReader};
