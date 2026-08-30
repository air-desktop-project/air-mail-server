// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! QUIC (RFC 9000) : la grammaire du transport, **sans entrée-sortie** (C1, C3).
//!
//! # CE QUI CHANGE PAR RAPPORT À TCP, ET POURQUOI CELA NOUS REGARDE
//!
//! QUIC n'est pas « TCP sur UDP ». Trois choses le distinguent, et toutes trois
//! déplacent du travail vers ce crate :
//!
//! - **le cadrage n'a qu'une source.** Toute longueur est un entier de §16, écrit
//!   une fois, borné à soixante-deux bits. Il n'y a pas de second champ qui
//!   pourrait dire autre chose — donc pas de contrebande de requête.
//! - **tout est chiffré, en-tête compris.** Le numéro de paquet lui-même est
//!   masqué (RFC 9001 §5.4). Un observateur ne relie pas deux paquets d'une même
//!   connexion en les regardant passer.
//! - **la perte est notre affaire.** Le noyau ne retransmet rien : la détection
//!   de perte, le contrôle de congestion et les temporisations (RFC 9002) sont du
//!   code, ici, et non un réglage du système.
//!
//! # CE QUI VIT ICI, ET CE QUI N'Y VIT PAS
//!
//! Ici : les entiers, les numéros de paquet, les en-têtes, les trames, les flux,
//! le contrôle de flux et la détection de perte. Rien de tout cela ne lit ni
//! n'écrit quoi que ce soit.
//!
//! Pas ici : la protection des paquets (RFC 9001), qui demande de l'AEAD et donc
//! une bibliothèque de chiffrement. Elle vit avec le reste du matériel TLS,
//! parce qu'un crate `no_std` qui dépendrait d'une bibliothèque de chiffrement
//! ne serait plus `no_std` — et parce que les clés viennent de la poignée de
//! main, pas de la grammaire.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

// LES TESTS, EUX, ONT LE DROIT D'ALLOUER.
#[cfg(test)]
extern crate std;

mod congestion;
mod connection_id;
mod error;
mod frame;
mod packet;
mod packet_number;
mod rtt;
mod stream_id;
mod transport;
mod varint;

pub use congestion::{
    Congestion, INITIAL_WINDOW, MAX_DATAGRAM_SIZE, MINIMUM_WINDOW, PACKET_THRESHOLD,
    PERSISTENT_CONGESTION_THRESHOLD, is_lost, time_threshold,
};
pub use connection_id::{CONNECTION_ID_MAX, ConnectionId};
pub use error::{Error, Reason, TransportError};
pub use frame::{
    Ack, AckRange, AckRanges, Directional, EcnCounts, Frame, MAX_STREAMS_LIMIT, PATH_DATA_OCTETS,
    STATELESS_RESET_TOKEN_OCTETS,
};
pub use packet::{
    Long, LongHeader, LongKind, RETRY_TAG_OCTETS, Retry, ShortHeader, VERSION_1,
    VERSION_NEGOTIATION, VersionNegotiation, is_long, parse_long,
};
pub use packet_number::{PACKET_NUMBER_MAX, PACKET_NUMBER_OCTETS_MAX};
pub use rtt::{ACK_DELAY_EXPONENT_MAX, GRANULARITY_US, INITIAL_RTT_US, Rtt, decode_ack_delay};
pub use stream_id::{Initiator, StreamId};
pub use transport::{
    DEFAULT_ACK_DELAY_EXPONENT, DEFAULT_ACTIVE_CONNECTION_ID_LIMIT, DEFAULT_MAX_ACK_DELAY_MS,
    DEFAULT_MAX_UDP_PAYLOAD_SIZE, MAX_ACK_DELAY_LIMIT_MS, MIN_ACTIVE_CONNECTION_ID_LIMIT,
    MIN_UDP_PAYLOAD_SIZE, Sender, TransportParameters,
};
pub use varint::VARINT_MAX;

/// Les entiers de longueur variable de §16.
pub mod varints {
    pub use crate::varint::{decode, encode, encoded_len};
}

/// Les numéros de paquet de §17.1.
pub mod packet_numbers {
    pub use crate::packet_number::{decode, encode, encoded_len};
}
