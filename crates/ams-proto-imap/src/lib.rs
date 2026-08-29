//! Grammaire IMAP : décodage et encodage, **sans entrée-sortie**.
//!
//! Périmètre visé : RFC 9051 (IMAP4rev2), avec l'interopérabilité RFC 3501
//! (IMAP4rev1) que les clients déployés exigent encore.
//!
//! IMAP est de loin la plus grosse des quatre grammaires : littéraux comptés,
//! réponses non sollicitées, séquences et UID, `FETCH` structuré. C'est aussi
//! celle qui justifie le plus l'absence d'entrée-sortie ici — un littéral
//! `{1024}` annonce une longueur venue du réseau, et ce genre de chemin se
//! vérifie sur des octets en mémoire, pas sur une connexion.
//!
//! # État
//!
//! **Le découpage des commandes est là** : le tag, les littéraux, les bornes, et
//! l'encodage des réponses. C'est la moitié du protocole qui décide de tout le
//! reste — un serveur IMAP qui découpe mal ses commandes est un serveur qu'on
//! fait lire ce qu'on veut.
//!
//! Ce qui n'y est pas : le vocabulaire des ARGUMENTS. `FETCH`, `SEARCH` et
//! `STORE` ont chacun leur grammaire, et elles viendront une par une.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

// LES TESTS, EUX, ONT LE DROIT D'ALLOUER.
#[cfg(test)]
extern crate std;

mod arguments;
mod command;
mod error;
mod fetch;
mod flags;
mod frame;
mod limits;
mod response;
mod sequence;
mod tag;

pub use arguments::{Args, Argument, argument_max};
pub use command::{Command, Line};
pub use error::Error;
pub use fetch::{FETCH_ITEMS_MAX, Fetch, FetchItem, Partial, Section};
pub use flags::{Flags, INTERNALDATE_MAX, write_internal_date};
pub use frame::{CommandReader, Need};
pub use limits::Limits;
pub use response::{
    Status, encode_continuation, encode_tagged, encode_untagged, encode_untagged_parts,
};
pub use sequence::{Ranges, SequenceSet};
pub use tag::Tag;
