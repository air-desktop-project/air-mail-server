//! Grammaire IMAP : décodage et encodage, **sans entrée-sortie**.
//!
//! Périmètre : RFC 9051 (IMAP4rev2), et ce que RFC 3501 exige EN PLUS.
//!
//! # LES DEUX VERSIONS, ET CE QUI LES SÉPARE VRAIMENT
//!
//! Ce serveur annonçait `IMAP4rev2` seul, et cette page a longtemps affirmé
//! « le clivage ne tient pas à ce que ce serveur SAIT faire, mais à une ligne
//! de capacités ». **C'était faux, et la mesure du 2026-09-05 l'a montré** :
//! ajouter la ligne ne suffisait pas. Quatre choses manquaient, dont trois
//! qu'un client rev1 emploie à chaque session :
//!
//! - `SELECT` doit rendre `* n RECENT` (RFC 3501 §6.3.1 : « the server MUST
//!   send ») ; rev2 l'a retiré (§A) ;
//! - `SEARCH` doit rendre `* SEARCH 2 4 5`, une LISTE, là où rev2 rend un
//!   ENSEMBLE comprimé — `* ESEARCH (TAG "a") ALL 2,4:5` ;
//! - `STATUS` doit admettre l'élément `RECENT` (§6.3.10) ;
//! - `LSUB` et `CHECK` doivent répondre (§6.3.9, §6.4.1).
//!
//! Ce qui a rendu la mesure possible est un pair extérieur : `imaplib`, de la
//! bibliothèque standard de Python, refusait la connexion avant d'envoyer une
//! seule commande — « server not IMAP4 compliant ». Et Dovecot, sur la machine
//! que ce serveur doit remplacer, n'annonce lui non plus que `IMAP4rev1`.
//!
//! **Les deux versions cohabitent comme §6.3.1 le prescrit** : on commence en
//! rev1, et `ENABLE IMAP4rev2` bascule. Un serveur qui basculerait tout seul
//! retirerait à un client ce qu'il n'a pas demandé de perdre.
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
//! **Le vocabulaire des ARGUMENTS y est aussi**, désormais : `FETCH`, `SEARCH`,
//! `STORE`, `APPEND` et `LIST` ont chacun leur grammaire, dans leur module.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

// LES TESTS, EUX, ONT LE DROIT D'ALLOUER.
#[cfg(test)]
extern crate std;

mod append;
mod arguments;
mod command;
mod date;
mod error;
mod fetch;
mod flags;
mod frame;
mod limits;
mod list;
mod mailbox;
mod response;
mod search;
mod sequence;
mod special;
mod status;
mod store;
mod tag;

pub use append::Append;
pub use arguments::{Args, Argument, argument_max};
pub use command::{Command, Line};
pub use date::parse_date_time;
pub use error::Error;
pub use fetch::{
    FETCH_ITEMS_MAX, Fetch, FetchItem, PartPath, PartWhat, Partial, SECTION_DEPTH_MAX, Section,
};
pub use flags::{Flags, INTERNALDATE_MAX, write_internal_date};
pub use frame::{CommandReader, Need, literal_announcement};
pub use limits::Limits;
pub use list::{LIST_PATTERNS_MAX, List};
pub use mailbox::{
    MAILBOX_COMPONENT_MAX, MAILBOX_DEPTH_MAX, MAILBOX_NAME_MAX, MAILBOX_SEPARATOR,
    mailbox_name_is_safe, mailbox_name_trimmed,
};
pub use response::{
    Status, encode_continuation, encode_tagged, encode_untagged, encode_untagged_parts,
};
pub use search::{
    Candidate, SEARCH_DEPTH_MAX, SEARCH_KEYS_MAX, Search, SearchReader, SearchReturn, SearchScope,
    SearchSource, write_quoted,
};
pub use sequence::{Ranges, SequenceSet};
pub use special::{SpecialUse, parse_create_params};
pub use status::{STATUS_ATTS_MAX, StatusAtt, StatusItems};
pub use store::{Store, StoreMode};
pub use tag::Tag;
