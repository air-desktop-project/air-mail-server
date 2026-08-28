//! Grammaire SMTP : décodage et encodage, **sans entrée-sortie** (C1).
//!
//! Périmètre visé : RFC 5321 (SMTP), et les extensions que le serveur décidera de
//! servir — `STARTTLS` (RFC 3207), `AUTH` (RFC 4954), `SIZE`, `8BITMIME`,
//! `PIPELINING`.
//!
//! # Ce que cette tranche couvre
//!
//! **Les commandes** — la ligne, le verbe, les chemins d'enveloppe, les
//! paramètres ESMTP — **et l'encodage des réponses**, multilignes comprises.
//!
//! Ne sont PAS écrits : `BDAT`/`CHUNKING`, et la validation complète d'une adresse
//! IPv6 (seule sa forme est vérifiée, cf. `check_address_literal`).
//!
//! ```
//! use ams_proto_smtp::{Command, Limits, Path};
//!
//! let commande = Command::parse(b"MAIL FROM:<moi@example.com> SIZE=1000\r\n", &Limits::DEFAULT)
//!     .expect("commande recevable");
//!
//! let Command::Mail { reverse_path, parameters } = commande else {
//!     panic!("attendu MAIL");
//! };
//! let Path::Mailbox(boite) = reverse_path else {
//!     panic!("attendu une boîte");
//! };
//! assert_eq!(boite.local_part().as_bytes(), b"moi");
//! assert_eq!(boite.domain().as_bytes(), b"example.com");
//! assert_eq!(parameters.find(b"size").expect("SIZE").value(), Some(b"1000".as_slice()));
//! ```
//!
//! # Où passe la frontière du refus
//!
//! Le refus **grammatical** vit ici : un verbe retiré par la RFC 5321, une route
//! source, un chemin sans chevrons, un CR isolé. Ce sont des propriétés du texte.
//!
//! Le refus de **politique** vit dans la session : exiger TLS avant `AUTH`,
//! n'offrir que l'ESMTP, borner le nombre de destinataires. Ce sont des
//! propriétés de l'état de la connexion, que ce décodeur ne connaît pas — et ne
//! doit pas connaître, sous peine de n'être plus décodable seul.
//!
//! D'où un point qui pourrait surprendre : **`HELO` se décode ici**, alors que C6
//! le range parmi ce qu'on ne sert pas. On ne peut pas refuser proprement ce
//! qu'on ne sait pas lire — et répondre « syntaxe invalide » à une commande qu'on
//! a comprise mais qu'on décline serait mentir au pair sur ce qui s'est passé.
//!
//! # Ce qui est refusé, et pourquoi
//!
//! - **Le CR et le LF isolés** — comme dans `ams-mime`, et pour la même raison :
//!   c'est le désaccord entre serveurs sur ce qui termine une ligne qui a rendu
//!   la contrebande SMTP possible en 2023.
//! - **Les routes sources** (`<@relais:boite@domaine>`) — syntaxe obsolète de la
//!   RFC 821, et vecteur historique de relais ouvert.
//! - **`SEND`, `SOML`, `SAML`, `TURN`** — retirés par la RFC 5321. `TURN` inverse
//!   les rôles client et serveur sur une connexion ouverte : un vol de courrier.
//! - **L'espace entre `FROM:` et `<`** — l'ABNF de la RFC 5321 §4.1.1.2 n'en
//!   prévoit pas. Beaucoup de clients en envoient un ; le tolérer serait une
//!   divergence d'interprétation de plus, et c'est un choix STRICT assumé.
//! - **Les zéros de tête dans un littéral IPv4** — `[192.0.2.010]` vaut `10` en
//!   décimal et `8` en octal selon le lecteur, et cette divergence a déjà servi à
//!   contourner des listes d'accès.
//! - **Tout octet non imprimable dans une réponse.** Une réponse contient souvent
//!   ce que le client vient d'envoyer ; un CR qui y passerait lui laisserait
//!   écrire une ligne de réponse ENTIÈRE de son choix, et donc mentir à ce qui lit
//!   la connexion derrière lui.
//!
//! # Aucune allocation
//!
//! Rien n'est alloué : tout est emprunté à la ligne reçue (C3). La crate est
//! `#![no_std]` **sans `alloc`**, donc utilisable telle quelle sur la cible Air.
//!
//! # La validation a lieu une fois
//!
//! [`Command::parse`] valide toute la ligne. Passé cet appel, les parcours — dont
//! celui des [`Parameters`] — ne peuvent plus échouer et ne rendent pas de
//! `Result`.

#![no_std]

// La crate livrée n'a ni `std` ni `alloc`. Les tests, eux, ont le droit
// d'allouer ; `cargo build` ne lie pas `std`, seul `cargo test` le fait.
#[cfg(test)]
extern crate std;

mod command;
mod domain;
mod error;
mod limits;
mod parameters;
mod path;
mod reply;

pub use command::Command;
pub use domain::ClientId;
pub use error::Error;
pub use limits::Limits;
pub use parameters::{Parameter, Parameters, ParametersIter};
pub use path::{LocalPart, Mailbox, Path, PathKind};
pub use reply::{Class, Code, encode, encoded_len};
