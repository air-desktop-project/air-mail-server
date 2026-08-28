//! POP3 (RFC 1939) : les commandes et les réponses, **sans entrée-sortie**
//! (C1, C3).
//!
//! # Ce que ce serveur ne servira PAS, et pourquoi
//!
//! - **`APOP`** (RFC 1939 §7). Deux raisons plutôt qu'une : MD5, et surtout
//!   l'obligation de conserver le mot de passe **en clair** côté serveur pour
//!   pouvoir calculer le condensat. Un mécanisme qui interdit de stocker une
//!   empreinte aggrave la fuite qu'il prétend éviter. C6 l'exclut nommément.
//! - **`USER`/`PASS` hors chiffrement.** Le mot de passe traverse le fil tel
//!   quel : ce n'est acceptable que sous TLS, et [`ams_session`] l'imposera sans
//!   réglage possible — exactement comme `AUTH` en SMTP.
//!
//! Ce qui reste : `STLS` (RFC 2595) pour chiffrer, `CAPA` (RFC 2449) pour
//! annoncer, `USER`/`PASS` pour ouvrir, et les commandes de relève.
//!
//! # Deux différences avec SMTP qui se paient si on les oublie
//!
//! **Il n'y a pas de code numérique.** Une réponse commence par `+OK` ou `-ERR`,
//! et rien d'autre. Un client ne peut donc pas distinguer « boîte inconnue » de
//! « mot de passe faux » autrement que par le texte — ce qui, ici, est une
//! chance : nos refus ne diront rien.
//!
//! **Le point d'une réponse multiligne est DOUBLÉ, pas échappé au sens SMTP.**
//! RFC 1939 §3 : toute ligne commençant par `.` en reçoit un second, et le
//! terminateur est `<CRLF>.<CRLF>`. C'est la même règle qu'en SMTP, dans l'autre
//! sens — et [`stuff_line`] est là pour qu'elle ne soit écrite qu'une fois.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

mod command;
mod error;
mod limits;
mod reply;

pub use command::{Command, MessageNumber};
pub use error::Error;
pub use limits::Limits;
pub use reply::{Status, encode, encoded_len, stuff_line, stuffed_len};
