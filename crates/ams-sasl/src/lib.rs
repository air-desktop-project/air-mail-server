//! SASL (RFC 4422) : le mécanisme `PLAIN`, et le base64 qui le transporte.
//!
//! **Sans entrée-sortie et sans allocation** (C1, C3) : cette crate décode des
//! tranches d'octets vers des tranches d'octets, et n'apprend jamais si les
//! identifiants qu'elle a lus sont les bons. C'est la politique de l'appelant
//! qui le sait, et elle seule.
//!
//! # Un seul mécanisme, et c'est un choix
//!
//! `PLAIN` (RFC 4616) est le seul offert.
//!
//! - **`LOGIN`** n'a jamais été normalisé, demande deux allers-retours de plus,
//!   et n'apporte rien que `PLAIN` n'apporte : les deux transmettent le mot de
//!   passe tel quel. Le servir ne serait que de la compatibilité avec des
//!   clients qui savent tous faire `PLAIN`.
//! - **`CRAM-MD5`** est exclu par C6, et pour deux raisons plutôt qu'une : MD5,
//!   et surtout l'obligation de conserver le mot de passe en clair côté serveur
//!   pour pouvoir calculer le condensat. Un mécanisme qui interdit de stocker
//!   une empreinte est un mécanisme qui aggrave la fuite qu'il prétend éviter.
//! - **`SCRAM-SHA-256`** (RFC 7677) serait le bon successeur : le serveur n'y
//!   voit jamais le mot de passe. Il exige en revanche un vérificateur stocké
//!   (sel, itérations, deux clés dérivées), c'est-à-dire un magasin
//!   d'identifiants — qui n'existe pas encore dans ce dépôt. L'écrire d'avance
//!   ferait supposer la forme de ce magasin ; il attendra donc qu'elle soit
//!   décidée.
//!
//! `PLAIN` transmet le mot de passe en clair dans le tuyau : il n'est acceptable
//! que **sous TLS**, et c'est [`ams_session`] qui l'impose, sans réglage possible.
//!
//! # Ce que cette crate ne fait PAS : SASLprep
//!
//! La RFC 4616 demande d'appliquer SASLprep (RFC 4013) aux identifiants avant de
//! les comparer — une normalisation Unicode qui rend équivalentes deux écritures
//! du même nom. Elle n'est pas implémentée : il faudrait embarquer les tables de
//! stringprep, et ce serait beaucoup de code non trivial pour une comparaison.
//!
//! **Le sens de l'erreur est celui qui va bien** : sans normalisation, deux
//! écritures différentes du même mot de passe sont traitées comme différentes.
//! On peut donc REFUSER une ouverture de session qu'un serveur normalisant
//! accepterait ; on n'en acceptera jamais une qu'il refuserait. C'est le côté du
//! compromis où une erreur ferme une porte au lieu d'en ouvrir une.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

mod base64;
mod plain;

pub use base64::{Error as Base64Error, decode as decode_base64, decoded_len};
pub use plain::{Credentials, Error as PlainError, parse as parse_plain};
