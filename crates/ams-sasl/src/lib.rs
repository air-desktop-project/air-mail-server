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
//! - **`SCRAM-SHA-256`** (RFC 7677) a longtemps figuré ici comme « le bon
//!   successeur », en attendant qu'un magasin d'identifiants existe. Il existe
//!   depuis, et **la décision est prise : ce sera non**, le 2026-09-06.
//!
//!   Il exige un vérificateur stocké — sel, itérations, `StoredKey`,
//!   `ServerKey` —, et `ams_auth` écrit sa raison d'être en une phrase : « une
//!   fuite du fichier de comptes ne doit pas être une fuite des mots de passe ».
//!   Ce vérificateur la contredit deux fois.
//!
//!   **Il est dérivé par PBKDF2**, que §2.2 de RFC 5802 impose : on ne peut pas
//!   y substituer l'`argon2id` du magasin sans cesser d'interopérer, puisque
//!   c'est le CLIENT qui calcule le sien. Un magasin portant les deux serait
//!   attaquable par le plus faible.
//!
//!   **Il est directement exploitable**, là où une empreinte demande d'abord
//!   d'être cassée : §9 dit que `ServerKey` permet d'usurper le serveur, et
//!   qu'une seule conversation écoutée suffit alors à reconstituer `ClientKey`.
//!
//!   Ce qu'il apporterait est mince en regard : sous TLS 1.3, `PLAIN` ne fait
//!   jamais traverser le mot de passe, et le certificat authentifie déjà le
//!   serveur. Voir `docs/v1.md` pour les trois conditions qui renverseraient ce
//!   choix.
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
