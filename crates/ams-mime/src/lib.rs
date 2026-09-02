//! Format des messages RFC 5322 et MIME : décodage et encodage, **sans
//! entrée-sortie** (C1).
//!
//! Le socle commun des quatre protocoles et des trois crates d'authentification :
//! SMTP transporte un message, IMAP en expose la structure, DKIM en canonicalise
//! les en-têtes pour signer. Une seule grammaire, écrite une fois.
//!
//! # Ce que cette tranche couvre
//!
//! Le **squelette** : la ligne, le pliage, la séparation en-tête/corps, et le
//! découpage en champs. Tout le reste — champs structurés, adresses, dates, MIME,
//! mots encodés — s'appuiera dessus et n'est pas écrit.
//!
//! ```
//! use ams_mime::{Limits, Message};
//!
//! let brut = b"From: moi\r\nSubject: replie\r\n sur deux lignes\r\n\r\ncorps";
//! let message = Message::parse(brut, &Limits::DEFAULT).expect("message recevable");
//!
//! assert_eq!(message.body(), b"corps");
//!
//! // Les noms de champ sont insensibles à la casse.
//! let sujet = message.fields().find(|f| f.name_is(b"subject")).expect("Subject");
//!
//! // Déplier retire les CRLF et RIEN d'autre : le blanc qui suit reste.
//! let mut valeur = Vec::new();
//! for morceau in sujet.unfolded() {
//!     valeur.extend_from_slice(morceau);
//! }
//! assert_eq!(valeur, b" replie sur deux lignes");
//! ```
//!
//! # CR et LF isolés sont REFUSÉS, et c'est le point le plus important
//!
//! Un `CR` sans `LF`, un `LF` sans `CR` : rejetés, jamais devinés. Ce n'est pas du
//! purisme. Les serveurs de courrier ne s'accordent pas sur lesquels de ces octets
//! terminent une ligne, et c'est exactement ce désaccord qui a rendu la
//! **contrebande SMTP** possible en 2023 : un message que deux serveurs découpent
//! différemment permet d'en faire passer un second, que le premier n'a pas vu.
//!
//! Tolérer, ici, ce serait décider à la place de l'expéditeur ce qu'il a voulu
//! dire — et se retrouver en désaccord avec le serveur suivant.
//!
//! # Aucune allocation, et pas par élégance
//!
//! Rien n'est alloué : tout est emprunté au tampon d'entrée. C'est ce qu'exige
//! [C3] — une longueur venue du réseau sert à **borner**, jamais à réserver. Un
//! décodeur qui allouerait ce qu'un en-tête annonce offrirait sa mémoire à qui
//! sait écrire un nombre.
//!
//! C'est aussi ce qui rend la crate `#![no_std]` **sans `alloc`**, donc utilisable
//! telle quelle sur la cible Air.
//!
//! # La validation a lieu une fois
//!
//! [`Message::parse`] valide tout le bloc d'en-tête. Passé cet appel, les
//! parcours — [`Message::fields`], [`Field::unfolded`] — ne peuvent plus échouer
//! et ne rendent donc pas de `Result`.
//!
//! [C3]: https://github.com/air-desktop-project/air-mail-server/blob/main/docs/contraintes.md

#![no_std]

// La crate livrée n'a ni `std` ni `alloc` — c'est la condition pour qu'elle serve
// telle quelle sur la cible Air. Les TESTS, eux, ont le droit d'allouer : ils
// concatènent des valeurs dépliées et collectent des champs, ce que la crate se
// refuse à faire pour son appelant.
//
// La frontière est nette et vérifiable : `cargo build` ne lie pas `std` ; seul
// `cargo test` le fait, sous ce `cfg`.
#[cfg(test)]
extern crate std;

mod address;
mod authres;
mod base64;
mod bounce;
mod compose;
mod date;
mod decode;
mod digest;
mod envelope;
mod error;
mod failure;
mod limits;
mod message;
mod plume;
mod received;
mod select;
mod structure;

pub use address::{AddressElements, address_elements, author_domain, bare_address, sole_address};
pub use authres::{
    AUTHRES_RESERVE, Authentication, DKIM_MAX, DkimResult, DkimSeen, DmarcResult, SpfIdentity,
    SpfResult, authres_max, write_authres, write_authres_padded,
};
pub use base64::{BASE64_LINE, base64_max, encode_base64};
pub use bounce::{Bounce, Failure, bounce_max, write_bounce};
pub use compose::{ReportMail, report_mail_max, write_report_mail};
pub use date::{DATE_MAX, RFC3339_MAX, read_day, write_date, write_rfc3339};
pub use decode::{decode_chunk, decode_encoded_words, decode_transfer, decoded_max};
pub use digest::{DIGEST_FROM_MAX, DIGEST_SUBJECT_MAX, Digest, write_digest};
pub use envelope::{ENVELOPE_ADDRESSES_MAX, write_envelope};
pub use error::Error;
pub use failure::{
    EXPOSES, FailureMail, failure_mail_max, write_failure_mail, write_reported_headers,
};
pub use limits::Limits;
pub use message::{Field, Fields, Message, Unfolded};
pub use received::{RECEIVED_MAX, Received, Transport, write_received};
pub use select::write_header_fields;
pub use structure::{
    BodyPart, BodyScanner, BodySpan, STRUCTURE_DEPTH_MAX, STRUCTURE_PARTS_MAX, write_body_structure,
};
