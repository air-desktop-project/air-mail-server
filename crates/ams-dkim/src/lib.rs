//! DKIM (RFC 6376) : signature et vérification, **sans entrée-sortie** (C1, C9).
//!
//! # Ce que DKIM prétend, et ce qu'il ne prétend pas
//!
//! Une signature DKIM dit : *le détenteur de ce domaine a apposé sa signature
//! sur ces en-têtes et ce corps*. Elle ne dit rien de l'expéditeur d'enveloppe
//! — c'est SPF —, rien de l'alignement entre les deux — c'est DMARC —, et rien
//! du contenu qu'elle ne couvre pas. Ces trois limites sont écrites ici parce
//! que chacune est une façon connue de se tromper sur ce qu'un `pass` vaut.
//!
//! # Ce que cette tranche couvre : CE QUI EST SIGNÉ
//!
//! - la grammaire des listes `tag=valeur` (§3.2), commune à la signature et à
//!   la clé ;
//! - le champ `DKIM-Signature` (§3.5), avec ses règles de cohérence ;
//! - l'enregistrement de clé publique (§3.6.1), révocation comprise ;
//! - **la canonicalisation** (§3.4), `simple` et `relaxed`, en-têtes et corps —
//!   c'est-à-dire la définition exacte des octets qu'une signature couvre.
//!
//! # Ce qu'elle ne couvre PAS, et pourquoi le report est propre
//!
//! **Le condensat et la signature elle-même.** Savoir CE QUI est signé et
//! savoir PAR QUI sont deux questions, et la seconde demande de la
//! cryptographie — SHA-256, RSA, Ed25519 — et une clé publique qui vit dans le
//! DNS. Elle viendra avec sa résolution rendue **sous forme d'action**, comme
//! `ams-spf` le fait de ses questions : c'est ce qui rend cette crate couvrable
//! à 100 % sans serveur DNS de test.
//!
//! La canonicalisation, elle, se vérifie **entièrement sur les vecteurs de la
//! RFC 6376 §3.4.5 et §3.4.6** — des octets, pas des condensats — et c'est
//! précisément ce qui rend cette tranche autonome.
//!
//! # Une signature qu'on ne sait pas lire ÉCHOUE
//!
//! RFC 6376 §3.9 : elle ne se vérifie pas « au mieux ». Les analyseurs de cette
//! crate valident donc la liste **entière** avant de rendre quoi que ce soit —
//! un parcours qui s'arrêterait à mi-chemin appliquerait la moitié d'une
//! signature que personne n'a écrite.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

// LES TESTS, EUX, ONT LE DROIT D'ALLOUER. La crate est `no_std` sans `alloc` —
// c'est ce qui la rendra utilisable telle quelle sur Air — mais un test qui
// rassemble une canonicalisation dans un `Vec` éprouve la même chose en se
// lisant mieux.
#[cfg(test)]
extern crate std;

mod base64;
mod body;
mod canonical;
mod error;
mod key;
mod sign;
mod signature;
mod tag;
mod verify;

pub use base64::{decoder_base64, encoder_base64};
pub use body::BodyCanon;
pub use canonical::{
    Canon, Canonicalization, Trailer, canonicalize_header, canonicalize_header_parts,
};
pub use error::Error;
pub use key::{KeyType, PublicKeyRecord};
pub use sign::{SIGNATURE_FIELD_MAX, Signer, SigningKey};
pub use signature::{Algorithm, Signature, SignedHeaders};
pub use tag::{Tag, Tags};
pub use verify::{
    BodyHasher, DIGEST_LEN, HeaderHasher, hash_signed_headers, verifier_la_signature, verify,
};
