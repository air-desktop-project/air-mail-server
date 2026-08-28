//! Schéma Cap'n Proto de la configuration, lecture et écriture (C11).
//!
//! # Pourquoi du binaire plutôt que du texte
//!
//! La configuration d'air-mail-server est un fichier **binaire** : pas de TOML,
//! pas de YAML, pas de JSON.
//!
//! Un format textuel se lit avec un analyseur, et un analyseur admet des
//! variantes : espaces, guillemets, ordres, encodages, sensibilité à la casse.
//! Chaque variante est un endroit où deux lecteurs peuvent diverger — c'est la
//! même famille de défauts que la contrebande SMTP, appliquée à un fichier.
//! **Un format à schéma n'en admet aucune** : un champ absent est absent, un
//! entier est un entier, et il n'y a rien à interpréter.
//!
//! Conséquence directe et assumée : la configuration **n'est pas éditable à la
//! main**. C'est ce qui rend `air-mail-admin` obligatoire plutôt que confortable
//! (C12).
//!
//! # Le schéma est la définition normative
//!
//! [`schema/ams-config.capnp`] dit ce qui est configurable ; le code Rust qui en
//! dérive est **généré et committé**, pour que le build et la CI n'aient besoin
//! d'aucun outil C++. Régénérer est une opération de mainteneur, rare et hors
//! CI : `crates/ams-config/regenerate.sh`.
//!
//! # C'est la seule crate de l'étage 2 qui alloue, et pourquoi c'est licite
//!
//! Construire un message Cap'n Proto demande d'allouer. C3 interdit d'allouer
//! **d'après une longueur venue du réseau** — ce n'est pas le cas ici : ce qui
//! est lu vient d'un fichier écrit par l'administrateur. La lecture est en outre
//! bornée par une limite de traversée explicite ([`TRAVERSAL_LIMIT_WORDS`]),
//! pour qu'un fichier corrompu ne fasse pas boucler le décodeur.
//!
//! [`schema/ams-config.capnp`]: https://github.com/air-desktop-project/air-mail-server

#![no_std]

extern crate alloc;

// La crate livrée n'a pas `std`. Les tests, eux, ont le droit de s'en servir.
#[cfg(test)]
extern crate std;

/// Le code dérivé du schéma. **Généré, committé, jamais édité à la main.**
///
/// Les `#[allow(...)]` sont posés ICI, en attribut externe : `include!` ne
/// tolère pas d'attribut interne dans le fichier inclus.
#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    unused_qualifications,
    reason = "code généré par capnpc-rust, hors de notre contrôle éditorial"
)]
mod ams_config_capnp {
    include!("ams_config_capnp.rs");
}

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    unused_qualifications,
    reason = "code généré par capnpc-rust, hors de notre contrôle éditorial"
)]
mod ams_accounts_capnp {
    include!("ams_accounts_capnp.rs");
}

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    unused_qualifications,
    reason = "code généré par capnpc-rust, hors de notre contrôle éditorial"
)]
mod ams_index_capnp {
    include!("ams_index_capnp.rs");
}

mod accounts;
mod codec;
mod index;

pub use accounts::{decode_accounts, encode_accounts};
pub use codec::{Configuration, Error, TRAVERSAL_LIMIT_WORDS, Timeouts, Tls, decode, encode};
pub use index::{decode_index, encode_index};
