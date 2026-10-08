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
mod ams_devices_capnp {
    include!("ams_devices_capnp.rs");
}

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    unused_qualifications,
    reason = "code généré par capnpc-rust, hors de notre contrôle éditorial"
)]
mod ams_app_passwords_capnp {
    include!("ams_app_passwords_capnp.rs");
}

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    unused_qualifications,
    reason = "code généré par capnpc-rust, hors de notre contrôle éditorial"
)]
mod ams_journal_capnp {
    include!("ams_journal_capnp.rs");
}

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    unused_qualifications,
    reason = "code généré par capnpc-rust, hors de notre contrôle éditorial"
)]
mod ams_delegations_capnp {
    include!("ams_delegations_capnp.rs");
}

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    unused_qualifications,
    reason = "code généré par capnpc-rust, hors de notre contrôle éditorial"
)]
mod ams_registre_capnp {
    include!("ams_registre_capnp.rs");
}

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

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    unused_qualifications,
    reason = "code généré par capnpc-rust, hors de notre contrôle éditorial"
)]
mod ams_scram_capnp {
    include!("ams_scram_capnp.rs");
}

/// Le chemin de la configuration quand personne n'en nomme un.
///
/// **UN SEUL DÉFAUT, ET IL EST ICI.** `air-mail-server` et `air-mail-admin` le
/// lisent tous les deux de cette constante : deux copies d'un chemin finissent
/// par diverger, et c'est au premier déménagement qu'on s'en aperçoit.
///
/// Il n'existe NI variable d'environnement NI réglage à la compilation pour le
/// changer. Ce serait une seconde source de configuration, ce que ce serveur
/// refuse par principe (C12) : un chemin qui peut venir de deux endroits finit
/// par venir du mauvais.
///
/// **CE DÉFAUT NE VAUT QUE SI RIEN N'EST FOURNI.** Une configuration existante
/// nomme ses chemins en absolu — magasins, boîtes, clefs —, et aucun d'eux ne
/// se déduit de celui-ci : les deux serveurs en service rangent leurs boîtes à
/// des endroits différents, et c'est légitime.
///
/// **`config write` N'EN PROFITE PAS, DÉLIBÉRÉMENT.** Cette commande remplace
/// le fichier ENTIER : sans chemin, une commande incomplète tapée par habitude
/// réécrirait la configuration vivante avec le seul jeu d'options frappé, et
/// effacerait tout le reste — dont le registre, sans lequel la réception refuse
/// par `451`. Elle exige donc qu'on nomme sa cible, et le dit quand on l'omet.
pub const CHEMIN_PAR_DEFAUT: &str = "/var/lib/air-mail/air-mail.conf";

mod accounts;
mod app_passwords;
mod codec;
mod delegations;
mod devices;
mod index;
mod journal;
mod push;
pub mod registre;
mod scram;

pub use accounts::{decode_accounts, encode_accounts};
pub use app_passwords::{APP_NOM_OCTETS_MAX, decode_app_passwords, encode_app_passwords};
pub use codec::{
    ANDROID_REVOCATION_MAX_DAYS, Asl, AslProtocol, AslService, AttestationMode, Configuration,
    Dkim, Dmarc, Enforcement, Error, Listener, Mtasts, Queue, Relay, Spf, TRAVERSAL_LIMIT_WORDS,
    Timeouts, Tls, Tlsrpt, decode, encode,
};
pub use delegations::{Delegation, Rights, decode_delegations, encode_delegations};
pub use devices::{
    Attested, Device, ID_OCTETS_MAX, NOM_OCTETS_MAX, decode_devices, encode_devices,
};
pub use index::{decode_index, encode_index};
pub use journal::{
    Delta, Disparu, Journal, Perime, Present, VANISHED_MAX, decode_journal, encode_journal,
};
pub use push::{
    APNS_TOKEN_MAX, ENDPOINT_MAX, FCM_TOKEN_MAX, Push, PushChannel, PushFault, WEBPUSH_AUTH_OCTETS,
    endpoint_is_acceptable,
};
pub use scram::{decode_scram, encode_scram};
