//! TLS **1.3 uniquement** (C4), avec l'échange de clés hybride post-quantique
//! `X25519MLKEM768` (C14). Sans entrée-sortie (C1).
//!
//! # TLS 1.3, et rien en dessous
//!
//! Pas de TLS 1.2, pas de repli négocié, pas d'option de compatibilité. Un client
//! qui ne sait pas faire TLS 1.3 n'est pas servi (C6). Ce n'est pas une intention
//! mais une **absence** : `rustls-rustcrypto` est pris sans sa feature `tls12`,
//! et le fournisseur n'offre donc que trois suites, toutes en 1.3.
//!
//! # Pas une ligne de C
//!
//! `aws-lc-rs` (le défaut de rustls) et `ring` embarquent du C ; le portage vers
//! Air ne peut pas payer ce prix. `rustls-rustcrypto` est le seul fournisseur
//! pur Rust — au prix d'être numéroté `0.0.2-alpha` par ses propres auteurs, et
//! d'être tiré par un `git` figé sur un SHA. C'est écrit dans le registre des
//! contraintes plutôt que découvert.
//!
//! # `X25519MLKEM768` est écrit ici, parce que personne ne le fournit
//!
//! `rustls-rustcrypto` n'a **aucune** trace de ML-KEM. Le seul fournisseur
//! rustls qui offre ce groupe est `aws-lc-rs`, que C4 exclut. Cette crate
//! l'implémente donc, en composant `ml-kem` et `x25519-dalek` — deux crates
//! auditées dont **aucune primitive n'est réécrite**.
//!
//! Ce qui est écrit ici, c'est le **combinateur** et son encodage sur le fil.
//! C'est peu de code, et c'est du code critique : voir [`kx`] pour l'ordre des
//! octets, relevé dans la spécification et non de mémoire.
//!
//! # Tout l'aléa vient du fournisseur
//!
//! Aucun appel à l'aléa du système : il est fourni par `SecureRandom`. C1
//! l'impose — lire l'aléa du système est une entrée-sortie — et le portage
//! l'exige, puisque sur Air l'aléa vient d'`AirRandom`.
//!
//! # Ce qui n'est PAS ici
//!
//! Le **branchement de `STARTTLS`** dans la boucle. `ams-session` refuse déjà
//! d'annoncer `STARTTLS` tant que l'appelant n'a pas déclaré savoir le conduire
//! ([`Capabilities`](https://docs.rs/)), et `ams-loop-tokio` refuse de servir une
//! configuration qui l'annoncerait. Rien ne ment donc ; il manque le fil, et il
//! viendra seul.

#![no_std]

extern crate alloc;

// La crate livrée n'a pas `std` en propre ; `rustls` l'exige pour l'instant, et
// les tests s'en servent.
#[cfg(test)]
extern crate std;

mod kx;
mod materiel;
mod provider;
mod quic;
mod relay;

pub use kx::{CLIENT_SHARE, SERVER_SHARE, SHARED_SECRET, X25519MlKem768};
pub use materiel::{ALPN_H2, Error as MaterialError, alpn, quic_server_config, server_config};
pub use provider::provider;
pub use quic::{ALPN_H3, alpn_h3, provider_quic};
pub use relay::relay_config;
