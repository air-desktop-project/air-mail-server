//! Boucle d'entrées-sorties Unix, sur tokio (C5).
//!
//! Elle lit des octets, les donne à une session d'[`ams_session`], écrit ce que
//! la session rend, et exécute l'action demandée. **Elle ne porte aucune logique
//! de protocole** : tout ce qui décide vit dans les crates sans entrée-sortie.
//!
//! C'est ce qui permet d'en écrire une seconde pour Air — sur `air-async` et
//! `air-uring` — sans rien réécrire d'autre. Cette seconde boucle **n'existe
//! pas** : une crate vide portant ce nom laisserait croire qu'un portage est
//! entamé.
//!
//! # Elle est HORS du 100 % de couverture (C2), et c'est le sujet
//!
//! Cette crate lit, écrit et attend. Y atteindre 100 % exigerait de simuler les
//! pannes du noyau — un `EINTR` ici, un `ENOSPC` là — et l'on mesurerait alors la
//! fidélité de la simulation, pas la justesse du code. C'est précisément pour que
//! ce périmètre reste petit que tout le reste est une machine à états.
//!
//! Elle est néanmoins éprouvée de bout en bout : [`serve_connection`] est
//! générique sur le flux, donc une conversation SMTP entière se joue en mémoire,
//! sans ouvrir un port.
//!
//! # Deux refus, tous deux AVANT de parler
//!
//! 1. **Le superutilisateur** ([`refuse_root`], C10). Jamais, pas même le temps
//!    de se lier à un port. Les ports privilégiés s'atteignent par une règle de
//!    redirection du pare-feu. Il n'y a donc **aucun** code d'abandon de
//!    privilèges ici : on ne se trompe pas dans ce qu'on n'écrit pas.
//! 2. **Une capacité qu'elle ne sait pas conduire.** Cette boucle ne fait ni TLS
//!    ni SASL. Servir une configuration qui les annonce reviendrait à mentir au
//!    pair dès la bannière, alors [`serve_connection`] refuse d'ouvrir la bouche.
//!
//! # Ce qui n'est pas écrit
//!
//! La boucle d'acceptation, la limitation du nombre de connexions, TLS, SASL, et
//! le stockage. Cette tranche sert **une** connexion, complètement.

#![forbid(unsafe_op_in_unsafe_fn)]

mod connection;
mod delivery;
mod error;
mod privileges;

pub use connection::{Summary, Timeouts, serve_connection};
pub use delivery::{Delivery, DeliveryFailure};
pub use error::Error;
pub use privileges::{is_root, refuse_root};
