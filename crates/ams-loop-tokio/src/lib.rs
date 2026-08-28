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
//! sans ouvrir un port. **Et cette généricité est ce qui rend `STARTTLS`
//! possible** : un flux chiffré est un flux comme un autre, le pilote y est
//! rejoué tel quel.
//!
//! Le chiffrement, lui, ne se prouve pas en mémoire : `tests/starttls.rs` fait
//! venir un vrai `openssl s_client -starttls smtp`, parce que se parler à
//! soi-même n'est pas se mettre d'accord.
//!
//! # Deux refus, tous deux AVANT de parler
//!
//! 1. **Le superutilisateur** ([`refuse_root`], C10). Jamais, pas même le temps
//!    de se lier à un port. Les ports privilégiés s'atteignent par une règle de
//!    redirection du pare-feu. Il n'y a donc **aucun** code d'abandon de
//!    privilèges ici : on ne se trompe pas dans ce qu'on n'écrit pas.
//! 2. **Une capacité qu'elle ne sait pas conduire.** Cette boucle ne fait pas de
//!    SASL, et ne fait de TLS que si on lui en donne le moyen ([`Service::tls`]).
//!    Annoncer `STARTTLS` sans certificat, ou `AUTH` tout court, reviendrait à
//!    mentir au pair dès la bannière — alors [`serve_connection`] refuse d'ouvrir
//!    la bouche.
//!
//! # `STARTTLS` : ce que la boucle fait, et ce qu'elle ne décide pas
//!
//! Elle conduit la poignée de main, puis rejoue son pilote au-dessus du flux
//! chiffré. Elle ne décide ni de l'annoncer (c'est la configuration), ni de la
//! réponse (c'est la session), ni du fournisseur cryptographique — celui-ci vient
//! de `ams-tls`, et l'appelant l'apporte tout fait. **Ce qu'un pair envoie
//! derrière son `STARTTLS` n'est jamais exécuté** : voir [`serve_connection`].
//!
//! # Ce qui n'est pas écrit
//!
//! SASL, et le chargement d'un certificat par le binaire `air-mail-server` — le
//! schéma de configuration (C11) n'a pas encore de section TLS, si bien que le
//! serveur livré ne chiffre pas encore, faute de pouvoir recevoir de quoi le
//! faire.

#![forbid(unsafe_op_in_unsafe_fn)]

mod connection;
mod delivery;
mod error;
mod guard;
mod privileges;
mod server;

pub use connection::{Outcome, Service, Summary, Timeouts, serve_connection};
pub use delivery::{Delivery, DeliveryFailure};
pub use error::Error;
pub use guard::SharedGuard;
pub use privileges::{is_root, refuse_root};
pub use server::{ServeOptions, Stats, serve, source_de};
