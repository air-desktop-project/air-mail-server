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
//! 2. **`STARTTLS` annoncé sans certificat.** Ce serait mentir au pair dès la
//!    bannière — et un pair peut décider d'envoyer un mot de passe sur la foi de
//!    cette annonce. [`serve_connection`] refuse alors d'ouvrir la bouche.
//!    `AUTH`, lui, ne figure plus dans ce refus : la boucle sait le conduire,
//!    parce qu'elle n'a rien à en connaître.
//!
//! # `STARTTLS` : ce que la boucle fait, et ce qu'elle ne décide pas
//!
//! Elle conduit la poignée de main, puis rejoue son pilote au-dessus du flux
//! chiffré. Elle ne décide ni de l'annoncer (c'est la configuration), ni de la
//! réponse (c'est la session), ni du fournisseur cryptographique — celui-ci vient
//! de `ams-tls`, et l'appelant l'apporte tout fait. **Ce qu'un pair envoie
//! derrière son `STARTTLS` n'est jamais exécuté** : voir [`serve_connection`].
//!
//! # `AUTH` : la boucle lit une ligne de plus, et c'est tout
//!
//! Après un défi, la session rend
//! [`Action::ReadAuthResponse`](ams_session::Action::ReadAuthResponse) : la
//! boucle lit **une ligne**, la décadre de son `CRLF`, et la passe à
//! [`feed_auth`](ams_session::SmtpSession::feed_auth). Elle ne connaît ni le
//! base64, ni le format de `PLAIN`, ni l'annulation par `*` — tout cela vit dans
//! `ams-sasl` et `ams-session`, c'est-à-dire dans le périmètre couvert à 100 %,
//! et n'aura pas à être réécrit pour Air.
//!
//! # Ce qui n'est pas écrit
//!
//! Le magasin d'identifiants. La boucle et la session savent conduire un échange
//! SASL, mais rien dans ce dépôt ne sait dire si un mot de passe est le bon : le
//! binaire livré n'annonce donc pas `AUTH`.

#![forbid(unsafe_op_in_unsafe_fn)]

mod connection;
mod delivery;
mod dkim;
mod dmarc;
mod error;
mod guard;
pub mod h3;
pub mod http;
pub mod imap;
mod mtasts;
pub mod pop3;
mod privileges;
mod queue;
pub mod quic;
mod relay;
mod reports;
mod resolver;
mod server;
mod spf;
mod tlsreports;

// Les types de RFC 3461 traversent cette caisse SANS CHANGER DE FORME : ce que
// la session écrit sur le fil est ce que la file a lu dans l'enveloppe, et un
// type de plus n'ajouterait qu'une occasion de les traduire de travers.
pub use ams_session::{ClientDsn, ClientReport};
pub use connection::{
    DkimTally, DmarcTally, Outcome, Service, Summary, Timeouts, TlsMode, serve_connection,
    serve_connection_with,
};
pub use delivery::{Delivery, DeliveryFailure};
pub use dkim::{
    DkimChecker, DkimResult, DkimSigner, DkimStream, DkimVerdict, PublicationDkim, publication_dkim,
};
pub use dmarc::{Authenticated, DmarcChecker, DmarcResult, DmarcVerdict, PourRapport};
pub use error::Error;
pub use guard::SharedGuard;
pub use mtasts::Sts;
pub use privileges::{is_root, masque_trop_large, refuse_root, restreindre_le_masque};
pub use queue::{Bounced, QueueTally, Spool};
pub use quic::{Application, QuicStats, SansApplication, serve_quic};
pub use relay::{Outgoing, Relay, RelayOutcome, SMTP_PORT};
pub use reports::{
    FailureObservation, Observation, PolitiqueLue, ReportSpool, SendTally, SignatureVue, SpfVu,
    SpoolTally,
};
pub use resolver::Resolver;
pub use server::{DkimSums, DmarcSums, ServeOptions, Stats, serve, source_de};
pub use spf::SenderChecker;
pub use tlsreports::{DOMAINES_MAX, TlsObservation, TlsReports, TlsSendTally, TlsSpoolTally};
