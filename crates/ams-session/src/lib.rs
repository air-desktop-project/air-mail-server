//! Machines à états des sessions serveur, **sans entrée-sortie** (C1).
//!
//! C'est ici que la contrainte « sans I/O » remonte au-dessus des codecs. Une
//! session reçoit une ligne ; elle rend des octets à émettre et une action à
//! exécuter. Elle n'attend jamais.
//!
//! # Ce que cette tranche couvre
//!
//! **La session POP3 entière** ([`pop3`]) : les trois états de la RFC 1939, le
//! refus d'`USER`/`PASS` hors chiffrement, les réponses multilignes et le
//! doublement du point.
//!
//! **La session SMTP entière** : la bannière, `EHLO`/`HELO`, l'annonce des
//! extensions, le séquencement `MAIL`/`RCPT`/`DATA`, `STARTTLS`, le refus
//! d'`AUTH` hors chiffrement, **et la phase de données**.
//!
//! # Ce qu'elle NE couvre PAS, et il faut le lire avant de s'en servir
//!
//! - **La vérification des identifiants.** La session conduit l'échange SASL de
//!   bout en bout — défi, base64, format de `PLAIN`, annulation par `*` — mais
//!   elle n'authentifie personne : elle demande à [`Policy::authenticate`]. Elle
//!   n'a ni comptes ni empreintes, et ne les invente pas.
//! - **La politique de relais.** Voir [`Policy`] : la session l'exige plutôt que
//!   de l'inventer.
//! - **Les délais et la limitation de débit.** Ils appartiennent à la boucle
//!   d'entrées-sorties et à `ams-guard`. Une machine à états qui n'attend jamais
//!   n'a pas d'horloge à consulter.
//!
//! # Trois propriétés tenues par construction
//!
//! 1. **`AUTH` hors TLS est refusé, et ce n'est pas un réglage.** Il n'existe
//!    aucun champ de configuration pour le rétablir : un interrupteur finirait
//!    par être basculé « juste pour un test ». `AUTH` n'est même pas *annoncé*
//!    avant chiffrement — annoncer un mécanisme qu'on refusera ferait envoyer un
//!    mot de passe en clair à un client qui aurait cru l'offre.
//!
//!    Et rien n'est annoncé que l'appelant n'ait **déclaré savoir conduire**
//!    ([`Capabilities`]) : le défaut n'offre ni `STARTTLS` ni `AUTH`, parce que
//!    c'est le seul défaut qui ne mente pas.
//! 2. **`STARTTLS` remet toute la session à zéro** (RFC 3207 §4.2). Ce qu'un pair
//!    a dit en clair a pu être dit par quelqu'un d'autre.
//! 3. **Un message refusé par la grammaire ne peut pas être accepté par
//!    l'appelant.** Quand [`SmtpSession::feed_data`] rend [`Error::DataRefused`],
//!    le verdict passé ensuite à [`SmtpSession::on_data_settled`] **n'est pas
//!    consulté** : la réponse est celle de la faute. Une boucle distraite ne peut
//!    donc pas remettre un message que le décodeur a rejeté.
//! 4. **Aucune réponse ne contient de donnée venue du client.** Pas d'adresse
//!    reprise, pas de commande citée, pas de détail d'erreur d'analyse.
//!    L'injection de réponse devient inexprimable ici, et pas seulement refusée
//!    par l'encodeur.
//!
//! # Une session, de bout en bout
//!
//! ```
//! use ams_proto_smtp::{Limits, Path};
//! use ams_session::{
//!     Action, Authenticator, Capabilities, Config, Policy, RecipientVerdict, SmtpSession,
//! };
//!
//! /// N'accepte que ce que ce serveur héberge — le reste n'est pas relayé.
//! struct NotreDomaine;
//!
//! // Elle n'authentifie personne : le défaut d'`Authenticator` refuse, et un
//! // défaut qui refuse ne peut ouvrir aucune porte.
//! impl Authenticator for NotreDomaine {}
//!
//! impl Policy for NotreDomaine {
//!     fn accepts_recipient(&self, forward_path: &Path<'_>) -> RecipientVerdict {
//!         match forward_path {
//!             Path::Mailbox(boite) if boite.domain().as_bytes() == b"example.com" => {
//!                 RecipientVerdict::Accept
//!             }
//!             _ => RecipientVerdict::RelayDenied,
//!         }
//!     }
//! }
//!
//! // On ne déclare que ce que la boucle sait conduire. Ici, elle sait chiffrer
//! // et conduire un échange SASL ; sans cette déclaration, ni `STARTTLS` ni
//! // `AUTH` ne seraient annoncés, et tous deux seraient refusés en `502`.
//! let config = Config::new(b"mail.example.com", 100, 10_485_760, Limits::DEFAULT)?
//!     .with_capabilities(Capabilities { starttls: true, auth: true });
//! let mut session = SmtpSession::new(config, NotreDomaine);
//! let mut out = [0_u8; 512];
//!
//! assert_eq!(session.greeting(&mut out)?, b"220 mail.example.com ESMTP\r\n");
//!
//! // Avant chiffrement, `AUTH` n'est même pas annoncé.
//! let tour = session.handle(b"EHLO client.example\r\n", &mut out)?;
//! assert!(!tour.reply().windows(4).any(|f| f == b"AUTH"));
//!
//! // Et il est refusé si on l'essaie quand même.
//! let tour = session.handle(b"AUTH PLAIN\r\n", &mut out)?;
//! assert!(tour.reply().starts_with(b"538 "));
//!
//! // Un destinataire hors du domaine hébergé n'est pas relayé.
//! session.handle(b"MAIL FROM:<moi@ailleurs.example>\r\n", &mut out)?;
//! let tour = session.handle(b"RCPT TO:<qui@ailleurs.example>\r\n", &mut out)?;
//! assert_eq!(tour.reply(), b"550 Relay access denied\r\n");
//!
//! // Celui-ci, si.
//! let tour = session.handle(b"RCPT TO:<jean@example.com>\r\n", &mut out)?;
//! assert_eq!(tour.reply(), b"250 Recipient ok\r\n");
//!
//! let tour = session.handle(b"DATA\r\n", &mut out)?;
//! assert_eq!(tour.action(), Action::ReceiveData);
//! # Ok::<(), ams_session::Error>(())
//! ```
//!
//! # Le relais ouvert est inexprimable
//!
//! Une session ne se construit pas sans [`Policy`] : la décision d'accepter un
//! destinataire n'a pas de valeur par défaut, parce que sa valeur par défaut
//! serait un relais ouvert — que C6 exclut.

#![no_std]

// La crate livrée n'a ni `std` ni `alloc`. Les tests, eux, ont le droit d'allouer.
#[cfg(test)]
extern crate std;

mod config;
mod digits;
mod error;
mod policy;
pub mod pop3;
mod recipients;
mod smtp;
mod tampon;

pub use config::{Capabilities, Config, SenderPolicy};
pub use error::Error;
pub use policy::{Authenticator, Policy, RecipientVerdict};
pub use recipients::{ARENA_OCTETS, RECIPIENTS_MAX, Recipients};
pub use smtp::{Action, DataOutcome, SenderIdentity, SmtpSession, Turn};
