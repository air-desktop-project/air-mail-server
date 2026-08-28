//! Index Maildir : noms, drapeaux, et **reconstruction**, sans entrée-sortie
//! (C1, C13).
//!
//! # Les fichiers sont la seule source de vérité
//!
//! Cette crate ne stocke rien : elle lit ce que les noms de fichiers portent, et
//! en tire ce dont IMAP a besoin. L'index n'est qu'un accélérateur ; s'il ne
//! l'était pas, il deviendrait une seconde source de vérité, capable de diverger
//! de la première sans que rien ne le signale.
//!
//! # Ce que « reconstructible » exige, et ce n'est pas évident
//!
//! Reconstruire un index, ce n'est pas le recalculer *d'une manière ou d'une
//! autre* : c'est retrouver **exactement les mêmes UID**. Un UID déduit d'un
//! ordre — date de modification, ordre de lecture du répertoire — change au
//! premier fichier restauré depuis une sauvegarde, et **tous les clients
//! resynchronisent alors la boîte entière**.
//!
//! **L'UID vit donc dans le nom du fichier**, sous la forme `,U=<uid>`. La partie
//! unique d'un nom Maildir est opaque et libre — hors `:` et `/` — ce qui suffit
//! à l'y loger.
//!
//! # Ce que cette tranche couvre
//!
//! Les noms, les drapeaux, et le **résumé d'une boîte** : le prochain UID à
//! attribuer, ce qui est déjà numéroté, et ce qui ne l'est pas encore. C'est un
//! **repliement** sur les noms — aucune table, donc aucune allocation, donc
//! aucune borne à choisir.
//!
//! Et **ce que les noms ne portent pas** : l'`UIDVALIDITY` de la boîte, et le
//! filigrane des UID qui doit survivre à l'effacement du message portant le plus
//! grand. Ces deux nombres-là sont écrits ([`MailboxState`]), et
//! [`reconcile`] dit ce qu'il faut en faire quand on les retrouve — ou quand on
//! ne les retrouve pas.
//!
//! # Ce qu'elle NE couvre PAS
//!
//! **L'écriture du fichier**, qui est une entrée-sortie : le codec Cap'n Proto
//! vit dans `ams-config`, et le fichier lui-même dans `ams-store`. Cette crate
//! ne fait que DÉCIDER, ce qui est exactement ce qui la rend couvrable à 100 %.
//!
//! ```
//! use ams_index::{Flags, MessageName, Uid, compose, summarise};
//!
//! // Un nom composé se relit à l'identique.
//! let mut tampon = [0_u8; 128];
//! let ecrits = compose(
//!     &mut tampon,
//!     b"1724832000.M1.mail.example.com",
//!     Uid::new(42).expect("non nul"),
//!     1024,
//!     Some(Flags::SEEN),
//! )?;
//! let nom = &tampon[..ecrits];
//! assert_eq!(nom, b"1724832000.M1.mail.example.com,U=42,S=1024:2,S");
//!
//! let lu = MessageName::parse(nom)?;
//! assert_eq!(lu.uid().map(Uid::value), Some(42));
//! assert_eq!(lu.size(), Some(1024));
//! assert!(lu.flags().contains(Flags::SEEN));
//!
//! // Le résumé d'une boîte se replie sur ses noms.
//! let resume = summarise([nom.as_ref(), b"1724832001.M2.host".as_ref()].into_iter());
//! assert_eq!(resume.next_uid.value(), 43);
//! assert_eq!(resume.numbered, 1);
//! assert_eq!(resume.unnumbered, 1);
//! # Ok::<(), ams_index::NameError>(())
//! ```

#![no_std]

// La crate livrée n'a ni `std` ni `alloc`. Les tests, eux, ont le droit d'allouer.
#[cfg(test)]
extern crate std;

mod flags;
mod name;
mod state;
mod summary;

pub use flags::{FlagError, Flags};
pub use name::{MessageName, NameError, Uid, compose};
pub use state::{
    MailboxState, Reconciliation, UID_RESERVATION, UidValidity, reconcile, reserved_watermark,
};
pub use summary::{MailboxSummary, summarise};
