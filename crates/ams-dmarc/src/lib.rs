//! DMARC (RFC 7489) : alignement et politique, **sans entrée-sortie** (C1, C9).
//!
//! # Ce que DMARC ajoute à SPF et à DKIM
//!
//! SPF dit si une adresse avait le droit d'émettre pour le domaine de
//! l'ENVELOPPE. DKIM dit qu'un domaine a signé un message. **Ni l'un ni l'autre
//! ne parle du `From:`** — c'est-à-dire de la seule ligne que l'humain lira.
//!
//! Un message peut donc passer SPF et DKIM sans qu'aucun des deux ne dise quoi
//! que ce soit de l'auteur affiché : il suffit d'émettre depuis un domaine qu'on
//! détient, de le signer, et d'écrire ce qu'on veut dans le `From:`. C'est
//! l'usurpation la plus ordinaire, et c'est celle que DMARC ferme.
//!
//! DMARC pose deux questions. **L'alignement** : le domaine que SPF a autorisé,
//! ou celui que DKIM a signé, est-il celui du `From:` ? **La politique** : que
//! veut le détenteur de ce domaine s'ils ne le sont pas ?
//!
//! # LE DOMAINE ORGANISATIONNEL NE SE DEVINE PAS
//!
//! L'alignement « relâché » compare les *domaines organisationnels* : `mail.
//! example.com` et `example.com` s'alignent. Or il n'existe aucune règle
//! syntaxique pour trouver ce domaine — `example.co.uk` en est un,
//! `example.com` aussi, et `co.uk` n'en est pas un. Il faut la **liste des
//! suffixes publics**, une donnée qui change et qui vit hors du code.
//!
//! Cette crate ne la devine donc pas : elle la DEMANDE, par [`PublicSuffix`].
//! Une implémentation naïve — « les deux dernières étiquettes » — ferait aligner
//! `attaquant.co.uk` avec `victime.co.uk`, c'est-à-dire exactement ce que DMARC
//! existe pour empêcher. C'est pourquoi cette crate n'en fournit aucune.
//!
//! # Elle ne décide pas non plus du hasard
//!
//! `pct=` échantillonne l'application d'une politique : « appliquer à 10 % des
//! messages ». Choisir ces 10 % demande de l'aléa, que C1 laisse à l'étage 3.
//! [`Assessment`] rend donc le pourcentage, et l'appelant tire.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

// LES TESTS, EUX, ONT LE DROIT D'ALLOUER. La crate est `no_std` sans `alloc` —
// c'est ce qui la rendra utilisable telle quelle sur Air.
#[cfg(test)]
extern crate std;

mod alignment;
mod error;
mod evaluate;
mod psl;
mod record;
mod tag;

pub use alignment::{Alignment, PublicSuffix, aligned};
pub use error::Error;
pub use evaluate::{Assessment, Authentication, Verdict, evaluate};
pub use psl::Suffixes;
pub use record::{POLICY_NAME_MAX, Policy, Record, policy_name};
pub use tag::{Tag, Tags};
