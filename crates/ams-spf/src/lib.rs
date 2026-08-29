//! SPF (RFC 7208) : évaluation de politique, **sans entrée-sortie** (C1, C9).
//!
//! # Pourquoi SPF fait partie du périmètre
//!
//! DMARC (C9) évalue l'alignement d'un message sur SPF **et/ou** DKIM. Sans SPF,
//! DMARC ne conclut que sur le courrier aligné DKIM — ce qui écarte une part
//! importante des expéditeurs légitimes et rend une politique `p=reject`
//! inapplicable.
//!
//! La crate a d'abord été **déduite** de C9, qui ne nommait que DKIM et DMARC ;
//! l'inclusion de SPF a été **confirmée le 2026-08-28**.
//!
//! # Ce que cette tranche couvre : la GRAMMAIRE, et rien d'autre
//!
//! Un enregistrement `v=spf1 …` se lit ici en termes — qualificateur, mécanisme,
//! argument — et les erreurs de syntaxe y sont détectées **une fois pour
//! toutes**. Les mécanismes qui ne demandent aucune résolution (`ip4`, `ip6`,
//! `all`) savent en outre répondre : ce sont des comparaisons d'adresses, et
//! elles n'ont besoin de personne.
//!
//! # Ce qu'elle ne couvre PAS, et pourquoi le report est propre
//!
//! **L'évaluation**, qui demande le DNS. `include`, `a`, `mx`, `ptr`, `exists`
//! et `redirect` résolvent des noms ; la RFC 7208 §4.6.4 borne à **dix** le
//! nombre de résolutions d'une évaluation — une limite qui existe pour empêcher
//! qu'un enregistrement hostile fasse travailler le résolveur d'autrui. Elle se
//! vérifie bien mieux sur une machine à états que dans un résolveur, et c'est
//! cette machine qui viendra ensuite : elle rendra ses résolutions **sous forme
//! d'actions**, comme `ams-dkim` le fera pour ses clés.
//!
//! **L'expansion des macros** (§7) l'accompagnera : un `exists:%{i}._spf.…` ne
//! prend son sens qu'au moment où l'on connaît l'adresse du pair. Les arguments
//! sont donc rendus **tels quels**, et la grammaire ne prétend pas les
//! comprendre.
//!
//! # Une erreur de syntaxe vaut `permerror`, et se voit tout de suite
//!
//! RFC 7208 §4.6 : un enregistrement mal formé ne s'évalue pas « au mieux », il
//! rend `permerror`. [`Record::parse`] valide donc l'enregistrement **entier**
//! avant d'en rendre le premier terme — un parcours qui s'arrêterait à
//! mi-chemin appliquerait la moitié d'une politique que son auteur n'a pas
//! écrite.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

// LES TESTS, EUX, ONT LE DROIT D'ALLOUER. La crate est `no_std` sans `alloc` —
// c'est ce qui la rendra utilisable telle quelle sur Air — mais un test qui
// collecte des termes dans un `Vec` éprouve la même chose en se lisant mieux.
#[cfg(test)]
extern crate std;

mod error;
mod eval;
mod header;
mod limits;
pub mod macros;
mod record;
mod term;

pub use error::Error;
pub use eval::{Answer, Evaluator, Query, Question, Step, Verdict};
pub use header::{Identity, RECEIVED_SPF_MAX, ReceivedSpf, write_received_spf};
pub use limits::Limits;
pub use macros::{Context, Expanded};
pub use record::{Record, Terms};
pub use term::{Lookup, Mechanism, Modifier, Qualifier, Resolution, Term};
