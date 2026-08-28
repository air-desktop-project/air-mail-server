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
//! Comme [`ams_dkim`], elle rend ses résolutions DNS sous forme d'actions plutôt
//! que de les exécuter — d'autant que SPF impose une limite stricte au nombre de
//! résolutions par évaluation, limite qui se vérifie bien mieux sur une machine à
//! états que sur un résolveur.
//!
//! # État
//!
//! **Rien n'est implémenté.** Emplacement réservé.

#![no_std]
