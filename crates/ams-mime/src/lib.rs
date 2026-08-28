//! Format des messages RFC 5322 et MIME : décodage et encodage, **sans
//! entrée-sortie** (C1).
//!
//! Le socle commun des quatre protocoles et des trois crates d'authentification :
//! SMTP transporte un message, IMAP en expose la structure (`BODYSTRUCTURE`),
//! DKIM en canonicalise les en-têtes pour signer. Une seule grammaire, écrite une
//! fois.
//!
//! Périmètre visé : RFC 5322 (messages), RFC 2045-2047 (MIME et en-têtes encodés),
//! RFC 6532 (en-têtes UTF-8).
//!
//! # État
//!
//! **Rien n'est implémenté.** Emplacement réservé.

#![no_std]
