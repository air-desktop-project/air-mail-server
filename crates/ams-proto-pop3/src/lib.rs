//! Grammaire POP3 : décodage et encodage, **sans entrée-sortie**.
//!
//! Périmètre visé : RFC 1939 (POP3), RFC 2449 (`CAPA`), RFC 5034 (`AUTH`),
//! RFC 2595 (`STLS`).
//!
//! Comme les autres crates `ams-proto-*`, celle-ci ne connaît ni socket ni
//! fichier : elle transforme des octets en commandes et des réponses en octets.
//!
//! # État
//!
//! **Rien n'est implémenté.** Cette crate est un emplacement réservé, créé avec
//! le squelette du dépôt.

#![no_std]
