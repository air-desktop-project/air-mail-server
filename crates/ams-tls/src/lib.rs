//! TLS **1.3 uniquement** (C4), sans entrée-sortie (C1).
//!
//! Rien en dessous de la version 1.3 : pas de TLS 1.2, pas de repli négocié, pas
//! d'option de compatibilité. Un client qui ne sait pas faire TLS 1.3 n'est pas
//! servi (C6).
//!
//! # Point ouvert : le fournisseur cryptographique
//!
//! `rustls` est sans entrée-sortie par construction — il traite des tampons, pas
//! des sockets — donc naturellement aligné avec C1. Mais son fournisseur par
//! défaut (`aws-lc-rs`) embarque du C, et `ring` aussi ; seul
//! `rustls-rustcrypto` est pur Rust, au prix d'être moins éprouvé. Le choix
//! engage le portage vers Air, où une dépendance C est un problème, et **il n'est
//! pas tranché**.
//!
//! # État
//!
//! **Rien n'est implémenté.** Emplacement réservé.
