//! TLS **1.3 uniquement** (C4), sans entrée-sortie (C1).
//!
//! Rien en dessous de la version 1.3 : pas de TLS 1.2, pas de repli négocié, pas
//! d'option de compatibilité. Un client qui ne sait pas faire TLS 1.3 n'est pas
//! servi (C6).
//!
//! # Le fournisseur cryptographique : `rustls-rustcrypto`, pur Rust
//!
//! `rustls` est sans entrée-sortie par construction — il traite des tampons, pas
//! des sockets — donc naturellement aligné avec C1. Son fournisseur sera
//! `rustls-rustcrypto`, seul fournisseur **sans une ligne de C** : `aws-lc-rs`
//! (le défaut) et `ring` en embarquent, et le portage vers Air ne peut pas payer
//! ce prix.
//!
//! **`default-features = false` est ce qui applique C4 et C6**, et non une
//! préférence de style : la feature `tls12` est dans les défauts de
//! `rustls-rustcrypto`, et la laisser active ferait entrer TLS 1.2 par la porte
//! de derrière.
//!
//! Mesuré le 2026-08-28 sur la configuration exacte du registre, par compilation
//! et exécution — pas déduit d'une documentation : 74 crates compilées, aucune
//! `ring`, aucune `cc`, aucune `*-sys` ; et exactement trois suites offertes,
//! toutes en TLS 1.3, aucune en 1.2.
//!
//! Les réserves — version publiée périmée, numérotation `0.0.2-alpha` par ses
//! propres auteurs, et **absence d'échange de clés post-quantique** — sont
//! consignées en C4 du registre des contraintes. La dernière reste un point
//! ouvert : un courrier intercepté aujourd'hui se déchiffre plus tard.
//!
//! # État
//!
//! **Rien n'est implémenté**, et `rustls` n'est pas encore une dépendance du
//! workspace. Emplacement réservé.
