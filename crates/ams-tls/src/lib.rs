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
//! Les réserves — version publiée périmée, et numérotation `0.0.2-alpha` par ses
//! propres auteurs — sont consignées en C4 du registre des contraintes.
//!
//! # Le post-quantique est obligatoire (C14), et il est à écrire ici
//!
//! Le serveur doit **toujours** offrir `X25519MLKEM768` (point de code `0x11ec`)
//! et le préférer ; `X25519` reste offert en second, pour les pairs dont la pile
//! TLS ne sait pas encore faire de post-quantique.
//!
//! `rustls-rustcrypto` **n'a aucune trace de ML-KEM** — ni feature, ni une
//! occurrence dans son code. Le seul fournisseur `rustls` qui offre ce groupe est
//! `aws-lc-rs`, qui embarque du C, ce que C4 exclut. Cette crate portera donc une
//! implémentation de [`rustls::crypto::SupportedKxGroup`] composant `ml-kem`
//! 0.3.2 et `x25519-dalek`, tous deux purs Rust — la première étant exactement
//! la version qu'Air épingle et a validée contre les vecteurs FIPS 203.
//!
//! **Ce que cela nous fait posséder.** Aucune primitive n'est inventée, mais le
//! combinateur hybride et son encodage sur le fil deviennent notre code, et il
//! est critique. L'ordre exact des octets se relève dans la spécification,
//! jamais de mémoire : deux moitiés interverties donnent un handshake qui échoue
//! en interopérabilité et réussit contre soi-même. Des vecteurs de test et une
//! interopérabilité vérifiée contre une implémentation de référence (OpenSSL
//! 3.5+, `aws-lc-rs`) sont exigés avant que ce code cesse d'être « écrit ».
//!
//! **Le résidu est nommé** : un pair sans post-quantique obtient `X25519`, et
//! cette connexion-là n'est pas protégée contre « intercepter aujourd'hui,
//! déchiffrer demain ». On ne présentera donc jamais ce serveur comme
//! « post-quantique » sans ajouter « quand le pair le veut bien ».
//!
//! # État
//!
//! **Rien n'est implémenté**, et `rustls` n'est pas encore une dépendance du
//! workspace. Emplacement réservé.
