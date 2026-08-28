//! Grammaire SMTP : décodage et encodage, **sans entrée-sortie**.
//!
//! Périmètre visé : RFC 5321 (SMTP), RFC 5322 (format des messages), et les
//! extensions que le serveur décidera de servir — `STARTTLS`, `AUTH`, `SIZE`,
//! `8BITMIME`, `PIPELINING`.
//!
//! Cette crate ne connaît ni socket, ni fichier, ni horloge : elle transforme des
//! octets en commandes et des réponses en octets. Deux raisons à cela — un
//! protocole texte se teste et se fuzze exhaustivement quand il n'ouvre pas de
//! port, et ce qui ne fait pas d'entrée-sortie n'a rien à porter le jour où
//! l'environnement change.
//!
//! # État
//!
//! **Rien n'est implémenté.** Cette crate est un emplacement réservé, créé avec
//! le squelette du dépôt. Aucun décodeur, aucun encodeur, aucune commande.

#![no_std]
