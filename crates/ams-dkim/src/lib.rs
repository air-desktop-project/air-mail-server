//! DKIM (RFC 6376) : signature et vérification, **sans entrée-sortie** (C1, C9).
//!
//! La clé publique du signataire vit dans le DNS. Cette crate ne la résout pas :
//! elle **rend l'action** « résoudre `sélecteur._domainkey.domaine` en TXT », et
//! la boucle lui réinjecte le résultat. C'est ce qui la rend couvrable à 100 %
//! sans serveur DNS de test.
//!
//! # État
//!
//! **Rien n'est implémenté.** Emplacement réservé.

#![no_std]
