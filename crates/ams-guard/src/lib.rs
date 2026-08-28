//! Détection de flooding et bannissement par source, **sans entrée-sortie** (C1,
//! C8).
//!
//! Deux mesures, tenues par source :
//!
//! 1. le **débit** de connexions et de commandes — le flooding ;
//! 2. le compte de **trames invalides**. Au-delà de `x` par minute, la source
//!    n'est plus acceptée pendant `y` heures. `x` et `y` viennent de la
//!    configuration, jamais du code.
//!
//! La crate reçoit `(source, événement, instant)` et rend un verdict. Elle ne lit
//! pas l'heure : on la lui donne. C'est ce qui permet d'éprouver une fenêtre de
//! douze heures en quelques microsecondes, et c'est indispensable pour un
//! composant dont un faux positif coupe du courrier légitime.
//!
//! # État
//!
//! **Rien n'est implémenté.** Emplacement réservé.

#![no_std]
