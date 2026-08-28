//! Boucle d'entrées-sorties Unix, sur tokio (C5).
//!
//! Elle lit des octets, les pousse dans une session d'[`ams_session`], exécute les
//! actions que celle-ci rend, et écrit ce qu'elle demande d'émettre. **Elle ne
//! porte aucune logique de protocole** : tout ce qui décide vit dans les crates
//! sans entrée-sortie.
//!
//! Une seconde boucle, adossée au moteur asynchrone d'Air (`air-async` sur
//! `air-uring`), lui répondra sur la cible `*-linux-air`. Elle **n'existe pas** :
//! une crate vide portant ce nom laisserait croire qu'un portage est entamé.
//!
//! Comme toute crate qui fait des entrées-sorties, celle-ci est hors du périmètre
//! de couverture à 100 % de C2.
//!
//! # État
//!
//! **Rien n'est implémenté** — tokio n'est pas encore une dépendance du
//! workspace. Emplacement réservé.
