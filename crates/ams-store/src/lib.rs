//! Stockage Maildir des messages (C13).
//!
//! Un fichier par message, contenu brut RFC 5322, atomicité par `rename()` de
//! `tmp/` vers `new/`, drapeaux portés par le nom du fichier. Aucun verrou : c'est
//! la propriété qui fait choisir Maildir.
//!
//! Cette crate **fait des entrées-sorties** — c'est son objet — et se trouve donc
//! hors du périmètre de couverture à 100 % de C2.
//!
//! # Conséquence connue et non résolue
//!
//! Maildir ne porte pas d'identifiant stable, alors qu'IMAP exige des UID stables
//! et croissants sous une `UIDVALIDITY` donnée. Un index sera nécessaire, et il
//! devra être **reconstructible depuis les fichiers** : sans quoi il devient une
//! seconde source de vérité, qui peut diverger de la première sans que rien ne le
//! signale. Sa forme n'est pas décidée.
//!
//! # État
//!
//! **Rien n'est implémenté.** Emplacement réservé.
