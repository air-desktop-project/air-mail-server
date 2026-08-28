//! Stockage Maildir des messages (C13).
//!
//! Un fichier par message, contenu brut RFC 5322, arrivée par `rename()` de
//! `tmp/` vers `new/`. `rename()` est **atomique** sur POSIX : un lecteur voit le
//! message entier ou ne le voit pas. Aucun verrou n'est nécessaire, donc aucun
//! n'est oublié — c'est la propriété qui fait choisir ce format.
//!
//! # Les fichiers sont la seule source de vérité
//!
//! Rien n'est cru sur parole. L'UID d'un message vit dans **son nom** (`,U=`),
//! et [`Maildir::summary`] le relit depuis le répertoire. L'index de C13 sera un
//! accélérateur, jamais une seconde vérité ; c'est [`ams_index`] qui en porte la
//! grammaire et la reconstruction, sans entrée-sortie.
//!
//! # Cette crate fait des entrées-sorties, donc elle est hors du 100 % (C2)
//!
//! Y atteindre 100 % exigerait de simuler les pannes du système de fichiers — un
//! `ENOSPC` ici, un `EINTR` là — et l'on mesurerait alors la fidélité de la
//! simulation. Ses tests écrivent donc dans de vrais répertoires temporaires.
//!
//! # Elle n'implémente PAS `Delivery`
//!
//! Le trait vit dans `ams-loop-tokio`, et l'implémenter ici ferait dépendre un
//! écrivain de fichiers de tokio. L'adaptation — quinze lignes — appartient au
//! binaire qui connaît les deux.
//!
//! Une remise **possède** ce dont elle a besoin : elle n'emprunte pas la boîte,
//! pour qu'une tâche qui la porte puisse vivre seule.
//!
//! **Et elle bloque.** `commit` fait deux `fsync`, ce qui peut prendre le temps
//! d'une écriture disque. Appelée telle quelle depuis une tâche asynchrone, elle
//! bloque l'ordonnanceur : l'adaptation devra passer par `spawn_blocking`. C'est
//! écrit ici plutôt que découvert en production.

mod error;
mod maildir;

pub use error::Error;
pub use maildir::{Incoming, Maildir, flags_of, fresh_uid_validity};
