//! Stockage Maildir des messages (C13).
//!
//! Un fichier par message, contenu brut RFC 5322, atomicité par `rename()` de
//! `tmp/` vers `new/`, drapeaux portés par le nom du fichier. Aucun verrou : c'est
//! la propriété qui fait choisir Maildir.
//!
//! Cette crate **fait des entrées-sorties** — c'est son objet — et se trouve donc
//! hors du périmètre de couverture à 100 % de C2.
//!
//! # L'index vit ailleurs, et c'est délibéré
//!
//! Maildir ne porte pas d'identifiant stable, alors qu'IMAP exige des UID
//! stables. Un index binaire Cap'n Proto les porte — mais son codec et sa
//! **reconstruction** vivent dans [`ams_index`], pas ici.
//!
//! La raison n'est pas esthétique : la reconstruction est la partie critique, elle
//! ne fait aucune entrée-sortie, et le gate de couverture de C2 travaille **par
//! crate**. La laisser dans cette crate-ci l'aurait de fait exemptée du 100 %.
//!
//! Cette crate fournit donc les noms de fichiers et écrit les octets ; elle ne
//! décide de rien. L'index s'y dépose comme un message : par `rename()` atomique.
//! Un index douteux **se reconstruit plutôt qu'il ne se répare** — c'est peu cher,
//! et cela évite d'avoir à faire confiance à des octets dont on doute.
//!
//! # État
//!
//! **Rien n'est implémenté.** Emplacement réservé.
