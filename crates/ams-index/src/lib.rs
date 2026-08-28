//! Index Maildir : codec Cap'n Proto et **reconstruction**, sans entrée-sortie
//! (C1, C13).
//!
//! Maildir ne porte pas d'identifiant stable, alors qu'IMAP exige des UID stables
//! et croissants sous une `UIDVALIDITY` donnée. Cet index — binaire, même format
//! que la configuration (C11) — porte les UID, les drapeaux et la `UIDVALIDITY`.
//!
//! **Les fichiers restent la seule source de vérité.** L'index n'est qu'un
//! accélérateur ; s'il ne l'était pas, il deviendrait une seconde source de
//! vérité, capable de diverger de la première sans que rien ne le signale.
//!
//! # Ce que « reconstructible » exige, et ce n'est pas évident
//!
//! Reconstruire un index, ce n'est pas le recalculer *d'une manière ou d'une
//! autre* : c'est retrouver **exactement les mêmes UID**. Un UID déduit d'un
//! ordre — date de modification, ordre de lecture du répertoire — n'est pas
//! stable : il change au premier fichier restauré depuis une sauvegarde, et le
//! client resynchronise toute la boîte.
//!
//! **L'UID vit donc dans le nom du fichier**, pas seulement ici. La partie unique
//! d'un nom Maildir est opaque et libre — hors `:` et `/` — ce qui suffit à l'y
//! porter.
//!
//! La propriété qui en découle est vérifiable, et c'est elle qu'un test devra
//! défendre : **perdre l'index coûte un parcours de répertoire, jamais une
//! resynchronisation client**. La `UIDVALIDITY` n'a alors aucune raison de
//! changer — et la changer forcerait chaque client à retélécharger l'intégralité
//! de la boîte.
//!
//! # Pourquoi cette crate, et pas un module d'`ams-store`
//!
//! La reconstruction — d'une liste de noms de fichiers vers un index — est la
//! partie critique, et elle ne fait aucune entrée-sortie. Elle relève donc du
//! 100 % de C2, que le gate de couverture applique **par crate** : la laisser
//! dans `ams-store`, qui lit et écrit, l'aurait de fait exemptée.
//!
//! `ams-store` fournit les noms et écrit les octets ; tout ce qui décide est ici.
//!
//! # État
//!
//! **Rien n'est implémenté** — pas même le schéma. Emplacement réservé.
