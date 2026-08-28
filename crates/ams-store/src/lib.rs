//! Stockage des messages et des boîtes.
//!
//! Ce que les quatre protocoles ont en commun se trouve ici : des boîtes, des
//! messages, des drapeaux, des UID stables. SMTP y dépose, POP3 et IMAP y lisent,
//! et c'est la seule crate qui a le droit de savoir comment tout cela est rangé.
//!
//! Le format de stockage n'est **pas choisi**. Maildir, une base embarquée, un
//! journal propre au projet : chacun a des conséquences différentes sur les UID
//! IMAP et sur la durabilité d'un `DATA` accepté. La décision viendra avec le
//! premier besoin réel, pas avec le squelette.
//!
//! # État
//!
//! **Rien n'est implémenté.** Cette crate est un emplacement réservé, créé avec
//! le squelette du dépôt.
