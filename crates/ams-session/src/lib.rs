//! Machines à états des sessions serveur, **sans entrée-sortie** (C1).
//!
//! C'est ici que la contrainte « sans I/O » remonte au-dessus des codecs. Une
//! session reçoit des octets et l'heure ; elle rend des octets à émettre et des
//! actions à exécuter (résoudre un nom, écrire un message, fermer). Elle
//! n'attend jamais.
//!
//! # Pourquoi le serveur lui-même, et pas seulement les protocoles
//!
//! Une machine à états se pilote pas à pas depuis un test : on lui donne des
//! octets, on lui donne une heure, on regarde ce qu'elle rend. Une boucle
//! asynchrone ne se pilote pas — on l'attend. C'est la seule disposition où le
//! 100 % de couverture exigé par C2 reste atteignable au-dessus des codecs, et
//! c'est la raison d'être de cette crate.
//!
//! Le prix est une boucle à écrire par moteur d'exécution ([`ams-loop-tokio`]
//! aujourd'hui, une boucle Air demain), qui ne porte aucune logique de protocole.
//!
//! # État
//!
//! **Rien n'est implémenté.** Emplacement réservé.
//!
//! [`ams-loop-tokio`]: https://github.com/air-desktop-project/air-mail-server

#![no_std]
