//! Le magasin d'identifiants, et la vérification **Argon2id** — sans
//! entrée-sortie (C1).
//!
//! # Ce qui est stocké, et ce qui ne l'est jamais
//!
//! Un compte est un **nom** et une **empreinte au format PHC** :
//!
//! ```text
//! $argon2id$v=19$m=19456,t=2,p=1$c2VsIGRlIHNlaXplIG9jdGV0cw$R+7MES/hWY6ZctiM4...
//! ```
//!
//! Le mot de passe, lui, n'est écrit nulle part. C'est l'unique raison d'être
//! d'une fonction de dérivation : une fuite du fichier de comptes ne doit pas
//! être une fuite des mots de passe.
//!
//! # Les paramètres, et d'où ils viennent
//!
//! `Argon2id`, **m = 19456 Kio (19 Mio), t = 2, p = 1** — la première des
//! configurations équivalentes que recommande l'OWASP *Password Storage Cheat
//! Sheet*. Ils ne sont pas devinés, et ils sont écrits dans
//! `docs/contraintes.md` pour qu'on sache quoi relire le jour où on les changera.
//!
//! **`Argon2id` et non `Argon2i` ni `Argon2d`** : c'est l'hybride, et c'est ce
//! que la RFC 9106 §4 recommande quand on ne sait rien de l'attaquant — ce qui
//! est exactement notre cas.
//!
//! # Le coût est le SUJET, pas un effet de bord
//!
//! Dix-neuf mébioctets et quelques dizaines de millisecondes par vérification,
//! c'est ce qui rend une attaque par dictionnaire coûteuse. C'est aussi une
//! **amplification** offerte à qui envoie des `AUTH` : quelques octets sur le
//! fil deviennent 19 Mio et du calcul chez nous.
//!
//! Cette crate ne peut pas régler cela — elle ne sait pas combien de
//! vérifications ont lieu en même temps. **C'est à l'appelant de borner leur
//! nombre**, et `ams-server` le fait. Le dire ici plutôt que de le supposer
//! ailleurs, c'est la moitié du travail.
//!
//! # Un compte, une boîte, et des adresses
//!
//! Le nom de compte est **aussi le nom du répertoire** de sa boîte. Deux
//! champs — un identifiant et un répertoire — auraient permis de les faire
//! diverger ; un seul impose ses contraintes des deux côtés, et
//! [`check_login`] les énonce. C'est une frontière de sécurité : un nom de
//! compte qui contiendrait `../` ferait écrire hors de la racine.
//!
//! Les adresses d'enveloppe, elles, sont une **liste** : `jean@example.com` et
//! `j.dupont@example.com` peuvent mener à la même boîte, et un compte sans
//! aucune adresse est un compte de soumission, qui envoie sans recevoir.
//!
//! # Ce qui est vérifié D'AVANCE sur une empreinte stockée
//!
//! Une vérification Argon2 emploie les paramètres inscrits **dans l'empreinte**,
//! pas ceux de cette crate : c'est ce qui permet de faire évoluer les paramètres
//! sans invalider les comptes existants. C'est aussi ce qui rend
//! [`check_stored`] nécessaire — une empreinte écrite avec `m=8,t=1` serait
//! vérifiée avec `m=8,t=1`, et personne ne le verrait. Le magasin refuse donc
//! d'être chargé si l'un de ses comptes est en dessous du plancher.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

mod store;

pub use store::{
    Account, DUMMY_HASH, Error, MEMORY_KIB, PARALLELISM, TIME_COST, authenticate, check_login,
    check_stored, hash_password, route,
};
