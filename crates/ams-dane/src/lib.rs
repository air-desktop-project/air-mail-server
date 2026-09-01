//! DANE pour SMTP (RFC 7672) : **ce qu'un `TLSA` autorise**, sans entrée-sortie
//! (C1).
//!
//! # LE PROBLÈME QUE DANE RÉSOUT, ET QU'IL EST SEUL À RÉSOUDRE
//!
//! Quand ce serveur remet du courrier, le serveur qu'il joint est désigné par un
//! `MX` — c'est-à-dire par quiconque peut répondre à cette question. Vérifier le
//! certificat du pair contre ce nom ne prouve rien : un tiers qui détourne la
//! résolution présente un certificat parfaitement valide pour le nom qu'il vient
//! de fabriquer. **La chaîne de confiance s'arrête un cran plus tôt, dans le
//! DNS.**
//!
//! DANE la reprend là : le domaine publie lui-même, dans son DNS signé,
//! l'empreinte du certificat qu'il présentera. Il n'y a plus de tiers à croire.
//!
//! # CE QUE CETTE CRATE FAIT, ET CE QU'ELLE NE PEUT PAS FAIRE
//!
//! Elle décode des enregistrements `TLSA`, dit lesquels sont UTILISABLES, et dit
//! si un certificat correspond — en retrouvant au besoin son
//! `SubjectPublicKeyInfo`, que le sélecteur `1` désigne. Elle ne résout rien, n'ouvre aucune connexion et
//! ne valide aucune signature DNSSEC : **c'est l'appelant qui garantit que les
//! enregistrements sont authentiques**, et c'est le point le plus important de
//! tout ce module.
//!
//! Un `TLSA` lu dans une réponse non authentifiée ne vaut RIEN — un tiers l'a
//! peut-être fabriqué, ou, pire, retiré. Voir [`Set::from_records`], qui exige de
//! l'appelant qu'il le dise.
//!
//! # DEUX USAGES SEULEMENT, ET C'EST LA RFC QUI LE DIT
//!
//! §3.1.3 de RFC 7672 : `PKIX-TA(0)` et `PKIX-EE(1)` ne s'appliquent PAS à SMTP,
//! et un enregistrement qui les porte doit être traité comme INUTILISABLE. La
//! raison est la même que plus haut : ils demandent une validation WebPKI contre
//! un nom qui vient du DNS, ce que DANE existe précisément pour ne plus avoir à
//! faire.
//!
//! Restent `DANE-TA(2)` — « voici mon autorité » — et `DANE-EE(3)` — « voici mon
//! certificat ». Ils ne se vérifient pas de la même façon, et [`Match`] le dit.
//!
//! # UN JEU ENTIÈREMENT INUTILISABLE N'EST PAS UN ÉCHEC
//!
//! §2.2 : si aucun enregistrement du jeu n'est utilisable, on fait **comme s'il
//! n'y en avait aucun** — chiffrement opportuniste. C'est la bonne façon
//! d'échouer : un domaine qui publie un usage qu'on ne sait pas traiter ne doit
//! pas voir son courrier s'arrêter. **Un jeu qui porte au moins un enregistrement
//! utilisable, lui, ENGAGE** : la remise doit être authentifiée, ou ne pas avoir
//! lieu.
//!
//! # Exemple
//!
//! ```
//! use ams_dane::{Set, Tlsa};
//!
//! // `3 1 1 <sha256 de la clé publique>` — le cas courant.
//! let mut rdata = std::vec![3, 1, 1];
//! rdata.extend_from_slice(&[0xab; 32]);
//!
//! let record = Tlsa::parse(&rdata).expect("un TLSA bien formé");
//! assert!(record.usable());
//!
//! // L'appelant DOIT dire si la réponse était authentifiée.
//! let jeu = Set::from_records(std::vec![record], true);
//! assert!(jeu.engage());
//!
//! // La même chose sans authentification n'engage à rien.
//! let sans = Set::from_records(std::vec![record], false);
//! assert!(!sans.engage());
//! ```

#![no_std]

extern crate alloc;

// La crate livrée n'a pas `std`. Les tests, eux, ont le droit d'allouer.
#[cfg(test)]
extern crate std;

mod record;
mod set;
mod spki;

pub use record::{Match, Matching, Selector, Tlsa, Usage};
pub use set::Set;
pub use spki::subject_public_key_info;

/// Le préfixe sous lequel un `TLSA` de SMTP se publie (§3.1 de RFC 7672).
///
/// **C'est le port et le protocole du SERVICE**, pas ceux du domaine : la
/// remise entre serveurs se fait sur 25 en TCP, et un `TLSA` publié ailleurs ne
/// dit rien de celle-ci.
pub const SMTP_PREFIX: &str = "_25._tcp.";
