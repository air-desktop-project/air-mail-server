//! DNS (RFC 1035) : **le codec d'un message, sans entrée-sortie** (C1).
//!
//! # Pourquoi cette crate existe
//!
//! SPF (C9) ne conclut rien sans résoudre des noms, et rien dans ce projet ne
//! savait parler au DNS. Deux chemins s'offraient : prendre une bibliothèque de
//! résolution toute faite, ou écrire le codec.
//!
//! C'est le codec, et pour la raison qui gouverne tout le reste : **le DNS est
//! un protocole, et C1 veut les protocoles sous forme de codecs sans
//! entrée-sortie, couverts à 100 % (C2) et fuzzés (C3)**. Une bibliothèque de
//! résolution apporte son propre modèle d'exécution, ses propres délais, ses
//! propres caches — c'est-à-dire exactement ce que l'étage 3 doit décider — et
//! elle ne se porterait pas telle quelle sur Air. Ce qu'on écrit ici tient en
//! quelques centaines de lignes parce qu'on n'écrit qu'un client stub : ce
//! serveur pose des questions, il n'en répond aucune.
//!
//! # Ces octets viennent d'un inconnu
//!
//! Une réponse DNS arrive par UDP, d'une adresse qu'on n'a pas authentifiée,
//! avec une charge que **n'importe qui sur le chemin peut fabriquer**. Le
//! décodeur ne suppose donc rien : ni que les sections ont la taille annoncée,
//! ni que les noms se terminent, ni que les pointeurs de compression pointent
//! vers de la mémoire qui existe.
//!
//! ## La compression, et la boucle qu'elle rend possible
//!
//! Un nom peut se poursuivre par un **pointeur** vers un nom déjà écrit
//! ailleurs dans le message (RFC 1035 §4.1.4). Un message hostile peut donc
//! faire pointer un nom vers lui-même, ou vers un cycle de deux — et un
//! décodeur naïf y tourne indéfiniment. C'est un déni de service qui tient en
//! quarante octets.
//!
//! La parade ici n'est pas un compteur de sauts, c'est une **impossibilité
//! structurelle** : chaque pointeur doit viser STRICTEMENT PLUS BAS que le
//! précédent. La suite des cibles décroît donc dans les entiers naturels, ce
//! qui ne peut pas ne pas s'arrêter. Et cette règle est celle de la RFC, qui
//! veut qu'un pointeur désigne « une occurrence antérieure ».
//!
//! # Ce que cette crate ne fait pas
//!
//! Elle ne résout pas : ni socket, ni délai, ni reprise en TCP, ni cache. Elle
//! encode une question et décode une réponse. Le résolveur vit dans la boucle,
//! qui seule a le droit d'attendre.
//!
//! Elle ne valide pas non plus DNSSEC. **C'est une lacune, pas un oubli** : sans
//! DNSSEC, un SPF `pass` ne vaut que ce que vaut le chemin jusqu'au résolveur, et
//! c'est pourquoi le résolveur doit être local ou joint par un lien de
//! confiance. Le dire ici vaut mieux que de le laisser croire.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

// LES TESTS, EUX, ONT LE DROIT D'ALLOUER : la crate est `no_std` sans `alloc`,
// mais un test qui rassemble des enregistrements dans un `Vec` éprouve la même
// chose en se lisant mieux.
#[cfg(test)]
extern crate std;

mod error;
mod message;
mod name;
mod query;

pub use error::Error;
pub use message::{Message, Record, Records, Status, Strings};
pub use name::{MAX_NAME, Name};
pub use query::{QUERY_MAX, encode_query};

/// Les types d'enregistrement que ce projet interroge.
///
/// Ceux dont SPF a besoin (RFC 7208 §5), plus `TLSA` pour DANE (RFC 7672) — et
/// pas un de plus : un type qu'on n'interroge pas est un décodeur qu'on
/// n'éprouve pas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Kind {
    /// Une adresse IPv4.
    A = 1,
    /// Un nom canonique. On ne l'interroge jamais, mais il ARRIVE : un résolveur
    /// récursif laisse la chaîne suivie dans la section des réponses.
    Cname = 5,
    /// Le nom d'une adresse, par résolution inverse.
    Ptr = 12,
    /// Un serveur de courrier.
    Mx = 15,
    /// Du texte — c'est là que vivent les politiques SPF.
    Txt = 16,
    /// Une adresse IPv6.
    Aaaa = 28,
    /// L'empreinte d'un certificat, publiée par le domaine lui-même (RFC 6698).
    ///
    /// **Elle ne vaut que si la réponse est authentifiée** : sans DNSSEC, un
    /// tiers qui détourne la résolution retire simplement l'enregistrement, et
    /// l'on retombe sur le chiffrement opportuniste sans s'en apercevoir. C'est
    /// le bit `AD` qui tranche — voir [`crate::Message::authentic_data`].
    Tlsa = 52,
}

impl Kind {
    /// Le nombre porté par le message.
    #[must_use]
    pub fn code(self) -> u16 {
        self as u16
    }
}

/// La classe `IN`, la seule qui existe encore.
///
/// `CH` et `HS` sont des vestiges ; un enregistrement d'une autre classe que
/// celle qu'on a demandée n'est pas une réponse à notre question.
pub const CLASS_IN: u16 = 1;

/// Le type `OPT` d'EDNS(0) (RFC 6891).
pub const KIND_OPT: u16 = 41;
