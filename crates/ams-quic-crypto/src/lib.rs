// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La protection des paquets QUIC (RFC 9001), **sans entrée-sortie** (C1).
//!
//! # POURQUOI CE N'EST PAS DANS `ams-proto-quic`
//!
//! La grammaire de QUIC est `no_std` et n'a aucune dépendance. Le chiffrement,
//! lui, en demande — AES, ChaCha20, HKDF. Les mélanger ferait d'un crate de
//! grammaire un crate qui traîne une bibliothèque de chiffrement, et l'on ne
//! pourrait plus lire un en-tête sans elle.
//!
//! La coupure suit d'ailleurs le protocole : §5.4 impose de lire l'en-tête AVANT
//! de pouvoir le déchiffrer, parce que la clé se trouve par l'identifiant de
//! destination. Grammaire d'abord, clés ensuite.
//!
//! # TOUT EST CHIFFRÉ, Y COMPRIS CE QUI NE SEMBLE PAS SECRET
//!
//! Le numéro de paquet est masqué (§5.4). Ce n'est pas une confidentialité de
//! plus : c'est ce qui empêche un observateur de relier deux paquets d'une même
//! connexion en les regardant passer — et donc de suivre un utilisateur qui
//! change de réseau. TCP, dont le numéro de séquence est en clair, ne peut pas
//! le faire.
//!
//! # ET LES CLÉS DES PAQUETS `Initial` SONT PUBLIQUES
//!
//! §5.2 : elles se dérivent de l'identifiant de destination que le client a
//! choisi, avec un sel écrit dans la RFC. **N'importe qui peut les calculer.**
//! Elles ne protègent donc rien du contenu ; elles protègent contre les
//! intermédiaires qui modifieraient les paquets sans le savoir — ce que
//! l'histoire de TCP a montré être un problème réel.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

// LES TESTS, EUX, ONT LE DROIT D'ALLOUER.
#[cfg(test)]
extern crate std;

mod error;
mod header;
mod keys;
mod label;
mod retry;
mod secret;
mod suite;
mod usage;

pub use error::{Error, Reason};
pub use header::{longueur_du_numero, protect, unprotect};
pub use keys::{HeaderKeys, INITIAL_SALT, Keys, PACKET_OCTETS_MAX, PacketKeys};
pub use label::{expand_sha256, expand_sha384, extract_sha256, hkdf_label};
pub use retry::{RETRY_KEY, RETRY_NONCE, retry_tag, verify_retry};
pub use secret::{Role, Secret};
pub use suite::{
    IV_OCTETS, KEY_OCTETS_MAX, MASK_OCTETS, SAMPLE_OCTETS, SECRET_OCTETS_MAX, Suite, TAG_OCTETS,
};
pub use usage::Usage;
