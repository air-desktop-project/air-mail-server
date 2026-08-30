// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le jeton d'intégrité d'un paquet `Retry` (RFC 9001 §5.8).
//!
//! # IL PROUVE QU'ON A VU LE PAQUET `Initial`, ET RIEN D'AUTRE
//!
//! §5.8 lui donne deux propriétés : jeter les `Retry` que le réseau a abîmés, et
//! **empêcher qu'un tiers en fabrique un**. La seconde est la vraie : un `Retry`
//! forgé renverrait un client vers un serveur qui n'existe pas, ou lui ferait
//! recommencer sa connexion sans fin.
//!
//! Ce qui rend la forge impossible n'est pas le secret de la clé — elle est dans
//! la RFC — mais le fait que le calcul inclue **l'identifiant de destination
//! d'origine**, celui du premier paquet du client. Seul quelqu'un qui a VU ce
//! paquet le connaît.
//!
//! # LA CLÉ EST PUBLIQUE, ET CE N'EST PAS UNE FAIBLESSE
//!
//! Elle vaut `0xbe0c690b9f66575a1d766b54e368c84e` pour tout le monde. §5.8 en
//! donne même la dérivation. Le jeton n'est donc pas une signature : c'est une
//! somme de contrôle qui atteste d'une CONNAISSANCE — celle de l'identifiant
//! d'origine —, et rien de plus.

use aes_gcm::{AeadInOut, Aes128Gcm, KeyInit};

use crate::error::{Error, Reason};
use crate::suite::TAG_OCTETS;

/// La clé de §5.8, la même pour toute connexion QUIC version 1.
pub const RETRY_KEY: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];

/// Le nonce de §5.8.
pub const RETRY_NONCE: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

/// Calcule le jeton d'intégrité d'un `Retry`.
///
/// `origine` est l'identifiant de destination du premier paquet du client ;
/// `retry` est le paquet `Retry` SANS son jeton ; `atelier` est un tampon de
/// travail d'au moins `1 + origine.len() + retry.len()` octets.
///
/// # POURQUOI UN TAMPON DE TRAVAIL
///
/// Les données associées d'un AEAD se donnent d'un seul tenant, et le
/// pseudo-paquet de §5.8 n'existe nulle part en mémoire : c'est une longueur, un
/// identifiant, et le paquet, mis bout à bout. Ce crate n'alloue pas — l'appelant
/// fournit donc la place, et sait ainsi ce qu'elle coûte.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`] si l'atelier ne suffit pas, ou si l'identifiant
/// dépasse ce qu'un octet peut annoncer.
pub fn retry_tag(
    origine: &[u8],
    retry: &[u8],
    atelier: &mut [u8],
) -> Result<[u8; TAG_OCTETS], Error> {
    let court = || Error::new(Reason::BufferTooSmall);
    // §5.8 : le pseudo-paquet commence par la LONGUEUR de l'identifiant
    // d'origine, sur un octet.
    let dite = u8::try_from(origine.len()).map_err(|_| court())?;
    let total = 1_usize
        .saturating_add(origine.len())
        .saturating_add(retry.len());
    let place = atelier.get_mut(..total).ok_or_else(court)?;
    let (tete, suite) = place.split_at_mut(1);
    tete[0] = dite;
    let (identifiant, corps) = suite.split_at_mut(origine.len());
    identifiant.copy_from_slice(origine);
    corps.copy_from_slice(retry);

    // Le clair est VIDE : ce chiffrement ne cache rien, il authentifie.
    //
    // **ET IL NE PEUT PAS ÉCHOUER** : GCM ne refuse qu'au-delà de soixante-quatre
    // gibioctets de données associées, et un `Retry` tient dans un datagramme.
    // `unwrap_or_default` porte cette impossibilité plutôt qu'une branche
    // qu'aucun paquet ne peut emprunter.
    let mut rien: [u8; 0] = [];
    let tag = Aes128Gcm::new(&RETRY_KEY.into())
        .encrypt_inout_detached((&RETRY_NONCE).into(), place, (&mut rien[..]).into())
        .unwrap_or_default();
    Ok(tag.into())
}

/// Vérifie le jeton d'intégrité d'un `Retry` reçu.
///
/// `paquet` est le `Retry` entier, jeton compris.
///
/// # Errors
///
/// [`Reason::NotAuthentic`] — **et le paquet se JETTE** : un `Retry` qu'on ne
/// peut pas authentifier peut venir de n'importe qui ;
/// [`Reason::BufferTooSmall`].
pub fn verify_retry(origine: &[u8], paquet: &[u8], atelier: &mut [u8]) -> Result<(), Error> {
    let court = || Error::new(Reason::BufferTooSmall);
    let coupure = paquet.len().checked_sub(TAG_OCTETS).ok_or_else(court)?;
    let (corps, jeton) = paquet.split_at(coupure);
    let attendu = retry_tag(origine, corps, atelier)?;
    // **LA COMPARAISON EST EN TEMPS CONSTANT**, et ce n'est pas de la pédanterie
    // ici : une comparaison qui s'arrête au premier octet différent laisserait
    // deviner le jeton octet par octet, et donc forger un `Retry` en quelques
    // milliers d'essais.
    let mut ecart = 0_u8;
    for (a, b) in attendu.iter().zip(jeton) {
        ecart |= a ^ b;
    }
    match ecart == 0 && jeton.len() == TAG_OCTETS {
        true => Ok(()),
        false => Err(Error::new(Reason::NotAuthentic)),
    }
}

#[cfg(test)]
mod tests;
