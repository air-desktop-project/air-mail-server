// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `HMAC-SHA-256` (RFC 2104), et la comparaison qui va avec.
//!
//! # POURQUOI ÉCRIT ICI
//!
//! HMAC n'est pas une primitive : c'est une construction de quinze lignes
//! au-dessus d'un hachage, et RFC 4231 en donne des vecteurs d'essai. Ces
//! vecteurs sont une meilleure preuve que « on a appelé une bibliothèque » — ils
//! prouvent le résultat, pas la provenance.
//!
//! Et l'écrire ici rend infaillible ce qui ne l'était pas : le constructeur des
//! bibliothèques HMAC rend un `Result` qu'aucune clé ne peut faire échouer, donc
//! une branche qu'aucun essai ne peut atteindre. **Une garde inatteignable n'est
//! pas une garde.**
//!
//! # LA COMPARAISON EST LA MOITIÉ QUI COMPTE
//!
//! Un sceau juste vérifié avec un `==` ne protège rien. `==` s'arrête au premier
//! octet qui diffère, et le temps qu'il met dit combien d'octets étaient bons :
//! on devine alors le sceau octet par octet, en trente-deux fois deux cent
//! cinquante-six essais au lieu de deux à la puissance deux cent cinquante-six.
//!
//! C'est pourquoi [`egales`] ne s'arrête jamais.

use sha2::{Digest, Sha256};

/// Ce qu'un sceau occupe.
pub const MAC_OCTETS: usize = 32;

/// La taille de bloc de SHA-256, en octets.
const BLOC: usize = 64;

/// Le remplissage intérieur de RFC 2104.
const IPAD: u8 = 0x36;

/// Le remplissage extérieur.
const OPAD: u8 = 0x5c;

/// `HMAC-SHA-256` de ce message sous cette clé.
///
/// # UNE CLÉ PLUS LONGUE QU'UN BLOC SE HACHE D'ABORD
///
/// §2 de RFC 2104. Sans cela, deux clés qui ne diffèrent qu'au-delà du
/// soixante-quatrième octet donneraient le même sceau — et la partie qui dépasse
/// ne servirait à rien tout en donnant l'illusion du contraire.
#[must_use]
pub fn hmac_sha256(clef: &[u8], message: &[u8]) -> [u8; MAC_OCTETS] {
    let mut normalisee = [0_u8; BLOC];
    match clef.len() > BLOC {
        true => {
            let condensee = Sha256::digest(clef);
            for (ou, lu) in normalisee.iter_mut().zip(condensee.iter()) {
                *ou = *lu;
            }
        }
        // Plus courte qu'un bloc : elle se complète de zéros, et c'est déjà fait.
        false => {
            for (ou, lu) in normalisee.iter_mut().zip(clef) {
                *ou = *lu;
            }
        }
    }

    let mut interieur = Sha256::new();
    let mut exterieur = Sha256::new();
    for octet in normalisee {
        interieur.update([octet ^ IPAD]);
        exterieur.update([octet ^ OPAD]);
    }
    interieur.update(message);
    exterieur.update(interieur.finalize());
    exterieur.finalize().into()
}

/// Ces deux tranches sont-elles égales, **sans jamais s'arrêter plus tôt** ?
///
/// La longueur, elle, se compare ordinairement : elle n'est pas un secret, et
/// elle se lit de toute façon dans la taille du message.
#[must_use]
pub fn egales(un: &[u8], deux: &[u8]) -> bool {
    // Une différence de longueur pose le drapeau d'emblée, et la boucle tourne
    // quand même sur ce qu'il y a de commun.
    let mut ecart = u8::from(un.len() != deux.len());
    for (a, b) in un.iter().zip(deux) {
        ecart |= a ^ b;
    }
    ecart == 0
}

#[cfg(test)]
mod tests;
