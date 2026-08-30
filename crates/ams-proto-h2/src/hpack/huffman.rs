// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le codage de Huffman de RFC 7541 §5.2 et annexe B.
//!
//! # TROIS FAUTES À REFUSER, ET LA RFC LES NOMME TOUTES LES TROIS
//!
//! §5.2, dernier paragraphe : « A padding strictly longer than 7 bits MUST be
//! treated as a decoding error. A padding not corresponding to the most
//! significant bits of the code for the EOS symbol MUST be treated as a decoding
//! error. A Huffman-encoded string literal containing the EOS symbol MUST be
//! treated as a decoding error. »
//!
//! Les trois ferment la même porte : **il ne doit y avoir qu'UNE façon d'écrire
//! une chaîne donnée**. Un remplissage libre, ou un `EOS` toléré, donneraient
//! deux encodages du même texte — et deux implémentations qui ne s'accordent pas
//! sur lequel est valide, ce qui est le début d'une contrebande.

use super::table_huffman::{CODE_EOS, CODE_MIN_BITS, EOS, code_d_octet, symbole_de};
use crate::error::{Cause, Error, ErrorCode};

/// Décode une chaîne comprimée, et rend ce qu'elle occupe une fois décodée.
///
/// # Errors
///
/// [`Cause::BadHuffman`] pour un code inconnu, un `EOS`, un remplissage trop
/// long ou mal formé ; [`Cause::BufferTooSmall`] si `out` ne suffit pas.
pub fn decode_huffman(comprime: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let faute = || Error::connection(ErrorCode::CompressionError, Cause::BadHuffman);
    let court = || Error::connection(ErrorCode::CompressionError, Cause::BufferTooSmall);
    let mut ecrits = 0_usize;
    let mut code = 0_u32;
    let mut bits = 0_u32;
    for octet in comprime {
        for rang in (0..8_u32).rev() {
            let bit = u32::from(*octet >> rang) & 1;
            code = (code << 1) | bit;
            bits = bits.saturating_add(1);
            if bits < CODE_MIN_BITS {
                continue;
            }
            // **AUCUNE GARDE DE LONGUEUR ICI, ET C'EST DÉMONTRÉ.** La table est
            // COMPLÈTE à trente bits : aucun nœud interne n'y subsiste, donc
            // tout chemin de trente bits aboutit à un symbole — le test
            // `aucun_chemin_de_trente_bits_ne_reste_sans_symbole` le prouve.
            // Écrire un `if bits >= 30 { refuser }` serait une garde qu'aucune
            // entrée ne peut emprunter, c'est-à-dire une affirmation non
            // vérifiée.
            //
            // Et si la table changeait : l'accumulation continuerait sans
            // trouver, la boucle finirait avec le tampon, et le contrôle de
            // remplissage plus bas refuserait — parce qu'il resterait plus de
            // sept bits en attente. Le filet est là, il est simplement ailleurs.
            let Some(symbole) = symbole_de(code, bits) else {
                continue;
            };
            // §5.2 : `EOS` dans une chaîne est une faute de décodage. Il ne
            // termine rien ici — la longueur de la chaîne le fait.
            if symbole == EOS {
                return Err(faute());
            }
            let place = out.get_mut(ecrits).ok_or_else(court)?;
            // Les symboles vont de 0 à 255 hors `EOS`, écarté juste au-dessus.
            // `to_be_bytes` prend l'octet de poids faible sans conversion à
            // refuser : il n'y a donc pas de branche d'échec à couvrir.
            *place = symbole.to_be_bytes()[1];
            ecrits = ecrits.saturating_add(1);
            code = 0;
            bits = 0;
        }
    }
    // **LE REMPLISSAGE : AU PLUS SEPT BITS, ET TOUS À UN.** Sept bits, c'est ce
    // qu'il faut pour compléter un octet ; huit voudraient dire qu'un symbole
    // entier a été omis. Et « tous à un », parce que ce sont les bits de tête du
    // code d'`EOS` — c'est ce que la RFC impose pour qu'il n'y ait qu'une
    // écriture possible.
    if bits >= 8 {
        return Err(faute());
    }
    let attendu = (1_u32 << bits).saturating_sub(1);
    if bits != 0 && code != attendu {
        return Err(faute());
    }
    Ok(ecrits)
}

/// Ce qu'une chaîne occuperait, comprimée, en octets.
#[must_use]
pub fn encoded_huffman_len(clair: &[u8]) -> usize {
    let bits: usize = clair
        .iter()
        // Tout octet a un code : la table couvre les deux cent cinquante-six.
        .map(|octet| code_d_octet(*octet).1 as usize)
        .sum();
    // Le remplissage complète l'octet en cours.
    bits.saturating_add(7) / 8
}

/// Comprime une chaîne.
///
/// # Errors
///
/// [`Cause::BufferTooSmall`] si `out` ne suffit pas.
pub fn encode_huffman(clair: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let court = || Error::connection(ErrorCode::InternalError, Cause::BufferTooSmall);
    let mut ecrits = 0_usize;
    let mut reserve = 0_u64;
    let mut bits = 0_u32;
    for octet in clair {
        let (code, longueur) = code_d_octet(*octet);
        // Trente bits au plus s'ajoutent à moins de huit déjà en réserve : le
        // total tient largement dans un `u64`.
        reserve = (reserve << longueur) | u64::from(code);
        bits = bits.saturating_add(longueur);
        while bits >= 8 {
            bits = bits.saturating_sub(8);
            let place = out.get_mut(ecrits).ok_or_else(court)?;
            // L'octet de poids faible, pris tel quel.
            *place = (reserve >> bits).to_be_bytes()[7];
            ecrits = ecrits.saturating_add(1);
        }
    }
    if bits > 0 {
        // LE REMPLISSAGE EST FAIT DES BITS DE TÊTE DU CODE D'`EOS`, et c'est
        // ce que §5.2 impose — non pas « des uns », mais CEUX-LÀ. Que le code
        // d'`EOS` ne soit fait que de uns rend les deux formulations
        // équivalentes ; seule la seconde dit pourquoi.
        let manque = 8_u32.saturating_sub(bits);
        let (code_eos, longueur_eos) = CODE_EOS;
        let tete = u64::from(code_eos >> longueur_eos.saturating_sub(manque));
        let complet = (reserve << manque) | tete;
        let place = out.get_mut(ecrits).ok_or_else(court)?;
        *place = complet.to_be_bytes()[7];
        ecrits = ecrits.saturating_add(1);
    }
    Ok(ecrits)
}

#[cfg(test)]
mod tests;
