// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Une chaîne littérale de RFC 7541 §5.2.

use super::huffman::{decode_huffman, encode_huffman, encoded_huffman_len};
use super::integer::{decode_integer, encode_integer};
use crate::error::{Cause, Error, ErrorCode};

/// Décode une chaîne littérale dans `out`.
///
/// Rend ce qui a été écrit dans `out` et le nombre d'octets consommés à
/// l'entrée.
///
/// # LA LONGUEUR VIENT DU RÉSEAU, ET ELLE EST VÉRIFIÉE AVANT D'ÊTRE CRUE
///
/// Une chaîne annonce sa longueur puis ses octets. Un décodeur qui découpe sans
/// vérifier que ces octets sont là lirait la suite du bloc comme du contenu — et
/// si la longueur dépasse le bloc entier, il lirait la mémoire d'à côté. La
/// vérification tient en une ligne, et c'est la ligne qui compte.
///
/// # Errors
///
/// [`Cause::BadString`] si la longueur déborde de ce qui reste ;
/// [`Cause::BufferTooSmall`] si `out` ne suffit pas ; les fautes de Huffman.
pub fn decode_string<'o>(entree: &[u8], out: &'o mut [u8]) -> Result<(&'o [u8], usize), Error> {
    let faute = || Error::connection(ErrorCode::CompressionError, Cause::BadString);
    let court = || Error::connection(ErrorCode::CompressionError, Cause::BufferTooSmall);
    // L'ENTIER D'ABORD : s'il se lit, c'est qu'il y avait un premier octet, et
    // le fanion de compression s'y trouve. Le demander avant obligerait à
    // refuser deux fois le tampon vide.
    let (longueur, lus) = decode_integer(entree, 7)?;
    let comprimee = entree.first().is_some_and(|premier| premier & 0x80 != 0);
    // `longueur` est un `u32` ; sur les cibles de ce projet il tient dans un
    // `usize`. La borne réelle est celle du tampon, deux lignes plus bas.
    let taille = longueur as usize;
    // `saturating_add` : `lus` ne dépasse pas six, et la somme ne peut donc
    // déborder qu'avec une longueur qu'aucun tampon ne portera. La borne réelle
    // est celle du tampon, ligne suivante.
    let fin = lus.saturating_add(taille);
    let brut = entree.get(lus..fin).ok_or_else(faute)?;
    let ecrits = match comprimee {
        true => decode_huffman(brut, out)?,
        false => {
            let place = out.get_mut(..brut.len()).ok_or_else(court)?;
            place.copy_from_slice(brut);
            brut.len()
        }
    };
    Ok((out.get(..ecrits).unwrap_or_default(), fin))
}

/// Encode une chaîne littérale.
///
/// # ON COMPRIME QUAND CELA RACCOURCIT, ET PAS AUTREMENT
///
/// §5.2 laisse le choix. Comprimer systématiquement allongerait les chaînes que
/// Huffman ne sert pas — un jeton en base64, par exemple, dont chaque octet
/// coûte plus de huit bits.
///
/// # Errors
///
/// [`Cause::BufferTooSmall`] si `out` ne suffit pas.
pub fn encode_string(clair: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let court = || Error::connection(ErrorCode::InternalError, Cause::BufferTooSmall);
    let comprime = encoded_huffman_len(clair);
    let serre = comprime < clair.len();
    let (drapeau, taille) = match serre {
        true => (0x80_u8, comprime),
        false => (0x00, clair.len()),
    };
    // **LA PLACE EST LA BORNE, ET ELLE SE VÉRIFIE EN ÉCRIVANT.** Une chaîne de
    // plus de quatre gibioctets ne tient dans aucun tampon de ce serveur : la
    // place manquera quelques lignes plus bas, et c'est la faute du tampon qui
    // remontera. `unwrap_or` porte donc cette impossibilité dans la bibliothèque
    // plutôt que dans une branche qu'aucun appel n'emprunte — et vérifier la
    // place D'ABORD rendrait inatteignables les quatre gardes qui suivent, ce
    // qui n'échangerait qu'une affirmation non vérifiée contre quatre.
    let longueur = u32::try_from(taille).unwrap_or(u32::MAX);
    let ecrits = encode_integer(longueur, 7, drapeau, out)?;
    // `encode_integer` vient d'écrire `ecrits` octets DANS `out` : la tranche
    // qui suit existe toujours, fût-elle vide. `unwrap_or_default` porte cela
    // dans la bibliothèque — et si elle est vide, c'est l'écriture du corps qui
    // dira que la place manque.
    let suite = out.get_mut(ecrits..).unwrap_or_default();
    let corps = match serre {
        true => encode_huffman(clair, suite)?,
        false => {
            let place = suite.get_mut(..clair.len()).ok_or_else(court)?;
            place.copy_from_slice(clair);
            clair.len()
        }
    };
    Ok(ecrits.saturating_add(corps))
}

#[cfg(test)]
mod tests;
