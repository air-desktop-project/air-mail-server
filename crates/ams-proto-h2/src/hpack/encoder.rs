// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! L'écriture d'un bloc d'en-têtes (RFC 7541 §6).
//!
//! # CET ENCODEUR N'INDEXE JAMAIS, ET C'EST UNE DÉCISION
//!
//! HPACK permet d'insérer dans une table dynamique pour que le champ suivant
//! coûte un octet. Cet encodeur ne le fait PAS, et voici pourquoi.
//!
//! §7.1 de RFC 7541 décrit l'attaque : quand un attaquant peut faire émettre par
//! le serveur des en-têtes de son choix À CÔTÉ d'un secret, la TAILLE du bloc
//! comprimé lui dit si sa devinette coïncide avec le secret. C'est CRIME et
//! BREACH, transposées à HPACK. La RFC recommande de ne pas indexer les champs
//! sensibles — ce qui suppose de savoir lesquels le sont.
//!
//! **On renverse la question** : rien n'est indexé, donc rien ne fuit, et il n'y
//! a pas de liste de champs sensibles à tenir à jour. Le coût est quelques
//! dizaines d'octets par réponse ; C7 dit que la sécurité prime, et il n'y a même
//! pas d'arbitrage difficile ici.
//!
//! La table STATIQUE, elle, sert : elle est publique, identique pour tous, et ne
//! porte aucun secret. `:status 200` s'écrit donc en un octet.
//!
//! # LE CORROLAIRE : NOTRE TABLE DYNAMIQUE D'ÉMISSION RESTE VIDE
//!
//! On n'a donc rien à en tenir, et rien à évincer. C'est aussi ce qui rend cet
//! encodeur sans état — et un encodeur sans état ne peut pas se désynchroniser.

use super::integer::encode_integer;
use super::string::encode_string;
use super::table_statique::STATIQUE;
use crate::error::{Cause, Error, ErrorCode};

/// Écrit un champ, sans jamais l'indexer.
///
/// Trois écritures, de la plus courte à la plus longue :
///
/// 1. le nom ET la valeur sont dans la table statique — un index suffit ;
/// 2. le nom seul y est — l'index du nom, puis la valeur littérale ;
/// 3. ni l'un ni l'autre — les deux littéraux.
///
/// # Errors
///
/// [`Cause::BufferTooSmall`] si `out` ne suffit pas.
pub fn encode_field(nom: &[u8], valeur: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if let Some(index) = index_exact(nom, valeur) {
        // §6.1 : `1xxxxxxx`, sur un préfixe de sept bits.
        return encode_integer(index, 7, 0x80, out);
    }
    // §6.2.2 : `0000xxxx`, littéral SANS indexation, sur un préfixe de quatre
    // bits. Ce motif-ci et non `0001xxxx` : « jamais indexé » est une consigne
    // qu'on donnerait aux intermédiaires, et nous n'avons pas à la donner pour
    // des champs qui n'ont rien de sensible. Voir l'en-tête du module.
    let index = index_du_nom(nom).unwrap_or(0);
    let mut ecrits = encode_integer(index, 4, 0x00, out)?;
    if index == 0 {
        let suite = out.get_mut(ecrits..).unwrap_or_default();
        ecrits = ecrits.saturating_add(encode_string(nom, suite)?);
    }
    let suite = out.get_mut(ecrits..).unwrap_or_default();
    ecrits = ecrits.saturating_add(encode_string(valeur, suite)?);
    Ok(ecrits)
}

/// Écrit un `:status`, qui est le premier champ de toute réponse.
///
/// # Errors
///
/// [`Cause::BufferTooSmall`] si `out` ne suffit pas.
pub fn encode_status(code: u16, out: &mut [u8]) -> Result<usize, Error> {
    let mut chiffres = [0_u8; 3];
    let ecrit = ams_proto_http::StatusCode::new(code)
        .and_then(|status| status.write(&mut chiffres).map(<[u8]>::len))
        .map_err(|_| Error::connection(ErrorCode::InternalError, Cause::BufferTooSmall))?;
    encode_field(b":status", chiffres.get(..ecrit).unwrap_or_default(), out)
}

/// L'index d'une entrée statique qui porte CE nom et CETTE valeur.
fn index_exact(nom: &[u8], valeur: &[u8]) -> Option<u32> {
    rang_vers_index(
        STATIQUE
            .iter()
            .position(|(connu, valeur_connue)| *connu == nom && *valeur_connue == valeur)?,
    )
}

/// L'index de la PREMIÈRE entrée statique qui porte ce nom.
///
/// **LA PREMIÈRE, PAS N'IMPORTE LAQUELLE** : `:status` en a huit, et n'importe
/// laquelle conviendrait pour désigner le nom — mais un choix stable rend deux
/// encodages du même en-tête identiques, donc comparables.
fn index_du_nom(nom: &[u8]) -> Option<u32> {
    rang_vers_index(STATIQUE.iter().position(|(connu, _)| *connu == nom)?)
}

/// Le rang dans la table devient l'index HPACK, qui commence à un.
fn rang_vers_index(rang: usize) -> Option<u32> {
    u32::try_from(rang.saturating_add(1)).ok()
}

#[cfg(test)]
mod tests;
