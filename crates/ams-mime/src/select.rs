// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Un CHOIX de champs d'en-tête, tel qu'IMAP le rend (RFC 9051 §6.4.5).
//!
//! `BODY[HEADER.FIELDS (FROM SUBJECT)]` est ce qu'un client demande pour peupler
//! une liste de messages : quelques champs, et non l'en-tête entier — qui porte
//! le routage, les signatures et tout ce dont l'affichage n'a que faire.
//!
//! # LES CHAMPS SORTENT TELS QU'ILS SONT ÉCRITS
//!
//! Pliage compris, ordre du message compris, doublons compris. Ce n'est pas de
//! la paresse : un client qui vérifie une signature DKIM sur ce qu'il a reçu
//! condense les octets du message, pas une version remise au propre. Réécrire
//! serait lui rendre autre chose que ce que le message porte.
//!
//! # LA LIGNE VIDE EST TOUJOURS LÀ
//!
//! §6.4.5 : le choix se termine par la ligne vide, comme un en-tête. Même quand
//! aucun champ ne correspond — et c'est le cas qu'on oublie : un client qui
//! recevrait zéro octet ne saurait pas distinguer « aucun champ » de « pas de
//! réponse ».

use crate::error::Error;
use crate::limits::Limits;
use crate::message::Message;
use crate::plume::Plume;

/// Écrit les champs que `names` désigne, ou tous les autres si `except`.
///
/// `names` porte les noms séparés par des blancs, tels que le client les a
/// écrits. La comparaison est insensible à la casse (RFC 5322 §1.2.2).
///
/// # Errors
///
/// [`Error::BufferTooSmall`] si `out` ne suffit pas, ou les erreurs de lecture
/// de l'en-tête.
pub fn write_header_fields(
    header: &[u8],
    names: &[u8],
    except: bool,
    out: &mut [u8],
    limits: &Limits,
) -> Result<usize, Error> {
    let message = Message::parse(header, limits)?;
    let mut plume = Plume::neuve(out);
    for champ in message.fields() {
        // `except` renverse le choix, et rien d'autre : c'est la même lecture
        // des noms, et donc les mêmes réponses aux mêmes questions.
        if nomme(names, champ.name()) == except {
            continue;
        }
        plume.pousser(champ.name())?;
        plume.pousser(b":")?;
        plume.pousser(champ.raw_value())?;
        plume.pousser(b"\r\n")?;
    }
    plume.pousser(b"\r\n")?;
    Ok(plume.ecrits())
}

/// Ce nom figure-t-il dans la liste ?
fn nomme(names: &[u8], nom: &[u8]) -> bool {
    names
        .split(|octet| matches!(*octet, b' ' | b'\t'))
        .any(|vu| !vu.is_empty() && vu.eq_ignore_ascii_case(nom))
}

#[cfg(test)]
#[path = "select/tests.rs"]
mod tests;
