// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Une section de champs entière : de la requête au message, et retour.
//!
//! # SANS TABLE DYNAMIQUE, UNE SECTION NE DÉPEND DE RIEN
//!
//! Le préfixe d'une section reçue doit annoncer zéro insertion — nous en avons
//! annoncé zéro, et §3.2.3 interdit au pair d'en faire. Une section qui en
//! réclamerait n'attendrait donc pas : elle attendrait pour toujours, et c'est
//! une faute qu'on dit plutôt qu'un blocage qu'on subit.
//!
//! De même, un index qui désigne la table dynamique ne désigne rien. Le pair
//! n'aurait pas pu l'y mettre.
//!
//! # ET CELLES QU'ON ÉCRIT N'EN DÉPENDENT PAS DAVANTAGE
//!
//! Nos réponses n'emploient que la table STATIQUE et des littéraux. C'est le
//! même choix que l'encodeur HPACK de ce dépôt, pour la même raison : ce qui
//! n'entre dans aucune table ne peut pas fuir par la taille d'un bloc comprimé.

use ams_field_codec::{encode_integer, encode_string, encoded_huffman_len};
use ams_proto_http::{HeadBuilder, Limits, RequestHead, StatusCode, response_field_is_serviceable};

use crate::error::{Error, Reason};
use crate::qpack::prefix::read_prefix;
use crate::qpack::representation::{FieldLine, Table, read_field_line};
use crate::qpack::table_statique::{STATIQUE, entree_statique};

/// Lit une section de champs, et en fait une requête.
///
/// # DEUX FAMILLES DE FAUTES, ET ELLES NE SE PUNISSENT PAS PAREIL
///
/// Une faute de DÉCOMPRESSION condamne la connexion : sans table partagée, le
/// pair et nous ne lirions plus les mêmes champs. Une liste bien décomprimée qui
/// ne fait pas une requête ne condamne que son FLUX (§4.1.2 de RFC 9114) — la
/// connexion, elle, n'a rien perdu.
///
/// # Errors
///
/// [`Reason::BadInsertCount`] pour une section qui dépend d'insertions ;
/// [`Reason::BadIndex`] pour un index qui ne désigne rien ;
/// [`Reason::BadFieldLine`] ; [`Reason::MalformedRequest`].
pub fn read_section<'o>(
    octets: &[u8],
    out: &'o mut [u8],
    limits: &Limits,
) -> Result<RequestHead<'o>, Error> {
    let malformee = || Error::new(Reason::MalformedRequest);
    let sans_index = || Error::new(Reason::BadIndex);
    // La capacité qu'on a annoncée est nulle : le préfixe se lit avec zéro
    // insertion reçue, et tout compte non nul se refusera de lui-même.
    let prefixe = read_prefix(octets, 0, 0)?;
    let mut reste = octets.get(prefixe.read..).unwrap_or_default();
    let mut libre = out;
    let mut tete = HeadBuilder::new(limits);
    while !reste.is_empty() {
        let decode = read_field_line(reste, libre)?;
        libre = decode.rest;
        reste = reste.get(decode.read..).unwrap_or_default();
        let (nom, valeur) = match decode.line {
            // **UN INDEX DYNAMIQUE NE DÉSIGNE RIEN** : nous n'avons pas de
            // table, et le pair n'avait pas le droit d'y mettre quoi que ce soit.
            FieldLine::Indexed {
                table: Table::Dynamic,
                ..
            }
            | FieldLine::IndexedPostBase { .. }
            | FieldLine::LiteralWithName {
                table: Table::Dynamic,
                ..
            }
            | FieldLine::LiteralWithPostBaseName { .. } => return Err(sans_index()),
            FieldLine::Indexed { index, .. } => entree_statique(index).ok_or_else(sans_index)?,
            FieldLine::LiteralWithName { index, value, .. } => {
                let (nom, _) = entree_statique(index).ok_or_else(sans_index)?;
                (nom, value)
            }
            FieldLine::Literal { name, value, .. } => (name, value),
        };
        tete.field(nom, valeur).map_err(|_| malformee())?;
    }
    tete.finish().map_err(|_| malformee())
}

/// Écrit la section de champs d'une réponse.
///
/// # Errors
///
/// [`Reason::BadResponseField`] pour un champ qu'on refuse d'écrire ;
/// [`Reason::BufferTooSmall`].
pub fn write_section(
    status: StatusCode,
    champs: &[(&[u8], &[u8])],
    out: &mut [u8],
) -> Result<usize, Error> {
    let court = || Error::new(Reason::BufferTooSmall);
    for (nom, valeur) in champs {
        if !response_field_is_serviceable(nom, valeur) {
            return Err(Error::new(Reason::BadResponseField));
        }
    }
    // §4.5.1 : le préfixe d'une section qui ne dépend de rien fait deux octets
    // nuls. Les écrire à la main plutôt que par l'encodeur d'entiers évite deux
    // gardes que ces deux zéros ne peuvent pas emprunter.
    let Some((prefixe, corps)) = out.split_at_mut_checked(2) else {
        return Err(court());
    };
    prefixe.fill(0);
    let mut ecrits = 0_usize;
    let mut poser = |nom: &[u8], valeur: &[u8]| -> Result<(), Error> {
        let place = corps.get_mut(ecrits..).unwrap_or_default();
        ecrits = ecrits.saturating_add(ecrire_champ(nom, valeur, place)?);
        Ok(())
    };
    poser(b":status", status.as_bytes().as_slice())?;
    for (nom, valeur) in champs {
        poser(nom, valeur)?;
    }
    Ok(ecrits.saturating_add(2))
}

/// Écrit un champ, sans jamais l'indexer.
///
/// Trois écritures, de la plus courte à la plus longue : le nom ET la valeur
/// dans la table statique, le nom seul, ou rien du tout.
fn ecrire_champ(nom: &[u8], valeur: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let court = || Error::new(Reason::BufferTooSmall);
    if let Some(index) = chercher(nom, Some(valeur)) {
        // §4.5.2 : `1Txxxxxx`, avec `T` à un pour la table statique.
        return encode_integer(index, 6, 0b1100_0000, out).map_err(|_| court());
    }
    if let Some(index) = chercher(nom, None) {
        // §4.5.4 : `01NTxxxx`, `N` à zéro et `T` à un.
        let ecrits = encode_integer(index, 4, 0b0101_0000, out).map_err(|_| court())?;
        let place = out.get_mut(ecrits..).unwrap_or_default();
        let encore = encode_string(valeur, place).map_err(|_| court())?;
        return Ok(ecrits.saturating_add(encore));
    }
    // §4.5.6 : `001NHxxx`, le nom puis la valeur.
    let ecrits = ecrire_nom(nom, out)?;
    let place = out.get_mut(ecrits..).unwrap_or_default();
    let encore = encode_string(valeur, place).map_err(|_| court())?;
    Ok(ecrits.saturating_add(encore))
}

/// Écrit le nom d'un champ littéral, dont le fanion de Huffman partage le
/// premier octet avec les bits de type (§4.5.6).
fn ecrire_nom(nom: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let court = || Error::new(Reason::BufferTooSmall);
    let comprime = encoded_huffman_len(nom);
    let serre = comprime < nom.len();
    // `001` puis `N=0` puis `H`, et les trois bits de bas portent la longueur.
    let (drapeaux, taille) = match serre {
        true => (0b0010_1000_u8, comprime),
        false => (0b0010_0000, nom.len()),
    };
    // La place est la borne, et elle se vérifie en écrivant : un nom de plus de
    // quatre gibioctets ne tient dans aucun tampon de ce serveur.
    let longueur = u32::try_from(taille).unwrap_or(u32::MAX);
    let ecrits = encode_integer(longueur, 3, drapeaux, out).map_err(|_| court())?;
    let place = out.get_mut(ecrits..).unwrap_or_default();
    let corps = match serre {
        true => ams_field_codec::encode_huffman(nom, place).map_err(|_| court())?,
        false => {
            let ou = place.get_mut(..nom.len()).ok_or_else(court)?;
            ou.copy_from_slice(nom);
            nom.len()
        }
    };
    Ok(ecrits.saturating_add(corps))
}

/// L'index statique d'un nom, avec ou sans sa valeur.
///
/// **LA PREMIÈRE OCCURRENCE GAGNE**, et l'ordre de la table est celui que la RFC
/// a optimisé : les champs les plus fréquents y portent les plus petits index.
fn chercher(nom: &[u8], valeur: Option<&[u8]>) -> Option<u32> {
    for (rang, (n, v)) in STATIQUE.iter().enumerate() {
        let convient = *n == nom && valeur.is_none_or(|cherchee| *v == cherchee);
        if convient {
            return u32::try_from(rang).ok();
        }
    }
    None
}

/// Un statut, en trois chiffres.
trait Chiffres {
    /// Les trois chiffres, en ASCII.
    fn as_bytes(&self) -> [u8; 3];
}

impl Chiffres for StatusCode {
    fn as_bytes(&self) -> [u8; 3] {
        let valeur = self.value();
        // Un statut vaut de cent à cinq cent quatre-vingt-dix-neuf : trois
        // chiffres, et `StatusCode::new` l'a déjà borné.
        [
            b'0'.saturating_add(chiffre(valeur, 100)),
            b'0'.saturating_add(chiffre(valeur, 10)),
            b'0'.saturating_add(chiffre(valeur, 1)),
        ]
    }
}

/// Le chiffre d'un rang décimal.
fn chiffre(valeur: u16, rang: u16) -> u8 {
    let extrait = valeur.checked_div(rang).unwrap_or(0) % 10;
    // Le reste d'une division par dix tient dans un octet.
    extrait.to_be_bytes()[1]
}

#[cfg(test)]
mod tests;
