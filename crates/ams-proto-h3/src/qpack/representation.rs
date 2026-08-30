// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les cinq représentations d'une ligne de champ (RFC 9204 §4.5.2 à §4.5.6).
//!
//! # DEUX FAÇONS DE DÉSIGNER LA TABLE DYNAMIQUE, ET C'EST CE QUI CHANGE TOUT
//!
//! HPACK n'en avait qu'une : un index, compté depuis la plus récente entrée.
//! QPACK en a deux — **relative au rang de la section**, et **après ce rang**.
//!
//! La raison est dans le désordre. Un encodeur qui insère une entrée PENDANT
//! qu'il écrit une section doit pouvoir la référencer ; mais l'index relatif se
//! compte depuis un rang FIXÉ AU DÉBUT de la section, et cette entrée n'existait
//! pas encore. D'où le second mode, qui compte vers l'avant.
//!
//! Sans lui, l'encodeur devrait choisir entre ne pas insérer pendant qu'il écrit,
//! ou refaire son préfixe après coup — c'est-à-dire écrire la section deux fois.
//!
//! # LE BIT `N` N'EST PAS UNE SUGGESTION
//!
//! §4.5.4 : un champ marqué « jamais indexé » ne doit être réémis que sous forme
//! littérale, avec le même bit. C'est ce qui protège un jeton d'authentification
//! contre CRIME et BREACH lorsqu'il traverse un intermédiaire. **Le perdre au
//! passage, c'est indexer le secret chez le suivant.**

use ams_field_codec::{decode_integer, decode_string};

use crate::error::{Error, Reason};

/// De quelle table un index parle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Table {
    /// La table statique, la même pour tout le monde.
    Static,
    /// La table dynamique, comptée depuis le rang de la section.
    Dynamic,
}

/// Une ligne de champ, telle qu'elle est écrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldLine<'o> {
    /// §4.5.2 — nom et valeur d'un coup, par un index.
    Indexed {
        /// L'index.
        index: u64,
        /// De quelle table.
        table: Table,
    },
    /// §4.5.3 — un index compté APRÈS le rang de la section.
    IndexedPostBase {
        /// Le rang, compté vers l'avant depuis la base.
        index: u64,
    },
    /// §4.5.4 — le nom vient d'une table, la valeur est écrite.
    LiteralWithName {
        /// L'index du nom.
        index: u64,
        /// De quelle table.
        table: Table,
        /// La valeur.
        value: &'o [u8],
        /// Ce champ ne doit jamais être indexé (§4.5.4).
        never: bool,
    },
    /// §4.5.5 — le nom vient de la table dynamique, APRÈS le rang.
    LiteralWithPostBaseName {
        /// Le rang du nom, compté vers l'avant.
        index: u64,
        /// La valeur.
        value: &'o [u8],
        /// Ce champ ne doit jamais être indexé.
        never: bool,
    },
    /// §4.5.6 — le nom et la valeur sont écrits tous les deux.
    Literal {
        /// Le nom.
        name: &'o [u8],
        /// La valeur.
        value: &'o [u8],
        /// Ce champ ne doit jamais être indexé.
        never: bool,
    },
}

/// Ce qu'une ligne décodée laisse derrière elle.
///
/// # LE RESTE DU TAMPON EN FAIT PARTIE, ET CE N'EST PAS UN DÉTAIL
///
/// Une ligne décodée EMPRUNTE le tampon qu'on a donné. Sans rendre ce qui n'a
/// pas servi, l'appelant ne pourrait décoder qu'UNE ligne par tampon : le second
/// appel voudrait le réemprunter, et l'emprunt du premier n'est pas fini.
///
/// Le décodeur HPACK de ce dépôt avait exactement ce défaut, et il ne s'est vu
/// qu'en écrivant l'appelant. On ne le réécrit pas ici.
#[derive(Debug)]
pub struct Decoded<'o> {
    /// La ligne.
    pub line: FieldLine<'o>,
    /// Ce qui a été consommé de l'entrée.
    pub read: usize,
    /// Ce qui reste du tampon, pour la ligne suivante.
    pub rest: &'o mut [u8],
}

/// Lit une ligne de champ.
///
/// # LE CLASSEMENT SE FAIT SUR LES BITS DE TÊTE, DU PLUS LONG AU PLUS COURT
///
/// `1xxxxxxx`, `01xxxxxx`, `001xxxxx`, `0001xxxx`, `0000xxxx` : les motifs se
/// recouvrent, et tester le plus court d'abord ferait lire une représentation
/// pour une autre. C'est la même règle qu'en HPACK, et la même conséquence — un
/// champ lu de travers, sans qu'aucune faute ne se voie.
///
/// # Errors
///
/// [`Reason::Truncated`] ; [`Reason::BadFieldLine`] pour une chaîne illisible ou
/// un tampon trop court.
pub fn read_field_line<'o>(octets: &[u8], out: &'o mut [u8]) -> Result<Decoded<'o>, Error> {
    let tronque = || Error::new(Reason::Truncated);
    let mauvaise = || Error::new(Reason::BadFieldLine);
    let premier = *octets.first().ok_or_else(tronque)?;

    // §4.5.2 : `1Txxxxxx` — nom et valeur d'un coup.
    if premier & 0b1000_0000 != 0 {
        let (index, read) = decode_integer(octets, 6).map_err(|_| tronque())?;
        return Ok(Decoded {
            line: FieldLine::Indexed {
                index: u64::from(index),
                table: table_de(premier & 0b0100_0000 != 0),
            },
            read,
            rest: out,
        });
    }

    // §4.5.4 : `01NTxxxx` — le nom vient d'une table, la valeur est écrite.
    if premier & 0b1100_0000 == 0b0100_0000 {
        let (index, lus) = decode_integer(octets, 4).map_err(|_| tronque())?;
        let suite = octets.get(lus..).unwrap_or_default();
        let (value, encore) = decode_string(suite, out).map_err(|_| mauvaise())?;
        let taille = value.len();
        let (value, rest) = couper(out, taille);
        return Ok(Decoded {
            line: FieldLine::LiteralWithName {
                index: u64::from(index),
                table: table_de(premier & 0b0001_0000 != 0),
                value,
                never: premier & 0b0010_0000 != 0,
            },
            read: lus.saturating_add(encore),
            rest,
        });
    }

    // §4.5.6 : `001NHxxx` — le nom ET la valeur sont écrits.
    //
    // **LE FANION DE HUFFMAN DU NOM VIT DANS CE PREMIER OCTET**, et non dans un
    // octet à part comme en HPACK : les trois bits de bas sont le préfixe de la
    // LONGUEUR DU NOM, et `H` la précède. Lire la longueur avec un préfixe de
    // sept bits, comme le ferait une chaîne ordinaire, la lirait de travers.
    if premier & 0b1110_0000 == 0b0010_0000 {
        let (name, lus) = decode_string_prefixe(octets, 3, out).map_err(|_| mauvaise())?;
        let nom_len = name.len();
        let suite = octets.get(lus..).unwrap_or_default();
        let apres_le_nom = out.get_mut(nom_len..).unwrap_or_default();
        let (value, encore) = decode_string(suite, apres_le_nom).map_err(|_| mauvaise())?;
        let valeur_len = value.len();
        let (name, apres) = couper(out, nom_len);
        let (value, rest) = couper(apres, valeur_len);
        return Ok(Decoded {
            line: FieldLine::Literal {
                name,
                value,
                never: premier & 0b0001_0000 != 0,
            },
            read: lus.saturating_add(encore),
            rest,
        });
    }

    // §4.5.3 : `0001xxxx` — un index compté APRÈS le rang.
    if premier & 0b1111_0000 == 0b0001_0000 {
        let (index, read) = decode_integer(octets, 4).map_err(|_| tronque())?;
        return Ok(Decoded {
            line: FieldLine::IndexedPostBase {
                index: u64::from(index),
            },
            read,
            rest: out,
        });
    }

    // **IL NE RESTE QUE `0000Nxxx`** (§4.5.5) : les quatre motifs précédents ont
    // épuisé tout ce qui commence autrement. Écrire un bras « sinon c'est une
    // faute » serait une branche qu'aucun octet ne peut emprunter.
    let (index, lus) = decode_integer(octets, 3).map_err(|_| tronque())?;
    let suite = octets.get(lus..).unwrap_or_default();
    let (value, encore) = decode_string(suite, out).map_err(|_| mauvaise())?;
    let taille = value.len();
    let (value, rest) = couper(out, taille);
    Ok(Decoded {
        line: FieldLine::LiteralWithPostBaseName {
            index: u64::from(index),
            value,
            never: premier & 0b0000_1000 != 0,
        },
        read: lus.saturating_add(encore),
        rest,
    })
}

/// La table qu'un bit `T` désigne.
const fn table_de(statique: bool) -> Table {
    match statique {
        true => Table::Static,
        false => Table::Dynamic,
    }
}

/// Coupe un tampon, sans jamais dépasser sa fin.
fn couper(tampon: &mut [u8], ou: usize) -> (&[u8], &mut [u8]) {
    let (pris, reste) = tampon.split_at_mut(ou.min(tampon.len()));
    (pris, reste)
}

/// Lit une chaîne dont le fanion de Huffman et la longueur partagent le premier
/// octet avec des bits de type (§4.5.6).
///
/// C'est la même chaîne que partout ailleurs — un fanion, une longueur, des
/// octets —, mais son préfixe fait `bits` bits au lieu de sept, et le fanion se
/// trouve juste au-dessus.
pub(super) fn decode_string_prefixe<'o>(
    entree: &[u8],
    bits: u32,
    out: &'o mut [u8],
) -> Result<(&'o [u8], usize), ams_field_codec::Error> {
    // On réécrit le premier octet comme une chaîne ordinaire le porterait : le
    // fanion en tête, la longueur sous un préfixe de sept bits. C'est la seule
    // différence entre les deux formes, et la refaire ici évite d'écrire un
    // second décodeur de chaînes qui pourrait diverger du premier.
    let (longueur, lus) = ams_field_codec::decode_integer(entree, bits)?;
    let comprimee = entree
        .first()
        .is_some_and(|premier| premier & (1 << bits) != 0);
    let taille = usize::try_from(longueur).unwrap_or(usize::MAX);
    let fin = lus.saturating_add(taille);
    let brut = entree
        .get(lus..fin)
        .ok_or_else(|| ams_field_codec::Error::new(ams_field_codec::Fault::BadString))?;
    let ecrits = match comprimee {
        true => ams_field_codec::decode_huffman(brut, out)?,
        false => {
            let place = brut.len();
            out.get_mut(..place)
                .ok_or_else(|| ams_field_codec::Error::new(ams_field_codec::Fault::BufferTooSmall))?
                .copy_from_slice(brut);
            place
        }
    };
    Ok((out.get(..ecrits).unwrap_or_default(), fin))
}

#[cfg(test)]
mod tests;
