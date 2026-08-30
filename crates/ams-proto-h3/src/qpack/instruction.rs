// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les instructions des deux flux QPACK (RFC 9204 §4.3 et §4.4).
//!
//! # DEUX FLUX QUI NE PORTENT QUE DE L'ÉTAT, ET JAMAIS DE MESSAGE
//!
//! Le flux d'ENCODEUR porte les insertions dans la table dynamique ; le flux de
//! DÉCODEUR porte les accusés de réception. Aucun des deux ne porte de requête
//! ni de réponse : ils ne servent qu'à ce que les deux tables restent la même.
//!
//! C'est ce qui rend QPACK utilisable sur un transport qui livre dans le
//! désordre. Les insertions voyagent sur un flux ORDONNÉ ; les sections de
//! champs, elles, arrivent comme elles veulent, et disent de combien
//! d'insertions elles dépendent.
//!
//! # CE SERVEUR ANNONCE UNE TABLE DE ZÉRO OCTET, ET C'EST UNE DÉCISION
//!
//! §3.2.3 : « An encoder MUST NOT insert entries into the dynamic table [...] if
//! the decoder's maximum table capacity is zero. » Annoncer zéro veut donc dire
//! qu'aucune insertion n'est licite, et cela ferme trois choses d'un coup :
//!
//! - **le blocage de compression**. Une section ne peut dépendre d'aucune
//!   insertion, donc ne peut jamais attendre. Le blocage de tête de ligne qu'on
//!   a retiré du transport ne revient pas par la compression.
//! - **CRIME et BREACH à la réception**. Une table dynamique partagée entre des
//!   champs d'origines différentes est ce qui rend l'attaque possible ; sans
//!   table, il n'y a rien à mesurer.
//! - **tout un étage de code**. Une table qu'on annonce inutilisable serait un
//!   chemin qu'aucune entrée ne peut emprunter — et la couverture le dirait.
//!
//! Le coût est quelques dizaines d'octets par requête, que le client aurait
//! économisés en indexant. C7 tranche, et il n'y a pas d'arbitrage difficile :
//! une API REST n'envoie pas mille requêtes identiques par connexion.
//!
//! **On lit quand même les instructions**, parce qu'un pair qui en envoie doit
//! s'entendre dire pourquoi on refuse — et non voir sa connexion se fermer sans
//! un mot.

use ams_field_codec::{decode_integer, decode_string, encode_integer};

use crate::error::{Error, Reason};
use crate::qpack::representation::Table;

/// Une instruction du flux d'encodeur (§4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncoderInstruction<'o> {
    /// §4.3.1 — le pair change la taille de SA table.
    ///
    /// **ZÉRO EST LICITE, ET TOUT LE RESTE NE L'EST PAS ICI** : §3.2.3 borne
    /// cette valeur par ce que le décodeur a annoncé, et nous annonçons zéro.
    SetCapacity {
        /// La capacité demandée.
        capacity: u64,
    },
    /// §4.3.2 — insère une entrée dont le nom vient d'une table.
    InsertWithNameRef {
        /// L'index du nom.
        index: u64,
        /// De quelle table.
        table: Table,
        /// La valeur.
        value: &'o [u8],
    },
    /// §4.3.3 — insère une entrée dont le nom est écrit.
    InsertWithLiteralName {
        /// Le nom.
        name: &'o [u8],
        /// La valeur.
        value: &'o [u8],
    },
    /// §4.3.4 — recopie une entrée existante en tête de table.
    Duplicate {
        /// L'index de l'entrée à recopier.
        index: u64,
    },
}

/// Ce qu'une instruction d'encodeur laisse derrière elle.
#[derive(Debug)]
pub struct DecodedInstruction<'o> {
    /// L'instruction.
    pub instruction: EncoderInstruction<'o>,
    /// Ce qui a été consommé de l'entrée.
    pub read: usize,
    /// Ce qui reste du tampon.
    pub rest: &'o mut [u8],
}

/// Lit une instruction du flux d'encodeur.
///
/// # Errors
///
/// [`Reason::Truncated`] ; [`Reason::BadEncoderInstruction`] pour une chaîne
/// illisible.
pub fn read_encoder_instruction<'o>(
    octets: &[u8],
    out: &'o mut [u8],
) -> Result<DecodedInstruction<'o>, Error> {
    let tronque = || Error::new(Reason::Truncated);
    let mauvaise = || Error::new(Reason::BadEncoderInstruction);
    let premier = *octets.first().ok_or_else(tronque)?;

    // §4.3.2 : `1Txxxxxx` — insertion avec un nom indexé.
    if premier & 0b1000_0000 != 0 {
        let (index, lus) = decode_integer(octets, 6).map_err(|_| tronque())?;
        let suite = octets.get(lus..).unwrap_or_default();
        let (value, encore) = decode_string(suite, out).map_err(|_| mauvaise())?;
        let taille = value.len();
        let (value, rest) = couper(out, taille);
        return Ok(DecodedInstruction {
            instruction: EncoderInstruction::InsertWithNameRef {
                index: u64::from(index),
                table: match premier & 0b0100_0000 != 0 {
                    true => Table::Static,
                    false => Table::Dynamic,
                },
                value,
            },
            read: lus.saturating_add(encore),
            rest,
        });
    }

    // §4.3.3 : `01Hxxxxx` — insertion avec un nom écrit. Comme en §4.5.6, le
    // fanion de Huffman du NOM partage le premier octet avec les bits de type.
    if premier & 0b1100_0000 == 0b0100_0000 {
        let (name, lus) =
            super::representation::decode_string_prefixe(octets, 5, out).map_err(|_| mauvaise())?;
        let nom_len = name.len();
        let suite = octets.get(lus..).unwrap_or_default();
        let apres_le_nom = out.get_mut(nom_len..).unwrap_or_default();
        let (value, encore) = decode_string(suite, apres_le_nom).map_err(|_| mauvaise())?;
        let valeur_len = value.len();
        let (name, apres) = couper(out, nom_len);
        let (value, rest) = couper(apres, valeur_len);
        return Ok(DecodedInstruction {
            instruction: EncoderInstruction::InsertWithLiteralName { name, value },
            read: lus.saturating_add(encore),
            rest,
        });
    }

    // §4.3.1 : `001xxxxx` — le pair change la taille de sa table.
    if premier & 0b1110_0000 == 0b0010_0000 {
        let (capacity, read) = decode_integer(octets, 5).map_err(|_| tronque())?;
        return Ok(DecodedInstruction {
            instruction: EncoderInstruction::SetCapacity {
                capacity: u64::from(capacity),
            },
            read,
            rest: out,
        });
    }

    // **IL NE RESTE QUE `000xxxxx`** (§4.3.4) : les trois motifs précédents ont
    // épuisé tout ce qui commence autrement.
    let (index, read) = decode_integer(octets, 5).map_err(|_| tronque())?;
    Ok(DecodedInstruction {
        instruction: EncoderInstruction::Duplicate {
            index: u64::from(index),
        },
        read,
        rest: out,
    })
}

/// Cette instruction est-elle recevable, sachant la table qu'on a annoncée ?
///
/// # POURQUOI CE N'EST PAS LA LECTURE QUI TRANCHE
///
/// Lire et juger sont deux choses. La lecture dit ce que le pair a écrit ; le
/// jugement dit si nous l'acceptons, et cela dépend de ce que NOUS avons
/// annoncé. Les mêmes octets sont licites pour un serveur qui tient une table et
/// fautifs pour celui-ci — et une lecture qui refuserait d'elle-même ne pourrait
/// plus servir aux deux.
///
/// # Errors
///
/// [`Reason::DynamicTableRefused`] pour toute insertion quand la capacité
/// annoncée est nulle, et pour une capacité au-delà de ce qu'on a annoncé.
pub fn check_encoder_instruction(
    instruction: EncoderInstruction<'_>,
    capacite_annoncee: u64,
) -> Result<(), Error> {
    let refus = || Err(Error::new(Reason::DynamicTableRefused));
    match instruction {
        // §3.2.3 : la capacité demandée ne peut pas dépasser ce qu'on a annoncé.
        EncoderInstruction::SetCapacity { capacity } if capacity <= capacite_annoncee => Ok(()),
        EncoderInstruction::SetCapacity { .. } => refus(),
        // §3.2.3 : sans table, aucune insertion n'est licite.
        _ if capacite_annoncee == 0 => refus(),
        _ => Ok(()),
    }
}

/// Une instruction du flux de décodeur (§4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoderInstruction {
    /// §4.4.1 — une section de champs a été traitée.
    ///
    /// **ELLE NE S'ENVOIE QUE POUR UNE SECTION QUI DÉPENDAIT D'INSERTIONS** :
    /// c'est ce qui dit à l'encodeur qu'il peut évincer ce qu'elle référençait.
    SectionAck {
        /// Le flux dont la section a été traitée.
        stream: u64,
    },
    /// §4.4.2 — un flux s'est arrêté sans qu'on ait lu ses sections.
    StreamCancellation {
        /// Le flux abandonné.
        stream: u64,
    },
    /// §4.4.3 — on a reçu tant d'insertions de plus.
    InsertCountIncrement {
        /// Combien.
        increment: u64,
    },
}

/// Lit une instruction du flux de décodeur.
///
/// # Errors
///
/// [`Reason::Truncated`].
pub fn read_decoder_instruction(octets: &[u8]) -> Result<(DecoderInstruction, usize), Error> {
    let tronque = || Error::new(Reason::Truncated);
    let premier = *octets.first().ok_or_else(tronque)?;
    // §4.4.1 : `1xxxxxxx`.
    if premier & 0b1000_0000 != 0 {
        let (stream, read) = decode_integer(octets, 7).map_err(|_| tronque())?;
        return Ok((
            DecoderInstruction::SectionAck {
                stream: u64::from(stream),
            },
            read,
        ));
    }
    // §4.4.2 : `01xxxxxx`.
    if premier & 0b1100_0000 == 0b0100_0000 {
        let (stream, read) = decode_integer(octets, 6).map_err(|_| tronque())?;
        return Ok((
            DecoderInstruction::StreamCancellation {
                stream: u64::from(stream),
            },
            read,
        ));
    }
    // **IL NE RESTE QUE `00xxxxxx`** (§4.4.3).
    let (increment, read) = decode_integer(octets, 6).map_err(|_| tronque())?;
    Ok((
        DecoderInstruction::InsertCountIncrement {
            increment: u64::from(increment),
        },
        read,
    ))
}

/// Écrit une instruction du flux de décodeur.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`] ; [`Reason::BadDecoderInstruction`] pour une
/// valeur qui ne tient pas dans ce que la représentation peut porter.
pub fn write_decoder_instruction(
    instruction: DecoderInstruction,
    out: &mut [u8],
) -> Result<usize, Error> {
    let court = || Error::new(Reason::BufferTooSmall);
    // Les entiers à préfixe de RFC 7541 s'arrêtent à 2^32-1 ; un numéro de flux
    // QUIC va jusqu'à 2^62-1. La borne est celle de la représentation, et non
    // celle du protocole : on le dit plutôt que de tronquer.
    let borner =
        |valeur: u64| u32::try_from(valeur).map_err(|_| Error::new(Reason::BadDecoderInstruction));
    let (valeur, bits, drapeau) = match instruction {
        DecoderInstruction::SectionAck { stream } => (borner(stream)?, 7, 0b1000_0000),
        DecoderInstruction::StreamCancellation { stream } => (borner(stream)?, 6, 0b0100_0000),
        DecoderInstruction::InsertCountIncrement { increment } => {
            (borner(increment)?, 6, 0b0000_0000)
        }
    };
    encode_integer(valeur, bits, drapeau, out).map_err(|_| court())
}

/// Coupe un tampon, sans jamais dépasser sa fin.
fn couper(tampon: &mut [u8], ou: usize) -> (&[u8], &mut [u8]) {
    let (pris, reste) = tampon.split_at_mut(ou.min(tampon.len()));
    (pris, reste)
}

#[cfg(test)]
mod tests;
