// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'il faut de CBOR (RFC 8949) pour lire un objet d'attestation d'App
//! Attest : des tables, des tableaux, des chaînes d'octets et de texte, des
//! entiers — et rien d'autre.
//!
//! # STRICT, ET BORNÉ
//!
//! Longueurs DÉFINIES seulement : une longueur indéfinie laisserait un inconnu
//! faire lire jusqu'à une fin qu'il choisit. Les étiquettes, les nombres à
//! virgule et les valeurs simples se refusent : un objet d'attestation n'en a
//! pas. Sauter une valeur se fait sous une profondeur bornée.

use crate::Refusal;

/// Un entier non signé.
const ENTIER: u8 = 0;
/// Une chaîne d'octets.
const OCTETS: u8 = 2;
/// Une chaîne de texte.
const TEXTE: u8 = 3;
/// Un tableau.
const TABLEAU: u8 = 4;
/// Une table.
const TABLE: u8 = 5;

/// La profondeur au-delà de laquelle un objet se refuse.
const PROFONDEUR_MAX: usize = 8;

/// Un curseur sur du CBOR.
#[derive(Debug, Clone)]
pub(crate) struct Cbor<'a> {
    reste: &'a [u8],
}

impl<'a> Cbor<'a> {
    /// Un curseur sur ces octets.
    pub(crate) const fn new(octets: &'a [u8]) -> Self {
        Self { reste: octets }
    }

    /// Tout a-t-il été lu ?
    pub(crate) const fn fini(&self) -> bool {
        self.reste.is_empty()
    }

    /// L'en-tête d'une donnée : son type majeur, et son argument.
    fn entete(&mut self) -> Result<(u8, u64), Refusal> {
        let (&premier, apres) = self.reste.split_first().ok_or(Refusal::Malformed)?;
        let majeur = premier >> 5;
        let (argument, apres) = match premier & 0x1F {
            petit @ 0..=23 => (u64::from(petit), apres),
            longueur @ 24..=27 => {
                let combien = match longueur {
                    24 => 1,
                    25 => 2,
                    26 => 4,
                    _ => 8,
                };
                let chiffres = apres.get(..combien).ok_or(Refusal::Malformed)?;
                let valeur = chiffres
                    .iter()
                    .fold(0_u64, |acc, &octet| (acc << 8) | u64::from(octet));
                (valeur, apres.get(combien..).unwrap_or_default())
            }
            // 28 à 30 sont réservés ; 31 est la longueur indéfinie.
            _ => return Err(Refusal::Malformed),
        };
        self.reste = apres;
        Ok((majeur, argument))
    }

    /// Une donnée de ce type, qui porte des octets : rend son contenu.
    fn chaine(&mut self, attendu: u8) -> Result<&'a [u8], Refusal> {
        let (majeur, longueur) = self.entete()?;
        if majeur != attendu {
            return Err(Refusal::Malformed);
        }
        // Une longueur qui ne tient pas dans un `usize` ne tient pas non plus
        // dans ce qui reste : le découpage la refuse de lui-même.
        let longueur = usize::try_from(longueur).unwrap_or(usize::MAX);
        let contenu = self.reste.get(..longueur).ok_or(Refusal::Malformed)?;
        self.reste = self.reste.get(longueur..).unwrap_or_default();
        Ok(contenu)
    }

    /// Une chaîne d'octets.
    pub(crate) fn octets(&mut self) -> Result<&'a [u8], Refusal> {
        self.chaine(OCTETS)
    }

    /// Une chaîne de texte, telle qu'écrite.
    pub(crate) fn texte(&mut self) -> Result<&'a [u8], Refusal> {
        self.chaine(TEXTE)
    }

    /// Un tableau : rend combien d'éléments suivent.
    pub(crate) fn tableau(&mut self) -> Result<u64, Refusal> {
        self.conteneur(TABLEAU)
    }

    /// Une table : rend combien de paires suivent.
    pub(crate) fn table(&mut self) -> Result<u64, Refusal> {
        self.conteneur(TABLE)
    }

    fn conteneur(&mut self, attendu: u8) -> Result<u64, Refusal> {
        let (majeur, combien) = self.entete()?;
        if majeur != attendu {
            return Err(Refusal::Malformed);
        }
        Ok(combien)
    }

    /// Saute une donnée quelconque, sous une profondeur bornée.
    pub(crate) fn sauter(&mut self, profondeur: usize) -> Result<(), Refusal> {
        if profondeur > PROFONDEUR_MAX {
            return Err(Refusal::Malformed);
        }
        let mut essai = self.clone();
        let (majeur, argument) = essai.entete()?;
        match majeur {
            ENTIER => *self = essai,
            OCTETS => {
                let _ = self.octets()?;
            }
            TEXTE => {
                let _ = self.texte()?;
            }
            TABLEAU | TABLE => {
                *self = essai;
                let elements = match majeur {
                    TABLE => argument.saturating_mul(2),
                    _ => argument,
                };
                for _ in 0..elements {
                    self.sauter(profondeur.saturating_add(1))?;
                }
            }
            _ => return Err(Refusal::Malformed),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
