// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Un lecteur DER — ce qu'il faut pour un certificat et une attestation, et
//! rien de plus.
//!
//! # STRICT, PARCE QUE C'EST UN INCONNU QUI ÉCRIT
//!
//! Ces octets arrivent d'un téléphone, avant toute vérification. Le lecteur
//! refuse donc tout ce que DER interdit et qu'un lecteur laxiste accepterait :
//! longueur indéfinie, longueur non minimale, étiquette haute mal formée. Deux
//! lecteurs qui ne lisent pas la même chose dans les mêmes octets sont
//! exactement ce qu'un certificat forgé exploite.

use crate::Refusal;

/// La classe universelle.
pub(crate) const UNIVERSELLE: u8 = 0x00;
/// La classe de contexte.
pub(crate) const CONTEXTE: u8 = 0x80;

/// `BOOLEAN`.
pub(crate) const BOOLEEN: u32 = 1;
/// `INTEGER`.
pub(crate) const ENTIER: u32 = 2;
/// `BIT STRING`.
pub(crate) const BITS: u32 = 3;
/// `OCTET STRING`.
pub(crate) const OCTETS: u32 = 4;
/// `OBJECT IDENTIFIER`.
pub(crate) const OID: u32 = 6;
/// `ENUMERATED`.
pub(crate) const ENUMERE: u32 = 10;
/// `SEQUENCE`.
pub(crate) const SEQUENCE: u32 = 16;
/// `SET`.
pub(crate) const ENSEMBLE: u32 = 17;
/// `UTCTime`.
pub(crate) const TEMPS_UTC: u32 = 23;
/// `GeneralizedTime`.
pub(crate) const TEMPS_GENERALISE: u32 = 24;

/// Un élément lu : son étiquette, son contenu, et ses octets entiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tlv<'a> {
    /// La classe : les deux bits de poids fort du premier octet.
    pub(crate) classe: u8,
    /// Construit (il contient d'autres éléments) ou primitif.
    pub(crate) construit: bool,
    /// Le numéro d'étiquette.
    pub(crate) numero: u32,
    /// Le contenu, sans l'étiquette ni la longueur.
    pub(crate) contenu: &'a [u8],
    /// L'élément entier, étiquette et longueur comprises.
    pub(crate) brut: &'a [u8],
}

impl Tlv<'_> {
    /// Est-ce un élément universel de ce numéro ?
    pub(crate) const fn est(&self, numero: u32) -> bool {
        self.classe == UNIVERSELLE && self.numero == numero
    }
}

/// Lit les éléments d'un contenu, l'un après l'autre.
#[derive(Debug, Clone)]
pub(crate) struct Lecteur<'a> {
    reste: &'a [u8],
}

impl<'a> Lecteur<'a> {
    /// Un lecteur sur ces octets.
    pub(crate) const fn new(octets: &'a [u8]) -> Self {
        Self { reste: octets }
    }

    /// Tout a-t-il été lu ?
    pub(crate) const fn fini(&self) -> bool {
        self.reste.is_empty()
    }

    /// Le prochain élément.
    ///
    /// # Errors
    ///
    /// [`Refusal::Malformed`] sur tout ce que DER interdit.
    pub(crate) fn lire(&mut self) -> Result<Tlv<'a>, Refusal> {
        let (&premier, apres) = self.reste.split_first().ok_or(Refusal::Malformed)?;
        let classe = premier & 0xC0;
        let construit = premier & 0x20 != 0;
        let (numero, apres) = match premier & 0x1F {
            0x1F => etiquette_haute(apres)?,
            bas => (u32::from(bas), apres),
        };
        let (longueur, apres) = longueur(apres)?;
        if apres.len() < longueur {
            return Err(Refusal::Malformed);
        }
        let (contenu, suite) = apres.split_at(longueur);
        // L'élément entier : tout ce qui précède la suite. La longueur vient
        // d'être vérifiée, et ce découpage ne peut pas déborder.
        let consomme = self.reste.len().saturating_sub(suite.len());
        let brut = self.reste.get(..consomme).unwrap_or_default();
        self.reste = suite;
        Ok(Tlv {
            classe,
            construit,
            numero,
            contenu,
            brut,
        })
    }

    /// Le prochain élément, qui doit être universel et de ce numéro.
    ///
    /// # Errors
    ///
    /// [`Refusal::Malformed`] s'il est autre, ou illisible.
    pub(crate) fn attendre(&mut self, numero: u32) -> Result<Tlv<'a>, Refusal> {
        let lu = self.lire()?;
        if lu.est(numero) {
            Ok(lu)
        } else {
            Err(Refusal::Malformed)
        }
    }

    /// Le prochain élément s'il est de contexte et de ce numéro ; sinon rien,
    /// et le lecteur n'avance pas.
    ///
    /// # Errors
    ///
    /// [`Refusal::Malformed`] si le prochain élément est illisible.
    pub(crate) fn optionnel(&mut self, numero: u32) -> Result<Option<Tlv<'a>>, Refusal> {
        if self.fini() {
            return Ok(None);
        }
        let mut essai = self.clone();
        let lu = essai.lire()?;
        if lu.classe == CONTEXTE && lu.numero == numero {
            *self = essai;
            Ok(Some(lu))
        } else {
            Ok(None)
        }
    }
}

/// Une étiquette en forme haute (§8.1.2.4 de X.690) : base 128, au plus quatre
/// octets, sans zéro de tête, et d'une valeur qui n'aurait pas tenu en forme
/// basse.
fn etiquette_haute(octets: &[u8]) -> Result<(u32, &[u8]), Refusal> {
    let mut numero = 0_u32;
    for (rang, &octet) in octets.iter().enumerate().take(4) {
        if rang == 0 && octet == 0x80 {
            return Err(Refusal::Malformed);
        }
        numero = (numero << 7) | u32::from(octet & 0x7F);
        if octet & 0x80 == 0 {
            if numero < 0x1F {
                return Err(Refusal::Malformed);
            }
            let suite = octets.get(rang.saturating_add(1)..).unwrap_or_default();
            return Ok((numero, suite));
        }
    }
    Err(Refusal::Malformed)
}

/// Une longueur définie, sous sa forme la plus courte.
fn longueur(octets: &[u8]) -> Result<(usize, &[u8]), Refusal> {
    let (&premier, apres) = octets.split_first().ok_or(Refusal::Malformed)?;
    if premier < 0x80 {
        return Ok((usize::from(premier), apres));
    }
    // 0x80 est la longueur INDÉFINIE, que DER interdit ; plus de trois octets
    // de longueur dépasseraient de loin tout ce qu'on lit ici.
    let combien = usize::from(premier & 0x7F);
    if combien == 0 || combien > 3 {
        return Err(Refusal::Malformed);
    }
    let (chiffres, apres) = (apres.get(..combien), apres.get(combien..));
    let (Some(chiffres), Some(apres)) = (chiffres, apres) else {
        return Err(Refusal::Malformed);
    };
    if chiffres.first() == Some(&0) {
        return Err(Refusal::Malformed);
    }
    let valeur = chiffres
        .iter()
        .fold(0_usize, |acc, &octet| (acc << 8) | usize::from(octet));
    // La forme longue d'une longueur qui tenait en forme courte n'est pas DER.
    if valeur < 0x80 {
        return Err(Refusal::Malformed);
    }
    Ok((valeur, apres))
}

/// Un entier positif ou nul qui tient sur 32 bits.
///
/// # Errors
///
/// [`Refusal::Malformed`] s'il est négatif, trop grand, ou mal encodé.
pub(crate) fn petit_entier(contenu: &[u8]) -> Result<u32, Refusal> {
    // Un zéro de tête n'est permis que devant un octet dont le bit de poids
    // fort est levé ; un premier octet au bit levé est négatif.
    let chiffres = match contenu {
        [] => return Err(Refusal::Malformed),
        [0, suivant, ..] if suivant & 0x80 == 0 => return Err(Refusal::Malformed),
        [premier, ..] if premier & 0x80 != 0 => return Err(Refusal::Malformed),
        [0, reste @ ..] if !reste.is_empty() => reste,
        tout => tout,
    };
    if chiffres.len() > 4 {
        return Err(Refusal::Malformed);
    }
    Ok(chiffres
        .iter()
        .fold(0_u32, |acc, &octet| (acc << 8) | u32::from(octet)))
}

#[cfg(test)]
mod tests;
