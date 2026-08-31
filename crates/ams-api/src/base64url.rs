// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le base64url de §5 de RFC 4648, **sans remplissage et sans souplesse**.
//!
//! # POURQUOI PAS CELUI DE DKIM
//!
//! Ce n'est pas la même fonction. DKIM emploie l'alphabet de §4 — avec `+` et
//! `/` — et son remplissage ; un jeton emploie celui de §5 — avec `-` et `_` —
//! et n'en a pas. Les partager demanderait de passer l'alphabet en paramètre,
//! c'est-à-dire de rendre configurable la chose même qu'on veut fixer.
//!
//! # ET SURTOUT : UNE SEULE ÉCRITURE PAR JETON
//!
//! §3.5 de RFC 4648 le dit sans détour : « the pad bits [...] MUST be set to
//! zero by conforming encoders », et un décodeur qui les ignore accepte
//! plusieurs écritures d'une même valeur.
//!
//! Pour un jeton porteur, ce n'est pas une subtilité d'encodage : c'est une
//! liste de révocation qui ne reconnaît plus le jeton qu'elle a révoqué, ou un
//! compteur d'usage qu'on remet à zéro en changeant un caractère. **Les bits de
//! remplissage non nuls se refusent.**

use crate::error::{Error, Reason};

/// L'alphabet de §5 de RFC 4648.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Ce qu'il faut de caractères pour écrire `octets` octets.
///
/// Quatre caractères pour trois octets, et le reste sans remplissage : deux
/// caractères pour un octet, trois pour deux.
#[must_use]
pub const fn encoded_len(octets: usize) -> usize {
    let groupes = octets / 3;
    let queue = match octets % 3 {
        0 => 0,
        n => n.saturating_add(1),
    };
    groupes.saturating_mul(4).saturating_add(queue)
}

/// Ce qu'il faut d'octets pour lire `caracteres` caractères.
///
/// `None` pour une longueur qu'aucune valeur ne peut produire : un seul
/// caractère de queue ne porte que six bits, ce qui ne fait pas un octet.
#[must_use]
pub const fn decoded_len(caracteres: usize) -> Option<usize> {
    let groupes = caracteres / 4;
    let entiers = groupes.saturating_mul(3);
    match caracteres % 4 {
        0 => Some(entiers),
        2 => Some(entiers.saturating_add(1)),
        3 => Some(entiers.saturating_add(2)),
        // **UN SEUL CARACTÈRE DE QUEUE EST IMPOSSIBLE** : six bits ne font pas
        // un octet, et l'accepter reviendrait à inventer les deux qui manquent.
        _ => None,
    }
}

/// Écrit `donnees` en base64url dans `sortie`.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`] si `sortie` ne suffit pas. **Notre faute.**
pub fn encode<'o>(donnees: &[u8], sortie: &'o mut [u8]) -> Result<&'o [u8], Error> {
    let voulu = encoded_len(donnees.len());
    let place = sortie
        .get_mut(..voulu)
        .ok_or(Error::new(Reason::BufferTooSmall))?;
    let mut ecrits = 0_usize;
    for groupe in donnees.chunks(3) {
        // Les octets absents valent zéro : ce sont les bits de remplissage, et
        // §3.5 impose qu'ils le soient.
        let un = u32::from(groupe.first().copied().unwrap_or(0));
        let deux = u32::from(groupe.get(1).copied().unwrap_or(0));
        let trois = u32::from(groupe.get(2).copied().unwrap_or(0));
        let paquet = (un << 16) | (deux << 8) | trois;
        // Un octet donne deux caractères, deux en donnent trois, trois en
        // donnent quatre.
        let combien = groupe.len().saturating_add(1);
        for rang in 0..combien {
            let decalage =
                18_u32.saturating_sub(u32::try_from(rang).unwrap_or(0).saturating_mul(6));
            let sextet = usize::try_from((paquet >> decalage) & 0x3f).unwrap_or(0);
            // Le masque borne le sextet à 63, et `ecrits` à ce que `voulu` a
            // réservé : les deux index sont bornés par construction, et une
            // garde ici serait une branche qu'aucune donnée ne peut emprunter.
            place[ecrits] = ALPHABET[sextet];
            ecrits = ecrits.saturating_add(1);
        }
    }
    Ok(place)
}

/// Lit du base64url dans `sortie`.
///
/// # Errors
///
/// [`Reason::BadToken`] pour un caractère hors alphabet, une longueur
/// impossible, ou des bits de remplissage non nuls ;
/// [`Reason::BufferTooSmall`] si `sortie` ne suffit pas.
pub fn decode<'o>(texte: &[u8], sortie: &'o mut [u8]) -> Result<&'o [u8], Error> {
    let voulu = decoded_len(texte.len()).ok_or(Error::new(Reason::BadToken))?;
    let place = sortie
        .get_mut(..voulu)
        .ok_or(Error::new(Reason::BufferTooSmall))?;
    let mut ecrits = 0_usize;
    for groupe in texte.chunks(4) {
        let mut paquet = 0_u32;
        for caractere in groupe {
            let sextet = sextet(*caractere).ok_or(Error::new(Reason::BadToken))?;
            paquet = (paquet << 6) | u32::from(sextet);
        }
        // # CE QUE PORTE UN GROUPE, ET CE QU'IL NE PORTE PAS
        //
        // Un groupe de `n` caractères porte `6n` bits, dont `8(n-1)` font des
        // octets. Le reste — deux bits pour trois caractères, quatre pour deux —
        // est du remplissage, et il occupe les bits de POIDS FAIBLE.
        //
        // Un premier jet comptait les bits des caractères ABSENTS, ce qui donne
        // douze au lieu de quatre : le masque couvrait alors les données
        // elles-mêmes, et « Zg » — le vecteur de §10 de RFC 4648 pour « f » — se
        // refusait. Trouvé par les vecteurs de la RFC.
        let combien = u32::try_from(groupe.len()).unwrap_or(0);
        let octets = combien.saturating_sub(1);
        let bits_utiles = octets.saturating_mul(8);
        let bits_de_remplissage = combien.saturating_mul(6).saturating_sub(bits_utiles);
        // **LES BITS DE REMPLISSAGE DOIVENT ÊTRE NULS** (§3.5) : sans ce refus,
        // plusieurs écritures désignent le même jeton, et une révocation cesse
        // de le reconnaître.
        let masque = 1_u32
            .checked_shl(bits_de_remplissage)
            .unwrap_or(1)
            .saturating_sub(1);
        if paquet & masque != 0 {
            return Err(Error::new(Reason::BadToken));
        }
        let donnees = paquet >> bits_de_remplissage;
        for rang in 0..octets {
            let decalage = bits_utiles
                .saturating_sub(8)
                .saturating_sub(rang.saturating_mul(8));
            let octet = u8::try_from((donnees >> decalage) & 0xff).unwrap_or(0);
            // `voulu` a réservé exactement ce que ces groupes vont écrire.
            place[ecrits] = octet;
            ecrits = ecrits.saturating_add(1);
        }
    }
    Ok(place)
}

/// La valeur d'un caractère de l'alphabet.
const fn sextet(caractere: u8) -> Option<u8> {
    match caractere {
        b'A'..=b'Z' => Some(caractere.wrapping_sub(b'A')),
        b'a'..=b'z' => Some(caractere.wrapping_sub(b'a').wrapping_add(26)),
        b'0'..=b'9' => Some(caractere.wrapping_sub(b'0').wrapping_add(52)),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
