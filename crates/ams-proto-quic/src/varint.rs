// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! L'entier de longueur variable de RFC 9000 §16.
//!
//! # DEUX BITS DISENT LA LONGUEUR, ET IL N'Y A PAS DE SECONDE LECTURE
//!
//! Les deux bits de poids fort du premier octet donnent le nombre d'octets :
//! un, deux, quatre ou huit. Le reste est la valeur, en gros-boutien. C'est
//! tout, et cette simplicité est le point : **la longueur d'un entier ne dépend
//! d'aucun contexte**, ne se contredit jamais, et se lit sans avoir lu ce qui
//! précède.
//!
//! Comparez au cadrage d'HTTP/1.1, où `Content-Length` et `Transfer-Encoding`
//! peuvent dire deux choses différentes de la même longueur : c'est de cette
//! contradiction que vit la contrebande de requête. Ici, il n'y a qu'une source.
//!
//! # L'ÉCRITURE N'EST PAS UNIQUE, ET LA LECTURE NE S'EN OFFUSQUE PAS
//!
//! §16 le dit en toutes lettres : « the encoding is not canonical ». La valeur
//! 37 s'écrit sur un, deux, quatre ou huit octets, et **les quatre écritures
//! sont valides**. Un décodeur qui refuserait les longues refuserait des paquets
//! parfaitement conformes — c'est le contraire de HPACK, où une écriture non
//! canonique est une attaque.
//!
//! La raison de cette différence tient en une ligne : ici, la longueur est
//! ANNONCÉE et bornée à huit octets. Là-bas, elle était implicite et non bornée.
//! **Ce n'est pas la canonicité qui protège, c'est la borne.**

use crate::error::{Error, Reason};

/// La plus grande valeur qu'un entier de §16 puisse porter : 2^62 - 1.
///
/// Les deux bits de poids fort du premier octet servent à la longueur : sur
/// huit octets, il en reste soixante-deux pour la valeur.
pub const VARINT_MAX: u64 = (1 << 62) - 1;

/// Ce qu'un entier occupe, selon les deux bits de tête.
const LONGUEURS: [usize; 4] = [1, 2, 4, 8];

/// Lit un entier de longueur variable.
///
/// Rend la valeur et le nombre d'octets consommés.
///
/// # Errors
///
/// [`Reason::Truncated`] si le tampon ne porte pas les octets annoncés.
pub fn decode(octets: &[u8]) -> Result<(u64, usize), Error> {
    let tronque = || Error::new(Reason::Truncated);
    let premier = *octets.first().ok_or_else(tronque)?;
    // Les deux bits de tête indexent la table : le `>> 6` d'un `u8` vaut au plus
    // trois, et `LONGUEURS` en a quatre. `unwrap_or` porte cette impossibilité
    // dans la bibliothèque plutôt que dans une branche qu'aucun octet n'emprunte.
    let longueur = *LONGUEURS.get(usize::from(premier >> 6)).unwrap_or(&1);
    let corps = octets.get(..longueur).ok_or_else(tronque)?;
    // **ON REPART DE ZÉRO ET ON EMPILE.** Le premier octet est amputé de ses
    // deux bits de tête ; les suivants entrent entiers. Une multiplication par
    // deux cent cinquante-six ne peut pas déborder : au plus huit octets, dont
    // le premier n'en porte que six bits — soit soixante-deux en tout.
    let mut valeur = u64::from(premier & 0x3f);
    for octet in corps.iter().skip(1) {
        valeur = valeur.saturating_mul(256).saturating_add(u64::from(*octet));
    }
    Ok((valeur, longueur))
}

/// Ce qu'une valeur occupera, écrite au plus court.
///
/// # Errors
///
/// [`Reason::VarintTooLarge`] au-delà de 2^62 - 1.
pub fn encoded_len(valeur: u64) -> Result<usize, Error> {
    match valeur {
        0..=63 => Ok(1),
        64..=16_383 => Ok(2),
        16_384..=1_073_741_823 => Ok(4),
        v if v <= VARINT_MAX => Ok(8),
        _ => Err(Error::new(Reason::VarintTooLarge)),
    }
}

/// Écrit un entier au plus court, et rend ce qu'il a occupé.
///
/// # ON ÉCRIT AU PLUS COURT, MÊME SI RIEN NE L'EXIGE
///
/// §16 laisse le choix, et un pair qui reçoit une écriture longue l'accepte.
/// Écrire court n'est donc pas une question de conformité : c'est ce qui fait
/// tenir un paquet dans un datagramme, et un datagramme dans un chemin dont on
/// ne connaît pas la MTU.
///
/// # Errors
///
/// [`Reason::VarintTooLarge`] au-delà de 2^62 - 1 ; [`Reason::BufferTooSmall`]
/// si `out` ne suffit pas.
pub fn encode(valeur: u64, out: &mut [u8]) -> Result<usize, Error> {
    let longueur = encoded_len(valeur)?;
    let place = out
        .get_mut(..longueur)
        .ok_or_else(|| Error::new(Reason::BufferTooSmall))?;
    // Le code de longueur : zéro pour un octet, un pour deux, deux pour quatre,
    // trois pour huit — le logarithme en base deux du nombre d'octets.
    // `encoded_len` ne rend que ces quatre longueurs : il ne reste que huit.
    let code = match longueur {
        1 => 0_u64,
        2 => 1,
        4 => 2,
        _ => 3,
    };
    // **LES DEUX BITS ENTRENT DANS LA VALEUR AVANT L'ÉCRITURE**, et non dans le
    // premier octet après coup. Les poser ensuite obligerait à retrouver cet
    // octet dans la tranche — et à écrire ce qu'on fait s'il n'y en a pas,
    // c'est-à-dire une branche qu'aucune longueur ne peut emprunter.
    //
    // Le décalage vise les deux bits de tête du premier octet écrit : six pour
    // un octet, quatorze pour deux, trente pour quatre, soixante-deux pour huit.
    let decalage = u32::try_from(longueur)
        .unwrap_or(1)
        .saturating_mul(8)
        .saturating_sub(2);
    let marquee = valeur | code.checked_shl(decalage).unwrap_or(0);
    // Les huit octets, gros-boutien ; on n'en garde que la queue.
    let huit = marquee.to_be_bytes();
    let depuis = huit.len().saturating_sub(longueur);
    for (place, lu) in place.iter_mut().zip(huit.get(depuis..).unwrap_or_default()) {
        *place = *lu;
    }
    Ok(longueur)
}

#[cfg(test)]
mod tests;
