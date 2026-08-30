// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! L'entier à préfixe de RFC 7541 §5.1.
//!
//! # UN ENTIER QUI S'ÉCRIT SUR AUTANT D'OCTETS QU'ON VEUT
//!
//! La représentation est simple : `N` bits dans le premier octet ; s'ils sont
//! tous à un, la suite s'écrit sur des octets de continuation, sept bits à la
//! fois. Elle est aussi **non bornée par construction** — `0xFF 0x80 0x80 0x80
//! 0x80 …` continue tant qu'on le laisse faire.
//!
//! Deux fautes s'y logent, et il faut refuser les deux :
//!
//! - **le débordement** : un entier qui ne tient pas dans ce qu'on retient. On
//!   s'arrête à `u32`, qui couvre tout ce que HPACK désigne — un index de table,
//!   une longueur de chaîne, une taille de table.
//! - **l'écriture non canonique** : `0x80` ajoute sept bits nuls, donc rien. Une
//!   suite de continuations vides fait un entier arbitrairement long qui vaut
//!   zéro, et c'est la même attaque sous un autre nom.
//!
//! **UNE SEULE BORNE LES FERME TOUTES LES DEUX**, et c'est ce qui a permis d'en
//! retirer une : le multiplicateur qui accompagne les octets de continuation
//! déborde au sixième. Compter les octets EN PLUS aurait été une garde qu'aucune
//! entrée ne peut emprunter — le multiplicateur y arrive toujours le premier.

use crate::error::{Error, Fault};

/// Lit un entier à préfixe de `bits` bits.
///
/// Rend la valeur et le nombre d'octets consommés.
///
/// # Errors
///
/// [`Fault::BadInteger`] si l'entier déborde, s'il n'est pas terminé, ou s'il
/// est écrit sur plus d'octets qu'un `u32` n'en exige.
pub fn decode_integer(octets: &[u8], bits: u32) -> Result<(u32, usize), Error> {
    let faute = || Error::new(Fault::BadInteger);
    // `bits` vient du code appelant, jamais du réseau : entre 1 et 8.
    let masque = u32::from(u8::MAX)
        .checked_shr(8_u32.saturating_sub(bits))
        .unwrap_or(0);
    let premier = u32::from(*octets.first().ok_or_else(faute)?) & masque;
    if premier < masque {
        return Ok((premier, 1));
    }
    let mut valeur = premier;
    // **UN MULTIPLICATEUR, ET NON UN DÉCALAGE.** `checked_shl` ne rend `None`
    // que si le DÉCALAGE dépasse la largeur du type : `127u32.checked_shl(28)`
    // rend `Some`, et jette silencieusement les bits qui débordent. On
    // multiplierait alors un entier faux par cent vingt-huit sans que rien ne le
    // dise. Le multiplicateur, lui, déborde AVANT — et c'est ce débordement-là
    // qui refuse l'entier.
    //
    // Ce défaut-ci a été écrit puis trouvé par son propre test, en une heure.
    // Il aurait fait lire `0xff 0xff 0xff 0xff 0xff 0x7f` comme la valeur 255.
    let mut multiplicateur = 1_u32;
    for (rang, octet) in octets.iter().enumerate().skip(1) {
        let sept = u32::from(*octet & 0x7f);
        valeur = sept
            .checked_mul(multiplicateur)
            .and_then(|morceau| valeur.checked_add(morceau))
            .ok_or_else(faute)?;
        if *octet & 0x80 == 0 {
            return Ok((valeur, rang.saturating_add(1)));
        }
        // Le tour suivant vaudra cent vingt-huit fois plus. S'il ne tient plus,
        // c'est que l'entier ne tiendra pas non plus.
        multiplicateur = multiplicateur.checked_mul(128).ok_or_else(faute)?;
    }
    // On est sorti sans voir d'octet final : il en manque.
    Err(faute())
}

/// Écrit un entier à préfixe de `bits` bits, en préservant les bits de tête de
/// `drapeaux`.
///
/// # Errors
///
/// [`Fault::BufferTooSmall`] si `out` ne suffit pas.
pub fn encode_integer(
    valeur: u32,
    bits: u32,
    drapeaux: u8,
    out: &mut [u8],
) -> Result<usize, Error> {
    let court = || Error::new(Fault::BufferTooSmall);
    let masque = u32::from(u8::MAX)
        .checked_shr(8_u32.saturating_sub(bits))
        .unwrap_or(0);
    // `bits` vaut de un à huit, et vient du code appelant : le masque tient donc
    // toujours dans un octet, et `valeur` sous le masque aussi. `to_be_bytes`
    // les prend sans conversion à refuser — écrire un `try_from` ici ouvrirait
    // deux branches qu'aucun appel ne peut emprunter.
    let garde = masque.to_be_bytes()[3];
    let tete = drapeaux & !garde;
    if valeur < masque {
        let place = out.first_mut().ok_or_else(court)?;
        *place = tete | valeur.to_be_bytes()[3];
        return Ok(1);
    }
    let place = out.first_mut().ok_or_else(court)?;
    *place = tete | garde;
    let mut reste = valeur.saturating_sub(masque);
    let mut ecrits = 1_usize;
    loop {
        let place = out.get_mut(ecrits).ok_or_else(court)?;
        // Les sept bits de poids faible, pris tels quels.
        let sept = (reste & 0x7f).to_be_bytes()[3];
        ecrits = ecrits.saturating_add(1);
        if reste < 0x80 {
            *place = sept;
            return Ok(ecrits);
        }
        *place = sept | 0x80;
        reste >>= 7;
    }
}

#[cfg(test)]
mod tests;
