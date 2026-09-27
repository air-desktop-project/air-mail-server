// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La valeur d'un paramètre MIME, décodée : `filename`, `name`, `charset`…
//!
//! # TROIS ÉCRITURES POUR UN MÊME NOM DE FICHIER
//!
//! - `filename="rapport.pdf"` — la forme de la RFC 2045 ;
//! - `filename*=utf-8''rapport%20d%C3%A9finitif.pdf` — la RFC 2231, qui porte
//!   un jeu de caractères et encode chaque octet hors de l'ASCII ;
//! - `filename*0*=utf-8''rapport%20; filename*1="définitif.pdf"` — la RFC 2231
//!   encore, coupée en morceaux numérotés pour tenir dans des lignes.
//!
//! Et une quatrième, que la RFC 2047 interdit (§5) et que la moitié des
//! logiciels écrit : `name="=?utf-8?B?…?="`. Ne pas la lire afficherait la soupe
//! encodée à la place du nom — on la lit.
//!
//! # LA FORME ÉTENDUE L'EMPORTE
//!
//! Un expéditeur prudent écrit les deux — `filename` en ASCII pour les vieux
//! lecteurs, `filename*` pour les autres —, et c'est le second qui dit le vrai
//! nom (RFC 6266 §4.3 fait le même choix pour HTTP).
//!
//! # CE QU'ON NE SAIT PAS CONVERTIR NE SE REND PAS
//!
//! Un jeu de caractères inconnu rend `None`, et non des octets que personne ne
//! saurait lire : un nom de fichier faux vaut moins que pas de nom.

use crate::decode::{decode_encoded_words, jeu_latin1};
use crate::error::Error;
use crate::structure::parametres;

/// Combien de morceaux au plus pour un paramètre coupé (RFC 2231 §3).
///
/// **Aucune RFC ne le borne.** Soixante-quatre morceaux de ligne pleine font
/// bien plus que ce qu'un nom de fichier porte.
pub const PARAMETER_SEGMENTS_MAX: usize = 64;

/// Ce qu'un paramètre porte, selon sa forme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Forme {
    /// `nom=…`
    Simple,
    /// `nom*=…`
    Etendue,
    /// `nom*k=…` ou `nom*k*=…` : le rang, et s'il est étendu.
    Morceau(usize, bool),
}

/// Écrit la valeur de `name` dans `out`, en UTF-8, et rend ce qu'elle occupe —
/// ou `None` si le paramètre est absent, ou dans un jeu qu'on ne sait pas lire.
///
/// `params` est ce qui suit le type : `; charset=utf-8; name="x.pdf"`. `work`
/// reçoit les octets avant conversion ; il doit être aussi grand que `params`,
/// et `out` deux fois plus (voir [`crate::decoded_max`]).
///
/// # Errors
///
/// [`Error::BufferTooSmall`] si `work` ou `out` ne suffit pas.
pub fn write_parameter(
    params: &[u8],
    name: &[u8],
    work: &mut [u8],
    out: &mut [u8],
) -> Result<Option<usize>, Error> {
    let mut simple: Option<(&[u8], bool)> = None;
    let mut etendue: Option<&[u8]> = None;
    let mut morceaux: [Option<(&[u8], bool, bool)>; PARAMETER_SEGMENTS_MAX] =
        [None; PARAMETER_SEGMENTS_MAX];
    parametres(params, |vu, valeur, citee| {
        // LE PREMIER DE CHAQUE NOM, comme partout dans cette crate : un
        // doublon ne laisse pas qui l'a écrit choisir lequel on lit.
        match forme(vu, name) {
            Some(Forme::Simple) if simple.is_none() => simple = Some((valeur, citee)),
            Some(Forme::Etendue) if etendue.is_none() => etendue = Some(valeur),
            Some(Forme::Morceau(rang, etendu)) => {
                if let Some(place @ None) = morceaux.get_mut(rang) {
                    *place = Some((valeur, etendu, citee));
                }
            }
            _ => {}
        }
        false
    });

    if let Some(valeur) = etendue {
        let mut plume = Plume {
            out: work,
            ecrits: 0,
        };
        let (jeu, reste) = prefixe(valeur);
        pourcents(&mut plume, reste)?;
        let ecrits = plume.ecrits;
        return convertir(jeu, work.get(..ecrits).unwrap_or_default(), out);
    }
    if let Some(Some((premier, _, _))) = morceaux.first() {
        // Seul le morceau zéro porte le jeu, et seulement s'il est étendu.
        let jeu = match morceaux.first() {
            Some(Some((_, true, _))) => prefixe(premier).0,
            _ => &b"us-ascii"[..],
        };
        let mut plume = Plume {
            out: work,
            ecrits: 0,
        };
        // LES MORCEAUX SE SUIVENT, ET LE PREMIER TROU ARRÊTE TOUT : un morceau
        // qui en suit un absent ne se raccorde à rien.
        for (rang, morceau) in morceaux.iter().enumerate() {
            let Some((valeur, etendu, citee)) = *morceau else {
                break;
            };
            match (etendu, rang) {
                (true, 0) => pourcents(&mut plume, prefixe(valeur).1)?,
                (true, _) => pourcents(&mut plume, valeur)?,
                (false, _) => litteral(&mut plume, valeur, citee)?,
            }
        }
        let ecrits = plume.ecrits;
        return convertir(jeu, work.get(..ecrits).unwrap_or_default(), out);
    }
    let Some((valeur, citee)) = simple else {
        return Ok(None);
    };
    let mut plume = Plume {
        out: work,
        ecrits: 0,
    };
    litteral(&mut plume, valeur, citee)?;
    let ecrits = plume.ecrits;
    decode_encoded_words(work.get(..ecrits).unwrap_or_default(), out).map(Some)
}

/// La forme sous laquelle `vu` désigne `nom`, s'il le désigne.
fn forme(vu: &[u8], nom: &[u8]) -> Option<Forme> {
    let (tete, queue) = vu.split_at_checked(nom.len())?;
    if !tete.eq_ignore_ascii_case(nom) {
        return None;
    }
    let Some(apres) = queue.strip_prefix(b"*") else {
        return queue.is_empty().then_some(Forme::Simple);
    };
    if apres.is_empty() {
        return Some(Forme::Etendue);
    }
    let (chiffres, etendu) = match apres.strip_suffix(b"*") {
        Some(chiffres) => (chiffres, true),
        None => (apres, false),
    };
    // §3 : pas de zéro en tête — `*01` n'est pas le morceau un, et le lire
    // comme tel laisserait deux écritures désigner le même morceau.
    let bien_forme = !chiffres.is_empty()
        && chiffres.iter().all(u8::is_ascii_digit)
        && (chiffres == b"0" || !chiffres.starts_with(b"0"))
        && chiffres.len() <= 2;
    if !bien_forme {
        return None;
    }
    let rang = chiffres.iter().fold(0_usize, |valeur, chiffre| {
        valeur
            .saturating_mul(10)
            .saturating_add(usize::from(chiffre.wrapping_sub(b'0')))
    });
    Some(Forme::Morceau(rang, etendu))
}

/// `utf-8'fr'reste` : le jeu, et ce qui suit la langue.
///
/// Sans les deux apostrophes, il n'y a pas de jeu : les octets sont de l'ASCII,
/// et c'est ainsi qu'on les lit.
fn prefixe(valeur: &[u8]) -> (&[u8], &[u8]) {
    let mut morceaux = valeur.splitn(3, |octet| *octet == b'\'');
    match (morceaux.next(), morceaux.next(), morceaux.next()) {
        (Some(jeu), Some(_), Some(reste)) => (jeu, reste),
        _ => (&b"us-ascii"[..], valeur),
    }
}

/// Écrit une valeur étendue : `%XX` vaut l'octet, le reste vaut lui-même.
fn pourcents(plume: &mut Plume<'_>, valeur: &[u8]) -> Result<(), Error> {
    let mut i = 0_usize;
    while i < valeur.len() {
        let octet = valeur.get(i).copied().unwrap_or(0);
        let echappe = match (octet, valeur.get(i.saturating_add(1)..i.saturating_add(3))) {
            (b'%', Some(&[haut, bas])) => quartet(haut).zip(quartet(bas)),
            _ => None,
        };
        match echappe {
            // UN `%` QUI N'OUVRE PAS UN OCTET RESTE UN `%` : c'est ce que
            // l'expéditeur a écrit, et deviner autre chose serait inventer.
            Some((haut, bas)) => {
                plume.pousser(haut.wrapping_shl(4) | bas)?;
                i = i.saturating_add(3);
            }
            None => {
                plume.pousser(octet)?;
                i = i.saturating_add(1);
            }
        }
    }
    Ok(())
}

/// La valeur d'un chiffre hexadécimal.
fn quartet(octet: u8) -> Option<u8> {
    match octet {
        b'0'..=b'9' => Some(octet.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(octet.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(octet.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

/// Écrit une valeur telle quelle, les échappements d'une chaîne citée défaits.
fn litteral(plume: &mut Plume<'_>, valeur: &[u8], citee: bool) -> Result<(), Error> {
    let mut i = 0_usize;
    while i < valeur.len() {
        let octet = valeur.get(i).copied().unwrap_or(0);
        let (vaut, saut) = match (octet, citee) {
            (b'\\', true) => (valeur.get(i.saturating_add(1)).copied().unwrap_or(b'\\'), 2),
            _ => (octet, 1),
        };
        // UN PLI N'EST PAS DU TEXTE : il s'efface, et le blanc qui le suit
        // reste.
        if !matches!(vaut, b'\r' | b'\n') {
            plume.pousser(vaut)?;
        }
        i = i.saturating_add(saut);
    }
    Ok(())
}

/// Convertit des octets d'un jeu connu en UTF-8.
fn convertir(jeu: &[u8], octets: &[u8], out: &mut [u8]) -> Result<Option<usize>, Error> {
    let Some(latin1) = jeu_latin1(jeu) else {
        return Ok(None);
    };
    let mut plume = Plume { out, ecrits: 0 };
    for octet in octets {
        if latin1 && *octet >= 0x80 {
            // `iso-8859-1` vers UTF-8 : deux octets, sans table.
            plume.pousser(0xC0_u8 | (*octet >> 6))?;
            plume.pousser(0x80_u8 | (*octet & 0x3F))?;
        } else {
            plume.pousser(*octet)?;
        }
    }
    Ok(Some(plume.ecrits))
}

/// De quoi écrire dans un tampon fixe, octet par octet.
struct Plume<'a> {
    out: &'a mut [u8],
    ecrits: usize,
}

impl Plume<'_> {
    fn pousser(&mut self, octet: u8) -> Result<(), Error> {
        *self.out.get_mut(self.ecrits).ok_or(Error::BufferTooSmall)? = octet;
        self.ecrits = self.ecrits.saturating_add(1);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
