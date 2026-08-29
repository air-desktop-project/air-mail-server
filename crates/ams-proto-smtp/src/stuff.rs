//! Le POINT-FARCISSAGE à l'émission (RFC 5321 §4.5.2).
//!
//! # La transparence des données, vue de l'autre côté
//!
//! Un message se termine par une ligne qui ne porte qu'un point. Un message qui
//! contiendrait lui-même une telle ligne se terminerait donc trop tôt, et la
//! suite serait lue comme des commandes — la contrebande SMTP dans sa forme la
//! plus simple. La RFC 5321 §4.5.2 l'empêche en doublant **tout point en début
//! de ligne**, et le receveur défait ce doublement.
//!
//! [`DataReceiver`](crate::DataReceiver) fait le second geste ; celui-ci fait le
//! premier. Les deux sont ici parce que ce sont les deux moitiés d'une même
//! règle : les séparer entre deux crates ferait qu'un jour, en corrigeant l'une,
//! on casserait l'autre.
//!
//! # UN SAUT DE LIGNE ISOLÉ FAIT REFUSER LE MESSAGE
//!
//! On pourrait « réparer » un `LF` seul en le transformant en `CRLF`. On ne le
//! fait pas. C'est le désaccord entre implémentations sur ce qui termine une
//! ligne qui a rendu la contrebande SMTP possible en 2023 : ce que nous
//! émettrions ne serait alors plus ce que nous avons lu, et la signature DKIM
//! qui couvre ce corps ne vaudrait plus rien. Un message mal terminé est un
//! message qu'on refuse d'émettre.

use crate::Error;

/// Ce qu'il faut au plus pour écrire `morceau` point-farci.
///
/// Chaque octet peut en devenir deux (un point en début de ligne), et la clôture
/// demande cinq octets de plus : `CRLF` s'il manque, puis `.CRLF`.
#[must_use]
pub fn stuffed_max(octets: usize) -> usize {
    octets.saturating_mul(2).saturating_add(5)
}

/// De quoi émettre un corps de message sans qu'il puisse se terminer tout seul.
#[derive(Debug, Clone, Copy)]
pub struct Stuffer {
    /// Le prochain octet ouvre-t-il une ligne ?
    ///
    /// **Vrai au départ** : un message qui commence par un point doit être
    /// farci lui aussi.
    debut_de_ligne: bool,
    /// Un `CR` attend son `LF`.
    attend_lf: bool,
}

impl Default for Stuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl Stuffer {
    /// Ouvre l'émission d'un corps.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            debut_de_ligne: true,
            attend_lf: false,
        }
    }

    /// Écrit `morceau` point-farci, et rend le nombre d'octets écrits.
    ///
    /// Le découpage n'a **aucune** importance : l'état traverse les appels, et
    /// un point qui ouvre une ligne est farci même s'il arrive seul dans son
    /// morceau.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedLineEnding`] si le corps porte un `CR` ou un `LF`
    /// isolé ; [`Error::BufferTooSmall`] si `out` ne suffit pas — voir
    /// [`stuffed_max`].
    pub fn push(&mut self, morceau: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let besoin = morceau.len().saturating_mul(2);
        let mut ecrits = 0_usize;
        for octet in morceau {
            if self.attend_lf {
                if *octet != b'\n' {
                    return Err(Error::MalformedLineEnding);
                }
                self.attend_lf = false;
                self.debut_de_ligne = true;
            } else {
                match *octet {
                    b'\r' => self.attend_lf = true,
                    b'\n' => return Err(Error::MalformedLineEnding),
                    b'.' if self.debut_de_ligne => {
                        ecrits = poser(out, ecrits, b'.', besoin)?;
                        self.debut_de_ligne = false;
                    }
                    _ => self.debut_de_ligne = false,
                }
            }
            ecrits = poser(out, ecrits, *octet, besoin)?;
        }
        Ok(ecrits)
    }

    /// Clôt le message : le `CRLF` qui manque, puis la ligne au point.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedLineEnding`] si le corps se termine sur un `CR` seul ;
    /// [`Error::BufferTooSmall`] si `out` ne suffit pas.
    pub fn finish(self, out: &mut [u8]) -> Result<usize, Error> {
        if self.attend_lf {
            return Err(Error::MalformedLineEnding);
        }
        let mut ecrits = 0_usize;
        // UN CORPS QUI NE FINIT PAS PAR UN SAUT DE LIGNE en reçoit un. Sans lui,
        // le point de clôture s'ajouterait à la dernière ligne du message au
        // lieu d'en ouvrir une, et le message n'aurait pas de fin.
        if !self.debut_de_ligne {
            ecrits = poser(out, ecrits, b'\r', CLOTURE_MAX)?;
            ecrits = poser(out, ecrits, b'\n', CLOTURE_MAX)?;
        }
        ecrits = poser(out, ecrits, b'.', CLOTURE_MAX)?;
        ecrits = poser(out, ecrits, b'\r', CLOTURE_MAX)?;
        poser(out, ecrits, b'\n', CLOTURE_MAX)
    }
}

/// Ce que la clôture demande au plus : `CRLF`, puis `.CRLF`.
const CLOTURE_MAX: usize = 5;

/// Écrit un octet, et rend le nouveau compte.
///
/// `besoin` est ce qu'il aurait fallu en tout — pas ce qui manque à cet
/// octet-là : un appelant à qui l'on répond « un octet de plus » recommencerait
/// autant de fois qu'il y a d'octets.
fn poser(out: &mut [u8], ecrits: usize, octet: u8, besoin: usize) -> Result<usize, Error> {
    let place = out
        .get_mut(ecrits)
        .ok_or(Error::BufferTooSmall { needed: besoin })?;
    *place = octet;
    Ok(ecrits.saturating_add(1))
}

#[cfg(test)]
mod tests;
