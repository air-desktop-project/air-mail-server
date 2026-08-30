// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `HKDF-Expand-Label`, tel que TLS 1.3 le définit (RFC 8446 §7.1).
//!
//! # UNE ÉTIQUETTE N'EST PAS UNE CHAÎNE, C'EST UNE STRUCTURE
//!
//! `HKDF-Expand-Label` ne passe pas l'étiquette à `HKDF-Expand` : il en compose
//! une structure — la longueur voulue sur deux octets, puis `"tls13 "` suivi de
//! l'étiquette, préfixés de leur longueur, puis un contexte lui aussi préfixé.
//!
//! **Le préfixe `"tls13 "` est ce qui sépare les univers.** Sans lui, une clé
//! dérivée pour QUIC et une clé dérivée pour autre chose à partir du même
//! secret et de la même étiquette seraient la même clé. Avec lui, deux
//! protocoles qui partagent un secret ne partagent aucune clé.
//!
//! # LES OCTETS DE STRUCTURE SE VÉRIFIENT, ET LA RFC LES DONNE
//!
//! L'annexe A.1 de RFC 9001 écrit les cinq structures en toutes lettres :
//! `00200f746c73313320636c69656e7420696e00` pour « client in », par exemple. Ce
//! sont ces octets-là que les tests comparent — non le résultat de la
//! dérivation, qui pourrait être juste par accident si la structure était fausse
//! et le secret aussi.

use hkdf::Hkdf;
use sha2::{Sha256, Sha384};

use crate::error::{Error, Reason};

/// Le préfixe que TLS 1.3 met devant chaque étiquette.
const PREFIXE: &[u8] = b"tls13 ";

/// Ce qu'une structure d'étiquette peut occuper.
///
/// Deux octets de longueur, un de longueur d'étiquette, `"tls13 "` et
/// l'étiquette, un de longueur de contexte. Les étiquettes de QUIC font au plus
/// neuf octets ; on en prévoit trente-deux, ce qui laisse la place à celles de
/// TLS sans en inventer.
const STRUCTURE_MAX: usize = 2 + 1 + 6 + 32 + 1;

/// Compose la structure `HkdfLabel` de RFC 8446 §7.1.
///
/// Rend ce qu'elle occupe dans `out`.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`] si l'étiquette ne tient pas — c'est notre code
/// qui la choisit, jamais le pair.
pub fn hkdf_label(longueur: u16, etiquette: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let court = || Error::new(Reason::BufferTooSmall);
    let totale = PREFIXE.len().saturating_add(etiquette.len());
    // §7.1 : la longueur de l'étiquette tient sur un octet, et elle vaut de sept
    // à deux cent cinquante-cinq. `try_from` la refuse au-delà.
    let dite = u8::try_from(totale).map_err(|_| court())?;
    let fin = 2_usize
        .saturating_add(1)
        .saturating_add(totale)
        .saturating_add(1);
    let place = out.get_mut(..fin).ok_or_else(court)?;
    let (tete, suite) = place.split_at_mut(2);
    tete.copy_from_slice(&longueur.to_be_bytes());
    let (compte, suite) = suite.split_at_mut(1);
    compte[0] = dite;
    let (prefixe, suite) = suite.split_at_mut(PREFIXE.len());
    prefixe.copy_from_slice(PREFIXE);
    let (nom, contexte) = suite.split_at_mut(etiquette.len());
    nom.copy_from_slice(etiquette);
    // **LE CONTEXTE EST VIDE, ET SA LONGUEUR S'ÉCRIT QUAND MÊME.** L'omettre
    // ferait une structure d'un octet plus courte, donc une clé différente — et
    // le pair, lui, aurait écrit le zéro.
    contexte[0] = 0;
    Ok(fin)
}

/// `HKDF-Expand-Label` avec SHA-256.
///
/// # DEUX HACHAGES, DEUX CORPS, ET UNE SEULE STRUCTURE
///
/// Les deux fonctions qui suivent ne diffèrent que par le type du hachage. Les
/// écrire génériquement demanderait de nommer les bornes de `HmacImpl`, ce qui
/// coûte plus de lignes que la répétition n'en économise. **Le seul morceau qui
/// pouvait diverger — la structure d'étiquette — est écrit une fois**, et c'est
/// lui qui porte le risque : une structure fausse donne des clés de la bonne
/// taille, valides, et fausses.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`].
pub fn expand_sha256(secret: &[u8], etiquette: &[u8], out: &mut [u8]) -> Result<(), Error> {
    let court = || Error::new(Reason::BufferTooSmall);
    let mut structure = [0_u8; STRUCTURE_MAX];
    let ecrits = structure_de(etiquette, out.len(), &mut structure)?;
    let info = structure.get(..ecrits).unwrap_or_default();
    Hkdf::<Sha256>::from_prk(secret)
        .map_err(|_| Error::new(Reason::BadSecretLength))?
        .expand(info, out)
        .map_err(|_| court())
}

/// `HKDF-Expand-Label` avec SHA-384.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`], [`Reason::BadSecretLength`].
pub fn expand_sha384(secret: &[u8], etiquette: &[u8], out: &mut [u8]) -> Result<(), Error> {
    let court = || Error::new(Reason::BufferTooSmall);
    let mut structure = [0_u8; STRUCTURE_MAX];
    let ecrits = structure_de(etiquette, out.len(), &mut structure)?;
    let info = structure.get(..ecrits).unwrap_or_default();
    Hkdf::<Sha384>::from_prk(secret)
        .map_err(|_| Error::new(Reason::BadSecretLength))?
        .expand(info, out)
        .map_err(|_| court())
}

/// `HKDF-Extract` avec SHA-256, puis la clé pseudo-aléatoire.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`] si `out` ne fait pas la taille du hachage.
pub fn extract_sha256(sel: &[u8], matiere: &[u8], out: &mut [u8]) -> Result<(), Error> {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(sel), matiere);
    let place = out
        .get_mut(..prk.len())
        .ok_or_else(|| Error::new(Reason::BufferTooSmall))?;
    place.copy_from_slice(&prk);
    Ok(())
}

/// La structure d'étiquette pour cette longueur voulue.
fn structure_de(etiquette: &[u8], voulue: usize, out: &mut [u8]) -> Result<usize, Error> {
    // La longueur voulue tient sur deux octets : au-delà, `HKDF-Expand` refuse
    // de lui-même, et la structure ne saurait pas l'écrire.
    let longueur = u16::try_from(voulue).map_err(|_| Error::new(Reason::BufferTooSmall))?;
    hkdf_label(longueur, etiquette, out)
}

#[cfg(test)]
mod tests;
