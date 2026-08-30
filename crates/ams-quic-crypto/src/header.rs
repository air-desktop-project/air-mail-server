// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La protection d'en-tête, appliquée et ôtée (RFC 9001 §5.4).
//!
//! # L'ÉCHANTILLON SE PREND À QUATRE OCTETS DU NUMÉRO, TOUJOURS
//!
//! §5.4.2 : quelle que soit la longueur RÉELLE du numéro de paquet, on
//! échantillonne comme s'il en faisait quatre. La raison est dans l'ordre des
//! opérations : le receveur ne connaît pas cette longueur — elle est justement
//! sous le masque qu'il cherche à ôter.
//!
//! **C'est un serpent qui se mord la queue, et §5.4.2 le coupe en fixant le
//! point d'échantillonnage.** Un décodeur qui échantillonnerait selon la
//! longueur qu'il croit lire lirait un autre échantillon que l'émetteur, et
//! obtiendrait un masque sans rapport.
//!
//! # QUATRE BITS SUR UN EN-TÊTE LONG, CINQ SUR UN COURT
//!
//! §5.4.1. Un en-tête long a un type sur deux bits qui reste en clair ; un
//! en-tête court n'en a pas, et masque un bit de plus — celui de la phase de
//! clé. Se tromper de masque laisse le bit de phase en clair, ce qui permet à un
//! observateur de compter les mises à jour de clé.

use crate::error::{Error, Reason};
use crate::keys::Keys;
use crate::suite::{MASK_OCTETS, SAMPLE_OCTETS};

/// Le bit de forme : un en-tête long l'a à un.
const BIT_FORME_LONGUE: u8 = 0x80;

/// Ce que les deux bits de bas disent de la longueur du numéro.
const MASQUE_LONGUEUR: u8 = 0x03;

/// Applique la protection d'en-tête à un paquet déjà chiffré.
///
/// `numero` est le rang du premier octet du numéro de paquet, `longueur` sa
/// taille en octets.
///
/// # Errors
///
/// [`Reason::TooShortToSample`] si le paquet ne porte pas seize octets à quatre
/// octets du numéro — §5.4.2 impose alors de le jeter.
pub fn protect(
    clefs: &Keys,
    paquet: &mut [u8],
    numero: usize,
    longueur: usize,
) -> Result<(), Error> {
    let masque = masque_de(clefs, paquet, numero)?;
    appliquer(paquet, numero, longueur, &masque);
    Ok(())
}

/// Ôte la protection d'en-tête, et rend la longueur du numéro de paquet.
///
/// # L'ORDRE EST INVERSE, ET C'EST TOUTE LA DIFFÉRENCE
///
/// À l'écriture, on connaît la longueur du numéro et l'on masque. À la lecture,
/// on démasque le premier octet, on Y LIT la longueur, puis on démasque le
/// numéro. §5.4.1 le dit en une phrase : « Removing header protection only
/// differs in the order in which the packet number length is determined. »
///
/// # Errors
///
/// [`Reason::TooShortToSample`].
pub fn unprotect(clefs: &Keys, paquet: &mut [u8], numero: usize) -> Result<usize, Error> {
    let masque = masque_de(clefs, paquet, numero)?;
    // Le premier octet d'abord : c'est lui qui porte la longueur.
    demasquer_le_premier(paquet, &masque);
    let longueur = longueur_du_numero(paquet);
    demasquer_le_numero(paquet, numero, longueur, &masque);
    Ok(longueur)
}

/// La longueur du numéro de paquet, lue dans un premier octet DÉMASQUÉ.
///
/// **ELLE VAUT DE UN À QUATRE**, toujours : deux bits plus un. Il n'y a donc
/// aucune longueur à refuser ici — le refus, s'il doit avoir lieu, porte sur ce
/// que le paquet contient, pas sur ces deux bits.
#[must_use]
pub fn longueur_du_numero(paquet: &[u8]) -> usize {
    let bits = paquet.first().copied().unwrap_or(0) & MASQUE_LONGUEUR;
    usize::from(bits).saturating_add(1)
}

/// Le masque, pris à quatre octets du numéro (§5.4.2).
fn masque_de(clefs: &Keys, paquet: &[u8], numero: usize) -> Result<[u8; MASK_OCTETS], Error> {
    let court = || Error::new(Reason::TooShortToSample);
    // §5.4.2 : « sample_offset = pn_offset + 4 », et le numéro est SUPPOSÉ faire
    // quatre octets même s'il en fait moins.
    let debut = numero.saturating_add(4);
    let fin = debut.saturating_add(SAMPLE_OCTETS);
    let echantillon = paquet.get(debut..fin).ok_or_else(court)?;
    clefs.header_mask(echantillon)
}

/// Applique le masque : le premier octet, puis le numéro.
fn appliquer(paquet: &mut [u8], numero: usize, longueur: usize, masque: &[u8; MASK_OCTETS]) {
    demasquer_le_premier(paquet, masque);
    demasquer_le_numero(paquet, numero, longueur, masque);
}

/// Ou-exclusif sur le premier octet, quatre bits ou cinq selon la forme.
///
/// **UN PAQUET VIDE N'ARRIVE PAS ICI** : l'échantillon exige déjà vingt octets
/// au moins. Le `zip` sur un seul élément porte cette impossibilité sans ouvrir
/// de branche — là où un `if let` en aurait laissé une qu'aucun paquet ne peut
/// emprunter.
fn demasquer_le_premier(paquet: &mut [u8], masque: &[u8; MASK_OCTETS]) {
    let premier = paquet.first().copied().unwrap_or(0);
    // §5.4.1 : quatre bits sur un en-tête long, cinq sur un court.
    let bits = match premier & BIT_FORME_LONGUE {
        0 => 0x1f,
        _ => 0x0f,
    };
    let applique = masque[0] & bits;
    for (place, lu) in paquet.iter_mut().zip(core::iter::once(applique)) {
        *place ^= lu;
    }
}

/// Ou-exclusif sur les octets du numéro de paquet.
///
/// **LES OCTETS DE MASQUE INEMPLOYÉS NE SERVENT À RIEN** (§5.4.1) : un numéro
/// d'un octet n'emploie qu'un octet de masque, et les trois autres se jettent.
fn demasquer_le_numero(
    paquet: &mut [u8],
    numero: usize,
    longueur: usize,
    masque: &[u8; MASK_OCTETS],
) {
    let fin = numero.saturating_add(longueur);
    let place = paquet.get_mut(numero..fin).unwrap_or_default();
    for (octet, lu) in place.iter_mut().zip(masque.iter().skip(1)) {
        *octet ^= *lu;
    }
}

#[cfg(test)]
mod tests;
