// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! L'identifiant de connexion de RFC 9000 §5.1.
//!
//! # CE N'EST PAS UNE ADRESSE, ET C'EST TOUT L'INTÉRÊT
//!
//! Une connexion TCP est identifiée par un quadruplet d'adresses et de ports :
//! changez de réseau, et elle meurt. Une connexion QUIC est identifiée par un
//! IDENTIFIANT que les pairs se donnent, et qui survit au changement d'adresse.
//! C'est ce qui permet à un téléphone de passer du wifi à la 5G sans rompre le
//! téléversement en cours.
//!
//! # ZÉRO À VINGT OCTETS, ET LA BORNE N'EST PAS DÉCORATIVE
//!
//! §17.2 : « The Destination Connection ID field […] can be 0 to 20 bytes in
//! length. Endpoints that receive a version 1 long header with a value larger
//! than 20 MUST drop the packet. » La longueur vient du fil, et un octet peut
//! en annoncer deux cent cinquante-cinq : sans la borne, un pair choisirait
//! combien on retient de lui.
//!
//! **UN IDENTIFIANT VIDE EST LÉGAL**, et ce n'est pas un cas dégénéré : un pair
//! qui n'a pas besoin de router ses connexions — parce qu'il n'a qu'une adresse
//! — n'en demande aucun, et économise vingt octets par paquet.

use crate::error::{Error, Reason};

/// La plus grande longueur qu'un identifiant puisse avoir (§17.2).
pub const CONNECTION_ID_MAX: usize = 20;

/// Un identifiant de connexion.
///
/// Il se copie : vingt et un octets tiennent dans un registre de plus, et une
/// référence obligerait à faire vivre le paquet aussi longtemps que la
/// connexion qu'il désigne.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionId {
    /// Les octets, dont seuls les `longueur` premiers valent.
    octets: [u8; CONNECTION_ID_MAX],
    /// Combien valent.
    longueur: u8,
}

impl ConnectionId {
    /// L'identifiant vide, celui d'un pair qui n'a rien à router.
    pub const EMPTY: Self = Self {
        octets: [0; CONNECTION_ID_MAX],
        longueur: 0,
    };

    /// Retient ces octets.
    ///
    /// # Errors
    ///
    /// [`Reason::ConnectionIdTooLong`] au-delà de vingt octets.
    pub fn new(octets: &[u8]) -> Result<Self, Error> {
        let mut identifiant = Self::EMPTY;
        let place = identifiant
            .octets
            .get_mut(..octets.len())
            .ok_or_else(|| Error::new(Reason::ConnectionIdTooLong))?;
        place.copy_from_slice(octets);
        // La longueur tient dans un octet : `place` a la même taille que
        // `octets`, et l'affectation ci-dessus a déjà refusé au-delà de vingt.
        identifiant.longueur = u8::try_from(octets.len()).unwrap_or(0);
        Ok(identifiant)
    }

    /// Les octets qui comptent.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.octets
            .get(..usize::from(self.longueur))
            .unwrap_or_default()
    }

    /// Combien d'octets.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.longueur as usize
    }

    /// N'a-t-il aucun octet ?
    ///
    /// **CE N'EST PAS UNE ANOMALIE** : un pair qui n'a qu'une adresse n'a rien à
    /// router, et vingt octets par paquet valent d'être économisés.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.longueur == 0
    }
}

#[cfg(test)]
mod tests;
