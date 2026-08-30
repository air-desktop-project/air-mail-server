// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les numéros de flux de RFC 9000 §2.1.
//!
//! # DEUX BITS DISENT TOUT, ET C'EST CE QUI SUPPRIME LA NÉGOCIATION
//!
//! Le bit de poids faible dit QUI a ouvert le flux — zéro pour le client, un
//! pour le serveur. Le suivant dit s'il est bidirectionnel ou non. Le reste est
//! un compteur.
//!
//! **Personne n'a donc à demander la permission d'ouvrir un flux**, ni à
//! s'accorder sur qui prend les numéros pairs : le numéro lui-même le dit. En
//! HTTP/2, la même question se réglait par la convention « le client prend les
//! impairs », et les flux poussés par le serveur ont fini par être dépréciés
//! parce que cette convention ne suffisait pas.
//!
//! # UN FLUX N'EXISTE QU'UNE FOIS, ET SON NUMÉRO NE SE REND PAS
//!
//! §2.1 : « Streams are opened in order » — ouvrir le flux `n` ouvre
//! implicitement tous ceux du même type en deçà. C'est ce qui permet de ne rien
//! retenir des flux fermés : au-delà du plus grand ouvert, un flux est oisif ;
//! en deçà et hors de la table, il est fermé.
//!
//! C'est exactement la règle d'HTTP/2 §5.1.1, et pour la même raison : un numéro
//! réemployé désignerait deux échanges au même moment.

use crate::error::{Error, Reason};
use crate::frame::Directional;
use crate::varint::VARINT_MAX;

/// Qui a ouvert un flux (§2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Initiator {
    /// Le client.
    Client,
    /// Le serveur.
    Server,
}

/// Un numéro de flux, et ce que ses deux bits de bas disent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct StreamId(u64);

impl StreamId {
    /// Le numéro tel quel.
    ///
    /// # Errors
    ///
    /// [`Reason::BadFrameField`] au-delà de 2^62 - 1 : un numéro de flux est un
    /// entier de §16, et n'a pas d'autre espace.
    pub fn new(numero: u64) -> Result<Self, Error> {
        match numero <= VARINT_MAX {
            true => Ok(Self(numero)),
            false => Err(Error::new(Reason::BadFrameField)),
        }
    }

    /// Le numéro sur le fil.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Qui l'a ouvert : le bit de poids faible.
    #[must_use]
    pub const fn initiator(self) -> Initiator {
        match self.0 & 0x1 {
            0 => Initiator::Client,
            // Il ne reste que un : le classement est TOTAL.
            _ => Initiator::Server,
        }
    }

    /// Bidirectionnel ou non : le bit suivant.
    #[must_use]
    pub const fn directional(self) -> Directional {
        match self.0 & 0x2 {
            0 => Directional::Bidirectional,
            _ => Directional::Unidirectional,
        }
    }

    /// Son rang parmi les flux de son type.
    ///
    /// **C'EST CE RANG QUE `MAX_STREAMS` BORNE**, et non le numéro : §4.6 compte
    /// les flux d'un type, et deux types différents ont leurs comptes séparés.
    #[must_use]
    pub const fn index(self) -> u64 {
        self.0 >> 2
    }

    /// Le numéro du flux de ce rang, de ce type.
    ///
    /// # Errors
    ///
    /// [`Reason::BadFrameField`] si le rang sort de l'espace — c'est la borne de
    /// 2^60 de §19.11, vue de l'autre côté.
    pub fn from_index(
        index: u64,
        initiator: Initiator,
        directional: Directional,
    ) -> Result<Self, Error> {
        let bits = match initiator {
            Initiator::Client => 0,
            Initiator::Server => 1,
        } | match directional {
            Directional::Bidirectional => 0,
            Directional::Unidirectional => 2,
        };
        let numero = index
            .checked_mul(4)
            .and_then(|decale| decale.checked_add(bits))
            .ok_or_else(|| Error::new(Reason::BadFrameField))?;
        Self::new(numero)
    }

    /// Ce flux peut-il recevoir des données de ce pair ?
    ///
    /// # UN FLUX UNIDIRECTIONNEL NE VA QUE DANS UN SENS, ET C'EST LE SIEN
    ///
    /// §2.1 : celui qui ouvre un flux unidirectionnel est le seul à y écrire.
    /// Recevoir des données sur un flux unidirectionnel qu'on a ouvert soi-même
    /// est une faute d'état (§19.8) — et non un cas qu'on tolérerait.
    #[must_use]
    pub const fn peer_can_send(self, nous: Initiator) -> bool {
        match self.directional() {
            Directional::Bidirectional => true,
            Directional::Unidirectional => !self.est_de(nous),
        }
    }

    /// Ce flux peut-il porter ce que NOUS envoyons ?
    #[must_use]
    pub const fn we_can_send(self, nous: Initiator) -> bool {
        match self.directional() {
            Directional::Bidirectional => true,
            Directional::Unidirectional => self.est_de(nous),
        }
    }

    /// Ce flux vient-il de ce côté-ci ?
    const fn est_de(self, qui: Initiator) -> bool {
        matches!(
            (self.initiator(), qui),
            (Initiator::Client, Initiator::Client) | (Initiator::Server, Initiator::Server)
        )
    }
}

#[cfg(test)]
mod tests;
