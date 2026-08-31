// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que la réception d'un paquet peut refuser.
//!
//! # DEUX FAÇONS DE REFUSER, ET ELLES NE SE VALENT PAS
//!
//! Un paquet peut se JETER, ou condamner la connexion. La distinction n'est pas
//! de degré : le port est ouvert au monde entier, et **fermer une connexion sur
//! un paquet qu'on n'a pas pu authentifier l'offrirait à qui sait envoyer un
//! datagramme**.
//!
//! On ne condamne donc que ce qui vient d'un pair AUTHENTIFIÉ — c'est-à-dire ce
//! qu'on découvre APRÈS avoir déchiffré.

use ams_proto_quic::TransportError;

/// Ce qui a mal tourné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Ce n'est pas un paquet qu'on sache lire : forme, version, ou troncature.
    ///
    /// **IL SE JETTE, EN SILENCE.**
    NotForUs,
    /// Le paquet ne s'authentifie pas. **Il se jette aussi.**
    NotAuthentic,
    /// Les bits réservés ne sont pas nuls (§17.2, §17.3.1).
    ///
    /// **CELLE-CI CONDAMNE**, parce qu'on ne la découvre qu'après avoir
    /// déchiffré : le pair est authentifié, et il parle mal.
    ReservedBitsSet,
    /// Le numéro de paquet ne se reconstruit pas.
    ///
    /// §12.3 : l'espace des numéros s'épuise, et la connexion doit être fermée
    /// avant d'y arriver. Qu'on nous demande de reconstruire quand même veut
    /// dire qu'on a manqué cette fermeture.
    BadPacketNumber,
}

impl Reason {
    /// Le code qu'on écrirait en fermant — `None` pour ce qui se jette.
    ///
    /// # UN PAQUET QU'ON JETTE N'A PAS DE CODE
    ///
    /// Il n'y a personne à qui l'imputer : il peut venir de n'importe qui, et
    /// le port est ouvert au monde entier. Rendre `None` le dit ; rendre un code
    /// qu'on n'enverra jamais laisserait croire le contraire.
    #[must_use]
    pub const fn code(self) -> Option<TransportError> {
        match self {
            Self::NotForUs | Self::NotAuthentic => None,
            // §17.2 et §12.3 les nomment : ce sont des pairs authentifiés qui
            // parlent mal.
            Self::ReservedBitsSet | Self::BadPacketNumber => {
                Some(TransportError::ProtocolViolation)
            }
        }
    }

    /// Ce paquet se jette-t-il sans rien dire ?
    ///
    /// §5.3 de RFC 9001 : « An endpoint MUST discard packets that cannot be
    /// authenticated. » Jeter n'est pas une indulgence : c'est ce qui empêche un
    /// tiers de fermer une connexion qui ne lui appartient pas.
    ///
    /// **C'EST LA MÊME QUESTION QUE `code`**, posée autrement : une faute qui se
    /// jette est exactement une faute sans code. Deux réponses séparées auraient
    /// pu diverger.
    #[must_use]
    pub const fn se_jette(self) -> bool {
        self.code().is_none()
    }
}

/// Une faute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    /// Ce qui a mal tourné.
    reason: Reason,
}

impl Error {
    /// La faute qui va avec cette raison.
    #[must_use]
    pub const fn new(reason: Reason) -> Self {
        Self { reason }
    }

    /// Ce qui a mal tourné.
    #[must_use]
    pub const fn reason(self) -> Reason {
        self.reason
    }

    /// Ce paquet se jette-t-il sans rien dire ?
    #[must_use]
    pub const fn se_jette(self) -> bool {
        self.reason.se_jette()
    }

    /// Le code qu'on écrirait en fermant — `None` pour ce qui se jette.
    #[must_use]
    pub const fn code(self) -> Option<TransportError> {
        self.reason.code()
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let quoi = match self.reason {
            Reason::NotForUs => "ce n'est pas un paquet qu'on sache lire",
            Reason::NotAuthentic => "le paquet ne s'authentifie pas",
            Reason::ReservedBitsSet => "les bits réservés ne sont pas nuls",
            Reason::BadPacketNumber => "le numéro de paquet ne se reconstruit pas",
        };
        let suite = match self.se_jette() {
            true => "on le jette",
            false => "on ferme",
        };
        write!(f, "{quoi} — {suite}")
    }
}

#[cfg(test)]
mod tests;
