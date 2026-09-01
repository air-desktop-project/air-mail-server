// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qui peut mal tourner en conduisant HTTP/3.
//!
//! # LE CODE QU'ON FERME AVEC N'EST PAS DÉCORATIF
//!
//! §8.1 de RFC 9114 range les fautes d'HTTP/3 dans l'espace des codes
//! applicatifs de QUIC, et c'est celui-là que le pair lira dans son journal pour
//! comprendre ce qu'il a fait de travers. Lui dire « erreur interne » quand il a
//! oublié ses réglages l'enverrait chercher au mauvais endroit.

use ams_proto_h3::H3Error;

/// Ce qui a mal tourné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Une faute que la grammaire HTTP/3 nomme (§8.1).
    H3(ams_proto_h3::Reason),
    /// Le transport a refusé.
    ///
    /// **SANS DIRE POURQUOI, ET C'EST VOULU** : §20 de RFC 9000 garde l'espace
    /// des codes de transport séparé de celui des applications, et HTTP/3 n'a
    /// pas à traduire l'un dans l'autre. Ce qu'il en sait suffit à fermer.
    Transport,
    /// **NOTRE FAUTE, ET NON CELLE DU PAIR** : un tampon trop court, une
    /// écriture qui ne passe pas. Le lui imputer rendrait son journal mensonger.
    Interne,
    /// Une trame de contrôle dont la charge ne se lit pas (§7.2).
    Malformee,
    /// Le pair dépasse ce qu'on lui a annoncé accepter (§4.2.2, §8.1).
    ///
    /// **IL LE SAIT** : nos réglages le lui ont dit. `H3_EXCESSIVE_LOAD` nomme
    /// exactement cela — « the endpoint detected that its peer is exhibiting a
    /// behavior that might be generating excessive load ».
    Excessive,
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

    /// La faute que cette raison de la grammaire décrit.
    #[must_use]
    pub const fn depuis_h3(erreur: ams_proto_h3::Error) -> Self {
        Self::new(Reason::H3(erreur.reason()))
    }

    /// Le transport a refusé.
    #[must_use]
    pub const fn transport() -> Self {
        Self::new(Reason::Transport)
    }

    /// Une faute qui n'appartient qu'à nous.
    #[must_use]
    pub const fn interne() -> Self {
        Self::new(Reason::Interne)
    }

    /// Une trame de contrôle qui ne se lit pas.
    #[must_use]
    pub const fn malformee() -> Self {
        Self::new(Reason::Malformee)
    }

    /// Le pair dépasse ce qu'on lui a annoncé.
    #[must_use]
    pub const fn excessive() -> Self {
        Self::new(Reason::Excessive)
    }

    /// Le code applicatif qu'on écrit en fermant (§8.1).
    #[must_use]
    pub fn close_code(self) -> u64 {
        match self.reason {
            Reason::H3(raison) => raison.code().value(),
            // **LE TRANSPORT A DÉJÀ SON CODE**, et il n'est pas dans l'espace
            // d'HTTP/3 : §20 de RFC 9000 garde les deux séparés exprès.
            Reason::Transport => H3Error::InternalError.value(),
            Reason::Interne => H3Error::InternalError.value(),
            Reason::Malformee => H3Error::FrameError.value(),
            Reason::Excessive => H3Error::ExcessiveLoad.value(),
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let quoi = match self.reason {
            Reason::H3(_) => "la grammaire HTTP/3 a refusé",
            Reason::Transport => "le transport a refusé",
            Reason::Interne => "notre propre tampon n'a pas suffi",
            Reason::Malformee => "une trame de contrôle ne se lit pas",
            Reason::Excessive => "le pair dépasse ce qu'on lui a annoncé",
        };
        write!(f, "{quoi} — on ferme avec {:#06x}", self.close_code())
    }
}

#[cfg(test)]
mod tests;
