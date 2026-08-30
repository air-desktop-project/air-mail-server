// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que la protection des paquets peut refuser.

use ams_proto_quic::TransportError;

/// Ce qui a mal tourné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// L'authentification a échoué : le paquet n'est pas celui qu'on croit.
    ///
    /// # ON NE FERME PAS LA CONNEXION POUR AUTANT
    ///
    /// §5.3 : « An endpoint MUST discard packets that cannot be
    /// authenticated. » Un paquet qui ne s'authentifie pas peut venir de
    /// n'importe qui — c'est de l'UDP —, et fermer sur lui offrirait la
    /// connexion à qui sait envoyer un datagramme. On le JETTE.
    NotAuthentic,
    /// Le tampon de sortie ne suffit pas. **Notre faute, pas celle du pair.**
    BufferTooSmall,
    /// Un paquet trop court pour porter un échantillon de protection d'en-tête.
    ///
    /// §5.4.2 : « An endpoint MUST discard packets that are not long enough to
    /// contain a complete sample. »
    TooShortToSample,
    /// Un secret d'une longueur que la suite n'emploie pas.
    BadSecretLength,
    /// On a chiffré ou refusé plus de paquets que la suite ne le permet (§6.6).
    AeadLimitReached,
}

impl Reason {
    /// Le code de transport qui va avec.
    #[must_use]
    pub const fn code(self) -> TransportError {
        match self {
            // §5.3 : un paquet qu'on jette n'a pas de code — il n'y a personne à
            // qui l'imputer. Celui-ci ne part sur le fil que si l'appelant
            // décide, lui, de fermer.
            Self::NotAuthentic | Self::TooShortToSample => TransportError::ProtocolViolation,
            // **LES NÔTRES** : un tampon mal dimensionné et un secret de la
            // mauvaise taille viennent de notre code, pas du pair.
            Self::BufferTooSmall | Self::BadSecretLength => TransportError::InternalError,
            // §6.6 le nomme explicitement, et demande de fermer AVANT d'y
            // arriver.
            Self::AeadLimitReached => TransportError::AeadLimitReached,
        }
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

    /// Le code de transport.
    #[must_use]
    pub const fn code(self) -> TransportError {
        self.reason.code()
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let quoi = match self.reason {
            Reason::NotAuthentic => "le paquet ne s'authentifie pas, et se jette",
            Reason::BufferTooSmall => "le tampon de sortie ne suffit pas",
            Reason::TooShortToSample => "le paquet est trop court pour un échantillon",
            Reason::BadSecretLength => "un secret d'une longueur que la suite n'emploie pas",
            Reason::AeadLimitReached => "on a atteint ce que la suite permet de chiffrer",
        };
        write!(f, "{quoi} (code 0x{:02x})", self.code().value())
    }
}

#[cfg(test)]
mod tests;
