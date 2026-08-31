// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les portées : ce qu'un jeton ouvre, et ce qu'il n'ouvre pas.
//!
//! # QUATRE DOMAINES QUI N'ONT RIEN À VOIR ENTRE EUX
//!
//! Lire son courrier, administrer les comptes, déposer un message, regarder les
//! compteurs : ce sont quatre pouvoirs différents, et le premier ne doit jamais
//! donner le deuxième. Un jeton de client de messagerie qui pourrait créer un
//! compte serait un jeton d'administration déguisé.
//!
//! # ET LA LECTURE N'EST PAS L'ÉCRITURE
//!
//! La distinction coûte un bit et évite la faute la plus commune : un jeton
//! donné pour consulter et qui pouvait effacer. Un tableau de bord, une
//! sauvegarde, un client mobile en mode consultation — tous n'ont besoin que de
//! lire, et le leur accorder seul rend inoffensif le vol de leur jeton.

/// Un domaine de l'API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Area {
    /// Le courrier : boîtes, messages, drapeaux, recherche.
    Mail,
    /// L'administration : comptes, adresses, domaines, bannissements.
    Admin,
    /// La soumission d'un message.
    Submit,
    /// La supervision : santé, compteurs.
    Observe,
}

impl Area {
    /// Les quatre, dans l'ordre où leurs bits sont rangés.
    pub const TOUS: [Self; 4] = [Self::Mail, Self::Admin, Self::Submit, Self::Observe];

    /// Le rang du bit de lecture de ce domaine.
    const fn rang(self) -> u8 {
        match self {
            Self::Mail => 0,
            Self::Admin => 2,
            Self::Submit => 4,
            Self::Observe => 6,
        }
    }

    /// Le nom de ce domaine, tel qu'il s'écrit dans un jeton.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Mail => "mail",
            Self::Admin => "admin",
            Self::Submit => "submit",
            Self::Observe => "observe",
        }
    }
}

/// Ce qu'on a le droit d'y faire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rights {
    /// Lire, et rien de plus.
    Read,
    /// Lire et modifier.
    ///
    /// **L'ÉCRITURE CONTIENT LA LECTURE**, et non l'inverse : un droit d'écrire
    /// sans droit de lire n'a aucun sens ici, puisque toute modification passe
    /// par une ressource qu'il faut d'abord désigner.
    Write,
}

/// Ce qu'un jeton ouvre.
///
/// Huit bits : deux par domaine, lecture puis écriture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Scope {
    /// Les bits.
    bits: u8,
}

impl Scope {
    /// Une portée qui n'ouvre rien.
    ///
    /// **C'EST LE DÉFAUT, ET C'EST VOULU** : un jeton mal construit n'ouvre rien
    /// plutôt que tout. La faute d'inattention penche alors du bon côté.
    #[must_use]
    pub const fn none() -> Self {
        Self { bits: 0 }
    }

    /// Une portée qui ouvre ce droit sur ce domaine.
    #[must_use]
    pub const fn one(area: Area, rights: Rights) -> Self {
        Self::none().with(area, rights)
    }

    /// La même, plus ce droit sur ce domaine.
    #[must_use]
    pub const fn with(self, area: Area, rights: Rights) -> Self {
        let lecture = 1_u8 << area.rang();
        let bits = match rights {
            // L'écriture pose les deux bits : elle contient la lecture.
            Rights::Write => lecture | (lecture << 1),
            Rights::Read => lecture,
        };
        Self {
            bits: self.bits | bits,
        }
    }

    /// Les bits, tels qu'ils s'écrivent dans un jeton.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.bits
    }

    /// La portée que ces bits décrivent.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self { bits }
    }

    /// Ce droit est-il ouvert sur ce domaine ?
    #[must_use]
    pub const fn allows(self, area: Area, rights: Rights) -> bool {
        let lecture = 1_u8 << area.rang();
        let voulu = match rights {
            Rights::Write => lecture << 1,
            Rights::Read => lecture,
        };
        self.bits & voulu != 0
    }

    /// Cette portée contient-elle celle qu'on demande ?
    ///
    /// **C'EST LA SEULE QUESTION QUE POSE LE CONTRÔLE D'ACCÈS**, et elle se pose
    /// en un `&` : tout bit demandé doit être présent. Une comparaison d'égalité
    /// refuserait un jeton plus large que nécessaire ; une comparaison partielle
    /// en accepterait un plus étroit.
    #[must_use]
    pub const fn contains(self, voulue: Self) -> bool {
        self.bits & voulue.bits == voulue.bits
    }
}

#[cfg(test)]
mod tests;
