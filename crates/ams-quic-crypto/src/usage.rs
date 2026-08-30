// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une clé a le droit de chiffrer, et ce qu'on a le droit de refuser
//! (RFC 9001 §6.6).
//!
//! # DEUX COMPTES, ET ILS NE COMPTENT PAS LA MÊME CHOSE
//!
//! La borne de CONFIDENTIALITÉ compte les paquets qu'on a chiffrés avec une
//! clé : au-delà, un adversaire distingue l'AEAD d'une permutation aléatoire.
//! Elle se remet à zéro à chaque mise à jour de clé, et c'est justement à cela
//! que sert la mise à jour.
//!
//! La borne d'INTÉGRITÉ compte les paquets qui ont échoué à s'authentifier,
//! **sur toute la connexion et toutes clés confondues**. Elle ne se remet jamais
//! à zéro : une mise à jour de clé ne fait pas oublier les essais d'un
//! adversaire.
//!
//! # ELLE EXISTE PARCE QUE QUIC JETTE AU LIEU DE FERMER
//!
//! TLS ferme au premier enregistrement qui ne s'authentifie pas. QUIC JETTE le
//! paquet et continue — sans quoi n'importe qui fermerait une connexion en
//! envoyant un datagramme. Mais cela donne à un adversaire autant d'essais qu'il
//! veut, et c'est ce compte-là qui les borne.

use crate::error::{Error, Reason};
use crate::suite::Suite;

/// Ce qu'une clé a chiffré, et ce que la connexion a refusé.
///
/// # LES BORNES SE RETIENNENT, ET NE SE REDEMANDENT PAS
///
/// Une première écriture comparait à `suite.integrity_limit()` à chaque appel.
/// C'était juste, et ce n'était pas éprouvable : la borne vaut 2^36 pour
/// ChaCha20-Poly1305, et aucun test ne la parcourt. **Une garde qu'on ne peut
/// pas atteindre est une garde qu'on ne peut pas vérifier** — et ce n'est pas
/// une nuance quand elle décide de fermer une connexion.
///
/// Les bornes vivent donc dans le compte, et [`Usage::with_limits`] permet d'en
/// poser de plus basses. §6.6 l'autorise explicitement, un opérateur prudent
/// peut le vouloir, et les tests s'en servent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Usage {
    /// Combien de paquets ont été chiffrés avec la clé courante.
    chiffres: u64,
    /// Combien de paquets ont échoué à s'authentifier, toutes clés confondues.
    refuses: u64,
    /// Au-delà de combien on refuse de chiffrer.
    confidentialite: u64,
    /// Au-delà de combien on ferme.
    integrite: u64,
}

impl Usage {
    /// Un compte neuf, avec les bornes que §6.6 donne à cette suite.
    #[must_use]
    pub const fn new(suite: Suite) -> Self {
        Self {
            chiffres: 0,
            refuses: 0,
            confidentialite: suite.confidentiality_limit(),
            integrite: suite.integrity_limit(),
        }
    }

    /// Un compte neuf, avec des bornes qu'on choisit.
    ///
    /// # ON PEUT DESCENDRE, ET JAMAIS MONTER
    ///
    /// Les bornes de §6.6 ne sont pas des préférences : l'annexe B les DÉMONTRE.
    /// Un appelant qui en voudrait de plus hautes demanderait à dépasser ce que
    /// l'analyse permet, et l'on ramène donc silencieusement à ce que la suite
    /// autorise. Plus basses, en revanche, elles sont toujours licites.
    #[must_use]
    pub const fn with_limits(suite: Suite, confidentialite: u64, integrite: u64) -> Self {
        let plafond_c = suite.confidentiality_limit();
        let plafond_i = suite.integrity_limit();
        Self {
            chiffres: 0,
            refuses: 0,
            confidentialite: if confidentialite < plafond_c {
                confidentialite
            } else {
                plafond_c
            },
            integrite: if integrite < plafond_i {
                integrite
            } else {
                plafond_i
            },
        }
    }

    /// La borne de confidentialité en vigueur.
    #[must_use]
    pub const fn confidentiality_limit(&self) -> u64 {
        self.confidentialite
    }

    /// La borne d'intégrité en vigueur.
    #[must_use]
    pub const fn integrity_limit(&self) -> u64 {
        self.integrite
    }

    /// Combien de paquets ont été chiffrés avec la clé courante.
    #[must_use]
    pub const fn sealed(&self) -> u64 {
        self.chiffres
    }

    /// Combien de paquets ont échoué à s'authentifier.
    #[must_use]
    pub const fn rejected(&self) -> u64 {
        self.refuses
    }

    /// Un paquet de plus a été chiffré.
    ///
    /// # Errors
    ///
    /// [`Reason::AeadLimitReached`] au-delà de la borne. §6.6 demande de fermer
    /// AVANT d'y arriver : cette faute est le dernier recours, pas le signal
    /// ordinaire — celui-là est [`Usage::should_update`].
    pub fn on_sealed(&mut self) -> Result<(), Error> {
        self.chiffres = self.chiffres.saturating_add(1);
        match self.chiffres > self.confidentialite {
            true => Err(Error::new(Reason::AeadLimitReached)),
            false => Ok(()),
        }
    }

    /// Un paquet de plus a échoué à s'authentifier.
    ///
    /// # Errors
    ///
    /// [`Reason::AeadLimitReached`] au-delà de la borne — et là, §6.6 est
    /// catégorique : « close the connection […] and not process any more
    /// packets ».
    pub fn on_rejected(&mut self) -> Result<(), Error> {
        self.refuses = self.refuses.saturating_add(1);
        match self.refuses > self.integrite {
            true => Err(Error::new(Reason::AeadLimitReached)),
            false => Ok(()),
        }
    }

    /// Les clés viennent d'être remplacées.
    ///
    /// **SEUL LE COMPTE DES CHIFFRÉS REPART** : les essais d'un adversaire ne
    /// s'oublient pas parce qu'on a changé de clé.
    pub const fn on_key_update(&mut self) {
        self.chiffres = 0;
    }

    /// Faut-il changer de clé avant le prochain paquet ?
    ///
    /// # ON PRÉVIENT À LA MOITIÉ, ET NON À LA BORNE
    ///
    /// §6.6 demande d'avoir mis à jour AVANT d'atteindre la borne. Attendre
    /// celle-ci pour s'en apercevoir laisserait la connexion sans clé utilisable
    /// au moment précis où il faudrait en changer.
    #[must_use]
    pub const fn should_update(&self) -> bool {
        self.chiffres >= self.confidentialite / 2
    }
}

#[cfg(test)]
mod tests;
