// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le contrôle de flux (§5.2, §6.9).
//!
//! # UNE FENÊTRE PEUT DEVENIR NÉGATIVE, ET C'EST LÉGAL
//!
//! C'est le piège de ce module, et il n'est pas rare de le manquer. §6.9.2 :
//! quand `SETTINGS_INITIAL_WINDOW_SIZE` change, toutes les fenêtres de flux
//! OUVERTS sont ajustées de la DIFFÉRENCE. Si le pair réduit la fenêtre initiale
//! alors qu'il a déjà envoyé des données, l'ajustement rend la fenêtre négative
//! — et la RFC le dit en toutes lettres : « This can cause the available space
//! in a flow-control window to become negative. »
//!
//! Une fenêtre stockée dans un `u32` ne peut pas être négative. Elle passerait
//! par zéro en soustrayant, ou déborderait par le haut — et dans les deux cas le
//! pair pourrait envoyer des données qu'on aurait dû refuser. **La fenêtre est
//! donc signée**, et sur soixante-quatre bits pour que l'arithmétique
//! intermédiaire ne déborde jamais.
//!
//! # DEUX FENÊTRES, ET IL FAUT LES DEUX
//!
//! §5.2.1 : chaque `DATA` consomme la fenêtre de son FLUX **et** celle de la
//! CONNEXION. N'en vérifier qu'une laisse un pair ouvrir cent flux et envoyer
//! cent fois la fenêtre — c'est la mémoire du serveur qu'il choisit.

use crate::error::{Cause, Error, ErrorCode};

/// La fenêtre initiale de §6.5.2, avant tout `SETTINGS`.
pub const INITIAL_WINDOW_SIZE: u32 = 65_535;

/// La plus grande valeur qu'une fenêtre puisse atteindre (§6.9.1).
pub const WINDOW_MAX: i64 = 0x7fff_ffff;

/// Une fenêtre de contrôle de flux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    /// Ce qui reste, en octets. **Peut être négatif** — voir l'en-tête du
    /// module.
    disponible: i64,
}

impl Window {
    /// Une fenêtre à sa taille initiale.
    ///
    /// # LA BORNE EST TENUE ICI, PAS SUPPOSÉE AILLEURS
    ///
    /// §6.5.2 refuse déjà une `SETTINGS_INITIAL_WINDOW_SIZE` au-delà de 2^31-1,
    /// et [`crate::Setting::check`] l'applique. Mais une structure qui GARANTIT
    /// son invariant vaut mieux qu'une qui le suppose : cette borne-ci a été
    /// écrite après qu'un fuzz eut construit une fenêtre de quatre gibioctets
    /// par un chemin qui ne passait pas par les réglages.
    #[must_use]
    pub fn new(initiale: u32) -> Self {
        Self {
            disponible: i64::from(initiale).min(WINDOW_MAX),
        }
    }

    /// Ce qui reste.
    #[must_use]
    pub const fn available(self) -> i64 {
        self.disponible
    }

    /// Consomme `octets`, ou refuse.
    ///
    /// # ON REFUSE AVANT DE CONSOMMER, JAMAIS APRÈS
    ///
    /// §6.9.1 : « A sender MUST NOT send a flow-controlled frame with a length
    /// that exceeds the space available. » Un récepteur qui soustrairait d'abord
    /// et vérifierait ensuite aurait déjà accepté les octets — et sa fenêtre
    /// dirait le contraire de ce qu'il a fait.
    ///
    /// # Errors
    ///
    /// [`Cause::WindowExceeded`], qui est une faute de `FLOW_CONTROL_ERROR`.
    pub fn consume(&mut self, octets: u32) -> Result<(), Error> {
        let demande = i64::from(octets);
        if demande > self.disponible {
            return Err(Error::connection(
                ErrorCode::FlowControlError,
                Cause::WindowExceeded,
            ));
        }
        // **`saturating_sub` NE SATURE JAMAIS ICI**, et l'on peut le dire :
        // `disponible` vit entre -(2^31-1) et 2^31-1, `demande` entre zéro et
        // 2^32-1, et la différence tient donc largement dans un `i64`. Ce n'est
        // pas une commodité — c'est l'invariant du module, tenu par les trois
        // opérations qui suivent.
        self.disponible = self.disponible.saturating_sub(demande);
        Ok(())
    }

    /// Ajoute du crédit, comme un `WINDOW_UPDATE`.
    ///
    /// # Errors
    ///
    /// [`Cause::ZeroWindowUpdate`] pour un incrément nul, que §6.9 interdit ;
    /// [`Cause::WindowOverflow`] au-delà de 2^31-1, que §6.9.1 nomme.
    pub fn increase(&mut self, credit: u32) -> Result<(), Error> {
        // §6.9 : « A receiver MUST treat the receipt of a WINDOW_UPDATE frame
        // with an increment of 0 as a stream error. » Ce n'est pas une
        // pinaillerie : un pair qui en envoie en boucle occupe la connexion
        // sans jamais rien débloquer.
        if credit == 0 {
            return Err(Error::stream(
                ErrorCode::ProtocolError,
                Cause::ZeroWindowUpdate,
            ));
        }
        let apres = self.disponible.saturating_add(i64::from(credit));
        if apres > WINDOW_MAX {
            return Err(Error::connection(
                ErrorCode::FlowControlError,
                Cause::WindowOverflow,
            ));
        }
        self.disponible = apres;
        Ok(())
    }

    /// Ajuste la fenêtre d'une variation de `SETTINGS_INITIAL_WINDOW_SIZE`
    /// (§6.9.2).
    ///
    /// **LE RÉSULTAT PEUT ÊTRE NÉGATIF**, et ce n'est pas une faute : c'est le
    /// pair qui a réduit sa fenêtre après avoir laissé envoyer. Ce qui EST une
    /// faute, c'est de dépasser 2^31-1 par le haut.
    ///
    /// # Errors
    ///
    /// [`Cause::WindowOverflow`] au-delà de 2^31-1.
    pub fn adjust(&mut self, variation: i64) -> Result<(), Error> {
        let apres = self.disponible.saturating_add(variation);
        if apres > WINDOW_MAX {
            return Err(Error::connection(
                ErrorCode::FlowControlError,
                Cause::WindowOverflow,
            ));
        }
        self.disponible = apres;
        Ok(())
    }
}

impl Default for Window {
    fn default() -> Self {
        Self::new(INITIAL_WINDOW_SIZE)
    }
}

#[cfg(test)]
mod tests;
