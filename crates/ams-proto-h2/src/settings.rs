// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les réglages de la connexion (§6.5.2).
//!
//! # ON IGNORE CE QU'ON NE CONNAÎT PAS, ON REFUSE CE QU'ON CONNAÎT ET QUI EST
//! FAUX
//!
//! §6.5.2 : « An endpoint that receives a SETTINGS frame with any unknown or
//! unsupported identifier MUST ignore that setting. » Un identifiant inconnu
//! s'ignore donc — c'est ce qui permet aux extensions d'exister. Mais un
//! `SETTINGS_MAX_FRAME_SIZE` à quarante-deux se refuse : on sait ce qu'il veut
//! dire, et ce qu'il dit est hors de la plage que la RFC définit.
//!
//! La distinction se paie quand on l'oublie, dans les deux sens : refuser
//! l'inconnu rend toute évolution impossible, ignorer le faux fait fonctionner
//! une connexion sur un réglage qu'on n'a pas retenu.

use crate::error::{Cause, Error, ErrorCode};

/// Ce qu'une entrée de `SETTINGS` occupe : deux octets d'identifiant, quatre de
/// valeur.
pub const SETTINGS_ENTRY_OCTETS: usize = 6;

/// Un réglage connu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Setting {
    /// `SETTINGS_HEADER_TABLE_SIZE` (0x1) — la table dynamique HPACK.
    HeaderTableSize,
    /// `SETTINGS_ENABLE_PUSH` (0x2).
    ///
    /// **DÉPRÉCIÉ** par §8.4. Ce serveur annonce zéro, et n'émet jamais de
    /// `PUSH_PROMISE`.
    EnablePush,
    /// `SETTINGS_MAX_CONCURRENT_STREAMS` (0x3).
    MaxConcurrentStreams,
    /// `SETTINGS_INITIAL_WINDOW_SIZE` (0x4).
    InitialWindowSize,
    /// `SETTINGS_MAX_FRAME_SIZE` (0x5).
    MaxFrameSize,
    /// `SETTINGS_MAX_HEADER_LIST_SIZE` (0x6).
    ///
    /// **C'EST UN RENSEIGNEMENT, PAS UNE GARDE** : rien n'oblige le pair à le
    /// respecter. La borne qui protège est celle qu'on applique en décodant.
    MaxHeaderListSize,
}

impl Setting {
    /// Lit un identifiant. `None` pour ce qu'on ne connaît pas — et ce qu'on ne
    /// connaît pas s'ignore.
    #[must_use]
    pub const fn from_wire(identifiant: u16) -> Option<Self> {
        match identifiant {
            0x1 => Some(Self::HeaderTableSize),
            0x2 => Some(Self::EnablePush),
            0x3 => Some(Self::MaxConcurrentStreams),
            0x4 => Some(Self::InitialWindowSize),
            0x5 => Some(Self::MaxFrameSize),
            0x6 => Some(Self::MaxHeaderListSize),
            _ => None,
        }
    }

    /// L'identifiant sur le fil.
    #[must_use]
    pub const fn value(self) -> u16 {
        match self {
            Self::HeaderTableSize => 0x1,
            Self::EnablePush => 0x2,
            Self::MaxConcurrentStreams => 0x3,
            Self::InitialWindowSize => 0x4,
            Self::MaxFrameSize => 0x5,
            Self::MaxHeaderListSize => 0x6,
        }
    }

    /// Cette valeur est-elle dans la plage que §6.5.2 définit ?
    ///
    /// # Errors
    ///
    /// [`Cause::SettingValueOutOfRange`], avec le code que la RFC nomme pour
    /// chacun : `FLOW_CONTROL_ERROR` pour la fenêtre, `PROTOCOL_ERROR` sinon.
    pub const fn check(self, valeur: u32) -> Result<(), Error> {
        let (recevable, code) = match self {
            // §6.5.2 : « Any value other than 0 or 1 MUST be treated as a
            // connection error of type PROTOCOL_ERROR. »
            Self::EnablePush => (valeur <= 1, ErrorCode::ProtocolError),
            // §6.5.2 : au-delà de 2^31-1, `FLOW_CONTROL_ERROR`.
            Self::InitialWindowSize => (valeur <= 0x7fff_ffff, ErrorCode::FlowControlError),
            // §6.5.2 : entre 2^14 et 2^24-1 inclus.
            Self::MaxFrameSize => (
                valeur >= 16_384 && valeur <= 16_777_215,
                ErrorCode::ProtocolError,
            ),
            // Les trois autres acceptent tout `u32`.
            Self::HeaderTableSize | Self::MaxConcurrentStreams | Self::MaxHeaderListSize => {
                (true, ErrorCode::ProtocolError)
            }
        };
        match recevable {
            true => Ok(()),
            false => Err(Error::connection(code, Cause::SettingValueOutOfRange)),
        }
    }
}

/// Les réglages en vigueur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// La table dynamique HPACK.
    pub header_table_size: u32,
    /// La poussée serveur, dépréciée.
    pub enable_push: bool,
    /// Combien de flux le pair accepte de front. `None` : il n'a rien dit.
    pub max_concurrent_streams: Option<u32>,
    /// La fenêtre initiale de chaque flux.
    pub initial_window_size: u32,
    /// La plus grande charge de cadre acceptée.
    pub max_frame_size: u32,
    /// Ce que le pair veut bien recevoir d'en-têtes. `None` : il n'a rien dit.
    pub max_header_list_size: Option<u32>,
}

impl Settings {
    /// Les valeurs par défaut de §6.5.2, celles qui valent AVANT tout `SETTINGS`.
    ///
    /// **ELLES VALENT DÈS LE PREMIER OCTET** : un pair peut envoyer des cadres
    /// avant que son `SETTINGS` n'arrive, et les juger sur des valeurs qu'on
    /// n'aurait pas encore posées reviendrait à ne pas les juger.
    pub const DEFAULT: Self = Self {
        header_table_size: 4_096,
        enable_push: true,
        max_concurrent_streams: None,
        initial_window_size: 65_535,
        max_frame_size: 16_384,
        max_header_list_size: None,
    };

    /// Applique un réglage lu.
    fn apply(&mut self, reglage: Setting, valeur: u32) {
        match reglage {
            Setting::HeaderTableSize => self.header_table_size = valeur,
            Setting::EnablePush => self.enable_push = valeur != 0,
            Setting::MaxConcurrentStreams => self.max_concurrent_streams = Some(valeur),
            Setting::InitialWindowSize => self.initial_window_size = valeur,
            Setting::MaxFrameSize => self.max_frame_size = valeur,
            Setting::MaxHeaderListSize => self.max_header_list_size = Some(valeur),
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Lit les entrées d'un cadre `SETTINGS`.
#[derive(Debug, Clone, Copy)]
pub struct SettingsReader;

impl SettingsReader {
    /// Applique toutes les entrées d'une charge de `SETTINGS`.
    ///
    /// La longueur a déjà été vérifiée multiple de six par
    /// [`crate::FrameHeader::check`] ; ce qui reste ici, ce sont les valeurs.
    ///
    /// # LA DERNIÈRE VALEUR GAGNE
    ///
    /// §6.5 : « The values in the SETTINGS frame MUST be processed in the order
    /// they appear, with no other frame processing between values. » Un
    /// identifiant répété n'est donc pas une faute — c'est un réglage posé deux
    /// fois, et c'est le second qui vaut.
    ///
    /// # Errors
    ///
    /// [`Cause::SettingValueOutOfRange`] pour un réglage CONNU dont la valeur
    /// est hors plage. Un identifiant inconnu s'ignore.
    pub fn apply_all(charge: &[u8], vers: &mut Settings) -> Result<(), Error> {
        // `as_chunks` PLUTÔT QUE `chunks_exact` : il rend des TABLEAUX de six,
        // et non des tranches dont il faudrait rouvrir la longueur. Ce qui
        // dépasse est écarté par la même occasion — mais la longueur a déjà été
        // vérifiée multiple de six, et le reste est donc toujours vide.
        let (entrees, _) = charge.as_chunks::<SETTINGS_ENTRY_OCTETS>();
        for entree in entrees {
            let identifiant = u16::from_be_bytes([entree[0], entree[1]]);
            let valeur = u32::from_be_bytes([entree[2], entree[3], entree[4], entree[5]]);
            let Some(reglage) = Setting::from_wire(identifiant) else {
                continue;
            };
            reglage.check(valeur)?;
            vers.apply(reglage, valeur);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
