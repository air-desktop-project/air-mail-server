// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les réglages d'HTTP/3 (RFC 9114 §7.2.4).
//!
//! # TROIS RÉGLAGES, ET DES TRAPPES POUR LES AUTRES
//!
//! HTTP/2 en avait six ; HTTP/3 n'en garde que ce que QUIC ne fait pas déjà. Le
//! contrôle de flux, la taille de cadre, le nombre de flux simultanés : tout
//! cela est descendu dans le transport, et n'a plus à être négocié ici.
//!
//! Ce qui reste tient à QPACK — sa table et ce qu'on accepte de bloquer — et à
//! la taille des en-têtes.
//!
//! # ET LES QUATRE IDENTIFIANTS D'HTTP/2 SONT UNE FAUTE
//!
//! §11.2.2 réserve 0x02, 0x03, 0x04 et 0x05 — ceux qu'HTTP/2 donnait à
//! `ENABLE_PUSH`, `MAX_CONCURRENT_STREAMS`, `INITIAL_WINDOW_SIZE` et
//! `MAX_FRAME_SIZE`. Les recevoir n'est pas un réglage inconnu qu'on ignore :
//! c'est un pair qui croit parler HTTP/2, et **ce qu'il croit avoir négocié ne
//! sera pas ce qu'on a compris**.

use ams_proto_quic::varints;

use crate::error::{Error, Reason};

/// Ce qu'on accepte d'en-têtes décomprimés, en octets.
///
/// Seize kibioctets, la même borne qu'en HTTP/2 : c'est ce qu'une bombe de
/// décompression a de mieux à franchir, et QPACK comprime comme HPACK.
pub const DEFAULT_MAX_FIELD_SECTION_SIZE: u64 = 16 * 1024;

/// Les réglages en vigueur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// La table dynamique QPACK que le pair accepte de tenir, en octets.
    ///
    /// **ZÉRO EST LA VALEUR PAR DÉFAUT**, et ce n'est pas rien : sans annonce,
    /// aucune table dynamique n'existe, et l'encodeur ne peut employer que la
    /// table statique. C'est le contraire d'HPACK, dont la table faisait quatre
    /// kibioctets d'office.
    pub qpack_max_table_capacity: u64,
    /// Combien de flux le pair accepte de voir bloqués sur la table.
    ///
    /// **ZÉRO PAR DÉFAUT, ET C'EST TOUT L'INTÉRÊT DE QPACK** : un flux bloqué
    /// attend une insertion qu'un autre flux n'a pas encore livrée. Zéro veut
    /// dire « ne me fais jamais attendre » — et c'est ce qui rend QPACK
    /// utilisable sur un transport qui livre dans le désordre.
    pub qpack_blocked_streams: u64,
    /// Ce que le pair accepte d'en-têtes décomprimés.
    ///
    /// `None` : il n'a rien dit, et **cela ne veut pas dire « sans limite »
    /// chez nous** — c'est un renseignement, pas une garde. La borne qui
    /// protège est celle qu'on applique en décodant.
    pub max_field_section_size: Option<u64>,
}

impl Default for Settings {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl Settings {
    /// Les réglages qui valent AVANT toute annonce (§7.2.4.1).
    pub const DEFAULT: Self = Self {
        qpack_max_table_capacity: 0,
        qpack_blocked_streams: 0,
        max_field_section_size: None,
    };

    /// Les identifiants que §11.2.2 réserve pour écarter HTTP/2.
    pub const RESERVES_PAR_HTTP2: [u64; 4] = [0x02, 0x03, 0x04, 0x05];

    /// Lit la charge d'une trame `SETTINGS`.
    ///
    /// # Errors
    ///
    /// [`Reason::Truncated`] ; [`Reason::BadSetting`] pour un identifiant
    /// réservé ou répété.
    pub fn read(charge: &[u8]) -> Result<Self, Error> {
        let tronque = || Error::new(Reason::Truncated);
        let faute = || Error::new(Reason::BadSetting);
        let mut lus = Self::DEFAULT;
        // Un bit par réglage connu : trois suffisent, et le compte tient dans
        // un `u8`. Répéter un réglage est une faute (§7.2.4).
        let mut vus = 0_u8;
        let mut reste = charge;
        while !reste.is_empty() {
            let (identifiant, avance) = varints::decode(reste).map_err(|_| tronque())?;
            reste = reste.get(avance..).unwrap_or_default();
            let (valeur, avance) = varints::decode(reste).map_err(|_| tronque())?;
            reste = reste.get(avance..).unwrap_or_default();
            if Self::RESERVES_PAR_HTTP2.contains(&identifiant) {
                return Err(faute());
            }
            let bit = match identifiant {
                0x01 => 0b001_u8,
                0x06 => 0b010,
                0x07 => 0b100,
                // §7.2.4.1 : CE QU'ON NE CONNAÎT PAS S'IGNORE, y compris les
                // réglages de graissage que §7.2.4.1 demande d'envoyer.
                _ => continue,
            };
            if vus & bit != 0 {
                return Err(faute());
            }
            vus |= bit;
            match identifiant {
                0x01 => lus.qpack_max_table_capacity = valeur,
                0x06 => lus.max_field_section_size = Some(valeur),
                // Il ne reste que 0x07 : le classement ci-dessus est total.
                _ => lus.qpack_blocked_streams = valeur,
            }
        }
        Ok(lus)
    }

    /// Écrit ces réglages sous la forme d'une charge de `SETTINGS`.
    ///
    /// # Errors
    ///
    /// [`Reason::BufferTooSmall`] si `out` ne suffit pas.
    pub fn write(&self, out: &mut [u8]) -> Result<usize, Error> {
        let court = || Error::new(Reason::BufferTooSmall);
        let mut ecrits = 0_usize;
        let mut poser = |identifiant: u64, valeur: u64| -> Result<(), Error> {
            for nombre in [identifiant, valeur] {
                // `ecrits` ne dépasse jamais ce qu'on a écrit : la tranche
                // existe toujours, fût-elle vide. `unwrap_or_default` porte cela
                // dans la bibliothèque — et si elle est vide, c'est l'écriture
                // qui dira que la place manque.
                let place = out.get_mut(ecrits..).unwrap_or_default();
                let poses = varints::encode(nombre, place).map_err(|_| court())?;
                ecrits = ecrits.saturating_add(poses);
            }
            Ok(())
        };
        poser(0x01, self.qpack_max_table_capacity)?;
        poser(0x07, self.qpack_blocked_streams)?;
        if let Some(taille) = self.max_field_section_size {
            poser(0x06, taille)?;
        }
        Ok(ecrits)
    }
}

#[cfg(test)]
mod tests;
