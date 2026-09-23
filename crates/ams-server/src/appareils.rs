// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le magasin d'appareils enrôlés, **modifiable pendant que le serveur sert**.
//!
//! # CE QU'IL RANGE
//!
//! Une clef publique par appareil, et ce qu'il faut pour que son propriétaire
//! sache lequel révoquer : un identifiant, un nom, deux dates. **Rien d'autre,
//! et surtout aucun identifiant matériel** — voir l'en-tête de
//! `ams_config::devices`.
//!
//! # IL N'A PAS LES MÊMES PERMISSIONS QUE CELUI DES COMPTES
//!
//! Celui des comptes porte des empreintes de mots de passe ; celui-ci ne porte
//! que des clefs **publiques**. Une fuite n'ouvre donc aucune session — elle
//! apprend seulement combien d'appareils chaque compte a. Les confondre ferait
//! traiter l'un comme l'autre, dans un sens ou dans l'autre.
//!
//! # LA MACHINERIE VIT DANS [`crate::magasin`]
//!
//! Veille du disque, verrou entre programmes, « on écrit d'abord, on publie
//! ensuite », « ce qu'on publie est ce qu'on a relu » : identiques à celles du
//! magasin de comptes, et écrites une seule fois. Ce fichier ne dit que ce qui
//! est propre aux appareils.

use std::vec::Vec;

use ams_config::Device;

use crate::magasin::{Contenu, Magasin};

pub use crate::magasin::Faute;

/// Comment nommer un appareil qu'on ne trouve pas.
pub const INTROUVABLE: Faute = Faute::Introuvable(DesAppareils::INTROUVABLE);

/// Ce qui distingue le magasin d'appareils de tout autre.
#[derive(Debug)]
pub struct DesAppareils;

impl Contenu for DesAppareils {
    type Element = Device;

    const INTROUVABLE: &'static str = "cet appareil";

    fn lire(octets: &[u8]) -> Result<Vec<Device>, ams_config::Error> {
        ams_config::decode_devices(octets)
    }

    fn ecrire(appareils: &[Device]) -> Result<Vec<u8>, ams_config::Error> {
        ams_config::encode_devices(appareils)
    }
}

/// Les appareils enrôlés, et le fichier dont ils sont la vue.
pub type Appareils = Magasin<DesAppareils>;

impl Appareils {
    /// Les appareils de ce compte, dans l'ordre du magasin.
    ///
    /// **ELLE REND DES COPIES**, et non des références : la vue est un
    /// instantané qu'on relâche en sortant, et rendre des emprunts dessus
    /// obligerait l'appelant à le tenir ouvert pendant qu'il travaille.
    ///
    /// Un compte sans appareil rend une liste vide. **Ce n'est pas une erreur** :
    /// c'est l'état de tout compte avant son premier enrôlement, et le confondre
    /// avec « ce compte n'existe pas » ferait répondre 404 à qui vient
    /// précisément enrôler.
    #[must_use]
    pub fn du_compte(&self, login: &str) -> Vec<Device> {
        self.vue()
            .iter()
            .filter(|appareil| appareil.login == login)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests;
