// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le magasin des délégations, **consulté à chaque requête** et modifiable
//! pendant que le serveur sert.
//!
//! Voir `ams_config::Delegation`. La machinerie — veille du disque, verrou,
//! « on écrit d'abord, on publie ensuite » — vit dans [`crate::magasin`].

use std::vec::Vec;

use ams_config::{Delegation, Rights};

use crate::magasin::{Contenu, Magasin};

pub use crate::magasin::Faute;

/// Comment nommer une délégation qu'on ne trouve pas.
pub const INTROUVABLE: Faute = Faute::Introuvable(DesDelegations::INTROUVABLE);

/// Ce qui distingue ce magasin de tout autre.
#[derive(Debug)]
pub struct DesDelegations;

impl Contenu for DesDelegations {
    type Element = Delegation;

    const INTROUVABLE: &'static str = "cette délégation";

    fn lire(octets: &[u8]) -> Result<Vec<Delegation>, ams_config::Error> {
        ams_config::decode_delegations(octets)
    }

    fn ecrire(tenues: &[Delegation]) -> Result<Vec<u8>, ams_config::Error> {
        ams_config::encode_delegations(tenues)
    }
}

/// Les délégations, et le fichier dont elles sont la vue.
pub type Delegations = Magasin<DesDelegations>;

impl Delegations {
    /// Les droits que `delegue` tient sur la boîte de `titulaire`, s'il en
    /// tient.
    #[must_use]
    pub fn droits(&self, delegue: &str, titulaire: &str) -> Option<Rights> {
        self.vue()
            .iter()
            .find(|tenue| tenue.delegate == delegue && tenue.owner == titulaire)
            .map(|tenue| tenue.rights)
    }

    /// Les délégations qu'un compte a reçues.
    #[must_use]
    pub fn recues_par(&self, delegue: &str) -> Vec<Delegation> {
        self.vue()
            .iter()
            .filter(|tenue| tenue.delegate == delegue)
            .cloned()
            .collect()
    }

    /// Les délégations qu'un titulaire a accordées.
    #[must_use]
    pub fn accordees_par(&self, titulaire: &str) -> Vec<Delegation> {
        self.vue()
            .iter()
            .filter(|tenue| tenue.owner == titulaire)
            .cloned()
            .collect()
    }
}
