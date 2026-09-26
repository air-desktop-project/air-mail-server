// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le magasin des mots de passe applicatifs, **modifiable pendant que le
//! serveur sert**.
//!
//! Voir `ams_auth::AppPassword` pour ce qu'ils sont, et pourquoi le serveur les
//! tire lui-même. La machinerie — veille du disque, verrou entre programmes,
//! « on écrit d'abord, on publie ensuite » — vit dans [`crate::magasin`] ; ce
//! fichier ne dit que ce qui leur est propre.

use std::vec::Vec;

use ams_auth::AppPassword;

use crate::magasin::{Contenu, Magasin};

pub use crate::magasin::Faute;

/// Comment nommer un mot de passe applicatif qu'on ne trouve pas.
pub const INTROUVABLE: Faute = Faute::Introuvable(DesApplicatifs::INTROUVABLE);

/// Tous les combien la date de dernière utilisation se réécrit, en secondes.
///
/// **UNE HEURE** : l'écrire à chaque ouverture de session ferait une écriture
/// disque par relève de courrier, et un client qui relève toutes les minutes
/// réécrirait le fichier soixante fois par heure pour ne rien apprendre à
/// personne. Ce que son propriétaire veut savoir est « ce client sert-il
/// encore ? », et l'heure y répond.
pub const PRECISION_SECONDES: u64 = 3_600;

/// Ce qui distingue ce magasin de tout autre.
#[derive(Debug)]
pub struct DesApplicatifs;

impl Contenu for DesApplicatifs {
    type Element = AppPassword;

    const INTROUVABLE: &'static str = "ce mot de passe applicatif";

    fn lire(octets: &[u8]) -> Result<Vec<AppPassword>, ams_config::Error> {
        ams_config::decode_app_passwords(octets)
    }

    fn ecrire(entrees: &[AppPassword]) -> Result<Vec<u8>, ams_config::Error> {
        ams_config::encode_app_passwords(entrees)
    }
}

/// Les mots de passe applicatifs, et le fichier dont ils sont la vue.
pub type Applicatifs = Magasin<DesApplicatifs>;

impl Applicatifs {
    /// Les mots de passe applicatifs de ce compte, dans l'ordre du magasin.
    ///
    /// Des copies, comme pour les appareils : la vue est un instantané qu'on
    /// relâche en sortant.
    #[must_use]
    pub fn du_compte(&self, login: &str) -> Vec<AppPassword> {
        self.vue()
            .iter()
            .filter(|entree| entree.login == login)
            .cloned()
            .collect()
    }

    /// Note qu'un mot de passe applicatif vient de servir — **au plus une fois
    /// par [`PRECISION_SECONDES`]**.
    ///
    /// # UN ÉCHEC D'ÉCRITURE NE REFUSE PAS LA SESSION
    ///
    /// C'est l'inverse du défi d'un appareil, dont la date EST l'usage unique :
    /// ici, la date n'informe que son propriétaire. Refuser une relève de
    /// courrier parce que le disque tousse punirait l'utilisateur pour une
    /// statistique. L'échec se dit dans le journal, et la session s'ouvre.
    pub fn noter_l_usage(&self, id: &str, maintenant: u64) {
        let recente = self.vue().iter().any(|entree| {
            entree.id == id && entree.last_used.saturating_add(PRECISION_SECONDES) > maintenant
        });
        if recente {
            return;
        }
        if let Err(quoi) = self.modifier(|entrees| {
            let entree = entrees
                .iter_mut()
                .find(|entree| entree.id == id)
                .ok_or(INTROUVABLE)?;
            entree.last_used = maintenant;
            Ok(())
        }) {
            eprintln!(
                "air-mail-server : mots de passe applicatifs — la dernière utilisation de \
                 `{id}` ne s'écrit pas ({quoi}) ; la session s'ouvre quand même"
            );
        }
    }
}

#[cfg(test)]
mod tests;
