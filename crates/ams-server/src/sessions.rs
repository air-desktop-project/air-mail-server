// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les sessions ouvertes, et le seul endroit où l'on peut les fermer.
//!
//! # POURQUOI UNE LISTE D'AUTORISATION, ET NON UNE LISTE DE REFUS
//!
//! Un jeton se vérifie sans rien consulter : c'est ce qui le rend rapide, et
//! c'est ce qui le rendait irrévocable. Pour le révoquer, il faut consulter
//! quelque chose — et il y a deux façons de le faire, qui ne tombent pas du
//! même côté quand le serveur redémarre.
//!
//! Une liste de REFUS retient les jetons révoqués. Un redémarrage la perd, et
//! **les jetons qu'on avait voulu tuer redeviennent valides** — sans que
//! personne ne s'en aperçoive. La panne est OUVERTE.
//!
//! Une liste d'AUTORISATION retient les sessions vivantes. Un redémarrage la
//! perd aussi, et **tout le monde doit se réauthentifier**. La panne est
//! FERMÉE, et c'est le seul argument qui compte : une révocation qu'on croit
//! faite et qui ne l'est pas est pire qu'une reconnexion.
//!
//! Le coût est mince : des jetons d'un quart d'heure, [`PAR_COMPTE`] au plus
//! par compte.
//!
//! # ELLE NE REMPLACE PAS LA VÉRIFICATION DU SCEAU, ELLE LA SUIT
//!
//! On ne consulte ce registre que pour un jeton DÉJÀ authentifié. Le consulter
//! avant reviendrait à laisser un inconnu faire chercher dans notre table avec
//! des octets qu'il a choisis.
//!
//! # ET L'APPAREIL VIENDRA ICI, PAS DANS LE JETON
//!
//! Quand les appareils s'enrôleront, il aurait fallu un format de jeton nouveau
//! pour y loger leur identité — avec sa bascule, sa transition et ses deux
//! versions à vérifier. Ce sera inutile : le jeton porte déjà l'identifiant qui
//! distingue une session des autres, et **c'est ce registre qui saura à quel
//! appareil elle appartient**. Révoquer un appareil sera balayer ses entrées.
//!
//! **RIEN N'EST ÉCRIT D'AVANCE POUR AUTANT** : le champ viendra avec son
//! appelant, et pas avant. Du code que personne n'appelle est du code que
//! personne n'éprouve.

use std::collections::BTreeMap;
use std::string::String;
use std::sync::{Mutex, PoisonError};
use std::vec::Vec;

/// Combien de sessions un compte peut tenir ouvertes à la fois.
///
/// # POURQUOI UN PLAFOND, ET POURQUOI CELUI-LÀ
///
/// Sans plafond, un compte dont le mot de passe a fuité laisse grandir cette
/// table à chaque ouverture — et la mémoire du serveur devient ce qu'un pair
/// décide. Vingt-quatre laisse la place à un téléphone, une tablette, deux
/// postes et leurs renouvellements, sans qu'un compte ordinaire s'en aperçoive.
///
/// **LA PLUS ANCIENNE CÈDE**, et non la nouvelle : refuser l'ouverture
/// enfermerait dehors quelqu'un qui a ses identifiants, ce qui est exactement
/// ce qu'un attaquant chercherait à provoquer.
pub const PAR_COMPTE: usize = 24;

/// Ce qu'on retient d'une session.
#[derive(Debug, Clone)]
struct Vivante {
    /// Quand elle cesse de valoir, en microsecondes depuis l'époque.
    expiration: u64,
}

/// Les sessions ouvertes, tous comptes confondus.
///
/// **UN SEUL VERROU**, et il est pris le temps d'une consultation : la table
/// compte quelques centaines d'entrées au plus, et un verrou par compte
/// coûterait plus en complexité qu'il ne rendrait en contention.
#[derive(Debug, Default)]
pub struct Sessions {
    /// Par compte, les identifiants de ses sessions vivantes.
    ouvertes: Mutex<BTreeMap<String, Vec<(u64, Vivante)>>>,
}

impl Sessions {
    /// Un registre vide.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Ouvre une session, et rend ce que le compte en tient désormais.
    ///
    /// **LA PURGE A LIEU ICI**, et nulle part ailleurs : un registre qui
    /// n'oublierait qu'à la lecture garderait la mémoire d'un compte qui ne se
    /// connecte plus. L'insertion est le seul moment où l'on sait qu'il vit.
    pub fn ouvrir(&self, compte: &str, identifiant: u64, expiration: u64, maintenant: u64) {
        let mut table = self.ouvertes.lock().unwrap_or_else(PoisonError::into_inner);
        let siennes = table.entry(String::from(compte)).or_default();
        siennes.retain(|(_, vue)| vue.expiration > maintenant);
        // **LA PLUS ANCIENNE CÈDE.** `Vec` garde l'ordre d'insertion, donc la
        // tête est la plus vieille — pas besoin de trier pour le savoir.
        while siennes.len() >= PAR_COMPTE {
            siennes.remove(0);
        }
        siennes.push((identifiant, Vivante { expiration }));
    }

    /// Cette session est-elle ouverte ?
    ///
    /// **L'EXPIRATION SE REVÉRIFIE ICI**, bien que le jeton la porte et que sa
    /// vérification l'ait déjà lue : une entrée périmée que personne n'a purgée
    /// ne doit pas ouvrir une porte que le jeton fermait.
    #[must_use]
    pub fn ouverte(&self, compte: &str, identifiant: u64, maintenant: u64) -> bool {
        let table = self.ouvertes.lock().unwrap_or_else(PoisonError::into_inner);
        table.get(compte).is_some_and(|siennes| {
            siennes
                .iter()
                .any(|(vu, vue)| *vu == identifiant && vue.expiration > maintenant)
        })
    }

    /// Ferme une session. Rend `true` si elle était ouverte.
    ///
    /// **FERMER CE QUI EST DÉJÀ FERMÉ N'EST PAS UNE FAUTE** — c'est l'état
    /// demandé —, mais l'appelant a le droit de savoir s'il a fait quelque
    /// chose : un client qui se déconnecte deux fois ne doit pas croire la
    /// seconde aussi efficace que la première.
    pub fn fermer(&self, compte: &str, identifiant: u64) -> bool {
        let mut table = self.ouvertes.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(siennes) = table.get_mut(compte) else {
            return false;
        };
        let avant = siennes.len();
        siennes.retain(|(vu, _)| *vu != identifiant);
        let ferme = siennes.len() != avant;
        // **UN COMPTE SANS SESSION NE LAISSE PAS D'ENTRÉE.** Sans cela, la table
        // retiendrait le nom de tous les comptes s'étant connectés un jour.
        if siennes.is_empty() {
            table.remove(compte);
        }
        ferme
    }

    /// Combien de sessions ce compte tient ouvertes.
    #[must_use]
    pub fn combien(&self, compte: &str, maintenant: u64) -> usize {
        let table = self.ouvertes.lock().unwrap_or_else(PoisonError::into_inner);
        table.get(compte).map_or(0, |siennes| {
            siennes
                .iter()
                .filter(|(_, vue)| vue.expiration > maintenant)
                .count()
        })
    }
}

#[cfg(test)]
mod tests;
