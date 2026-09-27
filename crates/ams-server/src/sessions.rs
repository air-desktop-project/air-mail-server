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
//! # ET L'APPAREIL EST ICI, PAS DANS LE JETON
//!
//! Loger l'identité de l'appareil dans le jeton aurait demandé un format
//! nouveau — avec sa bascule, sa transition et ses deux versions à vérifier.
//! C'est inutile : le jeton porte déjà l'identifiant qui distingue une session
//! des autres, et **c'est ce registre qui sait à quel appareil elle
//! appartient** (0.2.31). Révoquer un appareil, c'est balayer ses entrées : ses
//! jetons cessent de valoir sur-le-champ, et non à leur expiration.

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
    /// L'appareil qui l'a ouverte par sa clef, ou `None` pour une session
    /// ouverte par mot de passe.
    appareil: Option<String>,
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
    pub fn ouvrir(
        &self,
        compte: &str,
        identifiant: u64,
        expiration: u64,
        maintenant: u64,
        appareil: Option<&str>,
    ) {
        let mut table = self.ouvertes.lock().unwrap_or_else(PoisonError::into_inner);
        let siennes = table.entry(String::from(compte)).or_default();
        siennes.retain(|(_, vue)| vue.expiration > maintenant);
        // **LA PLUS ANCIENNE CÈDE.** `Vec` garde l'ordre d'insertion, donc la
        // tête est la plus vieille — pas besoin de trier pour le savoir.
        while siennes.len() >= PAR_COMPTE {
            siennes.remove(0);
        }
        siennes.push((
            identifiant,
            Vivante {
                expiration,
                appareil: appareil.map(String::from),
            },
        ));
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

    /// L'appareil qui a ouvert cette session, si c'est un appareil.
    ///
    /// `None` aussi pour une session inconnue ou périmée : il n'y a pas
    /// d'appareil à qui rattacher ce qui n'est plus ouvert.
    #[must_use]
    pub fn appareil(&self, compte: &str, identifiant: u64, maintenant: u64) -> Option<String> {
        let table = self.ouvertes.lock().unwrap_or_else(PoisonError::into_inner);
        table
            .get(compte)?
            .iter()
            .find(|(vu, vue)| *vu == identifiant && vue.expiration > maintenant)
            .and_then(|(_, vue)| vue.appareil.clone())
    }

    /// Ferme toutes les sessions qu'un appareil a ouvertes, et rend combien.
    ///
    /// **C'EST CE QUI FAIT QU'UNE RÉVOCATION RÉVOQUE** : sans cela, retirer la
    /// clef d'un téléphone volé laissait valoir ses jetons jusqu'à leur
    /// expiration — un quart d'heure pendant lequel le voleur lisait encore.
    pub fn fermer_l_appareil(&self, compte: &str, appareil: &str) -> usize {
        let mut table = self.ouvertes.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(siennes) = table.get_mut(compte) else {
            return 0;
        };
        let avant = siennes.len();
        siennes.retain(|(_, vue)| vue.appareil.as_deref() != Some(appareil));
        let fermees = avant.saturating_sub(siennes.len());
        if siennes.is_empty() {
            table.remove(compte);
        }
        fermees
    }

    /// Ferme toutes les sessions d'un compte, et rend combien.
    ///
    /// **UN COMPTE RETIRÉ NE GARDE PAS SES JETONS** : ils valaient encore jusqu'à
    /// leur expiration, pour un nom que plus rien n'authentifie — et qu'un
    /// compte recréé porterait.
    pub fn fermer_le_compte(&self, compte: &str) -> usize {
        let mut table = self.ouvertes.lock().unwrap_or_else(PoisonError::into_inner);
        table.remove(compte).map_or(0, |siennes| siennes.len())
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
