// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le débit de chaque appareil sur l'API REST, une fois authentifié.
//!
//! # PAR APPAREIL, ET NON PAR ADRESSE (phase 6)
//!
//! Le videur compte par source, et c'est juste pour ce qui arrive sans jeton.
//! Une requête authentifiée dit qui elle est : c'est son APPAREIL qui a un
//! débit. Des milliers d'abonnés mobiles derrière une seule adresse IPv4 n'ont
//! pas à se partager le leur, et un téléphone qui change d'antenne ne change pas
//! de seau.
//!
//! **LES SESSIONS PAR MOT DE PASSE PARTAGENT CELUI DE LEUR COMPTE.** Elles
//! n'ont pas d'appareil, et en ouvrir une de plus ne doit pas donner un seau de
//! plus : ce serait une rafale neuve à chaque connexion.
//!
//! # UN SEAU SURVIT À SES SESSIONS
//!
//! Il ne s'oublie que PLEIN — un seau neuf serait le même. L'oublier à la
//! fermeture de sa session permettrait de retrouver sa rafale en se
//! reconnectant, ce que le débit existe pour empêcher.
//!
//! # SA MÉMOIRE EST BORNÉE PAR CE QUI EST AUTHENTIFIÉ
//!
//! Une entrée ne naît que d'une requête dont le jeton a été vérifié et dont la
//! session est vivante : au plus un seau par appareil enrôlé, plus un par
//! compte. Un inconnu ne peut pas la faire grandir.

use std::collections::BTreeMap;
use std::string::String;
use std::sync::{Mutex, PoisonError};

use ams_guard::{Bucket, Instant, Rate};

/// Le seau d'un appareil — ou d'un compte, pour ses sessions par mot de passe.
type Clef = (String, Option<String>);

/// Les seaux, et ce qu'ils ont refusé.
#[derive(Debug)]
pub struct Debits {
    /// Le débit de chaque seau.
    debit: Rate,
    /// Ce qui change, sous un seul verrou.
    etat: Mutex<Etat>,
}

#[derive(Debug, Default)]
struct Etat {
    /// Les seaux entamés.
    seaux: BTreeMap<Clef, Bucket>,
    /// Par compte, combien de requêtes ont été refusées depuis le démarrage.
    refus: BTreeMap<String, u64>,
}

impl Debits {
    /// Des seaux à ce débit. Chaque zéro y prend la valeur de départ.
    #[must_use]
    pub fn new(debit: Rate) -> Self {
        Self {
            debit: debit.or_default(),
            etat: Mutex::new(Etat::default()),
        }
    }

    /// Le débit appliqué.
    #[cfg(test)]
    #[must_use]
    pub const fn debit(&self) -> Rate {
        self.debit
    }

    /// Prend un jeton au seau de cet appareil. `false` : la requête se refuse.
    ///
    /// `maintenant` est en microsecondes depuis l'époque, comme partout dans la
    /// chaîne HTTP.
    pub fn prendre(&self, compte: &str, appareil: Option<&str>, maintenant: u64) -> bool {
        let instant = Instant::from_millis(maintenant / 1000);
        let debit = self.debit;
        let mut etat = self.etat.lock().unwrap_or_else(PoisonError::into_inner);
        let clef = (String::from(compte), appareil.map(String::from));
        if !etat.seaux.contains_key(&clef) {
            // **LA PURGE A LIEU À LA NAISSANCE D'UN SEAU**, et nulle part
            // ailleurs : c'est le seul moment où la table grandit. Un seau
            // plein s'oublie sans rien rendre à personne.
            etat.seaux.retain(|_, seau| !seau.is_full(debit, instant));
        }
        let pris = etat
            .seaux
            .entry(clef)
            .or_insert_with(|| Bucket::full(debit, instant))
            .take(debit, instant);
        if !pris {
            let refus = etat.refus.entry(String::from(compte)).or_default();
            *refus = refus.saturating_add(1);
        }
        pris
    }

    /// Combien de requêtes de ce compte ont été refusées depuis le démarrage.
    #[must_use]
    pub fn refusees(&self, compte: &str) -> u64 {
        let etat = self.etat.lock().unwrap_or_else(PoisonError::into_inner);
        etat.refus.get(compte).copied().unwrap_or(0)
    }

    /// Oublie tout ce qui touche à ce compte.
    ///
    /// **UN COMPTE RECRÉÉ SOUS CE NOM N'HÉRITE NI DES SEAUX NI DES REFUS** de
    /// l'ancien, comme il n'hérite pas de ses sessions.
    pub fn oublier(&self, compte: &str) {
        let mut etat = self.etat.lock().unwrap_or_else(PoisonError::into_inner);
        etat.seaux.retain(|(vu, _), _| vu != compte);
        etat.refus.remove(compte);
    }

    /// Combien de seaux sont retenus.
    #[cfg(test)]
    fn retenus(&self) -> usize {
        let etat = self.etat.lock().unwrap_or_else(PoisonError::into_inner);
        etat.seaux.len()
    }
}

#[cfg(test)]
mod tests;
