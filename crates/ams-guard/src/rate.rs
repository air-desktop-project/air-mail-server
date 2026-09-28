// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le débit d'un appareil : un seau de jetons.
//!
//! # POURQUOI PAR APPAREIL, ET NON PAR ADRESSE
//!
//! Le [`Guard`](crate::Guard) compte par source, et c'est juste pour ce qui
//! arrive SANS jeton : on ne sait rien d'autre de qui frappe. Une requête
//! authentifiée, elle, dit qui elle est — et l'adresse devient le plus mauvais
//! des indices. Un opérateur mobile met des milliers d'abonnés derrière une
//! seule adresse IPv4 : les compter ensemble punirait des voisins, et un
//! téléphone qui change d'antenne changerait de compteur.
//!
//! # UN SEAU, ET NON UNE FENÊTRE
//!
//! Une fenêtre fixe laisse passer deux fois le seuil à cheval sur sa frontière,
//! et coupe net ensuite. Un seau laisse une RAFALE — l'ouverture d'une
//! application, qui relit ses boîtes d'un coup — puis un débit soutenu. C'est la
//! forme de l'usage d'un client de messagerie.
//!
//! Comme le garde, **le seau ne lit jamais l'heure** (C1) : on la lui donne.

use crate::Instant;

/// Ce qu'un appareil peut demander.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    /// La rafale : combien de requêtes un seau plein laisse passer d'un coup.
    pub burst: u32,
    /// Le débit soutenu : combien de jetons reviennent par seconde.
    ///
    /// **AU MOINS UN**, et c'est ce qui permet au refus de dire `Retry-After: 1`
    /// sans calcul : un seau vide a toujours retrouvé un jeton une seconde plus
    /// tard.
    pub per_second: u32,
}

impl Rate {
    /// Le débit de départ.
    ///
    /// **Aucune RFC ne le fixe.** Six cents requêtes d'un coup couvrent la
    /// première synchronisation d'une boîte chargée ; vingt par seconde, un
    /// client qui relit une page de messages et leurs pièces. Un seuil trop
    /// serré se remarque comme une application lente, et on ne le soupçonne
    /// pas : c'est pourquoi celui-ci est généreux.
    pub const DEFAULT: Self = Self {
        burst: 600,
        per_second: 20,
    };

    /// Ce débit, où chaque ZÉRO prend la valeur de départ.
    ///
    /// **UN FICHIER ÉCRIT AVANT CE RÉGLAGE DÉCODE DEUX ZÉROS**, et deux zéros
    /// voudraient dire « rien ne passe » : le serveur refuserait tout. Prendre
    /// le défaut rend le réglage ajoutable sans rien casser, et le limiteur n'a
    /// pas d'interrupteur — un appareil sans limite est ce que cette tranche
    /// retire.
    #[must_use]
    pub const fn or_default(self) -> Self {
        Self {
            burst: match self.burst {
                0 => Self::DEFAULT.burst,
                n => n,
            },
            per_second: match self.per_second {
                0 => Self::DEFAULT.per_second,
                n => n,
            },
        }
    }

    /// La contenance du seau, en millièmes de jeton.
    fn capacity(self) -> u64 {
        u64::from(self.burst).saturating_mul(MILLI)
    }
}

impl Default for Rate {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Mille millièmes font un jeton.
///
/// **LE SEAU COMPTE EN MILLIÈMES** : `per_second` jetons par seconde font
/// exactement `per_second` millièmes par milliseconde. Compter en jetons
/// entiers perdrait le retour d'une requête espacée de moins d'un
/// cinquantième de seconde — et à vingt par seconde, c'est toutes.
const MILLI: u64 = 1000;

/// Le seau d'un appareil.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bucket {
    /// Ce qu'il contient, en millièmes de jeton.
    milli: u64,
    /// Le dernier instant où on l'a rempli.
    last: Instant,
}

impl Bucket {
    /// Un seau plein : un appareil qu'on n'a jamais vu a droit à sa rafale.
    #[must_use]
    pub fn full(rate: Rate, now: Instant) -> Self {
        Self {
            milli: rate.capacity(),
            last: now,
        }
    }

    /// Prend un jeton. Rend `false` si le seau est vide — la requête se refuse.
    ///
    /// **UNE HORLOGE QUI RECULE NE REMPLIT RIEN**, et ne recule pas le seau :
    /// l'instant retenu reste le plus tardif. Sans cela, un recul suivi d'une
    /// avance compterait deux fois le même temps.
    pub fn take(&mut self, rate: Rate, now: Instant) -> bool {
        self.fill(rate, now);
        match self.milli.checked_sub(MILLI) {
            Some(reste) => {
                self.milli = reste;
                true
            }
            None => false,
        }
    }

    /// Le seau est-il plein à cet instant ?
    ///
    /// **UN SEAU PLEIN PEUT S'OUBLIER** : un seau neuf serait le même. C'est ce
    /// qui borne la mémoire de qui les garde, sans jamais rendre à un appareil
    /// une rafale qu'il vient de dépenser.
    #[must_use]
    pub fn is_full(&self, rate: Rate, now: Instant) -> bool {
        let mut copie = *self;
        copie.fill(rate, now);
        copie.milli >= rate.capacity()
    }

    /// Remplit le seau du temps écoulé depuis la dernière fois.
    fn fill(&mut self, rate: Rate, now: Instant) {
        let ecoule = now.as_millis().saturating_sub(self.last.as_millis());
        let rendu = ecoule.saturating_mul(u64::from(rate.per_second));
        self.milli = self.milli.saturating_add(rendu).min(rate.capacity());
        self.last = self.last.max(now);
    }
}

#[cfg(test)]
mod tests;
