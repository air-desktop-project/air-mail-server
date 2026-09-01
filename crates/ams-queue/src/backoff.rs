//! Quand réessayer, et quand renoncer.

use core::time::Duration;

/// Ce que la file fait d'un échec temporaire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Reprendre l'entrée à cet instant, en secondes depuis l'époque.
    Retry {
        /// L'instant du prochain essai.
        at: u64,
    },
    /// Renoncer : la péremption est atteinte. Un rapport de non-remise part.
    GiveUp,
}

/// L'attente entre deux essais, et le moment où l'on cesse d'essayer.
///
/// # POURQUOI L'ATTENTE DOUBLE
///
/// Un pair est en panne pour une raison qu'on ne connaît pas, et qui dure ce
/// qu'elle dure. Réessayer à intervalle fixe pendant cinq jours, c'est frapper
/// des centaines de fois à une porte fermée — et si mille messages attendent
/// pour ce même domaine, c'est le marteler pendant qu'il se relève.
///
/// Doubler donne un essai rapide pour la panne d'une minute, et une poignée
/// d'essais seulement pour la panne d'un jour. **Le plafond existe pour que
/// l'attente ne devienne pas plus longue que la péremption** : sans lui, un
/// message finirait par attendre plus que le temps qui lui reste, ce qui
/// reviendrait à renoncer sans le dire.
///
/// # RIEN ICI N'EST UNE CONSTANTE
///
/// Les trois durées viennent de la configuration, pour la même raison que les
/// seuils du garde : un délai gravé dans le code est un délai qu'on ne peut pas
/// desserrer le jour où il se trompe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    /// L'attente après le premier échec.
    pub first: Duration,
    /// Le plafond de l'attente.
    pub ceiling: Duration,
    /// Le temps accordé à un message depuis son dépôt.
    pub expiry: Duration,
}

impl Backoff {
    /// Des valeurs de départ.
    ///
    /// **Cinq jours de péremption**, parce que §4.5.4.1 de RFC 5321 demande au
    /// moins quatre à cinq jours avant d'abandonner : une panne de trois jours
    /// chez un pair est rare, mais elle arrive, et rendre le courrier à
    /// l'expéditeur au bout de quelques heures perdrait ce qui serait passé.
    ///
    /// **Un quart d'heure de départ**, qui laisse passer les pannes brèves sans
    /// que l'expéditeur ait le temps de s'inquiéter, et **six heures de
    /// plafond** : au-delà, l'essai suivant tomberait après la péremption plus
    /// souvent qu'il ne servirait.
    pub const DEFAULT: Self = Self {
        first: Duration::from_secs(900),
        ceiling: Duration::from_secs(6 * 3600),
        expiry: Duration::from_secs(5 * 86_400),
    };

    /// L'attente après `attempts` échecs.
    ///
    /// `attempts` compte l'essai qui vient d'échouer : le premier échec donne
    /// [`Backoff::first`], le deuxième le double, et ainsi de suite jusqu'au
    /// plafond.
    ///
    /// **Zéro rend la même chose qu'un.** Aucun appelant ne peut demander
    /// l'attente d'un échec qui n'a pas eu lieu — c'est après l'échec qu'on
    /// consulte —, et une fonction totale vaut mieux ici qu'une panique pour un
    /// cas que rien n'atteint.
    #[must_use]
    pub fn delay(&self, attempts: u32) -> Duration {
        let doublements = attempts.saturating_sub(1).min(u32::BITS.saturating_sub(1));
        // LE DÉCALAGE NE PEUT PAS DÉBORDER : il est borné à 31, et il porte sur
        // des secondes en `u64`. Le produit, lui, sature — une configuration
        // absurde donne une attente absurde, pas un débordement.
        let facteur = 1_u64.checked_shl(doublements).unwrap_or(u64::MAX);
        let attente = self.first.as_secs().saturating_mul(facteur);
        Duration::from_secs(attente.min(self.ceiling.as_secs()))
    }

    /// L'instant où le message n'a plus droit à rien.
    #[must_use]
    pub fn deadline(&self, deposited: u64) -> u64 {
        deposited.saturating_add(self.expiry.as_secs())
    }

    /// Ce qu'il advient d'une entrée dont l'essai vient d'échouer
    /// TEMPORAIREMENT.
    ///
    /// `deposited` est l'instant du dépôt, `attempts` le nombre d'essais faits —
    /// celui qui vient d'échouer compris — et `now` l'heure qu'il est.
    ///
    /// # LE DERNIER ESSAI TOMBE SUR LA PÉREMPTION, PAS AVANT
    ///
    /// Si l'attente calculée dépasserait l'échéance, on ne renonce pas tout de
    /// suite : on ramène l'essai À l'échéance. Renoncer plus tôt raccourcirait
    /// en silence les cinq jours annoncés, et le pair qui se relève dans la
    /// dernière heure n'aurait rien reçu.
    #[must_use]
    pub fn after_failure(&self, deposited: u64, attempts: u32, now: u64) -> Decision {
        let echeance = self.deadline(deposited);
        // ON RENONCE SEULEMENT UNE FOIS L'ÉCHÉANCE ATTEINTE, et c'est ce qui
        // fait qu'il n'y a qu'une règle : l'essai a eu lieu, il a échoué, et il
        // n'y a plus de temps. Un message qui a dormi pendant une panne du
        // serveur a ainsi eu son dernier essai.
        if now >= echeance {
            return Decision::GiveUp;
        }
        let attente = self.delay(attempts).as_secs();
        Decision::Retry {
            at: now.saturating_add(attente).min(echeance),
        }
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests;
