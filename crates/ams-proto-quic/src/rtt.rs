// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! L'estimation du temps d'aller-retour, et le délai avant retransmission
//! (RFC 9002 §5 et §6.2).
//!
//! # LA PERTE EST NOTRE AFFAIRE, ET C'EST LA DIFFÉRENCE AVEC TCP
//!
//! Le noyau ne retransmet rien : ce module et ceux qui l'entourent DÉCIDENT
//! qu'un paquet est perdu, et quand réessayer. Une estimation trop courte fait
//! retransmettre ce qui était en route — et l'on inonde un réseau déjà chargé.
//! Une estimation trop longue fait attendre une seconde ce qui aurait pu partir
//! en dix millisecondes.
//!
//! # LE PAIR DIT COMBIEN DE TEMPS IL A ATTENDU, ET IL PEUT MENTIR
//!
//! Un `ACK` porte un délai d'acquittement : le temps que le pair a laissé passer
//! avant de répondre. On le RETIRE de l'échantillon, sans quoi on prendrait sa
//! politesse pour de la latence.
//!
//! Mais ce délai vient de lui, et rien ne l'oblige à dire vrai. §5.3 pose donc
//! deux gardes : **on ne retire jamais le délai si cela ferait descendre sous le
//! minimum observé**, et le délai lui-même est borné par ce que le pair a
//! annoncé pouvoir attendre. Un pair qui annoncerait un délai énorme ferait
//! sinon croire à un réseau instantané — et l'on retransmettrait tout, tout le
//! temps.
//!
//! # LES CONSTANTES SONT CELLES DE L'ANNEXE A.2, ET ELLES NE SE DEVINENT PAS
//!
//! Un quart et trois quarts pour la variance, un huitième et sept huitièmes pour
//! la moyenne : ce sont celles de TCP depuis RFC 6298, et les changer sans
//! mesurer ferait un contrôle de congestion qui n'a été éprouvé nulle part.

use crate::error::{Error, Reason};

/// La granularité de l'horloge (§A.2), en microsecondes.
///
/// Une milliseconde. En deçà, le système ne sait pas mesurer, et une
/// temporisation plus courte se déclencherait sur le bruit de l'ordonnanceur.
pub const GRANULARITY_US: u64 = 1_000;

/// Le temps d'aller-retour supposé avant toute mesure (§6.2.2), en
/// microsecondes.
///
/// Trois cent trente-trois millisecondes. C'est ce que la RFC prescrit, et c'est
/// long exprès : la première retransmission d'une connexion est celle dont on
/// sait le moins, et se tromper par excès n'y coûte qu'une attente.
pub const INITIAL_RTT_US: u64 = 333_000;

/// Le plus grand exposant de délai d'acquittement qu'on accepte (§18.2).
///
/// Vingt. Au-delà, un délai annoncé ne tient plus dans l'espace des entiers, et
/// §18.2 en fait une faute de paramètre.
pub const ACK_DELAY_EXPONENT_MAX: u32 = 20;

/// L'estimation du temps d'aller-retour (§5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rtt {
    /// Le dernier échantillon, en microsecondes.
    latest: u64,
    /// Le plus petit jamais observé.
    ///
    /// **IL NE SE LISSE PAS, ET C'EST VOULU** (§5.2) : il sert de plancher pour
    /// juger si un délai d'acquittement est crédible, et une moyenne ferait
    /// remonter ce plancher avec la congestion — c'est-à-dire au moment précis
    /// où l'on en a besoin.
    min: u64,
    /// La moyenne lissée.
    smoothed: u64,
    /// La variance lissée.
    variance: u64,
    /// A-t-on déjà mesuré ?
    mesure: bool,
}

impl Default for Rtt {
    fn default() -> Self {
        Self::new()
    }
}

impl Rtt {
    /// Une estimation neuve, avec les suppositions de §6.2.2.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            latest: 0,
            min: 0,
            smoothed: INITIAL_RTT_US,
            variance: INITIAL_RTT_US / 2,
            mesure: false,
        }
    }

    /// A-t-on déjà un échantillon ?
    #[must_use]
    pub const fn has_sample(&self) -> bool {
        self.mesure
    }

    /// Le dernier échantillon, en microsecondes.
    #[must_use]
    pub const fn latest(&self) -> u64 {
        self.latest
    }

    /// Le plus petit observé, en microsecondes.
    #[must_use]
    pub const fn min(&self) -> u64 {
        self.min
    }

    /// La moyenne lissée, en microsecondes.
    #[must_use]
    pub const fn smoothed(&self) -> u64 {
        self.smoothed
    }

    /// La variance lissée, en microsecondes.
    #[must_use]
    pub const fn variance(&self) -> u64 {
        self.variance
    }

    /// Range un échantillon.
    ///
    /// `aller_retour` est le temps mesuré entre l'envoi et l'acquittement,
    /// `delai_annonce` ce que le pair dit avoir attendu, `delai_max` ce qu'il a
    /// annoncé pouvoir attendre — les trois en microsecondes.
    ///
    /// # L'ORDRE DES OPÉRATIONS DE §5.3, ET IL COMPTE
    ///
    /// 1. le minimum se met à jour sur l'échantillon BRUT — avant toute
    ///    correction, parce que c'est lui qui sert à juger les corrections ;
    /// 2. le délai annoncé est borné par ce que le pair a promis ;
    /// 3. il n'est retiré QUE si l'échantillon reste au-dessus du minimum.
    ///
    /// Intervertir 1 et 3 ferait juger une correction avec un minimum qu'elle
    /// vient elle-même d'abaisser — et l'estimation s'effondrerait sur un pair
    /// qui ment.
    pub fn sample(&mut self, aller_retour: u64, delai_annonce: u64, delai_max: u64) {
        self.latest = aller_retour;
        if !self.mesure {
            // §5.3 : le premier échantillon fonde tout, et ne se corrige pas —
            // il n'y a pas encore de minimum pour juger sa correction.
            self.mesure = true;
            self.min = aller_retour;
            self.smoothed = aller_retour;
            self.variance = aller_retour / 2;
            return;
        }
        self.min = self.min.min(aller_retour);
        // **LE DÉLAI DU PAIR EST BORNÉ PAR CE QU'IL A PROMIS** : un pair qui
        // annoncerait un délai énorme ferait croire à un réseau instantané.
        let delai = delai_annonce.min(delai_max);
        // **ET ON NE LE RETIRE QUE SI L'ÉCHANTILLON RESTE CRÉDIBLE** : sous le
        // minimum observé, la correction dirait que le réseau va plus vite que
        // tout ce qu'on a jamais mesuré.
        let corrige = match aller_retour >= self.min.saturating_add(delai) {
            true => aller_retour.saturating_sub(delai),
            false => aller_retour,
        };
        // §5.3, les constantes de RFC 6298 : trois quarts et un quart pour la
        // variance, sept huitièmes et un huitième pour la moyenne.
        let ecart = self.smoothed.abs_diff(corrige);
        self.variance = self
            .variance
            .saturating_mul(3)
            .saturating_add(ecart)
            .saturating_div(4);
        self.smoothed = self
            .smoothed
            .saturating_mul(7)
            .saturating_add(corrige)
            .saturating_div(8);
    }

    /// Le délai avant retransmission (§6.2.1), en microsecondes.
    ///
    /// `delai_max` est ce que le pair a annoncé pouvoir attendre avant
    /// d'acquitter ; `essais` compte les temporisations consécutives déjà
    /// écoulées.
    ///
    /// # LE DÉLAI DOUBLE À CHAQUE ESSAI, ET C'EST LA SEULE PROTECTION
    ///
    /// §6.2.1 : sans ce doublement, un serveur injoignable recevrait de chaque
    /// client une retransmission toutes les `pto` — et la panne d'un serveur
    /// deviendrait une inondation du réseau. C'est la même raison qui a fait
    /// mettre un repli exponentiel dans TCP, et elle n'a pas changé.
    ///
    /// # ET IL NE DOUBLE PAS INDÉFINIMENT
    ///
    /// La RFC ne borne pas le nombre d'essais ; elle borne la connexion, qui
    /// finit par expirer. Ici le calcul sature : un `essais` immense rendrait
    /// sinon un délai nul par débordement, et l'on retransmettrait sans fin au
    /// moment précis où l'on voulait attendre.
    ///
    /// **ET LA BOUCLE SE BORNE, ELLE AUSSI.** Une première écriture doublait
    /// `essais` fois ; avec `u32::MAX`, elle tournait quatre milliards de fois
    /// pour un résultat connu d'avance, et le test de saturation mettait
    /// soixante-treize secondes. Au-delà de soixante-quatre doublements, toute
    /// base a saturé — compter plus loin ne change rien. Une borne qu'on
    /// PARCOURT n'est pas une borne : c'est une attente.
    #[must_use]
    pub fn pto(&self, delai_max: u64, essais: u32) -> u64 {
        // §6.2.1 : `smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay`.
        let marge = self.variance.saturating_mul(4).max(GRANULARITY_US);
        let base = self
            .smoothed
            .saturating_add(marge)
            .saturating_add(delai_max);
        // `checked_shl` ne dit rien du débordement de VALEUR : au-delà de
        // soixante-trois, il rend `None`, et en deçà il peut jeter des bits.
        // On multiplie donc, et la saturation porte le reste.
        let mut delai = base;
        for _ in 0..essais.min(u64::BITS) {
            delai = delai.saturating_mul(2);
        }
        delai
    }
}

/// Décode un délai d'acquittement (§19.3, §18.2).
///
/// Le champ d'un `ACK` compte en unités de 2^`exposant` microsecondes. Le
/// multiplier sans borne ferait un délai que rien ne contient.
///
/// # Errors
///
/// [`Reason::BadFrameField`] si l'exposant dépasse vingt, ou si le délai
/// déborde.
pub fn decode_ack_delay(brut: u64, exposant: u32) -> Result<u64, Error> {
    if exposant > ACK_DELAY_EXPONENT_MAX {
        return Err(Error::new(Reason::BadFrameField));
    }
    // L'exposant vaut au plus vingt : l'unité tient largement dans un `u64`, et
    // un `checked_shl` n'aurait ici qu'une branche qu'aucun exposant ne peut
    // emprunter — la borne de §18.2 l'a déjà écartée. Vingt tours de boucle
    // coûtent moins qu'une garde inatteignable.
    let mut unite = 1_u64;
    for _ in 0..exposant {
        unite = unite.saturating_mul(2);
    }
    // **LE PRODUIT, LUI, PEUT DÉBORDER, ET UN DÉCALAGE LE CACHERAIT.** Un `<<`
    // jette les bits qui sortent sans rien dire ; `checked_mul` refuse. C'est le
    // même défaut qu'on avait écrit dans HPACK, et qu'un test avait trouvé.
    brut.checked_mul(unite)
        .ok_or_else(|| Error::new(Reason::BadFrameField))
}

#[cfg(test)]
mod tests;
