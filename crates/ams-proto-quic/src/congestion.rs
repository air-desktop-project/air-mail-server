// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La détection de perte et le contrôle de congestion (RFC 9002 §6.1 et §7).
//!
//! # CE N'EST PAS UNE OPTIMISATION, C'EST UNE OBLIGATION
//!
//! §7 : « Senders MUST either use congestion control or limit themselves to
//! sending at most a small amount of data. » Un émetteur QUIC sans contrôle de
//! congestion n'est pas un émetteur rapide : c'est un émetteur qui écroule le
//! chemin qu'il partage, et le noyau ne l'en empêchera pas — c'est ce qui change
//! avec TCP.
//!
//! # DEUX FAÇONS DE DIRE QU'UN PAQUET EST PERDU, ET IL FAUT LES DEUX
//!
//! §6.1 : un paquet est perdu si un paquet SUFFISAMMENT PLUS RÉCENT a été
//! acquitté — c'est le seuil de paquets —, ou s'il a été envoyé ASSEZ LONGTEMPS
//! avant le plus récent acquitté — c'est le seuil de temps.
//!
//! Aucun ne suffit seul. Le seuil de paquets ne voit rien quand il n'y a plus
//! rien à envoyer : le dernier paquet d'un échange n'a aucun successeur pour le
//! déclarer perdu. Le seuil de temps, lui, attend une fraction d'aller-retour
//! même quand la preuve est déjà là. **Les deux ensemble couvrent la file qui
//! avance et la file qui s'arrête.**
//!
//! # LE RÉORDONNANCEMENT N'EST PAS UNE PERTE
//!
//! Trois paquets d'écart, et neuf huitièmes d'aller-retour : ces deux chiffres
//! ne sont pas des réglages de confort. Ils disent ce qu'on accepte de voir
//! arriver dans le désordre avant d'appeler cela une perte — et déclarer perdu
//! ce qui n'était que en retard fait ralentir un chemin qui allait bien.

use crate::rtt::{GRANULARITY_US, Rtt};

/// Combien de paquets plus récents il faut voir acquittés (§6.1.1).
///
/// Trois, et c'est le chiffre de TCP depuis toujours : en deçà, le
/// réordonnancement ordinaire d'un réseau passerait pour une perte.
pub const PACKET_THRESHOLD: u64 = 3;

/// La taille de datagramme qu'on suppose (§7.2), en octets.
///
/// Mille deux cents : c'est ce que §14.1 exige de pouvoir porter, et donc le
/// plus petit qu'un chemin QUIC garantisse.
pub const MAX_DATAGRAM_SIZE: u64 = 1_200;

/// La fenêtre de départ (§7.2), en octets.
///
/// Dix datagrammes, borné à quatorze kibioctets et demi. **Elle décide de ce
/// qu'on ose envoyer avant d'avoir la moindre nouvelle du chemin** — trop, et la
/// première rafale l'écroule ; trop peu, et une petite réponse prend trois
/// allers-retours.
pub const INITIAL_WINDOW: u64 = {
    let dix = 10 * MAX_DATAGRAM_SIZE;
    let plafond = if 14_720 > 2 * MAX_DATAGRAM_SIZE {
        14_720
    } else {
        2 * MAX_DATAGRAM_SIZE
    };
    if dix < plafond { dix } else { plafond }
};

/// La plus petite fenêtre qu'on descende (§7.2), en octets.
///
/// Deux datagrammes. En deçà, on ne pourrait plus envoyer un paquet plein, et le
/// contrôle de congestion deviendrait un arrêt de service.
pub const MINIMUM_WINDOW: u64 = 2 * MAX_DATAGRAM_SIZE;

/// Combien de fois l'aller-retour doit s'écouler pour parler de congestion
/// persistante (§7.6).
pub const PERSISTENT_CONGESTION_THRESHOLD: u64 = 3;

/// L'état du contrôle de congestion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Congestion {
    /// Ce qu'on s'autorise à avoir en vol, en octets.
    fenetre: u64,
    /// Ce qui est en vol, en octets.
    en_vol: u64,
    /// Le seuil au-delà duquel on quitte le démarrage lent.
    ///
    /// `None` tant qu'aucune perte n'a eu lieu : **on ne sait pas encore ce que
    /// le chemin porte**, et se donner un seuil arbitraire reviendrait à le
    /// deviner.
    seuil: Option<u64>,
    /// Jusqu'à quel instant on est déjà en train de récupérer.
    ///
    /// **UNE PERTE PAR PÉRIODE DE RÉCUPÉRATION, ET PAS UNE PAR PAQUET** (§7.3.2)
    /// : une rafale perdue est UN événement de congestion. Diviser la fenêtre
    /// une fois par paquet perdu la ramènerait au minimum sur la première rafale
    /// venue, et l'on ne s'en relèverait qu'après plusieurs secondes.
    recuperation_jusqu_a: Option<u64>,
}

impl Default for Congestion {
    fn default() -> Self {
        Self::new()
    }
}

impl Congestion {
    /// Un contrôle neuf, à la fenêtre de départ.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            fenetre: INITIAL_WINDOW,
            en_vol: 0,
            seuil: None,
            recuperation_jusqu_a: None,
        }
    }

    /// La fenêtre, en octets.
    #[must_use]
    pub const fn window(&self) -> u64 {
        self.fenetre
    }

    /// Ce qui est en vol, en octets.
    #[must_use]
    pub const fn in_flight(&self) -> u64 {
        self.en_vol
    }

    /// Est-on encore en démarrage lent (§7.3.1) ?
    #[must_use]
    pub fn in_slow_start(&self) -> bool {
        self.seuil.is_none_or(|seuil| self.fenetre < seuil)
    }

    /// Ce qu'on peut encore envoyer, en octets.
    ///
    /// **ZÉRO N'EST PAS UNE FAUTE** : c'est une fenêtre pleine, et l'émetteur
    /// attend un acquittement.
    #[must_use]
    pub const fn available(&self) -> u64 {
        self.fenetre.saturating_sub(self.en_vol)
    }

    /// Un paquet part.
    pub const fn on_sent(&mut self, octets: u64) {
        self.en_vol = self.en_vol.saturating_add(octets);
    }

    /// Un paquet est acquitté, à cet instant.
    ///
    /// # DEUX RÉGIMES, ET LEUR FRONTIÈRE EST LE SEUIL
    ///
    /// En démarrage lent, la fenêtre croît d'autant qu'on a acquitté : elle
    /// double à chaque aller-retour, et l'on trouve la capacité du chemin en
    /// quelques allers-retours plutôt qu'en quelques minutes.
    ///
    /// Ensuite, elle croît d'un datagramme par aller-retour. C'est lent exprès :
    /// on partage le chemin, et l'augmentation additive contre la diminution
    /// multiplicative est ce qui fait converger plusieurs émetteurs vers une
    /// part équitable.
    pub fn on_acked(&mut self, octets: u64, instant: u64) {
        self.en_vol = self.en_vol.saturating_sub(octets);
        // §7.3.2 : UN PAQUET ACQUITTÉ ENVOYÉ AVANT LA FIN DE LA RÉCUPÉRATION NE
        // FAIT PAS CROÎTRE LA FENÊTRE. Il ne prouve rien du nouveau régime : il
        // était déjà en vol quand la congestion s'est produite.
        if self
            .recuperation_jusqu_a
            .is_some_and(|jusqu_a| instant <= jusqu_a)
        {
            return;
        }
        if self.in_slow_start() {
            self.fenetre = self.fenetre.saturating_add(octets);
            return;
        }
        // §7.3.3 : `cwnd += max_datagram_size * acked / cwnd`, ce qui fait un
        // datagramme par aller-retour complet.
        let gain = MAX_DATAGRAM_SIZE
            .saturating_mul(octets)
            .checked_div(self.fenetre)
            .unwrap_or(0);
        self.fenetre = self.fenetre.saturating_add(gain);
    }

    /// Une perte est constatée, à cet instant, pour un paquet envoyé à
    /// `envoye_a`.
    ///
    /// # UNE SEULE DIVISION PAR PÉRIODE, ET C'EST TOUT L'ART
    ///
    /// Une rafale perdue est UN événement de congestion, pas dix. La période de
    /// récupération dure jusqu'à ce que tout ce qui était en vol soit acquitté
    /// ou perdu ; pendant ce temps, les pertes suivantes ne divisent plus rien.
    pub fn on_lost(&mut self, octets: u64, envoye_a: u64, instant: u64) {
        self.en_vol = self.en_vol.saturating_sub(octets);
        // Le paquet perdu était-il déjà couvert par la récupération en cours ?
        if self
            .recuperation_jusqu_a
            .is_some_and(|jusqu_a| envoye_a <= jusqu_a)
        {
            return;
        }
        // §7.3.2 : la fenêtre est divisée par deux, et ne descend pas sous le
        // minimum — en deçà, on ne pourrait plus envoyer un paquet plein.
        self.fenetre = self.fenetre.saturating_div(2).max(MINIMUM_WINDOW);
        self.seuil = Some(self.fenetre);
        self.recuperation_jusqu_a = Some(instant);
    }

    /// Le chemin ne répond plus depuis assez longtemps pour qu'on reparte de
    /// zéro (§7.6).
    ///
    /// **CE N'EST PAS UNE PERTE DE PLUS.** Une congestion persistante veut dire
    /// que RIEN n'est passé pendant plusieurs allers-retours : le chemin a
    /// changé, ou il est coupé. Continuer avec une fenêtre héritée d'un chemin
    /// qui n'existe plus enverrait une rafale dans le vide.
    pub const fn on_persistent_congestion(&mut self) {
        self.fenetre = MINIMUM_WINDOW;
        self.seuil = None;
        self.recuperation_jusqu_a = None;
    }

    /// La durée au-delà de laquelle le silence devient une congestion
    /// persistante (§7.6.1), en microsecondes.
    #[must_use]
    pub fn persistent_congestion_duration(rtt: &Rtt, delai_max: u64) -> u64 {
        rtt.pto(delai_max, 0)
            .saturating_mul(PERSISTENT_CONGESTION_THRESHOLD)
    }
}

/// Le seuil de temps au-delà duquel un paquet est déclaré perdu (§6.1.2), en
/// microsecondes.
///
/// # NEUF HUITIÈMES, ET NON UN
///
/// §6.1.2 le fixe à `9/8 * max(smoothed_rtt, latest_rtt)`. Le huitième de marge
/// paie le réordonnancement ordinaire : à exactement un aller-retour, tout
/// paquet arrivé dans le désordre serait déclaré perdu, et l'on ralentirait un
/// chemin qui va bien.
///
/// Le plancher de granularité, lui, empêche un seuil plus court que ce que
/// l'horloge sait mesurer.
#[must_use]
pub fn time_threshold(rtt: &Rtt) -> u64 {
    let base = rtt.smoothed().max(rtt.latest());
    base.saturating_mul(9).saturating_div(8).max(GRANULARITY_US)
}

/// Ce paquet est-il perdu ?
///
/// `numero` est le sien, `envoye_a` l'instant de son envoi ; `plus_grand_acquitte`
/// et `envoye_a_du_plus_grand` décrivent le plus récent paquet acquitté.
///
/// # LES DEUX SEUILS, ET IL FAUT LES DEUX
///
/// Le seuil de PAQUETS ne voit rien quand il n'y a plus rien à envoyer : le
/// dernier paquet d'un échange n'a aucun successeur pour le déclarer perdu. Le
/// seuil de TEMPS, lui, attend une fraction d'aller-retour même quand la preuve
/// est déjà là.
#[must_use]
pub fn is_lost(
    numero: u64,
    envoye_a: u64,
    plus_grand_acquitte: u64,
    envoye_a_du_plus_grand: u64,
    rtt: &Rtt,
) -> bool {
    // Un paquet plus récent que le plus grand acquitté n'est pas en cause.
    let Some(ecart) = plus_grand_acquitte.checked_sub(numero) else {
        return false;
    };
    if ecart >= PACKET_THRESHOLD {
        return true;
    }
    let age = envoye_a_du_plus_grand.saturating_sub(envoye_a);
    age >= time_threshold(rtt)
}

#[cfg(test)]
mod tests;
