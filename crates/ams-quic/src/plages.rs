// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Un ensemble borné d'intervalles d'octets.
//!
//! # LES DEUX CÔTÉS D'UN FLUX POSENT LA MÊME QUESTION
//!
//! À la réception : « qu'est-ce qui est arrivé, et qu'est-ce qui manque encore
//! avant que je puisse livrer ? » À l'émission : « qu'est-ce qui est acquitté,
//! et qu'est-ce qu'il faut renvoyer ? » C'est le même calcul, sur les mêmes
//! décalages, avec les mêmes façons de se tromper — l'écrire deux fois donnerait
//! deux occasions de le rater.
//!
//! # LA BORNE EST UN REFUS, ET NON UN OUBLI
//!
//! On n'alloue pas. Quand la place manque, cet ensemble le DIT plutôt que de
//! laisser tomber un intervalle : à la réception, oublier ce qu'on a acquitté
//! perdrait des octets en silence ; à l'émission, oublier un acquittement ferait
//! renvoyer sans fin ce que le pair a déjà.

/// Combien d'intervalles disjoints on retient par flux.
///
/// # POURQUOI SOIXANTE-QUATRE
///
/// Un intervalle par paquet en vol qui porte ce flux, au pire. Un paquet porte
/// au plus 1200 octets utiles ; avec une fenêtre de 32 kibioctets, un pair ne
/// peut pas en avoir plus de vingt-huit en vol sur un même flux. Soixante-quatre
/// laissent donc de la marge, et refusent le millier qu'un pair choisirait pour
/// nous faire retenir.
pub const HOLES_MAX: usize = 64;

/// Un intervalle d'octets, en décalages absolus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plage {
    /// Le premier octet.
    pub debut: u64,
    /// Le premier octet APRÈS l'intervalle.
    pub fin: u64,
}

/// Des intervalles disjoints, triés par début croissant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plages {
    /// Les intervalles, tassés vers le début.
    plages: [Option<Plage>; HOLES_MAX],
}

impl Default for Plages {
    fn default() -> Self {
        Self::new()
    }
}

impl Plages {
    /// Un ensemble vide.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            plages: [None; HOLES_MAX],
        }
    }

    /// Combien d'intervalles disjoints.
    #[must_use]
    pub fn count(&self) -> usize {
        self.plages.iter().flatten().count()
    }

    /// Le premier intervalle, s'il y en a un.
    #[must_use]
    pub fn first(&self) -> Option<Plage> {
        self.plages.iter().flatten().next().copied()
    }

    /// Combien d'octets contigus à partir de `depuis`.
    ///
    /// Zéro si `depuis` n'est couvert par aucun intervalle : c'est exactement la
    /// question « puis-je livrer, ou est-ce qu'il manque encore ? ».
    #[must_use]
    pub fn contiguous_from(&self, depuis: u64) -> u64 {
        self.plages
            .iter()
            .flatten()
            .find(|plage| plage.debut <= depuis && plage.fin > depuis)
            .map_or(0, |plage| plage.fin.saturating_sub(depuis))
    }

    /// Ajoute un intervalle, en le fondant avec ceux qu'il touche.
    ///
    /// Un intervalle vide ne change rien.
    ///
    /// # ON RÉUNIT EN INSÉRANT, ET NON APRÈS
    ///
    /// Insérer d'abord puis réunir demanderait une place de plus le temps d'un
    /// appel — et cette place-là manque exactement quand on comble le dernier
    /// trou, c'est-à-dire au moment où le désordre DIMINUE. Un flux honnête se
    /// serait vu fermer pour avoir rangé ce qui manquait.
    ///
    /// Défaut écrit, puis trouvé par `combler_les_trous_libere_la_place`.
    ///
    /// # Errors
    ///
    /// [`Debordement`] si l'ensemble est plein : la place a manqué, et l'on ne
    /// laisse pas tomber en silence.
    pub fn insert(&mut self, debut: u64, fin: u64) -> Result<(), Debordement> {
        if fin <= debut {
            return Ok(());
        }
        let mut toutes = [None; HOLES_MAX];
        let mut rang = 0_usize;
        let mut porte = Some(Plage { debut, fin });
        for courante in self.plages.iter().flatten().copied() {
            // Les intervalles sont triés par début croissant, et disjoints.
            match porte {
                // Celui-ci commence après le neuf sans le toucher : le neuf
                // prend sa place ici, et la suite reste intacte.
                Some(neuf) if courante.debut > neuf.fin => {
                    rang = poser(&mut toutes, rang, neuf);
                    porte = None;
                }
                // Celui-ci touche le neuf : ils n'en font plus qu'un, et l'on
                // continue — les suivants peuvent le toucher aussi.
                Some(neuf) if courante.fin >= neuf.debut => {
                    porte = Some(Plage {
                        debut: neuf.debut.min(courante.debut),
                        fin: neuf.fin.max(courante.fin),
                    });
                    continue;
                }
                // Celui-ci finit avant le neuf, ou le neuf est déjà posé.
                _ => {}
            }
            rang = poser(&mut toutes, rang, courante);
        }
        if let Some(restant) = porte {
            rang = poser(&mut toutes, rang, restant);
        }
        // **SI TOUT N'A PAS TENU, LA PLACE A MANQUÉ.** On le dit.
        if rang > HOLES_MAX {
            return Err(Debordement);
        }
        self.plages = toutes;
        Ok(())
    }

    /// Ôte tout ce qui est sous `seuil`.
    ///
    /// Un intervalle entièrement dessous disparaît ; un intervalle à cheval se
    /// raccourcit.
    pub fn trim_below(&mut self, seuil: u64) {
        let mut restants = [None; HOLES_MAX];
        let mut rang = 0_usize;
        for courant in self.plages.iter().flatten().copied() {
            let debut = courant.debut.max(seuil);
            if debut < courant.fin {
                rang = poser(
                    &mut restants,
                    rang,
                    Plage {
                        debut,
                        fin: courant.fin,
                    },
                );
            }
        }
        self.plages = restants;
    }
}

/// La place a manqué.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Debordement;

/// Pose un intervalle au rang voulu, et rend le rang suivant.
///
/// Au-delà du tableau, le rang continue de monter sans rien écrire :
/// [`Plages::insert`] le lit pour savoir que la place a manqué.
fn poser(toutes: &mut [Option<Plage>; HOLES_MAX], rang: usize, plage: Plage) -> usize {
    if let Some(ou) = toutes.get_mut(rang) {
        *ou = Some(plage);
    }
    rang.saturating_add(1)
}

#[cfg(test)]
mod tests;
