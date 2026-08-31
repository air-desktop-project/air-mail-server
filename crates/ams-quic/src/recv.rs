// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le côté RÉCEPTION d'un flux (RFC 9000 §3.2, §4.1, §4.5).
//!
//! # UN FLUX ARRIVE DANS LE DÉSORDRE, ET SE LIT DANS L'ORDRE
//!
//! C'est tout le travail de ce module. QUIC livre les paquets comme ils
//! viennent ; un flux, lui, est une suite d'octets. Entre les deux, il faut
//! retenir ce qui est arrivé en avance jusqu'à ce que ce qui manque arrive.
//!
//! # LA FENÊTRE APPARTIENT À L'APPELANT, ET CE N'EST PAS UN DÉTAIL
//!
//! Ce crate n'alloue pas. La fenêtre de réassemblage est donc fournie, et sa
//! taille EST la limite de contrôle de flux qu'on annonce. Les deux ne peuvent
//! pas diverger : annoncer plus qu'on ne peut retenir ferait perdre des octets
//! qu'on a acquittés, et annoncer moins ferait attendre un pair qui a le droit
//! d'envoyer.
//!
//! # ON NE PEUT PAS RETIRER UN ACQUITTEMENT
//!
//! C'est la contrainte qui décide de tout ici. Une fois un paquet acquitté, son
//! contenu est à nous : le pair ne le renverra plus. Un réassembleur qui
//! jetterait ce qu'il ne peut pas ranger perdrait donc des octets **en silence**,
//! et le flux se figerait sans que rien ne l'explique.
//!
//! D'où deux règles : la fenêtre est aussi grande que ce qu'on annonce, et le
//! nombre de trous est borné par une valeur qu'un pair honnête ne peut pas
//! atteindre.

use crate::error::{Error, Reason};
use crate::plages::Plages;

/// Où en est la réception d'un flux (§3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvState {
    /// `Recv` — des octets arrivent encore, et l'on ne sait pas où cela finit.
    Recv,
    /// `Size Known` — le `FIN` est arrivé, mais il manque des octets.
    SizeKnown,
    /// `Data Recvd` — tout est là, et rien n'a encore été lu jusqu'au bout.
    DataRecvd,
    /// `Data Read` — l'application a tout lu.
    DataRead,
    /// `Reset Recvd` — le pair a annulé le flux.
    ResetRecvd,
    /// `Reset Read` — l'application sait que le flux a été annulé.
    ResetRead,
}

impl RecvState {
    /// Ce flux peut-il encore recevoir des octets ?
    #[must_use]
    pub const fn accepte(self) -> bool {
        matches!(self, Self::Recv | Self::SizeKnown)
    }

    /// Le flux est-il fini, d'une façon ou d'une autre ?
    #[must_use]
    pub const fn fini(self) -> bool {
        matches!(self, Self::DataRead | Self::ResetRead)
    }
}

/// Le côté réception d'un flux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recv {
    /// Jusqu'où le pair a le droit d'envoyer, en décalage absolu.
    limite: u64,
    /// Jusqu'où l'application a lu — c'est le début de la fenêtre.
    lu: u64,
    /// Le plus grand décalage reçu, exclusif.
    ///
    /// **C'EST CE QUE LE CONTRÔLE DE CONNEXION COMPTE** (§4.1) : la somme des
    /// plus grands décalages de tous les flux, et non le nombre d'octets reçus.
    /// Compter les octets ferait payer deux fois une retransmission.
    vu: u64,
    /// La taille finale, une fois connue (§4.5).
    finale: Option<u64>,
    /// Ce qui est arrivé, en intervalles.
    plages: Plages,
    /// L'état.
    etat: RecvState,
}

impl Recv {
    /// Un flux neuf, avec la limite qu'on annonce.
    ///
    /// **`limite` EST AUSSI LA TAILLE DE LA FENÊTRE** que l'appelant devra
    /// fournir : les deux ne peuvent pas diverger.
    #[must_use]
    pub const fn new(limite: u64) -> Self {
        Self {
            limite,
            lu: 0,
            vu: 0,
            finale: None,
            plages: Plages::new(),
            etat: RecvState::Recv,
        }
    }

    /// L'état.
    #[must_use]
    pub const fn state(&self) -> RecvState {
        self.etat
    }

    /// Le plus grand décalage reçu, exclusif.
    #[must_use]
    pub const fn largest(&self) -> u64 {
        self.vu
    }

    /// Jusqu'où l'application a lu.
    #[must_use]
    pub const fn read_offset(&self) -> u64 {
        self.lu
    }

    /// La limite en vigueur.
    #[must_use]
    pub const fn limit(&self) -> u64 {
        self.limite
    }

    /// La taille finale, si on la connaît.
    #[must_use]
    pub const fn final_size(&self) -> Option<u64> {
        self.finale
    }

    /// Combien d'octets contigus attendent d'être lus.
    #[must_use]
    pub fn readable(&self) -> u64 {
        self.plages.contiguous_from(self.lu)
    }

    /// Relève la limite (§19.10).
    ///
    /// **UNE LIMITE PLUS BASSE N'EST PAS UNE FAUTE, ET N'A PAS D'EFFET** (§4.1).
    /// La refuser fermerait des connexions pour un `MAX_STREAM_DATA` arrivé dans
    /// le désordre — ce qui arrive sans que personne n'ait tort.
    pub const fn set_limit(&mut self, limite: u64) {
        if limite > self.limite {
            self.limite = limite;
        }
    }

    /// Range les octets d'une trame `STREAM`.
    ///
    /// `fenetre` porte les octets à partir de [`Recv::read_offset`], et fait au
    /// moins [`Recv::limit`] moins ce décalage.
    ///
    /// Rend de combien le plus grand décalage a monté — **c'est ce que le
    /// contrôle de connexion doit compter** (§4.1).
    ///
    /// # Errors
    ///
    /// [`Reason::FlowControl`] au-delà de la limite ; [`Reason::FinalSize`] si
    /// la taille finale change ou si des octets arrivent au-delà ;
    /// [`Reason::TooManyHoles`] si le désordre dépasse ce qu'on retient ;
    /// [`Reason::WindowTooSmall`] si la fenêtre ne fait pas la taille annoncée —
    /// **celle-là est la nôtre**, et non celle du pair.
    pub fn on_stream(
        &mut self,
        decalage: u64,
        octets: &[u8],
        fin_de_flux: bool,
        fenetre: &mut [u8],
    ) -> Result<u64, Error> {
        // §3.2 : un flux annulé n'accepte plus rien, et le dire n'est pas une
        // faute — la trame a pu croiser notre `STOP_SENDING` sur le fil.
        //
        // **UN FLUX TERMINÉ, LUI, CONTINUE DE VÉRIFIER SA TAILLE FINALE** : §4.5
        // ne s'arrête pas à `Data Recvd`, et un second `FIN` à un autre décalage
        // reste une contradiction qu'il faut dire.
        if matches!(self.etat, RecvState::ResetRecvd | RecvState::ResetRead) {
            return Ok(0);
        }
        let longueur = u64::try_from(octets.len()).unwrap_or(u64::MAX);
        let bout = decalage.saturating_add(longueur);
        // §4.1 : au-delà de ce qu'on a annoncé, c'est une faute — et le pair ne
        // peut pas l'ignorer, puisque c'est nous qui avons annoncé.
        if bout > self.limite {
            return Err(Error::new(Reason::FlowControl));
        }
        self.verifier_la_taille_finale(bout, fin_de_flux)?;
        // **ON RANGE AVANT DE COMPTER, ET C'EST L'ORDRE QUI COMPTE** : si la
        // place manque, rien ne doit avoir bougé. Un refus qui aurait déjà fait
        // monter le plus grand décalage laisserait le contrôle de connexion
        // désaccordé de ce que le flux dit — et l'écart ne se rattrape pas.
        //
        // §2.2 : des octets déjà reçus peuvent revenir, et c'est normal.
        self.ranger(decalage, octets, fenetre)?;
        let avant = self.vu;
        self.vu = self.vu.max(bout);
        if fin_de_flux {
            self.finale = Some(bout);
            self.etat = RecvState::SizeKnown;
        }
        self.avancer_l_etat();
        Ok(self.vu.saturating_sub(avant))
    }

    /// Range un `RESET_STREAM` (§19.4).
    ///
    /// Rend de combien le plus grand décalage a monté : §4.5 impose de compter
    /// la taille finale d'un flux annulé dans le contrôle de connexion, **même
    /// si l'on n'a jamais reçu ces octets**.
    ///
    /// # Errors
    ///
    /// [`Reason::FlowControl`], [`Reason::FinalSize`].
    pub fn on_reset(&mut self, taille_finale: u64) -> Result<u64, Error> {
        if matches!(self.etat, RecvState::ResetRecvd | RecvState::ResetRead) {
            return Ok(0);
        }
        if taille_finale > self.limite {
            return Err(Error::new(Reason::FlowControl));
        }
        self.verifier_la_taille_finale(taille_finale, true)?;
        let avant = self.vu;
        self.vu = self.vu.max(taille_finale);
        self.finale = Some(taille_finale);
        self.etat = RecvState::ResetRecvd;
        Ok(self.vu.saturating_sub(avant))
    }

    /// L'application prend ce qui est prêt, dans l'ordre.
    ///
    /// Rend combien d'octets ont été pris, et décale la fenêtre d'autant.
    pub fn read(&mut self, fenetre: &mut [u8], vers: &mut [u8]) -> usize {
        let prets = self.readable();
        let combien = usize::try_from(prets)
            .unwrap_or(usize::MAX)
            .min(vers.len())
            .min(fenetre.len());
        let pris = fenetre.get(..combien).unwrap_or_default();
        vers.get_mut(..combien)
            .unwrap_or_default()
            .copy_from_slice(pris);
        // La fenêtre glisse : ce qu'on vient de prendre s'en va, et le reste
        // remonte.
        fenetre.copy_within(combien.., 0);
        self.lu = self.lu.saturating_add(u64::try_from(combien).unwrap_or(0));
        self.plages.trim_below(self.lu);
        self.avancer_l_etat();
        combien
    }

    /// L'application a pris acte de l'annulation.
    ///
    /// **C'EST UN ÉTAT SÉPARÉ** (§3.2) : entre `Reset Recvd` et `Reset Read`, on
    /// sait que le flux est mort mais l'application ne le sait pas encore, et
    /// c'est elle qui décide quand libérer ce qui va avec.
    pub const fn read_reset(&mut self) {
        if matches!(self.etat, RecvState::ResetRecvd) {
            self.etat = RecvState::ResetRead;
        }
    }

    /// La taille finale est-elle cohérente avec ce qu'on sait (§4.5) ?
    fn verifier_la_taille_finale(&self, bout: u64, definitif: bool) -> Result<(), Error> {
        let Some(connue) = self.finale else {
            return Ok(());
        };
        // §4.5 : « Once a final size for a stream is known, it cannot change. »
        let contredit = match definitif {
            true => bout != connue,
            // Et rien n'arrive AU-DELÀ d'une taille finale connue.
            false => bout > connue,
        };
        match contredit {
            true => Err(Error::new(Reason::FinalSize)),
            false => Ok(()),
        }
    }

    /// Écrit les octets dans la fenêtre, et note l'intervalle.
    fn ranger(&mut self, decalage: u64, octets: &[u8], fenetre: &mut [u8]) -> Result<(), Error> {
        // Ce qui est déjà lu ne se réécrit pas : la fenêtre commence à `lu`.
        let saut = self.lu.saturating_sub(decalage);
        let depuis = usize::try_from(saut).unwrap_or(usize::MAX);
        let utiles = octets.get(depuis..).unwrap_or_default();
        if utiles.is_empty() {
            return Ok(());
        }
        let debut = decalage.max(self.lu);
        let rang = usize::try_from(debut.saturating_sub(self.lu)).unwrap_or(usize::MAX);
        let fin = rang.saturating_add(utiles.len());
        // **UNE FENÊTRE TROP COURTE PERDRAIT DES OCTETS EN SILENCE**, et c'est
        // précisément ce que ce module existe pour empêcher. La contrainte —
        // fenêtre aussi grande que la limite annoncée — est celle de l'appelant,
        // et une contrainte qu'on ne vérifie pas n'en est pas une : elle se
        // saurait en production, sous la forme d'un flux qui se fige.
        let place = fenetre
            .get_mut(rang..fin)
            .ok_or(Error::new(Reason::WindowTooSmall))?;
        for (ou, lu) in place.iter_mut().zip(utiles) {
            *ou = *lu;
        }
        let fin = debut.saturating_add(u64::try_from(utiles.len()).unwrap_or(0));
        // **ON NE PEUT PAS RETIRER UN ACQUITTEMENT** : quand la place manque, on
        // le dit et l'appelant ferme, plutôt que de perdre des octets en
        // silence.
        self.plages
            .insert(debut, fin)
            .map_err(|_| Error::new(Reason::TooManyHoles))
    }

    /// Fait avancer l'état si ce qui manquait est arrivé.
    fn avancer_l_etat(&mut self) {
        let Some(finale) = self.finale else {
            return;
        };
        if matches!(self.etat, RecvState::ResetRecvd | RecvState::ResetRead) {
            return;
        }
        // Tout est là quand la première plage va de `lu` à la taille finale.
        let complet = self.lu >= finale
            || self
                .plages
                .first()
                .is_some_and(|plage| plage.debut <= self.lu && plage.fin >= finale);
        self.etat = match (complet, self.lu >= finale) {
            (_, true) => RecvState::DataRead,
            (true, false) => RecvState::DataRecvd,
            (false, false) => RecvState::SizeKnown,
        };
    }
}

#[cfg(test)]
mod tests;
