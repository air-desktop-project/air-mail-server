// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le côté ÉMISSION d'un flux (RFC 9000 §3.1, §3.3, §4.1).
//!
//! # ON N'ÉMET PAS CE QU'ON VEUT : ON ÉMET CE QU'ON NOUS A OUVERT
//!
//! Le pair annonce jusqu'où l'on peut aller, par flux (`MAX_STREAM_DATA`) et
//! pour la connexion entière (`MAX_DATA`). Dépasser l'un ou l'autre est une
//! faute de NOTRE part, que le pair sanctionne en fermant la connexion. C'est la
//! différence avec TCP, où le noyau tenait ce compte : ici, c'est nous.
//!
//! # ET CE QU'ON A ÉMIS N'EST PAS ENVOYÉ TANT QU'IL N'EST PAS ACQUITTÉ
//!
//! Un flux n'est fini que quand le pair a accusé réception de tout, `FIN`
//! compris (§3.1, `Data Recvd`). D'ici là, il faut savoir ce qui manque pour le
//! renvoyer — d'où l'ensemble d'intervalles acquittés, le même qu'à la
//! réception.
//!
//! # UN FLUX ANNULÉ NE SE TERMINE PAS, IL S'ARRÊTE
//!
//! `RESET_STREAM` et `FIN` s'excluent (§3.3) : une fois le flux annulé, plus un
//! octet ne part, et la taille finale est celle qu'on a déclarée. Renvoyer des
//! octets après aurait deux sens contradictoires de « où ce flux s'arrête », ce
//! que §4.5 refuse à la réception.

use crate::error::{Error, Reason};
use crate::plages::Plages;

/// Où en est l'émission d'un flux (§3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendState {
    /// `Ready` — le flux existe, rien n'est encore parti.
    Ready,
    /// `Send` — des octets sont partis, et il peut en partir d'autres.
    Send,
    /// `Data Sent` — tout est parti, `FIN` compris ; on attend les
    /// acquittements.
    DataSent,
    /// `Data Recvd` — le pair a tout accusé.
    DataRecvd,
    /// `Reset Sent` — on a annulé le flux.
    ResetSent,
    /// `Reset Recvd` — le pair a accusé l'annulation.
    ResetRecvd,
}

impl SendState {
    /// Peut-on encore écrire des octets sur ce flux ?
    #[must_use]
    pub const fn ouvert(self) -> bool {
        matches!(self, Self::Ready | Self::Send)
    }

    /// Le flux est-il arrivé au bout, d'une façon ou d'une autre ?
    #[must_use]
    pub const fn fini(self) -> bool {
        matches!(self, Self::DataRecvd | Self::ResetRecvd)
    }
}

/// Le côté émission d'un flux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Send {
    /// Jusqu'où le pair nous a ouvert, en décalage absolu.
    limite: u64,
    /// Le décalage du prochain octet à émettre.
    ecrit: u64,
    /// La taille finale, une fois `FIN` ou `RESET_STREAM` posé.
    finale: Option<u64>,
    /// Ce que le pair a accusé.
    acquittes: Plages,
    /// Le pair nous a-t-il demandé d'arrêter (§3.5) ?
    stoppe: Option<u64>,
    /// L'état.
    etat: SendState,
}

impl Send {
    /// Un flux neuf, avec ce que le pair nous a ouvert d'emblée.
    #[must_use]
    pub const fn new(limite: u64) -> Self {
        Self {
            limite,
            ecrit: 0,
            finale: None,
            acquittes: Plages::new(),
            stoppe: None,
            etat: SendState::Ready,
        }
    }

    /// L'état.
    #[must_use]
    pub const fn state(&self) -> SendState {
        self.etat
    }

    /// Le décalage du prochain octet à émettre.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.ecrit
    }

    /// La limite en vigueur.
    #[must_use]
    pub const fn limit(&self) -> u64 {
        self.limite
    }

    /// La taille finale, une fois posée.
    #[must_use]
    pub const fn final_size(&self) -> Option<u64> {
        self.finale
    }

    /// Le code d'application du `STOP_SENDING` reçu, s'il y en a eu un.
    #[must_use]
    pub const fn stop_sending(&self) -> Option<u64> {
        self.stoppe
    }

    /// Combien d'octets ce flux nous autorise encore à émettre.
    ///
    /// **CE N'EST PAS TOUT** : le crédit de connexion s'y ajoute, et c'est le
    /// plus petit des deux qui décide — voir [`Send::allowed`].
    #[must_use]
    pub const fn credit(&self) -> u64 {
        self.limite.saturating_sub(self.ecrit)
    }

    /// Combien d'octets peuvent partir, connexion comprise.
    ///
    /// **LES DEUX CRÉDITS SE CUMULENT SANS SE REMPLACER** (§4.1) : dépasser
    /// celui du flux ou celui de la connexion est la même faute, et il faut donc
    /// respecter le plus petit des deux.
    #[must_use]
    pub fn allowed(&self, connexion: u64) -> u64 {
        match self.etat.ouvert() {
            true => self.credit().min(connexion),
            // Un flux fermé ou annulé n'émet plus rien, quel que soit le crédit.
            false => 0,
        }
    }

    /// Le flux est-il bloqué par SON crédit à lui ?
    ///
    /// C'est ce qui décide d'un `STREAM_DATA_BLOCKED` (§19.13) : le dire à un
    /// pair qui nous a effectivement fermé le robinet lui apprend qu'on a
    /// quelque chose à envoyer ; le dire autrement serait du bruit.
    ///
    /// **ET UN FLUX FERMÉ N'EST PAS BLOQUÉ** : il n'a plus rien à envoyer.
    /// `ouvert()` le dit déjà — ajouter une garde sur la taille finale ferait
    /// une condition qu'aucun état ne peut emprunter, c'est-à-dire une
    /// affirmation non vérifiée déguisée en précaution.
    #[must_use]
    pub const fn blocked(&self) -> bool {
        self.etat.ouvert() && self.credit() == 0
    }

    /// Relève la limite sur un `MAX_STREAM_DATA` (§19.10).
    ///
    /// **UNE LIMITE PLUS BASSE N'EST PAS UNE FAUTE, ET N'A PAS D'EFFET** (§4.1) :
    /// deux `MAX_STREAM_DATA` peuvent arriver dans le désordre, et personne n'a
    /// tort.
    pub const fn set_limit(&mut self, limite: u64) {
        if limite > self.limite {
            self.limite = limite;
        }
    }

    /// Note que des octets viennent de partir.
    ///
    /// Rend le décalage du premier octet émis — celui à écrire dans la trame
    /// `STREAM`.
    ///
    /// # Errors
    ///
    /// [`Reason::SendClosed`] si le flux n'accepte plus rien, et
    /// [`Reason::SendOverflow`] au-delà de ce que le pair nous a ouvert. **CES
    /// DEUX-LÀ SONT NOS FAUTES, PAS LES SIENNES** : les rendre plutôt que de les
    /// saturer en silence est ce qui les fait voir en essai plutôt qu'en
    /// production, où le pair fermerait la connexion sans explication.
    pub fn on_sent(&mut self, longueur: u64, fin_de_flux: bool) -> Result<u64, Error> {
        if !self.etat.ouvert() {
            return Err(Error::new(Reason::SendClosed));
        }
        let bout = self.ecrit.saturating_add(longueur);
        if bout > self.limite {
            return Err(Error::new(Reason::SendOverflow));
        }
        let decalage = self.ecrit;
        self.ecrit = bout;
        self.etat = match fin_de_flux {
            true => {
                self.finale = Some(bout);
                SendState::DataSent
            }
            false => SendState::Send,
        };
        self.verifier_les_acquittements();
        Ok(decalage)
    }

    /// Note que le pair a accusé un morceau.
    ///
    /// # Errors
    ///
    /// [`Reason::TooManyHoles`] si les acquittements arrivent dans un désordre
    /// plus grand que ce qu'on retient. **OUBLIER UN ACQUITTEMENT FERAIT
    /// RENVOYER SANS FIN CE QUE LE PAIR A DÉJÀ.**
    pub fn on_acked(&mut self, decalage: u64, longueur: u64) -> Result<(), Error> {
        // §3.1 : après un `RESET_STREAM`, les acquittements de données ne
        // comptent plus — le flux ne se terminera pas normalement.
        if matches!(self.etat, SendState::ResetSent | SendState::ResetRecvd) {
            return Ok(());
        }
        self.acquittes
            .insert(decalage, decalage.saturating_add(longueur))
            .map_err(|_| Error::new(Reason::TooManyHoles))?;
        self.verifier_les_acquittements();
        Ok(())
    }

    /// Le premier octet que le pair n'a pas encore accusé.
    ///
    /// C'est par là que reprend une retransmission.
    #[must_use]
    pub fn first_unacked(&self) -> u64 {
        self.acquittes.contiguous_from(0)
    }

    /// Reste-t-il quelque chose à renvoyer ?
    #[must_use]
    pub fn en_attente(&self) -> bool {
        self.first_unacked() < self.ecrit || self.acquittes.count() > 1
    }

    /// Annule le flux (§19.4).
    ///
    /// Rend la taille finale à écrire dans la trame.
    ///
    /// # LA TAILLE FINALE EST CE QU'ON A DÉJÀ ÉMIS, ET RIEN D'AUTRE
    ///
    /// §4.5 : le receveur compte cette taille dans son contrôle de flux. En
    /// déclarer moins que ce qu'on a envoyé le ferait se contredire avec les
    /// octets qu'il a déjà ; en déclarer plus lui ferait réserver du crédit pour
    /// des octets qui ne viendront jamais.
    ///
    /// # Errors
    ///
    /// [`Reason::SendClosed`] si le flux est déjà terminé normalement : un flux
    /// dont tout est acquitté n'a plus rien à annuler, et le dire au pair le
    /// ferait douter de ce qu'il a déjà livré à son application.
    pub fn reset(&mut self) -> Result<u64, Error> {
        match self.etat {
            // Déjà annulé : on redit la même taille, ce qui est exactement ce
            // qu'une retransmission de `RESET_STREAM` doit faire.
            SendState::ResetSent | SendState::ResetRecvd => Ok(self.finale.unwrap_or(self.ecrit)),
            SendState::DataRecvd => Err(Error::new(Reason::SendClosed)),
            _ => {
                self.finale = Some(self.ecrit);
                self.etat = SendState::ResetSent;
                Ok(self.ecrit)
            }
        }
    }

    /// Note que le pair a accusé l'annulation (§3.1).
    pub const fn on_reset_acked(&mut self) {
        if matches!(self.etat, SendState::ResetSent) {
            self.etat = SendState::ResetRecvd;
        }
    }

    /// Range un `STOP_SENDING` (§3.5, §19.5).
    ///
    /// **CE N'EST PAS UNE FERMETURE, C'EST UNE DEMANDE.** §3.5 : on DEVRAIT
    /// répondre par un `RESET_STREAM`, mais rien n'oblige à le faire dans
    /// l'instant — un `STOP_SENDING` peut croiser sur le fil le `FIN` qui rendait
    /// la demande sans objet. C'est à l'appelant de décider, et
    /// [`Send::stop_sending`] lui dit qu'il y a une décision à prendre.
    pub const fn on_stop_sending(&mut self, code: u64) {
        if self.etat.ouvert() {
            self.stoppe = Some(code);
        }
    }

    /// Passe à `Data Recvd` si le pair a tout accusé, `FIN` compris.
    fn verifier_les_acquittements(&mut self) {
        if !matches!(self.etat, SendState::DataSent) {
            return;
        }
        // Tout est accusé quand un seul intervalle part de zéro et va jusqu'à la
        // taille finale.
        if self.acquittes.contiguous_from(0) >= self.finale.unwrap_or(u64::MAX) {
            self.etat = SendState::DataRecvd;
        }
    }
}

#[cfg(test)]
mod tests;
