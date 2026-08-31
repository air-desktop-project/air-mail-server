// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le contrôle de flux de la CONNEXION, et la concurrence des flux
//! (RFC 9000 §4.1, §4.6).
//!
//! # DEUX ROBINETS, ET IL FAUT LES DEUX
//!
//! Un flux a sa limite ; la connexion a la sienne. Sans la seconde, un pair
//! ouvrirait mille flux à leur limite chacun et nous ferait retenir mille fois
//! une fenêtre — le contrôle par flux ne borne rien tout seul.
//!
//! # ET C'EST LA SOMME DES PLUS GRANDS DÉCALAGES, NON LE NOMBRE D'OCTETS
//!
//! §4.1 : « the maximum of the sum of the absolute byte offsets of all
//! streams ». Compter les octets reçus ferait payer deux fois une
//! retransmission, et un pair honnête finirait par se voir fermer la connexion
//! pour avoir renvoyé ce qu'on n'avait pas reçu. C'est pourquoi [`Recv`] et
//! [`Send`] rendent une PROGRESSION, et non une longueur.
//!
//! [`Recv`]: crate::Recv
//! [`Send`]: crate::Send
//!
//! # LA MÊME ARITHMÉTIQUE, DEUX FAUTES DIFFÉRENTES
//!
//! Dépasser la limite qu'on a annoncée est la faute du PAIR, et se dit par un
//! `FLOW_CONTROL_ERROR`. Dépasser celle qu'il nous a annoncée est la NÔTRE, et
//! ne se dit à personne : elle se voit en essai, ou jamais. Le même compteur
//! porte donc les deux, et sait de quel côté il est.

use ams_proto_quic::{Directional, Initiator, StreamId};

use crate::error::{Error, Reason};

/// De quel côté un compteur regarde.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cote {
    /// Ce qu'on a annoncé au pair : le dépasser est SA faute.
    Reception,
    /// Ce que le pair nous a annoncé : le dépasser est la NÔTRE.
    Emission,
}

impl Cote {
    /// La faute que porte un dépassement de ce côté.
    const fn faute(self) -> Reason {
        match self {
            Self::Reception => Reason::FlowControl,
            Self::Emission => Reason::SendOverflow,
        }
    }
}

/// Le contrôle de flux d'une connexion, dans un sens (§4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flow {
    /// La limite en vigueur, en octets cumulés.
    limite: u64,
    /// Ce qui est déjà consommé.
    utilise: u64,
    /// De quel côté on regarde.
    cote: Cote,
}

impl Flow {
    /// Un compteur pour ce qu'on a annoncé au pair.
    #[must_use]
    pub const fn receiving(limite: u64) -> Self {
        Self {
            limite,
            utilise: 0,
            cote: Cote::Reception,
        }
    }

    /// Un compteur pour ce que le pair nous a annoncé.
    #[must_use]
    pub const fn sending(limite: u64) -> Self {
        Self {
            limite,
            utilise: 0,
            cote: Cote::Emission,
        }
    }

    /// La limite en vigueur.
    #[must_use]
    pub const fn limit(&self) -> u64 {
        self.limite
    }

    /// Ce qui est consommé.
    #[must_use]
    pub const fn used(&self) -> u64 {
        self.utilise
    }

    /// Ce qui reste.
    #[must_use]
    pub const fn available(&self) -> u64 {
        self.limite.saturating_sub(self.utilise)
    }

    /// Le robinet est-il fermé ?
    ///
    /// C'est ce qui décide d'un `DATA_BLOCKED` (§19.12) du côté émission.
    #[must_use]
    pub const fn blocked(&self) -> bool {
        self.available() == 0
    }

    /// Relève la limite sur un `MAX_DATA` (§19.9).
    ///
    /// **UNE LIMITE PLUS BASSE N'EST PAS UNE FAUTE, ET N'A PAS D'EFFET** (§4.1) :
    /// deux `MAX_DATA` peuvent arriver dans le désordre, et personne n'a tort.
    pub const fn set_limit(&mut self, limite: u64) {
        if limite > self.limite {
            self.limite = limite;
        }
    }

    /// Consomme une progression.
    ///
    /// `progression` est ce que [`Recv::on_stream`] ou [`Send::on_sent`] ont
    /// fait monter — jamais une longueur de trame.
    ///
    /// [`Recv::on_stream`]: crate::Recv::on_stream
    /// [`Send::on_sent`]: crate::Send::on_sent
    ///
    /// # Errors
    ///
    /// [`Reason::FlowControl`] du côté réception, [`Reason::SendOverflow`] du
    /// côté émission. **ET RIEN N'EST CONSOMMÉ QUAND ON REFUSE** : la connexion
    /// va se fermer, mais l'état qu'on rapportera restera celui d'avant.
    pub fn consume(&mut self, progression: u64) -> Result<(), Error> {
        let apres = self.utilise.saturating_add(progression);
        if apres > self.limite {
            return Err(Error::new(self.cote.faute()));
        }
        self.utilise = apres;
        Ok(())
    }

    /// De combien il faudrait relever pour laisser passer `voulu` de plus.
    ///
    /// Rend la nouvelle limite à annoncer, ou `None` si celle en vigueur suffit
    /// déjà — ce qui évite d'écrire un `MAX_DATA` qui ne dit rien de neuf.
    #[must_use]
    pub const fn grant(&self, voulu: u64) -> Option<u64> {
        match voulu > self.available() {
            true => Some(self.utilise.saturating_add(voulu)),
            false => None,
        }
    }
}

/// Combien de flux d'un type le pair peut ouvrir, et combien il en a ouvert
/// (§4.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Concurrence {
    /// Le plafond : seuls les rangs STRICTEMENT inférieurs sont permis.
    plafond: u64,
    /// Le rang du prochain flux jamais ouvert.
    ///
    /// **ON COMPTE PAR RANG, ET NON PAR FLUX VIVANTS** (§4.6) : « Only streams
    /// with a stream ID less than (max_streams * 4 + first_stream_id_of_type)
    /// can be opened ». Un flux fermé n'a pas rendu son rang ; c'est un
    /// `MAX_STREAMS` qui rend du crédit, et lui seul.
    suivant: u64,
}

impl Concurrence {
    /// Un compteur neuf, avec le plafond annoncé.
    #[must_use]
    pub const fn new(plafond: u64) -> Self {
        Self {
            plafond,
            suivant: 0,
        }
    }

    /// Le plafond en vigueur.
    #[must_use]
    pub const fn limit(&self) -> u64 {
        self.plafond
    }

    /// Le rang du prochain flux jamais ouvert.
    #[must_use]
    pub const fn next(&self) -> u64 {
        self.suivant
    }

    /// Combien de flux peuvent encore s'ouvrir.
    #[must_use]
    pub const fn available(&self) -> u64 {
        self.plafond.saturating_sub(self.suivant)
    }

    /// Ne peut-on plus en ouvrir ?
    ///
    /// C'est ce qui décide d'un `STREAMS_BLOCKED` (§19.14). §4.6 le dit
    /// « useful for debugging » : **ON NE L'ATTEND PAS POUR RENDRE DU CRÉDIT**,
    /// sans quoi le pair resterait bloqué un aller-retour entier, et
    /// indéfiniment s'il choisit de ne pas l'envoyer.
    #[must_use]
    pub const fn blocked(&self) -> bool {
        self.available() == 0
    }

    /// Relève le plafond sur un `MAX_STREAMS` (§19.11).
    ///
    /// **UN `MAX_STREAMS` QUI N'AUGMENTE PAS SE JETTE** (§4.6), et ce n'est pas
    /// une faute.
    pub const fn set_limit(&mut self, plafond: u64) {
        if plafond > self.plafond {
            self.plafond = plafond;
        }
    }

    /// Le pair ouvre le flux de rang `rang`.
    ///
    /// Sans effet si ce rang est déjà connu : une trame peut arriver deux fois,
    /// et les flux d'un type s'ouvrent dans le désordre.
    ///
    /// # Errors
    ///
    /// [`Reason::StreamLimit`] au-delà du plafond qu'on a annoncé.
    pub const fn open_remote(&mut self, rang: u64) -> Result<(), Error> {
        if rang >= self.plafond {
            return Err(Error::new(Reason::StreamLimit));
        }
        // **OUVRIR LE RANG N OUVRE AUSSI TOUS CEUX D'AVANT** (§2.1) : les flux
        // d'un type ne s'ouvrent pas dans l'ordre, et un rang qui saute des
        // numéros les crée implicitement. Compter autrement laisserait des rangs
        // jamais consommés, et le plafond ne bornerait plus rien.
        let apres = rang.saturating_add(1);
        if apres > self.suivant {
            self.suivant = apres;
        }
        Ok(())
    }

    /// On ouvre un flux, et l'on prend le rang suivant.
    ///
    /// # Errors
    ///
    /// [`Reason::StreamLimit`] au-delà du plafond que le pair a annoncé. **C'EST
    /// NOTRE FAUTE**, et l'appelant doit attendre un `MAX_STREAMS` plutôt que
    /// d'ouvrir.
    pub const fn open_local(&mut self) -> Result<u64, Error> {
        if self.suivant >= self.plafond {
            return Err(Error::new(Reason::StreamLimit));
        }
        let rang = self.suivant;
        self.suivant = rang.saturating_add(1);
        Ok(rang)
    }
}

/// Les quatre plafonds d'une connexion (§4.6).
///
/// Deux types de flux, deux sens d'ouverture : ce sont quatre comptes
/// indépendants, et les confondre laisserait un pair épuiser un crédit qu'on
/// avait accordé pour autre chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Concurrences {
    /// Ce que le pair peut ouvrir en bidirectionnel.
    entrants_bidi: Concurrence,
    /// Ce que le pair peut ouvrir en unidirectionnel.
    entrants_uni: Concurrence,
    /// Ce qu'on peut ouvrir en bidirectionnel.
    sortants_bidi: Concurrence,
    /// Ce qu'on peut ouvrir en unidirectionnel.
    sortants_uni: Concurrence,
    /// Qui nous sommes — c'est ce qui dit si un flux est entrant ou sortant.
    nous: Initiator,
}

impl Concurrences {
    /// Les quatre comptes, avec les plafonds des paramètres de transport
    /// (§18.2).
    ///
    /// `annonces` sont ceux qu'on a annoncés — donc ce que le PAIR peut ouvrir ;
    /// `recus` ceux qu'il a annoncés — donc ce que NOUS pouvons ouvrir.
    #[must_use]
    pub const fn new(nous: Initiator, annonces: (u64, u64), recus: (u64, u64)) -> Self {
        Self {
            entrants_bidi: Concurrence::new(annonces.0),
            entrants_uni: Concurrence::new(annonces.1),
            sortants_bidi: Concurrence::new(recus.0),
            sortants_uni: Concurrence::new(recus.1),
            nous,
        }
    }

    /// Le compte des flux entrants d'un sens.
    #[must_use]
    pub const fn incoming(&self, sens: Directional) -> &Concurrence {
        match sens {
            Directional::Bidirectional => &self.entrants_bidi,
            Directional::Unidirectional => &self.entrants_uni,
        }
    }

    /// Le compte des flux sortants d'un sens, pour le modifier.
    pub const fn outgoing_mut(&mut self, sens: Directional) -> &mut Concurrence {
        match sens {
            Directional::Bidirectional => &mut self.sortants_bidi,
            Directional::Unidirectional => &mut self.sortants_uni,
        }
    }

    /// Le compte des flux entrants d'un sens, pour le modifier.
    pub const fn incoming_mut(&mut self, sens: Directional) -> &mut Concurrence {
        match sens {
            Directional::Bidirectional => &mut self.entrants_bidi,
            Directional::Unidirectional => &mut self.entrants_uni,
        }
    }

    /// Le compte des flux sortants d'un sens.
    #[must_use]
    pub const fn outgoing(&self, sens: Directional) -> &Concurrence {
        match sens {
            Directional::Bidirectional => &self.sortants_bidi,
            Directional::Unidirectional => &self.sortants_uni,
        }
    }

    /// Range un flux dont une trame vient de parler.
    ///
    /// # Errors
    ///
    /// [`Reason::StreamLimit`] si le pair dépasse le plafond qu'on lui a
    /// annoncé ; [`Reason::WrongStreamDirection`] s'il parle sur un flux
    /// unidirectionnel qui nous appartient — celui-là, il n'a pas le droit de
    /// l'ouvrir, encore moins d'y écrire.
    pub fn seen(&mut self, flux: StreamId) -> Result<(), Error> {
        let sens = flux.directional();
        if flux.initiator() == self.nous {
            // **UN FLUX QU'ON A OUVERT NE S'OUVRE PAS PAR SA TRAME** : le pair
            // ne peut qu'y répondre, et seulement s'il est bidirectionnel.
            if !flux.peer_can_send(self.nous) {
                return Err(Error::new(Reason::WrongStreamDirection));
            }
            return Ok(());
        }
        self.incoming_mut(sens).open_remote(flux.index())
    }
}

#[cfg(test)]
mod tests;
