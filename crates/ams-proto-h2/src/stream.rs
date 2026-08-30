// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les flux : leurs numéros, leurs états, et ce qu'on accepte d'eux (§5).
//!
//! # LES NUMÉROS NE SE RÉEMPLOIENT PAS, ET C'EST UNE RÈGLE DE SÛRETÉ
//!
//! §5.1.1 : un client ouvre des flux IMPAIRS, et chaque nouveau numéro doit être
//! STRICTEMENT SUPÉRIEUR à tous ceux qu'il a déjà employés. Ce n'est pas de
//! l'hygiène : un numéro réemployé désignerait deux requêtes différentes au même
//! moment, et la réponse de l'une pourrait partir vers l'autre.
//!
//! La même section dit qu'ouvrir un flux **ferme implicitement** tous les flux
//! oisifs de numéro inférieur. C'est ce qui permet de ne RIEN retenir des flux
//! fermés : au-delà du plus grand numéro reçu, un flux est oisif ; en deçà, s'il
//! n'est pas dans la table, il est fermé. Deux mots d'état pour un espace de
//! deux milliards de numéros.
//!
//! # LES ÉTATS « RÉSERVÉS » N'EXISTENT PAS ICI
//!
//! §5.1 en définit deux, et ils ne servent qu'à la poussée serveur — que §8.4 a
//! dépréciée, que ce serveur n'émet pas, et dont il annonce `ENABLE_PUSH` à
//! zéro. Les porter quand même serait écrire deux états qu'aucune transition ne
//! peut atteindre.

use crate::error::{Cause, Error, ErrorCode};
use crate::flow::Window;

/// Combien de flux ce serveur traite de front.
///
/// C'est ce qu'on annonce dans `SETTINGS_MAX_CONCURRENT_STREAMS`, et donc la
/// taille de la table. §5.1.2 recommande de ne pas descendre sous cent.
pub const MAX_CONCURRENT_STREAMS: u32 = 128;

/// L'état d'un flux (§5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// `open` — les deux côtés peuvent encore envoyer.
    Open,
    /// `half-closed (remote)` — le pair a fini ; nous pouvons répondre.
    HalfClosedRemote,
    /// `half-closed (local)` — NOUS avons fini ; le pair peut encore envoyer.
    ///
    /// # IL EXISTE PARCE QU'ON RÉPOND PARFOIS AVANT LA FIN
    ///
    /// Un serveur qui refuse une requête n'attend pas d'en avoir lu le corps :
    /// il répond `413`, et le client peut encore être en train d'envoyer. Le
    /// flux n'est pas fermé pour autant — ce qui arrive après compte toujours
    /// dans les fenêtres, et l'oublier ferait diverger notre contrôle de flux de
    /// celui du pair.
    HalfClosedLocal,
    /// `closed` — plus rien ne passe.
    Closed,
}

/// Ce qu'un flux porte.
///
/// # DEUX FENÊTRES, ET ELLES NE SE RESSEMBLENT PAS
///
/// §5.2.1 en donne une par SENS. Celle de réception dit ce que le pair peut
/// encore nous envoyer : c'est NOUS qui l'ouvrons, et lui qui la consomme.
/// Celle d'émission dit ce que nous pouvons encore lui envoyer : c'est LUI qui
/// l'ouvre, et nous qui la consommons.
///
/// N'en tenir qu'une reviendrait à croire son propre compte pour celui du pair.
/// Elles partent de valeurs différentes — chacun annonce la sienne — et rien ne
/// les ramène jamais l'une à l'autre.
#[derive(Debug, Clone, Copy)]
struct Flux {
    /// Son numéro.
    id: u32,
    /// Où il en est.
    etat: StreamState,
    /// Sa fenêtre de RÉCEPTION : ce que le pair peut encore nous envoyer.
    fenetre: Window,
    /// Sa fenêtre d'ÉMISSION : ce que nous pouvons encore lui envoyer.
    emission: Window,
}

/// Les flux d'une connexion.
#[derive(Debug)]
pub struct Streams {
    /// Ceux qui vivent encore.
    ouverts: [Option<Flux>; MAX_CONCURRENT_STREAMS as usize],
    /// Le plus grand numéro que le pair ait employé.
    ///
    /// **C'EST LUI QUI DISTINGUE « OISIF » DE « FERMÉ »** : au-delà, un flux
    /// n'a jamais existé ; en deçà et hors de la table, il a existé et il est
    /// fermé. Sans lui, il faudrait retenir tous les flux fermés d'une
    /// connexion — ce qu'un pair choisirait alors comme il veut.
    dernier_recu: u32,
    /// La fenêtre initiale de RÉCEPTION des flux à venir — celle qu'on annonce.
    fenetre_initiale: u32,
    /// La fenêtre initiale d'ÉMISSION des flux à venir — celle que le pair
    /// annonce.
    ///
    /// Elle vaut la valeur par défaut de §6.5.2 **tant que le pair n'a rien
    /// dit** : ses cadres peuvent précéder son `SETTINGS`, et attendre pour
    /// compter reviendrait à ne pas compter.
    fenetre_pair: u32,
}

impl Streams {
    /// Une connexion sans flux.
    #[must_use]
    pub fn new(fenetre_initiale: u32) -> Self {
        Self {
            ouverts: [None; MAX_CONCURRENT_STREAMS as usize],
            dernier_recu: 0,
            fenetre_initiale,
            fenetre_pair: crate::flow::INITIAL_WINDOW_SIZE,
        }
    }

    /// Combien de flux vivent.
    #[must_use]
    pub fn len(&self) -> u32 {
        // La table a cent vingt-huit places : le compte y tient toujours.
        u32::try_from(self.ouverts.iter().flatten().count()).unwrap_or(u32::MAX)
    }

    /// Aucun flux ne vit-il ?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Le plus grand numéro reçu.
    #[must_use]
    pub const fn last_received(&self) -> u32 {
        self.dernier_recu
    }

    /// L'état d'un flux.
    ///
    /// **UN FLUX QU'ON NE CONNAÎT PAS N'EST PAS FORCÉMENT OISIF** : s'il est en
    /// deçà du plus grand numéro reçu, il a existé et il est FERMÉ. Les
    /// confondre ferait accepter sur un flux fermé ce qu'on doit refuser.
    #[must_use]
    pub fn state(&self, id: u32) -> Option<StreamState> {
        if let Some(flux) = self.trouver(id) {
            return Some(flux.etat);
        }
        match id <= self.dernier_recu {
            true => Some(StreamState::Closed),
            // Oisif : il n'a jamais existé.
            false => None,
        }
    }

    /// Ouvre un flux à la réception d'un `HEADERS`.
    ///
    /// # Errors
    ///
    /// [`Cause::BadStreamId`] pour un numéro pair, nul, ou qui ne progresse
    /// pas ; [`Cause::TooManyStreams`] au-delà de ce qu'on traite de front.
    pub fn open(&mut self, id: u32) -> Result<(), Error> {
        // §5.1.1 : LES FLUX D'UN CLIENT SONT IMPAIRS, et le flux zéro est la
        // connexion. Un numéro pair venu d'un client désignerait un flux que
        // seul un serveur peut ouvrir — pour une poussée qu'on ne fait pas.
        if id == 0 || id.is_multiple_of(2) {
            return Err(Error::connection(
                ErrorCode::ProtocolError,
                Cause::BadStreamId,
            ));
        }
        // §5.1.1 : STRICTEMENT SUPÉRIEUR. Un numéro réemployé désignerait deux
        // requêtes au même moment, et la réponse de l'une pourrait partir vers
        // l'autre.
        if id <= self.dernier_recu {
            return Err(Error::connection(
                ErrorCode::ProtocolError,
                Cause::BadStreamId,
            ));
        }
        // §5.1.2 : au-delà de ce qu'on traite, `REFUSED_STREAM` — et ce code est
        // une PROMESSE (§8.7) : le client peut réémettre sans risque, parce
        // qu'on n'a rien commencé.
        let Some(place) = self.ouverts.iter_mut().find(|place| place.is_none()) else {
            return Err(Error::stream(
                ErrorCode::RefusedStream,
                Cause::TooManyStreams,
            ));
        };
        *place = Some(Flux {
            id,
            etat: StreamState::Open,
            fenetre: Window::new(self.fenetre_initiale),
            emission: Window::new(self.fenetre_pair),
        });
        self.dernier_recu = id;
        Ok(())
    }

    /// Le pair a fini d'envoyer sur ce flux (`END_STREAM`).
    ///
    /// # ELLE NE REND PAS DE FAUTE, ET CE N'EST PAS UN RELÂCHEMENT
    ///
    /// La faute qu'elle pourrait rendre — recevoir sur un flux dont le pair a
    /// déjà fini — est rendue par ce qui PRÉCÈDE nécessairement tout
    /// `END_STREAM` : [`Streams::consume`] pour un `DATA`, [`Streams::open`]
    /// pour un `HEADERS`. La rendre ici une seconde fois ferait une branche
    /// qu'aucun appel ne peut emprunter, et **une garde inatteignable n'est pas
    /// une garde : c'est une affirmation non vérifiée.**
    ///
    /// Elle ne peut rien abîmer non plus : elle ne touche que les flux VIVANTS
    /// de la table — un flux fermé n'y est plus, et un flux qui avait déjà fini
    /// y reste tel quel.
    ///
    /// **QUAND NOUS AVIONS DÉJÀ FINI, LE FLUX SE FERME** : les deux côtés ont
    /// dit leur dernier mot, et le garder occuperait une place que §5.1.2
    /// compte.
    pub fn end_remote(&mut self, id: u32) {
        match self.state(id) {
            Some(StreamState::HalfClosedLocal) => self.close(id),
            Some(StreamState::Open | StreamState::HalfClosedRemote) => {
                self.poser(id, StreamState::HalfClosedRemote);
            }
            Some(StreamState::Closed) | None => {}
        }
    }

    /// NOUS avons fini d'envoyer sur ce flux (`END_STREAM`).
    ///
    /// Comme sa jumelle, elle ne rend pas de faute : l'appelant a déjà dû
    /// obtenir la permission d'écrire, et écrire deux fins ne change rien à
    /// l'état.
    pub fn end_local(&mut self, id: u32) {
        match self.state(id) {
            // Le pair avait fini : les deux côtés ont dit leur dernier mot.
            Some(StreamState::HalfClosedRemote) => self.close(id),
            Some(StreamState::Open) => self.poser(id, StreamState::HalfClosedLocal),
            Some(StreamState::HalfClosedLocal | StreamState::Closed) | None => {}
        }
    }

    /// Ferme un flux, et rend sa place.
    ///
    /// Sert au `RST_STREAM` du pair comme à notre propre conclusion. **Ce n'est
    /// jamais une faute** : §5.1 admet un `RST_STREAM` sur un flux déjà fermé,
    /// parce qu'il a pu croiser notre réponse sur le fil.
    pub fn close(&mut self, id: u32) {
        for place in &mut self.ouverts {
            if place.is_some_and(|flux| flux.id == id) {
                *place = None;
            }
        }
    }

    /// La fenêtre de réception d'un flux vivant.
    #[must_use]
    pub fn window(&self, id: u32) -> Option<Window> {
        self.trouver(id).map(|flux| flux.fenetre)
    }

    /// Consomme la fenêtre d'un flux à la réception d'un `DATA`.
    ///
    /// # Errors
    ///
    /// [`Cause::WrongStreamState`] hors d'un flux qui peut recevoir ;
    /// [`Cause::WindowExceeded`] au-delà de la fenêtre.
    pub fn consume(&mut self, id: u32, octets: u32) -> Result<(), Error> {
        let etat = self.exiger(id)?;
        // **UN FLUX DONT NOUS AVONS FINI REÇOIT ENCORE.** Nous avons cessé
        // d'écrire, pas lui : ce qui arrive compte dans les fenêtres, et le
        // refuser ferait diverger notre contrôle de flux du sien.
        if !matches!(etat, StreamState::Open | StreamState::HalfClosedLocal) {
            return Err(Error::stream(
                ErrorCode::StreamClosed,
                Cause::WrongStreamState,
            ));
        }
        // La recherche rend une COPIE : on modifie puis on repose, plutôt que de
        // tenir un emprunt mutable pendant qu'on lit l'état.
        let mut fenetre = self
            .trouver(id)
            .map(|flux| flux.fenetre)
            .unwrap_or_default();
        fenetre.consume(octets)?;
        self.poser_fenetre(id, fenetre);
        Ok(())
    }

    /// Rend pleine la fenêtre de réception d'un flux vivant.
    ///
    /// # POURQUOI REMPLIR, ET NON CRÉDITER
    ///
    /// Personne ne crédite notre fenêtre de réception : c'est NOUS qui
    /// l'ouvrons, et nous savons donc toujours à quelle valeur la ramener. Une
    /// méthode qui ajouterait un crédit rendrait deux fautes — un crédit nul,
    /// un débordement — qu'aucun appel ne pourrait provoquer, puisque
    /// l'appelant calcule ce crédit à partir de la fenêtre elle-même. Remplir
    /// ne peut pas échouer, et c'est ce qui rend la garde inutile plutôt
    /// qu'inatteignable.
    ///
    /// Elle ne touche que les flux VIVANTS : un flux fermé n'est plus dans la
    /// table, et lui rendre une fenêtre serait lui promettre ce qu'on ne
    /// tiendra pas.
    pub fn refill(&mut self, id: u32, pleine: u32) {
        self.poser_fenetre(id, Window::new(pleine));
    }

    /// Applique une nouvelle `SETTINGS_INITIAL_WINDOW_SIZE` (§6.9.2).
    ///
    /// # TOUTES LES FENÊTRES OUVERTES BOUGENT, DE LA MÊME DIFFÉRENCE
    ///
    /// Et certaines deviennent négatives : voir [`crate::Window`]. Ne l'appliquer
    /// qu'aux flux à venir ferait diverger notre compte de celui du pair, et le
    /// contrôle de flux ne contrôlerait plus rien.
    ///
    /// # Errors
    ///
    /// [`Cause::WindowOverflow`] si une fenêtre dépasserait 2^31-1.
    pub fn set_initial_window(&mut self, taille: u32) -> Result<(), Error> {
        // §6.5.2 : au-delà de 2^31-1, c'est un `FLOW_CONTROL_ERROR`. La lecture
        // des `SETTINGS` le refuse déjà — et on le refuse ICI aussi, parce que
        // cette méthode est publique et qu'un appelant qui l'oublierait
        // fabriquerait des fenêtres hors borne. Un fuzz l'a fait.
        if i64::from(taille) > crate::flow::WINDOW_MAX {
            return Err(Error::connection(
                ErrorCode::FlowControlError,
                Cause::WindowOverflow,
            ));
        }
        let variation = i64::from(taille).saturating_sub(i64::from(self.fenetre_initiale));
        // **ON VÉRIFIE TOUT AVANT D'APPLIQUER QUOI QUE CE SOIT.** Ajuster au fil
        // de la boucle et s'arrêter en chemin laisserait la moitié des fenêtres
        // déplacées et l'autre non — un état que ni nous ni le pair ne saurions
        // décrire, et qui ferait diverger les deux comptes pour de bon.
        let mut essai = self.ouverts;
        for place in &mut essai {
            if let Some(flux) = place.as_mut() {
                flux.fenetre.adjust(variation)?;
            }
        }
        self.ouverts = essai;
        self.fenetre_initiale = taille;
        Ok(())
    }

    /// La fenêtre d'émission d'un flux vivant : ce qu'on peut encore lui
    /// envoyer.
    #[must_use]
    pub fn send_window(&self, id: u32) -> Option<Window> {
        self.trouver(id).map(|flux| flux.emission)
    }

    /// Prend AU PLUS `voulu` octets à la fenêtre d'émission d'un flux, et rend
    /// ce qui a été pris.
    ///
    /// Comme [`Window::take`], elle ne rend pas de faute : à l'émission, on
    /// choisit combien envoyer, et jamais plus que ce qui est ouvert. Un flux
    /// qui n'est plus là ne donne rien.
    pub fn take_send(&mut self, id: u32, voulu: u32) -> u32 {
        let Some(mut fenetre) = self.send_window(id) else {
            return 0;
        };
        let pris = fenetre.take(voulu);
        self.poser_emission(id, fenetre);
        pris
    }

    /// Ajoute du crédit à la fenêtre d'émission d'un flux : le pair vient
    /// d'envoyer un `WINDOW_UPDATE`.
    ///
    /// # Errors
    ///
    /// [`Cause::ZeroWindowUpdate`], [`Cause::WindowOverflow`], ou l'état.
    pub fn credit_send(&mut self, id: u32, octets: u32) -> Result<(), Error> {
        self.exiger(id)?;
        let mut fenetre = self.send_window(id).unwrap_or_default();
        fenetre.increase(octets)?;
        self.poser_emission(id, fenetre);
        Ok(())
    }

    /// Applique la `SETTINGS_INITIAL_WINDOW_SIZE` que LE PAIR vient d'annoncer
    /// (§6.9.2).
    ///
    /// # CE N'EST PAS LA MÊME QUE LA NÔTRE, ET CE N'EST PAS LE MÊME SENS
    ///
    /// Le réglage qu'un pair annonce dit ce qu'IL accepte de recevoir : il borne
    /// donc ce que NOUS émettons. Le confondre avec le nôtre ferait bouger les
    /// fenêtres du mauvais côté — et les deux comptes divergeraient sans qu'un
    /// seul cadre soit fautif.
    ///
    /// # Errors
    ///
    /// [`Cause::WindowOverflow`] si une fenêtre dépasserait 2^31-1.
    pub fn set_peer_initial_window(&mut self, taille: u32) -> Result<(), Error> {
        if i64::from(taille) > crate::flow::WINDOW_MAX {
            return Err(Error::connection(
                ErrorCode::FlowControlError,
                Cause::WindowOverflow,
            ));
        }
        let variation = i64::from(taille).saturating_sub(i64::from(self.fenetre_pair));
        // ON VÉRIFIE TOUT AVANT D'APPLIQUER, comme pour la réception : la moitié
        // des fenêtres déplacées serait un état que personne ne sait décrire.
        let mut essai = self.ouverts;
        for place in &mut essai {
            if let Some(flux) = place.as_mut() {
                flux.emission.adjust(variation)?;
            }
        }
        self.ouverts = essai;
        self.fenetre_pair = taille;
        Ok(())
    }

    /// Le flux vivant de ce numéro.
    fn trouver(&self, id: u32) -> Option<Flux> {
        self.ouverts
            .iter()
            .flatten()
            .find(|flux| flux.id == id)
            .copied()
    }

    /// L'état d'un flux qui doit vivre, ou la faute qui convient.
    fn exiger(&self, id: u32) -> Result<StreamState, Error> {
        match self.state(id) {
            Some(StreamState::Closed) | None => Err(Error::stream(
                ErrorCode::StreamClosed,
                Cause::WrongStreamState,
            )),
            Some(etat) => Ok(etat),
        }
    }

    /// Pose l'état d'un flux.
    fn poser(&mut self, id: u32, etat: StreamState) {
        for place in &mut self.ouverts {
            if let Some(flux) = place.as_mut()
                && flux.id == id
            {
                flux.etat = etat;
            }
        }
    }

    /// Pose la fenêtre de réception d'un flux.
    fn poser_fenetre(&mut self, id: u32, fenetre: Window) {
        for place in &mut self.ouverts {
            if let Some(flux) = place.as_mut()
                && flux.id == id
            {
                flux.fenetre = fenetre;
            }
        }
    }

    /// Pose la fenêtre d'émission d'un flux.
    fn poser_emission(&mut self, id: u32, fenetre: Window) {
        for place in &mut self.ouverts {
            if let Some(flux) = place.as_mut()
                && flux.id == id
            {
                flux.emission = fenetre;
            }
        }
    }
}

#[cfg(test)]
mod tests;
