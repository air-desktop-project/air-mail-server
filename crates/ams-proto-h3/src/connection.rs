// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La machine de connexion : la discipline des flux critiques, les réglages, et
//! l'extinction ordonnée (§4.1, §5.2, §6.2, §7.2.4 de RFC 9114).
//!
//! # C'EST L'ÉTAGE DEUX, ET IL NE FAIT TOUJOURS AUCUNE ENTRÉE-SORTIE
//!
//! Les trames, les réglages, les types de flux et QPACK savaient chacun une
//! chose. Ici ils se nouent : un type de flux s'annonce, une trame arrive,
//! l'état bouge, et l'on sait si la connexion tient encore. Rien n'est lu, rien
//! n'est écrit (C1).
//!
//! # NOUS SOMMES LE SERVEUR, ET CELA SIMPLIFIE BEAUCOUP
//!
//! Ce serveur ne pousse pas, ne promet pas, et n'ouvre aucun flux
//! bidirectionnel. Les états qu'un client aurait — attendre une promesse, tenir
//! un compte de poussées à soi — n'existent donc pas ici, et pas davantage les
//! gardes qui les auraient protégés.
//!
//! # UNE CONNEXION HTTP/3 TIENT À TROIS FLUX, ET ILS NE SE FERMENT PAS
//!
//! Le flux de contrôle et les deux flux QPACK sont **critiques** : §6.2.1 et §4.2
//! de RFC 9204 disent que les fermer est une faute, et non un adieu. Il n'y en a
//! qu'un de chaque par sens, et un second est une faute aussi.
//!
//! La raison est la même dans les deux cas : ces flux portent l'état que les
//! autres présupposent. Un flux de contrôle qui se ferme emporte le seul canal
//! par où la connexion s'entend ; un second prétendrait décrire le même état
//! deux fois, et rien ne dirait lequel croire.
//!
//! # ET LES RÉGLAGES ARRIVENT EN PREMIER, OU JAMAIS
//!
//! §6.2.1 : si la première trame du flux de contrôle n'est pas `SETTINGS`, c'est
//! `H3_MISSING_SETTINGS`. Ce n'est pas du formalisme : les réglages disent ce
//! que le pair accepte, et traiter une trame avant de les connaître, c'est
//! travailler sur des bornes qu'on ignore encore.

use crate::error::{Error, Reason};
use crate::frame::FrameKind;
use crate::settings::Settings;
use crate::stream::StreamKind;

/// Combien de trames de service on accepte sur le flux de contrôle avant de
/// juger que le pair en fait trop.
///
/// # AUCUNE FENÊTRE NE BORNE CE FLUX-LÀ
///
/// Le contrôle de flux de QUIC borne les octets d'un flux, et §6.2.1 nous
/// demande justement de donner assez de crédit au flux de contrôle pour qu'il ne
/// bloque jamais. Un pair peut donc y écrire des `MAX_PUSH_ID`, des trames
/// inconnues et des `CANCEL_PUSH` sans fin : chacune coûte un traitement, et
/// aucune ne fait progresser quoi que ce soit.
///
/// C'est la même famille de défaut que *Rapid Reset* en HTTP/2 — un travail
/// gratuit qu'aucun compteur existant ne voit.
pub const SERVICE_FRAMES_MAX: u32 = 200;

/// Le plus grand identifiant qu'un serveur peut mettre dans un `GOAWAY` (§5.2).
///
/// 2^62 - 4 : c'est le plus grand identifiant de flux bidirectionnel ouvert par
/// un client qui tienne dans un entier variable. Le client, lui, y met un
/// identifiant de poussée, dont le maximum est 2^62 - 1.
pub const GOAWAY_MAX: u64 = (1 << 62) - 4;

/// Où en est la connexion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Le flux de contrôle du pair n'a pas encore dit ses réglages.
    Ouverture,
    /// Les réglages sont connus, et l'on sert.
    Ouverte,
    /// Un `GOAWAY` a été émis ou reçu : on finit ce qui est commencé.
    Extinction,
}

/// La connexion HTTP/3, côté serveur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Connection {
    /// Où l'on en est.
    etat: State,
    /// Ce que le pair a réglé, une fois qu'il l'a dit.
    reglages: Option<Settings>,
    /// A-t-on vu son flux de contrôle ?
    controle: bool,
    /// Son flux d'encodeur QPACK ?
    encodeur: bool,
    /// Son flux de décodeur QPACK ?
    decodeur: bool,
    /// Le plus petit `GOAWAY` qu'on ait émis (§5.2).
    goaway_emis: Option<u64>,
    /// Le plus petit `GOAWAY` qu'on ait reçu.
    goaway_recu: Option<u64>,
    /// Le plafond de poussées que le client a annoncé, s'il en a annoncé un.
    ///
    /// **ON NE POUSSE PAS**, et ce champ ne sert donc qu'à une chose : vérifier
    /// que le client ne le fait pas reculer. Le garder sans l'employer serait
    /// inutile ; l'ignorer laisserait passer une contradiction qu'on a le devoir
    /// de voir.
    max_push_id: Option<u64>,
    /// Combien de trames de service ont passé sans que rien n'avance.
    service: u32,
}

impl Default for Connection {
    fn default() -> Self {
        Self::new()
    }
}

impl Connection {
    /// Une connexion neuve, dont on n'a encore rien entendu.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            etat: State::Ouverture,
            reglages: None,
            controle: false,
            encodeur: false,
            decodeur: false,
            goaway_emis: None,
            goaway_recu: None,
            max_push_id: None,
            service: 0,
        }
    }

    /// L'état.
    #[must_use]
    pub const fn state(&self) -> State {
        self.etat
    }

    /// Ce que le pair a réglé, une fois qu'il l'a dit.
    #[must_use]
    pub const fn peer_settings(&self) -> Option<Settings> {
        self.reglages
    }

    /// Le plafond de poussées annoncé, s'il l'a été.
    #[must_use]
    pub const fn max_push_id(&self) -> Option<u64> {
        self.max_push_id
    }

    /// Le `GOAWAY` qu'on a émis, s'il l'a été.
    #[must_use]
    pub const fn goaway_sent(&self) -> Option<u64> {
        self.goaway_emis
    }

    /// Le `GOAWAY` qu'on a reçu, s'il l'a été.
    #[must_use]
    pub const fn goaway_received(&self) -> Option<u64> {
        self.goaway_recu
    }

    /// Le pair ouvre un flux unidirectionnel de ce type.
    ///
    /// # Errors
    ///
    /// [`Reason::DuplicateCriticalStream`] pour un second flux critique (§6.2.1,
    /// §4.2 de RFC 9204) ; [`Reason::PushRefused`] pour un flux de poussée, que
    /// seul un serveur peut ouvrir — le recevoir veut dire que le client se
    /// prend pour nous ; [`Reason::UnknownStreamType`] pour ce qu'on ne sait pas
    /// conduire.
    ///
    /// # UN TYPE INCONNU N'EST PAS UNE FAUTE DE CONNEXION
    ///
    /// §6.2 : « The recipient MUST NOT consider unknown stream types to be a
    /// connection error of any kind. » On rend donc une faute, mais l'appelant
    /// doit n'abandonner QUE ce flux — c'est ce qui permet à une extension
    /// d'ouvrir les siens sans casser les pairs qui ne la connaissent pas.
    pub fn on_peer_stream(&mut self, kind: StreamKind) -> Result<(), Error> {
        let deja = match kind {
            StreamKind::Control => core::mem::replace(&mut self.controle, true),
            StreamKind::QpackEncoder => core::mem::replace(&mut self.encodeur, true),
            StreamKind::QpackDecoder => core::mem::replace(&mut self.decodeur, true),
            // §6.2.2 : un flux de poussée vient d'un serveur. D'un client, c'est
            // qu'il s'est trompé de rôle, et la suite ne sera pas ce qu'on croit.
            StreamKind::Push => return Err(Error::new(Reason::PushRefused)),
            StreamKind::Unknown(_) => return Err(Error::new(Reason::UnknownStreamType)),
        };
        match deja {
            true => Err(Error::new(Reason::DuplicateCriticalStream)),
            false => Ok(()),
        }
    }

    /// Un flux critique du pair s'est fermé.
    ///
    /// # Errors
    ///
    /// Toujours [`Reason::CriticalStreamClosed`] : §6.2.1 et §4.2 de RFC 9204
    /// n'ont pas de cas où c'est acceptable. **CETTE FONCTION NE REND JAMAIS
    /// `Ok`**, et c'est voulu : son type dit ce que la RFC dit, plutôt que de
    /// laisser l'appelant croire qu'il existe une fermeture bénigne.
    pub const fn on_critical_stream_closed(&self) -> Result<(), Error> {
        Err(Error::new(Reason::CriticalStreamClosed))
    }

    /// Une trame arrive sur le flux de contrôle du pair.
    ///
    /// `reglages` porte les réglages lus quand la trame est un `SETTINGS`.
    ///
    /// # Errors
    ///
    /// [`Reason::MissingSettings`] si la première trame n'est pas `SETTINGS`
    /// (§6.2.1) ; [`Reason::RepeatedSettings`] pour un second (§7.2.4) ;
    /// [`Reason::FrameOnWrongStream`] pour ce qui n'a pas sa place là ;
    /// [`Reason::PushRefused`] pour un `MAX_PUSH_ID` qui recule (§7.2.7) ;
    /// [`Reason::GoAwayIncreased`] pour un `GOAWAY` qui monte (§5.2) ;
    /// [`Reason::ServiceFlood`] quand le pair n'envoie plus que du service.
    pub fn on_control_frame(
        &mut self,
        kind: FrameKind,
        reglages: Option<Settings>,
        identifiant: u64,
    ) -> Result<(), Error> {
        // **LA RÈGLE DE §6.2.1 PASSE AVANT CELLE DE §7.2**, et l'ordre n'est pas
        // arbitraire : « If the first frame of the control stream is any other
        // frame type, this MUST be treated as a connection error of type
        // H3_MISSING_SETTINGS. » *Any other* ne fait pas d'exception pour les
        // trames qui n'avaient de toute façon pas leur place ici.
        //
        // Les deux ferment la connexion, mais pas avec le même code — et c'est
        // le code que le pair lira dans son journal pour comprendre ce qu'il a
        // fait de travers. Lui dire « trame inattendue » quand il a simplement
        // oublié ses réglages l'enverrait chercher au mauvais endroit.
        //
        // Divergence trouvée par le fuzz, sur un `DATA` en première trame.
        if self.reglages.is_none() && !matches!(kind, FrameKind::Settings) {
            return Err(Error::new(Reason::MissingSettings));
        }
        if !kind.sur_le_controle() {
            return Err(Error::new(Reason::FrameOnWrongStream));
        }
        match kind {
            FrameKind::Settings => {
                // §7.2.4 : « it MUST NOT be sent subsequently ».
                if self.reglages.is_some() {
                    return Err(Error::new(Reason::RepeatedSettings));
                }
                self.reglages = Some(reglages.unwrap_or(Settings::DEFAULT));
                // **RIEN N'A PU NOUS FAIRE SORTIR DE `Ouverture` AVANT ICI** :
                // §6.2.1 refuse toute trame antérieure aux réglages, `GOAWAY`
                // compris. Une garde sur l'état serait donc une branche
                // qu'aucune séquence ne peut emprunter.
                self.etat = State::Ouverte;
                Ok(())
            }
            FrameKind::GoAway => self.on_goaway(identifiant),
            FrameKind::MaxPushId => self.on_max_push_id(identifiant),
            // `CANCEL_PUSH` et les types inconnus ne changent rien chez nous,
            // mais ils coûtent un traitement — et c'est cela qu'on compte.
            _ => self.service(),
        }
    }

    /// Une instruction QPACK licite qui ne fait rien avancer.
    ///
    /// # LE MÊME DÉFAUT QUE SUR LE FLUX DE CONTRÔLE, PAR UNE AUTRE PORTE
    ///
    /// §4.2 de RFC 9204 fait des deux flux QPACK des flux critiques : comme le
    /// flux de contrôle, ils doivent avoir de quoi ne jamais bloquer. Un pair
    /// peut donc y écrire sans fin des instructions que §4.4.2 rend parfaitement
    /// licites — une annulation de flux ne s'accompagne d'aucune condition
    /// d'erreur — et dont il n'y a **rien à faire** quand on ne tient pas de
    /// table.
    ///
    /// Chacune coûte un traitement et n'avance rien. C'est [`SERVICE_FRAMES_MAX`]
    /// qui compte, et c'est le même compteur que celui du flux de contrôle : un
    /// pair qui travaille le remet à zéro, un pair qui ne fait que cela finit par
    /// s'entendre dire qu'il en fait trop.
    ///
    /// # Errors
    ///
    /// [`Reason::ServiceFlood`] au-delà de [`SERVICE_FRAMES_MAX`].
    pub fn on_qpack_instruction(&mut self) -> Result<(), Error> {
        self.service()
    }

    /// Le client relève son plafond de poussées (§7.2.7).
    ///
    /// # Errors
    ///
    /// [`Reason::PushRefused`] s'il le fait RECULER : §7.2.7 ne parle que de
    /// l'augmenter, et un plafond qui descend contredirait des promesses qu'il
    /// nous a déjà autorisées.
    fn on_max_push_id(&mut self, plafond: u64) -> Result<(), Error> {
        if self.max_push_id.is_some_and(|avant| plafond < avant) {
            return Err(Error::new(Reason::PushRefused));
        }
        self.max_push_id = Some(plafond);
        self.service()
    }

    /// Le pair s'éteint (§5.2).
    ///
    /// # Errors
    ///
    /// [`Reason::GoAwayIncreased`] si l'identifiant MONTE : §5.2 en fait une
    /// faute `H3_ID_ERROR`, parce qu'un client a pu réémettre ailleurs les
    /// requêtes qu'un `GOAWAY` précédent avait déclarées perdues. Les
    /// réaccepter les ferait exécuter deux fois.
    fn on_goaway(&mut self, identifiant: u64) -> Result<(), Error> {
        if self.goaway_recu.is_some_and(|avant| identifiant > avant) {
            return Err(Error::new(Reason::GoAwayIncreased));
        }
        self.goaway_recu = Some(identifiant);
        self.etat = State::Extinction;
        Ok(())
    }

    /// On s'éteint : quel identifiant mettre dans notre `GOAWAY` (§5.2) ?
    ///
    /// Rend l'identifiant à écrire, borné par [`GOAWAY_MAX`] et par ce qu'on a
    /// déjà annoncé.
    ///
    /// # ON PEUT EN ENVOYER PLUSIEURS, MAIS JAMAIS PLUS HAUT
    ///
    /// §5.2 décrit exactement l'extinction en deux temps : d'abord [`GOAWAY_MAX`]
    /// pour que le client cesse d'ouvrir, puis, une fois les requêtes en vol
    /// arrivées, le rang réel de ce qu'on servira. **C'est notre propre règle
    /// qu'on tient ici** : la violer ferait réexécuter chez nous des requêtes
    /// qu'un client a déjà réémises ailleurs.
    pub fn goaway(&mut self, identifiant: u64) -> u64 {
        let borne = identifiant.min(GOAWAY_MAX);
        let dit = self.goaway_emis.map_or(borne, |avant| borne.min(avant));
        self.goaway_emis = Some(dit);
        self.etat = State::Extinction;
        dit
    }

    /// Accepte-t-on encore une requête sur ce flux ?
    ///
    /// §5.2 : « Requests or pushes with the indicated identifier or greater are
    /// rejected by the sender of the GOAWAY. » Une requête au-delà se refuse
    /// donc — et se refuse par un `H3_REQUEST_REJECTED`, qui promet au client
    /// que rien n'a été commencé et qu'il peut réémettre ailleurs.
    #[must_use]
    pub fn accepts(&self, flux: u64) -> bool {
        self.goaway_emis.is_none_or(|borne| flux < borne)
    }

    /// Compte une trame qui ne fait rien avancer.
    fn service(&mut self) -> Result<(), Error> {
        self.service = self.service.saturating_add(1);
        match self.service > SERVICE_FRAMES_MAX {
            true => Err(Error::new(Reason::ServiceFlood)),
            false => Ok(()),
        }
    }

    /// Une requête vient d'aboutir : le pair a fait avancer quelque chose.
    ///
    /// **C'EST CE QUI REMET LE COMPTEUR DE SERVICE À ZÉRO**, et c'est la seule
    /// chose qui le fasse. Un pair qui travaille peut envoyer autant de trames
    /// de service qu'il veut ; un pair qui n'envoie QUE cela finit par se voir
    /// dire qu'il en fait trop.
    pub const fn progres(&mut self) {
        self.service = 0;
    }
}

/// Où en est un message sur un flux de requête (§4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageState {
    /// Rien n'est encore arrivé : on attend la section d'en-têtes.
    Attente,
    /// Les en-têtes sont là ; le corps peut suivre.
    EnTetes,
    /// Le corps a commencé.
    Corps,
    /// La section terminale est là : plus rien ne peut suivre.
    Fin,
}

/// Un message sur un flux de requête, vu comme une suite de trames.
///
/// # LA SÉQUENCE EST COURTE, ET C'EST TOUT L'INTÉRÊT
///
/// §4.1 : une section d'en-têtes, puis des `DATA`, puis au plus une section
/// terminale. Un `DATA` avant les en-têtes ou quoi que ce soit après la section
/// terminale est une faute de CONNEXION, et non de flux — §4.1 le dit, et la
/// raison est qu'une telle suite ne vient pas d'un pair qui s'est trompé sur une
/// requête, mais d'un pair qui ne sait pas ce qu'il fait.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Message {
    /// Où l'on en est.
    etat: Option<MessageState>,
}

impl Message {
    /// Un message neuf.
    #[must_use]
    pub const fn new() -> Self {
        Self { etat: None }
    }

    /// L'état.
    #[must_use]
    pub fn state(&self) -> MessageState {
        self.etat.unwrap_or(MessageState::Attente)
    }

    /// Une trame arrive sur ce flux.
    ///
    /// # Errors
    ///
    /// [`Reason::FrameOnWrongStream`] pour ce qui n'a pas sa place sur une
    /// requête (§7.2) ; [`Reason::FrameOutOfOrder`] pour une suite que §4.1
    /// interdit.
    pub fn on_frame(&mut self, kind: FrameKind) -> Result<(), Error> {
        if !kind.sur_une_requete() {
            return Err(Error::new(Reason::FrameOnWrongStream));
        }
        // §4.1 : « Frames of unknown types MAY be sent before, after, or
        // interleaved with other frames. » Elles ne font donc pas avancer la
        // séquence — et ne peuvent pas la rompre non plus.
        if matches!(kind, FrameKind::Unknown(_)) {
            return Ok(());
        }
        let suivant = match (self.state(), kind) {
            // Une seule section d'en-têtes ouvre le message.
            (MessageState::Attente, FrameKind::Headers) => MessageState::EnTetes,
            // Le corps suit les en-têtes, et se poursuit.
            (MessageState::EnTetes | MessageState::Corps, FrameKind::Data) => MessageState::Corps,
            // La section terminale ferme, qu'il y ait eu un corps ou non.
            (MessageState::EnTetes | MessageState::Corps, FrameKind::Headers) => MessageState::Fin,
            // **UN `DATA` AVANT LES EN-TÊTES, OU QUOI QUE CE SOIT APRÈS LA
            // SECTION TERMINALE.** §4.1 les nomme tous les deux.
            _ => return Err(Error::new(Reason::FrameOutOfOrder)),
        };
        self.etat = Some(suivant);
        Ok(())
    }

    /// Le flux se termine : le message est-il complet ?
    ///
    /// **UN MESSAGE SANS EN-TÊTES N'EST PAS UN MESSAGE** (§4.1). §4.1 demande
    /// alors un `H3_REQUEST_INCOMPLETE`, qui ne condamne que le flux : un client
    /// qui abandonne sa requête en cours de route n'a pas cassé la connexion.
    ///
    /// # Errors
    ///
    /// [`Reason::IncompleteRequest`] si rien ou seulement une partie est arrivé.
    pub fn on_end(&self) -> Result<(), Error> {
        match self.state() {
            MessageState::EnTetes | MessageState::Corps | MessageState::Fin => Ok(()),
            MessageState::Attente => Err(Error::new(Reason::IncompleteRequest)),
        }
    }
}

#[cfg(test)]
mod tests;
