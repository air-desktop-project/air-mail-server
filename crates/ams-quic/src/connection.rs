// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La machine d'état d'une connexion (RFC 9000 §8.1, §10 ; RFC 9001 §4.1, §4.9).
//!
//! # UNE CONNEXION QUIC NE SE FERME PAS, ELLE S'ÉTEINT
//!
//! Il n'y a pas de `FIN` à acquitter, pas de poignée de main de fermeture : un
//! `CONNECTION_CLOSE` part, et l'émetteur reste **encore là un moment** à
//! répondre aux paquets en retard. §10.2 : ces états existent « to ensure that
//! connections close cleanly and that delayed or reordered packets are properly
//! discarded ».
//!
//! Sans eux, un paquet retardé arrivant après la disparition de l'état
//! trouverait un serveur qui ne le reconnaît pas — et qui répondrait par un
//! `Stateless Reset` à un pair qui n'a rien fait de mal.
//!
//! # ET AVANT D'ÊTRE ÉTABLIE, ELLE EST UN LEVIER
//!
//! §8.1 : un serveur qui répond librement à une adresse qu'il n'a pas validée
//! est une machine à amplifier. L'attaquant écrit l'adresse de sa victime dans
//! un datagramme de mille deux cents octets, et le serveur envoie à cette
//! victime ce qu'il croit être une réponse.
//!
//! D'où la borne de trois : **tant que l'adresse n'est pas validée, on n'émet
//! pas plus de trois fois ce qu'on a reçu**. Ce n'est pas une politique de
//! service, c'est ce qui empêche notre serveur d'être l'arme de quelqu'un
//! d'autre. Et le compte porte sur TOUS les octets reçus et attribués à la
//! connexion, y compris ceux des paquets qu'on a jetés — sans quoi il suffirait
//! d'envoyer du bruit pour ouvrir le robinet.
//!
//! # LE TEMPS VIENT DE L'APPELANT
//!
//! Ce crate ne lit pas d'horloge (C1). Tous les instants et toutes les durées
//! sont en microsecondes, et c'est l'appelant qui les fournit. La machine dit
//! quand il faudra la rappeler ; elle ne se réveille pas toute seule.

use ams_proto_quic::Space;
use ams_quic_crypto::Role;

/// Le facteur d'amplification de §8.1.
///
/// **TROIS, ET C'EST UN MAXIMUM, NON UN OBJECTIF.** Il vient de ce qu'un serveur
/// doit pouvoir répondre à un `Initial` de 1200 octets par un certificat, qui
/// n'y tient pas. Le monter donnerait un meilleur levier à l'attaquant ; le
/// descendre empêcherait des poignées de main honnêtes d'aboutir.
pub const AMPLIFICATION_FACTOR: u64 = 3;

/// Combien de délais de retransmission durent les états de fermeture (§10.2).
///
/// Trois. C'est ce qu'il faut pour que les paquets encore en vol arrivent, et
/// pour que le pair ait le temps de retransmettre le sien.
pub const CLOSING_PTOS: u64 = 3;

/// Le plancher du délai d'inactivité, en délais de retransmission (§10.1).
///
/// « To avoid excessively small idle timeout periods, endpoints MUST increase
/// the idle timeout period to be at least three times the current PTO. » Sans ce
/// plancher, un pair pourrait annoncer une milliseconde et faire expirer toute
/// connexion avant la première retransmission.
pub const IDLE_PTOS: u64 = 3;

/// Où en est une connexion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// La poignée de main est en cours.
    Handshaking,
    /// La poignée de main est confirmée (§4.1.2 de RFC 9001).
    Confirmed,
    /// On a émis un `CONNECTION_CLOSE`, et l'on répond encore (§10.2.1).
    Closing,
    /// Le pair a fermé : on n'émet plus rien (§10.2.2).
    Draining,
    /// L'état peut être jeté.
    Closed,
}

impl State {
    /// La connexion sert-elle encore à quelque chose ?
    #[must_use]
    pub const fn vivante(self) -> bool {
        matches!(self, Self::Handshaking | Self::Confirmed)
    }

    /// Est-on en train de s'éteindre ?
    #[must_use]
    pub const fn s_eteint(self) -> bool {
        matches!(self, Self::Closing | Self::Draining)
    }
}

/// Une connexion, vue comme une machine à états.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Connection {
    /// Qui nous sommes.
    role: Role,
    /// Où l'on en est.
    etat: State,
    /// Le délai d'inactivité négocié, en microsecondes ; zéro si aucun.
    inactivite: u64,
    /// L'instant de la dernière activité qui compte.
    dernier_signe: u64,
    /// Un paquet suscitant un acquittement est-il parti depuis la dernière
    /// réception ?
    ///
    /// §10.1 : le compteur ne se remet à zéro à l'émission que pour le PREMIER
    /// de ces paquets. Le remettre à chaque envoi laisserait un pair muet nous
    /// retenir indéfiniment, à condition qu'on parle.
    elicite_depuis_reception: bool,
    /// Ce qu'on a reçu, en octets de datagrammes attribués à la connexion.
    recu: u64,
    /// Ce qu'on a émis.
    emis: u64,
    /// L'adresse du pair est-elle validée (§8.1) ?
    adresse_validee: bool,
    /// L'échéance des états de fermeture.
    echeance: Option<u64>,
    /// A-t-on encore les clés `Initial` (§4.9.1 de RFC 9001) ?
    clefs_initiales: bool,
    /// Et celles de `Handshake` (§4.9.2) ?
    ///
    /// **CELLES DE L'ESPACE APPLICATIF NE SE JETTENT PAS**, et c'est pourquoi
    /// elles n'ont pas de champ ici. §4.9.3 ne parle que des clés `0-RTT`, que
    /// l'on n'offre pas (C6) ; celles de `1-RTT` vivent aussi longtemps que la
    /// connexion. Un troisième booléen serait un état qu'aucun événement ne peut
    /// changer — c'est-à-dire une affirmation non vérifiée.
    clefs_de_poignee: bool,
    /// Combien de paquets sont arrivés depuis qu'on ferme.
    recus_en_fermeture: u64,
    /// Au bout de combien on répondra de nouveau.
    prochaine_reponse: u64,
}

impl Connection {
    /// Une connexion neuve.
    ///
    /// `annonce` est le délai d'inactivité qu'on annonce, `recu` celui que le
    /// pair annonce, en microsecondes ; zéro veut dire « aucun ».
    ///
    /// # LE DÉLAI EFFECTIF EST LE PLUS PETIT DES DEUX NON NULS
    ///
    /// §10.1 : « the minimum of the two advertised values (or the sole
    /// advertised value, if only one endpoint advertises a non-zero value) ».
    /// Prendre le minimum tout court ferait qu'un pair qui n'annonce rien —
    /// c'est-à-dire qui accepte de rester indéfiniment — annulerait le délai de
    /// celui qui en voulait un.
    #[must_use]
    pub fn new(role: Role, annonce: u64, recu: u64, maintenant: u64) -> Self {
        let inactivite = match (annonce, recu) {
            (0, autre) | (autre, 0) => autre,
            (un, deux) => un.min(deux),
        };
        Self {
            role,
            etat: State::Handshaking,
            inactivite,
            dernier_signe: maintenant,
            elicite_depuis_reception: false,
            recu: 0,
            emis: 0,
            // **UN CLIENT N'A PAS D'ADRESSE À VALIDER** : c'est lui qui a écrit
            // le premier, et le serveur ne peut pas l'amplifier vers un tiers.
            adresse_validee: matches!(role, Role::Client),
            echeance: None,
            clefs_initiales: true,
            clefs_de_poignee: true,
            recus_en_fermeture: 0,
            prochaine_reponse: 1,
        }
    }

    /// L'état.
    #[must_use]
    pub const fn state(&self) -> State {
        self.etat
    }

    /// Qui nous sommes.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Le délai d'inactivité négocié, en microsecondes ; zéro si aucun.
    #[must_use]
    pub const fn idle_timeout(&self) -> u64 {
        self.inactivite
    }

    /// L'adresse du pair est-elle validée (§8.1) ?
    #[must_use]
    pub const fn address_validated(&self) -> bool {
        self.adresse_validee
    }

    /// A-t-on encore les clés de cet espace (§4.9 de RFC 9001) ?
    ///
    /// **LA QUESTION EST « LES A-T-ON JETÉES ? », ET NON « LES A-T-ON DÉRIVÉES ? »**
    /// Savoir si les clés applicatives sont prêtes appartient à la poignée de
    /// main TLS, qui vit ailleurs ; cette machine-ci ne sait que ce qu'elle a
    /// écarté. Répondre autrement mêlerait deux questions dont les réponses
    /// changent à des moments différents.
    #[must_use]
    pub const fn has_keys(&self, espace: Space) -> bool {
        match espace {
            Space::Initial => self.clefs_initiales,
            Space::Handshake => self.clefs_de_poignee,
            Space::Application => true,
        }
    }

    /// Combien d'octets on peut encore émettre (§8.1).
    ///
    /// `u64::MAX` une fois l'adresse validée : la borne d'amplification ne
    /// s'applique plus, et c'est le contrôle de congestion qui prend le relais.
    #[must_use]
    pub fn send_budget(&self) -> u64 {
        match self.adresse_validee {
            true => u64::MAX,
            false => self
                .recu
                .saturating_mul(AMPLIFICATION_FACTOR)
                .saturating_sub(self.emis),
        }
    }

    /// Est-on à la borne d'amplification ?
    ///
    /// C'est ce qui crée l'interblocage que §8.1 décrit : le serveur ne peut plus
    /// parler, et le client n'a plus rien à dire. C'est au client de le rompre en
    /// émettant sur son délai de retransmission — mais encore faut-il que le
    /// serveur sache le dire.
    #[must_use]
    pub fn amplification_limited(&self) -> bool {
        self.send_budget() == 0
    }

    /// Un datagramme est arrivé, et il est attribué à cette connexion.
    ///
    /// **ON COMPTE TOUT** (§8.1) : « servers MUST count all of the payload bytes
    /// received in datagrams that are uniquely attributed to a single
    /// connection. This includes datagrams that contain packets that are
    /// successfully processed and datagrams that contain packets that are all
    /// discarded. » Ne compter que ce qu'on a su lire donnerait moins de crédit
    /// à un pair honnête dont un paquet s'est perdu qu'à celui qui n'envoie que
    /// du bruit.
    ///
    /// Cela ne relance PAS le délai d'inactivité : §10.1 demande un paquet
    /// « received and processed successfully », et c'est
    /// [`Connection::on_packet_processed`] qui le dit.
    pub const fn on_datagram_received(&mut self, octets: u64) {
        self.recu = self.recu.saturating_add(octets);
    }

    /// Un paquet a été lu et traité avec succès.
    ///
    /// Trois conséquences suivent du même fait, et c'est pourquoi elles tiennent
    /// dans un seul appel :
    ///
    /// 1. le délai d'inactivité repart (§10.1) ;
    /// 2. un paquet `Handshake` valide l'adresse du pair (§8.1) — « receipt of a
    ///    packet protected with Handshake keys confirms that the peer
    ///    successfully processed an Initial packet » ;
    /// 3. un serveur qui traite son premier `Handshake` jette ses clés
    ///    `Initial` (§4.9.1 de RFC 9001).
    pub fn on_packet_processed(&mut self, espace: Space, maintenant: u64) {
        self.dernier_signe = maintenant;
        self.elicite_depuis_reception = false;
        if !matches!(espace, Space::Handshake) {
            return;
        }
        // **UN `Handshake` VALIDE L'ADRESSE, ET C'EST GRATUIT** : ses clés ne se
        // dérivent qu'après avoir lu les trames `CRYPTO` de l'`Initial`, ce
        // qu'un attaquant qui usurpe une adresse ne peut pas faire — il ne voit
        // pas la réponse.
        self.adresse_validee = true;
        if matches!(self.role, Role::Server) {
            self.clefs_initiales = false;
        }
    }

    /// Un paquet vient d'être émis.
    ///
    /// `eliciting` dit s'il suscite un acquittement — c'est ce qui décide si le
    /// délai d'inactivité repart (§10.1).
    ///
    /// Un client qui émet son premier `Handshake` jette ses clés `Initial`
    /// (§4.9.1 de RFC 9001).
    pub fn on_packet_sent(&mut self, espace: Space, octets: u64, eliciting: bool, maintenant: u64) {
        self.emis = self.emis.saturating_add(octets);
        // §10.1 : seulement pour le PREMIER paquet suscitant un acquittement
        // depuis la dernière réception.
        if eliciting && !self.elicite_depuis_reception {
            self.elicite_depuis_reception = true;
            self.dernier_signe = maintenant;
        }
        if matches!(espace, Space::Handshake) && matches!(self.role, Role::Client) {
            self.clefs_initiales = false;
        }
    }

    /// La poignée de main est confirmée (§4.1.2 de RFC 9001).
    ///
    /// Au serveur, c'est quand elle s'achève ; au client, quand un
    /// `HANDSHAKE_DONE` arrive.
    ///
    /// **ET LES CLÉS `Handshake` PARTENT AVEC** (§4.9.2) : les garder laisserait
    /// une protection plus faible utilisable après qu'une plus forte est
    /// disponible.
    pub fn on_handshake_confirmed(&mut self) {
        if !matches!(self.etat, State::Handshaking) {
            return;
        }
        self.etat = State::Confirmed;
        self.adresse_validee = true;
        self.clefs_initiales = false;
        self.clefs_de_poignee = false;
    }

    /// On ferme : un `CONNECTION_CLOSE` part, et l'on entre en `Closing`
    /// (§10.2.1).
    ///
    /// `pto` est le délai de retransmission courant, en microsecondes.
    ///
    /// **ON RESTE LÀ TROIS DÉLAIS**, et non parce que c'est poli : disparaître
    /// tout de suite ferait répondre par un `Stateless Reset` au prochain paquet
    /// en retard — c'est-à-dire dire à un pair qui n'a rien fait de mal que sa
    /// connexion n'a jamais existé.
    pub fn close(&mut self, pto: u64, maintenant: u64) {
        if !self.etat.vivante() {
            return;
        }
        self.etat = State::Closing;
        self.echeance = Some(maintenant.saturating_add(pto.saturating_mul(CLOSING_PTOS)));
    }

    /// Le pair a fermé : on entre en `Draining` (§10.2.2).
    ///
    /// **ON N'ÉMET PLUS RIEN** à partir de là. §10.2.2 : sans cette règle, deux
    /// pairs qui se répondent échangeraient des `CONNECTION_CLOSE` jusqu'à ce
    /// que l'un des deux abandonne.
    ///
    /// Venant de `Closing`, **l'échéance ne bouge pas** : §10.2.2 dit que « the
    /// draining state ends when the closing state would have ended ». La
    /// repousser laisserait un pair prolonger notre état en fermant après nous.
    pub fn on_connection_close(&mut self, pto: u64, maintenant: u64) {
        if matches!(self.etat, State::Draining | State::Closed) {
            return;
        }
        let deja = self.echeance;
        self.etat = State::Draining;
        self.echeance =
            Some(deja.unwrap_or(maintenant.saturating_add(pto.saturating_mul(CLOSING_PTOS))));
    }

    /// Quand il faudra rappeler la machine, en microsecondes absolues.
    ///
    /// `None` quand rien n'est à échoir : ni délai d'inactivité négocié, ni état
    /// de fermeture en cours.
    #[must_use]
    pub fn deadline(&self, pto: u64) -> Option<u64> {
        match self.etat {
            State::Closed => None,
            State::Closing | State::Draining => self.echeance,
            // §10.1 : au moins trois délais de retransmission, quoi qu'on ait
            // négocié.
            _ => match self.inactivite {
                0 => None,
                delai => Some(
                    self.dernier_signe
                        .saturating_add(delai.max(pto.saturating_mul(IDLE_PTOS))),
                ),
            },
        }
    }

    /// L'heure a sonné : la machine avance si son échéance est passée.
    ///
    /// Rend `true` si la connexion vient de s'éteindre.
    ///
    /// # L'INACTIVITÉ FERME EN SILENCE, ET C'EST VOULU
    ///
    /// §10.1 : « the connection is silently closed and its state is discarded ».
    /// Pas de `CONNECTION_CLOSE` : si le pair est parti, personne ne le lira, et
    /// s'il est encore là, son propre délai vient d'expirer aussi.
    pub fn on_timeout(&mut self, pto: u64, maintenant: u64) -> bool {
        let Some(echeance) = self.deadline(pto) else {
            return false;
        };
        if maintenant < echeance {
            return false;
        }
        self.etat = State::Closed;
        self.echeance = None;
        true
    }

    /// Un paquet est arrivé alors qu'on ferme : faut-il redire notre
    /// `CONNECTION_CLOSE` ?
    ///
    /// # ON RÉPOND DE MOINS EN MOINS SOUVENT, ET C'EST UNE OBLIGATION
    ///
    /// §10.2.1 : « An endpoint SHOULD limit the rate at which it generates
    /// packets in the closing state. For instance, an endpoint could wait for a
    /// progressively increasing number of received packets. » Sans cela, un pair
    /// qui continue d'émettre — parce qu'il n'a pas reçu notre fermeture, ou
    /// parce qu'il le fait exprès — obtiendrait une réponse par paquet, et l'on
    /// amplifierait au moment précis où l'on n'a plus rien à dire.
    ///
    /// On répond donc au premier, au deuxième, au quatrième, au huitième :
    /// l'écart double, et le coût total reste logarithmique.
    ///
    /// **ET EN `Draining`, ON NE RÉPOND JAMAIS** (§10.2.2).
    pub fn should_answer(&mut self) -> bool {
        if !matches!(self.etat, State::Closing) {
            return false;
        }
        self.recus_en_fermeture = self.recus_en_fermeture.saturating_add(1);
        if self.recus_en_fermeture < self.prochaine_reponse {
            return false;
        }
        self.prochaine_reponse = self.prochaine_reponse.saturating_mul(2);
        true
    }
}

#[cfg(test)]
mod tests;
