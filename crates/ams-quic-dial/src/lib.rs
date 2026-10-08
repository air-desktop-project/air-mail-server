// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Joindre un pair en QUIC, et lui parler HTTP/3.
//!
//! # LA MOITIÉ QUI MANQUAIT, ET CE QU'ELLE COÛTAIT
//!
//! Ce dépôt sert QUIC depuis le 2026-08-28, et la pile porte ses deux moitiés
//! depuis longtemps : `Connection::connect` est écrite à côté de
//! `Connection::accept`, et `ams_h3::Http3Client` à côté d'`ams_h3::Http3`.
//! **Ce qui n'existait pas, c'est ce fichier** : la socket, l'horloge et la
//! boucle qui font parler les deux.
//!
//! Faute de quoi, le seul client QUIC du dépôt était `ams-quic-client` — un
//! harnais d'essai, `publish = false`, qui compose ses paquets à la main et
//! n'entre jamais dans le serveur. Et la seule vraie boucle cliente écrite sur
//! cette pile vivait **dans un autre dépôt**, `air-service-locator-client`,
//! épinglée sur un commit de septembre : la moitié cliente de notre pile
//! avançait ici sans que ce qui la conduit avance avec elle.
//!
//! # CE QU'ELLE NE SAIT PAS, ET IL FAUT LE SAVOIR
//!
//! Elle hérite des limites de [`ams_quic_tls::Connection::connect`], qui sont
//! écrites là-bas : **ni `Retry`, ni négociation de version**. Notre serveur
//! n'en émet aucun ; un autre serveur le pourrait, et la connexion échouerait
//! au lieu de reprendre.
//!
//! Elle ne fait **aucune reprise** : pas de nouvelle tentative, pas de recul,
//! pas de bascule vers un second pair. Ce n'est pas un oubli — c'est une
//! politique, elle dépend de ce qu'on joint, et elle vit chez l'appelant
//! (`asl_client::Reprise` en est une).
//!
//! Elle ne **diffuse pas** un corps de requête : [`ams_h3::Http3Client`] écrit
//! la requête entière et termine le flux. Le corps d'une annonce fait quelques
//! centaines d'octets ; le jour où un appelant voudra diffuser, ce sera un
//! ajout là-bas.
//!
//! # UNE CONNEXION TENUE, ET CE QUE CELA CHANGE
//!
//! Un appel HTTP ordinaire ouvre, demande, lit, ferme. Celui-ci peut faire
//! autre chose : **garder la connexion**, y poser plusieurs requêtes, et tenir
//! un flux dont **la réponse ne se termine jamais** ([`Appel::tenir`]). C'est
//! ce que `GET /v1/poussees` d'`air-service-locator` demande, et c'est la
//! raison pour laquelle ce n'est pas une fonction mais un objet.
//!
//! Qui tient une connexion doit l'**entretenir** : [`Appel::entretenir`] lit ce
//! qui arrive, fait échoir les délais, et émet ce qui attend. Sans elle, le
//! keepalive ne part pas et le pair déclare l'inactivité.
//!
//! # L'ALÉA ET L'HEURE VIENNENT DE L'APPELANT
//!
//! §7.2 de RFC 9000 : le client choisit un identifiant de destination d'au
//! moins huit octets, et §5.2 en dérive les clés `Initial`. **Un identifiant
//! devinable rendrait ces clés-là devinables.** La pile ne tire rien
//! elle-même — c'est une entrée-sortie —, et cette crate-ci ne fait que
//! transmettre ce qu'on lui donne.
//!
//! L'heure, elle, est lue ici : c'est une crate d'étage 3, et attendre est son
//! métier.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ams_h3::{Http3Client, ReponseRecue};
use ams_proto_http::StatusCode;
use ams_proto_quic::{ConnectionId, StreamId};
use ams_quic::RecvState;
use ams_quic_tls::Connection;
use tokio::net::UdpSocket;

mod pont;

use pont::Pont;

/// Combien de temps la poignée de main a pour aboutir.
pub const POIGNEE_MS: u64 = 5_000;

/// Combien de temps une réponse a pour arriver en entier.
pub const REPONSE_MS: u64 = 10_000;

/// Ce qu'un datagramme peut occuper au plus.
///
/// **SOIXANTE-CINQ MILLE OCTETS, ET NON MILLE DEUX CENTS** — c'est le même
/// nombre et la même raison que dans l'écoute : §14 borne ce qu'on ÉMET, pas ce
/// qu'on reçoit. Un pair a le droit de nous écrire plus grand, et le tronquer
/// ferait échouer l'authentification de son dernier paquet, pour une raison
/// qu'aucun des deux côtés ne saurait nommer.
const PLACE_OCTETS: usize = 65_535;

/// Combien de fois de suite on rappelle le conducteur sur un même flux.
///
/// La boucle s'arrête d'elle-même dès que le conducteur ne prend plus rien
/// (voir [`Appel::servir`]) ; ce plafond est la ceinture, pour le cas où un
/// jour il rendrait la main sans avoir avancé.
const LECTURES_MAX: u32 = 64;

/// Ce qu'un appel peut refuser.
#[derive(Debug)]
pub enum Faute {
    /// La socket ou le noyau ont refusé.
    Socket(std::io::Error),
    /// Le transport QUIC a refusé.
    Quic(ams_quic_tls::Error),
    /// Le conducteur HTTP/3 a refusé.
    Http3(ams_h3::Error),
    /// Rien n'est arrivé dans le temps imparti.
    ///
    /// **CE N'EST PAS UNE FAUTE DU PAIR** : elle ne dit qu'une chose, qu'on n'a
    /// rien obtenu. En tirer une conséquence — réessayer, changer de pair,
    /// renoncer — appartient à l'appelant.
    Delai,
    /// La valeur ne s'exporte pas de cette poignée de main.
    ///
    /// **ELLE NE SE RATTRAPE PAS** : une liaison de canal (RFC 8446 §7.5) qui
    /// manque ne se remplace par rien, et s'en inventer une rendrait vérifiable
    /// une signature qui ne prouve plus rien.
    SansExport,
    /// La connexion est fermée : il n'y a plus rien à y faire.
    Fermee,
}

impl core::fmt::Display for Faute {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Socket(quoi) => write!(f, "la socket a refusé : {quoi}"),
            Self::Quic(quoi) => write!(f, "le transport a refusé : {quoi:?}"),
            Self::Http3(quoi) => write!(f, "HTTP/3 a refusé : {quoi:?}"),
            Self::Delai => write!(f, "rien n'est arrivé dans le temps imparti"),
            Self::SansExport => write!(f, "la valeur ne s'exporte pas de cette connexion"),
            Self::Fermee => write!(f, "la connexion est fermée"),
        }
    }
}

impl std::error::Error for Faute {}

/// L'heure, en microsecondes d'époque — ce que la pile attend partout.
fn maintenant() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |ecoule| u64::try_from(ecoule.as_micros()).unwrap_or(0))
}

/// Une connexion QUIC ouverte vers un pair, et le conducteur HTTP/3 dessus.
///
/// # LA LÂCHER, C'EST PARTIR SANS PRÉVENIR
///
/// La destruction ferme la socket, et le pair ne l'apprend qu'à l'expiration de
/// son délai d'inactivité. [`Appel::fermer`] le dit tout de suite : §10.2 de
/// RFC 9000 distingue un arrêt propre d'une coupure, et ce qui regarde de
/// l'autre côté ne traitera pas les deux pareil.
pub struct Appel {
    /// La socket, **connectée** : le noyau trie, et rien d'autre n'arrive.
    socket: UdpSocket,
    /// La connexion QUIC, **derrière une boîte**.
    ///
    /// # CENT TRENTE-SIX KIBIOCTETS, ET C'EST LA RAISON
    ///
    /// Une [`Connection`] porte ses fenêtres de réassemblage, ses tampons de
    /// sortie par espace et l'état de trois flux `CRYPTO`. Laissée sur la pile,
    /// elle traverse chaque `await` de cette crate, et deux appels ouverts à la
    /// suite dans un essai suffisent à la déborder.
    quic: Box<Connection>,
    /// Le conducteur HTTP/3.
    h3: Http3Client,
    /// Ce qu'on met dans `:authority`.
    ///
    /// **IL NE PROUVE RIEN DE LUI-MÊME** : ce qui est jugé, c'est le
    /// certificat, et c'est la configuration TLS de l'appelant qui en décide.
    autorite: String,
    /// Où le pair écoute.
    distante: SocketAddr,
    /// Le tampon de travail, prêté à l'émission puis à la réception.
    ///
    /// **UN SEUL, ET RETENU** : soixante-cinq kibioctets alloués à chaque tour
    /// de boucle, c'est une allocation par datagramme sur une connexion qu'on
    /// tient pour des mois.
    place: Vec<u8>,
}

impl Appel {
    /// Ouvre une connexion vers ce pair, et mène la poignée de main au bout.
    ///
    /// `nom` est ce que la poignée de main exige du certificat ; `autorite` est
    /// ce qui ira dans `:authority` des requêtes. **Ce sont deux choses**, et
    /// elles diffèrent chez qui vise une adresse littérale : le premier est une
    /// règle de confiance, le second un en-tête.
    ///
    /// `config` porte l'ALPN. Un serveur qui n'offre pas ce qu'elle demande
    /// fait échouer la poignée de main, et c'est voulu : une connexion montée
    /// sur un protocole qu'on ne sait pas parler ne servirait à rien.
    ///
    /// # Errors
    ///
    /// [`Faute::Socket`], [`Faute::Quic`], [`Faute::Delai`],
    /// [`Faute::Http3`].
    pub async fn ouvrir(
        pair: SocketAddr,
        nom: rustls::pki_types::ServerName<'static>,
        autorite: &str,
        config: Arc<rustls::ClientConfig>,
        alea: &(dyn Fn() -> [u8; 16] + Sync),
    ) -> Result<Self, Faute> {
        // **UNE SOCKET DE LA MÊME FAMILLE QUE LA CIBLE.** Se lier en IPv4 pour
        // joindre une adresse IPv6 échoue au premier envoi, et le message du
        // noyau ne dit pas pourquoi.
        let local = match pair {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };
        let socket = UdpSocket::bind(local).await.map_err(Faute::Socket)?;
        socket.connect(pair).await.map_err(Faute::Socket)?;

        let graine = alea();
        // **DEUX IDENTIFIANTS, ET NON UN.** Le nôtre est celui que le pair
        // devra employer pour nous répondre (§7.2) ; celui d'origine est celui
        // qu'on invente pour le joindre, et dont §5.2 dérive les clés
        // `Initial`. Les tirer du même tirage les rend tous deux
        // imprévisibles ; les confondre en ferait un seul, devinable dès qu'on
        // a vu l'autre.
        let notre = ConnectionId::new(graine.get(..8).unwrap_or_default())
            .map_err(|_| Faute::SansExport)?;
        let origine = ConnectionId::new(graine.get(8..).unwrap_or_default())
            .map_err(|_| Faute::SansExport)?;

        let quic = Box::new(
            Connection::connect(
                config,
                nom,
                notre,
                origine,
                ams_quic_tls::INACTIVITE_US,
                maintenant(),
            )
            .map_err(Faute::Quic)?,
        );

        let mut appel = Self {
            socket,
            quic,
            h3: Http3Client::new(),
            autorite: autorite.to_owned(),
            distante: pair,
            place: vec![0_u8; PLACE_OCTETS],
        };
        appel.poignee_de_main().await?;
        Ok(appel)
    }

    /// Mène la poignée de main, puis ouvre les flux qu'HTTP/3 exige.
    async fn poignee_de_main(&mut self) -> Result<(), Faute> {
        let echeance = maintenant().saturating_add(POIGNEE_MS.saturating_mul(1_000));
        while !self.quic.is_established() {
            // **ICI, ET SEULEMENT ICI, `vivante` NE SERT PAS** : `Handshaking`
            // est justement l'état où l'on est, et ce qui condamne est que la
            // connexion ait quitté la poignée de main sans l'avoir finie.
            if !matches!(self.quic.etat(), ams_quic::State::Handshaking) {
                return Err(Faute::Fermee);
            }
            if maintenant() >= echeance {
                return Err(Faute::Delai);
            }
            self.emettre().await?;
            self.recevoir(POIGNEE_MS.min(250)).await?;
        }

        // **LES TROIS FLUX S'OUVRENT MAINTENANT, ET PAS AVANT** : §7.4 de
        // RFC 9000 dit que les limites du pair ne sont pas authentifiées tant
        // que la poignée de main n'est pas terminée. Un flux ouvert plus tôt le
        // serait sur un crédit que personne n'a signé.
        let mut pont = Pont(&mut self.quic);
        self.h3.on_established(&mut pont).map_err(Faute::Http3)?;
        self.emettre().await
    }

    /// Dérive une valeur propre à CETTE connexion — RFC 8446 §7.5.
    ///
    /// C'est ce qui lie une signature au canal : les deux camps doivent
    /// employer la **même étiquette**, et un octet d'écart ferait échouer
    /// toutes les vérifications d'une manière indiscernable d'une fausse clé.
    /// L'étiquette appartient donc au protocole qui l'emploie, jamais à cette
    /// crate.
    ///
    /// # Errors
    ///
    /// [`Faute::SansExport`] si la poignée de main n'est pas terminée.
    pub fn exporter(
        &self,
        etiquette: &[u8],
        contexte: Option<&[u8]>,
    ) -> Result<[u8; ams_quic_tls::EXPORT_OCTETS], Faute> {
        self.quic
            .export(etiquette, contexte)
            .map_err(|_| Faute::SansExport)
    }

    /// Le protocole que l'ALPN a retenu, une fois la poignée de main faite.
    #[must_use]
    pub fn alpn(&self) -> Option<&[u8]> {
        self.quic.alpn()
    }

    /// L'adresse locale de la socket — ce sous quoi le pair nous verra, sauf
    /// NAT.
    ///
    /// # Errors
    ///
    /// [`Faute::Socket`].
    pub fn locale(&self) -> Result<SocketAddr, Faute> {
        self.socket.local_addr().map_err(Faute::Socket)
    }

    /// Où le pair écoute.
    #[must_use]
    pub const fn distante(&self) -> SocketAddr {
        self.distante
    }

    /// Peut-on encore s'en servir ?
    ///
    /// # ET CE N'EST PAS `is_closed`
    ///
    /// Une connexion en `Closing` — nous avons dit la fermeture — ou en
    /// `Draining` — le pair a dit la sienne — n'est **pas** oubliable : on y
    /// répond encore, de moins en moins souvent (§10.2.1). Elle n'est pourtant
    /// plus utilisable. La première écriture de cette fonction rendait
    /// `!is_closed()`, et répondait donc « vivante » juste après
    /// [`Appel::fermer`] ; l'essai l'a dit, et c'est ce qui a fait exposer
    /// [`Connection::etat`].
    #[must_use]
    pub const fn vivante(&self) -> bool {
        matches!(
            self.quic.etat(),
            ams_quic::State::Handshaking | ams_quic::State::Confirmed
        )
    }

    /// Règle le keepalive, en secondes.
    ///
    /// **CETTE VALEUR VIENT DU PAIR, JAMAIS D'ICI.** Le bon delta se mesure sur
    /// de vrais NAT ; le figer dans cette crate obligerait à mettre à jour tout
    /// ce qui l'embarque pour le corriger. Zéro l'éteint.
    pub fn maintenir(&mut self, secondes: u16) {
        self.quic
            .set_keepalive(u64::from(secondes).saturating_mul(1_000_000), maintenant());
    }

    /// Émet tout ce que la connexion a à dire.
    async fn emettre(&mut self) -> Result<(), Faute> {
        loop {
            let ecrit = self
                .quic
                .poll_transmit(&mut self.place, maintenant())
                .map_err(Faute::Quic)?;
            if ecrit == 0 {
                return Ok(());
            }
            let datagramme = self.place.get(..ecrit).unwrap_or_default();
            self.socket.send(datagramme).await.map_err(Faute::Socket)?;
        }
    }

    /// Attend un datagramme, au plus ce nombre de millisecondes.
    ///
    /// **UN DÉLAI ÉCOULÉ N'EST PAS UNE FAUTE** : c'est ce qui laisse la
    /// connexion faire échoir ses propres délais — retransmissions, keepalive,
    /// inactivité. Les confondre ferait échouer un appel parfaitement sain à la
    /// première seconde de silence.
    async fn recevoir(&mut self, attente_ms: u64) -> Result<(), Faute> {
        let attente = tokio::time::Duration::from_millis(attente_ms);
        // La socket est connectée : ce qui vient d'ailleurs, le noyau l'a déjà
        // jeté. Il n'y a donc rien à trier ici.
        match tokio::time::timeout(attente, self.socket.recv(&mut self.place)).await {
            Ok(Ok(lus)) => {
                let mut datagramme = self.place.get(..lus).unwrap_or_default().to_vec();
                self.quic
                    .on_datagram(&mut datagramme, maintenant())
                    .map_err(Faute::Quic)?;
                Ok(())
            }
            Ok(Err(quoi)) => Err(Faute::Socket(quoi)),
            Err(_) => {
                self.quic.on_timeout(maintenant());
                Ok(())
            }
        }
    }

    /// Passe au conducteur ce que les flux ont reçu.
    ///
    /// C'est la boucle de l'écoute, à l'envers : même règle d'arrêt, et pour la
    /// même raison. **Un conducteur qui n'a rien pris ni rien conclu ne prendra
    /// pas plus au tour suivant** ; le rappeler ferait tourner la boucle sans
    /// fin, et c'est nous que cela arrêterait.
    fn servir(&mut self) -> Result<(), Faute> {
        let flux: Vec<StreamId> = self.quic.streams_alive().collect();
        for un in flux {
            let mut tours = 0_u32;
            while tours < LECTURES_MAX {
                let avant = self.quic.readable(un);
                let etat = self.quic.recv_state(un);
                if avant == 0 && !matches!(etat, Some(RecvState::DataRecvd | RecvState::ResetRecvd))
                {
                    break;
                }
                let mut pont = Pont(&mut self.quic);
                self.h3.on_readable(&mut pont, un).map_err(Faute::Http3)?;
                if self.quic.readable(un) == avant && self.quic.recv_state(un) == etat {
                    break;
                }
                tours = tours.saturating_add(1);
            }
        }
        Ok(())
    }

    /// Un tour d'entretien : recevoir, servir, émettre.
    ///
    /// **C'EST CE QUI TIENT LA CONNEXION EN VIE.** Qui la garde doit appeler
    /// ceci régulièrement : sans elle, aucun keepalive ne part, aucune
    /// retransmission n'a lieu, et ce qui arrive sur un flux tenu reste dans la
    /// fenêtre de réassemblage sans être lu.
    ///
    /// `attente_ms` borne l'attente d'un datagramme. Elle ne décide **pas** de
    /// la cadence du keepalive — celle-là appartient à la connexion — mais de
    /// la finesse avec laquelle on la sert.
    ///
    /// # Errors
    ///
    /// [`Faute::Socket`], [`Faute::Quic`], [`Faute::Http3`].
    pub async fn entretenir(&mut self, attente_ms: u64) -> Result<(), Faute> {
        if !self.vivante() {
            return Err(Faute::Fermee);
        }
        self.recevoir(attente_ms).await?;
        self.servir()?;
        self.emettre().await
    }

    /// Ouvre un flux, y écrit cette requête, et **ne l'attend pas**.
    ///
    /// # À QUOI CELA SERT, ET POURQUOI CE N'EST PAS [`Appel::requete`]
    ///
    /// Certaines réponses ne se terminent jamais : le serveur rend `200`, garde
    /// le flux ouvert, et y écrit à mesure que les choses arrivent — c'est
    /// `GET /v1/poussees` d'`air-service-locator`. [`Appel::requete`]
    /// attendrait cette fin pour toujours.
    ///
    /// L'appelant garde le numéro rendu, entretient la connexion, et relit par
    /// [`Appel::recueillir`] ce qui s'y est accumulé. **Découper le flot en
    /// messages est son travail** : cette crate ne connaît pas le cadrage de ce
    /// qui voyage dessus.
    ///
    /// # Errors
    ///
    /// [`Faute::Http3`], [`Faute::Socket`], [`Faute::Quic`], [`Faute::Fermee`].
    pub async fn tenir(
        &mut self,
        methode: &str,
        chemin: &str,
        champs: &[(&[u8], &[u8])],
    ) -> Result<StreamId, Faute> {
        let flux = self.poser(methode, chemin, champs, &[])?;
        self.emettre().await?;
        Ok(flux)
    }

    /// Ce qui est arrivé sur ce flux depuis la dernière fois.
    ///
    /// **ELLE PREND, ELLE NE COPIE PAS** : deux appels de suite ne rendent pas
    /// deux fois les mêmes octets. Un appelant qui perdrait ce qu'elle rend
    /// l'aurait perdu pour de bon, et c'est délibéré — garder une seconde copie
    /// obligerait à décider quand la jeter.
    ///
    /// **ET `None` NE VEUT PAS DIRE « RIEN N'EST ARRIVÉ ».** Il veut dire que ce
    /// flux est inconnu — jamais ouvert, ou déjà pris par [`Appel::requete`].
    /// Rien de neuf sur un flux connu rend `Some` d'une tranche VIDE. Les
    /// confondre ferait prendre un flux tenu pour un flux disparu, et un
    /// appelant cesserait de le lire.
    ///
    /// # C'EST AUSSI CE QUI BORNE LA MÉMOIRE
    ///
    /// Sur un flux qui ne finit jamais, le corps s'accumule, et le conducteur
    /// refuse au-delà de sa propre borne. **Chaque appel vide** ; un appelant
    /// qui ne viderait pas finirait par voir la connexion refuser.
    #[must_use]
    pub fn recueillir(&mut self, flux: StreamId) -> Option<Vec<u8>> {
        self.h3.prendre_ce_qui_est_arrive(flux)
    }

    /// Le code d'état d'un flux, dès que ses champs sont lus.
    #[must_use]
    pub fn statut(&self, flux: StreamId) -> Option<StatusCode> {
        self.h3.statut(flux)
    }

    /// Ce flux a-t-il fini d'arriver ?
    #[must_use]
    pub fn fini(&self, flux: StreamId) -> bool {
        self.h3.est_fini(flux)
    }

    /// Envoie cette requête, et attend sa réponse entière.
    ///
    /// # Errors
    ///
    /// [`Faute::Http3`], [`Faute::Socket`], [`Faute::Quic`], [`Faute::Delai`]
    /// si la réponse n'est pas complète à temps, [`Faute::Fermee`] si le pair
    /// raccroche entre-temps.
    pub async fn requete(
        &mut self,
        methode: &str,
        chemin: &str,
        champs: &[(&[u8], &[u8])],
        corps: &[u8],
    ) -> Result<ReponseRecue, Faute> {
        let flux = self.poser(methode, chemin, champs, corps)?;
        self.emettre().await?;

        let echeance = maintenant().saturating_add(REPONSE_MS.saturating_mul(1_000));
        loop {
            if let Some(reponse) = self.h3.take_response(flux) {
                return Ok(reponse);
            }
            if !self.vivante() {
                return Err(Faute::Fermee);
            }
            if maintenant() >= echeance {
                return Err(Faute::Delai);
            }
            self.entretenir(250).await?;
        }
    }

    /// Écrit la requête sur un flux neuf. Ce qui est commun aux deux verbes.
    fn poser(
        &mut self,
        methode: &str,
        chemin: &str,
        champs: &[(&[u8], &[u8])],
        corps: &[u8],
    ) -> Result<StreamId, Faute> {
        if !self.vivante() {
            return Err(Faute::Fermee);
        }
        // L'autorité est copiée avant d'emprunter la connexion : elle vit dans
        // la même structure, et le conducteur veut les deux en même temps.
        let autorite = self.autorite.clone();
        let mut pont = Pont(&mut self.quic);
        self.h3
            .request(
                &mut pont,
                methode.as_bytes(),
                chemin.as_bytes(),
                autorite.as_bytes(),
                champs,
                corps,
            )
            .map_err(Faute::Http3)
    }

    /// Ferme proprement, et le dit au pair.
    ///
    /// # POURQUOI ON NE SE CONTENTE PAS DE LÂCHER L'OBJET
    ///
    /// §10.2 de RFC 9000 : une extinction annoncée se distingue d'une coupure.
    /// Pour qui regarde de l'autre côté, ce sont deux événements différents —
    /// « il est parti » et « il ne répond plus » —, et un service de découverte
    /// qui confondrait les deux publierait une adresse morte jusqu'à
    /// l'expiration de son délai d'inactivité.
    ///
    /// # Errors
    ///
    /// [`Faute::Socket`], [`Faute::Quic`].
    pub async fn fermer(&mut self) -> Result<(), Faute> {
        // **UNE SECONDE FERMETURE NE DIT RIEN DE PLUS**, et refuser l'idempotence
        // obligerait l'appelant à retenir ce qu'il a déjà fait pour un geste
        // qui ne se fait qu'une fois par nature.
        if !self.vivante() {
            return Ok(());
        }
        self.quic
            .close(ams_proto_quic::TransportError::NoError, maintenant());
        // **ÉMETTRE, ET NE RIEN ATTENDRE.** §10.2.3 : celui qui ferme n'a pas à
        // obtenir de réponse, et attendre un accusé donnerait à un pair muet le
        // pouvoir de retarder notre arrêt.
        self.emettre().await
    }
}

impl core::fmt::Debug for Appel {
    /// **SANS LA CONNEXION NI LE TAMPON.** La première fait cent trente-six
    /// kibioctets d'état de poignée de main, le second soixante-cinq mille
    /// octets dont le contenu est le dernier datagramme reçu : les imprimer
    /// noierait une trace et pourrait y déposer du secret.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Appel")
            .field("distante", &self.distante)
            .field("autorite", &self.autorite)
            .field("etablie", &self.quic.is_established())
            .field("fermee", &self.quic.is_closed())
            .finish_non_exhaustive()
    }
}
