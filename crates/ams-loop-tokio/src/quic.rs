// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! L'écoute QUIC : une socket, une carte, une boucle.
//!
//! # CE MODULE NE DÉCIDE RIEN, ET C'EST TOUT L'INTÉRÊT
//!
//! Le tri d'un datagramme est dans `ams_quic::Incoming`, la protection de paquet
//! dans `ams-quic-crypto`, la poignée de main dans `ams_quic_tls::Server`, et ce
//! qu'une connexion répond dans `ams_quic_tls::Connection`. **Tout cela est
//! couvert à 100 % (C2)** parce que rien de tout cela ne touche à une socket.
//!
//! Il reste ici trois choses, et elles ne sont que du rangement :
//!
//! 1. **une socket**, et de quoi lire et écrire des datagrammes ;
//! 2. **une carte** des identifiants de connexion vers les connexions ;
//! 3. **une boucle** qui attend le prochain datagramme ou le prochain délai.
//!
//! Le même partage que pour HTTP/2, où `ams-session::http` décide et
//! [`crate::http`] exécute.
//!
//! # UNE SEULE TÂCHE, ET NON UNE PAR CONNEXION
//!
//! TCP donne une socket par connexion ; UDP n'en donne qu'une pour tout le
//! monde. Une tâche par connexion demanderait donc de recopier chaque datagramme
//! vers une file, et de partager la socket d'émission — **deux synchronisations
//! pour un travail qui tient dans une boucle**.
//!
//! La contrepartie est écrite : une connexion coûteuse retarde les autres. C'est
//! acceptable tant qu'aucune ne fait d'entrée-sortie bloquante, ce qui est le
//! cas — le conducteur ne touche ni au disque ni au réseau.
//!
//! # CE QUI BORNE CE MODULE (C8)
//!
//! Le nombre de connexions vivantes, et rien d'autre. Au-delà, un `Initial` neuf
//! est **ignoré en silence** : lui répondre un refus coûterait autant que de le
//! servir, et §5.2.2 permet de le jeter. Un pair honnête réessaiera ; un
//! attaquant n'aura rien obtenu.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use ams_proto_quic::{ConnectionId, StreamId};
use ams_quic::{Incoming, LOCAL_CONNECTION_ID_OCTETS, RecvState, Route};
use ams_quic_tls::Connection;
use rustls::ServerConfig;
use tokio::net::UdpSocket;

use ams_guard::Source;

use crate::error::Error;
use crate::server::source_de;

/// Ce qu'un datagramme peut occuper au plus.
///
/// **SOIXANTE-CINQ MILLE OCTETS, ET NON MILLE DEUX CENTS.** §14 borne ce qu'on
/// ÉMET, pas ce qu'on reçoit : un pair a le droit de nous écrire un datagramme
/// plus grand, et le tronquer ferait échouer l'authentification de son dernier
/// paquet — pour une raison qu'aucun des deux côtés ne saurait nommer.
const RECEPTION_OCTETS_MAX: usize = 65_535;

/// Combien de connexions QUIC vivent en même temps.
///
/// # C'EST UNE BORNE DE MÉMOIRE, ET DONC UNE DÉFENSE (C8)
///
/// Chaque connexion tient trois fenêtres de réassemblage, trois tables de
/// paquets émis et une poignée de main TLS — quelques dizaines de kibioctets.
/// Sans borne, **il suffirait d'envoyer des `Initial` pour épuiser la mémoire**,
/// et ces paquets-là ne sont authentifiés par personne (§5.2 de RFC 9001).
const CONNEXIONS_MAX: usize = 1_024;

/// Combien de fois on rappelle l'application sur un même flux, en un tour.
///
/// **C'EST NOTRE BORNE, PAS LA SIENNE** (C3) : une application qui prendrait un
/// octet à la fois ferait tourner la boucle autant de fois qu'il y a d'octets,
/// pendant que les autres connexions attendent. Ce qui reste sera lu au tour
/// suivant.
const LECTURES_MAX: u32 = 64;

/// Ce qu'une écoute QUIC a compté.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QuicStats {
    /// Connexions ouvertes.
    pub accepted: u64,
    /// `Initial` refusés faute de place.
    pub refused: u64,
    /// Datagrammes jetés, toutes raisons confondues.
    ///
    /// **LES RAISONS SONT NOMMÉES DANS `ams_quic::Discard`**, et le jour où
    /// `air-log` existera elles seront comptées séparément. En attendant, un
    /// total vaut mieux que rien : il dit s'il faut regarder.
    pub discarded: u64,
    /// Connexions terminées.
    pub closed: u64,
}

/// Une connexion vivante, et l'adresse d'où elle parle.
struct Vivante {
    /// Ce qui décide, et qui ne touche à rien.
    conduite: Connection,
    /// A-t-on déjà dit à l'application que cette connexion était établie ?
    ///
    /// **UNE FOIS, ET UNE SEULE** : c'est là qu'une application ouvre ses flux
    /// de contrôle, et les rouvrir à chaque datagramme épuiserait le plafond de
    /// §4.6 en quelques tours.
    etablie_dite: bool,
    /// D'où le pair écrit.
    ///
    /// **ON NE SUIT PAS LES MIGRATIONS** (§9) : une connexion qui change
    /// d'adresse est une connexion qu'on cesse de servir. Les suivre demande de
    /// valider le nouveau chemin, faute de quoi un attaquant qui rejoue un
    /// paquet ferait rediriger le trafic vers sa victime.
    pair: SocketAddr,
}

/// Ce qu'une application fait des flux d'une connexion.
///
/// # LA BOUCLE CONDUIT LE TRANSPORT, CETTE INTERFACE DÉCIDE DU RESTE
///
/// C'est le même partage qu'entre `ams-session::http` et `ams-loop-tokio::http`,
/// et pour la même raison : ce qui décide et ce qui exécute ne se vérifient pas
/// de la même façon. L'écoute sait ouvrir un paquet, compter un crédit et
/// retransmettre ; **elle ne sait pas ce qu'un octet veut dire**, et n'a pas à
/// le savoir.
///
/// Une implémentation ne fait aucune entrée-sortie : elle lit avec
/// [`Connection::read`], répond avec [`Connection::write`] et
/// [`Connection::finish`], et c'est l'écoute qui décide quand ces octets partent
/// et comment ils sont retransmis.
///
/// # ELLE SAIT QUI PARLE, ET C8 L'EXIGE
///
/// Chaque rendez-vous porte la [`Source`] du pair. **Sans elle, aucune politique
/// par source n'est possible** : un refus d'identifiants ne pourrait pas compter
/// contre l'adresse qui l'a tenté, et HTTP/3 servirait sans la protection contre
/// les essais répétés que HTTP/2 a déjà. L'information existe — l'écoute la tient
/// pour chaque connexion —, et la garder pour elle serait la perdre.
pub trait Application {
    /// Une connexion vient de s'établir.
    ///
    /// **C'EST LE PREMIER INSTANT OÙ L'ON PEUT OUVRIR UN FLUX** : avant, les
    /// limites du pair ne sont pas authentifiées (§7.4). HTTP/3 y ouvre ses trois
    /// unidirectionnels — contrôle et QPACK —, que le client attend sans les
    /// avoir demandés.
    fn on_established(&mut self, _connexion: &mut Connection, _pair: Source) {}

    /// Ce flux a de quoi être lu, ou son pair vient d'en changer l'état.
    ///
    /// Appelé tant qu'il reste des octets prêts : une implémentation qui n'en
    /// lit qu'une partie sera rappelée. **L'état de réception dit le reste** —
    /// [`Connection::recv_state`] distingue un flux terminé d'un flux annulé, et
    /// les confondre ferait servir une requête tronquée.
    fn on_readable(&mut self, connexion: &mut Connection, flux: StreamId, pair: Source);

    /// Cette connexion s'éteint : ce qu'on tenait pour elle ne sert plus.
    fn on_closed(&mut self, _connexion: &Connection, _pair: Source) {}
}

/// Une application qui ne fait rien.
///
/// **ELLE N'EST PAS UN BOUCHON** : un serveur QUIC sans application sert quand
/// même la poignée de main, les acquittements et le contrôle de flux, et c'est
/// exactement ce qu'on veut pour éprouver le transport seul.
#[derive(Debug, Clone, Copy, Default)]
pub struct SansApplication;

impl Application for SansApplication {
    fn on_readable(&mut self, _connexion: &mut Connection, _flux: StreamId, _pair: Source) {}
}

/// Sert QUIC sur cette socket, jusqu'à l'arrêt.
///
/// # Errors
///
/// [`Error`] si la socket refuse de lire — c'est-à-dire si l'écoute elle-même
/// n'est plus possible. **Une connexion qui échoue ne regarde qu'elle** et ne
/// remonte pas ici.
pub async fn serve_quic<App, Arret>(
    socket: UdpSocket,
    tls: Arc<ServerConfig>,
    application: &mut App,
    shutdown: Arret,
) -> Result<QuicStats, Error>
where
    App: Application,
    Arret: Future<Output = ()>,
{
    let mut ecoute = Ecoute {
        socket,
        tls,
        connexions: Vec::new(),
        carte: HashMap::new(),
        stats: QuicStats::default(),
        graine: amorce(),
    };
    let mut arret = core::pin::pin!(shutdown);
    let mut recu = alloc_datagramme();
    let mut place = alloc_datagramme();

    loop {
        // **DEUX LECTURES DE L'HORLOGE, ET C'EST VOULU** : la première dit
        // combien attendre, la seconde dit quand on s'est réveillé. Réemployer
        // la première ferait croire que rien n'a pris de temps, et les délais
        // n'échoiraient jamais.
        let avant = maintenant();
        let attente = ecoute.prochain_delai(avant);
        let arrivee = tokio::select! {
            // `biased` : l'arrêt est examiné EN PREMIER, comme partout ailleurs
            // dans cette crate. Un serveur qu'on ne peut pas arrêter sous charge
            // est un serveur qu'on finit par tuer.
            biased;
            () = &mut arret => return Ok(ecoute.stats),
            () = dormir(attente) => None,
            lu = ecoute.socket.recv_from(&mut recu) => Some(lu),
        };

        let maintenant = maintenant();
        match arrivee {
            Some(Ok((combien, pair))) => {
                let datagramme = recu.get_mut(..combien).unwrap_or_default();
                ecoute.un_datagramme(datagramme, pair, maintenant);
                // **APRÈS LE DATAGRAMME, ET AVANT L'ÉMISSION** : ce que
                // l'application écrit en réponse part dans le même tour, sans
                // attendre un réveil de plus.
                ecoute.servir(application);
            }
            // **UNE LECTURE QUI ÉCHOUE N'EST PAS UNE ÉCOUTE QUI S'ARRÊTE.** Sur
            // UDP, `recv_from` peut rendre une erreur qui appartient au
            // datagramme PRÉCÉDENT — un `ICMP port unreachable`, par exemple. La
            // remonter fermerait le service pour la faute d'un tiers.
            Some(Err(_)) => ecoute.stats.discarded = ecoute.stats.discarded.saturating_add(1),
            None => {}
        }
        ecoute.les_delais(maintenant);
        ecoute.emettre(&mut place, maintenant).await;
        ecoute.oublier_les_eteintes(application);
    }
}

/// L'état d'une écoute.
struct Ecoute {
    /// La socket, unique et partagée par toutes les connexions.
    socket: UdpSocket,
    /// De quoi monter une poignée de main.
    tls: Arc<ServerConfig>,
    /// Les connexions vivantes, par rang.
    connexions: Vec<Vivante>,
    /// Les identifiants qu'on a distribués, vers ces rangs.
    ///
    /// **C'EST LA CARTE QUE `ams_quic::routing` NE TIENT PAS**, et pour cause :
    /// elle alloue. Ce qu'elle contient n'est pas une décision — c'est du
    /// rangement, et le rangement va où l'on peut allouer.
    carte: HashMap<Vec<u8>, usize>,
    /// Ce qu'on a compté.
    stats: QuicStats,
    /// De quoi fabriquer des identifiants qui ne se devinent pas.
    graine: u64,
}

impl Ecoute {
    /// Un datagramme est arrivé.
    fn un_datagramme(&mut self, datagramme: &mut [u8], pair: SocketAddr, maintenant: u64) {
        let Ok(arrivee) = Incoming::read(datagramme, LOCAL_CONNECTION_ID_OCTETS) else {
            self.stats.discarded = self.stats.discarded.saturating_add(1);
            return;
        };
        let connu = self
            .carte
            .get(arrivee.destination().as_bytes())
            .copied()
            .filter(|rang| self.connexions.get(*rang).is_some_and(|v| v.pair == pair));

        match arrivee.route(connu) {
            Route::Connection(rang) => self.a_une_connexion(rang, datagramme, maintenant),
            Route::New => self.un_client_neuf(&arrivee, datagramme, pair, maintenant),
            // §6.1 : négocier demanderait d'écrire un paquet de version, que ce
            // serveur ne sait pas fabriquer — il ne sert qu'une version. Le
            // jeter laisse le client abandonner de lui-même, ce que §6.2 prévoit.
            Route::Negotiate | Route::Drop(_) => {
                self.stats.discarded = self.stats.discarded.saturating_add(1);
            }
        }
    }

    /// Ce datagramme appartient à une connexion en cours.
    fn a_une_connexion(&mut self, rang: usize, datagramme: &mut [u8], maintenant: u64) {
        let Some(vivante) = self.connexions.get_mut(rang) else {
            self.stats.discarded = self.stats.discarded.saturating_add(1);
            return;
        };
        // **UNE FAUTE FERME CETTE CONNEXION, ET ELLE SEULE.** Le code de §20.1
        // part au pair pour qu'il sache pourquoi ; sans lui, il attendrait son
        // délai d'inactivité.
        if let Err(issue) = vivante.conduite.on_datagram(datagramme, maintenant) {
            vivante.conduite.close_with(issue.close_code(), maintenant);
        }
    }

    /// Un client neuf frappe à la porte.
    fn un_client_neuf(
        &mut self,
        arrivee: &Incoming,
        datagramme: &mut [u8],
        pair: SocketAddr,
        maintenant: u64,
    ) {
        if self.connexions.len() >= CONNEXIONS_MAX {
            // §5.2.2 permet un refus explicite ; on jette. Répondre coûterait
            // autant que de servir, et c'est précisément ce qu'un attaquant
            // cherche.
            self.stats.refused = self.stats.refused.saturating_add(1);
            return;
        }
        let local = self.un_identifiant();
        let Ok(mut conduite) = Connection::accept(
            Arc::clone(&self.tls),
            arrivee,
            local,
            arrivee.source(),
            maintenant,
        ) else {
            self.stats.discarded = self.stats.discarded.saturating_add(1);
            return;
        };
        if conduite.on_datagram(datagramme, maintenant).is_err() {
            self.stats.discarded = self.stats.discarded.saturating_add(1);
            return;
        }
        let rang = self.connexions.len();
        self.carte.insert(local.as_bytes().to_vec(), rang);
        self.connexions.push(Vivante {
            conduite,
            pair,
            etablie_dite: false,
        });
        self.stats.accepted = self.stats.accepted.saturating_add(1);
    }

    /// Le prochain délai à attendre, en microsecondes.
    fn prochain_delai(&self, maintenant: u64) -> Option<u64> {
        self.connexions
            .iter()
            .filter_map(|vivante| vivante.conduite.deadline(maintenant))
            .min()
            .map(|quand| quand.saturating_sub(maintenant))
    }

    /// Fait échoir ce qui doit l'être.
    fn les_delais(&mut self, maintenant: u64) {
        for vivante in &mut self.connexions {
            let echue = vivante
                .conduite
                .deadline(maintenant)
                .is_some_and(|quand| quand <= maintenant);
            if echue {
                vivante.conduite.on_timeout(maintenant);
            }
        }
    }

    /// Émet ce que chaque connexion a à dire.
    async fn emettre(&mut self, place: &mut [u8], maintenant: u64) {
        for vivante in &mut self.connexions {
            loop {
                let ecrit = match vivante.conduite.poll_transmit(place, maintenant) {
                    Ok(0) => break,
                    Ok(ecrit) => ecrit,
                    Err(issue) => {
                        vivante.conduite.close_with(issue.close_code(), maintenant);
                        break;
                    }
                };
                let paquet = place.get(..ecrit).unwrap_or_default();
                // **UNE ÉMISSION QUI ÉCHOUE NE FERME PAS LA CONNEXION.** Un
                // `send_to` peut refuser pour une raison qui ne la concerne pas
                // — un tampon plein, un `ICMP` en retard. Le pair réémettra, et
                // le sondage de §6.2 fera repartir ce qui manque.
                if self.socket.send_to(paquet, vivante.pair).await.is_err() {
                    break;
                }
            }
        }
    }

    /// Retire ce qui s'est éteint.
    ///
    /// # LES RANGS BOUGENT, ET LA CARTE AVEC
    ///
    /// On compacte le vecteur plutôt que d'y laisser des trous : un trou serait
    /// un rang qu'on peut encore trouver dans la carte, et donc un datagramme
    /// remis à une connexion qui n'existe plus.
    /// Donne à l'application ce qui est prêt, connexion par connexion.
    ///
    /// # POURQUOI RELIRE LA LISTE DES FLUX À CHAQUE TOUR
    ///
    /// Tenir une file des flux devenus lisibles demanderait de la maintenir
    /// juste — à l'arrivée d'un octet, à la lecture d'un autre, à l'annulation
    /// d'un flux —, et un oubli s'y verrait comme un flux qui se fige sans
    /// raison. La table fait trente-deux entrées : la relire coûte moins que de
    /// se tromper.
    ///
    /// **ON RAPPELLE TANT QU'IL RESTE DE QUOI LIRE**, mais pas indéfiniment :
    /// une application qui ne lirait rien ferait autrement tourner la boucle
    /// sans fin, et c'est nous que cela arrêterait, pas elle.
    fn servir<App: Application>(&mut self, application: &mut App) {
        for vivante in &mut self.connexions {
            if !vivante.conduite.is_established() {
                continue;
            }
            let pair = source_de(vivante.pair);
            if !vivante.etablie_dite {
                vivante.etablie_dite = true;
                application.on_established(&mut vivante.conduite, pair);
            }
            let flux: Vec<StreamId> = vivante.conduite.streams_alive().collect();
            for un in flux {
                let mut tours = 0_u32;
                while tours < LECTURES_MAX {
                    let avant = vivante.conduite.readable(un);
                    let etat = vivante.conduite.recv_state(un);
                    // Rien à lire, et rien de neuf à dire : on passe.
                    if avant == 0
                        && !matches!(etat, Some(RecvState::DataRecvd | RecvState::ResetRecvd))
                    {
                        break;
                    }
                    application.on_readable(&mut vivante.conduite, un, pair);
                    // **L'APPLICATION N'A RIEN PRIS NI RIEN CONCLU** : la
                    // rappeler ne donnerait que le même appel.
                    if vivante.conduite.readable(un) == avant
                        && vivante.conduite.recv_state(un) == etat
                    {
                        break;
                    }
                    tours = tours.saturating_add(1);
                }
            }
        }
    }

    fn oublier_les_eteintes<App: Application>(&mut self, application: &mut App) {
        if !self.connexions.iter().any(|v| v.conduite.is_closed()) {
            return;
        }
        let mut restantes = Vec::with_capacity(self.connexions.len());
        let mut carte = HashMap::with_capacity(self.carte.len());
        for vivante in core::mem::take(&mut self.connexions) {
            if vivante.conduite.is_closed() {
                self.stats.closed = self.stats.closed.saturating_add(1);
                // Ce que l'application tenait pour cette connexion ne sert plus.
                application.on_closed(&vivante.conduite, source_de(vivante.pair));
                continue;
            }
            carte.insert(
                vivante.conduite.local_id().as_bytes().to_vec(),
                restantes.len(),
            );
            restantes.push(vivante);
        }
        self.connexions = restantes;
        self.carte = carte;
    }

    /// Un identifiant de connexion qui ne se devine pas.
    ///
    /// # POURQUOI IL NE DOIT PAS SE DEVINER
    ///
    /// §5.1 : « an endpoint MUST NOT use a connection ID that can be used to
    /// correlate connections. » Un identifiant prévisible laisserait un
    /// observateur relier deux connexions du même client, et laisserait un tiers
    /// fabriquer des paquets qu'on attribuerait à quelqu'un d'autre — jusqu'à
    /// l'échec de l'authentification, qui coûte un déchiffrement.
    fn un_identifiant(&mut self) -> ConnectionId {
        // Un générateur congruentiel : il ne prétend pas être cryptographique,
        // et la graine vient de l'horloge et de l'adresse de la pile. §5.1 ne
        // demande pas d'imprévisibilité cryptographique — elle demande qu'on ne
        // puisse pas CORRÉLER, et huit octets tirés ainsi n'ont pas de motif.
        loop {
            self.graine = self
                .graine
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let octets = self.graine.to_be_bytes();
            if !self.carte.contains_key(&octets[..]) {
                return ConnectionId::new(&octets).unwrap_or(ConnectionId::EMPTY);
            }
        }
    }
}

/// Un tampon de la taille d'un datagramme.
fn alloc_datagramme() -> Vec<u8> {
    vec![0_u8; RECEPTION_OCTETS_MAX]
}

/// Attend ce délai, ou pour toujours.
async fn dormir(attente: Option<u64>) {
    match attente {
        Some(microsecondes) => {
            tokio::time::sleep(core::time::Duration::from_micros(microsecondes)).await;
        }
        // **PAS DE RÉVEIL PÉRIODIQUE.** Quand aucune connexion n'attend rien, il
        // n'y a rien à faire : se réveiller pour le constater coûterait un
        // changement de contexte par intervalle, pour toujours.
        None => core::future::pending().await,
    }
}

/// L'instant courant, en microsecondes depuis l'époque.
///
/// **EN MICROSECONDES, ET NON EN SECONDES** : les délais de QUIC se comptent en
/// fractions de trajet — un `PTO` vaut quelques dizaines de millisecondes —, et
/// une horloge à la seconde les arrondirait tous à zéro ou à un.
fn maintenant() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |ecoule| {
            u64::try_from(ecoule.as_micros()).unwrap_or(u64::MAX)
        })
}

/// De quoi amorcer le tirage des identifiants.
fn amorce() -> u64 {
    let horloge = maintenant();
    let pile = 0_u8;
    // L'adresse d'une variable de pile varie d'un lancement à l'autre quand
    // l'ASLR est en place ; mêlée à l'horloge, elle évite que deux serveurs
    // démarrés en même temps tirent la même suite.
    let adresse = core::ptr::from_ref(&pile) as u64;
    horloge.wrapping_mul(6_364_136_223_846_793_005) ^ adresse
}
