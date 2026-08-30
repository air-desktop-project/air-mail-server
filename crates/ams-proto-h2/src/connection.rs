// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La machine de connexion : ce que chaque cadre change, et ce qu'il faut
//! répondre (§5, §6).
//!
//! # C'EST L'ÉTAGE DEUX, ET IL NE FAIT TOUJOURS AUCUNE ENTRÉE-SORTIE
//!
//! Les cadres, les réglages, les flux et HPACK savaient chacun une chose. Ici
//! ils se nouent : un cadre entre, l'état bouge, une réponse s'écrit dans un
//! tampon que l'appelant fournit, et un événement remonte. Rien n'est lu, rien
//! n'est écrit — l'appelant apporte les octets et emporte ceux qu'on lui rend
//! (C1).
//!
//! # LE PRÉAMBULE NE PEUT PAS ÊTRE OUBLIÉ, PARCE QU'IL EST DANS LE TYPE
//!
//! Une connexion ne s'obtient qu'en lisant le préambule : [`Handshake::open`]
//! consomme le sien et rend une [`Connection`]. Il n'existe donc aucun état
//! « connexion dont le préambule n'est pas encore lu », et pas davantage la
//! garde qui l'aurait vérifié à chaque cadre. **Une garde inatteignable n'est
//! pas une garde : c'est une affirmation non vérifiée.**
//!
//! # DEUX INONDATIONS QU'AUCUNE FENÊTRE N'ARRÊTE
//!
//! Le contrôle de flux borne les DONNÉES. Il ne borne rien d'autre — et deux
//! familles de cadres passent donc à côté :
//!
//! - **les cadres de service** : `PING`, `SETTINGS`, `PRIORITY`,
//!   `WINDOW_UPDATE`, les types inconnus. Chacun coûte un traitement, certains
//!   coûtent une réponse, et aucun ne fait progresser quoi que ce soit. Un pair
//!   peut en envoyer sans fin.
//! - **les flux annulés** : `HEADERS` puis `RST_STREAM`, aussitôt, sans
//!   relâche. Le compteur de flux simultanés ne les voit jamais — ils sont
//!   fermés avant d'être comptés — et le serveur travaille pour rien. C'est
//!   *Rapid Reset* (CVE-2023-44487), qui a mis à genoux la moitié du web en
//!   octobre 2023.
//!
//! Les deux ont ici leur borne, et **ce ne sont pas les mêmes** : un compteur
//! que `DATA` remet à zéro pour les premiers, un budget que les réponses
//! rechargent pour les seconds. Confondre les deux ferait justement retomber
//! dans *Rapid Reset* : chaque `HEADERS` remettrait à zéro le compteur que le
//! `RST_STREAM` suivant vient d'incrémenter.

use crate::block::{BlockState, HeaderBlock};
use crate::error::{Cause, Error, ErrorCode};
use crate::flow::{INITIAL_WINDOW_SIZE, Window};
use crate::frame::{FRAME_HEADER_OCTETS, FrameHeader, FrameKind, Padded};
use crate::hpack::{Decoder, encode_field, encode_status};
use crate::preface::{Preface, read_preface};
use crate::settings::{Settings, SettingsReader};
use crate::stream::{StreamState, Streams};
use ams_proto_http::{
    FieldKind, HeadBuilder, Limits, RequestHead, StatusCode, field_kind, field_value_is_valid,
    is_connection_specific,
};

/// La charge d'un `PING`, en octets (§6.7).
pub const PING_OCTETS: usize = 8;

/// La charge d'un `RST_STREAM` et d'un `WINDOW_UPDATE`, en octets.
pub const CODE_OCTETS: usize = 4;

/// La charge minimale d'un `GOAWAY` (§6.8) : le dernier flux, puis le code.
pub const GOAWAY_OCTETS: usize = 8;

/// La charge d'un `PRIORITY`, en octets (§6.3).
pub const PRIORITY_OCTETS: usize = 5;

/// Combien de cadres de service on accepte d'affilée.
///
/// Deux cents. Un client qui mesure la latence envoie un `PING` de temps en
/// temps, pas deux cents de suite sans rien demander. Le compteur retombe à
/// zéro dès qu'un flux progresse : une connexion qui travaille ne l'approche
/// jamais.
pub const SERVICE_FRAMES_MAX: u32 = 200;

/// Combien de flux le pair peut annuler sans qu'on lui en tienne rigueur.
///
/// Cent, et **ce n'est pas un compteur : c'est un budget**. Chaque
/// `RST_STREAM` en dépense un ; chaque réponse menée à son terme en rend un.
/// Un client qui annule ce qu'il n'attend plus reste donc sous la borne aussi
/// longtemps qu'il consomme aussi ce qu'il demande — et un client qui n'annule
/// que pour faire travailler la remplit sans jamais la vider.
pub const CANCELLATIONS_MAX: u32 = 100;

/// De combien la fenêtre doit descendre avant qu'on la recharge.
///
/// La moitié. Recharger à chaque cadre ferait un `WINDOW_UPDATE` par `DATA` —
/// autant de cadres que de données, et le pair passerait son temps à les lire.
/// Attendre l'épuisement complet arrêterait l'émission entre le moment où la
/// fenêtre se ferme et celui où notre crédit arrive.
const FRACTION_DE_RECHARGE: u32 = 2;

/// Ce qu'un cadre a produit pour la couche du dessus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event<'a> {
    /// Rien à faire remonter : un cadre de service, ou un type inconnu.
    Nothing,
    /// Un bloc d'en-têtes est complet.
    ///
    /// # IL FAUT LE DÉCODER, MÊME QUAND `refused` EST RENSEIGNÉ
    ///
    /// La table dynamique HPACK est **commune à toute la connexion**, et se met
    /// à jour dans l'ordre des blocs. Sauter le décodage d'un bloc parce que
    /// son flux est refusé décalerait la table pour tous les blocs suivants :
    /// le pair et nous ne liraient plus les mêmes en-têtes, sans qu'un seul
    /// cadre soit fautif. Un flux refusé se décode donc, puis se jette.
    Head {
        /// Le flux.
        stream: u32,
        /// Combien d'octets le bloc occupe dans l'accumulateur.
        octets: usize,
        /// Le pair a-t-il fini d'envoyer sur ce flux ?
        end_stream: bool,
        /// Le flux a-t-il été refusé, et pour quelle raison ?
        refused: Option<ErrorCode>,
    },
    /// Des données pour un flux.
    Data {
        /// Le flux.
        stream: u32,
        /// La charge, remplissage ôté.
        payload: &'a [u8],
        /// Le pair a-t-il fini d'envoyer sur ce flux ?
        end_stream: bool,
    },
    /// Le pair a annulé un flux.
    Reset {
        /// Le flux.
        stream: u32,
        /// Ce qu'il en dit.
        code: ErrorCode,
    },
    /// Le pair s'en va.
    GoAway {
        /// Le dernier flux qu'il a traité.
        last: u32,
        /// Ce qu'il en dit.
        code: ErrorCode,
    },
}

/// Une connexion dont le préambule n'est pas encore lu.
///
/// Elle ne sait faire qu'une chose, et c'est ce qui la rend utile : lire le
/// préambule. Tant qu'il n'est pas là, aucun cadre ne peut être présenté à
/// quoi que ce soit.
#[derive(Debug, Clone, Copy)]
pub struct Handshake {
    /// Ce qu'on annoncera.
    nous: Settings,
}

impl Handshake {
    /// Une connexion à ouvrir, avec les réglages qu'on annoncera.
    #[must_use]
    pub const fn new(nous: Settings) -> Self {
        Self { nous }
    }

    /// Lit le préambule, et écrit nos `SETTINGS` quand il est complet.
    ///
    /// Rend la connexion — `None` tant que le préambule n'est pas complet — et
    /// combien d'octets ont été écrits dans `sortie`. Les [`crate::PREFACE`]
    /// octets du préambule sont à retirer du tampon d'entrée par l'appelant.
    ///
    /// # §3.4 : NOS `SETTINGS` PARTENT LES PREMIERS, ET SANS ATTENDRE
    ///
    /// « The server connection preface consists of a potentially empty SETTINGS
    /// frame that MUST be the first frame the server sends. » Attendre ceux du
    /// client pour envoyer les nôtres ferait deux pairs qui s'attendent.
    ///
    /// # Errors
    ///
    /// [`Cause::BadPreface`] ; [`Cause::BufferTooSmall`] si `sortie` ne suffit
    /// pas pour nos réglages.
    pub fn open(
        &self,
        tampon: &[u8],
        sortie: &mut [u8],
    ) -> Result<(Option<Connection>, usize), Error> {
        match read_preface(tampon)? {
            Preface::More => Ok((None, 0)),
            Preface::Complete => {
                // **ON ÉCRIT DANS `sortie`, ET NON DANS UN TAMPON À PART.** Un
                // tampon intermédiaire de la bonne taille rendrait l'échec de
                // `write` impossible — donc sa garde inatteignable — et il
                // faudrait quand même vérifier la place ici. Une seule
                // vérification, sur le seul tampon qui puisse manquer.
                let Some((tete, corps)) = sortie.split_at_mut_checked(FRAME_HEADER_OCTETS) else {
                    return Err(Error::connection(
                        ErrorCode::InternalError,
                        Cause::BufferTooSmall,
                    ));
                };
                let ecrits = self.nous.write(corps)?;
                let longueur = u32::try_from(ecrits).unwrap_or(u32::MAX);
                tete.copy_from_slice(
                    &FrameHeader::new(FrameKind::Settings, 0, 0, longueur).write(),
                );
                Ok((
                    Some(Connection::new(self.nous)),
                    FRAME_HEADER_OCTETS.saturating_add(ecrits),
                ))
            }
        }
    }
}

/// Une connexion HTTP/2 en marche.
#[derive(Debug)]
pub struct Connection {
    /// Ce qu'on a annoncé : cela borne ce qu'on ACCEPTE.
    nous: Settings,
    /// Ce que le pair a annoncé : cela borne ce qu'on ÉMET.
    pair: Settings,
    /// Attend-on encore le premier `SETTINGS` du pair (§3.4) ?
    premier_reglage: bool,
    /// Le pair a-t-il acquitté les nôtres ?
    acquitte: bool,
    /// Les flux.
    flux: Streams,
    /// La fenêtre de réception de la CONNEXION.
    reception: Window,
    /// La fenêtre d'émission de la CONNEXION.
    emission: Window,
    /// Le bloc d'en-têtes en cours.
    bloc: HeaderBlock,
    /// Le refus qui attend la fin du bloc en cours.
    refus: Option<ErrorCode>,
    /// La table dynamique HPACK, commune à toute la connexion.
    decodeur: Decoder,
    /// Combien de cadres de service se sont suivis sans progrès.
    sans_progres: u32,
    /// Combien de flux annulés n'ont pas encore été rendus par une réponse.
    annulations: u32,
    /// Le pair a-t-il dit qu'il s'en allait ?
    parti: bool,
}

impl Connection {
    /// Une connexion neuve, préambule lu.
    fn new(nous: Settings) -> Self {
        Self {
            nous,
            pair: Settings::DEFAULT,
            premier_reglage: true,
            acquitte: false,
            flux: Streams::new(nous.initial_window_size),
            // §6.9.2 : LA FENÊTRE DE LA CONNEXION NE SUIT PAS
            // `SETTINGS_INITIAL_WINDOW_SIZE`. Elle part de la valeur de §6.9.1,
            // et seul un `WINDOW_UPDATE` la change. Lui appliquer le réglage
            // ferait compter deux crédits pour un.
            reception: Window::new(INITIAL_WINDOW_SIZE),
            emission: Window::new(INITIAL_WINDOW_SIZE),
            bloc: HeaderBlock::new(),
            refus: None,
            decodeur: Decoder::new(),
            sans_progres: 0,
            annulations: 0,
            parti: false,
        }
    }

    /// Ce qu'on a annoncé.
    #[must_use]
    pub const fn settings(&self) -> Settings {
        self.nous
    }

    /// Ce que le pair a annoncé.
    #[must_use]
    pub const fn peer_settings(&self) -> Settings {
        self.pair
    }

    /// Le pair a-t-il acquitté nos réglages ?
    #[must_use]
    pub const fn settings_acknowledged(&self) -> bool {
        self.acquitte
    }

    /// Le pair a-t-il annoncé son départ ?
    #[must_use]
    pub const fn peer_left(&self) -> bool {
        self.parti
    }

    /// Les flux.
    #[must_use]
    pub const fn streams(&self) -> &Streams {
        &self.flux
    }

    /// La fenêtre de réception de la connexion.
    #[must_use]
    pub const fn receive_window(&self) -> Window {
        self.reception
    }

    /// La fenêtre d'émission de la connexion.
    #[must_use]
    pub const fn send_window(&self) -> Window {
        self.emission
    }

    /// La table dynamique HPACK, à qui décode les blocs.
    pub const fn decoder(&mut self) -> &mut Decoder {
        &mut self.decodeur
    }

    /// Une réponse est allée jusqu'au bout : elle rend un jeton d'annulation.
    ///
    /// C'est la couture avec l'étage qui émet. Sans elle, le budget de
    /// [`CANCELLATIONS_MAX`] ne se remplirait jamais, et une connexion longue
    /// finirait par tomber sur des annulations parfaitement légitimes.
    pub const fn response_sent(&mut self) {
        self.annulations = self.annulations.saturating_sub(1);
    }

    /// Lit un bloc d'en-têtes complet, et en fait une requête.
    ///
    /// `bloc` est ce que [`Event::Head`] a désigné dans l'accumulateur ; `out`
    /// reçoit les noms et les valeurs décodés, que la requête rendue emprunte.
    ///
    /// # IL FAUT L'APPELER MÊME POUR UN FLUX REFUSÉ
    ///
    /// La table dynamique HPACK est commune à toute la connexion, et se met à
    /// jour dans l'ordre des blocs. Sauter celui d'un flux refusé la décalerait
    /// pour tous les suivants. On décode, puis on jette.
    ///
    /// # DEUX FAMILLES DE FAUTES, ET ELLES NE SE PUNISSENT PAS PAREIL
    ///
    /// Une faute de COMPRESSION condamne la connexion : la table est partagée,
    /// et un décodeur qui s'est trompé une fois ne saura plus rien lire. Une
    /// liste bien décomprimée mais qui ne fait pas une requête — un
    /// pseudo-en-tête manquant, deux autorités qui se contredisent — ne
    /// condamne que son FLUX (§8.1.1) : la connexion, elle, n'a rien perdu.
    ///
    /// Les confondre coûterait cher dans les deux sens. Fermer la connexion sur
    /// une requête malformée, c'est offrir à un client maladroit d'emporter
    /// celles des autres ; ne fermer que le flux sur une faute HPACK, c'est
    /// continuer à lire une table dont on ne sait plus rien.
    ///
    /// # Errors
    ///
    /// Les fautes de §6 de RFC 7541, fatales ; [`Cause::MalformedRequest`] pour
    /// une liste qui ne fait pas une requête, et qui ne l'est pas.
    pub fn read_head<'o>(
        &mut self,
        bloc: &[u8],
        out: &'o mut [u8],
        limits: &Limits,
    ) -> Result<RequestHead<'o>, Error> {
        let malformee = || Error::stream(ErrorCode::ProtocolError, Cause::MalformedRequest);
        self.decodeur.begin_block();
        let mut tete = HeadBuilder::new(limits);
        let mut reste = bloc;
        let mut libre = out;
        while let Some(decode) = self.decodeur.next(reste, libre)? {
            // **LE DÉCODEUR REND CE QU'IL N'A PAS EMPLOYÉ**, et c'est ce qui
            // permet de décoder tout un bloc dans un seul tampon : sans cela,
            // le champ déjà rendu emprunterait encore celui du suivant.
            libre = decode.rest;
            reste = reste.get(decode.read..).unwrap_or_default();
            tete.field(decode.field.name, decode.field.value)
                .map_err(|_| malformee())?;
        }
        tete.finish().map_err(|_| malformee())
    }

    /// Range un cadre, et écrit ce qu'il faut répondre.
    ///
    /// `charge` est la charge du cadre, telle que [`crate::FrameReader`] l'a
    /// délimitée. `bloc` est l'accumulateur de blocs d'en-têtes, que l'appelant
    /// garde d'un cadre à l'autre. `sortie` reçoit les cadres à renvoyer.
    ///
    /// Rend l'événement et le nombre d'octets écrits dans `sortie`.
    ///
    /// # Errors
    ///
    /// Toutes celles de §5 et §6. Une faute FATALE ([`Error::is_fatal`])
    /// condamne la connexion ; les autres ne condamnent que leur flux.
    pub fn receive<'c>(
        &mut self,
        entete: FrameHeader,
        charge: &'c [u8],
        bloc: &mut [u8],
        sortie: &mut [u8],
    ) -> Result<(Event<'c>, usize), Error> {
        // **LES RÈGLES DE §4 SE VÉRIFIENT ICI AUSSI, ET CE N'EST PAS UN
        // DOUBLON.** [`crate::FrameReader`] les applique en découpant ; mais
        // rien n'oblige un appelant à passer par lui, et une machine d'état qui
        // croirait sur parole l'en-tête qu'on lui tend accepterait un `PING` de
        // neuf octets ou un `SETTINGS` sur un flux. La vérification est un
        // `match` sur un type : la redire coûte moins cher que de supposer
        // qu'elle a eu lieu.
        entete.check(self.nous.max_frame_size)?;
        // §4.3 : RIEN NE S'INTERCALE DANS UN BLOC D'EN-TÊTES. La question se
        // pose AVANT le type du cadre : un `PING` au milieu d'un bloc n'est pas
        // un `PING`, c'est une faute de connexion.
        self.bloc.accepts(entete)?;
        // §3.4 : le premier cadre du client est son `SETTINGS`. Le vérifier
        // APRÈS le bloc n'a pas d'importance — un bloc ne peut pas être en
        // cours avant le premier cadre — et le vérifier ici le met sur le
        // chemin de tous les types à la fois.
        if self.premier_reglage && entete.kind() != FrameKind::Settings {
            return Err(Error::connection(
                ErrorCode::ProtocolError,
                Cause::FirstFrameNotSettings,
            ));
        }
        match entete.kind() {
            FrameKind::Settings => self.reglages(entete, charge, sortie),
            FrameKind::Ping => self.ping(entete, charge, sortie),
            FrameKind::GoAway => self.adieu(charge),
            FrameKind::Priority => self.priorite(),
            FrameKind::RstStream => self.annulation(entete, charge),
            FrameKind::WindowUpdate => self.credit(entete, charge),
            FrameKind::Headers | FrameKind::Continuation => {
                self.entetes(entete, charge, bloc, sortie)
            }
            FrameKind::Data => self.donnees(entete, charge, sortie),
            // §8.4 : un client n'a jamais eu le droit de pousser, et ce serveur
            // annonce `ENABLE_PUSH` à zéro. Recevoir un `PUSH_PROMISE` d'un
            // client n'est donc pas une extension qu'on ignore : c'est un pair
            // qui parle un protocole qu'on ne sert pas.
            FrameKind::PushPromise => Err(Error::connection(
                ErrorCode::ProtocolError,
                Cause::PushFromClient,
            )),
            // §4.1 : ce qu'on ne connaît pas s'IGNORE. Il compte quand même
            // comme un cadre de service : un type inconnu inventé pour l'occasion
            // ferait sinon une inondation gratuite.
            FrameKind::Unknown(_) => {
                self.service()?;
                Ok((Event::Nothing, 0))
            }
        }
    }

    /// Un cadre de service de plus, et la borne qui va avec.
    fn service(&mut self) -> Result<(), Error> {
        self.sans_progres = self.sans_progres.saturating_add(1);
        match self.sans_progres > SERVICE_FRAMES_MAX {
            true => Err(Error::connection(
                ErrorCode::EnhanceYourCalm,
                Cause::TooManyServiceFrames,
            )),
            false => Ok(()),
        }
    }

    /// Un flux a progressé : les cadres de service repartent de zéro.
    ///
    /// **Et les annulations, elles, ne bougent pas.** Les remettre à zéro ici
    /// rendrait la borne des annulations inutile : *Rapid Reset* n'est fait que
    /// de flux qui progressent, chacun d'un `HEADERS`, puis meurent.
    const fn progres(&mut self) {
        self.sans_progres = 0;
    }

    /// `SETTINGS` (§6.5).
    fn reglages<'c>(
        &mut self,
        entete: FrameHeader,
        charge: &[u8],
        sortie: &mut [u8],
    ) -> Result<(Event<'c>, usize), Error> {
        self.service()?;
        if entete.flags().ack() {
            // §6.5 : un acquittement ne porte rien — et c'est
            // [`FrameHeader::check`], appelé en tête de [`Connection::receive`],
            // qui le dit. Le redire ici sur la TRANCHE plutôt que sur la
            // longueur annoncée ferait deux vérités pour une règle, et la
            // seconde ne serait vraie que si l'appelant les tient d'accord.
            self.acquitte = true;
            return Ok((Event::Nothing, 0));
        }
        SettingsReader::apply_all(charge, &mut self.pair)?;
        // §6.9.2 : le réglage que LE PAIR annonce borne ce que NOUS émettons.
        // Toutes les fenêtres d'émission bougent de la même différence, et
        // certaines deviennent négatives.
        self.flux
            .set_peer_initial_window(self.pair.initial_window_size)?;
        self.premier_reglage = false;
        // §6.5.3 : ON ACQUITTE, ET SANS TARDER. Les réglages du pair valent dès
        // qu'ils sont lus ; l'acquittement lui dit qu'ils valent chez nous, et
        // c'est ce qui lui permet de compter comme nous.
        let entete = FrameHeader::new(FrameKind::Settings, DRAPEAU_ACK, 0, 0);
        let poses = ecrire_cadre(entete, &[], sortie)?;
        Ok((Event::Nothing, poses))
    }

    /// `PING` (§6.7).
    fn ping<'c>(
        &mut self,
        entete: FrameHeader,
        charge: &[u8],
        sortie: &mut [u8],
    ) -> Result<(Event<'c>, usize), Error> {
        self.service()?;
        if entete.flags().ack() {
            // Un acquittement qui répond à un `PING` qu'on n'a pas envoyé ne
            // fait rien de mal : §6.7 n'oblige pas à le refuser, et le refuser
            // fermerait des connexions sur une mesure de latence croisée.
            return Ok((Event::Nothing, 0));
        }
        // §6.7 : ON RENVOIE LES HUIT OCTETS TELS QUELS. Les interpréter serait
        // leur donner un sens qu'ils n'ont pas — ils sont opaques, et c'est le
        // pair seul qui sait ce qu'il y a mis.
        let entete = FrameHeader::new(FrameKind::Ping, DRAPEAU_ACK, 0, PING_LONGUEUR);
        let poses = ecrire_cadre(entete, charge, sortie)?;
        Ok((Event::Nothing, poses))
    }

    /// `GOAWAY` (§6.8).
    fn adieu<'c>(&mut self, charge: &[u8]) -> Result<(Event<'c>, usize), Error> {
        // §6.8 : huit octets AU MOINS — le reste est un texte de débogage, dont
        // §6.8 dit qu'il ne doit rien changer à ce qu'on fait.
        let (Some(dernier), Some(code)) = (mot(charge, 0), mot(charge, CODE_OCTETS)) else {
            return Err(Error::connection(
                ErrorCode::FrameSizeError,
                Cause::WrongFixedSize,
            ));
        };
        self.service()?;
        self.parti = true;
        Ok((
            Event::GoAway {
                // Le bit de réserve du numéro de flux s'ignore (§4.1).
                last: dernier & MASQUE_RESERVE,
                code: ErrorCode::from_wire(code),
            },
            0,
        ))
    }

    /// `PRIORITY` (§6.3), déprécié par §5.3.2.
    fn priorite<'c>(&mut self) -> Result<(Event<'c>, usize), Error> {
        // ON LE LIT, ET ON N'EN FAIT RIEN. Construire l'arbre de priorités que
        // §5.3.2 a retiré demanderait de retenir un graphe que le pair choisit
        // — avec ses cycles, sa profondeur, et les failles qui vont avec.
        self.service()?;
        Ok((Event::Nothing, 0))
    }

    /// `RST_STREAM` (§6.4).
    fn annulation<'c>(
        &mut self,
        entete: FrameHeader,
        charge: &[u8],
    ) -> Result<(Event<'c>, usize), Error> {
        let Some(code) = mot(charge, 0) else {
            return Err(Error::connection(
                ErrorCode::FrameSizeError,
                Cause::WrongFixedSize,
            ));
        };
        // §6.4 : sur un flux OISIF, c'est une faute de connexion — annuler ce
        // qui n'a jamais commencé n'a pas de sens, et c'est une façon connue de
        // faire retenir des numéros de flux à un serveur.
        if self.flux.state(entete.stream()).is_none() {
            return Err(Error::connection(
                ErrorCode::ProtocolError,
                Cause::WrongStreamState,
            ));
        }
        self.service()?;
        // LE BUDGET DE *RAPID RESET*. Il ne se remplit que par
        // [`Connection::response_sent`] : un pair qui n'annule que pour faire
        // travailler ne rend jamais rien.
        self.annulations = self.annulations.saturating_add(1);
        if self.annulations > CANCELLATIONS_MAX {
            return Err(Error::connection(
                ErrorCode::EnhanceYourCalm,
                Cause::TooManyCancellations,
            ));
        }
        self.flux.close(entete.stream());
        Ok((
            Event::Reset {
                stream: entete.stream(),
                code: ErrorCode::from_wire(code),
            },
            0,
        ))
    }

    /// `WINDOW_UPDATE` (§6.9).
    fn credit<'c>(
        &mut self,
        entete: FrameHeader,
        charge: &[u8],
    ) -> Result<(Event<'c>, usize), Error> {
        let Some(brut) = mot(charge, 0) else {
            return Err(Error::connection(
                ErrorCode::FrameSizeError,
                Cause::WrongFixedSize,
            ));
        };
        self.service()?;
        // §6.9 : le bit de réserve s'ignore, et un crédit NUL est une faute.
        let ajout = brut & MASQUE_RESERVE;
        if ajout == 0 {
            let faute = Cause::ZeroWindowUpdate;
            return Err(match entete.stream() {
                0 => Error::connection(ErrorCode::ProtocolError, faute),
                // §6.9 : sur un flux, c'est une faute de FLUX — la connexion,
                // elle, n'a rien perdu.
                _ => Error::stream(ErrorCode::ProtocolError, faute),
            });
        }
        if entete.stream() == 0 {
            self.emission.increase(ajout)?;
            return Ok((Event::Nothing, 0));
        }
        match self.flux.state(entete.stream()) {
            // §6.9 : un `WINDOW_UPDATE` sur un flux OISIF est une faute de
            // connexion.
            None => Err(Error::connection(
                ErrorCode::ProtocolError,
                Cause::WrongStreamState,
            )),
            // **ET SUR UN FLUX FERMÉ, IL S'IGNORE.** §6.9 le dit en toutes
            // lettres : le crédit a pu croiser notre `RST_STREAM` sur le fil, et
            // en faire une faute punirait un pair qui n'a rien fait de mal.
            Some(StreamState::Closed) => Ok((Event::Nothing, 0)),
            Some(
                StreamState::Open | StreamState::HalfClosedRemote | StreamState::HalfClosedLocal,
            ) => {
                self.flux.credit_send(entete.stream(), ajout)?;
                Ok((Event::Nothing, 0))
            }
        }
    }

    /// `HEADERS` et `CONTINUATION` (§6.2, §6.10).
    fn entetes<'c>(
        &mut self,
        entete: FrameHeader,
        charge: &'c [u8],
        bloc: &mut [u8],
        sortie: &mut [u8],
    ) -> Result<(Event<'c>, usize), Error> {
        // §6.2 : le remplissage d'abord, la priorité ensuite. Les cinq octets de
        // priorité sont dépréciés et ne font rien — mais ils occupent la place,
        // et les laisser au bloc le rendrait illisible.
        let sans_remplissage = Padded::strip(charge, entete.flags().padded())?;
        let fragment = match entete.kind() == FrameKind::Headers && entete.flags().priority() {
            true => sans_remplissage
                .data()
                .get(PRIORITE_OCTETS..)
                .ok_or_else(|| {
                    Error::connection(ErrorCode::FrameSizeError, Cause::WrongFixedSize)
                })?,
            false => sans_remplissage.data(),
        };
        // Un `HEADERS` ouvre le flux ; une `CONTINUATION` continue le bloc d'un
        // flux déjà ouvert.
        if entete.kind() == FrameKind::Headers {
            self.refus = match self.flux.state(entete.stream()) {
                // Oisif : ce `HEADERS` l'ouvre.
                None => match self.flux.open(entete.stream()) {
                    Ok(()) => None,
                    // Une faute de FLUX ne condamne que lui — et le bloc doit
                    // être accumulé puis décodé quand même, sans quoi la table
                    // HPACK décalerait pour tous les blocs suivants.
                    Err(erreur) if !erreur.is_fatal() => Some(erreur.code()),
                    Err(erreur) => return Err(erreur),
                },
                // **LES REMORQUES NE SONT PAS SERVIES**, et c'est une décision.
                //
                // §8.1 permet un second `HEADERS` en fin de message. Rien ne
                // s'en sert pour une REQUÊTE — gRPC les emploie dans l'autre
                // sens — et les servir ferait passer un second jeu d'en-têtes
                // par toute la pile, après que la requête a été jugée sur le
                // premier. C7 tranche : ce qui n'apporte rien et ouvre un
                // chemin de plus ne se sert pas. Le flux est annulé, et lui
                // seul.
                Some(
                    StreamState::Open
                    | StreamState::HalfClosedRemote
                    | StreamState::HalfClosedLocal,
                ) => Some(ErrorCode::ProtocolError),
                // §5.1 : un `HEADERS` sur un flux fermé n'a plus de
                // destinataire.
                Some(StreamState::Closed) => Some(ErrorCode::StreamClosed),
            };
        }
        match self.bloc.push(entete, fragment, bloc)? {
            BlockState::More => Ok((Event::Nothing, 0)),
            BlockState::Complete(octets) => {
                let flux = entete.stream();
                let fin = self.bloc.end_stream();
                self.progres();
                let refus = self.refus.take();
                let mut poses = 0;
                match refus {
                    // Le flux est refusé : on le dit tout de suite, et on rend
                    // sa place. Le bloc, lui, remonte pour être décodé.
                    Some(code) => {
                        poses = self.ecrire_annulation(flux, code, sortie)?;
                        self.flux.close(flux);
                    }
                    // Le pair a tout dit : le flux passe en demi-fermé. Rien
                    // n'a pu s'intercaler depuis le `HEADERS` (§4.3), et le
                    // flux est donc bien celui qu'on vient d'ouvrir.
                    None if fin => self.flux.end_remote(flux),
                    None => {}
                }
                Ok((
                    Event::Head {
                        stream: flux,
                        octets,
                        end_stream: fin,
                        refused: refus,
                    },
                    poses,
                ))
            }
        }
    }

    /// `DATA` (§6.1).
    fn donnees<'c>(
        &mut self,
        entete: FrameHeader,
        charge: &'c [u8],
        sortie: &mut [u8],
    ) -> Result<(Event<'c>, usize), Error> {
        // §6.9.1 : **TOUTE LA CHARGE COMPTE, REMPLISSAGE COMPRIS**, et elle
        // compte pour la connexion AVANT de compter pour le flux. Un cadre
        // arrivé sur un flux fermé a quand même traversé la connexion : ne pas
        // l'y compter ferait diverger notre fenêtre de celle du pair, qui l'y a
        // compté, lui.
        // §5.1 : un cadre autre qu'un `HEADERS` sur un flux OISIF est une faute
        // de CONNEXION — pas de flux. Il n'y a pas de flux à qui l'imputer :
        // celui-là n'a jamais existé.
        if self.flux.state(entete.stream()).is_none() {
            return Err(Error::connection(
                ErrorCode::ProtocolError,
                Cause::WrongStreamState,
            ));
        }
        let longueur = entete.length();
        self.reception.consume(longueur)?;
        self.flux.consume(entete.stream(), longueur)?;
        let sans_remplissage = Padded::strip(charge, entete.flags().padded())?;
        self.progres();
        if entete.flags().end_stream() {
            // `consume` vient d'exiger que le flux soit OUVERT : la transition
            // ne peut pas échouer, et c'est pour cela qu'elle ne rend rien.
            self.flux.end_remote(entete.stream());
        }
        // ON RECHARGE APRÈS AVOIR CONSOMMÉ, et les deux fenêtres séparément :
        // celle de la connexion et celle du flux ne descendent pas au même
        // rythme, et recharger l'une pour l'autre les ferait diverger.
        let mut poses = self.recharger_connexion(sortie)?;
        let reste = sortie.get_mut(poses..).unwrap_or_default();
        poses = poses.saturating_add(self.recharger_flux(entete.stream(), reste)?);
        Ok((
            Event::Data {
                stream: entete.stream(),
                payload: sans_remplissage.data(),
                end_stream: entete.flags().end_stream(),
            },
            poses,
        ))
    }

    /// Rend à la fenêtre de la connexion ce qu'elle a perdu, si elle a assez
    /// perdu pour que cela vaille un cadre.
    fn recharger_connexion(&mut self, sortie: &mut [u8]) -> Result<usize, Error> {
        let Some(credit) = manque(self.reception, INITIAL_WINDOW_SIZE) else {
            return Ok(0);
        };
        // **ON REMPLIT, ON N'AJOUTE PAS.** Le crédit vient d'être calculé À
        // PARTIR de cette fenêtre : l'ajouter ne peut donner que la valeur
        // pleine, et passer par une addition qui peut déborder ferait une garde
        // qu'aucun appel ne peut emprunter.
        self.reception = Window::new(INITIAL_WINDOW_SIZE);
        ecrire_credit(0, credit, sortie)
    }

    /// De même pour un flux.
    ///
    /// **IL VIT FORCÉMENT** : on n'arrive ici qu'après un `DATA` que
    /// [`Streams::consume`] a accepté, et il n'accepte que sur un flux OUVERT.
    /// `unwrap_or_default` porte cette impossibilité dans la bibliothèque plutôt
    /// que dans une branche qu'aucun appel ne peut emprunter.
    fn recharger_flux(&mut self, id: u32, sortie: &mut [u8]) -> Result<usize, Error> {
        let fenetre = self.flux.window(id).unwrap_or_default();
        let Some(credit) = manque(fenetre, self.nous.initial_window_size) else {
            return Ok(0);
        };
        self.flux.refill(id, self.nous.initial_window_size);
        ecrire_credit(id, credit, sortie)
    }

    /// Écrit la tête d'une réponse : un `HEADERS` comprimé par HPACK.
    ///
    /// `end_stream` dit que la réponse n'a pas de corps.
    ///
    /// # ELLE TIENT DANS UN CADRE, OU ELLE NE PART PAS
    ///
    /// §6.10 permettrait de l'étaler sur des `CONTINUATION`. **On ne le fait
    /// pas**, et c'est une décision : le pair annonce au moins seize kibioctets
    /// de charge (§6.5.2), une tête de réponse qui n'y tient pas n'existe pas
    /// dans un service qui va bien, et n'émettre jamais de `CONTINUATION` nous
    /// retire de la liste de ceux qui peuvent en inonder un autre.
    ///
    /// # Errors
    ///
    /// [`Cause::WrongStreamState`] si le flux ne peut plus rien recevoir de
    /// nous ; [`Cause::BadResponseField`] pour un champ qu'on refuse d'écrire ;
    /// [`Cause::ResponseHeadTooLong`] ; [`Cause::BufferTooSmall`].
    pub fn write_head(
        &mut self,
        stream: u32,
        status: StatusCode,
        champs: &[(&[u8], &[u8])],
        end_stream: bool,
        sortie: &mut [u8],
    ) -> Result<usize, Error> {
        self.exiger_ecrivable(stream)?;
        for (nom, valeur) in champs {
            verifier_champ(nom, valeur)?;
        }
        // **ON ÉCRIT LE BLOC D'ABORD, L'EN-TÊTE ENSUITE** : sa longueur n'est
        // connue qu'une fois comprimée, et un tampon intermédiaire ferait une
        // copie et une borne de plus.
        let Some((tete, corps)) = sortie.split_at_mut_checked(FRAME_HEADER_OCTETS) else {
            return Err(Error::connection(
                ErrorCode::InternalError,
                Cause::BufferTooSmall,
            ));
        };
        let mut ecrits = encode_status(status.value(), corps)?;
        for (nom, valeur) in champs {
            let place = corps.get_mut(ecrits..).unwrap_or_default();
            ecrits = ecrits.saturating_add(encode_field(nom, valeur, place)?);
        }
        let longueur = u32::try_from(ecrits).unwrap_or(u32::MAX);
        if longueur > self.pair.max_frame_size {
            return Err(Error::connection(
                ErrorCode::InternalError,
                Cause::ResponseHeadTooLong,
            ));
        }
        let fanions = match end_stream {
            true => DRAPEAU_FIN_DE_BLOC | DRAPEAU_FIN_DE_MESSAGE,
            false => DRAPEAU_FIN_DE_BLOC,
        };
        tete.copy_from_slice(
            &FrameHeader::new(FrameKind::Headers, fanions, stream, longueur).write(),
        );
        if end_stream {
            self.conclure(stream);
        }
        Ok(FRAME_HEADER_OCTETS.saturating_add(ecrits))
    }

    /// Écrit autant de `corps` que les fenêtres et la place le permettent.
    ///
    /// Rend ce qui a été écrit dans `sortie` et ce qui a été pris de `corps`.
    /// **Zéro et zéro n'est pas une faute** : c'est une fenêtre fermée, et
    /// l'appelant attend le `WINDOW_UPDATE` du pair.
    ///
    /// # TROIS BORNES, ET C'EST LA PLUS PETITE QUI DÉCIDE
    ///
    /// La taille de cadre que le pair accepte, sa fenêtre de connexion, sa
    /// fenêtre de flux. En oublier une, c'est écrire un cadre que le pair
    /// traitera comme une faute de contrôle de flux — et il aura raison.
    ///
    /// # Errors
    ///
    /// [`Cause::WrongStreamState`] ; [`Cause::BufferTooSmall`] si `sortie` ne
    /// tient même pas un en-tête de cadre.
    pub fn write_data(
        &mut self,
        stream: u32,
        corps: &[u8],
        end_stream: bool,
        sortie: &mut [u8],
    ) -> Result<(usize, usize), Error> {
        self.exiger_ecrivable(stream)?;
        let Some((tete, place)) = sortie.split_at_mut_checked(FRAME_HEADER_OCTETS) else {
            return Err(Error::connection(
                ErrorCode::InternalError,
                Cause::BufferTooSmall,
            ));
        };
        // La plus petite des quatre : ce que le pair accepte par cadre, ce que
        // ses deux fenêtres laissent passer, et la place qu'on a.
        let fenetre_flux = self.flux.send_window(stream).unwrap_or_default();
        let ouvert = self
            .emission
            .available()
            .min(fenetre_flux.available())
            .max(0);
        let longueur = self
            .pair
            .max_frame_size
            .min(u32::try_from(place.len()).unwrap_or(u32::MAX))
            .min(u32::try_from(corps.len()).unwrap_or(u32::MAX))
            .min(u32::try_from(ouvert).unwrap_or(u32::MAX));
        let pris = usize::try_from(longueur).unwrap_or(usize::MAX);
        // **UN CADRE VIDE NE S'ÉCRIT QUE POUR DIRE LA FIN.** Sans cela, une
        // fenêtre fermée ferait envoyer des cadres qui ne portent rien.
        let fin = end_stream && pris == corps.len();
        if pris == 0 && !fin {
            return Ok((0, 0));
        }
        let morceau = corps.get(..pris).unwrap_or_default();
        place
            .get_mut(..pris)
            .unwrap_or_default()
            .copy_from_slice(morceau);
        // **ON PREND, ON NE CONSOMME PAS.** `longueur` vient d'être calculée À
        // PARTIR de ces deux fenêtres : une méthode qui rendrait une faute la
        // rendrait pour un appel que personne ne peut écrire.
        self.emission.take(longueur);
        self.flux.take_send(stream, longueur);
        let fanions = match fin {
            true => DRAPEAU_FIN_DE_MESSAGE,
            false => 0,
        };
        tete.copy_from_slice(&FrameHeader::new(FrameKind::Data, fanions, stream, longueur).write());
        if fin {
            self.conclure(stream);
        }
        Ok((FRAME_HEADER_OCTETS.saturating_add(pris), pris))
    }

    /// Écrit un `RST_STREAM` et ferme le flux.
    ///
    /// # Errors
    ///
    /// [`Cause::BufferTooSmall`].
    pub fn write_reset(
        &mut self,
        stream: u32,
        code: ErrorCode,
        sortie: &mut [u8],
    ) -> Result<usize, Error> {
        let poses = self.ecrire_annulation(stream, code, sortie)?;
        self.flux.close(stream);
        Ok(poses)
    }

    /// Écrit un `GOAWAY`, en disant jusqu'où on a traité.
    ///
    /// # LE DERNIER FLUX EST UNE PROMESSE, PAS UNE INDICATION
    ///
    /// §6.8 : au-delà de ce numéro, le pair sait que rien n'a été commencé, et
    /// peut réémettre ailleurs sans risque de doublon. Annoncer plus haut que ce
    /// qu'on a reçu ferait perdre des requêtes que personne ne saurait avoir
    /// perdues.
    ///
    /// # Errors
    ///
    /// [`Cause::BufferTooSmall`].
    pub fn write_goaway(&mut self, code: ErrorCode, sortie: &mut [u8]) -> Result<usize, Error> {
        let mut charge = [0_u8; GOAWAY_OCTETS];
        let (dernier, raison) = charge.split_at_mut(CODE_OCTETS);
        dernier.copy_from_slice(&self.flux.last_received().to_be_bytes());
        raison.copy_from_slice(&code.value().to_be_bytes());
        let longueur = u32::try_from(GOAWAY_OCTETS).unwrap_or(u32::MAX);
        let entete = FrameHeader::new(FrameKind::GoAway, 0, 0, longueur);
        ecrire_cadre(entete, &charge, sortie)
    }

    /// Ce flux peut-il encore recevoir quelque chose de nous ?
    fn exiger_ecrivable(&self, stream: u32) -> Result<(), Error> {
        match self.flux.state(stream) {
            Some(StreamState::Open | StreamState::HalfClosedRemote) => Ok(()),
            // Un flux que le pair a annulé, ou dont nous avons déjà fini : la
            // réponse arrive trop tard, et l'écrire serait parler dans le vide.
            // Ce n'est pas une faute de connexion — c'est une course que §5.1
            // prévoit.
            _ => Err(Error::stream(
                ErrorCode::StreamClosed,
                Cause::WrongStreamState,
            )),
        }
    }

    /// Nous avons dit notre dernier mot sur ce flux.
    ///
    /// **ET LE BUDGET DES ANNULATIONS S'EN TROUVE RECHARGÉ** : une réponse menée
    /// à son terme est exactement ce qui distingue un client qui travaille d'un
    /// client qui fait travailler.
    fn conclure(&mut self, stream: u32) {
        self.flux.end_local(stream);
        self.response_sent();
    }

    /// Écrit un `RST_STREAM`.
    fn ecrire_annulation(
        &self,
        flux: u32,
        code: ErrorCode,
        sortie: &mut [u8],
    ) -> Result<usize, Error> {
        let entete = FrameHeader::new(FrameKind::RstStream, 0, flux, CODE_LONGUEUR);
        ecrire_cadre(entete, &code.value().to_be_bytes(), sortie)
    }
}

/// Le fanion `ACK`, qui vaut aussi `END_STREAM` sur d'autres cadres — c'est le
/// même bit, et son sens vient du type.
const DRAPEAU_ACK: u8 = 0x1;

/// `END_STREAM`, le même bit que `ACK` sous un autre nom.
const DRAPEAU_FIN_DE_MESSAGE: u8 = 0x1;

/// `END_HEADERS`.
const DRAPEAU_FIN_DE_BLOC: u8 = 0x4;

/// Ce champ peut-il figurer dans une réponse qu'on écrit ?
///
/// # CE QU'ON REFUSE D'ÉCRIRE, ON LE REFUSE AUSSI DE SOI-MÊME
///
/// §8.2.2 interdit les champs propres à la connexion, et §8.3 réserve le `:` aux
/// pseudo-en-têtes — que cette couche écrit elle-même. Un serveur qui vérifie
/// ces règles à la RÉCEPTION mais pas à l'ÉMISSION laisse l'intermédiaire
/// suivant recevoir ce qu'il vient de refuser, et la contrebande repart de là.
///
/// La faute est `INTERNAL_ERROR` : c'est notre code qui a proposé ce champ, pas
/// le pair.
fn verifier_champ(nom: &[u8], valeur: &[u8]) -> Result<(), Error> {
    let refus = || {
        Err(Error::connection(
            ErrorCode::InternalError,
            Cause::BadResponseField,
        ))
    };
    if field_kind(nom) != FieldKind::Ordinary || is_connection_specific(nom) {
        return refus();
    }
    match field_value_is_valid(valeur) {
        true => Ok(()),
        false => refus(),
    }
}

/// Le masque qui ôte le bit de réserve d'un numéro de flux ou d'un crédit.
const MASQUE_RESERVE: u32 = 0x7fff_ffff;

/// Les octets de priorité qu'un `HEADERS` peut porter en tête (§6.2).
const PRIORITE_OCTETS: usize = 5;

/// [`PING_OCTETS`], dans le type qu'un en-tête de cadre demande.
///
/// # POURQUOI DEUX CONSTANTES POUR UN MÊME NOMBRE
///
/// Une longueur de cadre est un `u32`, une longueur de tranche est un `usize`,
/// et le workspace refuse les conversions qui peuvent tronquer. Les dériver
/// l'une de l'autre exigerait une conversion qu'aucune fonction `const` de la
/// bibliothèque n'offre à cette version de la chaîne. **Elles disent la même
/// chose, et les tests le vérifient** — c'est ce qui remplace ici la dérivation.
const PING_LONGUEUR: u32 = 8;

/// [`CODE_OCTETS`], dans le type qu'un en-tête de cadre demande.
const CODE_LONGUEUR: u32 = 4;

/// Ce qu'il manque à une fenêtre pour être pleine, quand il en manque assez.
///
/// `None` tant que la fenêtre n'est pas descendue sous la fraction voulue : un
/// crédit de zéro est une faute (§6.9), et un crédit d'un octet ferait un cadre
/// par octet reçu.
fn manque(fenetre: Window, pleine: u32) -> Option<u32> {
    let seuil = i64::from(pleine / FRACTION_DE_RECHARGE);
    if fenetre.available() > seuil {
        return None;
    }
    let manque = i64::from(pleine).saturating_sub(fenetre.available());
    // La fenêtre ne dépasse jamais `pleine` ici — on vient de le vérifier — et
    // le manque tient donc dans un `u32`. `unwrap_or` porte cette impossibilité
    // dans la bibliothèque plutôt que dans une branche qu'aucun appel n'emprunte.
    let credit = u32::try_from(manque).unwrap_or(u32::MAX);
    match credit {
        0 => None,
        _ => Some(credit),
    }
}

/// Écrit un `WINDOW_UPDATE`.
fn ecrire_credit(flux: u32, credit: u32, sortie: &mut [u8]) -> Result<usize, Error> {
    let entete = FrameHeader::new(FrameKind::WindowUpdate, 0, flux, CODE_LONGUEUR);
    ecrire_cadre(entete, &credit.to_be_bytes(), sortie)
}

/// Écrit un cadre entier — les neuf octets, puis la charge.
///
/// # Errors
///
/// [`Cause::BufferTooSmall`] : c'est NOTRE tampon, pas celui du pair, d'où
/// `INTERNAL_ERROR`.
fn ecrire_cadre(entete: FrameHeader, charge: &[u8], sortie: &mut [u8]) -> Result<usize, Error> {
    let court = || Error::connection(ErrorCode::InternalError, Cause::BufferTooSmall);
    let total = FRAME_HEADER_OCTETS.saturating_add(charge.len());
    let place = sortie.get_mut(..total).ok_or_else(court)?;
    let (tete, corps) = place.split_at_mut(FRAME_HEADER_OCTETS);
    tete.copy_from_slice(&entete.write());
    corps.copy_from_slice(charge);
    Ok(total)
}

/// Les quatre octets à ce rang, en gros-boutien.
fn mot(charge: &[u8], rang: usize) -> Option<u32> {
    // Deux gardes, et l'une n'est pas l'autre : la première refuse un rang
    // au-delà de la charge, la seconde une charge trop courte à partir de ce
    // rang. Un `try_into` aurait rendu la seconde inatteignable — une tranche
    // de quatre octets se convertit toujours.
    let quatre = charge.get(rang..)?.first_chunk::<CODE_OCTETS>()?;
    Some(u32::from_be_bytes(*quatre))
}

#[cfg(test)]
mod tests;
