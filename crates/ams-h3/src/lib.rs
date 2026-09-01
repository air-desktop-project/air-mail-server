// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le conducteur HTTP/3, **sans entrée-sortie** (C1).
//!
//! # LES PIÈCES EXISTAIENT ; RIEN NE SAVAIT DANS QUEL ORDRE
//!
//! `ams-proto-h3` sait lire une tête de flux, une trame, des réglages ; son
//! module `qpack` sait lire et écrire une section de champs ; `ams-session::http`
//! décide déjà des requêtes. Aucun ne sait **quel flux ouvrir en premier, ce
//! qu'il faut y écrire, ni à quoi rattacher les octets qui arrivent**. C'est
//! tout ce que ce crate décide.
//!
//! # IL NE TOUCHE À AUCUNE SOCKET
//!
//! Il conduit une [`Connection`] QUIC — il lit avec `read`, écrit avec `write`,
//! conclut avec `finish` —, et c'est l'écoute qui décide quand ces octets
//! partent. Le même partage qu'entre `ams-session::http` et
//! `ams-loop-tokio::http`, d'un étage plus haut.

#![forbid(unsafe_code)]

use ams_proto_h3::{
    Connection as H3Connection, FrameHeader, FrameKind, Message, Settings, StreamKind, qpack,
};
use ams_proto_quic::{Directional, Initiator, StreamId, varints};
use ams_quic::RecvState;

mod error;
mod service;
mod transport;

pub use error::{Error, Reason};
pub use service::{CHAMPS_MAX, Reponse, Service};
pub use transport::Transport;

/// Ce que la charge d'une trame de contrôle qu'on LIT peut faire.
///
/// **C'EST NOTRE BORNE, PAS CELLE DU PAIR** (C3) : §7.2 rend ces trames courtes
/// — des réglages, ou un seul entier de §16 —, et une qui dépasse donnerait au
/// pair le moyen de choisir combien nous retenons.
pub const CHARGE_OCTETS_MAX: usize = 64;

/// Ce qu'une section de champs peut faire, à la lecture (§4.2.2).
///
/// C'est le `SETTINGS_MAX_FIELD_SECTION_SIZE` qu'on annonce. Un client qui le
/// dépasse fait exactement ce que §8.1 nomme `H3_EXCESSIVE_LOAD` : il exhibe un
/// comportement qui pourrait engendrer une charge excessive, **après qu'on lui a
/// dit ce qu'on acceptait**.
pub const CHAMPS_OCTETS_MAX: usize = 16 * 1024;

/// Ce qu'un corps de requête peut faire.
///
/// **CE SERVEUR N'EST PAS UN DÉPÔT** : son API administre des boîtes, et ce qui
/// entre par une requête tient en quelques kibioctets. Un message de courrier
/// entre par SMTP, où il s'écoule sans être retenu.
pub const CORPS_OCTETS_MAX: usize = 64 * 1024;

/// Le code applicatif d'une extinction qui s'est bien passée (§8.1).
///
/// **`H3_NO_ERROR` N'EST PAS UN DÉTAIL** : fermer avec autre chose ferait
/// chercher au client une faute qui n'existe pas, et §5.2 dit exactement quand
/// l'employer — quand on a fini de s'éteindre proprement.
pub const NO_ERROR: u64 = ams_proto_h3::H3Error::NoError.value();

/// Les bornes de la sémantique HTTP qu'on applique en décodant (§4.2.2).
const LIMITES: ams_proto_http::Limits = ams_proto_http::Limits::DEFAULT;

/// Le plus long en-tête de §7.1 : deux entiers de §16, à huit octets chacun.
const ENTETE_OCTETS_MAX: usize = 16;

/// Combien d'insertions NOTRE encodeur a poussées dans la table du pair.
///
/// **ZÉRO, ET CE N'EST PAS UN COMPTEUR QUI ATTEND SA PREMIÈRE VALEUR** : ce
/// serveur n'emploie que la table statique de §3.1, donc n'ouvre jamais
/// d'insertion, donc n'émet jamais de section dont le compte d'insertions soit
/// non nul. C'est ce qui rend §4.4.1 et §4.4.3 applicables sans tenir d'état :
/// il n'y a rien à accuser, et rien à incrémenter.
const INSERTIONS_EMISES: u64 = 0;

/// Ce qu'on garde d'un flux tant qu'il n'a pas formé une trame complète.
///
/// # IL DOIT TENIR UNE TRAME ENTIÈRE, ET LA PLUS GRANDE
///
/// **La première version valait soixante-quatre, comme la charge seule** : un
/// `SETTINGS` de soixante-quatre octets remplissait alors le tampon sans jamais
/// tenir son en-tête, et le flux de contrôle se figeait pour toujours — sans une
/// erreur, sans une trace, et sans que le pair ait rien fait de mal. C'est la
/// couverture qui l'a montré, en signalant une branche qu'aucun essai
/// n'atteignait.
pub const TAMPON_OCTETS_MAX: usize = CHARGE_OCTETS_MAX.saturating_add(ENTETE_OCTETS_MAX);

/// Ce qu'un flux du pair s'est déclaré être.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// Sa tête n'est pas encore lue : un type peut s'étaler sur huit octets, et
    /// un flux QUIC les livre par morceaux.
    Inconnu,
    /// Le flux de contrôle du pair (§6.2.1).
    Controle,
    /// Le flux d'ENCODEUR du pair (§4.3 de RFC 9204).
    ///
    /// **IL NE PEUT PLUS RIEN PORTER QU'ON ACCEPTE**, et c'est notre propre
    /// annonce qui le décide : §3.2.3 interdit toute insertion quand la table
    /// vaut zéro. On le lit quand même, pour dire au pair ce qu'on refuse.
    QpackEncodeur,
    /// Le flux de DÉCODEUR du pair (§4.4 de RFC 9204).
    ///
    /// Il accuse réception de ce que NOTRE encodeur a inséré — c'est-à-dire de
    /// rien. Seule l'annulation d'un flux de §4.4.2 y reste licite.
    QpackDecodeur,
    /// Un flux de requête : bidirectionnel, ouvert par le client (§6.1).
    Requete,
    /// Un flux qu'on ne conduit plus : on le consomme, et rien de plus.
    ///
    /// Deux chemins y mènent, et ils demandent la même chose.
    ///
    /// §6.2 : « The recipient MUST NOT consider unknown stream types to be a
    /// connection error of any kind. » On abandonne CE flux et rien d'autre —
    /// c'est ce qui laisse une extension ouvrir les siens sans casser les pairs
    /// qui ne la connaissent pas.
    ///
    /// §5.2 : une requête au-delà de ce qu'un `GOAWAY` a annoncé est refusée. On
    /// lui a dit `H3_REQUEST_REJECTED`, et **le pair peut continuer d'écrire** —
    /// un `RESET_STREAM` n'arrête que NOTRE sens (§3.3 de RFC 9000). Consommer
    /// ce qui arrive est ce qui rouvre sa fenêtre.
    Abandonne,
}

/// Ce qu'on suit d'un flux.
#[derive(Debug)]
struct Suivi {
    /// Son numéro.
    flux: StreamId,
    /// Ce qu'il s'est déclaré être.
    role: Role,
    /// Les octets arrivés qui ne forment pas encore une trame.
    tampon: Vec<u8>,
    /// Ce qu'on suit d'une requête, si ce flux en porte une.
    requete: Option<Requete>,
    /// Ce qu'il reste à sauter d'une trame qu'on ignore (§9).
    ///
    /// **ON SAUTE SANS RETENIR** : une trame inconnue peut faire des mébioctets,
    /// et la mettre dans le tampon donnerait au pair le moyen de choisir combien
    /// nous retenons.
    a_sauter: u64,
}

/// Ce qu'on suit d'un flux de requête (§4.1).
#[derive(Debug, Default)]
struct Requete {
    /// La séquence de §4.1 : en-têtes, puis corps, puis au plus une section
    /// terminale.
    message: Message,
    /// La section de champs, telle qu'elle arrive.
    champs: Vec<u8>,
    /// Le corps.
    corps: Vec<u8>,
    /// La trame en cours, et ce qu'il en reste à lire.
    reste: Option<(FrameKind, u64)>,
    /// A-t-on déjà répondu ?
    ///
    /// **UNE FOIS, ET UNE SEULE** : §4.1 ne prévoit qu'un message de réponse par
    /// flux, et en écrire un second ferait lire au client une réponse qui ne
    /// répond à rien.
    repondu: bool,
}

/// Le conducteur HTTP/3 d'une connexion.
#[derive(Debug)]
pub struct Http3 {
    /// L'état de connexion de §6.2 et §7.2.
    h3: H3Connection,
    /// Ce qu'on suit, un par flux vivant.
    suivis: Vec<Suivi>,
    /// Notre flux de contrôle, une fois ouvert.
    controle: Option<StreamId>,
    /// Notre flux d'encodeur QPACK (§4.2 de RFC 9204).
    ///
    /// **IL NE PORTERA QUE SON TYPE**, et c'est entier : notre encodeur
    /// n'emploie que la table statique, et §4.3 ne connaît pas d'instruction qui
    /// dise « je n'insérerai rien ».
    encodeur: Option<StreamId>,
    /// Notre flux de décodeur QPACK (§4.2 de RFC 9204).
    ///
    /// **DE MÊME, ET POUR UNE AUTRE RAISON** : §4.4.1 ne demande un accusé que
    /// pour une section dont le compte d'insertions n'est pas nul, et le client
    /// ne peut pas en émettre puisqu'on lui a annoncé une table nulle.
    decodeur: Option<StreamId>,
    /// Les réglages qu'on annonce.
    nos_reglages: Settings,
    /// Le plus grand flux de requête qu'on ait servi, s'il y en a eu un.
    ///
    /// **C'EST CE QUI DONNE SON IDENTIFIANT AU `GOAWAY` PRÉCIS** (§5.2) : le
    /// second temps de l'extinction doit dire jusqu'où l'on est allé, et rien
    /// d'autre ne le sait. Le tenir à jour coûte une comparaison par réponse.
    dernier_servi: Option<u64>,
}

impl Default for Http3 {
    fn default() -> Self {
        Self::new()
    }
}

impl Http3 {
    /// Un conducteur pour une connexion qui vient de s'établir.
    #[must_use]
    pub fn new() -> Self {
        Self {
            h3: H3Connection::new(),
            suivis: Vec::new(),
            controle: None,
            encodeur: None,
            decodeur: None,
            nos_reglages: Settings::DEFAULT,
            dernier_servi: None,
        }
    }

    /// Notre flux de contrôle, une fois ouvert.
    #[must_use]
    pub const fn control_stream(&self) -> Option<StreamId> {
        self.controle
    }

    /// Notre flux d'encodeur QPACK, une fois ouvert (§4.2 de RFC 9204).
    #[must_use]
    pub const fn qpack_encoder_stream(&self) -> Option<StreamId> {
        self.encodeur
    }

    /// Notre flux de décodeur QPACK, une fois ouvert (§4.2 de RFC 9204).
    #[must_use]
    pub const fn qpack_decoder_stream(&self) -> Option<StreamId> {
        self.decodeur
    }

    /// Les réglages que le pair a annoncés (§7.2.4).
    #[must_use]
    pub const fn peer_settings(&self) -> Option<Settings> {
        self.h3.peer_settings()
    }

    /// La connexion QUIC est établie : on ouvre nos trois flux.
    ///
    /// # LE FLUX DE CONTRÔLE D'ABORD, ET §6.2.1 L'EXIGE
    ///
    /// « Each side MUST initiate a single control stream at the beginning of the
    /// connection and send its SETTINGS frame as the first frame on this
    /// stream. » Un client qui ne recevrait pas nos réglages devrait supposer
    /// les valeurs par défaut, et refuserait des réponses que nous jugeons
    /// acceptables.
    ///
    /// # PUIS LES DEUX FLUX QPACK, QUI NE PORTERONT QUE LEUR TYPE
    ///
    /// §4.2 de RFC 9204 dit « at most one » et non « exactly one » : les ouvrir
    /// n'est pas une obligation, et l'on n'y écrira jamais rien — notre encodeur
    /// n'emploie que la table statique, et notre décodeur n'a aucun accusé à
    /// rendre puisqu'on a annoncé une table nulle.
    ///
    /// **On les ouvre quand même, et c'est un choix.** Un flux absent et un flux
    /// muet ne se distinguent pas d'un flux qui tarde : un pair qui attend ceux
    /// de son vis-à-vis pour commencer attendrait indéfiniment, et rien dans ce
    /// qu'il verrait ne lui dirait qu'il attend pour rien. Deux octets à
    /// l'ouverture d'une connexion suppriment la question.
    ///
    /// Le prix est **trois flux unidirectionnels de crédit** au lieu d'un. §6.2
    /// de RFC 9114 demande justement au pair d'en donner assez pour ces trois-là ;
    /// un pair qui n'en donne qu'un ne verra pas la connexion s'ouvrir, et c'est
    /// ce que dit alors [`Reason::Transport`].
    ///
    /// # Errors
    ///
    /// [`Reason::Transport`] si le pair ne nous a pas ouvert de quoi ouvrir trois
    /// flux unidirectionnels, [`Reason::H3`] si nos propres réglages ne
    /// s'écrivent pas.
    pub fn on_established<T: Transport>(&mut self, quic: &mut T) -> Result<(), Error> {
        if self.controle.is_some() {
            return Ok(());
        }
        let flux = quic.open_uni()?;

        // **AUCUNE DE CES TROIS ÉCRITURES NE PEUT ÉCHOUER**, et un `?` ouvrirait
        // trois branches que rien ne peut emprunter : le type du flux tient sur
        // un octet, nos propres réglages sur quelques-uns, et le tampon fait la
        // taille d'une trame entière.
        let mut tete = [0_u8; TAMPON_OCTETS_MAX];
        // §6.2 : le type du flux d'abord, une seule fois, en tête.
        let mut pose = varints::encode(StreamKind::Control.value(), &mut tete)
            .expect("le type d'un flux de contrôle tient sur un octet");

        let mut charge = [0_u8; CHARGE_OCTETS_MAX];
        let combien = self
            .nos_reglages
            .write(&mut charge)
            .expect("nos propres réglages tiennent dans notre propre tampon");
        let place = tete.get_mut(pose..).unwrap_or_default();
        pose = pose.saturating_add(
            ams_proto_h3::write_header(
                FrameKind::Settings,
                u64::try_from(combien).unwrap_or(u64::MAX),
                place,
            )
            .expect("un en-tête de §7.1 tient dans ce qui reste"),
        );

        let mut sortie = Vec::with_capacity(pose.saturating_add(combien));
        sortie.extend_from_slice(tete.get(..pose).unwrap_or_default());
        sortie.extend_from_slice(charge.get(..combien).unwrap_or_default());
        quic.write(flux, &sortie)?;
        self.controle = Some(flux);

        // §4.2 de RFC 9204 : et nos deux flux QPACK, qui n'ont que leur type à
        // dire. L'ordre n'est pas imposé — seul le flux de contrôle doit venir
        // en premier, et il vient d'être ouvert.
        self.encodeur = Some(Self::ouvrir_un_flux(quic, StreamKind::QpackEncoder)?);
        self.decodeur = Some(Self::ouvrir_un_flux(quic, StreamKind::QpackDecoder)?);
        Ok(())
    }

    /// L'identifiant à mettre dans le `GOAWAY` du second temps (§5.2).
    ///
    /// « Requests or pushes with the indicated identifier or greater are rejected
    /// by the sender of the GOAWAY. » On désigne donc le flux qui SUIT le dernier
    /// qu'on ait servi — quatre de plus, puisque §2.1 de RFC 9000 numérote les
    /// bidirectionnels du client de quatre en quatre.
    ///
    /// **RIEN DE SERVI DONNE ZÉRO**, et c'est juste : tout est alors à rejouer.
    #[must_use]
    pub fn goaway_id(&self) -> u64 {
        self.dernier_servi
            .map_or(0, |dernier| dernier.saturating_add(4))
    }

    /// Le `GOAWAY` qu'on a émis, s'il l'a été (§5.2).
    #[must_use]
    pub const fn goaway_sent(&self) -> Option<u64> {
        self.h3.goaway_sent()
    }

    /// **PREMIER TEMPS DE L'EXTINCTION** : « n'ouvre plus rien » (§5.2).
    ///
    /// L'identifiant maximal ne condamne aucune requête en vol : il dit seulement
    /// que le client ne doit plus en ouvrir. C'est ce qui laisse au délai de grâce
    /// un sens — sans lui, on refuserait des requêtes qui allaient aboutir.
    ///
    /// # Errors
    ///
    /// [`Reason::Transport`] si le flux de contrôle n'accepte plus rien.
    pub fn shutdown<T: Transport>(&mut self, quic: &mut T) -> Result<(), Error> {
        self.goaway(quic, ams_proto_h3::GOAWAY_MAX)
    }

    /// **SECOND TEMPS** : le rang qui suit la dernière requête servie (§5.2).
    ///
    /// # Errors
    ///
    /// [`Reason::Transport`] si le flux de contrôle n'accepte plus rien.
    pub fn drain<T: Transport>(&mut self, quic: &mut T) -> Result<(), Error> {
        self.goaway(quic, self.goaway_id())
    }

    /// S'éteint : dit au pair jusqu'où l'on servira (§5.2).
    ///
    /// # L'EXTINCTION SE FAIT EN DEUX TEMPS, ET CETTE FONCTION EN FAIT UN
    ///
    /// §5.2 décrit exactement la manœuvre : d'abord un `GOAWAY` à l'identifiant
    /// maximal, qui dit « n'ouvre plus rien » sans rien condamner de ce qui est
    /// en vol ; puis, une fois les requêtes en vol arrivées, un second au rang
    /// réel de ce qu'on aura servi. Les deux passent par ici — c'est l'appelant
    /// qui tient le délai, parce que lui seul a une horloge (C1).
    ///
    /// **L'IDENTIFIANT NE PEUT QUE DESCENDRE**, et [`ams_proto_h3::Connection`]
    /// le tient : « the identifier in each frame MUST NOT be greater than the
    /// identifier in any previous frame ». Un client a pu rejouer ailleurs les
    /// requêtes qu'un premier `GOAWAY` avait déclarées perdues ; les réaccepter
    /// les ferait exécuter deux fois.
    ///
    /// **SANS FLUX DE CONTRÔLE, IL N'Y A RIEN À DIRE.** Ce n'est pas une faute :
    /// une connexion dont la poignée de main n'a jamais abouti n'a pas de pair à
    /// qui faire ses adieux.
    ///
    /// # Errors
    ///
    /// [`Reason::Transport`] si le flux de contrôle n'accepte plus rien.
    fn goaway<T: Transport>(&mut self, quic: &mut T, identifiant: u64) -> Result<(), Error> {
        let Some(controle) = self.controle else {
            return Ok(());
        };
        let dit = self.h3.goaway(identifiant);

        // **AUCUNE DE CES TROIS ÉCRITURES NE PEUT ÉCHOUER** : un identifiant de
        // §16 tient sur huit octets, et l'en-tête de §7.1 sur seize.
        let mut charge = [0_u8; ENTETE_OCTETS_MAX];
        let combien =
            varints::encode(dit, &mut charge).expect("un identifiant de §16 tient sur huit octets");
        let mut entete = [0_u8; ENTETE_OCTETS_MAX];
        let pose = ams_proto_h3::write_header(
            FrameKind::GoAway,
            u64::try_from(combien).unwrap_or(u64::MAX),
            &mut entete,
        )
        .expect("un en-tête de §7.1 tient sur seize octets");

        let mut sortie = Vec::with_capacity(pose.saturating_add(combien));
        sortie.extend_from_slice(entete.get(..pose).unwrap_or_default());
        sortie.extend_from_slice(charge.get(..combien).unwrap_or_default());
        quic.write(controle, &sortie)?;
        Ok(())
    }

    /// Ouvre un flux unidirectionnel qui n'a que son type à annoncer (§6.2).
    fn ouvrir_un_flux<T: Transport>(quic: &mut T, kind: StreamKind) -> Result<StreamId, Error> {
        let flux = quic.open_uni()?;
        let mut tete = [0_u8; ENTETE_OCTETS_MAX];
        // **CELLE-CI NON PLUS NE PEUT PAS ÉCHOUER** : les types de §11.2.3
        // tiennent sur un octet, et le tampon en fait seize.
        let pose = varints::encode(kind.value(), &mut tete)
            .expect("le type d'un flux QPACK tient sur un octet");
        quic.write(flux, tete.get(..pose).unwrap_or_default())?;
        Ok(flux)
    }
}

/// La lecture : à quoi rattacher les octets qui arrivent.
impl Http3 {
    /// Ce flux a de quoi être lu.
    ///
    /// # Errors
    ///
    /// [`Reason::H3`] pour ce que §6.2 et §7.2 condamnent, [`Reason::Quic`] si
    /// l'on ne peut plus écrire.
    pub fn on_readable<T: Transport, S: Service>(
        &mut self,
        quic: &mut T,
        service: &mut S,
        flux: StreamId,
    ) -> Result<(), Error> {
        // §6.1 : nos propres flux ne portent rien qu'on doive lire.
        if matches!(flux.initiator(), Initiator::Server) {
            return Ok(());
        }
        let rang = self.rang_de(flux);
        // §5.2 : « Requests [...] with the indicated identifier or greater are
        // rejected by the sender of the GOAWAY. » **ON REFUSE AVANT DE LIRE** :
        // avaler les octets d'une requête qu'on ne servira pas retiendrait de la
        // mémoire pour rien, et l'on veut justement s'éteindre.
        //
        // **LE RÔLE EST CE QUI REND CE REFUS UNIQUE** : `refuser` le fait passer à
        // `Abandonne`, et un second `RESET_STREAM` ne dirait rien de plus.
        if matches!(self.suivis[rang].role, Role::Requete) && !self.h3.accepts(flux.value()) {
            self.refuser(quic, rang)?;
        }
        self.avaler(quic, flux)?;
        let rang = self.rang_de(flux);
        if matches!(self.suivis[rang].role, Role::Requete) {
            return self.peut_etre_repondre(quic, service, flux, rang);
        }
        // §6.2.1 et §4.2 de RFC 9204 : un flux critique qui se ferme est une
        // faute, et il n'y a pas de cas où c'est acceptable.
        if matches!(
            self.suivis[rang].role,
            Role::Controle | Role::QpackEncodeur | Role::QpackDecodeur
        ) && matches!(
            quic.recv_state(flux),
            Some(RecvState::DataRecvd | RecvState::DataRead)
        ) {
            return Err(Error::depuis_h3(
                self.h3
                    .on_critical_stream_closed()
                    .expect_err("cette fonction ne rend jamais `Ok`"),
            ));
        }
        Ok(())
    }

    /// Refuse cette requête : rien n'a été fait, et le client peut rejouer.
    ///
    /// §8.1 : `H3_REQUEST_REJECTED` — « the request was not processed ». C'est
    /// une PROMESSE, et c'est elle qui rend l'extinction propre : un client qui
    /// la reçoit rejoue ailleurs sans risquer d'exécuter deux fois ce qu'il
    /// demande. Un `H3_REQUEST_CANCELLED` ne dirait pas cela, et un flux qu'on
    /// laisserait pendre ne dirait rien du tout.
    fn refuser<T: Transport>(&mut self, quic: &mut T, rang: usize) -> Result<(), Error> {
        let flux = self.suivis[rang].flux;
        self.suivis[rang].role = Role::Abandonne;
        // Ce qu'on avait commencé à retenir pour elle ne sert plus.
        self.suivis[rang].requete = None;
        self.suivis[rang].tampon = Vec::new();
        quic.reset(flux, ams_proto_h3::H3Error::RequestRejected.value())
    }

    /// Sert la requête si elle est entière, et une seule fois.
    ///
    /// # ON N'ATTEND PAS LA SECTION TERMINALE POUR RIEN
    ///
    /// §4.1 : une requête est faite quand le client a fini d'écrire. Répondre
    /// avant serait répondre à ce qu'on n'a pas encore lu — et l'application
    /// servirait une requête tronquée sans savoir qu'elle l'était.
    fn peut_etre_repondre<T: Transport, S: Service>(
        &mut self,
        quic: &mut T,
        service: &mut S,
        flux: StreamId,
        rang: usize,
    ) -> Result<(), Error> {
        let fini = matches!(
            quic.recv_state(flux),
            Some(RecvState::DataRecvd | RecvState::DataRead)
        );
        let requete = self.suivis[rang]
            .requete
            .as_ref()
            .expect("un flux de requête porte son état");
        // Rien n'est fini, ou l'on a déjà répondu, ou une trame est à cheval.
        if !fini || requete.repondu || requete.reste.is_some() {
            return Ok(());
        }
        // §4.1 : un flux qui se termine sans section d'en-têtes n'est pas une
        // requête, et le taire ferait servir une requête qui n'existe pas.
        requete.message.on_end().map_err(Error::depuis_h3)?;

        let champs = core::mem::take(&mut self.suivis[rang].requete.as_mut().expect("état").champs);
        let corps = core::mem::take(&mut self.suivis[rang].requete.as_mut().expect("état").corps);

        // **DEUX FOIS LA SECTION** : le codage de Huffman de §4.1.2 de RFC 9204
        // se décomprime, et jamais au-delà de huit cinquièmes. Deux laisse la
        // marge, et le tampon meurt avec la requête.
        let mut decode = vec![0_u8; CHAMPS_OCTETS_MAX.saturating_mul(2)];
        let tete = qpack::read_section(&champs, &mut decode, &LIMITES).map_err(Error::depuis_h3)?;

        let mut sortie = vec![0_u8; CORPS_OCTETS_MAX];
        let reponse = service.serve(&tete, &corps, &mut sortie);
        self.ecrire_la_reponse(quic, flux, &reponse)?;
        self.suivis[rang].requete.as_mut().expect("état").repondu = true;
        // §5.2 : le second temps de l'extinction dira jusqu'où l'on est allé.
        self.dernier_servi = Some(
            self.dernier_servi
                .map_or(flux.value(), |avant| avant.max(flux.value())),
        );
        Ok(())
    }

    /// Écrit la réponse : sa section de champs, puis son corps (§4.1).
    fn ecrire_la_reponse<T: Transport>(
        &mut self,
        quic: &mut T,
        flux: StreamId,
        reponse: &Reponse<'_>,
    ) -> Result<(), Error> {
        let champs: Vec<(&[u8], &[u8])> = reponse.fields().collect();
        let mut section = vec![0_u8; CHAMPS_OCTETS_MAX];
        let ecrits = qpack::write_section(reponse.status(), &champs, &mut section)
            .map_err(Error::depuis_h3)?;

        let mut entete = [0_u8; ENTETE_OCTETS_MAX];
        let mut paquet = Vec::with_capacity(ecrits.saturating_add(reponse.body().len()));
        let pose = ams_proto_h3::write_header(
            FrameKind::Headers,
            u64::try_from(ecrits).unwrap_or(u64::MAX),
            &mut entete,
        )
        .expect("un en-tête de §7.1 tient sur seize octets");
        paquet.extend_from_slice(entete.get(..pose).unwrap_or_default());
        paquet.extend_from_slice(section.get(..ecrits).unwrap_or_default());

        // §4.1 : le corps suit, dans une trame `DATA`. **UN CORPS VIDE N'EN
        // DEMANDE PAS** : une trame de zéro octet ne dit rien de plus que son
        // absence, et coûte deux octets à chaque réponse sans corps.
        if !reponse.body().is_empty() {
            let pose = ams_proto_h3::write_header(
                FrameKind::Data,
                u64::try_from(reponse.body().len()).unwrap_or(u64::MAX),
                &mut entete,
            )
            .expect("un en-tête de §7.1 tient sur seize octets");
            paquet.extend_from_slice(entete.get(..pose).unwrap_or_default());
            paquet.extend_from_slice(reponse.body());
        }
        quic.write(flux, &paquet)?;
        // §4.1 : et le flux se termine, sans quoi le client attendrait la suite.
        quic.finish(flux)
    }

    /// Le rang de ce flux dans ce qu'on suit, en l'ouvrant au besoin.
    fn rang_de(&mut self, flux: StreamId) -> usize {
        if let Some(rang) = self.suivis.iter().position(|suivi| suivi.flux == flux) {
            return rang;
        }
        // §6.1 : un bidirectionnel ouvert par le client porte une requête, et
        // n'annonce pas de type — c'est sa direction qui le dit.
        let role = match flux.directional() {
            Directional::Bidirectional => Role::Requete,
            Directional::Unidirectional => Role::Inconnu,
        };
        self.suivis.push(Suivi {
            flux,
            role,
            tampon: Vec::new(),
            requete: match role {
                Role::Requete => Some(Requete::default()),
                _ => None,
            },
            a_sauter: 0,
        });
        self.suivis.len().saturating_sub(1)
    }

    /// Prend ce qui est prêt sur ce flux, et le fait avancer.
    fn avaler<T: Transport>(&mut self, quic: &mut T, flux: StreamId) -> Result<(), Error> {
        let rang = self.rang_de(flux);
        let mut vers = [0_u8; TAMPON_OCTETS_MAX];
        loop {
            // Ce qu'on saute d'abord : une trame qu'on ignore (§9) ne doit pas
            // entrer dans le tampon.
            if self.suivis[rang].a_sauter > 0 {
                let combien = usize::try_from(self.suivis[rang].a_sauter)
                    .unwrap_or(usize::MAX)
                    .min(vers.len());
                let lus = quic.read(flux, vers.get_mut(..combien).unwrap_or_default());
                if lus == 0 {
                    return Ok(());
                }
                self.suivis[rang].a_sauter = self.suivis[rang]
                    .a_sauter
                    .saturating_sub(u64::try_from(lus).unwrap_or(0));
                continue;
            }

            // **PAS DE GARDE SUR UNE PLACE NULLE** : `un_pas` vide toujours ce
            // qu'il consomme, donc le tampon n'est jamais plein en début de
            // tour. Et s'il l'était, lire dans une tranche vide ne rendrait que
            // zéro — une garde ici serait une seconde façon de dire la même
            // chose, dont l'une ne servirait jamais.
            let place = TAMPON_OCTETS_MAX.saturating_sub(self.suivis[rang].tampon.len());
            let lus = quic.read(flux, vers.get_mut(..place).unwrap_or_default());
            self.suivis[rang]
                .tampon
                .extend_from_slice(vers.get(..lus).unwrap_or_default());
            // **RIEN N'A AVANCÉ** : ni de quoi lire, ni de quoi décider.
            if !self.un_pas(rang)? {
                return Ok(());
            }
        }
    }
}

/// Un pas de décision, à partir de ce que le tampon porte.
impl Http3 {
    /// Fait avancer ce flux d'un pas, s'il peut avancer.
    ///
    /// Rend `false` quand il faut davantage d'octets — c'est la condition
    /// d'arrêt de la boucle, et la seule.
    fn un_pas(&mut self, rang: usize) -> Result<bool, Error> {
        match self.suivis[rang].role {
            Role::Inconnu => self.une_tete(rang),
            // §9 : ce qu'on ne conduit pas, on le consomme sans le lire.
            // **CONSOMMER PLUTÔT QU'IGNORER** : les octets non lus ne rouvriraient
            // jamais la fenêtre du flux (§4.1 de RFC 9000), et le pair finirait
            // bloqué sans comprendre pourquoi.
            Role::Abandonne => {
                let vide = self.suivis[rang].tampon.is_empty();
                self.suivis[rang].tampon.clear();
                Ok(!vide)
            }
            Role::QpackEncodeur => self.une_instruction_d_encodeur(rang),
            Role::QpackDecodeur => self.une_instruction_de_decodeur(rang),
            Role::Controle => self.une_trame_de_controle(rang),
            Role::Requete => self.une_trame_de_requete(rang),
        }
    }

    /// Verse une trame d'un flux de requête, ou en lit l'en-tête (§4.1).
    fn une_trame_de_requete(&mut self, rang: usize) -> Result<bool, Error> {
        // La trame en cours d'abord : ses octets vont dans leur bac, et non dans
        // le tampon — un corps de soixante kibioctets n'a rien à y faire.
        if let Some((kind, manque)) = self.suivis[rang]
            .requete
            .as_ref()
            .and_then(|requete| requete.reste)
        {
            return self.verser(rang, kind, manque);
        }

        let entete = match FrameHeader::parse(&self.suivis[rang].tampon) {
            Ok(entete) => entete,
            Err(faute) if matches!(faute.reason(), ams_proto_h3::Reason::Truncated) => {
                return Ok(false);
            }
            Err(faute) => return Err(Error::depuis_h3(faute)),
        };
        let kind = entete.kind();
        let requete = self.suivis[rang]
            .requete
            .as_mut()
            .expect("un flux de requête porte son état");
        // §4.1 : une section d'en-têtes, puis des `DATA`, puis au plus une
        // section terminale. Ce qui sort de cette suite est une faute de
        // CONNEXION, et non de flux.
        requete.message.on_frame(kind).map_err(Error::depuis_h3)?;
        requete.reste = Some((kind, entete.length()));
        self.suivis[rang].tampon.drain(..entete.header_len());
        Ok(true)
    }

    /// Verse ce qui reste de la trame en cours dans son bac.
    fn verser(&mut self, rang: usize, kind: FrameKind, manque: u64) -> Result<bool, Error> {
        let dispo = self.suivis[rang].tampon.len();
        let combien = usize::try_from(manque).unwrap_or(usize::MAX).min(dispo);
        if combien == 0 {
            // La trame est finie, ou il faut davantage d'octets.
            let requete = self.suivis[rang]
                .requete
                .as_mut()
                .expect("un flux de requête porte son état");
            if manque == 0 {
                requete.reste = None;
                return Ok(true);
            }
            return Ok(false);
        }
        let pris: Vec<u8> = self.suivis[rang].tampon.drain(..combien).collect();
        let requete = self.suivis[rang]
            .requete
            .as_mut()
            .expect("un flux de requête porte son état");
        // §9 : ce qu'on ne connaît pas se jette, mais se consomme.
        let (bac, borne) = match kind {
            FrameKind::Headers => (Some(&mut requete.champs), CHAMPS_OCTETS_MAX),
            FrameKind::Data => (Some(&mut requete.corps), CORPS_OCTETS_MAX),
            _ => (None, 0),
        };
        if let Some(bac) = bac {
            // §4.2.2 et §8.1 : au-delà de ce qu'on a ANNONCÉ accepter, le pair
            // engendre une charge excessive — et il le sait, puisqu'on le lui a
            // dit dans nos réglages.
            if bac.len().saturating_add(pris.len()) > borne {
                return Err(Error::excessive());
            }
            bac.extend_from_slice(&pris);
        }
        requete.reste = Some((
            kind,
            manque.saturating_sub(u64::try_from(combien).unwrap_or(0)),
        ));
        Ok(true)
    }

    /// Lit une instruction du flux d'encodeur du pair (§4.3 de RFC 9204).
    ///
    /// # ON REFUSE SUR LE TYPE, AVANT DE LIRE LA CHARGE
    ///
    /// §3.2.3 : « When the maximum table capacity is zero, the encoder MUST NOT
    /// insert entries into the dynamic table and MUST NOT send any encoder
    /// instructions on the encoder stream. » Nous annonçons zéro, donc aucune
    /// insertion n'est licite — **quelle que soit sa charge**.
    ///
    /// La lire pour la jeter serait pourtant coûteux : §4.3.3 ne borne ni le nom
    /// ni la valeur d'une insertion, et le pair choisirait ainsi combien nous
    /// retenons (C3). Le premier octet dit le type ; il suffit à refuser.
    ///
    /// **CE CHEMIN NE SAIT LIRE QUE LA TABLE NULLE.** Le jour où l'on annoncerait
    /// une vraie table, il faudrait ici un tampon pour les littéraux de §4.3.3 et
    /// une table à nourrir — c'est-à-dire un autre code, et non une constante
    /// changée.
    fn une_instruction_d_encodeur(&mut self, rang: usize) -> Result<bool, Error> {
        let annoncee = self.nos_reglages.qpack_max_table_capacity;
        let Some(&premier) = self.suivis[rang].tampon.first() else {
            return Ok(false);
        };
        qpack::check_encoder_instruction_kind(qpack::encoder_instruction_kind(premier), annoncee)
            .map_err(Error::depuis_h3)?;

        // **IL NE RESTE QUE `Set Dynamic Table Capacity`** (§4.3.1), qui ne porte
        // aucune chaîne : le contrôle ci-dessus a refusé les trois autres types.
        let mut place = [0_u8; TAMPON_OCTETS_MAX];
        let (instruction, lus) =
            match qpack::read_encoder_instruction(&self.suivis[rang].tampon, &mut place) {
                Ok(lue) => (lue.instruction, lue.read),
                // Un entier à cheval n'est pas une faute : le pair écrira la suite.
                Err(_) if self.suivis[rang].tampon.len() < qpack::INSTRUCTION_OCTETS_MAX => {
                    return Ok(false);
                }
                // Au-delà de cette borne, il n'en manque plus : cet entier-là ne se
                // reconstruira jamais. Attendre encore figerait le flux pour toujours.
                Err(_) => {
                    return Err(Error::depuis_h3(ams_proto_h3::Error::new(
                        ams_proto_h3::Reason::BadEncoderInstruction,
                    )));
                }
            };
        qpack::check_encoder_instruction(instruction, annoncee).map_err(Error::depuis_h3)?;
        self.suivis[rang].tampon.drain(..lus);
        // Une capacité nulle redite ne change rien, et coûte un traitement.
        self.h3.on_qpack_instruction().map_err(Error::depuis_h3)?;
        Ok(true)
    }

    /// Lit une instruction du flux de décodeur du pair (§4.4 de RFC 9204).
    ///
    /// # CE FLUX ACCUSE RÉCEPTION DE CE QUE NOUS N'AVONS PAS ENVOYÉ
    ///
    /// Notre encodeur n'insère rien : aucune section que nous émettons ne déclare
    /// un compte d'insertions non nul. §4.4.1 et §4.4.3 font alors de tout accusé
    /// et de tout incrément une faute de connexion — non par formalisme, mais
    /// parce qu'un pair qui accuse ce qui n'existe pas ne tient pas la même table
    /// que nous, et que plus rien ne se lira ensuite.
    ///
    /// Reste §4.4.2, l'annulation d'un flux, que rien ne rend fautive.
    fn une_instruction_de_decodeur(&mut self, rang: usize) -> Result<bool, Error> {
        let (instruction, lus) = match qpack::read_decoder_instruction(&self.suivis[rang].tampon) {
            Ok(lue) => lue,
            // **LA SEULE FAUTE QUE §4.4 SAIT RENDRE EST `Truncated`** : ses trois
            // instructions sont un motif de bits et un entier, et il n'y a rien
            // d'autre à mal former. Reste à savoir s'il en manque, ou si l'entier
            // ne se reconstruira jamais — et c'est la borne qui tranche.
            Err(_) if self.suivis[rang].tampon.len() < qpack::INSTRUCTION_OCTETS_MAX => {
                return Ok(false);
            }
            Err(_) => {
                return Err(Error::depuis_h3(ams_proto_h3::Error::new(
                    ams_proto_h3::Reason::BadDecoderInstruction,
                )));
            }
        };
        qpack::check_decoder_instruction(instruction, INSERTIONS_EMISES)
            .map_err(Error::depuis_h3)?;
        self.suivis[rang].tampon.drain(..lus);
        // §4.4.2 : la seule qui passe ne demande rien. Elle coûte pourtant un
        // traitement, et §4.2 fait de ce flux un flux qui ne doit jamais bloquer
        // — donc que rien ne borne, sinon ce compteur.
        self.h3.on_qpack_instruction().map_err(Error::depuis_h3)?;
        Ok(true)
    }

    /// Lit le type d'un flux unidirectionnel du pair (§6.2).
    fn une_tete(&mut self, rang: usize) -> Result<bool, Error> {
        let ams_proto_h3::StreamHead::Ready { kind, read } =
            ams_proto_h3::read_stream_head(&self.suivis[rang].tampon)
        else {
            return Ok(false);
        };
        self.suivis[rang].tampon.drain(..read);

        match ams_proto_h3::accept_stream(kind) {
            Ok(()) => {
                // §6.2.1 et §4.2 de RFC 9204 : un second flux critique du même
                // type est une faute, et c'est `on_peer_stream` qui le sait.
                self.h3.on_peer_stream(kind).map_err(Error::depuis_h3)?;
                self.suivis[rang].role = match kind {
                    StreamKind::Control => Role::Controle,
                    StreamKind::QpackEncoder => Role::QpackEncodeur,
                    // **`accept_stream` N'A LAISSÉ PASSER QUE LES TROIS FLUX
                    // CRITIQUES**, et les deux premiers viennent d'être nommés.
                    _ => Role::QpackDecodeur,
                };
            }
            // §6.2.2 : un flux de poussée vient d'un serveur. D'un client, c'est
            // qu'il se prend pour nous, et la suite n'aurait pas le sens qu'on
            // lui prêterait.
            Err(faute) if matches!(kind, StreamKind::Push) => {
                return Err(Error::depuis_h3(faute));
            }
            // §6.2 : « The recipient MUST NOT consider unknown stream types to
            // be a connection error of any kind. » On abandonne CE flux, et rien
            // d'autre.
            Err(_) => self.suivis[rang].role = Role::Abandonne,
        }
        Ok(true)
    }

    /// Lit une trame du flux de contrôle du pair (§6.2.1, §7.2).
    fn une_trame_de_controle(&mut self, rang: usize) -> Result<bool, Error> {
        let entete = match FrameHeader::parse(&self.suivis[rang].tampon) {
            Ok(entete) => entete,
            // Un en-tête coupé en deux n'est pas une faute : le pair réémettra
            // le reste, et c'est la boucle qui rappellera.
            Err(faute) if matches!(faute.reason(), ams_proto_h3::Reason::Truncated) => {
                return Ok(false);
            }
            Err(faute) => return Err(Error::depuis_h3(faute)),
        };
        let kind = entete.kind();
        let longueur = entete.length();

        // Les trames dont on doit LIRE la charge pour décider. Toutes sont
        // courtes : des réglages, ou un seul entier de §16.
        let a_lire = matches!(
            kind,
            FrameKind::Settings | FrameKind::GoAway | FrameKind::MaxPushId | FrameKind::CancelPush
        );
        if !a_lire {
            // §7.2 valide la place de la trame AVANT qu'on saute quoi que ce
            // soit : un `DATA` sur le flux de contrôle est une faute, et sauter
            // sa charge d'abord la laisserait passer.
            self.h3
                .on_control_frame(kind, None, 0)
                .map_err(Error::depuis_h3)?;
            self.suivis[rang].tampon.drain(..entete.header_len());
            self.suivis[rang].a_sauter = longueur;
            return Ok(true);
        }

        // **NOTRE BORNE, ET ELLE EST LA SIENNE À RESPECTER** : ces trames-là ont
        // une taille que §7.2 rend petite. Une qui la dépasse est mal formée, et
        // l'accueillir donnerait au pair le moyen de choisir ce qu'on retient.
        let combien = usize::try_from(longueur).unwrap_or(usize::MAX);
        if combien > CHARGE_OCTETS_MAX {
            return Err(Error::malformee());
        }
        let total = entete.header_len().saturating_add(combien);
        if self.suivis[rang].tampon.len() < total {
            return Ok(false);
        }

        let charge = self.suivis[rang]
            .tampon
            .get(entete.header_len()..total)
            .unwrap_or_default();
        let (reglages, identifiant) = match kind {
            FrameKind::Settings => (Some(Settings::read(charge).map_err(Error::depuis_h3)?), 0),
            // §7.2.6 et §7.2.7 : un seul entier de §16, et rien d'autre.
            _ => (
                None,
                varints::decode(charge)
                    .map(|(valeur, _)| valeur)
                    .map_err(|_| Error::malformee())?,
            ),
        };
        self.h3
            .on_control_frame(kind, reglages, identifiant)
            .map_err(Error::depuis_h3)?;
        self.suivis[rang].tampon.drain(..total);
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
