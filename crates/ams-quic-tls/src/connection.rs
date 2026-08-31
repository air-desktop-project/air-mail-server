// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Une connexion QUIC, **sans entrée-sortie** (C1).
//!
//! # CE MODULE EST L'ASSEMBLAGE, ET RIEN QUE L'ASSEMBLAGE
//!
//! Toutes les pièces existaient : `ams-proto-quic` lit et écrit les trames,
//! `ams-quic-crypto` protège les paquets, `ams-quic` en fait la disposition,
//! trie les datagrammes et détecte les pertes, [`crate::Server`] conduit la
//! poignée de main. **Aucune ne savait ce qu'il fallait faire ensuite.**
//!
//! Ce qui se décide ici, et nulle part ailleurs :
//!
//! 1. **quelles trames vont dans quel paquet**, et à quel niveau de chiffrement ;
//! 2. **combien on a le droit d'émettre** — §8.1 borne à trois fois ce qu'on a
//!    reçu tant que l'adresse n'est pas validée, et §7 de RFC 9002 à la fenêtre
//!    de congestion ;
//! 3. **quand se réveiller** : le plus proche de quatre délais — inactivité,
//!    acquittement dû, perte à constater, sondage.
//!
//! # LA PORTÉE EST LA POIGNÉE DE MAIN, ET C'EST ÉCRIT
//!
//! `CRYPTO`, `ACK`, `PADDING`, `PING`, `HANDSHAKE_DONE` et `CONNECTION_CLOSE`.
//! **Pas de flux** : une connexion établie ne sait pas encore porter de requête,
//! et HTTP/3 viendra ensuite. Une trame qu'on ne sait pas encore traiter est
//! ignorée plutôt que refusée — la refuser fermerait des connexions qu'on saura
//! servir demain, et §12.4 ne condamne que ce qu'on ne sait pas LIRE.
//!
//! # LES DATAGRAMMES SE DONNENT EN ÉCRITURE, ET C'EST VOULU
//!
//! Le déchiffrement se fait en place (§5.3 de RFC 9001). Recopier chaque
//! datagramme pour préserver l'original coûterait une allocation par paquet
//! reçu, sur un port ouvert au monde entier.

use core::cmp::min;
use std::sync::Arc;

use ams_proto_quic::{
    Congestion, ConnectionId, DEFAULT_ACK_DELAY_EXPONENT, Directional, Frame, Initiator, LongKind,
    MAX_DATAGRAM_SIZE, Received, Rtt, Sender, Space, StreamId, TransportError, TransportParameters,
    decode_ack_delay,
};
use ams_quic::State;
use ams_quic::{
    FLUX_MAX, FLUX_PAR_FAMILLE_MAX, INITIAL_DATAGRAM_OCTETS_MIN, Incoming, Level, PacketKind, Plan,
    Sent, Streams, open_packet, payload_capacity, seal_packet,
};
use ams_quic_crypto::{Keys, Role, Secret};
use rustls::ServerConfig;
use rustls::quic::KeyChange;

use crate::{Clefs, Error, Reason, Server};

/// Combien d'espaces de numérotation une connexion tient (§12.3).
const ESPACES: usize = 3;

/// Ce qu'on annonce par flux, en octets (§18.2).
///
/// # POURQUOI SEIZE KIBIOCTETS, ET NON TRENTE-DEUX
///
/// C'est la fenêtre que l'appelant doit tenir POUR CHAQUE FLUX VIVANT, et elle
/// domine tout le reste du coût d'un flux — l'état, lui, tient en trois
/// kibioctets. Avec les trente-deux flux qu'une connexion tient, seize
/// kibioctets font un demi-mébioctet par connexion : c'est ce qu'un pair peut
/// nous faire retenir sans rien lire, et il faut pouvoir le multiplier par le
/// nombre de connexions qu'on accepte.
pub const FLUX_OCTETS: u64 = 16 * 1_024;

/// Le même nombre, dans le type que compte un tampon. L'assertion échoue à la
/// compilation s'ils divergent.
const FLUX_FENETRE: usize = 16 * 1_024;

const _: () = assert!(FLUX_OCTETS == FLUX_FENETRE as u64);

/// Et ce qu'on annonce pour toute la connexion.
///
/// Quatre fois la fenêtre d'un flux, et non leur somme : §4.1 est justement là
/// pour que le total ne soit pas le produit. Un pair qui ouvre trente-deux flux
/// n'obtient pas trente-deux fenêtres, mais quatre.
pub const CONNEXION_OCTETS: u64 = 4 * FLUX_OCTETS;

/// Ce qu'on garde en attente d'émission sur un flux.
///
/// **C'EST NOTRE PROPRE BORNE** (C3) : l'application écrit, et ces octets
/// attendent qu'un paquet les emporte. Sans borne, une application pressée
/// remplirait la mémoire du serveur plus vite que le réseau ne la vide.
pub const SORTIE_OCTETS_MAX: usize = 64 * 1_024;

/// L'en-tête d'une trame `STREAM` au pire (§19.8) : le type, puis trois entiers
/// de §16 à huit octets — numéro, décalage, longueur.
const ENTETE_STREAM_MAX: usize = 25;

/// Le délai d'inactivité qu'on annonce, en microsecondes.
///
/// **TRENTE SECONDES, ET C'EST UNE DÉFENSE AUTANT QU'UN RÉGLAGE** (C8) : une
/// connexion qu'on garde ouverte est de la mémoire qu'on prête. §10.1 fait
/// prendre le plus petit des deux délais annoncés, donc un pair ne peut que
/// raccourcir celui-ci, jamais l'allonger.
pub const INACTIVITE_US: u64 = 30_000_000;

/// Le délai maximal qu'on s'accorde avant d'acquitter (§13.2.1), en
/// millisecondes.
pub const ACQUITTEMENT_MAX_MS: u64 = 25;

/// Le même, en microsecondes.
const ACQUITTEMENT_MAX_US: u64 = ACQUITTEMENT_MAX_MS.saturating_mul(1_000);

/// Ce qu'une trame `CONNECTION_CLOSE` de transport occupe au minimum (§19.19).
///
/// Un type, un code, le type de trame fautive et une longueur de raison nulle —
/// quatre entiers de §16, un octet chacun quand ils sont petits.
const FERMETURE_OCTETS: usize = 4;

/// Ce qu'une trame `CRYPTO` occupe au pire avant ses octets (§19.6).
///
/// Un type sur un octet, puis un décalage et une longueur — deux entiers de §16,
/// huit octets chacun au pire.
const ENTETE_CRYPTO_MAX: usize = 17;

/// Ce qu'on retient d'un paquet émis, pour savoir quoi renvoyer s'il se perd.
///
/// # ON NE RETIENT QUE LE FLUX `CRYPTO`
///
/// C'est le seul contenu retransmissible de cette portée : un `ACK` perdu ne se
/// renvoie pas — il se refait, plus à jour (§13.2.1) —, et un `PADDING` n'a rien
/// à dire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Enveloppe {
    /// Le numéro du paquet.
    numero: u64,
    /// Ce qu'il portait du flux `CRYPTO` : décalage et longueur.
    crypto: Option<(u64, u64)>,
    /// Et ce qu'il emportait d'un flux : le numéro, le décalage, la longueur.
    ///
    /// **UN PAQUET N'EN PORTE QU'UN SEUL ICI.** En porter plusieurs demanderait
    /// une liste par paquet, pour économiser des en-têtes sur un échange que le
    /// contrôle de congestion borne déjà. Le jour où cela comptera, c'est ce
    /// champ qui deviendra une liste, et rien d'autre.
    flux: Option<(StreamId, u64, u64)>,
}

/// Ce qu'on a à émettre en `CRYPTO`, pour un niveau.
///
/// # LA RETRANSMISSION SE FAIT EN RECULANT, ET C'EST SUFFISANT
///
/// Quand un paquet se perd, on ramène le curseur d'émission au décalage qu'il
/// portait : tout ce qui suit repartira. **C'est parfois plus que nécessaire** —
/// des octets déjà reçus repartent —, et c'est sans conséquence : le pair les
/// reconnaît comme des doublons (§7.5 de RFC 9000), et une poignée de main tient
/// dans quelques kibioctets.
///
/// Tenir la liste exacte des trous demanderait un ensemble d'intervalles de
/// plus, pour économiser des octets sur un échange qui n'a lieu qu'une fois par
/// connexion.
#[derive(Debug, Default)]
struct Sortie {
    /// Tout ce que TLS a produit à ce niveau, dans l'ordre.
    octets: Vec<u8>,
    /// Jusqu'où l'on a émis.
    emis: u64,
    /// Jusqu'où le pair a acquitté, de façon contiguë.
    acquitte: u64,
}

impl Sortie {
    /// Ce qui reste à émettre, et à quel décalage il commence.
    fn en_attente(&self) -> (u64, &[u8]) {
        let depuis = usize::try_from(self.emis).unwrap_or(usize::MAX);
        (self.emis, self.octets.get(depuis..).unwrap_or_default())
    }

    /// Ces octets viennent de partir.
    fn on_sent(&mut self, longueur: u64) {
        self.emis = self.emis.saturating_add(longueur);
    }

    /// Le pair a acquitté ce morceau.
    ///
    /// **SEUL LE PRÉFIXE CONTIGU AVANCE.** Un acquittement qui arrive dans le
    /// désordre ne crédite rien : c'est plus prudent que juste, et la seule
    /// conséquence est de renvoyer un peu trop si une perte suit.
    fn on_acked(&mut self, decalage: u64, longueur: u64) {
        if decalage <= self.acquitte {
            self.acquitte = self.acquitte.max(decalage.saturating_add(longueur));
        }
    }

    /// Ce morceau s'est perdu : on repart de là.
    fn on_lost(&mut self, decalage: u64) {
        self.emis = self.emis.min(decalage);
    }
}

/// Cette trame a-t-elle le droit d'arriver à ce niveau (§12.4) ?
///
/// # LE TABLEAU DE §12.4, RÉDUIT À CE QU'ON ACCEPTE
///
/// Cinq trames vont partout : `PADDING`, `PING`, `ACK`, `CRYPTO` et
/// `CONNECTION_CLOSE`. **Tout le reste demande le niveau applicatif** — et
/// puisqu'on refuse le `0-RTT` (§8.3 de RFC 9001), « applicatif » veut dire
/// `1-RTT` et rien d'autre.
///
/// `HANDSHAKE_DONE` est à part : §19.20 en fait une faute pour un SERVEUR qui le
/// reçoit, quel que soit le niveau. C'est le client qui l'apprend, jamais lui.
const fn permise(trame: &Frame<'_>, niveau: Level) -> bool {
    match trame {
        Frame::Padding { .. }
        | Frame::Ping
        | Frame::Ack(_)
        | Frame::Crypto { .. }
        | Frame::ConnectionClose { .. } => true,
        // §19.20 : « A server MUST treat receipt of a HANDSHAKE_DONE frame as a
        // connection error of type PROTOCOL_VIOLATION. »
        Frame::HandshakeDone => false,
        _ => matches!(niveau, Level::OneRtt),
    }
}

/// Une connexion QUIC vue du serveur.
pub struct Connection {
    /// L'état de connexion : amplification, oisiveté, fermeture.
    etat: ams_quic::Connection,
    /// La poignée de main TLS, et ses trois flux `CRYPTO` en réception.
    poignee: Server,
    /// Ce qu'on a à émettre en `CRYPTO`, par espace.
    sortie: [Sortie; ESPACES],
    /// Ce qui est parti et attend un acquittement, par espace.
    emis: [Sent; ESPACES],
    /// Ce qui est arrivé, par espace.
    recus: [Received; ESPACES],
    /// Ce qu'on a retenu de chaque paquet émis, par espace.
    enveloppes: [Vec<Enveloppe>; ESPACES],
    /// Les clés de la poignée de main, par espace et par sens.
    ///
    /// **CELLES DE L'ESPACE `Initial` SONT AILLEURS** : elles ne viennent pas de
    /// `rustls`, et leur donner la même place laisserait croire qu'elles ont la
    /// même origine.
    chiffrement: [Option<Clefs>; ESPACES],
    dechiffrement: [Option<Clefs>; ESPACES],
    /// Les clés `Initial`, dérivées de l'identifiant que le client a choisi.
    initiales_emission: Option<Keys>,
    initiales_reception: Option<Keys>,
    /// Le trajet et la congestion.
    rtt: Rtt,
    congestion: Congestion,
    /// L'identifiant qu'on a choisi, et celui du pair.
    local: ConnectionId,
    distant: ConnectionId,
    /// Le prochain numéro de paquet, par espace.
    prochain: [u64; ESPACES],
    /// Combien de sondages ont été tentés sans réponse (§6.2.1 de RFC 9002).
    sondages: u32,
    /// Faut-il sonder au prochain envoi ?
    sonder: bool,
    /// Faut-il dire au client que la poignée de main est confirmée (§19.20) ?
    a_confirmer: bool,
    /// A-t-on déjà pris acte de la fin de la poignée de main ?
    ///
    /// # POURQUOI UN DRAPEAU À SOI, ET NON UN AUTRE DÉTOURNÉ
    ///
    /// La première version se servait de « l'adresse est-elle validée ? » comme
    /// verrou. Or §8.1 la valide **dès le premier paquet `Handshake` reçu** —
    /// c'est-à-dire AVANT que la poignée de main soit terminée. Le verrou était
    /// donc déjà fermé quand on en avait besoin, et rien de ce qu'il gardait ne
    /// se faisait : ni la vérification de l'ALPN, ni la lecture des paramètres
    /// du pair, ni le `HANDSHAKE_DONE`.
    ///
    /// **Un drapeau emprunté à une autre question finit toujours par répondre à
    /// celle-là.**
    confirmee: bool,
    /// Le code de fermeture à annoncer, s'il y en a un (§10.2).
    fermeture: Option<u64>,
    /// Faut-il le (re)dire maintenant ?
    ///
    /// # LE PREMIER PART TOUT DE SUITE, LES SUIVANTS SUR ARRIVÉE
    ///
    /// §10.2 : « An endpoint sends a CONNECTION_CLOSE frame […] to terminate the
    /// connection immediately. » §10.2.1 : et ensuite, « an endpoint SHOULD limit
    /// the rate at which it generates packets in the closing state ».
    ///
    /// Les deux règles ne se confondent pas : la première ne compte rien, la
    /// seconde compte les paquets REÇUS. Piloter la première avec le compteur de
    /// la seconde ferait qu'une fermeture ne partirait jamais si le pair se tait.
    a_dire: bool,
    /// Les paramètres que le pair a annoncés (§8.2 de RFC 9001).
    siens: Option<TransportParameters>,
    /// Ce que nous avons annoncé — gardé pour bâtir les flux quand les siens
    /// arrivent (§4.1, §4.6).
    notres: TransportParameters,
    /// Les flux, une fois la poignée de main aboutie.
    ///
    /// **PAS AVANT** : §4.1 et §4.6 se règlent sur des paramètres qu'on n'a le
    /// droit de croire qu'une fois TLS les ayant authentifiés (§7.4). Les bâtir
    /// plus tôt les réglerait sur des limites inventées.
    flux: Option<Streams>,
    /// Les fenêtres de réassemblage, une par rang de table.
    ///
    /// Elles ne s'allouent qu'au premier octet reçu sur un flux : un pair qui
    /// ouvre trente-deux flux sans rien y écrire ne doit pas nous faire réserver
    /// un demi-mébioctet.
    fenetres: Vec<Vec<u8>>,
    /// Ce qui attend d'être émis sur chaque flux, une par rang de table.
    sorties: Vec<Sortie>,
    /// Le `FIN` que l'application a demandé et qu'on n'a pas encore émis.
    fins: Vec<bool>,
    /// Le prochain rang par lequel commencer le tour d'émission.
    ///
    /// **SANS LUI, LE PREMIER FLUX AFFAMERAIT TOUS LES AUTRES** : à chaque
    /// paquet on repartirait du rang zéro, et un flux qui a toujours de quoi
    /// dire ne laisserait jamais la place.
    tour: usize,
    /// L'exposant qui décode le délai d'un `ACK` (§18.2).
    ///
    /// # POURQUOI UNE VALEUR, ET NON UNE QUESTION POSÉE À CHAQUE FOIS
    ///
    /// Il vaut le défaut de §18.2 jusqu'à ce que les paramètres du pair soient
    /// AUTHENTIFIÉS, puis le sien. Le relire dans une option à chaque `ACK`
    /// ferait une branche de plus, et cette branche-là ne dit rien que ce champ
    /// ne dise déjà : **croire un exposant avant de l'avoir vérifié fausserait
    /// la mesure du trajet**, et c'est le moment du changement qui l'empêche.
    exposant: u32,
}

impl Connection {
    /// Accueille un client neuf.
    ///
    /// `incoming` est ce que [`Incoming::read`] a lu du premier datagramme,
    /// `local` l'identifiant qu'on veut que le pair emploie désormais, et
    /// `distant` celui qu'il a annoncé comme source.
    ///
    /// # LES CLÉS `Initial` VIENNENT DE L'IDENTIFIANT QUE LE CLIENT A CHOISI
    ///
    /// §5.2 de RFC 9001 : elles se dérivent de l'identifiant de destination du
    /// premier paquet, en clair. **Tout le monde peut les fabriquer** — c'est ce
    /// qui rend l'espace `Initial` non authentifié, et pourquoi §14.1 y impose un
    /// plancher de taille.
    ///
    /// # Errors
    ///
    /// [`Reason::NoQuicSuite`] si le fournisseur ne sait pas chiffrer un paquet
    /// QUIC ; [`Reason::TlsSansAlerte`] si les clés ou les paramètres ne se
    /// fabriquent pas.
    pub fn accept(
        config: Arc<ServerConfig>,
        incoming: &Incoming,
        local: ConnectionId,
        distant: ConnectionId,
        maintenant: u64,
    ) -> Result<Self, Error> {
        let origine = incoming.destination();

        let mut annonce = TransportParameters::DEFAULT;
        annonce.max_idle_timeout_ms = INACTIVITE_US.saturating_div(1_000);
        annonce.max_ack_delay_ms = ACQUITTEMENT_MAX_MS;
        annonce.initial_source_connection_id = Some(local);
        // §4.1 et §4.6 : ce qu'on ouvre au pair. **CE QU'ON ANNONCE EST CE QU'ON
        // TIENT** — les plafonds de flux sont ceux de la table, et les fenêtres
        // celles qu'on saura vraiment réserver.
        annonce.initial_max_data = CONNEXION_OCTETS;
        annonce.initial_max_stream_data_bidi_local = FLUX_OCTETS;
        annonce.initial_max_stream_data_bidi_remote = FLUX_OCTETS;
        annonce.initial_max_stream_data_uni = FLUX_OCTETS;
        annonce.initial_max_streams_bidi = FLUX_PAR_FAMILLE_MAX;
        annonce.initial_max_streams_uni = FLUX_PAR_FAMILLE_MAX;
        // §7.3 : le serveur annonce l'identifiant que le client avait choisi.
        // **C'EST CE QUI PROUVE QUE LA POIGNÉE DE MAIN N'A PAS ÉTÉ DÉTOURNÉE** :
        // un intermédiaire qui aurait réécrit le premier paquet ne pourrait pas
        // le faire coïncider, puisque cette valeur-là est authentifiée par TLS.
        annonce.original_destination_connection_id = Some(origine);
        let mut ecrits = vec![0_u8; 256];
        // **DEUX CENT CINQUANTE-SIX OCTETS POUR UNE QUARANTAINE ÉCRITS**, et
        // aucune valeur hors de l'espace de §16 : l'écriture ne peut pas
        // échouer. Un `?` ouvrirait ici une branche qu'aucun essai ne pourrait
        // atteindre.
        let taille = annonce
            .write(Sender::Server, &mut ecrits)
            .expect("nos propres paramètres tiennent dans ce tampon");
        ecrits.truncate(taille);

        // **UN IDENTIFIANT DE CONNEXION FAIT AU PLUS VINGT OCTETS** (§17.2), et
        // `ConnectionId` l'a déjà refusé au-delà : la dérivation de §5.2 ne peut
        // pas échouer sur lui.
        let clefs = |role| {
            Secret::initial(origine.as_bytes(), role)
                .and_then(|secret| secret.keys())
                .expect("§17.2 borne l'identifiant, et §5.2 dérive de lui")
        };
        Ok(Self {
            etat: ams_quic::Connection::new(Role::Server, INACTIVITE_US, 0, maintenant),
            poignee: Server::new(config, ecrits)?,
            sortie: Default::default(),
            emis: [Sent::new(); ESPACES],
            recus: [Received::new(); ESPACES],
            enveloppes: Default::default(),
            chiffrement: [None, None, None],
            dechiffrement: [None, None, None],
            initiales_emission: Some(clefs(Role::Server)),
            initiales_reception: Some(clefs(Role::Client)),
            rtt: Rtt::new(),
            congestion: Congestion::new(),
            local,
            distant,
            prochain: [0; ESPACES],
            sondages: 0,
            sonder: false,
            a_confirmer: false,
            confirmee: false,
            fermeture: None,
            a_dire: false,
            siens: None,
            notres: annonce,
            flux: None,
            fenetres: Vec::new(),
            sorties: Vec::new(),
            fins: Vec::new(),
            tour: 0,
            exposant: DEFAULT_ACK_DELAY_EXPONENT,
        })
    }

    /// L'identifiant qu'on a choisi — **c'est LUI que le démultiplexeur range**.
    #[must_use]
    pub const fn local_id(&self) -> ConnectionId {
        self.local
    }

    /// La poignée de main est-elle terminée (§4.1.1 de RFC 9001) ?
    #[must_use]
    pub const fn is_established(&self) -> bool {
        self.poignee.is_complete()
    }

    /// La connexion peut-elle être oubliée ?
    ///
    /// **`Closing` N'EN EST PAS**, et c'est la distinction qui compte : on y
    /// répond encore, de moins en moins souvent (§10.2.1). Confondre les deux
    /// ferait disparaître la connexion avant que le pair ait su qu'elle ferme.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        matches!(self.etat.state(), State::Closed)
    }

    /// N'a-t-on plus rien à émettre, jamais ?
    ///
    /// §10.2.2 : « An endpoint in the draining state MUST NOT send any
    /// packets. » En `Closing`, au contraire, il reste la fermeture à dire —
    /// c'est même la seule raison d'y être.
    const fn muet(&self) -> bool {
        matches!(self.etat.state(), State::Draining | State::Closed)
    }

    /// Le protocole applicatif négocié, une fois la poignée de main terminée.
    #[must_use]
    pub fn alpn(&self) -> Option<&[u8]> {
        self.poignee.alpn()
    }

    /// Les paramètres de transport du pair, une fois authentifiés (§8.2).
    #[must_use]
    pub const fn peer_parameters(&self) -> Option<&TransportParameters> {
        self.siens.as_ref()
    }

    /// Ferme la connexion avec ce code de transport (§10.2).
    pub fn close(&mut self, code: TransportError, maintenant: u64) {
        self.close_with(code.value(), maintenant);
    }

    /// La même chose, avec un code déjà calculé.
    ///
    /// # POURQUOI DEUX PORTES POUR LA MÊME CHOSE
    ///
    /// [`Error::close_code`](crate::Error::close_code) rend un `u64` qui n'est
    /// pas toujours un code de transport : §4.8 de RFC 9001 loge les alertes TLS
    /// dans une plage à part. Les faire passer par [`TransportError`] demanderait
    /// de les y traduire, **et il n'y a pas de traduction** — c'est deux espaces
    /// de codes qui se recouvrent, et §20 les sépare exprès.
    pub fn close_with(&mut self, code: u64, maintenant: u64) {
        self.fermeture = Some(code);
        self.a_dire = true;
        let pto = self.rtt.pto(ACQUITTEMENT_MAX_US, self.sondages);
        self.etat.close(pto, maintenant);
    }

    /// Un datagramme est arrivé pour cette connexion.
    ///
    /// # CE QU'ON NE SAIT PAS OUVRIR ARRÊTE LE PARCOURS, ET NE CONDAMNE PAS
    ///
    /// §12.2 : plusieurs paquets tiennent dans un datagramme, et chacun porte sa
    /// longueur — sauf le dernier, à en-tête court. Un paquet qu'on ne sait pas
    /// ouvrir fait donc perdre la frontière du suivant : on s'arrête là, sans
    /// fermer. §5.2 le demande — « endpoints MUST discard packets that cannot be
    /// authenticated » —, et fermer offrirait la connexion à qui sait envoyer un
    /// datagramme.
    ///
    /// # Errors
    ///
    /// [`Reason::Quic`] pour ce que §4.1.3 de RFC 9001 refuse entre les niveaux,
    /// [`Reason::Tls`] si la poignée de main refuse ce qu'elle lit.
    pub fn on_datagram(&mut self, datagramme: &mut [u8], maintenant: u64) -> Result<(), Error> {
        // §8.1 : « servers MUST count all of the payload bytes received in
        // datagrams that are uniquely attributed to a single connection. This
        // includes […] datagrams that contain packets that are all discarded. »
        // **ON COMPTE AVANT DE LIRE** : sinon un datagramme illisible
        // n'élargirait pas le budget, et la connexion se figerait.
        self.etat
            .on_datagram_received(u64::try_from(datagramme.len()).unwrap_or(u64::MAX));

        // §10.2.1 : en fermeture, on redit notre `CONNECTION_CLOSE` de moins en
        // moins souvent — au premier paquet reçu, au deuxième, au quatrième. Le
        // faire à chaque paquet amplifierait au moment précis où l'on n'a plus
        // rien à dire.
        if self.fermeture.is_some() && self.etat.should_answer() {
            self.a_dire = true;
        }

        let mut rang = 0_usize;
        while rang < datagramme.len() {
            let reste = datagramme.get_mut(rang..).unwrap_or_default();
            let Some(avance) = self.un_paquet(reste, maintenant)? else {
                return Ok(());
            };
            // **PAS DE GARDE SUR UN ZÉRO** : un paquet ouvert occupe au moins
            // son en-tête, et §17 n'en connaît pas de vide. Une garde ici
            // rendrait une branche que rien ne peut emprunter.
            rang = rang.saturating_add(avance);
        }
        // Ce qui s'est terminé pendant ce datagramme rend sa place tout de
        // suite : la garder jusqu'au prochain refuserait une ouverture que le
        // pair a le droit de faire.
        self.recolter_les_flux();
        Ok(())
    }

    /// Ce qu'il y a à émettre, s'il y a quelque chose.
    ///
    /// Rend le nombre d'octets écrits dans `out` — zéro quand il n'y a rien à
    /// dire. **L'APPELANT BOUCLE JUSQU'À ZÉRO** : un datagramme ne porte pas
    /// toujours tout ce qui attend.
    ///
    /// # Errors
    ///
    /// [`Reason::Tls`] si la poignée de main refuse d'avancer.
    pub fn poll_transmit(&mut self, out: &mut [u8], maintenant: u64) -> Result<usize, Error> {
        if self.muet() {
            return Ok(0);
        }
        // Ce que l'application vient de finir de lire rend sa place avant qu'on
        // compose : c'est ce qui met le `MAX_STREAMS` dans CE paquet-ci plutôt
        // que dans le suivant.
        self.recolter_les_flux();
        self.avancer_la_poignee(maintenant)?;

        // §8.1 : trois fois ce qu'on a reçu, tant que l'adresse n'est pas
        // validée. §7 de RFC 9002 : et jamais plus que la fenêtre de congestion
        // — sauf pour un sondage, que §6.2.4 autorise à la dépasser.
        let fenetre = match self.sonder {
            true => MAX_DATAGRAM_SIZE,
            false => self.congestion.available(),
        };
        let budget = min(self.etat.send_budget(), fenetre);
        let place = min(
            usize::try_from(budget).unwrap_or(usize::MAX),
            min(
                out.len(),
                usize::try_from(MAX_DATAGRAM_SIZE).unwrap_or(1_200),
            ),
        );
        // **PAS DE GARDE SUR UN BUDGET NUL** : une tranche vide fait rendre
        // `None` à chaque espace, et l'on retombe sur le « rien à dire » plus
        // bas. Une garde ici serait une seconde façon de dire la même chose,
        // et l'une des deux ne serait jamais empruntée.
        let mut ecrit = 0_usize;
        let mut porte_un_initial = false;
        let mut sollicite = false;
        // §12.2 : « Coalescing packets in order of increasing encryption levels
        // […] makes it more likely that the receiver will be able to process all
        // the packets in a single pass. »
        for espace in [Space::Initial, Space::Handshake, Space::Application] {
            let reste = out.get_mut(ecrit..place).unwrap_or_default();
            let Some((avance, elicite)) = self.un_envoi(espace, reste, maintenant) else {
                continue;
            };
            porte_un_initial |= espace == Space::Initial;
            sollicite |= elicite;
            ecrit = ecrit.saturating_add(avance);
        }
        if ecrit == 0 {
            return Ok(0);
        }

        // §14.1 : « a server MUST expand the payload of all UDP datagrams
        // carrying ack-eliciting Initial packets to at least […] 1200 bytes. »
        //
        // **LE BOURRAGE SE MET DERRIÈRE, EN OCTETS NULS.** §19.1 : le type zéro
        // est `PADDING`, et un paquet à en-tête long dit sa propre longueur —
        // ces octets-là sont donc hors de tout paquet, et le pair les ignore
        // comme il ignore la fin d'un datagramme.
        if porte_un_initial && sollicite && ecrit < INITIAL_DATAGRAM_OCTETS_MIN {
            // `ecrit` est inférieur au plancher, et `cible` ne dépasse pas le
            // tampon : la découpe tient, et une garde y serait morte.
            let cible = min(INITIAL_DATAGRAM_OCTETS_MIN, out.len());
            out[ecrit.min(cible)..cible].fill(0);
            ecrit = ecrit.max(cible);
        }

        let octets = u64::try_from(ecrit).unwrap_or(0);
        // §8.1 compte TOUT ce qui part : la garde d'amplification borne les
        // octets, pas les paquets utiles.
        self.etat
            .on_packet_sent(Space::Initial, octets, sollicite, maintenant);
        // §2 de RFC 9002, en revanche : « Packets that contain only ACK frames
        // do not count toward congestion control limits. »
        //
        // **LA PREMIÈRE VERSION LES COMPTAIT**, et un essai l'a fait voir : un
        // serveur qui n'a plus que des acquittements à envoyer voyait sa fenêtre
        // se remplir d'octets que personne n'acquitterait jamais — puisqu'un
        // acquittement ne s'acquitte pas —, et finissait par se taire tout seul.
        if sollicite {
            self.congestion.on_sent(octets);
        }
        self.sonder = false;
        Ok(ecrit)
    }

    /// Quand se réveiller — le plus proche des délais qui comptent.
    #[must_use]
    pub fn deadline(&self, maintenant: u64) -> Option<u64> {
        let pto = self.rtt.pto(ACQUITTEMENT_MAX_US, self.sondages);
        let mut quand = self.etat.deadline(pto);
        for rang in 0..ESPACES {
            for candidat in [
                self.emis[rang].loss_time(),
                self.emis[rang].pto_deadline(&self.rtt, ACQUITTEMENT_MAX_US, self.sondages),
                self.recus[rang].ack_deadline(ACQUITTEMENT_MAX_US),
            ] {
                quand = plus_tot(quand, candidat);
            }
        }
        quand.map(|quand| quand.max(maintenant))
    }

    /// Le délai est échu. Rend `true` quand la connexion vient de s'éteindre.
    pub fn on_timeout(&mut self, maintenant: u64) -> bool {
        let pto = self.rtt.pto(ACQUITTEMENT_MAX_US, self.sondages);
        if self.etat.on_timeout(pto, maintenant) {
            return true;
        }
        for rang in 0..ESPACES {
            let perdus = self.emis[rang].detect_lost(&self.rtt, maintenant);
            self.sur_les_pertes(rang, &perdus);
        }
        // §6.2 : quand le sondage échoit, on réémet plutôt que d'attendre. Le
        // compte DOUBLE le délai suivant, et c'est le seul frein d'un émetteur
        // qui n'entend plus rien.
        let echu = (0..ESPACES).any(|rang| {
            self.emis[rang]
                .pto_deadline(&self.rtt, ACQUITTEMENT_MAX_US, self.sondages)
                .is_some_and(|quand| quand <= maintenant)
        });
        if echu {
            self.sondages = self.sondages.saturating_add(1);
            self.sonder = true;
        }
        false
    }

    /// Ouvre un paquet et traite ses trames. Rend ce qu'il occupait.
    ///
    /// `None` veut dire « on ne sait pas lire la suite » — et non « c'est une
    /// faute ».
    fn un_paquet(&mut self, reste: &mut [u8], maintenant: u64) -> Result<Option<usize>, Error> {
        let Ok(arrivee) = Incoming::read(reste, self.local.len()) else {
            return Ok(None);
        };
        let Some(niveau) = arrivee.kind().and_then(Level::of) else {
            return Ok(None);
        };
        // §8.3 de RFC 9001 : le `0-RTT` ne se sert pas, et nous ne l'offrons
        // pas (C6).
        if niveau == Level::ZeroRtt {
            return Ok(None);
        }
        let espace = niveau.space();
        let rang = rang_de(espace);
        let plus_grand = self.recus[rang].largest();

        // **LES CLÉS D'ABORD, LE DÉCHIFFREMENT ENSUITE.** Un espace dont on n'a
        // pas encore les clés fait s'arrêter le parcours : §5.7 de RFC 9001
        // permet de retenir ces paquets, mais retenir est de la mémoire offerte
        // à qui en demande, et le pair réémettra.
        let ouvert = match (rang, self.initiales_reception.as_ref()) {
            (0, Some(clefs)) => open_packet(reste, clefs, plus_grand, self.local.len()),
            (0, None) => return Ok(None),
            _ => match self.dechiffrement[rang].as_ref() {
                Some(clefs) => open_packet(reste, clefs, plus_grand, self.local.len()),
                None => return Ok(None),
            },
        };
        let Ok(ouvert) = ouvert else {
            return Ok(None);
        };

        // §12.4 : un paquet doit porter au moins une trame. Un paquet vide n'est
        // pas une amabilité, c'est un moyen de faire travailler sans rien dire.
        let charge = reste
            .get(ouvert.payload_at..ouvert.payload_at.saturating_add(ouvert.payload_len))
            .unwrap_or_default()
            .to_vec();
        let sollicite = self.les_trames(&charge, niveau, maintenant)?;

        // **CE REFUS EST LE NÔTRE, PAS CELUI DU PAIR.** `Received` refuse quand
        // il tient déjà plus d'intervalles qu'il n'en écrit (§19.3) — c'est-à-
        // dire quand le réseau est plus troué que ce qu'un `ACK` sait dire. On
        // en prend acte sans fermer : le pair réémettra, et les trous se
        // combleront.
        let _ = self.recus[rang].on_received(ouvert.number, sollicite, maintenant);
        // §4.9.1 de RFC 9001 : un serveur jette ses clés `Initial` dès qu'il
        // traite un paquet `Handshake` avec succès. Les garder laisserait
        // ouverte une porte que personne n'a plus de raison d'emprunter.
        if ouvert.kind == PacketKind::Long(LongKind::Handshake) {
            self.initiales_emission = None;
            self.initiales_reception = None;
            let rendus = self.emis[rang_de(Space::Initial)].discard();
            self.congestion.on_acked(rendus, maintenant);
            self.sortie[rang_de(Space::Initial)] = Sortie::default();
            self.enveloppes[rang_de(Space::Initial)].clear();
        }
        self.etat.on_packet_processed(espace, maintenant);
        Ok(Some(ouvert.total))
    }

    /// Traite les trames d'un paquet. Rend `true` si l'une sollicite un
    /// acquittement (§2 de RFC 9002).
    fn les_trames(&mut self, charge: &[u8], niveau: Level, maintenant: u64) -> Result<bool, Error> {
        let mut reste = charge;
        let mut sollicite = false;
        while !reste.is_empty() {
            let Ok((trame, lus)) = Frame::parse(reste) else {
                // §12.4 condamnerait ; on se contente de jeter le reste du
                // paquet, qui n'a plus de frontière connue. Le pair réémettra.
                return Ok(sollicite);
            };
            reste = reste.get(lus..).unwrap_or_default();
            // §2 : tout sauf `ACK`, `PADDING` et `CONNECTION_CLOSE` sollicite.
            sollicite |= !matches!(
                trame,
                Frame::Ack(_) | Frame::Padding { .. } | Frame::ConnectionClose { .. }
            );
            self.une_trame(&trame, niveau, maintenant)?;
        }
        Ok(sollicite)
    }

    /// Traite une trame.
    fn une_trame(
        &mut self,
        trame: &Frame<'_>,
        niveau: Level,
        maintenant: u64,
    ) -> Result<(), Error> {
        // §12.4 : chaque trame a ses niveaux. « An endpoint MUST treat receipt of
        // a frame in a packet type that is not permitted as a connection error
        // of type PROTOCOL_VIOLATION. »
        //
        // **CE N'EST PAS UNE FORMALITÉ** : sans ce contrôle, une trame de flux
        // dans un paquet de poignée de main atteindrait une collection qui
        // n'existe pas encore. Et l'ignorer en silence ne vaut pas mieux — le
        // pair croirait avoir dit quelque chose.
        if !permise(trame, niveau) {
            return Err(Error::new(Reason::Quic(ams_quic::Reason::FrameNotAllowed)));
        }
        match *trame {
            Frame::Crypto { offset, data } => {
                self.poignee.on_crypto(niveau, offset, data)?;
            }
            Frame::Ack(ref ack) => self.sur_un_acquittement(ack, niveau.space(), maintenant)?,
            Frame::ConnectionClose { .. } => {
                let pto = self.rtt.pto(ACQUITTEMENT_MAX_US, self.sondages);
                self.etat.on_connection_close(pto, maintenant);
            }
            Frame::Stream {
                stream,
                offset,
                data,
                fin,
            } => self.sur_un_flux(stream, offset, data, fin)?,
            Frame::ResetStream {
                stream, final_size, ..
            } => {
                self.sur_une_trame_de_flux(stream, |flux, id| flux.on_reset_stream(id, final_size))?
            }
            Frame::StopSending { stream, code } => {
                self.sur_une_trame_de_flux(stream, |flux, id| flux.on_stop_sending(id, code))?
            }
            Frame::MaxStreamData { stream, maximum } => {
                self.sur_une_trame_de_flux(stream, |flux, id| flux.on_max_stream_data(id, maximum))?
            }
            Frame::MaxData { maximum } => self
                .flux
                .as_mut()
                .expect("§12.4 a refusé cette trame avant que les flux existent")
                .on_max_data(maximum),
            Frame::MaxStreams {
                directional,
                maximum,
            } => self
                .flux
                .as_mut()
                .expect("§12.4 a refusé cette trame avant que les flux existent")
                .on_max_streams(directional, maximum),
            // Le reste ne concerne pas encore cette portée. **ON L'IGNORE
            // PLUTÔT QUE DE FERMER** : ce sont des trames que §19 définit, et
            // qu'on saura servir quand le chemin et les identifiants viendront.
            _ => {}
        }
        Ok(())
    }

    /// Les flux, une fois la poignée de main aboutie.
    ///
    /// `None` avant : §7.4 ne laisse croire les limites du pair qu'authentifiées.
    #[must_use]
    pub const fn streams(&self) -> Option<&Streams> {
        self.flux.as_ref()
    }

    /// On ouvre un flux (§2.1).
    ///
    /// # Errors
    ///
    /// [`Reason::PasEncoreDeFlux`] avant la fin de la poignée de main, et la
    /// faute de §4.6 au-delà du plafond que le pair a annoncé.
    pub fn open_stream(&mut self, sens: Directional) -> Result<StreamId, Error> {
        let flux = self
            .flux
            .as_mut()
            .ok_or_else(|| Error::new(Reason::PasEncoreDeFlux))?;
        flux.open(sens).map_err(Error::depuis_quic)
    }

    /// L'application écrit sur ce flux.
    ///
    /// Rend combien d'octets ont été pris. **CE N'EST PAS FORCÉMENT TOUT** : ce
    /// qui attend d'être émis est borné (C3), et une application pressée
    /// remplirait autrement la mémoire du serveur plus vite que le réseau ne la
    /// vide. Le reste se réécrit quand la place se libère.
    ///
    /// # Errors
    ///
    /// [`Reason::PasEncoreDeFlux`] avant la fin de la poignée de main, et la
    /// faute de §3.1 sur un flux qui n'émet pas.
    pub fn write(&mut self, flux: StreamId, octets: &[u8]) -> Result<usize, Error> {
        let rang = self.rang_ouvert(flux)?;
        let sortie = &mut self.sorties[rang];
        let place = SORTIE_OCTETS_MAX.saturating_sub(sortie.octets.len());
        let combien = place.min(octets.len());
        sortie
            .octets
            .extend_from_slice(octets.get(..combien).unwrap_or_default());
        Ok(combien)
    }

    /// L'application a fini d'écrire : le prochain paquet portera le `FIN`
    /// (§19.8).
    ///
    /// # Errors
    ///
    /// [`Reason::PasEncoreDeFlux`], et la faute de §3.1 sur un flux qui n'émet
    /// pas.
    pub fn finish(&mut self, flux: StreamId) -> Result<(), Error> {
        let rang = self.rang_ouvert(flux)?;
        self.fins[rang] = true;
        Ok(())
    }

    /// L'application lit ce qui est prêt sur ce flux, dans l'ordre.
    ///
    /// Rend combien d'octets ont été pris ; zéro si rien n'est prêt.
    pub fn read(&mut self, flux: StreamId, vers: &mut [u8]) -> usize {
        let Some(collection) = self.flux.as_mut() else {
            return 0;
        };
        let Some(rang) = collection.slot(flux) else {
            return 0;
        };
        collection.read(flux, &mut self.fenetres[rang], vers)
    }

    /// Combien d'octets sont prêts à être lus sur ce flux, dans l'ordre.
    #[must_use]
    pub fn readable(&self, flux: StreamId) -> u64 {
        self.flux
            .as_ref()
            .map_or(0, |collection| collection.readable(flux))
    }

    /// L'état de réception de ce flux, s'il en reçoit (§3.2).
    #[must_use]
    pub fn recv_state(&self, flux: StreamId) -> Option<ams_quic::RecvState> {
        self.flux
            .as_ref()
            .and_then(|collection| collection.recv_state(flux))
    }

    /// Les flux vivants, dans l'ordre de la table.
    ///
    /// **C'EST PAR LÀ QU'UNE APPLICATION LES PARCOURT** sans tenir elle-même la
    /// liste de ce qui vit — et sans que la table lui soit ouverte.
    pub fn streams_alive(&self) -> impl Iterator<Item = StreamId> + '_ {
        let collection = self.flux.as_ref();
        (0..FLUX_MAX).filter_map(move |rang| collection.and_then(|flux| flux.occupant(rang)))
    }

    /// L'application prend acte de l'annulation d'un flux (§3.2).
    ///
    /// **SANS CET APPEL, LA PLACE NE SE REND JAMAIS** : §3.2 sépare `Reset
    /// Recvd` de `Reset Read` justement pour que ce soit l'application qui
    /// décide quand elle a fini avec ce flux.
    pub fn read_reset(&mut self, flux: StreamId) {
        if let Some(collection) = self.flux.as_mut() {
            collection.read_reset(flux);
        }
    }

    /// Rend à la table les places des flux finis, et libère ce qui allait avec.
    ///
    /// # SANS CELA, UNE CONNEXION S'ÉPUISE SANS FAUTE
    ///
    /// Trente-deux flux, et plus jamais un de plus : la table se remplirait de
    /// flux morts, et le pair verrait ses ouvertures refusées sans avoir rien
    /// fait de mal. C'est aussi ce qui libère les fenêtres — un demi-mébioctet
    /// par connexion resterait autrement réservé pour rien.
    fn recolter_les_flux(&mut self) {
        let Some(collection) = self.flux.as_mut() else {
            return;
        };
        for rang in 0..FLUX_MAX {
            if collection.oublier(rang).is_some() {
                self.fenetres[rang] = Vec::new();
                self.sorties[rang] = Sortie::default();
                self.fins[rang] = false;
            }
        }
    }

    /// Le rang de ce flux, s'il est ouvert et que nous pouvons y écrire.
    fn rang_ouvert(&mut self, flux: StreamId) -> Result<usize, Error> {
        let collection = self
            .flux
            .as_ref()
            .ok_or_else(|| Error::new(Reason::PasEncoreDeFlux))?;
        // §3.1 : écrire sur un flux qui n'émet pas — parce qu'il n'existe pas,
        // parce qu'il ne va pas dans ce sens, ou parce qu'il est déjà terminé —
        // est NOTRE faute. La taire laisserait l'application croire que ses
        // octets partiront.
        match collection.can_send(flux) {
            true => Ok(collection
                .slot(flux)
                .expect("`can_send` ne dit vrai que d'un flux vivant")),
            false => Err(Error::new(Reason::PasEncoreDeFlux)),
        }
    }

    /// Range une trame `STREAM` (§19.8).
    ///
    /// # LA FENÊTRE NE S'ALLOUE QU'AU PREMIER OCTET
    ///
    /// Un pair qui ouvre trente-deux flux sans rien y écrire ne doit pas nous
    /// faire réserver un demi-mébioctet. C'est la même prudence que §5.2.2 pour
    /// les datagrammes : on ne dépense qu'après avoir vu quelque chose.
    fn sur_un_flux(
        &mut self,
        stream: u64,
        offset: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<(), Error> {
        // **LA COLLECTION EXISTE FORCÉMENT ICI** : §12.4 vient de refuser cette
        // trame hors du niveau applicatif, et les clés de lecture `1-RTT`
        // s'installent dans le même appel que la construction des flux. Un
        // `else` ouvrirait une branche que rien ne peut emprunter.
        let flux = self
            .flux
            .as_mut()
            .expect("§12.4 a refusé cette trame avant que les flux existent");
        // Le numéro vient d'un entier de §16, et `StreamId` a le même espace.
        let id = StreamId::new(stream).expect("un numéro de flux tient dans l'espace de §16");
        let rang = flux.accueillir(id).map_err(Error::depuis_quic)?;
        let fenetre = &mut self.fenetres[rang];
        if fenetre.is_empty() {
            fenetre.resize(FLUX_FENETRE, 0);
        }
        flux.on_stream(id, offset, data, fin, fenetre)
            .map_err(Error::depuis_quic)?;
        Ok(())
    }

    /// Range une trame qui parle d'un flux sans en porter les octets.
    ///
    /// **AVANT LA POIGNÉE DE MAIN, ON N'A PAS DE FLUX ET L'ON N'EN INVENTE PAS**
    /// : ces trames ne peuvent arriver qu'en `1-RTT`, et si les paramètres du
    /// pair ne sont pas encore lus, il n'y a rien à quoi les appliquer.
    fn sur_une_trame_de_flux(
        &mut self,
        stream: u64,
        quoi_faire: impl FnOnce(&mut Streams, StreamId) -> Result<(), ams_quic::Error>,
    ) -> Result<(), Error> {
        let flux = self
            .flux
            .as_mut()
            .expect("§12.4 a refusé cette trame avant que les flux existent");
        let id = StreamId::new(stream).expect("un numéro de flux tient dans l'espace de §16");
        quoi_faire(flux, id).map_err(Error::depuis_quic)?;
        Ok(())
    }

    /// Un `ACK` est arrivé : on en tire le trajet, la congestion et les pertes.
    fn sur_un_acquittement(
        &mut self,
        ack: &ams_proto_quic::Ack<'_>,
        espace: Space,
        maintenant: u64,
    ) -> Result<(), Error> {
        let rang = rang_de(espace);
        // **`false` : ON NE PRÉTEND PAS SAVOIR D'AVANCE** si cet `ACK` a déjà
        // été vu. §13.2.3 de RFC 9000 fait réacquitter ce qui l'a déjà été, et
        // c'est `Sent::on_ack` qui tranche — il ne rend un plus grand
        // nouvellement acquitté que s'il en a réellement retiré un.
        let acquis = self.emis[rang]
            .on_ack(ack, false)
            .map_err(|_| Error::new(Reason::Quic(ams_quic::Reason::TooManyHoles)))?;

        // §5.1 de RFC 9002 : l'échantillon de trajet ne se prend que sur le plus
        // grand nouvellement acquitté, ET s'il y avait un sollicitant.
        if let Some((_, parti_a)) = acquis.largest
            && acquis.eliciting
        {
            let aller_retour = maintenant.saturating_sub(parti_a);
            let annonce = decode_ack_delay(ack.delay, self.exposant).unwrap_or(0);
            self.rtt.sample(aller_retour, annonce, ACQUITTEMENT_MAX_US);
        }
        if acquis.bytes > 0 {
            self.congestion.on_acked(acquis.bytes, maintenant);
        }
        // **UN ACQUITTEMENT REMET LE COMPTE DE SONDAGES À ZÉRO** : le pair
        // parle, donc le doublement n'a plus de raison d'être.
        if acquis.count > 0 {
            self.sondages = 0;
        }
        self.sur_les_acquittements(rang, ack);

        let perdus = self.emis[rang].detect_lost(&self.rtt, maintenant);
        self.sur_les_pertes(rang, &perdus);
        Ok(())
    }

    /// Fait avancer le préfixe confirmé du flux `CRYPTO`.
    fn sur_les_acquittements(&mut self, rang: usize, ack: &ams_proto_quic::Ack<'_>) {
        // **`Sent::on_ack` A DÉJÀ REFUSÉ** un intervalle qui descend sous zéro
        // (§19.3.1) : on n'arrive ici qu'avec un `ACK` sain. Le repli sur le
        // plus grand ne crédite alors qu'un seul paquet — prudent, et sans
        // branche que rien n'emprunte.
        let plus_petit = ack.smallest().unwrap_or(ack.largest);
        let mut restantes = Vec::with_capacity(self.enveloppes[rang].len());
        for enveloppe in &self.enveloppes[rang] {
            // On ne déplie pas les intervalles : le premier suffit à faire
            // avancer un préfixe, et ce qui reste sera crédité par l'`ACK`
            // suivant — qui réacquitte (§13.2.3 de RFC 9000).
            let acquitte = enveloppe.numero >= plus_petit && enveloppe.numero <= ack.largest;
            if !acquitte {
                restantes.push(*enveloppe);
                continue;
            }
            if let Some((decalage, longueur)) = enveloppe.crypto {
                self.sortie[rang].on_acked(decalage, longueur);
            }
            if let Some((id, decalage, longueur)) = enveloppe.flux
                && let Some(place) = self.flux.as_ref().and_then(|flux| flux.slot(id))
            {
                // §3.1 : c'est ce qui fait passer un flux à `Data Recvd`, donc
                // ce qui rend sa place à la table.
                //
                // La collection existe : `slot` vient d'en rendre un rang.
                let _ = self
                    .flux
                    .as_mut()
                    .expect("`slot` vient d'en rendre un rang")
                    .on_acked(id, decalage, longueur);
                self.sorties[place].on_acked(decalage, longueur);
            }
        }
        self.enveloppes[rang] = restantes;
    }

    /// Ce qui est perdu repart, et la congestion en tient compte.
    fn sur_les_pertes(&mut self, rang: usize, perdus: &ams_quic::Lost) {
        if perdus.is_empty() {
            return;
        }
        let mut restantes = Vec::with_capacity(self.enveloppes[rang].len());
        for enveloppe in &self.enveloppes[rang] {
            match perdus.numbers().contains(&enveloppe.numero) {
                true => {
                    if let Some((decalage, _)) = enveloppe.crypto {
                        self.sortie[rang].on_lost(decalage);
                    }
                    // §13.3 : ce qui s'est perdu repart, en reculant le curseur.
                    if let Some((id, decalage, _)) = enveloppe.flux
                        && let Some(place) = self.flux.as_ref().and_then(|flux| flux.slot(id))
                    {
                        self.sorties[place].on_lost(decalage);
                    }
                }
                false => restantes.push(*enveloppe),
            }
        }
        self.enveloppes[rang] = restantes;
        self.congestion.on_lost(perdus.bytes(), 0, 0);
    }

    /// Tire de TLS ce qu'il a à dire, et installe les clés qu'il donne.
    fn avancer_la_poignee(&mut self, maintenant: u64) -> Result<(), Error> {
        while let Some(mut vol) = self.poignee.next_flight()? {
            let rang = rang_de(vol.level().space());
            self.sortie[rang].octets.extend_from_slice(vol.bytes());
            if let Some(change) = vol.take_change() {
                self.installer(change);
            }
        }
        // §4.1.2 de RFC 9001 : côté serveur, terminer c'est confirmer — et §19.20
        // demande de le DIRE au client, qui ne peut pas le deviner.
        if self.poignee.is_complete() && !self.confirmee {
            self.poignee.check_alpn()?;
            self.a_confirmer = true;
            // §7.4 : « An endpoint MUST treat receipt of transport parameters
            // that it cannot process as a connection error of type
            // TRANSPORT_PARAMETER_ERROR. » Les ignorer laisserait la connexion
            // tourner sur des limites qu'on aurait inventées.
            let siens = self
                .poignee
                .peer_parameters()
                .and_then(|octets| TransportParameters::read(octets, Sender::Client).ok())
                .ok_or_else(|| Error::new(Reason::BadParameters))?;
            // **ET C'EST MAINTENANT SEULEMENT** qu'on croit son exposant : avant,
            // rien ne l'authentifiait.
            self.exposant = siens.ack_delay_exponent;
            // **C'EST LE PREMIER INSTANT OÙ L'ON A LE DROIT DE BÂTIR LES FLUX** :
            // avant, ses limites n'étaient pas authentifiées.
            self.flux = Some(Streams::new(Initiator::Server, &self.notres, &siens));
            self.fenetres = (0..FLUX_MAX).map(|_| Vec::new()).collect();
            self.sorties = (0..FLUX_MAX).map(|_| Sortie::default()).collect();
            self.fins = vec![false; FLUX_MAX];
            self.siens = Some(siens);
            self.etat.on_handshake_confirmed();
            self.confirmee = true;
            let _ = maintenant;
        }
        Ok(())
    }

    /// Range les clés qu'un changement apporte.
    fn installer(&mut self, change: KeyChange) {
        let (espace, clefs) = match change {
            KeyChange::Handshake { keys } => (Space::Handshake, keys),
            KeyChange::OneRtt { keys, .. } => (Space::Application, keys),
        };
        let rang = rang_de(espace);
        self.chiffrement[rang] = Some(Clefs::new(clefs.local.packet, clefs.local.header));
        self.dechiffrement[rang] = Some(Clefs::new(clefs.remote.packet, clefs.remote.header));
    }

    /// Compose et scelle un paquet pour cet espace, s'il y a de quoi.
    ///
    /// Rend ce qu'il occupe et s'il sollicite un acquittement.
    ///
    /// # RIEN N'ÉCHOUE ICI, ET C'EST POURQUOI IL N'Y A PAS DE `Result`
    ///
    /// Tout ce qui pouvait refuser a été vérifié avant d'écrire : la place de
    /// chaque trame, la borne de §5.4.2, la présence des clés. **Un `Result`
    /// dont la variante d'erreur est inatteignable n'est pas une prudence** :
    /// c'est une branche que chaque appelant doit propager sans jamais
    /// l'emprunter.
    fn un_envoi(
        &mut self,
        espace: Space,
        out: &mut [u8],
        maintenant: u64,
    ) -> Option<(usize, bool)> {
        let rang = rang_de(espace);
        // **PAS DE GARDE SUR UN TAMPON VIDE** : `payload_capacity` rend zéro
        // pour lui, et le refus de §5.4.2 juste en dessous s'en charge. Deux
        // façons de dire la même chose laisseraient l'une des deux sans emploi.
        let numero = self.prochain[rang];
        let plus_grand = self.emis[rang].largest_acked();
        let plan = self.plan_de(espace);
        let capacite = payload_capacity(&plan, numero, plus_grand, out.len());
        if capacite < 4 {
            return None;
        }

        let mut trames = [0_u8; 1_500];
        // **LA BORNE SE CALCULE UNE FOIS**, avant tout emprunt : ce que le
        // paquet peut porter, et jamais plus que le tampon de composition.
        let borne = min(capacite, trames.len());
        let mut pose = 0_usize;
        let mut sollicite = false;

        // §13.2 : l'`ACK` d'abord. Il ne sollicite rien, et le placer devant
        // garantit qu'il part même si la charge est pleine.
        if self.recus[rang].owes_ack() {
            let place = trames.get_mut(..borne).unwrap_or_default();
            if let Ok(Some(ecrits)) =
                self.recus[rang].write_ack(maintenant, DEFAULT_ACK_DELAY_EXPONENT, place)
            {
                pose = ecrits;
                self.recus[rang].on_ack_sent();
            }
        }

        // §10.2 : une fermeture se dit, et à UN SEUL niveau — le plus haut dont
        // on ait les clés. La répéter dans chaque paquet du datagramme
        // n'apprendrait rien de plus au pair, et §10.2.3 demande seulement
        // qu'elle soit lisible par lui.
        if let Some(code) = self.fermeture
            && self.a_dire
            && espace == self.espace_de_fermeture()
        {
            let close = Frame::ConnectionClose {
                code,
                frame_type: Some(0),
                reason: &[],
            };
            // **ON DEMANDE LA PLACE AVANT D'ÉCRIRE**, plutôt que d'essayer et de
            // rattraper : un `if let Ok` mettrait la décision dans l'échec de
            // l'écriture, où elle est plus difficile à lire — et à éprouver.
            if borne.saturating_sub(pose) >= FERMETURE_OCTETS {
                let place = trames.get_mut(pose..borne).unwrap_or_default();
                pose = pose
                    .saturating_add(close.write(place).expect("la place vient d'être vérifiée"));
                self.a_dire = false;
            }
        }

        // Le flux `CRYPTO`, à la place qui reste.
        let mut porte = None;
        if self.fermeture.is_none() {
            let (decalage, attente) = self.sortie[rang].en_attente();
            if !attente.is_empty() {
                // La trame porte un type et deux entiers de §16, qui font huit
                // octets chacun au pire. **DIX-SEPT, ET NON SEIZE** : la
                // première version comptait trop court d'un octet, ce qui aurait
                // fait échouer l'écriture pour un décalage assez grand — donc
                // jamais pendant une poignée de main, et un jour en production.
                let entete = ENTETE_CRYPTO_MAX;
                let libre = borne.saturating_sub(pose).saturating_sub(entete);
                let combien = min(libre, attente.len());
                if combien > 0 {
                    let morceau = attente.get(..combien).unwrap_or_default();
                    let trame = Frame::Crypto {
                        offset: decalage,
                        data: morceau,
                    };
                    let place = trames.get_mut(pose..).unwrap_or_default();
                    // **LA PLACE A ÉTÉ RÉSERVÉE JUSTE AU-DESSUS**, en-tête
                    // compris : un `if let Ok` ouvrirait ici une branche que
                    // rien ne peut emprunter.
                    let ecrits = trame
                        .write(place)
                        .expect("`libre` a réservé l'en-tête de la trame");
                    pose = pose.saturating_add(ecrits);
                    sollicite = true;
                    porte = Some((decalage, u64::try_from(combien).unwrap_or(0)));
                }
            }
        }

        // Les flux, à la place qui reste, et seulement en `1-RTT`.
        let mut emporte = None;
        if self.fermeture.is_none() && espace == Space::Application {
            pose = self.annoncer_les_credits(&mut trames, pose, borne, &mut sollicite);
            if let Some((porte_flux, ecrits)) = self.poser_un_flux(&mut trames, pose, borne) {
                pose = pose.saturating_add(ecrits);
                sollicite = true;
                emporte = Some(porte_flux);
            }
        }

        // §19.20 : le serveur, et lui seul, dit que la poignée est confirmée.
        if self.a_confirmer && espace == Space::Application && pose < borne {
            let place = trames.get_mut(pose..borne).unwrap_or_default();
            pose = pose.saturating_add(
                Frame::HandshakeDone
                    .write(place)
                    .expect("un octet, et la place vient d'être vérifiée"),
            );
            sollicite = true;
            self.a_confirmer = false;
        }

        // §6.2.4 de RFC 9002 : un sondage doit SOLLICITER, sans quoi il ne
        // provoque pas l'acquittement qui le rendrait utile.
        if self.sonder && !sollicite && pose < borne {
            let place = trames.get_mut(pose..borne).unwrap_or_default();
            pose = pose.saturating_add(
                Frame::Ping
                    .write(place)
                    .expect("un octet, et la place vient d'être vérifiée"),
            );
            sollicite = true;
        }

        if pose == 0 {
            return None;
        }
        // §5.4.2 de RFC 9001 : de quoi échantillonner. Un `PADDING` complète.
        while pose < 4 && pose < trames.len() {
            trames[pose] = 0;
            pose = pose.saturating_add(1);
        }

        let corps = trames.get(..pose).unwrap_or_default();
        let ecrit = match rang {
            0 => self
                .initiales_emission
                .as_ref()
                .map(|clefs| seal_packet(out, clefs, &plan, numero, plus_grand, corps)),
            _ => self.chiffrement[rang]
                .as_ref()
                .map(|clefs| seal_packet(out, clefs, &plan, numero, plus_grand, corps)),
        };
        let Some(Ok(ecrit)) = ecrit else {
            return None;
        };

        self.prochain[rang] = numero.saturating_add(1);
        let octets = u64::try_from(ecrit).unwrap_or(0);
        // §2 de RFC 9002 : un paquet qui ne porte que des `ACK` ne compte pas en
        // vol. Le compter ferait rétrécir la fenêtre à chaque acquittement.
        let _ = self.emis[rang].on_sent(numero, maintenant, octets, sollicite, sollicite);
        self.enveloppes[rang].push(Enveloppe {
            numero,
            crypto: porte,
            flux: emporte,
        });
        if let Some((_, longueur)) = porte {
            self.sortie[rang].on_sent(longueur);
        }
        Some((ecrit, sollicite))
    }

    /// Annonce les crédits qu'on peut annoncer (§19.9, §19.11).
    ///
    /// # ON N'ANNONCE QUE CE QUI DIT QUELQUE CHOSE DE NEUF
    ///
    /// `grant_data` et `grant_streams` rendent `None` quand la limite en vigueur
    /// suffit déjà. Écrire quand même coûterait un paquet au pair sans rien lui
    /// apprendre — et §4.1 ne demande d'annoncer que ce qui change.
    fn annoncer_les_credits(
        &mut self,
        trames: &mut [u8],
        depart: usize,
        borne: usize,
        sollicite: &mut bool,
    ) -> usize {
        let mut pose = depart;
        let Some(flux) = self.flux.as_mut() else {
            return pose;
        };
        // §4.1 : on rouvre ce que l'application a lu. Une fenêtre qu'on ne
        // rouvrirait jamais figerait le flux dès qu'elle serait pleine.
        if let Some(limite) = flux.grant_data(CONNEXION_OCTETS)
            && let Some(place) = trames.get_mut(pose..borne)
            && let Ok(ecrits) = (Frame::MaxData { maximum: limite }).write(place)
        {
            pose = pose.saturating_add(ecrits);
            *sollicite = true;
            flux.set_max_data(limite);
        }
        for sens in [Directional::Bidirectional, Directional::Unidirectional] {
            if let Some(plafond) = flux.grant_streams(sens)
                && let Some(place) = trames.get_mut(pose..borne)
                && let Ok(ecrits) = (Frame::MaxStreams {
                    directional: sens,
                    maximum: plafond,
                })
                .write(place)
            {
                pose = pose.saturating_add(ecrits);
                *sollicite = true;
                // **APRÈS L'ÉCRITURE, ET PAS AVANT** : le plafond ne vaut que
                // lorsque la trame est réellement dans le paquet.
                flux.set_max_streams(sens, plafond);
            }
        }
        pose
    }

    /// Pose les octets d'un flux, à tour de rôle.
    ///
    /// Rend ce que le paquet emporte et combien d'octets la trame a pris.
    ///
    /// # UN SEUL FLUX PAR PAQUET, ET LE TOUR REPART D'OÙ IL S'ÉTAIT ARRÊTÉ
    ///
    /// Repartir du rang zéro à chaque paquet laisserait un flux qui a toujours
    /// de quoi dire affamer tous les autres. Le tour est ce qui rend
    /// l'entrelacement possible, et il ne coûte qu'un entier.
    fn poser_un_flux(
        &mut self,
        trames: &mut [u8],
        depart: usize,
        borne: usize,
    ) -> Option<((StreamId, u64, u64), usize)> {
        let libre = borne
            .saturating_sub(depart)
            .saturating_sub(ENTETE_STREAM_MAX);
        if libre == 0 {
            return None;
        }
        for tour in 0..FLUX_MAX {
            let rang = self.tour.saturating_add(tour) % FLUX_MAX;
            let Some(id) = self.flux.as_ref().and_then(|flux| flux.occupant(rang)) else {
                continue;
            };
            let (decalage, attente) = self.sorties[rang].en_attente();
            // §4.1 : ni au-delà du crédit du flux, ni au-delà de celui de la
            // connexion — et `credit` rend déjà le plus bas des deux.
            let credit = self.flux.as_ref().map_or(0, |flux| flux.credit(id));
            let combien = usize::try_from(credit)
                .unwrap_or(usize::MAX)
                .min(libre)
                .min(attente.len());
            // **LE `FIN` CHEVAUCHE LES DERNIERS OCTETS** (§19.8), et ne part pas
            // dans une trame à lui : l'attendre coûterait un paquet de plus par
            // flux, et un aller-retour de plus pour l'acquitter.
            let fin = self.fins[rang] && combien == attente.len();
            if combien == 0 && !fin {
                continue;
            }
            let longueur = u64::try_from(combien).unwrap_or(0);
            // **LES DEUX CONTRÔLES DE FLUX SE CONSOMMENT AVANT L'ÉCRITURE**, et
            // c'est l'ordre qui compte : un `FIN` redemandé sur un flux déjà
            // terminé est refusé ici (§3.1), et rien ne doit avoir été écrit.
            let flux = self.flux.as_mut().expect("`occupant` vient d'en rendre un");
            // **CE NE PEUT PAS ÉCHOUER, ET LA RAISON TIENT EN DEUX POINTS** :
            // `write` et `finish` refusent déjà un flux qui n'émet plus (§3.1),
            // et `combien` est tiré de `credit`, qui est le plus bas des deux
            // contrôles de flux (§4.1). Un `if` ici serait une garde qu'aucun
            // essai ne pourrait atteindre.
            flux.on_sent(id, longueur, fin)
                .expect("`can_send` et `credit` ont déjà tout vérifié");
            let morceau = attente.get(..combien).unwrap_or_default();
            let trame = Frame::Stream {
                stream: id.value(),
                offset: decalage,
                data: morceau,
                fin,
            };
            let place = trames.get_mut(depart..).unwrap_or_default();
            // **LA PLACE A ÉTÉ RÉSERVÉE**, en-tête compris.
            let ecrits = trame
                .write(place)
                .expect("`libre` a réservé l'en-tête de la trame");
            self.sorties[rang].on_sent(longueur);
            if fin {
                self.fins[rang] = false;
            }
            self.tour = rang.saturating_add(1) % FLUX_MAX;
            return Some(((id, decalage, longueur), ecrits));
        }
        None
    }

    /// À quel espace dire la fermeture (§10.2.3).
    ///
    /// **LE PLUS HAUT DONT LE PAIR AIT LES CLÉS.** §10.2.3 : « endpoints MUST
    /// send a CONNECTION_CLOSE frame in an Initial or Handshake packet if the
    /// handshake has not completed » — sans quoi le pair ne pourrait pas la lire,
    /// et attendrait son délai d'inactivité sans savoir pourquoi.
    fn espace_de_fermeture(&self) -> Space {
        match self.chiffrement[rang_de(Space::Application)].is_some() {
            true => Space::Application,
            // **PAS DE CAS `Handshake`, ET C'EST DÉLIBÉRÉ.** `rustls` rend les
            // clés de `Handshake` et celles de `1-RTT` au cours d'un même
            // vidage : l'état « les unes sans les autres » n'existe pas de ce
            // côté-ci. Un troisième bras serait une branche que rien ne peut
            // emprunter — et si l'amont changeait, la fermeture partirait en
            // `Initial`, que le pair sait toujours lire.
            false => Space::Initial,
        }
    }

    /// Le plan d'un paquet de cet espace.
    fn plan_de(&self, espace: Space) -> Plan<'static> {
        match espace {
            Space::Initial => Plan::Initial {
                destination: self.distant,
                source: self.local,
                token: &[],
            },
            Space::Handshake => Plan::Handshake {
                destination: self.distant,
                source: self.local,
            },
            Space::Application => Plan::OneRtt {
                destination: self.distant,
                key_phase: false,
            },
        }
    }
}

impl core::fmt::Debug for Connection {
    /// **RIEN DE CE QUI EST SECRET NE S'IMPRIME.**
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Connection")
            .field("established", &self.is_established())
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

/// Le rang d'un espace dans les tableaux de cette connexion.
const fn rang_de(espace: Space) -> usize {
    match espace {
        Space::Initial => 0,
        Space::Handshake => 1,
        Space::Application => 2,
    }
}

/// Le plus proche de deux instants, quand ils existent.
fn plus_tot(un: Option<u64>, deux: Option<u64>) -> Option<u64> {
    match (un, deux) {
        (Some(un), Some(deux)) => Some(un.min(deux)),
        (Some(seul), None) => Some(seul),
        (None, autre) => autre,
    }
}

#[cfg(test)]
mod tests;
