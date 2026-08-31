// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que §5.2.2, §6.1 et §14.1 imposent au tri d'un datagramme.
//!
//! # LES DATAGRAMMES SONT FABRIQUÉS À LA MAIN, ET NON PAR NOTRE ENCODEUR
//!
//! Un essai qui construirait ses paquets avec notre propre écriture ne
//! prouverait rien du fil : si l'ordre des champs était faux DES DEUX CÔTÉS, il
//! passerait quand même. Ici, chaque octet est posé d'après §17.2, à la main.

use ams_proto_quic::{LongKind, VERSION_1};

use super::{Discard, INITIAL_DATAGRAM_OCTETS_MIN, Incoming, LOCAL_CONNECTION_ID_OCTETS, Route};
use crate::receive::PacketKind;

/// L'identifiant de destination de nos essais, à la longueur qu'on distribue.
const DCID: [u8; LOCAL_CONNECTION_ID_OCTETS] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

/// Les bits de type d'un en-tête long (§17.2), forme et bit fixe compris.
const fn premier_octet(kind: LongKind) -> u8 {
    let type_ = match kind {
        LongKind::Initial => 0x00,
        LongKind::ZeroRtt => 0x10,
        LongKind::Handshake => 0x20,
        LongKind::Retry => 0x30,
    };
    // 0x80 : forme longue. 0x40 : bit fixe. 0x03 : deux octets de numéro, pour
    // les types qui en portent un.
    0x80 | 0x40 | type_ | 0x03
}

/// Un datagramme portant un en-tête long, rempli à `taille` octets.
fn long(kind: LongKind, version: u32, taille: usize) -> std::vec::Vec<u8> {
    let mut octets = std::vec::Vec::new();
    octets.push(premier_octet(kind));
    octets.extend_from_slice(&version.to_be_bytes());
    // §17.2 : la longueur de chaque identifiant précède ses octets.
    octets.push(u8::try_from(DCID.len()).expect("huit"));
    octets.extend_from_slice(&DCID);
    octets.push(0); // identifiant de source vide
    if kind == LongKind::Initial {
        octets.push(0); // longueur de jeton, en varint : zéro
    }
    if kind != LongKind::Retry {
        // La longueur de la charge, en varint sur deux octets.
        octets.extend_from_slice(&[0x44, 0x00]);
    }
    // Le bourrage : c'est le DATAGRAMME que §14.1 borne, pas le paquet.
    octets.resize(taille.max(octets.len()), 0);
    octets
}

/// Un datagramme portant un en-tête court.
fn court(taille: usize) -> std::vec::Vec<u8> {
    let mut octets = std::vec::Vec::new();
    // 0x40 : bit fixe, forme courte (le bit 0x80 est à zéro).
    octets.push(0x40);
    octets.extend_from_slice(&DCID);
    octets.resize(taille.max(octets.len()), 0);
    octets
}

/// Lit ce datagramme, ou dit pourquoi il ne se lit pas.
fn lire(datagram: &[u8]) -> Result<Incoming, Discard> {
    Incoming::read(datagram, LOCAL_CONNECTION_ID_OCTETS)
}

/// **UN `Initial` DE TAILLE SUFFISANTE OUVRE UNE CONNEXION** (§5.2.2).
#[test]
fn un_initial_de_taille_suffisante_ouvre_une_connexion() {
    let datagramme = long(LongKind::Initial, VERSION_1, INITIAL_DATAGRAM_OCTETS_MIN);
    let arrivee = lire(&datagramme).expect("lisible");
    assert_eq!(arrivee.kind(), Some(PacketKind::Long(LongKind::Initial)));
    assert_eq!(arrivee.version(), VERSION_1);
    assert_eq!(arrivee.destination().as_bytes(), DCID);
    assert_eq!(arrivee.datagram_len(), INITIAL_DATAGRAM_OCTETS_MIN);
    assert!(arrivee.big_enough_for_initial());
    assert_eq!(arrivee.route(None), Route::New);
}

/// **UN `Initial` TROP PETIT SE JETTE** (§14.1).
///
/// « A server MUST discard an Initial packet that is carried in a UDP datagram
/// with a payload that is smaller than […] 1200 bytes. » C'est la garde
/// d'amplification au plus tôt : l'accepter laisserait obtenir trois fois un
/// tout petit datagramme, autant de fois qu'on veut.
#[test]
fn un_initial_trop_petit_se_jette() {
    for taille in [64_usize, 1199] {
        let datagramme = long(LongKind::Initial, VERSION_1, taille);
        let arrivee = lire(&datagramme).expect("lisible");
        assert!(!arrivee.big_enough_for_initial(), "{taille}");
        assert_eq!(
            arrivee.route(None),
            Route::Drop(Discard::InitialTooSmall),
            "{taille}"
        );
    }
    // Et le plancher lui-même passe : la borne est inclusive.
    let pile = long(LongKind::Initial, VERSION_1, INITIAL_DATAGRAM_OCTETS_MIN);
    assert_eq!(lire(&pile).expect("lisible").route(None), Route::New);
}

/// **UN DATAGRAMME QUI APPARTIENT À QUELQU'UN LUI VA**, quelle que soit sa
/// taille : §14.1 ne borne que ce qui ouvre une connexion.
#[test]
fn ce_qui_appartient_a_quelqu_un_lui_va() {
    for kind in [LongKind::Initial, LongKind::ZeroRtt, LongKind::Handshake] {
        // Trente-deux octets : bien en deçà du plancher de §14.1.
        let datagramme = long(kind, VERSION_1, 32);
        let arrivee = lire(&datagramme).expect("lisible");
        assert_eq!(arrivee.route(Some(7)), Route::Connection(7), "{kind:?}");
    }
    let bref = court(32);
    assert_eq!(
        lire(&bref).expect("lisible").route(Some(3)),
        Route::Connection(3)
    );
}

/// **UNE VERSION QU'ON NE SERT PAS SE NÉGOCIE, SI LE DATAGRAMME EST ASSEZ
/// GRAND** (§5.2.2).
///
/// Et se jette sinon : « Servers MUST drop smaller packets that specify
/// unsupported versions. » Répondre aux petits ferait un amplificateur.
#[test]
fn une_version_inconnue_se_negocie_ou_se_jette() {
    for version in [0x0000_0002_u32, 0xdead_beef, 0x5155_4943] {
        let grand = long(LongKind::Initial, version, INITIAL_DATAGRAM_OCTETS_MIN);
        assert_eq!(
            lire(&grand).expect("lisible").route(None),
            Route::Negotiate,
            "{version:#010x}"
        );
        let petit = long(LongKind::Initial, version, 1199);
        assert_eq!(
            lire(&petit).expect("lisible").route(None),
            Route::Drop(Discard::UnknownVersionTooSmall),
            "{version:#010x}"
        );
    }
}

/// **LA VERSION SE JUGE AVANT LA CARTE**, et c'est l'ordre de §5.2.2.
///
/// « Packets with a supported version, or no Version field, are matched to a
/// connection using the connection ID. » Interroger la carte d'abord ferait
/// remettre à une connexion en cours un paquet d'une version qu'elle ne parle
/// pas — et §5.2 demande précisément de jeter ce qui est « inconsistent with the
/// state of that connection ».
#[test]
fn la_version_se_juge_avant_la_carte() {
    let datagramme = long(LongKind::Initial, 0xdead_beef, INITIAL_DATAGRAM_OCTETS_MIN);
    let arrivee = lire(&datagramme).expect("lisible");
    assert_eq!(
        arrivee.route(Some(1)),
        Route::Negotiate,
        "une connexion connue ne rattrape pas une version inconnue"
    );
}

/// **UN SERVEUR NE REÇOIT PAS DE NÉGOCIATION DE VERSION** (§6.1).
///
/// « An endpoint MUST NOT send a Version Negotiation packet in response to
/// receiving a Version Negotiation packet. » Sans cette règle, deux serveurs mal
/// dirigés l'un vers l'autre se renverraient des négociations sans fin.
#[test]
fn un_serveur_ne_recoit_pas_de_negociation_de_version() {
    let datagramme = long(LongKind::Initial, 0, INITIAL_DATAGRAM_OCTETS_MIN);
    let arrivee = lire(&datagramme).expect("lisible");
    // §17.2.1 : pas de type, parce que les bits n'en décrivent aucun.
    assert_eq!(arrivee.kind(), None);
    assert_eq!(arrivee.version(), 0);
    assert_eq!(
        arrivee.route(None),
        Route::Drop(Discard::VersionNegotiation)
    );
    // Et même adressée à une connexion connue, elle se jette.
    assert_eq!(
        arrivee.route(Some(2)),
        Route::Drop(Discard::VersionNegotiation)
    );
}

/// **UN SERVEUR NE REÇOIT PAS DE `Retry`** (§17.2.5) : c'est lui qui l'émet.
///
/// Il se jette AVANT la carte : c'est le seul paquet dont la seule présence est
/// déjà une faute, et le laisser filer lui donnerait une chance d'être remis à
/// quelqu'un.
#[test]
fn un_serveur_ne_recoit_pas_de_retry() {
    // Un `Retry` porte seize octets de tag, et rien qui ressemble à une
    // longueur : on l'écrit tel que §17.2.5 le décrit.
    let mut datagramme = long(LongKind::Retry, VERSION_1, 0);
    datagramme.extend_from_slice(&[0xaa; 16]);
    let arrivee = lire(&datagramme).expect("lisible");
    assert_eq!(arrivee.kind(), Some(PacketKind::Long(LongKind::Retry)));
    assert_eq!(arrivee.route(None), Route::Drop(Discard::Retry));
    assert_eq!(
        arrivee.route(Some(4)),
        Route::Drop(Discard::Retry),
        "même adressé à une connexion connue"
    );
}

/// **UN `Handshake` SANS CONNEXION SE JETTE** (§5.2.2).
///
/// « Clients are not able to send Handshake packets prior to receiving a server
/// response, so servers SHOULD ignore any such packets. » Un tel paquet ne peut
/// venir que d'un menteur ou d'un très grand retard.
#[test]
fn un_handshake_sans_connexion_se_jette() {
    let datagramme = long(LongKind::Handshake, VERSION_1, INITIAL_DATAGRAM_OCTETS_MIN);
    assert_eq!(
        lire(&datagramme).expect("lisible").route(None),
        Route::Drop(Discard::HandshakeWithoutConnection)
    );
}

/// **UN `0-RTT` SANS CONNEXION SE JETTE AUSSI.**
///
/// §5.2.2 permettrait d'en retenir quelques-uns en attendant un `Initial` en
/// retard. On ne le fait pas : nous n'offrons pas le `0-RTT` (C6), donc
/// l'`Initial` qui suivrait ne les rendrait pas plus lisibles. Les retenir
/// serait de la mémoire offerte à qui en demande.
#[test]
fn un_zero_rtt_sans_connexion_se_jette() {
    let datagramme = long(LongKind::ZeroRtt, VERSION_1, INITIAL_DATAGRAM_OCTETS_MIN);
    assert_eq!(
        lire(&datagramme).expect("lisible").route(None),
        Route::Drop(Discard::EarlyDataWithoutConnection)
    );
}

/// **UN EN-TÊTE COURT INCONNU SE JETTE.**
///
/// C'est ce qui arrive quand une connexion vient de s'éteindre — et c'est aussi
/// ce qui arrive quand quelqu'un cherche à voir ce qui répond sur ce port.
#[test]
fn un_entete_court_inconnu_se_jette() {
    let datagramme = court(64);
    let arrivee = lire(&datagramme).expect("lisible");
    assert_eq!(arrivee.kind(), Some(PacketKind::Short));
    // §17.3 : un en-tête court ne porte pas de version. On lui donne la nôtre,
    // faute de quoi il tomberait dans la négociation de version.
    assert_eq!(arrivee.version(), VERSION_1);
    assert_eq!(arrivee.destination().as_bytes(), DCID);
    assert_eq!(arrivee.route(None), Route::Drop(Discard::UnknownConnection));
}

/// **CE QU'ON NE SAIT PAS LIRE SE JETTE, SANS EN DIRE PLUS.**
///
/// Distinguer un bit fixe absent d'une troncature apprendrait, à qui balaie le
/// port, ce que nous savons lire. Un seul refus, et il ne dit rien.
#[test]
fn ce_qu_on_ne_sait_pas_lire_se_jette() {
    let cas: [(&str, std::vec::Vec<u8>); 6] = [
        ("rien du tout", std::vec![]),
        ("un seul octet", std::vec![0xc3]),
        // §17.2 : le bit fixe (0x40) manque.
        (
            "sans bit fixe, forme longue",
            std::vec![0x80, 0, 0, 0, 1, 0, 0],
        ),
        ("sans bit fixe, forme courte", std::vec![0x00; 32]),
        // Un en-tête long tronqué avant sa version.
        ("tronqué avant la version", std::vec![0xc3, 0x00, 0x00]),
        // Un identifiant de plus de vingt octets (§17.2).
        ("identifiant trop long", {
            let mut v = std::vec![0xc3, 0x00, 0x00, 0x00, 0x01, 21];
            v.resize(64, 0);
            v
        }),
    ];
    for (quoi, datagramme) in cas {
        assert_eq!(lire(&datagramme), Err(Discard::NotAPacket), "{quoi}");
    }
    // Un en-tête court plus court que l'identifiant qu'on distribue.
    let bref = court(0);
    assert_eq!(
        lire(bref.get(..4).expect("quatre octets")),
        Err(Discard::NotAPacket)
    );
}

/// **LA LONGUEUR DE L'IDENTIFIANT VIENT DE NOUS, PAS DU FIL** (§17.3).
///
/// Un en-tête court ne la porte pas. Lire avec une autre longueur que celle
/// qu'on a distribuée rendrait un identifiant qui n'est à personne — et c'est
/// pourquoi elle est une constante et non un réglage.
#[test]
fn la_longueur_de_l_identifiant_vient_de_nous() {
    let datagramme = court(64);
    let bon = Incoming::read(&datagramme, LOCAL_CONNECTION_ID_OCTETS).expect("lisible");
    assert_eq!(bon.destination().as_bytes(), DCID);

    let autre = Incoming::read(&datagramme, 4).expect("lisible aussi, hélas");
    assert_eq!(
        autre.destination().as_bytes(),
        &DCID[..4],
        "une autre longueur donne un autre identifiant, et il n'est à personne"
    );
    assert_ne!(bon.destination(), autre.destination());
}

/// **SEUL LE PREMIER PAQUET DÉCIDE** (§12.2).
///
/// Un `Initial` peut être suivi, dans le même datagramme, d'un `Handshake` que
/// rien ne routerait à lui seul. Ils vont tous à la connexion du premier.
#[test]
fn seul_le_premier_paquet_decide() {
    let mut datagramme = long(LongKind::Initial, VERSION_1, 64);
    // Un second paquet, d'un type qui se jetterait s'il était seul.
    datagramme.extend_from_slice(&long(LongKind::Handshake, VERSION_1, 0));
    datagramme.resize(INITIAL_DATAGRAM_OCTETS_MIN, 0);

    let arrivee = lire(&datagramme).expect("lisible");
    assert_eq!(arrivee.kind(), Some(PacketKind::Long(LongKind::Initial)));
    assert_eq!(arrivee.route(None), Route::New);
}

/// La taille mesurée est celle du DATAGRAMME, et non celle du paquet.
///
/// §14.1 borne le datagramme parce que c'est lui que le réseau transporte, et
/// lui qui sert de mesure à l'anti-amplification (§8.1). Compter le paquet
/// laisserait un `Initial` minuscule ouvrir une connexion pourvu qu'on l'ait
/// coalescé avec du vide.
#[test]
fn la_taille_mesuree_est_celle_du_datagramme() {
    let court_paquet = long(LongKind::Initial, VERSION_1, 40);
    let mesure = court_paquet.len();
    let arrivee = lire(&court_paquet).expect("lisible");
    assert_eq!(arrivee.datagram_len(), mesure);
    assert!(!arrivee.big_enough_for_initial());

    // Le même paquet, dans un datagramme bourré : §14.1 est satisfaite.
    let mut bourre = court_paquet;
    bourre.resize(INITIAL_DATAGRAM_OCTETS_MIN, 0);
    let arrivee = lire(&bourre).expect("lisible");
    assert_eq!(arrivee.datagram_len(), INITIAL_DATAGRAM_OCTETS_MIN);
    assert!(arrivee.big_enough_for_initial());
    assert_eq!(arrivee.route(None), Route::New);
}

/// **L'ADRESSE DE RETOUR EST CELLE QUE LE PAIR S'EST DONNÉE** (§7.2).
///
/// « Each endpoint […] chooses the connection ID that its peer uses. » Le
/// destinataire d'un paquet ne peut donc pas déduire de sa propre adresse celle
/// à écrire dans sa réponse : il lui faut LIRE l'identifiant de source, et c'est
/// la seule chose du datagramme qui la porte.
///
/// Un serveur qui l'ignorerait répondrait à un identifiant que le client ne
/// reconnaît pas, et sa réponse serait jetée sans un mot.
#[test]
fn l_adresse_de_retour_est_celle_que_le_pair_s_est_donnee() {
    /// L'identifiant que le pair s'est donné — d'une AUTRE longueur que le
    /// nôtre, pour qu'une confusion des deux se voie.
    const SCID: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

    let mut octets = std::vec::Vec::new();
    octets.push(premier_octet(LongKind::Initial));
    octets.extend_from_slice(&VERSION_1.to_be_bytes());
    octets.push(u8::try_from(DCID.len()).expect("huit"));
    octets.extend_from_slice(&DCID);
    octets.push(u8::try_from(SCID.len()).expect("quatre"));
    octets.extend_from_slice(&SCID);
    octets.push(0); // jeton vide
    octets.extend_from_slice(&[0x44, 0x00]);
    octets.resize(INITIAL_DATAGRAM_OCTETS_MIN, 0);

    let arrivee = lire(&octets).expect("lisible");
    assert_eq!(arrivee.destination().as_bytes(), DCID);
    assert_eq!(
        arrivee.source().as_bytes(),
        SCID,
        "c'est cet identifiant-là qu'une réponse doit porter"
    );
    assert_ne!(
        arrivee.source(),
        arrivee.destination(),
        "les deux sens ont chacun le leur"
    );
}

/// **UN EN-TÊTE COURT NE PORTE PAS D'ADRESSE DE RETOUR** (§17.3).
///
/// Le champ n'existe pas dans la forme courte : à ce stade, chacun connaît déjà
/// l'identifiant de l'autre. Rendre un identifiant vide plutôt qu'une option
/// dit exactement cela — il n'y a rien à y lire, jamais.
#[test]
fn un_en_tete_court_ne_porte_pas_d_adresse_de_retour() {
    let arrivee = lire(&court(64)).expect("lisible");
    assert_eq!(arrivee.destination().as_bytes(), DCID);
    assert!(
        arrivee.source().is_empty(),
        "§17.3 : la forme courte n'a pas ce champ"
    );
}
