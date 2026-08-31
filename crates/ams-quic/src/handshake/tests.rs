// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que §4 de RFC 9001 impose entre les niveaux de chiffrement.

use ams_proto_quic::{LongKind, Space, TransportError};

use super::{CRYPTO_OCTETS_MAX, Handshake, Level, crypto_error};
use crate::error::Reason;
use crate::receive::PacketKind;

/// Une fenêtre de la taille que le module demande.
fn fenetre() -> std::vec::Vec<u8> {
    std::vec![0_u8; CRYPTO_OCTETS_MAX]
}

/// **UN `Retry` NE PORTE PAS DE TRAMES**, donc pas de niveau où en lire.
#[test]
fn un_retry_n_a_pas_de_niveau() {
    assert_eq!(
        Level::of(PacketKind::Long(LongKind::Initial)),
        Some(Level::Initial)
    );
    assert_eq!(
        Level::of(PacketKind::Long(LongKind::ZeroRtt)),
        Some(Level::ZeroRtt)
    );
    assert_eq!(
        Level::of(PacketKind::Long(LongKind::Handshake)),
        Some(Level::Handshake)
    );
    assert_eq!(Level::of(PacketKind::Short), Some(Level::OneRtt));
    assert_eq!(
        Level::of(PacketKind::Long(LongKind::Retry)),
        None,
        "§17.2.5 : un Retry n'a pas de charge à déchiffrer"
    );
}

/// **QUATRE NIVEAUX, TROIS ESPACES** (§12.3) : `0-RTT` et `1-RTT` partagent.
#[test]
fn quatre_niveaux_pour_trois_espaces() {
    assert_eq!(Level::Initial.space(), Space::Initial);
    assert_eq!(Level::Handshake.space(), Space::Handshake);
    assert_eq!(Level::ZeroRtt.space(), Space::Application);
    assert_eq!(Level::OneRtt.space(), Space::Application);
    // Et l'ordre est celui de l'installation : c'est lui qui donne son sens à
    // « un niveau inférieur ».
    assert!(Level::Initial < Level::ZeroRtt);
    assert!(Level::ZeroRtt < Level::Handshake);
    assert!(Level::Handshake < Level::OneRtt);
}

/// **UN `CRYPTO` DANS UN PAQUET `0-RTT` CONDAMNE LA CONNEXION** (§8.3).
///
/// C'est par là qu'un `EndOfEarlyData` entrerait dans la transcription sans que
/// personne ne l'ait autorisé.
#[test]
fn un_crypto_en_zero_rtt_condamne() {
    let mut poignee = Handshake::new();
    let mut place = fenetre();
    let issue = poignee
        .on_crypto(Level::ZeroRtt, 0, b"salut", &mut place)
        .expect_err("§8.3 le nomme");
    assert_eq!(issue.reason(), Reason::CryptoInZeroRtt);
    assert_eq!(
        issue.reason().code(),
        Some(TransportError::ProtocolViolation)
    );
    // Et rien n'a été rangé nulle part.
    assert_eq!(poignee.readable(Level::ZeroRtt), 0);
    assert_eq!(poignee.read_offset(Level::ZeroRtt), 0);
    assert_eq!(poignee.take(Level::ZeroRtt, &mut place, &mut [0_u8; 8]), 0);
}

/// Ce qui arrive dans l'ordre se remet à TLS dans l'ordre.
#[test]
fn ce_qui_arrive_dans_l_ordre_se_lit_dans_l_ordre() {
    let mut poignee = Handshake::new();
    let mut place = fenetre();
    poignee
        .on_crypto(Level::Initial, 0, b"bon", &mut place)
        .expect("rangeable");
    poignee
        .on_crypto(Level::Initial, 3, b"jour", &mut place)
        .expect("rangeable");
    assert_eq!(poignee.readable(Level::Initial), 7);

    let mut vers = [0_u8; 16];
    assert_eq!(poignee.take(Level::Initial, &mut place, &mut vers), 7);
    assert_eq!(&vers[..7], b"bonjour");
    assert_eq!(poignee.read_offset(Level::Initial), 7);
    assert_eq!(poignee.readable(Level::Initial), 0);
}

/// **CE QUI ARRIVE DANS LE DÉSORDRE ATTEND SON TROU**, et c'est le travail que
/// §4.1.3 confie à QUIC plutôt qu'à TLS.
#[test]
fn ce_qui_arrive_dans_le_desordre_attend_son_trou() {
    let mut poignee = Handshake::new();
    let mut place = fenetre();
    poignee
        .on_crypto(Level::Initial, 3, b"jour", &mut place)
        .expect("rangeable");
    assert_eq!(
        poignee.readable(Level::Initial),
        0,
        "rien n'est contigu tant que le début manque"
    );
    let mut vers = [0_u8; 16];
    assert_eq!(poignee.take(Level::Initial, &mut place, &mut vers), 0);

    poignee
        .on_crypto(Level::Initial, 0, b"bon", &mut place)
        .expect("rangeable");
    assert_eq!(poignee.readable(Level::Initial), 7);
    assert_eq!(poignee.take(Level::Initial, &mut place, &mut vers), 7);
    assert_eq!(&vers[..7], b"bonjour");
}

/// TLS peut ne prendre qu'une partie de ce qui est prêt.
#[test]
fn tls_peut_ne_prendre_qu_un_morceau() {
    let mut poignee = Handshake::new();
    let mut place = fenetre();
    poignee
        .on_crypto(Level::Initial, 0, b"bonjour", &mut place)
        .expect("rangeable");
    let mut vers = [0_u8; 3];
    assert_eq!(poignee.take(Level::Initial, &mut place, &mut vers), 3);
    assert_eq!(&vers, b"bon");
    assert_eq!(poignee.read_offset(Level::Initial), 3);
    assert_eq!(poignee.readable(Level::Initial), 4);

    let mut reste = [0_u8; 8];
    assert_eq!(poignee.take(Level::Initial, &mut place, &mut reste), 4);
    assert_eq!(&reste[..4], b"jour");
}

/// **CE QUE TLS A DÉJÀ PRIS NE SE RÉÉCRIT PAS.**
///
/// Une retransmission recouvre ce qui est parti ; la laisser écrire dans la
/// fenêtre écraserait des octets que TLS n'a pas encore consommés.
#[test]
fn ce_qui_est_deja_pris_ne_se_reecrit_pas() {
    let mut poignee = Handshake::new();
    let mut place = fenetre();
    poignee
        .on_crypto(Level::Initial, 0, b"bonjour", &mut place)
        .expect("rangeable");
    let mut vers = [0_u8; 4];
    assert_eq!(poignee.take(Level::Initial, &mut place, &mut vers), 4);

    // Le pair renvoie tout depuis le début : les quatre premiers octets sont
    // déjà partis, et les trois derniers sont déjà là.
    poignee
        .on_crypto(Level::Initial, 0, b"bonjour", &mut place)
        .expect("une retransmission n'est pas une faute");
    assert_eq!(poignee.readable(Level::Initial), 3);
    let mut reste = [0_u8; 8];
    assert_eq!(poignee.take(Level::Initial, &mut place, &mut reste), 3);
    assert_eq!(&reste[..3], b"our");
}

/// Une trame entièrement déjà consommée ne change rien du tout.
#[test]
fn une_trame_entierement_consommee_ne_change_rien() {
    let mut poignee = Handshake::new();
    let mut place = fenetre();
    poignee
        .on_crypto(Level::Initial, 0, b"bonjour", &mut place)
        .expect("rangeable");
    let mut vers = [0_u8; 8];
    assert_eq!(poignee.take(Level::Initial, &mut place, &mut vers), 7);

    poignee
        .on_crypto(Level::Initial, 0, b"bon", &mut place)
        .expect("déjà vu, et sans conséquence");
    assert_eq!(poignee.readable(Level::Initial), 0);
    assert_eq!(poignee.read_offset(Level::Initial), 7);
}

/// **UN NIVEAU DÉPASSÉ NE REÇOIT PLUS DE NEUF** (§4.1.3).
///
/// Les retransmissions de ce qu'on a déjà vu restent licites — elles sont même
/// attendues, puisque les acquittements se croisent sur le réseau. Ce qui est
/// refusé, c'est de la matière NOUVELLE à un niveau que TLS a quitté : elle
/// entrerait dans une transcription que le pair croit close.
#[test]
fn un_niveau_depasse_ne_recoit_plus_de_neuf() {
    let mut poignee = Handshake::new();
    let mut place = fenetre();
    poignee
        .on_crypto(Level::Initial, 0, b"bonjour", &mut place)
        .expect("rangeable");
    let mut vers = [0_u8; 8];
    poignee.take(Level::Initial, &mut place, &mut vers);
    poignee
        .install_read(Level::Handshake)
        .expect("tout est consommé");

    // Une retransmission de ce qui a déjà été vu passe.
    poignee
        .on_crypto(Level::Initial, 0, b"bonjour", &mut place)
        .expect("une retransmission reste licite");

    // Un octet de plus, non.
    let issue = poignee
        .on_crypto(Level::Initial, 0, b"bonjours", &mut place)
        .expect_err("§4.1.3 le nomme");
    assert_eq!(issue.reason(), Reason::CryptoAfterLevel);
    assert_eq!(
        issue.reason().code(),
        Some(TransportError::ProtocolViolation)
    );
    // Et le neuf qui commence au-delà, non plus.
    let issue = poignee
        .on_crypto(Level::Initial, 7, b"!", &mut place)
        .expect_err("§4.1.3 le nomme");
    assert_eq!(issue.reason(), Reason::CryptoAfterLevel);
}

/// **INSTALLER UN NIVEAU SUR DES OCTETS NON LUS CONDAMNE** (§4.1.3).
///
/// Ce que les deux côtés ont haché diffèrerait — ce que la poignée de main est
/// justement censée rendre impossible.
#[test]
fn installer_un_niveau_sur_des_octets_non_lus_condamne() {
    let mut poignee = Handshake::new();
    let mut place = fenetre();
    poignee
        .on_crypto(Level::Initial, 0, b"bonjour", &mut place)
        .expect("rangeable");
    let issue = poignee
        .install_read(Level::Handshake)
        .expect_err("§4.1.3 le nomme");
    assert_eq!(issue.reason(), Reason::CryptoNotConsumed);
    assert_eq!(
        issue.reason().code(),
        Some(TransportError::ProtocolViolation)
    );
    assert_eq!(
        poignee.read_level(),
        Level::Initial,
        "le niveau n'a pas bougé"
    );

    // **ET UN TROU COMPTE AUSSI** : une donnée derrière un trou n'a pas
    // davantage été consommée par TLS qu'une donnée contiguë.
    let mut poignee = Handshake::new();
    let mut place = fenetre();
    poignee
        .on_crypto(Level::Initial, 3, b"jour", &mut place)
        .expect("rangeable");
    assert_eq!(poignee.readable(Level::Initial), 0, "rien n'est contigu");
    assert_eq!(
        poignee
            .install_read(Level::Handshake)
            .expect_err("et pourtant il reste des octets")
            .reason(),
        Reason::CryptoNotConsumed
    );
}

/// Une fois tout consommé, le niveau monte — et il ne redescend pas.
#[test]
fn un_niveau_monte_et_ne_redescend_pas() {
    let mut poignee = Handshake::new();
    assert_eq!(poignee.read_level(), Level::Initial);
    assert_eq!(poignee.write_level(), Level::Initial);

    poignee.install_read(Level::Handshake).expect("rien à lire");
    assert_eq!(poignee.read_level(), Level::Handshake);
    poignee.install_read(Level::Initial).expect("rien à lire");
    assert_eq!(
        poignee.read_level(),
        Level::Handshake,
        "un niveau ne redescend pas"
    );
    poignee.install_read(Level::OneRtt).expect("rien à lire");
    assert_eq!(poignee.read_level(), Level::OneRtt);

    poignee.install_write(Level::Handshake);
    assert_eq!(poignee.write_level(), Level::Handshake);
    poignee.install_write(Level::Initial);
    assert_eq!(poignee.write_level(), Level::Handshake);
    poignee.install_write(Level::OneRtt);
    assert_eq!(poignee.write_level(), Level::OneRtt);
}

/// **PLUS D'OCTETS QUE LA FENÊTRE, ET LE CODE EST CELUI DE LA RFC.**
///
/// §7.5 de RFC 9000 nomme `CRYPTO_BUFFER_EXCEEDED` pour ce cas précis. Ce n'est
/// PAS une faute interne : il n'y a pas de contrôle de flux sur `CRYPTO`, donc
/// rien n'avait annoncé de limite au pair — mais la RFC lui a quand même donné
/// un code, parce que la borne devait bien exister quelque part.
#[test]
fn plus_d_octets_que_la_fenetre_a_son_propre_code() {
    let mut poignee = Handshake::new();
    let mut place = fenetre();
    let trop = std::vec![0x41_u8; CRYPTO_OCTETS_MAX + 1];
    let issue = poignee
        .on_crypto(Level::Initial, 0, &trop, &mut place)
        .expect_err("§7.5 le nomme");
    assert_eq!(issue.reason(), Reason::CryptoBufferExceeded);
    assert_eq!(
        issue.reason().code(),
        Some(TransportError::CryptoBufferExceeded),
        "et surtout pas INTERNAL_ERROR : la faute est celle du pair"
    );

    // La fenêtre exacte, elle, passe.
    let pile = std::vec![0x41_u8; CRYPTO_OCTETS_MAX];
    poignee
        .on_crypto(Level::Initial, 0, &pile, &mut place)
        .expect("la borne elle-même tient");
    assert_eq!(
        poignee.readable(Level::Initial),
        u64::try_from(CRYPTO_OCTETS_MAX).expect("tient")
    );

    // Et un décalage lointain déborde aussi, même avec peu d'octets : c'est la
    // PLACE qui manque, pas la quantité.
    let mut autre = Handshake::new();
    assert_eq!(
        autre
            .on_crypto(Level::Initial, 1_000_000, b"x", &mut place)
            .expect_err("hors fenêtre")
            .reason(),
        Reason::CryptoBufferExceeded
    );
}

/// Trop de trous se refuse, et c'est NOTRE borne — donc notre faute.
#[test]
fn trop_de_trous_se_refuse() {
    let mut poignee = Handshake::new();
    let mut place = fenetre();
    // Un octet tous les deux : chaque trame ouvre un trou de plus.
    let mut refuse = None;
    for rang in 0..u64::try_from(crate::HOLES_MAX + 8).expect("tient") {
        let a = rang.saturating_mul(2).saturating_add(1);
        if let Err(issue) = poignee.on_crypto(Level::Initial, a, b"x", &mut place) {
            refuse = Some(issue.reason());
            break;
        }
    }
    assert_eq!(refuse, Some(Reason::TooManyHoles));
    assert_eq!(
        Reason::TooManyHoles.code(),
        Some(TransportError::InternalError),
        "un pair honnête ne l'atteint pas : la borne est la nôtre"
    );
}

/// **LES TROIS FLUX SONT INDÉPENDANTS**, et leurs décalages ne se mêlent pas.
///
/// §4.1.3 : « Each encryption level is associated with a different sequence of
/// bytes. » Un décalage 0 en `Handshake` n'est pas le décalage 0 en `Initial`.
#[test]
fn les_trois_flux_sont_independants() {
    let mut poignee = Handshake::new();
    let mut initial = fenetre();
    let mut handshake = fenetre();
    let mut application = fenetre();

    poignee
        .on_crypto(Level::Initial, 0, b"un", &mut initial)
        .expect("rangeable");
    poignee
        .on_crypto(Level::Handshake, 0, b"deux", &mut handshake)
        .expect("rangeable");
    poignee
        .on_crypto(Level::OneRtt, 0, b"trois", &mut application)
        .expect("rangeable");

    assert_eq!(poignee.readable(Level::Initial), 2);
    assert_eq!(poignee.readable(Level::Handshake), 4);
    assert_eq!(poignee.readable(Level::OneRtt), 5);

    let mut vers = [0_u8; 8];
    assert_eq!(poignee.take(Level::Handshake, &mut initial, &mut vers), 4);
    assert_eq!(
        poignee.read_offset(Level::Initial),
        0,
        "l'autre n'a pas bougé"
    );
    assert_eq!(poignee.read_offset(Level::Handshake), 4);
    assert_eq!(poignee.read_offset(Level::OneRtt), 0);
}

/// **UNE ALERTE TLS DEVIENT UN CODE `CRYPTO_ERROR`** (§4.8).
#[test]
fn une_alerte_devient_un_code_crypto_error() {
    // §4.8 donne l'exemple lui-même : « handshake_failure (0x0128 in QUIC) ».
    assert_eq!(crypto_error(40), 0x0128);
    // Les bornes de l'octet, pour que la composition ne déborde jamais.
    assert_eq!(crypto_error(0), 0x0100);
    assert_eq!(crypto_error(255), 0x01ff);
    // `bad_certificate` (42), `certificate_expired` (45), `no_application_protocol`
    // (120) — celle-là est ce qu'on renvoie quand l'ALPN ne donne pas `h3`.
    assert_eq!(crypto_error(42), 0x012a);
    assert_eq!(crypto_error(45), 0x012d);
    assert_eq!(crypto_error(120), 0x0178);
    // Et chaque alerte a son code : deux alertes ne se confondent pas.
    for alerte in 0..=u8::MAX {
        assert_eq!(crypto_error(alerte), 0x0100 | u64::from(alerte));
    }
}

/// Terminée, puis confirmée — et confirmer termine aussi (§4.1.2).
#[test]
fn terminee_puis_confirmee() {
    let mut poignee = Handshake::new();
    assert!(!poignee.is_complete());
    assert!(!poignee.is_confirmed());

    poignee.complete();
    assert!(poignee.is_complete());
    assert!(
        !poignee.is_confirmed(),
        "terminer n'est pas confirmer : le client attend HANDSHAKE_DONE"
    );

    poignee.confirm();
    assert!(poignee.is_complete());
    assert!(poignee.is_confirmed());

    // **POUR UN SERVEUR, C'EST LE MÊME MOMENT** : confirmer sans avoir terminé
    // termine aussi, parce que §4.1.2 le dit.
    let mut serveur = Handshake::new();
    serveur.confirm();
    assert!(serveur.is_complete());
    assert!(serveur.is_confirmed());
}

/// Une poignée de main neuve est celle que `Default` rend.
#[test]
fn la_poignee_par_defaut_est_celle_qui_commence() {
    assert_eq!(Handshake::default(), Handshake::new());
}
