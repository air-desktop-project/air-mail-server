// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une connexion accepte, ce qu'elle répond, et ce qu'elle refuse.

use super::{
    CANCELLATIONS_MAX, CODE_LONGUEUR, CODE_OCTETS, Connection, Event, GOAWAY_OCTETS, Handshake,
    PING_LONGUEUR, PING_OCTETS, PRIORITY_OCTETS, SERVICE_FRAMES_MAX,
};
use crate::error::{Cause, ErrorCode};
use crate::flow::INITIAL_WINDOW_SIZE;
use crate::frame::{FRAME_HEADER_OCTETS, FrameHeader, FrameKind};
use crate::preface::PREFACE;
use crate::settings::{Setting, Settings};
use crate::stream::StreamState;

/// Les fanions, par leur nom.
const END_STREAM: u8 = 0x1;
const ACK: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITE: u8 = 0x20;

/// Ce que ce serveur annonce dans les épreuves.
fn nos_reglages() -> Settings {
    Settings {
        max_concurrent_streams: Some(crate::stream::MAX_CONCURRENT_STREAMS),
        max_header_list_size: Some(16_384),
        enable_push: false,
        ..Settings::DEFAULT
    }
}

/// Une connexion ouverte, préambule lu, `SETTINGS` du client reçu.
fn ouverte() -> Connection {
    ouverte_avec(nos_reglages())
}

/// La même, avec les réglages qu'on veut annoncer.
fn ouverte_avec(nos: Settings) -> Connection {
    let mut sortie = [0_u8; 256];
    let (connexion, _) = Handshake::new(nos)
        .open(PREFACE, &mut sortie)
        .expect("le préambule est le bon");
    let mut connexion = connexion.expect("il est complet");
    connexion
        .receive(
            entete(FrameKind::Settings, 0, 0, 0),
            &[],
            &mut [],
            &mut sortie,
        )
        .expect("le premier cadre du client");
    connexion
}

/// Un en-tête de cadre.
fn entete(kind: FrameKind, flags: u8, stream: u32, length: u32) -> FrameHeader {
    FrameHeader::new(kind, flags, stream, length)
}

/// Ouvre un flux par un `HEADERS` vide et complet.
fn ouvrir(connexion: &mut Connection, id: u32) {
    let mut sortie = [0_u8; 64];
    let (evenement, poses) = connexion
        .receive(
            entete(FrameKind::Headers, END_HEADERS, id, 0),
            &[],
            &mut [0_u8; 16],
            &mut sortie,
        )
        .unwrap_or_else(|erreur| panic!("flux {id} : {erreur:?}"));
    assert_eq!(poses, 0, "un flux accepté ne fait rien écrire");
    assert!(matches!(evenement, Event::Head { refused: None, .. }));
}

/// **LES DEUX CONSTANTES DISENT LE MÊME NOMBRE**, dans les deux types que le
/// code demande. Rien ne les dérive l'une de l'autre : c'est ce test qui le
/// tient.
#[test]
fn les_longueurs_se_disent_dans_les_deux_types() {
    assert_eq!(usize::try_from(PING_LONGUEUR), Ok(PING_OCTETS));
    assert_eq!(usize::try_from(CODE_LONGUEUR), Ok(CODE_OCTETS));
    assert_eq!(GOAWAY_OCTETS, CODE_OCTETS.saturating_mul(2));
    assert_eq!(PRIORITY_OCTETS, 5);
}

/// **LE PRÉAMBULE EST DANS LE TYPE** : tant qu'il n'est pas lu, il n'y a pas de
/// connexion, et donc aucun cadre à lui présenter.
#[test]
fn une_connexion_ne_s_obtient_qu_avec_le_preambule() {
    let poignee = Handshake::new(nos_reglages());
    let mut sortie = [0_u8; 256];

    // Il en manque : rien n'est écrit, et rien n'est rendu.
    let (rien, poses) = poignee
        .open(b"PRI * HTTP", &mut sortie)
        .expect("le début est le bon");
    assert!(rien.is_none());
    assert_eq!(poses, 0);

    // Il est faux : on refuse dès l'octet qui diffère.
    let issue = poignee
        .open(b"GET / HTTP/1.1", &mut sortie)
        .expect_err("ce n'est pas HTTP/2");
    assert_eq!(issue.cause(), Cause::BadPreface);

    // Il est là : nos `SETTINGS` partent AVANT ceux du client (§3.4).
    let (connexion, poses) = poignee.open(PREFACE, &mut sortie).expect("le bon");
    assert!(connexion.is_some());
    let ecrit = FrameHeader::parse(
        sortie
            .get(..FRAME_HEADER_OCTETS)
            .and_then(|neuf| neuf.try_into().ok())
            .expect("neuf octets"),
    );
    assert_eq!(ecrit.kind(), FrameKind::Settings);
    assert_eq!(ecrit.stream(), 0);
    assert!(!ecrit.flags().ack(), "les nôtres, pas un acquittement");
    assert_eq!(poses, FRAME_HEADER_OCTETS.saturating_add(6 * 6));
}

/// Nos réglages ne tiennent pas dans un tampon trop court, et on le dit.
#[test]
fn nos_reglages_veulent_de_la_place() {
    // Huit octets : même l'en-tête ne tient pas. Vingt : l'en-tête tient, la
    // charge non. Ce sont deux manques distincts, et il faut les deux.
    for taille in [8_usize, 20] {
        let mut court = [0_u8; 64];
        let issue = Handshake::new(nos_reglages())
            .open(PREFACE, court.get_mut(..taille).expect("assez court"))
            .expect_err("la place manque");
        assert_eq!(issue.cause(), Cause::BufferTooSmall, "{taille}");
        assert_eq!(issue.code(), ErrorCode::InternalError, "{taille}");
    }
}

/// **§3.4 : LE PREMIER CADRE DU CLIENT EST SON `SETTINGS`.** Tout autre type
/// arrivant en premier condamne la connexion — c'est ce qui distingue un client
/// HTTP/2 d'un octet égaré qui ressemblait au préambule.
#[test]
fn le_premier_cadre_du_client_est_ses_reglages() {
    let mut sortie = [0_u8; 256];
    let (connexion, _) = Handshake::new(nos_reglages())
        .open(PREFACE, &mut sortie)
        .expect("ouvert");
    let mut connexion = connexion.expect("complet");

    let issue = connexion
        .receive(
            entete(FrameKind::Ping, 0, 0, PING_LONGUEUR),
            &[0; PING_OCTETS],
            &mut [],
            &mut sortie,
        )
        .expect_err("pas en premier");
    assert_eq!(issue.cause(), Cause::FirstFrameNotSettings);
    assert!(issue.is_fatal());
}

/// Les réglages du client s'appliquent, et on les acquitte sans tarder (§6.5.3).
#[test]
fn les_reglages_du_client_s_appliquent_et_s_acquittent() {
    let mut sortie = [0_u8; 256];
    let (connexion, _) = Handshake::new(nos_reglages())
        .open(PREFACE, &mut sortie)
        .expect("ouvert");
    let mut connexion = connexion.expect("complet");
    assert_eq!(connexion.peer_settings(), Settings::DEFAULT);
    assert!(!connexion.settings_acknowledged());
    assert_eq!(connexion.settings(), nos_reglages());

    let charge = [0, 4, 0, 0, 0x40, 0]; // INITIAL_WINDOW_SIZE = 16384
    let (evenement, poses) = connexion
        .receive(
            entete(FrameKind::Settings, 0, 0, 6),
            &charge,
            &mut [],
            &mut sortie,
        )
        .expect("des réglages valides");
    assert_eq!(evenement, Event::Nothing);
    assert_eq!(connexion.peer_settings().initial_window_size, 16_384);
    assert_eq!(poses, FRAME_HEADER_OCTETS, "un acquittement vide");
    let ecrit = FrameHeader::parse(
        sortie
            .get(..FRAME_HEADER_OCTETS)
            .and_then(|neuf| neuf.try_into().ok())
            .expect("neuf"),
    );
    assert_eq!(ecrit.kind(), FrameKind::Settings);
    assert!(ecrit.flags().ack());
    assert_eq!(ecrit.length(), 0);

    // Et l'acquittement du client, lui, ne fait rien écrire.
    let (evenement, poses) = connexion
        .receive(
            entete(FrameKind::Settings, ACK, 0, 0),
            &[],
            &mut [],
            &mut sortie,
        )
        .expect("un acquittement");
    assert_eq!(evenement, Event::Nothing);
    assert_eq!(poses, 0);
    assert!(connexion.settings_acknowledged());
}

/// **UN ACQUITTEMENT NE PORTE RIEN** (§6.5) : des octets dessus veulent dire que
/// le pair ne parle pas ce protocole.
#[test]
fn un_acquittement_de_reglages_ne_porte_rien() {
    let mut connexion = ouverte();
    let issue = connexion
        .receive(
            entete(FrameKind::Settings, ACK, 0, 6),
            &[0; 6],
            &mut [],
            &mut [0_u8; 64],
        )
        .expect_err("un acquittement chargé");
    assert_eq!(issue.cause(), Cause::SettingsAckNotEmpty);
    assert_eq!(issue.code(), ErrorCode::FrameSizeError);
}

/// Un `SETTINGS` sur un flux, et un acquittement qui n'a pas la place de
/// s'écrire.
#[test]
fn les_reglages_ont_leurs_bornes() {
    let mut connexion = ouverte();
    let issue = connexion
        .receive(
            entete(FrameKind::Settings, 0, 1, 0),
            &[],
            &mut [],
            &mut [0_u8; 64],
        )
        .expect_err("sur un flux");
    assert_eq!(issue.cause(), Cause::WrongStream);

    let issue = connexion
        .receive(entete(FrameKind::Settings, 0, 0, 0), &[], &mut [], &mut [])
        .expect_err("pas la place d'acquitter");
    assert_eq!(issue.cause(), Cause::BufferTooSmall);
}

/// **§6.9.2 : LE RÉGLAGE DU PAIR BOUGE NOS FENÊTRES D'ÉMISSION**, et un
/// ajustement qui déborde est une faute de contrôle de flux.
#[test]
fn le_reglage_du_pair_bouge_nos_fenetres_d_emission() {
    let mut connexion = ouverte();
    ouvrir(&mut connexion, 1);
    assert_eq!(
        connexion.streams().send_window(1).map(|f| f.available()),
        Some(i64::from(INITIAL_WINDOW_SIZE))
    );

    // Le pair ramène sa fenêtre initiale à mille.
    let mut sortie = [0_u8; 64];
    connexion
        .receive(
            entete(FrameKind::Settings, 0, 0, 6),
            &[0, 4, 0, 0, 0x03, 0xe8],
            &mut [],
            &mut sortie,
        )
        .expect("mille");
    assert_eq!(
        connexion.streams().send_window(1).map(|f| f.available()),
        Some(1_000)
    );

    // Et un ajustement qui ferait déborder est refusé.
    connexion
        .receive(
            entete(FrameKind::WindowUpdate, 0, 1, CODE_LONGUEUR),
            &0x7fff_f000_u32.to_be_bytes(),
            &mut [],
            &mut sortie,
        )
        .expect("du crédit");
    let issue = connexion
        .receive(
            entete(FrameKind::Settings, 0, 0, 6),
            &[0, 4, 0x7f, 0xff, 0xff, 0xff],
            &mut [],
            &mut sortie,
        )
        .expect_err("cela déborde");
    assert_eq!(issue.cause(), Cause::WindowOverflow);
    assert_eq!(issue.code(), ErrorCode::FlowControlError);
}

/// **ON RENVOIE LES HUIT OCTETS TELS QUELS** (§6.7) : ils sont opaques, et seul
/// le pair sait ce qu'il y a mis.
#[test]
fn un_ping_revient_tel_quel() {
    let mut connexion = ouverte();
    let mut sortie = [0_u8; 64];
    let charge = *b"douze345";

    let (evenement, poses) = connexion
        .receive(
            entete(FrameKind::Ping, 0, 0, PING_LONGUEUR),
            &charge,
            &mut [],
            &mut sortie,
        )
        .expect("un ping");
    assert_eq!(evenement, Event::Nothing);
    assert_eq!(poses, FRAME_HEADER_OCTETS.saturating_add(PING_OCTETS));
    let ecrit = FrameHeader::parse(
        sortie
            .get(..FRAME_HEADER_OCTETS)
            .and_then(|neuf| neuf.try_into().ok())
            .expect("neuf"),
    );
    assert_eq!(ecrit.kind(), FrameKind::Ping);
    assert!(ecrit.flags().ack());
    assert_eq!(
        sortie.get(FRAME_HEADER_OCTETS..poses),
        Some(charge.as_slice())
    );

    // Un acquittement ne se réacquitte pas : on ne répond rien.
    let (evenement, poses) = connexion
        .receive(
            entete(FrameKind::Ping, ACK, 0, PING_LONGUEUR),
            &charge,
            &mut [],
            &mut sortie,
        )
        .expect("un acquittement");
    assert_eq!(evenement, Event::Nothing);
    assert_eq!(poses, 0);
}

/// Un `PING` mal formé, et un `PING` qu'on n'a pas la place de renvoyer.
#[test]
fn un_ping_a_ses_bornes() {
    let mut connexion = ouverte();
    for (flags, flux, longueur, cause) in [
        (0_u8, 1_u32, PING_LONGUEUR, Cause::WrongStream),
        (0, 0, 7, Cause::WrongFixedSize),
    ] {
        let issue = connexion
            .receive(
                entete(FrameKind::Ping, flags, flux, longueur),
                &[0; PING_OCTETS],
                &mut [],
                &mut [0_u8; 64],
            )
            .expect_err("mal formé");
        assert_eq!(issue.cause(), cause);
    }

    let issue = connexion
        .receive(
            entete(FrameKind::Ping, 0, 0, PING_LONGUEUR),
            &[0; PING_OCTETS],
            &mut [],
            &mut [0_u8; 8],
        )
        .expect_err("pas la place");
    assert_eq!(issue.cause(), Cause::BufferTooSmall);
}

/// Le pair s'en va, et dit jusqu'où il a traité.
#[test]
fn un_adieu_se_lit() {
    let mut connexion = ouverte();
    assert!(!connexion.peer_left());

    let mut charge = [0_u8; 12];
    charge
        .get_mut(..CODE_OCTETS)
        .expect("quatre")
        // Le bit de réserve est mis : il doit être ignoré (§4.1).
        .copy_from_slice(&0x8000_0007_u32.to_be_bytes());
    charge
        .get_mut(CODE_OCTETS..GOAWAY_OCTETS)
        .expect("quatre")
        .copy_from_slice(&ErrorCode::EnhanceYourCalm.value().to_be_bytes());

    let (evenement, poses) = connexion
        .receive(
            entete(FrameKind::GoAway, 0, 0, 12),
            &charge,
            &mut [],
            &mut [0_u8; 64],
        )
        .expect("un adieu");
    assert_eq!(
        evenement,
        Event::GoAway {
            last: 7,
            code: ErrorCode::EnhanceYourCalm,
        }
    );
    assert_eq!(poses, 0, "on ne répond pas à un adieu");
    assert!(connexion.peer_left());
}

/// **HUIT OCTETS AU MOINS** (§6.8) : moins, et il n'y a ni dernier flux ni code.
#[test]
fn un_adieu_trop_court_se_refuse() {
    let mut connexion = ouverte();
    for charge in [[0_u8; 0].as_slice(), &[0; 4], &[0; 7]] {
        let longueur = u32::try_from(charge.len()).expect("court");
        let issue = connexion
            .receive(
                entete(FrameKind::GoAway, 0, 0, longueur),
                charge,
                &mut [],
                &mut [0_u8; 64],
            )
            .expect_err("trop court");
        assert_eq!(issue.cause(), Cause::WrongFixedSize);
        assert_eq!(issue.code(), ErrorCode::FrameSizeError);
    }
    let issue = connexion
        .receive(
            entete(FrameKind::GoAway, 0, 1, 8),
            &[0; 8],
            &mut [],
            &mut [0_u8; 64],
        )
        .expect_err("sur un flux");
    assert_eq!(issue.cause(), Cause::WrongStream);
}

/// **`PRIORITY` SE LIT ET NE FAIT RIEN** (§5.3.2). Construire l'arbre que la RFC
/// a retiré demanderait de retenir un graphe que le pair choisit.
#[test]
fn une_priorite_ne_fait_rien() {
    let mut connexion = ouverte();
    let (evenement, poses) = connexion
        .receive(
            entete(FrameKind::Priority, 0, 1, 5),
            &[0; PRIORITY_OCTETS],
            &mut [],
            &mut [0_u8; 64],
        )
        .expect("une priorité");
    assert_eq!(evenement, Event::Nothing);
    assert_eq!(poses, 0);

    for (flux, longueur, cause) in [
        (0_u32, 5_u32, Cause::WrongStream),
        (1, 4, Cause::WrongFixedSize),
    ] {
        let issue = connexion
            .receive(
                entete(FrameKind::Priority, 0, flux, longueur),
                &[0; PRIORITY_OCTETS],
                &mut [],
                &mut [0_u8; 64],
            )
            .expect_err("mal formée");
        assert_eq!(issue.cause(), cause);
    }
}

/// **§4.1 : CE QU'ON NE CONNAÎT PAS S'IGNORE**, et compte quand même comme un
/// cadre de service — un type inventé pour l'occasion ferait sinon une
/// inondation gratuite.
#[test]
fn un_type_inconnu_s_ignore() {
    let mut connexion = ouverte();
    let (evenement, poses) = connexion
        .receive(
            entete(FrameKind::Unknown(0x42), 0xff, 3, 4),
            &[1, 2, 3, 4],
            &mut [],
            &mut [0_u8; 64],
        )
        .expect("ignoré");
    assert_eq!(evenement, Event::Nothing);
    assert_eq!(poses, 0);
}

/// **UN CLIENT N'A JAMAIS EU LE DROIT DE POUSSER** (§8.4), et ce serveur annonce
/// `ENABLE_PUSH` à zéro.
#[test]
fn un_client_ne_pousse_pas() {
    let mut connexion = ouverte();
    let issue = connexion
        .receive(
            entete(FrameKind::PushPromise, END_HEADERS, 1, 4),
            &[0; 4],
            &mut [0_u8; 16],
            &mut [0_u8; 64],
        )
        .expect_err("un client ne pousse pas");
    assert_eq!(issue.cause(), Cause::PushFromClient);
    assert!(issue.is_fatal());
}

/// **§4.3 : RIEN NE S'INTERCALE DANS UN BLOC D'EN-TÊTES** — pas même un `PING`.
#[test]
fn rien_ne_s_intercale_dans_un_bloc() {
    let mut connexion = ouverte();
    let mut bloc = [0_u8; 64];
    let mut sortie = [0_u8; 64];
    connexion
        .receive(
            entete(FrameKind::Headers, 0, 1, 2),
            &[1, 2],
            &mut bloc,
            &mut sortie,
        )
        .expect("un fragment");

    let issue = connexion
        .receive(
            entete(FrameKind::Ping, 0, 0, PING_LONGUEUR),
            &[0; PING_OCTETS],
            &mut bloc,
            &mut sortie,
        )
        .expect_err("au milieu d'un bloc");
    assert_eq!(issue.cause(), Cause::BlockInterrupted);
    assert!(issue.is_fatal());
}

/// Un bloc s'étale sur des `CONTINUATION`, et le `END_STREAM` du PREMIER cadre
/// est celui qui compte.
#[test]
fn un_bloc_s_etale_et_garde_la_fin_du_premier_cadre() {
    let mut connexion = ouverte();
    let mut bloc = [0_u8; 64];
    let mut sortie = [0_u8; 64];

    let (evenement, _) = connexion
        .receive(
            entete(FrameKind::Headers, END_STREAM, 1, 2),
            &[0xaa, 0xbb],
            &mut bloc,
            &mut sortie,
        )
        .expect("un fragment");
    assert_eq!(evenement, Event::Nothing);
    assert_eq!(connexion.streams().state(1), Some(StreamState::Open));

    let (evenement, poses) = connexion
        .receive(
            entete(FrameKind::Continuation, END_HEADERS, 1, 1),
            &[0xcc],
            &mut bloc,
            &mut sortie,
        )
        .expect("la suite");
    assert_eq!(
        evenement,
        Event::Head {
            stream: 1,
            octets: 3,
            end_stream: true,
            refused: None,
        }
    );
    assert_eq!(poses, 0);
    assert_eq!(bloc.get(..3), Some([0xaa, 0xbb, 0xcc].as_slice()));
    // Le pair a fini : le flux est demi-fermé.
    assert_eq!(
        connexion.streams().state(1),
        Some(StreamState::HalfClosedRemote)
    );
}

/// Le remplissage et les cinq octets de priorité s'ôtent avant le bloc.
#[test]
fn un_headers_se_deshabille_avant_d_etre_accumule() {
    let mut connexion = ouverte();
    let mut bloc = [0_u8; 64];
    let mut sortie = [0_u8; 64];

    // Remplissage de deux, priorité de cinq, puis un octet de bloc.
    let charge = [2, 0, 0, 0, 0, 0, 0xee, 0, 0];
    let longueur = u32::try_from(charge.len()).expect("court");
    let (evenement, _) = connexion
        .receive(
            entete(
                FrameKind::Headers,
                END_HEADERS | PADDED | PRIORITE,
                1,
                longueur,
            ),
            &charge,
            &mut bloc,
            &mut sortie,
        )
        .expect("habillé");
    assert_eq!(
        evenement,
        Event::Head {
            stream: 1,
            octets: 1,
            end_stream: false,
            refused: None,
        }
    );
    assert_eq!(bloc.first(), Some(&0xee));
}

/// Un `HEADERS` qui annonce une priorité sans en porter les cinq octets.
#[test]
fn un_headers_ampute_de_sa_priorite_se_refuse() {
    let mut connexion = ouverte();
    let issue = connexion
        .receive(
            entete(FrameKind::Headers, END_HEADERS | PRIORITE, 1, 3),
            &[0, 0, 0],
            &mut [0_u8; 64],
            &mut [0_u8; 64],
        )
        .expect_err("trop court pour une priorité");
    assert_eq!(issue.cause(), Cause::WrongFixedSize);

    // Et sur le flux zéro, un `HEADERS` n'a pas de destinataire.
    let issue = connexion
        .receive(
            entete(FrameKind::Headers, END_HEADERS, 0, 0),
            &[],
            &mut [0_u8; 64],
            &mut [0_u8; 64],
        )
        .expect_err("sur la connexion");
    assert_eq!(issue.cause(), Cause::WrongStream);
}

/// **UN NUMÉRO DE FLUX FAUTIF CONDAMNE LA CONNEXION** : il n'y a pas de flux à
/// qui imputer la faute.
#[test]
fn un_numero_pair_condamne_la_connexion() {
    let mut connexion = ouverte();
    let issue = connexion
        .receive(
            entete(FrameKind::Headers, END_HEADERS, 2, 0),
            &[],
            &mut [0_u8; 16],
            &mut [0_u8; 64],
        )
        .expect_err("un pair vient du serveur");
    assert_eq!(issue.cause(), Cause::BadStreamId);
    assert!(issue.is_fatal());
}

/// **UN FLUX REFUSÉ SE DÉCODE QUAND MÊME** : la table HPACK est commune à la
/// connexion, et sauter un bloc la décalerait pour tous les suivants.
#[test]
fn un_flux_refuse_rend_son_bloc_et_son_annulation() {
    let mut connexion = ouverte();
    // On remplit la table des flux.
    for tour in 0..crate::stream::MAX_CONCURRENT_STREAMS {
        ouvrir(&mut connexion, tour.saturating_mul(2).saturating_add(1));
    }

    let trop = crate::stream::MAX_CONCURRENT_STREAMS
        .saturating_mul(2)
        .saturating_add(1);
    let mut bloc = [0_u8; 64];
    let mut sortie = [0_u8; 64];
    let (evenement, poses) = connexion
        .receive(
            entete(FrameKind::Headers, END_HEADERS, trop, 2),
            &[0x11, 0x22],
            &mut bloc,
            &mut sortie,
        )
        .expect("refusé, mais lu");
    assert_eq!(
        evenement,
        Event::Head {
            stream: trop,
            octets: 2,
            end_stream: false,
            refused: Some(ErrorCode::RefusedStream),
        }
    );
    assert_eq!(bloc.get(..2), Some([0x11, 0x22].as_slice()));

    // Et l'annulation part tout de suite.
    let ecrit = FrameHeader::parse(
        sortie
            .get(..FRAME_HEADER_OCTETS)
            .and_then(|neuf| neuf.try_into().ok())
            .expect("neuf"),
    );
    assert_eq!(ecrit.kind(), FrameKind::RstStream);
    assert_eq!(ecrit.stream(), trop);
    assert_eq!(poses, FRAME_HEADER_OCTETS.saturating_add(CODE_OCTETS));
    assert_eq!(
        sortie.get(FRAME_HEADER_OCTETS..poses),
        Some(ErrorCode::RefusedStream.value().to_be_bytes().as_slice())
    );
}

/// Le refus n'a pas la place de s'écrire : c'est notre tampon, donc notre faute.
#[test]
fn un_refus_veut_de_la_place() {
    let mut connexion = ouverte();
    for tour in 0..crate::stream::MAX_CONCURRENT_STREAMS {
        ouvrir(&mut connexion, tour.saturating_mul(2).saturating_add(1));
    }
    let trop = crate::stream::MAX_CONCURRENT_STREAMS
        .saturating_mul(2)
        .saturating_add(1);
    let issue = connexion
        .receive(
            entete(FrameKind::Headers, END_HEADERS, trop, 0),
            &[],
            &mut [0_u8; 16],
            &mut [0_u8; 4],
        )
        .expect_err("pas la place");
    assert_eq!(issue.cause(), Cause::BufferTooSmall);
    assert_eq!(issue.code(), ErrorCode::InternalError);
}

/// **LES REMORQUES NE SONT PAS SERVIES**, et un `HEADERS` sur un flux fermé non
/// plus. Chacun annule son flux, et lui seul.
#[test]
fn un_second_headers_annule_son_flux() {
    let mut connexion = ouverte();
    ouvrir(&mut connexion, 1);

    let mut sortie = [0_u8; 64];
    let (evenement, poses) = connexion
        .receive(
            entete(FrameKind::Headers, END_HEADERS | END_STREAM, 1, 0),
            &[],
            &mut [0_u8; 16],
            &mut sortie,
        )
        .expect("des remorques");
    assert_eq!(
        evenement,
        Event::Head {
            stream: 1,
            octets: 0,
            end_stream: true,
            refused: Some(ErrorCode::ProtocolError),
        }
    );
    assert!(poses > 0, "une annulation part");
    // Le flux est fermé : il n'est plus dans la table.
    assert_eq!(connexion.streams().state(1), Some(StreamState::Closed));

    // Et sur ce flux désormais fermé, c'est `STREAM_CLOSED`.
    let (evenement, _) = connexion
        .receive(
            entete(FrameKind::Headers, END_HEADERS, 1, 0),
            &[],
            &mut [0_u8; 16],
            &mut sortie,
        )
        .expect("lu, puis jeté");
    assert!(matches!(
        evenement,
        Event::Head {
            refused: Some(ErrorCode::StreamClosed),
            ..
        }
    ));
}

/// Des données arrivent, la fenêtre descend, et le crédit repart quand elle est
/// tombée sous la moitié.
#[test]
fn les_donnees_consomment_puis_rechargent_les_deux_fenetres() {
    let mut connexion = ouverte();
    ouvrir(&mut connexion, 1);
    let mut sortie = [0_u8; 64];

    // Un premier cadre, loin du seuil : rien ne repart.
    let (evenement, poses) = connexion
        .receive(
            entete(FrameKind::Data, 0, 1, 4),
            &[1, 2, 3, 4],
            &mut [],
            &mut sortie,
        )
        .expect("des données");
    assert_eq!(
        evenement,
        Event::Data {
            stream: 1,
            payload: &[1, 2, 3, 4],
            end_stream: false,
        }
    );
    assert_eq!(poses, 0, "au-dessus du seuil, rien ne repart");
    assert_eq!(
        connexion.receive_window().available(),
        i64::from(INITIAL_WINDOW_SIZE) - 4
    );

    // Des cadres pleins, jusqu'à passer sous la moitié.
    let plein = connexion.settings().max_frame_size;
    let charge = [0_u8; 16_384];
    let (_, poses) = connexion
        .receive(
            entete(FrameKind::Data, 0, 1, plein),
            &charge,
            &mut [],
            &mut sortie,
        )
        .expect("un cadre plein");
    assert_eq!(poses, 0, "encore au-dessus du seuil");

    let (_, poses) = connexion
        .receive(
            entete(FrameKind::Data, 0, 1, plein),
            &charge,
            &mut [],
            &mut sortie,
        )
        .expect("celui-ci passe le seuil");
    assert_eq!(
        poses,
        2 * FRAME_HEADER_OCTETS.saturating_add(CODE_OCTETS),
        "un crédit pour la connexion, un pour le flux"
    );
    assert_eq!(
        connexion.receive_window().available(),
        i64::from(INITIAL_WINDOW_SIZE),
        "la fenêtre est pleine à nouveau"
    );
    let pour_la_connexion = FrameHeader::parse(
        sortie
            .get(..FRAME_HEADER_OCTETS)
            .and_then(|neuf| neuf.try_into().ok())
            .expect("neuf"),
    );
    assert_eq!(pour_la_connexion.kind(), FrameKind::WindowUpdate);
    assert_eq!(pour_la_connexion.stream(), 0);
    let pour_le_flux = FrameHeader::parse(
        sortie
            .get(13..22)
            .and_then(|neuf| neuf.try_into().ok())
            .expect("neuf"),
    );
    assert_eq!(pour_le_flux.kind(), FrameKind::WindowUpdate);
    assert_eq!(pour_le_flux.stream(), 1);
}

/// **UN FLUX FERMÉ NE SE RECHARGE PAS** : lui offrir du crédit serait promettre
/// ce qu'on ne tiendra pas.
#[test]
fn un_flux_ferme_ne_se_recharge_pas() {
    let mut connexion = ouverte();
    ouvrir(&mut connexion, 1);
    let mut sortie = [0_u8; 64];
    let plein = connexion.settings().max_frame_size;
    let charge = [0_u8; 16_384];
    for _ in 0..3_u8 {
        connexion
            .receive(
                entete(FrameKind::Data, 0, 1, plein),
                &charge,
                &mut [],
                &mut sortie,
            )
            .expect("des données");
    }
    // Le dernier cadre ferme le flux ET passe le seuil : seule la connexion se
    // recharge.
    let (_, poses) = connexion
        .receive(
            entete(FrameKind::Data, END_STREAM, 1, plein),
            &charge,
            &mut [],
            &mut sortie,
        )
        .expect("le dernier");
    connexion
        .receive(
            entete(FrameKind::RstStream, 0, 1, CODE_LONGUEUR),
            &[0; CODE_OCTETS],
            &mut [],
            &mut sortie,
        )
        .expect("annulé");
    assert!(poses > 0);
}

/// **TOUTE LA CHARGE COMPTE, REMPLISSAGE COMPRIS** (§6.9.1), et le `END_STREAM`
/// ferme le flux à la réception.
#[test]
fn le_remplissage_compte_dans_la_fenetre() {
    let mut connexion = ouverte();
    ouvrir(&mut connexion, 1);
    let charge = [3, 0xaa, 0, 0, 0];
    let (evenement, _) = connexion
        .receive(
            entete(FrameKind::Data, PADDED | END_STREAM, 1, 5),
            &charge,
            &mut [],
            &mut [0_u8; 64],
        )
        .expect("rempli");
    assert_eq!(
        evenement,
        Event::Data {
            stream: 1,
            payload: &[0xaa],
            end_stream: true,
        }
    );
    assert_eq!(
        connexion.receive_window().available(),
        i64::from(INITIAL_WINDOW_SIZE) - 5,
        "cinq, et non un"
    );
    assert_eq!(
        connexion.streams().state(1),
        Some(StreamState::HalfClosedRemote)
    );
}

/// Un `DATA` sur un flux OISIF condamne la connexion ; sur un flux FERMÉ, il ne
/// condamne que le flux.
#[test]
fn des_donnees_hors_d_un_flux_vivant() {
    let mut connexion = ouverte();
    let issue = connexion
        .receive(
            entete(FrameKind::Data, 0, 5, 1),
            &[0],
            &mut [],
            &mut [0_u8; 64],
        )
        .expect_err("oisif");
    assert_eq!(issue.cause(), Cause::WrongStreamState);
    assert!(issue.is_fatal(), "un flux oisif n'existe pas : §5.1");

    ouvrir(&mut connexion, 7);
    connexion
        .receive(
            entete(FrameKind::RstStream, 0, 7, CODE_LONGUEUR),
            &ErrorCode::Cancel.value().to_be_bytes(),
            &mut [],
            &mut [0_u8; 64],
        )
        .expect("annulé");
    let issue = connexion
        .receive(
            entete(FrameKind::Data, 0, 7, 1),
            &[0],
            &mut [],
            &mut [0_u8; 64],
        )
        .expect_err("fermé");
    assert_eq!(issue.code(), ErrorCode::StreamClosed);
    assert!(!issue.is_fatal(), "le flux seul est en cause");

    // Et sur le flux zéro, un `DATA` n'a pas de destinataire.
    let issue = connexion
        .receive(
            entete(FrameKind::Data, 0, 0, 1),
            &[0],
            &mut [],
            &mut [0_u8; 64],
        )
        .expect_err("sur la connexion");
    assert_eq!(issue.cause(), Cause::WrongStream);
}

/// **LA FENÊTRE DE LA CONNEXION SE DÉPASSE QUAND ON ANNONCE DE GRANDS CADRES.**
/// Avec les valeurs par défaut, un cadre ne peut pas la dépasser à lui seul —
/// c'est le réglage qu'on annonce qui décide.
#[test]
fn au_dela_de_la_fenetre_de_connexion_on_refuse() {
    let mut connexion = ouverte_avec(Settings {
        max_frame_size: 1_048_576,
        ..nos_reglages()
    });
    ouvrir(&mut connexion, 1);
    let issue = connexion
        .receive(
            entete(FrameKind::Data, 0, 1, INITIAL_WINDOW_SIZE.saturating_add(1)),
            &[],
            &mut [],
            &mut [0_u8; 64],
        )
        .expect_err("au-delà");
    assert_eq!(issue.cause(), Cause::WindowExceeded);
    assert_eq!(issue.code(), ErrorCode::FlowControlError);
}

/// **LA FENÊTRE D'UN FLUX EST LA NÔTRE, PAS CELLE DE LA CONNEXION.** Un pair qui
/// respecte l'une peut dépasser l'autre, et ce sont deux comptes séparés.
#[test]
fn au_dela_de_la_fenetre_d_un_flux_on_refuse() {
    let mut connexion = ouverte_avec(Settings {
        initial_window_size: 1_000,
        ..nos_reglages()
    });
    ouvrir(&mut connexion, 1);
    let issue = connexion
        .receive(
            entete(FrameKind::Data, 0, 1, 2_000),
            &[0_u8; 2_000],
            &mut [],
            &mut [0_u8; 64],
        )
        .expect_err("au-delà du flux, pas de la connexion");
    assert_eq!(issue.cause(), Cause::WindowExceeded);
}

/// Le crédit de recharge n'a pas la place de s'écrire.
#[test]
fn une_recharge_veut_de_la_place() {
    let mut connexion = ouverte_avec(Settings {
        initial_window_size: 1_000,
        ..nos_reglages()
    });
    ouvrir(&mut connexion, 1);
    // Le flux passe sous la moitié de SA fenêtre, et le crédit ne tient pas.
    let issue = connexion
        .receive(
            entete(FrameKind::Data, 0, 1, 600),
            &[0_u8; 600],
            &mut [],
            &mut [0_u8; 8],
        )
        .expect_err("pas la place");
    assert_eq!(issue.cause(), Cause::BufferTooSmall);
}

/// Un `WINDOW_UPDATE` crédite la connexion, un flux vivant, et s'ignore sur un
/// flux fermé (§6.9) — il a pu croiser notre annulation sur le fil.
#[test]
fn un_credit_va_ou_il_doit() {
    let mut connexion = ouverte();
    ouvrir(&mut connexion, 1);
    let mut sortie = [0_u8; 64];

    let mille = 1_000_u32.to_be_bytes();
    let (evenement, poses) = connexion
        .receive(
            entete(FrameKind::WindowUpdate, 0, 0, CODE_LONGUEUR),
            &mille,
            &mut [],
            &mut sortie,
        )
        .expect("du crédit pour la connexion");
    assert_eq!(evenement, Event::Nothing);
    assert_eq!(poses, 0);
    assert_eq!(
        connexion.send_window().available(),
        i64::from(INITIAL_WINDOW_SIZE) + 1_000
    );

    connexion
        .receive(
            entete(FrameKind::WindowUpdate, 0, 1, CODE_LONGUEUR),
            // Le bit de réserve est mis : il s'ignore.
            &0x8000_0064_u32.to_be_bytes(),
            &mut [],
            &mut sortie,
        )
        .expect("du crédit pour le flux");
    assert_eq!(
        connexion.streams().send_window(1).map(|f| f.available()),
        Some(i64::from(INITIAL_WINDOW_SIZE) + 100)
    );

    // Sur un flux fermé, il s'ignore.
    connexion
        .receive(
            entete(FrameKind::RstStream, 0, 1, CODE_LONGUEUR),
            &ErrorCode::Cancel.value().to_be_bytes(),
            &mut [],
            &mut sortie,
        )
        .expect("annulé");
    let cent = 100_u32.to_be_bytes();
    let (evenement, poses) = connexion
        .receive(
            entete(FrameKind::WindowUpdate, 0, 1, CODE_LONGUEUR),
            &cent,
            &mut [],
            &mut sortie,
        )
        .expect("il a croisé notre annulation");
    assert_eq!(evenement, Event::Nothing);
    assert_eq!(poses, 0);
}

/// Un crédit NUL est une faute — de connexion sur le flux zéro, de flux
/// ailleurs. Et un crédit sur un flux OISIF condamne la connexion.
#[test]
fn un_credit_fautif_se_refuse() {
    let mut connexion = ouverte();
    ouvrir(&mut connexion, 1);

    let issue = connexion
        .receive(
            entete(FrameKind::WindowUpdate, 0, 0, CODE_LONGUEUR),
            &[0; CODE_OCTETS],
            &mut [],
            &mut [0_u8; 64],
        )
        .expect_err("nul");
    assert_eq!(issue.cause(), Cause::ZeroWindowUpdate);
    assert!(issue.is_fatal(), "sur la connexion, c'est fatal");

    let issue = connexion
        .receive(
            entete(FrameKind::WindowUpdate, 0, 1, CODE_LONGUEUR),
            &[0; CODE_OCTETS],
            &mut [],
            &mut [0_u8; 64],
        )
        .expect_err("nul");
    assert_eq!(issue.cause(), Cause::ZeroWindowUpdate);
    assert!(
        !issue.is_fatal(),
        "sur un flux, la connexion n'a rien perdu"
    );

    let issue = connexion
        .receive(
            entete(FrameKind::WindowUpdate, 0, 9, CODE_LONGUEUR),
            &1_u32.to_be_bytes(),
            &mut [],
            &mut [0_u8; 64],
        )
        .expect_err("oisif");
    assert_eq!(issue.cause(), Cause::WrongStreamState);
    assert!(issue.is_fatal());

    // Une charge plus courte que ce que l'en-tête annonce.
    let issue = connexion
        .receive(
            entete(FrameKind::WindowUpdate, 0, 1, CODE_LONGUEUR),
            &[0; 2],
            &mut [],
            &mut [0_u8; 64],
        )
        .expect_err("tronquée");
    assert_eq!(issue.cause(), Cause::WrongFixedSize);

    // Et un crédit qui ferait déborder la fenêtre de la connexion.
    connexion
        .receive(
            entete(FrameKind::WindowUpdate, 0, 0, CODE_LONGUEUR),
            &0x7fff_ffff_u32.to_be_bytes(),
            &mut [],
            &mut [0_u8; 64],
        )
        .expect_err("2^31-1 de plus, cela déborde");
}

/// Une annulation ferme le flux et remonte le code du pair.
#[test]
fn une_annulation_ferme_le_flux() {
    let mut connexion = ouverte();
    ouvrir(&mut connexion, 1);

    let annule = ErrorCode::Cancel.value().to_be_bytes();
    let (evenement, poses) = connexion
        .receive(
            entete(FrameKind::RstStream, 0, 1, CODE_LONGUEUR),
            &annule,
            &mut [],
            &mut [0_u8; 64],
        )
        .expect("annulé");
    assert_eq!(
        evenement,
        Event::Reset {
            stream: 1,
            code: ErrorCode::Cancel,
        }
    );
    assert_eq!(poses, 0, "on ne répond pas à une annulation");
    assert_eq!(connexion.streams().state(1), Some(StreamState::Closed));

    // Sur un flux OISIF, §6.4 en fait une faute de connexion : annuler ce qui
    // n'a jamais commencé n'a pas de sens.
    let issue = connexion
        .receive(
            entete(FrameKind::RstStream, 0, 99, CODE_LONGUEUR),
            &[0; CODE_OCTETS],
            &mut [],
            &mut [0_u8; 64],
        )
        .expect_err("oisif");
    assert_eq!(issue.cause(), Cause::WrongStreamState);
    assert!(issue.is_fatal());

    // Une charge plus courte que ce que l'en-tête annonce.
    let issue = connexion
        .receive(
            entete(FrameKind::RstStream, 0, 1, CODE_LONGUEUR),
            &[0; 1],
            &mut [],
            &mut [0_u8; 64],
        )
        .expect_err("tronquée");
    assert_eq!(issue.cause(), Cause::WrongFixedSize);
}

/// **L'INONDATION DE CADRES DE SERVICE A SA BORNE** : ils ne font rien
/// progresser, et le contrôle de flux ne les voit pas.
#[test]
fn les_cadres_de_service_ont_leur_borne() {
    let mut connexion = ouverte();
    let mut sortie = [0_u8; 64];
    // Le `SETTINGS` d'ouverture en a déjà consommé un.
    for tour in 1..SERVICE_FRAMES_MAX {
        connexion
            .receive(
                entete(FrameKind::Ping, ACK, 0, PING_LONGUEUR),
                &[0; PING_OCTETS],
                &mut [],
                &mut sortie,
            )
            .unwrap_or_else(|erreur| panic!("tour {tour} : {erreur:?}"));
    }
    let issue = connexion
        .receive(
            entete(FrameKind::Ping, ACK, 0, PING_LONGUEUR),
            &[0; PING_OCTETS],
            &mut [],
            &mut sortie,
        )
        .expect_err("un de trop");
    assert_eq!(issue.cause(), Cause::TooManyServiceFrames);
    assert_eq!(issue.code(), ErrorCode::EnhanceYourCalm);
    assert!(issue.is_fatal());
}

/// **UN FLUX QUI PROGRESSE REMET LE COMPTEUR À ZÉRO** — mais pas le budget des
/// annulations, sans quoi *Rapid Reset* passerait au travers.
#[test]
fn un_flux_qui_progresse_remet_le_compteur_a_zero() {
    let mut connexion = ouverte();
    let mut sortie = [0_u8; 64];
    for _ in 0..SERVICE_FRAMES_MAX.saturating_sub(1) {
        connexion
            .receive(
                entete(FrameKind::Ping, ACK, 0, PING_LONGUEUR),
                &[0; PING_OCTETS],
                &mut [],
                &mut sortie,
            )
            .expect("sous la borne");
    }
    // Un `HEADERS` complet : voilà un progrès.
    ouvrir(&mut connexion, 1);
    // Et l'on peut recommencer.
    for _ in 0..SERVICE_FRAMES_MAX {
        connexion
            .receive(
                entete(FrameKind::Ping, ACK, 0, PING_LONGUEUR),
                &[0; PING_OCTETS],
                &mut [],
                &mut sortie,
            )
            .expect("le compteur est reparti de zéro");
    }
}

/// **LE BUDGET DE *RAPID RESET*** (CVE-2023-44487) : chaque `HEADERS` suivi d'un
/// `RST_STREAM` fait travailler le serveur sans jamais compter dans les flux
/// simultanés. Seul un budget que les RÉPONSES rechargent l'arrête.
#[test]
fn les_annulations_ont_leur_budget() {
    let mut connexion = ouverte();
    let mut sortie = [0_u8; 64];
    let annule = ErrorCode::Cancel.value().to_be_bytes();
    let mut annuler = |connexion: &mut Connection, id: u32| {
        connexion
            .receive(
                entete(FrameKind::RstStream, 0, id, CODE_LONGUEUR),
                &annule,
                &mut [],
                &mut sortie,
            )
            .map(|(_, poses)| poses)
    };
    for tour in 0..CANCELLATIONS_MAX {
        let id = tour.saturating_mul(2).saturating_add(1);
        ouvrir(&mut connexion, id);
        annuler(&mut connexion, id).unwrap_or_else(|erreur| panic!("tour {tour} : {erreur:?}"));
    }

    // Le suivant dépasse.
    let id = CANCELLATIONS_MAX.saturating_mul(2).saturating_add(1);
    ouvrir(&mut connexion, id);
    let issue = annuler(&mut connexion, id).expect_err("un de trop");
    assert_eq!(issue.cause(), Cause::TooManyCancellations);
    assert_eq!(issue.code(), ErrorCode::EnhanceYourCalm);
    assert!(issue.is_fatal());
}

/// **UNE RÉPONSE MENÉE À SON TERME REND UN JETON** : c'est la couture avec
/// l'étage qui émet, et sans elle une connexion longue tomberait sur des
/// annulations parfaitement légitimes.
#[test]
fn une_reponse_rend_un_jeton_d_annulation() {
    let mut connexion = ouverte();
    let mut sortie = [0_u8; 64];
    for tour in 0..CANCELLATIONS_MAX {
        let id = tour.saturating_mul(2).saturating_add(1);
        ouvrir(&mut connexion, id);
        connexion
            .receive(
                entete(FrameKind::RstStream, 0, id, CODE_LONGUEUR),
                &[0; CODE_OCTETS],
                &mut [],
                &mut sortie,
            )
            .expect("sous la borne");
        // Le compteur des cadres de service, lui, repart à chaque `HEADERS`.
        connexion.response_sent();
    }
    // Le budget a été rendu autant de fois qu'il a été pris : on peut continuer.
    let id = CANCELLATIONS_MAX.saturating_mul(2).saturating_add(1);
    ouvrir(&mut connexion, id);
    connexion
        .receive(
            entete(FrameKind::RstStream, 0, id, CODE_LONGUEUR),
            &[0; CODE_OCTETS],
            &mut [],
            &mut sortie,
        )
        .expect("le budget est plein");
}

/// La table dynamique HPACK vit sur la connexion, et c'est elle qu'on prête à
/// qui décode.
#[test]
fn la_table_hpack_vit_sur_la_connexion() {
    let mut connexion = ouverte();
    assert_eq!(connexion.decoder().table().len(), 0);
}

/// **UN CADRE QUE LE CADRAGE AURAIT REFUSÉ EST REFUSÉ ICI AUSSI.** Rien n'oblige
/// un appelant à passer par [`crate::FrameReader`], et une machine d'état qui
/// croirait l'en-tête sur parole accepterait n'importe quoi.
#[test]
fn la_machine_ne_croit_pas_l_entete_sur_parole() {
    let mut connexion = ouverte();
    let trop_long = connexion.settings().max_frame_size.saturating_add(1);
    let issue = connexion
        .receive(
            entete(FrameKind::Data, 0, 1, trop_long),
            &[],
            &mut [],
            &mut [0_u8; 64],
        )
        .expect_err("plus long que ce qu'on a annoncé");
    assert_eq!(issue.cause(), Cause::FrameTooLong);
}

/// Les réglages qu'on annonce se relisent tels qu'on les a écrits.
#[test]
fn nos_reglages_se_relisent() {
    let mut sortie = [0_u8; 256];
    let (_, poses) = Handshake::new(nos_reglages())
        .open(PREFACE, &mut sortie)
        .expect("ouvert");
    let charge = sortie
        .get(FRAME_HEADER_OCTETS..poses)
        .expect("la charge suit l'en-tête");
    let mut relus = Settings::DEFAULT;
    crate::settings::SettingsReader::apply_all(charge, &mut relus).expect("relisibles");
    assert_eq!(relus, nos_reglages());
    // `ENABLE_PUSH` à zéro : ce serveur ne pousse pas, et le dit.
    assert!(!relus.enable_push);
    assert_eq!(Setting::EnablePush.value(), 0x2);
}

/// **UNE RECHARGE DE ZÉRO NE S'ÉCRIT PAS.** §6.9 fait d'un `WINDOW_UPDATE` nul
/// une faute — et une fenêtre annoncée à zéro, ce qui est licite, mènerait tout
/// droit à en fabriquer un si l'on rechargeait sans regarder le crédit.
#[test]
fn une_recharge_nulle_ne_s_ecrit_pas() {
    let mut connexion = ouverte_avec(Settings {
        initial_window_size: 0,
        ..nos_reglages()
    });
    ouvrir(&mut connexion, 1);
    let (evenement, poses) = connexion
        .receive(
            entete(FrameKind::Data, 0, 1, 0),
            &[],
            &mut [],
            &mut [0_u8; 64],
        )
        .expect("un cadre vide, que la fenêtre nulle autorise");
    assert_eq!(
        evenement,
        Event::Data {
            stream: 1,
            payload: &[],
            end_stream: false,
        }
    );
    assert_eq!(poses, 0, "rien à rendre, donc aucun cadre");
}

/// **CHAQUE TYPE DE CADRE DE SERVICE COMPTE**, et pas seulement celui qu'on a
/// pensé à éprouver. Un seul type oublié suffirait à rouvrir l'inondation.
#[test]
fn tous_les_cadres_de_service_comptent() {
    let annule = ErrorCode::Cancel.value().to_be_bytes();
    let credit = 1_u32.to_be_bytes();
    let cas: [(FrameKind, u8, u32, u32, &[u8]); 7] = [
        (FrameKind::Settings, 0, 0, 0, &[]),
        (FrameKind::Ping, ACK, 0, PING_LONGUEUR, &[0; PING_OCTETS]),
        (FrameKind::GoAway, 0, 0, 8, &[0; GOAWAY_OCTETS]),
        (FrameKind::Priority, 0, 1, 5, &[0; PRIORITY_OCTETS]),
        (FrameKind::RstStream, 0, 1, CODE_LONGUEUR, &annule),
        (FrameKind::WindowUpdate, 0, 1, CODE_LONGUEUR, &credit),
        (FrameKind::Unknown(0x63), 0, 0, 0, &[]),
    ];
    for (kind, flags, flux, longueur, charge) in cas {
        let mut connexion = ouverte();
        ouvrir(&mut connexion, 1);
        let mut sortie = [0_u8; 64];
        // On amène le compteur à la borne, sans toucher aux flux.
        for _ in 0..SERVICE_FRAMES_MAX {
            connexion
                .receive(
                    entete(FrameKind::Ping, ACK, 0, PING_LONGUEUR),
                    &[0; PING_OCTETS],
                    &mut [],
                    &mut sortie,
                )
                .expect("sous la borne");
        }
        let issue = connexion
            .receive(
                entete(kind, flags, flux, longueur),
                charge,
                &mut [0_u8; 64],
                &mut sortie,
            )
            .expect_err("un de trop");
        assert_eq!(issue.cause(), Cause::TooManyServiceFrames, "{kind:?}");
    }
}

/// Un réglage hors de la plage de §6.5.2 condamne la connexion.
#[test]
fn un_reglage_hors_plage_se_refuse() {
    let mut connexion = ouverte();
    let issue = connexion
        .receive(
            entete(FrameKind::Settings, 0, 0, 6),
            // `MAX_FRAME_SIZE` à quarante-deux : §6.5.2 exige au moins 2^14.
            &[0, 5, 0, 0, 0, 42],
            &mut [],
            &mut [0_u8; 64],
        )
        .expect_err("hors plage");
    assert_eq!(issue.cause(), Cause::SettingValueOutOfRange);
}

/// Un crédit qui ferait déborder la fenêtre d'émission D'UN FLUX.
#[test]
fn un_credit_qui_deborde_un_flux_se_refuse() {
    let mut connexion = ouverte();
    ouvrir(&mut connexion, 1);
    let beaucoup = 0x7fff_0000_u32.to_be_bytes();
    connexion
        .receive(
            entete(FrameKind::WindowUpdate, 0, 1, CODE_LONGUEUR),
            &beaucoup,
            &mut [],
            &mut [0_u8; 64],
        )
        .expect("du crédit");
    let issue = connexion
        .receive(
            entete(FrameKind::WindowUpdate, 0, 1, CODE_LONGUEUR),
            &beaucoup,
            &mut [],
            &mut [0_u8; 64],
        )
        .expect_err("cela déborde");
    assert_eq!(issue.cause(), Cause::WindowOverflow);
}

/// **LE REMPLISSAGE QUI DÉBORDE DE SON CADRE SE REFUSE**, sur un `HEADERS`
/// comme sur un `DATA` : c'est la même règle de §6.1, et elle vaut des deux
/// côtés.
#[test]
fn un_remplissage_qui_deborde_se_refuse() {
    // Le premier octet annonce neuf octets de remplissage pour une charge de
    // trois.
    let mut connexion = ouverte();
    let issue = connexion
        .receive(
            entete(FrameKind::Headers, PADDED | END_HEADERS, 1, 3),
            &[9, 0, 0],
            &mut [0_u8; 64],
            &mut [0_u8; 64],
        )
        .expect_err("le remplissage déborde");
    assert_eq!(issue.cause(), Cause::PaddingTooLong);

    let mut connexion = ouverte();
    ouvrir(&mut connexion, 1);
    let issue = connexion
        .receive(
            entete(FrameKind::Data, PADDED, 1, 3),
            &[9, 0, 0],
            &mut [],
            &mut [0_u8; 64],
        )
        .expect_err("le remplissage déborde");
    assert_eq!(issue.cause(), Cause::PaddingTooLong);
}

/// L'accumulateur de blocs ne suffit pas : c'est notre tampon, donc notre faute.
#[test]
fn un_bloc_veut_de_la_place() {
    let mut connexion = ouverte();
    let issue = connexion
        .receive(
            entete(FrameKind::Headers, END_HEADERS, 1, 4),
            &[1, 2, 3, 4],
            &mut [0_u8; 2],
            &mut [0_u8; 64],
        )
        .expect_err("pas la place d'accumuler");
    assert_eq!(issue.cause(), Cause::BufferTooSmall);
}

/// La recharge de la CONNEXION n'a pas la place de s'écrire — et c'est une autre
/// recharge que celle du flux, sur une autre fenêtre.
#[test]
fn la_recharge_de_la_connexion_veut_de_la_place() {
    let mut connexion = ouverte();
    ouvrir(&mut connexion, 1);
    let plein = connexion.settings().max_frame_size;
    let charge = [0_u8; 16_384];
    let mut sortie = [0_u8; 64];
    connexion
        .receive(
            entete(FrameKind::Data, 0, 1, plein),
            &charge,
            &mut [],
            &mut sortie,
        )
        .expect("encore au-dessus du seuil");
    let issue = connexion
        .receive(
            entete(FrameKind::Data, 0, 1, plein),
            &charge,
            &mut [],
            &mut [0_u8; 8],
        )
        .expect_err("pas la place");
    assert_eq!(issue.cause(), Cause::BufferTooSmall);
}
