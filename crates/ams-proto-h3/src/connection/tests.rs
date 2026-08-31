// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une connexion HTTP/3 a le droit de faire.

use super::{Connection, GOAWAY_MAX, Message, MessageState, SERVICE_FRAMES_MAX, State};
use crate::error::{H3Error, Reason};
use crate::frame::FrameKind;
use crate::settings::Settings;
use crate::stream::StreamKind;

/// Ouvre le flux de contrôle du pair et lui fait dire ses réglages.
fn ouverte() -> Connection {
    let mut connexion = Connection::new();
    connexion
        .on_peer_stream(StreamKind::Control)
        .expect("le premier flux de contrôle");
    connexion
        .on_control_frame(FrameKind::Settings, Some(Settings::DEFAULT), 0)
        .expect("les réglages d'abord");
    connexion
}

/// Une connexion neuve n'a rien entendu.
#[test]
fn une_connexion_neuve_n_a_rien_entendu() {
    let connexion = Connection::new();
    assert_eq!(connexion.state(), State::Ouverture);
    assert_eq!(connexion.peer_settings(), None);
    assert_eq!(connexion.max_push_id(), None);
    assert_eq!(connexion.goaway_sent(), None);
    assert_eq!(connexion.goaway_received(), None);
    assert!(connexion.accepts(0), "rien ne s'y oppose encore");
    assert_eq!(Connection::default(), connexion);
}

/// **IL N'Y A QU'UN FLUX CRITIQUE DE CHAQUE SORTE** (§6.2.1, §4.2 de RFC 9204) :
/// deux prétendraient décrire le même état, et rien ne dirait lequel croire.
#[test]
fn un_second_flux_critique_se_refuse() {
    for critique in [
        StreamKind::Control,
        StreamKind::QpackEncoder,
        StreamKind::QpackDecoder,
    ] {
        let mut connexion = Connection::new();
        connexion.on_peer_stream(critique).expect("le premier");
        let issue = connexion.on_peer_stream(critique).expect_err("le second");
        assert_eq!(
            issue.reason(),
            Reason::DuplicateCriticalStream,
            "{critique:?}"
        );
        assert_eq!(issue.code(), H3Error::StreamCreationError);
    }

    // Et les trois comptes sont séparés : ouvrir l'un n'empêche pas les autres.
    let mut connexion = Connection::new();
    for critique in [
        StreamKind::Control,
        StreamKind::QpackEncoder,
        StreamKind::QpackDecoder,
    ] {
        connexion.on_peer_stream(critique).expect("un de chaque");
    }
}

/// **UN FLUX DE POUSSÉE VIENT D'UN SERVEUR** (§6.2.2) : d'un client, c'est qu'il
/// s'est trompé de rôle, et la suite ne sera pas ce qu'on croit.
#[test]
fn un_flux_de_poussee_du_client_se_refuse() {
    let mut connexion = Connection::new();
    let issue = connexion
        .on_peer_stream(StreamKind::Push)
        .expect_err("le client ne pousse pas");
    assert_eq!(issue.reason(), Reason::PushRefused);
}

/// **UN TYPE INCONNU N'EST PAS UNE FAUTE DE CONNEXION** (§6.2) : on abandonne le
/// flux, et rien de plus — c'est ce qui permet à une extension d'ouvrir les
/// siens.
#[test]
fn un_type_inconnu_n_abandonne_que_son_flux() {
    let mut connexion = Connection::new();
    let issue = connexion
        .on_peer_stream(StreamKind::Unknown(0x21))
        .expect_err("on ne sait pas le conduire");
    assert_eq!(issue.reason(), Reason::UnknownStreamType);
    // La connexion, elle, n'a pas bougé.
    assert_eq!(connexion.state(), State::Ouverture);
    // Et un second du même type passe aussi mal, sans rien casser de plus.
    assert!(connexion.on_peer_stream(StreamKind::Unknown(0x21)).is_err());
    assert!(connexion.on_peer_stream(StreamKind::Control).is_ok());
}

/// **FERMER UN FLUX CRITIQUE EST UNE FAUTE, ET NON UN ADIEU** (§6.2.1).
#[test]
fn fermer_un_flux_critique_est_une_faute() {
    let connexion = ouverte();
    let issue = connexion
        .on_critical_stream_closed()
        .expect_err("jamais acceptable");
    assert_eq!(issue.reason(), Reason::CriticalStreamClosed);
    assert_eq!(issue.code(), H3Error::ClosedCriticalStream);
}

/// **LES RÉGLAGES ARRIVENT EN PREMIER, OU JAMAIS** (§6.2.1) : traiter une trame
/// avant de les connaître, c'est travailler sur des bornes qu'on ignore.
#[test]
fn les_reglages_arrivent_en_premier() {
    // **`ANY OTHER FRAME TYPE` NE FAIT PAS D'EXCEPTION** : même celles qui
    // n'avaient de toute façon pas leur place ici répondent `MISSING_SETTINGS`
    // tant qu'elles sont les premières.
    for avant in [
        FrameKind::GoAway,
        FrameKind::MaxPushId,
        FrameKind::CancelPush,
        FrameKind::Unknown(0x21),
        FrameKind::Data,
        FrameKind::Headers,
        FrameKind::PushPromise,
    ] {
        let mut connexion = Connection::new();
        let issue = connexion
            .on_control_frame(avant, None, 0)
            .expect_err("avant les réglages");
        assert_eq!(issue.reason(), Reason::MissingSettings, "{avant:?}");
        assert_eq!(issue.code(), H3Error::MissingSettings);
    }
}

/// **ET IL N'Y EN A QU'UN** (§7.2.4) : « it MUST NOT be sent subsequently ».
#[test]
fn un_second_settings_se_refuse() {
    let mut connexion = ouverte();
    assert_eq!(connexion.state(), State::Ouverte);
    assert_eq!(connexion.peer_settings(), Some(Settings::DEFAULT));

    let issue = connexion
        .on_control_frame(FrameKind::Settings, Some(Settings::DEFAULT), 0)
        .expect_err("le second");
    assert_eq!(issue.reason(), Reason::RepeatedSettings);
    assert_eq!(issue.code(), H3Error::FrameUnexpected);
}

/// Ce qui n'a pas sa place sur le flux de contrôle se refuse (§7.2).
#[test]
fn ce_qui_n_a_pas_sa_place_sur_le_controle_se_refuse() {
    let mut connexion = ouverte();
    for ailleurs in [FrameKind::Data, FrameKind::Headers, FrameKind::PushPromise] {
        let issue = connexion
            .on_control_frame(ailleurs, None, 0)
            .expect_err("pas ici");
        assert_eq!(issue.reason(), Reason::FrameOnWrongStream, "{ailleurs:?}");
    }
}

/// **UN `GOAWAY` QUI MONTE EST UNE FAUTE** (§5.2) : un client a pu réémettre
/// ailleurs les requêtes qu'un `GOAWAY` précédent avait déclarées perdues.
#[test]
fn un_goaway_qui_monte_se_refuse() {
    let mut connexion = ouverte();
    connexion
        .on_control_frame(FrameKind::GoAway, None, 100)
        .expect("le premier");
    assert_eq!(connexion.state(), State::Extinction);
    assert_eq!(connexion.goaway_received(), Some(100));

    // Plus bas : c'est l'extinction en deux temps que §5.2 décrit.
    connexion
        .on_control_frame(FrameKind::GoAway, None, 40)
        .expect("il descend");
    assert_eq!(connexion.goaway_received(), Some(40));
    // Le même : rien de neuf, et rien de faux.
    connexion
        .on_control_frame(FrameKind::GoAway, None, 40)
        .expect("le même");

    let issue = connexion
        .on_control_frame(FrameKind::GoAway, None, 41)
        .expect_err("il monte");
    assert_eq!(issue.reason(), Reason::GoAwayIncreased);
    assert_eq!(issue.code(), H3Error::IdError);
    assert_eq!(connexion.goaway_received(), Some(40), "rien n'a bougé");
}

/// **NOTRE `GOAWAY` NE MONTE PAS NON PLUS**, et c'est notre propre règle qu'on
/// tient : la violer ferait réexécuter chez nous des requêtes qu'un client a
/// déjà réémises ailleurs.
#[test]
fn notre_goaway_ne_monte_pas() {
    let mut connexion = ouverte();
    // §5.2 : d'abord le maximum, pour que le client cesse d'ouvrir.
    assert_eq!(connexion.goaway(u64::MAX), GOAWAY_MAX, "borné par §5.2");
    assert_eq!(connexion.state(), State::Extinction);
    // Puis le rang réel de ce qu'on servira.
    assert_eq!(connexion.goaway(40), 40);
    // Et une tentative plus haute redit ce qu'on avait dit.
    assert_eq!(connexion.goaway(9_000), 40);
    assert_eq!(connexion.goaway_sent(), Some(40));
}

/// **AU-DELÀ DE NOTRE `GOAWAY`, ON N'ACCEPTE PLUS** (§5.2) : « Requests with the
/// indicated identifier or greater are rejected by the sender of the GOAWAY. »
#[test]
fn au_dela_du_goaway_on_n_accepte_plus() {
    let mut connexion = ouverte();
    assert!(connexion.accepts(4_000), "rien ne s'y oppose encore");
    connexion.goaway(40);
    assert!(connexion.accepts(36));
    assert!(!connexion.accepts(40), "l'identifiant lui-même est refusé");
    assert!(!connexion.accepts(44));
}

/// **UN `MAX_PUSH_ID` QUI RECULE CONTREDIRAIT CE QU'IL A DÉJÀ AUTORISÉ**
/// (§7.2.7).
#[test]
fn un_max_push_id_qui_recule_se_refuse() {
    let mut connexion = ouverte();
    connexion
        .on_control_frame(FrameKind::MaxPushId, None, 10)
        .expect("le premier");
    assert_eq!(connexion.max_push_id(), Some(10));
    connexion
        .on_control_frame(FrameKind::MaxPushId, None, 20)
        .expect("il monte");
    assert_eq!(connexion.max_push_id(), Some(20));

    let issue = connexion
        .on_control_frame(FrameKind::MaxPushId, None, 19)
        .expect_err("il recule");
    assert_eq!(issue.reason(), Reason::PushRefused);
    assert_eq!(connexion.max_push_id(), Some(20), "rien n'a bougé");
}

/// **AUCUNE FENÊTRE NE BORNE LE FLUX DE CONTRÔLE** : §6.2.1 nous demande même de
/// lui donner assez de crédit pour qu'il ne bloque jamais. Un pair peut donc y
/// écrire du service sans fin, et c'est le seul compteur qui le voit.
#[test]
fn le_service_sans_fin_finit_par_se_dire() {
    let mut connexion = ouverte();
    for rang in 0..SERVICE_FRAMES_MAX {
        assert!(
            connexion
                .on_control_frame(FrameKind::CancelPush, None, 0)
                .is_ok(),
            "trame {rang}"
        );
    }
    let issue = connexion
        .on_control_frame(FrameKind::Unknown(0x21), None, 0)
        .expect_err("une de trop");
    assert_eq!(issue.reason(), Reason::ServiceFlood);
    assert_eq!(issue.code(), H3Error::ExcessiveLoad);
}

/// **SEUL UN PROGRÈS REMET LE COMPTEUR À ZÉRO** : un pair qui travaille peut
/// envoyer autant de service qu'il veut.
#[test]
fn un_progres_remet_le_compteur_a_zero() {
    let mut connexion = ouverte();
    for _ in 0..SERVICE_FRAMES_MAX {
        connexion
            .on_control_frame(FrameKind::CancelPush, None, 0)
            .expect("sous la borne");
    }
    connexion.progres();
    // Et l'on repart pour autant.
    for rang in 0..SERVICE_FRAMES_MAX {
        assert!(
            connexion
                .on_control_frame(FrameKind::CancelPush, None, 0)
                .is_ok(),
            "trame {rang}"
        );
    }
}

/// **UN `GOAWAY` NE COMPTE PAS COMME DU SERVICE** : il fait avancer la connexion
/// vers son extinction, ce qui est un progrès.
#[test]
fn un_goaway_n_est_pas_du_service() {
    let mut connexion = ouverte();
    for _ in 0..SERVICE_FRAMES_MAX {
        connexion
            .on_control_frame(FrameKind::CancelPush, None, 0)
            .expect("sous la borne");
    }
    // Celui-ci passe, alors que la borne est atteinte.
    connexion
        .on_control_frame(FrameKind::GoAway, None, 0)
        .expect("il fait avancer");
}

/// Un message neuf attend sa section d'en-têtes.
#[test]
fn un_message_neuf_attend_ses_en_tetes() {
    let message = Message::new();
    assert_eq!(message.state(), MessageState::Attente);
    assert_eq!(Message::default(), message);
}

/// **LA SÉQUENCE DE §4.1** : en-têtes, corps, section terminale.
#[test]
fn la_sequence_d_un_message_se_suit() {
    let mut message = Message::new();
    message.on_frame(FrameKind::Headers).expect("les en-têtes");
    assert_eq!(message.state(), MessageState::EnTetes);
    // §4.1 : la fin est possible dès les en-têtes — une requête sans corps.
    message.on_end().expect("un message sans corps");

    message.on_frame(FrameKind::Data).expect("le corps");
    assert_eq!(message.state(), MessageState::Corps);
    message
        .on_frame(FrameKind::Data)
        .expect("le corps continue");
    assert_eq!(message.state(), MessageState::Corps);

    message
        .on_frame(FrameKind::Headers)
        .expect("la section terminale");
    assert_eq!(message.state(), MessageState::Fin);
    message.on_end().expect("un message complet");
}

/// Une section terminale peut suivre les en-têtes sans corps entre les deux.
#[test]
fn la_section_terminale_peut_suivre_les_en_tetes() {
    let mut message = Message::new();
    message.on_frame(FrameKind::Headers).expect("les en-têtes");
    message.on_frame(FrameKind::Headers).expect("la terminale");
    assert_eq!(message.state(), MessageState::Fin);
}

/// **UN `DATA` AVANT LES EN-TÊTES** : §4.1 le nomme explicitement.
#[test]
fn un_corps_avant_les_en_tetes_se_refuse() {
    let mut message = Message::new();
    let issue = message
        .on_frame(FrameKind::Data)
        .expect_err("rien ne l'a ouvert");
    assert_eq!(issue.reason(), Reason::FrameOutOfOrder);
    assert_eq!(issue.code(), H3Error::FrameUnexpected);
    assert_eq!(message.state(), MessageState::Attente, "rien n'a bougé");
}

/// **RIEN NE SUIT LA SECTION TERMINALE**, §4.1 le nomme aussi.
#[test]
fn rien_ne_suit_la_section_terminale() {
    for apres in [FrameKind::Data, FrameKind::Headers] {
        let mut message = Message::new();
        message.on_frame(FrameKind::Headers).expect("les en-têtes");
        message.on_frame(FrameKind::Headers).expect("la terminale");
        let issue = message.on_frame(apres).expect_err("après la fin");
        assert_eq!(issue.reason(), Reason::FrameOutOfOrder, "{apres:?}");
    }
}

/// **UNE TRAME INCONNUE NE FAIT PAS AVANCER LA SÉQUENCE, ET NE LA ROMPT PAS**
/// (§4.1) : « before, after, or interleaved with other frames ».
#[test]
fn une_trame_inconnue_ne_change_rien() {
    let mut message = Message::new();
    message
        .on_frame(FrameKind::Unknown(0x21))
        .expect("avant tout");
    assert_eq!(message.state(), MessageState::Attente);

    message.on_frame(FrameKind::Headers).expect("les en-têtes");
    message
        .on_frame(FrameKind::Unknown(0x21))
        .expect("entre deux");
    assert_eq!(message.state(), MessageState::EnTetes);

    message.on_frame(FrameKind::Headers).expect("la terminale");
    message.on_frame(FrameKind::Unknown(0x21)).expect("après");
    assert_eq!(message.state(), MessageState::Fin);
}

/// Ce qui n'a pas sa place sur une requête se refuse (§7.2).
#[test]
fn ce_qui_n_a_pas_sa_place_sur_une_requete_se_refuse() {
    for ailleurs in [
        FrameKind::Settings,
        FrameKind::GoAway,
        FrameKind::MaxPushId,
        FrameKind::CancelPush,
        FrameKind::PushPromise,
    ] {
        let mut message = Message::new();
        let issue = message.on_frame(ailleurs).expect_err("pas ici");
        assert_eq!(issue.reason(), Reason::FrameOnWrongStream, "{ailleurs:?}");
    }
}

/// **UN MESSAGE SANS EN-TÊTES N'EST PAS UN MESSAGE** (§4.1), et cela ne condamne
/// que le flux : un client qui abandonne sa requête en route n'a pas cassé la
/// connexion.
#[test]
fn un_flux_qui_finit_sans_en_tetes_ne_fait_pas_un_message() {
    let message = Message::new();
    let issue = message.on_end().expect_err("rien n'est arrivé");
    assert_eq!(issue.reason(), Reason::IncompleteRequest);
    assert_eq!(issue.code(), H3Error::RequestIncomplete);
}
