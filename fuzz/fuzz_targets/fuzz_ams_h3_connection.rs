// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : la machine de connexion HTTP/3** (§4.1, §5.2, §6.2, §7.2.4 de
//! RFC 9114).
//!
//! # Pourquoi celle-ci
//!
//! Tout ce qui est ici est une propriété d'ORDRE : elle ne tient pas dans un
//! appel, mais dans une suite d'appels quelconque. Les réglages avant tout, un
//! seul flux critique de chaque sorte, un `GOAWAY` qui ne remonte jamais, une
//! séquence de trames qui ne se rejoue pas — chacune se vérifie sur des
//! séquences, et un essai ne couvre que celles qu'on a imaginées.
//!
//! Et l'une d'elles protège contre une réexécution : réaccepter une requête
//! au-delà d'un `GOAWAY` qu'on a déjà dit ferait exécuter deux fois une requête
//! que le client a réémise ailleurs. Pour un serveur de courrier, cela veut dire
//! un message livré deux fois.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quelle que soit la suite d'événements.
//! 2. **AUCUNE TRAME NE PASSE AVANT LES RÉGLAGES** (§6.2.1) : tant qu'ils ne
//!    sont pas là, tout est refusé — et une fois là, ils ne reviennent plus.
//! 3. **UN SEUL FLUX CRITIQUE DE CHAQUE SORTE** (§6.2.1, §4.2 de RFC 9204) : le
//!    second se refuse toujours, et les trois comptes sont indépendants.
//! 4. **UN `GOAWAY` NE REMONTE JAMAIS**, ni celui qu'on reçoit ni celui qu'on
//!    émet (§5.2), et le nôtre reste sous la borne de §5.2.
//! 5. **CE QU'ON A REFUSÉ RESTE REFUSÉ** : une requête au-delà de notre `GOAWAY`
//!    ne redevient pas acceptable.
//! 6. **UN `MAX_PUSH_ID` NE RECULE JAMAIS** (§7.2.7).
//! 7. **LA SÉQUENCE DE §4.1 NE SE REJOUE PAS** : une fois la section terminale
//!    passée, plus aucune trame connue n'est acceptée, et un état ne recule
//!    jamais.
//! 8. **LE SERVICE SANS FIN FINIT PAR SE DIRE** : un pair qui n'envoie que des
//!    trames qui ne font rien avancer se voit refuser avant d'avoir dépassé la
//!    borne d'une unité.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_proto_h3::{
    Connection, FrameKind, GOAWAY_MAX, Message, MessageState, Reason, SERVICE_FRAMES_MAX, Settings,
    State, StreamKind,
};

/// Un événement de connexion.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum Evenement {
    /// Le pair ouvre un flux unidirectionnel.
    Flux(u8),
    /// Une trame arrive sur le flux de contrôle.
    Controle(u8, u64),
    /// Un flux critique se ferme.
    Fermeture,
    /// On s'éteint.
    Goaway(u64),
    /// Une requête arrive sur ce flux.
    Requete(u64),
    /// Une trame arrive sur le flux de requête courant.
    Trame(u8),
    /// Le flux de requête courant se termine.
    FinDeRequete,
}

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree {
    /// Ce qui arrive.
    evenements: [Evenement; 48],
}

/// Le type de flux que désigne un octet.
const fn flux(brut: u8) -> StreamKind {
    match brut % 5 {
        0 => StreamKind::Control,
        1 => StreamKind::Push,
        2 => StreamKind::QpackEncoder,
        3 => StreamKind::QpackDecoder,
        _ => StreamKind::Unknown(0x21),
    }
}

/// Le type de trame que désigne un octet.
const fn trame(brut: u8) -> FrameKind {
    match brut % 7 {
        0 => FrameKind::Data,
        1 => FrameKind::Headers,
        2 => FrameKind::CancelPush,
        3 => FrameKind::Settings,
        4 => FrameKind::GoAway,
        5 => FrameKind::MaxPushId,
        _ => FrameKind::Unknown(0x21),
    }
}

/// Le rang d'un état de message : il ne recule jamais.
const fn rang(etat: MessageState) -> u8 {
    match etat {
        MessageState::Attente => 0,
        MessageState::EnTetes => 1,
        MessageState::Corps => 2,
        MessageState::Fin => 3,
    }
}

fuzz_target!(|entree: Entree| {
    let mut connexion = Connection::new();
    let mut message = Message::new();
    let mut ouverts = [false; 3];
    let mut refuses = std::vec::Vec::new();
    let mut services = 0_u32;
    let mut rang_du_message = 0_u8;

    for evenement in entree.evenements {
        match evenement {
            Evenement::Flux(brut) => {
                let sorte = flux(brut);
                let issue = connexion.on_peer_stream(sorte);
                // PROPRIÉTÉ 3 : un seul de chaque sorte.
                let place = match sorte {
                    StreamKind::Control => Some(0),
                    StreamKind::QpackEncoder => Some(1),
                    StreamKind::QpackDecoder => Some(2),
                    StreamKind::Push | StreamKind::Unknown(_) => None,
                };
                match place {
                    Some(rang) => {
                        let deja = ouverts.get_mut(rang).expect("trois flux critiques");
                        assert_eq!(
                            issue.is_ok(),
                            !*deja,
                            "un second flux critique {sorte:?} est passé"
                        );
                        *deja = true;
                    }
                    // Ni la poussée ni l'inconnu ne s'acceptent, jamais.
                    None => assert!(issue.is_err(), "{sorte:?} est passé"),
                }
            }
            Evenement::Controle(brut, identifiant) => {
                let sorte = trame(brut);
                let reglages_avant = connexion.peer_settings();
                let goaway_avant = connexion.goaway_received();
                let plafond_avant = connexion.max_push_id();
                let issue = connexion.on_control_frame(sorte, Some(Settings::DEFAULT), identifiant);

                // PROPRIÉTÉ 2 : rien ne passe avant les réglages.
                if reglages_avant.is_none() && !matches!(sorte, FrameKind::Settings) {
                    assert_eq!(
                        issue.expect_err("avant les réglages").reason(),
                        Reason::MissingSettings,
                        "{sorte:?} est passée avant les réglages"
                    );
                }
                // Et ils ne se redisent pas.
                if reglages_avant.is_some() && matches!(sorte, FrameKind::Settings) {
                    assert_eq!(
                        issue.expect_err("les réglages redits").reason(),
                        Reason::RepeatedSettings
                    );
                }

                // PROPRIÉTÉ 4 : le `GOAWAY` reçu ne remonte jamais.
                if let (Some(avant), Some(apres)) = (goaway_avant, connexion.goaway_received()) {
                    assert!(apres <= avant, "un `GOAWAY` reçu est remonté");
                }
                // PROPRIÉTÉ 6 : le plafond de poussées ne recule jamais.
                if let (Some(avant), Some(apres)) = (plafond_avant, connexion.max_push_id()) {
                    assert!(apres >= avant, "le plafond de poussées a reculé");
                }

                // PROPRIÉTÉ 8 : le service se compte, et finit par se dire.
                let du_service = matches!(
                    sorte,
                    FrameKind::CancelPush | FrameKind::MaxPushId | FrameKind::Unknown(_)
                );
                if du_service && connexion.peer_settings().is_some() {
                    services = services.saturating_add(1);
                    assert!(
                        services <= SERVICE_FRAMES_MAX.saturating_add(1),
                        "{services} trames de service ont passé"
                    );
                }
            }
            Evenement::Fermeture => {
                assert_eq!(
                    connexion
                        .on_critical_stream_closed()
                        .expect_err("jamais acceptable")
                        .reason(),
                    Reason::CriticalStreamClosed
                );
            }
            Evenement::Goaway(identifiant) => {
                let avant = connexion.goaway_sent();
                let dit = connexion.goaway(identifiant);
                // PROPRIÉTÉ 4 : le nôtre non plus, et il reste sous la borne.
                assert!(dit <= GOAWAY_MAX, "notre `GOAWAY` dépasse la borne");
                if let Some(avant) = avant {
                    assert!(dit <= avant, "notre `GOAWAY` est remonté");
                }
                assert_eq!(connexion.goaway_sent(), Some(dit));
                assert_eq!(connexion.state(), State::Extinction);
            }
            Evenement::Requete(identifiant) => {
                // PROPRIÉTÉ 5 : ce qu'on a refusé reste refusé.
                if !connexion.accepts(identifiant) {
                    refuses.push(identifiant);
                }
                for refuse in &refuses {
                    assert!(
                        !connexion.accepts(*refuse),
                        "la requête {refuse} est redevenue acceptable"
                    );
                }
                message = Message::new();
                rang_du_message = 0;
            }
            Evenement::Trame(brut) => {
                let sorte = trame(brut);
                let avant = message.state();
                let issue = message.on_frame(sorte);
                // PROPRIÉTÉ 7 : après la section terminale, plus rien de connu.
                if matches!(avant, MessageState::Fin)
                    && matches!(sorte, FrameKind::Data | FrameKind::Headers)
                {
                    assert_eq!(
                        issue.expect_err("après la fin").reason(),
                        Reason::FrameOutOfOrder
                    );
                }
                // Et l'état ne recule jamais.
                let apres = rang(message.state());
                assert!(
                    apres >= rang_du_message,
                    "l'état du message est reculé de {rang_du_message} à {apres}"
                );
                rang_du_message = apres;
            }
            Evenement::FinDeRequete => {
                // Un message sans en-têtes n'en est pas un.
                assert_eq!(
                    message.on_end().is_ok(),
                    !matches!(message.state(), MessageState::Attente),
                    "la complétude et l'état ne s'accordent pas"
                );
            }
        }
    }
});
