// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : la machine de connexion HTTP/2**, conduite par un flux de cadres
//! quelconque.
//!
//! # Pourquoi celle-ci
//!
//! Les étages du dessous ont chacun leur cible : le cadrage, HPACK, les blocs.
//! Chacun est juste PRIS SÉPARÉMENT. Ce qui casse, ce sont les jointures — un
//! `HEADERS` qui ouvre un flux que le bloc suivant refuse, un `SETTINGS` qui
//! déplace des fenêtres pendant qu'un `WINDOW_UPDATE` les crédite, un
//! `RST_STREAM` qui ferme un flux dont on accumule encore les en-têtes.
//!
//! Cette cible ne vérifie donc pas ce que chaque cadre fait, mais ce que la
//! connexion NE PEUT PAS DEVENIR, quelle que soit la suite reçue.
//!
//! # Les invariants
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **UNE FAUTE FATALE ARRÊTE TOUT.** Après elle, on ne présente plus rien :
//!    c'est le contrat de [`ams_proto_h2::Error::is_fatal`], et une machine qui
//!    continuerait travaillerait sur un état que le pair ne partage plus.
//! 3. **LES DEUX FENÊTRES DE LA CONNEXION RESTENT DANS LEURS BORNES**, jusqu'à
//!    2^31-1 par le haut. Celle de réception ne descend jamais sous zéro : c'est
//!    NOUS qui l'ouvrons, et rien ne peut nous la faire dépasser.
//! 4. **LA TABLE DES FLUX N'EXCÈDE JAMAIS CE QU'ON A ANNONCÉ**, et le plus grand
//!    numéro reçu ne recule jamais. Un numéro qui reculerait désignerait deux
//!    requêtes au même moment.
//! 5. **CE QU'ON ÉCRIT TIENT DANS LE TAMPON QU'ON A DONNÉ**, et se relit comme
//!    une suite de cadres entiers. Un octet de plus serait un débordement ; un
//!    cadre tronqué serait un pair qui ne peut plus nous lire.
//! 6. **UN BLOC RENDU COMPLET TIENT DANS L'ACCUMULATEUR.**
//! 7. **UN FLUX REFUSÉ EST FERMÉ**, et l'annulation part avec le bloc. Le
//!    laisser ouvert le compterait dans les flux simultanés sans que personne
//!    ne le serve jamais.
//! 8. **CE QU'ON ÉCRIT EN RÉPONSE RESPECTE CE QUE LE PAIR A ANNONCÉ** : jamais
//!    plus que sa taille de cadre, jamais plus que ses fenêtres. Un cadre qui
//!    les dépasserait serait traité par lui comme une faute de contrôle de
//!    flux — et il aurait raison.
//! 9. **UNE RÉPONSE ÉCRITE NE DÉBORDE PAS DE SON TAMPON**, et se relit comme
//!    une suite de cadres entiers.

#![no_main]

use libfuzzer_sys::fuzz_target;

use ams_proto_h2::{
    CODE_OCTETS, Event, FRAME_HEADER_OCTETS, FrameHeader, FrameKind, FrameReader, Handshake,
    MAX_CONCURRENT_STREAMS, Need, PREFACE, Settings, WINDOW_MAX,
};
use ams_proto_http::StatusCode;

/// L'accumulateur de blocs d'en-têtes.
const BLOC: usize = 16 * 1024;

/// Le tampon des réponses. Il doit tenir nos `SETTINGS`, un acquittement, un
/// `PING` renvoyé, deux crédits et une annulation — largement.
const SORTIE: usize = 256;

/// Ce que ce serveur annonce.
fn nos_reglages() -> Settings {
    Settings {
        max_concurrent_streams: Some(MAX_CONCURRENT_STREAMS),
        max_header_list_size: Some(16_384),
        enable_push: false,
        ..Settings::DEFAULT
    }
}

/// Relit ce qu'on a écrit : ce doit être une suite de cadres ENTIERS.
fn relire(ecrit: &[u8]) {
    let mut reste = ecrit;
    while !reste.is_empty() {
        let neuf: [u8; FRAME_HEADER_OCTETS] = match reste.get(..FRAME_HEADER_OCTETS) {
            Some(tete) => tete.try_into().expect("neuf octets"),
            None => panic!("un cadre tronqué : {} octets restants", reste.len()),
        };
        let entete = FrameHeader::parse(&neuf);
        let total = entete.total();
        assert!(
            total <= reste.len(),
            "un cadre annonce {total} octets, il en reste {}",
            reste.len()
        );
        reste = reste.get(total..).unwrap_or_default();
    }
}

/// Écrit une réponse complète, et vérifie que ce qui sort respecte ce que le
/// pair a annoncé.
fn repondre(connexion: &mut ams_proto_h2::Connection, stream: u32) {
    let mut sortie = [0_u8; SORTIE];
    let ok = StatusCode::new(200).expect("deux cents est un code licite");
    let champs: [(&[u8], &[u8]); 1] = [(b"content-type", b"application/json")];
    let Ok(poses) = connexion.write_head(stream, ok, &champs, false, &mut sortie) else {
        return;
    };
    verifier_sortie(connexion, sortie.get(..poses).unwrap_or_default());

    // Le corps part par morceaux, tant que les fenêtres en laissent passer.
    let corps = [b'x'; 4096];
    let mut reste = corps.as_slice();
    for _ in 0..8_u8 {
        let Ok((poses, pris)) = connexion.write_data(stream, reste, true, &mut sortie) else {
            return;
        };
        verifier_sortie(connexion, sortie.get(..poses).unwrap_or_default());
        if pris == 0 {
            // Fenêtre fermée : l'appelant attend un `WINDOW_UPDATE`.
            return;
        }
        reste = reste.get(pris..).unwrap_or_default();
        if reste.is_empty() {
            return;
        }
    }
}

/// Ce qu'on vient d'écrire respecte-t-il ce que le pair a annoncé ?
fn verifier_sortie(connexion: &ams_proto_h2::Connection, ecrit: &[u8]) {
    assert!(ecrit.len() <= SORTIE);
    relire(ecrit);
    let max = connexion.peer_settings().max_frame_size;
    let mut reste = ecrit;
    while !reste.is_empty() {
        let neuf: [u8; FRAME_HEADER_OCTETS] = reste
            .get(..FRAME_HEADER_OCTETS)
            .and_then(|tete| tete.try_into().ok())
            .expect("relire l'a déjà vérifié");
        let entete = FrameHeader::parse(&neuf);
        assert!(
            entete.length() <= max,
            "on a écrit un cadre de {} octets pour un maximum de {max}",
            entete.length()
        );
        assert!(
            connexion.send_window().available() >= 0,
            "la fenêtre d'émission de la connexion est passée sous zéro"
        );
        reste = reste.get(entete.total()..).unwrap_or_default();
    }
}

fuzz_target!(|donnees: &[u8]| {
    let mut sortie = [0_u8; SORTIE];
    let poignee = Handshake::new(nos_reglages());
    // Le préambule d'abord : sans lui, il n'y a pas de connexion — c'est dans le
    // type, et le fuzz ne peut pas l'oublier.
    let Ok((Some(mut connexion), poses)) = poignee.open(PREFACE, &mut sortie) else {
        return;
    };
    relire(sortie.get(..poses).unwrap_or_default());

    let mut bloc = [0_u8; BLOC];
    let mut reste = donnees;
    let mut dernier_flux = 0_u32;
    loop {
        let max = connexion.settings().max_frame_size;
        let Ok(Need::Complete(entete)) = FrameReader::poll(reste, max) else {
            return;
        };
        let total = entete.total();
        let cadre = match reste.get(..total) {
            Some(entier) => entier,
            None => return,
        };
        let charge = cadre.get(FRAME_HEADER_OCTETS..).unwrap_or_default();

        let issue = connexion.receive(entete, charge, &mut bloc, &mut sortie);
        let (evenement, poses) = match issue {
            Ok(rendu) => rendu,
            // **UNE FAUTE FATALE ARRÊTE TOUT** (invariant 2). Une faute de flux,
            // en revanche, ne condamne que lui : la connexion continue.
            Err(erreur) if erreur.is_fatal() => return,
            Err(_) => {
                reste = reste.get(total..).unwrap_or_default();
                continue;
            }
        };

        // 5. Ce qu'on écrit tient dans le tampon, et se relit.
        assert!(poses <= SORTIE, "on a écrit {poses} octets pour {SORTIE}");
        relire(sortie.get(..poses).unwrap_or_default());

        // 3. Les deux fenêtres de la connexion restent dans leurs bornes.
        let reception = connexion.receive_window().available();
        assert!(
            (0..=WINDOW_MAX).contains(&reception),
            "fenêtre de réception hors borne : {reception}"
        );
        assert!(
            connexion.send_window().available() <= WINDOW_MAX,
            "fenêtre d'émission au-delà de 2^31-1"
        );

        // 4. La table des flux tient ce qu'on a annoncé, et les numéros ne
        //    reculent pas.
        let flux = connexion.streams();
        assert!(
            flux.len() <= MAX_CONCURRENT_STREAMS,
            "{} flux ouverts pour {MAX_CONCURRENT_STREAMS} annoncés",
            flux.len()
        );
        assert!(
            flux.last_received() >= dernier_flux,
            "le plus grand numéro reçu a reculé"
        );
        dernier_flux = flux.last_received();

        match evenement {
            Event::Head {
                stream,
                octets,
                end_stream,
                refused,
            } => {
                // 6. Un bloc complet tient dans l'accumulateur.
                assert!(octets <= BLOC, "un bloc de {octets} octets pour {BLOC}");
                // 7. Un flux refusé est fermé, et son annulation part.
                if refused.is_some() {
                    assert_ne!(
                        flux.state(stream),
                        Some(ams_proto_h2::StreamState::Open),
                        "un flux refusé est resté ouvert"
                    );
                    assert!(
                        poses >= FRAME_HEADER_OCTETS.saturating_add(CODE_OCTETS),
                        "un flux refusé n'a pas envoyé son annulation"
                    );
                } else if end_stream {
                    // **ON RÉPOND, ET C'EST LÀ QUE L'ÉMISSION S'ÉPROUVE.** La
                    // requête est complète : le serveur écrirait sa réponse ici.
                    repondre(&mut connexion, stream);
                }
            }
            Event::Data { payload, .. } => {
                assert!(
                    payload.len() <= charge.len(),
                    "le remplissage ôté a rallongé la charge"
                );
            }
            Event::Nothing | Event::Reset { .. } | Event::GoAway { .. } => {}
        }

        // §4.1 : un type inconnu s'ignore, et ne fait donc rien écrire.
        if matches!(entete.kind(), FrameKind::Unknown(_)) {
            assert_eq!(poses, 0, "un type inconnu a fait répondre quelque chose");
        }

        reste = reste.get(total..).unwrap_or_default();
        if reste.is_empty() {
            return;
        }
    }
});
