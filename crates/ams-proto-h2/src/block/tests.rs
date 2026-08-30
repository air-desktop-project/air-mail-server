// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un bloc d'en-têtes a le droit d'être.

use super::{BLOCK_OCTETS_MAX, BlockState, CONTINUATIONS_MAX, HeaderBlock};
use crate::error::{Cause, ErrorCode};
use crate::frame::{FrameHeader, FrameKind};

/// `END_HEADERS`.
const FIN_ENTETES: u8 = 0x4;
/// `END_STREAM`.
const FIN_MESSAGE: u8 = 0x1;

/// Un en-tête de cadre.
fn cadre(kind: FrameKind, flags: u8, flux: u32, longueur: u32) -> FrameHeader {
    FrameHeader::new(kind, flags, flux, longueur)
}

/// Un bloc d'un seul cadre est complet tout de suite.
#[test]
fn un_bloc_d_un_seul_cadre_est_complet() {
    let mut bloc = HeaderBlock::new();
    let mut place = [0_u8; 64];
    assert!(!bloc.in_progress());
    assert_eq!(bloc.stream(), None);

    let etat = bloc
        .push(
            cadre(FrameKind::Headers, FIN_ENTETES | FIN_MESSAGE, 1, 3),
            b"abc",
            &mut place,
        )
        .expect("recevable");
    assert_eq!(etat, BlockState::Complete(3));
    assert_eq!(place.get(..3), Some(&b"abc"[..]));
    assert!(bloc.end_stream(), "le fanion vient du `HEADERS`");
    assert!(!bloc.in_progress(), "le bloc est refermé");
}

/// **`END_STREAM` EST SUR LE PREMIER CADRE, ET NULLE PART AILLEURS** : un
/// `CONTINUATION` n'en porte pas, et le lire sur le dernier ferait manquer la
/// fin de tous les messages dont le bloc s'étale.
#[test]
fn la_fin_de_message_vient_du_premier_cadre() {
    let mut bloc = HeaderBlock::new();
    let mut place = [0_u8; 64];
    bloc.push(
        cadre(FrameKind::Headers, FIN_MESSAGE, 1, 1),
        b"a",
        &mut place,
    )
    .expect("recevable");
    assert!(bloc.in_progress());
    assert_eq!(bloc.stream(), Some(1));
    assert!(bloc.end_stream());

    // Le `CONTINUATION` ne porte pas le fanion, et la fin reste vraie.
    let etat = bloc
        .push(
            cadre(FrameKind::Continuation, FIN_ENTETES, 1, 1),
            b"b",
            &mut place,
        )
        .expect("recevable");
    assert_eq!(etat, BlockState::Complete(2));
    assert_eq!(place.get(..2), Some(&b"ab"[..]));
    assert!(bloc.end_stream());
}

/// **RIEN NE S'INTERCALE DANS UN BLOC** (§4.3) : la table HPACK est mise à jour
/// dans l'ordre du bloc, et laisser un autre cadre s'y glisser rendrait cet
/// ordre dépendant de l'entrelacement.
#[test]
fn rien_ne_s_intercale_dans_un_bloc() {
    let mut bloc = HeaderBlock::new();
    let mut place = [0_u8; 64];
    bloc.push(cadre(FrameKind::Headers, 0, 1, 1), b"a", &mut place)
        .expect("recevable");

    for autre in [
        cadre(FrameKind::Data, 0, 1, 0),
        cadre(FrameKind::Ping, 0, 0, 8),
        cadre(FrameKind::Settings, 0, 0, 0),
        cadre(FrameKind::WindowUpdate, 0, 1, 4),
        // Même un `HEADERS` sur le même flux.
        cadre(FrameKind::Headers, FIN_ENTETES, 1, 0),
        // Et une `CONTINUATION` sur un AUTRE flux.
        cadre(FrameKind::Continuation, FIN_ENTETES, 3, 0),
    ] {
        let issue = bloc.accepts(autre).expect_err("refusé");
        assert_eq!(issue.cause(), Cause::BlockInterrupted, "{autre:?}");
        assert_eq!(issue.code(), ErrorCode::ProtocolError);
        assert!(issue.is_fatal(), "l'état HPACK est commun, et déjà perdu");
    }
    // La suite sur le bon flux passe.
    assert!(
        bloc.accepts(cadre(FrameKind::Continuation, FIN_ENTETES, 1, 0))
            .is_ok()
    );
}

/// **HORS BLOC, UNE `CONTINUATION` NE CONTINUE RIEN** (§6.10).
#[test]
fn une_continuation_orpheline_se_refuse() {
    let bloc = HeaderBlock::new();
    let issue = bloc
        .accepts(cadre(FrameKind::Continuation, FIN_ENTETES, 1, 0))
        .expect_err("refusé");
    assert_eq!(issue.cause(), Cause::BlockInterrupted);

    // Et après un bloc refermé, elle est orpheline de nouveau.
    let mut autre = HeaderBlock::new();
    let mut place = [0_u8; 64];
    autre
        .push(
            cadre(FrameKind::Headers, FIN_ENTETES, 1, 0),
            b"",
            &mut place,
        )
        .expect("recevable");
    assert!(
        autre
            .accepts(cadre(FrameKind::Continuation, FIN_ENTETES, 1, 0))
            .is_err()
    );
}

/// **DEUX BORNES, ET AUCUNE NE SUFFIT SEULE** : mille cadres d'un octet passent
/// sous une borne de taille, et un seul cadre énorme sous une borne de nombre.
/// C'est la faille dite « CONTINUATION flood ».
#[test]
fn le_flot_de_continuations_s_arrete_aux_deux_bornes() {
    // Par le NOMBRE : des cadres d'un octet, sans fin.
    let mut bloc = HeaderBlock::new();
    let mut place = [0_u8; BLOCK_OCTETS_MAX];
    bloc.push(cadre(FrameKind::Headers, 0, 1, 1), b"a", &mut place)
        .expect("recevable");
    for tour in 0..CONTINUATIONS_MAX {
        bloc.push(cadre(FrameKind::Continuation, 0, 1, 1), b"a", &mut place)
            .unwrap_or_else(|_| panic!("tour {tour}"));
    }
    let issue = bloc
        .push(cadre(FrameKind::Continuation, 0, 1, 1), b"a", &mut place)
        .expect_err("refusé");
    assert_eq!(issue.cause(), Cause::BlockTooLong);
    assert_eq!(issue.code(), ErrorCode::EnhanceYourCalm);
    assert!(issue.is_fatal());

    // Par la TAILLE : peu de cadres, mais énormes.
    let gros = std::vec![b'x'; BLOCK_OCTETS_MAX / 2];
    let mut autre = HeaderBlock::new();
    autre
        .push(cadre(FrameKind::Headers, 0, 1, 0), &gros, &mut place)
        .expect("le premier tient");
    autre
        .push(cadre(FrameKind::Continuation, 0, 1, 0), &gros, &mut place)
        .expect("le second remplit exactement");
    let issue = autre
        .push(cadre(FrameKind::Continuation, 0, 1, 0), b"x", &mut place)
        .expect_err("refusé");
    assert_eq!(issue.cause(), Cause::BlockTooLong);
}

/// Un accumulateur trop court le dit — c'est notre faute, pas celle du pair.
#[test]
fn un_accumulateur_trop_court_le_dit() {
    let mut bloc = HeaderBlock::new();
    let mut petit = [0_u8; 2];
    let issue = bloc
        .push(
            cadre(FrameKind::Headers, FIN_ENTETES, 1, 3),
            b"abc",
            &mut petit,
        )
        .expect_err("refusé");
    assert_eq!(issue.cause(), Cause::BufferTooSmall);
    assert_eq!(issue.code(), ErrorCode::InternalError);
}

/// Un type qui n'ouvre pas de bloc n'y a pas sa place non plus — et `push`
/// refuse par les DEUX chemins : celui d'`accepts`, et celui du classement.
#[test]
fn un_type_qui_n_ouvre_pas_de_bloc_se_refuse() {
    let mut bloc = HeaderBlock::new();
    let mut place = [0_u8; 64];
    // Hors bloc : `accepts` laisse passer un `DATA`, et c'est le classement qui
    // refuse — un `DATA` n'ouvre pas de bloc.
    let issue = bloc
        .push(cadre(FrameKind::Data, 0, 1, 1), b"a", &mut place)
        .expect_err("refusé");
    assert_eq!(issue.cause(), Cause::BlockInterrupted);

    // En cours de bloc : c'est `accepts` qui refuse, avant tout le reste.
    bloc.push(cadre(FrameKind::Headers, 0, 1, 1), b"a", &mut place)
        .expect("ouvert");
    let issue = bloc
        .push(cadre(FrameKind::Data, 0, 1, 1), b"b", &mut place)
        .expect_err("refusé");
    assert_eq!(issue.cause(), Cause::BlockInterrupted);
    assert!(bloc.in_progress(), "le bloc n'a pas été refermé");
    assert!(std::format!("{bloc:?}").contains("HeaderBlock"));
    assert!(std::format!("{:?}", BlockState::More).contains("More"));
}
