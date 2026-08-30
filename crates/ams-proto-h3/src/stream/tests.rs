// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un flux unidirectionnel a le droit d'être.

use ams_proto_quic::varints;

use super::{StreamHead, StreamKind, accept_stream, read_stream_head};
use crate::error::{H3Error, Reason};

/// Les quatre types de §6.2 se lisent et se réécrivent.
#[test]
fn les_quatre_types_se_lisent_et_se_reecrivent() {
    let cas = [
        (0x00_u64, StreamKind::Control),
        (0x01, StreamKind::Push),
        (0x02, StreamKind::QpackEncoder),
        (0x03, StreamKind::QpackDecoder),
    ];
    for (identifiant, kind) in cas {
        assert_eq!(StreamKind::from_wire(identifiant), kind);
        assert_eq!(kind.value(), identifiant);
    }
}

/// **UN FLUX CRITIQUE NE SE FERME PAS** (§6.2.1) : la connexion n'aurait plus
/// par où s'entendre. La poussée, elle, n'a rien de critique.
#[test]
fn les_flux_critiques_sont_ceux_dont_la_connexion_depend() {
    assert!(StreamKind::Control.est_critique());
    assert!(StreamKind::QpackEncoder.est_critique());
    assert!(StreamKind::QpackDecoder.est_critique());
    assert!(!StreamKind::Push.est_critique());
    assert!(!StreamKind::Unknown(0x21).est_critique());
}

/// **UN TYPE PEUT S'ÉTALER SUR HUIT OCTETS**, et un flux QUIC les livre par
/// morceaux : refuser tant qu'ils ne sont pas tous là serait refuser un pair qui
/// n'a rien fait de mal.
#[test]
fn un_type_incomplet_se_rappelle_plus_tard() {
    // Un entier de huit octets, tronqué à chaque endroit.
    let mut entier = [0_u8; 8];
    let ecrits = varints::encode(0x1f_u64 * 3 + 0x21, &mut entier).expect("écrivable");
    let complet = entier.get(..ecrits).expect("écrit");
    for coupure in 0..complet.len() {
        let court = complet.get(..coupure).expect("préfixe");
        assert_eq!(
            read_stream_head(court),
            StreamHead::More,
            "coupure {coupure}"
        );
    }
    let StreamHead::Ready { kind, read } = read_stream_head(complet) else {
        panic!("il est complet");
    };
    assert_eq!(kind, StreamKind::Unknown(0x1f * 3 + 0x21));
    assert_eq!(read, ecrits);
}

/// **ON ABANDONNE LE FLUX, PAS LA CONNEXION** (§6.2) : c'est ce qui permet à une
/// extension d'ouvrir ses propres flux sans casser les pairs qui ne la
/// connaissent pas.
#[test]
fn un_type_inconnu_abandonne_son_flux() {
    for identifiant in [0x21_u64, 0x40, 1_000] {
        let kind = StreamKind::from_wire(identifiant);
        assert!(!kind.servi(), "{identifiant:#x}");
        assert_eq!(
            kind.value(),
            identifiant,
            "un inconnu garde son identifiant"
        );
        let issue = accept_stream(kind).expect_err("pas conduit");
        assert_eq!(
            issue.reason(),
            Reason::UnknownStreamType,
            "{identifiant:#x}"
        );
        assert_eq!(issue.code(), H3Error::StreamCreationError);
    }
}

/// **LA POUSSÉE N'EST PAS SERVIE, ET C'EST UNE DÉCISION.** Un flux de poussée
/// est ouvert par le SERVEUR : un client qui en ouvrirait un prétendrait pousser
/// vers nous.
#[test]
fn la_poussee_se_refuse_pour_ce_qu_elle_est() {
    let issue = accept_stream(StreamKind::Push).expect_err("refusée");
    assert_eq!(issue.reason(), Reason::PushRefused);
    assert_eq!(issue.code(), H3Error::IdError);
    assert!(!StreamKind::Push.servi());
}

/// Les trois flux qu'on conduit s'acceptent.
#[test]
fn les_trois_flux_qu_on_conduit_s_acceptent() {
    for kind in [
        StreamKind::Control,
        StreamKind::QpackEncoder,
        StreamKind::QpackDecoder,
    ] {
        assert!(kind.servi(), "{kind:?}");
        assert!(accept_stream(kind).is_ok(), "{kind:?}");
    }
}
