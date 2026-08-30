// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un numéro de flux dit de lui-même.

use super::{Initiator, StreamId};
use crate::error::Reason;
use crate::frame::Directional;
use crate::varint::VARINT_MAX;

/// **LES QUATRE TYPES DE §2.1**, avec les numéros que la RFC leur donne.
#[test]
fn les_quatre_types_se_lisent_dans_deux_bits() {
    let cas = [
        (0_u64, Initiator::Client, Directional::Bidirectional),
        (1, Initiator::Server, Directional::Bidirectional),
        (2, Initiator::Client, Directional::Unidirectional),
        (3, Initiator::Server, Directional::Unidirectional),
    ];
    for (numero, qui, sens) in cas {
        let flux = StreamId::new(numero).expect("licite");
        assert_eq!(flux.initiator(), qui, "{numero}");
        assert_eq!(flux.directional(), sens, "{numero}");
        assert_eq!(flux.index(), 0, "{numero}");
        assert_eq!(flux.value(), numero);
        // Et le chemin inverse rend le même numéro.
        assert_eq!(
            StreamId::from_index(0, qui, sens).expect("licite"),
            flux,
            "{numero}"
        );
    }
}

/// **C'EST LE RANG QUE `MAX_STREAMS` BORNE, ET NON LE NUMÉRO** : §4.6 compte les
/// flux d'un type, et deux types ont leurs comptes séparés.
#[test]
fn le_rang_compte_par_type() {
    for rang in [0_u64, 1, 2, 1_000, (1 << 60) - 1] {
        for qui in [Initiator::Client, Initiator::Server] {
            for sens in [Directional::Bidirectional, Directional::Unidirectional] {
                let flux = StreamId::from_index(rang, qui, sens).expect("licite");
                assert_eq!(flux.index(), rang);
                assert_eq!(flux.initiator(), qui);
                assert_eq!(flux.directional(), sens);
            }
        }
    }
    // Le quatrième flux bidirectionnel du client porte le numéro douze.
    let flux =
        StreamId::from_index(3, Initiator::Client, Directional::Bidirectional).expect("licite");
    assert_eq!(flux.value(), 12);
}

/// **UN FLUX UNIDIRECTIONNEL NE VA QUE DANS UN SENS, ET C'EST LE SIEN** (§2.1).
#[test]
fn un_flux_unidirectionnel_ne_va_que_dans_un_sens() {
    let nous = Initiator::Server;

    // Un flux unidirectionnel ouvert par le CLIENT : il écrit, nous lisons.
    let du_client = StreamId::new(2).expect("licite");
    assert!(du_client.peer_can_send(nous));
    assert!(!du_client.we_can_send(nous), "on n'écrit pas dans le sien");

    // Un flux unidirectionnel ouvert par NOUS : nous écrivons, il lit.
    let de_nous = StreamId::new(3).expect("licite");
    assert!(!de_nous.peer_can_send(nous), "il n'écrit pas dans le nôtre");
    assert!(de_nous.we_can_send(nous));

    // Un flux bidirectionnel va dans les deux sens, quel qu'en soit l'auteur.
    for numero in [0_u64, 1] {
        let flux = StreamId::new(numero).expect("licite");
        assert!(flux.peer_can_send(nous), "{numero}");
        assert!(flux.we_can_send(nous), "{numero}");
    }

    // Et vu du client, les rôles s'échangent exactement.
    let nous = Initiator::Client;
    assert!(!du_client.peer_can_send(nous));
    assert!(du_client.we_can_send(nous));
    assert!(de_nous.peer_can_send(nous));
    assert!(!de_nous.we_can_send(nous));
}

/// **UN NUMÉRO DE FLUX EST UN ENTIER DE §16**, et n'a pas d'autre espace.
#[test]
fn au_dela_de_l_espace_on_refuse() {
    assert!(StreamId::new(VARINT_MAX).is_ok());
    for numero in [VARINT_MAX.saturating_add(1), u64::MAX] {
        let issue = StreamId::new(numero).expect_err("hors de l'espace");
        assert_eq!(issue.reason(), Reason::BadFrameField, "{numero}");
    }

    // Vu du rang, c'est la borne de 2^60 de §19.11.
    assert!(
        StreamId::from_index((1 << 60) - 1, Initiator::Client, Directional::Bidirectional).is_ok()
    );
    for rang in [1_u64 << 60, u64::MAX] {
        let issue = StreamId::from_index(rang, Initiator::Client, Directional::Bidirectional)
            .expect_err("hors de l'espace");
        assert_eq!(issue.reason(), Reason::BadFrameField, "{rang}");
    }
    // Un rang qui déborde la multiplication elle-même.
    let issue = StreamId::from_index(u64::MAX, Initiator::Server, Directional::Unidirectional)
        .expect_err("hors de l'espace");
    assert_eq!(issue.reason(), Reason::BadFrameField);
}

/// Les numéros se comparent, et l'ordre est celui du fil.
#[test]
fn les_numeros_s_ordonnent() {
    let un = StreamId::new(4).expect("licite");
    let deux = StreamId::new(8).expect("licite");
    assert!(un < deux);
    assert_eq!(un, StreamId::new(4).expect("licite"));
}
