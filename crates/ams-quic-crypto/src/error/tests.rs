// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une faute dit, et le code qu'elle porte.

use ams_proto_quic::TransportError;

use super::{Error, Reason};

/// Chaque raison porte son code, et se dit en français.
#[test]
fn chaque_raison_porte_son_code_et_se_dit() {
    let cas = [
        (
            Reason::NotAuthentic,
            TransportError::ProtocolViolation,
            "ne s'authentifie pas",
        ),
        (
            Reason::BufferTooSmall,
            TransportError::InternalError,
            "tampon de sortie",
        ),
        (
            Reason::TooShortToSample,
            TransportError::ProtocolViolation,
            "échantillon",
        ),
        (
            Reason::BadSecretLength,
            TransportError::InternalError,
            "longueur que la suite",
        ),
        (
            Reason::AeadLimitReached,
            TransportError::AeadLimitReached,
            "ce que la suite permet",
        ),
    ];
    for (raison, code, morceau) in cas {
        let faute = Error::new(raison);
        assert_eq!(faute.reason(), raison);
        assert_eq!(faute.code(), code, "{raison:?}");
        let dit = std::format!("{faute}");
        assert!(dit.contains(morceau), "{raison:?} dit « {dit} »");
        assert!(dit.contains("code 0x"), "{raison:?} ne dit pas son code");
    }
}
