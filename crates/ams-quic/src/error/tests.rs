// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une faute dit, et si elle ferme ou non.

use ams_proto_quic::TransportError;

use super::{Error, Reason};

/// **UN PAQUET QU'ON JETTE N'A PAS DE CODE**, et une faute qui ferme en a un.
/// C'est la même question posée deux fois, et elle ne peut pas diverger.
#[test]
fn jeter_et_ne_pas_avoir_de_code_sont_la_meme_chose() {
    let cas = [
        (Reason::NotForUs, None, "sache lire"),
        (Reason::NotAuthentic, None, "s'authentifie pas"),
        (
            Reason::ReservedBitsSet,
            Some(TransportError::ProtocolViolation),
            "bits réservés",
        ),
        (
            Reason::BadPacketNumber,
            Some(TransportError::ProtocolViolation),
            "ne se reconstruit pas",
        ),
        (
            Reason::FlowControl,
            Some(TransportError::FlowControlError),
            "dépassé ce qu'on lui avait ouvert",
        ),
        (
            Reason::FinalSize,
            Some(TransportError::FinalSizeError),
            "taille finale d'un flux se contredit",
        ),
        (
            Reason::TooManyHoles,
            Some(TransportError::InternalError),
            "désordre qu'on ne retient pas",
        ),
        (
            Reason::SendClosed,
            Some(TransportError::InternalError),
            "un flux qui n'émet plus",
        ),
        (
            Reason::SendOverflow,
            Some(TransportError::InternalError),
            "au-delà de ce qui nous est ouvert",
        ),
        (
            Reason::StreamLimit,
            Some(TransportError::StreamLimitError),
            "plus de flux qu'on ne lui en a ouvert",
        ),
        (
            Reason::WrongStreamDirection,
            Some(TransportError::StreamStateError),
            "à contresens",
        ),
        (
            Reason::WindowTooSmall,
            Some(TransportError::InternalError),
            "la taille annoncée",
        ),
        // §8.3 et §4.1.3 de RFC 9001 : trois façons de parler mal entre les
        // niveaux de chiffrement, et la même sanction.
        (
            Reason::CryptoInZeroRtt,
            Some(TransportError::ProtocolViolation),
            "0-RTT",
        ),
        (
            Reason::CryptoAfterLevel,
            Some(TransportError::ProtocolViolation),
            "déjà dépassé",
        ),
        (
            Reason::CryptoNotConsumed,
            Some(TransportError::ProtocolViolation),
            "non lus",
        ),
        // **ET CELLE-CI N'EST PAS UNE FAUTE INTERNE** : la RFC lui a donné son
        // propre code, parce qu'il n'y a pas de contrôle de flux sur CRYPTO.
        (
            Reason::CryptoBufferExceeded,
            Some(TransportError::CryptoBufferExceeded),
            "hors d'ordre",
        ),
    ];
    for (raison, code, morceau) in cas {
        let faute = Error::new(raison);
        assert_eq!(faute.reason(), raison);
        assert_eq!(faute.code(), code, "{raison:?}");
        assert_eq!(
            faute.se_jette(),
            code.is_none(),
            "{raison:?} : jeter et n'avoir pas de code doivent coïncider"
        );
        let dit = std::format!("{faute}");
        assert!(dit.contains(morceau), "{raison:?} dit « {dit} »");
        // Et le message dit ce qu'on va faire du paquet.
        let suite = match faute.se_jette() {
            true => "on le jette",
            false => "on ferme",
        };
        assert!(dit.contains(suite), "{raison:?} ne dit pas la suite");
    }
}
