// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une faute dit, et le code qu'elle porte.

use super::{Error, Reason, TransportError};

/// **LES DIX-SEPT CODES DE §20.1**, avec les valeurs que la RFC leur donne. Une
/// valeur fausse ferait fermer une connexion en donnant la mauvaise raison — et
/// le pair, lui, journaliserait cette raison-là.
#[test]
fn les_codes_sont_ceux_de_la_rfc() {
    let cas = [
        (TransportError::NoError, 0x00_u64),
        (TransportError::InternalError, 0x01),
        (TransportError::ConnectionRefused, 0x02),
        (TransportError::FlowControlError, 0x03),
        (TransportError::StreamLimitError, 0x04),
        (TransportError::StreamStateError, 0x05),
        (TransportError::FinalSizeError, 0x06),
        (TransportError::FrameEncodingError, 0x07),
        (TransportError::TransportParameterError, 0x08),
        (TransportError::ConnectionIdLimitError, 0x09),
        (TransportError::ProtocolViolation, 0x0a),
        (TransportError::InvalidToken, 0x0b),
        (TransportError::ApplicationError, 0x0c),
        (TransportError::CryptoBufferExceeded, 0x0d),
        (TransportError::KeyUpdateError, 0x0e),
        (TransportError::AeadLimitReached, 0x0f),
        (TransportError::NoViablePath, 0x10),
    ];
    for (code, valeur) in cas {
        assert_eq!(code.value(), valeur, "{code:?}");
    }
    // Et deux codes différents ne portent jamais la même valeur.
    for (rang, (code, valeur)) in cas.iter().enumerate() {
        for (autre, autre_valeur) in cas.get(rang.saturating_add(1)..).unwrap_or_default() {
            assert_ne!(valeur, autre_valeur, "{code:?} et {autre:?}");
        }
    }
}

/// **CHAQUE RAISON PORTE SON CODE**, et il ne se choisit pas à l'appel : une
/// même faute vue à deux endroits doit se dire pareil au pair.
#[test]
fn chaque_raison_porte_son_code() {
    let cas = [
        (Reason::Truncated, TransportError::FrameEncodingError),
        (
            Reason::BadPacketNumberLength,
            TransportError::FrameEncodingError,
        ),
        (Reason::VarintTooLarge, TransportError::InternalError),
        (Reason::BufferTooSmall, TransportError::InternalError),
        (Reason::PacketNumberTooLarge, TransportError::InternalError),
        (
            Reason::PacketNumberSpaceExhausted,
            TransportError::InternalError,
        ),
        (
            Reason::ConnectionIdTooLong,
            TransportError::ProtocolViolation,
        ),
        (Reason::NotAPacket, TransportError::ProtocolViolation),
        (Reason::UnknownFrame, TransportError::FrameEncodingError),
        (Reason::BadFrameField, TransportError::FrameEncodingError),
        (Reason::BadAckRange, TransportError::FrameEncodingError),
        (
            Reason::BadTransportParameter,
            TransportError::TransportParameterError,
        ),
    ];
    for (raison, code) in cas {
        let faute = Error::new(raison);
        assert_eq!(faute.reason(), raison);
        assert_eq!(faute.code(), code, "{raison:?}");
    }
}

/// Chaque faute se dit en français, et dit aussi son code — un journal qui ne
/// porte que « erreur de protocole » ne sert à personne.
#[test]
fn chaque_faute_se_dit() {
    let cas = [
        (Reason::Truncated, "ne sont pas tous là"),
        (Reason::VarintTooLarge, "§16 peut écrire"),
        (Reason::BufferTooSmall, "tampon de sortie"),
        (Reason::BadPacketNumberLength, "un à quatre"),
        (Reason::PacketNumberTooLarge, "numéro de paquet dépasse"),
        (Reason::PacketNumberSpaceExhausted, "espace des numéros"),
        (Reason::ConnectionIdTooLong, "identifiant de connexion"),
        (Reason::NotAPacket, "paquet QUIC"),
        (Reason::UnknownFrame, "négocié"),
        (Reason::BadFrameField, "champ de trame"),
        (Reason::BadAckRange, "acquittement"),
        (Reason::BadTransportParameter, "paramètre de transport"),
    ];
    for (raison, morceau) in cas {
        let dit = std::format!("{}", Error::new(raison));
        assert!(dit.contains(morceau), "{raison:?} dit « {dit} »");
        assert!(dit.contains("code 0x"), "{raison:?} ne dit pas son code");
    }
}
