// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une faute dit, et le code qu'elle porte.

use super::{Error, H3Error, Reason};

/// **LES VINGT CODES DE §8.1 ET DE RFC 9204 §6**, avec les valeurs que les RFC
/// leur donnent. Une valeur fausse ferait fermer une connexion en donnant la
/// mauvaise raison — et le pair journaliserait celle-là.
#[test]
fn les_codes_sont_ceux_des_rfc() {
    let cas = [
        (H3Error::NoError, 0x0100_u64),
        (H3Error::GeneralProtocolError, 0x0101),
        (H3Error::InternalError, 0x0102),
        (H3Error::StreamCreationError, 0x0103),
        (H3Error::ClosedCriticalStream, 0x0104),
        (H3Error::FrameUnexpected, 0x0105),
        (H3Error::FrameError, 0x0106),
        (H3Error::ExcessiveLoad, 0x0107),
        (H3Error::IdError, 0x0108),
        (H3Error::SettingsError, 0x0109),
        (H3Error::MissingSettings, 0x010a),
        (H3Error::RequestRejected, 0x010b),
        (H3Error::RequestCancelled, 0x010c),
        (H3Error::RequestIncomplete, 0x010d),
        (H3Error::MessageError, 0x010e),
        (H3Error::ConnectError, 0x010f),
        (H3Error::VersionFallback, 0x0110),
        (H3Error::QpackDecompressionFailed, 0x0200),
        (H3Error::QpackEncoderStreamError, 0x0201),
        (H3Error::QpackDecoderStreamError, 0x0202),
    ];
    for (code, valeur) in cas {
        assert_eq!(code.value(), valeur, "{code:?}");
    }
    for (rang, (code, valeur)) in cas.iter().enumerate() {
        for (autre, autre_valeur) in cas.get(rang.saturating_add(1)..).unwrap_or_default() {
            assert_ne!(valeur, autre_valeur, "{code:?} et {autre:?}");
        }
    }
}

/// Chaque raison porte son code, et le dit en français.
#[test]
fn chaque_raison_porte_son_code_et_se_dit() {
    let cas = [
        (Reason::Truncated, H3Error::FrameError, "pas tous là"),
        (
            Reason::BufferTooSmall,
            H3Error::InternalError,
            "tampon de sortie",
        ),
        (
            Reason::ReservedH2Frame,
            H3Error::FrameUnexpected,
            "écarter HTTP/2",
        ),
        (
            Reason::FrameOnWrongStream,
            H3Error::FrameUnexpected,
            "flux qui ne peut pas la porter",
        ),
        (Reason::MalformedFrame, H3Error::FrameError, "mal formée"),
        (Reason::BadSetting, H3Error::SettingsError, "réservé"),
        (
            Reason::UnknownStreamType,
            H3Error::StreamCreationError,
            "type de flux",
        ),
        (Reason::PushRefused, H3Error::IdError, "poussée"),
        (
            Reason::BadInsertCount,
            H3Error::QpackDecompressionFailed,
            "compte d'insertions",
        ),
        (
            Reason::BadFieldLine,
            H3Error::QpackDecompressionFailed,
            "représentation de champ",
        ),
        (
            Reason::BadIndex,
            H3Error::QpackDecompressionFailed,
            "index qui ne désigne",
        ),
        (
            Reason::BadEncoderInstruction,
            H3Error::QpackEncoderStreamError,
            "instruction d'encodeur",
        ),
        (
            Reason::BadDecoderInstruction,
            H3Error::QpackDecoderStreamError,
            "instruction de décodeur",
        ),
        (
            Reason::DynamicTableRefused,
            H3Error::QpackEncoderStreamError,
            "table qu'on a annoncée nulle",
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
