// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que les codes d'erreur disent.

use super::{Cause, Error, ErrorCode};

/// Les treize codes de §7 se lisent et se réécrivent.
#[test]
fn les_codes_se_lisent_et_se_reecrivent() {
    for (valeur, attendu) in [
        (0x0_u32, ErrorCode::NoError),
        (0x1, ErrorCode::ProtocolError),
        (0x2, ErrorCode::InternalError),
        (0x3, ErrorCode::FlowControlError),
        (0x4, ErrorCode::SettingsTimeout),
        (0x5, ErrorCode::StreamClosed),
        (0x6, ErrorCode::FrameSizeError),
        (0x7, ErrorCode::RefusedStream),
        (0x8, ErrorCode::Cancel),
        (0x9, ErrorCode::CompressionError),
        (0xa, ErrorCode::ConnectError),
        (0xb, ErrorCode::EnhanceYourCalm),
        (0xc, ErrorCode::InadequateSecurity),
        (0xd, ErrorCode::Http11Required),
    ] {
        assert_eq!(ErrorCode::from_wire(valeur), attendu, "{valeur:#x}");
        assert_eq!(attendu.value(), valeur, "{valeur:#x}");
    }
}

/// **UN CODE INCONNU DEVIENT `INTERNAL_ERROR`, ET NE FAIT PAS ÉCHOUER** (§7).
/// Le refuser ferait d'une extension une panne.
#[test]
fn un_code_inconnu_ne_fait_pas_echouer() {
    for valeur in [0xe_u32, 0xff, 1_000, u32::MAX] {
        assert_eq!(
            ErrorCode::from_wire(valeur),
            ErrorCode::InternalError,
            "{valeur:#x}"
        );
    }
}

/// **LA PORTÉE SE PORTE AVEC LA FAUTE.** Fermer la connexion pour une faute de
/// flux coupe des requêtes innocentes ; ne fermer qu'un flux pour une faute de
/// connexion laisse vivre un état faux.
#[test]
fn la_portee_se_porte_avec_la_faute() {
    let connexion = Error::connection(ErrorCode::ProtocolError, Cause::BadPreface);
    assert!(connexion.is_fatal());
    assert_eq!(connexion.code(), ErrorCode::ProtocolError);
    assert_eq!(connexion.cause(), Cause::BadPreface);

    let flux = Error::stream(ErrorCode::FrameSizeError, Cause::WrongFixedSize);
    assert!(!flux.is_fatal());
    assert_ne!(connexion, flux);
}

/// Chaque cause se dit, et le texte nomme la portée.
#[test]
fn chaque_cause_se_dit() {
    for (cause, extrait) in [
        (Cause::FrameTooLong, "dépasse"),
        (Cause::WrongFixedSize, "taille fixe"),
        (Cause::WrongStream, "sa place"),
        (Cause::PaddingTooLong, "déborde"),
        (Cause::PaddingNotZero, "n'est pas nul"),
        (Cause::SettingsNotAligned, "multiple de six"),
        (Cause::SettingsAckNotEmpty, "acquitté"),
        (Cause::SettingValueOutOfRange, "valeur exclue"),
        (Cause::BadPreface, "préambule"),
        (Cause::ZeroWindowUpdate, "WINDOW_UPDATE"),
        (Cause::BadInteger, "entier HPACK"),
        (Cause::BadString, "chaîne HPACK"),
        (Cause::BadHuffman, "Huffman"),
        (Cause::BufferTooSmall, "tampon de sortie"),
        (Cause::TableSizeTooLarge, "annoncé"),
        (Cause::BadIndex, "index HPACK"),
        (Cause::TableUpdateTooLate, "début d'un bloc"),
        (Cause::WindowExceeded, "fenêtre de contrôle"),
        (Cause::WindowOverflow, "deux gibioctets"),
        (Cause::BadStreamId, "numéro de flux"),
        (Cause::TooManyStreams, "de front"),
        (Cause::WrongStreamState, "dans cet état"),
        (Cause::BlockInterrupted, "intercalé"),
        (Cause::BlockTooLong, "bloc d'en-têtes dépasse"),
        (Cause::FirstFrameNotSettings, "premier cadre"),
        (Cause::PushFromClient, "poussé"),
        (Cause::TooManyServiceFrames, "progresser"),
        (Cause::TooManyCancellations, "annulés"),
    ] {
        let texte = std::format!("{}", Error::connection(ErrorCode::ProtocolError, cause));
        assert!(texte.contains(extrait), "{cause:?} : {texte}");
        assert!(texte.contains("connexion"), "{cause:?} : {texte}");
    }
    let sur_un_flux = std::format!("{}", Error::stream(ErrorCode::Cancel, Cause::WrongStream));
    assert!(sur_un_flux.contains("flux"), "{sur_un_flux}");
}
