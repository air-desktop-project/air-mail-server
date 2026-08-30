// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un réglage a le droit d'être.

use super::{Setting, Settings, SettingsReader};
use crate::error::{Cause, ErrorCode};

/// Compose une charge de `SETTINGS`.
fn charge(entrees: &[(u16, u32)]) -> std::vec::Vec<u8> {
    let mut octets = std::vec::Vec::new();
    for (identifiant, valeur) in entrees {
        octets.extend_from_slice(&identifiant.to_be_bytes());
        octets.extend_from_slice(&valeur.to_be_bytes());
    }
    octets
}

/// Les six réglages se lisent et se réécrivent.
#[test]
fn les_six_reglages_se_lisent() {
    for (identifiant, attendu) in [
        (0x1_u16, Setting::HeaderTableSize),
        (0x2, Setting::EnablePush),
        (0x3, Setting::MaxConcurrentStreams),
        (0x4, Setting::InitialWindowSize),
        (0x5, Setting::MaxFrameSize),
        (0x6, Setting::MaxHeaderListSize),
    ] {
        assert_eq!(Setting::from_wire(identifiant), Some(attendu));
        assert_eq!(attendu.value(), identifiant);
    }
}

/// **ON IGNORE CE QU'ON NE CONNAÎT PAS** (§6.5.2) : c'est ce qui permet aux
/// extensions d'exister.
#[test]
fn un_reglage_inconnu_s_ignore() {
    for identifiant in [0x0_u16, 0x7, 0x100, u16::MAX] {
        assert_eq!(Setting::from_wire(identifiant), None, "{identifiant:#x}");
    }
    // Et il ne fait pas échouer la lecture, même avec une valeur absurde.
    let mut reglages = Settings::DEFAULT;
    SettingsReader::apply_all(&charge(&[(0x99, u32::MAX)]), &mut reglages).expect("ignoré");
    assert_eq!(reglages, Settings::DEFAULT, "rien n'a bougé");
}

/// **ON REFUSE CE QU'ON CONNAÎT ET QUI EST FAUX**, avec le code que la RFC
/// nomme pour chacun.
#[test]
fn un_reglage_hors_plage_se_refuse() {
    for (identifiant, valeur, code) in [
        // §6.5.2 : autre chose que 0 ou 1 est un `PROTOCOL_ERROR`.
        (0x2_u16, 2_u32, ErrorCode::ProtocolError),
        (0x2, u32::MAX, ErrorCode::ProtocolError),
        // Au-delà de 2^31-1, `FLOW_CONTROL_ERROR`.
        (0x4, 0x8000_0000, ErrorCode::FlowControlError),
        (0x4, u32::MAX, ErrorCode::FlowControlError),
        // Hors de 2^14..=2^24-1, `PROTOCOL_ERROR`.
        (0x5, 16_383, ErrorCode::ProtocolError),
        (0x5, 0, ErrorCode::ProtocolError),
        (0x5, 16_777_216, ErrorCode::ProtocolError),
    ] {
        let mut reglages = Settings::DEFAULT;
        let issue = SettingsReader::apply_all(&charge(&[(identifiant, valeur)]), &mut reglages)
            .expect_err("refusé");
        assert_eq!(
            issue.cause(),
            Cause::SettingValueOutOfRange,
            "{identifiant:#x} {valeur}"
        );
        assert_eq!(issue.code(), code, "{identifiant:#x} {valeur}");
        assert!(issue.is_fatal());
    }
    // Les bornes exactes passent.
    for (identifiant, valeur) in [
        (0x2_u16, 0_u32),
        (0x2, 1),
        (0x4, 0x7fff_ffff),
        (0x5, 16_384),
        (0x5, 16_777_215),
        // Les trois autres acceptent tout.
        (0x1, u32::MAX),
        (0x3, u32::MAX),
        (0x6, u32::MAX),
    ] {
        let mut reglages = Settings::DEFAULT;
        assert!(
            SettingsReader::apply_all(&charge(&[(identifiant, valeur)]), &mut reglages).is_ok(),
            "{identifiant:#x} {valeur}"
        );
    }
}

/// Les valeurs se posent, et les défauts sont ceux de §6.5.2.
#[test]
fn les_valeurs_se_posent_sur_les_defauts() {
    assert_eq!(Settings::default(), Settings::DEFAULT);
    assert_eq!(Settings::DEFAULT.header_table_size, 4_096);
    const { assert!(Settings::DEFAULT.enable_push) };
    assert_eq!(Settings::DEFAULT.max_concurrent_streams, None);
    assert_eq!(Settings::DEFAULT.initial_window_size, 65_535);
    assert_eq!(Settings::DEFAULT.max_frame_size, 16_384);
    assert_eq!(Settings::DEFAULT.max_header_list_size, None);

    let mut reglages = Settings::DEFAULT;
    SettingsReader::apply_all(
        &charge(&[
            (0x1, 8_192),
            (0x2, 0),
            (0x3, 100),
            (0x4, 1_000_000),
            (0x5, 32_768),
            (0x6, 16_384),
        ]),
        &mut reglages,
    )
    .expect("recevables");
    assert_eq!(reglages.header_table_size, 8_192);
    assert!(!reglages.enable_push);
    assert_eq!(reglages.max_concurrent_streams, Some(100));
    assert_eq!(reglages.initial_window_size, 1_000_000);
    assert_eq!(reglages.max_frame_size, 32_768);
    assert_eq!(reglages.max_header_list_size, Some(16_384));
}

/// **LA DERNIÈRE VALEUR GAGNE** (§6.5) : un identifiant répété n'est pas une
/// faute, c'est un réglage posé deux fois.
#[test]
fn la_derniere_valeur_gagne() {
    let mut reglages = Settings::DEFAULT;
    SettingsReader::apply_all(&charge(&[(0x5, 20_000), (0x5, 30_000)]), &mut reglages)
        .expect("recevables");
    assert_eq!(reglages.max_frame_size, 30_000);
}

/// Une charge vide ne change rien, et n'est pas une faute.
#[test]
fn une_charge_vide_ne_change_rien() {
    let mut reglages = Settings::DEFAULT;
    SettingsReader::apply_all(b"", &mut reglages).expect("recevable");
    assert_eq!(reglages, Settings::DEFAULT);
    assert!(std::format!("{:?}", Setting::MaxFrameSize).contains("MaxFrameSize"));
}
