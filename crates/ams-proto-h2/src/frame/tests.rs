// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un cadre a le droit d'être.

use super::{FRAME_HEADER_OCTETS, FrameHeader, FrameKind, FrameReader, Need, Padded};
use crate::error::{Cause, ErrorCode};

/// La taille de cadre par défaut.
const DEFAUT: u32 = 16_384;

/// Compose les neuf octets d'un en-tête.
fn entete(longueur: u32, kind: FrameKind, flags: u8, stream: u32) -> [u8; FRAME_HEADER_OCTETS] {
    FrameHeader::new(kind, flags, stream, longueur).write()
}

/// Les dix types se lisent et se réécrivent.
#[test]
fn les_types_se_lisent_et_se_reecrivent() {
    for (octet, attendu) in [
        (0x0_u8, FrameKind::Data),
        (0x1, FrameKind::Headers),
        (0x2, FrameKind::Priority),
        (0x3, FrameKind::RstStream),
        (0x4, FrameKind::Settings),
        (0x5, FrameKind::PushPromise),
        (0x6, FrameKind::Ping),
        (0x7, FrameKind::GoAway),
        (0x8, FrameKind::WindowUpdate),
        (0x9, FrameKind::Continuation),
    ] {
        assert_eq!(FrameKind::from_wire(octet), attendu, "{octet:#x}");
        assert_eq!(attendu.value(), octet, "{octet:#x}");
    }
    // **CE QU'ON NE CONNAÎT PAS GARDE SON OCTET** : il faudra le sauter, donc
    // savoir combien.
    for octet in [0xa_u8, 0x10, 0xff] {
        assert_eq!(FrameKind::from_wire(octet), FrameKind::Unknown(octet));
        assert_eq!(FrameKind::Unknown(octet).value(), octet);
    }
}

/// Les neuf octets se lisent et se réécrivent à l'identique.
#[test]
fn les_neuf_octets_se_lisent_et_se_reecrivent() {
    let brut = entete(16_000, FrameKind::Data, 0x1, 5);
    let lu = FrameHeader::parse(&brut);
    assert_eq!(lu.length(), 16_000);
    assert_eq!(lu.kind(), FrameKind::Data);
    assert_eq!(lu.stream(), 5);
    assert!(lu.flags().end_stream());
    assert_eq!(lu.total(), 16_009);
    assert_eq!(lu.write(), brut);

    // La plus grande longueur qui tienne sur vingt-quatre bits.
    let grand = FrameHeader::parse(&entete(0xff_ffff, FrameKind::Data, 0, 1));
    assert_eq!(grand.length(), 0xff_ffff);
    // Le plus grand numéro de flux qui tienne sur trente et un bits.
    let flux = FrameHeader::parse(&entete(0, FrameKind::Data, 0, 0x7fff_ffff));
    assert_eq!(flux.stream(), 0x7fff_ffff);
}

/// **LE BIT RÉSERVÉ EST IGNORÉ** (§4.1) : le refuser casserait une extension
/// future qui s'en servirait.
#[test]
fn le_bit_reserve_est_ignore() {
    let mut brut = entete(0, FrameKind::Data, 0, 5);
    // Le bit de poids fort du premier octet du numéro de flux.
    brut[5] |= 0x80;
    let lu = FrameHeader::parse(&brut);
    assert_eq!(lu.stream(), 5, "le bit réservé ne change pas le flux");
    // Et il ne se réécrit pas : on l'émet toujours à zéro.
    assert_eq!(lu.write()[5] & 0x80, 0);
}

/// **LE MÊME BIT NE VEUT PAS DIRE LA MÊME CHOSE SELON LE CADRE.**
#[test]
fn les_fanions_se_lisent_par_leur_bit() {
    let tous = FrameHeader::parse(&entete(0, FrameKind::Headers, 0x2d, 1)).flags();
    assert!(tous.end_stream(), "0x1");
    assert!(tous.ack(), "0x1, l'autre nom du même bit");
    assert!(tous.end_headers(), "0x4");
    assert!(tous.padded(), "0x8");
    assert!(tous.priority(), "0x20");
    assert_eq!(tous.bits(), 0x2d);

    let aucun = FrameHeader::parse(&entete(0, FrameKind::Headers, 0, 1)).flags();
    assert!(!aucun.end_stream());
    assert!(!aucun.ack());
    assert!(!aucun.end_headers());
    assert!(!aucun.padded());
    assert!(!aucun.priority());
}

/// **LA LONGUEUR D'ABORD, ET POUR TOUS LES TYPES** — un type inconnu n'en est
/// pas dispensé : ce qu'on ignore, il faut quand même le sauter.
#[test]
fn une_longueur_demesuree_se_refuse_meme_pour_un_type_inconnu() {
    for kind in [
        FrameKind::Data,
        FrameKind::Headers,
        FrameKind::Settings,
        FrameKind::Unknown(0x42),
    ] {
        let trop = FrameHeader::new(kind, 0, 1, DEFAUT.saturating_add(1));
        let issue = trop.check(DEFAUT).expect_err("refusé");
        assert_eq!(issue.cause(), Cause::FrameTooLong, "{kind:?}");
        assert_eq!(issue.code(), ErrorCode::FrameSizeError, "{kind:?}");
        assert!(issue.is_fatal(), "{kind:?}");
    }
    // La borne exacte passe.
    assert!(
        FrameHeader::new(FrameKind::Data, 0, 1, DEFAUT)
            .check(DEFAUT)
            .is_ok()
    );
}

/// Les cadres de taille fixe ont leur taille, et rien d'autre.
#[test]
fn les_cadres_de_taille_fixe_ont_leur_taille() {
    for (kind, attendue, flux) in [
        (FrameKind::Priority, 5_u32, 1_u32),
        (FrameKind::RstStream, 4, 1),
        (FrameKind::Ping, 8, 0),
        (FrameKind::WindowUpdate, 4, 0),
    ] {
        assert!(
            FrameHeader::new(kind, 0, flux, attendue)
                .check(DEFAUT)
                .is_ok(),
            "{kind:?}"
        );
        for fausse in [attendue.saturating_sub(1), attendue.saturating_add(1), 0] {
            if fausse == attendue {
                continue;
            }
            let issue = FrameHeader::new(kind, 0, flux, fausse)
                .check(DEFAUT)
                .expect_err("refusé");
            assert_eq!(issue.cause(), Cause::WrongFixedSize, "{kind:?} {fausse}");
        }
    }
}

/// **CHAQUE CADRE A SA PLACE** : sur un flux, ou sur la connexion, jamais les
/// deux — sauf `WINDOW_UPDATE`, que §6.9 admet des deux côtés.
#[test]
fn chaque_cadre_a_sa_place() {
    for kind in [
        FrameKind::Data,
        FrameKind::Headers,
        FrameKind::PushPromise,
        FrameKind::Continuation,
        FrameKind::Priority,
        FrameKind::RstStream,
    ] {
        let longueur = match kind {
            FrameKind::Priority => 5,
            FrameKind::RstStream => 4,
            _ => 0,
        };
        let issue = FrameHeader::new(kind, 0, 0, longueur)
            .check(DEFAUT)
            .expect_err("un flux est exigé");
        assert_eq!(issue.cause(), Cause::WrongStream, "{kind:?}");
        assert!(FrameHeader::new(kind, 0, 1, longueur).check(DEFAUT).is_ok());
    }
    for (kind, longueur) in [
        (FrameKind::Settings, 0_u32),
        (FrameKind::Ping, 8),
        (FrameKind::GoAway, 8),
    ] {
        let issue = FrameHeader::new(kind, 0, 1, longueur)
            .check(DEFAUT)
            .expect_err("la connexion est exigée");
        assert_eq!(issue.cause(), Cause::WrongStream, "{kind:?}");
        assert!(FrameHeader::new(kind, 0, 0, longueur).check(DEFAUT).is_ok());
    }
    // `WINDOW_UPDATE` vaut des deux côtés.
    assert!(
        FrameHeader::new(FrameKind::WindowUpdate, 0, 0, 4)
            .check(DEFAUT)
            .is_ok()
    );
    assert!(
        FrameHeader::new(FrameKind::WindowUpdate, 0, 7, 4)
            .check(DEFAUT)
            .is_ok()
    );
    // Un type inconnu n'a pas de place imposée : on l'ignore, quel que soit le
    // flux.
    assert!(
        FrameHeader::new(FrameKind::Unknown(0x42), 0, 0, 3)
            .check(DEFAUT)
            .is_ok()
    );
    assert!(
        FrameHeader::new(FrameKind::Unknown(0x42), 0, 9, 3)
            .check(DEFAUT)
            .is_ok()
    );
}

/// Un `SETTINGS` porte des entrées de six octets, et un `SETTINGS` acquitté n'en
/// porte aucune.
#[test]
fn un_settings_se_compte_par_six() {
    assert!(
        FrameHeader::new(FrameKind::Settings, 0, 0, 0)
            .check(DEFAUT)
            .is_ok()
    );
    assert!(
        FrameHeader::new(FrameKind::Settings, 0, 0, 12)
            .check(DEFAUT)
            .is_ok()
    );
    for fausse in [1_u32, 5, 7, 11] {
        let issue = FrameHeader::new(FrameKind::Settings, 0, 0, fausse)
            .check(DEFAUT)
            .expect_err("refusé");
        assert_eq!(issue.cause(), Cause::SettingsNotAligned, "{fausse}");
    }
    // Acquitté et vide : bon. Acquitté et non vide : faute.
    assert!(
        FrameHeader::new(FrameKind::Settings, 0x1, 0, 0)
            .check(DEFAUT)
            .is_ok()
    );
    let issue = FrameHeader::new(FrameKind::Settings, 0x1, 0, 6)
        .check(DEFAUT)
        .expect_err("refusé");
    assert_eq!(issue.cause(), Cause::SettingsAckNotEmpty);
}

/// **LE DÉCOUPAGE REFUSE DÈS QUE L'EN-TÊTE EST LÀ**, sans attendre la charge :
/// un cadre qui annonce seize mébioctets n'a pas à être accumulé.
#[test]
fn le_decoupage_refuse_avant_d_accumuler() {
    let trop = entete(DEFAUT.saturating_add(1), FrameKind::Data, 0, 1);
    let issue = FrameReader::poll(&trop, DEFAUT).expect_err("refusé");
    assert_eq!(issue.cause(), Cause::FrameTooLong);
    assert_eq!(trop.len(), FRAME_HEADER_OCTETS, "l'en-tête a suffi");
}

/// Le découpage suit un tampon qui croît.
#[test]
fn le_decoupage_suit_un_tampon_qui_croit() {
    let mut cadre = std::vec::Vec::from(&entete(4, FrameKind::Data, 0, 1)[..]);
    cadre.extend_from_slice(b"abcd");
    for vus in 0..cadre.len() {
        assert_eq!(
            FrameReader::poll(cadre.get(..vus).unwrap_or_default(), DEFAUT),
            Ok(Need::More),
            "{vus} octets"
        );
    }
    let Ok(Need::Complete(entier)) = FrameReader::poll(&cadre, DEFAUT) else {
        panic!("le cadre est entier");
    };
    assert_eq!(entier.total(), cadre.len());
    // Ce qui suit ne le regarde pas.
    cadre.extend_from_slice(b"la suite");
    assert_eq!(
        FrameReader::poll(&cadre, DEFAUT),
        Ok(Need::Complete(entier))
    );
}

/// Le remplissage se retire, et ses deux fautes se distinguent.
#[test]
fn le_remplissage_se_retire() {
    // Sans fanion, la charge est la charge.
    let nu = Padded::strip(b"abc", false).expect("sans remplissage");
    assert_eq!(nu.data(), b"abc");

    // Avec fanion : un octet de longueur, la donnée, puis des zéros.
    let avec = Padded::strip(b"\x02abc\x00\x00", true).expect("avec remplissage");
    assert_eq!(avec.data(), b"abc");

    // Un remplissage de zéro octet est licite.
    assert_eq!(Padded::strip(b"\x00abc", true).expect("nul").data(), b"abc");
    // Et une charge qui n'est QUE du remplissage aussi.
    assert_eq!(
        Padded::strip(b"\x02\x00\x00", true).expect("tout").data(),
        b""
    );
}

/// **DEUX FAUTES DIFFÉRENTES, ET LA SECONDE EST UN CHOIX** : §6.1 n'oblige pas
/// à vérifier que le remplissage est nul. On le vérifie — des octets qu'un pair
/// choisit et qu'on ne regarde pas sont un canal caché, et C7 tranche.
#[test]
fn un_remplissage_fautif_se_refuse() {
    // Plus long que ce qui reste.
    for charge in [&b"\x05ab"[..], b"\x01", b""] {
        let issue = Padded::strip(charge, true).expect_err("refusé");
        assert_eq!(issue.cause(), Cause::PaddingTooLong, "{charge:?}");
        assert_eq!(issue.code(), ErrorCode::ProtocolError);
    }
    // Non nul.
    let issue = Padded::strip(b"\x02abc\x00\x01", true).expect_err("refusé");
    assert_eq!(issue.cause(), Cause::PaddingNotZero);
}
