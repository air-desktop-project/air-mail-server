// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un réglage HTTP/3 a le droit d'être.

use ams_proto_quic::varints;

use super::{DEFAULT_MAX_FIELD_SECTION_SIZE, Settings};
use crate::error::{H3Error, Reason};

/// Assemble une charge de `SETTINGS`.
fn charge(paires: &[(u64, u64)]) -> std::vec::Vec<u8> {
    let mut sortie = std::vec::Vec::new();
    for (identifiant, valeur) in paires {
        for nombre in [*identifiant, *valeur] {
            let mut place = [0_u8; 8];
            let ecrits = varints::encode(nombre, &mut place).expect("écrivable");
            sortie.extend_from_slice(place.get(..ecrits).unwrap_or_default());
        }
    }
    sortie
}

/// **ZÉRO EST LA VALEUR PAR DÉFAUT DE LA TABLE QPACK**, et ce n'est pas rien :
/// sans annonce, aucune table dynamique n'existe. C'est le contraire d'HPACK,
/// dont la table faisait quatre kibioctets d'office.
#[test]
fn les_defauts_sont_ceux_de_la_rfc() {
    let vides = Settings::read(&[]).expect("une charge vide est licite");
    assert_eq!(vides, Settings::DEFAULT);
    assert_eq!(vides, Settings::default());
    assert_eq!(vides.qpack_max_table_capacity, 0);
    assert_eq!(vides.qpack_blocked_streams, 0);
    assert_eq!(vides.max_field_section_size, None);
    assert_eq!(DEFAULT_MAX_FIELD_SECTION_SIZE, 16 * 1024);
}

/// Les trois réglages se lisent, et se réécrivent tels quels.
#[test]
fn les_trois_reglages_font_un_aller_retour() {
    let annonces = Settings {
        qpack_max_table_capacity: 4_096,
        qpack_blocked_streams: 16,
        max_field_section_size: Some(DEFAULT_MAX_FIELD_SECTION_SIZE),
    };
    let mut place = [0_u8; 64];
    let ecrits = annonces.write(&mut place).expect("écrivable");
    let relus = Settings::read(place.get(..ecrits).expect("écrit")).expect("relisible");
    assert_eq!(relus, annonces);

    // Sans taille annoncée, on écrit deux réglages au lieu de trois.
    let muets = Settings {
        max_field_section_size: None,
        ..annonces
    };
    let courts = muets.write(&mut place).expect("écrivable");
    assert!(courts < ecrits, "ce qu'on ne dit pas ne s'écrit pas");
    assert_eq!(
        Settings::read(place.get(..courts).expect("écrit")).expect("relisible"),
        muets
    );
}

/// **LES QUATRE IDENTIFIANTS D'HTTP/2 SONT UNE FAUTE** (§11.2.2) : les recevoir
/// veut dire qu'un pair croit parler HTTP/2, et que ce qu'il croit avoir négocié
/// ne sera pas ce qu'on a compris.
#[test]
fn les_reglages_d_http2_se_refusent() {
    for identifiant in Settings::RESERVES_PAR_HTTP2 {
        let brut = charge(&[(identifiant, 1)]);
        let issue = Settings::read(&brut).expect_err("réservé");
        assert_eq!(issue.reason(), Reason::BadSetting, "{identifiant:#x}");
        assert_eq!(issue.code(), H3Error::SettingsError);
    }
}

/// **CE QU'ON NE CONNAÎT PAS S'IGNORE** (§7.2.4.1), y compris les réglages de
/// graissage que la RFC demande d'envoyer.
#[test]
fn un_reglage_inconnu_s_ignore() {
    let brut = charge(&[
        (0x1f * 5 + 0x21, 0xdead),
        (0x01, 4_096),
        (0xffff, 1),
        (0x07, 8),
    ]);
    let lus = Settings::read(&brut).expect("lisible");
    assert_eq!(lus.qpack_max_table_capacity, 4_096, "rien n'a décalé");
    assert_eq!(lus.qpack_blocked_streams, 8);
}

/// **UN RÉGLAGE DEUX FOIS EST UNE FAUTE** (§7.2.4), y compris à l'identique.
#[test]
fn un_reglage_repete_se_refuse() {
    for identifiant in [0x01_u64, 0x06, 0x07] {
        let brut = charge(&[(identifiant, 1), (identifiant, 2)]);
        let issue = Settings::read(&brut).expect_err("répété");
        assert_eq!(issue.reason(), Reason::BadSetting, "{identifiant:#x}");
        // À l'identique aussi.
        let brut = charge(&[(identifiant, 1), (identifiant, 1)]);
        assert!(Settings::read(&brut).is_err(), "{identifiant:#x}");
    }
    // Mais trois réglages différents passent.
    let brut = charge(&[(0x01, 1), (0x06, 2), (0x07, 3)]);
    assert!(Settings::read(&brut).is_ok());
}

/// Une charge tronquée se refuse, sauf sur une frontière de réglage.
#[test]
fn une_charge_tronquee_se_refuse() {
    let un = charge(&[(0x01, 4_096)]);
    let entiere = charge(&[(0x01, 4_096), (0x07, 8)]);
    for coupure in 1..entiere.len() {
        let court = entiere.get(..coupure).expect("préfixe");
        let issue = Settings::read(court);
        match coupure == un.len() {
            true => assert!(issue.is_ok(), "la frontière {coupure} est une charge"),
            false => assert_eq!(
                issue.expect_err("tronquée").reason(),
                Reason::Truncated,
                "coupure {coupure}"
            ),
        }
    }
}

/// Un IDENTIFIANT de réglage tronqué, et non seulement sa valeur : le premier
/// octet annonce huit, et il n'y en a qu'un.
#[test]
fn un_identifiant_de_reglage_tronque_se_refuse() {
    let issue = Settings::read(&[0xc0]).expect_err("tronqué");
    assert_eq!(issue.reason(), Reason::Truncated);
}

/// La place manque à l'écriture, et c'est notre tampon.
#[test]
fn l_ecriture_veut_de_la_place() {
    let annonces = Settings {
        qpack_max_table_capacity: 4_096,
        qpack_blocked_streams: 16,
        max_field_section_size: Some(65_536),
    };
    let mut assez = [0_u8; 64];
    let complet = annonces.write(&mut assez).expect("écrivable");
    for taille in 0..complet {
        let mut court = [0_u8; 64];
        let issue = annonces
            .write(court.get_mut(..taille).expect("assez court"))
            .expect_err("la place manque");
        assert_eq!(issue.reason(), Reason::BufferTooSmall, "{taille}");
        assert_eq!(issue.code(), H3Error::InternalError);
    }
}
