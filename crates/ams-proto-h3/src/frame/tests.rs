// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une trame HTTP/3 a le droit d'être.

use ams_proto_quic::varints;

use super::{FrameHeader, FrameKind, Placement, write_header};
use crate::error::{H3Error, Reason};

/// Assemble un en-tête de trame.
fn entete(identifiant: u64, longueur: u64) -> std::vec::Vec<u8> {
    let mut sortie = std::vec::Vec::new();
    for nombre in [identifiant, longueur] {
        let mut place = [0_u8; 8];
        let ecrits = varints::encode(nombre, &mut place).expect("écrivable");
        sortie.extend_from_slice(place.get(..ecrits).unwrap_or_default());
    }
    sortie
}

/// Les sept types que §7.2 définit se lisent et se réécrivent.
#[test]
fn les_sept_types_se_lisent_et_se_reecrivent() {
    let cas = [
        (0x00_u64, FrameKind::Data),
        (0x01, FrameKind::Headers),
        (0x03, FrameKind::CancelPush),
        (0x04, FrameKind::Settings),
        (0x05, FrameKind::PushPromise),
        (0x07, FrameKind::GoAway),
        (0x0d, FrameKind::MaxPushId),
    ];
    for (identifiant, kind) in cas {
        assert_eq!(FrameKind::from_wire(identifiant).expect("connu"), kind);
        assert_eq!(kind.value(), identifiant);
    }
}

/// **LES TYPES RÉSERVÉS SONT UN PIÈGE, ET IL EST VOULU** (§11.2.1) : les
/// recevoir veut dire qu'un pair parle HTTP/2 sur une connexion HTTP/3, et que
/// ce qui suit ne sera pas ce qu'on croit.
#[test]
fn les_types_d_http2_se_refusent() {
    for identifiant in FrameKind::RESERVES_PAR_HTTP2 {
        let issue = FrameKind::from_wire(identifiant).expect_err("réservé");
        assert_eq!(issue.reason(), Reason::ReservedH2Frame, "{identifiant:#x}");
        assert_eq!(issue.code(), H3Error::FrameUnexpected);
        // Et à la lecture d'un en-tête entier aussi.
        let brut = entete(identifiant, 0);
        assert_eq!(
            FrameHeader::parse(&brut).expect_err("réservé").reason(),
            Reason::ReservedH2Frame
        );
    }
}

/// **UN TYPE INCONNU S'IGNORE** (§9) : les trames portent leur longueur, et une
/// extension peut donc traverser un pair qui ne la connaît pas.
#[test]
fn un_type_inconnu_se_saute() {
    // Les types de graissage de §7.2.8 : 0x1f * N + 0x21.
    for identifiant in [0x21_u64, 0x40, 0x1f * 7 + 0x21, 1_000_000] {
        let kind = FrameKind::from_wire(identifiant).expect("inconnu, mais lisible");
        assert_eq!(kind, FrameKind::Unknown(identifiant));
        assert_eq!(kind.value(), identifiant);
        // Un inconnu a sa place partout : c'est ce qui le rend ignorable.
        assert!(kind.sur_une_requete());
        assert!(kind.sur_le_controle());
    }
}

/// **ON REND LA LONGUEUR SANS EXIGER QUE LA CHARGE SOIT LÀ** : un flux QUIC
/// livre par morceaux, et accumuler un corps entier pour en connaître la taille
/// serait accumuler ce qu'on n'a pas décidé d'accepter.
#[test]
fn un_entete_se_lit_sans_sa_charge() {
    let brut = entete(0x00, 1_048_576);
    let lu = FrameHeader::parse(&brut).expect("lisible");
    assert_eq!(lu.kind(), FrameKind::Data);
    assert_eq!(lu.length(), 1_048_576);
    assert_eq!(lu.header_len(), brut.len());
    assert_eq!(
        lu.total(),
        u64::try_from(brut.len())
            .expect("court")
            .saturating_add(1_048_576)
    );
}

/// **UNE TRAME PEUT ANNONCER PLUS QU'UN `usize` NE TIENT** sur une cible de
/// trente-deux bits : la mesure se rend donc en `u64`, et c'est à l'appelant de
/// décider ce qu'il en fait.
#[test]
fn une_trame_immense_se_mesure_quand_meme() {
    let brut = entete(0x00, crate::frame::FRAME_LENGTH_MAX);
    let lu = FrameHeader::parse(&brut).expect("lisible");
    assert_eq!(lu.length(), crate::frame::FRAME_LENGTH_MAX);
    assert!(
        lu.total() > crate::frame::FRAME_LENGTH_MAX,
        "la mesure compte aussi l'en-tête"
    );
}

/// **§7.2 ATTACHE CHAQUE TYPE À UN FLUX**, et une trame ailleurs veut dire que
/// le pair a perdu le fil.
#[test]
fn chaque_trame_a_son_flux() {
    let cas = [
        (FrameKind::Data, true, false),
        (FrameKind::Headers, true, false),
        (FrameKind::Settings, false, true),
        (FrameKind::CancelPush, false, true),
        (FrameKind::GoAway, false, true),
        (FrameKind::MaxPushId, false, true),
        // `PUSH_PROMISE` n'a sa place ni sur l'un ni sur l'autre ici : ce
        // serveur ne pousse pas.
        (FrameKind::PushPromise, false, false),
        (FrameKind::Unknown(0x21), true, true),
    ];
    for (kind, requete, controle) in cas {
        assert_eq!(kind.sur_une_requete(), requete, "{kind:?}");
        assert_eq!(kind.sur_le_controle(), controle, "{kind:?}");
        let brut = entete(kind.value(), 0);
        let lu = FrameHeader::parse(&brut).expect("lisible");
        assert_eq!(
            lu.check_stream(Placement::Request).is_ok(),
            requete,
            "{kind:?}"
        );
        assert_eq!(
            lu.check_stream(Placement::Control).is_ok(),
            controle,
            "{kind:?}"
        );
    }

    // Et la faute porte son code.
    let brut = entete(0x04, 0);
    let issue = FrameHeader::parse(&brut)
        .expect("lisible")
        .check_stream(Placement::Request)
        .expect_err("SETTINGS n'est pas sur une requête");
    assert_eq!(issue.reason(), Reason::FrameOnWrongStream);
    assert_eq!(issue.code(), H3Error::FrameUnexpected);
}

/// Un en-tête tronqué se refuse, à chaque endroit possible.
#[test]
fn un_entete_tronque_se_refuse() {
    let entiere = entete(0x0d, 30_000);
    for coupure in 0..entiere.len() {
        let court = entiere.get(..coupure).expect("préfixe");
        let issue = FrameHeader::parse(court).expect_err("tronqué");
        assert_eq!(issue.reason(), Reason::Truncated, "coupure {coupure}");
        assert_eq!(issue.code(), H3Error::FrameError);
    }
    assert!(FrameHeader::parse(&entiere).is_ok());
}

/// **UN EN-TÊTE DE TRAME S'ÉCRIT, ET SE RELIT** (§7.1).
///
/// C'est le contrôle qui compte : ce qu'on écrit doit se lire par le même code
/// qui lit ce que le pair écrit, sans quoi une erreur d'un côté passerait
/// inaperçue des deux.
#[test]
fn un_entete_de_trame_s_ecrit_et_se_relit() {
    let mut octets = [0_u8; 32];
    for (kind, longueur) in [
        (FrameKind::Settings, 0_u64),
        (FrameKind::Data, 1_200),
        (FrameKind::Headers, 63),
        (FrameKind::GoAway, 1),
        (FrameKind::Unknown(0x21), 1 << 20),
    ] {
        let ecrits = write_header(kind, longueur, &mut octets).expect("écrivable");
        let relu = FrameHeader::parse(&octets).expect("relisible");
        assert_eq!(relu.kind(), kind);
        assert_eq!(relu.length(), longueur);
        assert_eq!(
            relu.header_len(),
            ecrits,
            "et l'on sait où la charge commence"
        );
    }
}

/// **UNE PLACE QUI MANQUE SE DIT** (C3).
///
/// **C'EST NOTRE FAUTE, PAS CELLE DU PAIR** : un tampon trop court est un défaut
/// de l'appelant, et le taire écrirait une trame tronquée que le pair lirait de
/// travers.
#[test]
fn une_place_qui_manque_se_dit() {
    // Rien du tout.
    assert_eq!(
        write_header(FrameKind::Settings, 0, &mut []).map_err(|e| e.reason()),
        Err(Reason::BufferTooSmall)
    );
    // De quoi le type, mais pas la longueur.
    let mut juste = [0_u8; 1];
    assert_eq!(
        write_header(FrameKind::Settings, 1 << 20, &mut juste).map_err(|e| e.reason()),
        Err(Reason::BufferTooSmall)
    );
}
