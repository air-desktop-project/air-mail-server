// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un numéro de paquet a le droit d'être.

use super::{PACKET_NUMBER_MAX, PACKET_NUMBER_OCTETS_MAX, decode, encode, encoded_len};
use crate::error::{Reason, TransportError};

/// **L'EXEMPLE DE L'ANNEXE A.3**, à la lettre : le plus grand traité vaut
/// 0xa82f30ea, le paquet porte 0x9b32 sur deux octets, et cela fait
/// 0xa82f9b32.
#[test]
fn l_exemple_de_l_annexe_se_reconstruit() {
    let reconstruit = decode(Some(0xa82f_30ea), 0x9b32, 2).expect("deux octets");
    assert_eq!(reconstruit, 0xa82f_9b32);
}

/// **LES DEUX EXEMPLES DE L'ANNEXE A.2**, qui disent combien d'octets il faut.
#[test]
fn les_exemples_de_l_annexe_disent_la_longueur() {
    // 29 519 paquets en attente : deux fois cela fait 0xe69e, seize bits.
    assert_eq!(
        encoded_len(0x00ac_5c02, Some(0x00ab_e8b3)).expect("mesurable"),
        2
    );
    // 65 611 en attente : deux fois cela fait 0x020096, vingt-quatre bits.
    assert_eq!(
        encoded_len(0x00ac_e8fe, Some(0x00ab_e8b3)).expect("mesurable"),
        3
    );
}

/// Sans rien d'acquitté, ce sont tous les paquets depuis le premier qui
/// comptent — et le premier paquet d'une connexion tient sur un octet.
#[test]
fn sans_acquittement_on_compte_depuis_le_debut() {
    assert_eq!(encoded_len(0, None).expect("mesurable"), 1);
    assert_eq!(encoded_len(62, None).expect("mesurable"), 1);
    assert_eq!(encoded_len(63, None).expect("mesurable"), 1);
    assert_eq!(encoded_len(127, None).expect("mesurable"), 2);
    assert_eq!(encoded_len(1_000_000, None).expect("mesurable"), 3);
    // **AU-DELÀ DE QUATRE OCTETS, ON ÉCRIT QUATRE** : c'est la borne de §17.1.
    assert_eq!(
        encoded_len(PACKET_NUMBER_MAX, None).expect("mesurable"),
        PACKET_NUMBER_OCTETS_MAX
    );
}

/// **CE QU'ON ÉCRIT SE RECONSTRUIT**, pourvu qu'on ait écrit assez long. C'est
/// toute la propriété, et le reste n'est que du calcul.
#[test]
fn ce_qu_on_ecrit_se_reconstruit() {
    for (numero, acquitte) in [
        (0_u64, None),
        (1, None),
        (255, Some(250_u64)),
        (256, Some(1)),
        (0xa82f_9b32, Some(0xa82f_30ea)),
        (1_000_000, Some(999_000)),
        (PACKET_NUMBER_MAX, Some(PACKET_NUMBER_MAX.saturating_sub(3))),
    ] {
        let octets = encoded_len(numero, acquitte).expect("mesurable");
        let mut ecrit = [0_u8; PACKET_NUMBER_OCTETS_MAX];
        let ecrits = encode(numero, octets, &mut ecrit).expect("écrivable");
        assert_eq!(ecrits, octets);
        // Ce que le receveur lit du fil : les octets, en gros-boutien.
        let mut tronque = 0_u64;
        for lu in ecrit.get(..ecrits).unwrap_or_default() {
            tronque = tronque.saturating_mul(256).saturating_add(u64::from(*lu));
        }
        // Le receveur a traité tout ce qui précède : c'est le cas courant.
        let largest = numero.checked_sub(1);
        let relu = decode(largest, tronque, octets).expect("reconstruit");
        assert_eq!(relu, numero, "numéro {numero}, acquitté {acquitte:?}");
    }
}

/// **LA FENÊTRE GLISSE DES DEUX CÔTÉS**, et les deux gardes de bord répondent à
/// deux situations différentes. Sans la première, un numéro proche de zéro
/// remonterait sous zéro ; sans la seconde, un numéro proche de 2^62
/// déborderait.
#[test]
fn la_fenetre_glisse_des_deux_cotes() {
    // Le candidat tombe trop bas : la fenêtre a glissé vers l'avant.
    // Attendu 0x101, reçu 0x02 sur un octet : le candidat 0x102 est bon.
    assert_eq!(decode(Some(0x100), 0x02, 1).expect("un octet"), 0x102);
    // Attendu 0x101, reçu 0xff : le candidat 0x1ff est trop haut d'une
    // demi-fenêtre — c'est 0x0ff, un paquet plus ancien qu'il n'y paraît.
    assert_eq!(decode(Some(0x100), 0xff, 1).expect("un octet"), 0x0ff);
    // Attendu 0x181, reçu 0x00 : le candidat 0x100 est trop bas d'une
    // demi-fenêtre — la fenêtre a glissé, et c'est 0x200.
    assert_eq!(decode(Some(0x180), 0x00, 1).expect("un octet"), 0x200);
    // Et le voisin immédiat, lui, ne glisse pas : 0x102 est dans la fenêtre.
    assert_eq!(decode(Some(0x180), 0x02, 1).expect("un octet"), 0x102);

    // **PRÈS DE ZÉRO, ON NE REMONTE PAS SOUS ZÉRO.** Aucun paquet traité : on
    // attend le zéro, et 0xff est un numéro qu'on n'a pas encore vu.
    assert_eq!(decode(None, 0xff, 1).expect("un octet"), 0xff);
    assert_eq!(decode(None, 0x00, 1).expect("un octet"), 0);

    // **PRÈS DE 2^62, ON NE DÉBORDE PAS.** Le candidat serait trop bas, mais
    // ajouter une fenêtre sortirait de l'espace : on garde le candidat.
    let haut = PACKET_NUMBER_MAX.saturating_sub(1);
    let relu = decode(Some(haut), 0x00, 1).expect("un octet");
    assert!(
        relu <= PACKET_NUMBER_MAX,
        "on est sorti de l'espace : {relu}"
    );
}

/// Une longueur hors de un..=quatre n'existe pas (§17.1).
#[test]
fn une_longueur_impossible_se_refuse() {
    for octets in [0_usize, 5, 8, usize::MAX] {
        let issue = decode(Some(10), 1, octets).expect_err("hors borne");
        assert_eq!(issue.reason(), Reason::BadPacketNumberLength, "{octets}");
        assert_eq!(issue.code(), TransportError::FrameEncodingError);
        let issue = encode(10, octets, &mut [0_u8; 4]).expect_err("hors borne");
        assert_eq!(issue.reason(), Reason::BadPacketNumberLength, "{octets}");
    }
}

/// Un numéro hors de l'espace, et un pair qui acquitte ce qu'on n'a pas envoyé.
#[test]
fn un_numero_impossible_se_refuse() {
    let trop = PACKET_NUMBER_MAX.saturating_add(1);
    assert_eq!(
        encode(trop, 4, &mut [0_u8; 4])
            .expect_err("hors borne")
            .reason(),
        Reason::PacketNumberTooLarge
    );
    assert_eq!(
        encoded_len(trop, None).expect_err("hors borne").reason(),
        Reason::PacketNumberTooLarge
    );
    // **UN PAIR NE PEUT PAS ACQUITTER CE QU'ON N'A PAS ENVOYÉ.** Le prendre au
    // mot ferait une soustraction sous zéro, et une longueur inventée.
    let issue = encoded_len(10, Some(11)).expect_err("il acquitte l'avenir");
    assert_eq!(issue.reason(), Reason::PacketNumberTooLarge);
    assert_eq!(issue.code(), TransportError::InternalError);
}

/// La place manque à l'écriture.
#[test]
fn l_ecriture_veut_de_la_place() {
    let issue = encode(0x1234, 2, &mut [0_u8; 1]).expect_err("la place manque");
    assert_eq!(issue.reason(), Reason::BufferTooSmall);
}

/// **UNE BORNE QU'ON NE VÉRIFIE QU'À LA SORTIE N'EST PAS UNE BORNE.** Un
/// `largest` hors de l'espace faisait rendre un numéro qu'aucun paquet ne peut
/// porter — défaut trouvé par le fuzz en trois minutes.
#[test]
fn un_plus_grand_traite_hors_de_l_espace_se_refuse() {
    for vu in [PACKET_NUMBER_MAX.saturating_add(1), u64::MAX] {
        let issue = decode(Some(vu), 0, 1).expect_err("hors de l'espace");
        assert_eq!(issue.reason(), Reason::PacketNumberTooLarge, "{vu}");
        assert_eq!(issue.code(), TransportError::InternalError);
    }
    // **À LA BORNE ELLE-MÊME, IL N'Y A PAS DE SUIVANT** : §12.3 veut qu'on ait
    // fermé avant, et rendre un candidat hors de l'espace serait pire que le
    // dire.
    let issue = decode(Some(PACKET_NUMBER_MAX), 0, 1).expect_err("épuisé");
    assert_eq!(issue.reason(), Reason::PacketNumberSpaceExhausted);
    assert_eq!(issue.code(), TransportError::InternalError);

    // Et jusqu'au dernier numéro utilisable, on reconstruit dans l'espace.
    for vu in [
        PACKET_NUMBER_MAX.saturating_sub(1),
        PACKET_NUMBER_MAX.saturating_sub(2),
        PACKET_NUMBER_MAX.saturating_sub(1_000),
    ] {
        for tronque in [0_u64, 1, 0x7f, 0xff] {
            let relu = decode(Some(vu), tronque, 1).expect("dans l'espace");
            assert!(relu <= PACKET_NUMBER_MAX, "sorti de l'espace : {relu}");
        }
    }
}
