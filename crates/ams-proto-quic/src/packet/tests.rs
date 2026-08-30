// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un en-tête de paquet a le droit d'être.

use super::{
    Long, LongKind, RETRY_TAG_OCTETS, ShortHeader, VERSION_1, VERSION_NEGOTIATION, is_long,
    parse_long,
};
use crate::connection_id::ConnectionId;
use crate::error::{Reason, TransportError};

/// Compose un en-tête long.
fn long(premier: u8, version: u32, dcid: &[u8], scid: &[u8], suite: &[u8]) -> std::vec::Vec<u8> {
    let mut octets = std::vec::Vec::new();
    octets.push(premier);
    octets.extend_from_slice(&version.to_be_bytes());
    octets.push(u8::try_from(dcid.len()).expect("court"));
    octets.extend_from_slice(dcid);
    octets.push(u8::try_from(scid.len()).expect("court"));
    octets.extend_from_slice(scid);
    octets.extend_from_slice(suite);
    octets
}

/// **UN `Initial` PORTE UN JETON**, et lui seul (§17.2.2).
#[test]
fn un_initial_se_lit_avec_son_jeton() {
    // Jeton de trois octets, puis une longueur de 0x1234 sur deux octets.
    let suite = [0x03, 0xaa, 0xbb, 0xcc, 0x52, 0x34];
    let paquet = long(0xc0, VERSION_1, &[1, 2, 3, 4], &[9, 8], &suite);
    let Long::Numbered(entete) = parse_long(&paquet).expect("lisible") else {
        panic!("ce devait être un paquet numéroté");
    };
    assert_eq!(entete.kind(), LongKind::Initial);
    assert_eq!(entete.version(), VERSION_1);
    assert_eq!(entete.destination().as_bytes(), &[1, 2, 3, 4]);
    assert_eq!(entete.source().as_bytes(), &[9, 8]);
    assert_eq!(entete.token(), &[0xaa, 0xbb, 0xcc]);
    assert_eq!(entete.length(), 0x1234);
    // Sept octets d'en-tête fixe, quatre de jeton, deux de longueur.
    assert_eq!(entete.number_offset(), paquet.len());
    assert!(is_long(&paquet));
}

/// **LES TROIS AUTRES TYPES N'EN PORTENT PAS**, et un `0-RTT` comme un
/// `Handshake` se lit sans jeton.
#[test]
fn les_autres_types_n_ont_pas_de_jeton() {
    for (bits, attendu) in [(0x10_u8, LongKind::ZeroRtt), (0x20, LongKind::Handshake)] {
        let paquet = long(0xc0 | bits, VERSION_1, &[7], &[], &[0x44, 0x00]);
        let Long::Numbered(entete) = parse_long(&paquet).expect("lisible") else {
            panic!("ce devait être un paquet numéroté");
        };
        assert_eq!(entete.kind(), attendu);
        assert!(entete.token().is_empty(), "{attendu:?}");
        assert_eq!(entete.length(), 0x400);
        assert!(entete.source().is_empty(), "un identifiant vide est licite");
    }
}

/// Les quatre types se lisent depuis leurs deux bits, et s'y réécrivent.
#[test]
fn les_quatre_types_se_lisent_et_se_reecrivent() {
    for kind in [
        LongKind::Initial,
        LongKind::ZeroRtt,
        LongKind::Handshake,
        LongKind::Retry,
    ] {
        assert_eq!(LongKind::from_bits(0xc0 | kind.bits()), kind);
        // Les bits voisins ne changent pas le type : seuls les deux du milieu
        // comptent, et les six autres sont mis à un ici pour le prouver.
        assert_eq!(LongKind::from_bits(0xcf | kind.bits()), kind);
    }
}

/// **UN `Retry` N'A NI LONGUEUR NI NUMÉRO** (§17.2.5) : tout ce qui suit les
/// identifiants est le jeton, sauf les seize derniers octets.
#[test]
fn un_retry_se_lit_a_l_envers() {
    let mut suite = std::vec::Vec::from(b"le-jeton".as_slice());
    suite.extend_from_slice(&[0x5a; RETRY_TAG_OCTETS]);
    let paquet = long(0xf0, VERSION_1, &[1], &[2, 3], &suite);
    let Long::Retry(retry) = parse_long(&paquet).expect("lisible") else {
        panic!("ce devait être un Retry");
    };
    assert_eq!(retry.destination.as_bytes(), &[1]);
    assert_eq!(retry.source.as_bytes(), &[2, 3]);
    assert_eq!(retry.token, b"le-jeton");
    assert_eq!(retry.tag, [0x5a; RETRY_TAG_OCTETS]);

    // Un `Retry` plus court que son propre jeton d'authentification n'en est
    // pas un.
    let paquet = long(0xf0, VERSION_1, &[1], &[2, 3], &[0_u8; 15]);
    let issue = parse_long(&paquet).expect_err("trop court");
    assert_eq!(issue.reason(), Reason::Truncated);

    // Et un `Retry` dont le jeton est vide est licite : seize octets pile.
    let paquet = long(0xf0, VERSION_1, &[], &[], &[0x11; RETRY_TAG_OCTETS]);
    let Long::Retry(retry) = parse_long(&paquet).expect("lisible") else {
        panic!("ce devait être un Retry");
    };
    assert!(retry.token.is_empty());
}

/// **LA VERSION ZÉRO N'EST PAS UNE VERSION** (§17.2.1) : le reste est une liste
/// de versions, et les bits de type ne veulent alors rien dire.
#[test]
fn la_version_zero_est_une_negociation() {
    let versions = [0x00, 0x00, 0x00, 0x01, 0x6b, 0x33, 0x43, 0xcf];
    // Les bits de type disent « Retry », et cela ne change rien.
    let paquet = long(0xf0, VERSION_NEGOTIATION, &[4, 5], &[6], &versions);
    let Long::Negotiation(negociation) = parse_long(&paquet).expect("lisible") else {
        panic!("ce devait être une négociation");
    };
    assert_eq!(negociation.destination.as_bytes(), &[4, 5]);
    assert_eq!(negociation.source.as_bytes(), &[6]);
    assert_eq!(negociation.versions, versions);
}

/// **LE BIT FIXE SE VÉRIFIE, ET LE PAQUET SE JETTE S'IL MANQUE** (§17.2). C'est
/// ce qui distingue QUIC d'autres protocoles sur le même port.
#[test]
fn sans_le_bit_fixe_ce_n_est_pas_un_paquet() {
    // Forme longue, bit fixe à zéro.
    let paquet = long(0x80, VERSION_1, &[1], &[], &[0x00]);
    let issue = parse_long(&paquet).expect_err("pas un paquet");
    assert_eq!(issue.reason(), Reason::NotAPacket);
    assert_eq!(issue.code(), TransportError::ProtocolViolation);

    // Forme courte présentée à la lecture d'un en-tête long.
    let paquet = long(0x40, VERSION_1, &[1], &[], &[0x00]);
    assert_eq!(
        parse_long(&paquet).expect_err("pas long").reason(),
        Reason::NotAPacket
    );
    assert!(!is_long(&paquet));

    // Et un tampon vide n'est rien du tout.
    assert_eq!(
        parse_long(&[]).expect_err("vide").reason(),
        Reason::Truncated
    );
    assert!(!is_long(&[]));
}

/// **AU-DELÀ DE VINGT OCTETS, ON JETTE** : la longueur vient du fil.
#[test]
fn un_identifiant_trop_long_fait_jeter_le_paquet() {
    let trop = [0xcc_u8; 21];
    let paquet = long(0xc0, VERSION_1, &trop, &[], &[0x00]);
    let issue = parse_long(&paquet).expect_err("hors borne");
    assert_eq!(issue.reason(), Reason::ConnectionIdTooLong);

    // Et sur l'identifiant de source aussi.
    let paquet = long(0xc0, VERSION_1, &[1], &trop, &[0x00]);
    assert_eq!(
        parse_long(&paquet).expect_err("hors borne").reason(),
        Reason::ConnectionIdTooLong
    );
}

/// Un en-tête tronqué à chaque endroit possible.
#[test]
fn un_entete_tronque_se_refuse() {
    let suite = [0x03, 0xaa, 0xbb, 0xcc, 0x52, 0x34];
    let entier = long(0xc0, VERSION_1, &[1, 2, 3, 4], &[9, 8], &suite);
    // Chaque préfixe strict est tronqué, sauf s'il est vide.
    for coupure in 0..entier.len() {
        let issue =
            parse_long(entier.get(..coupure).expect("préfixe")).expect_err("tronqué à {coupure}");
        assert_eq!(issue.reason(), Reason::Truncated, "coupure {coupure}");
        assert_eq!(issue.code(), TransportError::FrameEncodingError);
    }
    // Et l'entier, lui, se lit.
    assert!(parse_long(&entier).is_ok());
}

/// **UN JETON QUI ANNONCE PLUS QUE LE PAQUET NE PORTE** : la longueur vient du
/// fil, et un entier de §16 peut annoncer 2^62 octets.
#[test]
fn un_jeton_qui_ment_sur_sa_taille_se_refuse() {
    // Longueur de jeton annoncée à 2^62 - 1, sur huit octets.
    let suite = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00];
    let paquet = long(0xc0, VERSION_1, &[1], &[], &suite);
    let issue = parse_long(&paquet).expect_err("il ment");
    assert_eq!(issue.reason(), Reason::Truncated);
}

/// **LA LONGUEUR DE L'IDENTIFIANT COURT N'EST PAS SUR LE FIL** : c'est nous qui
/// l'avons choisie, et le pair ne nous la réapprend pas.
#[test]
fn un_entete_court_se_lit_avec_la_longueur_qu_on_a_emise() {
    let paquet = [0x41_u8, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
    let entete = ShortHeader::parse(&paquet, 4).expect("lisible");
    assert_eq!(entete.destination().as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(entete.number_offset(), 5);

    // La MÊME suite d'octets, lue avec une autre longueur, désigne une autre
    // connexion. C'est pourquoi un serveur doit se souvenir de ce qu'il émet.
    let entete = ShortHeader::parse(&paquet, 2).expect("lisible");
    assert_eq!(entete.destination().as_bytes(), &[0xde, 0xad]);
    assert_eq!(entete.number_offset(), 3);

    // Un identifiant vide est licite ici aussi.
    let entete = ShortHeader::parse(&paquet, 0).expect("lisible");
    assert_eq!(entete.destination(), ConnectionId::EMPTY);
    assert_eq!(entete.number_offset(), 1);
}

/// Un en-tête court mal formé, ou trop court pour l'identifiant annoncé.
#[test]
fn un_entete_court_mal_forme_se_refuse() {
    // Forme longue présentée à la lecture d'un en-tête court.
    assert_eq!(
        ShortHeader::parse(&[0xc0, 0x00], 1)
            .expect_err("pas court")
            .reason(),
        Reason::NotAPacket
    );
    // Bit fixe à zéro.
    assert_eq!(
        ShortHeader::parse(&[0x01, 0x00], 1)
            .expect_err("pas un paquet")
            .reason(),
        Reason::NotAPacket
    );
    // Vide.
    assert_eq!(
        ShortHeader::parse(&[], 0).expect_err("vide").reason(),
        Reason::Truncated
    );
    // Plus court que l'identifiant qu'on attend.
    assert_eq!(
        ShortHeader::parse(&[0x41, 0xde], 4)
            .expect_err("tronqué")
            .reason(),
        Reason::Truncated
    );
    // Et une longueur hors borne, que nous seuls pourrions demander.
    assert_eq!(
        ShortHeader::parse(&[0x41; 64], 21)
            .expect_err("hors borne")
            .reason(),
        Reason::ConnectionIdTooLong
    );
}
