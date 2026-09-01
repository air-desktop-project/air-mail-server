//! Ce que l'encodage d'une question doit tenir.

use super::{QUERY_MAX, encode_query};
use crate::{CLASS_IN, Error, KIND_OPT, Kind, Message};

#[test]
fn une_question_se_lit_comme_un_message() {
    // La meilleure preuve qu'une question est bien formée : le décodeur du
    // projet la marche jusqu'au bout. Il refuse de la lire comme une RÉPONSE —
    // c'est exactement ce qu'on veut qu'il fasse.
    let mut tampon = [0_u8; QUERY_MAX];
    let question = encode_query(&mut tampon, 0x1234, b"example.com", Kind::Txt).expect("encodée");

    assert_eq!(&question[0..2], &[0x12, 0x34], "l'identifiant");
    // **`RD` ET `AD`, ET RIEN D'AUTRE.** `AD` dans la QUESTION demande au
    // résolveur de dire s'il a validé (RFC 6840 §5.7) ; `DO`, qui demanderait
    // les signatures elles-mêmes, reste absent — on ne saurait pas les valider.
    assert_eq!(&question[2..4], &[0x01, 0x20], "RD et AD, et rien d'autre");
    assert_eq!(&question[4..6], &[0x00, 0x01], "une question");
    assert_eq!(&question[6..8], &[0x00, 0x00], "aucune réponse");
    assert_eq!(&question[8..10], &[0x00, 0x00], "aucune autorité");
    assert_eq!(&question[10..12], &[0x00, 0x01], "l'OPT d'EDNS(0)");
    assert_eq!(
        &question[12..25],
        &[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0
        ]
    );
    assert_eq!(&question[25..27], &Kind::Txt.code().to_be_bytes());
    assert_eq!(&question[27..29], &CLASS_IN.to_be_bytes());

    // L'OPT : nom racine, type 41, taille annoncée, TTL nul, aucune option.
    assert_eq!(question[29], 0);
    assert_eq!(&question[30..32], &KIND_OPT.to_be_bytes());
    assert_eq!(&question[32..34], &1232_u16.to_be_bytes());
    assert_eq!(&question[34..38], &[0, 0, 0, 0], "version 0, DO absent");
    assert_eq!(&question[38..40], &[0, 0]);
    assert_eq!(question.len(), 40);

    assert_eq!(Message::parse(question).unwrap_err(), (Error::NotAResponse));
}

#[test]
fn le_bit_do_n_est_jamais_pose() {
    // On ne demande pas les signatures DNSSEC PARCE QU'ON NE SAURAIT PAS LES
    // VALIDER. Les demander ferait croire à une vérification qui n'a pas lieu.
    let mut tampon = [0_u8; QUERY_MAX];
    let question = encode_query(&mut tampon, 1, b"example.com", Kind::A).expect("encodée");
    // Le TTL de l'OPT porte version et drapeaux ; `DO` est son bit de poids
    // fort.
    assert_eq!(question[34] & 0x80, 0);
}

#[test]
fn chaque_type_interrogeable_porte_son_nombre() {
    for (kind, code) in [
        (Kind::A, 1),
        (Kind::Cname, 5),
        (Kind::Ptr, 12),
        (Kind::Mx, 15),
        (Kind::Txt, 16),
        (Kind::Aaaa, 28),
    ] {
        assert_eq!(kind.code(), code, "{kind:?}");
        let mut tampon = [0_u8; QUERY_MAX];
        let question = encode_query(&mut tampon, 7, b"example.com", kind).expect("encodée");
        assert_eq!(&question[25..27], &code.to_be_bytes());
        assert!(!std::format!("{kind:?}").is_empty());
    }
    assert_eq!(Kind::A, Kind::A);
    assert_ne!(Kind::A, Kind::Aaaa);
}

#[test]
fn la_racine_s_interroge_aussi() {
    let mut tampon = [0_u8; QUERY_MAX];
    let question = encode_query(&mut tampon, 1, b"", Kind::Txt).expect("encodée");
    assert_eq!(question[12], 0);
}

#[test]
fn un_nom_impossible_est_refuse_avant_d_etre_emis() {
    let mut tampon = [0_u8; QUERY_MAX];
    assert_eq!(
        encode_query(&mut tampon, 1, b"a..b", Kind::A),
        Err(Error::EmptyLabel)
    );
    let long = "a".repeat(64);
    assert_eq!(
        encode_query(&mut tampon, 1, long.as_bytes(), Kind::A),
        Err(Error::NameTooLong)
    );
}

#[test]
fn un_tampon_trop_petit_est_refuse_a_chaque_etape() {
    // Chaque écriture a sa borne, et aucune n'écrit à moitié.
    for taille in 0..40 {
        let mut tampon = std::vec![0_u8; taille];
        assert_eq!(
            encode_query(&mut tampon, 1, b"example.com", Kind::Txt),
            Err(Error::BufferTooSmall),
            "taille {taille}"
        );
    }
    // Quarante octets : la question tient tout juste.
    let mut juste = [0_u8; 40];
    assert!(encode_query(&mut juste, 1, b"example.com", Kind::Txt).is_ok());
}

/// **`DO` N'EST PAS POSÉ**, et c'est ce qui distingue « dis-moi si tu as
/// validé » de « envoie-moi de quoi valider ».
///
/// `DO` vit dans le TTL de l'enregistrement `OPT` (RFC 6891 §6.1.3), bit de
/// poids fort. Le poser ferait grossir chaque réponse de ses signatures, que
/// cette crate ne saurait pas vérifier.
#[test]
fn le_bit_do_reste_absent_de_l_opt() {
    let mut tampon = [0_u8; QUERY_MAX];
    let question = encode_query(&mut tampon, 1, b"example.com", Kind::Tlsa).expect("encodée");
    // L'`OPT` : nom racine (1 octet), type (2), classe (2), puis le TTL (4).
    let debut_ttl = question.len() - 4 - 2;
    let ttl = &question[debut_ttl..debut_ttl + 4];
    assert_eq!(ttl[0] & 0x80, 0, "le bit DO est posé : {ttl:?}");
    assert_eq!(
        ttl,
        &[0, 0, 0, 0],
        "aucun drapeau EDNS, et aucun rcode étendu"
    );
}
