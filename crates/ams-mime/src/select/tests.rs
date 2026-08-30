//! Ce qu'un choix de champs rend.

use super::write_header_fields;
use crate::{Error, Limits};

const BORNES: Limits = Limits::DEFAULT;

// LE BLANC DU PLI EST SUR LA MÊME LIGNE SOURCE, et il le faut : la continuation
// `\` d'un littéral Rust mange les blancs de début de ligne, et mangerait donc
// le pli qu'on veut éprouver.
const ENTETE: &[u8] = b"From: jean@exemple.test\r\n\
Received: de partout\r\n\
Subject: un sujet\r\n replie sur deux lignes\r\n\
Received: et d'ailleurs\r\n\
To: chef@exemple.test\r\n\
\r\n\
le corps\r\n";

/// Compose un choix, ou panique.
fn choix(noms: &[u8], sauf: bool) -> std::string::String {
    let mut sortie = [0_u8; 4096];
    let ecrits = write_header_fields(ENTETE, noms, sauf, &mut sortie, &BORNES).expect("composable");
    std::string::String::from_utf8_lossy(sortie.get(..ecrits).unwrap_or_default()).into_owned()
}

/// **L'ORDRE EST CELUI DU MESSAGE**, et non celui de la demande : c'est ce que
/// §6.4.5 veut, et c'est ce qui permet à un client de recondenser ce qu'il a
/// reçu.
#[test]
fn l_ordre_est_celui_du_message() {
    assert_eq!(
        choix(b"subject from", false),
        "From: jean@exemple.test\r\n\
         Subject: un sujet\r\n replie sur deux lignes\r\n\
         \r\n"
    );
}

/// Le pliage sort tel qu'il est écrit : réécrire rendrait au client autre chose
/// que ce que le message porte.
#[test]
fn le_pliage_sort_tel_qu_il_est_ecrit() {
    assert!(choix(b"Subject", false).contains("un sujet\r\n replie sur deux lignes\r\n"));
}

/// Les doublons sortent tous : un `Received:` de plus est un saut de plus.
#[test]
fn les_doublons_sortent_tous() {
    let vu = choix(b"received", false);
    assert_eq!(vu.matches("Received:").count(), 2, "{vu}");
}

/// La casse ne compte pas (RFC 5322 §1.2.2).
#[test]
fn la_casse_des_noms_ne_compte_pas() {
    assert_eq!(choix(b"FROM", false), choix(b"from", false));
}

/// `HEADER.FIELDS.NOT` renverse le choix, et rien d'autre.
#[test]
fn le_choix_se_renverse() {
    let sauf = choix(b"received", true);
    assert!(sauf.contains("From:"), "{sauf}");
    assert!(sauf.contains("Subject:"), "{sauf}");
    assert!(sauf.contains("To:"), "{sauf}");
    assert!(!sauf.contains("Received:"), "{sauf}");
}

/// **LA LIGNE VIDE EST TOUJOURS LÀ**, même quand aucun champ ne correspond : un
/// client qui recevrait zéro octet ne saurait pas distinguer « aucun champ » de
/// « pas de réponse ».
#[test]
fn la_ligne_vide_est_toujours_la() {
    assert_eq!(choix(b"x-rien", false), "\r\n");
    assert_eq!(choix(b"", false), "\r\n");
    // Et tout sauf rien, c'est tout.
    assert!(choix(b"", true).starts_with("From:"));
}

/// Un nom vide dans la liste ne désigne rien.
#[test]
fn un_nom_vide_ne_designe_rien() {
    assert_eq!(choix(b"  \t ", false), "\r\n");
}

/// Un tampon trop court le dit, au lieu d'écrire un en-tête à moitié.
#[test]
fn un_tampon_trop_court_le_dit() {
    let complet = choix(b"from to", false);
    for place in 0..complet.len() {
        let mut sortie = std::vec![0_u8; place];
        assert_eq!(
            write_header_fields(ENTETE, b"from to", false, &mut sortie, &BORNES),
            Err(Error::BufferTooSmall),
            "avec {place} octets"
        );
    }
}

/// Un en-tête que la grammaire refuse n'a pas de choix.
#[test]
fn un_en_tete_illisible_n_a_pas_de_choix() {
    let bornes = Limits {
        max_fields: 1,
        ..Limits::DEFAULT
    };
    let mut sortie = [0_u8; 1024];
    assert!(write_header_fields(ENTETE, b"from", false, &mut sortie, &bornes).is_err());
}
