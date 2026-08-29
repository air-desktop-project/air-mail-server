//! Ce qu'une réponse a le droit de dire.

use super::{Status, encode_continuation, encode_tagged, encode_untagged};
use crate::{Error, Limits, Tag};

const BORNES: Limits = Limits::DEFAULT;

fn tag() -> Tag<'static> {
    Tag::parse(b"a001", &BORNES).expect("lisible")
}

#[test]
fn les_trois_formes_s_ecrivent() {
    let mut sortie = [0_u8; 128];
    assert_eq!(
        encode_tagged(&mut sortie, tag(), Status::Ok, b"NOOP completed", &BORNES)
            .expect("encodable"),
        b"a001 OK NOOP completed\r\n"
    );
    assert_eq!(
        encode_untagged(&mut sortie, b"CAPABILITY IMAP4rev2", &BORNES).expect("encodable"),
        b"* CAPABILITY IMAP4rev2\r\n"
    );
    assert_eq!(
        encode_continuation(&mut sortie, b"ready for literal", &BORNES).expect("encodable"),
        b"+ ready for literal\r\n"
    );
}

/// **La distinction n'est pas cosmétique** : un `NO` dit que la commande était
/// correcte et que la réponse est non ; un `BAD` qu'elle était mal écrite.
#[test]
fn chaque_conclusion_a_son_mot() {
    let mut sortie = [0_u8; 64];
    for (status, mot) in [(Status::Ok, "OK"), (Status::No, "NO"), (Status::Bad, "BAD")] {
        let ecrit = encode_tagged(&mut sortie, tag(), status, b"x", &BORNES).expect("encodable");
        assert_eq!(ecrit, std::format!("a001 {mot} x\r\n").as_bytes());
        assert_eq!(status.name(), mot.as_bytes());
        assert_eq!(status, status);
        assert!(!std::format!("{status:?}").is_empty());
    }
    assert_ne!(Status::Ok, Status::No);
}

/// **Un texte qui porterait un `CRLF` écrirait une réponse de plus**, du choix
/// de celui qui a fourni le texte — et ce texte vient souvent d'un nom de boîte.
#[test]
fn c_est_ici_que_l_injection_de_reponse_s_arrete() {
    let mut sortie = [0_u8; 256];
    for mechant in [
        &b"ok\r\n* BYE parti"[..],
        b"ok\nBYE",
        b"ok\r",
        b"ok\x00",
        b"ok\x7f",
        b"ok\t",
    ] {
        assert_eq!(
            encode_tagged(&mut sortie, tag(), Status::Ok, mechant, &BORNES),
            Err(Error::ResponseTextNotPrintable),
            "{mechant:?}"
        );
        assert_eq!(
            encode_untagged(&mut sortie, mechant, &BORNES),
            Err(Error::ResponseTextNotPrintable),
            "{mechant:?}"
        );
        assert_eq!(
            encode_continuation(&mut sortie, mechant, &BORNES),
            Err(Error::ResponseTextNotPrintable),
            "{mechant:?}"
        );
    }
}

#[test]
fn une_reponse_trop_longue_est_refusee() {
    let mut sortie = std::vec![0_u8; 16384];
    let long = std::vec![b'x'; BORNES.max_response_octets];
    assert_eq!(
        encode_untagged(&mut sortie, &long, &BORNES),
        Err(Error::LineTooLong {
            limit: BORNES.max_response_octets
        })
    );
    let juste = std::vec![b'x'; BORNES.max_response_octets - 2];
    assert!(encode_untagged(&mut sortie, &juste, &BORNES).is_ok());
}

#[test]
fn un_tampon_trop_court_dit_ce_qu_il_aurait_fallu() {
    let entier = b"a001 OK fait\r\n";
    for taille in 0..entier.len() {
        let mut sortie = std::vec![0_u8; taille];
        assert_eq!(
            encode_tagged(&mut sortie, tag(), Status::Ok, b"fait", &BORNES),
            Err(Error::BufferTooSmall {
                needed: entier.len()
            }),
            "taille {taille}"
        );
    }
    let mut juste = std::vec![0_u8; entier.len()];
    assert_eq!(
        encode_tagged(&mut juste, tag(), Status::Ok, b"fait", &BORNES).expect("encodable"),
        entier
    );
}

/// Un texte vide est une réponse acceptable : `* OK` sans commentaire.
#[test]
fn un_texte_vide_passe() {
    let mut sortie = [0_u8; 32];
    assert_eq!(
        encode_untagged(&mut sortie, b"", &BORNES).expect("encodable"),
        b"* \r\n"
    );
}

/// Les morceaux se recollent sans tampon intermédiaire — et il y a une borne au
/// nombre de morceaux, sans quoi la sienne serait la seule à ne pas exister.
#[test]
fn une_reponse_en_morceaux_s_ecrit() {
    use super::encode_untagged_parts;

    let mut sortie = [0_u8; 128];
    assert_eq!(
        encode_untagged_parts(
            &mut sortie,
            &[b"CAPABILITY ", b"IMAP4rev2", b" LITERAL-", b"", b""],
            &BORNES
        )
        .expect("encodable"),
        b"* CAPABILITY IMAP4rev2 LITERAL-\r\n"
    );
    // Aucun morceau : la réponse la plus courte qui soit.
    assert_eq!(
        encode_untagged_parts(&mut sortie, &[], &BORNES).expect("encodable"),
        b"* \r\n"
    );
    // Un morceau irrecevable fait refuser la réponse entière.
    assert_eq!(
        encode_untagged_parts(&mut sortie, &[b"ok", b"\r\n* BYE"], &BORNES),
        Err(Error::ResponseTextNotPrintable)
    );
    // Trop de morceaux : la borne existe, et elle se dit.
    let beaucoup = [&b"x"[..]; 15];
    assert_eq!(
        encode_untagged_parts(&mut sortie, &beaucoup, &BORNES),
        Err(Error::BufferTooSmall { needed: 15 })
    );
    // Un tampon trop court le dit aussi.
    let mut court = [0_u8; 3];
    assert!(matches!(
        encode_untagged_parts(&mut court, &[b"long texte"], &BORNES),
        Err(Error::BufferTooSmall { .. })
    ));
}
