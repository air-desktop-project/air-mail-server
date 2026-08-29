//! Le nom du fichier et la ligne de sujet.

use super::{FILENAME_MAX, SUBJECT_MAX, filename, subject};
use crate::Error;

#[test]
fn le_nom_suit_la_forme_de_la_rfc() {
    let mut tampon = [0_u8; FILENAME_MAX];
    let nom = filename(
        b"mail.receveur.test",
        b"example.com",
        1_013_662_812,
        1_013_749_130,
        None,
        &mut tampon,
    )
    .expect("nommable");
    assert_eq!(
        nom,
        &b"mail.receveur.test!example.com!1013662812!1013749130.xml.gz"[..]
    );
}

#[test]
fn l_identifiant_unique_s_ajoute_quand_il_est_la() {
    let mut tampon = [0_u8; FILENAME_MAX];
    let nom = filename(b"r.test", b"e.test", 0, 10, Some(b"7a3f"), &mut tampon).expect("nommable");
    assert_eq!(nom, &b"r.test!e.test!0!10!7a3f.xml.gz"[..]);
}

/// **Ce nom devient un fichier chez autrui**, et le domaine qui publie la
/// politique est choisi par celui qu'on rapporte.
#[test]
fn c_est_ici_que_la_traversee_de_repertoire_s_arrete() {
    let mut tampon = [0_u8; FILENAME_MAX];
    for mechant in [
        &b"../../etc/passwd"[..],
        b"a/b",
        b"a b",
        b"a\nb",
        b"a!b",
        b"",
        // Trouvé par le fuzzer : `a..b` n'est pas un domaine, et un `..` n'a
        // rien à faire dans un nom de fichier, même sans barre oblique pour
        // l'accompagner.
        b"a..b",
        b".a",
        b"a.",
        b"..",
    ] {
        assert_eq!(
            filename(b"r.test", mechant, 0, 1, None, &mut tampon),
            Err(Error::NotPrintable),
            "{mechant:?}"
        );
    }
}

#[test]
fn un_identifiant_douteux_est_refuse_lui_aussi() {
    let mut tampon = [0_u8; FILENAME_MAX];
    assert_eq!(
        filename(b"r.test", b"e.test", 0, 1, Some(b"a/b"), &mut tampon),
        Err(Error::NotPrintable)
    );
}

#[test]
fn un_nom_trop_long_est_refuse() {
    let long = [b'a'; 256];
    let mut tampon = [0_u8; FILENAME_MAX];
    assert_eq!(
        filename(&long, b"e.test", 0, 1, None, &mut tampon),
        Err(Error::DomainTooLong)
    );
}

/// Toutes les tailles, pas quelques-unes : le tampon peut céder à chaque
/// morceau, et chaque fois il doit le dire de la même façon.
#[test]
fn un_tampon_trop_court_le_dit_ou_qu_il_cede() {
    let mut assez = [0_u8; FILENAME_MAX];
    let entier = filename(b"r.test", b"e.test", 0, 1234, Some(b"7a3f"), &mut assez)
        .expect("nommable")
        .to_vec();
    for taille in 0..entier.len() {
        let mut tampon = std::vec![0_u8; taille];
        assert_eq!(
            filename(b"r.test", b"e.test", 0, 1234, Some(b"7a3f"), &mut tampon),
            Err(Error::BufferTooSmall),
            "taille {taille}"
        );
    }

    let mut assez = [0_u8; SUBJECT_MAX];
    let entier = subject(b"e.test", b"r.test", b"id", &mut assez)
        .expect("composable")
        .to_vec();
    for taille in 0..entier.len() {
        let mut tampon = std::vec![0_u8; taille];
        assert_eq!(
            subject(b"e.test", b"r.test", b"id", &mut tampon),
            Err(Error::BufferTooSmall),
            "taille {taille}"
        );
    }
}

#[test]
fn les_grands_nombres_s_ecrivent_en_entier() {
    let mut tampon = [0_u8; FILENAME_MAX];
    let nom = filename(b"r.test", b"e.test", 0, u64::MAX, None, &mut tampon).expect("nommable");
    assert_eq!(nom, &b"r.test!e.test!0!18446744073709551615.xml.gz"[..]);
}

#[test]
fn le_sujet_se_lit_a_l_oeil_et_se_trie_a_la_machine() {
    let mut tampon = [0_u8; SUBJECT_MAX];
    let ligne = subject(
        b"example.com",
        b"mail.receveur.test",
        b"7a3f-1",
        &mut tampon,
    )
    .expect("composable");
    assert_eq!(
        ligne,
        &b"Report Domain: example.com Submitter: mail.receveur.test Report-ID: 7a3f-1"[..]
    );
}

#[test]
fn le_sujet_refuse_lui_aussi_ce_qui_n_est_pas_un_nom() {
    let mut tampon = [0_u8; SUBJECT_MAX];
    assert_eq!(
        subject(
            b"e.test\r\nBcc: victime@x.test",
            b"r.test",
            b"id",
            &mut tampon
        ),
        Err(Error::NotPrintable)
    );
    assert_eq!(
        subject(b"e.test", b"r\r\n.test", b"id", &mut tampon),
        Err(Error::NotPrintable)
    );
    assert_eq!(
        subject(b"e.test", b"r.test", b"id\r\n", &mut tampon),
        Err(Error::NotPrintable)
    );
}
