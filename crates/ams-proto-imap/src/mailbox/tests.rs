//! Ce qu'un nom de boîte a le droit d'être.

use super::{
    MAILBOX_COMPONENT_MAX, MAILBOX_DEPTH_MAX, MAILBOX_NAME_MAX, mailbox_name_is_safe,
    mailbox_name_trimmed,
};

#[test]
fn les_noms_ordinaires_passent() {
    for nom in [
        &b"Archives"[..],
        b"Archives/2026",
        b"Sent Messages",
        b"a/b/c/d/e/f/g/h",
        b"INBOX",
        b"Brouillons-2026_v2",
        // Un `/` final est ignoré (§6.3.4).
        b"Archives/",
    ] {
        assert!(
            mailbox_name_is_safe(nom),
            "{:?} aurait dû passer",
            core::str::from_utf8(nom)
        );
    }
}

/// **C'est ici que la remontée de répertoire se ferme.**
#[test]
fn rien_qui_puisse_remonter_un_repertoire_ne_passe() {
    for nom in [
        &b".."[..],
        b"../etc",
        b"a/../b",
        b".",
        b"a/./b",
        // Un point, même seul dans un nom, fabriquerait un niveau Maildir++.
        b"Sent.2026",
        b"a/b.c",
    ] {
        assert!(
            !mailbox_name_is_safe(nom),
            "{:?} aurait dû être refusé",
            core::str::from_utf8(nom)
        );
    }
}

#[test]
fn les_formes_sans_signification_sont_refusees() {
    for nom in [
        &b""[..],
        b"/",
        b"/a",
        b"a//b",
        b"a/",
        b" ",
        b" a",
        b"a ",
        b"a/ /b",
    ] {
        // `a/` est le seul de la liste qui passe : le `/` final est ignoré.
        let attendu = nom == b"a/";
        assert_eq!(
            mailbox_name_is_safe(nom),
            attendu,
            "{:?}",
            core::str::from_utf8(nom)
        );
    }
}

#[test]
fn les_octets_dangereux_sont_refuses() {
    for mauvais in [b'\\', b'%', b'*', b'"', b':', 0, 0x7f, b'\n', b'\r'] {
        let nom = [b'a', mauvais, b'b'];
        assert!(
            !mailbox_name_is_safe(&nom),
            "l'octet {mauvais:#04x} aurait dû être refusé"
        );
    }
    // L'UTF-8 est refusé faute de savoir le transcrire sans risque.
    assert!(!mailbox_name_is_safe("Éléments".as_bytes()));
}

#[test]
fn les_bornes_sont_tenues() {
    let long = std::vec![b'a'; MAILBOX_COMPONENT_MAX];
    assert!(mailbox_name_is_safe(&long));
    let trop_long = std::vec![b'a'; MAILBOX_COMPONENT_MAX + 1];
    assert!(!mailbox_name_is_safe(&trop_long));

    let mut profond = std::vec::Vec::new();
    for _ in 0..MAILBOX_DEPTH_MAX {
        profond.extend_from_slice(b"a/");
    }
    profond.pop();
    assert!(mailbox_name_is_safe(&profond));
    profond.extend_from_slice(b"/a");
    assert!(!mailbox_name_is_safe(&profond));

    // Le nom entier est borné aussi, même à profondeur admissible.
    let mut large = std::vec::Vec::new();
    for _ in 0..5 {
        large.extend_from_slice(&std::vec![b'a'; MAILBOX_COMPONENT_MAX]);
        large.push(b'/');
    }
    large.pop();
    assert!(large.len() > MAILBOX_NAME_MAX);
    assert!(!mailbox_name_is_safe(&large));
}

#[test]
fn le_slash_final_se_retire() {
    assert_eq!(mailbox_name_trimmed(b"Archives/"), b"Archives");
    assert_eq!(mailbox_name_trimmed(b"Archives"), b"Archives");
    assert_eq!(mailbox_name_trimmed(b""), b"");
}
