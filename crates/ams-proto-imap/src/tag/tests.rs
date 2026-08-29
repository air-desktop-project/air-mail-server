//! Ce qu'un tag a le droit d'être.

use super::Tag;
use crate::{Error, Limits};

const BORNES: Limits = Limits::DEFAULT;

#[test]
fn les_tags_ordinaires_passent() {
    for texte in [
        &b"a001"[..],
        b"A0001",
        b".",
        b"tag",
        b"42",
        // `]` est un `resp-specials`, et `ASTRING-CHAR` l'inclut.
        b"a]b",
        b"a-b_c.d",
    ] {
        let tag = Tag::parse(texte, &BORNES).expect("lisible");
        assert_eq!(tag.as_bytes(), texte, "{texte:?}");
    }
}

/// **Un `CRLF` dans un tag écrirait une réponse entière de la main du client.**
/// Un `*` en ferait une réponse non sollicitée, un `+` une demande de
/// continuation : ce sont les trois formes que prend une réponse IMAP.
#[test]
fn c_est_ici_que_l_injection_de_reponse_s_arrete() {
    for mechant in [
        &b"a001\r\n* BYE"[..],
        b"a001\nOK",
        b"a001\r",
        b"a 001",
        b"a\x00b",
        b"a\x7fb",
        b"a*b",
        b"a%b",
        b"a\"b",
        b"a\\b",
        b"a(b",
        b"a)b",
        b"a{b",
        b"a+b",
    ] {
        assert_eq!(
            Tag::parse(mechant, &BORNES),
            Err(Error::MalformedTag),
            "{mechant:?}"
        );
    }
}

/// `+` seul est réservé : c'est le préfixe d'une demande de continuation.
#[test]
fn le_plus_est_reserve() {
    assert_eq!(Tag::parse(b"+", &BORNES), Err(Error::ReservedTag));
}

#[test]
fn un_tag_vide_n_en_est_pas_un() {
    assert_eq!(Tag::parse(b"", &BORNES), Err(Error::MissingTag));
}

/// **Le tag est recopié dans la réponse** : un tag de deux kibioctets ferait une
/// réponse de deux kibioctets.
#[test]
fn un_tag_trop_long_est_refuse() {
    let long = [b'a'; 33];
    assert_eq!(
        Tag::parse(&long, &BORNES),
        Err(Error::TagTooLong { limit: 32 })
    );
    let juste = [b'a'; 32];
    assert!(Tag::parse(&juste, &BORNES).is_ok());
}

#[test]
fn ce_qui_se_lit_se_montre_et_se_compare() {
    let tag = Tag::parse(b"a001", &BORNES).expect("lisible");
    let copie = tag;
    assert_eq!(tag, copie);
    assert_ne!(tag, Tag::parse(b"a002", &BORNES).expect("lisible"));
    assert!(!std::format!("{tag:?}").is_empty());
}
