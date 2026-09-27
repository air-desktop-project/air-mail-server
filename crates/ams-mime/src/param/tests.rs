//! Ce qu'un paramètre MIME vaut, décodé.

use std::string::String;
use std::vec::Vec;

use super::write_parameter;
use crate::Error;

fn valeur(params: &str, nom: &str) -> Option<String> {
    let mut travail = [0_u8; 512];
    let mut sortie = [0_u8; 1024];
    let ecrits = write_parameter(params.as_bytes(), nom.as_bytes(), &mut travail, &mut sortie)
        .expect("tient")?;
    Some(String::from_utf8(sortie[..ecrits].to_vec()).expect("UTF-8"))
}

fn octets(params: &[u8], nom: &str) -> Option<Vec<u8>> {
    let mut travail = [0_u8; 512];
    let mut sortie = [0_u8; 1024];
    let ecrits =
        write_parameter(params, nom.as_bytes(), &mut travail, &mut sortie).expect("tient")?;
    Some(sortie[..ecrits].to_vec())
}

#[test]
fn la_forme_simple_se_lit() {
    assert_eq!(valeur("; name=\"x.pdf\"", "name").as_deref(), Some("x.pdf"));
    assert_eq!(valeur("; NAME=x.pdf", "name").as_deref(), Some("x.pdf"));
    assert_eq!(
        valeur("; name=\"a \\\"b\\\" c.pdf\"", "name").as_deref(),
        Some("a \"b\" c.pdf")
    );
    // Un pli s'efface.
    assert_eq!(
        valeur("; name=\"a\r\n b.pdf\"", "name").as_deref(),
        Some("a b.pdf")
    );
    // Le premier l'emporte ; un autre nom n'est pas celui-ci.
    assert_eq!(valeur("; name=a; name=b", "name").as_deref(), Some("a"));
    assert_eq!(valeur("; names=a", "name"), None);
    assert_eq!(valeur("; nam=a", "name"), None);
    assert_eq!(valeur("; charset=utf-8", "name"), None);
    assert_eq!(valeur("", "name"), None);
}

/// §5 de RFC 2047 l'interdit, et la moitié des logiciels l'écrit.
#[test]
fn un_mot_encode_dans_la_forme_simple_se_decode() {
    assert_eq!(
        valeur("; name=\"=?utf-8?B?ZMOpZmluaXRpZi5wZGY=?=\"", "name").as_deref(),
        Some("définitif.pdf")
    );
}

#[test]
fn la_forme_etendue_se_lit_et_l_emporte() {
    assert_eq!(
        valeur("; filename*=utf-8''d%C3%A9finitif%20v2.pdf", "filename").as_deref(),
        Some("définitif v2.pdf")
    );
    assert_eq!(
        valeur(
            "; filename=\"defi.pdf\"; filename*=UTF-8'fr'd%C3%A9fi.pdf",
            "filename"
        )
        .as_deref(),
        Some("défi.pdf")
    );
    // `iso-8859-1` se convertit.
    assert_eq!(
        valeur("; filename*=iso-8859-1''d%E9fi.pdf", "filename").as_deref(),
        Some("défi.pdf")
    );
    // Sans jeu, c'est de l'ASCII ; un `%` qui n'ouvre rien reste un `%`.
    assert_eq!(
        valeur("; filename*=a%2", "filename").as_deref(),
        Some("a%2")
    );
    assert_eq!(
        valeur("; filename*=a%zz", "filename").as_deref(),
        Some("a%zz")
    );
    assert_eq!(
        valeur("; filename*=a%4a%4A", "filename").as_deref(),
        Some("aJJ")
    );
    // Un jeu inconnu ne rend rien : un nom faux vaut moins que pas de nom.
    assert_eq!(valeur("; filename*=koi8-r''%C1", "filename"), None);
    // Hors de l'UTF-8 annoncé, les octets restent ce qu'ils sont.
    assert_eq!(
        octets(b"; filename*=utf-8''%FF", "filename"),
        Some(std::vec![0xFF])
    );
}

#[test]
fn les_morceaux_se_raccordent_dans_l_ordre() {
    assert_eq!(
        valeur(
            "; filename*1=\"fin.pdf\"; filename*0*=utf-8''d%C3%A9but%20; x=y",
            "filename"
        )
        .as_deref(),
        Some("début fin.pdf")
    );
    // Sans jeu au morceau zéro, c'est de l'ASCII : les octets passent tels
    // quels, échappements d'une chaîne citée défaits.
    assert_eq!(
        valeur("; name*0=\"un \"; name*1*=%C3%A9; name*2=\"\\\"\"", "name").as_deref(),
        Some("un é\"")
    );
    // Le premier trou arrête tout.
    assert_eq!(valeur("; name*0=a; name*2=c", "name").as_deref(), Some("a"));
    // Le morceau zéro l'emporte sur la forme simple.
    assert_eq!(
        valeur("; name=simple; name*0=morceau", "name").as_deref(),
        Some("morceau")
    );
    // Sans morceau zéro, la forme simple reste.
    assert_eq!(
        valeur("; name=simple; name*1=perdu", "name").as_deref(),
        Some("simple")
    );
    // Un rang mal écrit, ou hors de la table, ne désigne aucun morceau.
    assert_eq!(valeur("; name*01=a", "name"), None);
    assert_eq!(valeur("; name*x=a", "name"), None);
    assert_eq!(valeur("; name**=a", "name"), None);
    assert_eq!(valeur("; name*100=a", "name"), None);
    assert_eq!(
        valeur("; name*0=a; name*70=b", "name").as_deref(),
        Some("a")
    );
    // Un doublon ne remplace pas le premier.
    assert_eq!(valeur("; name*0=a; name*0=b", "name").as_deref(), Some("a"));
}

#[test]
fn un_tampon_trop_court_le_dit() {
    let mut petit = [0_u8; 2];
    let mut sortie = [0_u8; 64];
    let mut travail = [0_u8; 64];
    for params in [
        &b"; name=abc"[..],
        b"; name*=utf-8''abc",
        b"; name*0=abc",
        b"; name*0*=utf-8''abc",
        b"; name*0=a; name*1*=bc",
        b"; name*=%41%42%43",
    ] {
        assert_eq!(
            write_parameter(params, b"name", &mut petit, &mut sortie),
            Err(Error::BufferTooSmall),
            "{params:?}"
        );
        assert_eq!(
            write_parameter(params, b"name", &mut travail, &mut petit),
            Err(Error::BufferTooSmall),
            "{params:?}"
        );
    }
    // La conversion peut grandir : un octet `iso-8859-1` en fait deux.
    assert_eq!(
        write_parameter(b"; name*=latin1''%E9", b"name", &mut travail, &mut []),
        Err(Error::BufferTooSmall)
    );
    let mut juste = [0_u8; 1];
    assert_eq!(
        write_parameter(b"; name*=latin1''%E9", b"name", &mut travail, &mut juste),
        Err(Error::BufferTooSmall)
    );
}
