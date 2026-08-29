//! Ce que le base64 d'un corps MIME écrit.

use super::{BASE64_LINE, base64_max, encode_base64};
use crate::Error;

/// Encode, et rend le texte.
fn encoder(valeur: &[u8]) -> std::string::String {
    let mut sortie = std::vec![0_u8; base64_max(valeur.len())];
    let ecrit = encode_base64(valeur, &mut sortie).expect("encodable");
    std::string::String::from_utf8(ecrit.to_vec()).expect("de l'ASCII")
}

/// Les vecteurs de la RFC 4648 §10, terminaison de ligne comprise.
#[test]
fn les_vecteurs_de_la_rfc_passent() {
    for (clair, attendu) in [
        (&b""[..], "\r\n"),
        (b"f", "Zg==\r\n"),
        (b"fo", "Zm8=\r\n"),
        (b"foo", "Zm9v\r\n"),
        (b"foob", "Zm9vYg==\r\n"),
        (b"fooba", "Zm9vYmE=\r\n"),
        (b"foobar", "Zm9vYmFy\r\n"),
    ] {
        assert_eq!(encoder(clair), attendu, "{clair:?}");
    }
}

/// **Un corps MIME est fait de lignes** : la dernière en a une aussi, sans quoi
/// elle serait recollée au délimiteur qui suit.
#[test]
fn chaque_ligne_a_sa_fin_y_compris_la_derniere() {
    let texte = encoder(&[0_u8; 200]);
    assert!(texte.ends_with("\r\n"));
    for ligne in texte.trim_end_matches("\r\n").split("\r\n") {
        assert!(
            ligne.len() <= BASE64_LINE,
            "ligne de {} caractères : {ligne}",
            ligne.len()
        );
    }
}

/// Soixante-seize est un multiple de quatre : aucun quadruplet n'est coupé.
#[test]
fn le_pliage_ne_coupe_jamais_un_groupe() {
    // 57 octets font exactement 76 caractères.
    let texte = encoder(&[b'x'; 57]);
    assert_eq!(texte, std::format!("{}\r\n", &encoder(&[b'x'; 57])[..76]));
    let long = encoder(&[b'x'; 114]);
    let lignes: std::vec::Vec<&str> = long.trim_end_matches("\r\n").split("\r\n").collect();
    assert_eq!(lignes.len(), 2);
    assert_eq!(lignes[0].len(), BASE64_LINE);
    assert_eq!(lignes[1].len(), BASE64_LINE);
}

#[test]
fn la_majoration_majore_toujours() {
    for taille in [0_usize, 1, 2, 3, 56, 57, 58, 113, 114, 115, 1000] {
        let valeur = std::vec![b'z'; taille];
        let mut juste = std::vec![0_u8; base64_max(taille)];
        let ecrit = encode_base64(&valeur, &mut juste).expect("encodable");
        assert!(
            ecrit.len() <= base64_max(taille),
            "taille {taille} : {} > {}",
            ecrit.len(),
            base64_max(taille)
        );
    }
    assert_eq!(base64_max(usize::MAX), usize::MAX);
}

/// Le tampon peut céder n'importe où : sur une lettre, sur un `=`, sur une fin
/// de ligne.
#[test]
fn un_tampon_trop_court_le_dit_ou_qu_il_cede() {
    let valeur = [b'q'; 100];
    let entier = encoder(&valeur);
    for taille in 0..entier.len() {
        let mut sortie = std::vec![0_u8; taille];
        assert_eq!(
            encode_base64(&valeur, &mut sortie),
            Err(Error::BufferTooSmall),
            "taille {taille}"
        );
    }
}
