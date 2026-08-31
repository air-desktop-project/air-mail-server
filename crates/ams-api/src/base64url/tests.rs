// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que le base64url a le droit d'être.

use std::string::{String, ToString};
use std::vec::Vec;

use super::{decode, decoded_len, encode, encoded_len};
use crate::error::Reason;

/// Un tampon confortable.
const PLACE: usize = 256;

/// Écrit, et rend le texte.
fn ecrire(donnees: &[u8]) -> String {
    let mut place = [0_u8; PLACE];
    let ecrit = encode(donnees, &mut place).expect("écrivable");
    core::str::from_utf8(ecrit).expect("de l'ASCII").to_string()
}

/// Lit, ou rend la faute.
fn lire(texte: &[u8]) -> Result<Vec<u8>, Reason> {
    let mut place = [0_u8; PLACE];
    decode(texte, &mut place)
        .map(<[u8]>::to_vec)
        .map_err(|e| e.reason())
}

/// **LES VECTEURS DE §10 DE RFC 4648**, transposés dans l'alphabet de §5 et sans
/// remplissage.
#[test]
fn les_vecteurs_de_la_rfc_4648() {
    let cas = [
        (&b""[..], ""),
        (b"f", "Zg"),
        (b"fo", "Zm8"),
        (b"foo", "Zm9v"),
        (b"foob", "Zm9vYg"),
        (b"fooba", "Zm9vYmE"),
        (b"foobar", "Zm9vYmFy"),
    ];
    for (donnees, attendu) in cas {
        assert_eq!(ecrire(donnees), attendu, "{donnees:?}");
        assert_eq!(lire(attendu.as_bytes()), Ok(donnees.to_vec()), "{attendu}");
    }
}

/// **L'ALPHABET EST CELUI DE §5** : `-` et `_`, jamais `+` ni `/`.
#[test]
fn l_alphabet_est_celui_de_l_url() {
    // Ces trois octets donnent les deux derniers caractères de l'alphabet.
    let ecrit = ecrire(&[0xfb, 0xff, 0xbf]);
    assert!(ecrit.contains('-'), "{ecrit}");
    assert!(ecrit.contains('_'), "{ecrit}");
    assert!(!ecrit.contains('+'));
    assert!(!ecrit.contains('/'));
    // Et l'on refuse ceux de §4.
    for hors in [&b"++++"[..], b"////", b"Zm9+", b"Zm9/"] {
        assert_eq!(lire(hors), Err(Reason::BadToken), "{hors:?}");
    }
}

/// **PAS DE REMPLISSAGE** : le `=` n'appartient pas à cette écriture.
#[test]
fn le_remplissage_se_refuse() {
    assert!(!ecrire(b"f").contains('='));
    assert!(!ecrire(b"fo").contains('='));
    for avec in [&b"Zg=="[..], b"Zm8=", b"="] {
        assert_eq!(lire(avec), Err(Reason::BadToken), "{avec:?}");
    }
}

/// **UN SEUL CARACTÈRE DE QUEUE EST IMPOSSIBLE** : six bits ne font pas un
/// octet, et l'accepter reviendrait à inventer les deux qui manquent.
#[test]
fn une_longueur_impossible_se_refuse() {
    for impossible in [&b"A"[..], b"AAAAA", b"Zm9vYmFyA"] {
        assert_eq!(lire(impossible), Err(Reason::BadToken), "{impossible:?}");
        assert_eq!(decoded_len(impossible.len()), None);
    }
}

/// **LES BITS DE REMPLISSAGE DOIVENT ÊTRE NULS** (§3.5 de RFC 4648).
///
/// Sans ce refus, plusieurs écritures désignent le même jeton — et une
/// révocation cesse de reconnaître ce qu'elle a révoqué.
#[test]
fn les_bits_de_remplissage_non_nuls_se_refusent() {
    // « Zg » écrit l'octet 0x66 ; les quatre bits de queue sont nuls. Les
    // caractères qui suivent `g` dans l'alphabet portent les mêmes huit bits de
    // tête avec des bits de queue non nuls.
    assert_eq!(lire(b"Zg"), Ok(std::vec![0x66]));
    for non_canonique in [&b"Zh"[..], b"Zi", b"Zj", b"Zk", b"Zl", b"Zm", b"Zn"] {
        assert_eq!(
            lire(non_canonique),
            Err(Reason::BadToken),
            "{non_canonique:?} porte des bits de remplissage non nuls"
        );
    }
    // Trois caractères : deux bits de queue.
    assert_eq!(lire(b"Zm8"), Ok(std::vec![0x66, 0x6f]));
    for non_canonique in [&b"Zm9"[..], b"Zm-"] {
        assert_eq!(
            lire(non_canonique),
            Err(Reason::BadToken),
            "{non_canonique:?}"
        );
    }
}

/// **CE QU'ON ÉCRIT SE RELIT, ET SE RÉÉCRIT IDENTIQUE.**
#[test]
fn l_aller_retour_est_stable() {
    for taille in 0..64_usize {
        let donnees: Vec<u8> = (0..taille)
            .map(|rang| u8::try_from(rang % 251).unwrap_or(0))
            .collect();
        let ecrit = ecrire(&donnees);
        assert_eq!(ecrit.len(), encoded_len(taille), "{taille} octets");
        assert_eq!(decoded_len(ecrit.len()), Some(taille));
        assert_eq!(lire(ecrit.as_bytes()), Ok(donnees.clone()), "{taille}");
        assert_eq!(ecrire(&donnees), ecrit, "l'écriture n'est pas déterministe");
    }
}

/// Les mesures s'accordent avec ce qu'on écrit.
#[test]
fn les_mesures_s_accordent() {
    assert_eq!(encoded_len(0), 0);
    assert_eq!(encoded_len(1), 2);
    assert_eq!(encoded_len(2), 3);
    assert_eq!(encoded_len(3), 4);
    assert_eq!(encoded_len(4), 6);
    assert_eq!(decoded_len(0), Some(0));
    assert_eq!(decoded_len(2), Some(1));
    assert_eq!(decoded_len(3), Some(2));
    assert_eq!(decoded_len(4), Some(3));
}

/// **NOTRE TAMPON, NOTRE FAUTE.**
#[test]
fn un_tampon_trop_court_est_notre_faute() {
    let mut minuscule = [0_u8; 2];
    let faute = encode(b"foobar", &mut minuscule).expect_err("trop court");
    assert_eq!(faute.reason(), Reason::BufferTooSmall);
    let faute = decode(b"Zm9vYmFy", &mut minuscule).expect_err("trop court");
    assert_eq!(faute.reason(), Reason::BufferTooSmall);
}
