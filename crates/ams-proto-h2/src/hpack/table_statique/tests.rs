// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que la table statique garantit.

use super::{STATIQUE, STATIQUE_LEN, entree_statique};

/// Quelques entrées, confrontées au texte de l'annexe A.
#[test]
fn les_entrees_sont_celles_de_l_annexe() {
    assert_eq!(entree_statique(1), Some((&b":authority"[..], &b""[..])));
    assert_eq!(entree_statique(2), Some((&b":method"[..], &b"GET"[..])));
    assert_eq!(entree_statique(3), Some((&b":method"[..], &b"POST"[..])));
    assert_eq!(entree_statique(4), Some((&b":path"[..], &b"/"[..])));
    assert_eq!(entree_statique(7), Some((&b":scheme"[..], &b"https"[..])));
    assert_eq!(entree_statique(8), Some((&b":status"[..], &b"200"[..])));
    assert_eq!(
        entree_statique(16),
        Some((&b"accept-encoding"[..], &b"gzip, deflate"[..]))
    );
    assert_eq!(entree_statique(32), Some((&b"cookie"[..], &b""[..])));
    assert_eq!(
        entree_statique(61),
        Some((&b"www-authenticate"[..], &b""[..]))
    );
}

/// **L'INDEX ZÉRO NE DÉSIGNE RIEN** (§6.1), et au-delà de soixante et un non
/// plus. Une soustraction sans garde ferait pointer le zéro sur la DERNIÈRE
/// entrée.
#[test]
fn ce_qui_ne_designe_rien_ne_designe_rien() {
    assert_eq!(entree_statique(0), None);
    assert_eq!(entree_statique(62), None);
    assert_eq!(entree_statique(u32::MAX), None);
}

/// **TOUS LES NOMS SONT EN MINUSCULES**, pseudo-en-têtes compris : une table qui
/// porterait `Content-Length` ferait écrire un nom que §8.2.1 refuse.
#[test]
fn tous_les_noms_sont_en_minuscules() {
    assert_eq!(STATIQUE.len(), STATIQUE_LEN as usize);
    for (rang, (nom, _)) in STATIQUE.iter().enumerate() {
        let numero = rang.saturating_add(1);
        assert!(!nom.is_empty(), "entrée {numero} sans nom");
        assert!(
            !nom.iter().any(u8::is_ascii_uppercase),
            "entrée {numero} porte une majuscule"
        );
        // Un nom est soit un pseudo-en-tête, soit un jeton.
        let corps = nom.strip_prefix(b":").unwrap_or(nom);
        assert!(
            ams_proto_http::field_name_is_valid(corps),
            "entrée {numero} n'est pas un nom recevable"
        );
    }
}
