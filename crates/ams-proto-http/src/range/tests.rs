// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une requête de portée demande, et ce qu'on en retient.

use super::{ByteRange, RangeFault, parse_range};

/// Une portée, pour comparer sans bruit.
fn portee(first: u64, last: u64) -> Result<ByteRange, RangeFault> {
    Ok(ByteRange { first, last })
}

/// **LE DERNIER OCTET EST DEDANS** (§14.1.1).
///
/// `bytes=0-0` demande UN octet. C'est le piège de cette section : un décalage
/// d'un octet ne se voit pas sur un message, il se voit sur le dernier.
#[test]
fn le_dernier_octet_est_compris() {
    assert_eq!(parse_range(b"bytes=0-0", 100), portee(0, 0));
    assert_eq!(
        parse_range(b"bytes=0-0", 100).expect("licite").octets(),
        1,
        "un octet, et non zéro"
    );
    assert_eq!(parse_range(b"bytes=0-99", 100), portee(0, 99));
    assert_eq!(
        parse_range(b"bytes=10-19", 100).expect("licite").octets(),
        10
    );
}

/// **LES TROIS FORMES DE §14.1.1 SE LISENT.**
#[test]
fn les_trois_formes_se_lisent() {
    // Un intervalle.
    assert_eq!(parse_range(b"bytes=0-499", 1_000), portee(0, 499));
    // Depuis un octet, jusqu'au bout.
    assert_eq!(parse_range(b"bytes=500-", 1_000), portee(500, 999));
    // Les N derniers.
    assert_eq!(parse_range(b"bytes=-500", 1_000), portee(500, 999));
}

/// **UN SUFFIXE PLUS GRAND QUE LA REPRÉSENTATION LA REND ENTIÈRE.**
///
/// §14.1.1 : « if the selected representation is shorter than the specified
/// suffix-length, the entire representation is used ».
#[test]
fn un_suffixe_plus_grand_rend_tout() {
    assert_eq!(parse_range(b"bytes=-5000", 100), portee(0, 99));
}

/// **UN DERNIER OCTET AU-DELÀ SE BORNE, ET NE SE REFUSE PAS** (§14.1.1).
///
/// Refuser obligerait un client à connaître la taille avant de demander — c'est
/// précisément ce qu'il vient chercher.
#[test]
fn un_dernier_octet_au_dela_se_borne() {
    assert_eq!(parse_range(b"bytes=0-99999", 100), portee(0, 99));
    assert_eq!(parse_range(b"bytes=50-99999", 100), portee(50, 99));
}

/// **CE QUI COMMENCE AU-DELÀ NE PEUT PAS ÊTRE SATISFAIT** (§15.5.17).
///
/// Et une représentation VIDE ne se découpe pas : aucune portée ne la satisfait.
#[test]
fn ce_qui_commence_au_dela_se_refuse() {
    assert_eq!(
        parse_range(b"bytes=100-", 100),
        Err(RangeFault::Unsatisfiable)
    );
    assert_eq!(
        parse_range(b"bytes=100-200", 100),
        Err(RangeFault::Unsatisfiable)
    );
    assert_eq!(parse_range(b"bytes=0-0", 0), Err(RangeFault::Unsatisfiable));
    assert_eq!(parse_range(b"bytes=-10", 0), Err(RangeFault::Unsatisfiable));
    // Un suffixe NUL ne désigne rien.
    assert_eq!(
        parse_range(b"bytes=-0", 100),
        Err(RangeFault::Unsatisfiable)
    );
}

/// **CE QU'ON NE COMPREND PAS S'IGNORE** (§14.2), et ne refuse pas la requête.
///
/// « An origin server MUST ignore a Range header field that contains a range unit
/// it does not understand. » Ce n'est pas une faute du client : c'est un champ
/// qu'on n'a pas compris, et la réponse est celle qu'on aurait donnée sans lui.
#[test]
fn ce_qu_on_ne_comprend_pas_s_ignore() {
    for valeur in [
        // Une unité qu'on ne sert pas.
        &b"items=1-3"[..],
        b"bytes 0-99",
        b"",
        // Pas de tiret.
        b"bytes=42",
        // Ni début ni fin.
        b"bytes=-",
        // Deux tirets : deviner reviendrait à inventer une syntaxe.
        b"bytes=1-2-3",
        // Un dernier octet avant le premier.
        b"bytes=99-0",
        // Ce qui n'est pas un chiffre — de chaque côté du tiret, et dans un
        // suffixe : chacun a son chemin de lecture.
        b"bytes=a-b",
        b"bytes=0-abc",
        b"bytes=-abc",
        b"bytes=+1-2",
        b"bytes=1.5-2",
        // Ce qui déborde : saturer ferait servir des octets qu'on n'a pas demandés.
        b"bytes=99999999999999999999999999-",
    ] {
        assert_eq!(
            parse_range(valeur, 1_000),
            Err(RangeFault::Ignored),
            "{}",
            core::str::from_utf8(valeur).unwrap_or("?")
        );
    }
}

/// **UNE SEULE PORTÉE, ET C'EST LA PREMIÈRE** (§14.2).
///
/// Les servir toutes demanderait une réponse `multipart/byteranges`, c'est-à-dire
/// un cadrage MIME que cette API ne produit nulle part ailleurs. Rendre la
/// première est sans ambiguïté : `Content-Range` dit exactement quels octets
/// partent.
#[test]
fn seule_la_premiere_portee_compte() {
    assert_eq!(parse_range(b"bytes=0-9,20-29", 100), portee(0, 9));
    assert_eq!(parse_range(b"bytes=50-59, 0-9", 100), portee(50, 59));
}

/// **LES BLANCS SE ROGNENT**, comme partout dans une valeur de champ.
#[test]
fn les_blancs_se_rognent() {
    assert_eq!(parse_range(b"bytes= 0 - 9 ", 100), portee(0, 9));
    assert_eq!(parse_range(b"bytes=\t10\t-\t19\t", 100), portee(10, 19));
}
