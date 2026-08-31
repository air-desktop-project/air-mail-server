// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un chemin a le droit d'être.

use std::string::{String, ToString};
use std::vec::Vec;

use super::{SEGMENT_OCTETS_MAX, SEGMENTS_MAX, decode, split_query};
use crate::error::Reason;

/// Un tampon confortable.
const PLACE: usize = 1_024;

/// Rend les segments d'un chemin, ou la faute.
fn segments(chemin: &[u8]) -> Result<Vec<String>, Reason> {
    let mut place = [0_u8; PLACE];
    let lus = decode(chemin, &mut place).map_err(|e| e.reason())?;
    Ok((0..lus.len())
        .map(|rang| lus.get(rang).to_string())
        .collect())
}

/// **LE POINT D'INTERROGATION NE FAIT PAS PARTIE DU CHEMIN** (§3.4 de
/// RFC 3986).
#[test]
fn la_chaine_de_requete_se_separe() {
    assert_eq!(split_query(b"/v1/health"), (&b"/v1/health"[..], &b""[..]));
    assert_eq!(
        split_query(b"/v1/health?verbeux=1"),
        (&b"/v1/health"[..], &b"verbeux=1"[..])
    );
    // Un `?` vide, et un `?` en tête.
    assert_eq!(split_query(b"/v1/health?"), (&b"/v1/health"[..], &b""[..]));
    assert_eq!(split_query(b"?tout"), (&b""[..], &b"tout"[..]));
    // Le PREMIER `?` seulement : les suivants appartiennent à la requête.
    assert_eq!(split_query(b"/a?b?c"), (&b"/a"[..], &b"b?c"[..]));
}

/// Un chemin ordinaire se découpe.
#[test]
fn un_chemin_ordinaire_se_decoupe() {
    assert_eq!(
        segments(b"/v1/mailboxes/INBOX/messages/12"),
        Ok(std::vec![
            "v1".to_string(),
            "mailboxes".to_string(),
            "INBOX".to_string(),
            "messages".to_string(),
            "12".to_string(),
        ])
    );
    // La racine : zéro segment, et non un segment vide.
    assert_eq!(segments(b"/"), Ok(std::vec![]));
}

/// **UN CHEMIN D'ORIGINE COMMENCE PAR UNE BARRE OBLIQUE** (§3.3) : le reste n'a
/// pas sa place sur une requête d'API.
#[test]
fn un_chemin_sans_barre_de_tete_se_refuse() {
    for mauvais in [&b""[..], b"v1/health", b"http://ailleurs/v1/health", b"*"] {
        assert_eq!(segments(mauvais), Err(Reason::BadPath), "{mauvais:?}");
    }
}

/// **LE `%2F` EST LE CŒUR DU SUJET** : découper avant de décoder est ce qui
/// empêche `a%2F..%2Fb` de devenir trois segments dont un `..`.
#[test]
fn un_pourcent_deux_f_reste_dans_son_segment() {
    assert_eq!(
        segments(b"/v1/mailboxes/a%2F..%2Fb"),
        Ok(std::vec![
            "v1".to_string(),
            "mailboxes".to_string(),
            "a/../b".to_string(),
        ]),
        "le segment doit rester entier, points compris"
    );
    // Et une barre oblique littérale, elle, découpe bien.
    assert_eq!(segments(b"/v1/mailboxes/a/b").map(|v| v.len()), Ok(4));
}

/// **NI `.` NI `..`** : le premier ne dit rien, le second remonte.
#[test]
fn les_segments_de_navigation_se_refusent() {
    for mauvais in [
        &b"/v1/./health"[..],
        b"/v1/../health",
        b"/..",
        b"/.",
        b"/v1/health/..",
        // Encodés, ils sont exactement les mêmes.
        b"/v1/%2e%2e/health",
        b"/v1/%2E/health",
    ] {
        assert_eq!(segments(mauvais), Err(Reason::BadPath), "{mauvais:?}");
    }
}

/// **UN SEGMENT VIDE EST UNE SECONDE ÉCRITURE DE LA MÊME CHOSE** : `//` et `/`
/// désignent la même ressource, et deux écritures sont une de trop.
#[test]
fn un_segment_vide_se_refuse() {
    for mauvais in [&b"//v1/health"[..], b"/v1//health", b"/v1/health/"] {
        assert_eq!(segments(mauvais), Err(Reason::BadPath), "{mauvais:?}");
    }
}

/// **AUCUN OCTET DE CONTRÔLE**, encodé ou non : un NUL coupe un nom de fichier
/// au milieu chez qui le lit en C, un saut de ligne coupe un journal en deux.
#[test]
fn les_octets_de_controle_se_refusent() {
    for mauvais in [
        &b"/v1/%00"[..],
        b"/v1/a%00b",
        b"/v1/%0a",
        b"/v1/%0D%0Aautre",
        b"/v1/%7f",
        b"/v1/a\nb",
    ] {
        assert_eq!(segments(mauvais), Err(Reason::BadPath), "{mauvais:?}");
    }
}

/// Un pourcentage mal écrit se refuse.
#[test]
fn un_pourcentage_mal_ecrit_se_refuse() {
    for mauvais in [
        &b"/v1/%"[..],
        b"/v1/%2",
        b"/v1/%zz",
        b"/v1/%2z",
        b"/v1/%g0",
        b"/v1/a%",
    ] {
        assert_eq!(segments(mauvais), Err(Reason::BadPath), "{mauvais:?}");
    }
}

/// **LES DEUX CASSES SONT LE MÊME OCTET** (§6.2.2.1 de RFC 3986) : les
/// distinguer ferait deux écritures là où la norme n'en voit qu'une.
#[test]
fn les_deux_casses_hexadecimales_se_lisent() {
    assert_eq!(segments(b"/%41%62"), segments(b"/%41%62"));
    assert_eq!(segments(b"/%2b"), Ok(std::vec!["+".to_string()]));
    assert_eq!(segments(b"/%2B"), Ok(std::vec!["+".to_string()]));
}

/// **DE L'UTF-8, ET RIEN D'AUTRE** : deux lecteurs qui ne voient pas le même nom,
/// c'est le même écart que deux écritures d'un chemin.
#[test]
fn ce_qui_n_est_pas_de_l_utf8_se_refuse() {
    // Une séquence tronquée, et un octet interdit.
    for mauvais in [&b"/%c3"[..], b"/%ff", b"/%ed%a0%80"] {
        assert_eq!(segments(mauvais), Err(Reason::BadPath), "{mauvais:?}");
    }
    // De l'UTF-8 valide passe, encodé ou non.
    assert_eq!(
        segments(b"/%C3%A9t%C3%A9"),
        Ok(std::vec!["été".to_string()])
    );
    assert_eq!(
        segments("/été".as_bytes()),
        Ok(std::vec!["été".to_string()])
    );
}

/// Un chemin plus long que ce qu'on retient se dit, et se distingue d'un chemin
/// inconnu.
#[test]
fn un_chemin_trop_long_se_dit() {
    let mut chemin = String::new();
    for rang in 0..=SEGMENTS_MAX {
        chemin.push_str(&std::format!("/s{rang}"));
    }
    assert_eq!(segments(chemin.as_bytes()), Err(Reason::PathTooLong));

    // Pile la borne passe.
    let mut pile = String::new();
    for rang in 0..SEGMENTS_MAX {
        pile.push_str(&std::format!("/s{rang}"));
    }
    assert_eq!(segments(pile.as_bytes()).map(|v| v.len()), Ok(SEGMENTS_MAX));
}

/// Un segment plus long que ce qu'un nom de fichier peut porter se refuse.
#[test]
fn un_segment_trop_long_se_refuse() {
    let long = std::format!("/{}", "a".repeat(SEGMENT_OCTETS_MAX + 1));
    assert_eq!(segments(long.as_bytes()), Err(Reason::BadPath));
    // Pile la borne passe.
    let pile = std::format!("/{}", "a".repeat(SEGMENT_OCTETS_MAX));
    assert_eq!(segments(pile.as_bytes()).map(|v| v.len()), Ok(1));
}

/// **LA LONGUEUR SE MESURE APRÈS DÉCODAGE** : un nom de 255 octets s'écrit sur
/// 255 octets, ou sur 765 s'il est entièrement encodé. Mesurer la forme reçue
/// ferait accepter ce nom dans une écriture et le refuser dans l'autre.
///
/// Défaut écrit, puis trouvé par le fuzz.
#[test]
fn la_longueur_se_mesure_apres_decodage() {
    // Le même nom, écrit deux fois : en clair, et entièrement encodé.
    let clair = std::format!("/{}", "a".repeat(SEGMENT_OCTETS_MAX));
    let encode = std::format!("/{}", "%61".repeat(SEGMENT_OCTETS_MAX));
    assert_eq!(
        segments(clair.as_bytes()),
        segments(encode.as_bytes()),
        "deux écritures d'un même nom ne donnent pas la même réponse"
    );
    assert!(segments(encode.as_bytes()).is_ok());

    // Et un octet de trop se refuse, quelle que soit l'écriture.
    let trop_clair = std::format!("/{}", "a".repeat(SEGMENT_OCTETS_MAX + 1));
    let trop_encode = std::format!("/{}", "%61".repeat(SEGMENT_OCTETS_MAX + 1));
    assert_eq!(segments(trop_clair.as_bytes()), Err(Reason::BadPath));
    assert_eq!(segments(trop_encode.as_bytes()), Err(Reason::BadPath));
}

/// **NOTRE TAMPON, NOTRE FAUTE** : le client n'a rien fait de mal, et lui
/// imputer la faute rendrait son journal mensonger.
#[test]
fn un_tampon_trop_court_est_notre_faute() {
    let mut minuscule = [0_u8; 3];
    let issue = decode(b"/v1/mailboxes", &mut minuscule).expect_err("trop court");
    assert_eq!(issue.reason(), Reason::BufferTooSmall);
}

/// Un rang au-delà de ce qui a été lu ne rend rien.
#[test]
fn un_rang_au_dela_ne_rend_rien() {
    let mut place = [0_u8; PLACE];
    let lus = decode(b"/v1", &mut place).expect("licite");
    assert_eq!(lus.len(), 1);
    assert!(!lus.is_empty());
    assert_eq!(lus.get(0), "v1");
    // **LA CHAÎNE VIDE NE PEUT DÉSIGNER QU'UNE ABSENCE** : aucun segment valide
    // n'est vide, puisque le décodage les refuse.
    assert_eq!(lus.get(1), "");
    assert_eq!(lus.get(SEGMENTS_MAX + 10), "");

    let vide = decode(b"/", &mut place).expect("licite");
    assert!(vide.is_empty());
}
