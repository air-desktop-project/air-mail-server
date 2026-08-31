// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un corps JSON a le droit d'être.

use std::string::{String, ToString};
use std::vec::Vec;

use super::{BODY_DEPTH_MAX, Event, FIELDS_MAX, Number, Reader, Str};
use crate::error::Reason;

/// Lit tout le corps, et rend les événements sous une forme comparable.
fn lire(corps: &[u8]) -> Result<Vec<String>, Reason> {
    let mut lecteur = Reader::new(corps);
    let mut vus = Vec::new();
    loop {
        match lecteur.read().map_err(|e| e.reason())? {
            None => return Ok(vus),
            Some(evenement) => vus.push(nommer(&evenement)),
        }
        assert!(vus.len() < 1_000, "le lecteur n'avance pas");
    }
}

/// Le nom d'un événement, pour comparer.
fn nommer(evenement: &Event<'_>) -> String {
    match *evenement {
        Event::ObjectStart => "{".to_string(),
        Event::ObjectEnd => "}".to_string(),
        Event::ArrayStart => "[".to_string(),
        Event::ArrayEnd => "]".to_string(),
        Event::Key(texte) => std::format!("clef:{}", texte.raw()),
        Event::Text(texte) => std::format!("texte:{}", texte.raw()),
        Event::Number(nombre) => std::format!("nombre:{:?}", nombre.as_i64()),
        Event::Bool(valeur) => std::format!("bool:{valeur}"),
        Event::Null => "null".to_string(),
    }
}

/// La chaîne que porte cet événement, s'il en porte une.
fn en_texte<'a>(evenement: Event<'a>) -> Option<Str<'a>> {
    match evenement {
        Event::Text(texte) => Some(texte),
        _ => None,
    }
}

/// Le nombre que porte cet événement, s'il en porte un.
fn en_nombre(evenement: Event<'_>) -> Option<Number> {
    match evenement {
        Event::Number(nombre) => Some(nombre),
        _ => None,
    }
}

/// Le premier événement d'un corps.
fn premier(corps: &[u8]) -> Event<'_> {
    Reader::new(corps)
        .read()
        .expect("un corps licite")
        .expect("un événement")
}

/// **LES EXTRACTEURS RENDENT `None` SUR AUTRE CHOSE**, et c'est ce qui permet
/// aux essais de dire `expect` plutôt que d'ouvrir un arc qu'ils n'empruntent
/// jamais.
#[test]
fn les_extracteurs_refusent_ce_qui_n_est_pas_du_bon_type() {
    assert!(en_texte(premier(b"1")).is_none());
    assert!(en_texte(premier(b"[]")).is_none());
    assert!(en_nombre(premier(br#""a""#)).is_none());
    assert!(en_nombre(premier(b"null")).is_none());
}

/// Ce corps est-il accepté ?
fn accepte(corps: &[u8]) -> bool {
    lire(corps).is_ok()
}

/// Un corps ordinaire se lit.
#[test]
fn un_corps_ordinaire_se_lit() {
    assert_eq!(
        lire(br#"{"boite":"INBOX","lus":12,"vide":false,"sujet":null}"#),
        Ok(std::vec![
            "{".to_string(),
            "clef:boite".to_string(),
            "texte:INBOX".to_string(),
            "clef:lus".to_string(),
            "nombre:Some(12)".to_string(),
            "clef:vide".to_string(),
            "bool:false".to_string(),
            "clef:sujet".to_string(),
            "null".to_string(),
            "}".to_string(),
        ])
    );
}

/// Les valeurs seules font des documents, comme §2 le dit.
#[test]
fn une_valeur_seule_fait_un_document() {
    assert_eq!(lire(b"42"), Ok(std::vec!["nombre:Some(42)".to_string()]));
    assert_eq!(lire(b"true"), Ok(std::vec!["bool:true".to_string()]));
    assert_eq!(lire(b"null"), Ok(std::vec!["null".to_string()]));
    assert_eq!(lire(br#""a""#), Ok(std::vec!["texte:a".to_string()]));
    assert_eq!(lire(b"{}"), Ok(std::vec!["{".to_string(), "}".to_string()]));
    assert_eq!(lire(b"[]"), Ok(std::vec!["[".to_string(), "]".to_string()]));
}

/// Les blancs de §2 se sautent, et rien d'autre ne se saute.
#[test]
fn seuls_les_blancs_de_la_rfc_se_sautent() {
    assert!(accepte(b" \t\r\n [ 1 , 2 ] \r\n"));
    // Ni la page suivante, ni l'espace insécable, ni la marque d'ordre des
    // octets : §8.1 interdit d'en ajouter une.
    assert!(!accepte(b"\x0c[1]"), "la page suivante n'est pas un blanc");
    assert!(
        !accepte("\u{a0}[1]".as_bytes()),
        "l'espace insécable non plus"
    );
    assert!(!accepte("\u{feff}[1]".as_bytes()), "ni la marque d'ordre");
}

/// **LES CLÉS RÉPÉTÉES SE REFUSENT** : §4 dit seulement « SHOULD be unique », et
/// chaque analyseur en fait ce qu'il veut.
#[test]
fn les_clefs_repetees_se_refusent() {
    assert!(!accepte(br#"{"admin":false,"admin":true}"#));
    assert!(!accepte(br#"{"a":1,"b":2,"a":3}"#));
    // Deux objets frères peuvent porter la même clé : ce n'est pas une
    // répétition.
    assert!(accepte(br#"[{"a":1},{"a":2}]"#));
    // Et un objet imbriqué non plus.
    assert!(accepte(br#"{"a":{"a":1}}"#));
}

/// **APRÈS LA VALEUR RACINE, PLUS RIEN** : deux documents collés se lisent
/// différemment selon l'analyseur.
#[test]
fn rien_ne_suit_la_valeur_racine() {
    assert!(!accepte(br#"{"a":1}{"b":2}"#));
    assert!(!accepte(b"1 2"));
    assert!(!accepte(b"[] []"));
    assert!(!accepte(b"nullnull"));
    // Des blancs, en revanche, sont permis.
    assert!(accepte(b"1  \n"));
}

/// **NI VIRGULE NI EXPOSANT** : la précision est laissée à l'implémentation
/// (§6), donc deux lecteurs peuvent voir deux valeurs.
#[test]
fn les_nombres_a_virgule_se_refusent() {
    for mauvais in [
        &b"1.0"[..],
        b"0.1",
        b"1e3",
        b"1E3",
        b"1e+3",
        b"-1.5",
        b"[1.0]",
    ] {
        assert!(!accepte(mauvais), "{mauvais:?}");
    }
}

/// **PAS DE ZÉRO DE TÊTE** (§6) : l'accepter donnerait deux écritures d'un même
/// nombre.
#[test]
fn les_zeros_de_tete_se_refusent() {
    assert!(!accepte(b"01"));
    assert!(!accepte(b"-01"));
    assert!(!accepte(b"[00]"));
    // Zéro seul, lui, est licite.
    assert_eq!(lire(b"0"), Ok(std::vec!["nombre:Some(0)".to_string()]));
    assert_eq!(lire(b"-0"), Ok(std::vec!["nombre:Some(0)".to_string()]));
}

/// Un mot-clé tronqué n'est pas un mot-clé.
#[test]
fn un_mot_clef_tronque_se_refuse() {
    for mauvais in [
        &b"tru"[..],
        b"fals",
        b"nul",
        b"t",
        b"f",
        b"n",
        b"trux",
        b"nulx",
    ] {
        assert!(!accepte(mauvais), "{mauvais:?}");
    }
}

/// Deux valeurs sans virgule ne font pas une suite.
#[test]
fn deux_valeurs_sans_virgule_se_refusent() {
    assert!(!accepte(b"[1 2]"));
    assert!(!accepte(br#"["a" "b"]"#));
    assert!(!accepte(br#"{"a":1 "b":2}"#));
}

/// **CHAQUE TRONCATURE D'UN CORPS VALIDE SE REFUSE.**
///
/// C'est la propriété qui compte pour un serveur : un corps coupé en route — par
/// une connexion perdue, par un intermédiaire, ou exprès — ne doit jamais se lire
/// comme un corps complet mais plus court. Sans cela, `{"admin":true}` tronqué à
/// `{"admin":tru` pourrait passer pour autre chose.
#[test]
fn chaque_troncature_d_un_corps_valide_se_refuse() {
    let entier = br#"{"boite":"a\nb","lus":12,"vide":false,"d":["x",-3],"s":null}"#;
    assert!(accepte(entier), "le corps entier doit passer");
    for coupe in 0..entier.len() {
        let tronque = entier.get(..coupe).unwrap_or_default();
        // Le message ne calcule rien : ce qui n'est évalué qu'en cas d'échec
        // n'est jamais parcouru quand l'essai passe.
        assert!(
            !accepte(tronque),
            "la troncature à {coupe} octets est passée"
        );
    }
}

/// Une chaîne mal formée à l'intérieur d'une structure se refuse aussi.
#[test]
fn une_chaine_mal_formee_dans_une_structure_se_refuse() {
    assert!(!accepte(br#"["a]"#));
    assert!(!accepte(br#"{"a":"b}"#));
    assert!(!accepte(br#"["\u00"#));
    assert!(!accepte(br#"["\ud83d\u"#));
    // Une moitié haute suivie d'un échappement qui n'est pas un `\u`.
    assert!(!accepte(br#""\ud83d\n""#));
}

/// **LES DEUX CASSES HEXADÉCIMALES SE LISENT** : `\u00E9` et `\u00e9`
/// désignent le même caractère, et §7 ne privilégie ni l'une ni l'autre.
#[test]
fn les_deux_casses_hexadecimales_se_lisent() {
    for corps in [&br#""\u00E9""#[..], br#""\u00e9""#] {
        let texte = en_texte(premier(corps)).expect("une chaîne");
        let mut place = [0_u8; 8];
        assert_eq!(texte.unescape(&mut place), Ok("é"), "{corps:?}");
    }
}

/// Ce qui n'est pas un nombre ne se lit pas comme tel.
#[test]
fn ce_qui_n_est_pas_un_nombre_se_refuse() {
    for mauvais in [&b"-"[..], b"+1", b"NaN", b"Infinity", b"-a", b"1a"] {
        assert!(!accepte(mauvais), "{mauvais:?}");
    }
}

/// **LE SIGNE ET LA GRANDEUR SONT SÉPARÉS** : aucun type entier ne porte les
/// deux, et c'est l'appelant qui dit dans quoi il veut ranger.
#[test]
fn le_signe_et_la_grandeur_se_demandent_separement() {
    let grand = en_nombre(premier(b"18446744073709551615")).expect("un nombre");
    assert_eq!(grand.as_u64(), Some(u64::MAX));
    assert_eq!(grand.as_i64(), None, "il ne tient pas dans un signé");

    let petit = en_nombre(premier(b"-9223372036854775808")).expect("un nombre");
    assert_eq!(petit.as_i64(), Some(i64::MIN));
    assert_eq!(petit.as_u64(), None, "il est négatif");

    // Zéro négatif vaut zéro, dans les deux sens.
    let zero = en_nombre(premier(b"-0")).expect("un nombre");
    assert_eq!(zero.as_u64(), Some(0));
    assert_eq!(zero.as_i64(), Some(0));
}

/// Ce qui déborde d'un `u64` se refuse à la lecture.
#[test]
fn un_nombre_qui_deborde_se_refuse() {
    assert!(!accepte(b"18446744073709551616"));
    assert!(!accepte(b"99999999999999999999999999"));
}

/// **PAS DE VIRGULE FINALE** : `[1,]` se lit différemment selon l'analyseur.
#[test]
fn les_virgules_finales_se_refusent() {
    assert!(!accepte(b"[1,]"));
    assert!(!accepte(br#"{"a":1,}"#));
    assert!(!accepte(b"[,]"));
    assert!(!accepte(b"[1,,2]"));
}

/// Une structure mal close se refuse.
#[test]
fn une_structure_mal_close_se_refuse() {
    for mauvais in [
        &b"["[..],
        b"{",
        b"]",
        b"}",
        b"[}",
        b"{]",
        br#"{"a"}"#,
        br#"{"a":}"#,
        br#"{"a":1"#,
        b"[1",
        b"",
        b"   ",
    ] {
        assert!(!accepte(mauvais), "{mauvais:?}");
    }
}

/// Une clé qui n'est pas une chaîne se refuse.
#[test]
fn une_clef_qui_n_est_pas_une_chaine_se_refuse() {
    assert!(!accepte(br#"{a:1}"#));
    assert!(!accepte(br#"{1:2}"#));
    assert!(!accepte(br#"{"a" 1}"#));
}

/// **AUCUN OCTET DE CONTRÔLE NON ÉCHAPPÉ** (§7) : l'accepter ferait passer un
/// saut de ligne dans un nom.
#[test]
fn les_octets_de_controle_se_refusent_dans_une_chaine() {
    for point in 0..0x20_u8 {
        let corps = [b'"', point, b'"'];
        assert!(!accepte(&corps), "le point {point:#04x} est passé");
    }
    // Échappés, ils passent.
    assert!(accepte(br#""\n""#));
    assert!(accepte(br#""\u0000""#));
}

/// Les échappements de §7 se lisent, et les autres se refusent.
#[test]
fn les_echappements_de_la_rfc() {
    for bon in [
        &br#""\"""#[..],
        br#""\\""#,
        br#""\/""#,
        br#""\b""#,
        br#""\f""#,
        br#""\n""#,
        br#""\r""#,
        br#""\t""#,
        br#""\u0041""#,
    ] {
        assert!(accepte(bon), "{bon:?}");
    }
    for mauvais in [
        &br#""\x41""#[..],
        br#""\a""#,
        br#""\""#,
        br#""\u""#,
        br#""\u00""#,
        br#""\u00zz""#,
        br#""\U0041""#,
    ] {
        assert!(!accepte(mauvais), "{mauvais:?}");
    }
}

/// **UNE MOITIÉ DE PAIRE N'EST PAS UN CARACTÈRE** : trois analyseurs en font
/// trois choses, dont deux silencieuses.
#[test]
fn une_moitie_de_paire_se_refuse() {
    // Une moitié haute seule.
    assert!(!accepte(br#""\ud83d""#));
    // Une moitié haute suivie d'autre chose qu'une basse.
    assert!(!accepte(br#""\ud83dA""#));
    assert!(!accepte(br#""\ud83d\ud83d""#));
    // Une moitié basse en premier n'ouvre rien.
    assert!(!accepte(br#""\ude00""#));
    // La paire entière, elle, passe.
    assert!(accepte(br#""\ud83d\ude00""#));
}

/// **ON NE DÉCODE QUE CE QUE L'APPELANT DEMANDE**, et une chaîne sans
/// échappement ne se copie pas.
#[test]
fn une_chaine_sans_echappement_ne_se_copie_pas() {
    let texte = en_texte(premier(br#""INBOX""#)).expect("une chaîne");
    assert_eq!(texte.as_plain(), Some("INBOX"));
    assert_eq!(texte.raw(), "INBOX");
    assert!(texte.is("INBOX"));
    assert!(!texte.is("AUTRE"));

    let echappee = en_texte(premier(br#""a\nb""#)).expect("une chaîne");
    assert_eq!(echappee.as_plain(), None, "elle porte un échappement");
    assert_eq!(echappee.raw(), r"a\nb");
    // **UNE CHAÎNE ÉCHAPPÉE NE VAUT JAMAIS UN LITTÉRAL.**
    assert!(!echappee.is("a\nb"), "la comparaison ne décode pas");
}

/// Ce qui est échappé se décode à la demande.
#[test]
fn les_echappements_se_decodent_a_la_demande() {
    let cas: [(&[u8], &str); 8] = [
        (br#""a\nb""#, "a\nb"),
        (br#""\t""#, "\t"),
        (br#""\r""#, "\r"),
        (br#""\b""#, "\u{8}"),
        (br#""\f""#, "\u{c}"),
        (br#""\/""#, "/"),
        (br#""\u0041\u00e9""#, "Aé"),
        (br#""\ud83d\ude00""#, "\u{1f600}"),
    ];
    for (corps, attendu) in cas {
        let texte = en_texte(premier(corps)).expect("une chaîne");
        let mut place = [0_u8; 64];
        assert_eq!(texte.unescape(&mut place), Ok(attendu), "{corps:?}");
    }
}

/// **NOTRE TAMPON, NOTRE FAUTE.**
#[test]
fn un_tampon_trop_court_pour_decoder_est_notre_faute() {
    let texte = en_texte(premier(br#""ABC""#)).expect("une chaîne");
    for taille in 0..3_usize {
        let mut petit = std::vec![0_u8; taille];
        assert_eq!(
            texte.unescape(&mut petit).map_err(|e| e.reason()),
            Err(Reason::BufferTooSmall),
            "{taille}"
        );
    }
    let mut pile = [0_u8; 3];
    assert_eq!(texte.unescape(&mut pile), Ok("ABC"));
}

/// **AUCUN ÉCHAPPEMENT DANS UNE CLÉ** : savoir lequel de deux noms équivalents
/// gagne est une question qu'on préfère ne pas poser.
#[test]
fn une_clef_echappee_se_refuse() {
    assert!(!accepte(br#"{"\u0061":1}"#));
    assert!(!accepte(br#"{"a\nb":1}"#));
    // Sans échappement, elle passe.
    assert!(accepte(br#"{"a":1}"#));
}

/// **IL NE RÉCURSE PAS**, et la borne se dit.
#[test]
fn au_dela_de_la_profondeur_on_refuse() {
    let trop = "[".repeat(BODY_DEPTH_MAX + 1);
    assert!(!accepte(trop.as_bytes()));
    // Pile la borne passe, et se referme.
    let pile = std::format!(
        "{}{}",
        "[".repeat(BODY_DEPTH_MAX),
        "]".repeat(BODY_DEPTH_MAX)
    );
    assert!(accepte(pile.as_bytes()), "{pile}");
    // Et un corps qui n'est que des crochets ouvrants ne fait pas grandir la
    // pile d'appels : il se heurte à la borne.
    let bombe = "[".repeat(100_000);
    assert!(!accepte(bombe.as_bytes()));

    // La même borne vaut pour les objets.
    let objets = std::format!(
        "{}1{}",
        r#"{"a":"#.repeat(BODY_DEPTH_MAX + 1),
        "}".repeat(BODY_DEPTH_MAX + 1)
    );
    assert!(!accepte(objets.as_bytes()));
    let pile_objets = std::format!(
        "{}1{}",
        r#"{"a":"#.repeat(BODY_DEPTH_MAX),
        "}".repeat(BODY_DEPTH_MAX)
    );
    assert!(accepte(pile_objets.as_bytes()), "{pile_objets}");
}

/// Au-delà de ce qu'on retient de clés, on refuse.
#[test]
fn au_dela_des_champs_qu_on_retient_on_refuse() {
    let mut corps = String::from("{");
    for rang in 0..FIELDS_MAX {
        if rang > 0 {
            corps.push(',');
        }
        corps.push_str(&std::format!("\"c{rang}\":1"));
    }
    corps.push('}');
    assert!(accepte(corps.as_bytes()), "{corps}");

    let mut trop = String::from("{");
    for rang in 0..=FIELDS_MAX {
        if rang > 0 {
            trop.push(',');
        }
        trop.push_str(&std::format!("\"c{rang}\":1"));
    }
    trop.push('}');
    assert!(!accepte(trop.as_bytes()));
}

/// Ce qui n'est pas de l'UTF-8 se refuse.
#[test]
fn ce_qui_n_est_pas_de_l_utf8_se_refuse() {
    assert!(!accepte(&[b'"', 0xff, b'"']));
    assert!(!accepte(&[b'"', 0xc3, b'"']));
    // De l'UTF-8 valide passe.
    assert!(accepte("\"été\"".as_bytes()));
}

/// Un corps imbriqué se lit dans l'ordre.
#[test]
fn un_corps_imbrique_se_lit_dans_l_ordre() {
    assert_eq!(
        lire(br#"{"drapeaux":["\\Seen","\\Answered"]}"#),
        Ok(std::vec![
            "{".to_string(),
            "clef:drapeaux".to_string(),
            "[".to_string(),
            r"texte:\\Seen".to_string(),
            r"texte:\\Answered".to_string(),
            "]".to_string(),
            "}".to_string(),
        ])
    );
}

/// Un nombre porte bien son signe et sa grandeur.
#[test]
fn un_nombre_se_range_ou_il_tient() {
    let cas: [(&[u8], Option<u64>, Option<i64>); 4] = [
        (b"0", Some(0), Some(0)),
        (b"12", Some(12), Some(12)),
        (b"-12", None, Some(-12)),
        (b"18446744073709551615", Some(u64::MAX), None),
    ];
    for (corps, non_signe, signe) in cas {
        let nombre = en_nombre(premier(corps)).expect("un nombre");
        assert_eq!(nombre.as_u64(), non_signe, "{corps:?}");
        assert_eq!(nombre.as_i64(), signe, "{corps:?}");
    }
}
