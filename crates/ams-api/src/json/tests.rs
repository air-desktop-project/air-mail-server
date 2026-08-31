// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un écrivain JSON a le droit d'écrire.

use std::string::{String, ToString};

use super::{DEPTH_MAX, Json};
use crate::error::{Error, Reason};

/// Un tampon confortable.
const PLACE: usize = 1_024;

/// Écrit ce que fait `quoi`, et rend le document.
fn ecrire(quoi: &dyn Fn(&mut Json<'_>) -> Result<(), Error>) -> Result<String, Reason> {
    let mut place = [0_u8; PLACE];
    let mut json = Json::new(&mut place);
    quoi(&mut json).map_err(|e| e.reason())?;
    let fini = json.finish().map_err(|e| e.reason())?;
    Ok(core::str::from_utf8(fini).expect("de l'UTF-8").to_string())
}

/// Une chaîne seule, échappée.
fn chaine(valeur: &str) -> String {
    ecrire(&|json| json.string(valeur)).expect("écrivable")
}

/// Les valeurs simples s'écrivent seules : §2 de RFC 8259 dit qu'un texte JSON
/// EST une valeur.
#[test]
fn une_valeur_seule_fait_un_document() {
    assert_eq!(chaine("salut"), "\"salut\"");
    assert_eq!(ecrire(&|json| json.number(42)), Ok("42".to_string()));
    assert_eq!(ecrire(&|json| json.boolean(true)), Ok("true".to_string()));
    assert_eq!(ecrire(&|json| json.boolean(false)), Ok("false".to_string()));
    assert_eq!(ecrire(&|json| json.null()), Ok("null".to_string()));
}

/// Un objet et un tableau s'écrivent, vides ou non.
#[test]
fn les_structures_s_ecrivent() {
    assert_eq!(
        ecrire(&|json| {
            json.begin_object().expect("cette étape doit passer");
            json.end_object()
        }),
        Ok("{}".to_string())
    );
    assert_eq!(
        ecrire(&|json| {
            json.begin_array().expect("cette étape doit passer");
            json.end_array()
        }),
        Ok("[]".to_string())
    );
    assert_eq!(
        ecrire(&|json| {
            json.begin_object().expect("cette étape doit passer");
            json.field_str("boite", "INBOX")
                .expect("cette étape doit passer");
            json.field_u64("messages", 12)
                .expect("cette étape doit passer");
            json.field_bool("abonnee", true)
                .expect("cette étape doit passer");
            json.key("drapeaux").expect("cette étape doit passer");
            json.begin_array().expect("cette étape doit passer");
            json.string("\\Seen").expect("cette étape doit passer");
            json.string("\\Answered").expect("cette étape doit passer");
            json.end_array().expect("cette étape doit passer");
            json.key("sujet").expect("cette étape doit passer");
            json.null().expect("cette étape doit passer");
            json.end_object()
        }),
        Ok(concat!(
            r#"{"boite":"INBOX","messages":12,"abonnee":true,"#,
            r#""drapeaux":["\\Seen","\\Answered"],"sujet":null}"#
        )
        .to_string())
    );
}

/// **UN GUILLEMET NON ÉCHAPPÉ FERME LA CHAÎNE**, et ce qui suit devient de la
/// structure. C'est la faute que ce module existe pour empêcher.
#[test]
fn un_guillemet_ne_ferme_jamais_la_chaine() {
    // Une tentative d'évasion : sans échappement, cela ajouterait un champ
    // « admin » que personne n'a voulu.
    let attaque = r#"a","admin":true,"x":"b"#;
    assert_eq!(
        chaine(attaque),
        r#""a\",\"admin\":true,\"x\":\"b""#,
        "l'échappement doit neutraliser l'évasion"
    );
}

/// **§7 DE RFC 8259 EXIGE CES ÉCHAPPEMENTS-LÀ**, et en oublier un laisse fermer
/// la chaîne.
#[test]
fn les_echappements_exiges_par_la_rfc() {
    assert_eq!(chaine("\""), r#""\"""#);
    assert_eq!(chaine("\\"), r#""\\""#);
    assert_eq!(chaine("\n"), r#""\n""#);
    assert_eq!(chaine("\r"), r#""\r""#);
    assert_eq!(chaine("\t"), r#""\t""#);
    assert_eq!(chaine("\u{8}"), r#""\b""#);
    assert_eq!(chaine("\u{c}"), r#""\f""#);
    // Tout ce qui est sous l'espace et n'a pas d'échappement court.
    assert_eq!(chaine("\u{0}"), "\"\\u0000\"");
    assert_eq!(chaine("\u{1}"), "\"\\u0001\"");
    assert_eq!(chaine("\u{1f}"), "\"\\u001f\"");
}

/// **AUCUN OCTET DE CONTRÔLE NE PASSE TEL QUEL**, quel qu'il soit.
#[test]
fn aucun_octet_de_controle_ne_passe() {
    for point in 0..0x20_u32 {
        let caractere = char::from_u32(point).expect("un caractère");
        let ecrit = chaine(&String::from(caractere));
        assert!(
            !ecrit.chars().any(|c| (c as u32) < 0x20),
            "le point {point:#04x} est passé tel quel : {ecrit:?}"
        );
    }
}

/// **`<`, `>` ET `&` S'ÉCHAPPENT** : un document JSON finit parfois dans une page
/// HTML, et un `<` non échappé y ouvre une balise.
#[test]
fn les_caracteres_html_s_echappent() {
    assert_eq!(chaine("<"), "\"\\u003c\"");
    assert_eq!(chaine(">"), "\"\\u003e\"");
    assert_eq!(chaine("&"), "\"\\u0026\"");
    let ecrit = chaine("<script>alert(1)</script>");
    assert!(!ecrit.contains('<'), "{ecrit}");
    assert!(!ecrit.contains('>'), "{ecrit}");
}

/// **`U+2028` ET `U+2029` TERMINENT UNE LIGNE EN JAVASCRIPT** : licites en JSON,
/// ils cassent l'analyseur du client.
#[test]
fn les_separateurs_de_ligne_unicode_s_echappent() {
    assert_eq!(chaine("\u{2028}"), "\"\\u2028\"");
    assert_eq!(chaine("\u{2029}"), "\"\\u2029\"");
}

/// Ce qui n'a pas besoin d'échappement passe tel quel, accents compris.
#[test]
fn ce_qui_est_ordinaire_passe_tel_quel() {
    assert_eq!(chaine("été"), "\"été\"");
    assert_eq!(chaine("a/b"), "\"a/b\"");
    assert_eq!(chaine("'"), "\"'\"");
    // Y compris hors du plan multilingue de base.
    assert_eq!(chaine("\u{1f600}"), "\"\u{1f600}\"");
}

/// Les entiers s'écrivent, jusqu'aux bornes.
#[test]
fn les_entiers_s_ecrivent() {
    for (valeur, attendu) in [
        (0_u64, "0"),
        (1, "1"),
        (9, "9"),
        (10, "10"),
        (99, "99"),
        (1_000, "1000"),
        (u64::MAX, "18446744073709551615"),
    ] {
        assert_eq!(
            ecrire(&|json| json.number(valeur)),
            Ok(attendu.to_string()),
            "{valeur}"
        );
    }
}

/// **UNE SUITE IMPOSSIBLE SE DIT PLUTÔT QUE DE S'ÉCRIRE.**
#[test]
fn une_suite_impossible_se_refuse() {
    // Fermer ce qu'on n'a pas ouvert.
    assert_eq!(ecrire(&|json| json.end_object()), Err(Reason::BadJson));
    assert_eq!(ecrire(&|json| json.end_array()), Err(Reason::BadJson));
    // **ON NE FERME PAS UN TABLEAU AVEC UNE ACCOLADE.**
    assert_eq!(
        ecrire(&|json| {
            json.begin_array().expect("cette étape doit passer");
            json.end_object()
        }),
        Err(Reason::BadJson)
    );
    assert_eq!(
        ecrire(&|json| {
            json.begin_object().expect("cette étape doit passer");
            json.end_array()
        }),
        Err(Reason::BadJson)
    );
    // Une clé hors d'un objet.
    assert_eq!(ecrire(&|json| json.key("a")), Err(Reason::BadJson));
    assert_eq!(
        ecrire(&|json| {
            json.begin_array().expect("cette étape doit passer");
            json.key("a")
        }),
        Err(Reason::BadJson)
    );
    // Deux clés de suite.
    assert_eq!(
        ecrire(&|json| {
            json.begin_object().expect("cette étape doit passer");
            json.key("a").expect("cette étape doit passer");
            json.key("b")
        }),
        Err(Reason::BadJson)
    );
    // Une valeur sans clé, dans un objet — quelle qu'elle soit.
    assert_eq!(
        ecrire(&|json| {
            json.begin_object().expect("cette étape doit passer");
            json.string("a")
        }),
        Err(Reason::BadJson)
    );
    assert_eq!(
        ecrire(&|json| {
            json.begin_object().expect("cette étape doit passer");
            json.null()
        }),
        Err(Reason::BadJson)
    );
    assert_eq!(
        ecrire(&|json| {
            json.begin_object().expect("cette étape doit passer");
            json.number(1)
        }),
        Err(Reason::BadJson)
    );
    assert_eq!(
        ecrire(&|json| {
            json.begin_object().expect("cette étape doit passer");
            json.boolean(true)
        }),
        Err(Reason::BadJson)
    );
    // Fermer un objet dont la clé attend sa valeur.
    assert_eq!(
        ecrire(&|json| {
            json.begin_object().expect("cette étape doit passer");
            json.key("a").expect("cette étape doit passer");
            json.end_object()
        }),
        Err(Reason::BadJson)
    );
}

/// **UNE SEULE VALEUR À LA RACINE** (§2 de RFC 8259) : deux à la suite feraient
/// deux documents collés, que chaque lecteur découperait à sa façon.
#[test]
fn une_seule_valeur_a_la_racine() {
    assert_eq!(
        ecrire(&|json| {
            json.number(1).expect("cette étape doit passer");
            json.number(2)
        }),
        Err(Reason::BadJson)
    );
    assert_eq!(
        ecrire(&|json| {
            json.begin_object().expect("cette étape doit passer");
            json.end_object().expect("cette étape doit passer");
            json.begin_object()
        }),
        Err(Reason::BadJson)
    );
}

/// **UN DOCUMENT TRONQUÉ NE SORT PAS D'ICI** : servi avec un 200, il ferait
/// croire à un client qu'il a tout lu.
#[test]
fn un_document_inacheve_ne_sort_pas() {
    // Rien du tout.
    assert_eq!(ecrire(&|_| Ok(())), Err(Reason::BadJson));
    // Un niveau resté ouvert.
    assert_eq!(ecrire(&|json| json.begin_object()), Err(Reason::BadJson));
    assert_eq!(
        ecrire(&|json| {
            json.begin_array().expect("cette étape doit passer");
            json.begin_object().expect("cette étape doit passer");
            json.end_object()
        }),
        Err(Reason::BadJson)
    );
}

/// **UNE BORNE FIXE EST CE QUI PERMET À LA PILE D'ÊTRE UN TABLEAU**, donc à cette
/// crate de ne rien allouer.
#[test]
fn au_dela_de_la_profondeur_on_refuse() {
    let issue = ecrire(&|json| {
        for _ in 0..DEPTH_MAX {
            json.begin_array().expect("cette étape doit passer");
        }
        // Celui-ci est celui de trop.
        json.begin_array()
    });
    assert_eq!(issue, Err(Reason::JsonTooDeep));

    // Pile la borne passe.
    let pile = ecrire(&|json| {
        for _ in 0..DEPTH_MAX {
            json.begin_array().expect("cette étape doit passer");
        }
        for _ in 0..DEPTH_MAX {
            json.end_array().expect("cette étape doit passer");
        }
        Ok(())
    });
    assert_eq!(pile, Ok("[[[[[[[[]]]]]]]]".to_string()));
}

/// **CHAQUE TAILLE DE TAMPON INSUFFISANTE SE DIT**, et à chaque étape.
///
/// Écrire à moitié puis rendre un document tronqué serait la pire des issues :
/// le client le lirait sans savoir qu'il manque quelque chose. Cet essai passe
/// par toutes les tailles jusqu'à la bonne, ce qui met en jeu chacune des
/// écritures du chemin.
#[test]
fn chaque_tampon_insuffisant_se_dit() {
    let document = |json: &mut Json<'_>| -> Result<(), Error> {
        json.begin_object()?;
        json.field_str("clef", "a\nb<&>\"\\\r\t\u{8}\u{c}")?;
        json.field_u64("n", 1_234)?;
        json.field_bool("b", false)?;
        json.key("liste")?;
        json.begin_array()?;
        json.null()?;
        json.boolean(true)?;
        json.string("x")?;
        json.number(0)?;
        json.end_array()?;
        json.end_object()
    };
    let entier = ecrire(&document).expect("écrivable");
    for taille in 0..entier.len() {
        let mut petit = std::vec![0_u8; taille];
        let mut json = Json::new(&mut petit);
        // Sous la taille voulue, l'écriture s'arrête toujours avant la fin :
        // c'est bien elle qui se plaint, et non la clôture.
        let issue = document(&mut json).expect_err("trop court");
        assert_eq!(issue.reason(), Reason::BufferTooSmall, "{taille}");
    }
}

/// On sait combien on a écrit, à tout instant.
#[test]
fn on_sait_combien_on_a_ecrit() {
    let mut place = [0_u8; PLACE];
    let mut json = Json::new(&mut place);
    assert_eq!(json.written(), 0);
    json.begin_object().expect("ouvrable");
    assert_eq!(json.written(), 1);
    json.field_u64("n", 12).expect("écrivable");
    assert_eq!(
        json.written(),
        7,
        "une accolade, une clé entre guillemets, deux-points, deux chiffres"
    );
    json.end_object().expect("fermable");
    assert_eq!(json.written(), 8);
    assert_eq!(json.finish().expect("complet").len(), 8);
}
