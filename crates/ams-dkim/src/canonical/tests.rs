//! Ce que la canonicalisation des en-têtes doit tenir.
//!
//! Les épreuves centrales sont **les vecteurs de la RFC 6376 §3.4.5** : une
//! canonicalisation inventée ici passerait ses propres tests et échouerait
//! contre le reste du monde.

use super::{Canon, Canonicalization, Trailer, canonicalize_header};
use crate::Error;

/// Canonicalise un champ et rend le résultat.
fn canon(algorithme: Canon, nom: &str, valeur: &str, fin: Trailer) -> std::string::String {
    let mut rendu = std::vec::Vec::new();
    canonicalize_header(
        algorithme,
        nom.as_bytes(),
        valeur.as_bytes(),
        fin,
        &mut |morceau| {
            rendu.extend_from_slice(morceau);
        },
    );
    std::string::String::from_utf8(rendu).expect("ASCII")
}

// ── LES VECTEURS DE LA RFC 6376 §3.4.5 ──────────────────────────────────────
//
// Le message de l'exemple, tel que la RFC l'écrit :
//
//     A: <SP> X <CRLF>
//     B <SP> : <SP> Y <HTAB><CRLF>
//     <HTAB> Z <SP><SP><CRLF>
//
// soit deux champs : « A » de valeur « <SP>X », et « B<SP> » de valeur
// « <SP>Y<HTAB><CRLF><HTAB>Z<SP><SP> ».

const NOM_A: &str = "A";
const VALEUR_A: &str = " X";
const NOM_B: &str = "B ";
const VALEUR_B: &str = " Y\t\r\n\tZ  ";

#[test]
fn relaxed_rend_ce_que_la_rfc_annonce() {
    // « a:X<CRLF> » et « b:Y<SP>Z<CRLF> ».
    assert_eq!(
        canon(Canon::Relaxed, NOM_A, VALEUR_A, Trailer::Crlf),
        "a:X\r\n"
    );
    assert_eq!(
        canon(Canon::Relaxed, NOM_B, VALEUR_B, Trailer::Crlf),
        "b:Y Z\r\n"
    );
}

#[test]
fn simple_ne_change_rien_du_tout() {
    // Le champ est rendu tel qu'il figure dans le message — deux-points,
    // pliage et blancs de queue compris.
    assert_eq!(
        canon(Canon::Simple, NOM_A, VALEUR_A, Trailer::Crlf),
        "A: X\r\n"
    );
    assert_eq!(
        canon(Canon::Simple, NOM_B, VALEUR_B, Trailer::Crlf),
        "B : Y\t\r\n\tZ  \r\n"
    );
}

#[test]
fn relaxed_met_le_nom_en_minuscules_et_serre_le_deux_points() {
    assert_eq!(
        canon(Canon::Relaxed, "DKIM-Signature", " v=1", Trailer::Crlf),
        "dkim-signature:v=1\r\n"
    );
    // Les blancs des DEUX côtés du deux-points disparaissent — celui d'avant
    // vient du nom, celui d'après de la valeur.
    assert_eq!(
        canon(Canon::Relaxed, "X ", "\t y", Trailer::Crlf),
        "x:y\r\n"
    );
}

#[test]
fn relaxed_deplie_et_reduit_les_blancs() {
    // Le pliage disparaît DANS la réduction : un `CRLF` de pliage est toujours
    // suivi d'un blanc, et le tout compte pour une seule espace.
    assert_eq!(
        canon(
            Canon::Relaxed,
            "Subject",
            " un\r\n  sujet\t\tplié",
            Trailer::Crlf
        ),
        "subject:un sujet plié\r\n"
    );
}

#[test]
fn relaxed_retire_les_blancs_de_queue() {
    assert_eq!(
        canon(Canon::Relaxed, "X", " y \t \r\n ", Trailer::Crlf),
        "x:y\r\n"
    );
}

#[test]
fn une_valeur_vide_reste_vide() {
    assert_eq!(canon(Canon::Relaxed, "X", "", Trailer::Crlf), "x:\r\n");
    assert_eq!(canon(Canon::Relaxed, "X", "   ", Trailer::Crlf), "x:\r\n");
    assert_eq!(canon(Canon::Simple, "X", "", Trailer::Crlf), "X:\r\n");
}

#[test]
fn le_champ_de_signature_entre_sans_son_crlf() {
    // §3.7 : il entre dans son PROPRE condensat, et au moment où le signataire
    // l'a calculé, le `CRLF` final n'était pas encore écrit. L'ajouter ferait
    // échouer toutes les signatures.
    assert_eq!(
        canon(Canon::Relaxed, "DKIM-Signature", " v=1; b=", Trailer::Aucun),
        "dkim-signature:v=1; b="
    );
    assert_eq!(
        canon(Canon::Simple, "DKIM-Signature", " v=1; b=", Trailer::Aucun),
        "DKIM-Signature: v=1; b="
    );
}

// ── LE COUPLE `c=` ──────────────────────────────────────────────────────────

#[test]
fn le_couple_se_lit_dans_les_deux_formes() {
    assert_eq!(
        Canonicalization::parse(b"relaxed/relaxed").expect("lisible"),
        Canonicalization {
            header: Canon::Relaxed,
            body: Canon::Relaxed
        }
    );
    assert_eq!(
        Canonicalization::parse(b"simple/relaxed").expect("lisible"),
        Canonicalization {
            header: Canon::Simple,
            body: Canon::Relaxed
        }
    );
}

#[test]
fn le_corps_absent_vaut_simple_et_non_la_valeur_des_en_tetes() {
    // §3.5 : `c=relaxed` veut dire `relaxed/simple`. Le lire autrement ferait
    // condenser un corps différent de celui que le signataire a condensé — et
    // toutes ces signatures-là échoueraient sans qu'on sache pourquoi.
    assert_eq!(
        Canonicalization::parse(b"relaxed").expect("lisible"),
        Canonicalization {
            header: Canon::Relaxed,
            body: Canon::Simple
        }
    );
}

#[test]
fn le_defaut_est_simple_des_deux_cotes() {
    // C'est le défaut de la RFC : un message qui n'écrit pas `c=` est signé
    // ainsi, et se tromper de défaut ferait échouer toutes ces signatures.
    assert_eq!(
        Canonicalization::default(),
        Canonicalization {
            header: Canon::Simple,
            body: Canon::Simple
        }
    );
    assert_eq!(Canon::default(), Canon::Simple);
}

#[test]
fn les_noms_se_lisent_sans_casse() {
    assert_eq!(Canon::parse(b"RELAXED").expect("lisible"), Canon::Relaxed);
    assert_eq!(Canon::parse(b"Simple").expect("lisible"), Canon::Simple);
}

#[test]
fn un_algorithme_inconnu_ne_se_rabat_sur_rien() {
    // Le vérifier autrement rendrait un verdict sur des octets que personne n'a
    // signés.
    for inconnu in [&b"strict"[..], b"", b"relaxed/strict", b"/simple"] {
        assert_eq!(
            Canonicalization::parse(inconnu),
            Err(Error::UnsupportedCanonicalization),
            "{}",
            std::string::String::from_utf8_lossy(inconnu)
        );
    }
}

#[test]
fn chaque_algorithme_porte_son_nom() {
    assert_eq!(Canon::Simple.name(), b"simple");
    assert_eq!(Canon::Relaxed.name(), b"relaxed");
}

#[test]
fn les_types_se_deboguent_et_se_comparent() {
    assert!(!std::format!("{:?}", Canon::Relaxed).is_empty());
    assert!(!std::format!("{:?}", Canonicalization::default()).is_empty());
    assert!(!std::format!("{:?}", Trailer::Aucun).is_empty());
    assert_ne!(Canon::Simple, Canon::Relaxed);
    assert_ne!(Trailer::Crlf, Trailer::Aucun);
    let copie = Canonicalization::default();
    assert_eq!(copie, Canonicalization::default());
}
