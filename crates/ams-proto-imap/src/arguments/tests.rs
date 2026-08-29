//! Ce qu'un argument a le droit d'être.

use super::{Args, Argument, argument_max};
use crate::{Error, Limits};

/// Lit tous les arguments d'une commande.
fn lire(entree: &[u8]) -> std::vec::Vec<Result<Argument<'_>, Error>> {
    Args::new(entree).collect()
}

/// Écrit la valeur d'un argument.
fn valeur(argument: &Argument<'_>) -> std::string::String {
    let mut sortie = [0_u8; 256];
    let ecrit = argument.value(&mut sortie).expect("assez de place");
    std::string::String::from_utf8_lossy(ecrit).into_owned()
}

#[test]
fn les_trois_ecritures_se_lisent() {
    let lus = lire(b"INBOX \"Mon dossier\" {7}\r\nabcdefg");
    assert_eq!(lus.len(), 3);
    assert_eq!(lus[0], Ok(Argument::Atom(b"INBOX")));
    assert_eq!(lus[1], Ok(Argument::Quoted(b"Mon dossier")));
    assert_eq!(lus[2], Ok(Argument::Literal(b"abcdefg")));
    assert_eq!(valeur(&lus[0].expect("lisible")), "INBOX");
    assert_eq!(valeur(&lus[1].expect("lisible")), "Mon dossier");
    assert_eq!(valeur(&lus[2].expect("lisible")), "abcdefg");
}

/// **`"a\"b"` vaut `a"b`** : trois octets là où la source en porte cinq. C'est
/// pourquoi la valeur ne se rend pas par emprunt.
#[test]
fn les_echappements_se_defont() {
    let lus = lire(b"\"a\\\"b\" \"c\\\\d\"");
    assert_eq!(valeur(&lus[0].expect("lisible")), "a\"b");
    assert_eq!(valeur(&lus[1].expect("lisible")), "c\\d");
}

/// §9 : seuls `"` et `\` s'échappent. Tout le reste après une contre-oblique
/// est une écriture qu'on ne sait pas lire.
#[test]
fn un_echappement_qu_on_ne_connait_pas_est_une_faute() {
    for mechant in [
        &b"\"a\\nb\""[..],
        b"\"a\\ b\"",
        // Une chaîne qui ne se referme pas.
        b"\"sans fin",
        // Une chaîne ne traverse pas les lignes.
        b"\"a\r\nb\"",
        b"\"a\nb\"",
    ] {
        assert_eq!(
            lire(mechant)[0],
            Err(Error::MalformedArgument),
            "{mechant:?}"
        );
    }
}

#[test]
fn un_litteral_mal_forme_est_une_faute() {
    for mechant in [
        // Pas d'accolade fermante.
        &b"{7"[..],
        // Une longueur qui n'en est pas une.
        b"{abc}\r\nx",
        b"{}\r\nx",
        // Pas de `CRLF` après l'annonce.
        b"{3}xyz",
        // L'annonce et le contenu ne s'accordent pas.
        b"{9}\r\nxyz",
        b"{99999999999999999999999}\r\nx",
    ] {
        assert_eq!(
            lire(mechant)[0],
            Err(Error::MalformedLiteral),
            "{mechant:?}"
        );
    }
    // Un littéral non synchronisant se lit comme l'autre : le découpage a déjà
    // fait la différence, elle n'en fait plus ici.
    assert_eq!(lire(b"{3+}\r\nxyz")[0], Ok(Argument::Literal(b"xyz")));
}

#[test]
fn un_litteral_vide_est_un_argument_vide() {
    let lus = lire(b"{0+}\r\n");
    assert_eq!(lus[0], Ok(Argument::Literal(b"")));
    assert_eq!(valeur(&lus[0].expect("lisible")), "");
}

/// Comparer sans tampon : c'est le cas de tous les mots-clés du protocole.
#[test]
fn la_comparaison_se_passe_de_tampon() {
    for (entree, mot, attendu) in [
        (&b"PLAIN"[..], &b"plain"[..], true),
        (b"PLAIN", b"login", false),
        (b"\"PLAIN\"", b"plain", true),
        (b"\"a\\\"b\"", b"a\"b", true),
        (b"\"a\\\"b\"", b"a\"c", false),
        (b"\"ab\"", b"abc", false),
        (b"{5+}\r\nPLAIN", b"plain", true),
    ] {
        let lu = lire(entree)[0].expect("lisible");
        assert_eq!(
            lu.equals_ignore_case(mot),
            attendu,
            "{entree:?} contre {mot:?}"
        );
    }
}

#[test]
fn les_espaces_multiples_ne_font_pas_d_arguments_vides() {
    let lus = lire(b"  a   b  ");
    assert_eq!(lus.len(), 2);
    assert_eq!(lus[0], Ok(Argument::Atom(b"a")));
    assert_eq!(lus[1], Ok(Argument::Atom(b"b")));
    assert!(lire(b"").is_empty());
    assert!(lire(b"     ").is_empty());
}

#[test]
fn un_tampon_trop_court_le_dit() {
    for entree in [&b"INBOX"[..], b"\"INBOX\"", b"{5+}\r\nINBOX"] {
        let lu = lire(entree)[0].expect("lisible");
        let mut court = [0_u8; 4];
        assert!(
            matches!(lu.value(&mut court), Err(Error::BufferTooSmall { .. })),
            "{entree:?}"
        );
        let mut juste = [0_u8; 5];
        assert_eq!(lu.value(&mut juste).expect("assez"), b"INBOX");
    }
}

#[test]
fn la_borne_d_un_argument_est_celle_d_un_litteral() {
    assert_eq!(
        argument_max(&Limits::DEFAULT),
        Limits::DEFAULT.max_literal_octets
    );
}

#[test]
fn ce_qui_se_lit_se_montre_et_se_compare() {
    let lu = lire(b"INBOX")[0].expect("lisible");
    let copie = lu;
    assert_eq!(lu, copie);
    assert_ne!(lu, Argument::Atom(b"AUTRE"));
    assert!(!std::format!("{lu:?}").is_empty());
    assert!(!std::format!("{:?}", Args::new(b"x")).is_empty());
    assert!(!std::format!("{:?}", Args::new(b"x").clone()).is_empty());
}
