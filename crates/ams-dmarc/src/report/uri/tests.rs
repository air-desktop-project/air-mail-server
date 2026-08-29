//! Ce qu'une liste de destinations a le droit de dire.

use super::{Uri, Uris, decode};
use crate::Error;

/// Lit une liste, et rend ce qui a été compris.
fn lire(valeur: &[u8]) -> std::vec::Vec<Result<Uri<'_>, Error>> {
    Uris::new(valeur).collect()
}

#[test]
fn une_adresse_seule_se_lit() {
    let liste = lire(b"mailto:dmarc@example.com");
    assert_eq!(liste.len(), 1);
    let uri = liste[0].expect("lisible");
    assert_eq!(uri.scheme, b"mailto");
    assert_eq!(uri.target, b"dmarc@example.com");
    assert_eq!(uri.max_size, None);
    assert!(uri.is_mailto());
    assert_eq!(uri.domain(), Some(&b"example.com"[..]));
}

#[test]
fn les_virgules_separent_et_les_blancs_ne_comptent_pas() {
    let liste = lire(b" mailto:a@x.test , mailto:b@y.test ");
    assert_eq!(liste.len(), 2);
    assert_eq!(liste[0].expect("lisible").target, b"a@x.test");
    assert_eq!(liste[1].expect("lisible").target, b"b@y.test");
}

#[test]
fn les_quatre_unites_de_taille_valent_ce_qu_elles_disent() {
    for (texte, attendu) in [
        (&b"mailto:a@x.test!100"[..], 100_u64),
        (b"mailto:a@x.test!1k", 1024),
        (b"mailto:a@x.test!2m", 2 * 1024 * 1024),
        (b"mailto:a@x.test!1g", 1024 * 1024 * 1024),
        (b"mailto:a@x.test!1t", 1024_u64 * 1024 * 1024 * 1024),
        (b"mailto:a@x.test!3M", 3 * 1024 * 1024),
        (b"mailto:a@x.test!1K", 1024),
        (b"mailto:a@x.test!1G", 1024 * 1024 * 1024),
        (b"mailto:a@x.test!1T", 1024_u64 * 1024 * 1024 * 1024),
    ] {
        let uri = lire(texte)[0].expect("lisible");
        assert_eq!(uri.max_size, Some(attendu), "{texte:?}");
    }
}

/// **Une taille qui déborde n'est pas une grande taille.** Repartie de zéro,
/// elle interdirait tout envoi au nom d'un domaine qui n'a rien demandé de tel.
#[test]
fn une_taille_qui_deborde_ecarte_la_destination() {
    for texte in [
        &b"mailto:a@x.test!99999999999999999999999"[..],
        b"mailto:a@x.test!18446744073709551615t",
        b"mailto:a@x.test!",
        b"mailto:a@x.test!k",
        b"mailto:a@x.test!1x2",
    ] {
        assert_eq!(lire(texte)[0], Err(Error::MalformedSize), "{texte:?}");
    }
}

/// **Le point d'exclamation se cherche EN PREMIER.** La RFC exige qu'il soit
/// encodé partout ailleurs ; le chercher en dernier laisserait une URI fautive
/// décider où commence la taille.
#[test]
fn le_premier_point_d_exclamation_separe() {
    assert_eq!(lire(b"mailto:a@x.test!1!2")[0], Err(Error::MalformedSize));
}

#[test]
fn ce_qui_n_est_pas_une_uri_est_ecarte() {
    for texte in [
        &b"dmarc@example.com"[..],
        b"",
        b":a@x.test",
        b"1mailto:a@x.test",
        b"mail to:a@x.test",
        b"mailto:",
    ] {
        assert_eq!(lire(texte)[0], Err(Error::MalformedUri), "{texte:?}");
    }
}

#[test]
fn un_schema_peut_porter_plus_ou_moins_et_point() {
    let uri = lire(b"x-report.v2+gz:cible")[0].expect("lisible");
    assert_eq!(uri.scheme, b"x-report.v2+gz");
    assert!(!uri.is_mailto());
    assert_eq!(uri.domain(), None);
}

#[test]
fn le_schema_se_compare_sans_egard_a_la_casse() {
    assert!(lire(b"MAILTO:a@x.test")[0].expect("lisible").is_mailto());
}

/// Le domaine sert à demander son consentement à la destination : un domaine
/// qu'on ne sait pas lire n'est pas un domaine qu'on interroge.
#[test]
fn un_domaine_douteux_ne_ressort_pas() {
    for texte in [
        &b"mailto:sans-arobase"[..],
        b"mailto:a@",
        b"mailto:a@ex%2Eample.com",
        b"mailto:a@ex ample.com",
    ] {
        assert_eq!(lire(texte)[0].expect("lisible").domain(), None, "{texte:?}");
    }
}

#[test]
fn un_domaine_trop_long_ne_ressort_pas() {
    let mut texte = std::vec::Vec::from(&b"mailto:a@"[..]);
    texte.extend(core::iter::repeat_n(b'a', 256));
    assert_eq!(lire(&texte)[0].expect("lisible").domain(), None);
}

#[test]
fn le_dernier_arobase_ouvre_le_domaine() {
    let uri = lire(b"mailto:a@b@example.com")[0].expect("lisible");
    assert_eq!(uri.domain(), Some(&b"example.com"[..]));
}

#[test]
fn une_liste_vide_donne_une_faute_et_s_arrete() {
    let liste = lire(b"");
    assert_eq!(liste.len(), 1);
    assert_eq!(liste[0], Err(Error::MalformedUri));
}

#[test]
fn l_iterateur_s_arrete_pour_de_bon() {
    let mut uris = Uris::new(b"mailto:a@x.test");
    assert!(uris.next().is_some());
    assert!(uris.next().is_none());
    assert!(uris.next().is_none());
}

#[test]
fn le_pourcent_se_decode() {
    let mut tampon = [0_u8; 64];
    let decode = decode(b"a%2Cb%21c@x.test", &mut tampon).expect("decodable");
    assert_eq!(decode, b"a,b!c@x.test");
}

#[test]
fn les_chiffres_hexadecimaux_vont_dans_les_deux_casses() {
    let mut tampon = [0_u8; 16];
    assert_eq!(
        decode(b"%2f%2F%aA%Ff", &mut tampon),
        Err(Error::NotPrintable)
    );
    assert_eq!(decode(b"%2f%2F", &mut tampon).expect("decodable"), b"//");
}

/// **Un `CR LF` décodé laisserait celui qui publie l'enregistrement écrire les
/// en-têtes qu'il veut dans le message qu'on lui envoie.**
#[test]
fn c_est_ici_que_l_injection_d_en_tete_s_arrete() {
    let mut tampon = [0_u8; 64];
    assert_eq!(
        decode(b"a@x.test%0D%0ABcc:%20victime@y.test", &mut tampon),
        Err(Error::NotPrintable)
    );
}

#[test]
fn un_pourcent_mal_forme_est_une_faute() {
    let mut tampon = [0_u8; 64];
    for texte in [&b"%"[..], b"%2", b"%zz", b"%2z", b"a%"] {
        assert_eq!(
            decode(texte, &mut tampon),
            Err(Error::MalformedUri),
            "{texte:?}"
        );
    }
}

#[test]
fn un_tampon_trop_court_le_dit() {
    let mut tampon = [0_u8; 3];
    assert_eq!(decode(b"abcd", &mut tampon), Err(Error::BufferTooSmall));
    let mut juste = [0_u8; 4];
    assert_eq!(decode(b"abcd", &mut juste).expect("decodable"), b"abcd");
}

#[test]
fn ce_qui_se_lit_se_montre_et_se_compare() {
    let uri = lire(b"mailto:a@x.test")[0].expect("lisible");
    assert_eq!(uri, uri);
    assert!(!std::format!("{uri:?}").is_empty());
    assert!(!std::format!("{:?}", Uris::new(b"")).is_empty());
    assert!(!std::format!("{:?}", Uris::new(b"").clone()).is_empty());
}
