//! Ce que la liste des suffixes publics doit tenir.

use super::Suffixes;
use crate::alignment::{Alignment, PublicSuffix, aligned};

/// Un extrait de la vraie liste, avec ses trois formes de règle.
const LISTE: &[u8] = b"// Une liste d'epreuve, au format de publicsuffix.org\n\
                       com\n\
                       net\n\
                       fr\n\
                       co.uk\n\
                       org.uk\n\
                       \n\
                       // ck : tout est suffixe, sauf www\n\
                       *.ck\n\
                       !www.ck\n\
                       !a.www.ck\n\
                       // github.io est un suffixe public, pas github.com\n\
                       github.io\n\
                       io\n";

fn organisationnel(domaine: &str) -> &str {
    let liste = Suffixes::new(LISTE);
    core::str::from_utf8(liste.organizational_domain(domaine.as_bytes())).expect("ASCII")
}

#[test]
fn une_regle_simple_donne_le_domaine_enregistrable() {
    assert_eq!(organisationnel("example.com"), "example.com");
    assert_eq!(organisationnel("mail.example.com"), "example.com");
    assert_eq!(organisationnel("a.b.c.example.fr"), "example.fr");
}

#[test]
fn une_regle_a_deux_etiquettes_est_respectee() {
    // C'EST LE PIÈGE QUI COMPTE. Une implémentation naïve rendrait `co.uk` et
    // ferait aligner `attaquant.co.uk` avec `victime.co.uk`.
    assert_eq!(organisationnel("example.co.uk"), "example.co.uk");
    assert_eq!(organisationnel("mail.example.co.uk"), "example.co.uk");
    assert_eq!(organisationnel("example.org.uk"), "example.org.uk");
}

#[test]
fn les_etiquettes_se_comparent_depuis_la_droite() {
    // `co.uk` ne correspond PAS à `xco.uk` : un suffixe comparé comme une
    // chaîne ferait correspondre le second.
    assert_eq!(organisationnel("example.xco.uk"), "xco.uk");
}

#[test]
fn un_joker_couvre_une_etiquette() {
    // `*.ck` : `bar.ck` est un suffixe public, donc `foo.bar.ck` est le domaine
    // enregistrable.
    assert_eq!(organisationnel("foo.bar.ck"), "foo.bar.ck");
    assert_eq!(organisationnel("a.foo.bar.ck"), "foo.bar.ck");
}

#[test]
fn la_plus_longue_des_exceptions_l_emporte() {
    // Deux exceptions peuvent correspondre : c'est la plus longue qui décide,
    // comme pour les règles ordinaires.
    assert_eq!(organisationnel("a.www.ck"), "a.www.ck");
    assert_eq!(organisationnel("b.a.www.ck"), "a.www.ck");
}

#[test]
fn une_regle_plus_longue_que_le_nom_ne_correspond_pas() {
    // `co.uk` ne correspond pas à `uk` : il n'y a pas assez d'étiquettes.
    assert_eq!(organisationnel("uk"), "uk");
}

#[test]
fn une_exception_l_emporte_sur_le_joker() {
    // `!www.ck` retire sa propre étiquette de tête : le suffixe public est
    // `ck`, et `www.ck` est donc enregistrable.
    assert_eq!(organisationnel("www.ck"), "www.ck");
    // `b.www.ck` : l'exception la plus longue (`!a.www.ck`) ne correspond pas,
    // c'est donc `!www.ck` qui décide.
    assert_eq!(organisationnel("b.www.ck"), "www.ck");
}

#[test]
fn la_regle_la_plus_longue_l_emporte() {
    // `github.io` est un suffixe public, `io` aussi : c'est le plus long qui
    // décide, et un dépôt n'est donc pas aligné avec un autre.
    assert_eq!(organisationnel("moi.github.io"), "moi.github.io");
    assert_eq!(organisationnel("pages.moi.github.io"), "moi.github.io");
}

#[test]
fn un_domaine_sans_regle_garde_sa_derniere_etiquette() {
    // La règle implicite est `*` : le domaine de tête est le suffixe public.
    assert_eq!(organisationnel("example.inconnu"), "example.inconnu");
    assert_eq!(organisationnel("a.b.example.inconnu"), "example.inconnu");
}

#[test]
fn un_domaine_qui_est_un_suffixe_reste_lui_meme() {
    // `com` n'a pas de domaine organisationnel : il ne s'alignera donc qu'avec
    // lui-même, ce qui est le comportement le plus étroit — et le bon.
    assert_eq!(organisationnel("com"), "com");
    assert_eq!(organisationnel("co.uk"), "co.uk");
    assert_eq!(organisationnel(""), "");
}

#[test]
fn les_commentaires_et_les_lignes_vides_s_ignorent() {
    let liste = Suffixes::new(b"// commentaire\n\n   \ncom\n");
    assert_eq!(
        liste.organizational_domain(b"mail.example.com"),
        b"example.com"
    );
    // Une liste VIDE se comporte comme la règle implicite : le domaine de tête.
    let vide = Suffixes::new(b"");
    assert_eq!(
        vide.organizational_domain(b"mail.example.com"),
        b"example.com"
    );
}

#[test]
fn les_fins_de_ligne_des_deux_mondes_se_lisent() {
    let liste = Suffixes::new(b"com\r\nco.uk\r\n");
    assert_eq!(
        liste.organizational_domain(b"mail.example.co.uk"),
        b"example.co.uk"
    );
}

#[test]
fn la_casse_ne_compte_pas() {
    let liste = Suffixes::new(LISTE);
    assert_eq!(
        liste.organizational_domain(b"Mail.EXAMPLE.Com"),
        b"EXAMPLE.Com"
    );
}

#[test]
fn un_nom_a_etiquette_vide_ne_correspond_a_rien() {
    // `example..com` n'est pas un nom ; on ne lui fabrique pas un domaine
    // organisationnel qui ferait aligner n'importe quoi.
    let liste = Suffixes::new(LISTE);
    assert_eq!(
        liste.organizational_domain(b"example..com"),
        b"example..com"
    );
    assert_eq!(liste.organizational_domain(b"."), b".");
}

#[test]
fn c_est_cette_liste_qui_ferme_l_usurpation() {
    // L'ÉPREUVE QUI RÉSUME TOUT : avec la vraie règle, ces deux-là ne
    // s'alignent pas. Avec « les deux dernières étiquettes », ils s'aligneraient.
    let liste = Suffixes::new(LISTE);
    assert!(!aligned(
        Alignment::Relaxed,
        b"attaquant.co.uk",
        b"victime.co.uk",
        &liste
    ));
    assert!(aligned(
        Alignment::Relaxed,
        b"mail.victime.co.uk",
        b"victime.co.uk",
        &liste
    ));
}

#[test]
fn la_liste_se_debogue_et_se_copie() {
    let liste = Suffixes::new(LISTE);
    let copie = liste;
    assert_eq!(
        copie.organizational_domain(b"a.example.com"),
        b"example.com"
    );
    assert!(!std::format!("{liste:?}").is_empty());
}
