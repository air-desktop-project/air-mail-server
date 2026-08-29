//! Ce que l'expansion des macros doit tenir.

use super::{Context, Expanded, expand};
use crate::Error;
use core::net::{IpAddr, Ipv4Addr};

fn contexte() -> Context<'static> {
    Context {
        client: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)),
        sender: b"strong-bad@email.example.com",
        helo: b"mx.example.org",
    }
}

fn developper(spec: &[u8]) -> Result<std::string::String, Error> {
    let mut sortie = Expanded::new();
    expand(spec, &contexte(), b"email.example.com", &mut sortie)?;
    Ok(std::string::String::from_utf8_lossy(sortie.as_bytes()).into_owned())
}

#[test]
fn les_exemples_de_la_rfc_7208_passent() {
    // §7.4, la table d'exemples — la référence la moins discutable qui soit.
    for (spec, attendu) in [
        (&b"%{s}"[..], "strong-bad@email.example.com"),
        (b"%{o}", "email.example.com"),
        (b"%{d}", "email.example.com"),
        (b"%{d4}", "email.example.com"),
        (b"%{d3}", "email.example.com"),
        (b"%{d2}", "example.com"),
        (b"%{d1}", "com"),
        (b"%{dr}", "com.example.email"),
        (b"%{d2r}", "example.email"),
        (b"%{l}", "strong-bad"),
        (b"%{l-}", "strong.bad"),
        (b"%{lr}", "strong-bad"),
        (b"%{lr-}", "bad.strong"),
        (b"%{l1r-}", "strong"),
    ] {
        assert_eq!(
            developper(spec).as_deref(),
            Ok(attendu),
            "{}",
            std::string::String::from_utf8_lossy(spec)
        );
    }
}

#[test]
fn les_exemples_composes_de_la_rfc_passent_aussi() {
    // §7.4, seconde table.
    for (spec, attendu) in [
        (
            &b"%{ir}.%{v}._spf.%{d2}"[..],
            "3.2.0.192.in-addr._spf.example.com",
        ),
        (b"%{lr-}.lp._spf.%{d2}", "bad.strong.lp._spf.example.com"),
        (
            b"%{lr-}.lp.%{ir}.%{v}._spf.%{d2}",
            "bad.strong.lp.3.2.0.192.in-addr._spf.example.com",
        ),
        (
            b"%{d2}.trusted-domains.example.net",
            "example.com.trusted-domains.example.net",
        ),
    ] {
        assert_eq!(
            developper(spec).as_deref(),
            Ok(attendu),
            "{}",
            std::string::String::from_utf8_lossy(spec)
        );
    }
}

#[test]
fn une_adresse_ipv6_s_ecrit_en_quartets() {
    // RFC 7208 §7.2 : c'est ce qui permet à `%{ir}` de composer un nom sous
    // `ip6.arpa`.
    let contexte = Context {
        client: IpAddr::V6("2001:db8::cb01:2003".parse().expect("adresse")),
        sender: b"jean@example.com",
        helo: b"mx.example.com",
    };
    let mut sortie = Expanded::new();
    expand(b"%{i}", &contexte, b"example.com", &mut sortie).expect("développable");
    assert_eq!(
        std::string::String::from_utf8_lossy(sortie.as_bytes()),
        "2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.b.0.1.2.0.0.3"
    );
    // Et `%{v}` change avec la famille.
    expand(b"%{v}", &contexte, b"example.com", &mut sortie).expect("développable");
    assert_eq!(sortie.as_bytes(), b"ip6");
}

#[test]
fn les_trois_echappements_se_developpent() {
    // RFC 7208 §7.1 : `%%`, `%_` et `%-`.
    assert_eq!(developper(b"%%").as_deref(), Ok("%"));
    assert_eq!(developper(b"%_").as_deref(), Ok(" "));
    assert_eq!(developper(b"%-").as_deref(), Ok("%20"));
    assert_eq!(developper(b"a%%b").as_deref(), Ok("a%b"));
}

#[test]
fn ce_qui_n_est_pas_une_macro_traverse_tel_quel() {
    assert_eq!(
        developper(b"_spf.example.com").as_deref(),
        Ok("_spf.example.com")
    );
    assert_eq!(developper(b"").as_deref(), Ok(""));
}

#[test]
fn p_vaut_toujours_unknown() {
    // RFC 7208 §7.3 le prévoit, et §5.5 déconseille de s'en servir : le
    // résoudre coûterait une résolution inverse par macro.
    assert_eq!(developper(b"%{p}").as_deref(), Ok("unknown"));
}

#[test]
fn un_expediteur_sans_arobase_a_postmaster_pour_partie_locale() {
    // RFC 7208 §7.2.
    let contexte = Context {
        client: IpAddr::V4(Ipv4Addr::LOCALHOST),
        sender: b"example.com",
        helo: b"mx.example.com",
    };
    let mut sortie = Expanded::new();
    expand(b"%{l}", &contexte, b"example.com", &mut sortie).expect("développable");
    assert_eq!(sortie.as_bytes(), b"postmaster");
    expand(b"%{o}", &contexte, b"example.com", &mut sortie).expect("développable");
    assert_eq!(sortie.as_bytes(), b"example.com");
}

#[test]
fn une_macro_mal_formee_est_refusee() {
    // Toutes valent `permerror` : la RFC 7208 §7.1 ne laisse pas le choix.
    for spec in [
        &b"%"[..],   // un `%` seul
        b"%x",       // un échappement inconnu
        b"%{",       // jamais refermée
        b"%{d",      // idem
        b"%{}",      // vide
        b"%{z}",     // lettre inconnue
        b"%{d0}",    // zéro étiquette ne désigne rien
        b"%{d0000}", // et quatre chiffres non plus
        b"%{d2x}",   // `x` n'est pas un délimiteur
    ] {
        assert_eq!(
            developper(spec),
            Err(Error::MalformedMacro),
            "{}",
            std::string::String::from_utf8_lossy(spec)
        );
    }
}

#[test]
fn une_expansion_plus_longue_qu_un_nom_de_domaine_est_refusee() {
    // Un nom fait au plus 255 octets (RFC 1035 §2.3.4). La tronquer en
    // désignerait un AUTRE, et l'interroger serait pire que de refuser.
    let long = "a".repeat(250);
    let contexte = Context {
        client: IpAddr::V4(Ipv4Addr::LOCALHOST),
        sender: b"jean@example.com",
        helo: b"mx.example.com",
    };
    let mut sortie = Expanded::new();
    let spec = std::format!("{long}.{long}");
    assert_eq!(
        expand(spec.as_bytes(), &contexte, b"example.com", &mut sortie),
        Err(Error::MacroTooLong)
    );
}

#[test]
fn un_tampon_neuf_est_vide_et_se_reutilise() {
    let vide = Expanded::default();
    assert_eq!(vide.as_bytes(), b"");
    // Une seconde expansion ÉCRASE la première : sans cela, la question posée
    // au DNS serait la concaténation de deux domaines.
    let mut sortie = Expanded::new();
    expand(b"un", &contexte(), b"d.example", &mut sortie).expect("développable");
    expand(b"deux", &contexte(), b"d.example", &mut sortie).expect("développable");
    assert_eq!(sortie.as_bytes(), b"deux");
    assert!(!std::format!("{sortie:?}").is_empty());
}

#[test]
fn le_helo_se_developpe() {
    // `%{h}` est le nom annoncé par le pair — DONC UNE DONNÉE QU'IL CHOISIT.
    // C'est aussi ce qui le rend utile : `exists:%{h}.liste.example` interroge
    // ce que le pair a dit de lui-même.
    assert_eq!(developper(b"%{h}").as_deref(), Ok("mx.example.org"));
    assert_eq!(developper(b"%{h2}").as_deref(), Ok("example.org"));
    assert_eq!(developper(b"%{hr}").as_deref(), Ok("org.example.mx"));
}

#[test]
fn une_expansion_plus_longue_qu_un_nom_est_refusee() {
    // Deux cent cinquante-cinq octets, la longueur d'un nom de domaine. La
    // tronquer désignerait un AUTRE nom — c'est-à-dire interroger autre chose
    // que ce que la politique a écrit.
    let long = std::vec![b'a'; 300];
    let contexte = Context {
        client: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)),
        sender: b"jean@example.com",
        helo: &long,
    };
    let mut sortie = Expanded::new();
    assert_eq!(
        expand(b"%{h}", &contexte, b"example.com", &mut sortie),
        Err(Error::MacroTooLong)
    );
}

#[test]
fn le_point_qui_recolle_les_parties_compte_aussi() {
    // Le tampon est plein pile après la première partie : c'est le séparateur
    // qui déborde, et il doit déborder proprement.
    let mut helo = std::vec![b'a'; 255];
    helo.push(b'.');
    helo.push(b'b');
    let contexte = Context {
        client: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)),
        sender: b"jean@example.com",
        helo: &helo,
    };
    let mut sortie = Expanded::new();
    assert_eq!(
        expand(b"%{h}", &contexte, b"example.com", &mut sortie),
        Err(Error::MacroTooLong)
    );
}

#[test]
fn les_trois_echappements_debordent_proprement() {
    // `%%`, `%_` et `%-` s'écrivent APRÈS le reste : si le tampon est déjà
    // plein, ils ne doivent pas se perdre en silence.
    let plein = std::vec![b'a'; 255];
    for echappement in [&b"%%"[..], b"%_", b"%-"] {
        let mut spec = plein.clone();
        spec.extend_from_slice(echappement);
        let mut sortie = Expanded::new();
        assert_eq!(
            expand(&spec, &contexte(), b"example.com", &mut sortie),
            Err(Error::MacroTooLong),
            "{}",
            std::string::String::from_utf8_lossy(echappement)
        );
    }
}

#[test]
fn une_valeur_de_plus_de_cent_vingt_huit_parties_est_refusee() {
    // Un nom de domaine n'a pas cent vingt-huit étiquettes ; une valeur qui en
    // aurait davantage ne désigne rien d'interrogeable. Le tableau des parties
    // est FIXE, et c'est lui qui dit non.
    let beaucoup: std::vec::Vec<u8> = b"a."[..].repeat(130);
    let contexte = Context {
        client: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)),
        sender: b"jean@example.com",
        helo: &beaucoup,
    };
    let mut sortie = Expanded::new();
    assert_eq!(
        expand(b"%{h}", &contexte, b"example.com", &mut sortie),
        Err(Error::MacroTooLong)
    );
}
