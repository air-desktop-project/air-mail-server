use super::{ENVID_MAX, Notify, ORCPT_MAX, Ret, decode_xtext, parse_orcpt};
use crate::Error;

// ── `NOTIFY` (§4.1) ─────────────────────────────────────────────────────────

/// **`FAILURE` SEUL EST LE DÉFAUT**, ce que SMTP fait depuis toujours.
#[test]
fn sans_parametre_on_rend_compte_des_echecs_et_de_rien_d_autre() {
    let defaut = Notify::default();
    assert!(defaut.on_failure());
    assert!(!defaut.on_success());
    assert!(!defaut.on_delay());
    assert!(!defaut.never());
}

#[test]
fn chaque_mot_se_decode_a_la_casse_pres() {
    let vu = Notify::parse(b"success,FAILURE,Delay").expect("recevable");
    assert!(vu.on_success() && vu.on_failure() && vu.on_delay());
    assert!(!vu.never());

    let jamais = Notify::parse(b"never").expect("recevable");
    assert!(jamais.never());
    assert!(!jamais.on_failure(), "`NEVER` ne demande RIEN");
    assert!(!std::format!("{jamais:?}").is_empty());
}

/// **`NEVER` NE SE COMBINE AVEC RIEN** (§4.1) : « ne me dis rien, sauf en cas de
/// succès » n'est pas une demande cohérente, et l'accepter reviendrait à choisir
/// soi-même laquelle des deux moitiés honorer.
#[test]
fn never_mele_a_autre_chose_est_refuse() {
    for mauvais in [
        &b"NEVER,SUCCESS"[..],
        b"SUCCESS,NEVER",
        b"NEVER,FAILURE,DELAY",
    ] {
        assert_eq!(
            Notify::parse(mauvais),
            Err(Error::MalformedParameter),
            "{mauvais:?} est passé"
        );
    }
}

/// **UN MOT RÉPÉTÉ EST UNE FAUTE**, et non un doublon anodin.
#[test]
fn une_valeur_de_notify_irrecevable_est_refusee() {
    for mauvais in [
        &b""[..],                               // vide
        b"SUCCESS,SUCCESS",                     // répété
        b"SUCCESS,",                            // un mot vide
        b",SUCCESS",                            // idem, en tête
        b"SUCCES",                              // inconnu
        b"SUCCESS FAILURE",                     // une espace n'est pas une virgule
        b"SUCCESS,FAILURE,DELAY,NEVER,SUCCESS", // plus de quatre
    ] {
        assert_eq!(
            Notify::parse(mauvais),
            Err(Error::MalformedParameter),
            "{mauvais:?} est passé"
        );
    }
}

// ── `RET` (§4.3) ────────────────────────────────────────────────────────────

#[test]
fn ret_ne_connait_que_deux_valeurs() {
    assert_eq!(Ret::parse(b"full"), Ok(Ret::Full));
    assert_eq!(Ret::parse(b"HDRS"), Ok(Ret::Headers));
    for mauvais in [&b""[..], b"HEADERS", b"FULL,HDRS", b"BODY"] {
        assert_eq!(Ret::parse(mauvais), Err(Error::MalformedParameter));
    }
    assert!(!std::format!("{:?}", Ret::Full).is_empty());
}

// ── `xtext` (§4) ────────────────────────────────────────────────────────────

/// **LE DÉCODAGE NE PEUT QUE RACCOURCIR** : `+41` fait un octet là où il en
/// occupait trois.
#[test]
fn un_xtext_se_decode_et_ne_grandit_jamais() {
    let mut sortie = [0_u8; ORCPT_MAX];
    for (code, clair) in [
        (&b"marie@example.com"[..], &b"marie@example.com"[..]),
        (b"a+2Bb", b"a+b"),
        (b"a+3Db", b"a=b"),
        (b"+41+42", b"AB"),
        (b"+7E", b"~"),
    ] {
        let vu = decode_xtext(code, &mut sortie).expect("recevable");
        assert_eq!(vu, clair, "{code:?}");
        assert!(vu.len() <= code.len(), "le décodage a grandi");
    }
    // Vide se décode en vide.
    assert_eq!(decode_xtext(b"", &mut sortie), Ok(&[][..]));
}

/// **LA MINUSCULE HEXADÉCIMALE EST REFUSÉE** : deux écritures d'un même octet
/// donneraient deux `ORCPT` pour une même adresse, donc deux rapports là où le
/// pair n'en attend qu'un.
#[test]
fn un_xtext_mal_forme_est_refuse() {
    let mut sortie = [0_u8; ORCPT_MAX];
    for mauvais in [
        &b"+2b"[..],    // minuscule
        b"+2",          // un seul chiffre
        b"+",           // rien derrière
        b"+ZZ",         // hors de l'hexadécimal
        b"a=b",         // `=` en clair
        b"a b",         // une espace n'est pas visible
        b"a\tb",        // ni une tabulation
        b"a\x7fb",      // ni un octet de contrôle
        b"caf\xc3\xa9", // ni de l'UTF-8
        // **UNE ÉCHAPPÉE QUI DÉCODE UNE FIN DE LIGNE** : c'est l'injection
        // que le fuzz a trouvée. `+0D+0A` écrirait un en-tête entier dans
        // le rapport, sous notre nom.
        b"+0D",
        b"+0A",
        b"a+0D+0AX-Faux:+20oui",
        b"+00", // l'octet nul
        b"+20", // une espace : la file s'en sert pour séparer
        b"+7F", // un octet de contrôle
        b"+B2", // hors de l'ASCII
    ] {
        assert_eq!(
            decode_xtext(mauvais, &mut sortie).map(<[u8]>::len),
            Err(Error::MalformedParameter),
            "{mauvais:?} est passé"
        );
    }
}

/// **UN TAMPON TROP COURT LE DIT** au lieu d'écrire à moitié.
#[test]
fn un_xtext_qui_ne_tient_pas_est_une_erreur() {
    let mut court = [0_u8; 2];
    assert!(matches!(
        decode_xtext(b"abc", &mut court),
        Err(Error::BufferTooSmall { .. })
    ));
    let mut vide = [0_u8; 0];
    assert!(matches!(
        decode_xtext(b"a", &mut vide),
        Err(Error::BufferTooSmall { .. })
    ));
    assert_eq!(decode_xtext(b"", &mut vide), Ok(&[][..]));
}

// ── `ORCPT` (§4.2) ──────────────────────────────────────────────────────────

#[test]
fn un_orcpt_se_coupe_en_type_et_adresse() {
    let mut sortie = [0_u8; ORCPT_MAX];
    let (type_adresse, adresse) =
        parse_orcpt(b"rfc822;marie@example.com", &mut sortie).expect("recevable");
    assert_eq!(type_adresse, b"rfc822");
    assert_eq!(adresse, b"marie@example.com");

    // L'adresse est un xtext : elle se décode.
    let (_, adresse) = parse_orcpt(b"rfc822;a+2Bb@example.com", &mut sortie).expect("recevable");
    assert_eq!(adresse, b"a+b@example.com");
    // Le TYPE, lui, ne se décode pas : §4.2 le veut en clair.
    let (type_adresse, _) = parse_orcpt(b"x-uni-2;a@b.co", &mut sortie).expect("recevable");
    assert_eq!(type_adresse, b"x-uni-2");
}

#[test]
fn un_orcpt_mal_forme_est_refuse() {
    let mut sortie = [0_u8; ORCPT_MAX];
    for mauvais in [
        &b"marie@example.com"[..], // pas de point-virgule
        b";marie@example.com",     // pas de type
        b"rfc822;",                // pas d'adresse
        b"rfc 822;a@b.co",         // un type qui n'en est pas un
        b"rfc822;a=b",             // l'adresse n'est pas un xtext
        b"rfc822;+2b",             // minuscule hexadécimale
    ] {
        assert!(
            parse_orcpt(mauvais, &mut sortie).is_err(),
            "{mauvais:?} est passé"
        );
    }
    // Un type plus long que quarante octets n'en est pas un.
    let mut long = b"a"[..].repeat(41);
    long.extend_from_slice(b";x@y.co");
    assert!(parse_orcpt(&long, &mut sortie).is_err());
    // Et une adresse qui ne tient pas dans le tampon le dit.
    let mut court = [0_u8; 4];
    assert!(parse_orcpt(b"rfc822;marie@example.com", &mut court).is_err());
    const { assert!(ENVID_MAX < ORCPT_MAX) };
}
