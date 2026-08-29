//! Ce que l'en-tête `Received-SPF` doit tenir.

use super::{Identity, RECEIVED_SPF_MAX, ReceivedSpf, write_received_spf};
use crate::{Error, Verdict};
use core::net::IpAddr;

fn champ<'a>(result: Verdict, sender: &'a str, helo: &'a str) -> ReceivedSpf<'a> {
    ReceivedSpf {
        result,
        client: "192.0.2.1".parse().expect("adresse"),
        sender: sender.as_bytes(),
        helo: helo.as_bytes(),
        receiver: b"mail.example.com",
        identity: Identity::MailFrom,
    }
}

fn composer(champ: &ReceivedSpf<'_>) -> std::string::String {
    let mut tampon = [0_u8; RECEIVED_SPF_MAX];
    let ecrit = write_received_spf(&mut tampon, champ).expect("composable");
    std::string::String::from_utf8(ecrit.to_vec()).expect("ASCII")
}

/// Le contenu de l'en-tête, replis retirés — ce qu'un analyseur lira.
fn deplie(entete: &str) -> std::string::String {
    entete.replace("\r\n ", " ").replace("\r\n", "")
}

#[test]
fn un_pass_dit_ce_qu_il_a_verifie() {
    let entete = composer(&champ(Verdict::Pass, "jean@example.com", "mx.example.com"));
    let plat = deplie(&entete);
    assert!(plat.starts_with("Received-SPF: pass "), "{plat}");
    let attendu =
        "(mail.example.com: domain of jean@example.com designates 192.0.2.1 as permitted sender)";
    assert!(plat.contains(attendu), "{plat}");
    assert!(plat.contains("client-ip=192.0.2.1"), "{plat}");
    assert!(
        plat.contains("envelope-from=\"jean@example.com\""),
        "{plat}"
    );
    assert!(plat.contains("helo=\"mx.example.com\""), "{plat}");
    assert!(plat.contains("identity=mailfrom"), "{plat}");
    assert!(plat.contains("receiver=\"mail.example.com\""), "{plat}");
    assert!(entete.ends_with("\r\n"), "{entete:?}");
}

#[test]
fn les_sept_verdicts_ont_chacun_leur_mot() {
    // RFC 7208 §2.6 : ce sont ces mots-là que les analyseurs en aval cherchent,
    // et un mot inventé ne serait lu par personne.
    for (verdict, mot) in [
        (Verdict::None, "none"),
        (Verdict::Neutral, "neutral"),
        (Verdict::Pass, "pass"),
        (Verdict::Fail, "fail"),
        (Verdict::SoftFail, "softfail"),
        (Verdict::TempError, "temperror"),
        (Verdict::PermError, "permerror"),
    ] {
        let plat = deplie(&composer(&champ(
            verdict,
            "jean@example.com",
            "mx.example.com",
        )));
        let attendu = std::format!("Received-SPF: {mot} ");
        assert!(plat.starts_with(&attendu), "{verdict:?} : {plat}");
        // Et chacun explique quelque chose : un commentaire vide ne dirait rien
        // à qui relit un message six mois plus tard.
        assert!(plat.contains("jean@example.com"), "{verdict:?} : {plat}");
        assert!(plat.contains("192.0.2.1"), "{verdict:?} : {plat}");
        assert!(
            plat.ends_with("receiver=\"mail.example.com\""),
            "{verdict:?} : {plat}"
        );
    }
}

#[test]
fn l_identite_verifiee_est_nommee() {
    // Un expéditeur nul se vérifie sur le `HELO` (RFC 7208 §2.4). Ne pas le dire
    // ferait croire que l'adresse de l'enveloppe a été vérifiée.
    let mut champ = champ(Verdict::Pass, "postmaster@mx.example.net", "mx.example.net");
    champ.identity = Identity::Helo;
    let plat = deplie(&composer(&champ));
    assert!(plat.contains("identity=helo"), "{plat}");
}

#[test]
fn une_adresse_ipv6_s_ecrit_sous_sa_forme_usuelle() {
    // On emprunte le `Display` de la bibliothèque standard : la forme abrégée a
    // ses règles (RFC 5952), et un second écrivain finirait par les appliquer
    // autrement.
    let mut champ = champ(Verdict::Pass, "jean@example.com", "mx.example.com");
    champ.client = "2001:db8::1".parse::<IpAddr>().expect("adresse");
    let plat = deplie(&composer(&champ));
    assert!(plat.contains("client-ip=2001:db8::1"), "{plat}");
}

// ── CE QUI VIENT DU PAIR ────────────────────────────────────────────────────

#[test]
fn un_saut_de_ligne_dans_l_expediteur_fait_refuser_l_entete() {
    // C'EST LA PROPRIÉTÉ QUI COMPTE. Recopier ces octets laisserait le pair
    // écrire les en-têtes qu'il veut dans le message qu'on remet.
    let mut tampon = [0_u8; RECEIVED_SPF_MAX];
    for mechant in [
        &b"jean\r\nX-Admin: oui@example.com"[..],
        b"jean\nX-Admin: oui@example.com",
        b"jean\r@example.com",
        b"jean\t@example.com",
        b"jean\0@example.com",
        "jean\u{e9}@example.com".as_bytes(),
    ] {
        let mut champ = champ(Verdict::Pass, "jean@example.com", "mx.example.com");
        champ.sender = mechant;
        assert_eq!(
            write_received_spf(&mut tampon, &champ),
            Err(Error::NotPrintable),
            "{}",
            std::string::String::from_utf8_lossy(mechant)
        );
    }
}

#[test]
fn les_trois_valeurs_du_pair_sont_examinees() {
    let mut tampon = [0_u8; RECEIVED_SPF_MAX];
    let modeles: [fn(&mut ReceivedSpf<'_>, &'static [u8]); 3] = [
        |champ, valeur| champ.sender = valeur,
        |champ, valeur| champ.helo = valeur,
        // Le nom du serveur ne vient pas du pair — mais il vient d'un fichier de
        // configuration, et un en-tête qu'on ne sait pas lire ne s'écrit pas
        // davantage parce que c'est l'administrateur qui s'est trompé.
        |champ, valeur| champ.receiver = valeur,
    ];
    for poser in modeles {
        let mut champ = champ(Verdict::Pass, "jean@example.com", "mx.example.com");
        poser(&mut champ, b"mauvais\r\nX-Admin: oui");
        assert_eq!(
            write_received_spf(&mut tampon, &champ),
            Err(Error::NotPrintable)
        );
    }
}

#[test]
fn les_quatre_octets_qui_ont_un_sens_sont_echappes() {
    // Une parenthèse dans une partie locale fermerait le commentaire, et la
    // suite se lirait comme des paramètres. Un guillemet ferait de même dans la
    // chaîne d'`envelope-from`.
    let mechant = "\"jean(x)\\y\"@example.com";
    let entete = composer(&champ(Verdict::Pass, mechant, "mx.example.com"));
    let plat = deplie(&entete);
    assert!(
        plat.contains("\\\"jean\\(x\\)\\\\y\\\"@example.com"),
        "{plat}"
    );
    // Et le commentaire reste équilibré : une seule parenthèse ouvrante non
    // échappée, une seule fermante.
    let ouvrantes = plat.matches("(").count() - plat.matches("\\(").count();
    let fermantes = plat.matches(")").count() - plat.matches("\\)").count();
    assert_eq!(ouvrantes, 1, "{plat}");
    assert_eq!(fermantes, 1, "{plat}");
}

#[test]
fn une_espace_est_permise_mais_pas_une_tabulation() {
    // Une partie locale entre guillemets peut porter une espace (RFC 5321
    // §4.1.2). Une tabulation, elle, est un octet de repli en puissance.
    let entete = composer(&champ(
        Verdict::Pass,
        "\"jean paul\"@example.com",
        "mx.example.com",
    ));
    assert!(deplie(&entete).contains("jean paul"), "{entete}");
}

// ── LE PLIAGE ───────────────────────────────────────────────────────────────

#[test]
fn aucune_ligne_ne_depasse_ce_qu_une_ligne_peut_faire() {
    // RFC 5322 §2.1.1 : 998 octets au plus, 78 recommandés. Un en-tête plus long
    // qu'une ligne n'est pas un en-tête — les analyseurs en aval le coupent où
    // ils veulent, et ce qu'ils en lisent n'est plus ce qu'on a écrit.
    let long_expediteur = std::format!("{}@{}.example", "a".repeat(60), "b".repeat(240));
    let long_helo = std::format!("{}.example", "c".repeat(240));
    let entete = composer(&champ(Verdict::SoftFail, &long_expediteur, &long_helo));
    for ligne in entete.trim_end_matches("\r\n").split("\r\n") {
        assert!(ligne.len() <= 998, "ligne de {} octets", ligne.len());
    }
    // Le repli commence par une espace : sans elle, la ligne suivante serait un
    // nouvel en-tête, et le message porterait un champ que personne n'a écrit.
    for suite in entete.split("\r\n").skip(1).filter(|l| !l.is_empty()) {
        assert!(suite.starts_with(' '), "repli sans espace : {suite:?}");
    }
    // Et tout y est encore.
    let plat = deplie(&entete);
    assert!(plat.contains(&long_expediteur), "{plat}");
    assert!(plat.contains(&long_helo), "{plat}");
}

#[test]
fn ce_qui_tient_sur_une_ligne_n_est_pas_plie_pour_rien() {
    let entete = composer(&champ(Verdict::Pass, "j@e.fr", "m.fr"));
    // Court, mais pas AU POINT de tenir sur une seule ligne : le commentaire et
    // les paramètres passent les 78 octets recommandés. On vérifie seulement
    // qu'on ne plie pas à chaque paramètre.
    // Trois replis au plus : le commentaire, puis les paramètres. Plier à
    // chaque paramètre donnerait un en-tête de sept lignes pour dire trois
    // choses.
    assert!(
        entete.matches("\r\n ").count() <= 3,
        "trop de replis : {entete:?}"
    );
}

#[test]
fn un_tampon_trop_petit_fait_refuser_plutot_que_couper() {
    // Un en-tête tronqué se lit comme un en-tête entier qui dit autre chose.
    // UN EXPÉDITEUR QUI S'ÉCHAPPE : sans lui, la contre-oblique qui précède un
    // octet de sens ne serait jamais écrite au bord du tampon, et son propre
    // refus resterait inéprouvé.
    let modele = champ(Verdict::Pass, "\"jean(x)\"@example.com", "mx.example.com");
    let entier = composer(&modele).len();
    // TOUTES les tailles, pas quelques-unes : chaque écriture a sa borne, et
    // celles qu'on ne visite pas sont celles qui déborderont un jour.
    for taille in 0..entier {
        let mut tampon = std::vec![0_u8; taille];
        assert_eq!(
            write_received_spf(&mut tampon, &modele),
            Err(Error::HeaderTooLong),
            "taille {taille}"
        );
    }
    let mut juste = std::vec![0_u8; entier];
    assert!(write_received_spf(&mut juste, &modele).is_ok());
}

#[test]
fn une_valeur_plus_longue_qu_une_ligne_est_refusee() {
    // Le pliage n'a lieu qu'AUX POINTS DE PLIAGE : une seule valeur de mille
    // octets ne se plie nulle part, et l'en-tête est refusé plutôt qu'émis
    // au-delà de la borne.
    let mut tampon = [0_u8; RECEIVED_SPF_MAX];
    let enorme = std::format!("{}@example.com", "a".repeat(1000));
    let mut champ = champ(Verdict::Pass, &enorme, "mx.example.com");
    champ.sender = enorme.as_bytes();
    assert_eq!(
        write_received_spf(&mut tampon, &champ),
        Err(Error::HeaderTooLong)
    );
}

#[test]
fn les_types_se_deboguent_et_se_copient() {
    let modele = champ(Verdict::Pass, "jean@example.com", "mx.example.com");
    let copie = modele;
    assert_eq!(copie.sender, modele.sender);
    assert!(!std::format!("{modele:?}").is_empty());
    assert_eq!(Identity::MailFrom, Identity::MailFrom);
    assert_ne!(Identity::MailFrom, Identity::Helo);
    assert!(!std::format!("{:?}", Identity::Helo).is_empty());
}

#[test]
fn une_ligne_trop_longue_est_refusee_avant_que_le_tampon_ne_manque() {
    // Les deux refus ne disent pas la même chose et ne surviennent pas au même
    // moment : ici, le tampon suffirait largement, mais le commentaire à lui
    // seul dépasse ce qu'une ligne peut porter.
    let mut tampon = [0_u8; RECEIVED_SPF_MAX];
    let long = std::format!("{}@example.com", "a".repeat(940));
    let mut modele = champ(Verdict::Pass, "jean@example.com", "mx.example.com");
    modele.sender = long.as_bytes();
    assert_eq!(
        write_received_spf(&mut tampon, &modele),
        Err(Error::HeaderTooLong)
    );
}
