use super::{
    RECEIVED_MAX, RETURN_PATH_MAX, Received, Transport, write_received, write_return_path,
};
use crate::Error;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Un champ ordinaire.
fn champ() -> Received<'static> {
    Received {
        helo: b"client.example.net",
        client: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        receiver: b"mail.nous.test",
        with: Transport::Esmtps,
        // 2026-09-02T06:00:00Z
        date: 1_788_242_400,
    }
}

/// Compose, et rend le texte.
fn composer(champ: &Received<'_>) -> std::string::String {
    let mut sortie = [0_u8; RECEIVED_MAX];
    let ecrit = write_received(&mut sortie, champ).expect("composable");
    std::string::String::from_utf8(ecrit.to_vec()).expect("ASCII")
}

// ── LA FORME ────────────────────────────────────────────────────────────────

#[test]
fn le_champ_dit_d_ou_par_ou_comment_et_quand() {
    let vu = composer(&champ());
    assert!(
        vu.starts_with("Received: from client.example.net ([192.0.2.1])\r\n\tby mail.nous.test with ESMTPS;\r\n\t"),
        "{vu:?}"
    );
    assert!(vu.ends_with("\r\n"), "{vu:?}");
    // La date est celle du calendrier du dépôt, et pas une seconde écriture.
    let mut date = [0_u8; crate::DATE_MAX];
    let attendue = crate::write_date(1_788_242_400, &mut date).expect("datable");
    assert!(
        vu.contains(core::str::from_utf8(attendue).expect("ASCII")),
        "{vu:?}"
    );
}

/// **AUCUNE CLAUSE `for`**, jamais : elle mettrait un destinataire dans un
/// en-tête qui voyage.
#[test]
fn le_champ_ne_nomme_aucun_destinataire() {
    assert!(!composer(&champ()).contains(" for "));
}

/// **UN SEUL CHAMP**, replié : une seule ligne ne commence pas par un blanc, et
/// c'est la première.
#[test]
fn le_champ_est_replie_et_reste_un_seul_champ() {
    let vu = composer(&champ());
    for (rang, ligne) in vu.split('\n').enumerate() {
        let ligne = ligne.strip_suffix('\r').unwrap_or(ligne);
        if ligne.is_empty() {
            continue;
        }
        assert!(
            rang == 0 || ligne.starts_with([' ', '\t']),
            "une seconde ligne d'en-tête : {vu:?}"
        );
        assert!(ligne.len() <= 998, "ligne de plus de 998 octets : {vu:?}");
    }
}

/// Les quatre mots de RFC 3848, et pas un de plus.
#[test]
fn chaque_transport_a_son_mot() {
    for (transport, mot) in [
        (Transport::Smtp, "SMTP"),
        (Transport::Esmtp, "ESMTP"),
        (Transport::Esmtps, "ESMTPS"),
        (Transport::EsmtpsA, "ESMTPSA"),
    ] {
        assert_eq!(transport.name(), mot);
        let vu = composer(&Received {
            with: transport,
            ..champ()
        });
        assert!(vu.contains(&std::format!(" with {mot};")), "{vu:?}");
    }
    assert!(!std::format!("{:?}", Transport::Smtp).is_empty());
}

/// Une adresse IPv6 s'écrit comme `core::net` l'écrit, et non autrement.
#[test]
fn une_adresse_ipv6_s_ecrit_entre_crochets() {
    let vu = composer(&Received {
        client: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ..champ()
    });
    assert!(vu.contains("([2001:db8::1])"), "{vu:?}");
}

// ── CE QUI EST REFUSÉ ───────────────────────────────────────────────────────

/// **CE QUI VIENT DU PAIR EST VÉRIFIÉ ICI**, et pas seulement à la grammaire :
/// ce champ s'écrit EN TÊTE du message, là où un octet de trop parle sous notre
/// nom.
#[test]
fn un_nom_qui_n_est_pas_de_l_ascii_visible_est_refuse() {
    for mauvais in [
        &b""[..],                 // vide
        b"client example",        // une espace couperait le champ
        b"client\r\nX-Faux: oui", // l'injection elle-même
        b"client\n",              // un LF nu
        b"cli\x00ent",            // un octet nul
        b"cli\xc3\xa9nt",         // hors de l'ASCII
        &[b'a'; 256],             // plus long qu'un nom de domaine
    ] {
        let mut sortie = [0_u8; RECEIVED_MAX];
        assert_eq!(
            write_received(
                &mut sortie,
                &Received {
                    helo: mauvais,
                    ..champ()
                }
            )
            .map(<[u8]>::len),
            Err(Error::NotPrintable),
            "{mauvais:?} est passé"
        );
    }
    // Et le nom du serveur est vérifié de la même façon : il vient d'une
    // configuration, mais une configuration s'écrit aussi de travers.
    let mut sortie = [0_u8; RECEIVED_MAX];
    assert_eq!(
        write_received(
            &mut sortie,
            &Received {
                receiver: b"mail nous test",
                ..champ()
            }
        )
        .map(<[u8]>::len),
        Err(Error::NotPrintable)
    );
}

/// **UN TAMPON TROP COURT LE DIT** au lieu d'écrire à moitié.
#[test]
fn un_tampon_trop_court_est_une_erreur() {
    // Toutes les tailles jusqu'à celle qui suffit : chaque `pousser` a sa
    // chance d'être celui qui manque de place.
    let complet = composer(&champ()).len();
    for taille in 0..complet {
        let mut sortie = std::vec![0_u8; taille];
        assert_eq!(
            write_received(&mut sortie, &champ()).map(<[u8]>::len),
            Err(Error::BufferTooSmall),
            "une taille de {taille} a suffi"
        );
    }
    let mut juste = std::vec![0_u8; complet];
    assert!(write_received(&mut juste, &champ()).is_ok());
}

// ── LE `Return-Path:` DE LA REMISE FINALE (RFC 5321 §4.4) ───────────────────

/// Compose la ligne, et la rend en texte.
fn chemin(depose: &[u8]) -> std::string::String {
    let mut place = [0_u8; RETURN_PATH_MAX];
    let ecrit = write_return_path(&mut place, depose).expect("composable");
    std::string::String::from_utf8_lossy(ecrit).into_owned()
}

/// **§4.4 EN EXIGE DEUX, ET CELUI-CI CONSIGNE L'EXPÉDITEUR D'ENVELOPPE.**
///
/// `From:` ne le dit pas — cet écart est toute la base de SPF, de DMARC et du
/// traitement des rebonds — et sans cette ligne il est perdu à la remise.
#[test]
fn le_chemin_de_retour_se_consigne_en_tete() {
    assert_eq!(
        chemin(b"jean@example.com"),
        "Return-Path: <jean@example.com>\r\n"
    );
    // Un littéral d'adresse s'écrit aussi : cette ligne consigne CE QUE LE PAIR
    // A DIT, et non l'adresse à laquelle un rapport reviendrait.
    assert_eq!(
        chemin(b"jean@[192.0.2.1]"),
        "Return-Path: <jean@[192.0.2.1]>\r\n"
    );
}

/// **`<>` N'EST PAS UNE ABSENCE, C'EST UNE VALEUR.**
///
/// Un chemin nul dit « ceci est un rapport », et §2 de RFC 3834 veut qu'un
/// répondeur automatique s'en abstienne. C'est cette ligne qui le lui apprend :
/// sans elle, rien ne distingue un rebond d'un message ordinaire.
#[test]
fn le_chemin_nul_s_ecrit_et_ne_s_omet_pas() {
    assert_eq!(chemin(b""), "Return-Path: <>\r\n");
}

/// **CETTE CAISSE NE CROIT PAS SON APPELANT.**
///
/// La ligne s'écrit EN TÊTE du message, là où un octet de trop parle sous notre
/// nom : un `CRLF` glissé dedans y écrirait un en-tête entier à notre place.
#[test]
fn un_chemin_qui_ecrirait_un_en_tete_est_refuse() {
    let mut place = [0_u8; RETURN_PATH_MAX];
    for mauvais in [
        &b"jean@example.com\r\nX-Forge: oui"[..],
        b"jean @example.com",       // l'espace couperait le champ
        b"jean@example.com>\r\n<x", // les chevrons sont les nôtres
        b"<jean@example.com",
        b"jean@exempl\xc3\xa9.com", // de l'UTF-8 : le message n'a pas de jeu déclaré
    ] {
        assert!(
            write_return_path(&mut place, mauvais).is_err(),
            "{mauvais:?} est passé"
        );
    }
    // Et un chemin plus long que ce qu'un nom peut peser ne s'écrit pas non plus.
    let long = std::vec![b'x'; 256];
    assert!(write_return_path(&mut place, &long).is_err());
}

/// **CE QUI NE TIENT PAS LE DIT**, et la borne annoncée suffit exactement.
#[test]
fn un_tampon_trop_court_le_dit() {
    let depose = b"jean@example.com";
    let complet = chemin(depose).len();
    for taille in 0..complet {
        let mut court = std::vec![0_u8; taille];
        assert!(
            write_return_path(&mut court, depose).is_err(),
            "une taille de {taille} a suffi"
        );
    }
    let mut juste = std::vec![0_u8; complet];
    assert!(write_return_path(&mut juste, depose).is_ok());
    // La borne couvre le pire cas : le plus long chemin qu'on accepte.
    let pire = std::vec![b'x'; 255];
    let mut place = [0_u8; RETURN_PATH_MAX];
    assert!(write_return_path(&mut place, &pire).is_ok());
}
