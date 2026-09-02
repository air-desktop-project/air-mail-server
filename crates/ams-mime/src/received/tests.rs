use super::{RECEIVED_MAX, Received, Transport, write_received};
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
