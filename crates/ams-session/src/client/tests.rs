//! Ce qu'une session cliente dit, et ce qu'elle refuse de dire.

use ams_proto_smtp::{Limits, Reply};

use super::{CLIENT_COMMAND_MAX, ClientConfig, ClientOutcome, ClientStep, SmtpClient};
use crate::Error;

/// Lit une réponse d'épreuve.
fn reponse(texte: &'static [u8]) -> Reply<'static> {
    Reply::parse(texte, &Limits::DEFAULT).expect("réponse lisible")
}

/// Une configuration ordinaire : un destinataire, pas d'exigence de chiffrement.
fn config() -> ClientConfig<'static> {
    ClientConfig {
        name: b"mail.nous.test",
        sender: b"",
        recipients: &[b"collecte@eux.test"],
        require_tls: false,
    }
}

/// Nourrit une réponse et rend le geste, avec ce qui a été écrit.
fn pas(client: &mut SmtpClient<'_>, texte: &'static [u8]) -> (ClientStep, std::vec::Vec<u8>) {
    let mut sortie = [0_u8; CLIENT_COMMAND_MAX];
    let geste = client
        .on_reply(&reponse(texte), &mut sortie)
        .expect("geste");
    let ecrits = match geste {
        ClientStep::Send(n) | ClientStep::Done { sent: n, .. } => n,
        ClientStep::Secure | ClientStep::SendBody => 0,
    };
    (geste, sortie.get(..ecrits).unwrap_or_default().to_vec())
}

// ── LE CHEMIN ORDINAIRE ─────────────────────────────────────────────────────

#[test]
fn une_remise_ordinaire_se_deroule_dans_l_ordre() {
    let mut client = SmtpClient::new(config()).expect("configurable");
    assert!(!client.is_encrypted());

    let (geste, ecrit) = pas(&mut client, b"220 eux.test ESMTP\r\n");
    assert!(matches!(geste, ClientStep::Send(_)));
    assert_eq!(ecrit, b"EHLO mail.nous.test\r\n");

    let (_, ecrit) = pas(&mut client, b"250-eux.test\r\n250 SIZE 1000\r\n");
    // L'expéditeur vide est l'expéditeur NUL : c'est ce qui empêche une boucle
    // entre deux serveurs qui se répondraient l'un à l'autre.
    assert_eq!(ecrit, b"MAIL FROM:<>\r\n");

    let (_, ecrit) = pas(&mut client, b"250 ok\r\n");
    assert_eq!(ecrit, b"RCPT TO:<collecte@eux.test>\r\n");

    let (_, ecrit) = pas(&mut client, b"250 ok\r\n");
    assert_eq!(ecrit, b"DATA\r\n");
    assert_eq!(client.accepted(), 1);

    let (geste, _) = pas(&mut client, b"354 allez-y\r\n");
    assert_eq!(geste, ClientStep::SendBody);

    let (geste, ecrit) = pas(&mut client, b"250 2.0.0 Ok: queued\r\n");
    assert_eq!(
        geste,
        ClientStep::Done {
            sent: 6,
            outcome: ClientOutcome::Delivered
        }
    );
    assert_eq!(ecrit, b"QUIT\r\n");
}

/// RFC 3207 §4 : tout ce que le serveur avait annoncé est **oublié**. Réutiliser
/// l'`EHLO` d'avant reviendrait à faire confiance à ce qu'on a entendu en clair.
#[test]
fn le_chiffrement_fait_recommencer_la_presentation() {
    let mut client = SmtpClient::new(ClientConfig {
        require_tls: true,
        ..config()
    })
    .expect("configurable");
    pas(&mut client, b"220 eux.test ESMTP\r\n");

    let (_, ecrit) = pas(&mut client, b"250-eux.test\r\n250 STARTTLS\r\n");
    assert_eq!(ecrit, b"STARTTLS\r\n");

    let (geste, _) = pas(&mut client, b"220 allez-y\r\n");
    assert_eq!(geste, ClientStep::Secure);
    assert!(!client.is_encrypted(), "la poignée de main n'a pas eu lieu");

    let mut sortie = [0_u8; CLIENT_COMMAND_MAX];
    let geste = client.on_secured(&mut sortie).expect("reprise");
    let ClientStep::Send(ecrits) = geste else {
        panic!("on se represente : {geste:?}");
    };
    assert_eq!(&sortie[..ecrits], b"EHLO mail.nous.test\r\n");
    assert!(client.is_encrypted());

    // Le second `EHLO` n'annonce plus `STARTTLS` : on passe à l'enveloppe.
    let (_, ecrit) = pas(&mut client, b"250-eux.test\r\n250 SIZE 1000\r\n");
    assert_eq!(ecrit, b"MAIL FROM:<>\r\n");
}

/// **Un serveur de la RFC 821 ne connaît pas `EHLO`** (§3.2). Sans ce repli, on
/// couperait du courrier vers des machines qui fonctionnent.
#[test]
fn un_ehlo_refuse_se_replie_sur_helo() {
    let mut client = SmtpClient::new(config()).expect("configurable");
    pas(&mut client, b"220 eux.test\r\n");
    let (_, ecrit) = pas(&mut client, b"500 commande inconnue\r\n");
    assert_eq!(ecrit, b"HELO mail.nous.test\r\n");
    let (_, ecrit) = pas(&mut client, b"250 eux.test\r\n");
    assert_eq!(ecrit, b"MAIL FROM:<>\r\n");
}

#[test]
fn un_helo_refuse_aussi_met_fin_a_la_remise() {
    let mut client = SmtpClient::new(config()).expect("configurable");
    pas(&mut client, b"220 eux.test\r\n");
    pas(&mut client, b"500 commande inconnue\r\n");
    let (geste, ecrit) = pas(&mut client, b"550 non\r\n");
    assert!(matches!(
        geste,
        ClientStep::Done {
            outcome: ClientOutcome::Rejected(_),
            ..
        }
    ));
    assert_eq!(ecrit, b"QUIT\r\n");
}

// ── LE CHIFFREMENT NE SE NÉGOCIE PAS À LA BAISSE ────────────────────────────

#[test]
fn sans_starttls_offert_l_exigence_arrete_tout() {
    let mut client = SmtpClient::new(ClientConfig {
        require_tls: true,
        ..config()
    })
    .expect("configurable");
    pas(&mut client, b"220 eux.test\r\n");
    let (geste, ecrit) = pas(&mut client, b"250 eux.test\r\n");
    assert_eq!(
        geste,
        ClientStep::Done {
            sent: 6,
            outcome: ClientOutcome::NoEncryption
        }
    );
    assert_eq!(ecrit, b"QUIT\r\n");
}

/// Pas d'`EHLO`, donc pas d'extension, donc pas de `STARTTLS`.
#[test]
fn un_serveur_sans_esmtp_ne_chiffre_pas_non_plus() {
    let mut client = SmtpClient::new(ClientConfig {
        require_tls: true,
        ..config()
    })
    .expect("configurable");
    pas(&mut client, b"220 eux.test\r\n");
    pas(&mut client, b"500 inconnu\r\n");
    let (geste, _) = pas(&mut client, b"250 eux.test\r\n");
    assert!(matches!(
        geste,
        ClientStep::Done {
            outcome: ClientOutcome::NoEncryption,
            ..
        }
    ));
}

/// **On ne se rabat pas sur le clair.** Un refus qu'un tiers peut provoquer est
/// exactement le levier d'une attaque par déclassement.
#[test]
fn un_starttls_annonce_puis_refuse_ne_fait_pas_retomber_en_clair() {
    let mut client = SmtpClient::new(config()).expect("configurable");
    pas(&mut client, b"220 eux.test\r\n");
    pas(&mut client, b"250-eux.test\r\n250 STARTTLS\r\n");
    let (geste, ecrit) = pas(&mut client, b"454 pas maintenant\r\n");
    assert_eq!(
        geste,
        ClientStep::Done {
            sent: 6,
            outcome: ClientOutcome::NoEncryption
        }
    );
    assert_eq!(ecrit, b"QUIT\r\n");
}

// ── LES REFUS, ET CE QU'ILS VALENT ──────────────────────────────────────────

/// On ne dit pas `QUIT` à qui vient de refuser la conversation.
#[test]
fn une_banniere_qui_refuse_clot_tout_de_suite() {
    let mut client = SmtpClient::new(config()).expect("configurable");
    let (geste, ecrit) = pas(&mut client, b"554 pas de service ici\r\n");
    assert!(matches!(
        geste,
        ClientStep::Done {
            sent: 0,
            outcome: ClientOutcome::Rejected(_)
        }
    ));
    assert!(ecrit.is_empty());
}

#[test]
fn une_enveloppe_refusee_met_fin_a_la_remise() {
    let mut client = SmtpClient::new(config()).expect("configurable");
    pas(&mut client, b"220 eux.test\r\n");
    pas(&mut client, b"250 eux.test\r\n");
    let (geste, _) = pas(&mut client, b"451 revenez plus tard\r\n");
    assert!(matches!(
        geste,
        ClientStep::Done {
            outcome: ClientOutcome::Deferred(_),
            ..
        }
    ));
}

/// **Un refus partiel n'arrête pas la remise** : renoncer parce qu'une adresse
/// sur trois est inconnue ferait perdre les deux autres.
#[test]
fn un_destinataire_refuse_n_emporte_pas_les_autres() {
    let mut client = SmtpClient::new(ClientConfig {
        recipients: &[b"a@eux.test", b"b@eux.test", b"c@eux.test"],
        ..config()
    })
    .expect("configurable");
    pas(&mut client, b"220 eux.test\r\n");
    pas(&mut client, b"250 eux.test\r\n");
    let (_, ecrit) = pas(&mut client, b"250 ok\r\n");
    assert_eq!(ecrit, b"RCPT TO:<a@eux.test>\r\n");
    let (_, ecrit) = pas(&mut client, b"550 inconnue\r\n");
    assert_eq!(ecrit, b"RCPT TO:<b@eux.test>\r\n");
    let (_, ecrit) = pas(&mut client, b"250 ok\r\n");
    assert_eq!(ecrit, b"RCPT TO:<c@eux.test>\r\n");
    let (_, ecrit) = pas(&mut client, b"250 ok\r\n");
    assert_eq!(ecrit, b"DATA\r\n");
    assert_eq!(client.accepted(), 2);
    assert_eq!(client.refused(), 1);
}

#[test]
fn personne_ne_veut_du_message_et_le_dernier_code_le_dit() {
    for (refus, attendu) in [
        (
            &b"550 inconnue\r\n"[..],
            ClientOutcome::Rejected as fn(_) -> _,
        ),
        (
            b"451 boite pleine\r\n",
            ClientOutcome::Deferred as fn(_) -> _,
        ),
    ] {
        let mut client = SmtpClient::new(ClientConfig {
            recipients: &[b"a@eux.test", b"b@eux.test"],
            ..config()
        })
        .expect("configurable");
        pas(&mut client, b"220 eux.test\r\n");
        pas(&mut client, b"250 eux.test\r\n");
        pas(&mut client, b"250 ok\r\n");
        let mut sortie = [0_u8; CLIENT_COMMAND_MAX];
        client
            .on_reply(&reponse(refus), &mut sortie)
            .expect("geste");
        let geste = client
            .on_reply(&reponse(refus), &mut sortie)
            .expect("geste");
        let ClientStep::Done { outcome, sent } = geste else {
            panic!("la remise devait s'arrêter : {geste:?}");
        };
        assert_eq!(sent, 6);
        assert_eq!(client.accepted(), 0);
        assert_eq!(client.refused(), 2);
        let code = match outcome {
            ClientOutcome::Rejected(code) | ClientOutcome::Deferred(code) => code,
            autre => panic!("{autre:?}"),
        };
        assert_eq!(outcome, attendu(code), "{refus:?}");
    }
}

#[test]
fn un_data_qui_n_ouvre_pas_met_fin_a_la_remise() {
    let mut client = SmtpClient::new(config()).expect("configurable");
    pas(&mut client, b"220 eux.test\r\n");
    pas(&mut client, b"250 eux.test\r\n");
    pas(&mut client, b"250 ok\r\n");
    pas(&mut client, b"250 ok\r\n");
    let (geste, _) = pas(&mut client, b"552 trop gros\r\n");
    assert!(matches!(
        geste,
        ClientStep::Done {
            outcome: ClientOutcome::Rejected(_),
            ..
        }
    ));
}

#[test]
fn le_verdict_final_suit_le_code() {
    for (reponse_finale, attendue) in [
        (&b"451 disque plein\r\n"[..], "differe"),
        (b"554 refuse\r\n", "refuse"),
        // Un `3yz` là où on attendait un verdict n'est pas un refus : c'est un
        // désaccord sur le protocole, et un message jeté pour cela ne revient
        // pas.
        (b"354 encore ?\r\n", "inattendu"),
    ] {
        let mut client = SmtpClient::new(config()).expect("configurable");
        pas(&mut client, b"220 eux.test\r\n");
        pas(&mut client, b"250 eux.test\r\n");
        pas(&mut client, b"250 ok\r\n");
        pas(&mut client, b"250 ok\r\n");
        pas(&mut client, b"354 allez-y\r\n");
        let (geste, _) = pas(&mut client, reponse_finale);
        let ClientStep::Done { outcome, .. } = geste else {
            panic!("{geste:?}");
        };
        let mot = match outcome {
            ClientOutcome::Deferred(_) => "differe",
            ClientOutcome::Rejected(_) => "refuse",
            ClientOutcome::Unexpected(_) => "inattendu",
            autre => panic!("{autre:?}"),
        };
        assert_eq!(mot, attendue, "{reponse_finale:?}");
    }
}

#[test]
fn une_reponse_de_trop_est_refusee() {
    let mut client = SmtpClient::new(config()).expect("configurable");
    pas(&mut client, b"554 non\r\n");
    let mut sortie = [0_u8; CLIENT_COMMAND_MAX];
    assert_eq!(
        client.on_reply(&reponse(b"250 encore\r\n"), &mut sortie),
        Err(Error::SessionClosed)
    );
}

// ── ON N'ÉCRIT PAS CE QU'ON N'A PAS REGARDÉ ─────────────────────────────────

/// L'adresse d'un rapport DMARC est publiée par le domaine qu'on rapporte.
/// **Un `CRLF` glissé dedans écrirait des commandes à notre place.**
#[test]
fn c_est_ici_que_l_injection_de_commande_s_arrete() {
    for mechante in [
        &b"a@x.test\r\nRCPT TO:<victime@y.test>"[..],
        b"a@x.test\nDATA",
        b"a b@x.test",
        b"a<b@x.test",
        b"a>b@x.test",
        b"a\0b@x.test",
        b"",
    ] {
        let destinataires = [mechante];
        assert_eq!(
            SmtpClient::new(ClientConfig {
                recipients: &destinataires,
                ..config()
            })
            .err(),
            Some(Error::UnsafeAddress),
            "{mechante:?}"
        );
    }
    // L'expéditeur et notre propre nom sont regardés de la même façon.
    assert_eq!(
        SmtpClient::new(ClientConfig {
            sender: b"nous\r\nQUIT",
            ..config()
        })
        .err(),
        Some(Error::UnsafeAddress)
    );
    assert_eq!(
        SmtpClient::new(ClientConfig {
            name: b"",
            ..config()
        })
        .err(),
        Some(Error::UnsafeAddress)
    );
}

#[test]
fn une_remise_sans_destinataire_est_refusee() {
    assert_eq!(
        SmtpClient::new(ClientConfig {
            recipients: &[],
            ..config()
        })
        .err(),
        Some(Error::NoRecipient)
    );
}

/// **Chaque commande peut manquer de place**, et aucune ne doit s'écrire à
/// moitié. On rejoue donc la conversation entière autant de fois qu'elle a
/// d'étapes, en n'offrant un tampon minuscule qu'à l'une d'elles.
#[test]
fn un_tampon_trop_court_le_dit_a_chaque_etape() {
    // Le chemin le plus long : bannière, `EHLO` refusé, `HELO`, enveloppe,
    // destinataire, `DATA`, message. Seul le geste qui suit le `354` n'écrit
    // rien — il n'y a rien à y manquer.
    const ECHANGE: &[&[u8]] = &[
        b"220 eux.test\r\n",
        b"500 inconnu\r\n",
        b"250 eux.test\r\n",
        b"250 ok\r\n",
        b"250 ok\r\n",
        b"354 allez-y\r\n",
        b"250 recu\r\n",
    ];
    for court in 0..ECHANGE.len() {
        let mut client = SmtpClient::new(config()).expect("configurable");
        let mut assez = [0_u8; CLIENT_COMMAND_MAX];
        let mut minuscule = [0_u8; 4];
        for (rang, texte) in ECHANGE.iter().enumerate() {
            let issue = if rang == court {
                client.on_reply(&reponse(texte), &mut minuscule)
            } else {
                client.on_reply(&reponse(texte), &mut assez)
            };
            if rang != court {
                issue.expect("geste");
                continue;
            }
            // Le geste qui suit le `354` n'écrit rien : il ne peut pas manquer
            // de place.
            if issue == Ok(ClientStep::SendBody) {
                break;
            }
            assert!(
                matches!(issue, Err(Error::Reply(_))),
                "étape {court} : {issue:?}"
            );
            break;
        }
    }

    // La reprise après chiffrement écrit elle aussi une commande.
    let mut client = SmtpClient::new(config()).expect("configurable");
    let mut minuscule = [0_u8; 4];
    assert!(matches!(
        client.on_secured(&mut minuscule),
        Err(Error::Reply(_))
    ));

    // Et le `STARTTLS` lui-même.
    let mut client = SmtpClient::new(config()).expect("configurable");
    let mut assez = [0_u8; CLIENT_COMMAND_MAX];
    client
        .on_reply(&reponse(b"220 eux.test\r\n"), &mut assez)
        .expect("geste");
    assert!(matches!(
        client.on_reply(
            &reponse(b"250-eux.test\r\n250 STARTTLS\r\n"),
            &mut minuscule
        ),
        Err(Error::Reply(_))
    ));
}

#[test]
fn ce_qui_se_deroule_se_montre() {
    let client = SmtpClient::new(config()).expect("configurable");
    assert!(!std::format!("{client:?}").is_empty());
    assert!(!std::format!("{:?}", client.clone()).is_empty());
    assert!(!std::format!("{:?}", config()).is_empty());
    assert!(!std::format!("{:?}", config().clone()).is_empty());
    assert!(!std::format!("{:?}", ClientStep::Secure).is_empty());
    assert!(!std::format!("{:?}", ClientOutcome::Delivered).is_empty());
    assert_eq!(ClientOutcome::Delivered, ClientOutcome::Delivered);
    assert_ne!(ClientOutcome::Delivered, ClientOutcome::NoEncryption);
    assert_ne!(ClientStep::Secure, ClientStep::SendBody);
}

/// **Renoncer demande de la place aussi.** Chaque chemin qui s'arrête écrit un
/// `QUIT` avant de fermer, et aucun ne doit l'écrire à moitié.
#[test]
fn chaque_renoncement_a_besoin_de_sa_place() {
    /// Conduit l'échange avec un grand tampon, puis offre un tampon minuscule
    /// à la dernière réponse — celle qui fait renoncer.
    fn court(exige_tls: bool, avant: &[&'static [u8]], dernier: &'static [u8]) {
        let mut client = SmtpClient::new(ClientConfig {
            require_tls: exige_tls,
            recipients: &[b"a@eux.test"],
            ..config()
        })
        .expect("configurable");
        let mut assez = [0_u8; CLIENT_COMMAND_MAX];
        for texte in avant {
            client.on_reply(&reponse(texte), &mut assez).expect("geste");
        }
        let mut minuscule = [0_u8; 4];
        let issue = client.on_reply(&reponse(dernier), &mut minuscule);
        assert!(
            matches!(issue, Err(Error::Reply(_))),
            "{dernier:?} : {issue:?}"
        );
    }

    // `EHLO` accepté sans `STARTTLS`, alors qu'on l'exigeait.
    court(true, &[b"220 eux.test\r\n"], b"250 eux.test\r\n");
    // `HELO` refusé après un `EHLO` refusé.
    court(
        false,
        &[b"220 eux.test\r\n", b"500 inconnu\r\n"],
        b"550 non\r\n",
    );
    // `HELO` accepté, mais on exigeait le chiffrement.
    court(
        true,
        &[b"220 eux.test\r\n", b"500 inconnu\r\n"],
        b"250 eux.test\r\n",
    );
    // `STARTTLS` annoncé puis refusé.
    court(
        false,
        &[b"220 eux.test\r\n", b"250-eux.test\r\n250 STARTTLS\r\n"],
        b"454 pas maintenant\r\n",
    );
    // Enveloppe refusée.
    court(
        false,
        &[b"220 eux.test\r\n", b"250 eux.test\r\n"],
        b"550 non\r\n",
    );
    // Le seul destinataire refusé.
    court(
        false,
        &[b"220 eux.test\r\n", b"250 eux.test\r\n", b"250 ok\r\n"],
        b"550 inconnue\r\n",
    );
    // `DATA` refusé.
    court(
        false,
        &[
            b"220 eux.test\r\n",
            b"250 eux.test\r\n",
            b"250 ok\r\n",
            b"250 ok\r\n",
        ],
        b"552 trop gros\r\n",
    );
}
