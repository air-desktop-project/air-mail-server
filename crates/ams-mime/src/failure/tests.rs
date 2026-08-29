//! Ce qu'un rapport d'échec recopie, et ce qu'il laisse tomber.

use super::{EXPOSES, FailureMail, failure_mail_max, write_failure_mail, write_reported_headers};
use crate::{Error, Limits};

/// Le bloc d'en-tête d'un message rapporté, avec de tout dedans.
const ENTETES: &[u8] = b"Received: from mechant.test (mechant.test [192.0.2.1])\r\n\
                         \tby mail.nous.test with ESMTP id 42\r\n\
                         From: Service <securite@banque.test>\r\n\
                         To: Marie Dupont <marie@nous.test>\r\n\
                         Cc: Jean <jean@nous.test>\r\n\
                         Subject: Votre compte\r\n\
                         Date: Sat, 29 Aug 2026 07:08:31 +0000\r\n\
                         Message-ID: <abc@banque.test>\r\n\
                         X-Interne: numero de dossier 12345\r\n\
                         DKIM-Signature: v=1; a=rsa-sha256; d=banque.test; s=sel;\r\n\
                         \tb=ZmF1c3Nl\r\n\
                         \r\n";

fn courrier() -> FailureMail<'static> {
    FailureMail {
        from: b"dmarc@nous.test",
        to: b"echecs@banque.test",
        subject: b"DMARC failure report for banque.test",
        message_id: b"7a3f@mail.nous.test",
        date: 1_787_987_311,
        boundary: b"----ams-echec-0e1d",
        text: b"An authentication failure report follows.\r\n",
        feedback: b"Feedback-Type: auth-failure\r\nVersion: 1\r\n",
        reported_headers: ENTETES,
    }
}

fn composer(mail: &FailureMail<'_>) -> Result<std::string::String, Error> {
    let mut sortie = std::vec![0_u8; failure_mail_max(mail)];
    let ecrit = write_failure_mail(&mut sortie, mail, &Limits::DEFAULT)?;
    Ok(std::string::String::from_utf8_lossy(ecrit).into_owned())
}

// ── LA LISTE BLANCHE ────────────────────────────────────────────────────────

/// **`To:` ne peut pas y être** : c'est la seule ligne qui nomme le tiers qu'on
/// protège. `Received:` non plus : chaque saut décrit un chemin interne que
/// personne n'a demandé à publier.
#[test]
fn c_est_ici_que_le_courrier_d_autrui_s_arrete() {
    let texte = composer(&courrier()).expect("composable");
    for interdit in [
        "To: Marie Dupont",
        "marie@nous.test",
        "Cc:",
        "jean@nous.test",
        "Received:",
        "mail.nous.test with ESMTP",
        "X-Interne",
        "12345",
    ] {
        assert!(
            !texte.contains(interdit),
            "{interdit:?} a fuité dans le rapport :\n{texte}"
        );
    }
}

/// Ce qui reste est ce qui sert à comprendre un échec d'authentification.
#[test]
fn ce_qui_reste_est_ce_qui_sert() {
    let texte = composer(&courrier()).expect("composable");
    for garde in [
        "From: Service <securite@banque.test>\r\n",
        "Subject: Votre compte\r\n",
        "Date: Sat, 29 Aug 2026 07:08:31 +0000\r\n",
        "Message-ID: <abc@banque.test>\r\n",
        "DKIM-Signature: v=1; a=rsa-sha256; d=banque.test; s=sel;\r\n\tb=ZmF1c3Nl\r\n",
    ] {
        assert!(texte.contains(garde), "{garde:?} manque dans :\n{texte}");
    }
}

/// **Une liste blanche arrête un en-tête nouveau sans qu'on ait rien à faire.**
#[test]
fn un_en_tete_inconnu_ne_passe_pas() {
    const NOUVEAU: &[u8] = b"From: a@x.test\r\nX-Tout-Nouveau: une donnee personnelle\r\n\r\n";
    let mut sortie = [0_u8; 512];
    let ecrit = write_reported_headers(&mut sortie, NOUVEAU, &Limits::DEFAULT, b"----ams")
        .expect("filtrable");
    let texte = std::string::String::from_utf8_lossy(ecrit).into_owned();
    assert_eq!(texte, "From: a@x.test\r\n");
    assert!(EXPOSES.iter().any(|nom| *nom == b"From"));
    assert!(!EXPOSES.iter().any(|nom| *nom == b"To"));
}

// ── LA FORME DU MESSAGE ─────────────────────────────────────────────────────

#[test]
fn le_message_est_un_multipart_report_a_trois_parties() {
    let texte = composer(&courrier()).expect("composable");
    for morceau in [
        "From: <dmarc@nous.test>\r\n",
        "To: <echecs@banque.test>\r\n",
        "Subject: DMARC failure report for banque.test\r\n",
        "Content-Type: multipart/report; report-type=feedback-report;\r\n\tboundary=\"----ams-echec-0e1d\"\r\n",
        "Content-Type: text/plain; charset=us-ascii\r\n",
        "Content-Type: message/feedback-report\r\n",
        "Content-Type: text/rfc822-headers\r\n",
        "Feedback-Type: auth-failure\r\n",
    ] {
        assert!(
            texte.contains(morceau),
            "{morceau:?} manque dans :\n{texte}"
        );
    }
    // Trois ouvertures et une clôture.
    assert_eq!(texte.matches("------ams-echec-0e1d").count(), 4);
    assert!(texte.ends_with("\r\n------ams-echec-0e1d--\r\n"), "{texte}");
}

#[test]
fn un_bloc_d_en_tete_illisible_fait_refuser_le_rapport() {
    assert!(matches!(
        composer(&FailureMail {
            // Un `LF` isolé : la faute que cette crate refuse partout.
            reported_headers: b"From: a@x.test\nTo: b@y.test\r\n\r\n",
            ..courrier()
        }),
        Err(Error::BareLineFeed { .. })
    ));
}

#[test]
fn c_est_ici_que_l_injection_d_en_tete_s_arrete() {
    for mechante in [&b"a@x.test\r\nBcc: victime@y.test"[..], b"a b@x.test", b""] {
        for mail in [
            FailureMail {
                to: mechante,
                ..courrier()
            },
            FailureMail {
                from: mechante,
                ..courrier()
            },
            FailureMail {
                message_id: mechante,
                ..courrier()
            },
            FailureMail {
                boundary: mechante,
                ..courrier()
            },
        ] {
            assert_eq!(composer(&mail), Err(Error::NotPrintable), "{mechante:?}");
        }
    }
    assert_eq!(
        composer(&FailureMail {
            subject: b"un\r\nsujet",
            ..courrier()
        }),
        Err(Error::NotPrintable)
    );
    assert_eq!(
        composer(&FailureMail {
            feedback: b"un champ\nmal termine",
            ..courrier()
        }),
        Err(Error::NotPrintable)
    );
}

#[test]
fn un_delimiteur_qui_figure_dans_une_partie_fait_refuser() {
    assert_eq!(
        composer(&FailureMail {
            text: b"voici ----ams-echec-0e1d\r\n",
            ..courrier()
        }),
        Err(Error::BoundaryInContent)
    );
    assert_eq!(
        composer(&FailureMail {
            feedback: b"Feedback-Type: ----ams-echec-0e1d\r\n",
            ..courrier()
        }),
        Err(Error::BoundaryInContent)
    );
    // Et jusque dans les en-têtes rapportés, qui viennent d'un pair.
    assert_eq!(
        composer(&FailureMail {
            reported_headers: b"Subject: ----ams-echec-0e1d\r\n\r\n",
            ..courrier()
        }),
        Err(Error::BoundaryInContent)
    );
}

#[test]
fn un_tampon_trop_court_le_dit_ou_qu_il_cede() {
    for mail in [
        courrier(),
        FailureMail {
            text: b"sans fin",
            ..courrier()
        },
    ] {
        let entier = composer(&mail).expect("composable");
        for taille in 0..entier.len() {
            let mut sortie = std::vec![0_u8; taille];
            assert_eq!(
                write_failure_mail(&mut sortie, &mail, &Limits::DEFAULT),
                Err(Error::BufferTooSmall),
                "taille {taille}"
            );
        }
        assert!(failure_mail_max(&mail) >= entier.len());
    }
    assert!(!std::format!("{:?}", courrier()).is_empty());
}
