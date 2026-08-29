//! Ce qu'un message de rapport dit, et ce qu'il refuse de dire.

use super::{ReportMail, report_mail_max, write_report_mail};
use crate::Error;

/// Un message d'épreuve.
fn courrier() -> ReportMail<'static> {
    ReportMail {
        from: b"dmarc@nous.test",
        to: b"collecte@eux.test",
        subject: b"Report Domain: eux.test Submitter: mail.nous.test Report-ID: 7a3f",
        message_id: b"7a3f@mail.nous.test",
        date: 1_787_987_311,
        boundary: b"----ams-7a3f-0e1d",
        text: b"Ceci est un rapport DMARC.\r\n",
        filename: b"mail.nous.test!eux.test!0!1!7a3f.xml.gz",
        attachment: b"\x1f\x8b\x08\x00rapport compresse",
    }
}

/// Compose, et rend le texte.
fn composer(mail: &ReportMail<'_>) -> Result<std::string::String, Error> {
    let mut sortie = std::vec![0_u8; report_mail_max(mail)];
    let ecrit = write_report_mail(&mut sortie, mail)?;
    Ok(std::string::String::from_utf8_lossy(ecrit).into_owned())
}

#[test]
fn un_message_de_rapport_a_toutes_ses_parties() {
    let texte = composer(&courrier()).expect("composable");
    for morceau in [
        "From: <dmarc@nous.test>\r\n",
        "To: <collecte@eux.test>\r\n",
        "Subject: Report Domain: eux.test",
        "Date: Sat, 29 Aug 2026 07:08:31 +0000\r\n",
        "Message-ID: <7a3f@mail.nous.test>\r\n",
        "MIME-Version: 1.0\r\n",
        // Un rapport est écrit par une machine : le dire évite qu'un répondeur
        // automatique lui réponde, et qu'une boucle s'installe.
        "Auto-Submitted: auto-generated\r\n",
        "Content-Type: multipart/mixed; boundary=\"----ams-7a3f-0e1d\"\r\n",
        "Content-Type: text/plain; charset=us-ascii\r\n",
        "Ceci est un rapport DMARC.\r\n",
        "Content-Type: application/gzip\r\n",
        "Content-Transfer-Encoding: base64\r\n",
        "filename=\"mail.nous.test!eux.test!0!1!7a3f.xml.gz\"\r\n",
    ] {
        assert!(
            texte.contains(morceau),
            "{morceau:?} manque dans :\n{texte}"
        );
    }
    // Un en-tête, une ligne vide, deux parties, une clôture.
    assert_eq!(texte.matches("\r\n------ams-7a3f-0e1d").count(), 3);
    assert!(texte.ends_with("\r\n------ams-7a3f-0e1d--\r\n"), "{texte}");
}

/// La pièce jointe est bien le contenu encodé, et pas autre chose.
///
/// Le vecteur est écrit à la main : un test qui réencoderait avec le même code
/// passerait même si l'encodeur était faux de bout en bout.
#[test]
fn la_piece_jointe_porte_le_contenu_encode() {
    let texte = composer(&ReportMail {
        attachment: b"foobar",
        ..courrier()
    })
    .expect("composable");
    assert!(
        texte.contains("\r\n\r\nZm9vYmFy\r\n\r\n------ams-7a3f-0e1d--\r\n"),
        "{texte}"
    );
}

/// **Un `CRLF` glissé dans une adresse écrirait des en-têtes à notre place**,
/// dans un message que nous composons et que nous remettons nous-mêmes.
#[test]
fn c_est_ici_que_l_injection_d_en_tete_s_arrete() {
    // **Une adresse n'a pas d'espace**, un sujet en a : `<a b@x.test>` n'est
    // pas une adresse, et l'écrire ferait lire au destinataire autre chose que
    // ce qu'on croit avoir écrit.
    for mechante in [
        &b"a@x.test\r\nBcc: victime@y.test"[..],
        b"a@x.test\nBcc: victime@y.test",
        b"a b@x.test",
        b"",
    ] {
        for mail in [
            ReportMail {
                to: mechante,
                ..courrier()
            },
            ReportMail {
                from: mechante,
                ..courrier()
            },
            ReportMail {
                message_id: mechante,
                ..courrier()
            },
            ReportMail {
                boundary: mechante,
                ..courrier()
            },
            ReportMail {
                filename: mechante,
                ..courrier()
            },
        ] {
            assert_eq!(composer(&mail), Err(Error::NotPrintable), "{mechante:?}");
        }
    }
    // Le sujet accepte l'espace, et rien d'autre de plus.
    for mechant in [
        &b"Report Domain: x\r\nBcc: victime@y.test"[..],
        b"Report\nDomain",
        b"Report\tDomain",
        b"",
    ] {
        assert_eq!(
            composer(&ReportMail {
                subject: mechant,
                ..courrier()
            }),
            Err(Error::NotPrintable),
            "{mechant:?}"
        );
    }
    assert!(
        composer(&ReportMail {
            subject: b"Report Domain: eux.test",
            ..courrier()
        })
        .is_ok(),
        "un sujet ordinaire porte des espaces"
    );
}

#[test]
fn un_texte_mal_termine_est_refuse() {
    for mechant in [
        &b"une ligne\nsans CR"[..],
        b"un CR\rseul",
        b"\x00",
        b"fin\r",
    ] {
        assert_eq!(
            composer(&ReportMail {
                text: mechant,
                ..courrier()
            }),
            Err(Error::NotPrintable),
            "{mechant:?}"
        );
    }
    // La tabulation, elle, passe : elle a sa place dans un texte, et la
    // RFC 5322 §2.2 la compte parmi les blancs.
    assert!(
        composer(&ReportMail {
            text: b"colonne\tcolonne\r\n",
            ..courrier()
        })
        .is_ok()
    );
    // Un texte SANS fin de ligne en reçoit une : sans elle, le délimiteur
    // suivant serait recollé à la dernière ligne du texte.
    let texte = composer(&ReportMail {
        text: b"sans fin",
        ..courrier()
    })
    .expect("composable");
    assert!(texte.contains("sans fin\r\n\r\n------ams"), "{texte}");
}

/// **Un `multipart` dont le délimiteur apparaît dans le contenu ne se découpe
/// plus là où son auteur croyait.**
#[test]
fn un_delimiteur_qui_figure_dans_une_partie_fait_refuser() {
    assert_eq!(
        composer(&ReportMail {
            text: b"voici ----ams-7a3f-0e1d au milieu\r\n",
            ..courrier()
        }),
        Err(Error::BoundaryInContent)
    );
    assert_eq!(
        composer(&ReportMail {
            attachment: b"xx----ams-7a3f-0e1dxx",
            ..courrier()
        }),
        Err(Error::BoundaryInContent)
    );
}

/// Le tampon peut céder n'importe où : dans un en-tête, au milieu de la date,
/// sur la fin de ligne qu'on ajoute à un texte qui n'en a pas, dans le base64,
/// sur la clôture. On essaie donc toutes les tailles, pour deux messages — l'un
/// dont le texte finit par un saut de ligne, l'autre non, parce que la
/// composition n'écrit pas la même chose dans les deux cas.
#[test]
fn un_tampon_trop_court_le_dit_ou_qu_il_cede() {
    for mail in [
        courrier(),
        ReportMail {
            text: b"sans fin",
            ..courrier()
        },
    ] {
        let entier = composer(&mail).expect("composable");
        for taille in 0..entier.len() {
            let mut sortie = std::vec![0_u8; taille];
            assert_eq!(
                write_report_mail(&mut sortie, &mail),
                Err(Error::BufferTooSmall),
                "taille {taille}"
            );
        }
        // La majoration, elle, suffit toujours.
        assert!(report_mail_max(&mail) >= entier.len());
    }
}

#[test]
fn ce_qui_se_compose_se_montre() {
    assert!(!std::format!("{:?}", courrier()).is_empty());
    let copie = courrier();
    assert_eq!(copie.date, courrier().date);
}
