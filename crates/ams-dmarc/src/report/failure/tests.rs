//! Ce qu'un rapport d'échec dit, et ce qu'il tait.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{
    AuthFailure, DeliveryResult, FeedbackReport, feedback_report_max, write_feedback_report,
};
use crate::Error;

/// Un rapport d'épreuve.
fn rapport() -> FeedbackReport<'static> {
    FeedbackReport {
        user_agent: b"air-mail-server/0.1.0",
        arrival_date: b"Sat, 29 Aug 2026 07:08:31 +0000",
        source_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        reported_domain: b"banque.test",
        original_mail_from: Some(b"expediteur@ailleurs.test"),
        dkim_domain: None,
        dkim_selector: None,
        spf_dns: Some(b"ailleurs.test"),
        auth_failure: AuthFailure::Dmarc,
        delivery_result: DeliveryResult::Rejected,
        aligned_dkim: false,
        aligned_spf: false,
    }
}

fn ecrire(report: &FeedbackReport<'_>) -> Result<std::string::String, Error> {
    let mut sortie = std::vec![0_u8; feedback_report_max(report)];
    let ecrit = write_feedback_report(&mut sortie, report)?;
    Ok(std::string::String::from_utf8_lossy(ecrit).into_owned())
}

#[test]
fn un_rapport_d_echec_porte_ce_que_la_rfc_demande() {
    let texte = ecrire(&rapport()).expect("composable");
    for ligne in [
        "Feedback-Type: auth-failure\r\n",
        "User-Agent: air-mail-server/0.1.0\r\n",
        "Version: 1\r\n",
        "Original-Mail-From: expediteur@ailleurs.test\r\n",
        "Arrival-Date: Sat, 29 Aug 2026 07:08:31 +0000\r\n",
        "Source-IP: 192.0.2.1\r\n",
        "Reported-Domain: banque.test\r\n",
        "Auth-Failure: dmarc\r\n",
        "Delivery-Result: reject\r\n",
        "SPF-DNS: ailleurs.test\r\n",
        "Identity-Alignment: none\r\n",
    ] {
        assert!(texte.contains(ligne), "{ligne:?} manque dans :\n{texte}");
    }
}

/// **Le destinataire du message n'est jamais nommé.** Le rapport part chez le
/// domaine qu'on rapporte — quand cela compte, chez celui qui usurpe — et lui
/// dire qui a reçu son message serait lui livrer ce qu'il cherchait.
#[test]
fn c_est_ici_que_le_destinataire_n_est_pas_livre() {
    let texte = ecrire(&rapport()).expect("composable");
    assert!(
        !texte.contains("Original-Rcpt-To"),
        "le rapport nomme son destinataire :\n{texte}"
    );
    // L'expéditeur d'enveloppe, lui, est de la main de celui qu'on rapporte.
    assert!(texte.contains("Original-Mail-From:"));
}

/// « Rien ne s'aligne » et « DKIM s'alignait mais pas SPF » ne se corrigent pas
/// de la même façon.
#[test]
fn l_alignement_dit_lequel_tenait() {
    for (dkim, spf, attendu) in [
        (false, false, "none"),
        (true, false, "dkim"),
        (false, true, "spf"),
        (true, true, "dkim, spf"),
    ] {
        let texte = ecrire(&FeedbackReport {
            aligned_dkim: dkim,
            aligned_spf: spf,
            ..rapport()
        })
        .expect("composable");
        assert!(
            texte.contains(&std::format!("Identity-Alignment: {attendu}\r\n")),
            "({dkim}, {spf}) :\n{texte}"
        );
    }
}

#[test]
fn les_champs_facultatifs_ne_s_ecrivent_que_s_ils_sont_la() {
    let texte = ecrire(&FeedbackReport {
        dkim_domain: Some(b"signataire.test"),
        dkim_selector: Some(b"sel"),
        spf_dns: None,
        ..rapport()
    })
    .expect("composable");
    assert!(texte.contains("DKIM-Domain: signataire.test\r\n"));
    assert!(texte.contains("DKIM-Selector: sel\r\n"));
    assert!(!texte.contains("SPF-DNS:"));

    // Sans expéditeur d'enveloppe, c'est l'expéditeur nul qu'on écrit.
    let texte = ecrire(&FeedbackReport {
        original_mail_from: None,
        ..rapport()
    })
    .expect("composable");
    assert!(texte.contains("Original-Mail-From: <>\r\n"), "{texte}");
}

#[test]
fn chaque_echec_et_chaque_issue_ont_leur_mot() {
    for (echec, mot) in [
        (AuthFailure::Dmarc, "dmarc"),
        (AuthFailure::Dkim, "dkim"),
        (AuthFailure::Spf, "spf"),
    ] {
        let texte = ecrire(&FeedbackReport {
            auth_failure: echec,
            ..rapport()
        })
        .expect("composable");
        assert!(texte.contains(&std::format!("Auth-Failure: {mot}\r\n")));
        assert_eq!(echec, echec);
        assert!(!std::format!("{echec:?}").is_empty());
    }
    for (issue, mot) in [
        (DeliveryResult::Delivered, "delivered"),
        (DeliveryResult::Rejected, "reject"),
        (DeliveryResult::Policy, "policy"),
        (DeliveryResult::Other, "other"),
    ] {
        let texte = ecrire(&FeedbackReport {
            delivery_result: issue,
            ..rapport()
        })
        .expect("composable");
        assert!(texte.contains(&std::format!("Delivery-Result: {mot}\r\n")));
        assert_eq!(issue, issue);
        assert!(!std::format!("{issue:?}").is_empty());
    }
}

#[test]
fn une_adresse_ipv6_s_ecrit_sous_sa_forme_abregee() {
    let texte = ecrire(&FeedbackReport {
        source_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ..rapport()
    })
    .expect("composable");
    assert!(texte.contains("Source-IP: 2001:db8::1\r\n"), "{texte}");
}

/// **Un `CRLF` y écrirait des champs à notre place**, dans un rapport que nous
/// composons et que nous remettons nous-mêmes.
#[test]
fn c_est_ici_que_l_injection_de_champ_s_arrete() {
    for mechante in [
        &b"banque.test\r\nAuth-Failure: none"[..],
        b"banque.test\nAuth-Failure: none",
        b"banque\x00test",
        b"",
    ] {
        for report in [
            FeedbackReport {
                reported_domain: mechante,
                ..rapport()
            },
            FeedbackReport {
                user_agent: mechante,
                ..rapport()
            },
            FeedbackReport {
                arrival_date: mechante,
                ..rapport()
            },
            FeedbackReport {
                original_mail_from: Some(mechante),
                ..rapport()
            },
            FeedbackReport {
                dkim_domain: Some(mechante),
                ..rapport()
            },
            FeedbackReport {
                dkim_selector: Some(mechante),
                ..rapport()
            },
            FeedbackReport {
                spf_dns: Some(mechante),
                ..rapport()
            },
        ] {
            assert_eq!(ecrire(&report), Err(Error::NotPrintable), "{mechante:?}");
        }
    }
}

/// Le tampon peut céder n'importe où — y compris au milieu d'une adresse, ou
/// sur le mot d'alignement, qui n'est pas le même selon ce qui tenait. On
/// essaie donc toutes les tailles, pour les quatre combinaisons.
#[test]
fn un_tampon_trop_court_le_dit_ou_qu_il_cede() {
    for (dkim, spf) in [(false, false), (true, false), (false, true), (true, true)] {
        let report = FeedbackReport {
            dkim_domain: Some(b"signataire.test"),
            dkim_selector: Some(b"sel"),
            source_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            aligned_dkim: dkim,
            aligned_spf: spf,
            ..rapport()
        };
        let entier = ecrire(&report).expect("composable");
        for taille in 0..entier.len() {
            let mut sortie = std::vec![0_u8; taille];
            assert_eq!(
                write_feedback_report(&mut sortie, &report),
                Err(Error::BufferTooSmall),
                "({dkim}, {spf}) taille {taille}"
            );
        }
        assert!(feedback_report_max(&report) >= entier.len());
        assert!(!std::format!("{report:?}").is_empty());
    }
}
