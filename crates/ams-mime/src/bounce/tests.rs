//! Ce qu'un rapport de non-remise dit, et ce qu'il refuse d'écrire.

use super::{Bounce, Failure, bounce_max, write_bounce};
use crate::Error;

const ECHEC: Failure<'static> = Failure {
    recipient: b"marie@ailleurs.test",
    status: b"5.1.1",
    diagnostic: b"550 5.1.1 <marie@ailleurs.test>: User unknown",
};

/// Un rapport bien formé, dont chaque essai modifie une pièce.
fn rapport<'a, 'f>(echecs: &'f [Failure<'a>]) -> Bounce<'a, 'f> {
    Bounce {
        from: b"postmaster@mail.example.com",
        to: b"jean@example.com",
        reporting_mta: b"mail.example.com",
        subject: b"Undelivered Mail Returned to Sender",
        message_id: b"bounce-1@mail.example.com",
        date: 1_700_000_000,
        arrival: 1_699_000_000,
        boundary: b"----ams-abcdef",
        text: b"Votre message n'a pas pu etre remis.\r\n",
        failures: echecs,
        original_headers: b"From: jean@example.com\r\nSubject: bonjour\r\n",
    }
}

/// Compose, et rend le rapport sous forme de chaîne.
fn composer(bounce: &Bounce<'_, '_>) -> std::string::String {
    let mut place = std::vec![0_u8; bounce_max(bounce)];
    let ecrit = write_bounce(&mut place, bounce).expect("composable");
    std::string::String::from_utf8(ecrit.to_vec()).expect("de l'ASCII")
}

#[test]
fn le_rapport_porte_les_trois_parties_de_rfc_3464() {
    let texte = composer(&rapport(&[ECHEC]));
    // L'enveloppe.
    assert!(texte.contains("Return-Path: <>\r\n"), "{texte}");
    assert!(texte.contains("From: <postmaster@mail.example.com>\r\n"));
    assert!(texte.contains("To: <jean@example.com>\r\n"));
    assert!(texte.contains("Auto-Submitted: auto-replied\r\n"));
    assert!(texte.contains("Content-Type: multipart/report; report-type=delivery-status;"));
    // Les trois parties, dans l'ordre.
    let humain = texte.find("text/plain").expect("la partie humaine");
    let machine = texte
        .find("message/delivery-status")
        .expect("la partie machine");
    let entetes = texte
        .find("text/rfc822-headers")
        .expect("les en-têtes d'origine");
    assert!(humain < machine && machine < entetes, "{texte}");
    // Ce que lit la machine.
    assert!(texte.contains("Reporting-MTA: dns; mail.example.com\r\n"));
    assert!(texte.contains("Arrival-Date: "));
    assert!(texte.contains("Final-Recipient: rfc822; marie@ailleurs.test\r\n"));
    assert!(texte.contains("Action: failed\r\nStatus: 5.1.1\r\n"));
    assert!(
        texte.contains("Diagnostic-Code: smtp; 550 5.1.1 <marie@ailleurs.test>: User unknown\r\n")
    );
    // Les en-têtes du message perdu, et pas son corps.
    assert!(texte.contains("From: jean@example.com\r\nSubject: bonjour\r\n"));
    // Et la clôture.
    assert!(texte.ends_with("\r\n------ams-abcdef--\r\n"), "{texte}");
}

#[test]
fn le_chemin_de_retour_est_nul() {
    // §6.1 de RFC 5321 : un rapport dont le rebond rebondirait ferait tourner
    // deux serveurs l'un contre l'autre.
    let texte = composer(&rapport(&[ECHEC]));
    assert!(texte.starts_with("Return-Path: <>\r\n"), "{texte}");
}

#[test]
fn un_diagnostic_absent_omet_le_champ_plutot_que_de_l_inventer() {
    // Une panne de réseau ou un `MX` nul ne donnent aucune réponse du pair. Un
    // diagnostic qu'on écrirait soi-même se lirait comme le sien.
    let muet = Failure {
        diagnostic: b"",
        ..ECHEC
    };
    let texte = composer(&rapport(&[muet]));
    assert!(!texte.contains("Diagnostic-Code"), "{texte}");
    assert!(texte.contains("Status: 5.1.1\r\n"));
}

#[test]
fn chaque_destinataire_a_son_groupe() {
    let autre = Failure {
        recipient: b"paul@encore.test",
        status: b"4.4.1",
        diagnostic: b"",
    };
    let texte = composer(&rapport(&[ECHEC, autre]));
    assert_eq!(texte.matches("Final-Recipient: rfc822; ").count(), 2);
    assert_eq!(texte.matches("Action: failed").count(), 2);
    assert!(texte.contains("Status: 4.4.1\r\n"));
}

#[test]
fn un_rapport_sans_echec_est_refuse() {
    let mut place = [0_u8; 4096];
    assert_eq!(
        write_bounce(&mut place, &rapport(&[])),
        Err(Error::EmptyReport)
    );
}

#[test]
fn un_crlf_dans_le_diagnostic_du_pair_n_ecrit_pas_d_en_tete() {
    // **C'EST L'ENTRÉE HOSTILE DE CE MODULE** : le texte de refus vient d'un
    // serveur inconnu, et il finit dans la boîte d'un de nos comptes.
    let mut place = [0_u8; 4096];
    for hostile in [
        &b"550 nope\r\nStatus: 2.0.0"[..],
        b"550 nope\nAction: delivered",
        b"550 nope\r",
        b"550 \x00 nul",
        "550 caf\u{e9}".as_bytes(),
    ] {
        let echec = Failure {
            diagnostic: hostile,
            ..ECHEC
        };
        // Le message se construit AVANT l'assertion : un argument de `assert!`
        // n'est évalué qu'à l'échec, et C2 compterait sa région découverte.
        let quoi = std::format!(
            "« {} » aurait dû être refusé",
            std::string::String::from_utf8_lossy(hostile)
        );
        assert_eq!(
            write_bounce(&mut place, &rapport(&[echec])),
            Err(Error::NotPrintable),
            "{quoi}"
        );
    }
}

#[test]
fn un_statut_libre_est_refuse() {
    // Il est LU PAR UNE MACHINE : chiffres et points, et rien d'autre.
    let mut place = [0_u8; 4096];
    for mauvais in [&b""[..], b"5.1.1 ok", b"cinq", b"5.1.1\r\nX: y"] {
        let echec = Failure {
            status: mauvais,
            ..ECHEC
        };
        assert_eq!(
            write_bounce(&mut place, &rapport(&[echec])),
            Err(Error::NotPrintable)
        );
    }
}

#[test]
fn une_adresse_de_destinataire_illisible_est_refusee() {
    let mut place = [0_u8; 4096];
    for mauvaise in [&b""[..], b"a b@x.test", b"a\r\nb@x.test"] {
        let echec = Failure {
            recipient: mauvaise,
            ..ECHEC
        };
        assert_eq!(
            write_bounce(&mut place, &rapport(&[echec])),
            Err(Error::NotPrintable)
        );
    }
}

#[test]
fn une_valeur_d_enveloppe_illisible_est_refusee() {
    let mut place = [0_u8; 4096];
    let modeles: [(&str, Bounce<'_, '_>); 6] = [
        (
            "from",
            Bounce {
                from: b"",
                ..rapport(&[ECHEC])
            },
        ),
        (
            "to",
            Bounce {
                to: b"a b@x.test",
                ..rapport(&[ECHEC])
            },
        ),
        (
            "mta",
            Bounce {
                reporting_mta: b"",
                ..rapport(&[ECHEC])
            },
        ),
        (
            "message_id",
            Bounce {
                message_id: b"a\r\nb",
                ..rapport(&[ECHEC])
            },
        ),
        (
            "boundary",
            Bounce {
                boundary: b"",
                ..rapport(&[ECHEC])
            },
        ),
        (
            "subject",
            Bounce {
                subject: b"",
                ..rapport(&[ECHEC])
            },
        ),
    ];
    for (quoi, modele) in modeles {
        assert_eq!(
            write_bounce(&mut place, &modele),
            Err(Error::NotPrintable),
            "{quoi} aurait dû être refusé"
        );
    }
    // Un sujet a le droit d'avoir des espaces ; un `CRLF`, non.
    assert_eq!(
        write_bounce(
            &mut place,
            &Bounce {
                subject: b"deux\r\nlignes",
                ..rapport(&[ECHEC])
            }
        ),
        Err(Error::NotPrintable)
    );
}

#[test]
fn un_texte_ou_des_entetes_mal_termines_sont_refuses() {
    let mut place = [0_u8; 4096];
    assert_eq!(
        write_bounce(
            &mut place,
            &Bounce {
                text: b"une ligne\nseule",
                ..rapport(&[ECHEC])
            }
        ),
        Err(Error::NotPrintable)
    );
    assert_eq!(
        write_bounce(
            &mut place,
            &Bounce {
                original_headers: b"From: x\rSubject: y",
                ..rapport(&[ECHEC])
            }
        ),
        Err(Error::NotPrintable)
    );
}

#[test]
fn le_delimiteur_ne_doit_figurer_dans_aucune_partie() {
    let mut place = [0_u8; 4096];
    assert_eq!(
        write_bounce(
            &mut place,
            &Bounce {
                text: b"voici ----ams-abcdef en plein texte\r\n",
                ..rapport(&[ECHEC])
            }
        ),
        Err(Error::BoundaryInContent)
    );
    assert_eq!(
        write_bounce(
            &mut place,
            &Bounce {
                original_headers: b"X-Ruse: ----ams-abcdef\r\n",
                ..rapport(&[ECHEC])
            }
        ),
        Err(Error::BoundaryInContent)
    );
}

#[test]
fn un_texte_sans_fin_de_ligne_en_gagne_une() {
    // Sans cela, le délimiteur suivant collerait à la dernière ligne du texte,
    // et la partie ne se fermerait pas là où on croit.
    let texte = composer(&Bounce {
        text: b"sans fin de ligne",
        original_headers: b"From: x",
        ..rapport(&[ECHEC])
    });
    assert!(
        texte.contains("sans fin de ligne\r\n\r\n------ams-"),
        "{texte}"
    );
    assert!(texte.contains("From: x\r\n\r\n------ams-"), "{texte}");
}

#[test]
fn des_entetes_d_origine_absents_restent_licites() {
    // Un message dont on n'a pas su relire les en-têtes vaut mieux qu'aucun
    // rapport : l'expéditeur doit savoir que son courrier n'est pas parti.
    let texte = composer(&Bounce {
        original_headers: b"",
        ..rapport(&[ECHEC])
    });
    assert!(
        texte.contains("text/rfc822-headers\r\n\r\n\r\n------ams-"),
        "{texte}"
    );
}

#[test]
fn un_tampon_trop_court_est_une_erreur_pas_un_rapport_tronque() {
    let bounce = rapport(&[ECHEC]);
    let taille = bounce_max(&bounce);
    // **CHAQUE POINT DE RUPTURE, ET PAS SEULEMENT LE PREMIER** : s'arrêter au
    // premier refus laisserait toutes les écritures suivantes sans épreuve, et
    // une seule d'entre elles qui tronquerait au lieu de refuser suffirait à
    // émettre un rapport coupé en deux.
    //
    // La seconde forme n'est pas un doublon : ses fins de ligne AJOUTÉES sont
    // deux écritures que la première ne fait jamais, et elles doivent refuser
    // comme les autres.
    let sans_fins = Bounce {
        text: b"sans fin de ligne",
        original_headers: b"From: x",
        ..rapport(&[ECHEC])
    };
    for modele in [&bounce, &sans_fins] {
        let combien = bounce_max(modele);
        let mut refuses = 0_usize;
        for court in 0..combien {
            let mut place = std::vec![0_u8; court];
            match write_bounce(&mut place, modele) {
                // `bounce_max` MAJORE : au-delà de la longueur réelle, la place
                // suffit avant d'atteindre la taille annoncée.
                Ok(_) => {}
                Err(erreur) => {
                    assert_eq!(erreur, Error::BufferTooSmall, "à {court} octets");
                    refuses = refuses.saturating_add(1);
                }
            }
        }
        assert!(refuses > 0, "aucune taille n'a été refusée");
    }
    let mut place = std::vec![0_u8; taille];
    assert!(write_bounce(&mut place, &bounce).is_ok());
}

#[test]
fn les_types_se_copient_et_se_deboguent() {
    let copie = ECHEC;
    assert_eq!(copie, ECHEC);
    assert_ne!(
        copie,
        Failure {
            status: b"4.4.1",
            ..ECHEC
        }
    );
    assert!(!std::format!("{ECHEC:?}").is_empty());
    let bounce = rapport(&[ECHEC]);
    let jumelle = bounce;
    assert!(!std::format!("{jumelle:?}").is_empty());
}
