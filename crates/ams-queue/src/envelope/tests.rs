//! Ce que l'enveloppe accepte de porter, et ce qu'elle refuse.

use super::{Envelope, RECIPIENTS_MAX, envelope_max, parse_envelope, write_envelope};
use crate::Error;

/// Écrit une enveloppe et rend le texte, possédé.
fn ecrire(enveloppe: &Envelope<'_, '_>) -> std::string::String {
    let mut place = std::vec![0_u8; envelope_max(enveloppe)];
    std::string::String::from(write_envelope(enveloppe, &mut place).expect("écrivable"))
}

#[test]
fn une_enveloppe_ecrite_se_relit_a_l_identique() {
    let destinataires = ["marie@ailleurs.test", "jean@autre.test"];
    let enveloppe = Envelope {
        return_path: "jean@example.com",
        recipients: &destinataires,
        envelope_id: "",
        reports: &[],
    };
    let texte = ecrire(&enveloppe);
    assert_eq!(
        texte,
        "jean@example.com\nmarie@ailleurs.test\njean@autre.test\n"
    );

    let mut place = [""; 8];
    let mut rapports = [super::Report::default(); RECIPIENTS_MAX];
    let relue = parse_envelope(&texte, &mut place, &mut rapports).expect("relisible");
    assert_eq!(relue.return_path, "jean@example.com");
    assert_eq!(relue.recipients, &destinataires);
}

#[test]
fn un_saut_de_ligne_dans_une_adresse_n_ajoute_pas_un_destinataire() {
    // **C'EST L'INJECTION QUE CETTE CRATE DOIT FERMER.** Une adresse qui porte
    // un `LF` écrirait une ligne de plus dans un fichier que nous composons
    // nous-mêmes, et la reprise suivante la lirait comme un destinataire.
    let destinataires = ["marie@ailleurs.test\nvictime@banque.test"];
    let mut place = [0_u8; 512];
    assert_eq!(
        write_envelope(
            &Envelope {
                return_path: "jean@example.com",
                recipients: &destinataires,
                envelope_id: "",
                reports: &[],
            },
            &mut place
        ),
        Err(Error::BadAddress)
    );
    // Et par le chemin de retour non plus.
    assert_eq!(
        write_envelope(
            &Envelope {
                return_path: "jean@example.com\nautre@x.test",
                recipients: &["marie@ailleurs.test"],
                envelope_id: "",
                reports: &[],
            },
            &mut place
        ),
        Err(Error::BadAddress)
    );
}

#[test]
fn une_adresse_vide_ou_avec_un_espace_est_refusee() {
    let mut place = [0_u8; 512];
    for mauvaise in ["", " ", "a b@x.test", "a\tb@x.test", "café@x.test"] {
        assert_eq!(
            write_envelope(
                &Envelope {
                    return_path: mauvaise,
                    recipients: &["marie@ailleurs.test"],
                    envelope_id: "",
                    reports: &[],
                },
                &mut place
            ),
            Err(Error::BadAddress),
            "« {mauvaise} » aurait dû être refusée"
        );
    }
}

#[test]
fn une_adresse_trop_longue_est_refusee() {
    // §4.5.3.1.3 de RFC 5321 borne un chemin à 256 octets.
    let longue = "a".repeat(257);
    let mut place = [0_u8; 1024];
    assert_eq!(
        write_envelope(
            &Envelope {
                return_path: &longue,
                recipients: &["marie@ailleurs.test"],
                envelope_id: "",
                reports: &[],
            },
            &mut place
        ),
        Err(Error::BadAddress)
    );
    let juste = "a".repeat(256);
    assert!(
        write_envelope(
            &Envelope {
                return_path: &juste,
                recipients: &["marie@ailleurs.test"],
                envelope_id: "",
                reports: &[],
            },
            &mut place
        )
        .is_ok()
    );
}

#[test]
fn une_enveloppe_sans_destinataire_est_refusee() {
    let mut place = [0_u8; 512];
    assert_eq!(
        write_envelope(
            &Envelope {
                return_path: "jean@example.com",
                recipients: &[],
                envelope_id: "",
                reports: &[],
            },
            &mut place
        ),
        Err(Error::BadRecipients)
    );
    // Et à la relecture aussi : un fichier qui n'a qu'un chemin de retour ne
    // désigne personne, et le remettre ne veut rien dire.
    let mut cases = [""; 4];
    let mut rapports = [super::Report::default(); RECIPIENTS_MAX];
    assert_eq!(
        parse_envelope("jean@example.com\n", &mut cases, &mut rapports),
        Err(Error::BadRecipients)
    );
}

#[test]
fn une_enveloppe_vide_est_refusee() {
    let mut cases = [""; 4];
    let mut rapports = [super::Report::default(); RECIPIENTS_MAX];
    assert_eq!(
        parse_envelope("", &mut cases, &mut rapports),
        Err(Error::BadAddress)
    );
    let mut rapports = [super::Report::default(); RECIPIENTS_MAX];
    assert_eq!(
        parse_envelope("\n\n", &mut cases, &mut rapports),
        Err(Error::BadAddress)
    );
}

#[test]
fn plus_de_destinataires_que_la_borne_est_refuse() {
    let beaucoup: std::vec::Vec<&str> = std::vec!["a@x.test"; RECIPIENTS_MAX + 1];
    let mut place = std::vec![0_u8; 65_536];
    assert_eq!(
        write_envelope(
            &Envelope {
                return_path: "jean@example.com",
                recipients: &beaucoup,
                envelope_id: "",
                reports: &[],
            },
            &mut place
        ),
        Err(Error::BadRecipients)
    );
    // La borne elle-même passe.
    let juste: std::vec::Vec<&str> = std::vec!["a@x.test"; RECIPIENTS_MAX];
    assert!(
        write_envelope(
            &Envelope {
                return_path: "jean@example.com",
                recipients: &juste,
                envelope_id: "",
                reports: &[],
            },
            &mut place
        )
        .is_ok()
    );
}

#[test]
fn un_fichier_plus_garni_que_la_place_est_refuse_pas_tronque() {
    // **REMETTRE À UNE PARTIE DES DESTINATAIRES EN OUBLIANT LES AUTRES EST
    // EXACTEMENT CE QU'UNE FILE NE DOIT PAS FAIRE.**
    let texte = "jean@example.com\na@x.test\nb@x.test\nc@x.test\n";
    let mut trop_petite = [""; 2];
    let mut rapports = [super::Report::default(); RECIPIENTS_MAX];
    assert_eq!(
        parse_envelope(texte, &mut trop_petite, &mut rapports),
        Err(Error::BadRecipients)
    );
    let mut juste = [""; 3];
    let mut rapports = [super::Report::default(); RECIPIENTS_MAX];
    assert_eq!(
        parse_envelope(texte, &mut juste, &mut rapports)
            .expect("relisible")
            .recipients
            .len(),
        3
    );
}

#[test]
fn une_adresse_illisible_fait_refuser_le_fichier_entier() {
    let mut cases = [""; 8];
    for mauvais in [
        "jean@example.com\na b@x.test\n",
        " \na@x.test\n",
        "jean@example.com\n\u{e9}@x.test\n",
    ] {
        let mut rapports = [super::Report::default(); RECIPIENTS_MAX];
        assert!(
            parse_envelope(mauvais, &mut cases, &mut rapports).is_err(),
            "« {mauvais} » aurait dû être refusé"
        );
    }
}

#[test]
fn un_tampon_trop_court_est_une_erreur() {
    let enveloppe = Envelope {
        return_path: "jean@example.com",
        recipients: &["marie@ailleurs.test"],
        envelope_id: "",
        reports: &[],
    };
    let taille = envelope_max(&enveloppe);
    for court in 0..taille {
        let mut place = std::vec![0_u8; court];
        assert_eq!(
            write_envelope(&enveloppe, &mut place),
            Err(Error::BufferTooSmall)
        );
    }
    // Et la taille annoncée suffit, exactement.
    let mut place = std::vec![0_u8; taille];
    assert!(write_envelope(&enveloppe, &mut place).is_ok());
}

#[test]
fn les_lignes_vides_se_sautent() {
    // Un fichier recopié à la main peut en porter ; les refuser ferait perdre
    // du courrier pour une raison qui n'en est pas une.
    let mut cases = [""; 4];
    let mut rapports = [super::Report::default(); RECIPIENTS_MAX];
    let relue = parse_envelope(
        "jean@example.com\n\na@x.test\n\n",
        &mut cases,
        &mut rapports,
    )
    .expect("relisible");
    assert_eq!(relue.recipients, &["a@x.test"]);
}

#[test]
fn une_enveloppe_se_copie_et_se_debogue() {
    let destinataires = ["a@x.test"];
    let enveloppe = Envelope {
        return_path: "jean@example.com",
        recipients: &destinataires,
        envelope_id: "",
        reports: &[],
    };
    let copie = enveloppe;
    assert_eq!(copie, enveloppe);
    assert!(!std::format!("{enveloppe:?}").is_empty());
    assert_ne!(
        enveloppe,
        Envelope {
            return_path: "autre@example.com",
            recipients: &destinataires,
            envelope_id: "",
            reports: &[],
        }
    );
    assert!(!std::format!("{:?}", Error::BadAddress).is_empty());
    assert_ne!(Error::BadAddress, Error::BadRecipients);
    let copie_d_erreur = Error::BufferTooSmall;
    assert_eq!(copie_d_erreur, Error::BufferTooSmall);
}

// ── CE QUE RFC 3461 AJOUTE ──────────────────────────────────────────────────

/// **UNE ENVELOPPE ÉCRITE AVANT CETTE TRANCHE SE RELIT SANS RIEN PERDRE.**
///
/// Une adresse est de l'ASCII VISIBLE : elle ne porte jamais de tabulation. Ce
/// qui suit la première tabulation est donc, par construction, ce qu'on a
/// ajouté — et son absence vaut le défaut de §4.1.
#[test]
fn une_enveloppe_ancienne_se_relit_avec_les_defauts() {
    let mut cases = [""; 4];
    let mut rapports = [super::Report::default(); RECIPIENTS_MAX];
    let relue = parse_envelope(
        "jean@example.com\nmarie@ailleurs.test\npaul@ailleurs.test\n",
        &mut cases,
        &mut rapports,
    )
    .expect("relisible");
    assert_eq!(relue.return_path, "jean@example.com");
    assert_eq!(relue.envelope_id, "");
    for rapport in relue.reports {
        assert!(!rapport.never, "le silence ne se suppose pas");
        assert!(!rapport.on_success);
        assert_eq!(rapport.original, "");
    }
}

/// **CE QU'UN DESTINATAIRE A DEMANDÉ LUI EST PROPRE**, et se relit à l'identique.
#[test]
fn ce_que_chaque_destinataire_demande_traverse_le_fichier() {
    let rapports_ecrits = [
        super::Report {
            never: true,
            original: "",
            ..super::Report::default()
        },
        super::Report {
            on_success: true,
            // **LES QUATRE LETTRES SE RELISENT ENSEMBLE**, et non chacune de
            // son côté : c'est la relecture d'une combinaison qui attrape une
            // lettre écrite mais jamais lue.
            on_delay: true,
            delay_sent: true,
            original: "paul+liste@ailleurs.test",
            ..super::Report::default()
        },
        super::Report::default(),
    ];
    let enveloppe = Envelope {
        return_path: "jean@example.com",
        recipients: &["marie@ailleurs.test", "paul@ailleurs.test", "luc@x.test"],
        envelope_id: "envoi-42",
        reports: &rapports_ecrits,
    };
    let mut place = std::vec![0_u8; envelope_max(&enveloppe)];
    let texte = write_envelope(&enveloppe, &mut place).expect("écrivable");

    let mut cases = [""; 8];
    let mut relus = [super::Report::default(); RECIPIENTS_MAX];
    let relue = parse_envelope(texte, &mut cases, &mut relus).expect("relisible");
    assert_eq!(relue.return_path, "jean@example.com");
    assert_eq!(relue.envelope_id, "envoi-42");
    assert_eq!(relue.recipients.len(), 3);
    assert_eq!(relue.reports, &rapports_ecrits[..]);
}

/// **UN FICHIER QU'ON N'A PAS ÉCRIT SOI-MÊME EST REFUSÉ**, et non deviné.
#[test]
fn une_enveloppe_dsn_mal_formee_est_refusee() {
    let mut cases = [""; 4];
    for mauvais in [
        // Une lettre inconnue.
        "jean@example.com\nmarie@x.test\tZ\n",
        // Une lettre répétée : deux lectures d'un même fichier doivent
        // s'accorder.
        "jean@example.com\nmarie@x.test\tNN\n",
        // Une adresse d'origine qui n'en est pas une.
        "jean@example.com\nmarie@x.test\tN a b\n",
        // Un identifiant d'enveloppe irrecevable.
        "jean@example.com\ta b\nmarie@x.test\n",
    ] {
        let mut rapports = [super::Report::default(); RECIPIENTS_MAX];
        assert!(
            parse_envelope(mauvais, &mut cases, &mut rapports).is_err(),
            "« {mauvais} » aurait dû être refusé"
        );
    }
}

/// **CE QU'ON REFUSE D'ÉCRIRE, ON LE DIT** plutôt que de l'écrire de travers.
#[test]
fn une_valeur_dsn_irrecevable_ne_s_ecrit_pas() {
    let mauvais = [super::Report {
        // Un espace couperait la ligne en deux à la relecture.
        original: "a b",
        ..super::Report::default()
    }];
    let enveloppe = Envelope {
        return_path: "jean@example.com",
        recipients: &["marie@x.test"],
        envelope_id: "",
        reports: &mauvais,
    };
    let mut place = std::vec![0_u8; 256];
    assert_eq!(
        write_envelope(&enveloppe, &mut place),
        Err(Error::BadAddress)
    );
    // Et un identifiant d'enveloppe irrecevable non plus.
    let enveloppe = Envelope {
        return_path: "jean@example.com",
        recipients: &["marie@x.test"],
        envelope_id: "a b",
        reports: &[],
    };
    assert_eq!(
        write_envelope(&enveloppe, &mut place),
        Err(Error::BadAddress)
    );
}

/// La borne annoncée est EXACTE, y compris avec ce que RFC 3461 ajoute.
#[test]
fn la_borne_annoncee_suffit_exactement_avec_dsn() {
    let rapports = [super::Report {
        never: true,
        on_success: true,
        on_delay: true,
        delay_sent: true,
        original: "paul+liste@ailleurs.test",
    }];
    let enveloppe = Envelope {
        return_path: "jean@example.com",
        recipients: &["paul@ailleurs.test"],
        envelope_id: "envoi-42",
        reports: &rapports,
    };
    let taille = envelope_max(&enveloppe);
    for court in 0..taille {
        let mut place = std::vec![0_u8; court];
        assert_eq!(
            write_envelope(&enveloppe, &mut place),
            Err(Error::BufferTooSmall),
            "une taille de {court} a suffi"
        );
    }
    let mut juste = std::vec![0_u8; taille];
    assert_eq!(
        write_envelope(&enveloppe, &mut juste)
            .expect("écrivable")
            .len(),
        taille
    );
}

/// **UN TABLEAU DE RAPPORTS TROP COURT EST UN REFUS**, et non un silence.
///
/// Rendre les destinataires sans leurs rapports ferait retomber chacun sur le
/// défaut de §4.1 — c'est-à-dire enverrait un rapport de non-remise à qui avait
/// demandé le silence, et personne ne le saurait.
#[test]
fn un_tableau_de_rapports_trop_court_est_refuse() {
    let mut cases = [""; 4];
    let mut un_seul = [super::Report::default(); 1];
    assert_eq!(
        parse_envelope(
            "jean@example.com\na@x.test\tN\nb@x.test\tS\n",
            &mut cases,
            &mut un_seul,
        ),
        Err(Error::BadRecipients)
    );
    // Avec la place qu'il faut, les deux arrivent avec ce qu'ils ont demandé.
    let mut deux = [super::Report::default(); 2];
    let relue = parse_envelope(
        "jean@example.com\na@x.test\tN\nb@x.test\tS\n",
        &mut cases,
        &mut deux,
    )
    .expect("relisible");
    assert_eq!(relue.recipients, &["a@x.test", "b@x.test"]);
    assert!(relue.reports[0].never && relue.reports[1].on_success);
}
