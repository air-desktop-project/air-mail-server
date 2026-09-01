//! Ce qu'un rapport dit, et ce qu'on refuse d'y écrire.

use super::{Failure, Policy, PolicyType, Report, ResultType, Summary, begin};
use crate::Error;

const ENTETE: Report<'static> = Report {
    organization_name: "Nous",
    contact_info: "postmaster@mail.nous.test",
    report_id: "abc-123",
    start: 1_700_000_000,
    end: 1_700_086_400,
};

/// Écrit un rapport complet, et rend son JSON.
fn composer(place: &mut [u8]) -> std::string::String {
    let mut ecriture = begin(place, &ENTETE).expect("ouvrable");
    let lignes = ["version: STSv1", "mode: enforce"];
    let serveurs = ["mx1.example.com", "mx2.example.com"];
    ecriture
        .policy(
            &Policy {
                policy_type: PolicyType::Sts,
                policy_domain: "example.com",
                policy_strings: &lignes,
                mx_hosts: &serveurs,
            },
            &Summary {
                successful: 42,
                failed: 3,
            },
        )
        .expect("politique");
    ecriture
        .failure(&Failure {
            result_type: ResultType::CertificateExpired,
            sending_mta_ip: "192.0.2.1",
            receiving_mx_hostname: "mx1.example.com",
            failed_session_count: 3,
        })
        .expect("échec");
    let ecrit = ecriture.finish().expect("clôturable");
    std::string::String::from_utf8(ecrit.to_vec()).expect("de l'ASCII")
}

#[test]
fn un_rapport_porte_ce_que_la_rfc_demande() {
    let mut place = [0_u8; 4096];
    let json = composer(&mut place);
    assert!(
        json.starts_with("{\"organization-name\":\"Nous\","),
        "{json}"
    );
    assert!(json.contains("\"contact-info\":\"postmaster@mail.nous.test\""));
    assert!(json.contains("\"report-id\":\"abc-123\""));
    // §4.1 : des dates de RFC 3339, et non un nombre de secondes.
    assert!(
        json.contains("\"start-datetime\":\"2023-11-14T22:13:20Z\""),
        "{json}"
    );
    assert!(json.contains("\"end-datetime\":\"2023-11-15T22:13:20Z\""));
    // §4.4 : la politique.
    assert!(json.contains("\"policy-type\":\"sts\""));
    assert!(json.contains("\"policy-domain\":\"example.com\""));
    assert!(json.contains("\"policy-string\":[\"version: STSv1\",\"mode: enforce\"]"));
    assert!(json.contains("\"mx-host\":[\"mx1.example.com\",\"mx2.example.com\"]"));
    // §4.2 : le décompte.
    assert!(json.contains("\"total-successful-session-count\":42"));
    assert!(json.contains("\"total-failure-session-count\":3"));
    // §4.3 : le détail.
    assert!(json.contains("\"result-type\":\"certificate-expired\""));
    assert!(json.contains("\"sending-mta-ip\":\"192.0.2.1\""));
    assert!(json.contains("\"receiving-mx-hostname\":\"mx1.example.com\""));
    assert!(json.contains("\"failed-session-count\":3"));
    assert!(json.ends_with("]}]}"), "{json}");
}

/// **LES MOTS SONT CEUX DE LA RFC, PAS LES NÔTRES.**
#[test]
fn chaque_type_porte_le_mot_de_la_rfc() {
    assert_eq!(PolicyType::Tlsa.name(), "tlsa");
    assert_eq!(PolicyType::Sts.name(), "sts");
    assert_eq!(PolicyType::NoPolicyFound.name(), "no-policy-found");
    for (resultat, mot) in [
        (ResultType::StarttlsNotSupported, "starttls-not-supported"),
        (ResultType::ValidationFailure, "validation-failure"),
        (ResultType::ValidationFailureDane, "dane-required"),
        (ResultType::StsPolicyInvalid, "sts-policy-invalid"),
        (ResultType::StsPolicyFetchError, "sts-policy-fetch-error"),
        (
            ResultType::CertificateHostMismatch,
            "certificate-host-mismatch",
        ),
        (ResultType::CertificateExpired, "certificate-expired"),
        (ResultType::CertificateNotTrusted, "certificate-not-trusted"),
    ] {
        assert_eq!(resultat.name(), mot);
    }
}

/// Plusieurs politiques se suivent, séparées par une virgule et pas davantage.
#[test]
fn plusieurs_politiques_se_suivent() {
    let mut place = [0_u8; 4096];
    let mut ecriture = begin(&mut place, &ENTETE).expect("ouvrable");
    for domaine in ["a.test", "b.test"] {
        ecriture
            .policy(
                &Policy {
                    policy_type: PolicyType::NoPolicyFound,
                    policy_domain: domaine,
                    policy_strings: &[],
                    mx_hosts: &[],
                },
                &Summary {
                    successful: 1,
                    failed: 0,
                },
            )
            .expect("politique");
    }
    let ecrit = ecriture.finish().expect("clôturable");
    let json = core::str::from_utf8(ecrit).expect("de l'ASCII");
    assert!(json.contains("},{\"policy\":"), "{json}");
    // `no-policy-found` n'a ni lignes ni serveurs, et ne les écrit donc pas.
    assert!(!json.contains("policy-string"), "{json}");
    assert!(!json.contains("mx-host"), "{json}");
}

/// **SANS POLITIQUE OUVERTE, IL N'Y A RIEN À DÉTAILLER.**
#[test]
fn un_echec_hors_politique_est_sans_effet() {
    let mut place = [0_u8; 1024];
    let mut ecriture = begin(&mut place, &ENTETE).expect("ouvrable");
    ecriture
        .failure(&Failure {
            result_type: ResultType::ValidationFailure,
            sending_mta_ip: "192.0.2.1",
            receiving_mx_hostname: "mx.x.test",
            failed_session_count: 1,
        })
        .expect("sans effet");
    let ecrit = ecriture.finish().expect("clôturable");
    let json = core::str::from_utf8(ecrit).expect("de l'ASCII");
    assert!(!json.contains("result-type"), "{json}");
    assert!(json.ends_with("\"policies\":[]}"), "{json}");
}

/// **ON REFUSE PLUTÔT QUE D'ÉCHAPPER.**
///
/// Un guillemet ou une barre oblique inverse écrirait une structure à notre
/// place, dans un fichier qu'on compose et qu'on remet nous-mêmes. Les valeurs
/// viennent en partie de tiers : le nom d'un `MX`, une politique publiée.
#[test]
fn une_valeur_qui_ecrirait_du_json_est_refusee() {
    let mut place = [0_u8; 4096];
    for hostile in ["\"", "a\"b", "a\\b", "a\r\nb", "a\tb", "\u{e9}", "a\u{0}b"] {
        let entete = Report {
            organization_name: hostile,
            ..ENTETE
        };
        assert_eq!(
            begin(&mut place, &entete).err(),
            Some(Error::NotPrintable),
            "« {hostile} »"
        );
    }
    // Et dans une politique aussi — c'est là que viennent les valeurs de tiers.
    let mut ecriture = begin(&mut place, &ENTETE).expect("ouvrable");
    let lignes = ["mode: \"enforce\""];
    assert_eq!(
        ecriture.policy(
            &Policy {
                policy_type: PolicyType::Sts,
                policy_domain: "example.com",
                policy_strings: &lignes,
                mx_hosts: &[],
            },
            &Summary {
                successful: 0,
                failed: 0,
            },
        ),
        Err(Error::NotPrintable)
    );
}

/// **UN NOM DE SERVEUR VIENT DU DOMAINE QU'ON RAPPORTE.**
#[test]
fn un_nom_de_serveur_hostile_est_refuse() {
    let mut place = [0_u8; 4096];
    let mut ecriture = begin(&mut place, &ENTETE).expect("ouvrable");
    ecriture
        .policy(
            &Policy {
                policy_type: PolicyType::Sts,
                policy_domain: "example.com",
                policy_strings: &[],
                mx_hosts: &[],
            },
            &Summary {
                successful: 0,
                failed: 1,
            },
        )
        .expect("politique");
    assert_eq!(
        ecriture.failure(&Failure {
            result_type: ResultType::ValidationFailure,
            sending_mta_ip: "192.0.2.1",
            receiving_mx_hostname: "mx\",\"injecte\":\"",
            failed_session_count: 1,
        }),
        Err(Error::NotPrintable)
    );
}

#[test]
fn un_tampon_trop_court_est_une_erreur_pas_un_rapport_tronque() {
    // On éprouve CHAQUE point de rupture : s'arrêter au premier laisserait
    // toutes les écritures suivantes sans épreuve, et une seule qui tronquerait
    // au lieu de refuser suffirait à émettre un JSON coupé en deux.
    //
    // **DEUX POLITIQUES, DEUX SERVEURS, DEUX ÉCHECS** : les séparateurs entre
    // eux sont des écritures que le premier de chaque espèce ne fait jamais.
    let mut refuses = 0_usize;
    let mut acceptes = 0_usize;
    for taille in 0..1_400 {
        let mut place = std::vec![0_u8; taille];
        let issue = (|| -> Result<usize, Error> {
            let mut ecriture = begin(&mut place, &ENTETE)?;
            let lignes = ["version: STSv1", "mode: enforce"];
            let serveurs = ["mx1.example.com", "mx2.example.com"];
            for domaine in ["example.com", "autre.test"] {
                ecriture.policy(
                    &Policy {
                        policy_type: PolicyType::Sts,
                        policy_domain: domaine,
                        policy_strings: &lignes,
                        mx_hosts: &serveurs,
                    },
                    &Summary {
                        successful: 1,
                        failed: 2,
                    },
                )?;
                for serveur in serveurs {
                    ecriture.failure(&Failure {
                        result_type: ResultType::CertificateExpired,
                        sending_mta_ip: "192.0.2.1",
                        receiving_mx_hostname: serveur,
                        failed_session_count: 1,
                    })?;
                }
            }
            Ok(ecriture.finish()?.len())
        })();
        match issue {
            Ok(_) => acceptes = acceptes.saturating_add(1),
            Err(erreur) => {
                assert_eq!(erreur, Error::BufferTooSmall, "à {taille} octets");
                refuses = refuses.saturating_add(1);
            }
        }
    }
    assert!(refuses > 0, "aucune taille n'a été refusée");
    // **ET LE BALAYAGE VA JUSQU'AU BOUT** : sans cela, la clôture du rapport ne
    // serait jamais atteinte, et son refus jamais éprouvé.
    assert!(acceptes > 0, "aucune taille n'a suffi");
}

/// L'époque et les bissextiles : la date se calcule, elle ne s'approxime pas.
#[test]
fn les_dates_se_calculent_juste() {
    for (secondes, attendu) in [
        (0_u64, "1970-01-01T00:00:00Z"),
        (951_782_400, "2000-02-29T00:00:00Z"),
        (1_709_164_800, "2024-02-29T00:00:00Z"),
        (1_700_086_399, "2023-11-15T22:13:19Z"),
    ] {
        let mut place = [0_u8; 1024];
        let entete = Report {
            start: secondes,
            end: secondes,
            ..ENTETE
        };
        let ecriture = begin(&mut place, &entete).expect("ouvrable");
        let ecrit = ecriture.finish().expect("clôturable");
        let json = core::str::from_utf8(ecrit).expect("de l'ASCII");
        assert!(
            json.contains(&std::format!("\"start-datetime\":\"{attendu}\"")),
            "{secondes} : {json}"
        );
    }
}

#[test]
fn les_types_se_copient_et_se_deboguent() {
    let copie = ENTETE;
    assert!(!std::format!("{copie:?}").is_empty());
    assert!(!std::format!("{:?}", PolicyType::Tlsa).is_empty());
    assert_ne!(PolicyType::Tlsa, PolicyType::Sts);
    assert!(!std::format!("{:?}", ResultType::CertificateExpired).is_empty());
    assert_ne!(
        ResultType::CertificateExpired,
        ResultType::ValidationFailure
    );
    let resume = Summary {
        successful: 1,
        failed: 0,
    };
    assert_eq!(resume, resume);
    assert_ne!(
        resume,
        Summary {
            successful: 0,
            failed: 1
        }
    );
    assert!(!std::format!("{resume:?}").is_empty());
    let politique = Policy {
        policy_type: PolicyType::Sts,
        policy_domain: "x.test",
        policy_strings: &[],
        mx_hosts: &[],
    };
    assert!(!std::format!("{politique:?}").is_empty());
    let echec = Failure {
        result_type: ResultType::ValidationFailure,
        sending_mta_ip: "192.0.2.1",
        receiving_mx_hostname: "mx.x.test",
        failed_session_count: 1,
    };
    assert!(!std::format!("{echec:?}").is_empty());
}
