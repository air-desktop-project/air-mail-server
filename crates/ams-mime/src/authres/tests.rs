//! Ce que l'en-tête dit, et ce qu'on refuse d'y écrire.

use super::{
    AUTHRES_RESERVE, Authentication, DKIM_MAX, DkimResult, DkimSeen, DmarcResult, SpfIdentity,
    SpfResult, authres_max, write_authres, write_authres_padded,
};
use crate::Error;

const NOUS: &[u8] = b"mail.nous.test";

/// Compose, et rend l'en-tête sous forme de chaîne.
fn composer(authentication: &Authentication<'_, '_>) -> std::string::String {
    let mut place = std::vec![0_u8; authres_max(authentication)];
    let ecrit = write_authres(&mut place, authentication).expect("composable");
    std::string::String::from_utf8(ecrit.to_vec()).expect("de l'ASCII")
}

#[test]
fn les_trois_verdicts_s_ecrivent() {
    let signatures = [DkimSeen {
        result: DkimResult::Pass,
        domain: b"example.net",
        selector: b"sel",
    }];
    let entete = composer(&Authentication {
        serv_id: NOUS,
        spf: Some((SpfResult::Pass, SpfIdentity::MailFrom, b"example.net")),
        dkim: &signatures,
        dmarc: Some((DmarcResult::Fail, b"example.com")),
        auth: None,
    });
    assert_eq!(
        entete,
        "Authentication-Results: mail.nous.test;\r\n\
         \tspf=pass smtp.mailfrom=example.net;\r\n\
         \tdkim=pass header.d=example.net header.s=sel;\r\n\
         \tdmarc=fail header.from=example.com\r\n"
    );
}

/// **§2.2 : QUAND RIEN N'A ÉTÉ VÉRIFIÉ, LE MOT EST `none`.**
///
/// Un identifiant seul ne serait pas un en-tête valable.
#[test]
fn sans_rien_de_verifie_le_mot_est_none() {
    let entete = composer(&Authentication {
        serv_id: NOUS,
        spf: None,
        dkim: &[],
        dmarc: None,
        auth: None,
    });
    assert_eq!(entete, "Authentication-Results: mail.nous.test; none\r\n");
}

/// **CHAQUE MÉCANISME S'ÉCRIT SEUL, SI C'EST LE SEUL QU'ON A VÉRIFIÉ.**
///
/// Un serveur sans résolveur ne vérifie pas SPF ; un message non signé n'a pas
/// de `dkim=` ; un domaine sans politique n'a pas de `dmarc=`. Les trois
/// combinaisons partielles doivent s'écrire, et non pas rien.
#[test]
fn chaque_mecanisme_s_ecrit_seul() {
    let signatures = [DkimSeen {
        result: DkimResult::Pass,
        domain: b"example.net",
        selector: b"sel",
    }];
    let seule_dkim = composer(&Authentication {
        serv_id: NOUS,
        spf: None,
        dkim: &signatures,
        dmarc: None,
        auth: None,
    });
    assert_eq!(
        seule_dkim,
        "Authentication-Results: mail.nous.test;\r\n\
         \tdkim=pass header.d=example.net header.s=sel\r\n"
    );

    let seul_spf = composer(&Authentication {
        serv_id: NOUS,
        spf: Some((SpfResult::Neutral, SpfIdentity::MailFrom, b"example.net")),
        dkim: &[],
        dmarc: None,
        auth: None,
    });
    assert_eq!(
        seul_spf,
        "Authentication-Results: mail.nous.test;\r\n\
         \tspf=neutral smtp.mailfrom=example.net\r\n"
    );

    let seul_dmarc = composer(&Authentication {
        serv_id: NOUS,
        spf: None,
        dkim: &[],
        dmarc: Some((DmarcResult::None, b"example.com")),
        auth: None,
    });
    assert_eq!(
        seul_dmarc,
        "Authentication-Results: mail.nous.test;\r\n\
         \tdmarc=none header.from=example.com\r\n"
    );
}

/// **CHAQUE RÉSULTAT SUR SA LIGNE.**
///
/// §2.2 de RFC 5322 borne une ligne à 998 octets, et huit signatures avec leurs
/// domaines la dépasseraient.
#[test]
fn aucune_ligne_ne_depasse_la_borne_de_rfc_5322() {
    let domaine = "a".repeat(100);
    let signatures: std::vec::Vec<DkimSeen<'_>> = (0..DKIM_MAX)
        .map(|_| DkimSeen {
            result: DkimResult::Pass,
            domain: domaine.as_bytes(),
            selector: b"selecteur-assez-long-pour-compter",
        })
        .collect();
    let entete = composer(&Authentication {
        serv_id: NOUS,
        spf: Some((SpfResult::Pass, SpfIdentity::MailFrom, domaine.as_bytes())),
        dkim: &signatures,
        dmarc: Some((DmarcResult::Pass, domaine.as_bytes())),
        auth: None,
    });
    for ligne in entete.split("\r\n") {
        assert!(ligne.len() <= 998, "{} octets : {ligne}", ligne.len());
    }
    // Et chaque continuation commence par un blanc, comme §2.2.3 l'exige.
    for ligne in entete.split("\r\n").skip(1).filter(|l| !l.is_empty()) {
        assert!(ligne.starts_with('\t'), "« {ligne} » ne continue rien");
    }
}

/// **LA BORNE DE C3 EST CELLE DE LA CRATE.**
#[test]
fn plus_de_signatures_que_la_borne_est_refuse() {
    let signatures: std::vec::Vec<DkimSeen<'_>> = (0..=DKIM_MAX)
        .map(|_| DkimSeen {
            result: DkimResult::Pass,
            domain: b"x.test",
            selector: b"s",
        })
        .collect();
    let authentication = Authentication {
        serv_id: NOUS,
        spf: None,
        dkim: &signatures,
        dmarc: None,
        auth: None,
    };
    let mut place = std::vec![0_u8; authres_max(&authentication)];
    assert_eq!(
        write_authres(&mut place, &authentication),
        Err(Error::TooManyFields { limit: DKIM_MAX })
    );
}

/// **UN `CRLF` DANS UN DOMAINE ÉCRIRAIT UN EN-TÊTE À NOTRE PLACE**, dans un
/// en-tête que les filtres du destinataire croient sur parole.
#[test]
fn une_valeur_qui_ecrirait_un_entete_est_refusee() {
    let mut place = [0_u8; 1024];
    for hostile in [
        &b""[..],
        b"a b",
        b"a\r\nX-Faux: oui",
        b"a\tb",
        b"caf\xc3\xa9.test",
        // **NI POINT-VIRGULE** : il sépare les résultats, et un domaine qui en
        // porterait un ferait lire deux résultats là où on en écrit un.
        b"a;dkim=pass",
    ] {
        let signatures = [DkimSeen {
            result: DkimResult::Pass,
            domain: hostile,
            selector: b"s",
        }];
        assert_eq!(
            write_authres(
                &mut place,
                &Authentication {
                    serv_id: NOUS,
                    spf: None,
                    dkim: &signatures,
                    dmarc: None,
                    auth: None,
                }
            ),
            Err(Error::NotPrintable),
            "domaine DKIM {hostile:?}"
        );
        // Et pour chacune des quatre autres valeurs.
        assert_eq!(
            write_authres(
                &mut place,
                &Authentication {
                    serv_id: hostile,
                    spf: None,
                    dkim: &[],
                    dmarc: None,
                    auth: None,
                }
            ),
            Err(Error::NotPrintable),
            "identifiant {hostile:?}"
        );
        assert_eq!(
            write_authres(
                &mut place,
                &Authentication {
                    serv_id: NOUS,
                    spf: Some((SpfResult::Pass, SpfIdentity::MailFrom, hostile)),
                    dkim: &[],
                    dmarc: None,
                    auth: None,
                }
            ),
            Err(Error::NotPrintable),
            "domaine SPF {hostile:?}"
        );
        assert_eq!(
            write_authres(
                &mut place,
                &Authentication {
                    serv_id: NOUS,
                    spf: None,
                    dkim: &[],
                    dmarc: Some((DmarcResult::Pass, hostile)),
                    auth: None,
                }
            ),
            Err(Error::NotPrintable),
            "domaine DMARC {hostile:?}"
        );
        let signatures = [DkimSeen {
            result: DkimResult::Pass,
            domain: b"x.test",
            selector: hostile,
        }];
        assert_eq!(
            write_authres(
                &mut place,
                &Authentication {
                    serv_id: NOUS,
                    spf: None,
                    dkim: &signatures,
                    dmarc: None,
                    auth: None,
                }
            ),
            Err(Error::NotPrintable),
            "sélecteur {hostile:?}"
        );
    }
}

#[test]
fn une_valeur_trop_longue_est_refusee() {
    let mut place = [0_u8; 4096];
    let long = std::vec![b'a'; 254];
    assert_eq!(
        write_authres(
            &mut place,
            &Authentication {
                serv_id: &long,
                spf: None,
                dkim: &[],
                dmarc: None,
                auth: None,
            }
        ),
        Err(Error::NotPrintable)
    );
    // Deux cent cinquante-trois passent : la borne est celle-là.
    let juste = std::vec![b'a'; 253];
    assert!(
        write_authres(
            &mut place,
            &Authentication {
                serv_id: &juste,
                spf: None,
                dkim: &[],
                dmarc: None,
                auth: None,
            }
        )
        .is_ok()
    );
}

/// **LES MOTS SONT CEUX DE LA RFC, PAS LES NÔTRES.**
///
/// Un filtre à l'autre bout ne connaît que ceux-là.
#[test]
fn chaque_verdict_porte_le_mot_de_la_rfc() {
    for (resultat, mot) in [
        (SpfResult::None, "none"),
        (SpfResult::Neutral, "neutral"),
        (SpfResult::Pass, "pass"),
        (SpfResult::Fail, "fail"),
        (SpfResult::SoftFail, "softfail"),
        (SpfResult::TempError, "temperror"),
        (SpfResult::PermError, "permerror"),
    ] {
        assert_eq!(resultat.name(), mot);
    }
    for (resultat, mot) in [
        (DkimResult::None, "none"),
        (DkimResult::Pass, "pass"),
        (DkimResult::Fail, "fail"),
        (DkimResult::Policy, "policy"),
        (DkimResult::Neutral, "neutral"),
        (DkimResult::TempError, "temperror"),
        (DkimResult::PermError, "permerror"),
    ] {
        assert_eq!(resultat.name(), mot);
    }
    for (resultat, mot) in [
        (DmarcResult::None, "none"),
        (DmarcResult::Pass, "pass"),
        (DmarcResult::Fail, "fail"),
        (DmarcResult::TempError, "temperror"),
        (DmarcResult::PermError, "permerror"),
    ] {
        assert_eq!(resultat.name(), mot);
    }
    assert_eq!(SpfIdentity::MailFrom.property(), "smtp.mailfrom");
    assert_eq!(SpfIdentity::Helo.property(), "smtp.helo");
}

/// L'identité `helo` s'écrit quand le chemin de retour est nul (RFC 7208 §2.4).
#[test]
fn l_identite_helo_s_ecrit_aussi() {
    let entete = composer(&Authentication {
        serv_id: NOUS,
        spf: Some((SpfResult::SoftFail, SpfIdentity::Helo, b"client.example")),
        dkim: &[],
        dmarc: None,
        auth: None,
    });
    assert!(
        entete.contains("spf=softfail smtp.helo=client.example"),
        "{entete}"
    );
}

#[test]
fn un_tampon_trop_court_est_une_erreur_pas_un_entete_tronque() {
    let signatures = [DkimSeen {
        result: DkimResult::Fail,
        domain: b"example.net",
        selector: b"sel",
    }];
    let authentication = Authentication {
        serv_id: NOUS,
        spf: Some((SpfResult::Fail, SpfIdentity::MailFrom, b"example.net")),
        dkim: &signatures,
        dmarc: Some((DmarcResult::Fail, b"example.com")),
        auth: None,
    };
    // **CHAQUE POINT DE RUPTURE**, et pas seulement le premier.
    let mut refuses = 0_usize;
    for court in 0..authres_max(&authentication) {
        let mut place = std::vec![0_u8; court];
        match write_authres(&mut place, &authentication) {
            Ok(_) => {}
            Err(erreur) => {
                assert_eq!(erreur, Error::BufferTooSmall, "à {court} octets");
                refuses = refuses.saturating_add(1);
            }
        }
    }
    assert!(refuses > 0, "aucune taille n'a été refusée");
    // Et sur le chemin du `none`, qui écrit autre chose.
    let vide = Authentication {
        serv_id: NOUS,
        spf: None,
        dkim: &[],
        dmarc: None,
        auth: None,
    };
    for court in 0..authres_max(&vide) {
        let mut place = std::vec![0_u8; court];
        match write_authres(&mut place, &vide) {
            Ok(_) => {}
            Err(erreur) => assert_eq!(erreur, Error::BufferTooSmall, "à {court} octets"),
        }
    }
}

#[test]
fn les_types_se_copient_et_se_deboguent() {
    let vue = DkimSeen {
        result: DkimResult::Pass,
        domain: b"x.test",
        selector: b"s",
    };
    let copie = vue;
    assert_eq!(copie, vue);
    assert!(!std::format!("{vue:?}").is_empty());
    assert_ne!(
        vue,
        DkimSeen {
            result: DkimResult::Fail,
            ..vue
        }
    );
    assert!(!std::format!("{:?}", SpfResult::Pass).is_empty());
    assert_ne!(SpfResult::Pass, SpfResult::Fail);
    assert!(!std::format!("{:?}", DkimResult::Policy).is_empty());
    assert_ne!(DkimResult::Policy, DkimResult::Neutral);
    assert!(!std::format!("{:?}", DmarcResult::TempError).is_empty());
    assert_ne!(DmarcResult::TempError, DmarcResult::PermError);
    assert!(!std::format!("{:?}", SpfIdentity::Helo).is_empty());
    assert_ne!(SpfIdentity::Helo, SpfIdentity::MailFrom);
    let authentication = Authentication {
        serv_id: NOUS,
        spf: None,
        dkim: &[],
        dmarc: None,
        auth: None,
    };
    let jumelle = authentication;
    assert!(!std::format!("{jumelle:?}").is_empty());
}

// ── La place réservée ───────────────────────────────────────────────────────

/// **L'EN-TÊTE OCCUPE EXACTEMENT LA PLACE RÉSERVÉE**, ni plus ni moins.
///
/// Un octet de trop écraserait le premier en-tête du pair ; un de moins
/// laisserait un trou au milieu du message.
#[test]
fn l_entete_rempli_occupe_exactement_la_place() {
    let signatures = [DkimSeen {
        result: DkimResult::Pass,
        domain: b"example.net",
        selector: b"sel",
    }];
    let authentication = Authentication {
        serv_id: NOUS,
        spf: Some((SpfResult::Pass, SpfIdentity::MailFrom, b"example.net")),
        dkim: &signatures,
        dmarc: Some((DmarcResult::Fail, b"example.com")),
        auth: None,
    };
    for taille in [64_usize, 128, 512, AUTHRES_RESERVE, 4096] {
        let mut place = std::vec![0_u8; taille];
        let Ok(ecrit) = write_authres_padded(&mut place, &authentication) else {
            continue;
        };
        assert_eq!(ecrit.len(), taille, "à {taille} octets");
    }
}

/// **LE REMPLISSAGE EST UN PLI**, et le champ reste UN champ.
///
/// §3.2.2 de RFC 5322 : une continuation est un `CRLF` suivi d'un blanc. Un
/// bourrage qui ne le serait pas ferait lire un second en-tête, ou couperait le
/// message.
#[test]
fn le_remplissage_est_une_continuation_valide() {
    let mut place = [0_u8; AUTHRES_RESERVE];
    let authentication = Authentication {
        serv_id: NOUS,
        spf: Some((SpfResult::Fail, SpfIdentity::MailFrom, b"example.net")),
        dkim: &[],
        dmarc: Some((DmarcResult::Fail, b"example.com")),
        auth: None,
    };
    let ecrit = write_authres_padded(&mut place, &authentication).expect("composable");
    let texte = std::str::from_utf8(ecrit).expect("de l'ASCII");

    assert!(texte.starts_with("Authentication-Results: "));
    assert!(texte.ends_with("\r\n"), "le champ ne se termine pas");
    // CHAQUE LIGNE SAUF LA PREMIÈRE COMMENCE PAR UN BLANC : c'est ce qui en
    // fait des continuations du MÊME champ.
    let mut lignes = texte.split("\r\n");
    let _premiere = lignes.next();
    for ligne in lignes.filter(|ligne| !ligne.is_empty()) {
        assert!(
            ligne.starts_with(' ') || ligne.starts_with('\t'),
            "« {ligne} » ne continue rien"
        );
    }
    // ET AUCUNE LIGNE NE DÉPASSE LA BORNE de §2.1.1.
    for ligne in texte.split("\r\n") {
        assert!(ligne.len() <= 998, "{} octets", ligne.len());
    }
    // Le verdict est bien là, et pas noyé.
    assert!(
        texte.contains("dmarc=fail header.from=example.com"),
        "{texte}"
    );
}

/// **CE QUI NE TIENT PAS EST LAISSÉ, ET SPF ET DMARC TIENNENT TOUJOURS.**
///
/// Les signatures sont la seule partie dont la longueur suit ce qu'un tiers a
/// écrit ; l'alternative serait une place qui croît avec ce qu'un pair décide.
#[test]
fn les_signatures_qui_ne_tiennent_pas_sont_laissees() {
    let domaine = "d".repeat(200);
    let signatures: std::vec::Vec<DkimSeen<'_>> = (0..DKIM_MAX)
        .map(|_| DkimSeen {
            result: DkimResult::Pass,
            domain: domaine.as_bytes(),
            selector: b"selecteur",
        })
        .collect();
    let mut place = [0_u8; AUTHRES_RESERVE];
    let ecrit = write_authres_padded(
        &mut place,
        &Authentication {
            serv_id: NOUS,
            spf: Some((SpfResult::Pass, SpfIdentity::MailFrom, b"example.net")),
            dkim: &signatures,
            dmarc: Some((DmarcResult::Pass, b"example.com")),
            auth: None,
        },
    )
    .expect("composable");
    let texte = std::str::from_utf8(ecrit).expect("de l'ASCII");
    // SPF et DMARC sont là, quoi qu'il arrive.
    assert!(texte.contains("spf=pass"), "{texte}");
    assert!(texte.contains("dmarc=pass"), "{texte}");
    // Et il reste MOINS de signatures qu'on n'en a données.
    let vues = texte.matches("dkim=").count();
    assert!(vues < DKIM_MAX, "{vues} signatures rapportées");
    assert_eq!(ecrit.len(), AUTHRES_RESERVE);
}

/// **UNE PLACE TROP PETITE POUR L'EN-TÊTE MINIMAL EST UNE ERREUR**, et non un
/// en-tête tronqué : un champ coupé en deux ferait lire son reste comme un
/// autre.
#[test]
fn une_place_trop_petite_est_une_erreur() {
    let authentication = Authentication {
        serv_id: NOUS,
        spf: Some((SpfResult::Pass, SpfIdentity::MailFrom, b"example.net")),
        dkim: &[],
        dmarc: None,
        auth: None,
    };
    for taille in 0..40 {
        let mut place = std::vec![0_u8; taille];
        assert_eq!(
            write_authres_padded(&mut place, &authentication),
            Err(Error::BufferTooSmall),
            "à {taille} octets"
        );
    }
}

/// Et le cas `none` se remplit aussi : un serveur qui ne vérifie rien écrit
/// tout de même son identifiant.
#[test]
fn le_cas_none_se_remplit_aussi() {
    let mut place = [0_u8; AUTHRES_RESERVE];
    let ecrit = write_authres_padded(
        &mut place,
        &Authentication {
            serv_id: NOUS,
            spf: None,
            dkim: &[],
            dmarc: None,
            auth: None,
        },
    )
    .expect("composable");
    assert_eq!(ecrit.len(), AUTHRES_RESERVE);
    let texte = std::str::from_utf8(ecrit).expect("de l'ASCII");
    assert!(
        texte.starts_with("Authentication-Results: mail.nous.test; none"),
        "{texte}"
    );
}

/// **UNE VALEUR QU'ON REFUSE D'ÉCRIRE N'EST PAS UNE QUESTION DE PLACE.**
///
/// Retirer des signatures n'y changerait rien : le refus se rend tel quel,
/// plutôt que déguisé en tampon trop petit.
#[test]
fn un_refus_de_valeur_traverse_le_remplissage() {
    let mut place = [0_u8; AUTHRES_RESERVE];
    assert_eq!(
        write_authres_padded(
            &mut place,
            &Authentication {
                serv_id: b"a\r\nX-Faux: oui",
                spf: None,
                dkim: &[],
                dmarc: None,
                auth: None,
            }
        ),
        Err(Error::NotPrintable)
    );
    // Et la borne de signatures aussi.
    let signatures: std::vec::Vec<DkimSeen<'_>> = (0..=DKIM_MAX)
        .map(|_| DkimSeen {
            result: DkimResult::Pass,
            domain: b"x.test",
            selector: b"s",
        })
        .collect();
    assert_eq!(
        write_authres_padded(
            &mut place,
            &Authentication {
                serv_id: NOUS,
                spf: None,
                dkim: &signatures,
                dmarc: None,
                auth: None,
            }
        ),
        Err(Error::TooManyFields { limit: DKIM_MAX })
    );
}

/// **AUCUNE LIGNE NE DÉPASSE 998 OCTETS, QUELLE QUE SOIT LA RÉSERVE.**
///
/// # Le défaut que cet essai ferme
///
/// Le bourrage se repliait UNE fois, et occupait ensuite toute la place d'un
/// trait. Cela tenait tant que [`AUTHRES_RESERVE`] valait 1 024 — la plus longue
/// ligne mesurait 906 octets. La validité du message dépendait donc de la valeur
/// d'une constante que rien n'empêchait de monter :
///
/// ```text
/// réserve  512 : ligne la plus longue  394 octets
/// réserve 1024 : ligne la plus longue  906 octets
/// réserve 1200 : ligne la plus longue 1082 octets   ← §2.1.1 dit 998 au plus
/// réserve 4096 : ligne la plus longue 3978 octets
/// ```
///
/// # Pourquoi les essais existants ne le voyaient pas
///
/// `l_entete_rempli_occupe_exactement_la_place` exerce DÉJÀ 4 096 octets, mais
/// ne vérifie que la taille TOTALE ; `le_remplissage_est_une_continuation_valide`
/// vérifie bien la longueur des lignes, mais à la seule réserve d'aujourd'hui.
/// Aucun des deux ne pouvait donc dire ce que l'autre regardait.
#[test]
fn aucune_ligne_ne_depasse_la_borne_quelle_que_soit_la_reserve() {
    let signatures = [DkimSeen {
        result: DkimResult::Pass,
        domain: b"example.net",
        selector: b"sel",
    }];
    for authentication in [
        Authentication {
            serv_id: NOUS,
            spf: Some((SpfResult::Pass, SpfIdentity::MailFrom, b"example.net")),
            dkim: &signatures,
            dmarc: Some((DmarcResult::Pass, b"example.com")),
            auth: None,
        },
        // Le cas le plus court : rien n'a été vérifié. C'est lui qui laisse le
        // plus de place à bourrer, donc le plus long bourrage.
        Authentication {
            serv_id: b"a",
            spf: None,
            dkim: &[],
            dmarc: None,
            auth: None,
        },
    ] {
        for taille in [
            64_usize,
            128,
            512,
            AUTHRES_RESERVE,
            1_200,
            2_048,
            4_096,
            9_999,
        ] {
            let mut place = std::vec![0_u8; taille];
            let Ok(ecrit) = write_authres_padded(&mut place, &authentication) else {
                continue;
            };
            assert_eq!(ecrit.len(), taille, "à {taille} octets");
            let texte = std::str::from_utf8(ecrit).expect("de l'ASCII");
            // Le champ se termine par un `CRLF` : le dernier morceau du découpage
            // est vide, et ne compte pas pour une ligne.
            for ligne in texte.trim_end_matches("\r\n").split("\r\n") {
                assert!(
                    ligne.len() <= 998,
                    "réserve {taille} : une ligne de {} octets",
                    ligne.len()
                );
            }
            // ET LE CHAMP RESTE UN CHAMP : chaque ligne sauf la première ouvre
            // par un blanc. Un pli mal posé ferait lire un second en-tête.
            for (rang, ligne) in texte.trim_end_matches("\r\n").split("\r\n").enumerate() {
                assert!(
                    rang == 0 || ligne.starts_with([' ', '\t']),
                    "réserve {taille}, ligne {rang} n'ouvre pas par un blanc : {ligne:.40}"
                );
            }
        }
    }
}

/// **UN RÉSULTAT SANS PROPRIÉTÉS S'ÉCRIT, ET SEUL.**
///
/// §2.2 de RFC 8601 : « The "propspec" may be omitted if, for example, the
/// method was unable to extract any properties to do its evaluation yet still
/// has a result to report. »
///
/// C'est le cas d'une signature dont la SYNTAXE est invalide : §6.1.1 de
/// RFC 6376 exige d'en rendre compte en `permerror`, et l'on n'a alors lu ni
/// `d=` ni `s=` — c'est tout le problème.
#[test]
fn une_signature_sans_proprietes_s_ecrit_sans_elles() {
    let sans = [DkimSeen {
        result: DkimResult::PermError,
        domain: b"",
        selector: b"",
    }];
    let mut place = [0_u8; 256];
    let ecrit = write_authres(
        &mut place,
        &Authentication {
            serv_id: NOUS,
            spf: None,
            dkim: &sans,
            dmarc: None,
            auth: None,
        },
    )
    .expect("composable");
    let texte = std::str::from_utf8(ecrit).expect("de l'ASCII");
    assert!(texte.contains("dkim=permerror"), "{texte}");
    // NI L'UNE NI L'AUTRE : `header.d=` vide serait une propriété illisible, et
    // `header.s=` seul ne désignerait aucune clé.
    assert!(!texte.contains("header.d="), "{texte}");
    assert!(!texte.contains("header.s="), "{texte}");
}

/// **ET ELLE COHABITE AVEC UNE SIGNATURE QUI, ELLE, A DES PROPRIÉTÉS.**
///
/// Un message peut porter les deux : une signature lisible et une malformée. Le
/// cas mérite son essai parce que la boucle qui compose écrit les deux formes,
/// et qu'une erreur d'ordre y ferait perdre le `;` qui les sépare.
#[test]
fn les_deux_formes_de_signature_se_composent_ensemble() {
    let deux = [
        DkimSeen {
            result: DkimResult::Pass,
            domain: b"example.net",
            selector: b"sel",
        },
        DkimSeen {
            result: DkimResult::PermError,
            domain: b"",
            selector: b"",
        },
    ];
    let mut place = [0_u8; 512];
    let ecrit = write_authres(
        &mut place,
        &Authentication {
            serv_id: NOUS,
            spf: None,
            dkim: &deux,
            dmarc: None,
            auth: None,
        },
    )
    .expect("composable");
    let texte = std::str::from_utf8(ecrit).expect("de l'ASCII");
    assert!(
        texte.contains("dkim=pass header.d=example.net header.s=sel"),
        "{texte}"
    );
    assert!(texte.contains("dkim=permerror\r\n"), "{texte}");
    // Chaque ligne sauf la première ouvre par un blanc : le champ reste UN champ.
    for (rang, ligne) in texte.trim_end_matches("\r\n").split("\r\n").enumerate() {
        assert!(
            rang == 0 || ligne.starts_with([' ', '\t']),
            "ligne {rang} : {ligne:.40}"
        );
    }
}

/// **UNE MOITIÉ DE PAIRE EST REFUSÉE**, et ce n'est pas de la pédanterie.
///
/// `header.s` sans `header.d` ne désigne aucune clé : un sélecteur ne vaut que
/// dans le DNS d'un domaine. L'écrire donnerait à un lecteur en aval une
/// propriété qu'il ne pourrait pas résoudre, et la faire disparaître en silence
/// cacherait une erreur d'appelant.
#[test]
fn une_moitie_de_paire_est_refusee() {
    for (domaine, selecteur) in [(b"" as &[u8], b"sel" as &[u8]), (b"example.net", b"")] {
        let bancale = [DkimSeen {
            result: DkimResult::Pass,
            domain: domaine,
            selector: selecteur,
        }];
        let mut place = [0_u8; 256];
        assert!(
            write_authres(
                &mut place,
                &Authentication {
                    serv_id: NOUS,
                    spf: None,
                    dkim: &bancale,
                    dmarc: None,
                    auth: None,
                },
            )
            .is_err(),
            "`d={domaine:?}` `s={selecteur:?}` aurait dû être refusé"
        );
    }
}

/// **UNE SOUMISSION AUTHENTIFIÉE NE PORTE QUE `auth=`** (§2.7.4).
///
/// Les trois autres méthodes jugent ce qu'un INCONNU prétend être. Sur une
/// soumission, ce serveur est l'origine et connaît déjà le déposant : il
/// consigne au nom de qui il a accepté, et n'invente pas de verdict pour des
/// vérifications qu'il n'a pas conduites.
#[test]
fn une_soumission_authentifiee_ne_porte_que_le_compte() {
    let entete = composer(&Authentication {
        serv_id: NOUS,
        spf: None,
        dkim: &[],
        dmarc: None,
        auth: Some(b"ofrou-sierre"),
    });
    assert_eq!(
        entete,
        "Authentication-Results: mail.nous.test;\r\n\
         \tauth=pass smtp.auth=ofrou-sierre\r\n"
    );
}

/// **`auth=` EMPÊCHE LE MOT `none`.**
///
/// Sans cela, une soumission authentifiée serait écrite « rien n'a été
/// vérifié » — alors qu'on a précisément vérifié la seule chose qui compte ici.
#[test]
fn le_compte_seul_n_est_pas_none() {
    let entete = composer(&Authentication {
        serv_id: NOUS,
        spf: None,
        dkim: &[],
        dmarc: None,
        auth: Some(b"contact"),
    });
    assert!(!entete.contains("none"), "{entete}");
}

/// **`auth=` VIENT EN PREMIER**, parce qu'il dit sous quelle autorité le reste
/// a été accepté. L'ordre n'est pas cosmétique : un lecteur qui parcourt
/// l'en-tête doit apprendre d'abord d'où vient le message.
#[test]
fn le_compte_precede_les_autres_methodes() {
    let signatures = [DkimSeen {
        result: DkimResult::Pass,
        domain: b"example.net",
        selector: b"sel",
    }];
    let entete = composer(&Authentication {
        serv_id: NOUS,
        spf: Some((SpfResult::Pass, SpfIdentity::MailFrom, b"example.net")),
        dkim: &signatures,
        dmarc: Some((DmarcResult::Pass, b"example.net")),
        auth: Some(b"contact"),
    });
    let rang_auth = entete.find("auth=pass").expect("écrit");
    assert!(rang_auth < entete.find("spf=").expect("écrit"), "{entete}");
    assert!(rang_auth < entete.find("dkim=").expect("écrit"), "{entete}");
    assert!(
        rang_auth < entete.find("dmarc=").expect("écrit"),
        "{entete}"
    );
}

/// **UN NOM DE COMPTE IMPRÉSENTABLE EST REFUSÉ, PAS ÉCHAPPÉ.**
///
/// Même règle que pour les domaines : un octet qu'on ne sait pas écrire dans
/// un en-tête casserait la syntaxe de RFC 8601, et un en-tête cassé se lit
/// comme un en-tête d'un autre.
#[test]
fn un_compte_impresentable_est_refuse() {
    let mut place = [0_u8; AUTHRES_RESERVE];
    assert_eq!(
        write_authres(
            &mut place,
            &Authentication {
                serv_id: NOUS,
                spf: None,
                dkim: &[],
                dmarc: None,
                auth: Some(b"con\r\ntact"),
            }
        ),
        Err(Error::NotPrintable)
    );
}

/// La place réservée majore bien ce que le compte occupe.
#[test]
fn la_place_reservee_tient_compte_du_compte() {
    let court = Authentication {
        serv_id: NOUS,
        spf: None,
        dkim: &[],
        dmarc: None,
        auth: Some(b"a"),
    };
    let long = Authentication {
        auth: Some(b"un-nom-de-compte-nettement-plus-long"),
        ..court
    };
    assert!(authres_max(&long) > authres_max(&court));
    // Et il compose vraiment dans la place annoncée.
    let mut place = std::vec![0_u8; authres_max(&long)];
    assert!(write_authres(&mut place, &long).is_ok());
}

/// **UN TAMPON TROP COURT EST UNE ERREUR, JAMAIS UN EN-TÊTE TRONQUÉ** — y
/// compris au milieu du champ `auth`.
///
/// On éprouve TOUTES les tailles plutôt que d'en deviner deux : la coupure
/// peut tomber dans le nom de la propriété comme dans le nom du compte, et un
/// en-tête coupé en deux se lirait comme un en-tête d'un autre.
#[test]
fn une_coupure_dans_le_compte_est_refusee_a_toutes_les_tailles() {
    let authentification = Authentication {
        serv_id: NOUS,
        spf: None,
        dkim: &[],
        dmarc: None,
        auth: Some(b"ofrou-sierre"),
    };
    let entier = composer(&authentification).len();
    let mut refus = 0_usize;
    for taille in 0..entier {
        let mut place = std::vec![0_u8; taille];
        assert_eq!(
            write_authres(&mut place, &authentification),
            Err(Error::BufferTooSmall),
            "taille {taille} aurait dû refuser"
        );
        refus = refus.saturating_add(1);
    }
    assert_eq!(
        refus, entier,
        "toutes les tailles courtes ont été éprouvées"
    );
    // Et à la taille exacte, il compose.
    let mut place = std::vec![0_u8; entier];
    assert!(write_authres(&mut place, &authentification).is_ok());
}
