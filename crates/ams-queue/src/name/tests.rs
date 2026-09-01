//! Ce qu'un nom d'entrée porte, et ce qu'il refuse de porter.

use super::{Entry, NAME_MAX, parse_name, write_name};
use crate::Error;

/// Écrit un nom, et le rend sous forme possédée pour que l'emprunt finisse.
fn nommer(entry: &Entry<'_>) -> std::string::String {
    let mut place = [0_u8; NAME_MAX];
    std::string::String::from(write_name(entry, &mut place).expect("nommable"))
}

#[test]
fn un_nom_ecrit_se_relit_a_l_identique() {
    let entree = Entry {
        due: 1_700_000_123,
        deposited: 1_699_999_000,
        attempts: 3,
        id: "a1b2c3-4d5e",
    };
    let nom = nommer(&entree);
    assert_eq!(parse_name(&nom), Some(entree));
}

#[test]
fn l_instant_est_complete_par_des_zeros() {
    // **SANS CELA, UN `ls` MENTIRAIT SUR L'ORDRE DES REPRISES** : `9999999999`
    // se trierait avant `100000000000`.
    let tot = nommer(&Entry {
        due: 42,
        deposited: 0,
        attempts: 0,
        id: "x",
    });
    let tard = nommer(&Entry {
        due: 1_700_000_000,
        deposited: 0,
        attempts: 0,
        id: "x",
    });
    assert!(tot.starts_with("000000000042!000000000000!0!x"), "{tot}");
    assert!(tot < tard, "{tot} devrait se trier avant {tard}");
}

#[test]
fn le_nombre_d_essais_ne_se_complete_pas() {
    // Il n'a aucune raison de se trier, et le compléter allongerait le nom pour
    // rien.
    let nom = nommer(&Entry {
        due: 1,
        deposited: 2,
        attempts: 0,
        id: "z",
    });
    assert!(nom.ends_with("!0!z.eml"), "{nom}");
    let beaucoup = nommer(&Entry {
        due: 1,
        deposited: 2,
        attempts: u32::MAX,
        id: "z",
    });
    assert!(beaucoup.ends_with("!4294967295!z.eml"), "{beaucoup}");
}

#[test]
fn un_instant_extreme_tient_dans_le_nom() {
    // Douze chiffres portent jusqu'à l'an 33 658 ; au-delà, le nom s'allonge
    // plutôt que de tronquer un instant, ce qui ferait mentir le nom.
    let nom = nommer(&Entry {
        due: u64::MAX,
        deposited: u64::MAX,
        attempts: 1,
        id: "z",
    });
    assert!(nom.starts_with("18446744073709551615!"), "{nom}");
    assert!(parse_name(&nom).is_some());
}

#[test]
fn un_identifiant_qui_sortirait_du_repertoire_est_refuse() {
    // **LES TROIS FAÇONS DE SORTIR DE LA FILE.** Un `/` désigne un autre
    // répertoire, un `.` en tête cache le fichier, un `!` casse le découpage.
    for mauvais in ["../ailleurs", "a/b", "a!b", ".cache", "a.b", "a b", "é", ""] {
        let entree = Entry {
            due: 1,
            deposited: 1,
            attempts: 0,
            id: mauvais,
        };
        let mut place = [0_u8; NAME_MAX];
        assert_eq!(
            write_name(&entree, &mut place),
            Err(Error::BadIdentifier),
            "« {mauvais} » aurait dû être refusé"
        );
    }
}

#[test]
fn un_identifiant_trop_long_est_refuse() {
    let long = "a".repeat(65);
    let mut place = [0_u8; NAME_MAX];
    assert_eq!(
        write_name(
            &Entry {
                due: 1,
                deposited: 1,
                attempts: 0,
                id: &long,
            },
            &mut place
        ),
        Err(Error::BadIdentifier)
    );
    // Soixante-quatre passent : la borne est celle-là, et pas une de moins.
    let juste = "a".repeat(64);
    assert!(
        write_name(
            &Entry {
                due: 1,
                deposited: 1,
                attempts: 0,
                id: &juste,
            },
            &mut place
        )
        .is_ok()
    );
}

#[test]
fn un_tampon_trop_court_est_une_erreur_pas_un_nom_tronque() {
    let entree = Entry {
        due: 1,
        deposited: 1,
        attempts: 0,
        id: "abc",
    };
    // La borne va jusqu'au nom ENTIER : sans cela, c'est toujours le même
    // `pousser` qui refuserait, et les suivants ne seraient jamais éprouvés.
    for taille in 0..35 {
        let mut place = std::vec![0_u8; taille];
        assert_eq!(write_name(&entree, &mut place), Err(Error::BufferTooSmall));
    }
}

#[test]
fn rien_de_ce_qui_n_a_pas_cette_forme_n_est_touche() {
    // **UN RÉPERTOIRE QU'ON PARTAGE NE SE REPREND PAS AU JUGÉ.**
    for etranger in [
        "README",
        "1!2!3!x",              // pas de suffixe
        "1.eml",                // ni dépôt, ni essais, ni identifiant
        "1!2.eml",              // ni essais, ni identifiant
        "1!2!3!x-sans-suffixe", // pas de suffixe
        "1!2!3.eml",            // pas d'identifiant
        "1!2!3!x!y.eml",        // un séparateur de trop
        "a!2!3!x.eml",          // un instant qui n'en est pas un
        "1!b!3!x.eml",
        "1!2!c!x.eml",
        "1!2!3!../ailleurs.eml", // un identifiant qui sort
        "-1!2!3!x.eml",
        "1!2!99999999999999999999!x.eml", // un compteur qui déborde
        ".eml",
    ] {
        assert_eq!(
            parse_name(etranger),
            None,
            "« {etranger} » aurait dû être ignoré"
        );
    }
}

#[test]
fn le_quatrieme_separateur_ne_se_laisse_pas_absorber() {
    // Sans ce refus, un nom qu'on écrit ne se relirait pas à l'identique, et la
    // file oublierait des essais.
    assert_eq!(parse_name("1!2!3!a!b.eml"), None);
}

#[test]
fn une_entree_se_copie_et_se_debogue() {
    let entree = Entry {
        due: 1,
        deposited: 2,
        attempts: 3,
        id: "x",
    };
    let copie = entree;
    assert_eq!(copie, entree);
    assert!(!std::format!("{entree:?}").is_empty());
    assert_ne!(entree, Entry { due: 9, ..entree });
}
