//! Ce qu'un nom d'entrée de cache porte, et ce qu'il refuse de porter.

use super::{Entry, NAME_MAX, parse_name, write_name};
use crate::Error;

/// Écrit un nom, et le rend possédé pour que l'emprunt finisse.
fn nommer(entry: &Entry<'_>) -> std::string::String {
    let mut place = [0_u8; NAME_MAX];
    std::string::String::from(write_name(entry, &mut place).expect("nommable"))
}

const UNE: Entry<'static> = Entry {
    fetched: 1_700_000_000,
    id: "20160831085700Z",
    domain: "example.com",
};

#[test]
fn un_nom_ecrit_se_relit_a_l_identique() {
    let nom = nommer(&UNE);
    assert_eq!(nom, "001700000000!20160831085700Z!example.com.mtasts");
    assert_eq!(parse_name(&nom), Some(UNE));
}

#[test]
fn l_instant_est_complete_par_des_zeros() {
    // Sans cela, un `ls` mentirait sur l'ordre des récupérations.
    let tot = nommer(&Entry { fetched: 42, ..UNE });
    let tard = nommer(&UNE);
    assert!(tot.starts_with("000000000042!"), "{tot}");
    assert!(tot < tard, "{tot} devrait se trier avant {tard}");
    // Un instant démesuré allonge le nom plutôt que de se tronquer.
    let extreme = nommer(&Entry {
        fetched: u64::MAX,
        ..UNE
    });
    assert!(extreme.starts_with("18446744073709551615!"), "{extreme}");
    assert!(parse_name(&extreme).is_some());
}

/// **LE CACHE NE SE PÉRIME QUE PAR LE TEMPS.**
#[test]
fn la_fraicheur_se_juge_sur_l_age() {
    let entree = Entry {
        fetched: 1_000,
        ..UNE
    };
    assert!(entree.fresh(100, 1_000), "à l'instant même");
    assert!(entree.fresh(100, 1_099), "une seconde avant la péremption");
    assert!(!entree.fresh(100, 1_100), "à la péremption exacte");
    assert!(!entree.fresh(100, 2_000), "bien après");
    // Un `max_age` nul ne garde rien — la politique l'interdit, et la garde le
    // dit quand même.
    assert!(!entree.fresh(0, 1_000));
}

/// **L'HORLOGE QUI RECULE NE PROLONGE RIEN.**
///
/// Une entrée récupérée « dans le futur » — l'horloge a été remise à l'heure —
/// est traitée comme périmée, plutôt que de valoir jusqu'à ce futur-là.
#[test]
fn une_entree_venue_du_futur_est_perimee() {
    let entree = Entry {
        fetched: 2_000,
        ..UNE
    };
    assert!(!entree.fresh(u32::MAX, 1_000));
}

/// **LES TROIS FAÇONS DE SORTIR DU RÉPERTOIRE.**
#[test]
fn un_domaine_ou_un_identifiant_qui_sortirait_est_refuse() {
    let mut place = [0_u8; NAME_MAX];
    for mauvais in [
        "../ailleurs",
        "a/b",
        "a!b",
        ".cache",
        "example.com.",
        "",
        "é",
    ] {
        assert_eq!(
            write_name(
                &Entry {
                    domain: mauvais,
                    ..UNE
                },
                &mut place
            ),
            Err(Error::BadName),
            "domaine « {mauvais} »"
        );
    }
    for mauvais in ["../ailleurs", "a/b", "a!b", "a.b", "a-b", "", "é"] {
        assert_eq!(
            write_name(&Entry { id: mauvais, ..UNE }, &mut place),
            Err(Error::BadName),
            "identifiant « {mauvais} »"
        );
    }
}

#[test]
fn un_domaine_ou_un_identifiant_trop_long_est_refuse() {
    let mut place = [0_u8; NAME_MAX];
    let long = "a".repeat(254);
    assert_eq!(
        write_name(
            &Entry {
                domain: &long,
                ..UNE
            },
            &mut place
        ),
        Err(Error::BadName)
    );
    let long = "a".repeat(33);
    assert_eq!(
        write_name(&Entry { id: &long, ..UNE }, &mut place),
        Err(Error::BadName)
    );
    // Les deux bornes elles-mêmes passent.
    let juste = "a".repeat(253);
    assert!(
        write_name(
            &Entry {
                domain: &juste,
                ..UNE
            },
            &mut place
        )
        .is_ok()
    );
}

#[test]
fn un_tampon_trop_court_est_une_erreur_pas_un_nom_tronque() {
    let entier = nommer(&UNE);
    for taille in 0..entier.len() {
        let mut place = std::vec![0_u8; taille];
        assert_eq!(
            write_name(&UNE, &mut place),
            Err(Error::BufferTooSmall),
            "à {taille} octets"
        );
    }
}

#[test]
fn rien_de_ce_qui_n_a_pas_cette_forme_n_est_touche() {
    for etranger in [
        "README",
        "1!abc!example.com",
        "1!abc.mtasts",
        "1.mtasts",
        "1!abc!example.com!x.mtasts",
        "a!abc!example.com.mtasts",
        "1!ab-c!example.com.mtasts",
        "1!abc!../ailleurs.mtasts",
        ".mtasts",
    ] {
        assert_eq!(parse_name(etranger), None, "« {etranger} »");
    }
}

#[test]
fn une_entree_se_copie_et_se_debogue() {
    let copie = UNE;
    assert_eq!(copie, UNE);
    assert!(!std::format!("{UNE:?}").is_empty());
    assert_ne!(UNE, Entry { fetched: 9, ..UNE });
}
