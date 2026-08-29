//! Ce qu'une date dit.

use super::{DATE_MAX, write_date};
use crate::Error;

fn dater(secondes: u64) -> std::string::String {
    let mut sortie = [0_u8; DATE_MAX];
    let ecrit = write_date(secondes, &mut sortie).expect("datable");
    std::string::String::from_utf8(ecrit.to_vec()).expect("de l'ASCII")
}

/// Des dates connues, choisies pour ce qu'elles éprouvent.
#[test]
fn des_dates_connues_s_ecrivent_juste() {
    for (secondes, attendue) in [
        // L'époque elle-même : un jeudi.
        (0_u64, "Thu, 01 Jan 1970 00:00:00 +0000"),
        (1, "Thu, 01 Jan 1970 00:00:01 +0000"),
        // Le 1er mars d'une année NON bissextile : la veille était un 28.
        (1_677_628_800, "Wed, 01 Mar 2023 00:00:00 +0000"),
        (1_677_542_400, "Tue, 28 Feb 2023 00:00:00 +0000"),
        // Le 29 février d'une année bissextile ordinaire.
        (1_709_164_800, "Thu, 29 Feb 2024 00:00:00 +0000"),
        // Le 29 février de l'an 2000 : divisible par 100 ET par 400.
        (951_782_400, "Tue, 29 Feb 2000 00:00:00 +0000"),
        // Le 1er mars 1900 aurait été décalé d'un jour par un calcul naïf.
        (2_147_483_647, "Tue, 19 Jan 2038 03:14:07 +0000"),
        (1_787_987_311, "Sat, 29 Aug 2026 07:08:31 +0000"),
    ] {
        assert_eq!(dater(secondes), attendue, "à {secondes} secondes");
    }
}

/// Le jour de la semaine avance d'un par jour, et boucle sur sept.
#[test]
fn les_jours_de_la_semaine_se_suivent() {
    const SEMAINE: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    for jour in 0..21_u64 {
        let ecrite = dater(jour.saturating_mul(86_400));
        let attendu = SEMAINE[usize::try_from(jour % 7).expect("petit")];
        assert!(ecrite.starts_with(attendu), "jour {jour} : {ecrite}");
    }
}

/// Le mois et le jour tiennent sur deux chiffres, l'année sur quatre.
#[test]
fn les_nombres_sont_completes_a_gauche() {
    assert_eq!(dater(0), "Thu, 01 Jan 1970 00:00:00 +0000");
    // Une heure à un chiffre s'écrit sur deux.
    assert!(dater(3_600 + 120 + 3).contains("01:02:03"));
}

/// Une année à cinq chiffres ne se tronque pas : elle s'écrit en entier.
#[test]
fn une_annee_lointaine_ne_se_tronque_pas() {
    // Bien au-delà de l'an 10000.
    let ecrite = dater(400_000_000_000);
    assert!(ecrite.contains("14645"), "{ecrite}");
    assert!(ecrite.ends_with(" +0000"));
}

#[test]
fn un_tampon_trop_court_le_dit_ou_qu_il_cede() {
    let entier = dater(1_787_987_311);
    for taille in 0..entier.len() {
        let mut sortie = std::vec![0_u8; taille];
        assert_eq!(
            write_date(1_787_987_311, &mut sortie),
            Err(Error::BufferTooSmall),
            "taille {taille}"
        );
    }
}
