//! Ce que les drapeaux disent, et comment une date d'arrivée s'écrit.

use super::{Flags, INTERNALDATE_MAX, write_internal_date};
use crate::Error;

fn ecrire(drapeaux: Flags) -> std::string::String {
    let mut sortie = [0_u8; 64];
    let ecrit = drapeaux.write(&mut sortie).expect("assez de place");
    std::string::String::from_utf8_lossy(ecrit).into_owned()
}

#[test]
fn les_cinq_drapeaux_s_ecrivent_dans_l_ordre() {
    assert_eq!(ecrire(Flags::NONE), "");
    assert_eq!(ecrire(Flags::SEEN), "\\Seen");
    assert_eq!(
        ecrire(Flags::SEEN.with(Flags::ANSWERED).with(Flags::DRAFT)),
        "\\Seen \\Answered \\Draft"
    );
    assert_eq!(
        ecrire(
            Flags::SEEN
                .with(Flags::ANSWERED)
                .with(Flags::FLAGGED)
                .with(Flags::DELETED)
                .with(Flags::DRAFT)
        ),
        "\\Seen \\Answered \\Flagged \\Deleted \\Draft"
    );
}

#[test]
fn les_drapeaux_se_posent_et_se_retirent() {
    let mut drapeaux = Flags::NONE;
    assert!(!drapeaux.contains(Flags::SEEN));
    drapeaux = drapeaux.with(Flags::SEEN).with(Flags::DELETED);
    assert!(drapeaux.contains(Flags::SEEN));
    assert!(drapeaux.contains(Flags::DELETED));
    assert!(!drapeaux.contains(Flags::DRAFT));
    drapeaux = drapeaux.without(Flags::SEEN);
    assert!(!drapeaux.contains(Flags::SEEN));
    assert!(drapeaux.contains(Flags::DELETED));
    // `NONE` est contenu par tout le monde : c'est l'ensemble vide.
    assert!(Flags::NONE.contains(Flags::NONE));
    assert_eq!(Flags::default(), Flags::NONE);
}

#[test]
fn les_noms_se_lisent_sans_egard_a_la_casse() {
    for (nom, attendu) in [
        (&b"\\Seen"[..], Flags::SEEN),
        (b"\\seen", Flags::SEEN),
        (b"\\ANSWERED", Flags::ANSWERED),
        (b"\\Flagged", Flags::FLAGGED),
        (b"\\Deleted", Flags::DELETED),
        (b"\\Draft", Flags::DRAFT),
    ] {
        assert_eq!(Flags::parse_one(nom), Some(attendu), "{nom:?}");
    }
}

/// **Un drapeau inconnu n'est pas une faute** : la RFC 9051 §2.3.2 admet des
/// mots-clés propres à chaque serveur. Le refuser ferait échouer un `STORE` que
/// la RFC autorise.
#[test]
fn un_drapeau_inconnu_n_est_pas_une_faute() {
    for inconnu in [&b"\\Recent"[..], b"$Important", b"maison", b"", b"\\"] {
        assert_eq!(Flags::parse_one(inconnu), None, "{inconnu:?}");
    }
}

#[test]
fn un_tampon_trop_court_le_dit_ou_qu_il_cede() {
    let tous = Flags::SEEN
        .with(Flags::ANSWERED)
        .with(Flags::FLAGGED)
        .with(Flags::DELETED)
        .with(Flags::DRAFT);
    let entier = ecrire(tous);
    for taille in 0..entier.len() {
        let mut sortie = std::vec![0_u8; taille];
        assert!(
            matches!(tous.write(&mut sortie), Err(Error::BufferTooSmall { .. })),
            "taille {taille}"
        );
    }
}

// ── LA DATE D'ARRIVÉE ───────────────────────────────────────────────────────

fn dater(secondes: u64) -> std::string::String {
    let mut sortie = [0_u8; INTERNALDATE_MAX];
    let ecrit = write_internal_date(secondes, &mut sortie).expect("datable");
    std::string::String::from_utf8_lossy(ecrit).into_owned()
}

/// **Son écriture n'est pas celle de la RFC 5322** : guillemets compris, et le
/// jour d'abord.
#[test]
fn des_dates_connues_s_ecrivent_juste() {
    for (secondes, attendue) in [
        (0_u64, "\"01-Jan-1970 00:00:00 +0000\""),
        (1_787_987_311, "\"29-Aug-2026 07:08:31 +0000\""),
        // Le 29 février de l'an 2000 : divisible par 100 ET par 400.
        (951_782_400, "\"29-Feb-2000 00:00:00 +0000\""),
        (1_709_164_800, "\"29-Feb-2024 00:00:00 +0000\""),
        (1_677_628_800, "\"01-Mar-2023 00:00:00 +0000\""),
        (2_147_483_647, "\"19-Jan-2038 03:14:07 +0000\""),
    ] {
        assert_eq!(dater(secondes), attendue, "à {secondes} secondes");
    }
}

#[test]
fn un_tampon_trop_court_pour_la_date_le_dit() {
    let entier = dater(1_787_987_311);
    for taille in 0..entier.len() {
        let mut sortie = std::vec![0_u8; taille];
        assert!(
            matches!(
                write_internal_date(1_787_987_311, &mut sortie),
                Err(Error::BufferTooSmall { .. })
            ),
            "taille {taille}"
        );
    }
    assert!(INTERNALDATE_MAX >= entier.len());
}

/// Une année lointaine ne se tronque pas.
#[test]
fn une_annee_lointaine_ne_se_tronque_pas() {
    let mut sortie = [0_u8; 64];
    let ecrit = write_internal_date(400_000_000_000, &mut sortie).expect("datable");
    let texte = std::string::String::from_utf8_lossy(ecrit).into_owned();
    assert!(texte.contains("14645"), "{texte}");
}

#[test]
fn ce_qui_se_lit_se_montre_et_se_compare() {
    assert!(!std::format!("{:?}", Flags::SEEN).is_empty());
    assert_eq!(Flags::SEEN, Flags::SEEN);
    assert_ne!(Flags::SEEN, Flags::DRAFT);
}
