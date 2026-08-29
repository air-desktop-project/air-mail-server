//! Lire ce qu'on écrit.

use super::parse_date_time;

#[test]
fn la_date_qu_on_rend_se_relit() {
    // Ce que `write_internal_date` écrit, à la seconde près.
    assert_eq!(
        parse_date_time(b"\"29-Aug-2026 07:08:31 +0000\""),
        Some(1_787_987_311)
    );
}

/// **Le décalage se RETRANCHE.** L'ajouter ferait vieillir chaque message à
/// chaque passage.
#[test]
fn le_decalage_se_retranche() {
    let universel = parse_date_time(b"\"29-Aug-2026 12:00:00 +0000\"").expect("lisible");
    let paris = parse_date_time(b"\"29-Aug-2026 14:00:00 +0200\"").expect("lisible");
    assert_eq!(paris, universel);
    let ouest = parse_date_time(b"\"29-Aug-2026 08:00:00 -0400\"").expect("lisible");
    assert_eq!(ouest, universel);
}

#[test]
fn le_jour_peut_etre_precede_d_un_espace() {
    assert_eq!(
        parse_date_time(b"\" 1-Jan-2020 00:00:00 +0000\""),
        Some(1_577_836_800)
    );
}

#[test]
fn la_seconde_intercalaire_est_admise() {
    assert!(parse_date_time(b"\"31-Dec-2016 23:59:60 +0000\"").is_some());
}

#[test]
fn les_formes_fautives_sont_refusees() {
    for texte in [
        &b""[..],
        b"\"\"",
        // Sans guillemets, ou avec un seul.
        b"29-Aug-2026 07:08:31 +0000",
        b"\"29-Aug-2026 07:08:31 +0000",
        // Une heure à champ vide.
        b"\"29-Aug-2026 :08:31 +0000\"",
        b"\"29-Aug-2026 07::31 +0000\"",
        // Une zone plus courte que deux chiffres.
        b"\"29-Aug-2026 07:08:31 +\"",
        b"\"29-Aug-2026 07:08:31 +0\"",
        // Sans zone.
        b"\"29-Aug-2026 07:08:31\"",
        // Un morceau de trop.
        b"\"29-Aug-2026 07:08:31 +0000 encore\"",
        // Des champs hors bornes.
        b"\"32-Aug-2026 07:08:31 +0000\"",
        b"\"29-Aug-1969 07:08:31 +0000\"",
        b"\"29-Zzz-2026 07:08:31 +0000\"",
        b"\"29-Aug-2026 24:08:31 +0000\"",
        b"\"29-Aug-2026 07:60:31 +0000\"",
        b"\"29-Aug-2026 07:08:61 +0000\"",
        b"\"29-Aug-2026 07:08:31 +2400\"",
        b"\"29-Aug-2026 07:08:31 +0060\"",
        // Une zone illisible.
        b"\"29-Aug-2026 07:08:31 0000\"",
        b"\"29-Aug-2026 07:08:31 +00\"",
        b"\"29-Aug-2026 07:08:31 +00x0\"",
        // Une date ou une heure incomplète.
        b"\"29-Aug 07:08:31 +0000\"",
        b"\"29-Aug-2026-1 07:08:31 +0000\"",
        b"\"29-Aug-2026 07:08 +0000\"",
        b"\"29-Aug-2026 07:08:31:1 +0000\"",
        // Un nombre qui déborde, au produit puis à la somme.
        b"\"29-Aug-99999999999999999999 07:08:31 +0000\"",
        b"\"29-Aug-18446744073709551616 07:08:31 +0000\"",
    ] {
        assert!(
            parse_date_time(texte).is_none(),
            "{:?} aurait dû être refusée",
            core::str::from_utf8(texte)
        );
    }
}

/// Une date d'avant l'époque, une fois le décalage retranché, n'est pas une date
/// négative : elle n'est pas une date du tout.
#[test]
fn une_date_qui_precede_l_epoque_est_refusee() {
    assert_eq!(parse_date_time(b"\"1-Jan-1970 00:00:00 +0100\""), None);
}
