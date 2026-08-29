//! Ce que la canonicalisation du corps doit tenir.

use super::BodyCanon;
use crate::canonical::Canon;

/// Canonicalise un corps d'un seul tenant.
fn canon(algorithme: Canon, corps: &str) -> std::string::String {
    par_morceaux(algorithme, &[corps], None)
}

/// Canonicalise un corps donné en plusieurs morceaux.
fn par_morceaux(algorithme: Canon, morceaux: &[&str], limite: Option<u64>) -> std::string::String {
    let mut rendu = std::vec::Vec::new();
    let mut machine = BodyCanon::new(algorithme, limite);
    for morceau in morceaux {
        machine.update(morceau.as_bytes(), &mut |sortie| {
            rendu.extend_from_slice(sortie);
        });
    }
    let ecrits = machine.finish(&mut |sortie| rendu.extend_from_slice(sortie));
    assert_eq!(
        ecrits,
        u64::try_from(rendu.len()).expect("petit"),
        "le compte des octets écrits ne suit pas ce qui est sorti"
    );
    std::string::String::from_utf8(rendu).expect("ASCII")
}

// ── LES VECTEURS DE LA RFC 6376 §3.4.5 ──────────────────────────────────────
//
// Le corps de l'exemple, tel que la RFC l'écrit :
//
//     <SP> C <SP><CRLF>
//     D <SP><HTAB><SP> E <CRLF>
//     <CRLF>
//     <CRLF>

const CORPS: &str = " C \r\nD \t E\r\n\r\n\r\n";

#[test]
fn relaxed_rend_ce_que_la_rfc_annonce() {
    // « <SP>C<CRLF>D<SP>E<CRLF> » : les blancs de queue disparaissent, les
    // suites se réduisent à une espace, les lignes vides de la fin s'ignorent —
    // et l'espace de TÊTE, elle, reste.
    assert_eq!(canon(Canon::Relaxed, CORPS), " C\r\nD E\r\n");
}

#[test]
fn simple_rend_ce_que_la_rfc_annonce() {
    // « <SP>C<SP><CRLF>D<SP><HTAB><SP>E<CRLF> » : rien ne change, sinon les
    // lignes vides de la fin.
    assert_eq!(canon(Canon::Simple, CORPS), " C \r\nD \t E\r\n");
}

// ── LES CORPS LIMITES ───────────────────────────────────────────────────────

#[test]
fn un_corps_vide_ne_se_canonicalise_pas_pareil_des_deux_cotes() {
    // §3.4.3 : « s'il n'y a pas de corps, un `CRLF` est ajouté ».
    // §3.4.4 : « un corps entièrement vide se canonicalise en une entrée nulle ».
    // LES DEUX NE DISENT PAS LA MÊME CHOSE, et les confondre fait échouer
    // toutes les signatures d'un des deux algorithmes.
    assert_eq!(canon(Canon::Simple, ""), "\r\n");
    assert_eq!(canon(Canon::Relaxed, ""), "");
}

#[test]
fn un_corps_de_lignes_vides_est_un_corps_vide() {
    assert_eq!(canon(Canon::Simple, "\r\n\r\n\r\n"), "\r\n");
    assert_eq!(canon(Canon::Relaxed, "\r\n\r\n\r\n"), "");
    // En `relaxed`, une ligne de blancs EST une ligne vide.
    assert_eq!(canon(Canon::Relaxed, "  \t \r\n \r\n"), "");
    // En `simple`, elle ne l'est pas : les blancs sont du contenu.
    assert_eq!(canon(Canon::Simple, "  \t \r\n \r\n"), "  \t \r\n \r\n");
}

#[test]
fn un_corps_sans_fin_de_ligne_finale_en_recoit_une() {
    assert_eq!(canon(Canon::Simple, "abc"), "abc\r\n");
    assert_eq!(canon(Canon::Relaxed, "abc"), "abc\r\n");
    assert_eq!(canon(Canon::Relaxed, "abc  "), "abc\r\n");
}

#[test]
fn les_lignes_vides_du_milieu_restent() {
    // Seules celles de la FIN s'ignorent : une ligne vide au milieu sépare deux
    // paragraphes, et la retirer changerait le message.
    assert_eq!(
        canon(Canon::Simple, "a\r\n\r\n\r\nb\r\n"),
        "a\r\n\r\n\r\nb\r\n"
    );
    assert_eq!(
        canon(Canon::Relaxed, "a\r\n\r\n\r\nb\r\n"),
        "a\r\n\r\n\r\nb\r\n"
    );
}

#[test]
fn un_cr_seul_est_un_octet_comme_un_autre() {
    // Une fin de ligne, c'est `CRLF`. Un `CR` que rien ne suit est du contenu —
    // le prendre pour une fin de ligne condenserait autre chose que ce qui a
    // été signé.
    assert_eq!(canon(Canon::Simple, "a\rb\r\n"), "a\rb\r\n");
    assert_eq!(canon(Canon::Relaxed, "a\rb\r\n"), "a\rb\r\n");
    assert_eq!(canon(Canon::Simple, "abc\r"), "abc\r\r\n");
    // Un `LF` seul aussi : ce n'est pas une fin de ligne.
    assert_eq!(canon(Canon::Simple, "a\nb\r\n"), "a\nb\r\n");
}

#[test]
fn le_decoupage_en_morceaux_ne_change_rien() {
    // LA PROPRIÉTÉ QUI COMPTE POUR UNE MACHINE EN FLUX : le pair choisit la
    // taille de ses paquets, et le condensat ne doit pas en dépendre. Une fin
    // de ligne coupée en deux est le cas qui casse les implémentations naïves.
    let entier = canon(Canon::Relaxed, CORPS);
    for coupe in 1..CORPS.len() {
        let (avant, apres) = CORPS.split_at(coupe);
        assert_eq!(
            par_morceaux(Canon::Relaxed, &[avant, apres], None),
            entier,
            "coupé à {coupe}"
        );
    }
    let entier = canon(Canon::Simple, CORPS);
    for coupe in 1..CORPS.len() {
        let (avant, apres) = CORPS.split_at(coupe);
        assert_eq!(
            par_morceaux(Canon::Simple, &[avant, apres], None),
            entier,
            "coupé à {coupe}"
        );
    }
    // Et octet par octet, ce qui coupe TOUT ce qui peut l'être.
    let un_par_un: std::vec::Vec<&str> = CORPS.split("").filter(|m| !m.is_empty()).collect();
    assert_eq!(
        par_morceaux(Canon::Relaxed, &un_par_un, None),
        canon(Canon::Relaxed, CORPS)
    );
}

// ── LA BORNE `l=` ───────────────────────────────────────────────────────────

#[test]
fn la_borne_coupe_le_corps_canonicalise() {
    // Elle compte les octets APRÈS canonicalisation (§3.7), pas ceux du fil.
    assert_eq!(par_morceaux(Canon::Relaxed, &[CORPS], Some(4)), " C\r\n");
    assert_eq!(par_morceaux(Canon::Relaxed, &[CORPS], Some(1)), " ");
    assert_eq!(par_morceaux(Canon::Relaxed, &[CORPS], Some(0)), "");
    // Une borne plus grande que le corps ne coupe rien.
    assert_eq!(
        par_morceaux(Canon::Relaxed, &[CORPS], Some(1000)),
        canon(Canon::Relaxed, CORPS)
    );
}

#[test]
fn la_borne_coupe_aussi_la_fin_de_ligne_ajoutee() {
    // Elle ne fait pas d'exception pour ce que la canonicalisation ajoute :
    // c'est du corps canonicalisé comme le reste.
    assert_eq!(par_morceaux(Canon::Simple, &["abc"], Some(4)), "abc\r");
    assert_eq!(par_morceaux(Canon::Simple, &[""], Some(1)), "\r");
}

#[test]
fn le_compte_des_octets_se_lit_en_chemin() {
    let mut machine = BodyCanon::new(Canon::Relaxed, None);
    assert_eq!(machine.written(), 0);
    machine.update(b"abc\r\n", &mut |_| {});
    assert_eq!(machine.written(), 3);
    assert_eq!(machine.finish(&mut |_| {}), 5);
}

#[test]
fn la_machine_se_debogue_et_se_copie() {
    let machine = BodyCanon::new(Canon::Simple, Some(10));
    let copie = machine.clone();
    assert_eq!(copie.written(), machine.written());
    assert!(!std::format!("{machine:?}").is_empty());
}
