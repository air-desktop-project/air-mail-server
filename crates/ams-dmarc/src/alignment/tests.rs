//! Ce que l'alignement doit tenir.

use super::{Alignment, PublicSuffix, aligned};
use crate::Error;

/// Une liste de suffixes publics d'épreuve.
///
/// Elle en connaît trois, dont un à deux étiquettes — c'est ce dernier qui
/// distingue une implémentation juste d'une implémentation naïve.
struct Suffixes;

impl PublicSuffix for Suffixes {
    fn organizational_domain<'a>(&self, domain: &'a [u8]) -> &'a [u8] {
        for suffixe in [&b".co.uk"[..], b".com", b".net", b".fr"] {
            let Some(reste) = domain.len().checked_sub(suffixe.len()) else {
                continue;
            };
            if !domain
                .get(reste..)
                .is_some_and(|queue| queue.eq_ignore_ascii_case(suffixe))
            {
                continue;
            }
            // Le domaine organisationnel est le suffixe PLUS une étiquette.
            let avant = domain.get(..reste).unwrap_or_default();
            let debut = avant
                .iter()
                .rposition(|octet| *octet == b'.')
                .map_or(0, |rang| rang.saturating_add(1));
            return domain.get(debut..).unwrap_or(domain);
        }
        domain
    }
}

#[test]
fn deux_domaines_identiques_s_alignent_toujours() {
    for mode in [Alignment::Relaxed, Alignment::Strict] {
        assert!(aligned(mode, b"example.com", b"example.com", &Suffixes));
        // La comparaison ignore la casse (RFC 4343) : un domaine écrit en
        // majuscules est le même domaine.
        assert!(aligned(mode, b"EXAMPLE.com", b"example.COM", &Suffixes));
    }
}

#[test]
fn le_mode_strict_n_admet_rien_d_autre() {
    // Un sous-domaine ne s'aligne pas : c'est tout ce que `s` veut dire.
    assert!(!aligned(
        Alignment::Strict,
        b"mail.example.com",
        b"example.com",
        &Suffixes
    ));
    assert!(!aligned(
        Alignment::Strict,
        b"example.com",
        b"mail.example.com",
        &Suffixes
    ));
}

#[test]
fn le_mode_relache_admet_le_meme_domaine_organisationnel() {
    // Dans les deux sens, et sur plusieurs niveaux.
    assert!(aligned(
        Alignment::Relaxed,
        b"mail.example.com",
        b"example.com",
        &Suffixes
    ));
    assert!(aligned(
        Alignment::Relaxed,
        b"example.com",
        b"a.b.c.example.com",
        &Suffixes
    ));
}

#[test]
fn deux_domaines_etrangers_ne_s_alignent_jamais() {
    for mode in [Alignment::Relaxed, Alignment::Strict] {
        assert!(!aligned(mode, b"attaquant.net", b"victime.com", &Suffixes));
        // Et le piège du suffixe : `badexample.com` finit par `example.com`
        // sans en être un sous-domaine.
        assert!(!aligned(mode, b"badexample.com", b"example.com", &Suffixes));
    }
}

#[test]
fn un_suffixe_a_deux_etiquettes_ne_fait_pas_aligner_deux_inconnus() {
    // C'EST LE CŒUR DU SUJET. Une implémentation naïve — « les deux dernières
    // étiquettes » — ferait aligner ces deux-là, c'est-à-dire exactement
    // l'usurpation que DMARC existe pour empêcher.
    assert!(!aligned(
        Alignment::Relaxed,
        b"attaquant.co.uk",
        b"victime.co.uk",
        &Suffixes
    ));
    // Et deux noms sous le MÊME domaine organisationnel, eux, s'alignent.
    assert!(aligned(
        Alignment::Relaxed,
        b"mail.victime.co.uk",
        b"victime.co.uk",
        &Suffixes
    ));
}

#[test]
fn un_domaine_vide_ne_s_aligne_avec_rien() {
    // Il n'y a rien à comparer, et rendre « aligné » ferait passer un message
    // dont aucun mécanisme n'a rien prouvé.
    for mode in [Alignment::Relaxed, Alignment::Strict] {
        assert!(!aligned(mode, b"", b"example.com", &Suffixes));
        assert!(!aligned(mode, b"example.com", b"", &Suffixes));
        assert!(!aligned(mode, b"", b"", &Suffixes));
    }
}

#[test]
fn les_deux_modes_se_lisent_sans_casse() {
    assert_eq!(Alignment::parse(b"r").expect("lisible"), Alignment::Relaxed);
    assert_eq!(Alignment::parse(b"S").expect("lisible"), Alignment::Strict);
    assert_eq!(Alignment::parse(b"x"), Err(Error::UnknownAlignment));
    assert_eq!(Alignment::parse(b""), Err(Error::UnknownAlignment));
    assert_eq!(Alignment::parse(b"relaxed"), Err(Error::UnknownAlignment));
}

#[test]
fn le_defaut_est_relache() {
    // C'est celui de la RFC : un domaine qui n'écrit pas `adkim=` aligne ses
    // sous-domaines, et se tromper de défaut ferait échouer son courrier.
    assert_eq!(Alignment::default(), Alignment::Relaxed);
    assert_eq!(Alignment::Relaxed.name(), b"r");
    assert_eq!(Alignment::Strict.name(), b"s");
}

#[test]
fn la_liste_se_prete_par_reference() {
    // `impl PublicSuffix for &T` : l'appelant qui n'a qu'une référence n'a pas
    // à la recopier.
    let par_reference: &dyn PublicSuffix = &Suffixes;
    assert_eq!(
        par_reference.organizational_domain(b"mail.example.com"),
        b"example.com"
    );
    let liste = &Suffixes;
    assert!(aligned(
        Alignment::Relaxed,
        b"mail.example.com",
        b"example.com",
        &liste
    ));
}

#[test]
fn les_types_se_deboguent_et_se_comparent() {
    assert!(!std::format!("{:?}", Alignment::Strict).is_empty());
    assert_ne!(Alignment::Relaxed, Alignment::Strict);
    let copie = Alignment::Strict;
    assert_eq!(copie, Alignment::Strict);
}
