// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : la politique DMARC d'un domaine, et l'alignement qu'elle exige.**
//!
//! L'enregistrement vient du DNS, c'est-à-dire d'un domaine que **l'expéditeur
//! choisit** — celui de son propre `From:`. Les domaines comparés viennent, eux,
//! de SPF et de DKIM : ce sont des noms qu'un pair a écrits.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **Un enregistrement accepté commence par `v=DMARC1` et porte un `p=`.**
//!    Ce sont les deux choses sans lesquelles la RFC 7489 §6.6.3 l'écarte.
//! 3. **L'alignement est RÉFLEXIF ET SYMÉTRIQUE** : un domaine s'aligne avec
//!    lui-même, et l'ordre des deux ne change rien. Une comparaison qui
//!    dépendrait de l'ordre ferait passer un message dans un sens et pas dans
//!    l'autre.
//! 4. **Le mode strict est plus étroit que le relâché** : ce que `s` aligne, `r`
//!    l'aligne aussi. L'inverse ferait qu'un domaine qui durcit sa politique
//!    laisserait passer davantage.
//! 5. **Un verdict de réussite exige un mécanisme aligné**, et un domaine vide
//!    n'aligne rien.
//! 6. **Le pourcentage tient dans ses bornes** : de zéro à cent, jamais
//!    au-delà.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_dmarc::{
    Alignment, Authentication, POLICY_NAME_MAX, PublicSuffix, Record, Verdict, aligned, evaluate,
    policy_name,
};

/// Une liste de suffixes publics d'épreuve : elle en connaît trois, dont un à
/// deux étiquettes — c'est celui-là qui distingue une implémentation juste
/// d'une implémentation naïve.
struct Suffixes;

impl PublicSuffix for Suffixes {
    fn organizational_domain<'a>(&self, domain: &'a [u8]) -> &'a [u8] {
        for suffixe in [&b".co.uk"[..], b".com", b".net"] {
            let Some(reste) = domain.len().checked_sub(suffixe.len()) else {
                continue;
            };
            if !domain
                .get(reste..)
                .is_some_and(|queue| queue.eq_ignore_ascii_case(suffixe))
            {
                continue;
            }
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

#[derive(Debug, Arbitrary)]
struct Entree<'a> {
    /// L'enregistrement `_dmarc`, tel que le DNS le rend.
    enregistrement: &'a [u8],
    /// Le domaine du `From:`, et ceux que SPF et DKIM ont authentifiés.
    from: &'a [u8],
    spf: Option<&'a [u8]>,
    dkim: Vec<&'a [u8]>,
    /// Le `From:` est-il un sous-domaine de celui qui publie ?
    sous_domaine: bool,
}

fuzz_target!(|entree: Entree| {
    // ── 3, 4 : ce que l'alignement promet ───────────────────────────────────
    for gauche in [entree.from, entree.spf.unwrap_or_default()] {
        for droite in [entree.from, entree.spf.unwrap_or_default()] {
            for mode in [Alignment::Relaxed, Alignment::Strict] {
                let ici = aligned(mode, gauche, droite, &Suffixes);
                assert_eq!(
                    ici,
                    aligned(mode, droite, gauche, &Suffixes),
                    "l'alignement dépend de l'ordre"
                );
            }
            // Le strict est plus étroit que le relâché.
            if aligned(Alignment::Strict, gauche, droite, &Suffixes) {
                assert!(
                    aligned(Alignment::Relaxed, gauche, droite, &Suffixes),
                    "le mode strict aligne ce que le relâché refuse"
                );
            }
        }
        // Un domaine non vide s'aligne avec lui-même, dans les deux modes.
        if !gauche.is_empty() {
            assert!(aligned(Alignment::Strict, gauche, gauche, &Suffixes));
            assert!(aligned(Alignment::Relaxed, gauche, gauche, &Suffixes));
        }
    }

    // ── Le nom où chercher la politique ─────────────────────────────────────
    let mut nom = [0_u8; POLICY_NAME_MAX];
    if let Ok(ecrit) = policy_name(entree.from, &mut nom) {
        assert!(
            ecrit.starts_with(b"_dmarc."),
            "le nom ne porte pas son préfixe"
        );
        assert_eq!(&ecrit[7..], entree.from, "le domaine a été altéré");
    }

    // ── 1, 2 : l'enregistrement ─────────────────────────────────────────────
    let Ok(enregistrement) = Record::parse(entree.enregistrement) else {
        return;
    };
    assert!(
        entree.enregistrement.trim_ascii_start().len() >= 8,
        "un enregistrement accepté porte au moins `v=DMARC1`"
    );
    // ── 6 : le pourcentage ──────────────────────────────────────────────────
    assert!(enregistrement.percent <= 100, "un pourcentage hors bornes");

    // ── 5 : le verdict ──────────────────────────────────────────────────────
    let authentification = Authentication {
        spf: entree.spf,
        dkim: &entree.dkim,
    };
    let juge = evaluate(
        &enregistrement,
        entree.from,
        entree.sous_domaine,
        &authentification,
        &Suffixes,
    );
    assert_eq!(juge.percent, enregistrement.percent);
    assert_eq!(
        juge.policy,
        enregistrement.applicable(entree.sous_domaine),
        "la politique rendue n'est pas celle qui s'applique"
    );

    if entree.from.is_empty() {
        assert_eq!(
            juge.verdict,
            Verdict::Fail,
            "un `From:` vide s'est aligné avec quelque chose"
        );
    }
    if juge.verdict == Verdict::Pass {
        // Une réussite EXIGE un mécanisme aligné : il doit être possible de
        // dire lequel.
        let par_spf = entree.spf.is_some_and(|enveloppe| {
            aligned(
                enregistrement.spf_alignment,
                enveloppe,
                entree.from,
                &Suffixes,
            )
        });
        let par_dkim = entree
            .dkim
            .iter()
            .any(|signe| aligned(enregistrement.dkim_alignment, signe, entree.from, &Suffixes));
        assert!(par_spf || par_dkim, "une réussite sans mécanisme aligné");
    }
});
