// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : MTA-STS** — une politique écrite par un serveur qu'on ne choisit
//! pas.
//!
//! # CE QUI EST HOSTILE ICI
//!
//! Tout. Le `TXT` vient du DNS, sans authentification ; la politique vient d'un
//! `https://` dont le certificat a été vérifié — mais le certificat prouve QUI
//! parle, pas que ce qu'il dit est bien formé. Un domaine compromis, ou
//! simplement mal configuré, écrit ce qu'il veut dans son propre fichier.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **LE JOKER COUVRE EXACTEMENT UNE ÉTIQUETTE.** C'est la propriété qui
//!    compte : un joker qui en couvrirait deux laisserait un sous-domaine
//!    délégué à un tiers recevoir le courrier du domaine entier.
//! 3. **CE QU'UNE POLITIQUE PERMET VIENT DE SES `mx`, ET DE RIEN D'AUTRE.** Un
//!    nom permis correspond à l'un des motifs lus.
//! 4. **UN NOM DE CACHE ÉCRIT SE RELIT À L'IDENTIQUE, ET NE SORT PAS DU
//!    RÉPERTOIRE.**
//! 5. **UNE ENTRÉE VENUE DU FUTUR EST PÉRIMÉE** : une horloge qu'on remet à
//!    l'heure ne prolonge pas un cache.

#![no_main]

use ams_mtasts::{Entry, MX_MAX, Mode, NAME_MAX, parse_id, parse_name, parse_policy, write_name};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Entree {
    /// Un `TXT` arbitraire.
    txt: String,
    /// Une politique arbitraire.
    politique: String,
    /// Un nom de serveur à confronter à la politique.
    hote: String,
    /// Un nom de cache arbitraire, à relire.
    nom: String,
    /// De quoi composer un nom de cache.
    recuperee: u64,
    identifiant: String,
    domaine: String,
    /// L'heure qu'il est, et la durée de validité.
    maintenant: u64,
    age: u32,
}

fuzz_target!(|entree: Entree| {
    // ── 1. Lire n'importe quoi ne panique jamais ────────────────────────────
    let _ = parse_id(&entree.txt);
    let _ = parse_name(&entree.nom);

    let mut place = vec![""; MX_MAX + 1];
    if let Ok(politique) = parse_policy(&entree.politique, &mut place) {
        // La borne de C3 est celle de la crate, quelle que soit la place donnée.
        assert!(
            politique.mx().len() <= MX_MAX,
            "plus de motifs que la borne"
        );
        // `enforce` et `testing` exigent au moins un serveur ; `none` non.
        if politique.mode() != Mode::None {
            assert!(!politique.mx().is_empty(), "une politique sans serveur");
        }
        assert!(politique.max_age() > 0, "une politique sans durée");

        // ── 3. CE QU'ELLE PERMET VIENT DE SES `mx` ──────────────────────────
        if politique.allows(&entree.hote) {
            assert!(
                politique
                    .mx()
                    .iter()
                    .any(|motif| correspond(motif, &entree.hote)),
                "un nom permis ne correspond à aucun motif"
            );
        }

        // ── 2. LE JOKER COUVRE EXACTEMENT UNE ÉTIQUETTE ─────────────────────
        //
        // Pour chaque motif à joker, on fabrique un nom à DEUX étiquettes de
        // plus et l'on exige qu'il ne passe pas par CE motif.
        for motif in politique.mx() {
            let Some(suffixe) = motif.strip_prefix("*.") else {
                continue;
            };
            let trop = format!("a.b.{suffixe}");
            assert!(
                !correspond(motif, &trop),
                "« {motif} » a couvert deux étiquettes"
            );
            // Et zéro étiquette non plus.
            assert!(
                !correspond(motif, suffixe),
                "« {motif} » a couvert zéro étiquette"
            );
        }
    }

    // ── 4. UN NOM ÉCRIT SE RELIT, ET NE SORT PAS ────────────────────────────
    let voulue = Entry {
        fetched: entree.recuperee,
        id: &entree.identifiant,
        domain: &entree.domaine,
    };
    let mut tampon = [0_u8; NAME_MAX];
    if let Ok(ecrit) = write_name(&voulue, &mut tampon) {
        assert_eq!(
            parse_name(ecrit),
            Some(voulue),
            "« {ecrit} » ne se relit pas"
        );
        assert!(
            !ecrit.contains('/'),
            "« {ecrit} » désigne un autre répertoire"
        );
        assert!(!ecrit.starts_with('.'), "« {ecrit} » se cacherait");
        assert!(
            ecrit.ends_with(".mtasts"),
            "« {ecrit} » n'est pas une entrée"
        );
        assert!(ecrit.is_ascii(), "« {ecrit} » n'est pas de l'ASCII");

        // ── 5. UNE ENTRÉE VENUE DU FUTUR EST PÉRIMÉE ────────────────────────
        if entree.recuperee > entree.maintenant {
            assert!(
                !voulue.fresh(entree.age, entree.maintenant),
                "un cache venu du futur est resté frais"
            );
        }
        // Et une durée nulle ne garde jamais rien.
        assert!(!voulue.fresh(0, entree.maintenant));
    }
});

/// La même règle que `Policy::allows`, réécrite : un harnais qui appellerait la
/// fonction éprouvée ne prouverait rien.
fn correspond(motif: &str, hote: &str) -> bool {
    match motif.strip_prefix("*.") {
        None => motif.eq_ignore_ascii_case(hote),
        Some(suffixe) => match hote.split_once('.') {
            Some((etiquette, reste)) => {
                !etiquette.is_empty() && reste.eq_ignore_ascii_case(suffixe)
            }
            None => false,
        },
    }
}
