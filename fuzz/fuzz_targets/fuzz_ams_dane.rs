// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : DANE** — ce qu'un `TLSA` autorise, et ce qu'il ne doit jamais
//! autoriser.
//!
//! # CE QUI EST HOSTILE ICI
//!
//! Deux choses, et de deux provenances différentes. Le `RDATA` vient du DNS —
//! c'est-à-dire de quiconque peut répondre, tant que la réponse n'est pas
//! authentifiée. Et le certificat vient du pair à qui l'on parle, qui est
//! précisément celui dont on cherche à savoir s'il est bien celui qu'il prétend.
//!
//! Le décodeur X.509 est le morceau délicat : il traverse un certificat en
//! sautant des éléments, et un décodeur qui lirait au-delà de ce qu'on lui donne
//! rendrait une empreinte calculée sur de la mémoire voisine.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets des deux côtés.
//! 2. **UN JEU NON AUTHENTIFIÉ N'ENGAGE JAMAIS.** C'est la propriété qui tient
//!    tout : sans elle, un `TLSA` fabriqué par un tiers ferait exiger un
//!    certificat qu'il aurait choisi.
//! 3. **UN INUTILISABLE NE SATISFAIT RIEN**, et surtout pas tout : un usage
//!    qu'on ne sait pas traiter ne doit jamais devenir un laissez-passer.
//! 4. **LA CLEF RENDUE VIENT DU CERTIFICAT**, et pas d'ailleurs : la tranche est
//!    une sous-suite de ce qu'on a donné à lire.
//! 5. **DEUX CERTIFICATS DIFFÉRENTS NE SATISFONT PAS LE MÊME `3 x 1`** — sauf
//!    collision de SHA-256, ce qui n'arrive pas.

#![no_main]

use ams_dane::{Match, Set, Tlsa, subject_public_key_info};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Entree {
    /// Des `RDATA` arbitraires, tels que le DNS les rendrait.
    rdata: Vec<Vec<u8>>,
    /// Le résolveur a-t-il dit avoir validé ?
    authentique: bool,
    /// Le certificat que le pair présente.
    certificat: Vec<u8>,
    /// Un second, pour éprouver qu'ils ne se confondent pas.
    autre: Vec<u8>,
}

fuzz_target!(|entree: Entree| {
    // ── 1. Lire n'importe quoi ne panique jamais ────────────────────────────
    let _ = subject_public_key_info(&entree.certificat);

    let records: Vec<Tlsa<'_>> = entree
        .rdata
        .iter()
        .filter_map(|octets| Tlsa::parse(octets))
        .collect();

    // ── 4. LA CLEF RENDUE VIENT DU CERTIFICAT ───────────────────────────────
    if let Some(clef) = subject_public_key_info(&entree.certificat) {
        assert!(!clef.is_empty(), "une clef vide");
        assert!(
            clef.len() <= entree.certificat.len(),
            "la clef dépasse le certificat"
        );
        // Une sous-suite, et pas une invention.
        assert!(
            entree
                .certificat
                .windows(clef.len())
                .any(|fenetre| fenetre == clef),
            "la clef ne vient pas du certificat"
        );
    }

    // ── 3. UN INUTILISABLE NE SATISFAIT RIEN ────────────────────────────────
    for record in &records {
        if record.usable() {
            assert!(record.requirement().is_some(), "utilisable sans exigence");
        } else {
            assert!(record.requirement().is_none(), "inutilisable avec exigence");
            assert!(
                !record.matches(&entree.certificat),
                "un inutilisable a été satisfait"
            );
        }
    }

    // ── 2. UN JEU NON AUTHENTIFIÉ N'ENGAGE JAMAIS ───────────────────────────
    let sans = Set::from_records(records.clone(), false);
    assert!(!sans.engage(), "un jeu non authentifié a engagé");
    assert!(!sans.authentic());

    let jeu = Set::from_records(records, entree.authentique);
    assert_eq!(jeu.authentic(), entree.authentique);
    // Engager exige les deux : l'authenticité, et au moins un utilisable.
    assert_eq!(
        jeu.engage(),
        entree.authentique && jeu.usable().count() > 0,
        "l'engagement ne suit pas ses deux conditions"
    );

    // ── 5. DEUX CERTIFICATS NE SE CONFONDENT PAS ────────────────────────────
    //
    // On ne compare que lorsqu'ils diffèrent VRAIMENT : deux tranches d'octets
    // égales sont le même certificat, et doivent évidemment donner la même
    // réponse.
    let verdict = jeu.matching(&entree.certificat);
    if entree.certificat != entree.autre {
        let autre = jeu.matching(&entree.autre);
        // Un `Match::LeafOnly` désigne UN certificat précis : deux certificats
        // différents ne peuvent pas l'obtenir tous les deux du même jeu, sauf
        // collision de SHA-256 — que le fuzzer ne trouvera pas.
        if verdict == Some(Match::LeafOnly) && autre == Some(Match::LeafOnly) {
            let sur_le_certificat = jeu.usable().any(|record| record.selector().code() == 0);
            let sur_la_clef = jeu.usable().any(|record| record.selector().code() == 1);
            // Deux certificats différents peuvent porter la MÊME clef ; c'est
            // même tout l'intérêt du sélecteur `1`, qui survit au
            // renouvellement. Ce n'est donc une anomalie que sur le sélecteur
            // `0`, et seulement s'il est seul.
            assert!(
                sur_la_clef || !sur_le_certificat,
                "deux certificats différents ont satisfait la même empreinte de certificat"
            );
        }
    }
    // Et le même certificat donne toujours la même réponse.
    assert_eq!(jeu.matching(&entree.certificat), verdict);
});
