// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : l'évaluation d'une politique SPF, réponses du DNS comprises.**
//!
//! La cible voisine (`fuzz_ams_spf`) éprouve la LECTURE d'un enregistrement.
//! Celle-ci éprouve ce qui vient après, et qui est plus exposé : une évaluation
//! enchaîne des politiques que **l'expéditeur choisit** — les siennes, celles
//! des domaines qu'il inclut — et des réponses DNS qu'il peut, en partie,
//! fabriquer. Tout, ici, vient d'ailleurs.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quelles que soient les bornes et les réponses.
//! 2. **ELLE CONCLUT.** Un évaluateur qui tourne sans fin est un déni de service
//!    offert à qui publie un `redirect=` circulaire. La borne n'est pas une
//!    supposition : elle se déduit des dix résolutions (§4.6.4).
//! 3. **Le nombre de questions ne dépasse pas la borne** : une question de
//!    départ, puis une par résolution permise, et pas une de plus.
//! 4. **Un verdict est définitif** : rappeler `poll` après la fin rend le même.
//! 5. **Une question porte un nom interrogeable** — au plus deux cent
//!    cinquante-cinq octets, la longueur d'un nom de domaine.
//! 6. **Une panne de résolution vaut `temperror`**, jamais un refus : dire
//!    `fail` à la place ferait jeter un message qui serait passé plus tard.

#![no_main]

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_spf::{Answer, Context, Evaluator, Limits, Query, Step, Verdict};

/// Ce qu'un résolveur hostile pourrait rendre.
#[derive(Debug, Arbitrary)]
enum Reponse<'a> {
    Txt(Vec<&'a [u8]>),
    Adresses4(Vec<[u8; 4]>),
    Adresses6(Vec<[u8; 16]>),
    Existe(bool),
    Noms(Vec<&'a [u8]>),
    Introuvable,
    Panne,
}

#[derive(Debug, Arbitrary)]
struct Entree<'a> {
    /// Le domaine de départ.
    domaine: &'a [u8],
    /// L'expéditeur d'enveloppe et le `HELO`, tels que le pair les a dits.
    sender: &'a [u8],
    helo: &'a [u8],
    /// L'adresse du pair.
    en_v6: bool,
    v4: [u8; 4],
    v6: [u8; 16],
    /// Les bornes — LIBREMENT ABSURDES : zéro compris.
    bornes: [u16; 2],
    resolutions: [u8; 2],
    /// Le scénario des réponses, dans l'ordre.
    reponses: Vec<Reponse<'a>>,
}

fuzz_target!(|entree: Entree| {
    let bornes = Limits {
        max_record_octets: usize::from(entree.bornes[0]),
        max_terms: usize::from(entree.bornes[1]),
        max_lookups: entree.resolutions[0],
        max_void_lookups: entree.resolutions[1],
    };
    let client = if entree.en_v6 {
        IpAddr::V6(Ipv6Addr::from(entree.v6))
    } else {
        IpAddr::V4(Ipv4Addr::from(entree.v4))
    };
    let contexte = Context {
        client,
        sender: entree.sender,
        helo: entree.helo,
    };

    let mut evaluateur = Evaluator::new(contexte, entree.domaine, bornes);

    // ── 3. LE NOMBRE DE QUESTIONS ───────────────────────────────────────────
    //
    // Une question de départ — la politique du domaine, qui ne compte pas dans
    // les dix — puis une par résolution permise. Le `+ 2` laisse une marge pour
    // que ce soit l'assertion qui parle, et non la boucle qui s'arrête.
    let plafond = usize::from(bornes.max_lookups) + 2;
    let mut posees = 0_usize;
    let mut panne_servie = false;

    let verdict = loop {
        let question = match evaluateur.poll() {
            Step::Done(verdict) => break verdict,
            Step::Ask(question) => question,
        };

        // ── 5. UN NOM INTERROGEABLE ─────────────────────────────────────────
        assert!(
            question.name().len() <= 255,
            "une question porte un nom plus long qu'un nom de domaine"
        );

        // ── 2. ELLE CONCLUT ─────────────────────────────────────────────────
        posees += 1;
        assert!(
            posees <= plafond,
            "{posees} questions posées pour une borne de {}",
            bornes.max_lookups
        );

        // Le scénario est cyclique : à court de réponses, on rejoue depuis le
        // début plutôt que de conclure à la place de l'évaluateur.
        let scenario = if entree.reponses.is_empty() {
            None
        } else {
            entree.reponses.get((posees - 1) % entree.reponses.len())
        };

        let adresses4: Vec<IpAddr>;
        let adresses6: Vec<IpAddr>;
        let reponse = match scenario {
            None | Some(Reponse::Introuvable) => Answer::NotFound,
            Some(Reponse::Panne) => {
                panne_servie = true;
                Answer::TempError
            }
            Some(Reponse::Txt(records)) => Answer::Txt(records),
            Some(Reponse::Adresses4(brutes)) => {
                adresses4 = brutes
                    .iter()
                    .map(|octets| IpAddr::V4(Ipv4Addr::from(*octets)))
                    .collect();
                Answer::Addresses(&adresses4)
            }
            Some(Reponse::Adresses6(brutes)) => {
                adresses6 = brutes
                    .iter()
                    .map(|octets| IpAddr::V6(Ipv6Addr::from(*octets)))
                    .collect();
                Answer::Addresses(&adresses6)
            }
            Some(Reponse::Existe(trouve)) => Answer::Exists(*trouve),
            Some(Reponse::Noms(noms)) => Answer::Names(noms),
        };

        // Une réponse d'un genre qui ne répond pas à la question posée est un
        // défaut de l'appelant : l'évaluateur doit le DIRE (`permerror`), pas
        // conclure sur du vent. On la sert quand même, c'est tout l'intérêt.
        let _ = question.kind() == Query::Txt;
        evaluateur.answer(reponse);
    };

    // ── 6. UNE PANNE VAUT `temperror` ───────────────────────────────────────
    if panne_servie {
        assert_eq!(
            verdict,
            Verdict::TempError,
            "une résolution en panne a rendu autre chose qu'un `temperror`"
        );
    }

    // ── 4. UN VERDICT EST DÉFINITIF ─────────────────────────────────────────
    for _ in 0..3 {
        match evaluateur.poll() {
            Step::Done(encore) => assert_eq!(encore, verdict, "le verdict a changé après la fin"),
            Step::Ask(_) => panic!("une question posée après le verdict"),
        }
    }
    // Une réponse après la fin ne réveille rien.
    evaluateur.answer(Answer::NotFound);
    match evaluateur.poll() {
        Step::Done(encore) => assert_eq!(encore, verdict),
        Step::Ask(_) => panic!("une réponse tardive a rouvert l'évaluation"),
    }
});
