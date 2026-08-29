// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : l'enregistrement SPF d'un domaine qu'on interroge.**
//!
//! Ces octets-là viennent du DNS, c'est-à-dire d'un domaine que **l'expéditeur
//! choisit**. Un serveur qui panique en lisant l'enregistrement d'autrui offre
//! son arrêt à qui sait publier un TXT.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quelles que soient les bornes.
//! 2. **La validation est d'un seul tenant** : un enregistrement accepté se
//!    reparcourt en entier sans jamais échouer, et rend toujours les mêmes
//!    termes. Un parcours qui dépendrait de ce qu'on lui demande appliquerait
//!    une politique différente selon le pair.
//! 3. **Les bornes sont tenues** : ni plus de termes ni plus d'octets que ce
//!    qu'on a permis (C3).
//! 4. **Un mécanisme qui répond sans DNS répond toujours la même chose** pour la
//!    même adresse, et jamais `None` ; un mécanisme qui résout ne répond jamais.

#![no_main]

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_spf::{Limits, Mechanism, Record, Term};

#[derive(Debug, Arbitrary)]
struct Entree<'a> {
    /// Le TXT, tel qu'un domaine le publie.
    txt: &'a [u8],
    /// Les bornes — LIBREMENT ABSURDES : zéro compris.
    bornes: [u16; 2],
    /// L'adresse du pair, dans les deux familles.
    v4: [u8; 4],
    v6: [u8; 16],
}

fuzz_target!(|entree: Entree| {
    let bornes = Limits {
        max_record_octets: usize::from(entree.bornes[0]),
        max_terms: usize::from(entree.bornes[1]),
    };

    let Ok(enregistrement) = Record::parse(entree.txt, &bornes) else {
        // Refusé : pas du SPF, trop long, trop de termes, ou mal formé. C'est
        // le lecteur qui fait son travail.
        //
        // On repasse tout de même avec les bornes du produit : ce sont celles
        // qui serviront, et elles ne doivent pas paniquer davantage.
        let _ = Record::parse(entree.txt, &Limits::DEFAULT);
        return;
    };

    // ── 2. LA VALIDATION EST D'UN SEUL TENANT ───────────────────────────────
    let premiers: Vec<Term<'_>> = enregistrement.terms().collect();
    let seconds: Vec<Term<'_>> = enregistrement.terms().collect();
    assert_eq!(
        premiers, seconds,
        "deux parcours ont rendu des termes différents"
    );

    // ── 3. LES BORNES SONT TENUES ───────────────────────────────────────────
    assert!(entree.txt.len() <= bornes.max_record_octets);
    assert!(
        premiers.len() <= bornes.max_terms,
        "plus de termes que la borne ne permet"
    );

    // ── 4. LES RÉPONSES SANS DNS ────────────────────────────────────────────
    for client in [
        IpAddr::V4(Ipv4Addr::from(entree.v4)),
        IpAddr::V6(Ipv6Addr::from(entree.v6)),
    ] {
        for terme in &premiers {
            let Term::Mechanism { mechanism, .. } = terme else {
                continue;
            };
            let reponse = mechanism.matches_without_dns(client);
            // Deux fois la même question, deux fois la même réponse : une
            // comparaison d'adresses ne dépend de rien d'autre.
            assert_eq!(reponse, mechanism.matches_without_dns(client));
            match mechanism {
                Mechanism::All => assert_eq!(reponse, Some(true), "`all` doit correspondre"),
                Mechanism::Ip4 { .. } | Mechanism::Ip6 { .. } => {
                    assert!(reponse.is_some(), "une adresse littérale sait répondre");
                }
                // Ceux-là ne répondent JAMAIS : répondre `false` à leur place
                // les ferait passer pour « ne correspond pas », ce qui est une
                // réponse — et ils n'en ont pas encore.
                Mechanism::A(_)
                | Mechanism::Mx(_)
                | Mechanism::Include(_)
                | Mechanism::Exists(_)
                | Mechanism::Ptr(_) => {
                    assert_eq!(reponse, None, "un mécanisme qui résout a répondu seul");
                }
            }
        }
    }
});
