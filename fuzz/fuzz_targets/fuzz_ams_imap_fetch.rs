// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : ce qu'un `FETCH` désigne** — l'ensemble de numéros et la liste
//! d'éléments.
//!
//! # Pourquoi celle-ci
//!
//! `FETCH` est la commande qui rend des octets. Ce qu'elle rend est choisi par
//! deux lectures distinctes du même texte : `contains` répond « ce message
//! est-il demandé ? » (chemin `UID FETCH`), et `ranges` énumère « quels
//! messages sont demandés ? » (chemin de l'émission). **Deux lectures qui se
//! contrediraient, c'est un message rendu à qui ne l'a pas demandé** — ou un
//! message tu à qui l'a demandé. Aucun test d'exemple ne couvre les 2^32
//! numéros ; celle-ci les tire au sort.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **UN ENSEMBLE ACCEPTÉ EST BORNÉ** : il ne rend jamais plus
//!    d'intervalles que `max_sequence_items`. Sans cela, un `1:2,1:2,…` de
//!    mille octets ferait mille parcours de boîte par commande.
//! 3. **UN INTERVALLE RENDU EST ORDONNÉ ET NON NUL** : `bas <= haut`, et
//!    `bas >= 1`. Le zéro n'est pas un numéro de message (§9), et un intervalle
//!    à l'envers ferait une boucle qui ne tourne pas.
//! 4. **LES DEUX LECTURES S'ACCORDENT** : `contains(n)` vaut exactement « un
//!    intervalle rendu couvre `n` ».
//! 5. **LE TEXTE RECOPIÉ SE RELIT PAREIL** : `as_bytes` puis `parse` rend les
//!    mêmes intervalles — le texte qu'on retient est bien celui qu'on a lu.
//! 6. **UNE LISTE D'ÉLÉMENTS ACCEPTÉE EST BORNÉE ET COHÉRENTE** :
//!    `items().len()` ne dépasse pas `max_fetch_items`, et une section partielle
//!    ne demande jamais zéro octet — une longueur nulle annoncée serait un
//!    littéral `{0}` que le client attendrait de lire.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_proto_imap::{FETCH_ITEMS_MAX, Fetch, FetchItem, Limits, SequenceSet};

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// Le texte de l'ensemble, tel qu'il arriverait du client.
    ensemble: &'a [u8],
    /// La taille de la boîte, c'est-à-dire ce que vaut `*`.
    star: u32,
    /// Quelques numéros à confronter aux deux lectures.
    numeros: [u32; 4],
    /// Les arguments complets d'un `FETCH`.
    arguments: &'a [u8],
}

/// Rassemble les intervalles rendus, en s'arrêtant à la borne.
fn intervalles(ensemble: &SequenceSet<'_>, star: u32, bornes: &Limits) -> Vec<(u32, u32)> {
    let recus: Vec<(u32, u32)> = ensemble.ranges(star).collect();
    // PROPRIÉTÉ 2 : borné.
    assert!(
        recus.len() <= bornes.max_sequence_items,
        "{} intervalles pour une borne de {}",
        recus.len(),
        bornes.max_sequence_items
    );
    for (bas, haut) in &recus {
        // PROPRIÉTÉ 3 : ordonné, non nul.
        assert!(*bas >= 1, "un intervalle commence à zéro");
        assert!(bas <= haut, "un intervalle rendu est à l'envers");
    }
    recus
}

fuzz_target!(|entree: Entree<'_>| {
    let bornes = Limits::DEFAULT;

    if let Ok(ensemble) = SequenceSet::parse(entree.ensemble, &bornes) {
        let recus = intervalles(&ensemble, entree.star, &bornes);

        // PROPRIÉTÉ 4 : les deux lectures s'accordent.
        for numero in entree.numeros {
            let couvert = recus
                .iter()
                .any(|(bas, haut)| numero >= *bas && numero <= *haut);
            assert_eq!(
                ensemble.contains(numero, entree.star),
                couvert,
                "les deux lectures de {:?} se contredisent sur {numero} (star = {})",
                core::str::from_utf8(ensemble.as_bytes()),
                entree.star
            );
        }

        // PROPRIÉTÉ 5 : le texte retenu se relit pareil.
        let relu =
            SequenceSet::parse(ensemble.as_bytes(), &bornes).expect("un texte accepté se relit");
        assert_eq!(
            relu.ranges(entree.star).collect::<Vec<_>>(),
            recus,
            "le texte recopié ne se relit pas pareil"
        );
    }

    if let Ok(fetch) = Fetch::parse(entree.arguments, &bornes) {
        // PROPRIÉTÉ 6 : borné et cohérent.
        let items = fetch.items();
        assert!(items.len() <= bornes.max_fetch_items.min(FETCH_ITEMS_MAX));
        assert!(!items.is_empty(), "un FETCH accepté ne demande rien");
        for item in items {
            if let FetchItem::Body { partial, .. } = item
                && let Some(partial) = partial
            {
                assert!(partial.length > 0, "une section partielle vide");
            }
        }
        // L'ensemble qu'il porte est celui qu'il a lu, et il est lisible.
        let ensemble = fetch.set();
        assert_eq!(ensemble.as_bytes(), fetch.set_text());
        let _ = intervalles(&ensemble, entree.star, &bornes);
    }
});
