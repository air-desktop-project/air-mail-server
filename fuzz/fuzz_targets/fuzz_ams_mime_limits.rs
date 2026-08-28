//! Fuzz : le découpage d'`ams-mime` avec des **bornes elles aussi arbitraires**.
//!
//! Les bornes de C3 viennent de la configuration (C8), donc d'un administrateur —
//! qui peut poser un zéro, un `usize::MAX`, ou toute valeur entre les deux. Une
//! borne absurde ne doit produire qu'un refus, jamais un débordement ni une
//! panique.
//!
//! C'est la cible qui garde les CALCULS de borne, là où la première garde la
//! grammaire : `max_line_octets: 0` refuse tout, `usize::MAX` n'a rien à
//! déborder, et les deux doivent tenir les mêmes sept propriétés que le reste.
//!
//! Harnais **pur** : aucune entrée-sortie.

#![no_main]

use ams_mime::{Limits, Message};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[path = "invariants.rs"]
mod invariants;

/// Une entrée : des bornes, et des octets à leur soumettre.
#[derive(Debug, Arbitrary)]
struct Entree {
    max_line_octets: usize,
    max_fields: usize,
    max_header_octets: usize,
    message: Vec<u8>,
}

fuzz_target!(|entree: Entree| {
    let limits = Limits {
        max_line_octets: entree.max_line_octets,
        max_fields: entree.max_fields,
        max_header_octets: entree.max_header_octets,
    };
    if let Ok(message) = Message::parse(&entree.message, &limits) {
        invariants::verifier(&entree.message, &message, &limits);
    }
});
