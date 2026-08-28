//! Fuzz : le décodage d'une commande SMTP avec des **bornes arbitraires**.
//!
//! Les cinq bornes de C3 viennent de la configuration (C8), donc d'un
//! administrateur : un zéro, un `usize::MAX`, ou toute valeur entre les deux. Une
//! borne absurde ne doit produire qu'un refus, jamais un débordement.
//!
//! Harnais **pur** : aucune entrée-sortie.

#![no_main]

use ams_proto_smtp::{Command, Limits};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[path = "invariants_smtp.rs"]
mod invariants_smtp;

/// Une entrée : des bornes, et une ligne à leur soumettre.
#[derive(Debug, Arbitrary)]
struct Entree {
    max_command_octets: usize,
    max_local_part_octets: usize,
    max_domain_octets: usize,
    max_path_octets: usize,
    max_parameters: usize,
    ligne: Vec<u8>,
}

fuzz_target!(|entree: Entree| {
    let limits = Limits {
        max_command_octets: entree.max_command_octets,
        max_local_part_octets: entree.max_local_part_octets,
        max_domain_octets: entree.max_domain_octets,
        max_path_octets: entree.max_path_octets,
        max_parameters: entree.max_parameters,
    };
    if let Ok(commande) = Command::parse(&entree.ligne, &limits) {
        invariants_smtp::verifier(&entree.ligne, &commande, &limits);
    }
});
