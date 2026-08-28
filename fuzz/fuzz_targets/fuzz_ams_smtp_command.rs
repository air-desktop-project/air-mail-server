//! Fuzz : le décodage d'une commande SMTP, sur les bornes par défaut.
//!
//! Une ligne de commande est ce qu'un serveur SMTP lit **avant toute
//! authentification** : la surface la plus exposée du produit. Une panique y est
//! un déni de service que n'importe qui peut déclencher en ouvrant une connexion.
//!
//! Huit propriétés sont éprouvées à chaque itération acceptée (cf.
//! `invariants_smtp`), dont deux qui portent le reste : aucun CR ni LF isolé ne
//! survit — la propriété qui ferme la contrebande SMTP — et les deux côtés de
//! l'enveloppe n'admettent jamais la valeur de l'autre.
//!
//! Harnais **pur** : aucune entrée-sortie (C1).

#![no_main]

use ams_proto_smtp::{Command, Limits};
use libfuzzer_sys::fuzz_target;

#[path = "invariants_smtp.rs"]
mod invariants_smtp;

fuzz_target!(|data: &[u8]| {
    let limits = Limits::DEFAULT;
    if let Ok(commande) = Command::parse(data, &limits) {
        invariants_smtp::verifier(data, &commande, &limits);
    }
});
