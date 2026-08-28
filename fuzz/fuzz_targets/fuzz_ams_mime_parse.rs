//! Fuzz : le découpage d'un message par `ams-mime`, sur les bornes par défaut.
//!
//! Un message est **la** donnée externe d'un serveur de courrier : n'importe qui
//! peut en composer un et l'envoyer. Une panique dans ce décodeur serait un déni
//! de service offert à qui sait écrire quinze octets.
//!
//! Sept propriétés sont éprouvées à chaque itération acceptée (cf. `invariants`),
//! dont deux qui portent tout le reste : le découpage ne perd ni n'invente aucun
//! octet, et **aucun CR ni LF isolé ne survit dans l'en-tête** — la propriété qui
//! ferme la contrebande SMTP.
//!
//! Harnais **pur** : aucune entrée-sortie, conformément à ce que la crate
//! elle-même s'interdit (C1).

#![no_main]

use ams_mime::{Limits, Message};
use libfuzzer_sys::fuzz_target;

#[path = "invariants.rs"]
mod invariants;

fuzz_target!(|data: &[u8]| {
    let limits = Limits::DEFAULT;
    if let Ok(message) = Message::parse(data, &limits) {
        invariants::verifier(data, &message, &limits);
    }
});
