//! Binaire du serveur air-mail-server.
//!
//! Ce binaire assemblera les quatre protocoles, le stockage et une implémentation
//! d'[`ams_rt`] ; c'est ici que vivront les décisions que les bibliothèques
//! refusent de prendre — quels ports écouter, quels délais d'attente, quelles
//! limites, quelle journalisation.
//!
//! # État
//!
//! **Aucun service n'est rendu.** Les crates de protocole sont des emplacements
//! réservés ; ce `main` ne fait qu'annoncer sa version et le dire.

fn main() {
    println!(
        "air-mail-server {} — squelette : aucun protocole n'est encore servi.",
        env!("CARGO_PKG_VERSION")
    );
}
