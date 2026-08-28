//! Le serveur air-mail-server — binaire `air-mail-server` (C12).
//!
//! Il assemblera les codecs, les machines à états de session et une boucle
//! d'entrées-sorties choisie par cible (C5) : tokio sur Unix, le moteur d'Air sur
//! `*-linux-air`.
//!
//! # État
//!
//! **Aucun service n'est rendu.** Toutes les crates de protocole sont des
//! emplacements réservés ; ce `main` annonce sa version et le dit.

fn main() {
    println!(
        "air-mail-server {} — squelette : aucun protocole n'est encore servi.",
        env!("CARGO_PKG_VERSION")
    );
}
