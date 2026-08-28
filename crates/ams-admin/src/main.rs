//! L'outil de contrôle et de configuration — binaire `air-mail-admin` (C12).
//!
//! La configuration d'air-mail-server est un fichier binaire Cap'n Proto (C11),
//! donc **pas éditable à la main**. Cet outil en est le seul moyen de production
//! et de lecture ; ce n'est pas une commodité, c'est la conséquence de C11.
//!
//! # État
//!
//! **Aucune commande n'existe.** Ce `main` annonce sa version et le dit.

fn main() {
    println!(
        "air-mail-admin {} — squelette : aucune commande n'est encore disponible.",
        env!("CARGO_PKG_VERSION")
    );
}
