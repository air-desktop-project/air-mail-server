// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qui est propre au magasin des mots de passe applicatifs : la recherche
//! par compte, et la date de dernière utilisation à l'heure près.

use std::path::PathBuf;

use ams_auth::AppPassword;

use super::{Applicatifs, PRECISION_SECONDES};

/// Un répertoire d'essai, effacé quand il tombe.
struct Atelier(PathBuf);

impl Drop for Atelier {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn atelier(nom: &str) -> Atelier {
    let chemin = std::env::temp_dir().join(std::format!(
        "ams-applicatifs-{nom}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&chemin);
    std::fs::create_dir_all(&chemin).expect("un répertoire d'essai");
    Atelier(chemin)
}

fn entree(login: &str, id: &str, vu: u64) -> AppPassword {
    AppPassword {
        login: login.into(),
        id: id.into(),
        name: "Thunderbird".into(),
        created: 1_790_000_000,
        last_used: vu,
        digest: [1; 32],
    }
}

/// Un magasin sur disque, avec ces entrées.
fn magasin(atelier: &Atelier, entrees: &[AppPassword]) -> Applicatifs {
    let chemin = atelier.0.join("applicatifs.bin");
    std::fs::write(
        &chemin,
        ams_config::encode_app_passwords(entrees).expect("encodable"),
    )
    .expect("écriture");
    Applicatifs::new(chemin, entrees.to_vec())
}

const A: &str = "0123456789abcdef";
const B: &str = "fedcba9876543210";

#[test]
fn chacun_ne_voit_que_les_siens() {
    let atelier = atelier("siens");
    let magasin = magasin(&atelier, &[entree("marie", A, 0), entree("paul", B, 0)]);
    let siens = magasin.du_compte("marie");
    assert_eq!(siens.len(), 1);
    assert_eq!(siens.first().map(|e| e.id.as_str()), Some(A));
    assert!(magasin.du_compte("personne").is_empty());
}

/// **LA DATE SE NOTE, MAIS PAS À CHAQUE FOIS** : à l'heure près, sans quoi
/// chaque relève de courrier réécrirait le fichier.
#[tokio::test(flavor = "multi_thread")]
async fn l_usage_se_note_a_l_heure_pres() {
    let atelier = atelier("usage");
    let magasin = magasin(&atelier, &[entree("marie", A, 0)]);
    let date = |magasin: &Applicatifs| {
        magasin
            .du_compte("marie")
            .first()
            .map_or(u64::MAX, |e| e.last_used)
    };

    // Jamais servi : la première utilisation s'écrit.
    magasin.noter_l_usage(A, 1_790_000_000);
    assert_eq!(date(&magasin), 1_790_000_000);
    // Et elle est sur le disque, pas seulement en mémoire.
    let relu = ams_config::decode_app_passwords(
        &std::fs::read(atelier.0.join("applicatifs.bin")).expect("lisible"),
    )
    .expect("relisible");
    assert_eq!(relu.first().map(|e| e.last_used), Some(1_790_000_000));

    // Moins d'une heure après : rien ne bouge.
    magasin.noter_l_usage(A, 1_790_000_000 + PRECISION_SECONDES - 1);
    assert_eq!(date(&magasin), 1_790_000_000);
    // Une heure après : elle avance.
    magasin.noter_l_usage(A, 1_790_000_000 + PRECISION_SECONDES);
    assert_eq!(date(&magasin), 1_790_000_000 + PRECISION_SECONDES);
}

/// **UN ÉCHEC D'ÉCRITURE NE PANIQUE PAS ET NE CHANGE RIEN** : la date n'informe
/// que le propriétaire, et la session s'ouvre quand même.
#[tokio::test(flavor = "multi_thread")]
async fn une_entree_disparue_ne_fait_rien() {
    let atelier = atelier("disparue");
    let magasin = magasin(&atelier, &[entree("marie", A, 0)]);
    magasin.noter_l_usage(B, 1_790_000_000);
    assert_eq!(
        magasin.du_compte("marie").first().map(|e| e.last_used),
        Some(0)
    );
}
