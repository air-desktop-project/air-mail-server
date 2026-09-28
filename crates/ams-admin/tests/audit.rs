// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **`air-mail-admin audit` lit le journal d'audit d'un compte** (phase 6).
//!
//! Ces essais lancent le binaire : ce qu'on éprouve est ce qu'on livre — la
//! configuration qui nomme le répertoire, la lecture des deux fichiers, l'ordre,
//! la borne, et les refus.

use std::path::PathBuf;
use std::process::Command;

/// Un répertoire d'essai, effacé quand il tombe.
struct Atelier(PathBuf);

impl Drop for Atelier {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn atelier(nom: &str) -> Atelier {
    let chemin = std::env::temp_dir().join(format!("ams-admin-{nom}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&chemin);
    std::fs::create_dir_all(&chemin).expect("un répertoire d'essai");
    Atelier(chemin)
}

/// Lance l'outil ; rend sa sortie standard, son erreur, et son code.
fn outil(arguments: &[&str]) -> (String, String, Option<i32>) {
    let issue = Command::new(env!("CARGO_BIN_EXE_air-mail-admin"))
        .args(arguments)
        .output()
        .expect("l'outil se lance");
    (
        String::from_utf8_lossy(&issue.stdout).into_owned(),
        String::from_utf8_lossy(&issue.stderr).into_owned(),
        issue.status.code(),
    )
}

/// Écrit une configuration, avec ou sans journal d'audit.
fn configuration(atelier: &Atelier, audit: Option<&str>) -> String {
    let fichier = atelier.0.join("ams.conf").display().to_string();
    let mut arguments = vec![
        "config",
        "write",
        fichier.as_str(),
        "--domain",
        "mail.example.com",
        "--hosted",
        "example.com",
    ];
    if let Some(repertoire) = audit {
        arguments.extend(["--audit", repertoire]);
    }
    let (_, erreur, code) = outil(&arguments);
    assert_eq!(code, Some(0), "{erreur}");
    fichier
}

#[test]
fn le_journal_se_lit_le_plus_recent_d_abord_et_borne() {
    let atelier = atelier("audit-lire");
    let repertoire = atelier.0.join("audit");
    std::fs::create_dir_all(&repertoire).expect("répertoire");
    let entree =
        |quand: u32| format!("{{\"at\":{quand},\"event\":\"session.opened\",\"source\":null}}\n");
    // L'ancien fichier, puis le courant — et une ligne interrompue à la fin.
    std::fs::write(repertoire.join("marie.1.jsonl"), entree(1) + &entree(2)).expect("écriture");
    std::fs::write(
        repertoire.join("marie.jsonl"),
        entree(3) + &entree(4) + "{\"at\":5,\"ev",
    )
    .expect("écriture");
    let fichier = configuration(&atelier, Some(&repertoire.display().to_string()));

    let (sortie, erreur, code) = outil(&["audit", &fichier, "--login", "marie"]);
    assert_eq!(code, Some(0), "{erreur}");
    let dates: Vec<&str> = sortie
        .lines()
        .map(|ligne| ligne.split(',').next().unwrap_or_default())
        .collect();
    assert_eq!(
        dates,
        ["{\"at\":4", "{\"at\":3", "{\"at\":2", "{\"at\":1"],
        "{sortie}"
    );

    let (sortie, _, code) = outil(&["audit", &fichier, "--login", "marie", "--limit", "1"]);
    assert_eq!(code, Some(0));
    assert_eq!(sortie.lines().count(), 1);

    // Un compte sans journal : rien, et ce n'est pas une faute.
    let (sortie, _, code) = outil(&["audit", &fichier, "--login", "paul"]);
    assert_eq!((sortie.as_str(), code), ("", Some(0)));

    // **UN NOM QUI N'EST PAS UN COMPTE NE DEVIENT PAS UN CHEMIN.**
    let (_, _, code) = outil(&["audit", &fichier, "--login", "../marie"]);
    assert_eq!(code, Some(2));
    let (_, _, code) = outil(&["audit", &fichier, "--login", "marie", "--limit", "0"]);
    assert_eq!(code, Some(2));
}

#[test]
fn sans_journal_la_commande_le_dit() {
    let atelier = atelier("audit-absent");
    let fichier = configuration(&atelier, None);
    let (_, erreur, code) = outil(&["audit", &fichier, "--login", "marie"]);
    assert_eq!(code, Some(1));
    assert!(erreur.contains("--audit"), "{erreur}");

    let (sortie, _, code) = outil(&["config", "show", &fichier]);
    assert_eq!(code, Some(0));
    assert!(sortie.contains("journal d'audit    AUCUN"), "{sortie}");

    let (_, erreur, code) = outil(&["audit", "/nulle/part.conf", "--login", "marie"]);
    assert_eq!(code, Some(1));
    assert!(erreur.contains("/nulle/part.conf"), "{erreur}");
}
