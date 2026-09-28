// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **`air-mail-admin device` liste et révoque les appareils** (0.2.41) — la
//! voie de secours quand un utilisateur a perdu son seul téléphone.
//!
//! Ces essais lancent le binaire, sur un magasin écrit à la main.

use std::path::PathBuf;
use std::process::Command;

/// Le point générateur de P-256 : une clef valide, qui n'ouvre rien.
const POINT: [u8; 65] = [
    0x04, 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40,
    0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2,
    0x96, 0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E,
    0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51,
    0xF5,
];

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

fn appareil(login: &str, id: &str, nom: &str) -> ams_config::Device {
    ams_config::Device {
        login: String::from(login),
        id: String::from(id),
        name: String::from(nom),
        public_key: ams_auth::Cle::lire(&POINT).expect("le point générateur"),
        enrolled: 1_790_000_000,
        last_seen: 1_790_003_600_000,
        push: None,
        attestation: Some(ams_config::Attested::Tee),
    }
}

fn relire(fichier: &std::path::Path) -> Vec<(String, String)> {
    ams_config::decode_devices(&std::fs::read(fichier).expect("lisible"))
        .expect("décodable")
        .into_iter()
        .map(|appareil| (appareil.login, appareil.id))
        .collect()
}

#[test]
fn les_appareils_se_listent_et_se_revoquent() {
    let atelier = atelier("appareils");
    let magasin = atelier.0.join("appareils.bin");
    std::fs::write(
        &magasin,
        ams_config::encode_devices(&[
            appareil("marie", "a1", "Pixel"),
            appareil("marie", "b2", ""),
            appareil("paul", "c3", "iPhone"),
        ])
        .expect("encodable"),
    )
    .expect("écriture");
    let fichier = magasin.display().to_string();

    let (sortie, _, code) = outil(&["device", "list", &fichier]);
    assert_eq!(code, Some(0));
    assert_eq!(sortie.lines().count(), 3, "{sortie}");
    assert!(
        sortie.contains(
            "marie\ta1\tPixel\tenrôlé 1790000000\tvu 1790003600\tattestation tee\tréveil aucun"
        ),
        "{sortie}"
    );
    assert!(sortie.contains("(sans nom)"), "{sortie}");
    let (sortie, _, _) = outil(&["device", "list", &fichier, "--login", "paul"]);
    assert_eq!(sortie.lines().count(), 1, "{sortie}");

    // Un appareil nommé ; un inconnu se refuse sans rien toucher.
    let (_, erreur, code) = outil(&[
        "device", "revoke", &fichier, "--login", "marie", "--id", "zz",
    ]);
    assert_eq!(code, Some(1));
    assert!(erreur.contains("aucun appareil `zz`"), "{erreur}");
    let (_, _, code) = outil(&[
        "device", "revoke", &fichier, "--login", "marie", "--id", "a1",
    ]);
    assert_eq!(code, Some(0));
    assert_eq!(relire(&magasin).len(), 2);

    // Tous ceux d'un compte — et seulement les siens.
    let (sortie, _, code) = outil(&["device", "revoke", &fichier, "--login", "marie", "--all"]);
    assert_eq!(code, Some(0));
    assert!(sortie.contains("1 appareil(s) de `marie`"), "{sortie}");
    assert_eq!(
        relire(&magasin),
        [(String::from("paul"), String::from("c3"))]
    );
    let (_, erreur, code) = outil(&["device", "revoke", &fichier, "--login", "marie", "--all"]);
    assert_eq!(code, Some(1));
    assert!(erreur.contains("aucun appareil enrôlé"), "{erreur}");
    let (sortie, _, _) = outil(&["device", "list", &fichier, "--login", "marie"]);
    assert!(sortie.contains("aucun appareil"), "{sortie}");
}

#[test]
fn un_magasin_absent_est_vide_et_un_illisible_se_dit() {
    let atelier = atelier("appareils-absent");
    let absent = atelier.0.join("rien.bin").display().to_string();
    let (sortie, _, code) = outil(&["device", "list", &absent]);
    assert_eq!(code, Some(0));
    assert!(sortie.contains("aucun appareil"), "{sortie}");
    let illisible = atelier.0.join("illisible.bin");
    std::fs::write(&illisible, b"pas un magasin").expect("écriture");
    let illisible = illisible.display().to_string();
    let (_, _, code) = outil(&["device", "list", &illisible]);
    assert_eq!(code, Some(1));
    let (_, _, code) = outil(&["device", "revoke", &illisible, "--login", "marie", "--all"]);
    assert_eq!(code, Some(1));
}
