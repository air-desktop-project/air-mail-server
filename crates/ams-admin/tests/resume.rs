// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `summary` relit une boîte **sans rien y écrire**.
//!
//! Jusqu'en 0.2.19, elle OUVRAIT la boîte : les fichiers sans UID étaient
//! adoptés, l'index réécrit avec une nouvelle réserve. Sur une boîte que le
//! serveur tient ouverte, c'était donner des UID que le serveur — qui garde son
//! compteur en mémoire — donnerait à son tour.

use std::path::PathBuf;
use std::process::Command;

struct Atelier(PathBuf);

impl Drop for Atelier {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Le contenu d'un répertoire, noms triés.
fn noms(repertoire: &std::path::Path) -> Vec<String> {
    let mut vus: Vec<String> = std::fs::read_dir(repertoire)
        .expect("lisible")
        .flatten()
        .map(|entree| entree.file_name().to_string_lossy().into_owned())
        .collect();
    vus.sort();
    vus
}

#[test]
fn summary_ne_touche_a_rien() {
    let atelier = Atelier(std::env::temp_dir().join(format!(
        "ams-resume-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    )));
    let _ = std::fs::remove_dir_all(&atelier.0);
    let boite = atelier.0.join("boite");
    // Une boîte ordinaire, avec son index et un message numéroté…
    {
        let maildir =
            ams_store::Maildir::open(boite.clone(), b"essai", ams_store::fresh_uid_validity())
                .expect("ouvrable");
        let mut arrivee = maildir.deliver().expect("remise");
        arrivee
            .write(b"Subject: un\r\n\r\ncorps\r\n")
            .expect("écriture");
        arrivee.commit().expect("validée");
    }
    // …et un message déposé à côté, SANS UID.
    std::fs::write(
        boite.join("new").join("1790000000.M1P2.ailleurs"),
        b"Subject: deux\r\n\r\ncorps\r\n",
    )
    .expect("dépôt");
    let index_avant = std::fs::read(boite.join("ams-index.bin")).expect("index");
    let new_avant = noms(&boite.join("new"));
    let racine_avant = noms(&boite);

    let sortie = Command::new(env!("CARGO_BIN_EXE_air-mail-admin"))
        .arg("summary")
        .arg(&boite)
        .output()
        .expect("l'outil se lance");
    let dit = String::from_utf8_lossy(&sortie.stdout).into_owned();
    assert!(sortie.status.success(), "{dit}");
    assert!(dit.contains("messages          1"), "{dit}");
    assert!(dit.contains("sans UID          1"), "{dit}");
    assert!(dit.contains("UIDVALIDITY"), "{dit}");

    // **RIEN N'A BOUGÉ** : ni le nom du fichier sans UID, ni l'index, ni rien
    // d'autre dans la boîte.
    assert_eq!(
        noms(&boite.join("new")),
        new_avant,
        "un fichier a été renommé"
    );
    assert_eq!(
        std::fs::read(boite.join("ams-index.bin")).expect("index"),
        index_avant,
        "l'index a été réécrit"
    );
    assert_eq!(noms(&boite), racine_avant, "un fichier est apparu");

    // Et un chemin qui n'est pas une boîte se refuse.
    let sortie = Command::new(env!("CARGO_BIN_EXE_air-mail-admin"))
        .arg("summary")
        .arg(atelier.0.join("nulle-part"))
        .output()
        .expect("l'outil se lance");
    assert!(!sortie.status.success());
}
