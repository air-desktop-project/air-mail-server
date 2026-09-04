// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `--help` demande l'aide, et n'est jamais pris pour un chemin.
//!
//! # Le défaut que ces essais ferment
//!
//! Chaque commande prend un chemin en PREMIÈRE position, et le dispatch le
//! prenait tel quel. `config write --help` écrivait donc une configuration dans
//! un fichier NOMMÉ `--help`, en annonçant son succès :
//!
//! ```text
//! écrit : --help (648 octets) — domaine `localhost`, écoute `127.0.0.1:2525`
//! ```
//!
//! Les six autres commandes rendaient une erreur de lecture sur un fichier de ce
//! nom, ou un « commande inconnue ». L'aide de l'outil promettait pourtant, mot
//! pour mot : « `config write --help` les liste ».
//!
//! # Ce qui distingue ce défaut d'un simple message trompeur
//!
//! Le fichier créé. Il porte un nom qu'on n'efface pas sans savoir que
//! `rm -- ./--help` est nécessaire — le tiret le fait passer pour une option de
//! `rm`. C'est pourquoi ces essais tournent dans un répertoire à eux et
//! vérifient qu'il en ressort VIDE : c'est la conséquence, pas la formulation,
//! qui compte.
//!
//! Et il passait outre le refus d'écraser un fichier qu'on ne reconnaît pas :
//! celui-ci ne garde que les fichiers EXISTANTS, et `--help` était créé de
//! toutes pièces.

use std::path::PathBuf;
use std::process::Command;

/// Les sept commandes, telles qu'un exploitant les tape.
///
/// **CE TABLEAU EST LA LISTE ENTIÈRE**, et non un échantillon : c'est
/// précisément parce que le défaut frappait les sept qu'une correction par bras
/// aurait laissé passer celui qu'on aurait oublié.
const COMMANDES: [&[&str]; 7] = [
    &["config", "write"],
    &["config", "show"],
    &["summary"],
    &["token"],
    &["account", "list"],
    &["account", "add"],
    &["account", "remove"],
];

/// Un répertoire d'essai, effacé quand il tombe.
struct Atelier(PathBuf);

impl Drop for Atelier {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn atelier(nom: &str) -> Atelier {
    let chemin = std::env::temp_dir().join(format!(
        "ams-aide-{nom}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&chemin);
    std::fs::create_dir_all(&chemin).expect("un répertoire d'essai");
    Atelier(chemin)
}

/// Lance l'outil DANS `atelier`, et rend (sortie standard, succès).
///
/// Le répertoire courant compte ici plus qu'ailleurs : c'est là que le fichier
/// parasite naissait, et c'est là qu'on vérifie qu'il ne naît plus.
fn outil(atelier: &Atelier, arguments: &[&str]) -> (String, bool) {
    let issue = Command::new(env!("CARGO_BIN_EXE_air-mail-admin"))
        .current_dir(&atelier.0)
        .args(arguments)
        .output()
        .expect("l'outil se lance");
    (
        String::from_utf8_lossy(&issue.stdout).to_string(),
        issue.status.success(),
    )
}

/// Ce que le répertoire contient, hors `.` et `..`.
fn contenu(atelier: &Atelier) -> Vec<String> {
    std::fs::read_dir(&atelier.0)
        .expect("lu")
        .filter_map(Result::ok)
        .map(|entree| entree.file_name().to_string_lossy().into_owned())
        .collect()
}

/// **LES SEPT COMMANDES RENDENT L'AIDE, ET NE CRÉENT RIEN.**
#[test]
fn aucune_commande_ne_prend_help_pour_un_chemin() {
    for commande in COMMANDES {
        for demande in ["--help", "-h"] {
            let atelier = atelier("sept");
            let mut arguments = commande.to_vec();
            arguments.push(demande);
            let (dit, bon) = outil(&atelier, &arguments);

            assert!(bon, "`{commande:?} {demande}` doit réussir");
            assert!(
                dit.contains("air-mail-admin") || dit.contains("OPTIONS DE"),
                "`{commande:?} {demande}` ne rend pas une aide : {dit:.80}"
            );
            // **LA CONSÉQUENCE, ET NON LA FORMULATION.** C'est ce point-ci qui
            // distingue le défaut d'un message maladroit.
            assert!(
                contenu(&atelier).is_empty(),
                "`{commande:?} {demande}` a créé {:?}",
                contenu(&atelier)
            );
        }
    }
}

/// **`config write` MONTRE SES PROPRES OPTIONS**, et c'est ce que l'aide
/// générale renvoie chercher : « `config write --help` les liste ».
///
/// Cette phrase était fausse ; elle est vraie maintenant, et cet essai est ce
/// qui la garde vraie.
#[test]
fn config_write_montre_ses_options_et_les_autres_l_aide_generale() {
    let atelier = atelier("options");
    let (dit, bon) = outil(&atelier, &["config", "write", "--help"]);
    assert!(bon);
    assert!(dit.contains("OPTIONS DE"), "{dit:.120}");
    // Les seuils du garde y sont, puisque l'aide générale le promet.
    assert!(dit.contains("--invalid-frames-per-minute"), "{dit:.400}");

    let (dit, bon) = outil(&atelier, &["config", "show", "--help"]);
    assert!(bon);
    assert!(dit.contains("USAGE"), "{dit:.120}");
}

/// **SANS ARGUMENT, L'AIDE ENTIÈRE**, comme avant : l'interception ne doit pas
/// avoir emporté ce cas-là en passant.
#[test]
fn sans_argument_l_aide_entiere_reste() {
    let atelier = atelier("vide");
    let (dit, bon) = outil(&atelier, &[]);
    assert!(bon);
    assert!(
        dit.contains("USAGE") && dit.contains("OPTIONS DE"),
        "{dit:.120}"
    );
}

/// **`--version` N'EST PAS L'AIDE**, et l'interception ne doit pas l'avaler.
#[test]
fn la_version_reste_la_version() {
    let atelier = atelier("version");
    for demande in ["--version", "-V"] {
        let (dit, bon) = outil(&atelier, &[demande]);
        assert!(bon);
        assert!(dit.starts_with("air-mail-admin "), "{dit:.80}");
        assert!(!dit.contains("USAGE"), "{demande} rend l'aide : {dit:.80}");
    }
}
