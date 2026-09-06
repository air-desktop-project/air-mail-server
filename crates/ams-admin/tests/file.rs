// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `config show` REND COMPTE DE CHAQUE MOLETTE DE LA FILE, sans en oublier une.
//!
//! # Le défaut que cet essai ferme
//!
//! La file a quatre réglages — première attente, plafond, seuil de retard,
//! péremption. `config show` en affichait TROIS, et la ligne de démarrage du
//! serveur les mêmes trois. `--queue-warn-seconds` se réglait donc sans laisser
//! la moindre trace :
//!
//! ```text
//! réémission  vers `…/file` — 1er essai à 2 s, plafond 8 s, abandon à 40 s
//! ```
//!
//! # Pourquoi cet oubli-là coûte plus cher que les autres
//!
//! Un exploitant qui règle une molette et ne la voit nulle part n'a AUCUN moyen
//! de savoir si elle a été prise. Les trois autres se constatent en attendant :
//! l'attente se chronomètre, la péremption se voit arriver. L'avis de retard,
//! lui, ne part QUE si le déposant a écrit `NOTIFY=DELAY` (RFC 3461 §4.1) — son
//! silence est donc AMBIGU. Ne rien recevoir peut vouloir dire « le seuil n'est
//! pas atteint », « le seuil n'a pas été pris », ou « personne ne l'a demandé »,
//! et rien dans le produit ne distinguait ces trois cas.
//!
//! C'est le piège où je suis tombé le 2026-09-06 en éprouvant la file : réglage
//! à 10 s, péremption à 40 s, aucun avis reçu. J'ai commencé à écrire un défaut
//! avant de trouver que mon client n'avait rien demandé.
//!
//! # Ce que cet essai vérifie, et pourquoi ainsi
//!
//! Il ne recopie pas la liste des molettes : il la LIT dans la source qui les
//! accepte. Une cinquième ajoutée demain sans être affichée fera échouer cet
//! essai, ce qu'une liste recopiée ne saurait pas faire.

use std::path::PathBuf;
use std::process::Command;

/// La source qui accepte les options, lue à la compilation.
const SOURCE_DES_OPTIONS: &str = include_str!("../../ams-admin-options/src/lib.rs");

struct Atelier(PathBuf);

impl Drop for Atelier {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn atelier(nom: &str) -> Atelier {
    let chemin = std::env::temp_dir().join(format!(
        "ams-file-{nom}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&chemin);
    std::fs::create_dir_all(&chemin).expect("un répertoire d'essai");
    Atelier(chemin)
}

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

/// Les `--queue-…-seconds` que la source accepte, dans l'ordre où elle les cite.
///
/// On les cherche là où elles sont TRAITÉES (`"--queue-…" =>`), et non dans le
/// texte de l'aide : une molette qu'on aurait cessé d'accepter en continuant de
/// la documenter ne doit pas être exigée ici.
fn molettes_de_la_file() -> Vec<String> {
    let mut trouvees = Vec::new();
    for morceau in SOURCE_DES_OPTIONS.split("\"--queue-").skip(1) {
        let Some(fin) = morceau.find('"') else {
            continue;
        };
        let nom = &morceau[..fin];
        if !nom.ends_with("-seconds") {
            continue;
        }
        // La branche qui la TRAITE porte `=>` juste après le guillemet fermant.
        let apres = morceau.get(fin.saturating_add(1)..).unwrap_or_default();
        if !apres.trim_start().starts_with("=>") {
            continue;
        }
        let complet = format!("--queue-{nom}");
        if !trouvees.contains(&complet) {
            trouvees.push(complet);
        }
    }
    trouvees
}

/// **CHAQUE MOLETTE DE LA FILE SE RETROUVE DANS `config show`.**
///
/// Chacune reçoit une valeur qui n'appartient qu'à elle, si bien qu'un affichage
/// qui en confondrait deux ne passerait pas non plus.
#[test]
fn config_show_rend_compte_de_chaque_molette_de_la_file() {
    let molettes = molettes_de_la_file();
    assert!(
        molettes.len() >= 4,
        "la source devrait accepter au moins les quatre molettes connues, \
         trouvé {molettes:?}"
    );

    let atelier = atelier("molettes");
    // Des valeurs distinctes, et qu'aucune autre ligne n'affiche : les tailles
    // et les seuils du garde sont ronds, ceux-ci ne le sont pas.
    let valeurs: Vec<String> = (0..molettes.len())
        .map(|rang| (7_001_usize.saturating_add(rang.saturating_mul(13))).to_string())
        .collect();

    let mut arguments: Vec<&str> = vec![
        "config",
        "write",
        "f.conf",
        "--relay",
        "--queue-spool",
        "file",
        "--tls-cert",
        "cert.pem",
        "--tls-key",
        "cle.pem",
    ];
    for (molette, valeur) in molettes.iter().zip(&valeurs) {
        arguments.push(molette);
        arguments.push(valeur);
    }
    let (_, bon) = outil(&atelier, &arguments);
    assert!(bon, "`config write` avec les {} molettes", molettes.len());

    let (dit, bon) = outil(&atelier, &["config", "show", "f.conf"]);
    assert!(bon, "`config show` réussit");
    for (molette, valeur) in molettes.iter().zip(&valeurs) {
        assert!(
            dit.contains(valeur.as_str()),
            "`{molette} {valeur}` ne se retrouve pas dans `config show` :\n{dit}"
        );
    }
}

/// La source du serveur, et celle qui définit la politique de reprise.
const SOURCE_DU_SERVEUR: &str = include_str!("../../ams-server/src/main.rs");
const SOURCE_DE_LA_REPRISE: &str = include_str!("../../ams-queue/src/backoff.rs");

/// Les champs de durée que porte `Backoff`, lus dans sa propre source.
fn champs_de_la_reprise() -> Vec<String> {
    let mut trouves = Vec::new();
    for ligne in SOURCE_DE_LA_REPRISE.lines() {
        let ligne = ligne.trim();
        let Some(reste) = ligne.strip_prefix("pub ") else {
            continue;
        };
        let Some((nom, typage)) = reste.split_once(": ") else {
            continue;
        };
        if typage.trim_end_matches(',') == "Duration" {
            trouves.push(nom.to_owned());
        }
    }
    trouves
}

/// **LES DEUX AFFICHAGES DE LA FILE DISENT LA POLITIQUE ENTIÈRE.**
///
/// `config show` la dit à qui écrit la configuration ; la ligne de démarrage la
/// dit à qui lit le journal. Un exploitant peut n'avoir que l'un des deux sous
/// les yeux, et il n'y a pas de raison qu'il en apprenne moins.
///
/// Cet essai lit les champs dans `Backoff` plutôt que de les nommer : un
/// cinquième réglage ajouté demain devra apparaître aux deux endroits, sans
/// quoi cet essai refusera.
#[test]
fn les_deux_affichages_de_la_file_disent_la_politique_entiere() {
    let champs = champs_de_la_reprise();
    assert!(
        champs.len() >= 4,
        "`Backoff` devrait porter au moins quatre durées, trouvé {champs:?}"
    );

    for champ in &champs {
        let cite = format!("reprise.{champ}.as_secs()");
        assert!(
            SOURCE_DU_SERVEUR.contains(&cite),
            "la ligne de démarrage du serveur ne dit pas `{champ}` — cherché `{cite}`"
        );
    }
}
