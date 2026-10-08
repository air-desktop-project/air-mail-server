// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le chemin de la configuration se devine, et rien d'autre ne se devine.
//!
//! # Ce que ces essais tiennent
//!
//! Quatre familles de commandes — `config show`, `token`, `audit`,
//! `registre` — prennent [`ams_config::CHEMIN_PAR_DEFAUT`] quand la ligne de
//! commande n'en nomme pas. Trois choses doivent rester vraies, et chacune
//! casse d'une façon différente :
//!
//! 1. **le défaut s'applique**, et le message d'erreur NOMME le chemin tenté —
//!    sans quoi on remplace une erreur claire par une erreur muette ;
//! 2. **un chemin fourni reste prioritaire**, y compris quand il est faux : un
//!    défaut qui se substituerait à l'argument donnerait à l'exploitant la
//!    configuration d'une autre machine ;
//! 3. **`config write` refuse de deviner**, parce qu'elle remplace le fichier
//!    entier.
//!
//! # LE PIÈGE QUE CES ESSAIS FERMENT, ET IL N'EST PAS THÉORIQUE
//!
//! Chaque commande prend son chemin en PREMIÈRE position. Rendre ce chemin
//! facultatif expose donc à ce que l'option suivante soit prise pour lui :
//! `registre cherche --limit 20` lirait une configuration nommée `--limit`, et
//! `token --login thierry` scellerait avec une configuration nommée `--login`.
//! Les deux échoueraient, mais sur un message qui ne dirait pas la cause.
//!
//! C'est exactement la famille de défauts que `aide.rs` a déjà fermée pour
//! `--help` : le dispatch prenait `--help` pour un chemin et ÉCRIVAIT un
//! fichier de ce nom. La règle est donc la même, et elle est explicite dans le
//! code : un mot qui commence par deux tirets n'est pas un chemin.

use std::process::Command;

/// Un chemin qui n'existe nulle part, et qui n'est pas le défaut.
const AILLEURS: &str = "/nulle/part/ailleurs.conf";

/// Lance l'outil et rend (sortie standard, sortie d'erreur, code de sortie).
fn outil(arguments: &[&str]) -> (String, String, i32) {
    let issue = Command::new(env!("CARGO_BIN_EXE_air-mail-admin"))
        .args(arguments)
        .output()
        .expect("l'outil se lance");
    (
        String::from_utf8_lossy(&issue.stdout).to_string(),
        String::from_utf8_lossy(&issue.stderr).to_string(),
        issue.status.code().unwrap_or(-1),
    )
}

/// Les formes qui doivent prendre le défaut, telles qu'un exploitant les tape.
///
/// **CE TABLEAU EST LA LISTE ENTIÈRE** des formes sans chemin, et non un
/// échantillon : chaque bras du dispatch a dû être ajouté à la main, et celui
/// qu'on oublierait serait précisément celui qui prendrait `--login` pour un
/// nom de fichier.
const SANS_CHEMIN: [&[&str]; 6] = [
    &["config", "show"],
    &["registre", "verifie"],
    &["registre", "cherche", "--limit", "5"],
    &["audit", "--login", "quelqu-un"],
    &["audit", "--login", "quelqu-un", "--limit", "3"],
    &["token", "--login", "quelqu-un"],
];

/// **LE DÉFAUT S'APPLIQUE, ET LE MESSAGE LE NOMME.**
///
/// Le chemin par défaut n'existe pas sur la machine qui fait tourner ces
/// essais : l'échec est donc attendu. Ce qui compte est QUEL chemin l'erreur
/// nomme — c'est la seule preuve que le défaut a été retenu, et le seul moyen
/// pour un exploitant de comprendre ce que l'outil a cherché.
#[test]
fn les_quatre_familles_prennent_le_defaut_et_le_nomment() {
    for commande in SANS_CHEMIN {
        let (_, plainte, code) = outil(commande);
        assert!(
            plainte.contains(ams_config::CHEMIN_PAR_DEFAUT),
            "`{commande:?}` doit nommer `{}` dans sa plainte, or elle dit : {plainte}",
            ams_config::CHEMIN_PAR_DEFAUT
        );
        assert_ne!(
            code, 0,
            "`{commande:?}` ne peut pas réussir sans configuration"
        );
    }
}

/// **OMETTRE LE CHEMIN NE CHANGE QUE LE CHEMIN.**
///
/// Le reste des arguments doit se découper exactement comme lorsqu'un chemin
/// est fourni. On compare donc les deux plaintes, une fois le chemin retiré de
/// chacune : elles doivent être identiques mot pour mot.
///
/// # Pourquoi ce contrôle et pas un plus simple
///
/// La première version de cet essai vérifiait que la plainte ne nommait pas
/// `--limit`. Elle est restée VERTE pendant que le garde était neutralisé,
/// parce que le découpage fautif produit « `5` attend une valeur » — une
/// plainte qui ne nomme ni `--limit`, ni le défaut, ni rien de reconnaissable.
/// Un essai dont on ne sait pas provoquer le rouge ne prouve rien, et celui-là
/// a été remplacé pour cette raison.
#[test]
fn omettre_le_chemin_ne_change_que_le_chemin() {
    // Les mêmes commandes, avec et sans chemin. L'insertion se fait juste
    // après le verbe, là où le chemin se tape.
    let paires: [(&[&str], &[&str]); 4] = [
        (&["config", "show"], &["config", "show", AILLEURS]),
        (&["registre", "verifie"], &["registre", "verifie", AILLEURS]),
        (
            &["registre", "cherche", "--limit", "5"],
            &["registre", "cherche", AILLEURS, "--limit", "5"],
        ),
        (
            &["audit", "--login", "quelqu-un", "--limit", "3"],
            &["audit", AILLEURS, "--login", "quelqu-un", "--limit", "3"],
        ),
    ];
    for (sans, avec) in paires {
        let (_, nue, code_nu) = outil(sans);
        let (_, nommee, code_nomme) = outil(avec);
        assert_eq!(
            nue.replace(ams_config::CHEMIN_PAR_DEFAUT, "<CONFIG>"),
            nommee.replace(AILLEURS, "<CONFIG>"),
            "`{sans:?}` et `{avec:?}` doivent se comporter de la même façon, \
             au chemin près"
        );
        assert_eq!(code_nu, code_nomme, "et rendre le même code de sortie");
    }
}

/// **UN CHEMIN FOURNI RESTE PRIORITAIRE, MÊME FAUX.**
///
/// Un défaut qui se substituerait à l'argument ferait lire à l'exploitant une
/// autre configuration que celle qu'il a nommée — sur une machine qui en porte
/// plusieurs (`essai.conf`, les `.bak-*`), c'est une confusion qui coûte cher.
#[test]
fn un_chemin_fourni_passe_avant_le_defaut() {
    let formes: [&[&str]; 5] = [
        &["config", "show", AILLEURS],
        &["registre", "verifie", AILLEURS],
        &["registre", "cherche", AILLEURS, "--limit", "5"],
        &["audit", AILLEURS, "--login", "quelqu-un"],
        &["token", AILLEURS, "--login", "quelqu-un"],
    ];
    for commande in formes {
        let (_, plainte, code) = outil(commande);
        assert!(
            plainte.contains(AILLEURS),
            "`{commande:?}` doit nommer le chemin FOURNI, or elle dit : {plainte}"
        );
        assert!(
            !plainte.contains(ams_config::CHEMIN_PAR_DEFAUT),
            "`{commande:?}` a retenu le défaut malgré un chemin fourni : {plainte}"
        );
        assert_ne!(code, 0, "le chemin fourni n'existe pas non plus");
    }
}

/// **`config write` REFUSE DE DEVINER, ET DIT POURQUOI.**
///
/// Cette commande remplace le fichier ENTIER : sans chemin, une commande
/// incomplète tapée par habitude réécrirait la configuration vivante avec le
/// seul jeu d'options frappé, et effacerait tout le reste — dont le registre,
/// sans lequel la réception refuse par `451`. Le refus doit donc DIRE cela, et
/// pas seulement refuser : un message qui n'explique pas se contourne.
#[test]
fn config_write_exige_sa_cible() {
    for commande in [
        ["config", "write"].as_slice(),
        &["config", "write", "--domain", "exemple.net"],
    ] {
        let (_, plainte, code) = outil(commande);
        assert_eq!(code, 2, "`{commande:?}` est un emploi fautif : {plainte}");
        assert!(
            plainte.contains("exige le chemin"),
            "`{commande:?}` doit dire ce qu'elle exige : {plainte}"
        );
        assert!(
            plainte.contains("REMPLACE le fichier entier"),
            "`{commande:?}` doit dire POURQUOI elle l'exige : {plainte}"
        );
        assert!(
            !plainte.contains(ams_config::CHEMIN_PAR_DEFAUT),
            "`config write` ne doit même pas NOMMER le défaut, pour que personne \
             ne croie qu'il suffit de le retaper : {plainte}"
        );
    }
}

/// **LE DÉFAUT EST UN CHEMIN ABSOLU, ET NE DÉPEND PAS DU RÉPERTOIRE COURANT.**
///
/// Un défaut relatif ferait lire une configuration différente selon l'endroit
/// d'où l'on tape la commande — et un exploitant qui vérifie depuis son `$HOME`
/// ne verrait pas ce que le service lit.
#[test]
fn le_defaut_est_absolu() {
    assert!(
        std::path::Path::new(ams_config::CHEMIN_PAR_DEFAUT).is_absolute(),
        "`{}` doit être absolu",
        ams_config::CHEMIN_PAR_DEFAUT
    );
}
