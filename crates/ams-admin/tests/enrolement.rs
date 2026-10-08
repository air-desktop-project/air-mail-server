// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `asl enroll` : tout ce qui se refuse SANS toucher au réseau.
//!
//! # POURQUOI CES REFUS-LÀ MÉRITENT UN BANC
//!
//! Le code d'enrôlement est **à usage unique et valable quelques minutes**. Un
//! refus qui arrive après l'aller-retour vers l'annuaire a donc grillé le code,
//! et il faut retourner dans l'application en demander un autre. Chacun des
//! quatre refus éprouvés ici répond AVANT d'ouvrir la moindre connexion, et
//! c'est la propriété que ces essais tiennent.
//!
//! # CE QU'ILS N'ÉPROUVENT PAS, ET IL FAUT LE DIRE
//!
//! L'enrôlement lui-même. Il demande un annuaire qui parle QUIC et HTTP/3,
//! connaisse le code, et rende une machine — c'est-à-dire un vrai annuaire, ou
//! un faux qui dirait ce que nous croyons qu'un annuaire dit. Ce que ces essais
//! garantissent est qu'on n'y arrive jamais pour une raison qu'on pouvait voir
//! d'ici.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Un répertoire d'essai, effacé quand il tombe.
struct Atelier(PathBuf);

impl Drop for Atelier {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn atelier(nom: &str) -> Atelier {
    let chemin = std::env::temp_dir().join(format!(
        "ams-enrolement-{nom}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&chemin);
    std::fs::create_dir_all(&chemin).expect("un répertoire d'essai");
    Atelier(chemin)
}

/// Lance l'outil, et rend (sortie d'erreur, succès).
fn outil(arguments: &[&str]) -> (String, bool) {
    let issue = Command::new(env!("CARGO_BIN_EXE_air-mail-admin"))
        .args(arguments)
        .output()
        .expect("l'outil se lance");
    (
        String::from_utf8_lossy(&issue.stderr).into_owned(),
        issue.status.success(),
    )
}

/// Écrit une configuration minimale, avec ou sans répertoire d'état.
fn configuration(atelier: &Atelier, etat: Option<&Path>) -> PathBuf {
    let fichier = atelier.0.join("air-mail.conf");
    let mut arguments = vec![
        String::from("config"),
        String::from("write"),
        fichier.display().to_string(),
        String::from("--domain"),
        String::from("mail.example.com"),
        String::from("--maildir"),
        atelier.0.join("boite").display().to_string(),
    ];
    if let Some(etat) = etat {
        arguments.push(String::from("--asl-state"));
        arguments.push(etat.display().to_string());
    }
    let refs: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let (dit, bon) = outil(&refs);
    assert!(bon, "la configuration d'essai doit s'écrire : {dit}");
    fichier
}

/// **UN CODE MAL FORMÉ EST REFUSÉ SANS TOUCHER AU RÉSEAU.**
///
/// C'est le refus qui compte le plus : un code recopié de travers, soumis à
/// l'annuaire, serait refusé là-bas — et l'aller-retour aurait coûté le temps
/// qu'il reste au vrai code.
#[test]
fn un_code_mal_forme_se_refuse_avant_toute_connexion() {
    let atelier = atelier("code");
    let etat = atelier.0.join("asl");
    std::fs::create_dir_all(&etat).expect("le répertoire d'état");
    let config = configuration(&atelier, Some(&etat));

    let (dit, bon) = outil(&[
        "asl",
        "enroll",
        &config.display().to_string(),
        "ceci n'est pas un code",
    ]);
    assert!(!bon, "un code illisible ne doit pas réussir");
    assert!(
        dit.contains("n'est pas un code d'enrôlement"),
        "le refus doit nommer sa cause : {dit}"
    );
}

/// **SANS `--asl-state`, IL N'Y A PAS OÙ ÉCRIRE, ET LE REFUS LE DIT.**
///
/// Il donne la commande à taper : celui qui lit ce message a écrit la
/// configuration, et il a le droit de savoir quoi corriger.
#[test]
fn sans_repertoire_d_etat_le_refus_dit_quoi_ecrire() {
    let atelier = atelier("sans-etat");
    let config = configuration(&atelier, None);

    let (dit, bon) = outil(&[
        "asl",
        "enroll",
        &config.display().to_string(),
        "4K9M2-P7R1T",
    ]);
    assert!(!bon);
    assert!(dit.contains("--asl-state"), "{dit}");
}

/// **UN RÉPERTOIRE D'ÉTAT ABSENT EST REFUSÉ, ET NON CRÉÉ.**
///
/// Le créer obligerait à inventer son propriétaire — et c'est précisément ce
/// qu'on cherche à ne pas faire : la fiche hérite du propriétaire du
/// répertoire, qui vient du déploiement. Le refus donne donc la commande, avec
/// le propriétaire dedans.
#[test]
fn un_repertoire_d_etat_absent_est_refuse_et_non_cree() {
    let atelier = atelier("etat-absent");
    let etat = atelier.0.join("pas-la");
    let config = configuration(&atelier, Some(&etat));

    let (dit, bon) = outil(&[
        "asl",
        "enroll",
        &config.display().to_string(),
        "4K9M2-P7R1T",
    ]);
    assert!(!bon);
    assert!(dit.contains("install -d -m 0700"), "{dit}");
    assert!(
        !etat.exists(),
        "le répertoire ne doit PAS avoir été créé : son propriétaire serait inventé"
    );
}

/// **UNE FICHE DÉJÀ LÀ ARRÊTE TOUT.**
///
/// Réenrôler jetterait la clé que l'annuaire connaît, et les services de cette
/// machine disparaîtraient de l'annuaire sans que personne ne l'ait demandé. Le
/// refus dit comment forcer, et laisse le geste à qui l'assume.
#[test]
fn une_fiche_deja_la_arrete_tout() {
    let atelier = atelier("deja-enrolee");
    let etat = atelier.0.join("asl");
    std::fs::create_dir_all(&etat).expect("le répertoire d'état");
    let fiche = etat.join("identite");
    std::fs::write(&fiche, b"machine = m-26W610F86BVRH6GPKGSSQK9H4S\n").expect("une fiche");
    let config = configuration(&atelier, Some(&etat));

    let (dit, bon) = outil(&[
        "asl",
        "enroll",
        &config.display().to_string(),
        "4K9M2-P7R1T",
    ]);
    assert!(!bon);
    assert!(dit.contains("existe déjà"), "{dit}");
    assert!(
        dit.contains("disparaîtraient"),
        "le refus doit dire la CONSÉQUENCE, et non seulement le fait : {dit}"
    );
    // **ET LA FICHE N'A PAS BOUGÉ** : c'est la seule chose qui compte vraiment.
    assert_eq!(
        std::fs::read(&fiche).expect("elle est toujours là"),
        b"machine = m-26W610F86BVRH6GPKGSSQK9H4S\n",
        "la fiche existante ne doit pas être touchée"
    );
}

/// **UN ANNUAIRE DÉCLARÉ SANS SON IDENTITÉ EST REFUSÉ.**
///
/// `hôte:port` seul ne serait cru par rien : l'identité après le `=` est la
/// SEULE chose qui soit jugée, puisqu'un annuaire présente un certificat
/// auto-signé. Le refus le dit, plutôt que de laisser la poignée de main
/// échouer sur une cause qu'on ne devinerait pas.
#[test]
fn un_annuaire_sans_identite_est_refuse() {
    let atelier = atelier("annuaire-nu");
    let etat = atelier.0.join("asl");
    std::fs::create_dir_all(&etat).expect("le répertoire d'état");
    let fichier = atelier.0.join("air-mail.conf");
    let (dit, bon) = outil(&[
        "config",
        "write",
        &fichier.display().to_string(),
        "--domain",
        "mail.example.com",
        "--maildir",
        &atelier.0.join("boite").display().to_string(),
        "--asl-state",
        &etat.display().to_string(),
        "--asl-directory",
        "192.0.2.9:6630",
    ]);
    assert!(
        bon,
        "la configuration l'accepte : c'est l'enrôlement qui juge : {dit}"
    );

    let (dit, bon) = outil(&[
        "asl",
        "enroll",
        &fichier.display().to_string(),
        "4K9M2-P7R1T",
    ]);
    assert!(!bon);
    assert!(dit.contains("ne dit pas d'identité"), "{dit}");
}
