// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que les commandes `app-password` font vraiment, contre le binaire.
//!
//! Le secret créé est RÉELLEMENT essayé — par la vérification que le serveur
//! emploie —, et non seulement constaté dans le fichier : un magasin bien formé
//! dont le condensat ne correspond à rien a exactement la même allure.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

struct Atelier(PathBuf);

impl Drop for Atelier {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn atelier(nom: &str) -> Atelier {
    let chemin = std::env::temp_dir().join(format!(
        "ams-applicatifs-{nom}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&chemin);
    std::fs::create_dir_all(&chemin).expect("un répertoire d'essai");
    Atelier(chemin)
}

/// Lance l'outil, avec `entree` sur l'entrée standard.
fn outil(entree: &str, arguments: &[&str]) -> (String, String, bool) {
    let mut enfant = Command::new(env!("CARGO_BIN_EXE_air-mail-admin"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("l'outil se lance");
    if let Some(flux) = enfant.stdin.as_mut() {
        let _ = flux.write_all(entree.as_bytes());
    }
    let fini = enfant.wait_with_output().expect("l'outil finit");
    (
        String::from_utf8_lossy(&fini.stdout).into_owned(),
        String::from_utf8_lossy(&fini.stderr).into_owned(),
        fini.status.success(),
    )
}

/// Ces identifiants ouvrent-ils, et par quel chemin ?
fn ouvre(atelier: &Atelier, qui: &str, secret: &str) -> ams_auth::Ouverture {
    let comptes =
        ams_config::decode_accounts(&std::fs::read(atelier.0.join("comptes.bin")).expect("c"))
            .expect("comptes");
    let applicatifs = match std::fs::read(atelier.0.join("applicatifs.bin")) {
        Ok(octets) => ams_config::decode_app_passwords(&octets).expect("applicatifs"),
        Err(_) => Vec::new(),
    };
    ams_auth::authenticate_all(
        &comptes,
        &applicatifs,
        &ams_sasl::Credentials {
            authorization_identity: b"",
            authentication_identity: qui.as_bytes(),
            password: secret.as_bytes(),
        },
    )
}

#[test]
fn le_cycle_complet_d_un_mot_de_passe_applicatif() {
    let atelier = atelier("cycle");
    let comptes = atelier.0.join("comptes.bin").display().to_string();
    let applicatifs = atelier.0.join("applicatifs.bin").display().to_string();
    for nom in ["jean", "paul"] {
        let (_, plainte, ok) = outil(
            "principal",
            &[
                "account",
                "add",
                &comptes,
                "--login",
                nom,
                "--address",
                &format!("{nom}@e.com"),
            ],
        );
        assert!(ok, "{plainte}");
    }

    // ── CRÉER ───────────────────────────────────────────────────────────────
    let (secret, dit, ok) = outil(
        "",
        &[
            "app-password",
            "add",
            &applicatifs,
            "--accounts",
            &comptes,
            "--login",
            "jean",
            "--name",
            "Thunderbird",
        ],
    );
    assert!(ok, "{dit}");
    assert!(dit.contains("NE SERA PLUS JAMAIS AFFICHÉ"), "{dit}");
    let secret = secret.trim().to_string();
    assert!(secret.starts_with("amsp-"), "{secret}");
    let Some(id) = ams_auth::identifiant_applicatif(secret.as_bytes()).map(str::to_string) else {
        panic!("`{secret}` n'a pas la forme d'un mot de passe applicatif");
    };

    // Il ouvre SON compte, et le mot de passe principal aussi.
    assert_eq!(
        ouvre(&atelier, "jean", &secret),
        ams_auth::Ouverture::Applicatif(id.clone())
    );
    assert_eq!(
        ouvre(&atelier, "jean", "principal"),
        ams_auth::Ouverture::Principal
    );
    // Pas celui d'un autre.
    assert_eq!(
        ouvre(&atelier, "paul", &secret),
        ams_auth::Ouverture::Refusee
    );

    // ── LISTER : JAMAIS LE SECRET ───────────────────────────────────────────
    let (liste, plainte, ok) = outil("", &["app-password", "list", &applicatifs]);
    assert!(ok, "{plainte}");
    assert!(
        liste.contains(&id) && liste.contains("Thunderbird"),
        "{liste}"
    );
    assert!(liste.contains("jamais servi"), "{liste}");
    assert!(!liste.contains(&secret), "LE SECRET S'AFFICHE : {liste}");
    let (liste, _, _) = outil(
        "",
        &["app-password", "list", &applicatifs, "--login", "paul"],
    );
    assert!(liste.contains("aucun"), "{liste}");

    // ── RÉVOQUER ────────────────────────────────────────────────────────────
    // Sous le mauvais compte : refusé, et rien ne bouge.
    let (_, plainte, ok) = outil(
        "",
        &[
            "app-password",
            "remove",
            &applicatifs,
            "--login",
            "paul",
            "--id",
            &id,
        ],
    );
    assert!(!ok && plainte.contains("aucun"), "{plainte}");
    assert!(matches!(
        ouvre(&atelier, "jean", &secret),
        ams_auth::Ouverture::Applicatif(_)
    ));
    // Sous le bon.
    let (_, plainte, ok) = outil(
        "",
        &[
            "app-password",
            "remove",
            &applicatifs,
            "--login",
            "jean",
            "--id",
            &id,
        ],
    );
    assert!(ok, "{plainte}");
    assert_eq!(
        ouvre(&atelier, "jean", &secret),
        ams_auth::Ouverture::Refusee
    );
    assert_eq!(
        ouvre(&atelier, "jean", "principal"),
        ams_auth::Ouverture::Principal,
        "révoquer un mot de passe applicatif ne touche pas au principal"
    );
}

#[test]
fn un_compte_inconnu_ou_un_nom_vide_sont_refuses() {
    let atelier = atelier("refus");
    let comptes = atelier.0.join("comptes.bin").display().to_string();
    let applicatifs = atelier.0.join("applicatifs.bin").display().to_string();
    outil(
        "principal",
        &["account", "add", &comptes, "--login", "jean"],
    );

    let (_, plainte, ok) = outil(
        "",
        &[
            "app-password",
            "add",
            &applicatifs,
            "--accounts",
            &comptes,
            "--login",
            "jaen",
            "--name",
            "x",
        ],
    );
    assert!(!ok && plainte.contains("aucun compte `jaen`"), "{plainte}");
    let (_, plainte, ok) = outil(
        "",
        &[
            "app-password",
            "add",
            &applicatifs,
            "--accounts",
            &comptes,
            "--login",
            "jean",
            "--name",
            "",
        ],
    );
    assert!(!ok && plainte.contains("--name"), "{plainte}");
    assert!(
        !atelier.0.join("applicatifs.bin").exists(),
        "un refus a créé le magasin"
    );
}

/// **RETIRER UN COMPTE EMPORTE SES MOTS DE PASSE APPLICATIFS**, quand on nomme
/// leur magasin — un compte recréé sous le même nom en hériterait sinon.
#[test]
fn retirer_un_compte_emporte_ses_mots_de_passe_applicatifs() {
    let atelier = atelier("retrait");
    let comptes = atelier.0.join("comptes.bin").display().to_string();
    let applicatifs = atelier.0.join("applicatifs.bin").display().to_string();
    for nom in ["jean", "paul"] {
        outil("principal", &["account", "add", &comptes, "--login", nom]);
        let (_, plainte, ok) = outil(
            "",
            &[
                "app-password",
                "add",
                &applicatifs,
                "--accounts",
                &comptes,
                "--login",
                nom,
                "--name",
                "client",
            ],
        );
        assert!(ok, "{plainte}");
    }
    let (dit, plainte, ok) = outil(
        "",
        &[
            "account",
            "remove",
            &comptes,
            "--login",
            "jean",
            "--app-passwords",
            &applicatifs,
        ],
    );
    assert!(ok, "{plainte}");
    assert!(
        dit.contains("1 mot(s) de passe applicatif(s) de `jean` retiré(s)"),
        "{dit}"
    );
    let restants = ams_config::decode_app_passwords(
        &std::fs::read(atelier.0.join("applicatifs.bin")).expect("lisible"),
    )
    .expect("relisible");
    assert_eq!(restants.len(), 1);
    assert!(restants.iter().all(|entree| entree.login == "paul"));
}

/// **`config show` DIT OÙ EST LE MAGASIN DES MOTS DE PASSE APPLICATIFS** — et
/// qu'il n'y en a pas, quand il n'y en a pas. La 0.2.17 l'écrivait sans que
/// cette commande le montre : l'exploitant qui relisait sa configuration avant
/// de redémarrer ne pouvait pas vérifier qu'il y était.
#[test]
fn config_show_montre_le_magasin_des_mots_de_passe_applicatifs() {
    let atelier = atelier("montrer");
    let avec = atelier.0.join("avec.conf").display().to_string();
    let sans = atelier.0.join("sans.conf").display().to_string();
    let (_, plainte, ok) = outil(
        "",
        &[
            "config",
            "write",
            &avec,
            "--app-passwords",
            "/x/applicatifs.bin",
        ],
    );
    assert!(ok, "{plainte}");
    let (dit, plainte, ok) = outil("", &["config", "show", &avec]);
    assert!(ok, "{plainte}");
    assert!(
        dit.lines()
            .any(|ligne| ligne.starts_with("mdp applicatifs")
                && ligne.contains("/x/applicatifs.bin")),
        "{dit}"
    );

    let (_, plainte, ok) = outil("", &["config", "write", &sans]);
    assert!(ok, "{plainte}");
    let (dit, _, _) = outil("", &["config", "show", &sans]);
    assert!(
        dit.lines()
            .any(|ligne| ligne.starts_with("mdp applicatifs") && ligne.contains("AUCUN MAGASIN")),
        "{dit}"
    );
}

/// **RETIRER UN COMPTE EMPORTE SES DÉLÉGATIONS, DANS LES DEUX SENS** — un
/// compte recréé sous le même nom atteindrait sinon des boîtes qu'on ne lui a
/// jamais ouvertes. Celles qui ne le nomment pas restent.
#[test]
fn retirer_un_compte_emporte_ses_delegations() {
    use ams_config::{Delegation, Rights};
    let atelier = atelier("delegations");
    let comptes = atelier.0.join("comptes.bin").display().to_string();
    let chemin = atelier.0.join("delegations.bin");
    let delegations = chemin.display().to_string();
    for nom in ["jean", "paul", "support"] {
        outil("principal", &["account", "add", &comptes, "--login", nom]);
    }
    let une = |delegate: &str, owner: &str| Delegation {
        delegate: delegate.to_owned(),
        owner: owner.to_owned(),
        rights: Rights::READ,
    };
    let tenues = [
        une("jean", "support"),
        une("paul", "jean"),
        une("paul", "support"),
    ];
    std::fs::write(
        &chemin,
        ams_config::encode_delegations(&tenues).expect("encodable"),
    )
    .expect("écrit");

    let (dit, plainte, ok) = outil(
        "",
        &[
            "account",
            "remove",
            &comptes,
            "--login",
            "jean",
            "--delegations",
            &delegations,
        ],
    );
    assert!(ok, "{plainte}");
    assert!(
        dit.contains("2 délégation(s) de ou vers `jean` retirée(s)"),
        "{dit}"
    );
    let restantes =
        ams_config::decode_delegations(&std::fs::read(&chemin).expect("lisible")).expect("relu");
    assert_eq!(restantes, vec![une("paul", "support")]);
}

/// Une option de purge donnée deux fois, ou inconnue, est refusée AVANT de
/// retirer quoi que ce soit.
#[test]
fn account_remove_refuse_une_purge_mal_dite() {
    let atelier = atelier("purge");
    let comptes = atelier.0.join("comptes.bin").display().to_string();
    outil(
        "principal",
        &["account", "add", &comptes, "--login", "jean"],
    );
    for reste in [
        &["--delegations", "/x/a", "--delegations", "/x/b"][..],
        &["--inconnue", "/x/a"][..],
        &["--delegations"][..],
    ] {
        let mut arguments = vec!["account", "remove", &comptes, "--login", "jean"];
        arguments.extend_from_slice(reste);
        let (_, plainte, ok) = outil("", &arguments);
        assert!(!ok && !plainte.is_empty(), "{reste:?}");
    }
    let tenus =
        ams_config::decode_accounts(&std::fs::read(&comptes).expect("lisible")).expect("relu");
    assert_eq!(tenus.len(), 1, "un refus a retiré le compte");
}
