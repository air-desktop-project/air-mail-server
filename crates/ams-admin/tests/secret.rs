// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que `account passwd` change, et surtout ce qu'il NE change pas.
//!
//! # Pourquoi ces essais existent
//!
//! Cette commande va être passée cinq fois sur des comptes de production, le
//! jour de la bascule de narro.ch. Le chemin qu'elle remplace — `account add`
//! avec un `--login` et rien d'autre — EFFACE toutes les adresses du compte
//! sans le dire : le compte s'authentifie encore, relève encore son courrier
//! ancien, et ne reçoit plus rien. Personne ne s'en aperçoit avant des heures.
//!
//! Ces essais tiennent donc les trois propriétés qui comptent, contre le
//! BINAIRE : le nouveau secret ouvre, l'ancien ferme, et les adresses sont
//! exactement celles d'avant.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Un répertoire d'essai, effacé quand il tombe.
struct Atelier(PathBuf);

impl Drop for Atelier {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Ouvre un répertoire d'essai à soi — le nom porte le fil, car ces essais
/// tournent en parallèle.
fn atelier(nom: &str) -> Atelier {
    let chemin = std::env::temp_dir().join(format!(
        "ams-secret-{nom}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&chemin);
    std::fs::create_dir_all(&chemin).expect("un répertoire d'essai");
    Atelier(chemin)
}

/// Lance l'outil en lui donnant `secret` sur l'entrée standard.
///
/// **LE MOT DE PASSE NE PASSE PAS PAR LA LIGNE DE COMMANDE**, ici comme en
/// production : ce que `ps` affiche, tout le monde le lit.
fn outil(secret: &str, arguments: &[&str]) -> (String, String, bool) {
    let mut enfant = Command::new(env!("CARGO_BIN_EXE_air-mail-admin"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("l'outil se lance");
    enfant
        .stdin
        .take()
        .expect("une entrée standard")
        .write_all(secret.as_bytes())
        .expect("le secret part");
    let issue = enfant.wait_with_output().expect("l'outil finit");
    (
        String::from_utf8_lossy(&issue.stdout).trim().to_string(),
        String::from_utf8_lossy(&issue.stderr).to_string(),
        issue.status.success(),
    )
}

/// Ce compte-là ouvre-t-il avec ce secret ?
///
/// On relit le magasin SUR LE DISQUE et on éprouve l'empreinte, plutôt que de
/// croire le message de l'outil : c'est le fichier que le serveur lira.
fn ouvre(fichier: &Path, login: &str, secret: &str) -> bool {
    let octets = std::fs::read(fichier).expect("le magasin se lit");
    let comptes = ams_config::decode_accounts(&octets).expect("le magasin se décode");
    ams_auth::authenticate(
        &comptes,
        &ams_sasl::Credentials {
            authorization_identity: b"",
            authentication_identity: login.as_bytes(),
            password: secret.as_bytes(),
        },
    )
}

/// Les adresses de ce compte, dans l'ordre où elles sont écrites.
fn adresses(fichier: &Path, login: &str) -> Vec<String> {
    let octets = std::fs::read(fichier).expect("le magasin se lit");
    ams_config::decode_accounts(&octets)
        .expect("le magasin se décode")
        .into_iter()
        .find(|compte| compte.login == login)
        .map(|compte| compte.addresses)
        .unwrap_or_default()
}

/// Le magasin d'essai : un compte, deux adresses, un secret connu.
fn magasin(atelier: &Atelier) -> PathBuf {
    let chemin = atelier.0.join("comptes.bin");
    let (_, erreur, bon) = outil(
        "secret-initial",
        &[
            "account",
            "add",
            chemin.to_str().expect("chemin"),
            "--login",
            "jean",
            "--address",
            "jean@narro.ch",
            "--address",
            "contact@narro.ch",
        ],
    );
    assert!(bon, "{erreur}");
    chemin
}

#[test]
fn le_secret_change_et_les_adresses_restent() {
    let atelier = atelier("change");
    let fichier = magasin(&atelier);

    let (dit, erreur, bon) = outil(
        "choisi-par-jean",
        &[
            "account",
            "passwd",
            fichier.to_str().expect("chemin"),
            "--login",
            "jean",
        ],
    );
    assert!(bon, "{erreur}");
    assert!(dit.contains("secret du compte `jean` changé"), "{dit}");

    // Les trois propriétés, et aucune ne se déduit des deux autres.
    assert!(ouvre(&fichier, "jean", "choisi-par-jean"), "le neuf ouvre");
    assert!(
        !ouvre(&fichier, "jean", "secret-initial"),
        "L'ANCIEN NE DOIT PLUS OUVRIR"
    );
    assert_eq!(
        adresses(&fichier, "jean"),
        ["jean@narro.ch", "contact@narro.ch"],
        "LES ADRESSES SONT CELLES D'AVANT"
    );
}

/// **LE CONTRE-EXEMPLE, ET C'EST LUI QUI JUSTIFIE LA COMMANDE.**
///
/// `account add` avec le seul `--login` fait très exactement ce qu'on cherche à
/// éviter. L'essai le CONSTATE plutôt que de le décrire : le jour où `add`
/// changerait d'avis, il faudra revenir ici, et cette page dira pourquoi la
/// commande existe.
#[test]
fn account_add_efface_les_adresses_et_c_est_le_piege() {
    let atelier = atelier("piege");
    let fichier = magasin(&atelier);

    let (_, erreur, bon) = outil(
        "secret-neuf",
        &[
            "account",
            "add",
            fichier.to_str().expect("chemin"),
            "--login",
            "jean",
        ],
    );
    assert!(bon, "{erreur}");
    assert!(ouvre(&fichier, "jean", "secret-neuf"), "le secret a changé");
    assert!(
        adresses(&fichier, "jean").is_empty(),
        "`add` remplace le compte ENTIER — c'est le piège que `passwd` évite"
    );
}

/// Un compte inconnu est une ERREUR, et le magasin n'est pas touché.
///
/// C'est ce qui sépare `passwd` d'`add` : une faute de frappe sur `--login`
/// ferait créer par `add` un compte fantôme, sans adresse, portant le mot de
/// passe qu'on croyait poser ailleurs — et le vrai compte garderait l'ancien.
#[test]
fn un_compte_inconnu_est_refuse_sans_rien_changer() {
    let atelier = atelier("inconnu");
    let fichier = magasin(&atelier);
    let avant = std::fs::read(&fichier).expect("le magasin se lit");

    let (_, erreur, bon) = outil(
        "peu-importe",
        &[
            "account",
            "passwd",
            fichier.to_str().expect("chemin"),
            "--login",
            "jeanne",
        ],
    );
    assert!(!bon, "un compte inconnu doit faire échouer");
    assert!(erreur.contains("aucun compte `jeanne`"), "{erreur}");
    assert!(
        erreur.contains("account list"),
        "le message doit dire où regarder : {erreur}"
    );

    assert_eq!(
        std::fs::read(&fichier).expect("le magasin se lit"),
        avant,
        "LE MAGASIN NE DOIT PAS AVOIR BOUGÉ"
    );
    assert!(ouvre(&fichier, "jean", "secret-initial"), "`jean` intact");
}
