// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que `config write` fait du secret de scellement, éprouvé par le BINAIRE.
//!
//! # Pourquoi ces essais existent
//!
//! La tranche qui a ouvert l'API REST a été vérifiée À LA MAIN : neuf commandes
//! tapées, neuf sorties lues. C'est ce qu'il fallait pour l'écrire, et cela ne
//! garde rien — une vérification qu'on ne peut pas rejouer n'est pas une garde.
//!
//! # Ce qu'ils éprouvent que `jeton.rs` n'éprouve pas
//!
//! Celui-là vérifie un jeton CRYPTOGRAPHIQUEMENT, mais contre une clé que
//! l'essai a posée lui-même dans la configuration. Le chemin qui manquait est
//! celui-ci : un secret TIRÉ PAR L'OUTIL scelle-t-il un jeton que la clé relue
//! DANS LE FICHIER QU'IL A ÉCRIT sait vérifier ? C'est la boucle entière, et
//! c'est elle qui dirait qu'un encodage hexadécimal de travers, ou une longueur
//! d'un octet en moins, a passé la relecture sans que personne ne s'en aperçoive.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Un répertoire d'essai, effacé quand il tombe.
struct Atelier(PathBuf);

impl Drop for Atelier {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Ouvre un répertoire d'essai à soi.
///
/// Le nom porte le fil : ces essais tournent en parallèle, et deux qui
/// partageraient un répertoire écriraient la même configuration.
fn atelier(nom: &str) -> Atelier {
    let chemin = std::env::temp_dir().join(format!(
        "ams-scellement-{nom}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&chemin);
    std::fs::create_dir_all(&chemin).expect("un répertoire d'essai");
    Atelier(chemin)
}

/// Lance l'outil, et rend (sortie standard, erreur standard, succès).
fn outil(arguments: &[&str]) -> (String, String, bool) {
    let issue = Command::new(env!("CARGO_BIN_EXE_air-mail-admin"))
        .args(arguments)
        .output()
        .expect("l'outil se lance");
    (
        String::from_utf8_lossy(&issue.stdout).trim().to_string(),
        String::from_utf8_lossy(&issue.stderr).to_string(),
        issue.status.success(),
    )
}

/// De quoi ouvrir l'API : un certificat et une clé, dont le CONTENU n'importe
/// pas ici — l'outil vérifie qu'on les a nommés, le serveur qu'ils sont bons.
fn paire(atelier: &Atelier) -> (String, String) {
    let cert = atelier.0.join("chaine.pem");
    let clef = atelier.0.join("cle.pem");
    std::fs::write(&cert, b"").expect("écrit");
    std::fs::write(&clef, b"").expect("écrit");
    (cert.display().to_string(), clef.display().to_string())
}

/// Écrit une configuration qui ouvre l'API, et rend son chemin.
fn ecrire_avec_api(atelier: &Atelier, en_plus: &[&str]) -> PathBuf {
    let (cert, clef) = paire(atelier);
    let chemin = atelier.0.join("ams.conf");
    let mut arguments = vec![
        "config",
        "write",
        &chemin.to_str().expect("chemin"),
        "--domain",
        "mail.example.com",
        "--listen-http",
        "127.0.0.1:8443",
        "--tls-cert",
        &cert,
        "--tls-key",
        &clef,
    ];
    arguments.extend_from_slice(en_plus);
    let (_, erreur, bon) = outil(&arguments);
    assert!(bon, "l'écriture doit réussir : {erreur}");
    chemin
}

/// Le secret que porte une configuration écrite.
fn secret_de(chemin: &Path) -> String {
    let octets = std::fs::read(chemin).expect("relu");
    ams_config::decode(&octets).expect("décodable").token_key
}

/// **LA BOUCLE ENTIÈRE : CE QUE L'OUTIL TIRE SCELLE CE QU'IL FRAPPE.**
///
/// Le secret n'a été ni choisi ni vu par cet essai : il est tiré du noyau par
/// `config write`, relu du fichier que celui-ci a posé, et il doit vérifier un
/// jeton frappé par la même commande que l'exploitant taperait.
#[test]
fn un_secret_tire_par_l_outil_scelle_un_jeton_verifiable() {
    let atelier = atelier("boucle");
    let chemin = ecrire_avec_api(&atelier, &[]);

    // LE SECRET EST BIEN UNE CLÉ, ce qui n'allait pas de soi : trente-deux
    // octets exactement, en hexadécimal, sinon `key_from_hex` la refuse.
    let secret = secret_de(&chemin);
    assert_eq!(secret.len(), 64, "trente-deux octets en hexadécimal");
    let clef = ams_api::key_from_hex(&secret).expect("le secret tiré est une clé licite");

    let (jeton, erreur, bon) = outil(&[
        "token",
        chemin.to_str().expect("chemin"),
        "--login",
        "thierry",
    ]);
    assert!(bon, "la frappe doit réussir : {erreur}");

    let mut place = [0_u8; ams_api::TOKEN_OCTETS_MAX];
    let vu = ams_api::verify(&clef, jeton.as_bytes(), 1_000_000, &mut place)
        .expect("le jeton se vérifie avec la clé du fichier");
    assert_eq!(vu.login, "thierry");
    assert!(
        vu.scope
            .allows(ams_api::Area::Admin, ams_api::Rights::Write),
        "et il ouvre l'administration"
    );
}

/// **LE SECRET EST REPRIS D'UNE ÉCRITURE À L'AUTRE**, si bien que changer autre
/// chose dans la configuration ne révoque rien.
///
/// C'est tout l'intérêt de le reprendre plutôt que de le retirer à chaque fois :
/// ajouter un domaine hébergé ne doit pas déconnecter l'administrateur.
#[test]
fn le_secret_survit_a_une_reecriture() {
    let atelier = atelier("reprise");
    let chemin = ecrire_avec_api(&atelier, &[]);
    let avant = secret_de(&chemin);

    let (dit, erreur, bon) = outil(&[
        "config",
        "write",
        chemin.to_str().expect("chemin"),
        "--domain",
        "mail.example.com",
        "--hosted",
        "autre.test",
        "--listen-http",
        "127.0.0.1:8443",
        "--tls-cert",
        &atelier.0.join("chaine.pem").display().to_string(),
        "--tls-key",
        &atelier.0.join("cle.pem").display().to_string(),
    ]);
    assert!(bon, "{erreur}");
    assert!(dit.contains("REPRIS"), "l'outil doit le dire : {dit}");
    assert_eq!(
        secret_de(&chemin),
        avant,
        "le secret a changé sans qu'on le demande"
    );
}

/// **LA ROTATION CHANGE LE SECRET, ET C'EST CE QU'ON LUI DEMANDE.**
///
/// Un jeton frappé avant ne doit plus se vérifier : sans quoi « renouveler »
/// n'aurait révoqué personne, tout en le laissant croire.
#[test]
fn la_rotation_invalide_ce_qui_a_ete_frappe_avant() {
    let atelier = atelier("rotation");
    let chemin = ecrire_avec_api(&atelier, &[]);
    let (ancien_jeton, _, bon) = outil(&[
        "token",
        chemin.to_str().expect("chemin"),
        "--login",
        "thierry",
    ]);
    assert!(bon);
    let ancien_secret = secret_de(&chemin);

    let (dit, erreur, bon) = outil(&[
        "config",
        "write",
        chemin.to_str().expect("chemin"),
        "--domain",
        "mail.example.com",
        "--listen-http",
        "127.0.0.1:8443",
        "--tls-cert",
        &atelier.0.join("chaine.pem").display().to_string(),
        "--tls-key",
        &atelier.0.join("cle.pem").display().to_string(),
        "--rotate-token-key",
    ]);
    assert!(bon, "{erreur}");
    assert!(dit.contains("RENOUVELÉ"), "l'outil doit le dire : {dit}");

    let neuf_secret = secret_de(&chemin);
    assert_ne!(neuf_secret, ancien_secret, "la rotation n'a rien changé");

    let clef = ams_api::key_from_hex(&neuf_secret).expect("licite");
    let mut place = [0_u8; ams_api::TOKEN_OCTETS_MAX];
    ams_api::verify(&clef, ancien_jeton.as_bytes(), 1_000_000, &mut place)
        .expect_err("le jeton d'avant ne doit plus valoir");
}

/// **SANS API, AUCUN SECRET N'EST TIRÉ.** L'absence de valeur est l'absence de
/// service ; en inventer un mettrait dans le fichier une clé que rien n'emploie.
#[test]
fn sans_api_le_fichier_ne_porte_aucun_secret() {
    let atelier = atelier("sans-api");
    let chemin = atelier.0.join("ams.conf");
    let (dit, erreur, bon) = outil(&[
        "config",
        "write",
        chemin.to_str().expect("chemin"),
        "--domain",
        "mail.example.com",
    ]);
    assert!(bon, "{erreur}");
    assert!(secret_de(&chemin).is_empty());
    // ON CHERCHE LA LIGNE, ET NON LE MOT. Le chemin du répertoire d'essai porte
    // « scellement » dans son nom, et l'outil affiche ce chemin : chercher le
    // mot faisait échouer l'essai sur sa propre installation.
    assert!(
        !dit.lines().any(|ligne| ligne.starts_with("scellement :")),
        "et l'outil n'en dit rien : {dit}"
    );
}

/// **FERMER L'API NE JETTE PAS LE SECRET**, ce qui rend le geste réversible :
/// la rouvrir laisse valables les jetons qu'on avait frappés.
#[test]
fn fermer_l_api_conserve_le_secret() {
    let atelier = atelier("fermeture");
    let chemin = ecrire_avec_api(&atelier, &[]);
    let avant = secret_de(&chemin);

    let (_, erreur, bon) = outil(&[
        "config",
        "write",
        chemin.to_str().expect("chemin"),
        "--domain",
        "mail.example.com",
    ]);
    assert!(bon, "{erreur}");
    let config = ams_config::decode(&std::fs::read(&chemin).expect("relu")).expect("décodable");
    assert!(config.listen_http.is_empty(), "l'API est bien refermée");
    assert_eq!(config.token_key, avant, "et le secret est resté");
}

/// **UN FICHIER QU'ON NE RECONNAÎT PAS NE S'ÉCRASE PAS.**
///
/// Un chemin tapé de travers désigne le fichier de quelqu'un d'autre. C'est la
/// conséquence heureuse de relire la cible : `config write` la regardait déjà
/// pour reprendre le secret, et il peut donc refuser ce qu'il ne reconnaît pas.
#[test]
fn un_fichier_etranger_n_est_pas_ecrase() {
    let atelier = atelier("etranger");
    let chemin = atelier.0.join("passwd");
    let contenu = b"racine:x:0:0::/root:/bin/sh\n";
    std::fs::write(&chemin, contenu).expect("écrit");

    let (_, erreur, bon) = outil(&[
        "config",
        "write",
        chemin.to_str().expect("chemin"),
        "--domain",
        "mail.example.com",
    ]);
    assert!(!bon, "l'outil doit refuser");
    assert!(
        erreur.contains("n'est pas une configuration"),
        "et dire pourquoi : {erreur}"
    );
    assert_eq!(
        std::fs::read(&chemin).expect("relu"),
        contenu,
        "le fichier a été touché"
    );
}
