// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **`air-mail-admin token` frappe un jeton d'administration.**
//!
//! # POURQUOI CETTE COMMANDE EXISTE, ET POURQUOI ELLE EST ICI
//!
//! Un mot de passe ouvre le courrier, la soumission et la supervision de SON
//! compte. Il n'ouvre pas l'administration, et cette limite est dans le code du
//! serveur, non dans une configuration : un réglage finirait par être basculé, et
//! un compte compromis deviendrait alors le serveur entier.
//!
//! Il reste donc à frapper le jeton depuis l'endroit qui tient déjà le secret de
//! scellement — la machine du serveur, par qui peut lire sa configuration. C'est
//! la même autorité que celle qui peut arrêter le service ou lire les boîtes ; on
//! n'en ajoute aucune.
//!
//! # CES ESSAIS LANCENT LE BINAIRE
//!
//! Ce qu'on éprouve est ce qu'on livre : la lecture des arguments, celle de la
//! configuration, et ce qui sort sur la sortie standard. Appeler les fonctions
//! directement laisserait le câblage de `main` sans témoin.

use std::path::{Path, PathBuf};
use std::process::Command;

use ams_config::{Configuration, Timeouts, Tls};
use ams_guard::Thresholds;
use ams_proto_smtp::Limits;

/// Le secret de scellement d'essai — trente-deux octets, en hexadécimal.
const CLEF: &str = "0000000000000000000000000000000000000000000000000000000000000001";

/// Un répertoire d'essai, effacé quand il tombe.
struct Atelier(PathBuf);

impl Drop for Atelier {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Ouvre un répertoire d'essai à soi.
fn atelier(nom: &str) -> Atelier {
    let chemin = std::env::temp_dir().join(format!("ams-admin-{nom}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&chemin);
    std::fs::create_dir_all(&chemin).expect("un répertoire d'essai");
    Atelier(chemin)
}

/// Écrit une configuration portant ce secret de scellement.
fn configuration(repertoire: &Path, clef: &str) -> PathBuf {
    let config = Configuration {
        domain: String::from("mail.example.com"),
        listen: String::from("127.0.0.1:0"),
        maildir: repertoire.join("boite").display().to_string(),
        hosted: vec![String::from("example.com")],
        max_recipients: 100,
        listen_http: String::new(),
        listen_h3: String::new(),
        token_key: String::from(clef),
        max_message_octets: 10_485_760,
        max_connections: 16,
        limits: Limits::DEFAULT,
        guard: Thresholds::DEFAULT,
        tracked_sources: 64,
        // AUCUNE ÉMISSION : ces essais reçoivent, ils n'émettent pas.
        relay: ams_config::Relay::default(),
        // MTA-STS NON ÉVALUÉ : ces essais ne joignent aucun hôte de politique.
        mtasts: ams_config::Mtasts::default(),
        timeouts: Timeouts {
            command_seconds: 10,
            data_seconds: 10,
        },
        tls: Tls {
            certificate_chain_path: String::new(),
            private_key_path: String::new(),
        },
        spf: ams_config::Spf::default(),
        dmarc: ams_config::Dmarc::default(),
        dkim: ams_config::Dkim::default(),
        accounts: String::new(),
        listen_pop3: String::new(),
        listen_imap: String::new(),
    };
    let chemin = repertoire.join("ams.conf");
    std::fs::write(&chemin, ams_config::encode(&config).expect("encodable")).expect("écriture");
    chemin
}

/// Lance l'outil, et rend (sortie standard, erreur standard, succès).
fn frapper(arguments: &[&str]) -> (String, String, bool) {
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

/// **LE JETON FRAPPÉ PORTE L'ADMINISTRATION, ET RIEN D'AUTRE.**
///
/// Y ajouter le courrier ferait de ce jeton un passe-partout, alors qu'il existe
/// pour une tâche précise.
#[test]
fn le_jeton_frappe_porte_l_administration_et_rien_d_autre() {
    let atelier = atelier("frappe");
    let config = configuration(&atelier.0, CLEF);
    let (dit, erreur, bon) = frapper(&["token", &config.display().to_string(), "--login", "root"]);
    assert!(bon, "l'outil doit réussir : {erreur}");
    assert!(!dit.is_empty(), "et écrire le jeton sur sa sortie standard");

    let clef = ams_api::key_from_hex(CLEF).expect("licite");
    let mut place = [0_u8; ams_api::TOKEN_OCTETS_MAX];
    let maintenant = 1_000_000_u64;
    let jeton = ams_api::verify(&clef, dit.as_bytes(), maintenant, &mut place).expect("vérifiable");
    assert_eq!(jeton.login, "root", "il dit qui agit");
    assert!(
        jeton
            .scope
            .allows(ams_api::Area::Admin, ams_api::Rights::Write),
        "il ouvre l'administration"
    );
    for domaine in [
        ams_api::Area::Mail,
        ams_api::Area::Submit,
        ams_api::Area::Observe,
    ] {
        assert!(
            !jeton.scope.allows(domaine, ams_api::Rights::Read),
            "et rien d'autre : {domaine:?}"
        );
    }
}

/// **UN QUART D'HEURE PAR DÉFAUT, ET C'EST LE POINT.**
///
/// Ce jeton ouvre le serveur entier ; un jeton qui traîne dans un historique de
/// terminal est un jeton volé. Le refrapper coûte une commande.
#[test]
fn la_duree_par_defaut_est_courte_et_se_regle() {
    let atelier = atelier("duree");
    let config = configuration(&atelier.0, CLEF);
    let clef = ams_api::key_from_hex(CLEF).expect("licite");

    let lire = |arguments: &[&str]| {
        let (dit, erreur, bon) = frapper(arguments);
        assert!(bon, "{erreur}");
        let mut place = [0_u8; ams_api::TOKEN_OCTETS_MAX];
        // On ne vérifie pas la date exacte — l'horloge tourne pendant l'essai —,
        // mais qu'il vit encore juste avant et plus juste après.
        let avant = ams_api::verify(&clef, dit.as_bytes(), 0, &mut place);
        assert!(avant.is_ok(), "il vit à l'instant zéro");
        dit
    };

    let chemin = config.display().to_string();
    let court = lire(&["token", &chemin, "--login", "root", "--minutes", "1"]);
    let long = lire(&["token", &chemin, "--login", "root", "--minutes", "60"]);
    assert_ne!(court, long, "deux frappes ne donnent pas le même jeton");
}

/// **UN JETON DIFFÈRE DU PRÉCÉDENT, MÊME POUR LE MÊME NOM.**
///
/// L'aléa vient du noyau, et c'est lui qui permettrait de révoquer un jeton seul.
/// Sans lui, deux jetons frappés dans la même seconde seraient le même.
#[test]
fn deux_frappes_ne_donnent_pas_le_meme_jeton() {
    let atelier = atelier("alea");
    let chemin = configuration(&atelier.0, CLEF).display().to_string();
    let une = frapper(&["token", &chemin, "--login", "root"]).0;
    let deux = frapper(&["token", &chemin, "--login", "root"]).0;
    assert_ne!(une, deux);
}

/// **CE QUI MANQUE SE DIT, ET L'OUTIL ÉCHOUE.**
///
/// Celui qui lit ces refus a écrit la configuration : il a le droit de savoir ce
/// qu'il doit corriger.
#[test]
fn ce_qui_manque_se_dit() {
    let atelier = atelier("refus");
    let bonne = configuration(&atelier.0, CLEF).display().to_string();
    let sans_clef = {
        let ailleurs = atelier.0.join("sans-clef");
        std::fs::create_dir_all(&ailleurs).expect("un répertoire");
        configuration(&ailleurs, "").display().to_string()
    };

    let cas: [(&[&str], &str); 6] = [
        (&["token", &bonne], "attend un `--login`"),
        (&["token", &bonne, "--login"], "attend un nom"),
        (
            &["token", &bonne, "--login", "root", "--minutes"],
            "attend un nombre",
        ),
        (
            &["token", &bonne, "--login", "root", "--minutes", "0"],
            "hors des bornes",
        ),
        (
            &["token", &bonne, "--login", "root", "--minutes", "721"],
            "hors des bornes",
        ),
        (&["token", &sans_clef, "--login", "root"], "aucun secret"),
    ];
    for (arguments, indice) in cas {
        let (dit, erreur, bon) = frapper(arguments);
        assert!(!bon, "cela devait échouer : {arguments:?}");
        assert!(dit.is_empty(), "et n'écrire aucun jeton : {dit}");
        assert!(
            erreur.contains(indice),
            "on attendait « {indice} » : {erreur}"
        );
    }
}

/// **UNE CONFIGURATION QU'ON NE PEUT PAS LIRE SE DIT AUSSI.**
#[test]
fn une_configuration_illisible_se_dit() {
    let atelier = atelier("illisible");
    let absente = atelier.0.join("rien.conf").display().to_string();
    let (_dit, erreur, bon) = frapper(&["token", &absente, "--login", "root"]);
    assert!(!bon);
    assert!(erreur.contains("rien.conf"), "{erreur}");

    let cassee = atelier.0.join("cassee.conf");
    std::fs::write(&cassee, b"ceci n'est pas du Cap'n Proto").expect("écriture");
    let (_dit, erreur, bon) = frapper(&["token", &cassee.display().to_string(), "--login", "root"]);
    assert!(!bon);
    assert!(erreur.contains("cassee.conf"), "{erreur}");
}

/// **UN ARGUMENT INATTENDU N'EST PAS IGNORÉ.**
///
/// L'ignorer ferait frapper un jeton que l'exploitant croit réglé autrement.
#[test]
fn un_argument_inattendu_se_refuse() {
    let atelier = atelier("inattendu");
    let chemin = configuration(&atelier.0, CLEF).display().to_string();
    let (_dit, erreur, bon) = frapper(&["token", &chemin, "--login", "root", "--jours", "3"]);
    assert!(!bon);
    assert!(erreur.contains("inattendu"), "{erreur}");
}
