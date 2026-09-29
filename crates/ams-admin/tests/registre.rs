// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **`air-mail-admin registre` vérifie et fouille le registre de réception**
//! (0.2.44).
//!
//! Ces essais lancent le binaire sur des fichiers écrits comme le serveur les
//! écrit : un jour scellé, puis le jour en cours qui le cite.

use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;

use ams_config::registre::{
    EnTetes, Enregistrement, Entete, Inverse, IssueSession, IssueTransaction, Salut, Sceau,
    Session, Transaction, trame, verifier,
};

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

fn configuration(atelier: &Atelier, registre: Option<&str>) -> String {
    let fichier = atelier.0.join("ams.conf").display().to_string();
    let mut arguments = vec![
        "config",
        "write",
        fichier.as_str(),
        "--domain",
        "mail.example.com",
        "--hosted",
        "example.com",
    ];
    if let Some(repertoire) = registre {
        arguments.extend(["--registre", repertoire]);
    }
    let (_, erreur, code) = outil(&arguments);
    assert_eq!(code, Some(0), "{erreur}");
    fichier
}

fn session(id: u8, pair: IpAddr, helo: &str) -> Enregistrement {
    Enregistrement::Session(Box::new(Session {
        id: [id; 16],
        ouverte: 1,
        fermee: 2,
        ecoute: String::from("0.0.0.0:25"),
        pair,
        port: 40_000,
        inverse: Inverse::default(),
        salut: Salut {
            nom: String::from(helo),
            ..Salut::default()
        },
        tls: None,
        commandes: 5,
        messages: 1,
        authentifiee: false,
        mecanisme: String::new(),
        issue: IssueSession::Servie,
        erreur: String::new(),
        version: String::from("0.2.44"),
        presentation: String::new(),
    }))
}

fn transaction(id: u8, pair: IpAddr, message_id: &str) -> Enregistrement {
    Enregistrement::Transaction(Box::new(Transaction {
        session: [id; 16],
        numero: 1,
        recue: 3,
        soumission: false,
        mail_from: String::from("a@expediteur.example"),
        destinataires: Vec::new(),
        octets: 10,
        entetes: EnTetes {
            message_id: String::from(message_id),
            ..EnTetes::default()
        },
        spf: None,
        dkim: Vec::new(),
        dmarc: None,
        authentification: String::new(),
        issue: IssueTransaction::Acceptee,
        inverse: Inverse::default(),
        salut: Salut::default(),
        pair,
        tls: None,
        presentation: String::new(),
    }))
}

/// Un fichier : son entête, ces enregistrements, et son sceau s'il le faut.
fn fichier(
    jour: &str,
    precedent: Option<[u8; 32]>,
    contenu: &[Enregistrement],
    scelle: bool,
) -> Vec<u8> {
    let mut octets = trame(&Enregistrement::Entete(Entete {
        format: ams_config::registre::FORMAT,
        jour: String::from(jour),
        precedent,
        version: String::from("0.2.44"),
        ouvert: 0,
    }))
    .expect("codable");
    for quoi in contenu {
        octets.extend(trame(quoi).expect("codable"));
    }
    if scelle {
        let bilan = verifier(&octets).expect("juste");
        octets.extend(
            trame(&Enregistrement::Sceau(Sceau {
                enregistrements: bilan.enregistrements,
                condensat: bilan.condensat,
                scelle: 9,
                tronques: 0,
            }))
            .expect("codable"),
        );
    }
    octets
}

fn v4(dernier: u8) -> IpAddr {
    IpAddr::from([192, 0, 2, dernier])
}

/// Deux jours : le premier scellé, le second ouvert qui le cite.
fn deux_jours(atelier: &Atelier, chaine_juste: bool) -> String {
    let repertoire = atelier.0.join("registre");
    std::fs::create_dir_all(&repertoire).expect("répertoire");
    let lundi = fichier(
        "2026-09-28",
        None,
        &[
            session(1, v4(7), "mx.expediteur.example"),
            transaction(1, v4(7), "<un@expediteur.example>"),
        ],
        true,
    );
    let condensat = verifier(&lundi).expect("juste").condensat;
    std::fs::write(repertoire.join("2026-09-28.amsr"), &lundi).expect("écrit");
    let mardi = fichier(
        "2026-09-29",
        Some(if chaine_juste { condensat } else { [0; 32] }),
        &[
            session(2, v4(9), "autre.example"),
            transaction(2, v4(9), "<deux@autre.example>"),
        ],
        false,
    );
    std::fs::write(repertoire.join("2026-09-29.amsr"), &mardi).expect("écrit");
    std::fs::write(repertoire.join("notes.txt"), b"ignore").expect("écrit");
    configuration(atelier, Some(&repertoire.display().to_string()))
}

#[test]
fn un_registre_juste_se_verifie() {
    let atelier = atelier("registre-juste");
    let config = deux_jours(&atelier, true);
    let (sortie, erreur, code) = outil(&["registre", "verifie", &config]);
    assert_eq!(code, Some(0), "{sortie}{erreur}");
    assert!(
        sortie.contains("2026-09-28.amsr : 3 enregistrement(s), scellé, premier"),
        "{sortie}"
    );
    assert!(
        sortie.contains(
            "2026-09-29.amsr : 3 enregistrement(s), ouvert (le jour en cours), chaîné au précédent"
        ),
        "{sortie}"
    );
}

#[test]
fn une_chaine_rompue_se_voit() {
    let atelier = atelier("registre-rompu");
    let config = deux_jours(&atelier, false);
    let (sortie, erreur, code) = outil(&["registre", "verifie", &config]);
    assert_eq!(code, Some(1), "{sortie}{erreur}");
    assert!(sortie.contains("CHAÎNE ROMPUE"), "{sortie}");
    // Un fichier illisible, et un jour passé resté ouvert.
    let repertoire = atelier.0.join("registre");
    std::fs::write(repertoire.join("2026-09-27.amsr"), b"abime").expect("écrit");
    std::fs::write(
        repertoire.join("2026-09-30.amsr"),
        fichier("2026-09-30", None, &[], false),
    )
    .expect("écrit");
    let (sortie, _, code) = outil(&["registre", "verifie", &config]);
    assert_eq!(code, Some(1));
    assert!(sortie.contains("2026-09-27.amsr : FAUTE"), "{sortie}");
    assert!(sortie.contains("NON SCELLÉ"), "{sortie}");
}

#[test]
fn le_registre_se_fouille() {
    let atelier = atelier("registre-fouille");
    let config = deux_jours(&atelier, true);
    let chercher = |filtres: &[&str]| -> Vec<String> {
        let mut arguments = vec!["registre", "cherche", config.as_str()];
        arguments.extend(filtres);
        let (sortie, erreur, code) = outil(&arguments);
        assert_eq!(code, Some(0), "{erreur}");
        sortie.lines().map(String::from).collect()
    };
    // Sans filtre : tout, entêtes et sceau compris, dans l'ordre du temps.
    let tout = chercher(&[]);
    assert_eq!(tout.len(), 7, "{tout:?}");
    assert!(tout[0].contains("\"type\":\"entete\""));
    // Par adresse, par domaine, par Message-ID, par session.
    let par_ip = chercher(&["--ip", "192.0.2.7"]);
    assert_eq!(par_ip.len(), 2, "{par_ip:?}");
    assert!(par_ip.iter().all(|ligne| ligne.contains("192.0.2.7")));
    // Les deux transactions partent de `a@expediteur.example` ; la première
    // session s'annonce `mx.expediteur.example`, la seconde `autre.example`.
    assert_eq!(chercher(&["--domaine", "EXPEDITEUR.example"]).len(), 3);
    assert_eq!(chercher(&["--domaine", "autre.example"]).len(), 1);
    let par_id = chercher(&["--message-id", "deux@"]);
    assert_eq!(par_id.len(), 1);
    assert!(par_id[0].contains("<deux@autre.example>"));
    assert_eq!(chercher(&["--session", "0202"]).len(), 2);
    // Les jours, et la borne — les plus récents retenus.
    assert_eq!(chercher(&["--depuis", "2026-09-29"]).len(), 3);
    assert_eq!(chercher(&["--jusqu-a", "2026-09-28"]).len(), 4);
    let dernier = chercher(&["--limit", "1"]);
    assert_eq!(dernier.len(), 1);
    assert!(
        dernier[0].contains("\"type\":\"transaction\""),
        "{dernier:?}"
    );
}

#[test]
fn une_fouille_mal_dite_se_refuse() {
    let ici = atelier("registre-refus");
    let config = deux_jours(&ici, true);
    for (filtres, extrait) in [
        (&["--ip", "pas-une-ip"][..], "n'est pas une adresse IP"),
        (&["--depuis", "29/09/2026"][..], "n'est pas un jour"),
        (&["--limit", "0"][..], "au moins un"),
        (&["--ip"][..], "attend une valeur"),
        (&["--inconnue", "x"][..], "ne connaît pas"),
    ] {
        let mut arguments = vec!["registre", "cherche", config.as_str()];
        arguments.extend(filtres);
        let (_, erreur, code) = outil(&arguments);
        assert_eq!(code, Some(2), "{filtres:?}");
        assert!(erreur.contains(extrait), "{filtres:?} : {erreur}");
    }
    // Une configuration sans registre.
    let sans = atelier("registre-sans");
    let fichier = configuration(&sans, None);
    let (_, erreur, code) = outil(&["registre", "verifie", &fichier]);
    assert_eq!(code, Some(1));
    assert!(erreur.contains("ne tient pas de registre"), "{erreur}");
}
