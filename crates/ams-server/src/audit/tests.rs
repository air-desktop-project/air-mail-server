// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::{Audit, Evenement, ROTATION_OCTETS, ajouter, entree_valide, ligne};
use std::path::PathBuf;
use std::string::String;
use std::sync::atomic::AtomicU64;
use std::vec::Vec;

/// Un répertoire d'essai à soi, effacé d'abord.
fn atelier(nom: &str) -> PathBuf {
    let chemin = std::env::temp_dir().join(format!("ams-audit-{}-{nom}", std::process::id()));
    let _ = std::fs::remove_dir_all(&chemin);
    chemin
}

fn texte(octets: &[u8]) -> String {
    String::from_utf8(octets.to_vec()).expect("de l'UTF-8")
}

/// Attend que le fil d'écriture ait écrit `combien` entrées pour ce compte.
fn attendre(audit: &Audit, compte: &str, combien: usize) -> Vec<Vec<u8>> {
    for _ in 0..500 {
        let lues = audit.lire(compte, 100);
        if lues.len() >= combien {
            return lues;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("le fil d'écriture n'a pas écrit {combien} entrée(s) pour `{compte}`");
}

#[test]
fn chaque_evenement_s_ecrit_sur_une_ligne() {
    let source = Some("2001:db8::1");
    let cas: [(Evenement<'_>, &str); 13] = [
        (
            Evenement::SessionOuverte { appareil: None },
            r#"{"at":7,"event":"session.opened","source":"2001:db8::1","device":null,"detail":"password"}"#,
        ),
        (
            Evenement::SessionOuverte {
                appareil: Some("ab12"),
            },
            r#"{"at":7,"event":"session.opened","source":"2001:db8::1","device":"ab12","detail":"device"}"#,
        ),
        (
            Evenement::Refus { porte: "password" },
            r#"{"at":7,"event":"auth.refused","source":"2001:db8::1","device":null,"detail":"password"}"#,
        ),
        (
            Evenement::AppareilEnrole {
                appareil: "ab12",
                nom: "Téléphone",
            },
            r#"{"at":7,"event":"device.enrolled","source":"2001:db8::1","device":"ab12","detail":"Téléphone"}"#,
        ),
        (
            Evenement::AppareilAppaire {
                appareil: "cd34",
                nom: "Tablette",
            },
            r#"{"at":7,"event":"device.paired","source":"2001:db8::1","device":"cd34","detail":"Tablette"}"#,
        ),
        (
            Evenement::AppareilRevoque { appareil: "ab12" },
            r#"{"at":7,"event":"device.revoked","source":"2001:db8::1","device":"ab12","detail":null}"#,
        ),
        (
            Evenement::SecretChange { par: "admin" },
            r#"{"at":7,"event":"password.changed","source":"2001:db8::1","device":null,"detail":"admin"}"#,
        ),
        (
            Evenement::ApplicatifCree {
                id: "0123",
                nom: "Thunderbird",
            },
            r#"{"at":7,"event":"app-password.created","source":"2001:db8::1","device":null,"detail":"0123","name":"Thunderbird"}"#,
        ),
        (
            Evenement::ApplicatifRevoque { id: "0123" },
            r#"{"at":7,"event":"app-password.revoked","source":"2001:db8::1","device":null,"detail":"0123"}"#,
        ),
        (
            Evenement::DelegationPosee {
                titulaire: "support",
                delegue: "marie",
            },
            r#"{"at":7,"event":"delegation.granted","source":"2001:db8::1","owner":"support","delegate":"marie"}"#,
        ),
        (
            Evenement::DelegationRetiree {
                titulaire: "support",
                delegue: "marie",
            },
            r#"{"at":7,"event":"delegation.removed","source":"2001:db8::1","owner":"support","delegate":"marie"}"#,
        ),
        (
            Evenement::Abonnement {
                appareil: "ab12",
                canal: "apns",
            },
            r#"{"at":7,"event":"push.subscribed","source":"2001:db8::1","device":"ab12","detail":"apns"}"#,
        ),
        (
            Evenement::Desabonnement { appareil: "ab12" },
            r#"{"at":7,"event":"push.unsubscribed","source":"2001:db8::1","device":"ab12","detail":null}"#,
        ),
    ];
    for (evenement, attendu) in cas {
        let ecrite = ligne(evenement, source, 7);
        assert_eq!(texte(&ecrite), format!("{attendu}\n"), "{evenement:?}");
        assert!(entree_valide(&ecrite).is_some(), "{attendu}");
    }
    assert_eq!(
        texte(&ligne(Evenement::InvitationEmise, None, 9)),
        "{\"at\":9,\"event\":\"invitation.issued\",\"source\":null,\"device\":null,\"detail\":null}\n"
    );
}

/// **UN NOM CHOISI PAR L'UTILISATEUR NE CASSE PAS LA LIGNE** : il s'échappe,
/// et un nom démesuré se coupe sur une frontière de caractère.
#[test]
fn un_nom_s_echappe_et_se_borne() {
    let ecrite = ligne(
        Evenement::AppareilEnrole {
            appareil: "ab",
            nom: "a\"b\nc",
        },
        None,
        1,
    );
    let dite = texte(&ecrite);
    assert!(dite.contains(r#""detail":"a\"b\nc""#), "{dite}");
    assert_eq!(dite.matches('\n').count(), 1, "{dite}");

    let long = "é".repeat(100);
    let dite = texte(&ligne(
        Evenement::AppareilEnrole {
            appareil: "ab",
            nom: &long,
        },
        None,
        1,
    ));
    // Cent vingt-huit octets, soit soixante-quatre « é » entiers.
    assert!(dite.contains(&"é".repeat(64)), "{dite}");
    assert!(!dite.contains(&"é".repeat(65)), "{dite}");
}

#[test]
fn seule_une_ligne_entiere_est_une_entree() {
    assert_eq!(
        entree_valide(b"{\"at\":1,\"event\":\"x\"}\n"),
        Some(&b"{\"at\":1,\"event\":\"x\"}"[..])
    );
    // Sans fin de ligne : une écriture interrompue.
    assert_eq!(entree_valide(b"{\"at\":1,\"event\":\"x\"}"), None);
    // Une ligne interrompue suivie d'une autre.
    assert_eq!(
        entree_valide(b"{\"at\":1,\"ev{\"at\":2,\"event\":\"x\"}\n"),
        None
    );
    // Ni une autre forme.
    assert_eq!(entree_valide(b"[1]\n"), None);
    assert_eq!(entree_valide(b"{\"at\":1\n"), None);
}

#[test]
fn le_journal_s_ecrit_et_se_relit_du_plus_recent_au_plus_ancien() {
    let racine = atelier("relire");
    let audit = Audit::ouvrir(racine.clone()).expect("le journal s'ouvre");
    for rang in 1..=3_u64 {
        audit.noter(
            "marie",
            Evenement::SessionOuverte { appareil: None },
            Some("192.0.2.1"),
            rang,
        );
    }
    let lues = attendre(&audit, "marie", 3);
    let dates: Vec<String> = lues.iter().map(|entree| texte(&entree[..8])).collect();
    assert_eq!(dates, ["{\"at\":3,", "{\"at\":2,", "{\"at\":1,"]);
    assert_eq!(audit.lire("marie", 2).len(), 2);
    assert!(
        audit.lire("paul", 10).is_empty(),
        "un compte sans journal ne lit rien"
    );

    // **LE FICHIER EST À SON COMPTE SEUL**, et le répertoire aussi.
    use std::os::unix::fs::PermissionsExt as _;
    let mode = |chemin: &std::path::Path| {
        std::fs::metadata(chemin)
            .expect("présent")
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode(&racine), 0o700);
    assert_eq!(mode(&racine.join("marie.jsonl")), 0o600);

    // Oublier efface, dans l'ordre des écritures qui précèdent.
    audit.oublier("marie");
    for _ in 0..500 {
        if !racine.join("marie.jsonl").exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(audit.lire("marie", 10).is_empty());
    let _ = std::fs::remove_dir_all(&racine);
}

/// **UN NOM QUI N'EST PAS UN COMPTE NE DEVIENT PAS UN CHEMIN.**
#[test]
fn un_nom_qui_n_est_pas_un_compte_n_ecrit_rien() {
    let racine = atelier("chemin");
    let audit = Audit::ouvrir(racine.clone()).expect("le journal s'ouvre");
    for nom in ["../evade", ".cache", "", "a/b"] {
        audit.noter(nom, Evenement::InvitationEmise, None, 1);
        assert!(audit.lire(nom, 10).is_empty());
        audit.oublier(nom);
    }
    // Une entrée légitime après : la file l'écrit, et elle seule.
    audit.noter("marie", Evenement::InvitationEmise, None, 1);
    attendre(&audit, "marie", 1);
    let presents: Vec<String> = std::fs::read_dir(&racine)
        .expect("lisible")
        .filter_map(Result::ok)
        .map(|entree| entree.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(presents, ["marie.jsonl"]);
    assert!(
        !racine
            .parent()
            .expect("un parent")
            .join("evade.jsonl")
            .exists()
    );
    let _ = std::fs::remove_dir_all(&racine);
}

/// **LE FICHIER TOURNE**, et l'ancien se relit encore.
#[test]
fn au_dela_de_sa_taille_le_fichier_tourne() {
    let racine = atelier("rotation");
    std::fs::create_dir_all(&racine).expect("répertoire");
    let vieille = ligne(Evenement::InvitationEmise, None, 1);
    let mut plein = Vec::new();
    while u64::try_from(plein.len()).expect("petit") < ROTATION_OCTETS {
        plein.extend_from_slice(&vieille);
    }
    std::fs::write(racine.join("marie.jsonl"), &plein).expect("écriture");
    ajouter(
        &racine,
        "marie",
        &ligne(Evenement::InvitationEmise, None, 2),
    )
    .expect("ajout");
    assert!(racine.join("marie.1.jsonl").exists());
    let courant = std::fs::read(racine.join("marie.jsonl")).expect("lisible");
    assert_eq!(courant, ligne(Evenement::InvitationEmise, None, 2));

    // La lecture traverse les deux fichiers, la plus récente d'abord.
    let (envoi, _reception) = std::sync::mpsc::sync_channel(1);
    let audit = Audit {
        racine: racine.clone(),
        envoi,
        perdues: AtomicU64::new(0),
        recentes: std::sync::Mutex::new(std::collections::HashMap::new()),
    };
    let lues = audit.lire("marie", 3);
    assert_eq!(lues.len(), 3);
    assert!(texte(&lues[0]).starts_with("{\"at\":2,"));
    assert!(texte(&lues[1]).starts_with("{\"at\":1,"));
    let _ = std::fs::remove_dir_all(&racine);
}

/// **UNE ENTRÉE QUI NE PEUT PAS PARTIR SE COMPTE**, au lieu de bloquer.
#[test]
fn une_file_fermee_perd_et_le_compte() {
    let (envoi, reception) = std::sync::mpsc::sync_channel(1);
    drop(reception);
    let audit = Audit {
        racine: atelier("perte"),
        envoi,
        perdues: AtomicU64::new(0),
        recentes: std::sync::Mutex::new(std::collections::HashMap::new()),
    };
    audit.noter("marie", Evenement::InvitationEmise, None, 1);
    audit.noter("marie", Evenement::InvitationEmise, None, 2);
    assert_eq!(audit.perdues(), 2);
    // Un oubli sur une file fermée ne bloque pas non plus.
    audit.oublier("marie");
    assert!(!std::format!("{audit:?}").is_empty());
}

#[test]
fn une_connexion_de_courrier_dit_son_protocole_et_son_mot_de_passe() {
    let dite = texte(&ligne(
        Evenement::ConnexionCourrier {
            porte: "imap",
            applicatif: Some("0123"),
        },
        Some("192.0.2.1"),
        5,
    ));
    assert_eq!(
        dite,
        "{\"at\":5,\"event\":\"session.opened\",\"source\":\"192.0.2.1\",\"device\":null,\"detail\":\"imap\",\"appPassword\":\"0123\"}\n"
    );
    let dite = texte(&ligne(
        Evenement::ConnexionCourrier {
            porte: "smtp",
            applicatif: None,
        },
        None,
        5,
    ));
    assert!(!dite.contains("appPassword"), "{dite}");
}

/// **CE QUI SE RÉPÈTE SE REGROUPE**, par compte, événement, protocole,
/// mot de passe et adresse — et seulement pendant l'intervalle.
#[test]
fn ce_qui_se_repete_se_regroupe() {
    let racine = atelier("regrouper");
    let audit = Audit::ouvrir(racine.clone()).expect("le journal s'ouvre");
    let imap = Evenement::ConnexionCourrier {
        porte: "imap",
        applicatif: None,
    };
    let a = Some("192.0.2.1");
    audit.noter_au_plus("marie", imap, a, 1000, 3600);
    audit.noter_au_plus("marie", imap, a, 1500, 3600);
    // Une autre adresse, un autre protocole, un autre compte : chacun s'écrit.
    audit.noter_au_plus("marie", imap, Some("192.0.2.2"), 1500, 3600);
    audit.noter_au_plus(
        "marie",
        Evenement::ConnexionCourrier {
            porte: "smtp",
            applicatif: None,
        },
        a,
        1500,
        3600,
    );
    audit.noter_au_plus("paul", imap, a, 1500, 3600);
    // L'intervalle passé, la même s'écrit de nouveau.
    audit.noter_au_plus("marie", imap, a, 4600, 3600);
    // Un nom qui n'est pas un compte ne s'écrit ni ne se retient.
    audit.noter_au_plus("../x", imap, a, 1, 3600);
    attendre(&audit, "paul", 1);
    let lues = attendre(&audit, "marie", 4);
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert_eq!(audit.lire("marie", 10).len(), 4, "{lues:?}");
    let _ = std::fs::remove_dir_all(&racine);
}

/// **LA TABLE DE REGROUPEMENT EST BORNÉE** : pleine, elle oublie ce qui a plus
/// d'une heure, puis tout — une entrée de trop, jamais une de moins.
#[test]
fn la_table_de_regroupement_est_bornee() {
    let (envoi, _reception) = std::sync::mpsc::sync_channel(super::RECENTES_MAX.saturating_mul(2));
    let audit = Audit {
        racine: atelier("borne"),
        envoi,
        perdues: AtomicU64::new(0),
        recentes: std::sync::Mutex::new(std::collections::HashMap::new()),
    };
    let refus = Evenement::Refus { porte: "smtp" };
    let taille = || audit.recentes.lock().expect("verrou").len();
    for rang in 0..super::RECENTES_MAX {
        audit.noter_au_plus("marie", refus, Some(&format!("r{rang}")), 10, 60);
    }
    assert_eq!(taille(), super::RECENTES_MAX);
    // Tout est récent : la table se vide, et la nouvelle entrée y entre.
    audit.noter_au_plus("marie", refus, Some("neuve"), 20, 60);
    assert_eq!(taille(), 1);
    for rang in 1..super::RECENTES_MAX {
        audit.noter_au_plus("marie", refus, Some(&format!("s{rang}")), 5000, 60);
    }
    // Pleine de nouveau : ce qui a plus d'une heure s'oublie seul.
    audit.noter_au_plus("marie", refus, Some("autre"), 5000, 60);
    assert_eq!(taille(), super::RECENTES_MAX);
}
