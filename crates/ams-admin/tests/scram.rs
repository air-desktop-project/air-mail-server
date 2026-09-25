// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que `scram init` et les deux options `--scram*` posent vraiment.
//!
//! # Pourquoi ces essais existent
//!
//! Un vérificateur SCRAM ne se vérifie pas à l'œil : c'est un scellé. Sans ces
//! essais, tout ce qu'on saurait de cette chaîne, c'est que l'outil n'a pas
//! affiché d'erreur — et un magasin bien formé dont le contenu ne correspond à
//! aucun mot de passe a exactement cette allure-là. On OUVRE donc le
//! vérificateur écrit, et on vérifie qu'il correspond au mot de passe qu'on
//! vient de poser, et **plus à celui d'avant**.
//!
//! Les essais tournent contre le BINAIRE, comme ceux de `secret.rs` : c'est la
//! chaîne entière qu'on éprouve, pas une fonction prise à part.

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

fn atelier(nom: &str) -> Atelier {
    let chemin = std::env::temp_dir().join(format!(
        "ams-scram-{nom}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&chemin);
    std::fs::create_dir_all(&chemin).expect("un répertoire d'essai");
    Atelier(chemin)
}

/// Lance l'outil en lui donnant `secret` sur l'entrée standard.
fn outil(secret: &str, arguments: &[&str]) -> (String, String, bool) {
    let mut enfant = Command::new(env!("CARGO_BIN_EXE_air-mail-admin"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("l'outil se lance");
    if let Some(entree) = enfant.stdin.as_mut() {
        let _ = entree.write_all(secret.as_bytes());
    }
    let fini = enfant.wait_with_output().expect("l'outil finit");
    (
        String::from_utf8_lossy(&fini.stdout).into_owned(),
        String::from_utf8_lossy(&fini.stderr).into_owned(),
        fini.status.success(),
    )
}

/// Ouvre le vérificateur d'un compte, et rend sa `StoredKey`.
fn stored_key_de(repertoire: &Path, login: &str) -> [u8; 32] {
    let clef_lue = std::fs::read(repertoire.join("scram.key")).expect("clé lisible");
    let mut clef = [0_u8; 32];
    clef.copy_from_slice(&clef_lue);
    let magasin = ams_config::decode_scram(
        &std::fs::read(repertoire.join("scram.bin")).expect("magasin lisible"),
    )
    .expect("magasin valide");
    let v = magasin
        .iter()
        .find(|v| v.login == login)
        .expect("le compte a un vérificateur");
    ams_auth::scram_ouvrir(v, &empreinte_de(repertoire, login), &clef)
        .expect("le scellé s'ouvre")
        .stored
}

/// L'empreinte que le fichier de comptes porte pour ce compte.
fn empreinte_de(repertoire: &Path, login: &str) -> String {
    ams_config::decode_accounts(&std::fs::read(repertoire.join("comptes.bin")).expect("comptes"))
        .expect("comptes valides")
        .into_iter()
        .find(|compte| compte.login == login)
        .expect("le compte existe")
        .hash
}

/// La `StoredKey` que ce mot de passe produirait, avec le sel du magasin.
fn stored_key_attendue(repertoire: &Path, login: &str, mot_de_passe: &str) -> [u8; 32] {
    let magasin = ams_config::decode_scram(
        &std::fs::read(repertoire.join("scram.bin")).expect("magasin lisible"),
    )
    .expect("magasin valide");
    let v = magasin
        .iter()
        .find(|v| v.login == login)
        .expect("le compte a un vérificateur");
    let salted = ams_sasl::derive_salted_password(mot_de_passe.as_bytes(), &v.sel, v.iterations);
    ams_sasl::stored_key(&ams_sasl::client_key(&salted))
}

#[test]
fn scram_init_tire_une_clef_et_refuse_de_l_ecraser() {
    let atelier = atelier("init");
    let clef = atelier.0.join("scram.key");
    let chemin = clef.display().to_string();

    let (dit, _, ok) = outil("", &["scram", "init", &chemin]);
    assert!(ok, "l'outil a refusé de tirer la clé");
    assert!(dit.contains("32 octets"), "{dit}");
    // **IL DIT DE LA RANGER AILLEURS**, et c'est la moitié de ce que cette
    // commande sert à faire : deux fichiers au même endroit ne valent pas mieux
    // qu'un seul en clair.
    assert!(dit.contains("AILLEURS"), "{dit}");
    assert_eq!(
        std::fs::read(&clef).expect("clé lisible").len(),
        32,
        "la clé ne fait pas trente-deux octets"
    );

    // Un second passage NE DOIT PAS écraser : une clé perdue rend tous les
    // vérificateurs illisibles d'un coup, et rien ne les reconstitue.
    let avant = std::fs::read(&clef).expect("clé lisible");
    let (_, plainte, ok) = outil("", &["scram", "init", &chemin]);
    assert!(!ok, "l'outil a écrasé une clé existante");
    assert!(plainte.contains("existe déjà"), "{plainte}");
    assert_eq!(
        std::fs::read(&clef).expect("clé lisible"),
        avant,
        "la clé a changé malgré le refus"
    );
}

#[test]
fn un_compte_ajoute_avec_scram_a_un_verificateur_qui_ouvre() {
    let atelier = atelier("ajout");
    let clef = atelier.0.join("scram.key").display().to_string();
    let magasin = atelier.0.join("scram.bin").display().to_string();
    let comptes = atelier.0.join("comptes.bin").display().to_string();

    let (_, _, ok) = outil("", &["scram", "init", &clef]);
    assert!(ok);
    let (_, plainte, ok) = outil(
        "ouvre-toi",
        &[
            "account",
            "add",
            &comptes,
            "--login",
            "jean",
            "--address",
            "jean@example.com",
            "--scram-key",
            &clef,
            "--scram",
            &magasin,
        ],
    );
    assert!(ok, "{plainte}");

    // **ON OUVRE LE SCELLÉ**, et on vérifie qu'il correspond au mot de passe.
    // Sans cela, un magasin bien formé et vide de sens passerait pour bon.
    assert_eq!(
        stored_key_de(&atelier.0, "jean"),
        stored_key_attendue(&atelier.0, "jean", "ouvre-toi"),
        "le vérificateur ne correspond pas au mot de passe posé"
    );
}

#[test]
fn changer_le_secret_remplace_le_verificateur_au_lieu_d_en_ajouter_un() {
    // Une entrée ajoutée sans retirer l'ancienne laisserait un débris : lié à
    // l'ancienne empreinte, il ne s'ouvrirait plus, mais le magasin porterait
    // deux entrées pour un compte — ce que son chargement refuse.
    let atelier = atelier("remplace");
    let clef = atelier.0.join("scram.key").display().to_string();
    let magasin = atelier.0.join("scram.bin").display().to_string();
    let comptes = atelier.0.join("comptes.bin").display().to_string();

    outil("", &["scram", "init", &clef]);
    outil(
        "ouvre-toi",
        &[
            "account",
            "add",
            &comptes,
            "--login",
            "jean",
            "--address",
            "j@e.com",
            "--scram-key",
            &clef,
            "--scram",
            &magasin,
        ],
    );
    let (_, plainte, ok) = outil(
        "un-autre",
        &[
            "account",
            "passwd",
            &comptes,
            "--login",
            "jean",
            "--scram-key",
            &clef,
            "--scram",
            &magasin,
        ],
    );
    assert!(ok, "{plainte}");

    let magasin_lu =
        ams_config::decode_scram(&std::fs::read(atelier.0.join("scram.bin")).expect("magasin"))
            .expect("magasin valide");
    assert_eq!(
        magasin_lu.len(),
        1,
        "le vérificateur a été AJOUTÉ, pas remplacé"
    );
    assert_eq!(
        stored_key_de(&atelier.0, "jean"),
        stored_key_attendue(&atelier.0, "jean", "un-autre"),
        "le vérificateur ne suit pas le nouveau mot de passe"
    );
    assert_ne!(
        stored_key_de(&atelier.0, "jean"),
        stored_key_attendue(&atelier.0, "jean", "ouvre-toi"),
        "l'ancien mot de passe ouvre encore"
    );
}

#[test]
fn sans_les_deux_options_aucun_verificateur_n_est_ecrit() {
    // SCRAM n'existe que si on le demande : ni annoncé, ni stocké autrement.
    let atelier = atelier("sans");
    let comptes = atelier.0.join("comptes.bin").display().to_string();
    let (_, _, ok) = outil(
        "ouvre-toi",
        &["account", "add", &comptes, "--login", "jean"],
    );
    assert!(ok);
    assert!(
        !atelier.0.join("scram.bin").exists(),
        "un magasin SCRAM est apparu sans qu'on le demande"
    );
}

#[test]
fn une_option_sans_l_autre_est_refusee_au_terminal() {
    let atelier = atelier("appariees");
    let comptes = atelier.0.join("comptes.bin").display().to_string();
    let ailleurs = atelier.0.join("x").display().to_string();

    let (_, plainte, ok) = outil(
        "x",
        &[
            "account", "add", &comptes, "--login", "jean", "--scram", &ailleurs,
        ],
    );
    assert!(!ok);
    assert!(plainte.contains("ne s'ouvrirait pas"), "{plainte}");

    let (_, plainte, ok) = outil(
        "x",
        &[
            "account",
            "add",
            &comptes,
            "--login",
            "jean",
            "--scram-key",
            &ailleurs,
        ],
    );
    assert!(!ok);
    assert!(plainte.contains("rien à sceller"), "{plainte}");
}

#[test]
fn une_clef_de_mauvaise_taille_est_refusee() {
    // **PAS DE COMPLÉTION SILENCIEUSE.** Une clé plus courte complétée de zéros
    // serait plus faible que ce que son nom promet, et rien ne le dirait.
    let atelier = atelier("clef-courte");
    let clef = atelier.0.join("scram.key");
    std::fs::write(&clef, [1_u8; 31]).expect("clé courte écrite");
    let comptes = atelier.0.join("comptes.bin").display().to_string();
    let magasin = atelier.0.join("scram.bin").display().to_string();

    let (_, plainte, ok) = outil(
        "x",
        &[
            "account",
            "add",
            &comptes,
            "--login",
            "jean",
            "--scram-key",
            &clef.display().to_string(),
            "--scram",
            &magasin,
        ],
    );
    assert!(!ok, "une clé de trente-et-un octets a été acceptée");
    assert!(plainte.contains("31 octet"), "{plainte}");
}

#[test]
fn account_passwd_refuse_une_adresse() {
    let atelier = atelier("passwd-adresse");
    let comptes = atelier.0.join("comptes.bin").display().to_string();
    let (_, plainte, ok) = outil(
        "x",
        &[
            "account",
            "passwd",
            &comptes,
            "--login",
            "jean",
            "--address",
            "a@b.c",
        ],
    );
    assert!(!ok);
    assert!(plainte.contains("ne change QUE le secret"), "{plainte}");
}

/// **`scram bind` LIE LES VÉRIFICATEURS D'AVANT LA 0.2.16**, retire ceux dont
/// le compte n'existe plus, et laisse tels quels ceux qui sont déjà liés.
///
/// Le magasin « ancien » est fabriqué ici comme la 0.2.15 l'écrivait : le même
/// clair, scellé sous le SEUL login. C'est la seule façon d'éprouver la
/// migration sur ce qu'elle rencontrera réellement.
#[test]
fn scram_bind_lie_les_anciens_verificateurs() {
    use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};

    let atelier = atelier("lier");
    let clef = atelier.0.join("scram.key").display().to_string();
    let magasin = atelier.0.join("scram.bin").display().to_string();
    let comptes = atelier.0.join("comptes.bin").display().to_string();

    outil("", &["scram", "init", &clef]);
    for (nom, secret) in [("jean", "ouvre-toi"), ("paul", "sesame")] {
        let (_, plainte, ok) = outil(
            secret,
            &[
                "account",
                "add",
                &comptes,
                "--login",
                nom,
                "--address",
                &format!("{nom}@e.com"),
                "--scram-key",
                &clef,
                "--scram",
                &magasin,
            ],
        );
        assert!(ok, "{plainte}");
    }
    let attendue = stored_key_de(&atelier.0, "jean");

    // ── LE MAGASIN TEL QUE LA 0.2.15 L'ÉCRIVAIT ────────────────────────────
    let clef_lue: [u8; 32] = std::fs::read(atelier.0.join("scram.key"))
        .expect("clé")
        .try_into()
        .expect("trente-deux octets");
    let boite = chacha20poly1305::ChaCha20Poly1305::new(&clef_lue.into());
    let lus = ams_config::decode_scram(&std::fs::read(atelier.0.join("scram.bin")).expect("m"))
        .expect("magasin");
    let mut anciens = std::vec::Vec::new();
    for v in &lus {
        let cles = ams_auth::scram_ouvrir(v, &empreinte_de(&atelier.0, &v.login), &clef_lue)
            .expect("ouverture");
        let mut clair = cles.stored.to_vec();
        clair.extend_from_slice(&cles.server);
        let scelle = boite
            .encrypt(
                &v.nonce.into(),
                Payload {
                    msg: &clair,
                    aad: v.login.as_bytes(),
                },
            )
            .expect("scellement");
        anciens.push(ams_auth::ScramVerifier {
            scelle,
            lie: false,
            ..v.clone()
        });
    }
    // Un vérificateur ORPHELIN : son compte n'existe pas.
    anciens.push(ams_auth::ScramVerifier {
        login: String::from("disparu"),
        ..anciens.first().expect("un vérificateur").clone()
    });
    std::fs::write(
        atelier.0.join("scram.bin"),
        ams_config::encode_scram(&anciens).expect("encodage"),
    )
    .expect("écriture");

    // **NON LIÉ, IL NE S'OUVRE PLUS** : c'est ce que la mise à jour fait aux
    // magasins qu'on ne migre pas.
    let avant = ams_config::decode_scram(&std::fs::read(atelier.0.join("scram.bin")).expect("m"))
        .expect("magasin");
    let jean = avant.iter().find(|v| v.login == "jean").expect("jean");
    assert_eq!(
        ams_auth::scram_ouvrir(jean, &empreinte_de(&atelier.0, "jean"), &clef_lue),
        Err(ams_auth::ScramError::NonLie)
    );

    // ── LA MIGRATION ────────────────────────────────────────────────────────
    let (dit, plainte, ok) = outil(
        "",
        &[
            "scram",
            "bind",
            &comptes,
            "--scram-key",
            &clef,
            "--scram",
            &magasin,
        ],
    );
    assert!(ok, "{plainte}");
    assert!(dit.contains("2 vérificateur(s) lié(s)"), "{dit}");
    assert!(dit.contains("1 retiré(s)"), "{dit}");
    assert_eq!(
        stored_key_de(&atelier.0, "jean"),
        attendue,
        "lié, le vérificateur rend les MÊMES clés qu'avant"
    );
    let apres = ams_config::decode_scram(&std::fs::read(atelier.0.join("scram.bin")).expect("m"))
        .expect("magasin");
    assert_eq!(apres.len(), 2, "l'orphelin est retiré");
    assert!(apres.iter().all(|v| v.lie));

    // **RELANCÉE, ELLE NE CHANGE RIEN** : une migration qu'on repasse par
    // prudence ne doit pas échouer.
    let (dit, plainte, ok) = outil(
        "",
        &[
            "scram",
            "bind",
            &comptes,
            "--scram-key",
            &clef,
            "--scram",
            &magasin,
        ],
    );
    assert!(ok, "{plainte}");
    assert!(
        dit.contains("0 vérificateur(s) lié(s), 2 déjà lié(s)"),
        "{dit}"
    );

    // **ET UN MOT DE PASSE CHANGÉ ÉTEINT LE VÉRIFICATEUR LIÉ**, même quand ce
    // n'est pas cet outil qui le change : on réécrit l'empreinte à la main,
    // comme l'API le ferait, sans toucher au magasin SCRAM.
    let mut lus =
        ams_config::decode_accounts(&std::fs::read(atelier.0.join("comptes.bin")).expect("c"))
            .expect("comptes");
    let autre = lus
        .iter()
        .find(|c| c.login == "paul")
        .expect("paul")
        .hash
        .clone();
    lus.iter_mut()
        .find(|c| c.login == "jean")
        .expect("jean")
        .hash = autre;
    std::fs::write(
        atelier.0.join("comptes.bin"),
        ams_config::encode_accounts(&lus).expect("encodage"),
    )
    .expect("écriture");
    let jean = apres.iter().find(|v| v.login == "jean").expect("jean");
    assert_eq!(
        ams_auth::scram_ouvrir(jean, &empreinte_de(&atelier.0, "jean"), &clef_lue),
        Err(ams_auth::ScramError::Sceau),
        "l'ancien mot de passe ouvre encore par SCRAM"
    );
}

/// **UN VÉRIFICATEUR QUI NE S'OUVRE PAS SOUS LA CLÉ ARRÊTE LA MIGRATION**, et
/// le magasin n'est pas touché.
#[test]
fn scram_bind_refuse_ce_qui_ne_s_ouvre_pas() {
    let atelier = atelier("lier-refus");
    let clef = atelier.0.join("scram.key").display().to_string();
    let magasin = atelier.0.join("scram.bin").display().to_string();
    let comptes = atelier.0.join("comptes.bin").display().to_string();
    outil("", &["scram", "init", &clef]);
    outil(
        "ouvre-toi",
        &[
            "account",
            "add",
            &comptes,
            "--login",
            "jean",
            "--address",
            "j@e.com",
            "--scram-key",
            &clef,
            "--scram",
            &magasin,
        ],
    );
    // Un vérificateur lié, dont on prétend qu'il ne l'est pas : il ne s'ouvre
    // pas sous le seul login.
    let mut lus = ams_config::decode_scram(&std::fs::read(atelier.0.join("scram.bin")).expect("m"))
        .expect("magasin");
    lus.iter_mut().for_each(|v| v.lie = false);
    let octets = ams_config::encode_scram(&lus).expect("encodage");
    std::fs::write(atelier.0.join("scram.bin"), &octets).expect("écriture");

    let (_, plainte, ok) = outil(
        "",
        &[
            "scram",
            "bind",
            &comptes,
            "--scram-key",
            &clef,
            "--scram",
            &magasin,
        ],
    );
    assert!(!ok);
    assert!(
        plainte.contains("ne s'ouvre pas sous cette clé"),
        "{plainte}"
    );
    assert_eq!(
        std::fs::read(atelier.0.join("scram.bin")).expect("m"),
        octets,
        "le magasin a été touché malgré le refus"
    );
}
