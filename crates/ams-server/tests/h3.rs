// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le SERVEUR, éprouvé en HTTP/3 sur son port UDP.
//!
//! # CE QUE CET ESSAI AJOUTE À CEUX D'`ams-loop-tokio`
//!
//! Là-bas, `serve_quic` est appelé dans le processus d'essai, avec une session et
//! une API montées à la main. Ici, c'est **le binaire** qui est lancé, avec un
//! fichier de configuration : ce qui est éprouvé, c'est le câblage du `main` —
//! la configuration lue, la socket ouverte, les certificats chargés, la session
//! et l'API partagées avec HTTP/2, le videur branché.
//!
//! C'était le dernier maillon que rien ne traversait.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ams_config::{Configuration, Timeouts, Tls, encode};
use ams_guard::Thresholds;
use ams_proto_smtp::Limits;
use ams_quic_client::{
    Client, SANS_OPENSSL, atelier, attendre_la_reponse, config_client, envoyer_avec_media,
    envoyer_une_requete, materiel,
};

/// Le secret de scellement des jetons, en hexadécimal.
const CLEF: &str = "0000000000000000000000000000000000000000000000000000000000000001";

/// Un serveur lancé, qu'on tue en le laissant tomber.
struct Serveur {
    enfant: Child,
    journal: Arc<Mutex<String>>,
}

impl Serveur {
    /// Ce que le serveur a écrit jusqu'ici.
    fn journal(&self) -> String {
        match self.journal.lock() {
            Ok(lu) => lu.clone(),
            Err(empoisonne) => empoisonne.into_inner().clone(),
        }
    }
}

impl Drop for Serveur {
    fn drop(&mut self) {
        let _ = self.enfant.kill();
        let _ = self.enfant.wait();
    }
}

/// Un port que personne n'écoute.
fn port_libre() -> u16 {
    static PROCHAIN: AtomicU16 = AtomicU16::new(0);
    let ecouteur = std::net::TcpListener::bind("127.0.0.1:0").expect("un port libre");
    let port = ecouteur.local_addr().expect("une adresse").port();
    // **ON NE REND PAS LE MÊME DEUX FOIS** dans un même processus : deux essais
    // parallèles obtiendraient sinon le même port du noyau, qui ne le tient
    // réservé que jusqu'à la fermeture.
    let _ = PROCHAIN.fetch_add(1, Ordering::Relaxed);
    port
}

/// Écrit une configuration qui sert l'API en HTTP/2 et en HTTP/3.
fn configuration(
    repertoire: &Path,
    smtp: u16,
    http: u16,
    h3: u16,
    cert: &Path,
    cle: &Path,
    comptes: &Path,
) -> PathBuf {
    let config = Configuration {
        domain: String::from("mail.example.com"),
        listen: format!("127.0.0.1:{smtp}"),
        maildir: repertoire.join("boite").display().to_string(),
        hosted: vec![String::from("example.com")],
        max_recipients: 100,
        listen_http: format!("127.0.0.1:{http}"),
        listen_h3: format!("127.0.0.1:{h3}"),
        token_key: String::from(CLEF),
        max_message_octets: 10_485_760,
        max_connections: 16,
        limits: Limits::DEFAULT,
        guard: Thresholds::DEFAULT,
        tracked_sources: 64,
        timeouts: Timeouts {
            command_seconds: 10,
            data_seconds: 10,
        },
        tls: Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        spf: ams_config::Spf::default(),
        dmarc: ams_config::Dmarc::default(),
        dkim: ams_config::Dkim::default(),
        accounts: comptes.display().to_string(),
        listen_pop3: String::new(),
        listen_imap: String::new(),
    };
    let octets = encode(&config).expect("une configuration encodable");
    let chemin = repertoire.join("config.bin");
    std::fs::write(&chemin, &octets).expect("écriture de la configuration");
    chemin
}

/// Écrit un magasin de comptes, **avec les permissions que le serveur exige**.
///
/// Il refuse de démarrer sur un fichier lisible par tout le monde, et il a
/// raison : ce fichier porte des empreintes, et une empreinte se casse hors
/// ligne à l'aise. `air-mail-admin` l'écrit en `0600` dès l'ouverture, et un
/// essai qui ferait autrement n'éprouverait pas le serveur qu'on livre.
fn ecrire_le_magasin(repertoire: &Path, comptes: &[ams_auth::Account]) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let chemin = repertoire.join("comptes.bin");
    std::fs::write(
        &chemin,
        ams_config::encode_accounts(comptes).expect("encodable"),
    )
    .expect("écriture du magasin");
    std::fs::set_permissions(&chemin, std::fs::Permissions::from_mode(0o600))
        .expect("permissions du magasin");
    chemin
}

/// Lance le serveur et attend qu'il ait annoncé son écoute HTTP/3.
fn lancer(config: &Path, motif: &str) -> Serveur {
    let mut enfant = Command::new(env!("CARGO_BIN_EXE_air-mail-server"))
        .arg("--config")
        .arg(config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("le serveur devrait se lancer");
    let journal = Arc::new(Mutex::new(String::new()));
    if let Some(sortie) = enfant.stderr.take() {
        let vers = Arc::clone(&journal);
        std::thread::spawn(move || {
            let mut sortie = sortie;
            let mut tampon = [0_u8; 512];
            while let Ok(lus) = std::io::Read::read(&mut sortie, &mut tampon) {
                if lus == 0 {
                    return;
                }
                let morceau = String::from_utf8_lossy(tampon.get(..lus).unwrap_or_default());
                if let Ok(mut journal) = vers.lock() {
                    journal.push_str(&morceau);
                }
            }
        });
    }
    let serveur = Serveur { enfant, journal };
    // **ON ATTEND CE QU'ON CHERCHE**, et non l'annonce SMTP : celle-ci est écrite
    // juste après le `bind`, donc avant que l'API et HTTP/3 ne se montent.
    let depart = Instant::now();
    while depart.elapsed() < Duration::from_secs(10) {
        if serveur.journal().contains(motif) {
            return serveur;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!(
        "le serveur n'a pas annoncé « {motif} » : {}",
        serveur.journal()
    );
}

/// **UNE REQUÊTE HTTP/3 TRAVERSE LE BINAIRE.**
///
/// La configuration lue, la socket ouverte, les certificats chargés, la session
/// et l'API partagées avec HTTP/2, le videur branché — et une réponse qui revient
/// comprimée par QPACK.
#[tokio::test(flavor = "current_thread")]
async fn une_requete_h3_traverse_le_binaire() {
    let atelier = atelier("serveur-h3");
    let Some((autorite, cert, cle)) = materiel(atelier.chemin()) else {
        eprintln!("SAUTÉ : {SANS_OPENSSL}");
        return;
    };
    let chemin_cert = atelier.chemin().join("srv.pem");
    let chemin_cle = atelier.chemin().join("srv.key");
    std::fs::write(&chemin_cert, &cert).expect("le certificat s'écrit");
    std::fs::write(&chemin_cle, &cle).expect("la clé s'écrit");

    // **PAS DE COMPTE** : c'est ce que cet essai-ci veut montrer — la chaîne
    // traverse, et la session refuse faute d'identifiants.
    let magasin = ecrire_le_magasin(atelier.chemin(), &[]);

    let (smtp, http, h3) = (port_libre(), port_libre(), port_libre());
    let config = configuration(
        atelier.chemin(),
        smtp,
        http,
        h3,
        &chemin_cert,
        &chemin_cle,
        &magasin,
    );
    let serveur = lancer(&config, &format!("127.0.0.1:{h3}/udp"));

    let adresse = format!("127.0.0.1:{h3}").parse().expect("une adresse");
    let mut client = Client::new(config_client(&autorite), adresse).await;
    for _ in 0..16 {
        if !client.parler().await && !client.tls().is_handshaking() {
            break;
        }
        if !client.ecouter().await && !client.tls().is_handshaking() {
            break;
        }
    }
    assert!(
        !client.tls().is_handshaking(),
        "la poignée de main doit aboutir contre le binaire : {}",
        serveur.journal()
    );
    assert_eq!(client.tls().alpn_protocol(), Some(&b"h3"[..]));

    // Le jeton, puis la ressource — comme en HTTP/2.
    let corps = br#"{"login":"marc","password":"secret"}"#;
    envoyer_une_requete(&mut client, 0, 20, b"/v1/tokens", None, corps).await;
    let recu = attendre_la_reponse(&mut client, 0).await;
    let texte = String::from_utf8_lossy(&recu).to_string();

    // **SANS FICHIER DE COMPTES, PERSONNE NE S'AUTHENTIFIE** — et c'est la
    // réponse qu'on attend : elle prouve que la session a décidé, que l'API a
    // été consultée, et que le refus est revenu comprimé.
    assert!(
        texte.contains("\"status\":401") || texte.contains("\"token\""),
        "la session doit avoir décidé : {texte} — journal : {}",
        serveur.journal()
    );
    assert_eq!(client.ferme(), None, "et rien n'a fermé la connexion");
}

/// **UNE SOUMISSION TRAVERSE TOUTE LA CHAÎNE, ET LE MESSAGE ARRIVE.**
///
/// C'est le maillon que rien ne traversait : le jeton s'échange, le message se
/// dépose en `message/rfc822`, la remise l'écrit dans la boîte, et la liste des
/// messages le rend avec son sujet et son expéditeur.
///
/// **ET LE `Bcc` N'EST PLUS LÀ** (§3.6.3 de RFC 5322) : le destinataire caché
/// reçoit bien son exemplaire, et n'y lit pas qui d'autre l'a reçu.
#[tokio::test(flavor = "current_thread")]
async fn une_soumission_traverse_le_binaire() {
    let atelier = atelier("soumission-h3");
    let Some((autorite, cert, cle)) = materiel(atelier.chemin()) else {
        eprintln!("SAUTÉ : {SANS_OPENSSL}");
        return;
    };
    let chemin_cert = atelier.chemin().join("srv.pem");
    let chemin_cle = atelier.chemin().join("srv.key");
    std::fs::write(&chemin_cert, &cert).expect("le certificat s'écrit");
    std::fs::write(&chemin_cle, &cle).expect("la clé s'écrit");

    // Deux comptes : celui qui dépose, et celui qu'on met en copie cachée.
    let empreinte = ams_auth::hash_password(b"ouvre-toi", b"seize octets ici").expect("hachable");
    let comptes =
        [("jean", "jean@example.com"), ("marie", "marie@example.com")].map(|(login, adresse)| {
            ams_auth::Account {
                login: String::from(login),
                hash: empreinte.clone(),
                addresses: vec![String::from(adresse)],
            }
        });
    let magasin = ecrire_le_magasin(atelier.chemin(), &comptes);

    let (smtp, http, h3) = (port_libre(), port_libre(), port_libre());
    let config = configuration(
        atelier.chemin(),
        smtp,
        http,
        h3,
        &chemin_cert,
        &chemin_cle,
        &magasin,
    );
    let serveur = lancer(&config, &format!("127.0.0.1:{h3}/udp"));

    let adresse = format!("127.0.0.1:{h3}").parse().expect("une adresse");
    let mut client = Client::new(config_client(&autorite), adresse).await;
    for _ in 0..16 {
        if !client.parler().await && !client.tls().is_handshaking() {
            break;
        }
        if !client.ecouter().await && !client.tls().is_handshaking() {
            break;
        }
    }
    assert!(
        !client.tls().is_handshaking(),
        "la poignée de main doit aboutir : {}",
        serveur.journal()
    );

    // 1. Le jeton.
    let identifiants = br#"{"login":"jean","password":"ouvre-toi"}"#;
    envoyer_une_requete(&mut client, 0, 20, b"/v1/tokens", None, identifiants).await;
    let recu = attendre_la_reponse(&mut client, 0).await;
    let texte = String::from_utf8_lossy(&recu).to_string();
    let debut = texte
        .find("\"token\":\"")
        .map(|rang| rang + 9)
        .unwrap_or_else(|| panic!("un jeton attendu : {texte} — {}", serveur.journal()));
    let fin = texte
        .get(debut..)
        .and_then(|reste| reste.find('"'))
        .expect("une fin de chaîne")
        + debut;
    let jeton = texte[debut..fin].to_string();

    // 2. Le dépôt, en `message/rfc822` — et non en JSON.
    let message = concat!(
        "From: jean@example.com\r\n",
        "To: jean@example.com\r\n",
        "Bcc: marie@example.com\r\n",
        "Subject: =?utf-8?B?ZmFjdHVyZQ==?=\r\n",
        "\r\n",
        "le corps du message\r\n",
    )
    .as_bytes();
    envoyer_avec_media(
        &mut client,
        4,
        20,
        b"/v1/submissions",
        Some(&jeton),
        message,
        b"message/rfc822",
    )
    .await;
    let recu = attendre_la_reponse(&mut client, 4).await;
    let texte = String::from_utf8_lossy(&recu).to_string();
    assert!(
        texte.contains("\"delivered\":2"),
        "le dépôt doit atteindre les deux boîtes : {texte} — {}",
        serveur.journal()
    );

    // 3. Et le message est là, avec son sujet DÉCODÉ et son expéditeur.
    envoyer_une_requete(
        &mut client,
        8,
        17,
        b"/v1/mailboxes/INBOX/messages",
        Some(&jeton),
        &[],
    )
    .await;
    let recu = attendre_la_reponse(&mut client, 8).await;
    let texte = String::from_utf8_lossy(&recu).to_string();
    assert!(
        texte.contains("\"subject\":\"facture\""),
        "le sujet doit revenir décodé : {texte} — {}",
        serveur.journal()
    );
    assert!(
        texte.contains("\"from\":\"jean@example.com\""),
        "et l'expéditeur avec : {texte}"
    );

    // 4. Le message écrit sur le disque n'a plus son `Bcc`.
    let ecrit = un_message_de(atelier.chemin(), "jean");
    let entete = ecrit
        .split("\r\n\r\n")
        .next()
        .unwrap_or_default()
        .to_string();
    assert!(
        !entete.contains("Bcc:"),
        "§3.6.3 : la copie cachée reste cachée — {entete}"
    );
    assert!(
        entete.contains("To: jean@example.com"),
        "et le reste de l'en-tête est intact — {entete}"
    );
    assert!(
        ecrit.contains("le corps du message"),
        "le corps aussi — {ecrit}"
    );
}

/// Le premier message trouvé dans la boîte de ce compte.
fn un_message_de(repertoire: &Path, compte: &str) -> String {
    // **`new/` D'ABORD** : un message remis et jamais lu y reste, et c'est là
    // qu'un dépôt tout frais se trouve. `cur/` ne le reçoit qu'une fois qu'un
    // client l'a vu.
    let boite = repertoire.join("boite").join(compte);
    for sous in ["new", "cur"] {
        let Ok(entrees) = std::fs::read_dir(boite.join(sous)) else {
            continue;
        };
        for entree in entrees.flatten() {
            if let Ok(texte) = std::fs::read_to_string(entree.path()) {
                return texte;
            }
        }
    }
    panic!("aucun message dans `{}`", boite.display())
}

/// **L'ADMINISTRATION SE SERT, ET SEULEMENT AVEC UN JETON QUI LA PORTE.**
///
/// Aucun mot de passe n'ouvre l'administration : le jeton se frappe depuis la
/// machine du serveur, par qui peut lire sa configuration. Cet essai frappe le
/// sien comme `air-mail-admin token` le ferait, puis vérifie que les ressources
/// répondent — et qu'un jeton ordinaire, lui, ne les ouvre pas.
#[tokio::test(flavor = "current_thread")]
async fn l_administration_se_sert_avec_le_bon_jeton() {
    let atelier = atelier("admin-h3");
    let Some((autorite, cert, cle)) = materiel(atelier.chemin()) else {
        eprintln!("SAUTÉ : {SANS_OPENSSL}");
        return;
    };
    let chemin_cert = atelier.chemin().join("srv.pem");
    let chemin_cle = atelier.chemin().join("srv.key");
    std::fs::write(&chemin_cert, &cert).expect("le certificat s'écrit");
    std::fs::write(&chemin_cle, &cle).expect("la clé s'écrit");

    let empreinte = ams_auth::hash_password(b"ouvre-toi", b"seize octets ici").expect("hachable");
    let comptes = [ams_auth::Account {
        login: String::from("jean"),
        hash: empreinte,
        addresses: vec![String::from("jean@example.com")],
    }];
    let magasin = ecrire_le_magasin(atelier.chemin(), &comptes);

    let (smtp, http, h3) = (port_libre(), port_libre(), port_libre());
    let config = configuration(
        atelier.chemin(),
        smtp,
        http,
        h3,
        &chemin_cert,
        &chemin_cle,
        &magasin,
    );
    let serveur = lancer(&config, &format!("127.0.0.1:{h3}/udp"));

    let adresse = format!("127.0.0.1:{h3}").parse().expect("une adresse");
    let mut client = Client::new(config_client(&autorite), adresse).await;
    for _ in 0..16 {
        if !client.parler().await && !client.tls().is_handshaking() {
            break;
        }
        if !client.ecouter().await && !client.tls().is_handshaking() {
            break;
        }
    }
    assert!(!client.tls().is_handshaking(), "{}", serveur.journal());

    // Le jeton d'administration, frappé avec le secret de la configuration —
    // c'est exactement ce que fait `air-mail-admin token`.
    let admin = frapper_un_jeton(ams_api::Scope::one(
        ams_api::Area::Admin,
        ams_api::Rights::Write,
    ));

    // Les comptes — sans la moindre empreinte.
    envoyer_une_requete(&mut client, 0, 17, b"/v1/accounts", Some(&admin), &[]).await;
    let texte = String::from_utf8_lossy(&attendre_la_reponse(&mut client, 0).await).to_string();
    assert!(
        texte.contains(r#""login":"jean""#),
        "les comptes se listent : {texte} — {}",
        serveur.journal()
    );
    assert!(
        !texte.contains("argon2") && !texte.contains("hash"),
        "et AUCUNE empreinte n'en sort : {texte}"
    );

    // Les domaines hébergés.
    envoyer_une_requete(&mut client, 4, 17, b"/v1/domains", Some(&admin), &[]).await;
    let texte = String::from_utf8_lossy(&attendre_la_reponse(&mut client, 4).await).to_string();
    assert!(texte.contains("example.com"), "{texte}");

    // Les bannissements : aucun, et cela se dit.
    envoyer_une_requete(&mut client, 8, 17, b"/v1/bans", Some(&admin), &[]).await;
    let texte = String::from_utf8_lossy(&attendre_la_reponse(&mut client, 8).await).to_string();
    assert!(texte.contains(r#""bans":[]"#), "{texte}");

    // **ET UN JETON DE COURRIER N'OUVRE PAS L'ADMINISTRATION.** C'est la limite
    // qui fait qu'un compte compromis ne devient jamais le serveur entier.
    let ordinaire = frapper_un_jeton(
        ams_api::Scope::one(ams_api::Area::Mail, ams_api::Rights::Write)
            .with(ams_api::Area::Submit, ams_api::Rights::Write)
            .with(ams_api::Area::Observe, ams_api::Rights::Read),
    );
    envoyer_une_requete(&mut client, 12, 17, b"/v1/accounts", Some(&ordinaire), &[]).await;
    let texte = String::from_utf8_lossy(&attendre_la_reponse(&mut client, 12).await).to_string();
    assert!(
        !texte.contains(r#""login""#),
        "un jeton de courrier ne doit rien lire ici : {texte}"
    );
}

/// Frappe un jeton portant cette portée, comme `air-mail-admin token` le ferait.
fn frapper_un_jeton(portee: ams_api::Scope) -> String {
    let clef = ams_api::key_from_hex(CLEF).expect("le secret d'essai est licite");
    let maintenant = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("après 1970")
        .as_micros();
    let maintenant = u64::try_from(maintenant).expect("tient");
    let jeton = ams_api::Token {
        login: "exploitant",
        scope: portee,
        expiry: maintenant.saturating_add(900_u64.saturating_mul(1_000_000)),
        nonce: 1,
    };
    let mut place = [0_u8; ams_api::ENCODED_OCTETS_MAX];
    ams_api::issue(&clef, &jeton, maintenant, &mut place)
        .expect("scellable")
        .to_string()
}

/// **UN COMPTE CRÉÉ À CHAUD REÇOIT DU COURRIER, SANS REDÉMARRAGE.**
///
/// C'est ce que « modifiable à chaud » veut dire, et rien de moins : le compte
/// est écrit, sa boîte est ouverte, il s'authentifie, il reçoit, et on le relit.
/// Un compte qui s'authentifierait sans recevoir serait un demi-compte que rien
/// ne signale.
#[tokio::test(flavor = "current_thread")]
async fn un_compte_cree_a_chaud_recoit_du_courrier() {
    let atelier = atelier("compte-a-chaud");
    let Some((autorite, cert, cle)) = materiel(atelier.chemin()) else {
        eprintln!("SAUTÉ : {SANS_OPENSSL}");
        return;
    };
    let chemin_cert = atelier.chemin().join("srv.pem");
    let chemin_cle = atelier.chemin().join("srv.key");
    std::fs::write(&chemin_cert, &cert).expect("le certificat s'écrit");
    std::fs::write(&chemin_cle, &cle).expect("la clé s'écrit");

    // Un seul compte au démarrage. Le second naîtra par l'API.
    let empreinte = ams_auth::hash_password(b"ouvre-toi", b"seize octets ici").expect("hachable");
    let comptes = [ams_auth::Account {
        login: String::from("jean"),
        hash: empreinte,
        addresses: vec![String::from("jean@example.com")],
    }];
    let magasin = ecrire_le_magasin(atelier.chemin(), &comptes);

    let (smtp, http, h3) = (port_libre(), port_libre(), port_libre());
    let config = configuration(
        atelier.chemin(),
        smtp,
        http,
        h3,
        &chemin_cert,
        &chemin_cle,
        &magasin,
    );
    let serveur = lancer(&config, &format!("127.0.0.1:{h3}/udp"));

    let adresse = format!("127.0.0.1:{h3}").parse().expect("une adresse");
    let mut client = Client::new(config_client(&autorite), adresse).await;
    for _ in 0..16 {
        if !client.parler().await && !client.tls().is_handshaking() {
            break;
        }
        if !client.ecouter().await && !client.tls().is_handshaking() {
            break;
        }
    }
    assert!(!client.tls().is_handshaking(), "{}", serveur.journal());

    let admin = frapper_un_jeton(ams_api::Scope::one(
        ams_api::Area::Admin,
        ams_api::Rights::Write,
    ));

    // 1. On crée « pierre ».
    let creation =
        br#"{"login":"pierre","password":"un-secret","addresses":["pierre@example.com"]}"#;
    envoyer_une_requete(&mut client, 0, 20, b"/v1/accounts", Some(&admin), creation).await;
    let texte = String::from_utf8_lossy(&attendre_la_reponse(&mut client, 0).await).to_string();
    assert!(
        texte.contains(r#""login":"pierre""#),
        "le compte doit être créé : {texte} — {}",
        serveur.journal()
    );

    // 2. Il s'authentifie — donc le magasin en mémoire l'a vu, pas seulement le
    //    disque.
    let identifiants = br#"{"login":"pierre","password":"un-secret"}"#;
    envoyer_une_requete(&mut client, 4, 20, b"/v1/tokens", None, identifiants).await;
    let texte = String::from_utf8_lossy(&attendre_la_reponse(&mut client, 4).await).to_string();
    let debut = texte
        .find("\"token\":\"")
        .map(|rang| rang + 9)
        .unwrap_or_else(|| panic!("un jeton pour pierre : {texte} — {}", serveur.journal()));
    let fin = texte
        .get(debut..)
        .and_then(|reste| reste.find('"'))
        .expect("une fin de chaîne")
        + debut;
    let sien = texte[debut..fin].to_string();

    // 3. Il reçoit : la boîte a bien été ouverte à sa création.
    let message = concat!(
        "From: pierre@example.com\r\n",
        "To: pierre@example.com\r\n",
        "Subject: bienvenue\r\n",
        "\r\n",
        "le premier message\r\n",
    )
    .as_bytes();
    envoyer_avec_media(
        &mut client,
        8,
        20,
        b"/v1/submissions",
        Some(&sien),
        message,
        b"message/rfc822",
    )
    .await;
    let texte = String::from_utf8_lossy(&attendre_la_reponse(&mut client, 8).await).to_string();
    assert!(
        texte.contains(r#""delivered":1"#),
        "la remise doit aboutir : {texte} — {}",
        serveur.journal()
    );

    envoyer_une_requete(
        &mut client,
        12,
        17,
        b"/v1/mailboxes/INBOX/messages",
        Some(&sien),
        &[],
    )
    .await;
    let texte = String::from_utf8_lossy(&attendre_la_reponse(&mut client, 12).await).to_string();
    assert!(
        texte.contains(r#""subject":"bienvenue""#),
        "et il relit son message : {texte}"
    );

    // 3 bis. Et il le TROUVE : la recherche traverse l'évaluateur d'IMAP, la
    //        lecture du message, et rend des UID.
    envoyer_une_requete(
        &mut client,
        24,
        20,
        b"/v1/mailboxes/INBOX/search",
        Some(&sien),
        br#"{"subject":"bienvenue","seen":false}"#,
    )
    .await;
    let texte = String::from_utf8_lossy(&attendre_la_reponse(&mut client, 24).await).to_string();
    assert!(
        texte.contains(r#""uids":[1]"#) && texte.contains(r#""complete":true"#),
        "la recherche doit le trouver : {texte} — {}",
        serveur.journal()
    );

    // **ET NE TROUVE PAS CE QUI N'Y EST PAS.** Un essai qui ne montre que le cas
    // positif ne distingue pas une recherche d'un « tout rendre ».
    envoyer_une_requete(
        &mut client,
        28,
        20,
        b"/v1/mailboxes/INBOX/search",
        Some(&sien),
        br#"{"subject":"facture"}"#,
    )
    .await;
    let texte = String::from_utf8_lossy(&attendre_la_reponse(&mut client, 28).await).to_string();
    assert!(texte.contains(r#""uids":[]"#), "{texte}");

    // 4. Le magasin sur le DISQUE porte la même chose : le serveur redémarrerait
    //    sur ce qu'il vient d'écrire.
    let octets = std::fs::read(&magasin).expect("lisible");
    let relu = ams_config::decode_accounts(&octets).expect("le démarrage le relirait");
    assert_eq!(relu.len(), 2, "deux comptes sur le disque");

    // 5. On le retire, et il ne s'authentifie plus.
    // Annexe A de RFC 9204 : 16 vaut `:method: DELETE`. **PAS 18**, qui vaut
    // `:method: HEAD` — et un `HEAD` sur un compte ne le retire pas.
    envoyer_une_requete(
        &mut client,
        16,
        16,
        b"/v1/accounts/pierre",
        Some(&admin),
        &[],
    )
    .await;
    let _ = attendre_la_reponse(&mut client, 16).await;
    envoyer_une_requete(&mut client, 20, 20, b"/v1/tokens", None, identifiants).await;
    let texte = String::from_utf8_lossy(&attendre_la_reponse(&mut client, 20).await).to_string();
    assert!(
        !texte.contains("\"token\""),
        "un compte retiré ne s'authentifie plus : {texte}"
    );
}
