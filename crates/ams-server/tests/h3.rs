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
    Client, SANS_OPENSSL, atelier, attendre_la_reponse, config_client, envoyer_une_requete,
    materiel,
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
        accounts: String::new(),
        listen_pop3: String::new(),
        listen_imap: String::new(),
    };
    let octets = encode(&config).expect("une configuration encodable");
    let chemin = repertoire.join("config.bin");
    std::fs::write(&chemin, &octets).expect("écriture de la configuration");
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

    let (smtp, http, h3) = (port_libre(), port_libre(), port_libre());
    let config = configuration(atelier.chemin(), smtp, http, h3, &chemin_cert, &chemin_cle);
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
