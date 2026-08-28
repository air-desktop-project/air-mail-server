// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le BINAIRE LIVRÉ chiffre-t-il ?
//!
//! # Pourquoi ce test-là, et pas un de plus en mémoire
//!
//! `ams-tls` prouve que le matériel s'assemble. `ams-loop-tokio` prouve que la
//! boucle conduit `STARTTLS`. Aucun des deux ne prouve que **le programme qu'on
//! installe** lit sa configuration, y trouve un certificat, et l'offre.
//!
//! C'est exactement la marche qui manquait jusqu'ici : la boucle savait chiffrer
//! depuis le commit précédent, et le serveur servait pourtant en clair, faute de
//! pouvoir recevoir un certificat. Un test qui monte tout l'assemblage est le
//! seul qui aurait vu la différence.
//!
//! Il lance donc le vrai exécutable, sur une vraie configuration binaire, et lui
//! envoie un vrai client.

use std::io::Write as _;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ams_config::{Configuration, Timeouts, Tls};
use ams_guard::Thresholds;
use ams_proto_smtp::Limits;

const SANS_OPENSSL: &str = "ce test EXIGE `openssl` : il fabrique le certificat du serveur \
                            et joue le client";

/// Un répertoire de travail qui se nettoie tout seul.
struct Atelier(PathBuf);

impl Drop for Atelier {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Un serveur lancé, tué à la fin quoi qu'il arrive.
struct Serveur(Child);

impl Drop for Serveur {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Un répertoire PAR TEST, et pas un par processus : `cargo test` lance les
/// tests d'un même binaire EN PARALLÈLE, et un nom partagé faisait effacer par
/// l'un le répertoire de l'autre. Invisible en les lançant un à un.
fn atelier(nom: &str) -> Atelier {
    let chemin = std::env::temp_dir().join(format!("ams-server-{nom}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&chemin);
    std::fs::create_dir_all(&chemin).expect("répertoire temporaire");
    Atelier(chemin)
}

/// Fabrique une paire certificat/clé, la clé en `0600`.
fn paire(repertoire: &Path) -> Option<(PathBuf, PathBuf)> {
    use std::os::unix::fs::PermissionsExt as _;

    let cert = repertoire.join("chaine.pem");
    let cle = repertoire.join("cle.pem");
    let genere = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "ec"])
        .args(["-pkeyopt", "ec_paramgen_curve:P-256"])
        .args(["-nodes", "-days", "1", "-subj", "/CN=localhost"])
        .arg("-keyout")
        .arg(&cle)
        .arg("-out")
        .arg(&cert)
        .output()
        .ok()?;
    if !genere.status.success() {
        return None;
    }
    // Le serveur refuse une clé lisible par tout le monde, et `openssl` la crée
    // avec le masque de l'utilisateur : on la resserre plutôt que d'espérer.
    std::fs::set_permissions(&cle, std::fs::Permissions::from_mode(0o600)).ok()?;
    Some((cert, cle))
}

/// Un port libre — puis on le rend, et le serveur le reprend.
///
/// La course est réelle et assumée : entre le `drop` et le `bind` du serveur,
/// un autre processus pourrait prendre le port. C'est la façon habituelle de
/// faire, faute de pouvoir demander à un exécutable quel port éphémère il a
/// obtenu, et l'échec serait bruyant plutôt que silencieux.
fn port_libre() -> u16 {
    let ecouteur = TcpListener::bind("127.0.0.1:0").expect("écoute");
    ecouteur.local_addr().expect("adresse").port()
}

fn configuration(atelier: &Atelier, port: u16, tls: Tls) -> PathBuf {
    let config = Configuration {
        domain: String::from("mail.example.com"),
        listen: format!("127.0.0.1:{port}"),
        maildir: atelier.0.join("boite").display().to_string(),
        hosted: vec![String::from("example.com")],
        max_recipients: 100,
        max_message_octets: 10_485_760,
        max_connections: 16,
        limits: Limits::DEFAULT,
        guard: Thresholds::DEFAULT,
        tracked_sources: 64,
        timeouts: Timeouts {
            command_seconds: 10,
            data_seconds: 10,
        },
        tls,
    };
    let chemin = atelier.0.join("ams.conf");
    std::fs::write(&chemin, ams_config::encode(&config).expect("encodable")).expect("écriture");
    chemin
}

/// Lance le serveur et attend qu'il accepte, ou explique ce qu'il a dit.
fn lancer(config: &Path, port: u16) -> Serveur {
    let enfant = Command::new(env!("CARGO_BIN_EXE_air-mail-server"))
        .arg("--config")
        .arg(config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("le serveur devrait se lancer");
    let mut serveur = Serveur(enfant);

    let adresse = SocketAddr::from(([127, 0, 0, 1], port));
    // `checked_add` plutôt qu'un `+` : le workspace interdit l'arithmétique qui
    // peut déborder, y compris dans les tests, et une exception ici serait la
    // première d'une longue série.
    let depart = Instant::now();
    while depart.elapsed() < Duration::from_secs(10) {
        if TcpStream::connect_timeout(&adresse, Duration::from_millis(200)).is_ok() {
            return serveur;
        }
        if let Ok(Some(code)) = serveur.0.try_wait() {
            // On lit ce qu'il a dit : un démarrage refusé porte toujours sa
            // raison sur l'erreur standard, et la taire ferait de ce test un
            // « le serveur n'écoute pas » sans plus d'explication.
            let mut plainte = String::new();
            if let Some(erreur) = serveur.0.stderr.as_mut() {
                let _ = std::io::Read::read_to_string(erreur, &mut plainte);
            }
            panic!("le serveur s'est arrêté au démarrage ({code}) : {plainte}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("le serveur n'écoute toujours pas au bout de dix secondes");
}

#[test]
fn le_binaire_offre_starttls_quand_la_configuration_nomme_un_certificat() {
    let atelier = atelier("chiffrement");
    let Some((cert, cle)) = paire(&atelier.0) else {
        panic!("{SANS_OPENSSL}");
    };
    let port = port_libre();
    let config = configuration(
        &atelier,
        port,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
    );
    let _serveur = lancer(&config, port);

    let mut client = Command::new("openssl")
        .args(["s_client", "-connect"])
        .arg(format!("127.0.0.1:{port}"))
        .args(["-starttls", "smtp", "-ign_eof"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect(SANS_OPENSSL);
    client
        .stdin
        .as_mut()
        .expect("entrée standard")
        .write_all(b"EHLO client.example\r\nQUIT\r\n")
        .expect("écriture");
    let dit = client.wait_with_output().expect("openssl s_client");
    let chiffre = String::from_utf8_lossy(&dit.stdout).into_owned();
    let trace = String::from_utf8_lossy(&dit.stderr).into_owned();
    let tout = format!("--- chiffré ---\n{chiffre}\n--- trace ---\n{trace}");

    assert!(tout.contains("TLSv1.3"), "pas de TLS 1.3 — C4.\n{tout}");
    // Le dialogue chiffré a bien eu lieu : la réponse au second `EHLO` et le
    // congé sont arrivés PAR le tuyau.
    assert!(
        chiffre.contains("250-mail.example.com"),
        "le EHLO chiffré n'a pas reçu de réponse.\n{tout}"
    );
    assert!(chiffre.contains("221 "), "pas de congé.\n{tout}");
}

#[test]
fn sans_certificat_le_binaire_sert_en_clair_et_ne_ment_pas() {
    // L'autre moitié de la propriété, et elle compte autant : un serveur sans
    // certificat ne doit PAS annoncer `STARTTLS`. L'annoncer ferait envoyer à un
    // pair des données qu'il croirait sur le point d'être protégées.
    let atelier = atelier("en-clair");
    let port = port_libre();
    let config = configuration(&atelier, port, Tls::default());
    let _serveur = lancer(&config, port);

    let mut flux = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port))).expect("connexion");
    flux.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("délai");
    flux.write_all(b"EHLO client.example\r\nQUIT\r\n")
        .expect("écriture");
    let mut dit = String::new();
    std::io::Read::read_to_string(&mut flux, &mut dit).expect("lecture");

    assert!(dit.contains("250-mail.example.com"), "{dit}");
    assert!(
        !dit.contains("STARTTLS"),
        "le serveur annonce STARTTLS sans savoir chiffrer.\n{dit}"
    );
}
