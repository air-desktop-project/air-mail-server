// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que le BINAIRE fait de la configuration de l'API REST.
//!
//! # CET ESSAI NE PARLE PAS HTTP, ET C'EST VOULU
//!
//! Le protocole est éprouvé de bout en bout ailleurs — `ams-loop-tokio`,
//! `tests/http.rs`, sur un vrai socket. Ce qui n'y est pas vérifié, c'est le
//! RACCORDEMENT : que le binaire refuse d'ouvrir ce port quand il manque un
//! certificat ou un secret, et qu'il le dise au démarrage.
//!
//! **Chaque refus se lit dans le journal, et se confirme par un port fermé.**
//! Vérifier l'annonce sans vérifier le port laisserait passer un serveur qui dit
//! non et écoute quand même.

use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
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
///
/// # SON ERREUR STANDARD EST LUE EN CONTINU, PAR UN FIL À PART
///
/// La lire à la demande ne marche pas : `read_to_string` sur le tuyau d'un
/// enfant VIVANT n'atteint jamais la fin de fichier, et l'appel y attend pour
/// toujours. Le tuer d'abord répondait à cela, mais alors le journal n'est
/// disponible qu'une fois — et le démarrage, lui, a besoin de le lire pendant
/// que le serveur tourne.
///
/// Un fil qui recopie le tuyau dans un tampon partagé ferme les deux : le
/// journal est lisible à tout instant, sans jamais bloquer, et le tuyau ne se
/// remplit pas au point d'arrêter l'enfant qui écrit dedans.
struct Serveur {
    enfant: Child,
    journal: Arc<Mutex<String>>,
}

impl Serveur {
    /// Ce que le serveur a écrit jusqu'ici.
    fn journal(&self) -> String {
        match self.journal.lock() {
            Ok(lu) => lu.clone(),
            // Un fil de lecture qui a paniqué a laissé le verrou empoisonné :
            // ce qu'il avait déjà recopié reste bon à lire, et c'est justement
            // dans ce cas-là qu'on en a besoin.
            Err(empoisonne) => empoisonne.into_inner().clone(),
        }
    }

    /// Ce que le serveur est devenu, et ce qu'il en a dit.
    ///
    /// # UNE CONNEXION REFUSÉE NE DIT PAS POURQUOI
    ///
    /// « Connection refused » ne distingue pas un serveur qui n'a jamais démarré
    /// d'un serveur qui s'est arrêté en chemin. C'est arrivé en intégration
    /// continue, et le journal n'en disait rien de plus : le test échouait sans
    /// que personne ne puisse conclure. On lit donc l'état de l'enfant ET ce
    /// qu'il a écrit sur l'erreur standard, et l'échec porte la raison.
    fn plainte(&mut self) -> String {
        let etat = match self.enfant.try_wait() {
            Ok(Some(code)) => format!("le serveur s'est arrêté ({code})"),
            Ok(None) => String::from("le serveur tourne encore"),
            Err(erreur) => format!("état du serveur illisible : {erreur}"),
        };
        format!("{etat} — il a dit : {}", self.journal())
    }
}

impl Drop for Serveur {
    fn drop(&mut self) {
        let _ = self.enfant.kill();
        let _ = self.enfant.wait();
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
/// Un port qu'aucun autre test de ce fichier ne demandera.
///
/// # Pourquoi pas `bind(":0")`, qui serait plus court
///
/// Parce qu'il faut RENDRE le port avant que le serveur ne le prenne — la
/// configuration le nomme, et le serveur est un autre processus. Entre les deux,
/// le noyau peut donner le même port à un test voisin qui demande au même
/// instant : deux serveurs se disputent alors une adresse, le second meurt, et
/// le premier voit sa sonde de démarrage réussir sur le serveur de l'autre. On
/// l'a vu — « connexion refusée » sur un serveur que la sonde venait de joindre.
///
/// Un compteur atomique ferme cela : deux appels ne rendent jamais le même
/// nombre. La plage est choisie SOUS les ports éphémères du noyau (32768 et
/// au-delà sous Linux), là où rien d'autre n'écoute.
fn port_libre() -> u16 {
    static SUIVANT: AtomicU16 = AtomicU16::new(0);
    for _ in 0..64_u16 {
        let rang = SUIVANT.fetch_add(1, Ordering::Relaxed);
        // **UNE PLAGE PAR BINAIRE D'ESSAI** : `api.rs` et `chiffrement.rs`
        // partaient tous deux de 24000 avec chacun son compteur, et se
        // tendaient donc les mêmes ports dans le même ordre. Un serveur de
        // l'un encore vivant quand l'autre démarre suffisait : « Address already
        // in use », deux fois dans la barrière, sur des essais sans rapport.
        let candidat = 24_000_u16.saturating_add(rang % 2_000);
        // On éprouve qu'il est libre — que personne n'y répond, et qu'on peut
        // le lier —, et on le rend aussitôt : c'est tout ce qu'on peut faire
        // pour un serveur qui liera lui-même. La connexion voit aussi une
        // écoute sur l'adresse joker, que la liaison seule laisse passer.
        let occupe = std::net::TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], candidat)),
            Duration::from_millis(50),
        )
        .is_ok();
        if !occupe && TcpListener::bind(("127.0.0.1", candidat)).is_ok() {
            return candidat;
        }
    }
    panic!("aucun port libre dans la plage des tests");
}

/// Une configuration qui décrit aussi l'écoute HTTP.
fn configuration_api(
    atelier: &Atelier,
    port: u16,
    tls: Tls,
    ecoute_http: &str,
    clef: &str,
) -> PathBuf {
    configuration_complete(atelier, port, tls, "", "", "", ecoute_http, "", clef)
}

/// La même, avec une écoute HTTP/3 en plus.
fn configuration_avec_h3(
    atelier: &Atelier,
    port: u16,
    tls: Tls,
    ecoute_http: &str,
    ecoute_h3: &str,
    clef: &str,
) -> PathBuf {
    configuration_complete(atelier, port, tls, "", "", "", ecoute_http, ecoute_h3, clef)
}

#[expect(
    clippy::too_many_arguments,
    reason = "un montage d'essai décrit une configuration, et une configuration a des champs"
)]
fn configuration_complete(
    atelier: &Atelier,
    port: u16,
    tls: Tls,
    comptes: &str,
    appareils: &str,
    pop3: &str,
    ecoute_http: &str,
    ecoute_h3: &str,
    clef: &str,
) -> PathBuf {
    let config = Configuration {
        // Ces essais portent sur le transport, pas sur l'enveloppe.
        require_fqdn_helo: false,
        // Ce banc ne sert pas SCRAM : les deux chemins restent vides.
        scram_key: String::new(),
        scram_store: String::new(),
        devices: appareils.to_string(),
        app_passwords: String::new(),
        delegations: String::new(),
        drafts: String::new(),
        push_vapid_key: String::new(),
        push_contact: String::new(),
        apns_key: String::new(),
        apns_key_id: String::new(),
        apns_team_id: String::new(),
        apns_topic: String::new(),
        apns_sandbox: false,
        fcm_service_account: String::new(),
        audit: String::new(),
        android_attestation: ams_config::AttestationMode::Off,
        android_package: String::new(),
        android_signers: Vec::new(),
        android_roots: String::new(),
        android_revocation: String::new(),
        android_revocation_max_days: 7,
        apple_attestation: ams_config::AttestationMode::Off,
        apple_app_id: String::new(),
        apple_development: false,
        registre: String::new(),
        // **CES BANCS NE S'ANNONCENT PAS** : ils éprouvent le courrier et
        // l'API, pas la découverte de services. Le défaut — un répertoire
        // d'état vide — est exactement ce qu'un fichier écrit avant ce
        // champ décode.
        asl: ams_config::Asl::default(),
        about: true,
        require_fqdn_sender: false,
        require_fqdn_recipient: false,
        require_sender_domain: false,
        // Une seule écoute, en `STARTTLS` : la liste vide dirait la même
        // chose, et l'écrire ici la rend lisible.
        smtp_listeners: Vec::new(),
        imap_listeners: Vec::new(),
        pop3_listeners: Vec::new(),
        imap_implicit_tls: false,
        domain: String::from("mail.example.com"),
        listen: format!("127.0.0.1:{port}"),
        maildir: atelier.0.join("boite").display().to_string(),
        hosted: vec![String::from("example.com")],
        max_recipients: 100,
        listen_http: String::from(ecoute_http),
        listen_h3: String::from(ecoute_h3),
        token_key: String::from(clef),
        max_message_octets: 10_485_760,
        max_connections: 16,
        limits: Limits::DEFAULT,
        guard: Thresholds::DEFAULT,
        tracked_sources: 64,
        api_rate: ams_guard::Rate::DEFAULT,
        // AUCUNE ÉMISSION : ces essais reçoivent, ils n'émettent pas.
        relay: ams_config::Relay::default(),
        // ET AUCUNE FILE : rien ne sort dans ces essais.
        queue: ams_config::Queue::default(),
        // MTA-STS NON ÉVALUÉ : ces essais ne joignent aucun hôte de politique.
        mtasts: ams_config::Mtasts::default(),
        // AUCUN RAPPORT TLS : ces essais n'émettent vers personne.
        tlsrpt: ams_config::Tlsrpt::default(),
        timeouts: Timeouts {
            command_seconds: 10,
            data_seconds: 10,
            quic_idle_seconds: 0,
        },
        tls,
        spf: ams_config::Spf::default(),
        dmarc: ams_config::Dmarc::default(),
        dkim: ams_config::Dkim::default(),
        accounts: comptes.to_string(),
        listen_pop3: pop3.to_string(),
        listen_imap: String::new(),
    };
    let chemin = atelier.0.join("ams.conf");
    std::fs::write(&chemin, ams_config::encode(&config).expect("encodable")).expect("écriture");
    chemin
}

/// Lance le serveur et attend qu'il écoute, ou explique ce qu'il a dit.
///
/// # ON NE SONDE PLUS LE PORT, ET C'EST UN DÉFAUT RÉEL QUI L'A IMPOSÉ
///
/// Cette fonction ouvrait une connexion d'essai et la fermait aussitôt, sans
/// rien lire. Le serveur y répondait sa bannière ; le pair, déjà fermé, la
/// renvoyait par un `RST` — **et un `RST` détruit la socket cliente sans passer
/// par `TIME-WAIT`**. Le port éphémère redevenait donc libre sur-le-champ, et le
/// `connect` suivant pouvait le reprendre : même quadruplet, à quelques
/// microsecondes de la connexion que le serveur n'avait pas encore effacée de sa
/// table. Le `SYN` tombait alors sur une connexion qu'il croyait établie, et la
/// nouvelle connexion mourait sans qu'un octet ne l'ait traversée.
///
/// C'est ce qui faisait échouer ce fichier une fois sur vingt-cinq — davantage
/// sous charge, la fenêtre s'élargissant avec l'ordonnancement — et ce qui a
/// fini par arrêter l'intégration continue. Le symptôme accusait le serveur, qui
/// n'y était pour rien : il écoutait, il était vivant, il avait tout dit.
///
/// **La sonde était donc la panne qu'elle prétendait mesurer.** On attend
/// maintenant que le serveur ANNONCE son écoute — il l'écrit sur son erreur
/// standard, juste après le `bind` — et l'attente ne touche plus au réseau. Le
/// port n'a pas besoin d'être sondé : entre le `bind` et le premier `accept`,
/// le noyau met les connexions en file, et le client n'y voit rien.
fn lancer(config: &Path, port: u16) -> Serveur {
    let mut enfant = Command::new(env!("CARGO_BIN_EXE_air-mail-server"))
        .arg("--config")
        .arg(config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("le serveur devrait se lancer");
    let journal = Arc::new(Mutex::new(String::new()));
    // ON VIDE LE TUYAU SANS DISCONTINUER : un enfant dont l'erreur standard se
    // remplit s'arrête d'écrire, donc de servir. Le fil s'achève tout seul à la
    // mort de l'enfant, quand le tuyau atteint sa fin de fichier.
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
    let mut serveur = Serveur { enfant, journal };

    // La ligne que le serveur écrit juste après avoir lié son écoute. La
    // chercher AVEC le port distingue l'annonce SMTP de celles de POP3 et
    // d'IMAP, qui portent le même verbe sur d'autres adresses.
    let annonce = format!("écoute sur 127.0.0.1:{port}");
    let depart = Instant::now();
    while depart.elapsed() < Duration::from_secs(10) {
        if serveur.journal().contains(&annonce) {
            return serveur;
        }
        if let Ok(Some(_)) = serveur.enfant.try_wait() {
            // On lit ce qu'il a dit : un démarrage refusé porte toujours sa
            // raison sur l'erreur standard, et la taire ferait de ce test un
            // « le serveur n'écoute pas » sans plus d'explication.
            panic!("au démarrage : {}", serveur.plainte());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!(
        "le serveur n'écoute toujours pas au bout de dix secondes — {}",
        serveur.plainte()
    );
}

/// Une clé de scellement d'essai, en hexadécimal.
const CLEF: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

/// Frappe un jeton d'ADMINISTRATION, comme `air-mail-admin token` le fait.
fn jeton_d_administration() -> String {
    let clef = ams_api::key_from_hex(CLEF).expect("la clé d'essai est lisible");
    let maintenant = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("après 1970")
            .as_micros(),
    )
    .expect("l'horloge tient dans un u64");
    let jeton = ams_api::Token {
        login: "jean",
        // **LA MÊME PORTÉE QUE L'OUTIL**, et pas une de plus : un essai qui se
        // donnerait le courrier en plus n'éprouverait pas ce qu'un exploitant a
        // réellement entre les mains.
        scope: ams_api::Scope::one(ams_api::Area::Admin, ams_api::Rights::Write),
        expiry: maintenant.saturating_add(900_000_000),
        nonce: 42,
    };
    let mut place = [0_u8; ams_api::ENCODED_OCTETS_MAX];
    ams_api::issue(&clef, &jeton, maintenant, &mut place)
        .expect("le jeton se scelle")
        .to_string()
}

/// **L'API EST SERVIE À UN CLIENT QUI N'EST PAS DE NOTRE MAIN.**
///
/// # CE QUE LES AUTRES ESSAIS DE CE FICHIER NE FONT PAS
///
/// Ils jouent le client avec `openssl` et des requêtes écrites ici. HTTP/2 n'est
/// pourtant pas un protocole qu'on improvise : HPACK, le cadrage, les fenêtres.
/// Un malentendu sur l'un des trois se retrouverait des DEUX côtés, écrit par la
/// même main, et aucun de ces essais ne le verrait.
///
/// `libcurl` en a sa propre implémentation, éprouvée contre le reste du monde.
///
/// # ET IL VÉRIFIE AUSSI CE QU'ON REFUSE
///
/// Un jeton d'administration ouvre `/v1/accounts` et `/v1/domains`, et **ne doit
/// pas** ouvrir `/v1/mailboxes` : `air-mail-admin token` ne frappe que la portée
/// `Admin`. Le refus se lit `404` et non `403`, délibérément — voir
/// `ams_api::problem` : « `NoSuchResource` et `Forbidden` répondent toutes deux
/// 404, précisément pour que "cette ressource existe" ne se lise pas dans la
/// réponse ».
#[test]
fn un_client_curl_parle_a_l_api_en_http2() {
    let atelier = atelier("interop-curl-api");
    let Some((cert, cle)) = paire(&atelier.0) else {
        panic!("{SANS_OPENSSL}");
    };
    if std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("IGNORÉ : `curl` est absent — cet essai n'a RIEN éprouvé.");
        return;
    }

    let port_smtp = port_libre();
    let port_http = port_libre();
    let config = configuration_api(
        &atelier,
        port_smtp,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        &format!("127.0.0.1:{port_http}"),
        CLEF,
    );
    let serveur = lancer_avec_api(&config, port_smtp, port_http);

    let jeton = jeton_d_administration();
    let appeler = |chemin: &str| -> (String, String) {
        let sortie = std::process::Command::new("curl")
            .arg("-s")
            .arg("--insecure")
            .arg("--http2")
            .args(["-H", &format!("Authorization: Bearer {jeton}")])
            .args(["-w", "\n%{http_code} %{http_version}"])
            .arg(format!("https://127.0.0.1:{port_http}{chemin}"))
            .output()
            .expect("curl s'exécute");
        let tout = reponse_de_curl(&serveur, &sortie);
        let (corps, fin) = tout.rsplit_once('\n').unwrap_or(("", ""));
        (corps.to_string(), fin.to_string())
    };

    // ── CE QUE LA PORTÉE OUVRE ──────────────────────────────────────────────
    let (corps, fin) = appeler("/v1/accounts");
    assert_eq!(
        fin, "200 2",
        "curl doit lire les comptes en HTTP/2 : {corps}"
    );
    assert!(
        corps.contains('{') || corps.contains('['),
        "la réponse doit être du JSON : {corps}"
    );
    let (_, fin) = appeler("/v1/domains");
    assert_eq!(fin, "200 2", "curl doit lire les domaines");

    // ── CE QU'ELLE N'OUVRE PAS, ET QUI NE DIT PAS QU'IL EXISTE ─────────────
    let (corps, fin) = appeler("/v1/mailboxes");
    assert_eq!(
        fin, "404 2",
        "un jeton d'administration ne doit pas ouvrir le courrier"
    );
    assert!(
        corps.contains("not-found"),
        "le refus doit être indiscernable d'une route inconnue : {corps}"
    );

    // ── UN SECRET VIDE SE REFUSE, MÊME À UN ADMINISTRATEUR ─────────────────
    //
    // Le contrôle précède la recherche du compte : un corps qu'on ne pourrait
    // de toute façon pas appliquer se refuse avant d'aller voir s'il existe
    // quelqu'un à qui l'appliquer.
    let poser = |corps: &str| -> String {
        let sortie = std::process::Command::new("curl")
            .args(["-s", "-S", "--insecure", "--http2", "-X", "PUT"])
            .args(["-H", &format!("Authorization: Bearer {jeton}")])
            .args(["-H", "Content-Type: application/json"])
            .args(["-d", corps])
            .args(["-o", "/dev/null", "-w", "%{http_code}"])
            .arg(format!(
                "https://127.0.0.1:{port_http}/v1/accounts/marc/password"
            ))
            .output()
            .expect("curl s'exécute");
        reponse_de_curl(&serveur, &sortie)
    };
    assert_eq!(
        poser(r#"{"password":""}"#),
        "400",
        "`air-mail-admin` refuse un secret vide ; l'API doit le refuser aussi"
    );
    // Et un secret non vide passe le contrôle DE CORPS — il échoue ensuite sur
    // le compte, qui n'existe pas dans cette configuration sans magasin. Les
    // deux codes distincts montrent que ce sont bien deux contrôles.
    assert_eq!(poser(r#"{"password":"quelque-chose"}"#), "404");

    // ── ET SANS JETON, RIEN ────────────────────────────────────────────────
    let sortie = std::process::Command::new("curl")
        .arg("-s")
        .arg("--insecure")
        .arg("--http2")
        .args(["-o", "/dev/null", "-w", "%{http_code}"])
        .arg(format!("https://127.0.0.1:{port_http}/v1/accounts"))
        .output()
        .expect("curl s'exécute");
    assert_eq!(
        String::from_utf8_lossy(&sortie.stdout),
        "401",
        "sans jeton, l'API doit refuser"
    );

    // **`/v1/health` NE FAIT PAS EXCEPTION**, et `bascule.md` s'appuie dessus :
    // la vérification de pare-feu qu'il prescrit attend un `401`, qui prouve
    // que le port est ouvert ET que le serveur parle. Si cette route devenait
    // un jour libre d'accès, la marche à suivre dirait une chose fausse le jour
    // de la bascule — et l'on chercherait la panne du mauvais côté.
    let sortie = std::process::Command::new("curl")
        .arg("-s")
        .arg("--insecure")
        .arg("--http2")
        .args(["-o", "/dev/null", "-w", "%{http_code}"])
        .arg(format!("https://127.0.0.1:{port_http}/v1/health"))
        .output()
        .expect("curl s'exécute");
    assert_eq!(
        String::from_utf8_lossy(&sortie.stdout),
        "401",
        "`/v1/health` exige la portée `Observe` : sans jeton, c'est 401"
    );
}

/// Ce port accepte-t-il une connexion ?
fn ecoute_ouverte(port: u16) -> bool {
    let adresse: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().expect("une adresse");
    std::net::TcpStream::connect_timeout(&adresse, Duration::from_millis(500)).is_ok()
}

/// **SANS CERTIFICAT, CE PORT N'EXISTE PAS** — et c'est la différence avec SMTP,
/// POP3 et IMAP, qui servent en clair et refusent l'authentification.
#[test]
fn sans_certificat_l_api_ne_s_ouvre_pas() {
    let atelier = atelier("api-sans-cert");
    let smtp = port_libre();
    let http = port_libre();
    let config = configuration_api(
        &atelier,
        smtp,
        Tls {
            certificate_chain_path: String::new(),
            private_key_path: String::new(),
        },
        &format!("127.0.0.1:{http}"),
        CLEF,
    );
    let serveur = lancer(&config, smtp);
    // `attendre_le_journal` GARANTIT la première moitié : il panique en le
    // disant si la ligne ne vient pas. Ce qui reste à vérifier ici est la
    // RAISON qu'elle donne, et l'échec ne parle donc plus que d'elle.
    let journal = attendre_le_journal(&serveur, "API REST NON SERVIE");
    assert!(
        journal.contains("aucun certificat"),
        "le serveur doit dire POURQUOI il n'ouvre pas ce port : {journal}"
    );
    assert!(
        !ecoute_ouverte(http),
        "le port {http} ne doit pas être ouvert"
    );
}

/// **SANS SECRET DE SCELLEMENT, RIEN NON PLUS** : aucun jeton ne pourrait être
/// scellé ni vérifié, et le découvrir à la première requête serait tard.
#[test]
fn sans_secret_l_api_ne_s_ouvre_pas() {
    let atelier = atelier("api-sans-clef");
    let Some((cert, cle)) = paire(&atelier.0) else {
        eprintln!("SAUTÉ : {SANS_OPENSSL}");
        return;
    };
    let smtp = port_libre();
    let http = port_libre();
    let config = configuration_api(
        &atelier,
        smtp,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        &format!("127.0.0.1:{http}"),
        "",
    );
    let serveur = lancer(&config, smtp);
    let journal = attendre_le_journal(&serveur, "API REST NON SERVIE");
    assert!(
        journal.contains("aucun secret"),
        "le serveur doit dire POURQUOI il n'ouvre pas ce port : {journal}"
    );
    assert!(!ecoute_ouverte(http), "le port {http} ne doit pas s'ouvrir");
}

/// **UN SECRET QUI N'EST PAS DE L'HEXADÉCIMAL ARRÊTE LE DÉMARRAGE.**
///
/// Ce n'est pas un refus poli comme les deux précédents : une configuration qui
/// dit vouloir l'API avec un secret illisible s'est trompée, et démarrer sans
/// elle ferait croire que tout va bien.
#[test]
fn un_secret_illisible_arrete_le_demarrage() {
    let atelier = atelier("api-mauvaise-clef");
    let Some((cert, cle)) = paire(&atelier.0) else {
        eprintln!("SAUTÉ : {SANS_OPENSSL}");
        return;
    };
    let smtp = port_libre();
    let http = port_libre();
    let config = configuration_api(
        &atelier,
        smtp,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        &format!("127.0.0.1:{http}"),
        "pas de l'hexadécimal du tout",
    );
    let issue = Command::new(env!("CARGO_BIN_EXE_air-mail-server"))
        .arg("--config")
        .arg(&config)
        .stdin(Stdio::null())
        .output()
        .expect("le serveur devrait se lancer");
    assert!(
        !issue.status.success(),
        "un secret illisible doit arrêter le démarrage"
    );
    let dit = String::from_utf8_lossy(&issue.stderr);
    // Les deux refus possibles — nombre impair de chiffres, ou chiffre qui n'en
    // est pas un — nomment tous deux le secret. C'est ce qu'un administrateur
    // cherche dans son journal.
    assert!(dit.contains("secret de scellement des jetons"), "{dit}");
}

/// **AVEC LES TROIS, LE PORT S'OUVRE ET SERT `h2`.**
#[test]
fn avec_certificat_et_secret_l_api_sert_h2() {
    let atelier = atelier("api-servie");
    let Some((cert, cle)) = paire(&atelier.0) else {
        eprintln!("SAUTÉ : {SANS_OPENSSL}");
        return;
    };
    let smtp = port_libre();
    let http = port_libre();
    let config = configuration_api(
        &atelier,
        smtp,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        &format!("127.0.0.1:{http}"),
        CLEF,
    );
    let serveur = lancer(&config, smtp);
    let annonce = format!("API REST sur 127.0.0.1:{http}");
    // L'annonce elle-même est garantie par l'attente : la réasserter ici ne
    // pourrait plus échouer, et une assertion qui ne peut pas échouer se lit
    // comme une garantie qu'elle ne donne pas.
    let journal = attendre_le_journal(&serveur, &annonce);
    // **CE QUE LE DÉMARRAGE DIT DE LA PORTÉE** : un mot de passe n'ouvre pas
    // l'administration, et le serveur l'annonce plutôt que de le laisser
    // découvrir.
    assert!(
        journal.contains("N'OUVRE PAS L'ADMINISTRATION"),
        "{journal}"
    );

    // Le port sert vraiment : `openssl s_client` négocie `h2` par ALPN.
    let issue = Command::new("openssl")
        .args(["s_client", "-connect", &format!("127.0.0.1:{http}")])
        .args(["-alpn", "h2", "-brief"])
        .stdin(Stdio::null())
        .output()
        .expect("openssl");
    let dit = String::from_utf8_lossy(&issue.stderr);
    assert!(
        dit.contains("ALPN protocol: h2") || dit.contains("Protocol version: TLSv1.3"),
        "la poignée de main devrait aboutir en TLS 1.3 avec `h2` : {dit}"
    );

    // **ET UN CLIENT QUI N'OFFRE QUE `http/1.1` NE PASSE PAS.**
    let refus = Command::new("openssl")
        .args(["s_client", "-connect", &format!("127.0.0.1:{http}")])
        .args(["-alpn", "http/1.1", "-brief"])
        .stdin(Stdio::null())
        .output()
        .expect("openssl");
    let dit = String::from_utf8_lossy(&refus.stderr);
    assert!(
        !dit.contains("ALPN protocol: http/1.1"),
        "`http/1.1` ne doit jamais être négocié : {dit}"
    );
}

/// Combien de temps on laisse au serveur pour écrire une ligne de démarrage.
///
/// # DIX SECONDES, ET C'EST LA MÊME BORNE QUE POUR L'ÉCOUTE
///
/// Elle valait cinq, là où l'attente de l'écoute en accordait dix. Deux bornes
/// différentes pour la même chose — « le serveur a-t-il fini de monter ? » —
/// n'ont pas de raison d'être, et la plus courte cédait la première.
///
/// Généreuse, parce qu'elle **ne coûte rien quand tout va bien** : on ne
/// l'atteint que lorsqu'il y a un défaut à voir. La resserrer ne rendrait la
/// suite plus rapide que dans les cas où elle échoue.
const ATTENTE_DU_JOURNAL: Duration = Duration::from_secs(10);

/// Attend que le serveur ait écrit cette ligne, et rend ce qu'il a dit.
///
/// # POURQUOI ATTENDRE PLUTÔT QUE DE LIRE
///
/// `lancer` rend la main dès l'annonce de l'écoute SMTP, qui est écrite juste
/// après le `bind` — donc **avant** que l'API, HTTP/3 et le reste ne se montent.
/// Lire le journal à cet instant, c'est le lire au hasard de l'ordonnancement :
/// l'essai passe la plupart du temps, et échoue sous charge sans rien apprendre.
///
/// # CETTE AIDE RENONÇAIT EN SILENCE, ET C'EST CE QU'ELLE PRÉTENDAIT ÉVITER
///
/// Elle rendait le journal au bout du délai **que le motif y soit ou non**, et
/// les trois essais qui l'appellent assertent aussitôt derrière. Sous charge,
/// l'échec ne disait donc pas « j'ai attendu dix secondes et cette ligne n'est
/// jamais venue » : il disait « le journal ne contient pas X », en montrant un
/// journal d'apparence normale.
///
/// **C'est très exactement la forme d'un défaut qu'on ne reproduit pas.** Un
/// échec dont le message ne nomme pas sa cause envoie chercher ailleurs — et le
/// registre de ce dépôt porte un essai instable qu'une vingtaine d'exécutions
/// n'ont pas su expliquer.
///
/// # Panics
///
/// Si la ligne n'est jamais venue, en le DISANT — avec ce qu'on attendait,
/// combien de temps, et tout ce que le serveur a écrit pendant ce temps.
/// Lance le serveur et attend que **l'API REST** soit liée, pas seulement SMTP.
///
/// # POURQUOI CE HELPER EXISTE
///
/// `lancer` n'attend que l'écoute SMTP, et l'API s'ouvre APRÈS elle. Dix-sept
/// essais de ce fichier partaient donc leur première requête sur un port qui
/// pouvait n'être pas encore lié : `curl` ne joignait personne, rendait une
/// sortie VIDE, et une assertion de la forme `assert!(!rendu.contains("token"))`
/// s'en trouvait satisfaite. L'essai se croyait au vert sur une requête qui
/// n'avait pas eu lieu.
///
/// C'est ce qui rendait `le_journal_d_audit_dit_les_sessions_et_les_refus`
/// instable — son refus n'avait jamais lieu, l'entrée d'audit n'était donc pas
/// EN RETARD mais JAMAIS PRODUITE. Deux correctifs l'ont manqué pour cette
/// raison : allonger l'attente du journal (0.2.47), puis accélérer le fil
/// d'audit (0.2.49). Aucun des deux ne pouvait rien pour une requête perdue.
///
/// **LE BON COMPORTEMENT DOIT ÊTRE LE PLUS FACILE** : ce helper rend l'attente
/// automatique, là où dix-sept copies de `lancer` l'oubliaient chacune.
fn lancer_avec_api(config: &Path, port_smtp: u16, port_http: u16) -> Serveur {
    let serveur = lancer(config, port_smtp);
    attendre_le_journal(&serveur, &format!("API REST sur 127.0.0.1:{port_http}"));
    serveur
}

/// Rend la sortie standard de `curl`, ou **dit tout ce qu'on sait** si elle
/// manque.
///
/// # POURQUOI CE HELPER EXISTE
///
/// Ces essais pilotent le serveur par des séquences d'appels `curl`, et c'est
/// cette famille-là qui fournit presque toutes les chutes sous charge. Le motif
/// qu'ils partageaient — `String::from_utf8_lossy(&sortie.stdout)` sans rien
/// vérifier — a deux trous, et les deux ont coûté des heures d'enquête :
///
///   — **`curl` QUI N'A JOINT PERSONNE REND 0 ET UNE SORTIE VIDE.** Aucun de
///     ces essais ne passe `-f`, donc `curl` ne se plaint pas d'un `4xx` ni
///     d'un `5xx` : un code non nul signifie qu'il n'a pas pu PARLER au
///     serveur. C'est précisément ce qui arrivait quand l'API n'écoutait pas
///     encore.
///   — **UNE SORTIE VIDE SATISFAISAIT LES ASSERTIONS NÉGATIVES.** Un
///     `assert!(!rendu.contains("token"))` était vrai pour une requête qui
///     n'avait pas eu lieu. L'essai se croyait au vert, et le défaut se
///     manifestait ailleurs, plus tard, sous une forme incompréhensible.
///
/// # CE QU'IL DIT, ET POURQUOI CHAQUE PIÈCE COMPTE
///
/// Le code de sortie, la sortie d'erreur de `curl` — qui nomme le refus de
/// connexion —, et ce qui a quand même été rendu. `#[track_caller]` fait
/// pointer la panique sur L'APPEL, pas sur ce helper : l'échec dit donc
/// *laquelle* des requêtes de l'essai a manqué.
///
/// **UN ROUGE DOIT S'EXPLIQUER À SA PREMIÈRE OCCURRENCE.** Sur cette famille
/// d'essais, un défaut se reproduit une fois sur vingt sous charge : rejouer
/// pour comprendre coûte une demi-heure, et trois enquêtes ont été refaites
/// de zéro faute de cette trace.
#[track_caller]
fn reponse_de_curl(serveur: &Serveur, sortie: &std::process::Output) -> String {
    let dehors = String::from_utf8_lossy(&sortie.stdout).into_owned();
    // **LE JOURNAL SE LAISSE RATTRAPER AVANT D'ÊTRE LU.** Il arrive par un
    // tuyau que vide un fil : la ligne que le serveur vient d'écrire peut
    // n'être pas encore dans l'instantané. Lire trop tôt a déjà fait conclure
    // à tort, cette nuit, qu'un registre n'avait pas été ouvert. On ne paie ce
    // délai QUE sur un échec.
    let journal_du_serveur = || {
        std::thread::sleep(Duration::from_millis(250));
        serveur.journal()
    };
    assert!(
        sortie.status.success(),
        "`curl` n'a pas pu parler au serveur (code {:?}) — ce n'est PAS un refus \
         applicatif, aucun appel ici ne passe `-f`.\n\
         Les codes qu'on voit ici : 7 « connexion refusée » (rien n'écoute), \
         28 « délai dépassé », 35 « échec de la poignée de main TLS ».\n\
         --- sortie d'erreur de curl ---\n{}\n\
         --- ce qui a quand même été rendu ---\n{dehors}\n\
         --- ce que le SERVEUR a dit ---\n{}",
        sortie.status.code(),
        String::from_utf8_lossy(&sortie.stderr),
        journal_du_serveur()
    );
    assert!(
        !dehors.is_empty(),
        "`curl` a rendu une sortie VIDE — une requête qui n'a pas eu lieu ne doit pas \
         passer pour une réponse.\n--- sortie d'erreur de curl ---\n{}\n\
         --- ce que le SERVEUR a dit ---\n{}",
        String::from_utf8_lossy(&sortie.stderr),
        journal_du_serveur()
    );
    dehors
}

fn attendre_le_journal(serveur: &Serveur, motif: &str) -> String {
    let depart = Instant::now();
    loop {
        let journal = serveur.journal();
        if journal.contains(motif) {
            return journal;
        }
        if depart.elapsed() >= ATTENTE_DU_JOURNAL {
            std::panic!(
                "le serveur n'a jamais écrit `{motif}` en {} secondes.\n\
                 CE N'EST PAS FORCÉMENT UN DÉFAUT DU SERVEUR : sous forte charge,\n\
                 ce délai peut être trop court. Ce qu'il a dit :\n{journal}",
                ATTENTE_DU_JOURNAL.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Un port UDP est-il ouvert ?
///
/// **ON NE PEUT PAS SE CONNECTER À UDP** : il n'y a pas de poignée de main. On
/// tente donc de s'y attacher soi-même — si cela réussit, personne n'écoutait.
fn ecoute_udp_ouverte(port: u16) -> bool {
    std::net::UdpSocket::bind(format!("127.0.0.1:{port}")).is_err()
}

/// **HTTP/3 NE S'OUVRE PAS TOUT SEUL.**
///
/// Il se sert conventionnellement sur le même numéro de port que HTTP/2, en UDP.
/// L'ouvrir dès que HTTP/2 l'est serait ouvrir un port derrière un pare-feu que
/// l'exploitant n'a pas ouvert — et une surprise sur un port est un incident.
#[test]
fn http3_ne_s_ouvre_pas_tout_seul() {
    let atelier = atelier("h3-silencieux");
    let Some((cert, cle)) = paire(&atelier.0) else {
        eprintln!("SAUTÉ : {SANS_OPENSSL}");
        return;
    };
    let smtp = port_libre();
    let http = port_libre();
    let config = configuration_api(
        &atelier,
        smtp,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        &format!("127.0.0.1:{http}"),
        CLEF,
    );
    let serveur = lancer(&config, smtp);
    let journal = attendre_le_journal(&serveur, "API REST sur");
    assert!(
        journal.contains("API REST sur") && !journal.contains("HTTP/3"),
        "HTTP/2 s'ouvre, HTTP/3 ne se mentionne même pas : {journal}"
    );
    assert!(
        !ecoute_udp_ouverte(http),
        "le port UDP {http} ne doit pas être ouvert"
    );
}

/// **CONFIGURÉ, IL S'OUVRE — ET IL LE DIT.**
#[test]
fn http3_configure_s_ouvre() {
    let atelier = atelier("h3-ouvert");
    let Some((cert, cle)) = paire(&atelier.0) else {
        eprintln!("SAUTÉ : {SANS_OPENSSL}");
        return;
    };
    let smtp = port_libre();
    let http = port_libre();
    let h3 = port_libre();
    let config = configuration_avec_h3(
        &atelier,
        smtp,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        &format!("127.0.0.1:{http}"),
        &format!("127.0.0.1:{h3}"),
        CLEF,
    );
    let serveur = lancer(&config, smtp);
    let journal = attendre_le_journal(&serveur, &format!("127.0.0.1:{h3}/udp"));
    assert!(
        journal.contains("ALPN `h3` seul"),
        "le serveur doit dire ce qu'il ouvre : {journal}"
    );
    // **LE JOURNAL EST DANS LE MESSAGE, ET C'EST LE CŒUR DE CET ESSAI.**
    //
    // Le serveur LIE la socket avant de l'annoncer : s'il a écrit cette ligne,
    // le port était ouvert. Trouver le port libre ensuite veut donc dire qu'il
    // l'a RELÂCHÉ — c'est-à-dire qu'il est mort entre les deux, et la seule
    // chose qui puisse le dire est ce qu'il a écrit en mourant.
    //
    // Sans le journal, ce refus s'est présenté deux fois comme « le port UDP
    // 24010 doit être ouvert », ce qui ne désigne aucune cause et envoie
    // soupçonner l'ouverture elle-même. Le cas le plus probable est une course
    // de `port_libre()` sur une AUTRE écoute du même serveur — trois ports sont
    // tirés, et la suite entière tourne en parallèle.
    assert!(
        ecoute_udp_ouverte(h3),
        "le port UDP {h3} doit être ouvert — le serveur l'a pourtant annoncé, \
         donc il l'a relâché depuis. Ce qu'il a dit :\n{}",
        serveur.journal()
    );
}

/// **SANS `listenHttp`, HTTP/3 NE SE SERT PAS NON PLUS.**
///
/// La session et l'API se montent avec le port TCP. Les monter une seconde fois
/// pour HTTP/3 donnerait deux clés de scellement — donc des jetons qui ne
/// s'ouvriraient pas d'un côté à l'autre.
#[test]
fn sans_http2_http3_ne_se_sert_pas() {
    let atelier = atelier("h3-orphelin");
    let Some((cert, cle)) = paire(&atelier.0) else {
        eprintln!("SAUTÉ : {SANS_OPENSSL}");
        return;
    };
    let smtp = port_libre();
    let h3 = port_libre();
    let config = configuration_avec_h3(
        &atelier,
        smtp,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        "",
        &format!("127.0.0.1:{h3}"),
        CLEF,
    );
    let serveur = lancer(&config, smtp);
    let journal = attendre_le_journal(&serveur, "API REST EN HTTP/3 NON SERVIE");
    assert!(
        journal.contains("API REST EN HTTP/3 NON SERVIE"),
        "le serveur doit dire pourquoi : {journal}"
    );
    assert!(!ecoute_udp_ouverte(h3), "et ne pas ouvrir le port {h3}");
}

/// **UN UTILISATEUR CHANGE SON PROPRE MOT DE PASSE, DE BOUT EN BOUT.**
///
/// # Ce que cet essai éprouve et qu'aucun autre ne touche
///
/// La chaîne entière, avec un jeton d'UTILISATEUR — pas d'administrateur :
/// l'échange d'identifiants contre un jeton, la route `/v1/me/password` qui
/// n'exige aucune portée, la vérification du mot de passe ACTUEL, l'écriture du
/// magasin, et le fait que le serveur relise ce magasin sans redémarrer.
///
/// Les trois propriétés qui comptent, et aucune ne se déduit des deux autres :
/// le nouveau secret ouvre, l'ancien ferme, et un ancien mot de passe FAUX ne
/// change rien du tout.
#[test]
fn un_utilisateur_change_son_propre_mot_de_passe() {
    let atelier = atelier("mon-secret");
    let Some((cert, cle)) = paire(&atelier.0) else {
        panic!("{SANS_OPENSSL}");
    };
    if std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("IGNORÉ : `curl` est absent — cet essai n'a RIEN éprouvé.");
        return;
    }

    // Un compte ordinaire, avec une adresse : on vérifiera qu'elle survit.
    let empreinte =
        ams_auth::hash_password(b"secret-initial", b"seize octets ici").expect("hachable");
    let magasin = atelier.0.join("comptes.bin");
    std::fs::write(
        &magasin,
        ams_config::encode_accounts(&[ams_auth::Account {
            login: String::from("marie"),
            hash: empreinte,
            addresses: vec![String::from("marie@example.com")],
        }])
        .expect("encodable"),
    )
    .expect("le magasin s'écrit");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&magasin, std::fs::Permissions::from_mode(0o600))
            .expect("permissions du magasin");
    }

    let port_smtp = port_libre();
    let port_http = port_libre();
    let config = configuration_complete(
        &atelier,
        port_smtp,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        &magasin.display().to_string(),
        "",
        "",
        &format!("127.0.0.1:{port_http}"),
        "",
        CLEF,
    );
    let serveur = lancer_avec_api(&config, port_smtp, port_http);

    let base = format!("https://127.0.0.1:{port_http}");

    // Échange des identifiants contre un jeton, et rend (corps, code).
    let ouvrir = |secret: &str| -> (String, String) {
        let sortie = std::process::Command::new("curl")
            .args(["-s", "-S", "--insecure", "--http2"])
            .args(["-H", "Content-Type: application/json"])
            .args([
                "-d",
                &format!(r#"{{"login":"marie","password":"{secret}"}}"#),
            ])
            .args(["-w", "\n%{http_code}"])
            .arg(format!("{base}/v1/tokens"))
            .output()
            .expect("curl s'exécute");
        let tout = reponse_de_curl(&serveur, &sortie);
        let (corps, code) = tout.rsplit_once('\n').unwrap_or(("", ""));
        (corps.to_string(), code.to_string())
    };

    // ── LE JETON D'UN UTILISATEUR, ET NON D'UN ADMINISTRATEUR ───────────────
    let (corps, code) = ouvrir("secret-initial");
    // **201, ET NON 200** : `POST /v1/tokens` CRÉE un jeton, et §15.3.2 de
    // RFC 9110 réserve le 201 à cela.
    assert_eq!(code, "201", "l'échange doit réussir : {corps}");
    let jeton = corps
        .split_once("\"token\":\"")
        .and_then(|(_, reste)| reste.split_once('"'))
        .map(|(jeton, _)| jeton.to_string())
        .unwrap_or_else(|| panic!("un jeton dans {corps}"));

    // Ce jeton-là n'ouvre PAS l'administration : c'est ce qui rend la route
    // « moi » nécessaire, et l'essai le constate plutôt que de le supposer.
    let changer = |jeton: &str, corps_json: &str, chemin: &str| -> String {
        let sortie = std::process::Command::new("curl")
            .args(["-s", "-S", "--insecure", "--http2", "-X", "PUT"])
            .args(["-H", &format!("Authorization: Bearer {jeton}")])
            .args(["-H", "Content-Type: application/json"])
            .args(["-d", corps_json])
            .args(["-o", "/dev/null", "-w", "%{http_code}"])
            .arg(format!("{base}{chemin}"))
            .output()
            .expect("curl s'exécute");
        reponse_de_curl(&serveur, &sortie)
    };
    assert_eq!(
        changer(
            &jeton,
            r#"{"password":"peu-importe"}"#,
            "/v1/accounts/marie/password"
        ),
        "404",
        "la route d'administration reste fermée à un utilisateur"
    );

    // ── UN ANCIEN MOT DE PASSE FAUX NE CHANGE RIEN ──────────────────────────
    assert_eq!(
        changer(
            &jeton,
            r#"{"current_password":"pas-le-bon","password":"tentative"}"#,
            "/v1/me/password"
        ),
        "403",
        "sans le secret actuel, un jeton volé ne doit pas verrouiller le compte"
    );
    assert_eq!(
        ouvrir("secret-initial").1,
        "201",
        "APRÈS LE REFUS, L'ANCIEN SECRET OUVRE TOUJOURS"
    );
    assert_eq!(ouvrir("tentative").1, "401", "et le refusé n'ouvre pas");

    // ── ET AVEC LE BON, IL CHANGE ───────────────────────────────────────────
    assert_eq!(
        changer(
            &jeton,
            r#"{"current_password":"secret-initial","password":"choisi-par-marie"}"#,
            "/v1/me/password"
        ),
        "204",
        "le changement doit réussir"
    );

    // Les trois propriétés. Aucun redémarrage : le serveur relit son magasin.
    assert_eq!(ouvrir("choisi-par-marie").1, "201", "LE NEUF OUVRE");
    assert_eq!(ouvrir("secret-initial").1, "401", "L'ANCIEN NE FERME PLUS");
    let relu = ams_config::decode_accounts(&std::fs::read(&magasin).expect("le magasin se lit"))
        .expect("le magasin se décode");
    assert_eq!(
        relu.first().map(|compte| compte.addresses.clone()),
        Some(vec![String::from("marie@example.com")]),
        "L'ADRESSE DOIT AVOIR SURVÉCU"
    );

    // ── ET LE MARTÈLEMENT SE FAIT BANNIR ────────────────────────────────────
    //
    // **C'EST LA PROPRIÉTÉ QUI COMPTE, ET ELLE NE SE DÉDUIT PAS DU 403.** Un
    // refus poli répété six cents fois par minute est un oracle : le mot de
    // passe vaut plus que le jeton, puisque le second expire et le premier non.
    // Chaque `current_password` faux compte donc comme une trame invalide, et
    // le videur ferme la porte au-delà du seuil.
    let (jeton_neuf, _) = {
        let (corps, code) = ouvrir("choisi-par-marie");
        assert_eq!(code, "201", "{corps}");
        (
            corps
                .split_once("\"token\":\"")
                .and_then(|(_, reste)| reste.split_once('"'))
                .map(|(jeton, _)| jeton.to_string())
                .unwrap_or_else(|| panic!("un jeton dans {corps}")),
            (),
        )
    };
    // ── UN MOT DE PASSE VIDE N'EN EST PAS UN ────────────────────────────────
    //
    // `air-mail-admin` le refuse depuis toujours sur l'entrée standard ; l'API
    // le hachait sans rien dire, et le compte s'ouvrait ensuite avec `""`. Le
    // laxisme était du côté que des PROGRAMMES appellent, la rigueur du côté
    // qu'un humain tape — l'inverse de ce qu'il faut, une faute de frappe au
    // terminal se voyant et un champ vide dans un corps JSON non.
    let (jeton_courant, _) = {
        let (corps, code) = ouvrir("choisi-par-marie");
        assert_eq!(code, "201", "{corps}");
        (
            corps
                .split_once("\"token\":\"")
                .and_then(|(_, reste)| reste.split_once('"'))
                .map(|(jeton, _)| jeton.to_string())
                .unwrap_or_else(|| panic!("un jeton dans {corps}")),
            (),
        )
    };
    assert_eq!(
        changer(
            &jeton_courant,
            r#"{"current_password":"choisi-par-marie","password":""}"#,
            "/v1/me/password"
        ),
        "400",
        "un secret vide se refuse, et AVANT de vérifier l'ancien"
    );
    assert_eq!(
        ouvrir("").1,
        "401",
        "et le compte ne s'ouvre donc pas avec le vide"
    );
    assert_eq!(
        ouvrir("choisi-par-marie").1,
        "201",
        "le secret d'avant tient toujours"
    );

    // ── ICI, UN `curl` QUI ÉCHOUE EST LE RÉSULTAT ATTENDU ───────────────────
    //
    // C'est le SEUL endroit de ce banc où l'échec de `curl` prouve quelque
    // chose : un pair banni ne reçoit RIEN, pas même un refus — le garde ferme
    // la connexion sans un mot, et c'est délibéré (répondre apprendrait à qui
    // frappe qu'il a été vu). `curl` rend alors 35, « unexpected eof while
    // reading », et un code HTTP vide.
    //
    // **CETTE BOUCLE NE PEUT DONC PAS PASSER PAR `changer`**, qui appelle
    // `reponse_de_curl` : celle-ci PANIQUE sur un `curl` en échec, et elle a
    // raison partout ailleurs — c'est tout son objet. Les deux exigences sont
    // contradictoires, et la contradiction a tenu la CI rouge du 2026-10-07 au
    // 2026-10-08 : `reponse_de_curl` est née ce jour-là pour fermer un trou sur
    // trente-cinq sites d'appel, et a cassé le seul où l'échec est le but.
    //
    // On appelle donc `curl` directement, et l'on distingue les deux issues
    // plutôt que de les confondre.
    let essayer_un_faux_secret = |jeton: &str| -> Option<String> {
        let sortie = std::process::Command::new("curl")
            .args(["-s", "-S", "--insecure", "--http2", "-X", "PUT"])
            .args(["-H", &format!("Authorization: Bearer {jeton}")])
            .args(["-H", "Content-Type: application/json"])
            .args(["-d", r#"{"current_password":"encore-faux","password":"x"}"#])
            .args(["-o", "/dev/null", "-w", "%{http_code}"])
            .arg(format!("{base}/v1/me/password"))
            .output()
            .expect("curl s'exécute");
        // `None` : la connexion n'a pas abouti — c'est la signature du ban.
        sortie
            .status
            .success()
            .then(|| String::from_utf8_lossy(&sortie.stdout).trim().to_string())
    };

    let seuil = usize::try_from(Thresholds::DEFAULT.invalid_frames_per_minute)
        .expect("le seuil tient dans un usize");
    let mut banni = false;
    let mut refuses = 0_usize;
    for essai in 0..=seuil.saturating_add(2) {
        match essayer_un_faux_secret(&jeton_neuf) {
            // Le refus applicatif : le serveur parle encore.
            Some(code) if code == "403" => refuses = refuses.saturating_add(1),
            // Il parle, mais autre chose que `403` : ce n'est NI un refus
            // attendu NI un ban. On le dit plutôt que de le compter pour l'un
            // ou pour l'autre.
            Some(code) => panic!(
                "au {essai}e essai, le serveur a rendu `{code}` — on attendait `403` \
                 tant qu'il parle, puis plus rien du tout.\n\
                 --- ce que le SERVEUR a dit ---\n{}",
                serveur.journal()
            ),
            None => {
                banni = true;
                eprintln!("banni après {essai} essais, dont {refuses} refusés par `403`");
                break;
            }
        }
    }
    assert!(
        banni,
        "après {seuil} mots de passe faux, le videur doit fermer la porte"
    );
    // **ET IL DOIT AVOIR PARLÉ AVANT DE SE TAIRE.** Sans ce contrôle, un
    // serveur mort dès le premier essai passerait pour un videur efficace — on
    // conclurait au ban sur une panne, ce qui est exactement l'erreur que
    // `reponse_de_curl` existe pour empêcher ailleurs.
    assert!(
        refuses > 0,
        "le ban doit SUIVRE des refus applicatifs ; aucun `403` n'a été rendu, \
         ce qui ressemble à une panne et non à un bannissement.\n\
         --- ce que le SERVEUR a dit ---\n{}",
        serveur.journal()
    );
}

/// **UN JETON RÉVOQUÉ EST REFUSÉ, ET UN JETON D'ADMINISTRATION NE L'EST PAS.**
///
/// # CE QUE CET ESSAI PROUVE, ET QUE RIEN D'AUTRE NE PROUVAIT
///
/// Un jeton se vérifiait sans rien consulter : sa SEULE fin garantie était son
/// expiration. `DELETE /v1/tokens/current` rendait `501` — il annonçait une
/// révocation qui n'existait pas, ce qui est pire que de ne pas l'annoncer.
///
/// L'essai va jusqu'au bout de la chaîne réelle : un vrai serveur, `curl`, un
/// jeton obtenu par `POST /v1/tokens`. Il vérifie qu'il ouvre, qu'il se ferme,
/// et qu'une fois fermé **il ne rouvre plus** — ce qu'aucune vérification de
/// sceau ne peut dire.
///
/// # ET LE SECOND VOLET EST AUSSI IMPORTANT QUE LE PREMIER
///
/// Le registre a failli refuser TOUS les jetons d'administration, qui ne
/// passent jamais par `POST /v1/tokens` et n'ont donc aucune session ouverte.
/// L'exploitant se serait retrouvé sans son outil sur un serveur en service.
#[test]
fn une_session_fermee_ne_rouvre_plus() {
    // **UN NOM D'ATELIER PAR ESSAI, ET C'EST OBLIGATOIRE** : `atelier` EFFACE le
    // répertoire avant de le créer, et deux essais du même nom tournant en
    // parallèle se détruisent mutuellement leurs fichiers. Le coût de l'oubli
    // est un `503` à l'écriture du magasin de comptes, que rien ne relie à sa
    // cause — vu ici même.
    let atelier = atelier("session-fermee");
    let Some((cert, cle)) = paire(&atelier.0) else {
        panic!("{SANS_OPENSSL}");
    };
    if std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("IGNORÉ : `curl` est absent — cet essai n'a RIEN éprouvé.");
        return;
    }

    let empreinte =
        ams_auth::hash_password(b"secret-initial", b"seize octets ici").expect("hachable");
    let magasin = atelier.0.join("comptes.bin");
    std::fs::write(
        &magasin,
        ams_config::encode_accounts(&[ams_auth::Account {
            login: String::from("marie"),
            hash: empreinte,
            addresses: vec![String::from("marie@example.com")],
        }])
        .expect("encodable"),
    )
    .expect("le magasin s'écrit");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&magasin, std::fs::Permissions::from_mode(0o600))
            .expect("permissions du magasin");
    }

    let port_smtp = port_libre();
    let port_http = port_libre();
    let config = configuration_complete(
        &atelier,
        port_smtp,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        &magasin.display().to_string(),
        "",
        "",
        &format!("127.0.0.1:{port_http}"),
        "",
        CLEF,
    );
    let serveur = lancer_avec_api(&config, port_smtp, port_http);
    let base = format!("https://127.0.0.1:{port_http}");

    // Un appel quelconque avec ce jeton, et le code qu'il rend.
    let code_de = |jeton: &str, chemin: &str| -> String {
        let sortie = std::process::Command::new("curl")
            .args(["-s", "-S", "--insecure", "--http2"])
            .args(["-H", &format!("Authorization: Bearer {jeton}")])
            .args(["-o", "/dev/null", "-w", "%{http_code}"])
            .arg(format!("{base}{chemin}"))
            .output()
            .expect("curl s'exécute");
        reponse_de_curl(&serveur, &sortie)
    };

    // ── 1. UN JETON D'UTILISATEUR, OBTENU PAR LA PORTE ORDINAIRE ────────────
    let sortie = std::process::Command::new("curl")
        .args(["-s", "-S", "--insecure", "--http2"])
        .args(["-H", "Content-Type: application/json"])
        .args(["-d", r#"{"login":"marie","password":"secret-initial"}"#])
        .arg(format!("{base}/v1/tokens"))
        .output()
        .expect("curl s'exécute");
    let corps = reponse_de_curl(&serveur, &sortie);
    let jeton = corps
        .split_once("\"token\":\"")
        .and_then(|(_, reste)| reste.split_once('"'))
        .map(|(jeton, _)| jeton.to_string())
        .unwrap_or_else(|| panic!("un jeton dans {corps}"));

    // Il ouvre.
    assert_eq!(
        code_de(&jeton, "/v1/mailboxes"),
        "200",
        "un jeton frais doit ouvrir"
    );

    // ── 2. ON LE RÉVOQUE ────────────────────────────────────────────────────
    let sortie = std::process::Command::new("curl")
        .args(["-s", "-S", "--insecure", "--http2", "-X", "DELETE"])
        .args(["-H", &format!("Authorization: Bearer {jeton}")])
        .args(["-o", "/dev/null", "-w", "%{http_code}"])
        .arg(format!("{base}/v1/tokens/current"))
        .output()
        .expect("curl s'exécute");
    assert_eq!(
        String::from_utf8_lossy(&sortie.stdout),
        "204",
        "fermer sa session doit réussir — et ne plus rendre 501"
    );

    // ── 3. ET IL NE ROUVRE PLUS ─────────────────────────────────────────────
    //
    // **C'EST TOUT L'OBJET DE LA TRANCHE.** Le sceau est toujours bon et
    // l'heure n'est pas passée : seul le registre peut refuser ce jeton-là.
    assert_eq!(
        code_de(&jeton, "/v1/mailboxes"),
        "401",
        "un jeton dont la session est fermée ne doit plus rien ouvrir"
    );

    // Et le refermer dit qu'il n'y avait plus rien à fermer.
    let sortie = std::process::Command::new("curl")
        .args(["-s", "-S", "--insecure", "--http2", "-X", "DELETE"])
        .args(["-H", &format!("Authorization: Bearer {jeton}")])
        .args(["-o", "/dev/null", "-w", "%{http_code}"])
        .arg(format!("{base}/v1/tokens/current"))
        .output()
        .expect("curl s'exécute");
    assert_eq!(
        String::from_utf8_lossy(&sortie.stdout),
        "401",
        "la session étant close, même la fermer n'est plus possible"
    );

    // ── 4. LE JETON D'ADMINISTRATION, LUI, N'A JAMAIS EU DE SESSION ─────────
    //
    // Il est frappé hors bande par `air-mail-admin token`. Exiger qu'il ait une
    // session ouverte retirerait à l'exploitant l'outil qu'on lui a donné.
    let administrateur = jeton_d_administration();
    assert_eq!(
        code_de(&administrateur, "/v1/accounts"),
        "200",
        "un jeton d'administration ne dépend d'aucune session"
    );
}

/// **LA VOIE DE SECOURS : L'EXPLOITANT RÉVOQUE, PUIS RÉINVITE** (0.2.41).
///
/// # CE QUE CET ESSAI ÉPROUVE
///
/// Un utilisateur a perdu son seul téléphone. Il ne peut pas en approuver un
/// autre, et une invitation ne vaut que pour un compte sans appareil. Avant
/// cette version, le réinviter demandait de supprimer son compte.
///
/// L'administration voit ses appareils, les révoque TOUS — les sessions du
/// téléphone perdu cessent de valoir sur-le-champ —, et une invitation neuve
/// enrôle de nouveau. Et un appareil retiré du magasin HORS de l'API — ce que
/// fait `air-mail-admin device revoke` — perd lui aussi ses sessions à la
/// requête suivante.
#[test]
fn l_exploitant_revoque_tout_puis_reinvite() {
    let atelier = atelier("voie-de-secours");
    let Some((cert, cle)) = paire(&atelier.0) else {
        panic!("{SANS_OPENSSL}");
    };
    if std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("IGNORÉ : `curl` est absent — cet essai n'a RIEN éprouvé.");
        return;
    }
    let empreinte =
        ams_auth::hash_password(b"secret-initial", b"seize octets ici").expect("hachable");
    let magasin = atelier.0.join("comptes.bin");
    std::fs::write(
        &magasin,
        ams_config::encode_accounts(&[ams_auth::Account {
            login: String::from("marie"),
            hash: empreinte,
            addresses: vec![String::from("marie@example.com")],
        }])
        .expect("encodable"),
    )
    .expect("le magasin s'écrit");
    std::fs::set_permissions(&magasin, std::fs::Permissions::from_mode(0o600))
        .expect("permissions du magasin");
    let appareils = atelier.0.join("appareils.bin");
    let port_smtp = port_libre();
    let port_http = port_libre();
    let config = configuration_complete(
        &atelier,
        port_smtp,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        &magasin.display().to_string(),
        &appareils.display().to_string(),
        "",
        &format!("127.0.0.1:{port_http}"),
        "",
        CLEF,
    );
    let serveur = lancer_avec_api(&config, port_smtp, port_http);
    let base = format!("https://127.0.0.1:{port_http}");
    let admin = jeton_d_administration();

    let appeler = |verbe: &str, chemin: &str, corps: Option<&str>, jeton: Option<&str>| {
        let mut commande = std::process::Command::new("curl");
        commande
            .args(["-s", "-S", "--insecure", "--http2", "-X", verbe])
            .args(["-w", "\n%{http_code}"]);
        if let Some(corps) = corps {
            commande
                .args(["-H", "Content-Type: application/json"])
                .args(["-d", corps]);
        }
        if let Some(jeton) = jeton {
            commande.args(["-H", &format!("Authorization: Bearer {jeton}")]);
        }
        let sortie = commande
            .arg(format!("{base}{chemin}"))
            .output()
            .expect("curl s'exécute");
        let tout = reponse_de_curl(&serveur, &sortie);
        let (corps, code) = tout.rsplit_once('\n').unwrap_or(("", ""));
        (corps.to_string(), code.to_string())
    };
    let champ = |corps: &str, nom: &str| -> String {
        corps
            .split_once(&format!("\"{nom}\":\""))
            .and_then(|(_, reste)| reste.split_once('"'))
            .map(|(valeur, _)| valeur.to_string())
            .unwrap_or_else(|| panic!("`{nom}` dans {corps}"))
    };
    // Invite, enrôle cette clef, et ouvre une session par elle.
    let enroler_et_ouvrir =
        |privee: &p256::ecdsa::SigningKey, publique: &[u8; 65]| -> (String, String) {
            let (corps, code) = appeler(
                "POST",
                "/v1/invitations",
                Some(r#"{"login":"marie"}"#),
                Some(&admin),
            );
            assert_eq!(code, "201", "{corps}");
            let invitation = champ(&corps, "invitation");
            let (corps, code) = appeler(
                "POST",
                "/v1/devices",
                Some(&format!(
                    r#"{{"invitation":"{invitation}","publicKey":"{}"}}"#,
                    en_base64url(publique)
                )),
                None,
            );
            assert_eq!(code, "201", "{corps}");
            let appareil = champ(&corps, "id");
            let (corps, code) = appeler(
                "POST",
                "/v1/sessions/challenge",
                Some(&format!(r#"{{"login":"marie","deviceId":"{appareil}"}}"#)),
                None,
            );
            assert_eq!(code, "201", "{corps}");
            let defi = champ(&corps, "challenge");
            let condensat = condensat_a_signer(
                &champ(&corps, "role"),
                &champ(&corps, "serverIdentity"),
                &defi,
            );
            let (corps, code) = appeler(
                "POST",
                "/v1/sessions",
                Some(&format!(
                    r#"{{"challenge":"{defi}","signature":"{}"}}"#,
                    signer_avec(privee, &condensat)
                )),
                None,
            );
            assert_eq!(code, "201", "{corps}");
            (appareil, champ(&corps, "token"))
        };

    // ── LE TÉLÉPHONE, PUIS SA PERTE ─────────────────────────────────────────
    let (telephone, jeton) = enroler_et_ouvrir(&cle_privee(), &cle_publique());
    assert_eq!(appeler("GET", "/v1/mailboxes", None, Some(&jeton)).1, "200");
    // Une seconde invitation ne sert à rien tant qu'il reste un appareil.
    let (corps, code) = appeler(
        "POST",
        "/v1/invitations",
        Some(r#"{"login":"marie"}"#),
        Some(&admin),
    );
    assert_eq!(code, "201");
    let (_, code) = appeler(
        "POST",
        "/v1/devices",
        Some(&format!(
            r#"{{"invitation":"{}","publicKey":"{}"}}"#,
            champ(&corps, "invitation"),
            en_base64url(&cle_publique_de(9))
        )),
        None,
    );
    assert_eq!(code, "409");

    // ── L'ADMINISTRATION VOIT, PUIS RÉVOQUE TOUT ────────────────────────────
    let (liste, code) = appeler("GET", "/v1/accounts/marie/devices", None, Some(&admin));
    assert_eq!(code, "200", "{liste}");
    assert!(liste.contains(&telephone), "{liste}");
    // Un jeton d'utilisateur n'y a pas accès.
    assert_eq!(
        appeler("GET", "/v1/accounts/marie/devices", None, Some(&jeton)).1,
        "404"
    );
    assert_eq!(
        appeler("DELETE", "/v1/accounts/marie/devices", None, Some(&admin)).1,
        "204"
    );
    // Le jeton du téléphone perdu ne vaut plus, sur-le-champ.
    assert_eq!(appeler("GET", "/v1/mailboxes", None, Some(&jeton)).1, "401");
    // Révoquer tout sur un compte qui n'a rien est déjà l'état demandé.
    assert_eq!(
        appeler("DELETE", "/v1/accounts/marie/devices", None, Some(&admin)).1,
        "204"
    );

    // ── UNE INVITATION NEUVE ENRÔLE DE NOUVEAU ──────────────────────────────
    let (nouveau, jeton) = enroler_et_ouvrir(&cle_privee_de(9), &cle_publique_de(9));
    assert_eq!(appeler("GET", "/v1/mailboxes", None, Some(&jeton)).1, "200");
    // Un appareil nommé se révoque aussi seul ; un inconnu, non.
    assert_eq!(
        appeler(
            "DELETE",
            "/v1/accounts/marie/devices/inconnu",
            None,
            Some(&admin)
        )
        .1,
        "404"
    );

    // ── RETIRÉ DU MAGASIN HORS DE L'API, IL PERD SES SESSIONS AUSSI ─────────
    //
    // C'est ce que fait `air-mail-admin device revoke` : il écrit le fichier.
    let restants: Vec<ams_config::Device> =
        ams_config::decode_devices(&std::fs::read(&appareils).expect("le magasin existe"))
            .expect("lisible")
            .into_iter()
            .filter(|appareil| appareil.id != nouveau)
            .collect();
    std::fs::write(
        &appareils,
        ams_config::encode_devices(&restants).expect("encodable"),
    )
    .expect("écriture");
    let mut ferme = false;
    for _ in 0..50 {
        if appeler("GET", "/v1/mailboxes", None, Some(&jeton)).1 == "401" {
            ferme = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(ferme, "un appareil retiré du magasin garde ses sessions");
}

/// Un constructeur DER, pour fabriquer une chaîne d'attestation PENDANT
/// l'essai : son défi dépend de l'invitation, qui n'existe qu'une fois le
/// serveur lancé.
mod attestation_d_essai {
    use p256::ecdsa::signature::Signer as _;
    use sha2::Digest as _;

    pub(super) fn tlv(etiquette: &[u8], contenu: &[u8]) -> Vec<u8> {
        let mut sortie = etiquette.to_vec();
        let n = contenu.len();
        if n < 0x80 {
            sortie.push(u8::try_from(n).expect("court"));
        } else if n < 0x100 {
            sortie.extend_from_slice(&[0x81, u8::try_from(n).expect("court")]);
        } else {
            let deux = u16::try_from(n).expect("court").to_be_bytes();
            sortie.extend_from_slice(&[0x82, deux[0], deux[1]]);
        }
        sortie.extend_from_slice(contenu);
        sortie
    }

    fn seq(parts: &[&[u8]]) -> Vec<u8> {
        tlv(&[0x30], &parts.concat())
    }

    fn octets(contenu: &[u8]) -> Vec<u8> {
        tlv(&[0x04], contenu)
    }

    fn oid(contenu: &[u8]) -> Vec<u8> {
        tlv(&[0x06], contenu)
    }

    fn bits(contenu: &[u8]) -> Vec<u8> {
        tlv(&[0x03], &[&[0_u8][..], contenu].concat())
    }

    /// Un entier positif, sous sa forme DER minimale.
    fn entier(grand_boutien: &[u8]) -> Vec<u8> {
        let debut = grand_boutien
            .iter()
            .position(|octet| *octet != 0)
            .unwrap_or(grand_boutien.len().saturating_sub(1));
        let mut chiffres = grand_boutien[debut..].to_vec();
        if chiffres[0] & 0x80 != 0 {
            chiffres.insert(0, 0);
        }
        tlv(&[0x02], &chiffres)
    }

    /// Un élément de contexte construit ; forme haute au-delà de 30.
    fn contexte(numero: u32, contenu: &[u8]) -> Vec<u8> {
        if numero < 31 {
            return tlv(&[0xA0 | u8::try_from(numero).expect("petit")], contenu);
        }
        let mut groupes = Vec::new();
        let mut reste = numero;
        loop {
            groupes.insert(0, u8::try_from(reste & 0x7F).expect("sept bits"));
            reste >>= 7;
            if reste == 0 {
                break;
            }
        }
        let dernier = groupes.len().saturating_sub(1);
        for groupe in &mut groupes[..dernier] {
            *groupe |= 0x80;
        }
        tlv(&[&[0xBF][..], &groupes].concat(), contenu)
    }

    /// La `SubjectPublicKeyInfo` d'une clef P-256.
    pub(super) fn spki(cle: &p256::ecdsa::SigningKey) -> Vec<u8> {
        let point = cle.verifying_key().to_sec1_point(false);
        seq(&[
            &seq(&[
                &oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]),
                &oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]),
            ]),
            &bits(point.as_bytes()),
        ])
    }

    /// Un certificat : `sujet` signé par `emetteur`, avec ces extensions.
    fn certificat(
        serie: u8,
        sujet: &p256::ecdsa::SigningKey,
        emetteur: &p256::ecdsa::SigningKey,
        extensions: &[&[u8]],
    ) -> Vec<u8> {
        let ecdsa_sha256 = seq(&[&oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02])]);
        let nom = seq(&[]);
        let validite = seq(&[
            &tlv(&[0x17], b"250101000000Z"),
            &tlv(&[0x18], b"20350101000000Z"),
        ]);
        let mut champs: Vec<Vec<u8>> = vec![
            contexte(0, &entier(&[2])),
            entier(&[serie]),
            ecdsa_sha256.clone(),
            nom.clone(),
            validite,
            nom,
            spki(sujet),
        ];
        if !extensions.is_empty() {
            champs.push(contexte(3, &seq(extensions)));
        }
        let refs: Vec<&[u8]> = champs.iter().map(Vec::as_slice).collect();
        let tbs = seq(&refs);
        let signature: p256::ecdsa::Signature = emetteur.sign(&tbs);
        let (r, s_) = signature.split_bytes();
        let valeur = seq(&[&entier(&r), &entier(&s_)]);
        seq(&[&tbs, &ecdsa_sha256, &bits(&valeur)])
    }

    /// L'empreinte du certificat qui signe l'application d'essai.
    pub(super) fn empreinte() -> [u8; 32] {
        sha2::Sha256::digest(b"certificat air-desktop.org d'essai").into()
    }

    /// Une chaîne feuille ‖ intermédiaire ‖ racine, dont la feuille atteste la
    /// clef `appareil`, sous le défi SHA-256(`invitation`).
    pub(super) fn chaine(
        appareil: &p256::ecdsa::SigningKey,
        racine: &p256::ecdsa::SigningKey,
        invitation: &str,
    ) -> Vec<u8> {
        let intermediaire =
            p256::ecdsa::SigningKey::from_slice(&[22_u8; 32]).expect("une clef valide");
        let defi = sha2::Sha256::digest(invitation.as_bytes());
        let application = seq(&[
            &tlv(
                &[0x31],
                &seq(&[&octets(b"org.airdesktop.mail"), &entier(&[1])]),
            ),
            &tlv(&[0x31], &octets(&empreinte())),
        ]);
        let description = seq(&[
            &entier(&[200]),
            &tlv(&[0x0A], &[1]),
            &entier(&[200]),
            &tlv(&[0x0A], &[1]),
            &octets(&defi),
            &octets(b""),
            &seq(&[&contexte(709, &octets(&application))]),
            &seq(&[
                &contexte(702, &entier(&[0])),
                &contexte(
                    704,
                    &seq(&[
                        &octets(&[0; 32]),
                        &tlv(&[0x01], &[0xFF]),
                        &tlv(&[0x0A], &[0]),
                        &octets(&[0; 32]),
                    ]),
                ),
            ]),
        ]);
        let extension = seq(&[
            &oid(&[0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x01, 0x11]),
            &octets(&description),
        ]);
        // Des numéros de série distincts : la liste de révocation en nomme un.
        [
            certificat(1, appareil, &intermediaire, &[&extension]),
            certificat(0x2a, &intermediaire, racine, &[]),
            certificat(3, racine, racine, &[]),
        ]
        .concat()
    }

    /// L'identifiant de l'application iOS d'essai.
    pub(super) const APPLICATION_APPLE: &str = "TEAM123456.org.airdesktop.mail";

    fn cbor(majeur: u8, n: usize) -> Vec<u8> {
        let majeur = majeur << 5;
        match u16::try_from(n) {
            Ok(petit @ 0..=23) => vec![majeur | u8::try_from(petit).expect("petit")],
            Ok(octet @ 24..=255) => vec![majeur | 24, u8::try_from(octet).expect("un octet")],
            Ok(deux) => [&[majeur | 25][..], &deux.to_be_bytes()].concat(),
            Err(_) => panic!("trop long pour l'essai"),
        }
    }

    fn cbor_octets(contenu: &[u8]) -> Vec<u8> {
        [cbor(2, contenu.len()), contenu.to_vec()].concat()
    }

    fn cbor_texte(texte: &str) -> Vec<u8> {
        [cbor(3, texte.len()), texte.as_bytes().to_vec()].concat()
    }

    /// Un objet App Attest : la clef d'App Attest — qui n'est PAS la clef
    /// d'appareil — attestée sous `racine`, pour le `clientDataHash` que
    /// l'application iOS tire de l'invitation ET de la clef d'appareil.
    pub(super) fn app_attest(
        appareil: &p256::ecdsa::SigningKey,
        racine: &p256::ecdsa::SigningKey,
        invitation: &str,
    ) -> Vec<u8> {
        let cle_app_attest =
            p256::ecdsa::SigningKey::from_slice(&[23_u8; 32]).expect("une clef valide");
        let intermediaire =
            p256::ecdsa::SigningKey::from_slice(&[24_u8; 32]).expect("une clef valide");
        let point_appareil = appareil.verifying_key().to_sec1_point(false);
        let donnees_client = sha2::Sha256::new()
            .chain_update(invitation.as_bytes())
            .chain_update([0])
            .chain_update(point_appareil.as_bytes())
            .finalize();
        let point = cle_app_attest.verifying_key().to_sec1_point(false);
        let identifiant = sha2::Sha256::digest(point.as_bytes());
        let longueur = u16::try_from(identifiant.len())
            .expect("court")
            .to_be_bytes();
        let auth_data = [
            &sha2::Sha256::digest(APPLICATION_APPLE.as_bytes())[..],
            &[0x40],
            &[0; 4],
            b"appattest\0\0\0\0\0\0\0",
            &longueur,
            &identifiant,
        ]
        .concat();
        let nonce = sha2::Sha256::new()
            .chain_update(&auth_data)
            .chain_update(donnees_client)
            .finalize();
        let extension = seq(&[
            &oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x63, 0x64, 0x08, 0x02]),
            &octets(&seq(&[&contexte(1, &octets(&nonce))])),
        ]);
        [
            cbor(5, 3),
            cbor_texte("fmt"),
            cbor_texte("apple-appattest"),
            cbor_texte("attStmt"),
            cbor(5, 2),
            cbor_texte("x5c"),
            cbor(4, 2),
            cbor_octets(&certificat(
                1,
                &cle_app_attest,
                &intermediaire,
                &[&extension],
            )),
            cbor_octets(&certificat(2, &intermediaire, racine, &[])),
            cbor_texte("receipt"),
            cbor_octets(b"recu"),
            cbor_texte("authData"),
            cbor_octets(&auth_data),
        ]
        .concat()
    }
}

/// La plateforme dont un essai d'attestation éprouve le câblage.
enum Plateforme {
    /// Android en `require`, sous cette liste de révocation ; `admise` dit si
    /// la bonne attestation doit enrôler.
    Android { liste: &'static [u8], admise: bool },
    /// App Attest en `require`, Android éteint.
    Apple,
}

/// **UNE CLEF ANDROID PROUVE OÙ ELLE VIT, ET POUR QUELLE INVITATION** (0.2.39).
///
/// # CE QUE CET ESSAI ÉPROUVE
///
/// Que l'attestation est câblée de bout en bout, en mode `require` : une
/// chaîne dont le défi est le SHA-256 de l'invitation, sous une racine admise,
/// enrôle l'appareil — et le magasin retient que sa clef vit dans le TEE. Sans
/// attestation, ou avec une attestation fabriquée pour une AUTRE invitation,
/// l'enrôlement se refuse en `422`, sans consommer l'invitation.
#[test]
fn une_attestation_android_se_verifie_a_l_enrolement() {
    enroler_sous_attestation(
        "attestation-android",
        &Plateforme::Android {
            liste: br#"{"entries":{"ff":{"status":"REVOKED"}}}"#,
            admise: true,
        },
    );
}

/// **UNE CLEF iOS PROUVE, PAR APP ATTEST, QU'ELLE EST CELLE DE NOTRE
/// APPLICATION** (0.2.43).
///
/// # CE QUE CET ESSAI ÉPROUVE
///
/// Le même câblage qu'Android, sous App Attest en `require` : un objet dont le
/// `clientDataHash` lie l'invitation ET la clef d'appareil enrôle — et le
/// magasin le retient. Sans attestation, pour une autre invitation, ou une
/// chaîne Android alors qu'Android n'est pas jugé : `422`.
#[test]
fn une_attestation_app_attest_se_verifie_a_l_enrolement() {
    enroler_sous_attestation("attestation-apple", &Plateforme::Apple);
}

/// **UNE CLEF D'USINE RÉVOQUÉE PAR GOOGLE N'ENRÔLE RIEN** (0.2.40) : la même
/// attestation, en règle en tout point, sous une liste qui révoque son
/// intermédiaire — `422`.
#[test]
fn une_attestation_revoquee_n_enrole_rien() {
    enroler_sous_attestation(
        "attestation-revoquee",
        &Plateforme::Android {
            liste: br#"{"entries":{"2a":{"status":"SUSPENDED","reason":"KEY_COMPROMISE"}}}"#,
            admise: false,
        },
    );
}

/// Le banc des essais d'attestation : un serveur qui exige celle de cette
/// plateforme.
fn enroler_sous_attestation(nom: &str, plateforme: &Plateforme) {
    let atelier = atelier(nom);
    let Some((cert, cle)) = paire(&atelier.0) else {
        panic!("{SANS_OPENSSL}");
    };
    if std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("IGNORÉ : `curl` est absent — cet essai n'a RIEN éprouvé.");
        return;
    }
    let empreinte =
        ams_auth::hash_password(b"secret-initial", b"seize octets ici").expect("hachable");
    let magasin = atelier.0.join("comptes.bin");
    std::fs::write(
        &magasin,
        ams_config::encode_accounts(&[ams_auth::Account {
            login: String::from("marie"),
            hash: empreinte,
            addresses: vec![String::from("marie@example.com")],
        }])
        .expect("encodable"),
    )
    .expect("le magasin s'écrit");
    std::fs::set_permissions(&magasin, std::fs::Permissions::from_mode(0o600))
        .expect("permissions du magasin");
    let appareils = atelier.0.join("appareils.bin");

    // LA RACINE D'ESSAI, en PEM de clef publique, admise en plus de Google.
    let racine = p256::ecdsa::SigningKey::from_slice(&[21_u8; 32]).expect("une clef valide");
    let standard: String = en_base64url(&attestation_d_essai::spki(&racine))
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            autre => autre,
        })
        .collect();
    let rembourre = format!(
        "{standard}{}",
        "=".repeat(4_usize.saturating_sub(standard.len() % 4) % 4)
    );
    let racines = atelier.0.join("racines.pem");
    std::fs::write(
        &racines,
        format!("-----BEGIN PUBLIC KEY-----\n{rembourre}\n-----END PUBLIC KEY-----\n"),
    )
    .expect("le fichier de racines s'écrit");

    let port_smtp = port_libre();
    let port_http = port_libre();
    let config = configuration_complete(
        &atelier,
        port_smtp,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        &magasin.display().to_string(),
        &appareils.display().to_string(),
        "",
        &format!("127.0.0.1:{port_http}"),
        "",
        CLEF,
    );
    let mut lue =
        ams_config::decode(&std::fs::read(&config).expect("relisible")).expect("décodable");
    // Les racines en plus valent pour les deux plateformes.
    lue.android_roots = racines.display().to_string();
    let admise = match plateforme {
        Plateforme::Android { liste, admise } => {
            lue.android_attestation = ams_config::AttestationMode::Require;
            lue.android_package = String::from("org.airdesktop.mail");
            lue.android_signers = vec![attestation_d_essai::empreinte()];
            // LA LISTE DE RÉVOCATION, locale : sans elle, rien ne passerait.
            // Celle de l'essai de révocation nomme l'intermédiaire, sous le
            // numéro 0x2a.
            let chemin = atelier.0.join("revocation.json");
            std::fs::write(&chemin, liste).expect("la liste s'écrit");
            lue.android_revocation = chemin.display().to_string();
            *admise
        }
        Plateforme::Apple => {
            lue.apple_attestation = ams_config::AttestationMode::Require;
            lue.apple_app_id = String::from(attestation_d_essai::APPLICATION_APPLE);
            true
        }
    };
    let fabriquer = |invitation: &str| -> Vec<u8> {
        match plateforme {
            Plateforme::Android { .. } => {
                attestation_d_essai::chaine(&cle_privee(), &racine, invitation)
            }
            Plateforme::Apple => {
                attestation_d_essai::app_attest(&cle_privee(), &racine, invitation)
            }
        }
    };
    std::fs::write(&config, ams_config::encode(&lue).expect("encodable")).expect("écriture");
    let serveur = lancer_avec_api(&config, port_smtp, port_http);
    let base = format!("https://127.0.0.1:{port_http}");

    let admin = jeton_d_administration();
    let poster = |chemin: &str, corps: &str, entete: Option<&str>| -> (String, String) {
        let mut commande = std::process::Command::new("curl");
        commande
            .args(["-s", "-S", "--insecure", "--http2", "-X", "POST"])
            .args(["-H", "Content-Type: application/json"])
            .args(["-d", corps])
            .args(["-w", "\n%{http_code}"]);
        if let Some(valeur) = entete {
            commande.args(["-H", valeur]);
        }
        let sortie = commande
            .arg(format!("{base}{chemin}"))
            .output()
            .expect("curl s'exécute");
        let tout = reponse_de_curl(&serveur, &sortie);
        let (corps, code) = tout.rsplit_once('\n').unwrap_or(("", ""));
        (corps.to_string(), code.to_string())
    };
    let inviter = || -> String {
        let (corps, code) = poster(
            "/v1/invitations",
            r#"{"login":"marie"}"#,
            Some(&format!("Authorization: Bearer {admin}")),
        );
        assert_eq!(code, "201", "{corps}");
        corps
            .split_once("\"invitation\":\"")
            .and_then(|(_, reste)| reste.split_once('"'))
            .map(|(texte, _)| texte.to_string())
            .unwrap_or_else(|| panic!("une invitation dans {corps}"))
    };
    let clef = en_base64url(&cle_publique());
    let invitation = inviter();

    // ── SANS ATTESTATION, `require` REFUSE ──────────────────────────────────
    let (corps, code) = poster(
        "/v1/devices",
        &format!(r#"{{"invitation":"{invitation}","publicKey":"{clef}"}}"#),
        None,
    );
    assert_eq!(code, "422", "{corps}");
    assert!(corps.contains("/problems/attestation-refused"), "{corps}");

    // ── UNE ATTESTATION FAITE POUR UNE AUTRE INVITATION NE VAUT PAS ─────────
    let autre = fabriquer("une autre invitation");
    let (corps, code) = poster(
        "/v1/devices",
        &format!(
            r#"{{"invitation":"{invitation}","publicKey":"{clef}","attestation":"{}"}}"#,
            en_base64url(&autre)
        ),
        None,
    );
    assert_eq!(code, "422", "{corps}");

    // ── LA BONNE ENRÔLE, ET LE MAGASIN SAIT OÙ VIT LA CLEF ──────────────────
    //
    // La même invitation : les deux refus ne l'ont pas consommée.
    // ── UNE PLATEFORME QUE LE SERVEUR NE JUGE PAS NE PROUVE RIEN ────────────
    if matches!(plateforme, Plateforme::Apple) {
        let android = attestation_d_essai::chaine(&cle_privee(), &racine, &invitation);
        let (corps, code) = poster(
            "/v1/devices",
            &format!(
                r#"{{"invitation":"{invitation}","publicKey":"{clef}","attestation":"{}"}}"#,
                en_base64url(&android)
            ),
            None,
        );
        assert_eq!(code, "422", "{corps}");
    }
    let bonne = fabriquer(&invitation);
    let (corps, code) = poster(
        "/v1/devices",
        &format!(
            r#"{{"invitation":"{invitation}","publicKey":"{clef}","name":"Pixel","attestation":"{}"}}"#,
            en_base64url(&bonne)
        ),
        None,
    );
    if !admise {
        assert_eq!(code, "422", "une clef révoquée a enrôlé : {corps}");
        assert!(corps.contains("/problems/attestation-refused"), "{corps}");
        assert!(!appareils.exists(), "rien ne s'est écrit");
        return;
    }
    assert_eq!(code, "201", "{corps}");
    let ranges = ams_config::decode_devices(&std::fs::read(&appareils).expect("le magasin existe"))
        .expect("lisible");
    assert_eq!(ranges.len(), 1);
    assert_eq!(
        ranges[0].attestation,
        Some(match plateforme {
            Plateforme::Android { .. } => ams_config::Attested::Tee,
            Plateforme::Apple => ams_config::Attested::AppAttest,
        })
    );
}

/// **LE JOURNAL D'AUDIT DIT QUI S'EST CONNECTÉ, QUI A ÉCHOUÉ, ET D'OÙ** (phase 6).
///
/// # CE QUE CET ESSAI ÉPROUVE
///
/// Que tout est câblé derrière de vraies requêtes : une session ouverte et un
/// mot de passe faux s'écrivent au journal du compte, avec l'adresse du pair ;
/// le titulaire les lit par `/v1/me/audit`, l'administration par
/// `/v1/accounts/{compte}/audit` ; et **un compte qui n'existe pas n'écrit
/// rien** — pas même un fichier à son nom.
#[test]
fn le_journal_d_audit_dit_les_sessions_et_les_refus() {
    let atelier = atelier("journal-d-audit");
    let Some((cert, cle)) = paire(&atelier.0) else {
        panic!("{SANS_OPENSSL}");
    };
    if std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("IGNORÉ : `curl` est absent — cet essai n'a RIEN éprouvé.");
        return;
    }

    let empreinte =
        ams_auth::hash_password(b"secret-initial", b"seize octets ici").expect("hachable");
    let magasin = atelier.0.join("comptes.bin");
    std::fs::write(
        &magasin,
        ams_config::encode_accounts(&[ams_auth::Account {
            login: String::from("marie"),
            hash: empreinte,
            addresses: vec![String::from("marie@example.com")],
        }])
        .expect("encodable"),
    )
    .expect("le magasin s'écrit");
    std::fs::set_permissions(&magasin, std::fs::Permissions::from_mode(0o600))
        .expect("permissions du magasin");

    let port_smtp = port_libre();
    let port_http = port_libre();
    let config = configuration_complete(
        &atelier,
        port_smtp,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        &magasin.display().to_string(),
        "",
        "",
        &format!("127.0.0.1:{port_http}"),
        "",
        CLEF,
    );
    let repertoire = atelier.0.join("audit");
    let mut lue =
        ams_config::decode(&std::fs::read(&config).expect("relisible")).expect("décodable");
    lue.audit = repertoire.display().to_string();
    std::fs::write(&config, ams_config::encode(&lue).expect("encodable")).expect("écriture");
    let serveur = lancer(&config, port_smtp);
    // **`lancer` N'ATTEND QUE SMTP, ET L'API S'OUVRE APRÈS.** C'est ce qui
    // rendait cet essai instable, environ une fois sur vingt passes de la suite
    // complète : la première requête partait avant que le port de l'API ne soit
    // lié, `curl` ne joignait personne, et le refus n'avait donc JAMAIS LIEU.
    // Le journal lu ensuite portait `session.opened` — la troisième requête,
    // elle, arrivait à temps — et pas `auth.refused`.
    //
    // L'entrée n'était ni en retard ni perdue : elle n'était pas produite. D'où
    // l'inutilité d'allonger l'attente, essayée en 0.2.47, et celle d'accélérer
    // le fil d'audit, essayée en 0.2.49.
    attendre_le_journal(&serveur, &format!("API REST sur 127.0.0.1:{port_http}"));
    let base = format!("https://127.0.0.1:{port_http}");

    let presenter = |login: &str, secret: &str| -> String {
        let sortie = std::process::Command::new("curl")
            .args(["-s", "-S", "--insecure", "--http2"])
            .args(["-H", "Content-Type: application/json"])
            .args([
                "-d",
                &format!(r#"{{"login":"{login}","password":"{secret}"}}"#),
            ])
            .arg(format!("{base}/v1/tokens"))
            .output()
            .expect("curl s'exécute");
        let rendu = reponse_de_curl(&serveur, &sortie);
        // **UNE RÉPONSE VIDE N'EST PAS UN REFUS**, et c'est l'autre moitié du
        // défaut : `assert!(!rendu.contains("token"))` passait pour un `curl`
        // qui n'avait joint personne. L'essai se croyait donc au vert sur une
        // requête qui n'avait pas eu lieu.
        assert!(
            !rendu.is_empty(),
            "`curl` n'a rien rendu pour `{login}` — le serveur a-t-il répondu ? {}",
            serveur.journal()
        );
        rendu
    };
    let lire = |jeton: &str, chemin: &str, verbe: &str| -> String {
        let sortie = std::process::Command::new("curl")
            .args(["-s", "-S", "--insecure", "--http2", "-i", "-X", verbe])
            .args(["-H", &format!("Authorization: Bearer {jeton}")])
            .arg(format!("{base}{chemin}"))
            .output()
            .expect("curl s'exécute");
        reponse_de_curl(&serveur, &sortie)
    };

    // ── 1. UN REFUS, PUIS UNE SESSION ───────────────────────────────────────
    assert!(!presenter("marie", "faux").contains("token"));
    // Un compte inconnu, refusé lui aussi : il ne doit RIEN écrire.
    assert!(!presenter("fantome", "faux").contains("token"));
    let corps = presenter("marie", "secret-initial");
    let jeton = corps
        .split_once("\"token\":\"")
        .and_then(|(_, reste)| reste.split_once('"'))
        .map(|(jeton, _)| jeton.to_string())
        .unwrap_or_else(|| panic!("un jeton dans {corps}"));

    // ── 1 bis. `OPTIONS` RÉPOND, ET SON `Allow` ARRIVE JUSQU'AU CLIENT ──────
    //
    // **LA SEULE MESURE QUI VAILLE EST CELLE-CI**, et c'est la leçon du
    // 2026-10-09 : le commentaire de `Resource::allowed` annonçait « c'est ce
    // qu'on écrit dans `Allow` » depuis l'origine, et rien ne l'écrivait ;
    // `Resource::serves` laissait passer `OPTIONS`, et l'application rendait
    // 501. Les deux fautes étaient invisibles dans le code, qui les disait
    // tenues. Une requête les montre.
    let tour = lire(&jeton, "/v1/me/audit", "OPTIONS");
    assert!(
        tour.contains(" 204"),
        "`OPTIONS` devrait rendre 204, pas ceci :\n{tour}"
    );
    assert!(
        tour.to_ascii_lowercase()
            .contains("allow: get, head, options"),
        "`OPTIONS` devrait porter son `Allow` :\n{tour}"
    );
    // §15.5.6 de RFC 9110 : un 405 le porte aussi.
    let refuse = lire(&jeton, "/v1/me/audit", "POST");
    assert!(
        refuse.contains(" 405"),
        "un `POST` sur le journal devrait rendre 405 :\n{refuse}"
    );
    assert!(
        refuse
            .to_ascii_lowercase()
            .contains("allow: get, head, options"),
        "un 405 devrait porter son `Allow` :\n{refuse}"
    );

    // ── 2. LE TITULAIRE LIT SON JOURNAL, LE PLUS RÉCENT D'ABORD ─────────────
    //
    // L'écriture passe par un fil : on laisse la file se vider.
    //
    // **CINQ SECONDES NE SUFFISAIENT PAS SOUS CHARGE.** Cette attente était de
    // cent tours de cinquante millisecondes, et l'essai échouait environ une
    // fois sur trois quand les quatre cibles d'essai de ce paquet tournaient
    // ensemble : le fil d'audit n'avait pas fini d'écrire, et
    // `find("auth.refused")` rendait `None`. Le budget est maintenant de trente
    // secondes — un essai qui attend trop longtemps ne coûte que du temps le
    // jour où il échoue VRAIMENT ; un essai qui n'attend pas assez coûte une
    // enquête à chaque fois qu'il ment.
    let mut journal = String::new();
    for _ in 0..600 {
        journal = lire(&jeton, "/v1/me/audit?limit=10", "GET");
        if journal.contains("session.opened") && journal.contains("auth.refused") {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(journal.starts_with("HTTP/2 200"), "{journal}");
    // **CE QU'ON A VU SE DIT**, sinon l'échec n'apprend rien : un `expect` nu
    // laissait l'enquêteur relancer l'essai pour savoir ce qui manquait.
    //
    // **ET LE JOURNAL DU SERVEUR AVEC** : une entrée d'audit qui manque est soit
    // jamais produite, soit PERDUE parce que la file a débordé — et seul le
    // serveur le dit (« entrée(s) PERDUE(S) »). Sans cette trace, les deux cas
    // se ressemblent, et l'enquête recommence à zéro à chaque échec.
    let ouverte = journal.find("session.opened").unwrap_or_else(|| {
        panic!(
            "la session devrait s'y lire : {journal}\n--- journal du serveur ---\n{}",
            serveur.journal()
        )
    });
    let refus = journal.find("auth.refused").unwrap_or_else(|| {
        panic!(
            "le refus devrait s'y lire : {journal}\n--- journal du serveur ---\n{}",
            serveur.journal()
        )
    });
    assert!(ouverte < refus, "le plus récent d'abord : {journal}");
    assert!(journal.contains(r#""source":"127.0.0.1""#), "{journal}");
    assert!(journal.contains(r#""detail":"password""#), "{journal}");

    // ── 3. L'ADMINISTRATION LIT LE MÊME ─────────────────────────────────────
    let administrateur = jeton_d_administration();
    let vu = lire(&administrateur, "/v1/accounts/marie/audit", "GET");
    assert!(vu.starts_with("HTTP/2 200"), "{vu}");
    assert!(
        vu.contains("session.opened") && vu.contains("auth.refused"),
        "{vu}"
    );

    // ── 4. UN JOURNAL NE S'ÉCRIT PAS, ET UN INCONNU N'Y EST PAS ─────────────
    assert!(lire(&jeton, "/v1/me/audit", "DELETE").starts_with("HTTP/2 405"));
    assert!(
        !repertoire.join("fantome.jsonl").exists(),
        "un compte inconnu a laissé un fichier à son nom"
    );
    let presents: Vec<String> = std::fs::read_dir(&repertoire)
        .expect("le répertoire existe")
        .filter_map(Result::ok)
        .map(|entree| entree.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(presents, ["marie.jsonl"]);
}

/// **UN APPAREIL TROP PRESSÉ LIT `429`, ET SE RECONNECTER NE LUI REND RIEN** (phase 6).
///
/// # CE QUE CET ESSAI ÉPROUVE
///
/// Que le seau est câblé derrière un vrai jeton, sur une vraie socket : la
/// rafale passe, la requête suivante lit `429` avec `Retry-After: 1`, et une
/// SECONDE session du même compte — par mot de passe, donc sans appareil —
/// tombe dans le même seau au lieu d'en ouvrir un neuf. C'est ce qui empêche
/// de retrouver sa rafale en se reconnectant.
///
/// # IL NE COMPTE PAS AU PLUS JUSTE, ET C'EST VOULU
///
/// Le seau se remplit d'un jeton par seconde pendant que l'essai tourne, et
/// une machine chargée espace les requêtes. L'essai boucle donc jusqu'au
/// premier refus, et vérifie des bornes qu'aucun ordonnancement ne franchit :
/// au moins la rafale, puis un refus ; et une session neuve refusée bien avant
/// la rafale qu'un seau neuf lui aurait donnée.
#[test]
fn un_appareil_trop_presse_lit_429_et_se_reconnecter_ne_lui_rend_rien() {
    // UNE RAFALE DE CINQ, UN JETON PAR SECONDE : assez petit pour l'atteindre
    // vite, assez grand pour distinguer un seau neuf d'un seau vide.
    const RAFALE: usize = 5;
    let atelier = atelier("debit-par-appareil");
    let Some((cert, cle)) = paire(&atelier.0) else {
        panic!("{SANS_OPENSSL}");
    };
    if std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("IGNORÉ : `curl` est absent — cet essai n'a RIEN éprouvé.");
        return;
    }

    let empreinte =
        ams_auth::hash_password(b"secret-initial", b"seize octets ici").expect("hachable");
    let magasin = atelier.0.join("comptes.bin");
    std::fs::write(
        &magasin,
        ams_config::encode_accounts(&[ams_auth::Account {
            login: String::from("marie"),
            hash: empreinte,
            addresses: vec![String::from("marie@example.com")],
        }])
        .expect("encodable"),
    )
    .expect("le magasin s'écrit");
    std::fs::set_permissions(&magasin, std::fs::Permissions::from_mode(0o600))
        .expect("permissions du magasin");

    let port_smtp = port_libre();
    let port_http = port_libre();
    let config = configuration_complete(
        &atelier,
        port_smtp,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        &magasin.display().to_string(),
        "",
        "",
        &format!("127.0.0.1:{port_http}"),
        "",
        CLEF,
    );
    let mut lue =
        ams_config::decode(&std::fs::read(&config).expect("relisible")).expect("décodable");
    lue.api_rate = ams_guard::Rate {
        burst: 5,
        per_second: 1,
    };
    std::fs::write(&config, ams_config::encode(&lue).expect("encodable")).expect("écriture");
    let serveur = lancer_avec_api(&config, port_smtp, port_http);
    let base = format!("https://127.0.0.1:{port_http}");

    let jeton_neuf = || -> String {
        let sortie = std::process::Command::new("curl")
            .args(["-s", "-S", "--insecure", "--http2"])
            .args(["-H", "Content-Type: application/json"])
            .args(["-d", r#"{"login":"marie","password":"secret-initial"}"#])
            .arg(format!("{base}/v1/tokens"))
            .output()
            .expect("curl s'exécute");
        let corps = reponse_de_curl(&serveur, &sortie);
        corps
            .split_once("\"token\":\"")
            .and_then(|(_, reste)| reste.split_once('"'))
            .map(|(jeton, _)| jeton.to_string())
            .unwrap_or_else(|| panic!("un jeton dans {corps}"))
    };
    // Une requête, et ses en-têtes et son corps, tels que curl les rend.
    let appel = |jeton: &str, chemin: &str| -> String {
        let sortie = std::process::Command::new("curl")
            .args(["-s", "-S", "--insecure", "--http2", "-i"])
            .args(["-H", &format!("Authorization: Bearer {jeton}")])
            .arg(format!("{base}{chemin}"))
            .output()
            .expect("curl s'exécute");
        reponse_de_curl(&serveur, &sortie)
    };
    let est_refus = |reponse: &str| reponse.starts_with("HTTP/2 429");

    // ── 1. LA RAFALE PASSE, PUIS UN REFUS ───────────────────────────────────
    let premier = jeton_neuf();
    let mut servies = 0_usize;
    let refus = loop {
        let reponse = appel(&premier, "/v1/mailboxes");
        if est_refus(&reponse) {
            break reponse;
        }
        assert!(reponse.starts_with("HTTP/2 200"), "{reponse}");
        servies = servies.saturating_add(1);
        assert!(
            servies < 50,
            "cinquante requêtes sans refus : le débit n'est pas appliqué"
        );
    };
    assert!(
        servies >= RAFALE,
        "la rafale n'est pas passée entière : {servies}"
    );
    let refus_minuscule = refus.to_ascii_lowercase();
    assert!(refus_minuscule.contains("retry-after: 1"), "{refus}");
    assert!(refus.contains("/problems/too-many-requests"), "{refus}");

    // ── 2. UNE SECONDE SESSION DU MÊME COMPTE N'A PAS DE SEAU NEUF ──────────
    //
    // Un seau neuf lui laisserait cinq requêtes. Le seau vide du compte ne peut
    // en avoir rendu qu'une ou deux pendant ces quelques curl.
    let second = jeton_neuf();
    let mut passees = 0_usize;
    while !est_refus(&appel(&second, "/v1/mailboxes")) {
        passees = passees.saturating_add(1);
        assert!(
            passees < RAFALE,
            "une session neuve a retrouvé une rafale entière : se reconnecter vide le débit"
        );
    }

    // ── 3. LES REFUS SE VOIENT DANS LES MÉTRIQUES DU COMPTE ─────────────────
    std::thread::sleep(Duration::from_millis(1200));
    let metriques = appel(&second, "/v1/metrics");
    assert!(metriques.starts_with("HTTP/2 200"), "{metriques}");
    let compte = metriques
        .split_once("\"requestsThrottled\":")
        .and_then(|(_, reste)| {
            reste
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|chiffres| chiffres.parse::<u64>().ok())
        })
        .unwrap_or_else(|| panic!("requestsThrottled dans {metriques}"));
    assert!(compte >= 2, "deux refus au moins : {metriques}");
}

/// **UN UTILISATEUR VOIT SES APPAREILS ET EN RÉVOQUE UN, SANS ADMINISTRATEUR.**
///
/// # CE QUE CET ESSAI ÉPROUVE, ET QU'AUCUN AUTRE NE PEUT
///
/// Les essais d'unité montrent que le magasin range, que le routeur route et que
/// le rendu écrit. Aucun ne montre que les trois sont CÂBLÉS ENSEMBLE derrière
/// un vrai jeton, sur une vraie socket TLS — et c'est exactement le genre de
/// défaut qui a laissé, une semaine plus tôt, quatre routes d'écriture servir la
/// lecture sans que rien ne bronche.
///
/// # ET IL ÉPROUVE LA CLOISON ENTRE COMPTES
///
/// Le jeton de Marie ne doit pas révoquer l'appareil de Paul, et il doit obtenir
/// pour cela un `404` — le même que pour un identifiant qui n'existe pas. Un
/// `403` distinguerait les deux, et cette distinction est l'information
/// elle-même : elle laisserait énumérer les appareils du serveur.
#[test]
fn un_utilisateur_voit_et_revoque_ses_appareils() {
    let atelier = atelier("mes-appareils");
    let Some((cert, cle)) = paire(&atelier.0) else {
        panic!("{SANS_OPENSSL}");
    };
    if std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("IGNORÉ : `curl` est absent — cet essai n'a RIEN éprouvé.");
        return;
    }

    let empreinte =
        ams_auth::hash_password(b"secret-initial", b"seize octets ici").expect("hachable");
    let magasin = atelier.0.join("comptes.bin");
    std::fs::write(
        &magasin,
        ams_config::encode_accounts(&[ams_auth::Account {
            login: String::from("marie"),
            hash: empreinte,
            addresses: vec![String::from("marie@example.com")],
        }])
        .expect("encodable"),
    )
    .expect("le magasin s'écrit");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&magasin, std::fs::Permissions::from_mode(0o600))
            .expect("permissions du magasin");
    }

    // Une clef publique P-256 valide, figée : le point `7 · G`.
    const CLE_VALIDE: [u8; 65] = [
        0x04, 0x1e, 0x18, 0x53, 0x2f, 0xd4, 0x75, 0x4c, 0x02, 0xf3, 0x04, 0x1d, 0x9c, 0x75, 0xce,
        0xb3, 0x3b, 0x83, 0xff, 0xd8, 0x1a, 0xc7, 0xce, 0x4f, 0xe8, 0x82, 0xcc, 0xb1, 0xc9, 0x8b,
        0xc5, 0x89, 0x6e, 0xa4, 0x6c, 0x31, 0x1c, 0x4e, 0x2f, 0xf4, 0x0d, 0xd9, 0x6a, 0x36, 0x53,
        0xe6, 0xe4, 0x54, 0x45, 0xd3, 0x2d, 0xfe, 0x48, 0x6e, 0xce, 0xd7, 0x5c, 0x7a, 0x90, 0xc6,
        0xa1, 0x88, 0x81, 0xc0, 0xa3,
    ];
    let clef = ams_auth::Cle::lire(&CLE_VALIDE).expect("une clef d'épreuve valide");
    let appareil = |login: &str, id: &str, nom: &str, vu: u64| ams_config::Device {
        login: String::from(login),
        id: String::from(id),
        name: String::from(nom),
        public_key: clef.clone(),
        enrolled: 1_790_000_000,
        last_seen: vu,
        push: None,
        attestation: None,
    };
    let appareils = atelier.0.join("appareils.bin");
    std::fs::write(
        &appareils,
        ams_config::encode_devices(&[
            appareil(
                "marie",
                "tel-de-marie",
                "iPhone de Marie",
                1_790_003_600_000,
            ),
            // JAMAIS VU : c'est le cas qui écrit `lastSeenAt: 0`.
            appareil("marie", "portable-de-marie", "portable du bureau", 0),
            // CELUI D'UN AUTRE : il ne doit ni se voir, ni se révoquer.
            appareil("paul", "tel-de-paul", "le téléphone de Paul", 0),
        ])
        .expect("encodable"),
    )
    .expect("le magasin d'appareils s'écrit");

    let port_smtp = port_libre();
    let port_http = port_libre();
    let config = configuration_complete(
        &atelier,
        port_smtp,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        &magasin.display().to_string(),
        &appareils.display().to_string(),
        "",
        &format!("127.0.0.1:{port_http}"),
        "",
        CLEF,
    );
    let serveur = lancer_avec_api(&config, port_smtp, port_http);
    let base = format!("https://127.0.0.1:{port_http}");

    // ── LE JETON D'UNE UTILISATRICE ORDINAIRE ───────────────────────────────
    let sortie = std::process::Command::new("curl")
        .args(["-s", "-S", "--insecure", "--http2"])
        .args(["-H", "Content-Type: application/json"])
        .args(["-d", r#"{"login":"marie","password":"secret-initial"}"#])
        .arg(format!("{base}/v1/tokens"))
        .output()
        .expect("curl s'exécute");
    let corps = reponse_de_curl(&serveur, &sortie);
    let jeton = corps
        .split_once("\"token\":\"")
        .and_then(|(_, reste)| reste.split_once('"'))
        .map(|(jeton, _)| jeton.to_string())
        .unwrap_or_else(|| panic!("un jeton dans {corps}"));

    let appeler = |methode: &str, chemin: &str| -> (String, String) {
        let sortie = std::process::Command::new("curl")
            .args(["-s", "-S", "--insecure", "--http2", "-X", methode])
            .args(["-H", &format!("Authorization: Bearer {jeton}")])
            .args(["-w", "\n%{http_code}"])
            .arg(format!("{base}{chemin}"))
            .output()
            .expect("curl s'exécute");
        let tout = reponse_de_curl(&serveur, &sortie);
        let (corps, code) = tout.rsplit_once('\n').unwrap_or(("", ""));
        (corps.to_string(), code.to_string())
    };

    // ── ELLE VOIT LES SIENS, ET SEULEMENT LES SIENS ─────────────────────────
    let (corps, code) = appeler("GET", "/v1/me/devices");
    assert_eq!(code, "200", "la liste doit se servir : {corps}");
    assert!(corps.contains("tel-de-marie"), "{corps}");
    assert!(corps.contains("portable-de-marie"), "{corps}");
    assert!(
        !corps.contains("tel-de-paul"),
        "l'appareil d'un autre ne doit pas s'y trouver : {corps}"
    );
    assert!(corps.contains("\"lastSeenAt\":0"), "{corps}");
    // **LE MAGASIN COMPTE EN MILLISECONDES, L'API REND DES SECONDES**, comme
    // pour toutes ses dates.
    assert!(corps.contains("\"lastSeenAt\":1790003600"), "{corps}");
    assert!(!corps.contains("1790003600000"), "{corps}");
    // Et la clef publique n'en sort pas.
    assert!(!corps.contains("publicKey"), "{corps}");

    // ── CELUI D'UN AUTRE EST « INTROUVABLE », ET NON « INTERDIT » ───────────
    let (_, chez_paul) = appeler("DELETE", "/v1/me/devices/tel-de-paul");
    let (_, inexistant) = appeler("DELETE", "/v1/me/devices/jamais-vu");
    assert_eq!(
        chez_paul, inexistant,
        "les deux cas DOIVENT se répondre pareil, sinon on énumère"
    );
    assert_eq!(chez_paul, "404");

    // ── ET LA RÉVOCATION DU SIEN ABOUTIT ────────────────────────────────────
    let (corps, code) = appeler("DELETE", "/v1/me/devices/tel-de-marie");
    assert_eq!(code, "204", "la révocation doit aboutir : {corps}");

    let (corps, code) = appeler("GET", "/v1/me/devices");
    assert_eq!(code, "200");
    assert!(
        !corps.contains("tel-de-marie"),
        "il ne doit plus s'y trouver : {corps}"
    );
    assert!(corps.contains("portable-de-marie"), "{corps}");

    // **ET LE DISQUE A SUIVI** : c'est lui qui fait foi au prochain démarrage.
    let relu = ams_config::decode_devices(&std::fs::read(&appareils).expect("lisible"))
        .expect("relisible");
    assert_eq!(relu.len(), 2);
    assert!(relu.iter().all(|connu| connu.id != "tel-de-marie"));
    assert!(
        relu.iter().any(|connu| connu.login == "paul"),
        "celui de Paul est resté"
    );

    // ── REVOQUER DEUX FOIS REND 404 LA SECONDE ──────────────────────────────
    let (_, code) = appeler("DELETE", "/v1/me/devices/tel-de-marie");
    assert_eq!(code, "404");
}

/// **SANS MAGASIN D'APPAREILS, LES DEUX ROUTES RÉPONDENT 501.**
///
/// Et non une liste vide : une configuration oubliée ne doit pas ressembler à un
/// compte qui n'a rien enrôlé. L'exploitant chercherait sinon le défaut chez
/// l'utilisateur.
#[test]
fn sans_magasin_les_appareils_ne_se_servent_pas() {
    let atelier = atelier("sans-appareils");
    let Some((cert, cle)) = paire(&atelier.0) else {
        panic!("{SANS_OPENSSL}");
    };
    if std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("IGNORÉ : `curl` est absent — cet essai n'a RIEN éprouvé.");
        return;
    }

    let empreinte =
        ams_auth::hash_password(b"secret-initial", b"seize octets ici").expect("hachable");
    let magasin = atelier.0.join("comptes.bin");
    std::fs::write(
        &magasin,
        ams_config::encode_accounts(&[ams_auth::Account {
            login: String::from("marie"),
            hash: empreinte,
            addresses: vec![String::from("marie@example.com")],
        }])
        .expect("encodable"),
    )
    .expect("le magasin s'écrit");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&magasin, std::fs::Permissions::from_mode(0o600))
            .expect("permissions du magasin");
    }

    let port_smtp = port_libre();
    let port_http = port_libre();
    // LE CHEMIN DES APPAREILS EST VIDE : c'est tout le sujet de cet essai.
    let config = configuration_complete(
        &atelier,
        port_smtp,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        &magasin.display().to_string(),
        "",
        "",
        &format!("127.0.0.1:{port_http}"),
        "",
        CLEF,
    );
    let serveur = lancer_avec_api(&config, port_smtp, port_http);
    let base = format!("https://127.0.0.1:{port_http}");

    let sortie = std::process::Command::new("curl")
        .args(["-s", "-S", "--insecure", "--http2"])
        .args(["-H", "Content-Type: application/json"])
        .args(["-d", r#"{"login":"marie","password":"secret-initial"}"#])
        .arg(format!("{base}/v1/tokens"))
        .output()
        .expect("curl s'exécute");
    let corps = reponse_de_curl(&serveur, &sortie);
    let jeton = corps
        .split_once("\"token\":\"")
        .and_then(|(_, reste)| reste.split_once('"'))
        .map(|(jeton, _)| jeton.to_string())
        .unwrap_or_else(|| panic!("un jeton dans {corps}"));

    for (methode, chemin) in [("GET", "/v1/me/devices"), ("DELETE", "/v1/me/devices/a1")] {
        let sortie = std::process::Command::new("curl")
            .args(["-s", "-S", "--insecure", "--http2", "-X", methode])
            .args(["-H", &format!("Authorization: Bearer {jeton}")])
            .args(["-w", "\n%{http_code}"])
            .arg(format!("{base}{chemin}"))
            .output()
            .expect("curl s'exécute");
        let tout = reponse_de_curl(&serveur, &sortie);
        let (corps, code) = tout.rsplit_once('\n').unwrap_or(("", ""));
        assert_eq!(code, "501", "{methode} {chemin}");

        // **LE CORPS DOIT DIRE LE MÊME CODE QUE LA LIGNE DE STATUT.**
        //
        // Il disait `"status":404` sous un 501 : `pas_encore` composait son
        // document avec `NoSuchResource`, dont le statut vaut 404. §3.1 de
        // RFC 9457 demande que les deux coïncident, et un client qui croirait le
        // corps chercherait une route disparue au lieu d'une capacité que
        // l'exploitant n'a pas configurée.
        //
        // **VU EN PRODUCTION, ET NON PAR UN ESSAI** : le bras était inatteignable
        // avant que ces deux routes ne l'empruntent, et aucun essai ne regardait
        // le CORPS d'un 501.
        assert!(
            corps.contains("\"status\":501"),
            "{methode} {chemin} : le corps contredit le statut — {corps}"
        );
        assert!(
            corps.contains("/problems/not-implemented"),
            "{methode} {chemin} : {corps}"
        );
    }
}

/// **UNE INVITATION AMORCE LE PREMIER APPAREIL, ET UN SEUL.**
///
/// # CE QUE CET ESSAI ÉPROUVE, ET QU'AUCUN AUTRE NE PEUT
///
/// Cinq couches doivent être câblées ensemble pour qu'un enrôlement aboutisse :
/// le sceau (`ams-api`), la route, la session qui vérifie l'invitation SANS
/// jeton, le conducteur qui distingue un enrôlement d'une session, et le
/// magasin. Chacune est éprouvée chez elle ; aucune de ces épreuves ne dit
/// qu'elles se parlent.
///
/// # ET IL ÉPROUVE L'USAGE UNIQUE
///
/// C'est la propriété qui a décidé de toute la conception : l'invitation ne vaut
/// que tant que le compte n'a AUCUN appareil. Rejouer la MÊME invitation, encore
/// valide, doit échouer — sans quoi qui l'intercepte s'enrôle un second appareil
/// permanent.
#[test]
fn une_invitation_amorce_le_premier_appareil_et_un_seul() {
    let atelier = atelier("invitation");
    let Some((cert, cle)) = paire(&atelier.0) else {
        panic!("{SANS_OPENSSL}");
    };
    if std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("IGNORÉ : `curl` est absent — cet essai n'a RIEN éprouvé.");
        return;
    }

    let empreinte =
        ams_auth::hash_password(b"secret-initial", b"seize octets ici").expect("hachable");
    let magasin = atelier.0.join("comptes.bin");
    std::fs::write(
        &magasin,
        ams_config::encode_accounts(&[ams_auth::Account {
            login: String::from("marie"),
            hash: empreinte,
            addresses: vec![String::from("marie@example.com")],
        }])
        .expect("encodable"),
    )
    .expect("le magasin s'écrit");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&magasin, std::fs::Permissions::from_mode(0o600))
            .expect("permissions du magasin");
    }

    // Le magasin d'appareils est NOMMÉ mais ABSENT : il se crée au premier
    // enrôlement, et c'est le cas d'un serveur neuf.
    let appareils = atelier.0.join("appareils.bin");
    assert!(!appareils.exists());

    let port_smtp = port_libre();
    let port_http = port_libre();
    let config = configuration_complete(
        &atelier,
        port_smtp,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        &magasin.display().to_string(),
        &appareils.display().to_string(),
        "",
        &format!("127.0.0.1:{port_http}"),
        "",
        CLEF,
    );
    let serveur = lancer_avec_api(&config, port_smtp, port_http);
    let base = format!("https://127.0.0.1:{port_http}");

    // ── LE JETON D'ADMINISTRATION, SEUL À POUVOIR INVITER ───────────────────
    let admin = jeton_d_administration();
    let poster = |chemin: &str, corps: &str, entete: Option<&str>| -> (String, String) {
        let mut commande = std::process::Command::new("curl");
        commande
            .args(["-s", "-S", "--insecure", "--http2", "-X", "POST"])
            .args(["-H", "Content-Type: application/json"])
            .args(["-d", corps])
            .args(["-w", "\n%{http_code}"]);
        if let Some(valeur) = entete {
            commande.args(["-H", valeur]);
        }
        let sortie = commande
            .arg(format!("{base}{chemin}"))
            .output()
            .expect("curl s'exécute");
        let tout = reponse_de_curl(&serveur, &sortie);
        let (corps, code) = tout.rsplit_once('\n').unwrap_or(("", ""));
        (corps.to_string(), code.to_string())
    };

    // **SANS PORTÉE `admin`, ON N'INVITE PAS.** Un jeton d'utilisateur ne doit
    // pas pouvoir s'inviter lui-même : ce serait s'enrôler sans exploitant.
    let (corps, code) = poster(
        "/v1/tokens",
        r#"{"login":"marie","password":"secret-initial"}"#,
        None,
    );
    assert_eq!(code, "201", "{corps}");
    let jeton_de_marie = corps
        .split_once("\"token\":\"")
        .and_then(|(_, reste)| reste.split_once('"'))
        .map(|(jeton, _)| jeton.to_string())
        .unwrap_or_else(|| panic!("un jeton dans {corps}"));
    let (_, code) = poster(
        "/v1/invitations",
        r#"{"login":"marie"}"#,
        Some(&format!("Authorization: Bearer {jeton_de_marie}")),
    );
    assert_eq!(
        code, "404",
        "un jeton d'utilisateur ne doit pas pouvoir inviter"
    );

    // ── L'EXPLOITANT INVITE ─────────────────────────────────────────────────
    let (corps, code) = poster(
        "/v1/invitations",
        r#"{"login":"marie"}"#,
        Some(&format!("Authorization: Bearer {admin}")),
    );
    assert_eq!(code, "201", "l'invitation doit se frapper : {corps}");
    assert!(corps.contains("\"login\":\"marie\""), "{corps}");
    assert!(corps.contains("\"expiresAt\":"), "{corps}");
    let invitation = corps
        .split_once("\"invitation\":\"")
        .and_then(|(_, reste)| reste.split_once('"'))
        .map(|(texte, _)| texte.to_string())
        .unwrap_or_else(|| panic!("une invitation dans {corps}"));

    // Inviter un compte qui n'existe pas se refuse : c'est une faute de frappe
    // de l'exploitant, et elle ne doit pas se découvrir chez l'utilisateur.
    let (_, code) = poster(
        "/v1/invitations",
        r#"{"login":"personne"}"#,
        Some(&format!("Authorization: Bearer {admin}")),
    );
    assert_eq!(code, "404");

    // ── L'ENRÔLEMENT, SANS AUCUN JETON ──────────────────────────────────────
    //
    let clef = en_base64url(&cle_publique());

    // **AUCUN EN-TÊTE `Authorization`** : c'est tout le sujet.
    let (corps, code) = poster(
        "/v1/devices",
        &format!(
            r#"{{"invitation":"{invitation}","publicKey":"{clef}","name":"iPhone de Marie"}}"#
        ),
        None,
    );
    assert_eq!(
        code, "201",
        "l'enrôlement doit aboutir sans jeton : {corps}"
    );
    assert!(corps.contains("\"login\":\"marie\""), "{corps}");
    assert!(
        corps.contains("marie@example.com"),
        "les adresses doivent revenir, l'application n'a pas de second appel : {corps}"
    );
    let id = corps
        .split_once("\"id\":\"")
        .and_then(|(_, reste)| reste.split_once('"'))
        .map(|(texte, _)| texte.to_string())
        .unwrap_or_else(|| panic!("un identifiant dans {corps}"));
    // **L'IDENTIFIANT EST LE CONDENSAT DE LA CLEF** : soixante-quatre chiffres
    // hexadécimaux minuscules, et rien d'autre.
    assert_eq!(id.len(), 64, "{id}");
    assert!(
        id.bytes()
            .all(|o| o.is_ascii_digit() || (b'a'..=b'f').contains(&o)),
        "{id}"
    );

    // ── ET LE DISQUE A SUIVI ────────────────────────────────────────────────
    let relu = ams_config::decode_devices(&std::fs::read(&appareils).expect("lisible"))
        .expect("relisible");
    assert_eq!(relu.len(), 1);
    assert_eq!(relu[0].login, "marie");
    assert_eq!(relu[0].public_key.octets(), cle_publique());

    // ── LA MÊME INVITATION NE SERT PAS DEUX FOIS ────────────────────────────
    //
    // Elle est encore valide — son heure n'est pas passée —, mais le compte a
    // maintenant un appareil. C'est là, et nulle part ailleurs, que l'usage
    // unique se décide.
    let (corps, code) = poster(
        "/v1/devices",
        &format!(r#"{{"invitation":"{invitation}","publicKey":"{clef}","name":"le second"}}"#),
        None,
    );
    assert_eq!(code, "409", "la seconde fois doit échouer : {corps}");
    assert!(corps.contains("/problems/conflict"), "{corps}");
    assert_eq!(
        ams_config::decode_devices(&std::fs::read(&appareils).expect("lisible"))
            .expect("relisible")
            .len(),
        1,
        "rien ne s'est ajouté"
    );

    // ── ET L'APPAREIL SE VOIT SOUS SON COMPTE ───────────────────────────────
    let sortie = std::process::Command::new("curl")
        .args(["-s", "-S", "--insecure", "--http2"])
        .args(["-H", &format!("Authorization: Bearer {jeton_de_marie}")])
        .arg(format!("{base}/v1/me/devices"))
        .output()
        .expect("curl s'exécute");
    let liste = reponse_de_curl(&serveur, &sortie);
    assert!(liste.contains(&id), "{liste}");
    assert!(liste.contains("iPhone de Marie"), "{liste}");
}

/// **CE QU'UN ENRÔLEMENT REFUSE, ET AVEC QUEL CODE.**
///
/// Les distinctions comptent : qui présente une invitation que NOTRE clé a
/// scellée est autorisé, et lui répondre « aucune ressource ici » l'enverrait
/// chercher un défaut de chemin. Ce qu'il doit corriger, il doit l'apprendre.
#[test]
fn un_enrolement_refuse_dit_ce_qu_il_faut() {
    let atelier = atelier("enrolement-refus");
    let Some((cert, cle)) = paire(&atelier.0) else {
        panic!("{SANS_OPENSSL}");
    };
    if std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("IGNORÉ : `curl` est absent — cet essai n'a RIEN éprouvé.");
        return;
    }

    let empreinte =
        ams_auth::hash_password(b"secret-initial", b"seize octets ici").expect("hachable");
    let magasin = atelier.0.join("comptes.bin");
    std::fs::write(
        &magasin,
        ams_config::encode_accounts(&[ams_auth::Account {
            login: String::from("marie"),
            hash: empreinte,
            addresses: vec![String::from("marie@example.com")],
        }])
        .expect("encodable"),
    )
    .expect("le magasin s'écrit");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&magasin, std::fs::Permissions::from_mode(0o600))
            .expect("permissions du magasin");
    }

    let port_smtp = port_libre();
    let port_http = port_libre();
    let config = configuration_complete(
        &atelier,
        port_smtp,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        &magasin.display().to_string(),
        &atelier.0.join("appareils.bin").display().to_string(),
        "",
        &format!("127.0.0.1:{port_http}"),
        "",
        CLEF,
    );
    let serveur = lancer_avec_api(&config, port_smtp, port_http);
    let base = format!("https://127.0.0.1:{port_http}");

    let admin = jeton_d_administration();
    let sortie = std::process::Command::new("curl")
        .args(["-s", "-S", "--insecure", "--http2", "-X", "POST"])
        .args(["-H", "Content-Type: application/json"])
        .args(["-H", &format!("Authorization: Bearer {admin}")])
        .args(["-d", r#"{"login":"marie"}"#])
        .arg(format!("{base}/v1/invitations"))
        .output()
        .expect("curl s'exécute");
    let corps = reponse_de_curl(&serveur, &sortie);
    let invitation = corps
        .split_once("\"invitation\":\"")
        .and_then(|(_, reste)| reste.split_once('"'))
        .map(|(texte, _)| texte.to_string())
        .unwrap_or_else(|| panic!("une invitation dans {corps}"));

    let enroler = |corps: &str| -> String {
        let sortie = std::process::Command::new("curl")
            .args(["-s", "-S", "--insecure", "--http2", "-X", "POST"])
            .args(["-H", "Content-Type: application/json"])
            .args(["-d", corps])
            .args(["-o", "/dev/null", "-w", "%{http_code}"])
            .arg(format!("{base}/v1/devices"))
            .output()
            .expect("curl s'exécute");
        reponse_de_curl(&serveur, &sortie)
    };

    // **UNE INVITATION FORGÉE : 401**, comme un jeton qui ne se vérifie pas.
    assert_eq!(
        enroler(r#"{"invitation":"AAAAAAAAAAAAAAAAAAAAAAAA","publicKey":"BAECAwQ"}"#),
        "401"
    );

    // **UNE CLEF QUI N'EST PAS UN POINT DE LA COURBE : 400.**
    //
    // L'invitation est bonne — il est autorisé —, c'est son corps qui cloche, et
    // c'est ce qu'il doit apprendre pour le corriger.
    assert_eq!(
        enroler(&format!(
            r#"{{"invitation":"{invitation}","publicKey":"BAECAwQ"}}"#
        )),
        "400",
        "une clef trop courte"
    );

    // Et le magasin n'a rien gardé de tout cela.
    assert!(
        !atelier.0.join("appareils.bin").exists(),
        "un refus ne doit rien poser"
    );
}

// ── DE QUOI TENIR LE RÔLE DU TÉLÉPHONE ──────────────────────────────────────
//
// Ces quatre aides servent à l'essai d'enrôlement ET à celui de session par
// clef. Les dupliquer ferait deux copies qui finiraient par différer — donc
// deux clefs qui ne se correspondraient plus.

/// La clef privée d'épreuve : des octets FIXES, jamais un tirage.
///
/// **PAS D'ALÉA DANS UN ESSAI** : celui qui tire au sort échoue un jour sur
/// mille, et ce jour-là personne ne sait pourquoi.
fn cle_privee() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[7_u8; 32]).expect("une clef valide")
}

/// Sa clef publique, en forme non compressée SEC 1 (§2.3.3).
fn cle_publique() -> [u8; 65] {
    let point = cle_privee().verifying_key().to_sec1_point(false);
    let mut sortie = [0_u8; 65];
    sortie.copy_from_slice(point.as_bytes());
    sortie
}

/// Le base64url de §5 de RFC 4648, **sans remplissage** — celui que l'API lit.
fn en_base64url(octets: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut texte = String::new();
    for morceau in octets.chunks(3) {
        let mut bloc = [0_u8; 3];
        for (place, lu) in bloc.iter_mut().zip(morceau) {
            *place = *lu;
        }
        let valeur = (u32::from(bloc[0]) << 16) | (u32::from(bloc[1]) << 8) | u32::from(bloc[2]);
        // **UN MORCEAU DE `n` OCTETS DONNE `n + 1` CARACTÈRES** : un pour deux,
        // deux pour trois, trois pour quatre. L'écrire ainsi évite le calcul de
        // bits arrondi vers le haut, qui se relit mal et s'écrit de travers.
        for decalage in [18_u32, 12, 6, 0]
            .iter()
            .take(morceau.len().saturating_add(1))
        {
            let rang = ((valeur >> decalage) & 0x3f) as usize;
            texte.push(char::from(ALPHABET[rang]));
        }
    }
    texte
}

/// Signe ce condensat comme le ferait une enclave : **forme fixe de
/// soixante-quatre octets**, et la forme de `s` telle qu'elle sort.
fn signer(condensat: &[u8; 32]) -> String {
    signer_avec(&cle_privee(), condensat)
}

/// Une clef d'épreuve tirée de cette graine — des octets FIXES, jamais un
/// tirage.
///
/// **PLUSIEURS CLEFS DISTINCTES SONT NÉCESSAIRES** : un appairage où
/// l'approbateur et l'approuvé porteraient la même clef n'éprouverait rien,
/// puisque le magasin refuse deux fois le même identifiant.
fn cle_privee_de(graine: u8) -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[graine; 32]).expect("une clef valide")
}

/// Sa clef publique, en forme non compressée SEC 1 (§2.3.3).
fn cle_publique_de(graine: u8) -> [u8; 65] {
    let point = cle_privee_de(graine).verifying_key().to_sec1_point(false);
    let mut sortie = [0_u8; 65];
    sortie.copy_from_slice(point.as_bytes());
    sortie
}

/// Signe ce condensat avec cette clef, en forme fixe.
fn signer_avec(privee: &p256::ecdsa::SigningKey, condensat: &[u8; 32]) -> String {
    use p256::ecdsa::signature::hazmat::PrehashSigner as _;
    let signature: p256::ecdsa::Signature = privee.sign_prehash(condensat).expect("signable");
    en_base64url(&signature.to_bytes())
}

/// Le condensat qu'un appareil signe : rôle, identité du serveur, défi —
/// séparés par des octets nuls, et **jamais le défi nu**.
fn condensat_a_signer(role: &str, identite: &str, defi: &str) -> [u8; 32] {
    let mut a_signer = Vec::new();
    a_signer.extend_from_slice(role.as_bytes());
    a_signer.push(0);
    a_signer.extend_from_slice(identite.as_bytes());
    a_signer.push(0);
    a_signer.extend_from_slice(defi.as_bytes());
    ams_sasl::sha256(&a_signer)
}

/// Le condensat d'un APPAIRAGE : celui d'une session, sous le rôle
/// `ams-pairing`, suivi de l'identifiant de l'appareil approuvé.
fn condensat_d_appairage(identite: &str, defi: &str, nouvel_appareil: &str) -> [u8; 32] {
    let mut a_signer = Vec::new();
    a_signer.extend_from_slice(b"ams-pairing");
    a_signer.push(0);
    a_signer.extend_from_slice(identite.as_bytes());
    a_signer.push(0);
    a_signer.extend_from_slice(defi.as_bytes());
    a_signer.push(0);
    a_signer.extend_from_slice(nouvel_appareil.as_bytes());
    ams_sasl::sha256(&a_signer)
}

/// L'identifiant d'appareil de la clef tirée de cette graine : le condensat
/// SHA-256 de sa forme SEC 1, en hexadécimal minuscule.
fn identifiant_de(graine: u8) -> String {
    ams_sasl::sha256(&cle_publique_de(graine))
        .iter()
        .map(|octet| format!("{octet:02x}"))
        .collect()
}

/// **UNE CLEF ENRÔLÉE OUVRE UNE SESSION, ET LE DÉFI NE SERT QU'UNE FOIS.**
///
/// # CE QUE CET ESSAI ÉPROUVE, ET QU'AUCUN AUTRE NE PEUT
///
/// Le cycle complet, avec une VRAIE signature ECDSA P-256 : invitation,
/// enrôlement, défi, signature, session, puis un appel authentifié par le jeton
/// obtenu. Six couches doivent s'accorder, et notamment sur **le condensat
/// signé** — rôle, domaine du serveur, défi. Un désaccord d'un seul octet sur
/// l'une des trois parties fait échouer toutes les signatures, et aucune épreuve
/// d'unité ne le verrait.
///
/// # ET IL ÉPROUVE L'USAGE UNIQUE
///
/// C'est la promesse de la feuille de route, et elle ne vient d'aucun registre :
/// un défi n'est recevable que s'il a été émis APRÈS la dernière session de
/// l'appareil. Rejouer le même couple défi-signature, encore dans ses soixante
/// secondes, doit échouer.
#[test]
fn une_clef_enrolee_ouvre_une_session_et_le_defi_ne_sert_qu_une_fois() {
    let atelier = atelier("session-par-clef");
    let Some((cert, cle)) = paire(&atelier.0) else {
        panic!("{SANS_OPENSSL}");
    };
    if std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("IGNORÉ : `curl` est absent — cet essai n'a RIEN éprouvé.");
        return;
    }

    let empreinte =
        ams_auth::hash_password(b"secret-initial", b"seize octets ici").expect("hachable");
    let magasin = atelier.0.join("comptes.bin");
    std::fs::write(
        &magasin,
        ams_config::encode_accounts(&[ams_auth::Account {
            login: String::from("marie"),
            hash: empreinte,
            addresses: vec![String::from("marie@example.com")],
        }])
        .expect("encodable"),
    )
    .expect("le magasin s'écrit");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&magasin, std::fs::Permissions::from_mode(0o600))
            .expect("permissions du magasin");
    }

    let appareils = atelier.0.join("appareils.bin");
    let port_smtp = port_libre();
    let port_http = port_libre();
    let config = configuration_complete(
        &atelier,
        port_smtp,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        &magasin.display().to_string(),
        &appareils.display().to_string(),
        "",
        &format!("127.0.0.1:{port_http}"),
        "",
        CLEF,
    );
    let serveur = lancer_avec_api(&config, port_smtp, port_http);
    let base = format!("https://127.0.0.1:{port_http}");

    let poster = |chemin: &str, corps: &str, entete: Option<&str>| -> (String, String) {
        let mut commande = std::process::Command::new("curl");
        commande
            .args(["-s", "-S", "--insecure", "--http2", "-X", "POST"])
            .args(["-H", "Content-Type: application/json"])
            .args(["-d", corps])
            .args(["-w", "\n%{http_code}"]);
        if let Some(valeur) = entete {
            commande.args(["-H", valeur]);
        }
        let sortie = commande
            .arg(format!("{base}{chemin}"))
            .output()
            .expect("curl s'exécute");
        let tout = reponse_de_curl(&serveur, &sortie);
        let (corps, code) = tout.rsplit_once('\n').unwrap_or(("", ""));
        (corps.to_string(), code.to_string())
    };
    let champ = |corps: &str, nom: &str| -> String {
        corps
            .split_once(&format!("\"{nom}\":\""))
            .and_then(|(_, reste)| reste.split_once('"'))
            .map(|(valeur, _)| valeur.to_string())
            .unwrap_or_else(|| panic!("`{nom}` dans {corps}"))
    };

    // ── ENRÔLER, PAR INVITATION ─────────────────────────────────────────────
    let admin = jeton_d_administration();
    let (corps, code) = poster(
        "/v1/invitations",
        r#"{"login":"marie"}"#,
        Some(&format!("Authorization: Bearer {admin}")),
    );
    assert_eq!(code, "201", "{corps}");
    let invitation = champ(&corps, "invitation");

    let (corps, code) = poster(
        "/v1/devices",
        &format!(
            r#"{{"invitation":"{invitation}","publicKey":"{}","name":"le téléphone"}}"#,
            en_base64url(&cle_publique())
        ),
        None,
    );
    assert_eq!(code, "201", "{corps}");
    let appareil = champ(&corps, "id");

    // ── UN DÉFI, SANS AUCUN JETON ───────────────────────────────────────────
    let (corps, code) = poster(
        "/v1/sessions/challenge",
        &format!(r#"{{"login":"marie","deviceId":"{appareil}"}}"#),
        None,
    );
    assert_eq!(code, "201", "le défi doit s'émettre sans jeton : {corps}");
    let defi = champ(&corps, "challenge");
    let role = champ(&corps, "role");
    let identite = champ(&corps, "serverIdentity");
    assert_eq!(role, "ams-session");
    assert_eq!(
        identite, "mail.example.com",
        "l'identité annoncée doit être le domaine du serveur"
    );
    assert!(corps.contains("\"expiresInSeconds\":60"), "{corps}");

    // ── SIGNER COMME LE FERAIT UN TÉLÉPHONE ─────────────────────────────────
    //
    // **PAS LE DÉFI NU** : le condensat porte le rôle, l'identité du serveur et
    // le défi, séparés par des octets nuls. C'est ce qui empêche une signature
    // obtenue ici de valoir ailleurs.
    let mut a_signer = Vec::new();
    a_signer.extend_from_slice(role.as_bytes());
    a_signer.push(0);
    a_signer.extend_from_slice(identite.as_bytes());
    a_signer.push(0);
    a_signer.extend_from_slice(defi.as_bytes());
    let condensat = ams_sasl::sha256(&a_signer);
    let signature = signer(&condensat);

    // ── OUVRIR LA SESSION ───────────────────────────────────────────────────
    let (corps, code) = poster(
        "/v1/sessions",
        &format!(r#"{{"challenge":"{defi}","signature":"{signature}"}}"#),
        None,
    );
    assert_eq!(code, "201", "la session doit s'ouvrir : {corps}");
    let jeton = champ(&corps, "token");

    // **ET LE JETON OUVRE VRAIMENT LE COURRIER.** Un jeton qu'on rend sans qu'il
    // serve à rien serait une réussite de façade.
    let sortie = std::process::Command::new("curl")
        .args(["-s", "-S", "--insecure", "--http2"])
        .args(["-H", &format!("Authorization: Bearer {jeton}")])
        .args(["-o", "/dev/null", "-w", "%{http_code}"])
        .arg(format!("{base}/v1/mailboxes"))
        .output()
        .expect("curl s'exécute");
    assert_eq!(String::from_utf8_lossy(&sortie.stdout), "200");

    // ── LE MÊME DÉFI NE SERT PAS DEUX FOIS ──────────────────────────────────
    //
    // Il est encore dans ses soixante secondes, et la signature est la même.
    // Ce qui l'a tué est la date de session que l'ouverture vient d'écrire.
    let (corps, code) = poster(
        "/v1/sessions",
        &format!(r#"{{"challenge":"{defi}","signature":"{signature}"}}"#),
        None,
    );
    assert_eq!(code, "401", "le rejeu doit échouer : {corps}");

    // ── UN DÉFI EST ÉMIS MÊME POUR UN APPAREIL INCONNU ──────────────────────
    //
    // Sans cela, l'émission serait un oracle d'énumération : qui cherche un
    // identifiant valide n'aurait qu'à regarder lequel obtient un défi.
    let (corps, code) = poster(
        "/v1/sessions/challenge",
        r#"{"login":"marie","deviceId":"appareil-qui-n-existe-pas"}"#,
        None,
    );
    assert_eq!(code, "201", "{corps}");
    let (corps, code) = poster(
        "/v1/sessions/challenge",
        r#"{"login":"compte-qui-n-existe-pas","deviceId":"a1"}"#,
        None,
    );
    assert_eq!(code, "201", "{corps}");
    // Mais il ne mène nulle part : la signature ne peut pas correspondre.
    let inconnu = champ(&corps, "challenge");
    let (_, code) = poster(
        "/v1/sessions",
        &format!(r#"{{"challenge":"{inconnu}","signature":"{signature}"}}"#),
        None,
    );
    assert_eq!(code, "401");

    // ── ET UNE SIGNATURE FAUSSE SUR UN DÉFI FRAIS ÉCHOUE ────────────────────
    let (corps, _) = poster(
        "/v1/sessions/challenge",
        &format!(r#"{{"login":"marie","deviceId":"{appareil}"}}"#),
        None,
    );
    let frais = champ(&corps, "challenge");
    let (_, code) = poster(
        "/v1/sessions",
        &format!(r#"{{"challenge":"{frais}","signature":"{signature}"}}"#),
        None,
    );
    assert_eq!(
        code, "401",
        "une signature d'un AUTRE défi ne doit pas passer"
    );

    // ── L'ABONNEMENT AUX NOTIFICATIONS, PAR LA SESSION DE L'APPAREIL ──────
    //
    // `jeton` a été ouvert par la clef : c'est lui qui désigne l'appareil. Un
    // jeton ouvert par mot de passe n'en désigne aucun.
    let appeler = |verbe: &str, chemin: &str, corps: &str, avec: &str| -> (String, String) {
        let mut commande = std::process::Command::new("curl");
        commande
            .args(["-s", "-S", "--insecure", "--http2", "-X", verbe])
            .args(["-H", &format!("Authorization: Bearer {avec}")])
            .args(["-w", "\n%{http_code}"]);
        if !corps.is_empty() {
            commande
                .args(["-H", "Content-Type: application/json"])
                .args(["-d", corps]);
        }
        let sortie = commande
            .arg(format!("{base}{chemin}"))
            .output()
            .expect("curl s'exécute");
        let tout = reponse_de_curl(&serveur, &sortie);
        let (corps, code) = tout.rsplit_once('\n').unwrap_or(("", ""));
        (corps.to_string(), code.to_string())
    };
    let (corps, code) = appeler("GET", "/v1/me/push", "", &jeton);
    assert_eq!(
        (code.as_str(), corps.as_str()),
        ("200", r#"{"push":null,"vapidKey":null}"#)
    );
    let apns = "ab".repeat(32);
    let (corps, code) = appeler(
        "PUT",
        "/v1/me/push",
        &format!(r#"{{"channel":"apns","token":"{apns}"}}"#),
        &jeton,
    );
    assert_eq!(code, "200", "{corps}");
    assert!(corps.contains(r#""channel":"apns""#), "{corps}");
    assert!(!corps.contains(&apns), "le jeton ne revient pas : {corps}");
    let (corps, _) = appeler("GET", "/v1/me/devices", "", &jeton);
    assert!(corps.contains(r#""push":"apns""#), "{corps}");
    // **LE SERVEUR NE POSTERA PAS VERS L'INTÉRIEUR.**
    let cle = en_base64url(&cle_publique());
    let (corps, code) = appeler(
        "PUT",
        "/v1/me/push",
        &format!(
            r#"{{"channel":"webpush","endpoint":"https://10.0.0.1/x","keys":{{"p256dh":"{cle}","auth":"AAAAAAAAAAAAAAAAAAAAAA"}}}}"#
        ),
        &jeton,
    );
    assert_eq!(code, "400", "{corps}");
    let (corps, code) = appeler(
        "PUT",
        "/v1/me/push",
        &format!(
            r#"{{"channel":"webpush","endpoint":"https://push.example.com/x","keys":{{"p256dh":"{cle}","auth":"AAAAAAAAAAAAAAAAAAAAAA"}}}}"#
        ),
        &jeton,
    );
    assert_eq!(code, "200", "{corps}");
    assert!(corps.contains(r#""channel":"webpush""#), "{corps}");
    // Un canal qu'on ne connaît pas.
    let (_, code) = appeler(
        "PUT",
        "/v1/me/push",
        r#"{"channel":"sms","token":"x"}"#,
        &jeton,
    );
    assert_eq!(code, "400");
    // **UNE SESSION PAR MOT DE PASSE N'A PAS D'APPAREIL** : `409`.
    let (corps, _) = poster(
        "/v1/tokens",
        r#"{"login":"marie","password":"secret-initial"}"#,
        None,
    );
    let par_mot_de_passe = champ(&corps, "token");
    for (verbe, corps) in [
        ("GET", ""),
        ("PUT", r#"{"channel":"fcm","token":"x"}"#),
        ("DELETE", ""),
    ] {
        let (dit, code) = appeler(verbe, "/v1/me/push", corps, &par_mot_de_passe);
        assert_eq!(code, "409", "{verbe} : {dit}");
    }
    let (_, code) = appeler("DELETE", "/v1/me/push", "", &jeton);
    assert_eq!(code, "204");
    let (corps, _) = appeler("GET", "/v1/me/push", "", &jeton);
    assert_eq!(corps, r#"{"push":null,"vapidKey":null}"#);

    // ── RÉVOQUER L'APPAREIL FERME SES SESSIONS, SUR-LE-CHAMP ─────────────
    let (_, code) = appeler(
        "DELETE",
        &format!("/v1/me/devices/{appareil}"),
        "",
        &par_mot_de_passe,
    );
    assert_eq!(code, "204");
    let (_, code) = appeler("GET", "/v1/mailboxes", "", &jeton);
    assert_eq!(
        code, "401",
        "le jeton d'un appareil révoqué ne doit plus rien ouvrir"
    );
    // Celui du mot de passe, lui, vit toujours.
    let (_, code) = appeler("GET", "/v1/mailboxes", "", &par_mot_de_passe);
    assert_eq!(code, "200");

    // ── UN COMPTE RETIRÉ EMPORTE SES APPAREILS ET SES SESSIONS ────────────
    //
    // Réenrôlé, l'appareil rouvre une session ; puis le compte est retiré et
    // recréé sous le même nom. **L'ANCIENNE CLEF NE DOIT PAS OUVRIR LE NOUVEAU
    // COMPTE**, ni l'ancien jeton valoir encore.
    let (corps, _) = poster(
        "/v1/invitations",
        r#"{"login":"marie"}"#,
        Some(&format!("Authorization: Bearer {admin}")),
    );
    let invitation = champ(&corps, "invitation");
    let (corps, code) = poster(
        "/v1/devices",
        &format!(
            r#"{{"invitation":"{invitation}","publicKey":"{}","name":"le retour"}}"#,
            en_base64url(&cle_publique())
        ),
        None,
    );
    assert_eq!(code, "201", "{corps}");
    let revenu = champ(&corps, "id");
    let ouvrir_par_la_clef = |id: &str| -> (String, String) {
        let (corps, _) = poster(
            "/v1/sessions/challenge",
            &format!(r#"{{"login":"marie","deviceId":"{id}"}}"#),
            None,
        );
        let defi = champ(&corps, "challenge");
        let mut a_signer = Vec::new();
        for (rang, morceau) in ["ams-session", "mail.example.com", defi.as_str()]
            .iter()
            .enumerate()
        {
            if rang > 0 {
                a_signer.push(0);
            }
            a_signer.extend_from_slice(morceau.as_bytes());
        }
        let signature = signer(&ams_sasl::sha256(&a_signer));
        poster(
            "/v1/sessions",
            &format!(r#"{{"challenge":"{defi}","signature":"{signature}"}}"#),
            None,
        )
    };
    let (corps, code) = ouvrir_par_la_clef(&revenu);
    assert_eq!(code, "201", "{corps}");
    let jeton_revenu = champ(&corps, "token");
    let (_, code) = appeler("DELETE", "/v1/accounts/marie", "", &admin);
    assert_eq!(code, "204");
    let (_, code) = appeler("GET", "/v1/mailboxes", "", &jeton_revenu);
    assert_eq!(code, "401", "le jeton d'un compte retiré ne vaut plus");
    let (_, code) = appeler("GET", "/v1/mailboxes", "", &par_mot_de_passe);
    assert_eq!(code, "401", "ni celui de son mot de passe");
    let (corps, code) = appeler(
        "PUT",
        "/v1/accounts/marie",
        r#"{"password":"un-tout-autre-secret","addresses":["marie@example.com"]}"#,
        &admin,
    );
    assert_eq!(code, "201", "{corps}");
    let (corps, code) = ouvrir_par_la_clef(&revenu);
    assert_eq!(
        code, "401",
        "l'ancienne clef ne doit pas ouvrir le compte recréé : {corps}"
    );
}

/// **UN APPAREIL ENRÔLÉ EN APPROUVE UN AUTRE, ET UN JETON N'Y SUFFIT PAS.**
///
/// # CE QUE CET ESSAI ÉPROUVE, ET QU'AUCUN AUTRE NE PEUT
///
/// L'appairage croisé, de bout en bout, avec de VRAIES signatures ECDSA P-256 :
/// un premier appareil arrivé par invitation en approuve un second, sans que
/// l'exploitant intervienne et sans révoquer quoi que ce soit.
///
/// # ET IL ÉPROUVE LA SÉPARATION DES RÔLES, QUI EST LE CŒUR DU DISPOSITIF
///
/// Une signature obtenue pour **ouvrir une session** ne doit pas valoir pour
/// **approuver un appairage**. Sans cette séparation, une application qui
/// demande « ouvre ma boîte » à son propriétaire obtiendrait de quoi lui ajouter
/// un appareil permanent — et le propriétaire n'aurait rien vu d'autre qu'une
/// invite biométrique ordinaire.
#[test]
fn un_appareil_enrole_en_approuve_un_autre() {
    let atelier = atelier("appairage");
    let Some((cert, cle)) = paire(&atelier.0) else {
        panic!("{SANS_OPENSSL}");
    };
    if std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("IGNORÉ : `curl` est absent — cet essai n'a RIEN éprouvé.");
        return;
    }

    let empreinte =
        ams_auth::hash_password(b"secret-initial", b"seize octets ici").expect("hachable");
    let magasin = atelier.0.join("comptes.bin");
    std::fs::write(
        &magasin,
        ams_config::encode_accounts(&[ams_auth::Account {
            login: String::from("marie"),
            hash: empreinte,
            addresses: vec![String::from("marie@example.com")],
        }])
        .expect("encodable"),
    )
    .expect("le magasin s'écrit");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&magasin, std::fs::Permissions::from_mode(0o600))
            .expect("permissions du magasin");
    }

    let appareils = atelier.0.join("appareils.bin");
    let port_smtp = port_libre();
    let port_http = port_libre();
    let config = configuration_complete(
        &atelier,
        port_smtp,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        &magasin.display().to_string(),
        &appareils.display().to_string(),
        "",
        &format!("127.0.0.1:{port_http}"),
        "",
        CLEF,
    );
    let serveur = lancer_avec_api(&config, port_smtp, port_http);
    let base = format!("https://127.0.0.1:{port_http}");

    let poster = |chemin: &str, corps: &str, entete: Option<&str>| -> (String, String) {
        let mut commande = std::process::Command::new("curl");
        commande
            .args(["-s", "-S", "--insecure", "--http2", "-X", "POST"])
            .args(["-H", "Content-Type: application/json"])
            .args(["-d", corps])
            .args(["-w", "\n%{http_code}"]);
        if let Some(valeur) = entete {
            commande.args(["-H", valeur]);
        }
        let sortie = commande
            .arg(format!("{base}{chemin}"))
            .output()
            .expect("curl s'exécute");
        let tout = reponse_de_curl(&serveur, &sortie);
        let (corps, code) = tout.rsplit_once('\n').unwrap_or(("", ""));
        (corps.to_string(), code.to_string())
    };
    let champ = |corps: &str, nom: &str| -> String {
        corps
            .split_once(&format!("\"{nom}\":\""))
            .and_then(|(_, reste)| reste.split_once('"'))
            .map(|(valeur, _)| valeur.to_string())
            .unwrap_or_else(|| panic!("`{nom}` dans {corps}"))
    };

    // ── LE PREMIER APPAREIL, PAR INVITATION ─────────────────────────────────
    let admin = jeton_d_administration();
    let (corps, code) = poster(
        "/v1/invitations",
        r#"{"login":"marie"}"#,
        Some(&format!("Authorization: Bearer {admin}")),
    );
    assert_eq!(code, "201", "{corps}");
    let invitation = champ(&corps, "invitation");
    let (corps, code) = poster(
        "/v1/devices",
        &format!(
            r#"{{"invitation":"{invitation}","publicKey":"{}","name":"le telephone"}}"#,
            en_base64url(&cle_publique_de(7))
        ),
        None,
    );
    assert_eq!(code, "201", "{corps}");
    let telephone = champ(&corps, "id");

    // **UN JETON ORDINAIRE, PAR MOT DE PASSE.** Il suffit à atteindre la route,
    // et c'est précisément ce que l'essai doit montrer : il ne suffit PAS à
    // appairer.
    let (corps, code) = poster(
        "/v1/tokens",
        r#"{"login":"marie","password":"secret-initial"}"#,
        None,
    );
    assert_eq!(code, "201", "{corps}");
    let jeton = champ(&corps, "token");
    let porteur = format!("Authorization: Bearer {jeton}");

    // Obtient un défi pour cet appareil, sous cet usage.
    let defi_pour = |appareil: &str, usage: &str| -> (String, String) {
        let (corps, code) = poster(
            "/v1/sessions/challenge",
            &format!(r#"{{"login":"marie","deviceId":"{appareil}","purpose":"{usage}"}}"#),
            None,
        );
        assert_eq!(code, "201", "{corps}");
        (champ(&corps, "challenge"), champ(&corps, "role"))
    };

    // ── L'APPAIRAGE ─────────────────────────────────────────────────────────
    let (defi, role) = defi_pour(&telephone, "pairing");
    assert_eq!(role, "ams-pairing", "l'usage doit choisir le rôle");
    let signature = signer_avec(
        &cle_privee_de(7),
        &condensat_d_appairage("mail.example.com", &defi, &identifiant_de(9)),
    );
    let (corps, code) = poster(
        "/v1/me/devices",
        &format!(
            r#"{{"challenge":"{defi}","signature":"{signature}","publicKey":"{}","name":"la tablette"}}"#,
            en_base64url(&cle_publique_de(9))
        ),
        Some(&porteur),
    );
    assert_eq!(code, "201", "l'appairage doit aboutir : {corps}");
    let tablette = champ(&corps, "id");
    assert_ne!(tablette, telephone);

    // **LES DEUX APPAREILS SONT LÀ**, et le premier n'a pas été révoqué.
    let sortie = std::process::Command::new("curl")
        .args(["-s", "-S", "--insecure", "--http2"])
        .args(["-H", &porteur])
        .arg(format!("{base}/v1/me/devices"))
        .output()
        .expect("curl s'exécute");
    let liste = reponse_de_curl(&serveur, &sortie);
    assert!(liste.contains(&telephone), "{liste}");
    assert!(liste.contains(&tablette), "{liste}");
    assert!(liste.contains("la tablette"), "{liste}");

    // ── LA SÉPARATION DES RÔLES ─────────────────────────────────────────────
    //
    // La tablette vient d'être enrôlée : sa date de dernière session vaut zéro,
    // donc un défi frais lui est recevable. **Le seul motif de refus possible
    // est le rôle**, et c'est ce qui rend cet essai concluant.
    let (defi, _) = defi_pour(&tablette, "pairing");
    let a_tort = signer_avec(
        &cle_privee_de(9),
        // Le rôle d'une SESSION, sur un défi d'appairage.
        &condensat_a_signer("ams-session", "mail.example.com", &defi),
    );
    let (corps, code) = poster(
        "/v1/me/devices",
        &format!(
            r#"{{"challenge":"{defi}","signature":"{a_tort}","publicKey":"{}","name":"le poste"}}"#,
            en_base64url(&cle_publique_de(11))
        ),
        Some(&porteur),
    );
    assert_eq!(
        code, "401",
        "une signature de SESSION ne doit pas approuver un appairage : {corps}"
    );

    // **ET LA MÊME DEMANDE, AVEC LE BON RÔLE, ABOUTIT.** Sans ce second volet,
    // l'essai ci-dessus prouverait seulement que quelque chose a échoué.
    let (defi, _) = defi_pour(&tablette, "pairing");
    let comme_il_faut = signer_avec(
        &cle_privee_de(9),
        &condensat_d_appairage("mail.example.com", &defi, &identifiant_de(11)),
    );

    // ── LA SIGNATURE COUVRE CE QU'ELLE APPROUVE ─────────────────────────────
    //
    // La tablette a signé pour LE POSTE. La même signature, présentée avec une
    // AUTRE clef, doit se refuser : sans quoi qui la détient avec un jeton
    // enrôlerait ce qu'il veut, et la confirmation d'empreinte ne garantirait
    // rien. Le refus ne consomme pas le défi — d'où le second volet, qui
    // réussit avec la MÊME signature et la bonne clef.
    let (corps, code) = poster(
        "/v1/me/devices",
        &format!(
            r#"{{"challenge":"{defi}","signature":"{comme_il_faut}","publicKey":"{}","name":"un intrus"}}"#,
            en_base64url(&cle_publique_de(13))
        ),
        Some(&porteur),
    );
    assert_eq!(
        code, "401",
        "une signature d'appairage ne doit valoir que pour la clef approuvée : {corps}"
    );
    let (corps, code) = poster(
        "/v1/me/devices",
        &format!(
            r#"{{"challenge":"{defi}","signature":"{comme_il_faut}","publicKey":"{}","name":"le poste"}}"#,
            en_base64url(&cle_publique_de(11))
        ),
        Some(&porteur),
    );
    assert_eq!(code, "201", "{corps}");

    // ── UN APPAIRAGE REFUSÉ NE CONSOMME RIEN ────────────────────────────────
    //
    // La tablette approuve une clef DÉJÀ enrôlée : la signature est bonne, la
    // demande n'a pas de sens, et c'est un `409`. **Son défi n'est pas
    // consommé**, et la session qu'elle ouvre AUSSITÔT — sans la moindre
    // attente — doit aboutir. En 0.2.13, la preuve écrivait la date avant que
    // le doublon ne se découvre, et cette session se prenait pour un rejeu.
    let (defi, _) = defi_pour(&tablette, "pairing");
    let signature = signer_avec(
        &cle_privee_de(9),
        &condensat_d_appairage("mail.example.com", &defi, &identifiant_de(7)),
    );
    let (corps, code) = poster(
        "/v1/me/devices",
        &format!(
            r#"{{"challenge":"{defi}","signature":"{signature}","publicKey":"{}","name":"encore"}}"#,
            en_base64url(&cle_publique_de(7))
        ),
        Some(&porteur),
    );
    assert_eq!(code, "409", "la clef du téléphone est déjà là : {corps}");

    // **DEUX SESSIONS D'AFFILÉE, SANS ATTENDRE.** La date de dernière session
    // compte en millisecondes : la seconde n'est plus prise pour un rejeu de la
    // première, même si les deux tombent dans la même seconde.
    for fois in ["la première", "la seconde"] {
        let (defi, role) = defi_pour(&tablette, "session");
        assert_eq!(role, "ams-session");
        let signature = signer_avec(
            &cle_privee_de(9),
            &condensat_a_signer(&role, "mail.example.com", &defi),
        );
        let (corps, code) = poster(
            "/v1/sessions",
            &format!(r#"{{"challenge":"{defi}","signature":"{signature}"}}"#),
            None,
        );
        assert_eq!(code, "201", "{fois} session doit s'ouvrir : {corps}");
    }

    // ── ET LE DISQUE PORTE LES TROIS ────────────────────────────────────────
    let relu = ams_config::decode_devices(&std::fs::read(&appareils).expect("lisible"))
        .expect("relisible");
    assert_eq!(relu.len(), 3);
    assert!(relu.iter().all(|connu| connu.login == "marie"));
}

/// **UN APPAIRAGE SANS PREUVE DE CLEF SE REFUSE, JETON VALIDE OU NON.**
///
/// C'est la propriété qui justifie toute la conception : un jeton vaut quinze
/// minutes, une clef vaut jusqu'à sa révocation. Si un porteur suffisait, un vol
/// de quinze minutes deviendrait un accès permanent — que fermer la session ne
/// retirerait même pas.
#[test]
fn un_jeton_seul_n_appaire_rien() {
    let atelier = atelier("appairage-refus");
    let Some((cert, cle)) = paire(&atelier.0) else {
        panic!("{SANS_OPENSSL}");
    };
    if std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("IGNORÉ : `curl` est absent — cet essai n'a RIEN éprouvé.");
        return;
    }

    let empreinte =
        ams_auth::hash_password(b"secret-initial", b"seize octets ici").expect("hachable");
    let magasin = atelier.0.join("comptes.bin");
    std::fs::write(
        &magasin,
        ams_config::encode_accounts(&[ams_auth::Account {
            login: String::from("marie"),
            hash: empreinte,
            addresses: vec![String::from("marie@example.com")],
        }])
        .expect("encodable"),
    )
    .expect("le magasin s'écrit");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&magasin, std::fs::Permissions::from_mode(0o600))
            .expect("permissions du magasin");
    }

    let appareils = atelier.0.join("appareils.bin");
    let port_smtp = port_libre();
    let port_http = port_libre();
    let config = configuration_complete(
        &atelier,
        port_smtp,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        &magasin.display().to_string(),
        &appareils.display().to_string(),
        "",
        &format!("127.0.0.1:{port_http}"),
        "",
        CLEF,
    );
    let serveur = lancer_avec_api(&config, port_smtp, port_http);
    let base = format!("https://127.0.0.1:{port_http}");

    let sortie = std::process::Command::new("curl")
        .args(["-s", "-S", "--insecure", "--http2", "-X", "POST"])
        .args(["-H", "Content-Type: application/json"])
        .args(["-d", r#"{"login":"marie","password":"secret-initial"}"#])
        .arg(format!("{base}/v1/tokens"))
        .output()
        .expect("curl s'exécute");
    let corps = reponse_de_curl(&serveur, &sortie);
    let jeton = corps
        .split_once("\"token\":\"")
        .and_then(|(_, reste)| reste.split_once('"'))
        .map(|(v, _)| v.to_string())
        .unwrap_or_else(|| panic!("un jeton dans {corps}"));

    let appairer = |corps: &str| -> String {
        let sortie = std::process::Command::new("curl")
            .args(["-s", "-S", "--insecure", "--http2", "-X", "POST"])
            .args(["-H", "Content-Type: application/json"])
            .args(["-H", &format!("Authorization: Bearer {jeton}")])
            .args(["-d", corps])
            .args(["-o", "/dev/null", "-w", "%{http_code}"])
            .arg(format!("{base}/v1/me/devices"))
            .output()
            .expect("curl s'exécute");
        reponse_de_curl(&serveur, &sortie)
    };

    let clef = en_base64url(&cle_publique_de(9));
    // **AUCUN APPAREIL N'EST ENRÔLÉ** : il n'existe personne pour approuver.
    assert_eq!(
        appairer(&format!(
            r#"{{"challenge":"AAAAAAAAAAAAAAAAAAAAAA","signature":"AQID","publicKey":"{clef}"}}"#
        )),
        "401",
        "un défi forgé ne doit rien approuver"
    );
    // Un corps sans défi ni signature se refuse aussi, et par le corps.
    assert_eq!(appairer(&format!(r#"{{"publicKey":"{clef}"}}"#)), "400");

    // **ET RIEN N'A ÉTÉ POSÉ** : un refus ne laisse pas de magasin derrière lui.
    assert!(!appareils.exists(), "un refus ne doit rien écrire");
}

/// **UN MOT DE PASSE POSÉ PAR L'API REDÉRIVE SON VÉRIFICATEUR SCRAM, ET
/// L'ANCIEN NE S'OUVRE PLUS.**
///
/// # LE DÉFAUT QUE CET ESSAI GARDE FERMÉ
///
/// Jusqu'en 0.2.15, `PUT /v1/me/password` réécrivait l'empreinte du compte et
/// laissait le magasin SCRAM intact : **l'ancien mot de passe ouvrait encore la
/// boîte par SCRAM**, que Thunderbird choisit. On ouvre donc le vérificateur
/// écrit, sous l'empreinte que le compte porte APRÈS, et l'on vérifie qu'il
/// correspond au NOUVEAU mot de passe — et que celui d'avant, lié à l'ancienne
/// empreinte, ne s'ouvre plus.
#[test]
fn un_mot_de_passe_pose_par_l_api_rederive_son_verificateur_scram() {
    let atelier = atelier("api-scram");
    let Some((cert, cle)) = paire(&atelier.0) else {
        panic!("{SANS_OPENSSL}");
    };
    if std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("IGNORÉ : `curl` est absent — cet essai n'a RIEN éprouvé.");
        return;
    }

    const CLEF_SCRAM: [u8; 32] = [5; 32];
    let empreinte =
        ams_auth::hash_password(b"secret-initial", b"seize octets ici").expect("hachable");
    let magasin = atelier.0.join("comptes.bin");
    std::fs::write(
        &magasin,
        ams_config::encode_accounts(&[ams_auth::Account {
            login: String::from("marie"),
            hash: empreinte.clone(),
            addresses: vec![String::from("marie@example.com")],
        }])
        .expect("encodable"),
    )
    .expect("le magasin s'écrit");
    let chemin_clef = atelier.0.join("scram.key");
    let chemin_scram = atelier.0.join("scram.bin");
    let ancien = ams_auth::scram_deriver(
        b"secret-initial",
        "marie",
        &empreinte,
        [3; 16],
        4_096,
        [9; 12],
        &CLEF_SCRAM,
    )
    .expect("dérivation");
    std::fs::write(&chemin_clef, CLEF_SCRAM).expect("clé");
    std::fs::write(
        &chemin_scram,
        ams_config::encode_scram(std::slice::from_ref(&ancien)).expect("encodage"),
    )
    .expect("magasin SCRAM");
    {
        use std::os::unix::fs::PermissionsExt as _;
        for fichier in [&magasin, &chemin_clef, &chemin_scram] {
            std::fs::set_permissions(fichier, std::fs::Permissions::from_mode(0o600))
                .expect("permissions");
        }
    }

    let port_smtp = port_libre();
    let port_http = port_libre();
    let config = configuration_complete(
        &atelier,
        port_smtp,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        &magasin.display().to_string(),
        "",
        "",
        &format!("127.0.0.1:{port_http}"),
        "",
        CLEF,
    );
    // Ce banc-ci SERT SCRAM : on rouvre la configuration pour le lui dire.
    let mut lue = ams_config::decode(&std::fs::read(&config).expect("config")).expect("décodable");
    lue.scram_key = chemin_clef.display().to_string();
    lue.scram_store = chemin_scram.display().to_string();
    std::fs::write(&config, ams_config::encode(&lue).expect("encodable")).expect("écriture");
    let serveur = lancer_avec_api(&config, port_smtp, port_http);
    let base = format!("https://127.0.0.1:{port_http}");

    let sortie = std::process::Command::new("curl")
        .args(["-s", "-S", "--insecure", "--http2"])
        .args(["-H", "Content-Type: application/json"])
        .args(["-d", r#"{"login":"marie","password":"secret-initial"}"#])
        .arg(format!("{base}/v1/tokens"))
        .output()
        .expect("curl s'exécute");
    let corps = reponse_de_curl(&serveur, &sortie);
    let jeton = corps
        .split_once("\"token\":\"")
        .and_then(|(_, reste)| reste.split_once('"'))
        .map(|(jeton, _)| jeton.to_string())
        .unwrap_or_else(|| panic!("un jeton dans {corps}"));

    // Pose un secret par cette route, avec ce jeton, et rend le code.
    let poser = |jeton: &str, chemin: &str, corps_json: &str| -> String {
        let sortie = std::process::Command::new("curl")
            .args(["-s", "-S", "--insecure", "--http2", "-X", "PUT"])
            .args(["-H", &format!("Authorization: Bearer {jeton}")])
            .args(["-H", "Content-Type: application/json"])
            .args(["-d", corps_json])
            .args(["-o", "/dev/null", "-w", "%{http_code}"])
            .arg(format!("{base}{chemin}"))
            .output()
            .expect("curl s'exécute");
        reponse_de_curl(&serveur, &sortie)
    };
    // Le vérificateur de marie, ouvert sous l'empreinte que son compte porte
    // MAINTENANT ; et la StoredKey que ce mot de passe produirait avec son sel.
    let constater = |mot_de_passe: &[u8]| {
        let comptes = ams_config::decode_accounts(&std::fs::read(&magasin).expect("comptes"))
            .expect("comptes");
        let actuelle = &comptes.first().expect("marie").hash;
        let verificateurs =
            ams_config::decode_scram(&std::fs::read(&chemin_scram).expect("scram")).expect("scram");
        assert_eq!(verificateurs.len(), 1, "remplacé, et non ajouté");
        let v = verificateurs.first().expect("un vérificateur");
        let cles = ams_auth::scram_ouvrir(v, actuelle, &CLEF_SCRAM)
            .expect("le vérificateur neuf s'ouvre sous l'empreinte du compte");
        let salted = ams_sasl::derive_salted_password(mot_de_passe, &v.sel, v.iterations);
        assert_eq!(
            cles.stored,
            ams_sasl::stored_key(&ams_sasl::client_key(&salted)),
            "le vérificateur ne suit pas le nouveau mot de passe"
        );
        assert_eq!(
            ams_auth::scram_ouvrir(&ancien, actuelle, &CLEF_SCRAM),
            Err(ams_auth::ScramError::Sceau),
            "L'ANCIEN VÉRIFICATEUR S'OUVRE ENCORE : l'ancien mot de passe passerait par SCRAM"
        );
    };

    // ── PAR L'UTILISATEUR LUI-MÊME ──────────────────────────────────────────
    assert_eq!(
        poser(
            &jeton,
            "/v1/me/password",
            r#"{"current_password":"secret-initial","password":"nouveau-secret"}"#
        ),
        "204"
    );
    constater(b"nouveau-secret");

    // ── PAR L'ADMINISTRATION ────────────────────────────────────────────────
    assert_eq!(
        poser(
            &jeton_d_administration(),
            "/v1/accounts/marie/password",
            r#"{"password":"pose-par-l-admin"}"#
        ),
        "204"
    );
    constater(b"pose-par-l-admin");
}

/// **LE CYCLE D'UN MOT DE PASSE APPLICATIF, DE BOUT EN BOUT, PAR LE VRAI
/// SERVEUR** : créé par l'API, employé par un vrai client de courrier en SMTP,
/// refusé par l'API elle-même, puis révoqué — et le client est aussitôt
/// refusé.
///
/// # CE QUE CET ESSAI ÉPROUVE, ET QU'AUCUN AUTRE NE PEUT
///
/// Que SMTP passe bien par la vérification qui connaît les mots de passe
/// applicatifs, et que l'API REST, elle, ne les connaît pas : sans ce second
/// volet, le client de courrier d'un poste perdu pourrait créer d'autres
/// mots de passe, et le révoquer ne suffirait plus.
#[test]
fn un_mot_de_passe_applicatif_ouvre_smtp_et_pas_l_api() {
    let atelier = atelier("api-applicatifs");
    let Some((cert, cle)) = paire(&atelier.0) else {
        panic!("{SANS_OPENSSL}");
    };
    if std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("IGNORÉ : `curl` est absent — cet essai n'a RIEN éprouvé.");
        return;
    }

    let empreinte =
        ams_auth::hash_password(b"secret-initial", b"seize octets ici").expect("hachable");
    let magasin = atelier.0.join("comptes.bin");
    std::fs::write(
        &magasin,
        ams_config::encode_accounts(&[ams_auth::Account {
            login: String::from("marie"),
            hash: empreinte,
            addresses: vec![String::from("marie@example.com")],
        }])
        .expect("encodable"),
    )
    .expect("le magasin s'écrit");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&magasin, std::fs::Permissions::from_mode(0o600))
            .expect("permissions");
    }
    let applicatifs = atelier.0.join("applicatifs.bin");

    let port_smtp = port_libre();
    let port_http = port_libre();
    let config = configuration_complete(
        &atelier,
        port_smtp,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        &magasin.display().to_string(),
        "",
        "",
        &format!("127.0.0.1:{port_http}"),
        "",
        CLEF,
    );
    let mut lue = ams_config::decode(&std::fs::read(&config).expect("config")).expect("décodable");
    lue.app_passwords = applicatifs.display().to_string();
    std::fs::write(&config, ams_config::encode(&lue).expect("encodable")).expect("écriture");
    let serveur = lancer_avec_api(&config, port_smtp, port_http);
    let base = format!("https://127.0.0.1:{port_http}");

    // Un appel HTTP, et rend (corps, code).
    let appeler = |methode: &str, chemin: &str, corps: Option<&str>, jeton: Option<&str>| {
        let mut commande = std::process::Command::new("curl");
        commande
            .args(["-s", "-S", "--insecure", "--http2", "-X", methode])
            .args(["-w", "\n%{http_code}"]);
        if let Some(corps) = corps {
            commande
                .args(["-H", "Content-Type: application/json"])
                .args(["-d", corps]);
        }
        if let Some(jeton) = jeton {
            commande.args(["-H", &format!("Authorization: Bearer {jeton}")]);
        }
        let sortie = commande
            .arg(format!("{base}{chemin}"))
            .output()
            .expect("curl s'exécute");
        let tout = reponse_de_curl(&serveur, &sortie);
        let (corps, code) = tout.rsplit_once('\n').unwrap_or(("", ""));
        (corps.to_string(), code.to_string())
    };
    let champ = |corps: &str, nom: &str| -> String {
        corps
            .split_once(&format!("\"{nom}\":\""))
            .and_then(|(_, reste)| reste.split_once('"'))
            .map(|(valeur, _)| valeur.to_string())
            .unwrap_or_else(|| panic!("`{nom}` dans {corps}"))
    };
    // Soumet une lettre en SMTP avec ce secret, et dit si curl a abouti.
    let lettre = atelier.0.join("lettre.eml");
    std::fs::write(
        &lettre,
        "From: <marie@example.com>\r\nSubject: par Thunderbird\r\n\r\ncorps\r\n",
    )
    .expect("écriture");
    let soumettre = |secret: &str| -> bool {
        std::process::Command::new("curl")
            .args(["-s", "-S", "--insecure", "--ssl-reqd"])
            .args(["-u", &format!("marie:{secret}")])
            .args(["--mail-from", "marie@example.com"])
            .args(["--mail-rcpt", "marie@example.com"])
            .arg("-T")
            .arg(&lettre)
            .arg(format!("smtp://127.0.0.1:{port_smtp}"))
            .output()
            .expect("curl s'exécute")
            .status
            .success()
    };

    // ── CRÉÉ PAR L'API, AVEC UN JETON DE MOT DE PASSE ───────────────────────
    let (corps, code) = appeler(
        "POST",
        "/v1/tokens",
        Some(r#"{"login":"marie","password":"secret-initial"}"#),
        None,
    );
    assert_eq!(code, "201", "{corps}");
    let jeton = champ(&corps, "token");
    let (corps, code) = appeler(
        "POST",
        "/v1/me/app-passwords",
        Some(r#"{"name":"Thunderbird — bureau"}"#),
        Some(&jeton),
    );
    assert_eq!(code, "201", "{corps}");
    let secret = champ(&corps, "password");
    let id = champ(&corps, "id");
    assert!(secret.starts_with("amsp-"), "{secret}");
    assert!(
        corps.contains("Thunderbird \u{2014} bureau"),
        "le nom échappé doit se lire : {corps}"
    );

    // La liste le montre — nom, dates —, et JAMAIS le secret.
    let (liste, code) = appeler("GET", "/v1/me/app-passwords", None, Some(&jeton));
    assert_eq!(code, "200", "{liste}");
    assert!(liste.contains(&id), "{liste}");
    assert!(liste.contains("\"lastUsedAt\":0"), "{liste}");
    assert!(
        !liste.contains("amsp-"),
        "LE SECRET SORT DE LA LISTE : {liste}"
    );

    // ── UN VRAI CLIENT DE COURRIER S'EN SERT ────────────────────────────────
    assert!(
        soumettre(&secret),
        "le mot de passe applicatif doit ouvrir SMTP"
    );
    assert!(soumettre("secret-initial"), "le principal reste valable");
    // Et sa dernière utilisation est notée.
    let (liste, _) = appeler("GET", "/v1/me/app-passwords", None, Some(&jeton));
    assert!(!liste.contains("\"lastUsedAt\":0"), "{liste}");

    // ── IL N'OUVRE PAS L'API ────────────────────────────────────────────────
    let (corps, code) = appeler(
        "POST",
        "/v1/tokens",
        Some(&format!(r#"{{"login":"marie","password":"{secret}"}}"#)),
        None,
    );
    assert_eq!(
        code, "401",
        "UN MOT DE PASSE APPLICATIF OUVRE L'API : un poste perdu fabriquerait des accès — {corps}"
    );

    // ── ET UN MOT DE PASSE PRINCIPAL NE PREND PAS SA FORME ──────────────────
    let (corps, code) = appeler(
        "PUT",
        "/v1/me/password",
        Some(&format!(
            r#"{{"current_password":"secret-initial","password":"{secret}"}}"#
        )),
        Some(&jeton),
    );
    assert_eq!(code, "400", "{corps}");

    // ── RÉVOQUÉ, IL EST REFUSÉ SUR-LE-CHAMP ─────────────────────────────────
    let (_, code) = appeler(
        "DELETE",
        &format!("/v1/me/app-passwords/{id}"),
        None,
        Some(&jeton),
    );
    assert_eq!(code, "204");
    assert!(
        !soumettre(&secret),
        "un mot de passe révoqué ouvre encore SMTP"
    );
    assert!(
        soumettre("secret-initial"),
        "révoquer n'a pas touché au principal"
    );
    let (_, code) = appeler(
        "DELETE",
        &format!("/v1/me/app-passwords/{id}"),
        None,
        Some(&jeton),
    );
    assert_eq!(code, "404", "révoquer deux fois rend 404");
}

/// **UN MESSAGE DE PLUS DE 64 KIO ARRIVE ENTIER, ET AU-DELÀ D'UN MÉBIOCTET
/// IL SE REFUSE** — contre le vrai serveur, par `curl` en HTTP/2.
///
/// Jusqu'à la 0.2.24, HTTP/2 cessait d'écrire le corps au-delà de 64 Kio, et
/// la requête partait avec un corps TRONQUÉ : le message déposé était amputé,
/// sans que rien ne le dise. On dépose ici trois cents kibioctets, et on relit
/// le message brut : il doit revenir à l'octet près.
#[test]
fn un_gros_message_arrive_entier_en_http2() {
    let atelier = atelier("gros-corps");
    let Some((cert, cle)) = paire(&atelier.0) else {
        panic!("{SANS_OPENSSL}");
    };
    if std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("IGNORÉ : `curl` est absent — cet essai n'a RIEN éprouvé.");
        return;
    }
    let empreinte =
        ams_auth::hash_password(b"secret-initial", b"seize octets ici").expect("hachable");
    let magasin = atelier.0.join("comptes.bin");
    std::fs::write(
        &magasin,
        ams_config::encode_accounts(&[ams_auth::Account {
            login: String::from("marie"),
            hash: empreinte,
            addresses: vec![String::from("marie@example.com")],
        }])
        .expect("encodable"),
    )
    .expect("le magasin s'écrit");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&magasin, std::fs::Permissions::from_mode(0o600))
            .expect("permissions du magasin");
    }
    let port_smtp = port_libre();
    let port_http = port_libre();
    let config = configuration_complete(
        &atelier,
        port_smtp,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        &magasin.display().to_string(),
        "",
        "",
        &format!("127.0.0.1:{port_http}"),
        "",
        CLEF,
    );
    let serveur = lancer_avec_api(&config, port_smtp, port_http);
    let base = format!("https://127.0.0.1:{port_http}");

    let sortie = std::process::Command::new("curl")
        .args(["-s", "-S", "--insecure", "--http2"])
        .args(["-H", "Content-Type: application/json"])
        .args(["-d", r#"{"login":"marie","password":"secret-initial"}"#])
        .arg(format!("{base}/v1/tokens"))
        .output()
        .expect("curl s'exécute");
    let corps = reponse_de_curl(&serveur, &sortie);
    let jeton = corps
        .split_once("\"token\":\"")
        .and_then(|(_, reste)| reste.split_once('"'))
        .map(|(jeton, _)| jeton.to_string())
        .unwrap_or_else(|| panic!("un jeton dans {corps} — {}", serveur.journal()));

    // Un message de trois cents kibioctets : des lignes de soixante-dix
    // caractères, comme un corps de courrier ordinaire.
    let fabriquer = |octets: usize| -> Vec<u8> {
        let mut message = b"From: marie@example.com\r\nSubject: gros\r\n\r\n".to_vec();
        let ligne = format!("{}\r\n", "x".repeat(68));
        while message.len() + ligne.len() <= octets {
            message.extend_from_slice(ligne.as_bytes());
        }
        message
    };
    let deposer = |message: &[u8]| -> (String, String) {
        let fichier = atelier.0.join("message.eml");
        std::fs::write(&fichier, message).expect("écrit");
        let sortie = std::process::Command::new("curl")
            .args(["-s", "-S", "--insecure", "--http2"])
            .args(["-H", &format!("Authorization: Bearer {jeton}")])
            .args(["-H", "Content-Type: message/rfc822"])
            .args(["--data-binary", &format!("@{}", fichier.display())])
            .args(["-w", "\n%{http_code} %{http_version}"])
            .arg(format!("{base}/v1/mailboxes/INBOX/messages"))
            .output()
            .expect("curl s'exécute");
        let tout = reponse_de_curl(&serveur, &sortie);
        let (corps, fin) = tout.rsplit_once('\n').unwrap_or(("", ""));
        (corps.to_string(), fin.to_string())
    };

    let gros = fabriquer(300 * 1024);
    let (corps, fin) = deposer(&gros);
    assert_eq!(
        fin,
        "201 2",
        "le dépôt doit réussir : {corps} — {}",
        serveur.journal()
    );
    let uid = corps
        .trim_start_matches("{\"uid\":")
        .trim_end_matches('}')
        .to_string();
    // On relit PAR TRANCHES : au-delà de 64 Kio, la relecture brute exige
    // `Range` (§14) — c'est voulu, et c'est ce que ferait un client.
    let mut relu: Vec<u8> = Vec::new();
    while relu.len() < gros.len() {
        let debut = relu.len();
        let sortie = std::process::Command::new("curl")
            .args(["-s", "-S", "--insecure", "--http2"])
            .args(["-H", &format!("Authorization: Bearer {jeton}")])
            .args(["-r", &format!("{debut}-{}", debut + 64 * 1024 - 1)])
            .arg(format!("{base}/v1/mailboxes/INBOX/messages/{uid}/raw"))
            .output()
            .expect("curl s'exécute");
        // **LA TRANCHE PASSE PAR LE MÊME CONTRÔLE QUE TOUT LE RESTE** : une
        // tranche vide disait seulement « vide à tel rang », sans dire si
        // `curl` avait joint le serveur. Le helper le dit.
        let tranche = reponse_de_curl(&serveur, &sortie);
        assert!(
            !tranche.is_empty(),
            "une tranche vide à {debut} sur {} octets attendus",
            gros.len()
        );
        relu.extend_from_slice(&sortie.stdout);
    }
    assert_eq!(
        relu.len(),
        gros.len(),
        "le message doit revenir ENTIER, et non tronqué à 64 Kio"
    );
    assert!(relu == gros, "et octet pour octet");

    let (corps, fin) = deposer(&fabriquer(1024 * 1024 + 4096));
    assert_eq!(fin, "413 2", "au-delà d'un mébioctet : {corps}");
    assert!(corps.contains("content-too-large"), "{corps}");
}

/// **UN MESSAGE AVEC PIÈCE JOINTE PASSE PAR UN BROUILLON** — contre le vrai
/// serveur, par `curl` en HTTP/2.
///
/// Décision de l'exploitant : le corps d'abord, les pièces jointes ensuite,
/// par morceaux écrits sur disque. D'un seul tenant, un `multipart/mixed` se
/// refuse (`422`) ; par un brouillon, trois morceaux envoyés dans le désordre
/// se rassemblent, et le message composé se range, puis s'envoie.
#[test]
fn un_message_avec_piece_jointe_passe_par_un_brouillon() {
    let atelier = atelier("brouillons");
    let Some((cert, cle)) = paire(&atelier.0) else {
        panic!("{SANS_OPENSSL}");
    };
    if std::process::Command::new("curl")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("IGNORÉ : `curl` est absent — cet essai n'a RIEN éprouvé.");
        return;
    }
    let empreinte =
        ams_auth::hash_password(b"secret-initial", b"seize octets ici").expect("hachable");
    let magasin = atelier.0.join("comptes.bin");
    std::fs::write(
        &magasin,
        ams_config::encode_accounts(&[ams_auth::Account {
            login: String::from("marie"),
            hash: empreinte,
            addresses: vec![String::from("marie@example.com")],
        }])
        .expect("encodable"),
    )
    .expect("le magasin s'écrit");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&magasin, std::fs::Permissions::from_mode(0o600))
            .expect("permissions du magasin");
    }
    let port_smtp = port_libre();
    let port_http = port_libre();
    let chemin = configuration_complete(
        &atelier,
        port_smtp,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        &magasin.display().to_string(),
        "",
        "",
        &format!("127.0.0.1:{port_http}"),
        "",
        CLEF,
    );
    // Le répertoire des brouillons, que `configuration_complete` ne pose pas.
    let mut config =
        ams_config::decode(&std::fs::read(&chemin).expect("lisible")).expect("décodable");
    config.drafts = atelier.0.join("brouillons").display().to_string();
    std::fs::write(&chemin, ams_config::encode(&config).expect("encodable")).expect("écrite");
    let serveur = lancer_avec_api(&chemin, port_smtp, port_http);
    let base = format!("https://127.0.0.1:{port_http}");

    let sortie = std::process::Command::new("curl")
        .args(["-s", "-S", "--insecure", "--http2"])
        .args(["-H", "Content-Type: application/json"])
        .args(["-d", r#"{"login":"marie","password":"secret-initial"}"#])
        .arg(format!("{base}/v1/tokens"))
        .output()
        .expect("curl s'exécute");
    let corps = reponse_de_curl(&serveur, &sortie);
    let jeton = corps
        .split_once("\"token\":\"")
        .and_then(|(_, reste)| reste.split_once('"'))
        .map(|(jeton, _)| jeton.to_string())
        .unwrap_or_else(|| panic!("un jeton dans {corps} — {}", serveur.journal()));

    // Une requête, et rend (corps, code).
    let appeler = |verbe: &str, chemin: &str, type_: &str, extra: &[&str], donnees: &[u8]| {
        let fichier = atelier.0.join("envoi.bin");
        std::fs::write(&fichier, donnees).expect("écrit");
        let mut commande = std::process::Command::new("curl");
        commande
            .args(["-s", "-S", "--insecure", "--http2", "-X", verbe])
            .args(["-H", &format!("Authorization: Bearer {jeton}")])
            .args(["-w", "\n%{http_code}"]);
        if !type_.is_empty() {
            commande
                .args(["-H", &format!("Content-Type: {type_}")])
                .args(["--data-binary", &format!("@{}", fichier.display())]);
        }
        for champ in extra {
            commande.args(["-H", champ]);
        }
        let sortie = commande
            .arg(format!("{base}{chemin}"))
            .output()
            .expect("curl s'exécute");
        let tout = reponse_de_curl(&serveur, &sortie);
        let (corps, code) = tout.rsplit_once('\n').unwrap_or(("", ""));
        (corps.to_string(), code.to_string())
    };

    // ── D'UN SEUL TENANT, UNE PIÈCE JOINTE SE REFUSE ───────────────────────
    let mixte = b"From: marie@example.com\r\nTo: marie@example.com\r\n\
        Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\nx\r\n--b--\r\n";
    let (corps, code) = appeler("POST", "/v1/submissions", "message/rfc822", &[], mixte);
    assert_eq!(code, "422", "{corps}");
    assert!(corps.contains("attachments-need-draft"), "{corps}");

    // ── LE CORPS D'ABORD ────────────────────────────────────────────────────
    let texte = b"From: marie@example.com\r\nTo: marie@example.com\r\nSubject: rapport\r\n\
        Content-Type: text/plain; charset=utf-8\r\n\r\nci-joint le rapport\r\n";
    let creer = || {
        let (corps, code) = appeler("POST", "/v1/drafts", "message/rfc822", &[], texte);
        assert_eq!(code, "201", "{corps} — {}", serveur.journal());
        corps
            .split_once("\"id\":\"")
            .and_then(|(_, reste)| reste.split_once('"'))
            .map(|(id, _)| id.to_string())
            .unwrap_or_else(|| panic!("un identifiant dans {corps}"))
    };
    let id = creer();

    // ── LA PIÈCE JOINTE ENSUITE, PAR MORCEAUX, DANS LE DÉSORDRE ─────────────
    let donnees: Vec<u8> = (0..300_000_u32).map(|i| (i % 253) as u8).collect();
    let (corps, code) = appeler(
        "POST",
        &format!("/v1/drafts/{id}/attachments"),
        "application/json",
        &[],
        // Le nom ÉCHAPPÉ, comme `json.dumps` de Python l'écrirait.
        r#"{"name":"donn\u00e9es.bin","type":"application/octet-stream","size":300000}"#.as_bytes(),
    );
    assert_eq!(code, "201", "{corps}");
    let mut dernier = String::new();
    for debut in [200_000_usize, 0, 100_000] {
        let (corps, code) = appeler(
            "PUT",
            &format!("/v1/drafts/{id}/attachments/1"),
            "application/octet-stream",
            &[&format!(
                "Content-Range: bytes {debut}-{}/300000",
                debut + 99_999
            )],
            &donnees[debut..debut + 100_000],
        );
        assert_eq!(code, "200", "{corps} — {}", serveur.journal());
        dernier = corps;
    }
    assert!(dernier.contains(r#""complete":true"#), "{dernier}");
    let (etat, code) = appeler("GET", &format!("/v1/drafts/{id}"), "", &[], b"");
    assert_eq!(code, "200");
    assert!(etat.contains(r#""received":[[0,299999]]"#), "{etat}");

    // ── RANGÉ DANS UNE BOÎTE, IL SE RELIT ───────────────────────────────────
    let (corps, code) = appeler(
        "POST",
        &format!("/v1/drafts/{id}/store"),
        "application/json",
        &[],
        br#"{"mailbox":"INBOX"}"#,
    );
    assert_eq!(code, "201", "{corps} — {}", serveur.journal());
    let uid = corps
        .trim_start_matches("{\"uid\":")
        .trim_end_matches('}')
        .to_string();
    let mut relu: Vec<u8> = Vec::new();
    loop {
        let debut = relu.len();
        let sortie = std::process::Command::new("curl")
            .args(["-s", "-S", "--insecure", "--http2"])
            .args(["-H", &format!("Authorization: Bearer {jeton}")])
            .args(["-r", &format!("{debut}-{}", debut + 64 * 1024 - 1)])
            .args(["-w", "\n%{http_code}"])
            .arg(format!("{base}/v1/mailboxes/INBOX/messages/{uid}/raw"))
            .output()
            .expect("curl s'exécute");
        let (octets, code) = sortie.stdout.split_at(sortie.stdout.len() - 4);
        relu.extend_from_slice(octets);
        if code != b"\n206" || octets.len() < 64 * 1024 {
            break;
        }
    }
    let message = String::from_utf8_lossy(&relu).into_owned();
    assert!(
        message.contains("multipart/mixed"),
        "{}",
        &message[..400.min(message.len())]
    );
    assert!(message.contains("ci-joint le rapport"));
    assert!(message.contains("filename*=UTF-8''donn%C3%A9es.bin"));
    // La première ligne de base64 : les 57 premiers octets de la pièce.
    let mut place = [0_u8; 128];
    let ligne = ams_mime::encode_base64_line(&donnees[..57], &mut place).expect("encodable");
    assert!(message.contains(core::str::from_utf8(ligne).expect("ascii")));

    // ── LA PIÈCE SE RELIT DÉCODÉE, PAR PORTÉES SUR LE DÉCODÉ ────────────────
    // `…/parts/2` rend le fichier et non son base64 : ce sont les trois cent
    // mille octets envoyés, et les portées se comptent sur eux.
    let entetes = atelier.0.join("entetes.txt");
    let mut piece: Vec<u8> = Vec::new();
    let mut premiers = String::new();
    loop {
        let debut = piece.len();
        let sortie = std::process::Command::new("curl")
            .args(["-s", "-S", "--insecure", "--http2", "-D"])
            .arg(&entetes)
            .args(["-H", &format!("Authorization: Bearer {jeton}")])
            .args(["-r", &format!("{debut}-{}", debut + 50_000 - 1)])
            .args(["-w", "\n%{http_code}"])
            .arg(format!("{base}/v1/mailboxes/INBOX/messages/{uid}/parts/2"))
            .output()
            .expect("curl s'exécute");
        let (octets, code) = sortie.stdout.split_at(sortie.stdout.len() - 4);
        assert_eq!(code, b"\n206", "{}", serveur.journal());
        if debut == 0 {
            premiers = std::fs::read_to_string(&entetes).expect("les en-têtes");
        }
        piece.extend_from_slice(octets);
        if octets.len() < 50_000 || piece.len() >= donnees.len() {
            break;
        }
    }
    assert!(piece == donnees, "la pièce relue n'est pas celle envoyée");
    let premiers = premiers.to_ascii_lowercase();
    for attendu in [
        "content-type: application/octet-stream",
        "content-range: bytes 0-49999/300000",
        "content-disposition: attachment; filename=\"donn_es.bin\"; filename*=utf-8''donn%c3%a9es.bin",
        "content-security-policy: default-src 'none'; sandbox",
        "x-content-type-options: nosniff",
    ] {
        assert!(premiers.contains(attendu), "{attendu} — {premiers}");
    }
    // Le corps texte se lit décodé lui aussi, sous son jeu.
    let (texte_lu, code) = appeler(
        "GET",
        &format!("/v1/mailboxes/INBOX/messages/{uid}/parts/1"),
        "",
        &[],
        b"",
    );
    assert_eq!(code, "200");
    assert!(texte_lu.contains("ci-joint le rapport"), "{texte_lu}");
    // Un `multipart` n'a pas de contenu à lui.
    let (_, code) = appeler(
        "GET",
        &format!("/v1/mailboxes/INBOX/messages/{uid}/parts/9"),
        "",
        &[],
        b"",
    );
    assert_eq!(code, "404");
    // Le brouillon est parti avec le rangement.
    let (_, code) = appeler("GET", &format!("/v1/drafts/{id}"), "", &[], b"");
    assert_eq!(code, "404");

    // ── UN SECOND BROUILLON S'ENVOIE ─────────────────────────────────────────
    let id = creer();
    let (_, code) = appeler(
        "POST",
        &format!("/v1/drafts/{id}/attachments"),
        "application/json",
        &[],
        br#"{"name":"a.txt","type":"text/plain","size":3}"#,
    );
    assert_eq!(code, "201");
    // Envoyer avant la fin : la pièce manque.
    let (corps, code) = appeler("POST", &format!("/v1/drafts/{id}/send"), "", &[], b"");
    assert_eq!(code, "409", "{corps}");
    let (_, code) = appeler(
        "PUT",
        &format!("/v1/drafts/{id}/attachments/1"),
        "application/octet-stream",
        &["Content-Range: bytes 0-2/3"],
        b"abc",
    );
    assert_eq!(code, "200");
    let (corps, code) = appeler("POST", &format!("/v1/drafts/{id}/send"), "", &[], b"");
    assert_eq!(code, "200", "{corps} — {}", serveur.journal());
    assert!(corps.contains(r#""delivered":1"#), "{corps}");
}
