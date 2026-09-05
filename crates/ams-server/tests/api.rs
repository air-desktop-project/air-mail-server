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
        let candidat = 24_000_u16.saturating_add(rang % 4_000);
        // On éprouve qu'il est libre, et on le rend aussitôt : c'est tout ce
        // qu'on peut faire pour un serveur qui liera lui-même.
        if TcpListener::bind(("127.0.0.1", candidat)).is_ok() {
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
    configuration_complete(atelier, port, tls, "", "", ecoute_http, "", clef)
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
    configuration_complete(atelier, port, tls, "", "", ecoute_http, ecoute_h3, clef)
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
    pop3: &str,
    ecoute_http: &str,
    ecoute_h3: &str,
    clef: &str,
) -> PathBuf {
    let config = Configuration {
        // Une seule écoute, en `STARTTLS` : la liste vide dirait la même
        // chose, et l'écrire ici la rend lisible.
        smtp_listeners: Vec::new(),
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
    assert!(ecoute_udp_ouverte(h3), "le port UDP {h3} doit être ouvert");
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
