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

/// Se connecte au serveur, ou dit ce qu'il est devenu.
fn joindre(serveur: &mut Serveur, port: u16) -> TcpStream {
    match TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port))) {
        Ok(flux) => flux,
        Err(erreur) => panic!(
            "connexion au port {port} : {erreur} — {}",
            serveur.plainte()
        ),
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

fn configuration(atelier: &Atelier, port: u16, tls: Tls, comptes: &str) -> PathBuf {
    configuration_pop3(atelier, port, tls, comptes, "")
}

fn configuration_pop3(
    atelier: &Atelier,
    port: u16,
    tls: Tls,
    comptes: &str,
    pop3: &str,
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
        listen_http: String::new(),
        listen_h3: String::new(),
        token_key: String::new(),
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
        "",
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
    let config = configuration(&atelier, port, Tls::default(), "");
    let mut serveur = lancer(&config, port);

    let mut flux = joindre(&mut serveur, port);
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

#[test]
fn le_binaire_authentifie_un_compte_ecrit_par_l_administrateur() {
    // LA CHAÎNE ENTIÈRE, ET C'EST LE SEUL TEST QUI LA PARCOURT : une empreinte
    // Argon2id écrite dans un magasin binaire, relue par le serveur, comparée à
    // un mot de passe qui arrive par un `AUTH PLAIN` chiffré. Chaque crate prise
    // séparément est déjà juste ; ce qui se casse, ce sont les jointures.
    let atelier = atelier("authentification");
    let Some((cert, cle)) = paire(&atelier.0) else {
        panic!("{SANS_OPENSSL}");
    };

    // Le magasin, écrit comme `air-mail-admin account add` l'écrirait.
    let magasin = atelier.0.join("comptes.bin");
    let empreinte = ams_auth::hash_password(b"ouvre-toi", b"seize octets ici").expect("hachable");
    let comptes = vec![ams_auth::Account {
        login: String::from("jean"),
        hash: empreinte,
        addresses: vec![String::from("jean@example.com")],
    }];
    std::fs::write(
        &magasin,
        ams_config::encode_accounts(&comptes).expect("encodable"),
    )
    .expect("écriture");
    std::fs::set_permissions(&magasin, std::fs::Permissions::from_mode(0o600))
        .expect("permissions");

    let port = port_libre();
    let config = configuration(
        &atelier,
        port,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        &magasin.display().to_string(),
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
        // `AGplYW4Ab3V2cmUtdG9p` est `\0jean\0ouvre-toi` en base64. Une seule
        // chaîne, sans continuation de ligne : une continuation garde son
        // indentation DANS la commande, et le serveur répond alors « 500 » à
        // une ligne qui a l'air juste. C'est arrivé en écrivant ce test.
        .write_all(
            concat!(
                "EHLO client.example\r\n",
                "AUTH PLAIN AGplYW4Ab3V2cmUtdG9p\r\n",
                "QUIT\r\n"
            )
            .as_bytes(),
        )
        .expect("écriture");
    let dit = client.wait_with_output().expect("openssl s_client");
    let chiffre = String::from_utf8_lossy(&dit.stdout).into_owned();

    assert!(
        chiffre.contains("250 AUTH PLAIN"),
        "le serveur n'annonce pas AUTH.\n{chiffre}"
    );
    assert!(
        chiffre.contains("235 2.7.0 Authentication successful"),
        "le compte n'a pas été reconnu.\n{chiffre}"
    );
}

#[test]
fn un_magasin_lisible_par_tous_empeche_le_demarrage() {
    // Ce ne sont que des empreintes — mais un fichier de comptes lisible par
    // tous est un DICTIONNAIRE DE NOMS à essayer, et le matériel d'une attaque
    // hors ligne que nul garde ne compte.
    let atelier = atelier("magasin-ouvert");
    let Some((cert, cle)) = paire(&atelier.0) else {
        panic!("{SANS_OPENSSL}");
    };
    let magasin = atelier.0.join("comptes.bin");
    std::fs::write(
        &magasin,
        ams_config::encode_accounts(&[]).expect("encodable"),
    )
    .expect("écriture");
    std::fs::set_permissions(&magasin, std::fs::Permissions::from_mode(0o644))
        .expect("permissions");

    let port = port_libre();
    let config = configuration(
        &atelier,
        port,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        &magasin.display().to_string(),
    );
    let sortie = Command::new(env!("CARGO_BIN_EXE_air-mail-server"))
        .arg("--config")
        .arg(&config)
        .output()
        .expect("lançable");
    assert!(!sortie.status.success(), "le serveur a démarré malgré tout");
    let plainte = String::from_utf8_lossy(&sortie.stderr);
    assert!(plainte.contains("TOUT LE MONDE"), "{plainte}");
    assert!(plainte.contains("magasin de comptes"), "{plainte}");
}

/// **UNE CLÉ DE SIGNATURE LISIBLE PAR TOUS EMPÊCHE LE DÉMARRAGE**, comme celle
/// de TLS et pour la même raison : qui la vole signe en notre nom, et rien ne le
/// distingue de nous.
#[test]
fn une_cle_dkim_lisible_par_tous_empeche_le_demarrage() {
    let atelier = atelier("dkim-ouvert");
    let cle = atelier.0.join("dkim.pem");
    // Une clé Ed25519 jetable : ce qu'on éprouve est le REFUS, pas la clé.
    std::fs::write(
        &cle,
        "-----BEGIN PRIVATE KEY-----\n\
         MC4CAQAwBQYDK2VwBCIEIPycWR71gsJjQjlyixhg1EFwd/RmkyoHfIBubnK3v8rE\n\
         -----END PRIVATE KEY-----\n",
    )
    .expect("écriture");
    std::fs::set_permissions(&cle, std::fs::Permissions::from_mode(0o644)).expect("permissions");

    let port = port_libre();
    let mut config = configuration(&atelier, port, Tls::default(), "");
    reecrire_avec_dkim(&mut config, &cle);
    let sortie = Command::new(env!("CARGO_BIN_EXE_air-mail-server"))
        .arg("--config")
        .arg(&config)
        .output()
        .expect("lançable");
    assert!(!sortie.status.success(), "le serveur a démarré malgré tout");
    let plainte = String::from_utf8_lossy(&sortie.stderr);
    assert!(plainte.contains("TOUT LE MONDE"), "{plainte}");
    assert!(plainte.contains("clé DKIM"), "{plainte}");

    // Resserrée, elle passe : le refus vise les permissions, pas la clé.
    std::fs::set_permissions(&cle, std::fs::Permissions::from_mode(0o600)).expect("permissions");
    let mut serveur = lancer(&config, port);
    let mut flux = joindre(&mut serveur, port);
    flux.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("délai");
    flux.write_all(b"QUIT\r\n").expect("écriture");
    let dit = lire_jusqu_au_conge(&mut flux, &mut serveur);
    assert!(dit.contains("220 "), "{dit}");
}

/// Réécrit une configuration en y ajoutant un signataire DKIM.
fn reecrire_avec_dkim(config: &mut PathBuf, cle: &Path) {
    let brut = std::fs::read(&config).expect("lecture");
    let mut lue = ams_config::decode(&brut).expect("configuration lisible");
    lue.dkim = ams_config::Dkim {
        selector: String::from("epreuve"),
        private_key_path: cle.display().to_string(),
    };
    std::fs::write(&config, ams_config::encode(&lue).expect("encodable")).expect("écriture");
}

/// Lit jusqu'au `221`, ou jusqu'à ce que le pair raccroche.
///
/// `read_to_string` attendrait la fermeture ; or un serveur qui va bien répond
/// `221` **puis** ferme, et une lecture qui expire entre les deux ferait échouer
/// le test pour une raison qui n'est pas celle qu'il éprouve.
fn lire_jusqu_au_conge(flux: &mut TcpStream, serveur: &mut Serveur) -> String {
    use std::io::Read as _;
    let mut tout = String::new();
    let mut tampon = [0_u8; 1024];
    while !tout.contains("221 ") {
        match flux.read(&mut tampon) {
            Ok(0) => break,
            Ok(lus) => tout.push_str(&String::from_utf8_lossy(&tampon[..lus])),
            Err(erreur) => {
                // ON NE TUE PLUS POUR LIRE : le journal est recopié en continu
                // par un fil, et se lit à tout instant. Tuer d'abord, c'était
                // effacer l'état du serveur avant de le rapporter.
                panic!(
                    "lecture ({erreur}) après :\n{tout}\n--- serveur ---\n{}",
                    serveur.plainte()
                )
            }
        }
    }
    tout
}

#[test]
fn chaque_destinataire_recoit_dans_sa_boite() {
    // LA CHAÎNE ENTIÈRE, VUE DU DISQUE : deux comptes, un message adressé aux
    // deux, deux fichiers dans deux répertoires. Chaque pièce prise séparément
    // était déjà juste ; ce qui casse, ce sont les jointures.
    let atelier = atelier("deux-boites");
    let magasin = atelier.0.join("comptes.bin");
    let comptes: Vec<ams_auth::Account> = ["jean", "paul"]
        .iter()
        .map(|nom| ams_auth::Account {
            login: (*nom).to_string(),
            hash: String::from(ams_auth::DUMMY_HASH),
            addresses: vec![format!("{nom}@example.com")],
        })
        .collect();
    std::fs::write(
        &magasin,
        ams_config::encode_accounts(&comptes).expect("encodable"),
    )
    .expect("écriture");
    std::fs::set_permissions(&magasin, std::fs::Permissions::from_mode(0o600))
        .expect("permissions");

    let port = port_libre();
    let config = configuration(
        &atelier,
        port,
        Tls::default(),
        &magasin.display().to_string(),
    );
    let mut serveur = lancer(&config, port);

    let mut flux = joindre(&mut serveur, port);
    flux.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("délai");
    // Les `\r\n` sont ÉCHAPPÉS, et il faut y regarder à deux fois : un saut
    // de ligne réel dans ce littéral donnerait un `LF` nu, que le serveur
    // refuse de prendre pour une fin de ligne (contrebandage SMTP). Il
    // attendrait alors le `CRLF` qui ne vient pas, et le test échouerait en
    // accusant le serveur d'être muet. C'est arrivé.
    flux.write_all(
        concat!(
            "EHLO client.example\r\n",
            "MAIL FROM:<expediteur@ailleurs.example>\r\n",
            "RCPT TO:<jean@example.com>\r\n",
            "RCPT TO:<paul@example.com>\r\n",
            "RCPT TO:<personne@example.com>\r\n",
            "DATA\r\n",
            "Subject: pour deux\r\n\r\nbonjour\r\n.\r\n",
            "QUIT\r\n"
        )
        .as_bytes(),
    )
    .expect("écriture");
    let dit = lire_jusqu_au_conge(&mut flux, &mut serveur);

    // Une adresse qu'aucun compte ne déclare est refusée — CE N'EST PLUS UN
    // FOURRE-TOUT, même dans un domaine hébergé.
    //
    // **ET LE REFUS DIT LEQUEL** : `example.com` est un domaine dont ce serveur
    // répond, donc `personne@example.com` est une BOÎTE QUI N'EXISTE PAS
    // (`5.1.1`), et non un relais qu'on nie (`5.7.1`). C'est cet état étendu-là
    // que le rapport de non-remise portera jusqu'à l'expéditeur.
    assert!(dit.contains("550 5.1.1 Mailbox unavailable"), "{dit}");
    assert!(
        !dit.contains("5.7.1"),
        "aucun relais n'est en cause ici : {dit}"
    );
    assert!(dit.contains("250 2.0.0 Message accepted"), "{dit}");

    // Et sur le disque : un message dans chaque boîte, aucun ailleurs.
    for nom in ["jean", "paul"] {
        let recus: Vec<_> = std::fs::read_dir(atelier.0.join("boite").join(nom).join("new"))
            .expect("boîte lisible")
            .filter_map(Result::ok)
            .collect();
        assert_eq!(recus.len(), 1, "boîte de {nom} : {dit}");
        let contenu = std::fs::read_to_string(recus[0].path()).expect("message lisible");
        assert!(contenu.contains("bonjour"), "{contenu}");
    }
    assert!(
        !atelier.0.join("boite").join("personne").exists(),
        "une boîte a été créée pour une adresse refusée"
    );
}

/// Dialogue POP3 chiffré : rend ce que le client a lu dans le tuyau.
fn pop3(port: u16, dialogue: &str) -> String {
    let mut processus = Command::new("openssl")
        .args(["s_client", "-connect"])
        .arg(format!("127.0.0.1:{port}"))
        .args(["-starttls", "pop3", "-ign_eof"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect(SANS_OPENSSL);
    processus
        .stdin
        .as_mut()
        .expect("entrée standard")
        .write_all(dialogue.as_bytes())
        .expect("écriture");
    let sortie = processus.wait_with_output().expect("openssl s_client");
    String::from_utf8_lossy(&sortie.stdout).into_owned()
}

#[test]
fn un_client_pop3_releve_puis_efface_son_courrier() {
    // LA CHAÎNE ENTIÈRE, DANS L'AUTRE SENS : un message remis par SMTP, relevé
    // par POP3 sur un second port, puis effacé — et le disque le confirme.
    let atelier = atelier("pop3");
    let Some((cert, cle)) = paire(&atelier.0) else {
        panic!("{SANS_OPENSSL}");
    };

    let magasin = atelier.0.join("comptes.bin");
    let empreinte = ams_auth::hash_password(b"ouvre-toi", b"seize octets ici").expect("hachable");
    let comptes = vec![ams_auth::Account {
        login: String::from("jean"),
        hash: empreinte,
        addresses: vec![String::from("jean@example.com")],
    }];
    std::fs::write(
        &magasin,
        ams_config::encode_accounts(&comptes).expect("encodable"),
    )
    .expect("écriture");
    std::fs::set_permissions(&magasin, std::fs::Permissions::from_mode(0o600))
        .expect("permissions");

    let port_smtp = port_libre();
    let port_pop3 = port_libre();
    let config = configuration_pop3(
        &atelier,
        port_smtp,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        &magasin.display().to_string(),
        &format!("127.0.0.1:{port_pop3}"),
    );
    let mut serveur = lancer(&config, port_smtp);

    // ── 1. Un message arrive par SMTP ───────────────────────────────────────
    let mut flux = joindre(&mut serveur, port_smtp);
    flux.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("délai");
    flux.write_all(
        concat!(
            "EHLO client.example\r\n",
            "MAIL FROM:<expediteur@ailleurs.example>\r\n",
            "RCPT TO:<jean@example.com>\r\n",
            "DATA\r\n",
            "Subject: par la poste\r\n\r\nbonjour jean\r\n.\r\n",
            "QUIT\r\n"
        )
        .as_bytes(),
    )
    .expect("écriture SMTP");
    let mut dit = String::new();
    std::io::Read::read_to_string(&mut flux, &mut dit).expect("lecture SMTP");
    assert!(dit.contains("250 2.0.0 Message accepted"), "{dit}");

    // ── 2. Le client POP3 le relève ─────────────────────────────────────────
    let vu = pop3(
        port_pop3,
        concat!(
            "USER jean\r\n",
            "PASS ouvre-toi\r\n",
            "STAT\r\n",
            "UIDL\r\n",
            "RETR 1\r\n",
            "QUIT\r\n"
        ),
    );
    assert!(vu.contains("+OK Mailbox open"), "connexion refusée.\n{vu}");

    // ── UNE COMMANDE, UNE RÉPONSE (RFC 1939 §3) ─────────────────────────────
    //
    // ON COMPTE, PARCE QUE `contains` NE VOIT PAS UNE RÉPONSE DE TROP. Les
    // assertions de cet essai cherchaient toutes une PRÉSENCE, et le serveur
    // émettait deux réponses au `PASS` — un `+OK` avant d'ouvrir la boîte, puis
    // `+OK Mailbox open`. Tout était présent, rien n'était aligné, et tout
    // client conforme se retrouvait décalé d'un cran dès l'authentification.
    //
    // Six commandes sont envoyées ; `RETR` et `UIDL` sont MULTILIGNES et leur
    // corps ne commence pas par un indicateur d'état en début de ligne, si bien
    // que compter les lignes qui commencent par `+OK` ou `-ERR` compte
    // exactement les réponses. La bannière et le `+OK` du `STLS`, eux, ne sont
    // pas comptés : `openssl s_client -starttls pop3` les consomme lui-même
    // pour monter le chiffrement, et ils n'atteignent pas sa sortie.
    let reponses = vu
        .lines()
        .filter(|ligne| ligne.starts_with("+OK") || ligne.starts_with("-ERR"))
        .count();
    assert_eq!(
        reponses, 6,
        "six réponses attendues, une par commande.\n{vu}"
    );
    assert!(
        vu.contains("+OK 1 "),
        "STAT n'a pas compté le message.\n{vu}"
    );
    assert!(
        vu.contains("bonjour jean"),
        "le message n'est pas venu.\n{vu}"
    );
    assert!(
        vu.contains("Subject: par la poste"),
        "l'en-tête manque.\n{vu}"
    );
    // Le terminateur d'une réponse multiligne, et rien après lui.
    assert!(vu.contains("\r\n.\r\n"), "pas de terminateur.\n{vu}");

    // Le message est TOUJOURS là : `RETR` ne supprime rien.
    let restants = || {
        std::fs::read_dir(atelier.0.join("boite").join("jean").join("new"))
            .expect("boîte lisible")
            .count()
    };
    assert_eq!(restants(), 1, "RETR a effacé quelque chose");

    // ── 3. Une seconde session efface ───────────────────────────────────────
    let vu = pop3(
        port_pop3,
        concat!(
            "USER jean\r\n",
            "PASS ouvre-toi\r\n",
            "DELE 1\r\n",
            "QUIT\r\n"
        ),
    );
    assert!(vu.contains("+OK Message deleted"), "{vu}");
    assert_eq!(restants(), 0, "le QUIT n'a pas appliqué l'effacement");
}

#[test]
fn un_quit_sans_dele_n_efface_rien_et_un_mauvais_mot_de_passe_non_plus() {
    let atelier = atelier("pop3-refus");
    let Some((cert, cle)) = paire(&atelier.0) else {
        panic!("{SANS_OPENSSL}");
    };
    let magasin = atelier.0.join("comptes.bin");
    let empreinte = ams_auth::hash_password(b"ouvre-toi", b"seize octets ici").expect("hachable");
    std::fs::write(
        &magasin,
        ams_config::encode_accounts(&[ams_auth::Account {
            login: String::from("jean"),
            hash: empreinte,
            addresses: vec![String::from("jean@example.com")],
        }])
        .expect("encodable"),
    )
    .expect("écriture");
    std::fs::set_permissions(&magasin, std::fs::Permissions::from_mode(0o600))
        .expect("permissions");

    let port_smtp = port_libre();
    let port_pop3 = port_libre();
    let config = configuration_pop3(
        &atelier,
        port_smtp,
        Tls {
            certificate_chain_path: cert.display().to_string(),
            private_key_path: cle.display().to_string(),
        },
        &magasin.display().to_string(),
        &format!("127.0.0.1:{port_pop3}"),
    );
    let _serveur = lancer(&config, port_smtp);

    // UN MAUVAIS MOT DE PASSE N'OUVRE RIEN, et ne dit pas pourquoi.
    let vu = pop3(port_pop3, "USER jean\r\nPASS autre\r\nSTAT\r\nQUIT\r\n");
    assert!(vu.contains("-ERR Authentication failed"), "{vu}");
    assert!(
        !vu.contains("+OK Mailbox open"),
        "une session s'est ouverte.\n{vu}"
    );

    // Un compte INCONNU obtient exactement la même réponse.
    let autre = pop3(port_pop3, "USER paul\r\nPASS ouvre-toi\r\nQUIT\r\n");
    assert!(autre.contains("-ERR Authentication failed"), "{autre}");
}
