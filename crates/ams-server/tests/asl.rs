// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que le serveur fait du groupe `asl`, contre le VRAI binaire.
//!
//! # POURQUOI CONTRE LE BINAIRE, ET NON EN BIBLIOTHÈQUE
//!
//! Les deux refus qui comptent sont des refus de DÉMARRAGE : le serveur lit la
//! fiche d'identité, ne peut pas s'en servir, et s'arrête. Une fonction appelée
//! depuis un essai le dirait aussi — mais elle ne dirait pas que le binaire
//! s'arrête vraiment, ni ce qu'il écrit en s'arrêtant, qui est la seule chose
//! que l'exploitant verra.
//!
//! # AUCUN DE CES ESSAIS NE TOUCHE AUX VRAIES RACINES
//!
//! Celui qui démarre vise `127.0.0.1:1` — un port du bouclage sous 1024, où
//! personne n'écoute et où aucun autre essai ne peut se lier. Sans cela, un
//! `cargo test` ouvrirait des connexions vers nitrogen et argon, ce qu'un banc
//! n'a aucun droit de faire.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ams_config::{Configuration, Timeouts};
use ams_guard::Thresholds;
use ams_proto_smtp::Limits;

/// Un répertoire d'essai, effacé quand il tombe.
struct Atelier(PathBuf);

impl Drop for Atelier {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn atelier(nom: &str) -> Atelier {
    let chemin = std::env::temp_dir().join(format!(
        "ams-asl-{nom}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&chemin);
    std::fs::create_dir_all(chemin.join("boite")).expect("un répertoire d'essai");
    Atelier(chemin)
}

/// Écrit une configuration minimale, dont le groupe `asl` est ce qui varie.
fn configuration(atelier: &Atelier, port: u16, asl: ams_config::Asl) -> PathBuf {
    let config = Configuration {
        // Ces essais portent sur le transport, pas sur l'enveloppe.
        require_fqdn_helo: false,
        // Ce banc ne sert pas SCRAM : les deux chemins restent vides.
        scram_key: String::new(),
        scram_store: String::new(),
        devices: String::new(),
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
        // **C'EST LE SEUL CHAMP QUE CE BANC FAIT VARIER.** Tout le reste est
        // le minimum qui démarre : ces essais ne portent ni sur le courrier ni
        // sur l'API, mais sur ce que le serveur fait de ce groupe-ci.
        asl,
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
        listen_http: String::new(),
        listen_h3: String::new(),
        token_key: String::new(),
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
        tls: ams_config::Tls::default(),
        spf: ams_config::Spf::default(),
        dmarc: ams_config::Dmarc::default(),
        dkim: ams_config::Dkim::default(),
        accounts: String::new(),
        listen_pop3: String::new(),
        listen_imap: String::new(),
    };
    let chemin = atelier.0.join("ams.conf");
    std::fs::write(&chemin, ams_config::encode(&config).expect("encodable")).expect("écriture");
    chemin
}

/// Un port libre, pour l'écoute SMTP dont ces essais n'ont rien à faire.
fn port_libre() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|ecoute| ecoute.local_addr())
        .map(|adresse| adresse.port())
        .expect("un port libre")
}

/// Lance le binaire et rend ce qu'il a écrit sur son erreur standard, une fois
/// qu'il a dit `motif` — ou tout ce qu'il a dit avant de mourir.
fn journal_jusqu_a(config: &Path, motif: &str) -> (String, bool) {
    let mut enfant = Command::new(env!("CARGO_BIN_EXE_air-mail-server"))
        .arg("--config")
        .arg(config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("le serveur se lance");

    // ON VIDE LE TUYAU SANS DISCONTINUER : un enfant dont l'erreur standard se
    // remplit s'arrête d'écrire, donc de servir.
    let journal = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    if let Some(sortie) = enfant.stderr.take() {
        let vers = std::sync::Arc::clone(&journal);
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

    // **ON REGARDE LA MORT, ET NON L'ANNONCE DE LA MORT.** La première écriture
    // de cette fonction sortait dès que le motif apparaissait, et rendait donc
    // « vivant » pour un serveur qui s'arrêtait juste après avoir dit pourquoi.
    // Les deux essais de refus passaient alors pour des échecs, en accusant le
    // serveur de servir quand il refusait.
    //
    // L'ordre compte : on constate d'abord une sortie, puis le motif — et quand
    // le motif est là, on laisse une grâce pour voir s'il meurt derrière.
    let depart = Instant::now();
    let mut fini = false;
    while depart.elapsed() < Duration::from_secs(10) {
        if let Ok(Some(_)) = enfant.try_wait() {
            fini = true;
            break;
        }
        let dit = journal
            .lock()
            .map(|place| place.clone())
            .unwrap_or_default();
        if dit.contains(motif) {
            std::thread::sleep(Duration::from_millis(300));
            if let Ok(Some(_)) = enfant.try_wait() {
                fini = true;
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let vivant = !fini;
    // **ON LE TUE DANS TOUS LES CAS**, y compris quand il a déjà fini : un
    // essai qui laisserait un serveur derrière lui en ferait échouer un autre.
    let _ = enfant.kill();
    let _ = enfant.wait();
    std::thread::sleep(Duration::from_millis(50));
    let dit = journal
        .lock()
        .map(|place| place.clone())
        .unwrap_or_default();
    (dit, vivant)
}

/// **SANS RÉPERTOIRE D'ÉTAT, LE SERVEUR LE DIT ET SERT QUAND MÊME.**
///
/// C'est le défaut, et c'est ce qu'un fichier écrit avant ce champ décode. Le
/// serveur dit ce qu'il sert ET ce qui manque ; l'annonce éteinte appartient à
/// la seconde liste, avec « aucune émission » et « rapports TLS non composés ».
#[test]
fn sans_repertoire_d_etat_l_annonce_est_eteinte_et_le_serveur_sert() {
    let atelier = atelier("eteinte");
    let config = configuration(&atelier, port_libre(), ams_config::Asl::default());
    let (dit, vivant) = journal_jusqu_a(&config, "annonce ASL ÉTEINTE");
    assert!(
        vivant,
        "le serveur ne doit pas s'arrêter pour autant : {dit}"
    );
    assert!(dit.contains("annonce ASL ÉTEINTE"), "{dit}");
    assert!(
        dit.contains("asl enroll"),
        "il dit comment l'allumer : {dit}"
    );
}

/// **UN RÉPERTOIRE D'ÉTAT SANS FICHE EMPÊCHE DE DÉMARRER.**
///
/// Annoncer est un engagement envers des clients qui vont s'y fier pour
/// trouver ce serveur. Démarrer en silence sans pouvoir le tenir serait pire
/// que de ne pas démarrer — c'est la règle de SCRAM, appliquée ici.
#[test]
fn un_repertoire_sans_fiche_empeche_de_demarrer() {
    let atelier = atelier("sans-fiche");
    let etat = atelier.0.join("asl");
    std::fs::create_dir_all(&etat).expect("le répertoire d'état");
    let config = configuration(
        &atelier,
        port_libre(),
        ams_config::Asl {
            state: etat.display().to_string(),
            services: Vec::new(),
            directories: Vec::new(),
        },
    );

    let (dit, vivant) = journal_jusqu_a(&config, "fiche d'identité ASL");
    assert!(!vivant, "il doit s'arrêter : {dit}");
    assert!(dit.contains("fiche d'identité ASL"), "{dit}");
    assert!(
        dit.contains("identite"),
        "il nomme le fichier qui manque : {dit}"
    );
}

/// **UNE FICHE LISIBLE PAR D'AUTRES N'EST PLUS UNE CLÉ.**
///
/// Le serveur refuse de démarrer et donne le `chmod`. `asl` refuse la même
/// chose, pour la même raison : les deux programmes lisent le même fichier, et
/// doivent refuser la même chose.
#[test]
fn une_fiche_lisible_par_d_autres_empeche_de_demarrer() {
    use std::os::unix::fs::PermissionsExt as _;

    let atelier = atelier("trop-ouverte");
    let etat = atelier.0.join("asl");
    std::fs::create_dir_all(&etat).expect("le répertoire d'état");
    let fiche = etat.join("identite");
    std::fs::write(
        &fiche,
        format!(
            "machine = {}\ngraine = {}\n",
            asl_id::Identifiant::depuis_entropie(asl_id::Genre::Machine, [0x71; 16])
                .texte()
                .as_str(),
            "3c".repeat(32)
        ),
    )
    .expect("une fiche");
    std::fs::set_permissions(&fiche, std::fs::Permissions::from_mode(0o644))
        .expect("le mode se pose");

    let config = configuration(
        &atelier,
        port_libre(),
        ams_config::Asl {
            state: etat.display().to_string(),
            services: Vec::new(),
            directories: Vec::new(),
        },
    );

    let (dit, vivant) = journal_jusqu_a(&config, "n'est plus une clé");
    assert!(!vivant, "il doit s'arrêter : {dit}");
    assert!(dit.contains("0644"), "il dit le mode trouvé : {dit}");
    assert!(dit.contains("chmod 600"), "et comment le corriger : {dit}");
}

/// **AVEC UNE FICHE JUSTE, IL ANNONCE — ET IL DIT QUOI.**
///
/// L'annuaire visé est `127.0.0.1:1`, où personne n'écoute : ce que cet essai
/// mesure est que le serveur DÉMARRE quand même et dise ce qu'il annonce. C'est
/// la propriété de §1.4 — un annuaire injoignable n'empêche pas de démarrer —
/// vue depuis le binaire entier.
#[test]
fn avec_une_fiche_juste_il_annonce_et_dit_quoi() {
    use std::os::unix::fs::PermissionsExt as _;

    let atelier = atelier("annonce");
    let etat = atelier.0.join("asl");
    std::fs::create_dir_all(&etat).expect("le répertoire d'état");
    let machine = asl_id::Identifiant::depuis_entropie(asl_id::Genre::Machine, [0x71; 16]);
    let fiche = etat.join("identite");
    std::fs::write(
        &fiche,
        format!(
            "machine = {}\ngraine = {}\n",
            machine.texte().as_str(),
            "3c".repeat(32)
        ),
    )
    .expect("une fiche");
    std::fs::set_permissions(&fiche, std::fs::Permissions::from_mode(0o600))
        .expect("le mode se pose");

    let annuaire = asl_id::Identifiant::depuis_entropie(asl_id::Genre::Annuaire, [0x0a; 16]);
    let config = configuration(
        &atelier,
        port_libre(),
        ams_config::Asl {
            state: etat.display().to_string(),
            services: std::vec![
                ams_config::AslService {
                    name: String::from("air-mail-imaps"),
                    protocol: ams_config::AslProtocol::Tcp,
                    port: 993,
                },
                ams_config::AslService {
                    name: String::from("air-mail-api-h3"),
                    protocol: ams_config::AslProtocol::Udp,
                    port: 8443,
                },
            ],
            directories: std::vec![format!("127.0.0.1:1={}", annuaire.texte().as_str())],
        },
    );

    let (dit, vivant) = journal_jusqu_a(&config, "annonce ASL — machine");
    assert!(
        vivant,
        "un annuaire injoignable n'empêche PAS de démarrer : {dit}"
    );
    assert!(dit.contains(machine.texte().as_str()), "{dit}");
    assert!(dit.contains("2 service(s)"), "{dit}");
    assert!(dit.contains("air-mail-imaps → tcp:993"), "{dit}");
    assert!(dit.contains("air-mail-api-h3 → udp:8443"), "{dit}");
    assert!(
        !dit.contains("racines embarquées"),
        "un annuaire est déclaré : ce ne sont pas les racines : {dit}"
    );
}
