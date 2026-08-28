//! Le serveur air-mail-server — binaire `air-mail-server` (C12).
//!
//! Il assemble les pièces : le codec SMTP, la machine à états de session, le
//! garde anti-flooding, la boucle d'entrées-sorties et la boîte Maildir. Il ne
//! contient lui-même **aucune logique de protocole** — seulement le fil.
//!
//! # Ce qu'il sert, et ce qu'il ne sert pas
//!
//! Il reçoit du courrier en clair, pour les domaines qu'on lui nomme, et le
//! dépose dans une boîte Maildir. Il refuse les sources qui abusent.
//!
//! **Ni TLS ni authentification** : ni `STARTTLS` ni `AUTH` ne sont annoncés,
//! parce que rien ne sait les conduire, et qu'annoncer ce qu'on ne sait pas faire
//! ferait envoyer un mot de passe à un serveur sans de quoi le protéger.
//!
//! **Une seule boîte pour tout le monde.** Répartir par destinataire demande un
//! modèle de comptes qui n'existe pas — et dériver un nom de répertoire d'une
//! partie locale est précisément là où vit la traversée de répertoire. On ne
//! l'improvise pas.
//!
//! **Pas de journal structuré** : quelques lignes sur la sortie d'erreur, et
//! c'est tout.
//!
//! # Il ne se règle QUE par un fichier
//!
//! C11 veut une configuration binaire ; ce binaire ne lit rien d'autre. Il n'a
//! pas d'options de réglage, et c'est délibéré : deux sources de configuration
//! seraient une de trop — c'est ainsi qu'un serveur finit par tourner autrement
//! que ce que son administrateur croit avoir demandé. Le fichier se produit avec
//! `air-mail-admin config write`.

mod delivery;
mod policy;

use std::process::ExitCode;
use std::sync::Arc;

use std::path::{Path, PathBuf};
use std::time::Duration;

use ams_config::Configuration;
use ams_loop_tokio::{ServeOptions, SharedGuard, Timeouts, refuse_root, serve};
use ams_session::Config;
use ams_store::Maildir;
use tokio::net::TcpListener;

use crate::delivery::MaildirDelivery;
use crate::policy::DomainesHeberges;

/// Le texte de `--help`.
const AIDE: &str = "\
air-mail-server — serveur de courrier SMTP

USAGE
    air-mail-server --config <fichier>

Le fichier de configuration est BINAIRE, et se produit avec
`air-mail-admin config write`. Ce serveur n'a AUCUNE autre option de réglage :
deux sources de configuration seraient une de trop.

    --config <fichier>  la configuration
    --help              ce texte
    --version           la version

CE QUI N'EST PAS ENCORE LÀ
    TLS et l'authentification ne sont pas implémentés, donc ni STARTTLS ni AUTH
    ne sont annoncés. Le courrier reçu va dans UNE SEULE boîte : répartir par
    destinataire demande un modèle de comptes qui n'existe pas.
";

/// L'ordonnanceur est MULTI-FILS, et ce n'est pas un défaut de configuration :
/// la remise Maildir appelle `block_in_place` pour ses `fsync`, qui panique sur
/// l'ordonnanceur mono-fil.
#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let mots: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let fichier = match mots.as_slice() {
        ["--help" | "-h"] => {
            println!("{AIDE}");
            return ExitCode::SUCCESS;
        }
        ["--version" | "-V"] => {
            println!("air-mail-server {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        ["--config", fichier] => PathBuf::from(fichier),
        autre => {
            eprintln!("air-mail-server : arguments inattendus : {autre:?}");
            eprintln!("Essayez `air-mail-server --help`.");
            return ExitCode::from(2);
        }
    };

    match servir(&fichier).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("air-mail-server : {message}");
            ExitCode::FAILURE
        }
    }
}

/// Monte le serveur et le fait tourner jusqu'à l'arrêt.
async fn servir(fichier: &Path) -> Result<(), String> {
    // LE REFUS DU SUPERUTILISATEUR VIENT AVANT TOUT LE RESTE (C10) — avant
    // d'ouvrir un port, avant de créer un répertoire. Rien de ce qui suit ne doit
    // s'exécuter avec ces privilèges, pas même une seconde.
    refuse_root().map_err(|erreur| erreur.to_string())?;

    let octets =
        std::fs::read(fichier).map_err(|erreur| format!("`{}` : {erreur}", fichier.display()))?;
    let options: Configuration = ams_config::decode(&octets)
        .map_err(|erreur| format!("`{}` : {erreur}", fichier.display()))?;
    let ecoute: std::net::SocketAddr = options
        .listen
        .parse()
        .map_err(|_| format!("`{}` n'est pas une adresse d'écoute", options.listen))?;
    let maildir = PathBuf::from(&options.maildir);

    if options.hosted.is_empty() {
        eprintln!(
            "air-mail-server : aucun `--hosted` : ce serveur n'acceptera de courrier \
             pour personne."
        );
    }

    // Le domaine vit aussi longtemps que le processus. Le fuir est ici exact :
    // il est lu une fois, jamais remplacé, et libéré à la sortie du programme.
    let domaine: &'static [u8] = Box::leak(options.domain.clone().into_bytes().into_boxed_slice());
    let config = Config::new(
        domaine,
        usize::try_from(options.max_recipients).unwrap_or(usize::MAX),
        options.max_message_octets,
        options.limits,
    )
    .map_err(|erreur| format!("domaine `{}` : {erreur}", options.domain))?;

    let boite = Arc::new(
        Maildir::open(&maildir, domaine)
            .map_err(|erreur| format!("boîte `{}` : {erreur}", options.maildir))?,
    );
    let resume = boite
        .summary()
        .map_err(|erreur| format!("lecture de la boîte : {erreur}"))?;

    let ecouteur = TcpListener::bind(ecoute)
        .await
        .map_err(|erreur| format!("écoute sur {ecoute} : {erreur}"))?;

    eprintln!(
        "air-mail-server {} : {} écoute sur {}, boîte `{}` ({} message(s), prochain UID {})",
        env!("CARGO_PKG_VERSION"),
        options.domain,
        ecoute,
        options.maildir,
        resume.numbered,
        resume.next_uid.value()
    );
    eprintln!(
        "air-mail-server : domaines servis : {}",
        if options.hosted.is_empty() {
            String::from("(aucun)")
        } else {
            options.hosted.join(", ")
        }
    );

    let garde = Arc::new(SharedGuard::new(
        usize::try_from(options.tracked_sources).unwrap_or(usize::MAX),
        options.guard,
    ));
    let politique = Arc::new(DomainesHeberges::new(&options.hosted));
    let pour_la_remise = Arc::clone(&boite);

    let stats = serve(
        ecouteur,
        config,
        politique,
        garde,
        move || MaildirDelivery::new(Arc::clone(&pour_la_remise)),
        ServeOptions {
            max_connections: usize::try_from(options.max_connections).unwrap_or(usize::MAX),
            timeouts: Timeouts {
                command: Duration::from_secs(u64::from(options.timeouts.command_seconds)),
                data: Duration::from_secs(u64::from(options.timeouts.data_seconds)),
                // Pas de champ dans le schéma : le délai de poignée de main reste
                // celui de la boucle. Il n'aura de sens à régler que le jour où
                // ce binaire saura recevoir un certificat.
                handshake: Timeouts::default().handshake,
            },
            // AUCUN CHIFFREMENT ICI, ET C'EST DIT PLUTÔT QUE SOUS-ENTENDU. La
            // boucle sait conduire `STARTTLS` ; ce binaire, lui, n'a aucun moyen
            // de recevoir un certificat — le schéma Cap'n Proto (C11) n'a pas de
            // section TLS, et `air-mail-admin` n'a donc rien à y écrire.
            //
            // La configuration n'annonce pas `STARTTLS` non plus : les capacités
            // valent faux par défaut. Le serveur ne ment donc à personne — il ne
            // chiffre simplement pas encore, et C4/C14 restent tenues par les
            // crates, pas par le service.
            tls: None,
        },
        arret(),
    )
    .await
    .map_err(|erreur| erreur.to_string())?;

    eprintln!(
        "air-mail-server : arrêt ; {} connexion(s) acceptée(s), {} refusée(s) par le noyau",
        stats.accepted, stats.failed
    );
    Ok(())
}

/// Attend `SIGINT` ou `SIGTERM`.
///
/// Les deux, et pas seulement `Ctrl-C` : un service arrêté par un gestionnaire
/// reçoit `SIGTERM`, et l'ignorer le ferait tuer au bout du délai de grâce —
/// c'est-à-dire au milieu d'une remise.
async fn arret() {
    let interruption = tokio::signal::ctrl_c();
    let mut terminaison =
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(erreur) => {
                eprintln!("air-mail-server : `SIGTERM` non écouté : {erreur}");
                let _ = interruption.await;
                return;
            }
        };
    tokio::select! {
        resultat = interruption => {
            if let Err(erreur) = resultat {
                eprintln!("air-mail-server : `SIGINT` non écouté : {erreur}");
            }
        }
        _ = terminaison.recv() => {}
    }
}
