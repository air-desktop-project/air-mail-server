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

mod delivery;
mod options;
mod policy;

use std::process::ExitCode;
use std::sync::Arc;

use ams_guard::Thresholds;
use ams_loop_tokio::{ServeOptions, SharedGuard, Timeouts, refuse_root, serve};
use ams_proto_smtp::Limits;
use ams_session::Config;
use ams_store::Maildir;
use tokio::net::TcpListener;

use crate::delivery::MaildirDelivery;
use crate::options::{AIDE, Demande, Options};
use crate::policy::DomainesHeberges;

/// Le nombre de sources que le garde suit en même temps.
///
/// Sa mémoire est bornée par construction (C8) : au-delà, il cesse d'apprendre
/// plutôt que d'oublier une peine en cours.
const SOURCES_SUIVIES: usize = 4096;

/// L'ordonnanceur est MULTI-FILS, et ce n'est pas un défaut de configuration :
/// la remise Maildir appelle `block_in_place` pour ses `fsync`, qui panique sur
/// l'ordonnanceur mono-fil.
#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let demande = match options::parse(&arguments) {
        Ok(demande) => demande,
        Err(erreur) => {
            eprintln!("air-mail-server : {}", erreur.message);
            eprintln!("Essayez `air-mail-server --help`.");
            return ExitCode::from(2);
        }
    };

    let options = match demande {
        Demande::Aide => {
            println!("{AIDE}");
            return ExitCode::SUCCESS;
        }
        Demande::Version => {
            println!("air-mail-server {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Demande::Servir(options) => *options,
    };

    match servir(options).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("air-mail-server : {message}");
            ExitCode::FAILURE
        }
    }
}

/// Monte le serveur et le fait tourner jusqu'à l'arrêt.
async fn servir(options: Options) -> Result<(), String> {
    // LE REFUS DU SUPERUTILISATEUR VIENT AVANT TOUT LE RESTE (C10) — avant
    // d'ouvrir un port, avant de créer un répertoire. Rien de ce qui suit ne doit
    // s'exécuter avec ces privilèges, pas même une seconde.
    refuse_root().map_err(|erreur| erreur.to_string())?;

    if options.hosted.is_empty() {
        eprintln!(
            "air-mail-server : aucun `--hosted` : ce serveur n'acceptera de courrier \
             pour personne."
        );
    }

    // Le domaine vit aussi longtemps que le processus. Le fuir est ici exact :
    // il est lu une fois, jamais remplacé, et libéré à la sortie du programme.
    let domaine: &'static [u8] = Box::leak(options.domain.clone().into_bytes().into_boxed_slice());
    let config = Config::new(domaine, 100, options.max_message_octets, Limits::DEFAULT)
        .map_err(|erreur| format!("domaine `{}` : {erreur}", options.domain))?;

    let boite = Arc::new(
        Maildir::open(&options.maildir, domaine)
            .map_err(|erreur| format!("boîte `{}` : {erreur}", options.maildir.display()))?,
    );
    let resume = boite
        .summary()
        .map_err(|erreur| format!("lecture de la boîte : {erreur}"))?;

    let ecouteur = TcpListener::bind(options.listen)
        .await
        .map_err(|erreur| format!("écoute sur {} : {erreur}", options.listen))?;

    eprintln!(
        "air-mail-server {} : {} écoute sur {}, boîte `{}` ({} message(s), prochain UID {})",
        env!("CARGO_PKG_VERSION"),
        options.domain,
        options.listen,
        options.maildir.display(),
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

    let garde = Arc::new(SharedGuard::new(SOURCES_SUIVIES, Thresholds::DEFAULT));
    let politique = Arc::new(DomainesHeberges::new(&options.hosted));
    let pour_la_remise = Arc::clone(&boite);

    let stats = serve(
        ecouteur,
        config,
        politique,
        garde,
        move || MaildirDelivery::new(Arc::clone(&pour_la_remise)),
        ServeOptions {
            max_connections: options.max_connections,
            timeouts: Timeouts::default(),
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
