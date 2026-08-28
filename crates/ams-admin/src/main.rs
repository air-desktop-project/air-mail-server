//! L'outil de contrôle et de configuration — binaire `air-mail-admin` (C12).
//!
//! # Il est le SEUL moyen de produire une configuration
//!
//! C11 veut un fichier **binaire** : la configuration n'est donc pas éditable à
//! la main, et cet outil n'est pas une commodité — c'est la conséquence directe
//! du format. `air-mail-server` ne lit qu'un fichier ; il ne se règle pas par sa
//! ligne de commande, parce que deux sources de configuration seraient une de
//! trop.
//!
//! # Et il sait regarder une boîte
//!
//! `summary` n'est pas un ornement : c'est la reconstruction de C13 exécutée à la
//! demande, celle qui prouve que les fichiers suffisent à retrouver ce que
//! l'index dirait.

mod options;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ams_config::Configuration;
use ams_store::Maildir;

use crate::options::{Demande, OPTIONS_AIDE};

/// Le texte de `--help`.
const AIDE: &str = "\
air-mail-admin — contrôle et configuration d'air-mail-server

USAGE
    air-mail-admin <COMMANDE> [ARGUMENTS]

COMMANDES
    config write <fichier> [OPTIONS]
                        écrit une configuration BINAIRE. C'est le seul moyen
                        d'en produire une : le format n'est pas éditable à la
                        main, et c'est délibéré.
    config show <fichier>
                        relit une configuration et l'affiche.
    summary <maildir>   relit une boîte et rend ce que ses noms de fichiers
                        portent : messages numérotés, messages à adopter, noms
                        illisibles, et le prochain UID.
    --help              ce texte
    --version           la version
";

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let mots: Vec<&str> = arguments.iter().map(String::as_str).collect();
    match mots.as_slice() {
        [] | ["--help" | "-h"] => {
            println!("{AIDE}\n{OPTIONS_AIDE}");
            ExitCode::SUCCESS
        }
        ["--version" | "-V"] => {
            println!("air-mail-admin {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        ["summary", racine] => resumer(Path::new(racine)),
        ["config", "write", fichier, reste @ ..] => ecrire(Path::new(fichier), reste),
        ["config", "show", fichier] => montrer(Path::new(fichier)),
        autre => {
            eprintln!("air-mail-admin : commande inconnue : {autre:?}");
            eprintln!("Essayez `air-mail-admin --help`.");
            ExitCode::from(2)
        }
    }
}

/// Écrit une configuration binaire.
fn ecrire(fichier: &Path, arguments: &[&str]) -> ExitCode {
    let options = match options::parse(arguments) {
        Ok(Demande::Ecrire(options)) => *options,
        Ok(Demande::Aide) => {
            println!("{OPTIONS_AIDE}");
            return ExitCode::SUCCESS;
        }
        Ok(Demande::Version) => {
            println!("air-mail-admin {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Err(erreur) => {
            eprintln!("air-mail-admin : {}", erreur.message);
            return ExitCode::from(2);
        }
    };

    let config = options.en_configuration();
    let octets = match ams_config::encode(&config) {
        Ok(octets) => octets,
        Err(erreur) => {
            eprintln!("air-mail-admin : {erreur}");
            return ExitCode::FAILURE;
        }
    };
    // On RELIT ce qu'on vient d'écrire, avant de le poser sur le disque. Un
    // fichier de configuration que le serveur refuserait de charger n'a aucune
    // raison d'exister, et le découvrir au démarrage coûte plus cher que de le
    // découvrir ici.
    if let Err(erreur) = ams_config::decode(&octets) {
        eprintln!("air-mail-admin : la configuration écrite ne se relit pas : {erreur}");
        return ExitCode::FAILURE;
    }
    if let Err(erreur) = std::fs::write(fichier, &octets) {
        eprintln!("air-mail-admin : `{}` : {erreur}", fichier.display());
        return ExitCode::FAILURE;
    }
    println!(
        "écrit : {} ({} octets) — domaine `{}`, écoute `{}`",
        fichier.display(),
        octets.len(),
        config.domain,
        config.listen
    );
    if config.hosted.is_empty() {
        println!(
            "ATTENTION  aucun domaine hébergé : ce serveur n'acceptera de courrier \
             pour personne."
        );
    }
    ExitCode::SUCCESS
}

/// Relit une configuration et l'affiche.
fn montrer(fichier: &Path) -> ExitCode {
    let octets = match std::fs::read(fichier) {
        Ok(octets) => octets,
        Err(erreur) => {
            eprintln!("air-mail-admin : `{}` : {erreur}", fichier.display());
            return ExitCode::FAILURE;
        }
    };
    let config = match ams_config::decode(&octets) {
        Ok(config) => config,
        Err(erreur) => {
            eprintln!("air-mail-admin : `{}` : {erreur}", fichier.display());
            return ExitCode::FAILURE;
        }
    };
    afficher(&config);
    ExitCode::SUCCESS
}

/// Rend une configuration lisible par un humain.
fn afficher(config: &Configuration) {
    println!("domaine            {}", config.domain);
    println!("écoute             {}", config.listen);
    println!("boîte              {}", config.maildir);
    println!(
        "domaines hébergés  {}",
        if config.hosted.is_empty() {
            String::from("(aucun)")
        } else {
            config.hosted.join(", ")
        }
    );
    println!("destinataires max  {}", config.max_recipients);
    println!("message max        {} octets", config.max_message_octets);
    println!("connexions max     {}", config.max_connections);
    println!("sources suivies    {}", config.tracked_sources);
    println!(
        "garde              {} conn./min, {} cmd./min, {} trames invalides/min, ban {} s",
        config.guard.connections_per_minute,
        config.guard.commands_per_minute,
        config.guard.invalid_frames_per_minute,
        config.guard.ban_duration.as_secs()
    );
    println!(
        "préfixes comptés   IPv4 /{}, IPv6 /{}",
        config.guard.ipv4_prefix_bits, config.guard.ipv6_prefix_bits
    );
    println!(
        "délais             commande {} s, données {} s",
        config.timeouts.command_seconds, config.timeouts.data_seconds
    );
    // ON DIT « EN CLAIR » PLUTÔT QUE DE SE TAIRE. Une ligne absente se lit comme
    // « rien à signaler » ; or servir en clair est précisément ce qu'il faut
    // signaler.
    if config.tls.est_configure() {
        println!("TLS                STARTTLS offert");
        println!("  certificat       {}", config.tls.certificate_chain_path);
        println!("  clé privée       {}", config.tls.private_key_path);
    } else {
        println!("TLS                AUCUN — le serveur sert EN CLAIR");
    }
}

/// Relit une boîte et rend ce que ses noms portent.
fn resumer(racine: &Path) -> ExitCode {
    // Le nom d'hôte ne sert qu'à composer de NOUVEAUX noms ; relire n'en a pas
    // besoin, mais l'ouverture ADOPTE ce qui traîne, et l'adoption en compose.
    let boite = match Maildir::open(PathBuf::from(racine), b"air-mail-admin") {
        Ok(boite) => boite,
        Err(erreur) => {
            eprintln!("air-mail-admin : `{}` : {erreur}", racine.display());
            return ExitCode::FAILURE;
        }
    };
    let resume = match boite.summary() {
        Ok(resume) => resume,
        Err(erreur) => {
            eprintln!("air-mail-admin : `{}` : {erreur}", racine.display());
            return ExitCode::FAILURE;
        }
    };

    println!("boîte             {}", racine.display());
    println!("messages          {}", resume.numbered);
    println!("sans UID          {}", resume.unnumbered);
    println!("noms illisibles   {}", resume.unreadable);
    println!("prochain UID      {}", resume.next_uid.value());
    if resume.exhausted {
        // Ce n'est pas un détail : au-delà, il n'y a plus d'UID à donner sans
        // changer l'`UIDVALIDITY`, ce qui fait retélécharger la boîte entière à
        // tous les clients.
        println!("ATTENTION         la boîte a épuisé ses UID ; son `UIDVALIDITY` doit changer");
    }
    ExitCode::SUCCESS
}
