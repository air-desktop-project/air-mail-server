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

use ams_auth::Account;
use ams_config::{Configuration, Enforcement};
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
    account add <fichier> --login <nom> [--address <adresse>]...
                        ajoute ou remplace un compte. LE MOT DE PASSE SE LIT SUR
                        L'ENTRÉE STANDARD, jamais sur la ligne de commande : ce
                        que `ps` affiche, tout le monde le lit.
                        `--address` est répétable, et donne les adresses qui
                        arrivent dans la boîte de ce compte. SANS AUCUNE, le
                        compte se connecte mais ne reçoit rien.
                        Le nom du compte est aussi le nom de sa boîte : ni vide,
                        ni `.`, ni `..`, sans `/`, et sans point en tête.
    account list <fichier>
                        liste les noms de comptes. Jamais les empreintes.
    account remove <fichier> --login <nom>
                        retire un compte.
    summary <maildir>   relit une boîte et rend ce que ses noms de fichiers
                        portent : messages numérotés, messages à adopter, noms
                        illisibles, et le prochain UID.
    --help              ce texte
    --version           la version
";

/// Rend à `SIGPIPE` son comportement par défaut.
///
/// # Pourquoi un outil en ligne de commande en a besoin
///
/// Rust ignore `SIGPIPE` au démarrage, ce qui convient à un serveur : une
/// écriture sur une connexion fermée doit rendre une erreur, pas tuer le
/// processus. Pour un outil dont on lit la sortie dans un tube, cela donne
/// l'inverse de ce qu'on veut : `… | head -3` fait PANIQUER le programme sur
/// « Broken pipe » au lieu de le faire finir en silence.
///
/// On rétablit donc le comportement d'Unix, celui que `head` et `grep`
/// attendent de tout ce qu'ils lisent.
fn rendre_sigpipe_au_systeme() {
    // SAFETY: `signal` avec `SIG_DFL` sur `SIGPIPE` est l'appel que fait tout
    // programme C au démarrage ; il ne touche à aucune mémoire de ce processus.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

fn main() -> ExitCode {
    rendre_sigpipe_au_systeme();
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
        ["account", "add", fichier, "--login", nom, reste @ ..] => match adresses_de(reste) {
            Ok(adresses) => ajouter(Path::new(fichier), nom, &adresses),
            Err(message) => {
                eprintln!("air-mail-admin : {message}");
                ExitCode::from(2)
            }
        },
        ["account", "list", fichier] => lister(Path::new(fichier)),
        ["account", "remove", fichier, "--login", nom] => retirer(Path::new(fichier), nom),
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
    println!(
        "écoute POP3        {}",
        if config.listen_pop3.is_empty() {
            "(aucune — POP3 n'est pas servi)"
        } else {
            &config.listen_pop3
        }
    );
    println!(
        "écoute IMAP        {}",
        if config.listen_imap.is_empty() {
            "(aucune — IMAP n'est pas servi)"
        } else {
            &config.listen_imap
        }
    );
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
    // Et de même pour SPF : ne rien afficher se lirait « rien à signaler », or
    // un serveur qui ne vérifie pas l'expéditeur accepte du courrier au nom de
    // n'importe qui.
    if config.spf.est_configure() {
        println!(
            "SPF                {}",
            match config.spf.enforcement {
                Enforcement::Enforce =>
                    "APPLIQUÉ — un `fail` est refusé (550), une panne \
                                         ajournée (451)",
                Enforcement::Observe => "vérifié et RETENU, sans rien opposer",
            }
        );
        println!("  résolveurs       {}", config.spf.resolvers.join(", "));
        println!("  délai par requête {} ms", config.spf.timeout_millis);
        println!("  DNSSEC           NON VALIDÉ — ces résolveurs sont crus sur parole");
    } else {
        println!("SPF                AUCUN RÉSOLVEUR — l'expéditeur n'est pas vérifié");
    }
    if config.dmarc.est_configure() {
        println!(
            "DMARC              {}",
            match config.dmarc.enforcement {
                Enforcement::Enforce => "APPLIQUÉ — un `p=reject` est opposé (550)",
                Enforcement::Observe => "évalué et RETENU, sans rien opposer",
            }
        );
        println!("  suffixes publics {}", config.dmarc.public_suffix_list);
        if config.dmarc.rapporte() {
            println!("  rapports         {}", config.dmarc.report_directory);
            println!(
                "  vidange          toutes les {} s",
                if config.dmarc.report_interval_seconds == 0 {
                    86_400
                } else {
                    config.dmarc.report_interval_seconds
                }
            );
            if config.dmarc.rapporte_les_echecs() {
                println!("  rapports d'échec OUI — en-têtes filtrés, corps jamais recopié");
            } else {
                println!("  rapports d'échec NON — seuls les rapports agrégés sont composés");
            }
            if config.dmarc.envoie() {
                println!("  remise           OUI — vers les destinations qui ont consenti (§7.1)");
            } else {
                println!("  remise           NON — les rapports sont déposés, pas envoyés");
            }
        } else {
            println!("  rapports         AUCUN DOSSIER — rien n'est rapporté aux domaines");
        }
    } else {
        println!("DMARC              AUCUNE LISTE DE SUFFIXES — l'alignement n'est pas évalué");
    }
    // Là encore, on DIT l'absence. Une ligne manquante se lit « rien à
    // signaler » ; or un serveur sans comptes n'authentifie personne, et c'est
    // précisément ce qu'il faut signaler.
    if config.accounts.is_empty() {
        println!("comptes            AUCUN — `AUTH` n'est pas annoncé");
    } else {
        println!("comptes            {}", config.accounts);
    }
}

/// Lit le magasin, ou rend un magasin vide si le fichier n'existe pas encore.
///
/// **Un fichier absent n'est pas une erreur** pour `account add` : c'est le
/// premier compte. Il en est une pour `list` et `remove`, qui n'ont rien à dire
/// d'un fichier qui n'existe pas.
fn lire_magasin(fichier: &Path, tolerer_absence: bool) -> Result<Vec<Account>, String> {
    match std::fs::read(fichier) {
        Ok(octets) => ams_config::decode_accounts(&octets)
            .map_err(|erreur| format!("`{}` : {erreur}", fichier.display())),
        Err(erreur) if tolerer_absence && erreur.kind() == std::io::ErrorKind::NotFound => {
            Ok(Vec::new())
        }
        Err(erreur) => Err(format!("`{}` : {erreur}", fichier.display())),
    }
}

/// Écrit le magasin, en `0600`.
///
/// # Les permissions sont posées AVANT le contenu
///
/// Un fichier créé en `0644` puis resserré est lisible par tout le monde
/// pendant l'intervalle. Court, mais réel — et il n'y a aucune raison de le
/// laisser ouvert une seule instruction.
fn ecrire_magasin(fichier: &Path, comptes: &[Account]) -> Result<(), String> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let octets =
        ams_config::encode_accounts(comptes).map_err(|erreur| format!("encodage : {erreur}"))?;
    let mut sortie = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(fichier)
        .map_err(|erreur| format!("`{}` : {erreur}", fichier.display()))?;
    sortie
        .write_all(&octets)
        .map_err(|erreur| format!("`{}` : {erreur}", fichier.display()))?;
    Ok(())
}

/// Lit un mot de passe sur l'entrée standard.
///
/// # Pourquoi pas une option de ligne de commande
///
/// Parce que `ps` l'afficherait à tous les comptes de la machine, et que
/// l'historique du shell le garderait. Un mot de passe passé en argument est un
/// mot de passe publié.
///
/// L'écho n'est pas coupé : cela demanderait `termios`, et cet outil n'a pas de
/// dépendance système. L'usage prévu est donc le tube —
/// `printf %s "$MDP" | air-mail-admin account add …` — et le texte d'aide le dit.
fn lire_mot_de_passe() -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    let mut secret = Vec::new();
    std::io::stdin()
        .read_to_end(&mut secret)
        .map_err(|erreur| format!("lecture du mot de passe : {erreur}"))?;
    // Un tube ajoute presque toujours un saut de ligne final, et un mot de passe
    // qui finit par `\n` est un mot de passe que personne ne saura retaper.
    while secret
        .last()
        .is_some_and(|&octet| octet == b'\n' || octet == b'\r')
    {
        secret.pop();
    }
    if secret.is_empty() {
        return Err(String::from(
            "mot de passe vide : il se lit sur l'entrée standard, par exemple \
             `printf %s \"$MDP\" | air-mail-admin account add …`",
        ));
    }
    Ok(secret)
}

/// Un sel de seize octets, tiré du noyau.
///
/// `/dev/urandom` plutôt qu'une crate : ce binaire est déjà Unix seulement
/// (C10), et une dépendance de plus pour seize octets serait une dépendance de
/// plus à surveiller.
fn sel() -> Result<[u8; 16], String> {
    use std::io::Read as _;
    let mut graine = [0_u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut graine))
        .map_err(|erreur| format!("/dev/urandom : {erreur}"))?;
    Ok(graine)
}

/// Lit les `--address` répétés.
fn adresses_de(arguments: &[&str]) -> Result<Vec<String>, String> {
    let mut adresses = Vec::new();
    let mut reste = arguments.iter();
    while let Some(argument) = reste.next() {
        if *argument != "--address" {
            return Err(format!("option inconnue : `{argument}`"));
        }
        let valeur = reste
            .next()
            .ok_or_else(|| String::from("`--address` attend une valeur"))?;
        if valeur.is_empty() {
            return Err(String::from("une adresse vide ne désigne personne"));
        }
        adresses.push((*valeur).to_string());
    }
    Ok(adresses)
}

/// Ajoute ou remplace un compte.
fn ajouter(fichier: &Path, nom: &str, adresses: &[String]) -> ExitCode {
    match ajouter_ou_dire(fichier, nom, adresses) {
        Ok(remplace) => {
            println!(
                "{} : compte `{nom}` {}",
                fichier.display(),
                if remplace { "remplacé" } else { "ajouté" }
            );
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("air-mail-admin : {message}");
            ExitCode::FAILURE
        }
    }
}

fn ajouter_ou_dire(fichier: &Path, nom: &str, adresses: &[String]) -> Result<bool, String> {
    // LE MÊME CONTRÔLE QU'AU CHARGEMENT, et devant le terminal : le nom devient
    // un nom de répertoire, et le dire ici coûte une seconde plutôt qu'un
    // démarrage refusé.
    ams_auth::check_login(nom).map_err(|cause| format!("nom de compte : {cause}"))?;
    let secret = lire_mot_de_passe()?;
    let empreinte = ams_auth::hash_password(&secret, &sel()?)
        .map_err(|erreur| format!("hachage : {erreur}"))?;

    let mut comptes = lire_magasin(fichier, true)?;
    let remplace = comptes.iter().any(|compte| compte.login == nom);
    comptes.retain(|compte| compte.login != nom);
    comptes.push(Account {
        login: nom.to_string(),
        hash: empreinte,
        addresses: adresses.to_vec(),
    });
    // ON RELIT CE QU'ON VIENT D'ÉCRIRE avant de le poser sur le disque : c'est
    // la même discipline que `config write`. Un magasin illisible découvert au
    // démarrage du serveur coûte bien plus cher qu'ici.
    let octets =
        ams_config::encode_accounts(&comptes).map_err(|erreur| format!("encodage : {erreur}"))?;
    ams_config::decode_accounts(&octets)
        .map_err(|erreur| format!("le magasin écrit ne se relit pas : {erreur}"))?;
    ecrire_magasin(fichier, &comptes)?;
    Ok(remplace)
}

/// Liste les noms de comptes — **jamais les empreintes**.
fn lister(fichier: &Path) -> ExitCode {
    match lire_magasin(fichier, false) {
        Ok(comptes) if comptes.is_empty() => {
            println!("{} : aucun compte", fichier.display());
            ExitCode::SUCCESS
        }
        Ok(comptes) => {
            for compte in &comptes {
                // LE NOM ET LES ADRESSES, JAMAIS L'EMPREINTE. Elle n'a rien à
                // faire dans un terminal, un journal ou une capture d'écran.
                if compte.addresses.is_empty() {
                    println!(
                        "{}  (aucune adresse — ce compte ne reçoit rien)",
                        compte.login
                    );
                } else {
                    println!("{}  {}", compte.login, compte.addresses.join(", "));
                }
            }
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("air-mail-admin : {message}");
            ExitCode::FAILURE
        }
    }
}

/// Retire un compte.
fn retirer(fichier: &Path, nom: &str) -> ExitCode {
    let resultat = lire_magasin(fichier, false).and_then(|mut comptes| {
        let avant = comptes.len();
        comptes.retain(|compte| compte.login != nom);
        if comptes.len() == avant {
            return Err(format!("aucun compte `{nom}` dans ce magasin"));
        }
        ecrire_magasin(fichier, &comptes)
    });
    match resultat {
        Ok(()) => {
            println!("{} : compte `{nom}` retiré", fichier.display());
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("air-mail-admin : {message}");
            ExitCode::FAILURE
        }
    }
}

/// Relit une boîte et rend ce que ses noms portent.
fn resumer(racine: &Path) -> ExitCode {
    // Le nom d'hôte ne sert qu'à composer de NOUVEAUX noms ; relire n'en a pas
    // besoin, mais l'ouverture ADOPTE ce qui traîne, et l'adoption en compose.
    let boite = match Maildir::open(
        PathBuf::from(racine),
        b"air-mail-admin",
        // Une boîte SANS index en reçoit un, avec cette validité-ci. C'est une
        // réparation, pas un effet de bord subi : le serveur en ferait autant à
        // sa prochaine ouverture, et une boîte qui a déjà un index garde le sien.
        ams_store::fresh_uid_validity(),
    ) {
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
    println!("UIDVALIDITY       {}", boite.uid_validity().value());
    println!("messages          {}", resume.numbered);
    println!("sans UID          {}", resume.unnumbered);
    println!("noms illisibles   {}", resume.unreadable);
    // DEUX NOMBRES, ET CE N'EST PAS UNE REDONDANCE. Le premier dit ce que les
    // FICHIERS portent ; le second, ce que la boîte SERVIRA — plus loin après
    // une réouverture, parce que le filigrane écrit couvre les UID réservés.
    // N'en montrer qu'un ferait annoncer un numéro qui ne sera pas donné.
    println!("plus grand UID +1 {}", resume.next_uid.value());
    println!("prochain UID servi {}", boite.next_uid().value());
    if resume.exhausted {
        // Ce n'est pas un détail : au-delà, il n'y a plus d'UID à donner sans
        // changer l'`UIDVALIDITY`, ce qui fait retélécharger la boîte entière à
        // tous les clients.
        println!("ATTENTION         la boîte a épuisé ses UID ; son `UIDVALIDITY` doit changer");
    }
    ExitCode::SUCCESS
}
