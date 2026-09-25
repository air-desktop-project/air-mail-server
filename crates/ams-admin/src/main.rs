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

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ams_auth::Account;
use ams_config::{Configuration, Enforcement};
use ams_store::Maildir;

use ams_admin_options::{Demande, OPTIONS_AIDE};

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
                        LES SEUILS DU GARDE S'Y RÈGLENT (C8) : `config write
                        --help` les liste, et dit où zéro veut dire « jamais »
                        et où il veut dire « tout de suite ».
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
    account passwd <fichier> --login <nom>
                        change LE SEUL MOT DE PASSE d'un compte existant. Le
                        secret se lit sur l'entrée standard, comme pour `add`.
                        À PRÉFÉRER À `account add` POUR CE SEUL USAGE : `add`
                        remplace le compte ENTIER, et sans ses `--address` il
                        les efface — le compte s'authentifie encore et ne reçoit
                        plus rien, sans que rien ne le dise.
                        Un compte inconnu est REFUSÉ, et le magasin n'est pas
                        touché : une faute de frappe ferait créer par `add` un
                        compte fantôme portant le secret qu'on croyait poser
                        ailleurs.
    account add|passwd … --scram-key <clé> --scram <fichier>
                        pose AUSSI un vérificateur SCRAM pour ce compte, dans un
                        magasin SÉPARÉ et SCELLÉ. Les deux options vont
                        ensemble, ou aucune : sans elles, SCRAM n'existe pas —
                        ni annoncé, ni stocké.
                        LE VÉRIFICATEUR NE SE DÉRIVE QUE DU MOT DE PASSE EN
                        CLAIR : un compte créé sans ces options n'en aura
                        jamais, tant que son mot de passe n'aura pas été reposé.
    scram init <clé>    tire la clé de scellement du magasin SCRAM — trente-deux
                        octets du noyau, en 0600. RANGEZ-LA AILLEURS QUE LE
                        MAGASIN : c'est toute la raison d'être des deux
                        fichiers. Refuse d'écraser une clé existante, parce
                        qu'une clé perdue rend tous les vérificateurs illisibles.
    scram bind <comptes> --scram-key <clé> --scram <fichier>
                        lie à l'empreinte ACTUELLE de leur compte les
                        vérificateurs écrits avant la 0.2.16 — qui, sans cela,
                        ne s'ouvrent plus. À lancer UNE FOIS après la mise à
                        jour. N'EMPLOYEZ-LA QUE SI AUCUN MOT DE PASSE N'A ÉTÉ
                        CHANGÉ PAR L'API depuis la dernière dérivation : lier
                        le vérificateur d'un ancien mot de passe le rouvrirait.
                        En cas de doute, `account passwd --scram` redérive.
    account list <fichier>
                        liste les noms de comptes. Jamais les empreintes.
    account remove <fichier> --login <nom>
                        retire un compte.
    config write … --relay --queue-spool <chemin>
                        ouvre l'ÉMISSION pour les comptes authentifiés. Éteinte
                        par défaut : ce serveur reçoit, il n'émet pas.
    config write … --listen-http <adr> --tls-cert … --tls-key …
                        ouvre l'API REST d'administration. Éteinte par défaut.
                        LE SECRET DE SCELLEMENT EST TIRÉ DU NOYAU à la première
                        écriture qui l'ouvre, puis REPRIS à chaque écriture
                        suivante — les jetons en cours restent donc valables
                        quand on change autre chose. Personne n'a besoin de le
                        connaître, et personne n'a donc à le garder.
    token <config> --login <nom> [--minutes <n>]
                        frappe un jeton d'ADMINISTRATION, et l'écrit sur la
                        sortie standard. Il se scelle avec le secret que la
                        configuration porte, donc depuis la machine du serveur
                        et par qui peut lire ce fichier.
                        AUCUN MOT DE PASSE N'OUVRE L'ADMINISTRATION : c'est ce
                        qui fait qu'un compte compromis ne devient jamais le
                        serveur entier, et c'est pourquoi ce jeton se frappe ici.
                        `--minutes` vaut 15 par défaut, et douze heures au plus.
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

/// Restreint le masque de création : **rien pour le groupe, rien pour les
/// autres**.
///
/// # Pourquoi cet outil en a besoin autant que le serveur
///
/// Il écrit les deux fichiers les plus sensibles du service : la configuration,
/// qui porte le secret de scellement des jetons d'administration, et le magasin
/// des comptes, qui porte les empreintes des mots de passe. Le second posait
/// déjà `0600` à l'ouverture ; le premier passait par `std::fs::write`, donc
/// `0666` moins le masque hérité — `0644` avec celui que donne un shell
/// ordinaire.
///
/// Le modèle de sécurité du jeton repose pourtant, mot pour mot, sur « la
/// machine du serveur, PAR QUI PEUT LIRE CE FICHIER ». Écrit en `0644`, ce
/// fichier se lit par tout le monde, et cette phrase devient fausse.
///
/// C'est le même choix que dans le serveur : un masque de processus plutôt qu'un
/// mode à chaque appel, parce que le mode à chaque appel est ce qui a été oublié.
fn restreindre_le_masque() {
    // SAFETY : `umask` ne prend qu'un entier, ne touche à aucune mémoire de ce
    // processus et ne peut pas échouer. Cet outil est monofil, et l'appel a lieu
    // avant tout le reste.
    unsafe {
        libc::umask(0o077);
    }
}

/// L'aide à écrire si l'un des arguments la demande, ou `None`.
///
/// # `--help` N'EST JAMAIS UN CHEMIN
///
/// Chaque commande prend un chemin en PREMIÈRE position, et le dispatch le
/// prenait tel quel. `config write --help` écrivait donc une configuration dans
/// un fichier NOMMÉ `--help` — en annonçant son succès —, et les six autres
/// commandes rendaient une erreur de lecture sur un fichier de ce nom, ou un
/// « commande inconnue ».
///
/// L'aide de cet outil promettait pourtant, mot pour mot : « `config write
/// --help` les liste ». Sept commandes, sept réponses fausses, dont une qui
/// crée un fichier difficile à effacer sans savoir que `rm -- ./--help` est
/// nécessaire.
///
/// # UNE SEULE RÈGLE, ET NON SEPT BRAS
///
/// Sept bras se maintiennent mal : la huitième commande oublierait le sien, et
/// c'est exactement la forme de défaut que ce dépôt a corrigée six fois. La
/// règle est donc unique et vient AVANT le dispatch — `--help` demande l'aide,
/// où qu'il se trouve, et ne peut plus être pris pour autre chose.
///
/// `config write` montre ses propres options : ce sont les seules qu'il y ait,
/// et c'est ce que l'aide générale renvoie chercher.
fn aide_demandee(mots: &[&str]) -> Option<&'static str> {
    if !mots.iter().any(|mot| matches!(*mot, "--help" | "-h")) {
        return None;
    }
    if matches!(mots.first(), Some(&"config")) && matches!(mots.get(1), Some(&"write")) {
        return Some(OPTIONS_AIDE);
    }
    Some(AIDE)
}

fn main() -> ExitCode {
    rendre_sigpipe_au_systeme();
    restreindre_le_masque();
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let mots: Vec<&str> = arguments.iter().map(String::as_str).collect();
    if let Some(texte) = aide_demandee(&mots) {
        println!("{texte}");
        return ExitCode::SUCCESS;
    }
    match mots.as_slice() {
        [] => {
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
        ["account", "add", fichier, "--login", nom, reste @ ..] => match demande_de_compte(reste) {
            Ok((adresses, scram)) => ajouter(Path::new(fichier), nom, &adresses, scram.as_ref()),
            Err(message) => {
                eprintln!("air-mail-admin : {message}");
                ExitCode::from(2)
            }
        },
        ["scram", "init", clef] => initialiser_la_clef(Path::new(clef)),
        [
            "scram",
            "bind",
            fichier,
            "--scram-key",
            clef,
            "--scram",
            magasin,
        ] => lier_les_verificateurs(Path::new(fichier), Path::new(clef), Path::new(magasin)),
        ["account", "list", fichier] => lister(Path::new(fichier)),
        ["account", "passwd", fichier, "--login", nom, reste @ ..] => {
            match demande_de_compte(reste) {
                Ok((adresses, scram)) if adresses.is_empty() => {
                    changer_le_secret(Path::new(fichier), nom, scram.as_ref())
                }
                // **`passwd` NE PREND PAS D'ADRESSE**, et le dire vaut mieux que
                // de l'ignorer : qui en passe une croit la poser.
                Ok(_) => {
                    eprintln!(
                        "air-mail-admin : `account passwd` ne change QUE le secret — \
                         `--address` n'a pas de sens ici, et `account add` les pose."
                    );
                    ExitCode::from(2)
                }
                Err(message) => {
                    eprintln!("air-mail-admin : {message}");
                    ExitCode::from(2)
                }
            }
        }
        ["token", fichier, reste @ ..] => match jeton_demande(reste) {
            Ok((nom, minutes)) => frapper(Path::new(fichier), &nom, minutes),
            Err(quoi) => {
                eprintln!("air-mail-admin : {quoi}");
                ExitCode::FAILURE
            }
        },
        ["account", "remove", fichier, "--login", nom] => retirer(Path::new(fichier), nom),
        autre => {
            eprintln!("air-mail-admin : commande inconnue : {autre:?}");
            eprintln!("Essayez `air-mail-admin --help`.");
            ExitCode::from(2)
        }
    }
}

/// Ce qu'on a décidé du secret de scellement, et ce qu'on en dit.
struct Scellement {
    /// La clé à écrire — hexadécimale, ou vide s'il n'y a pas d'API.
    clef: String,
    /// La ligne à afficher, ou `None` s'il n'y a rien à dire.
    ///
    /// **CE QUI NE CHANGE PAS NE SE DIT PAS** : une ligne « secret repris » à
    /// chaque écriture d'un serveur sans API est une ligne qu'on cesse de lire,
    /// et c'est alors la ligne qui compte qu'on manque.
    dire: Option<String>,
}

/// Décide du secret de scellement : le REPRENDRE, le TIRER, ou rien.
///
/// # Pourquoi cet outil lit le fichier qu'il va remplacer
///
/// C'est la seule valeur d'une configuration qui ne vienne pas des options, et
/// ce n'est pas une inconséquence. Un secret de scellement ne doit être connu de
/// personne : ni de celui qui tape la commande, ni de son historique de shell,
/// ni de `ps`. Le donner en argument serait le publier ; le lire sur l'entrée
/// standard obligerait à le CONSERVER quelque part pour le refournir à chaque
/// écriture, c'est-à-dire à en faire un secret de plus à garder.
///
/// Il est donc tiré du noyau la première fois que l'API est demandée, puis
/// repris tel quel — ce qui laisse valables les jetons en cours quand on change
/// autre chose dans la configuration. `--rotate-token-key` le renouvelle
/// explicitement, et dit alors ce que cela coûte.
///
/// # ON REFUSE D'ÉCRASER CE QU'ON NE RECONNAÎT PAS
///
/// Un fichier présent qui ne se décode pas n'est peut-être pas le nôtre : un
/// chemin tapé de travers désigne un fichier de quelqu'un d'autre, et
/// `config write` l'écraserait sans un mot. Le refus protège donc bien au-delà
/// du secret — et il se lève en effaçant le fichier soi-même, ce qui demande de
/// l'avoir regardé.
///
/// # Errors
///
/// Le message à afficher : fichier illisible, ou illisible EN TANT QUE
/// configuration.
fn sceller(fichier: &Path, config: &Configuration, renouveler: bool) -> Result<Scellement, String> {
    let ancienne = match std::fs::read(fichier) {
        Ok(octets) => match ams_config::decode(&octets) {
            Ok(ancienne) => Some(ancienne),
            Err(erreur) => {
                return Err(format!(
                    "`{}` existe mais n'est pas une configuration ({erreur}) — ce n'est \
                     peut-être pas le fichier que vous croyez. Effacez-le si c'en est bien un \
                     que vous voulez remplacer.",
                    fichier.display()
                ));
            }
        },
        Err(erreur) if erreur.kind() == std::io::ErrorKind::NotFound => None,
        Err(erreur) => {
            return Err(format!("`{}` : {erreur}", fichier.display()));
        }
    };
    let ancien = ancienne.map(|config| config.token_key).unwrap_or_default();
    let sert_l_api = !config.listen_http.is_empty() || !config.listen_h3.is_empty();

    if renouveler {
        return Ok(Scellement {
            clef: secret_de_scellement()?,
            dire: Some(String::from(
                "secret RENOUVELÉ — les jetons frappés avant cet instant ne valent plus",
            )),
        });
    }
    if !ancien.is_empty() {
        return Ok(Scellement {
            clef: ancien,
            // On ne le dit que si quelqu'un s'en sert : sinon, c'est du bruit.
            dire: sert_l_api.then(|| {
                String::from(
                    "secret REPRIS du fichier existant — les jetons en cours valent \
                              toujours",
                )
            }),
        });
    }
    if sert_l_api {
        return Ok(Scellement {
            clef: secret_de_scellement()?,
            dire: Some(String::from(
                "secret TIRÉ (32 octets) — les jetons se frappent avec `air-mail-admin token`",
            )),
        });
    }
    // PAS D'API, PAS DE SECRET. L'absence de valeur EST l'absence de service :
    // en inventer un ici mettrait dans le fichier une clé que rien n'emploie.
    Ok(Scellement {
        clef: String::new(),
        dire: None,
    })
}

/// Trente-deux octets du noyau, en hexadécimal.
///
/// **C'EST LA LONGUEUR QUE `key_from_hex` EXIGE**, et non un choix de confort :
/// en deçà, elle refuse la clé. La redire ici en chiffres la ferait diverger le
/// jour où l'autre changerait ; c'est pourquoi le tableau est dimensionné par la
/// constante de cette crate-là.
fn secret_de_scellement() -> Result<String, String> {
    use std::io::Read as _;
    let mut graine = [0_u8; ams_api::KEY_OCTETS_MIN];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut graine))
        .map_err(|erreur| format!("/dev/urandom : {erreur}"))?;
    Ok(graine.iter().map(|octet| format!("{octet:02x}")).collect())
}

/// Écrit une configuration binaire.
fn ecrire(fichier: &Path, arguments: &[&str]) -> ExitCode {
    let options = match ams_admin_options::parse(arguments) {
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

    let mut config = options.en_configuration();

    // **LE SECRET DU RELAIS SE LIT SUR L'ENTRÉE STANDARD**, comme celui d'un
    // compte, et pour la même raison : ce que `ps` affiche, tout le monde le
    // lit — y compris les autres comptes de la machine, et les journaux du
    // shell.
    //
    // On ne le demande QUE si un relais est nommé, et l'on RÉÉCRIT alors la
    // configuration : le mot de passe n'a jamais transité par `parse`.
    if !config.relay.relayhost.is_empty() {
        match lire_mot_de_passe() {
            Ok(secret) => match std::string::String::from_utf8(secret) {
                Ok(texte) => config.relay.relayhost_password = texte,
                Err(_) => {
                    eprintln!(
                        "air-mail-admin : le mot de passe du relais n'est pas de l'UTF-8 valide"
                    );
                    return ExitCode::from(2);
                }
            },
            Err(message) => {
                eprintln!("air-mail-admin : {message}");
                return ExitCode::from(2);
            }
        }
    }

    let scellement = match sceller(fichier, &config, options.rotate_token_key) {
        Ok(quoi) => quoi,
        Err(message) => {
            eprintln!("air-mail-admin : {message}");
            return ExitCode::FAILURE;
        }
    };
    config.token_key = scellement.clef;
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
    // **ET ON LA POSE SANS LA TRONQUER D'ABORD.** `std::fs::write` vide le
    // fichier avant d'écrire : réécrire une configuration et être interrompu
    // laissait un serveur qui ne redémarre plus, alors que l'ancienne était
    // parfaitement valable et qu'on n'avait rien demandé de tel.
    if let Err(erreur) = ams_fichier::poser(fichier, &octets) {
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
    if let Some(dit) = scellement.dire {
        println!("scellement : {dit}");
    }
    println!(
        "garde : {} conn./min, {} cmd./min, {} trames invalides/min, ban {} s, \
         IPv4 /{}, IPv6 /{}, {} sources suivies",
        config.guard.connections_per_minute,
        config.guard.commands_per_minute,
        config.guard.invalid_frames_per_minute,
        config.guard.ban_duration.as_secs(),
        config.guard.ipv4_prefix_bits,
        config.guard.ipv6_prefix_bits,
        config.tracked_sources
    );
    for dit in avertissements(&config) {
        println!("{dit}");
    }
    ExitCode::SUCCESS
}

/// Ce qu'il y a à dire d'inquiétant dans cette configuration.
///
/// # ELLE REND LES LIGNES, ELLE NE LES ÉCRIT PAS
///
/// Ces cinq avertissements ont vécu jusqu'ici dans le corps de `config write`,
/// mêlés aux `println!` qui rendent compte de l'écriture. Aucun essai ne les
/// touchait — cette crate n'en avait AUCUN, et n'est pas dans le périmètre de
/// couverture. C'est ce qui a permis à l'un d'eux d'annoncer pendant longtemps
/// une absence de certificat à qui venait d'en fournir un.
///
/// Une fonction qui REND ce qu'elle a à dire se vérifie ; une fonction qui écrit
/// ne se vérifie qu'en lisant sa sortie, c'est-à-dire jamais. C'est le même choix
/// que pour `Incidents::survenu` du côté serveur.
///
/// # CHACUN NE PARLE QUE SI SA CONDITION TIENT
///
/// C'est la règle de ce bloc, et elle vaut jusqu'à l'intérieur d'une phrase : une
/// clause qui s'imprime quoi qu'il arrive s'adresse aussi à ceux qu'elle ne
/// concerne pas, et leur fait chercher un problème qu'ils n'ont pas.
fn avertissements(config: &Configuration) -> std::vec::Vec<String> {
    let mut dits = std::vec::Vec::new();
    if config.hosted.is_empty() {
        dits.push(String::from(
            "ATTENTION  aucun domaine hébergé : ce serveur n'acceptera de courrier \
             pour personne.",
        ));
    }
    // **UN COMPTEUR ÉTEINT SE DIT AU MOMENT OÙ ON L'ÉTEINT.** Ailleurs, zéro
    // veut dire « tout de suite » ; ici il veut dire « jamais », et c'est
    // exactement l'endroit où quelqu'un peut s'être trompé de sens.
    if config.guard.refused_recipients_per_minute == 0 {
        dits.push(String::from(
            "ATTENTION  récolte d'adresses NON COMPTÉE : `--refused-recipients-per-minute 0` \
             éteint ce compteur. Une rafale de destinataires refusés ne sera plus remarquée.",
        ));
    }
    if config.relay.enabled {
        dits.push(String::from(
            "ATTENTION  ÉMISSION OUVERTE : ce serveur relaiera vers l'extérieur pour tout \
             compte AUTHENTIFIÉ.",
        ));
        // **ET SANS CERTIFICAT, ELLE EST OUVERTE POUR PERSONNE.**
        //
        // L'authentification n'est annoncée que sous chiffrement : `--relay` sans
        // `--tls-cert` ouvre une émission dont aucun compte ne peut se servir.
        // C'est l'avertissement qui COMPTE — et il se disait jusqu'ici dans la
        // même phrase que le précédent, donc aussi à qui avait fourni un
        // certificat. Il s'y noyait, et faisait douter les autres du leur.
        if !config.tls.est_configure() {
            dits.push(String::from(
                "ATTENTION  … et INUTILISABLE : sans `--tls-cert`, l'authentification n'est \
                 pas annoncée, et aucun compte ne pourra donc émettre.",
            ));
        }
    } else if !config.queue.spool.is_empty() {
        dits.push(String::from(
            "ATTENTION  dossier de file nommé SANS `--relay` : rien ne sera émis, et rien \
             n'y sera écrit.",
        ));
    }
    if config.guard.ban_duration.as_secs() == 0 {
        dits.push(String::from(
            "ATTENTION  aucun bannissement : `--ban-seconds 0` fait AJOURNER au lieu de \
             bannir. Une source fautive reviendra à la connexion suivante.",
        ));
    }
    dits
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

/// Comment le TLS se pose sur une écoute, en toutes lettres.
///
/// **LES DEUX MODES OCCUPENT LA MÊME LIGNE**, et rien d'autre ne les distingue :
/// une écoute IMAP sur le 993 en `STARTTLS` et la même en TLS implicite ne
/// diffèrent que par ce mot. Sans lui, un exploitant ne peut pas relire ce qu'il
/// a écrit — et c'est précisément le port où se tromper ne se voit qu'au moment
/// où un client refuse de se connecter.
const fn mode_tls(implicite: bool) -> &'static str {
    match implicite {
        true => "TLS implicite (RFC 8314 §3)",
        false => "STARTTLS",
    }
}

/// Les écoutes d'un protocole, qui peuvent être PLUSIEURS et de modes différents.
///
/// L'adresse simple porte celle de la première ; la liste, quand elle n'est pas
/// vide, EST la liste. Ne montrer que la simple — ce que cette commande faisait
/// — cachait toutes les autres, et le 465 avec elles.
///
/// **UNE SEULE COPIE POUR LES TROIS PROTOCOLES.** Trois copies de cette
/// vingtaine de lignes se ressembleraient assez pour qu'on n'en relise aucune.
fn lignes_des_ecoutes(
    titre: &str,
    liste: &[ams_config::Listener],
    simple: &str,
    implicite: bool,
) -> Vec<String> {
    // Le titre occupe dix-huit colonnes, et les suivantes s'alignent dessous.
    let creux = " ".repeat(titre.chars().count());
    if liste.is_empty() {
        if simple.is_empty() {
            return Vec::new();
        }
        return std::vec![std::format!("{titre} {simple} — {}", mode_tls(implicite))];
    }
    liste
        .iter()
        .enumerate()
        .map(|(rang, ecoute)| {
            let etiquette = match rang {
                0 => titre,
                _ => &creux,
            };
            std::format!(
                "{etiquette} {} — {}",
                ecoute.address,
                mode_tls(ecoute.implicit_tls)
            )
        })
        .collect()
}

/// Rend une configuration lisible par un humain.
fn afficher(config: &Configuration) {
    println!("domaine            {}", config.domain);
    for (titre, liste, simple, implicite, absente) in [
        (
            "écoute            ",
            &config.smtp_listeners,
            &config.listen,
            false,
            "(aucune — le serveur ne reçoit rien)",
        ),
        (
            "écoute POP3       ",
            &config.pop3_listeners,
            &config.listen_pop3,
            false,
            "(aucune — POP3 n'est pas servi)",
        ),
        (
            "écoute IMAP       ",
            &config.imap_listeners,
            &config.listen_imap,
            config.imap_implicit_tls,
            "(aucune — IMAP n'est pas servi)",
        ),
    ] {
        let lignes = lignes_des_ecoutes(titre, liste, simple, implicite);
        if lignes.is_empty() {
            println!("{titre} {absente}");
            continue;
        }
        for ligne in lignes {
            println!("{ligne}");
        }
    }
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
        "récolte d'adresses {}",
        match config.guard.refused_recipients_per_minute {
            // **UN COMPTEUR ÉTEINT SE DIT**, et ne se devine pas à un zéro.
            0 => String::from("compteur ÉTEINT — ce fichier est antérieur à ce seuil"),
            combien => format!("{combien} destinataires refusés/min avant bannissement"),
        }
    );
    println!(
        "`HELO` qualifié    {}",
        match config.require_fqdn_helo {
            // **UN REFUS SE DIT.** Un exploitant qui pose ce drapeau refuse du
            // courrier ; ne pas le relire ici, c'est la même faute que le
            // compteur éteint ci-dessus.
            true => "EXIGÉ — un nom sans point est refusé (550) ; un littéral d'adresse passe",
            false => "non exigé — tout nom de la grammaire est accepté",
        }
    );
    println!(
        "enveloppe          {}",
        match (config.require_fqdn_sender, config.require_fqdn_recipient) {
            // **CHAQUE REFUS SE DIT**, et séparément : les deux exigences sont
            // indépendantes, et n'en montrer qu'une laisserait croire à l'autre.
            (false, false) => "aucune exigence — tout domaine de la grammaire est accepté",
            (true, false) => "EXPÉDITEUR pleinement qualifié exigé (550)",
            (false, true) => "DESTINATAIRE pleinement qualifié exigé (550)",
            (true, true) => "EXPÉDITEUR et DESTINATAIRE pleinement qualifiés exigés (550)",
        }
    );
    println!(
        "domaine expéditeur {}",
        match config.require_sender_domain {
            true => "doit EXISTER dans le DNS (550 s'il est absent, 451 sur panne)",
            false => "non vérifié",
        }
    );
    println!(
        "rapports TLS       {}",
        match (config.tlsrpt.compose(), config.tlsrpt.envoie()) {
            (false, _) => String::from("AUCUN — aucun dossier nommé"),
            (true, false) => format!(
                "déposés dans `{}` — DÉPOSÉS, PAS REMIS",
                config.tlsrpt.directory
            ),
            (true, true) => format!(
                "déposés dans `{}` PUIS REMIS aux destinations qui ont consenti (§3)",
                config.tlsrpt.directory
            ),
        }
    );
    // **CE QUE LE SERVEUR SERVIRA, LE MONTRER**, sans quoi `config show` dit
    // une partie de la vérité : un mécanisme d'authentification qu'un fichier
    // porte et qu'aucun affichage ne nomme ne se vérifie qu'en le servant.
    println!(
        "SCRAM              {}",
        if config.scram_key.is_empty() || config.scram_store.is_empty() {
            String::from("NON SERVI — `PLAIN` seul, et sous chiffrement seul")
        } else {
            format!(
                "magasin `{}`, scellé par `{}` (et `-PLUS` en TLS 1.3)",
                config.scram_store, config.scram_key
            )
        }
    );
    println!(
        "appareils          {}",
        if config.devices.is_empty() {
            String::from("AUCUN MAGASIN — pas de session par clef, le mot de passe seul")
        } else {
            format!(
                "magasin `{}` — clefs PUBLIQUES seules, aucun secret",
                config.devices
            )
        }
    );
    println!(
        "MTA-STS            {}",
        if config.mtasts.est_configure() {
            format!(
                "autorités `{}`, cache `{}`",
                config.mtasts.anchors, config.mtasts.cache
            )
        } else {
            String::from("NON ÉVALUÉ — aucune autorité nommée")
        }
    );
    println!(
        "réémission         {}",
        if config.relay.enabled {
            let reprise = config.queue.backoff();
            format!(
                "vers `{}` — 1er essai à {} s, plafond {} s, retard dit à {} s, \
                 abandon à {} s{}",
                config.queue.spool,
                reprise.first.as_secs(),
                reprise.ceiling.as_secs(),
                reprise.warning.as_secs(),
                reprise.expiry.as_secs(),
                // **UN RELAIS DE SORTIE SE VOIT ICI, OU NULLE PART.** C'est le
                // même défaut que `--queue-warn-seconds`, corrigé le matin même :
                // une molette qu'on règle et qui ne laisse aucune trace ne
                // permet pas de savoir si elle a été prise. Celle-ci change TOUT
                // le chemin du courrier sortant.
                if config.relay.relayhost.is_empty() {
                    String::from(" — remise DIRECTE, sans relais")
                } else {
                    format!(
                        " — PAR LE RELAIS `{}:{}` ({}), compte `{}`. DANE et MTA-STS \
                         ne s'appliquent plus.",
                        config.relay.relayhost,
                        config.relay.relayhost_port,
                        if config.relay.relayhost_implicit_tls {
                            "TLS implicite"
                        } else {
                            "STARTTLS"
                        },
                        config.relay.relayhost_user
                    )
                }
            )
        } else {
            String::from("AUCUNE — ce serveur reçoit, il n'émet pas pour ses comptes")
        }
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
    // ON DIT L'API MÊME ABSENTE, pour la raison qui vaut pour TLS : une ligne
    // manquante se lit « rien à signaler », or une API d'administration ouverte
    // est ce qu'il y a de plus sensible dans ce fichier.
    if config.listen_http.is_empty() {
        println!("API REST           AUCUNE — l'administration ne s'ouvre pas par le réseau");
    } else {
        println!("API REST           {}", config.listen_http);
        if config.listen_h3.is_empty() {
            println!("  HTTP/3           AUCUN — seul HTTP/2 la sert");
        } else {
            println!("  HTTP/3           {}", config.listen_h3);
        }
        // **JAMAIS LE SECRET, JAMAIS SA LONGUEUR UTILE** : on dit qu'il est là,
        // comme `account list` dit les noms sans jamais les empreintes.
        println!(
            "  scellement       {}",
            if config.token_key.is_empty() {
                "AUCUN — aucun jeton ne peut être scellé ni vérifié"
            } else {
                "présent — `air-mail-admin token` frappe les jetons"
            }
        );
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
        // **CE QUE LE BIT `AD` VAUT ICI, ET RIEN DE PLUS.** Cette ligne disait
        // « ces résolveurs sont crus sur parole », ce qui n'est plus vrai : ils
        // ne le sont que sur la boucle locale, ou sur déclaration.
        let distants: Vec<&String> = config
            .spf
            .resolvers
            .iter()
            .filter(|brute| {
                brute
                    .parse::<std::net::SocketAddr>()
                    .is_ok_and(|adresse| !adresse.ip().is_loopback())
            })
            .collect();
        println!("  DNSSEC           NON VALIDÉ en propre (RFC 7672 §2.1)");
        println!(
            "  bit `AD`         {}",
            match (distants.is_empty(), config.spf.resolvers_trusted) {
                (true, _) => String::from("CRU — boucle locale ; DANE peut s'engager"),
                (false, true) => std::format!(
                    "CRU — lien DÉCLARÉ de confiance jusqu'à {} ; DANE peut s'engager",
                    distants
                        .iter()
                        .map(|nom| nom.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                (false, false) => std::format!(
                    "JETÉ — {} hors de la boucle locale, sans `--resolver-trusted` ; \
                     DANE ne s'engage pas, MTA-STS décide",
                    distants
                        .iter()
                        .map(|nom| nom.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            }
        );
    } else {
        println!("SPF                AUCUN RÉSOLVEUR — l'expéditeur n'est pas vérifié");
    }
    if config.dmarc.est_configure(&config.spf) {
        println!(
            "DMARC              {}",
            match config.dmarc.enforcement {
                Enforcement::Enforce => "APPLIQUÉ — un `p=reject` est opposé (550)",
                Enforcement::Observe => "évalué et RETENU, sans rien opposer",
            }
        );
        println!("  suffixes publics {}", config.dmarc.public_suffix_list);
        if config.dmarc.met_en_quarantaine(&config.spf) {
            println!("  quarantaine      {}", config.dmarc.quarantine_folder);
        } else {
            println!("  quarantaine      AUCUN DOSSIER — un `p=quarantine` est remis quand même");
        }
        if config.dmarc.rapporte(&config.spf) {
            println!("  rapports         {}", config.dmarc.report_directory);
            println!(
                "  vidange          toutes les {} s",
                if config.dmarc.report_interval_seconds == 0 {
                    86_400
                } else {
                    config.dmarc.report_interval_seconds
                }
            );
            if config.dmarc.rapporte_les_echecs(&config.spf) {
                println!("  rapports d'échec OUI — en-têtes filtrés, corps jamais recopié");
            } else {
                println!("  rapports d'échec NON — seuls les rapports agrégés sont composés");
            }
            if config.dmarc.envoie(&config.spf) {
                println!("  remise           OUI — vers les destinations qui ont consenti (§7.1)");
            } else {
                println!("  remise           NON — les rapports sont déposés, pas envoyés");
            }
        } else {
            println!("  rapports         AUCUN DOSSIER — rien n'est rapporté aux domaines");
        }
    } else if config.dmarc.public_suffix_list.is_empty() {
        println!("DMARC              AUCUNE LISTE DE SUFFIXES — l'alignement n'est pas évalué");
    } else {
        // **LES DEUX MOITIÉS MANQUANTES NE SE DISENT PAS PAREIL.** Sans liste,
        // il n'y a rien à corriger d'urgent : personne n'a rien demandé. Ici, au
        // contraire, une liste EST nommée — quelqu'un a cru configurer DMARC —
        // et il ne se passe rien. C'est le cas qui mérite des majuscules, et
        // c'est celui que cette sortie annonçait naguère « APPLIQUÉ ».
        println!(
            "DMARC              NON ÉVALUÉ — une liste de suffixes est nommée, mais AUCUN \
             RÉSOLVEUR ne l'est"
        );
        println!("  suffixes publics {}", config.dmarc.public_suffix_list);
        println!(
            "  ce qu'il manque  `--resolver <adresse:port>` : la politique du domaine se lit \
             dans le DNS"
        );
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

/// Écrit le magasin, sans laisser la place à une interruption.
///
/// # Ce que la version d'avant faisait, et ce qu'elle coûtait
///
/// Elle tronquait le fichier SUR PLACE avant d'écrire. Or `account add` est une
/// lecture-modification-écriture : il relit tous les comptes, en ajoute un, et
/// réécrit le tout. Une coupure, un disque plein ou un `SIGTERM` entre la
/// troncature et la fin de l'écriture laissait un magasin illisible — et au
/// démarrage suivant, ce n'était pas le compte qu'on ajoutait qui manquait,
/// c'étaient TOUS les autres.
///
/// Elle posait aussi `.mode(0o600)` à l'ouverture, ce qui ne fait rien sur un
/// fichier déjà là : un magasin restauré d'une sauvegarde en `0644` y restait,
/// pendant que la documentation de cette fonction affirmait `0600`.
fn ecrire_magasin(fichier: &Path, comptes: &[Account]) -> Result<(), String> {
    let octets =
        ams_config::encode_accounts(comptes).map_err(|erreur| format!("encodage : {erreur}"))?;
    ams_fichier::poser(fichier, &octets)
        .map_err(|erreur| format!("`{}` : {erreur}", fichier.display()))
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

/// Tire la clé de scellement du magasin SCRAM.
///
/// # POURQUOI ELLE NE S'ÉCRASE PAS
///
/// Une clé perdue rend TOUS les vérificateurs illisibles d'un coup, et rien ne
/// les reconstitue : il faudrait reposer chaque mot de passe. Un `scram init`
/// lancé deux fois par distraction coûterait donc autant qu'une suppression du
/// magasin. On refuse, et on dit quoi faire.
fn initialiser_la_clef(chemin: &Path) -> ExitCode {
    match initialiser_la_clef_ou_dire(chemin) {
        Ok(()) => {
            println!(
                "{} : clé de scellement SCRAM écrite (32 octets, 0600)",
                chemin.display()
            );
            println!(
                "RANGEZ-LA AILLEURS QUE LE MAGASIN : les deux au même endroit ne valent \
                 pas mieux qu'un seul fichier en clair."
            );
            ExitCode::SUCCESS
        }
        Err(quoi) => {
            eprintln!("air-mail-admin : {quoi}");
            ExitCode::FAILURE
        }
    }
}

fn initialiser_la_clef_ou_dire(chemin: &Path) -> Result<(), String> {
    if chemin.exists() {
        return Err(format!(
            "`{}` existe déjà — une clé perdue rend tous les vérificateurs \
             illisibles, et ce refus est ce qui vous en protège. Écartez-la \
             vous-même si vous voulez vraiment en tirer une neuve.",
            chemin.display()
        ));
    }
    let mut clef = [0_u8; ams_auth::CLE_SCELLEMENT_OCTETS];
    {
        use std::io::Read as _;
        std::fs::File::open("/dev/urandom")
            .and_then(|mut source| source.read_exact(&mut clef))
            .map_err(|erreur| format!("/dev/urandom : {erreur}"))?;
    }
    ams_fichier::poser(chemin, &clef).map_err(|erreur| format!("`{}` : {erreur}", chemin.display()))
}

/// Lit une clé de scellement, et refuse ce qui n'en est pas une.
fn lire_la_clef(chemin: &Path) -> Result<[u8; ams_auth::CLE_SCELLEMENT_OCTETS], String> {
    let lue = std::fs::read(chemin)
        .map_err(|erreur| format!("clé SCRAM `{}` : {erreur}", chemin.display()))?;
    // **LA TAILLE EXACTE, ET NON « AU MOINS »** : une clé plus courte complétée
    // de zéros serait une clé plus faible que ce que son nom promet, et rien ne
    // le dirait. `scram init` en écrit trente-deux.
    if lue.len() != ams_auth::CLE_SCELLEMENT_OCTETS {
        return Err(format!(
            "clé SCRAM `{}` : {} octet(s) au lieu de {} — `scram init` en tire une juste",
            chemin.display(),
            lue.len(),
            ams_auth::CLE_SCELLEMENT_OCTETS
        ));
    }
    let mut clef = [0_u8; ams_auth::CLE_SCELLEMENT_OCTETS];
    for (place, octet) in clef.iter_mut().zip(&lue) {
        *place = *octet;
    }
    Ok(clef)
}

/// Dérive et range le vérificateur SCRAM d'un compte, si l'appelant l'a demandé.
///
/// **UNE ENTRÉE PAR COMPTE, REMPLACÉE ET NON AJOUTÉE.** Le vérificateur est LIÉ
/// à `empreinte` — celle que le compte portera —, donc un ancien vérificateur
/// laissé en place ne s'ouvrirait de toute façon plus ; le remplacer garde
/// simplement le magasin sans débris.
fn poser_le_verificateur(
    scram: Option<&DemandeScram>,
    nom: &str,
    secret: &[u8],
    empreinte: &str,
) -> Result<(), String> {
    let Some(demande) = scram else {
        return Ok(());
    };
    let clef = lire_la_clef(&demande.clef)?;
    let sel_scram = sel()?;
    let nonce = nonce()?;
    let neuf = ams_auth::scram_deriver(
        secret,
        nom,
        empreinte,
        sel_scram,
        ams_auth::SCRAM_ITERATIONS,
        nonce,
        &clef,
    )
    .map_err(|erreur| format!("dérivation SCRAM : {erreur:?}"))?;

    // Le même verrou que pour les comptes, et pour la même raison : le serveur
    // écrit ce fichier depuis son API.
    let _verrou = ams_fichier::verrouiller(&demande.magasin)
        .map_err(|erreur| format!("`{}` : {erreur}", demande.magasin.display()))?;
    let mut magasin = match std::fs::read(&demande.magasin) {
        Ok(octets) => ams_config::decode_scram(&octets)
            .map_err(|erreur| format!("`{}` : {erreur}", demande.magasin.display()))?,
        // Un magasin absent n'est pas une erreur : c'est le premier
        // vérificateur, comme pour `comptes.bin`.
        Err(erreur) if erreur.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(erreur) => {
            return Err(format!("`{}` : {erreur}", demande.magasin.display()));
        }
    };
    magasin.retain(|v| !v.login.eq_ignore_ascii_case(nom));
    magasin.push(neuf);

    // ON RELIT CE QU'ON VIENT D'ÉCRIRE, comme partout ailleurs dans cet outil.
    let octets = ams_config::encode_scram(&magasin)
        .map_err(|erreur| format!("encodage SCRAM : {erreur}"))?;
    ams_config::decode_scram(&octets)
        .map_err(|erreur| format!("le magasin SCRAM écrit ne se relit pas : {erreur}"))?;
    ams_fichier::poser(&demande.magasin, &octets)
        .map_err(|erreur| format!("`{}` : {erreur}", demande.magasin.display()))?;

    // **CE QUI EST FAIT SE DIT.** Sans cette ligne, la commande annonçait « le
    // compte est ajouté » et rien d'autre : l'exploitant qui a passé les deux
    // options de SCRAM n'avait aucun moyen de savoir si elles avaient servi, et
    // le seul indice était l'apparition d'un fichier.
    println!(
        "{} : vérificateur SCRAM posé pour `{nom}` ({} au total)",
        demande.magasin.display(),
        magasin.len()
    );
    Ok(())
}

/// Lie à l'empreinte ACTUELLE de leur compte les vérificateurs SCRAM écrits
/// avant la 0.2.16.
///
/// # CE QUE L'EXPLOITANT AFFIRME EN LA LANÇANT
///
/// **Que chaque vérificateur a été dérivé du mot de passe que le compte porte
/// aujourd'hui.** C'est vrai tant qu'aucun mot de passe n'a été changé par
/// l'API depuis la dernière dérivation — l'API ne touchait pas le magasin
/// SCRAM, et c'est précisément le défaut que la liaison ferme. Un vérificateur
/// dérivé d'un ANCIEN mot de passe, lié à l'empreinte du NOUVEAU, rouvrirait
/// la porte : en cas de doute sur un compte, `account passwd --scram` le
/// redérive plutôt.
///
/// Un vérificateur dont le compte n'existe plus est RETIRÉ : il n'a plus
/// d'empreinte à laquelle se lier, et le garder ne servirait à personne.
fn lier_les_verificateurs(fichier: &Path, clef: &Path, magasin: &Path) -> ExitCode {
    match lier_les_verificateurs_ou_dire(fichier, clef, magasin) {
        Ok((lies, deja, retires)) => {
            println!(
                "{} : {lies} vérificateur(s) lié(s), {deja} déjà lié(s), {retires} retiré(s) \
                 faute de compte",
                magasin.display()
            );
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("air-mail-admin : {message}");
            ExitCode::FAILURE
        }
    }
}

fn lier_les_verificateurs_ou_dire(
    fichier: &Path,
    clef: &Path,
    magasin: &Path,
) -> Result<(usize, usize, usize), String> {
    let clef = lire_la_clef(clef)?;
    // Les comptes se LISENT seulement : on n'écrit que le magasin SCRAM, sous
    // son propre verrou.
    let comptes = lire_magasin(fichier, false)?;
    let _verrou = ams_fichier::verrouiller(magasin)
        .map_err(|erreur| format!("`{}` : {erreur}", magasin.display()))?;
    let octets =
        std::fs::read(magasin).map_err(|erreur| format!("`{}` : {erreur}", magasin.display()))?;
    let anciens = ams_config::decode_scram(&octets)
        .map_err(|erreur| format!("`{}` : {erreur}", magasin.display()))?;

    let (mut lies, mut deja, mut retires) = (0_usize, 0_usize, 0_usize);
    let mut neufs = Vec::with_capacity(anciens.len());
    for ancien in &anciens {
        let Some(compte) = comptes.iter().find(|compte| compte.login == ancien.login) else {
            retires = retires.saturating_add(1);
            continue;
        };
        if ancien.lie {
            deja = deja.saturating_add(1);
            neufs.push(ancien.clone());
            continue;
        }
        let lie =
            ams_auth::scram_lier(ancien, &compte.hash, nonce()?, &clef).map_err(|erreur| {
                format!(
                    "vérificateur de `{}` : {erreur:?} — ne s'ouvre pas sous cette clé",
                    ancien.login
                )
            })?;
        lies = lies.saturating_add(1);
        neufs.push(lie);
    }

    let octets =
        ams_config::encode_scram(&neufs).map_err(|erreur| format!("encodage SCRAM : {erreur}"))?;
    ams_config::decode_scram(&octets)
        .map_err(|erreur| format!("le magasin SCRAM écrit ne se relit pas : {erreur}"))?;
    ams_fichier::poser(magasin, &octets)
        .map_err(|erreur| format!("`{}` : {erreur}", magasin.display()))?;
    Ok((lies, deja, retires))
}

/// Un nonce de scellement, tiré du noyau.
fn nonce() -> Result<[u8; ams_auth::NONCE_OCTETS], String> {
    use std::io::Read as _;
    let mut nonce = [0_u8; ams_auth::NONCE_OCTETS];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut nonce))
        .map_err(|erreur| format!("/dev/urandom : {erreur}"))?;
    Ok(nonce)
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

/// Où vivent les deux fichiers de SCRAM.
///
/// **LES DEUX VONT ENSEMBLE, OU AUCUN.** Une clé sans magasin n'a rien à
/// sceller ; un magasin sans clé ne s'ouvre pas. Les exiger ensemble refuse au
/// terminal ce qui, séparé, ne se découvrirait qu'à la première ouverture de
/// session.
pub struct DemandeScram {
    /// Le fichier qui porte la clé de scellement.
    pub clef: PathBuf,
    /// Le magasin des vérificateurs.
    pub magasin: PathBuf,
}

/// Lit les `--address` répétés et, s'il y en a, les deux options de SCRAM.
fn demande_de_compte(arguments: &[&str]) -> Result<(Vec<String>, Option<DemandeScram>), String> {
    let mut adresses = Vec::new();
    let mut clef: Option<PathBuf> = None;
    let mut magasin: Option<PathBuf> = None;
    let mut reste = arguments.iter();
    while let Some(argument) = reste.next() {
        match *argument {
            "--address" => {
                let valeur = reste
                    .next()
                    .ok_or_else(|| String::from("`--address` attend une valeur"))?;
                if valeur.is_empty() {
                    return Err(String::from("une adresse vide ne désigne personne"));
                }
                adresses.push((*valeur).to_string());
            }
            "--scram-key" => {
                let valeur = reste
                    .next()
                    .ok_or_else(|| String::from("`--scram-key` attend un chemin"))?;
                clef = Some(PathBuf::from(*valeur));
            }
            "--scram" => {
                let valeur = reste
                    .next()
                    .ok_or_else(|| String::from("`--scram` attend un chemin"))?;
                magasin = Some(PathBuf::from(*valeur));
            }
            autre => return Err(format!("option inconnue : `{autre}`")),
        }
    }
    let scram = match (clef, magasin) {
        (Some(clef), Some(magasin)) => Some(DemandeScram { clef, magasin }),
        (None, None) => None,
        // **L'UNE SANS L'AUTRE EST REFUSÉE AU TERMINAL**, et non ignorée : qui
        // passe `--scram` seul croit avoir posé un vérificateur.
        (Some(_), None) => {
            return Err(String::from(
                "`--scram-key` sans `--scram` : la clé n'aurait rien à sceller",
            ));
        }
        (None, Some(_)) => {
            return Err(String::from(
                "`--scram` sans `--scram-key` : le magasin ne s'ouvrirait pas",
            ));
        }
    };
    Ok((adresses, scram))
}

/// Ajoute ou remplace un compte.
fn ajouter(
    fichier: &Path,
    nom: &str,
    adresses: &[String],
    scram: Option<&DemandeScram>,
) -> ExitCode {
    match ajouter_ou_dire(fichier, nom, adresses, scram) {
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

fn ajouter_ou_dire(
    fichier: &Path,
    nom: &str,
    adresses: &[String],
    scram: Option<&DemandeScram>,
) -> Result<bool, String> {
    // LE MÊME CONTRÔLE QU'AU CHARGEMENT, et devant le terminal : le nom devient
    // un nom de répertoire, et le dire ici coûte une seconde plutôt qu'un
    // démarrage refusé.
    ams_auth::check_login(nom).map_err(|cause| format!("nom de compte : {cause}"))?;
    let secret = lire_mot_de_passe()?;
    let empreinte = ams_auth::hash_password(&secret, &sel()?)
        .map_err(|erreur| format!("hachage : {erreur}"))?;
    // **LE VÉRIFICATEUR SE DÉRIVE ICI, OU JAMAIS.** C'est l'un des deux seuls
    // endroits de cet outil où le mot de passe est en clair ; ailleurs, il n'y
    // a qu'une empreinte, dont on ne remonte pas.
    poser_le_verificateur(scram, nom, &secret, &empreinte)?;

    // **LE VERROU AVANT LA LECTURE, ET TENU JUSQU'À L'ÉCRITURE.** Ce qui suit
    // est une lecture-modification-écriture, et le serveur écrit le MÊME
    // fichier depuis son API. Sans lui, deux ajouts qui se croisent produisent
    // un magasin parfaitement valable auquel il manque un compte — et les deux
    // programmes disent « ajouté ».
    //
    // Le hachage du mot de passe a lieu AVANT : il coûte quelques dizaines de
    // millisecondes, et les passer sous le verrou ferait attendre l'autre
    // écrivain pour un calcul qui ne regarde pas le fichier.
    let _verrou = ams_fichier::verrouiller(fichier)
        .map_err(|erreur| format!("`{}` : {erreur}", fichier.display()))?;
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

/// Change le secret d'un compte, ET RIEN D'AUTRE.
///
/// # POURQUOI CETTE COMMANDE EXISTE, ALORS QU'`add` REMPLACE DÉJÀ
///
/// `account add` remplace le compte ENTIER. Changer un mot de passe avec lui
/// oblige à réécrire toutes les `--address` du compte, et en oublier une les
/// efface : le compte s'authentifie encore, relève encore son courrier ancien,
/// et NE REÇOIT PLUS RIEN. L'utilisateur ne s'en aperçoit qu'après des heures
/// de silence, et rien dans la sortie ne l'avait annoncé.
///
/// Cette commande-ci ne touche que l'empreinte. Les adresses sont reprises
/// telles quelles, parce qu'on ne les a jamais lues.
///
/// # ET ELLE REFUSE UN COMPTE INCONNU
///
/// C'est ce qui la sépare d'`add`. Une faute de frappe sur `--login` ferait
/// créer par `add` un compte fantôme, sans adresse, avec le mot de passe qu'on
/// croyait poser ailleurs — et le vrai compte garderait l'ancien. Ici, un nom
/// inconnu est une erreur, et le magasin n'est pas touché.
fn changer_le_secret(fichier: &Path, nom: &str, scram: Option<&DemandeScram>) -> ExitCode {
    match changer_le_secret_ou_dire(fichier, nom, scram) {
        Ok(()) => {
            println!("{} : secret du compte `{nom}` changé", fichier.display());
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("air-mail-admin : {message}");
            ExitCode::FAILURE
        }
    }
}

fn changer_le_secret_ou_dire(
    fichier: &Path,
    nom: &str,
    scram: Option<&DemandeScram>,
) -> Result<(), String> {
    ams_auth::check_login(nom).map_err(|cause| format!("nom de compte : {cause}"))?;
    let secret = lire_mot_de_passe()?;
    let empreinte = ams_auth::hash_password(&secret, &sel()?)
        .map_err(|erreur| format!("hachage : {erreur}"))?;
    // Le second des deux endroits où le mot de passe est en clair. **ET IL EST
    // POSÉ AVANT LE VERROU DES COMPTES** : le magasin SCRAM est un autre
    // fichier, avec son propre verrou, et les tenir tous les deux en même temps
    // ouvrirait la porte à un interblocage avec l'API du serveur.
    poser_le_verificateur(scram, nom, &secret, &empreinte)?;

    // Le même verrou, tenu de la lecture à l'écriture, et pour la même raison
    // qu'en §`ajouter_ou_dire` : le serveur écrit ce fichier depuis son API.
    let _verrou = ams_fichier::verrouiller(fichier)
        .map_err(|erreur| format!("`{}` : {erreur}", fichier.display()))?;
    let mut comptes = lire_magasin(fichier, false)?;
    let Some(compte) = comptes.iter_mut().find(|compte| compte.login == nom) else {
        return Err(format!(
            "`{}` : aucun compte `{nom}` — `account list` dit lesquels existent, et \
             `account add` en crée un",
            fichier.display()
        ));
    };
    // **SEULE L'EMPREINTE BOUGE.** `addresses` n'est pas relu, pas réécrit, pas
    // même nommé ici : ce qu'on ne touche pas ne peut pas se perdre.
    compte.hash = empreinte;

    let octets =
        ams_config::encode_accounts(&comptes).map_err(|erreur| format!("encodage : {erreur}"))?;
    ams_config::decode_accounts(&octets)
        .map_err(|erreur| format!("le magasin écrit ne se relit pas : {erreur}"))?;
    ecrire_magasin(fichier, &comptes)
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

/// Combien de temps un jeton d'administration vit, par défaut.
///
/// Un quart d'heure. **C'EST COURT, ET C'EST LE POINT** : ce jeton ouvre le
/// serveur entier, et un jeton qui traîne dans un historique de terminal ou dans
/// un journal est un jeton volé. Le refrapper coûte une commande.
const MINUTES_PAR_DEFAUT: u64 = 15;

/// Le plus longtemps qu'un jeton puisse vivre, en minutes (§`LIFETIME_MAX_US`).
const MINUTES_MAX: u64 = 12 * 60;

/// Lit `--login` et `--minutes`.
fn jeton_demande(arguments: &[&str]) -> Result<(String, u64), String> {
    let mut nom: Option<String> = None;
    let mut minutes = MINUTES_PAR_DEFAUT;
    let mut reste = arguments.iter();
    while let Some(argument) = reste.next() {
        match *argument {
            "--login" => {
                let valeur = reste
                    .next()
                    .ok_or_else(|| String::from("`--login` attend un nom de compte"))?;
                nom = Some((*valeur).to_string());
            }
            "--minutes" => {
                let valeur = reste
                    .next()
                    .ok_or_else(|| String::from("`--minutes` attend un nombre"))?;
                minutes = valeur
                    .parse()
                    .map_err(|_| format!("`{valeur}` n'est pas un nombre de minutes"))?;
            }
            autre => return Err(format!("argument inattendu : `{autre}`")),
        }
    }
    let nom = nom.ok_or_else(|| String::from("`token` attend un `--login`"))?;
    if minutes == 0 || minutes > MINUTES_MAX {
        return Err(format!(
            "une durée de {minutes} minutes est hors des bornes : de 1 à {MINUTES_MAX}"
        ));
    }
    Ok((nom, minutes))
}

/// Frappe un jeton d'administration, et l'écrit sur la sortie standard.
///
/// # POURQUOI CE JETON SE FRAPPE ICI, ET NON PAR L'API
///
/// Un mot de passe ouvre le courrier, la soumission et la supervision de SON
/// compte. Il n'ouvre pas l'administration — et cette limite est dans le code du
/// serveur, non dans une configuration : un réglage finirait par être basculé, et
/// un compte compromis deviendrait alors le serveur entier.
///
/// Il reste donc à frapper le jeton depuis l'endroit qui tient déjà le secret de
/// scellement : **la machine du serveur, par qui peut lire sa configuration**.
/// C'est la même autorité que celle qui peut arrêter le service ou lire les
/// boîtes ; on n'en ajoute aucune.
///
/// # LE NOM DE COMPTE N'A PAS BESOIN D'EXISTER
///
/// Il ne désigne pas une boîte : il dit QUI AGIT, et se retrouve dans ce que le
/// serveur journalise. Exiger un compte existant ferait croire que le jeton en
/// ouvre la boîte — il n'ouvre que l'administration.
fn frapper(fichier: &Path, nom: &str, minutes: u64) -> ExitCode {
    match frapper_ou_dire(fichier, nom, minutes) {
        Ok(jeton) => {
            println!("{jeton}");
            ExitCode::SUCCESS
        }
        Err(quoi) => {
            eprintln!("air-mail-admin : {quoi}");
            ExitCode::FAILURE
        }
    }
}

/// Frappe le jeton, ou dit ce qui a manqué.
fn frapper_ou_dire(fichier: &Path, nom: &str, minutes: u64) -> Result<String, String> {
    let octets =
        std::fs::read(fichier).map_err(|erreur| format!("`{}` : {erreur}", fichier.display()))?;
    let config = ams_config::decode(&octets)
        .map_err(|erreur| format!("`{}` : {erreur}", fichier.display()))?;
    if config.token_key.is_empty() {
        return Err(String::from(
            "cette configuration ne porte aucun secret de scellement : sans clé, aucun jeton ne \
             peut être scellé ni vérifié",
        ));
    }
    let clef = ams_api::key_from_hex(&config.token_key).map_err(|quoi| {
        String::from(match quoi {
            ams_api::KeyProblem::OddLength => {
                "le secret de scellement n'a pas un nombre pair de chiffres"
            }
            ams_api::KeyProblem::NotHex => "le secret de scellement n'est pas de l'hexadécimal",
            ams_api::KeyProblem::TooShort => {
                "le secret de scellement fait moins de trente-deux octets"
            }
        })
    })?;

    let maintenant = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| String::from("l'horloge de cette machine est avant 1970"))?
        .as_micros();
    let maintenant = u64::try_from(maintenant)
        .map_err(|_| String::from("l'horloge de cette machine est hors de portée"))?;

    let jeton = ams_api::Token {
        login: nom,
        // **L'ADMINISTRATION, ET RIEN D'AUTRE.** Y ajouter le courrier ferait de
        // ce jeton un passe-partout, alors qu'il existe pour une tâche précise.
        scope: ams_api::Scope::one(ams_api::Area::Admin, ams_api::Rights::Write),
        expiry: maintenant.saturating_add(minutes.saturating_mul(60).saturating_mul(1_000_000)),
        nonce: aléa()?,
    };
    let mut place = [0_u8; ams_api::ENCODED_OCTETS_MAX];
    ams_api::issue(&clef, &jeton, maintenant, &mut place)
        .map(ToString::to_string)
        .map_err(|_| String::from("ce jeton ne se scelle pas : le nom de compte est-il licite ?"))
}

/// Un aléa de huit octets, tiré du noyau.
///
/// **IL DISTINGUE CE JETON DES AUTRES**, et c'est ce qui permettrait de le
/// révoquer seul. Sans lui, deux jetons frappés dans la même seconde pour le même
/// nom seraient le même jeton.
fn aléa() -> Result<u64, String> {
    use std::io::Read as _;
    let mut graine = [0_u8; 8];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut graine))
        .map_err(|erreur| format!("/dev/urandom : {erreur}"))?;
    Ok(u64::from_ne_bytes(graine))
}

/// Retire un compte.
fn retirer(fichier: &Path, nom: &str) -> ExitCode {
    // MÊME VERROU QUE POUR L'AJOUT, et pour la même raison : retirer un compte
    // réécrit tous les autres.
    //
    // **IL EST LIÉ À UNE VARIABLE, ET NON PASSÉ À UNE FERMETURE** : `and_then`
    // rendrait le verrou à la fin de SA fermeture, c'est-à-dire avant la
    // lecture-modification-écriture qu'il existe pour protéger. Un verrou qui ne
    // couvre pas ce qu'il protège ne protège rien.
    let resultat = (|| {
        let _verrou = ams_fichier::verrouiller(fichier)
            .map_err(|erreur| format!("`{}` : {erreur}", fichier.display()))?;
        let mut comptes = lire_magasin(fichier, false)?;
        let avant = comptes.len();
        comptes.retain(|compte| compte.login != nom);
        if comptes.len() == avant {
            return Err(format!("aucun compte `{nom}` dans ce magasin"));
        }
        ecrire_magasin(fichier, &comptes)
    })();
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
    // **ON N'EN CRÉE PAS UNE EN VOULANT LA LIRE.** `Maildir::open` crée
    // l'arborescence qu'on lui nomme : cette commande, dont l'aide dit
    // « relit une boîte », fabriquait un répertoire, ses trois sous-dossiers et
    // un index sur un chemin tapé de travers — puis annonçait « 0 message » et
    // rendait un code nul. Qui l'a tapé conclut que la boîte est vide alors
    // qu'elle n'existe pas.
    let boite = match Maildir::open_existing(
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

#[cfg(test)]
mod tests {
    use super::{avertissements, lignes_des_ecoutes};

    /// La configuration que cette ligne de commande produit.
    ///
    /// **ON PASSE PAR L'ANALYSEUR RÉEL**, et non par une structure montée à la
    /// main : ce qu'on éprouve est ce qu'un exploitant obtient en tapant ceci.
    fn config_de(arguments: &[&str]) -> ams_config::Configuration {
        // `parse` ne reçoit QUE les options : le nom du fichier est traité à
        // part par `ecrire`.
        let mut ligne = std::vec![
            "--domain",
            "mail.example.com",
            "--listen",
            "127.0.0.1:2525",
            "--maildir",
            "/tmp/boites",
            "--accounts",
            "/tmp/comptes.bin",
            "--hosted",
            "example.com",
        ];
        ligne.extend_from_slice(arguments);
        match ams_admin_options::parse(ligne).expect("ligne recevable") {
            ams_admin_options::Demande::Ecrire(options) => options.en_configuration(),
            autre => std::panic!("attendu une écriture, obtenu {autre:?}"),
        }
    }

    /// Y a-t-il un avertissement qui porte ce fragment ?
    fn dit(config: &ams_config::Configuration, fragment: &str) -> bool {
        avertissements(config)
            .iter()
            .any(|ligne| ligne.contains(fragment))
    }

    /// **LE DÉFAUT LUI-MÊME, DEUXIÈME ESPÈCE.**
    ///
    /// `--listen-imap` et `--listen-imaps` écrivaient DEUX fichiers différents et
    /// s'affichaient à l'identique. Un exploitant ne pouvait donc pas relire ce
    /// qu'il avait écrit — sur le port même où se tromper de mode ne se voit
    /// qu'au moment où un client refuse de se connecter.
    #[test]
    fn les_deux_modes_imap_ne_s_affichent_pas_pareil() {
        let explicite = config_de(&["--listen-imap", "0.0.0.0:9993"]);
        let implicite = config_de(&["--listen-imaps", "0.0.0.0:9993"]);

        // LA MÊME ADRESSE : c'est bien le mode, et lui seul, qui diffère.
        assert_eq!(explicite.listen_imap, implicite.listen_imap);
        let dire = |config: &ams_config::Configuration| {
            lignes_des_ecoutes(
                "écoute IMAP       ",
                &config.imap_listeners,
                &config.listen_imap,
                config.imap_implicit_tls,
            )
            .join("\n")
        };
        assert_ne!(
            dire(&explicite),
            dire(&implicite),
            "les deux modes s'affichaient à l'identique"
        );
    }

    /// Une écoute IMAP absente le dit, plutôt que de laisser une ligne vide.
    /// Une écoute absente rend une liste VIDE, et c'est l'appelant qui le dit —
    /// une seule fois, pour les trois protocoles.
    #[test]
    fn une_ecoute_imap_absente_rend_une_liste_vide() {
        let config = config_de(&[]);
        assert!(
            lignes_des_ecoutes(
                "écoute IMAP       ",
                &config.imap_listeners,
                &config.listen_imap,
                false
            )
            .is_empty()
        );
    }

    /// **LA SECONDE ÉCOUTE SMTP NE DOIT PAS DISPARAÎTRE.**
    ///
    /// L'affichage ne montrait que `listen`, et le 465 n'apparaissait nulle part.
    #[test]
    fn toutes_les_ecoutes_smtp_s_affichent_avec_leur_mode() {
        let config = config_de(&["--listen-smtps", "127.0.0.1:4465"]);
        let lignes = lignes_des_ecoutes(
            "écoute            ",
            &config.smtp_listeners,
            &config.listen,
            false,
        )
        .join("\n");

        assert!(
            lignes.contains("127.0.0.1:2525") && lignes.contains("STARTTLS"),
            "l'écoute `STARTTLS` manque : {lignes}"
        );
        assert!(
            lignes.contains("127.0.0.1:4465") && lignes.contains("implicite"),
            "l'écoute en TLS implicite manque : {lignes}"
        );
    }

    /// Une configuration écrite avant la liste n'a qu'une écoute, en `STARTTLS`.
    #[test]
    fn sans_liste_l_ecoute_unique_se_dit_en_starttls() {
        let mut config = config_de(&[]);
        config.smtp_listeners.clear();
        let lignes = lignes_des_ecoutes(
            "écoute            ",
            &config.smtp_listeners,
            &config.listen,
            false,
        )
        .join("\n");

        assert!(
            lignes.contains("127.0.0.1:2525") && lignes.contains("STARTTLS"),
            "{lignes}"
        );
    }

    /// **LE DÉFAUT LUI-MÊME.**
    ///
    /// « Sans certificat TLS, l'authentification n'est pas annoncée » s'imprimait
    /// dès que `--relay` était posé — donc AUSSI à qui venait de fournir un
    /// certificat, qui se demandait alors si le sien avait été pris.
    #[test]
    fn le_certificat_fourni_ne_se_fait_pas_reprocher() {
        let config = config_de(&[
            "--relay",
            "--queue-spool",
            "/tmp/file",
            "--tls-cert",
            "/tmp/cert.pem",
            "--tls-key",
            "/tmp/cle.pem",
        ]);

        assert!(
            dit(&config, "ÉMISSION OUVERTE"),
            "l'émission ouverte se dit toujours : c'est une décision lourde"
        );
        assert!(
            !dit(&config, "INUTILISABLE"),
            "mais on ne reproche pas une absence à qui a fourni ce qu'il fallait"
        );
    }

    /// **ET L'AVERTISSEMENT QUI COMPTE SE DIT QUAND IL COMPTE.**
    ///
    /// Sans certificat, l'authentification n'est pas annoncée : l'émission est
    /// ouverte pour personne. C'est ce que l'exploitant doit lire, et cela se
    /// noyait jusqu'ici dans une phrase adressée à tous.
    #[test]
    fn une_emission_sans_certificat_est_dite_inutilisable() {
        let config = config_de(&["--relay", "--queue-spool", "/tmp/file"]);

        assert!(dit(&config, "ÉMISSION OUVERTE"));
        assert!(
            dit(&config, "INUTILISABLE"),
            "sans certificat, aucun compte ne peut s'authentifier pour émettre"
        );
    }

    /// Une file nommée sans émission n'écrit rien, et le dit.
    #[test]
    fn une_file_sans_relais_se_dit() {
        let config = config_de(&["--queue-spool", "/tmp/file"]);

        assert!(dit(&config, "SANS `--relay`"));
        assert!(
            !dit(&config, "ÉMISSION OUVERTE"),
            "rien n'est ouvert : ce serait le contraire de la vérité"
        );
    }

    /// Un compteur éteint se dit au moment où on l'éteint.
    #[test]
    fn un_compteur_de_recolte_eteint_se_dit() {
        assert!(dit(
            &config_de(&["--refused-recipients-per-minute", "0"]),
            "récolte d'adresses NON COMPTÉE"
        ));
        assert!(!dit(
            &config_de(&["--refused-recipients-per-minute", "50"]),
            "récolte d'adresses NON COMPTÉE"
        ));
    }

    /// Un bannissement de zéro seconde AJOURNE au lieu de bannir.
    #[test]
    fn un_bannissement_nul_se_dit() {
        assert!(dit(
            &config_de(&["--ban-seconds", "0"]),
            "aucun bannissement"
        ));
        assert!(!dit(
            &config_de(&["--ban-seconds", "3600"]),
            "aucun bannissement"
        ));
    }

    /// **UNE CONFIGURATION SAINE NE DIT RIEN**, et c'est ce qui rend les autres
    /// lisibles : un outil qui avertit toujours n'avertit jamais.
    #[test]
    fn une_configuration_saine_se_tait() {
        let config = config_de(&["--tls-cert", "/tmp/cert.pem", "--tls-key", "/tmp/cle.pem"]);

        assert_eq!(
            avertissements(&config),
            std::vec::Vec::<std::string::String>::new(),
            "rien d'inquiétant, donc rien à dire"
        );
    }
}
