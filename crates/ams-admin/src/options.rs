//! Les options de `config write`, et ce qu'elles produisent.
//!
//! # C'est ici que la ligne de commande s'arrête
//!
//! C11 veut un fichier de configuration **binaire**, et cet outil pour le
//! produire. La ligne de commande sert donc à ÉCRIRE une configuration, jamais à
//! régler un serveur : `air-mail-server` ne lit qu'un fichier.
//!
//! Deux sources de configuration seraient une de trop — c'est ainsi qu'un serveur
//! finit par tourner autrement que ce que son administrateur croit avoir demandé.

use std::net::SocketAddr;
use std::path::PathBuf;

use ams_config::{Configuration, Timeouts};
use ams_guard::Thresholds;
use ams_proto_smtp::Limits;

/// Ce dont le serveur a besoin pour démarrer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// Où écouter.
    ///
    /// Par défaut `127.0.0.1:2525`, et **jamais un port privilégié** : C10
    /// interdit d'exécuter le serveur en superutilisateur, et les ports sous 1024
    /// s'atteignent par une règle de redirection du pare-feu.
    pub listen: SocketAddr,
    /// La racine de la boîte Maildir.
    pub maildir: PathBuf,
    /// Le nom que le serveur annonce.
    pub domain: String,
    /// Les domaines pour lesquels il accepte du courrier.
    ///
    /// Vide, il n'en accepte pour **aucun** : un serveur qui accepterait tout
    /// serait un relais ouvert, que C6 exclut.
    pub hosted: Vec<String>,
    /// La taille maximale d'un message, annoncée par `SIZE`.
    pub max_message_octets: u64,
    /// Les connexions servies en même temps.
    pub max_connections: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 2525)),
            maildir: PathBuf::from("maildir"),
            domain: String::from("localhost"),
            hosted: Vec::new(),
            max_message_octets: 10 * 1024 * 1024,
            max_connections: 256,
        }
    }
}

impl Options {
    /// Compose la configuration que ces options décrivent.
    ///
    /// Les bornes du décodeur et les seuils du garde prennent leurs valeurs par
    /// défaut : les régler mérite ses propres options, et les inventer ici
    /// donnerait un fichier qui dit autre chose que ce qui a été demandé.
    #[must_use]
    pub fn en_configuration(&self) -> Configuration {
        Configuration {
            domain: self.domain.clone(),
            listen: self.listen.to_string(),
            maildir: self.maildir.display().to_string(),
            hosted: self.hosted.clone(),
            max_recipients: 100,
            max_message_octets: self.max_message_octets,
            max_connections: u32::try_from(self.max_connections).unwrap_or(u32::MAX),
            limits: Limits::DEFAULT,
            guard: Thresholds::DEFAULT,
            tracked_sources: 4096,
            timeouts: Timeouts {
                command_seconds: 300,
                data_seconds: 600,
            },
        }
    }
}

/// Ce que la ligne de commande demande.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Demande {
    /// Écrire une configuration avec ces paramètres.
    Ecrire(Box<Options>),
    /// Afficher l'aide.
    Aide,
    /// Afficher la version.
    Version,
}

/// Ce qui rend une ligne de commande irrecevable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgError {
    /// Ce qui n'allait pas.
    pub message: String,
}

impl ArgError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Le texte des options de `config write`.
pub const OPTIONS_AIDE: &str = "\
OPTIONS DE `config write`
    --listen <adresse>     où écouter          (défaut 127.0.0.1:2525)
    --maildir <chemin>     racine de la boîte  (défaut ./maildir)
    --domain <nom>         nom annoncé         (défaut localhost)
    --hosted <domaine>     domaine servi ; répétable. SANS AUCUN, le serveur
                           n'accepte de courrier pour personne — un serveur qui
                           accepterait tout serait un relais ouvert.
    --max-message <octets> taille maximale     (défaut 10485760)
    --max-connections <n>  connexions simultanées (défaut 256)

    Le port par défaut n'est pas 25 : le serveur refuse de s'exécuter en
    superutilisateur (C10), et les ports privilégiés s'atteignent par une règle
    de redirection du pare-feu.

    Les bornes du décodeur et les seuils du garde prennent leurs valeurs par
    défaut : les régler mérite ses propres options, et les inventer ici donnerait
    un fichier qui dit autre chose que ce qui a été demandé.
";

/// Lit une ligne de commande.
///
/// # Errors
///
/// [`ArgError`] pour une option inconnue, ou une valeur manquante ou illisible.
pub fn parse<I, S>(arguments: I) -> Result<Demande, ArgError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut options = Options::default();
    let mut arguments = arguments.into_iter();

    while let Some(argument) = arguments.next() {
        let argument = argument.as_ref();
        let mut valeur = || {
            arguments
                .next()
                .map(|brute| brute.as_ref().to_owned())
                .ok_or_else(|| ArgError::new(format!("`{argument}` attend une valeur")))
        };
        match argument {
            "--help" | "-h" => return Ok(Demande::Aide),
            "--version" | "-V" => return Ok(Demande::Version),
            "--listen" => {
                let brute = valeur()?;
                options.listen = brute
                    .parse()
                    .map_err(|_| ArgError::new(format!("`{brute}` n'est pas une adresse")))?;
            }
            "--maildir" => options.maildir = PathBuf::from(valeur()?),
            "--domain" => options.domain = valeur()?,
            "--hosted" => options.hosted.push(valeur()?),
            "--max-message" => {
                let brute = valeur()?;
                options.max_message_octets = brute
                    .parse()
                    .map_err(|_| ArgError::new(format!("`{brute}` n'est pas un nombre")))?;
            }
            "--max-connections" => {
                let brute = valeur()?;
                options.max_connections = brute
                    .parse()
                    .map_err(|_| ArgError::new(format!("`{brute}` n'est pas un nombre")))?;
            }
            inconnu => {
                return Err(ArgError::new(format!("option inconnue : `{inconnu}`")));
            }
        }
    }
    Ok(Demande::Ecrire(Box::new(options)))
}

#[cfg(test)]
mod tests {
    use super::{ArgError, Demande, Options, parse};
    use std::net::SocketAddr;
    use std::path::PathBuf;

    fn ecrire(arguments: &[&str]) -> Options {
        match parse(arguments).expect("recevable") {
            Demande::Ecrire(options) => *options,
            autre => panic!("attendu `Ecrire`, obtenu {autre:?}"),
        }
    }

    #[test]
    fn sans_argument_les_defauts_s_appliquent() {
        let options = ecrire(&[]);
        assert_eq!(options, Options::default());
        // LE PORT PAR DÉFAUT N'EST PAS PRIVILÉGIÉ : le serveur refuse de
        // s'exécuter en superutilisateur (C10).
        assert_eq!(options.listen.port(), 2525);
        // ET IL N'HÉBERGE RIEN : un serveur qui accepterait tout serait un
        // relais ouvert.
        assert!(options.hosted.is_empty());
    }

    #[test]
    fn chaque_option_est_lue() {
        let options = ecrire(&[
            "--listen",
            "0.0.0.0:2626",
            "--maildir",
            "/var/mail/spool",
            "--domain",
            "mail.example.com",
            "--hosted",
            "example.com",
            "--hosted",
            "example.org",
            "--max-message",
            "1024",
            "--max-connections",
            "8",
        ]);
        assert_eq!(
            options.listen,
            "0.0.0.0:2626".parse::<SocketAddr>().expect("adresse")
        );
        assert_eq!(options.maildir, PathBuf::from("/var/mail/spool"));
        assert_eq!(options.domain, "mail.example.com");
        assert_eq!(options.hosted, ["example.com", "example.org"]);
        assert_eq!(options.max_message_octets, 1024);
        assert_eq!(options.max_connections, 8);
    }

    #[test]
    fn l_aide_et_la_version_court_circuitent() {
        for argument in ["--help", "-h"] {
            assert_eq!(parse([argument]), Ok(Demande::Aide));
        }
        for argument in ["--version", "-V"] {
            assert_eq!(parse([argument]), Ok(Demande::Version));
        }
        // Même au milieu d'options qui suivraient.
        assert_eq!(parse(["--domain", "x", "--help"]), Ok(Demande::Aide));
    }

    #[test]
    fn une_ligne_de_commande_irrecevable_est_refusee() {
        for (arguments, extrait) in [
            (["--inconnue"].as_slice(), "option inconnue"),
            (&["--listen"], "attend une valeur"),
            (&["--listen", "pas-une-adresse"], "n'est pas une adresse"),
            (&["--max-message", "beaucoup"], "n'est pas un nombre"),
            (&["--max-connections", "-1"], "n'est pas un nombre"),
        ] {
            let erreur = parse(arguments).expect_err("refusé");
            assert!(
                erreur.message.contains(extrait),
                "{arguments:?} : « {} » ne mentionne pas « {extrait} »",
                erreur.message
            );
        }
    }

    #[test]
    fn les_options_deviennent_une_configuration() {
        let options = ecrire(&["--domain", "mail.example.com", "--hosted", "example.com"]);
        let config = options.en_configuration();
        assert_eq!(config.domain, "mail.example.com");
        assert_eq!(config.hosted, ["example.com"]);
        assert_eq!(config.listen, "127.0.0.1:2525");
        assert_eq!(config.limits, ams_proto_smtp::Limits::DEFAULT);
        assert_eq!(config.guard, ams_guard::Thresholds::DEFAULT);
        // Et elle se relit à l'identique une fois écrite.
        let octets = ams_config::encode(&config).expect("encodable");
        assert_eq!(ams_config::decode(&octets).expect("relisible"), config);
    }

    #[test]
    fn les_types_se_deboguent() {
        let erreur = ArgError::new("essai");
        assert!(!format!("{erreur:?}").is_empty());
        assert_eq!(erreur.clone(), erreur);
        let options = Options::default();
        assert!(!format!("{options:?}").is_empty());
        assert_eq!(options.clone(), options);
        assert_ne!(Demande::Aide, Demande::Version);
    }
}
