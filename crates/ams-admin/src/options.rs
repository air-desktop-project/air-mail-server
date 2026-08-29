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

use ams_config::{Configuration, Dmarc, Enforcement, Spf, Timeouts, Tls};
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
    /// La chaîne de certificats, au format PEM. Vide : pas de chiffrement.
    pub tls_cert: Option<PathBuf>,
    /// La clé privée, au format PEM. Vide : pas de chiffrement.
    pub tls_key: Option<PathBuf>,
    /// Le fichier de comptes. Vide : pas d'`AUTH`.
    pub accounts: Option<PathBuf>,
    /// Où écouter en POP3. Vide : POP3 n'est pas servi.
    pub listen_pop3: Option<SocketAddr>,
    /// Les résolveurs DNS. Vide : SPF n'est pas vérifié.
    pub resolvers: Vec<SocketAddr>,
    /// Refuse-t-on un `fail`, ou se contente-t-on de le retenir ?
    pub spf_enforce: bool,
    /// Le temps accordé à une question DNS.
    pub spf_timeout_millis: u32,
    /// La liste des suffixes publics. Vide : DMARC n'est pas évalué.
    pub public_suffix_list: Option<PathBuf>,
    /// Oppose-t-on un `p=reject`, ou se contente-t-on de le retenir ?
    pub dmarc_enforce: bool,
    /// Où déposer les rapports agrégés. Vide : aucun n'est composé.
    pub dmarc_report_dir: Option<PathBuf>,
    /// Le nom sous lequel ce receveur se présente dans ses rapports.
    pub dmarc_org_name: Option<String>,
    /// L'adresse à laquelle le joindre à propos d'un rapport.
    pub dmarc_report_email: Option<String>,
    /// Tous les combien vider le journal des rapports.
    pub dmarc_report_interval: u32,
    /// Remet-on les rapports, ou se contente-t-on de les déposer ?
    pub dmarc_send: bool,
    /// Compose-t-on des rapports d'échec ?
    pub dmarc_failures: bool,
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
            // PAS DE CHIFFREMENT PAR DÉFAUT, et ce n'est pas un renoncement :
            // un défaut qui chiffrerait nommerait des fichiers qui n'existent
            // pas, et le serveur refuserait de démarrer sur une configuration
            // que personne n'a demandée.
            tls_cert: None,
            tls_key: None,
            // PAS DE COMPTES PAR DÉFAUT : un serveur qui n'a personne à qui
            // répondre oui n'annonce pas `AUTH`.
            accounts: None,
            // PAS DE POP3 PAR DÉFAUT : un port ouvert qu'on n'a pas demandé est
            // une surface de plus, et celui-ci ne sert personne sans certificat.
            listen_pop3: None,
            // PAS DE RÉSOLVEUR PAR DÉFAUT, et surtout pas celui du système : le
            // lire dans `/etc/resolv.conf` ferait interroger, sans que personne
            // l'ait demandé, un serveur qui n'est peut-être pas de confiance —
            // et un `pass` SPF ne vaut que ce que vaut ce chemin-là.
            resolvers: Vec::new(),
            // ON REGARDE AVANT DE REFUSER. Une politique mal écrite chez un
            // partenaire refuserait du courrier légitime ; mieux vaut le
            // découvrir dans un journal que dans un appel téléphonique.
            spf_enforce: false,
            spf_timeout_millis: 5_000,
            // PAS DE LISTE PAR DÉFAUT : sans elle, DMARC n'est pas évalué. En
            // embarquer une la ferait vieillir avec le binaire, et personne ne
            // saurait de quand date la sienne.
            public_suffix_list: None,
            // ON REGARDE AVANT DE REFUSER, et plus longtemps qu'ailleurs : un
            // domaine qui publie `p=reject` refuse aussi le courrier de ses
            // propres listes de diffusion.
            dmarc_enforce: false,
            // PAS DE DOSSIER PAR DÉFAUT : composer des rapports est un service
            // qu'on rend à autrui, et il se demande. En choisir un d'office
            // ferait écrire un serveur là où l'administrateur ne l'attend pas.
            dmarc_report_dir: None,
            dmarc_org_name: None,
            dmarc_report_email: None,
            // Un jour, comme le défaut de `ri=` (RFC 7489 §6.3).
            dmarc_report_interval: 86_400,
            // ÉMETTRE DU COURRIER VERS DES TIERS NE SE DÉCIDE PAS À LA PLACE DE
            // CELUI QUI EXPLOITE LA MACHINE. On dépose ; il relève, ou il
            // demande qu'on remette.
            dmarc_send: false,
            // ILS PORTENT LE COURRIER DE QUELQU'UN. Le défaut n'en compose pas.
            dmarc_failures: false,
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
            tls: Tls {
                certificate_chain_path: chemin(self.tls_cert.as_ref()),
                private_key_path: chemin(self.tls_key.as_ref()),
            },
            spf: Spf {
                resolvers: self
                    .resolvers
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect(),
                enforcement: if self.spf_enforce {
                    Enforcement::Enforce
                } else {
                    Enforcement::Observe
                },
                timeout_millis: self.spf_timeout_millis,
            },
            dmarc: Dmarc {
                public_suffix_list: chemin(self.public_suffix_list.as_ref()),
                enforcement: if self.dmarc_enforce {
                    Enforcement::Enforce
                } else {
                    Enforcement::Observe
                },
                report_directory: chemin(self.dmarc_report_dir.as_ref()),
                report_org_name: self.dmarc_org_name.clone().unwrap_or_default(),
                report_email: self.dmarc_report_email.clone().unwrap_or_default(),
                report_interval_seconds: self.dmarc_report_interval,
                send_reports: self.dmarc_send,
                failure_reports: self.dmarc_failures,
            },
            accounts: chemin(self.accounts.as_ref()),
            listen_pop3: self
                .listen_pop3
                .map(|adresse| adresse.to_string())
                .unwrap_or_default(),
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
    --tls-cert <chemin>    chaîne de certificats, en PEM
    --tls-key <chemin>     clé privée, en PEM
    --accounts <chemin>    fichier de comptes (`air-mail-admin account add`)
    --listen-pop3 <adr>    où écouter en POP3 (défaut : pas de POP3)

    LES DEUX OPTIONS TLS VONT ENSEMBLE, ou aucune. Avec elles, le serveur annonce
    `STARTTLS` et chiffre ; sans elles, il sert en clair et ne l'annonce pas. Il
    n'y a pas de troisième réglage : « annoncer sans pouvoir » ferait mentir la
    bannière, et « pouvoir sans annoncer » ne chiffrerait rien.

    Le serveur refuse de démarrer si la clé privée est lisible par tout le monde.
    Le partage par groupe, lui, reste permis.

    POP3 EXIGE UN CERTIFICAT POUR SERVIR À QUELQUE CHOSE : la session y refuse
    `USER`/`PASS` hors chiffrement, sans réglage possible. Un `--listen-pop3`
    sans `--tls-cert` ouvre un port où personne ne pourra relever son courrier ;
    le serveur le dit au démarrage.

    LE MAGASIN DE COMPTES SERT DEUX CHOSES, et il faut les distinguer :

      - le ROUTAGE — seules les adresses qu'un compte déclare sont acceptées, et
        chacune mène à la boîte de son compte. Cela ne demande aucun chiffrement.
        SANS `--accounts`, le serveur n'accepte de courrier pour PERSONNE.
      - l'AUTHENTIFICATION — `AUTH PLAIN`, qui n'est annoncé que sous
        chiffrement, donc jamais sans `--tls-cert`/`--tls-key`. C'est un refus
        que rien ne règle.

    Le port par défaut n'est pas 25 : le serveur refuse de s'exécuter en
    superutilisateur (C10), et les ports privilégiés s'atteignent par une règle
    de redirection du pare-feu.

    SPF (C9) NE SE VÉRIFIE QUE SI UN RÉSOLVEUR EST NOMMÉ. Il n'y a pas d'option
    pour « activer » : `--resolver` suffit, et son absence dit l'inverse. Le
    résolveur n'est PAS lu dans `/etc/resolv.conf` — ce serveur ne valide pas
    DNSSEC, un `pass` ne vaut donc que ce que vaut le chemin jusqu'au résolveur,
    et hériter en silence de celui du système serait hériter d'une confiance que
    personne n'a accordée. Nommez-en un local, ou joint par un lien que vous
    maîtrisez.

    `--spf observe` (le défaut) vérifie et RETIENT sans rien opposer ; `--spf
    enforce` refuse un `fail` par un 550 et ajourne une panne de résolution par
    un 451. Commencez par `observe` : une politique mal écrite chez un
    partenaire refuse du courrier légitime, et il vaut mieux le lire dans un
    journal que l'apprendre au téléphone.

    DMARC (C9) N'EST ÉVALUÉ QUE SI UNE LISTE DE SUFFIXES PUBLICS EST NOMMÉE, et
    que des résolveurs le sont aussi — il faut aller chercher la politique du
    domaine de l'en-tête `From:`. La liste est celle de publicsuffix.org, telle
    quelle : `--public-suffix-list /chemin/public_suffix_list.dat`.

    Elle n'est PAS embarquée dans le binaire, et c'est délibéré : elle pèse
    quelques centaines de kibioctets, change toutes les semaines, et l'alignement
    relâché de DMARC en dépend. Embarquée, elle vieillirait sans que personne ne
    sache de quand date la sienne — et s'y tromper fait aligner deux domaines
    étrangers, ce que DMARC existe précisément pour empêcher.

    `--dmarc observe` (le défaut) évalue et retient ; `--dmarc enforce` oppose un
    550 aux messages qu'un `p=reject` condamne. Restez en observation plus
    longtemps qu'ailleurs : un domaine qui publie `p=reject` refuse aussi le
    courrier de ses propres listes de diffusion.

    LES RAPPORTS AGRÉGÉS (RFC 7489 §7.2) NE SONT COMPOSÉS QUE SI UN DOSSIER EST
    NOMMÉ : `--dmarc-report-dir /var/spool/ams/rapports`. Ils y sont DÉPOSÉS, pas
    envoyés — envoyer demande un client SMTP sortant que ce serveur n'a pas
    encore. Chaque rapport est accompagné d'un fichier `.destinations` qui dit à
    qui il revient, après la vérification de §7.1 : sans elle, n'importe qui
    publierait `rua=mailto:victime@banque.test` et ferait bombarder cette adresse
    par tous les receveurs du monde.

    `--dmarc-send` REMET les rapports au lieu de seulement les déposer. Ce n'est
    pas le défaut : émettre du courrier vers des tiers ne se décide pas à la
    place de celui qui exploite la machine. Sans lui, les rapports s'accumulent
    dans le dossier et un opérateur les relève. Avec lui, ils partent — aux
    destinations qui ont consenti (§7.1) et à elles seules, un rapport remis est
    effacé, un rapport refusé définitivement aussi, et un rapport de plus de sept
    jours est abandonné.

    `--dmarc-failure-reports` compose en plus des rapports d'ÉCHEC (`ruf=`,
    RFC 6591). ILS PORTENT LE COURRIER DE QUELQU'UN : un rapport agrégé est un
    dénombrement, celui-ci dit tout d'un message précis, et il part chez le
    domaine qu'on rapporte — c'est-à-dire, quand ça compte, chez celui qui
    usurpe. Ce serveur n'y met ni le corps, ni le destinataire, ni les en-têtes
    de routage : seule une liste blanche d'en-têtes en sort, et un même domaine
    n'en vaut que cent par période. Cela ne rend pas la décision anodine, et
    c'est pourquoi ce n'est pas le défaut.

    `--dmarc-org-name` est le nom sous lequel ce receveur se présente (défaut :
    le nom annoncé), `--dmarc-report-email` l'adresse où le joindre (défaut :
    `postmaster@` suivi du nom annoncé), `--dmarc-report-interval` le nombre de
    secondes entre deux vidanges du journal (défaut : 86400, un jour).

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
            "--tls-cert" => options.tls_cert = Some(PathBuf::from(valeur()?)),
            "--tls-key" => options.tls_key = Some(PathBuf::from(valeur()?)),
            "--accounts" => options.accounts = Some(PathBuf::from(valeur()?)),
            "--resolver" => {
                let brute = valeur()?;
                let adresse: SocketAddr = brute
                    .parse()
                    .map_err(|_| ArgError::new(format!("`{brute}` n'est pas une adresse")))?;
                options.resolvers.push(adresse);
            }
            "--spf" => {
                let mot = valeur()?;
                match mot.as_str() {
                    "observe" => options.spf_enforce = false,
                    "enforce" => options.spf_enforce = true,
                    autre => {
                        return Err(ArgError::new(format!(
                            "`{autre}` n'est ni `observe` ni `enforce`"
                        )));
                    }
                }
            }
            "--dmarc-report-dir" => {
                options.dmarc_report_dir = Some(PathBuf::from(valeur()?));
            }
            "--dmarc-send" => options.dmarc_send = true,
            "--dmarc-failure-reports" => options.dmarc_failures = true,
            "--dmarc-org-name" => options.dmarc_org_name = Some(valeur()?),
            "--dmarc-report-email" => options.dmarc_report_email = Some(valeur()?),
            "--dmarc-report-interval" => {
                let brute = valeur()?;
                options.dmarc_report_interval = brute
                    .parse()
                    .map_err(|_| ArgError::new(format!("`{brute}` n'est pas un nombre")))?;
            }
            "--public-suffix-list" => {
                options.public_suffix_list = Some(PathBuf::from(valeur()?));
            }
            "--dmarc" => {
                let mot = valeur()?;
                match mot.as_str() {
                    "observe" => options.dmarc_enforce = false,
                    "enforce" => options.dmarc_enforce = true,
                    autre => {
                        return Err(ArgError::new(format!(
                            "`{autre}` n'est ni `observe` ni `enforce`"
                        )));
                    }
                }
            }
            "--spf-timeout-ms" => {
                let brute = valeur()?;
                options.spf_timeout_millis = brute
                    .parse()
                    .map_err(|_| ArgError::new(format!("`{brute}` n'est pas un nombre")))?;
            }
            "--listen-pop3" => {
                let brute = valeur()?;
                options.listen_pop3 = Some(
                    brute
                        .parse()
                        .map_err(|_| ArgError::new(format!("`{brute}` n'est pas une adresse")))?,
                );
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
    // On refuse ICI plutôt qu'au chargement du serveur : l'administrateur est
    // devant son terminal, et c'est le seul moment où lui dire coûte une seconde
    // plutôt qu'une astreinte.
    if options.tls_cert.is_some() != options.tls_key.is_some() {
        return Err(ArgError::new(
            "`--tls-cert` et `--tls-key` vont ENSEMBLE : l'un sans l'autre ne veut dire ni \
             « chiffre » ni « ne chiffre pas »",
        ));
    }
    Ok(Demande::Ecrire(Box::new(options)))
}

/// Un chemin, ou la chaîne vide qui dit « rien ».
fn chemin(valeur: Option<&PathBuf>) -> String {
    valeur.map(|c| c.display().to_string()).unwrap_or_default()
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
    fn les_deux_chemins_tls_traversent_jusqu_a_la_configuration() {
        let options = ecrire(&[
            "--domain",
            "mail.example.com",
            "--tls-cert",
            "/etc/ams/chaine.pem",
            "--tls-key",
            "/etc/ams/cle.pem",
        ]);
        let config = options.en_configuration();
        assert!(config.tls.est_configure());
        assert_eq!(config.tls.certificate_chain_path, "/etc/ams/chaine.pem");
        assert_eq!(config.tls.private_key_path, "/etc/ams/cle.pem");
    }

    #[test]
    fn sans_option_tls_la_configuration_ne_chiffre_pas() {
        let config = ecrire(&["--domain", "mail.example.com"]).en_configuration();
        assert!(!config.tls.est_configure());
        assert!(config.tls.certificate_chain_path.is_empty());
    }

    #[test]
    fn l_adresse_pop3_traverse_jusqu_a_la_configuration() {
        let config = ecrire(&[
            "--domain",
            "mail.example.com",
            "--listen-pop3",
            "127.0.0.1:2110",
        ])
        .en_configuration();
        assert_eq!(config.listen_pop3, "127.0.0.1:2110");
        // Sans l'option, POP3 n'est pas servi — et l'absence se lit à une
        // chaîne vide, pas à un drapeau qui pourrait la contredire.
        let sans = ecrire(&["--domain", "mail.example.com"]).en_configuration();
        assert!(sans.listen_pop3.is_empty());
    }

    #[test]
    fn une_adresse_pop3_illisible_est_refusee() {
        let erreur = parse(["--listen-pop3", "pas-une-adresse"]).expect_err("refusé");
        assert!(
            erreur.message.contains("n'est pas une adresse"),
            "{}",
            erreur.message
        );
    }

    #[test]
    fn des_comptes_sans_chiffrement_sont_licites() {
        // Ils ne servent alors qu'au ROUTAGE, et `AUTH` n'est pas annoncé. Le
        // refuser interdirait un serveur qui reçoit du courrier en clair pour
        // des boîtes connues — ce qui est exactement ce que fait un serveur de
        // courrier entrant.
        let config = ecrire(&[
            "--domain",
            "mail.example.com",
            "--accounts",
            "/etc/ams/comptes.bin",
        ])
        .en_configuration();
        assert_eq!(config.accounts, "/etc/ams/comptes.bin");
        assert!(!config.tls.est_configure());
    }

    #[test]
    fn un_seul_des_deux_chemins_tls_est_refuse_tout_de_suite() {
        // Refusé DEVANT LE TERMINAL, et pas au démarrage du serveur : c'est le
        // seul moment où le dire coûte une seconde plutôt qu'une astreinte.
        for arguments in [
            ["--tls-cert", "/etc/ams/chaine.pem"].as_slice(),
            &["--tls-key", "/etc/ams/cle.pem"],
        ] {
            let erreur = parse(arguments).expect_err("refusé");
            assert!(erreur.message.contains("ENSEMBLE"), "{}", erreur.message);
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
