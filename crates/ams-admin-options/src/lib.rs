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

use core::time::Duration;
use std::net::SocketAddr;
use std::path::PathBuf;

use ams_config::{Configuration, Dkim, Dmarc, Enforcement, Spf, Timeouts, Tls};
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
    /// `s=` — le sélecteur DKIM publié dans le DNS.
    pub dkim_selector: Option<String>,
    /// La clé privée DKIM, en PEM.
    pub dkim_key: Option<PathBuf>,
    /// La clé privée, au format PEM. Vide : pas de chiffrement.
    pub tls_key: Option<PathBuf>,
    /// Le fichier de comptes. Vide : pas d'`AUTH`.
    pub accounts: Option<PathBuf>,
    /// Où écouter en POP3. Vide : POP3 n'est pas servi.
    pub listen_pop3: Option<SocketAddr>,
    /// Où écouter en IMAP. Absente : IMAP n'est pas servi.
    pub listen_imap: Option<SocketAddr>,
    /// Où servir l'API REST en HTTP/2. Absente : elle n'est pas servie.
    ///
    /// **ELLE EXIGE UN CERTIFICAT**, et le serveur le refuse sans : l'API porte
    /// des jetons porteurs, et un jeton qui traverse un réseau en clair est un
    /// jeton volé (C4).
    pub listen_http: Option<SocketAddr>,
    /// Où servir la même API en HTTP/3. Absente : seul HTTP/2 la sert.
    ///
    /// **ELLE EXIGE `--listen-http`**, et pas seulement un certificat :
    /// `Alt-Svc` est le seul moyen par lequel un client découvre un port
    /// HTTP/3 (RFC 7838, §3.1 de RFC 9114), et il s'annonce depuis les réponses
    /// HTTP/2. Sans elles, ce port UDP serait ouvert sans que personne ne le
    /// cherche jamais.
    pub listen_h3: Option<SocketAddr>,
    /// Renouvelle le secret de scellement plutôt que de reprendre l'ancien.
    ///
    /// **CE N'EST PAS SANS CONSÉQUENCE** : les jetons frappés avant cessent de
    /// valoir. C'est ce qu'on veut d'une rotation, et c'est pourquoi elle se
    /// demande explicitement au lieu d'arriver à chaque écriture.
    pub rotate_token_key: bool,
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
    /// Le dossier où mettre de côté ce que `p=quarantine` vise.
    ///
    /// **Vide, la quarantaine n'existe pas** : le message va dans la boîte de
    /// réception, et le rapport dit `none`, parce que c'est la vérité.
    pub dmarc_quarantine: Option<String>,
    /// Les seuils du garde — le `x` et le `y` de C8, et le reste.
    ///
    /// **RIEN ICI N'EST UNE CONSTANTE**, dit C8 ; il fallait donc que l'outil
    /// qui écrit la configuration sache les écrire. Tant qu'il posait
    /// `Thresholds::DEFAULT`, la contrainte était vraie dans le format et
    /// fausse en pratique : personne ne pouvait desserrer un seuil qui se
    /// trompe, ni resserrer celui qui ne suffit plus.
    pub guard: Thresholds,
    /// L'émission pour les comptes authentifiés — voir [`Options::queue_spool`].
    ///
    /// **ÉTEINTE PAR DÉFAUT.** Émettre du courrier vers des tiers ne se décide
    /// pas à la place de celui qui exploite la machine.
    pub relay: bool,
    /// Le dossier de la file. **Exigé dès que quelque chose sort.**
    pub queue_spool: Option<PathBuf>,
    /// L'attente après le premier échec, en secondes. Zéro prend le défaut.
    pub queue_retry: u32,
    /// Le plafond de l'attente, en secondes. Zéro prend le défaut.
    pub queue_max_retry: u32,
    /// Le temps accordé à un message depuis son dépôt. Zéro prend le défaut.
    pub queue_expire: u32,
    /// Le retard à partir duquel on PRÉVIENT le déposant. Zéro prend le défaut.
    pub queue_warn: u32,
    /// Le fichier PEM des autorités pour MTA-STS. Absent : non évalué.
    pub mtasts_anchors: Option<PathBuf>,
    /// Le dossier du cache des politiques MTA-STS. **Exigé avec le premier.**
    pub mtasts_cache: Option<PathBuf>,
    /// Le dossier des rapports TLSRPT. Absent : aucun n'est composé.
    pub tlsrpt_dir: Option<PathBuf>,
    /// Remet-on les rapports TLSRPT ?
    pub tlsrpt_send: bool,
    /// Combien de sources la table du garde retient à la fois.
    ///
    /// C'est ce qui empêche la table d'être un épuisement de mémoire offert à
    /// qui dispose d'un `/64` : elle est bornée, et une fois pleine de peines
    /// en cours elle CESSE D'APPRENDRE plutôt que d'oublier un banni.
    pub tracked_sources: u32,
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
            dkim_selector: None,
            dkim_key: None,
            tls_key: None,
            // PAS DE COMPTES PAR DÉFAUT : un serveur qui n'a personne à qui
            // répondre oui n'annonce pas `AUTH`.
            accounts: None,
            // PAS DE POP3 PAR DÉFAUT : un port ouvert qu'on n'a pas demandé est
            // une surface de plus, et celui-ci ne sert personne sans certificat.
            listen_pop3: None,
            listen_imap: None,
            listen_http: None,
            listen_h3: None,
            rotate_token_key: false,
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
            dmarc_quarantine: None,
            // PAS DE RELAIS PAR DÉFAUT. Un serveur qu'on met à jour ne devient
            // pas un émetteur sans que personne l'ait décidé — la même règle que
            // pour `--dmarc-send`, et pour la même raison.
            relay: false,
            queue_spool: None,
            // ZÉRO PARTOUT, QUI VEUT DIRE « LE DÉFAUT DE `ams-queue` ». Recopier
            // les durées ici ferait deux vérités pour une seule décision.
            queue_retry: 0,
            queue_max_retry: 0,
            queue_expire: 0,
            queue_warn: 0,
            // PAS DE MTA-STS PAR DÉFAUT, et pas de drapeau : l'absence de
            // valeur EST l'absence de service. Embarquer des racines les ferait
            // vieillir avec le binaire ; lire celles du système sans qu'on l'ait
            // dit serait une confiance héritée en silence.
            // PAS DE RAPPORT TLS PAR DÉFAUT, et pas de drapeau pour composer :
            // l'absence de dossier EST l'absence de service, comme pour les
            // rapports DMARC. Et PAS DE REMISE non plus : émettre du courrier
            // vers des tiers ne se décide pas à la place de l'exploitant.
            tlsrpt_dir: None,
            tlsrpt_send: false,
            mtasts_anchors: None,
            mtasts_cache: None,
            // LES SEUILS DU GARDE VIENNENT DE `ams-guard`, et pas d'ici : les
            // recopier ferait deux vérités pour une seule décision, et la
            // seconde vieillirait en silence.
            guard: Thresholds::DEFAULT,
            // Quatre mille sources : assez pour que la table apprenne, assez peu
            // pour qu'elle tienne dans un budget qu'on peut dire à l'avance.
            tracked_sources: 4096,
        }
    }
}

impl Options {
    /// Compose la configuration que ces options décrivent.
    ///
    /// Les bornes du décodeur prennent leurs valeurs par défaut : les régler
    /// mérite ses propres options, et les inventer ici donnerait un fichier qui
    /// dit autre chose que ce qui a été demandé. Les seuils du garde, eux, ont
    /// désormais les leurs, parce que C8 l'exige.
    #[must_use]
    pub fn en_configuration(&self) -> Configuration {
        Configuration {
            domain: self.domain.clone(),
            listen: self.listen.to_string(),
            maildir: self.maildir.display().to_string(),
            hosted: self.hosted.clone(),
            max_recipients: 100,
            // **L'API REST N'EST PAS SERVIE PAR DÉFAUT** : l'absence d'adresse
            // EST l'absence de service, comme partout ailleurs ici.
            listen_http: adresse(self.listen_http.as_ref()),
            listen_h3: adresse(self.listen_h3.as_ref()),
            // **LE SECRET DE SCELLEMENT NE SE DÉCIDE PAS ICI**, et c'est la
            // seule valeur de cette structure dans ce cas. Il se TIRE du noyau,
            // ou se REPREND du fichier qu'on remplace — deux choses que cette
            // fonction ne peut pas faire, C1 lui interdisant toute
            // entrée-sortie. C'est `air-mail-admin` qui le pose, juste après.
            token_key: String::new(),
            max_message_octets: self.max_message_octets,
            max_connections: u32::try_from(self.max_connections).unwrap_or(u32::MAX),
            limits: Limits::DEFAULT,
            guard: self.guard,
            tracked_sources: self.tracked_sources,
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
                quarantine_folder: self.dmarc_quarantine.clone().unwrap_or_default(),
            },
            dkim: Dkim {
                selector: self.dkim_selector.clone().unwrap_or_default(),
                private_key_path: chemin(self.dkim_key.as_ref()),
            },
            accounts: chemin(self.accounts.as_ref()),
            tlsrpt: ams_config::Tlsrpt {
                directory: chemin(self.tlsrpt_dir.as_ref()),
                send: self.tlsrpt_send,
            },
            mtasts: ams_config::Mtasts {
                anchors: chemin(self.mtasts_anchors.as_ref()),
                cache: chemin(self.mtasts_cache.as_ref()),
            },
            relay: ams_config::Relay {
                enabled: self.relay,
            },
            queue: ams_config::Queue {
                spool: chemin(self.queue_spool.as_ref()),
                retry_seconds: self.queue_retry,
                max_retry_seconds: self.queue_max_retry,
                expire_seconds: self.queue_expire,
                warn_seconds: self.queue_warn,
            },
            listen_pop3: self
                .listen_pop3
                .map(|adresse| adresse.to_string())
                .unwrap_or_default(),
            listen_imap: self
                .listen_imap
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

/// Un nom de dossier, ou la raison pour laquelle ce n'en est pas un.
///
/// # LA RÈGLE EST CELLE D'IMAP, PARCE QUE LE DOSSIER EN EST UN
///
/// Ce nom deviendra un répertoire Maildir++ à la racine d'un compte et une
/// boîte que `LIST` annonce. Écrire ici une seconde règle « à peu près
/// équivalente » ferait accepter un nom que le serveur refuserait ensuite de
/// montrer — et l'administrateur ne saurait pas lequel des deux a raison.
fn nom_de_dossier(brut: &str) -> Result<String, ArgError> {
    // Le `/` final est celui qu'IMAP tolère et ignore ; on l'ôte ICI plutôt que
    // de l'écrire dans le fichier, où il ferait un répertoire dont le nom se
    // termine par un point.
    let brut = brut.strip_suffix('/').unwrap_or(brut);
    if !ams_proto_imap::mailbox_name_is_safe(brut.as_bytes()) {
        return Err(ArgError::new(format!(
            "`{brut}` n'est pas un nom de boîte : chaque morceau séparé par `/` doit être en \
             ASCII visible, sans espace en bordure, et sans `.` `\\` `%` `*` `\"` `:` — ce \
             dossier devient une boîte IMAP"
        )));
    }
    Ok(String::from(brut))
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
    --dkim-selector <s>    sélecteur DKIM publié dans le DNS
    --dkim-key <chemin>    clé privée DKIM, en PEM
    --tls-cert <chemin>    chaîne de certificats, en PEM
    --tls-key <chemin>     clé privée, en PEM
    --accounts <chemin>    fichier de comptes (`air-mail-admin account add`)
    --listen-pop3 <adr>    où écouter en POP3 (défaut : pas de POP3)
    --listen-imap <adr>    où écouter en IMAP (défaut : pas d'IMAP)

    L'API REST
    --listen-http <adr>    où la servir en HTTP/2. EXIGE `--tls-cert` et
                           `--tls-key` : elle porte des jetons porteurs, et un
                           jeton qui traverse un réseau en clair est un jeton
                           volé (C4). Défaut : pas d'API.
    --listen-h3 <adr>      la même, en HTTP/3 sur QUIC. EXIGE `--listen-http` :
                           `Alt-Svc` est le seul moyen par lequel un client
                           découvre un port HTTP/3, et il s'annonce depuis les
                           réponses HTTP/2.
    --rotate-token-key     renouvelle le secret de scellement. LES JETONS
                           FRAPPÉS AVANT CESSENT DE VALOIR. Sans cette option,
                           le secret d'un fichier existant est REPRIS, et les
                           jetons en cours restent valables.

    LE SECRET DE SCELLEMENT NE SE DONNE PAS SUR LA LIGNE DE COMMANDE, et ne se
    lit nulle part : il est tiré du noyau à la première écriture qui ouvre
    l'API, puis repris tel quel à chaque écriture suivante. Ce que `ps` affiche,
    tout le monde le lit — et un secret que personne n'a besoin de connaître est
    un secret que personne ne doit avoir à garder.

    TLSRPT (RFC 8460)
    --tlsrpt-dir <chemin>               dossier des rapports (défaut : aucun)
    --tlsrpt-send                       les REMETTRE, et pas seulement les déposer

    MTA-STS (RFC 8461)
    --mta-sts-anchors <chemin>          les autorités, en PEM (défaut : non évalué)
    --mta-sts-cache <chemin>            le dossier des politiques (EXIGÉ avec le premier)

    LA FILE DE RÉÉMISSION SORTANTE
    --relay                             émettre pour les comptes authentifiés

    LA FILE D'ATTENTE — tout ce qui sort passe par elle
    --queue-spool <chemin>              le dossier de la file (EXIGÉ dès qu'on émet)
    --queue-retry-seconds <n>           attente après le 1er échec  (défaut 900)
    --queue-max-retry-seconds <n>       plafond de l'attente        (défaut 21600)
    --queue-expire-seconds <n>          avant d'abandonner          (défaut 432000)
    --queue-warn-seconds <n>            avant de PRÉVENIR d'un retard (défaut 14400)

    LES SEUILS DU GARDE (C8)
    --connections-per-minute <n>        connexions par source   (défaut 60)
    --commands-per-minute <n>           commandes par source    (défaut 600)
    --invalid-frames-per-minute <n>     le `x` de C8            (défaut 20)
    --refused-recipients-per-minute <n> récolte d'adresses      (défaut 50)
    --ban-seconds <n>                   le `y` de C8            (défaut 3600)
    --ipv4-prefix-bits <n>              1 à 32                  (défaut 32)
    --ipv6-prefix-bits <n>              1 à 128                 (défaut 64)
    --tracked-sources <n>               sources retenues        (défaut 4096)

    LES DEUX OPTIONS DKIM VONT ENSEMBLE, ou aucune. Avec elles, le serveur SIGNE ce
    qu'il émet — aujourd'hui les rapports DMARC. Sans elles, il émet non signé, ce
    qui reste recevable. Il n'y a pas de troisième réglage : un sélecteur sans clé
    ne veut dire ni « signe » ni « ne signe pas ».

    La clé se publie dans le DNS sous `<sélecteur>._domainkey.<domaine>`, et le
    serveur refuse de démarrer si elle est lisible par tout le monde. Les formats
    lus sont le PKCS#8 (`BEGIN PRIVATE KEY`, RSA ou Ed25519) et le PKCS#1
    (`BEGIN RSA PRIVATE KEY`).

    LES DEUX OPTIONS TLS VONT ENSEMBLE, ou aucune. Avec elles, le serveur annonce
    `STARTTLS` et chiffre ; sans elles, il sert en clair et ne l'annonce pas. Il
    n'y a pas de troisième réglage : « annoncer sans pouvoir » ferait mentir la
    bannière, et « pouvoir sans annoncer » ne chiffrerait rien.

    Le serveur refuse de démarrer si la clé privée est lisible par tout le monde.
    Le partage par groupe, lui, reste permis.

    POP3 ET IMAP EXIGENT UN CERTIFICAT POUR SERVIR À QUELQUE CHOSE : leurs
    sessions refusent l'authentification hors chiffrement, sans réglage possible.
    Un `--listen-pop3` ou un `--listen-imap` sans `--tls-cert` ouvre un port où
    personne ne pourra relever son courrier ; le serveur le dit au démarrage.

    TOUTES LES COMMANDES DE RFC 9051 RÉPONDENT : `SELECT`, `LIST`, `STATUS`, `FETCH`,
    `STORE`, `EXPUNGE`, `SEARCH`, `COPY`, `MOVE`, `APPEND`, `CREATE`, `DELETE`,
    `RENAME`, `SUBSCRIBE` et `UNSUBSCRIBE`. `FETCH` rend une `ENVELOPE`, une `BODYSTRUCTURE`, une partie
    désignée — `BODY[1]`, `BODY[1.MIME]` — et un choix de champs d'en-tête —
    `BODY[HEADER.FIELDS (FROM)]`. La recherche lit aussi DANS les messages —
    `SUBJECT`, `BODY`, `TEXT` — en défaisant les mots encodés et les encodages de
    transfert : on cherche le texte, pas les octets. `BINARY[…]` rend le contenu
    transfert-décodé d'une partie, et refuse par `NO [UNKNOWN-CTE]` un encodage
    qu'il ne sait pas défaire. `NAMESPACE` et `ENABLE` répondent. `IDLE` fait attendre
    la session et lui pousse un `* n EXISTS` quand du courrier arrive : seule la
    croissance se dit, parce qu'annoncer une disparition renumérote des rangs que
    le client a déjà retenus. LES ABONNEMENTS S'ÉCRIVENT DANS LA RACINE DU
    COMPTE, un nom par ligne, sous `ams-abonnements` — `LIST (SUBSCRIBED)` les
    filtre, `LIST … RETURN (SUBSCRIBED)` les signale, et un abonnement dont la
    boîte a disparu se rend `\\NonExistent` plutôt que d'être retiré d'office.

    LES OPTIONS QUE rev2 A ABSORBÉES SONT SERVIES AUSSI (RFC 9051 §E) : `STATUS`
    rend ce qu'on lui demande — `UNSEEN`, `DELETED` et `SIZE` compris —,
    `LIST … RETURN (STATUS (…))` en rend un par boîte listée,
    `SEARCH RETURN (MIN MAX ALL COUNT SAVE)` répond de quatre façons, et `$`
    désigne ce que la dernière recherche a retenu. Ce résultat se retient EN UID :
    un message effacé en sort de lui-même, là où des rangs demanderaient d'être
    décalés à chaque effacement.

    `SENTBEFORE`, `SENTON` et `SENTSINCE` comparent le champ `Date:` du message, là
    où `BEFORE`, `ON` et `SINCE` comparent sa date d'arrivée : un message écrit
    lundi et reçu vendredi répond à l'une et pas à l'autre.

    LES CINQ MOTS-CLEFS DE §E.15 SONT SERVIS — `$MDNSent`, `$Forwarded`, `$Junk`,
    `$NonJunk` et `$Phishing` —, avec `KEYWORD` et `UNKEYWORD`. Maildir les porte
    dans le nom du fichier, en minuscules, ce qui les fait survivre comme les
    autres drapeaux. L'ENSEMBLE EST FERMÉ : un mot-clef qu'on ne saurait pas faire
    survivre est refusé, plutôt que de répondre `OK` à une étiquette qu'on
    perdrait, et `PERMANENTFLAGS` n'annonce donc pas `\\*`.

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

    `--dmarc-quarantine-folder Junk` MET DE CÔTÉ ce qu'un `p=quarantine` vise, dans
    un dossier de ce nom, créé au besoin à la remise. C'est un dossier IMAP
    ordinaire, que tout client montre sans rien connaître de DMARC ; en POP3, où
    il n'y a qu'une boîte, il ne se voit pas — le message y est simplement absent,
    et l'en-tête `Authentication-Results` dit pourquoi.

    SANS CETTE OPTION, RIEN NE CHANGE : le message va dans la boîte de réception,
    et le rapport agrégé dit `none`, parce que c'est ce qui a été fait. Écrire
    `quarantine` sans dossier ferait croire à un domaine qu'il est protégé là où
    il ne l'est pas, et c'est le seul mensonge qu'un rapport ne peut pas se
    permettre.

    ELLE NE DÉPEND PAS DE `--dmarc enforce`. `observe` et `enforce` gouvernent le
    REFUS d'un `p=reject` — ce qui se perd si l'on se trompe. La quarantaine, elle,
    REMET : elle déplace, elle ne jette pas, et il n'y a donc rien à découvrir
    avant de l'ouvrir.

    `--dmarc-org-name` est le nom sous lequel ce receveur se présente (défaut :
    le nom annoncé), `--dmarc-report-email` l'adresse où le joindre (défaut :
    `postmaster@` suivi du nom annoncé), `--dmarc-report-interval` le nombre de
    secondes entre deux vidanges du journal (défaut : 86400, un jour).

    SANS `--relay`, RIEN NE SORT, et c'est le défaut. Un destinataire qui n'est pas
    d'ici est refusé par un `550`, même pour un compte authentifié : ce serveur
    reçoit, il n'émet pas. Émettre du courrier vers des tiers ne se décide pas à
    la place de celui qui exploite la machine — la même règle que
    `--dmarc-send` — et une mise à jour ne transforme donc personne en relais.

    AVEC `--relay`, ON NE RELAIE QUE POUR UN COMPTE AUTHENTIFIÉ. C'est la seule
    chose qui sépare un relais d'un relais ouvert, et ce n'est pas réglable.
    L'authentification n'étant annoncée que sous chiffrement, `--relay` sans
    `--tls-cert` n'ouvre l'émission à personne ; le serveur le dit au démarrage.

    `--queue-spool` EST EXIGÉ DÈS QUE QUELQUE CHOSE SORT — `--relay`,
    `--dmarc-send` ou `--tlsrpt-send`. TOUT ce qui sort passe par la même file :
    il y avait trois politiques de reprise dans ce produit, dont deux écrites à
    la main pour les rapports, et trois politiques sont trois vérités qui
    divergent. Il n'y en a plus qu'une.

    Le dossier est DISTINCT du Maildir : ce qui attend d'être émis n'est pas du
    courrier reçu, et les mélanger ferait apparaître dans une boîte ce qui n'y
    est jamais arrivé. Accepter un message qu'on n'a nulle part où poser serait
    le perdre en silence, et c'est pourquoi le manque est refusé ici plutôt qu'au
    démarrage.

    LES ANCIENS NOMS `--relay-spool` ET SES TROIS VOISINS SONT REFUSÉS, en
    disant le nouveau : la file n'appartient plus au relais, et les laisser
    passer ferait croire qu'ils ne gouvernent que lui.

    L'ATTENTE DOUBLE À CHAQUE ÉCHEC, jusqu'au plafond. Réessayer à intervalle fixe
    pendant cinq jours, c'est frapper des centaines de fois à une porte fermée —
    et si mille messages attendent pour ce même domaine, c'est le marteler pendant
    qu'il se relève. La péremption par défaut est de cinq jours, ce que
    §4.5.4.1 de RFC 5321 demande au moins.

    QUAND ON RENONCE, UN RAPPORT DE NON-REMISE (RFC 3464) PART — et il est remis
    LOCALEMENT, dans la boîte du compte qui avait déposé. Ce serveur n'envoie
    jamais de rebond à un inconnu : le chemin de retour est toujours l'une de ses
    propres adresses, puisqu'il ne relaie que pour ses comptes. C'est ce qui le
    tient hors de la rétro-diffusion — émettre un rebond vers une adresse qu'un
    tiers a écrite dans un `MAIL FROM:` usurpé ferait de nous l'instrument de son
    envoi.

    LES RAPPORTS TLS NE SONT COMPOSÉS QUE SI UN DOSSIER EST NOMMÉ, et ils sont
    DÉPOSÉS, pas remis. `--tlsrpt-send` les envoie. Deux crans, exactement comme
    les rapports DMARC : un exploitant peut lire ce qu'il enverrait avant de
    l'envoyer, et émettre du courrier vers des tiers ne se décide pas à sa place.

    C'EST LE SEUL MÉCANISME DE CE SERVEUR DONT LE BÉNÉFICIAIRE EST QUELQU'UN
    D'AUTRE. DANE et MTA-STS protègent VOTRE courrier ; TLSRPT rend au domaine
    d'en face ce que vous seul savez — que ses `TLSA` sont mal renouvelés, que sa
    politique nomme un serveur disparu, que son certificat a expiré. Un domaine
    qui publie `mode: testing` publie précisément pour l'apprendre.

    ON NE RAPPORTE QU'À QUI A DEMANDÉ (§3) : sans `_smtp._tls.<domaine>`, rien
    n'est composé pour lui. Et quand la destination `rua` est d'un AUTRE domaine,
    ce tiers doit avoir dit qu'il l'accepte, en publiant
    `<rapporté>._report._smtp._tls.<destination>` — sans quoi n'importe qui
    publierait `rua=mailto:victime@banque.test` et ferait bombarder cette adresse
    par tous les émetteurs du monde. C'est le même mécanisme que §7.1 de RFC 7489
    pour DMARC, et il n'est pas plus facultatif ici.

    LES DEUX TRANSPORTS DE §3 SONT SERVIS. `mailto:` passe par le client sortant,
    donc par DANE et MTA-STS comme n'importe quel message ; `https:` POSTE le
    rapport en `application/tlsrpt+gzip`, et VÉRIFIE LE CERTIFICAT contre les
    autorités de `--mta-sts-anchors` — sans elles, seul `mailto:` fonctionne, et
    le serveur le dit au démarrage.

    LE RAPPORT DIT AUSSI NOTRE ADRESSE D'ÉMISSION (`sending-mta-ip`, facultatif
    en §4.3). Elle est écrite : le destinataire la connaît déjà — c'est nous qui
    l'avons appelé — et elle lui permet de corréler avec ses propres journaux.

    MTA-STS N'EST ÉVALUÉ QUE SI DES AUTORITÉS SONT NOMMÉES. Il n'y a pas d'option
    pour « activer » : `--mta-sts-anchors` suffit, et son absence dit l'inverse.
    Un domaine qui publie une politique sur `https://mta-sts.<domaine>/` dit quels
    serveurs peuvent recevoir son courrier, et c'est la WebPKI qui atteste que la
    politique vient bien de lui.

    LES RACINES NE SONT PAS EMBARQUÉES, et ce n'est pas un oubli : embarquées,
    elles vieilliraient avec le binaire et personne ne saurait de quand datent les
    siennes — le même argument que pour la liste des suffixes publics. Les lire
    dans `/etc/ssl/certs` sans qu'on l'ait dit serait pire : une confiance héritée
    en silence, comme le `/etc/resolv.conf` que ce serveur refuse déjà de lire.
    Nommez celui de votre distribution :
    `--mta-sts-anchors /etc/ssl/certs/ca-certificates.crt`.

    LE CACHE EST LA PROTECTION, PAS UNE OPTIMISATION. §5 de RFC 8461 : un
    attaquant qui peut bloquer le `https://` obtiendrait, sans cache, une remise
    sans politique — c'est-à-dire le déclassement que MTA-STS existe pour fermer.
    Une politique en cache reste valable jusqu'à sa péremption, quoi qu'il arrive
    au réseau, et un cache en mémoire seule rouvrirait cette fenêtre à chaque
    redémarrage. C'est pourquoi les deux options vont ensemble.

    DANE L'EMPORTE quand un domaine publie les deux (§2 de RFC 8461) : sa
    confiance ne passe par aucun tiers, et MTA-STS n'est alors même pas consulté.

    `testing` CONSIGNE ET REMET QUAND MÊME. Un domaine qui s'installe publie
    `mode: testing` pour dire « ne refusez pas encore » ; on évalue, on écrit dans
    le journal ce qui aurait échoué, et l'on remet. `enforce`, lui, ajourne : le
    message reste en file et repartira.

    UNE LIMITE ASSUMÉE : l'hôte de politique est joint en TLS 1.3, comme tout le
    reste de ce serveur (C4, C6). Un domaine dont cet hôte ne sait faire que
    TLS 1.2 ne sera donc pas lu, et sa remise retombera sur le chiffrement
    opportuniste. Ce n'est pas une faille — on ne prétend rien qu'on n'a pas —
    mais c'est une protection qu'on n'obtient pas.

    LE GARDE SE RÈGLE ICI, ET NULLE PART AILLEURS. C8 demande que ce qui borne une
    source vienne de la configuration : un seuil gravé dans le code est un seuil
    qu'on ne peut pas desserrer le jour où il se trompe, ni resserrer le jour où
    il ne suffit plus. Ces huit options sont ce qui rend cette exigence vraie
    ailleurs que dans le format.

    `--connections-per-minute` et `--commands-per-minute` AJOURNENT ; les deux
    autres compteurs BANNISSENT. Ajourner ferme la connexion du moment ; bannir
    ferme la porte à la source pour `--ban-seconds`, sans un mot — pas même une
    bannière, parce que répondre confirmerait qu'il y a un serveur ici.

    `--max-connections` N'EST PAS `--connections-per-minute` : le premier dit
    combien de sessions le serveur mène EN MÊME TEMPS, toutes sources
    confondues ; le second, combien de fois UNE MÊME SOURCE a le droit de se
    présenter par minute.

    ZÉRO NE VEUT PAS DIRE LA MÊME CHOSE PARTOUT, et c'est ce qu'il faut lire
    avant de taper l'une de ces options :

      - `--refused-recipients-per-minute 0` ÉTEINT le comptage de la récolte
        d'adresses. C'est ce qui a permis d'ajouter ce seuil sans rien casser :
        une configuration écrite avant qu'il n'existe décode zéro, et se
        comporte comme avant. `config show` et le serveur au démarrage le disent
        tous les deux, parce qu'un compteur éteint qu'on croit allumé est pire
        qu'un compteur absent.
      - `--invalid-frames-per-minute 0` fait L'INVERSE : il bannit au premier
        écart. C'est une politique dure, mais elle se comprend d'elle-même, et
        l'interdire reviendrait à décider à la place de qui exploite la machine.
      - `--ban-seconds 0` dit « NE BANNIS PAS » : le garde ajourne au lieu de
        bannir. Une peine qui finit à l'instant où elle commence n'en est pas
        une, et le garde refuse de l'annoncer.
      - PARTOUT AILLEURS, zéro est REFUSÉ, parce qu'il ne veut rien dire :
        zéro connexion par minute ne sert personne, zéro commande ne laisse même
        pas dire `QUIT`, et une table de zéro source ne retient rien donc ne
        reproche rien.

    LES PRÉFIXES DÉCIDENT DE QUI PAIE POUR QUI. On ne compte pas une adresse mais
    un BLOC : bannir une IPv6 seule ne sert à rien, puisque le plus petit bloc
    qu'un fournisseur attribue est un `/64` et que le pair banni revient à
    l'adresse suivante. En IPv4 le défaut est `/32` — le bloc d'un abonné EST
    souvent une adresse, et élargir y punirait des voisins. Un préfixe de zéro
    bit est refusé : il mettrait tout l'Internet dans le même seau, et le premier
    banni bannirait tout le monde.

    `--tracked-sources` BORNE LA TABLE, et cette borne est ce qui l'empêche
    d'être un épuisement de mémoire offert à qui dispose d'un `/64`. Une table
    pleine de peines en cours CESSE D'APPRENDRE plutôt que d'oublier un banni :
    évincer « le bannissement qui expire le plus tôt » suffisait à s'en libérer
    en remplissant la table, et le fuzz l'a montré.

    Les bornes du décodeur, elles, prennent toujours leurs valeurs par défaut :
    les régler mérite ses propres options, et les inventer ici donnerait un
    fichier qui dit autre chose que ce qui a été demandé.
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
                // **ZÉRO ANNONCERAIT L'INVERSE DE CE QU'IL FAIT.** §3 de RFC 1870
                // donne un sens à `SIZE 0` : « aucune taille maximale n'est en
                // vigueur ». Or ce serveur compare `> max_message`, si bien
                // qu'un plafond nul refuse TOUT message d'au moins un octet. Le
                // pair lirait « pas de limite » et se verrait refuser sur un
                // octet, sans rien à corriger chez lui.
                //
                // Et l'illimité n'est pas une option que ce serveur offre : C3
                // veut des longueurs bornées. Il n'y a donc pas de sens à donner
                // à ce zéro-là, seulement un refus.
                options.max_message_octets = pas_zero(
                    &valeur()?,
                    "un plafond nul annonce `SIZE 0` — « aucune limite » au sens de RFC 1870 \
                     §3 — et refuse pourtant tout message d'au moins un octet",
                )?;
            }
            "--tls-cert" => options.tls_cert = Some(PathBuf::from(valeur()?)),
            "--dkim-selector" => options.dkim_selector = Some(valeur()?),
            "--dkim-key" => options.dkim_key = Some(PathBuf::from(valeur()?)),
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
            "--dmarc-quarantine-folder" => {
                options.dmarc_quarantine = Some(nom_de_dossier(&valeur()?)?);
            }
            "--dmarc-org-name" => options.dmarc_org_name = Some(valeur()?),
            "--dmarc-report-email" => options.dmarc_report_email = Some(valeur()?),
            // ZÉRO EST LICITE ICI, ET IL VEUT DIRE « UN JOUR ». C'est la valeur
            // que la configuration substitue, et c'est ce qui rend ce champ
            // ajoutable sans rien casser : un fichier antérieur décode zéro.
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
                // **UN DÉLAI NUL EXPIRE AVANT QUE LA QUESTION PARTE.** Toute
                // interrogation du résolveur échoue alors, et SPF ne rend plus
                // que des pannes. Sous `--spf enforce`, une panne s'ajourne :
                // CHAQUE message reçoit un `451`, et le serveur n'accepte plus
                // rien — sans qu'aucune ligne ne dise pourquoi.
                options.spf_timeout_millis = pas_zero(
                    &valeur()?,
                    "un délai nul fait expirer la question avant qu'elle parte : SPF ne rend \
                     plus que des pannes, et `--spf enforce` ajourne alors chaque message",
                )?;
            }
            "--listen-pop3" => {
                let brute = valeur()?;
                options.listen_pop3 = Some(
                    brute
                        .parse()
                        .map_err(|_| ArgError::new(format!("`{brute}` n'est pas une adresse")))?,
                );
            }
            "--listen-imap" => {
                let brute = valeur()?;
                options.listen_imap = Some(
                    brute
                        .parse()
                        .map_err(|_| ArgError::new(format!("`{brute}` n'est pas une adresse")))?,
                );
            }
            // ── L'API REST ─────────────────────────────────────────────────
            "--listen-http" => {
                let brute = valeur()?;
                options.listen_http = Some(
                    brute
                        .parse()
                        .map_err(|_| ArgError::new(format!("`{brute}` n'est pas une adresse")))?,
                );
            }
            "--listen-h3" => {
                let brute = valeur()?;
                options.listen_h3 = Some(
                    brute
                        .parse()
                        .map_err(|_| ArgError::new(format!("`{brute}` n'est pas une adresse")))?,
                );
            }
            "--rotate-token-key" => options.rotate_token_key = true,
            "--max-connections" => {
                // **C'EST LE MÊME REFUS QUE `--connections-per-minute`**, en plus
                // total : celui-là n'accepte personne pendant une minute,
                // celui-ci jamais. Le nombre devient le compte de jetons d'un
                // sémaphore, sur les quatre écoutes à la fois ; à zéro, aucune
                // connexion n'est jamais servie. Le refuser là et pas ici serait
                // garder la petite porte et laisser la grande.
                options.max_connections = pas_zero(
                    &valeur()?,
                    "un serveur qui n'accepte aucune connexion ne sert personne, sur aucune \
                     de ses écoutes",
                )?;
            }
            // ── TLSRPT (RFC 8460) ───────────────────────────────────────────
            "--tlsrpt-dir" => options.tlsrpt_dir = Some(PathBuf::from(valeur()?)),
            "--tlsrpt-send" => options.tlsrpt_send = true,
            // ── MTA-STS (RFC 8461) ──────────────────────────────────────────
            "--mta-sts-anchors" => {
                options.mtasts_anchors = Some(PathBuf::from(valeur()?));
            }
            "--mta-sts-cache" => options.mtasts_cache = Some(PathBuf::from(valeur()?)),
            // ── La file de réémission sortante ──────────────────────────────
            "--relay" => options.relay = true,
            "--queue-spool" => options.queue_spool = Some(PathBuf::from(valeur()?)),
            "--queue-retry-seconds" => {
                options.queue_retry = pas_zero(
                    &valeur()?,
                    "une attente nulle ferait réessayer aussi vite que le disque tourne",
                )?;
            }
            "--queue-max-retry-seconds" => {
                options.queue_max_retry = pas_zero(
                    &valeur()?,
                    "un plafond nul ramènerait toutes les attentes à rien",
                )?;
            }
            "--queue-expire-seconds" => {
                options.queue_expire = pas_zero(
                    &valeur()?,
                    "une péremption nulle rendrait le message à son expéditeur sans avoir \
                     essayé une seule fois",
                )?;
            }
            "--queue-warn-seconds" => {
                options.queue_warn = pas_zero(
                    &valeur()?,
                    "un seuil nul avertirait d'un retard dès le premier essai, c'est-à-dire \
                     pour chaque message qui n'est pas parti du premier coup",
                )?;
            }
            // **LES ANCIENS NOMS SE REFUSENT EN DISANT LE NOUVEAU.**
            //
            // La file n'appartient plus au relais : les rapports DMARC et TLS
            // l'empruntent aussi. Les laisser passer sous leur ancien nom ferait
            // croire qu'ils ne gouvernent que le relais ; les traiter comme des
            // options inconnues laisserait chercher.
            ancien @ ("--relay-spool"
            | "--relay-retry-seconds"
            | "--relay-max-retry-seconds"
            | "--relay-expire-seconds") => {
                let neuf = ancien.replacen("--relay-", "--queue-", 1);
                return Err(ArgError::new(format!(
                    "`{ancien}` s'appelle désormais `{neuf}` : la file n'est plus celle du \
                     relais, les rapports DMARC et TLS l'empruntent aussi"
                )));
            }
            // ── Les seuils du garde (C8) ────────────────────────────────────
            //
            // **ZÉRO NE VEUT PAS DIRE LA MÊME CHOSE PARTOUT**, et c'est le piège
            // de cette famille d'options. Pour les destinataires refusés il
            // ÉTEINT le compteur ; pour les trames invalides il bannit au
            // premier écart ; pour les connexions il n'accepterait plus
            // personne. On refuse donc les zéros qui ne veulent rien dire, et on
            // documente ceux qui en veulent un.
            "--connections-per-minute" => {
                options.guard.connections_per_minute = pas_zero(
                    &valeur()?,
                    "un serveur qui accepte zéro connexion par minute ne sert personne",
                )?;
            }
            "--commands-per-minute" => {
                options.guard.commands_per_minute = pas_zero(
                    &valeur()?,
                    "une session qui n'a droit à aucune commande ne peut même pas dire `QUIT`",
                )?;
            }
            "--invalid-frames-per-minute" => {
                // ZÉRO EST LICITE ICI : il dit « bannis au premier écart ». Le
                // refuser interdirait une politique dure que quelqu'un peut
                // vouloir tenir, et qui se comprend d'elle-même.
                options.guard.invalid_frames_per_minute = nombre(&valeur()?)?;
            }
            "--refused-recipients-per-minute" => {
                // ZÉRO EST LICITE ICI AUSSI, et il veut dire l'INVERSE : il
                // éteint le comptage. C'est ce qui rend ce seuil ajoutable sans
                // rien casser, puisqu'un fichier antérieur au champ décode zéro.
                options.guard.refused_recipients_per_minute = nombre(&valeur()?)?;
            }
            "--ban-seconds" => {
                // ZÉRO EST LICITE : il dit « ne bannis pas ». Le garde ajourne
                // alors la source au lieu de la bannir — une peine qui finit à
                // l'instant où elle commence n'en est pas une.
                let secondes = nombre(&valeur()?)?;
                options.guard.ban_duration = Duration::from_secs(u64::from(secondes));
            }
            "--ipv4-prefix-bits" => {
                options.guard.ipv4_prefix_bits = prefixe(&valeur()?, 32)?;
            }
            "--ipv6-prefix-bits" => {
                options.guard.ipv6_prefix_bits = prefixe(&valeur()?, 128)?;
            }
            "--tracked-sources" => {
                options.tracked_sources = pas_zero(
                    &valeur()?,
                    "une table de capacité nulle ne retient rien, donc ne reproche rien : \
                     le garde laisse alors tout passer",
                )?;
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
    // ── L'API REST NE S'OUVRE PAS EN CLAIR ──────────────────────────────────
    //
    // Elle porte des jetons PORTEURS : qui lit le jeton devient administrateur.
    // Un jeton qui traverse un réseau en clair est un jeton volé, et C4 ferme ce
    // port sans certificat. Le serveur le refuse déjà au démarrage ; le dire ici
    // coûte une seconde plutôt qu'une astreinte.
    if options.listen_http.is_some() && !(options.tls_cert.is_some() && options.tls_key.is_some()) {
        return Err(ArgError::new(
            "`--listen-http` demande `--tls-cert` et `--tls-key` : cette API porte des jetons \
             porteurs, et un jeton qui traverse un réseau en clair est un jeton volé",
        ));
    }
    // **`Alt-Svc` EST LE SEUL MOYEN DE TROUVER UN PORT HTTP/3** (RFC 7838, §3.1
    // de RFC 9114), et il s'annonce depuis les réponses HTTP/2. Un port H3 sans
    // port HTTP/2 est donc un port UDP que personne ne cherchera jamais : la
    // même faute que d'annoncer une alternative absente, dans l'autre sens.
    if options.listen_h3.is_some() && options.listen_http.is_none() {
        return Err(ArgError::new(
            "`--listen-h3` demande `--listen-http` : `Alt-Svc` est le seul moyen par lequel un \
             client découvre un port HTTP/3, et il s'annonce depuis les réponses HTTP/2",
        ));
    }
    // UNE ROTATION QUI NE ROTATIONNE RIEN. Sans API, aucun jeton n'est scellé ni
    // vérifié : renouveler le secret ne changerait rien à rien, et laisserait
    // croire qu'on vient de révoquer quelque chose.
    if options.rotate_token_key && options.listen_http.is_none() {
        return Err(ArgError::new(
            "`--rotate-token-key` demande `--listen-http` : sans API, aucun jeton n'est scellé, \
             et renouveler le secret ne révoquerait rien",
        ));
    }

    // ── DMARC NE SE DEMANDE PAS À MOITIÉ ────────────────────────────────────
    //
    // L'évaluer exige DEUX choses, et pas une : une liste de suffixes publics,
    // pour savoir si deux domaines s'alignent, ET un résolveur, pour aller lire
    // la politique du domaine de l'en-tête `From:`. À défaut de l'une des deux,
    // AUCUN message n'est évalué — et tout ce qu'on aurait réglé par ailleurs ne
    // s'applique alors à rien, en silence.
    //
    // CE REFUS REMPLACE CELUI QUI NE VISAIT QUE LA QUARANTAINE, parce que le
    // défaut n'était pas propre à elle : `--dmarc enforce` promettait un refus
    // qui n'avait pas lieu, `--dmarc-report-dir` un dossier qui restait vide, et
    // `config show` annonçait « DMARC APPLIQUÉ » sur la ligne qui suit « SPF
    // AUCUN RÉSOLVEUR ». Un cas particulier corrigé seul laisse ses frères.
    //
    // UNE LISTE SEULE N'EST PAS REFUSÉE, pour la raison qui vaut déjà pour un
    // dossier de file sans émission : elle ne promet rien à personne, et permet
    // de la préparer avant.
    let demande = [
        (options.dmarc_enforce, "--dmarc enforce"),
        (
            options.dmarc_quarantine.is_some(),
            "--dmarc-quarantine-folder",
        ),
        (options.dmarc_report_dir.is_some(), "--dmarc-report-dir"),
        (options.dmarc_send, "--dmarc-send"),
        (options.dmarc_failures, "--dmarc-failure-reports"),
    ]
    .into_iter()
    .find_map(|(demandee, nom)| demandee.then_some(nom));
    if let Some(option) = demande
        && let Some(manque) = manque_pour_evaluer_dmarc(&options)
    {
        return Err(ArgError::new(format!(
            "`{option}` demande que DMARC soit évalué, et il manque {manque} : sans cela aucun \
             message n'est évalué, et cette option ne s'appliquerait à rien"
        )));
    }

    // **UN RELAIS SANS DOSSIER PERDRAIT LE COURRIER EN SILENCE** : on aurait dit
    // `250` à un message qu'on n'a nulle part où poser. Le serveur le refuserait
    // aussi au démarrage ; le dire ici coûte une seconde plutôt qu'une astreinte.
    // **TOUT CE QUI SORT PASSE PAR LA FILE**, et pas seulement le relais : les
    // rapports DMARC et TLS l'empruntent aussi depuis qu'il n'y a plus qu'une
    // politique de reprise.
    let emet = options.relay || options.dmarc_send || options.tlsrpt_send;
    if emet && options.queue_spool.is_none() {
        return Err(ArgError::new(
            "il faut `--queue-spool` dès que quelque chose sort — `--relay`, `--dmarc-send` \
             ou `--tlsrpt-send` : un message accepté qu'on n'a nulle part où poser est un \
             message perdu",
        ));
    }
    // L'INVERSE N'EST PAS REFUSÉ, et c'est délibéré : nommer un dossier sans
    // rien émettre ne promet rien à personne, et permet de le préparer avant.
    // Le serveur le dit au démarrage.
    // **LES DEUX VONT ENSEMBLE, OU AUCUNE.** Sans autorités, on ne saurait pas à
    // qui l'on parle en allant chercher la politique ; sans cache, un
    // redémarrage rouvrirait la fenêtre de déclassement que §5 de RFC 8461
    // ferme. L'une sans l'autre ne veut dire ni « évalue » ni « n'évalue pas ».
    if options.mtasts_anchors.is_some() != options.mtasts_cache.is_some() {
        return Err(ArgError::new(
            "`--mta-sts-anchors` et `--mta-sts-cache` vont ENSEMBLE : sans autorités on ne \
             saurait pas à qui l'on parle, et sans cache un redémarrage rouvrirait la fenêtre \
             de déclassement que le cache existe pour fermer",
        ));
    }
    if options.dkim_selector.is_some() != options.dkim_key.is_some() {
        return Err(ArgError::new(
            "`--dkim-selector` et `--dkim-key` vont ENSEMBLE : l'un sans l'autre ne veut dire ni \
             « signe » ni « ne signe pas »",
        ));
    }
    Ok(Demande::Ecrire(Box::new(options)))
}

/// Ce qui manque pour que DMARC soit évalué, ou `None` s'il ne manque rien.
///
/// **LES DEUX MOITIÉS SE NOMMENT SÉPARÉMENT.** Dire « il manque quelque chose »
/// obligerait l'administrateur à relire la documentation pour savoir quoi ; dire
/// laquelle des deux manque lui coûte une seconde.
fn manque_pour_evaluer_dmarc(options: &Options) -> Option<&'static str> {
    match (
        options.public_suffix_list.is_none(),
        options.resolvers.is_empty(),
    ) {
        (true, true) => Some("`--public-suffix-list` ET `--resolver`"),
        (true, false) => Some("`--public-suffix-list`"),
        (false, true) => Some("`--resolver`"),
        (false, false) => None,
    }
}

/// Un nombre, ou ce qui n'en est pas un.
fn nombre(brute: &str) -> Result<u32, ArgError> {
    brute
        .parse()
        .map_err(|_| ArgError::new(format!("`{brute}` n'est pas un nombre")))
}

/// Un nombre dont zéro ne voudrait rien dire, et `pourquoi` le dit.
/// # Pourquoi elle est GÉNÉRIQUE
///
/// Les nombres qu'elle garde ne sont pas du même type : un plafond de message se
/// compte en `u64`, un nombre de connexions en `usize`, un délai en `u32`. Trois
/// copies auraient laissé la règle s'appliquer à deux d'entre eux — c'est
/// exactement ce qui était arrivé, et le prix en a été trois zéros destructeurs
/// qu'aucun refus n'arrêtait.
fn pas_zero<T>(brute: &str, pourquoi: &str) -> Result<T, ArgError>
where
    T: core::str::FromStr + PartialEq + From<u8>,
{
    let combien: T = brute
        .parse()
        .map_err(|_| ArgError::new(format!("`{brute}` n'est pas un nombre")))?;
    if combien == T::from(0) {
        // ON REFUSE ICI, PAS AU DÉMARRAGE DU SERVEUR : l'administrateur est
        // devant son terminal, et c'est le seul moment où le lui dire coûte une
        // seconde plutôt qu'une astreinte.
        return Err(ArgError::new(format!("`0` est refusé : {pourquoi}")));
    }
    Ok(combien)
}

/// Une longueur de préfixe, entre `1` et `maximum` bits.
///
/// **ZÉRO EST REFUSÉ, ET C'EST LE REFUS QUI COMPTE LE PLUS ICI** : un préfixe de
/// zéro bit met tout l'Internet dans le même seau, et le premier pair banni
/// bannirait alors tout le monde. `ams-guard` se contente de RABOTER ce qui
/// dépasse — c'est ce qu'une bibliothèque doit faire d'une entrée qu'elle ne
/// choisit pas —, mais un `/48` tapé pour de l'IPv4 et compté comme un `/32`
/// serait une configuration qui dit autre chose que ce qui a été demandé.
fn prefixe(brute: &str, maximum: u8) -> Result<u8, ArgError> {
    let bits = nombre(brute)?;
    if bits == 0 {
        return Err(ArgError::new(
            "`0` est refusé : un préfixe de zéro bit met toutes les adresses dans le même \
             seau, et le premier banni bannirait tout le monde",
        ));
    }
    if bits > u32::from(maximum) {
        return Err(ArgError::new(format!(
            "`{bits}` dépasse {maximum} bits : ce préfixe serait raboté en silence"
        )));
    }
    // **CETTE CONVERSION NE PEUT PAS ÉCHOUER, ET LE DIRE VAUT MIEUX QUE DE
    // FAIRE SEMBLANT DE S'EN GARDER.** Le refus juste au-dessus établit
    // `bits <= maximum`, et `maximum` est un `u8` — donc `bits` tient dans un
    // `u8` par construction. Le `map_err` qui vivait ici rendait une erreur que
    // rien ne pouvait produire : une garde qu'aucun essai ne peut éprouver n'est
    // pas une garde, c'est une branche morte qui fait croire à une vérification.
    Ok(u8::try_from(bits).expect("bits <= maximum, et maximum est un u8"))
}

/// Un chemin, ou la chaîne vide qui dit « rien ».
fn chemin(valeur: Option<&PathBuf>) -> String {
    valeur.map(|c| c.display().to_string()).unwrap_or_default()
}

/// Une adresse d'écoute, ou la chaîne vide qui dit « ce service n'est pas rendu ».
fn adresse(valeur: Option<&SocketAddr>) -> String {
    valeur.map(SocketAddr::to_string).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{ArgError, Demande, Options, Thresholds, parse};
    use core::time::Duration;
    use std::net::SocketAddr;
    use std::path::PathBuf;

    /// **ON APPELLE `parse` SUR UNE TRANCHE, JAMAIS SUR UN TABLEAU.**
    ///
    /// `parse` est générique sur ce qu'on lui donne à parcourir, et un tableau de
    /// taille fixe porte SA TAILLE dans son type : `parse(["--a"])` et
    /// `parse(["--a", "b"])` sont deux fonctions différentes, chacune avec ses
    /// propres fermetures. `llvm-cov` compte les régions de chaque
    /// monomorphisation ; celles qu'un appel de taille 1 ne peut pas atteindre
    /// restent découvertes à jamais, quel que soit le nombre d'essais.
    ///
    /// C'est ce qui a tenu cette crate à 99,77 % avec toutes ses lignes et toutes
    /// ses fonctions à 100 % — trois régions introuvables, que la vue textuelle
    /// FUSIONNE et que seul `--show-instantiations` montre. Une tranche n'a
    /// qu'un type, donc qu'une instanciation.
    fn ecrire(arguments: &[&str]) -> Options {
        match parse(arguments).expect("recevable") {
            Demande::Ecrire(options) => *options,
            autre => panic!("attendu `Ecrire`, obtenu {autre:?}"),
        }
    }

    /// **CE `panic!` N'EST PAS DÉCORATIF**, et c'est pourquoi il est éprouvé.
    ///
    /// Un essai qui demanderait l'aide en croyant écrire une configuration
    /// examinerait des options par défaut en pensant examiner les siennes, et
    /// conclurait n'importe quoi sans rien signaler. Le bras s'arrête donc net.
    #[test]
    #[should_panic(expected = "attendu `Ecrire`")]
    fn le_secours_des_essais_refuse_une_demande_qui_n_ecrit_pas() {
        let _ = ecrire(&["--help"]);
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
    fn l_adresse_imap_traverse_jusqu_a_la_configuration() {
        let config = ecrire(&[
            "--domain",
            "mail.example.com",
            "--listen-imap",
            "127.0.0.1:2143",
        ])
        .en_configuration();
        assert_eq!(config.listen_imap, "127.0.0.1:2143");
        let sans = ecrire(&["--domain", "mail.example.com"]).en_configuration();
        assert!(sans.listen_imap.is_empty());
    }

    #[test]
    fn une_adresse_imap_illisible_est_refusee() {
        let erreur = parse(["--listen-imap", "pas-une-adresse"].as_slice()).expect_err("refusé");
        assert!(
            erreur.message.contains("n'est pas une adresse"),
            "{}",
            erreur.message
        );
    }

    #[test]
    fn une_adresse_pop3_illisible_est_refusee() {
        let erreur = parse(["--listen-pop3", "pas-une-adresse"].as_slice()).expect_err("refusé");
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
            assert_eq!(parse([argument].as_slice()), Ok(Demande::Aide));
        }
        for argument in ["--version", "-V"] {
            assert_eq!(parse([argument].as_slice()), Ok(Demande::Version));
        }
        // Même au milieu d'options qui suivraient.
        assert_eq!(
            parse(["--domain", "x", "--help"].as_slice()),
            Ok(Demande::Aide)
        );
    }

    #[test]
    fn une_ligne_de_commande_irrecevable_est_refusee() {
        for (arguments, extrait) in [
            (["--inconnue"].as_slice(), "option inconnue"),
            (&["--listen"], "attend une valeur"),
            (&["--listen", "pas-une-adresse"], "n'est pas une adresse"),
            // LES DEUX ADRESSES DE L'API AUSSI : une adresse illisible se
            // refuse avant que la cohérence ne se prononce, si bien que le
            // certificat manquant n'a pas encore à être signalé.
            (
                &["--listen-http", "pas-une-adresse"],
                "n'est pas une adresse",
            ),
            (&["--listen-h3", "pas-une-adresse"], "n'est pas une adresse"),
            (&["--max-message", "beaucoup"], "n'est pas un nombre"),
            (&["--max-connections", "-1"], "n'est pas un nombre"),
            // ── Les zéros qui ne veulent rien dire, et les préfixes absurdes ─
            (&["--connections-per-minute", "0"], "ne sert personne"),
            (
                &["--commands-per-minute", "0"],
                "ne peut même pas dire `QUIT`",
            ),
            (&["--tracked-sources", "0"], "ne retient rien"),
            (&["--ipv4-prefix-bits", "0"], "le même seau"),
            (&["--ipv6-prefix-bits", "0"], "le même seau"),
            (&["--ipv4-prefix-bits", "33"], "dépasse 32 bits"),
            (&["--ipv6-prefix-bits", "129"], "dépasse 128 bits"),
            (&["--ban-seconds", "toujours"], "n'est pas un nombre"),
            (
                &["--invalid-frames-per-minute", "trop"],
                "n'est pas un nombre",
            ),
            (
                &["--refused-recipients-per-minute", "plein"],
                "n'est pas un nombre",
            ),
            (
                &["--connections-per-minute", "beaucoup"],
                "n'est pas un nombre",
            ),
            (&["--tracked-sources"], "attend une valeur"),
            // Les trois durées de la file : zéro n'y veut rien dire.
            (&["--queue-retry-seconds", "0"], "aussi vite que le disque"),
            (&["--queue-max-retry-seconds", "0"], "à rien"),
            (&["--queue-expire-seconds", "0"], "sans avoir essayé"),
            (&["--queue-spool"], "attend une valeur"),
            // Les anciens noms se refusent EN DISANT LE NOUVEAU.
            (&["--relay-spool", "/x"], "--queue-spool"),
            (&["--relay-expire-seconds", "1"], "--queue-expire-seconds"),
            (&["--mta-sts-anchors"], "attend une valeur"),
            (&["--mta-sts-cache"], "attend une valeur"),
            (&["--tlsrpt-dir"], "attend une valeur"),
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

    // ── TLSRPT (RFC 8460) ───────────────────────────────────────────────────

    /// **PAS DE DOSSIER, AUCUN RAPPORT ; PAS DE DRAPEAU, AUCUNE REMISE.**
    #[test]
    fn sans_dossier_aucun_rapport_tls() {
        let options = ecrire(&["--domain", "mail.example.com"]);
        assert!(options.tlsrpt_dir.is_none());
        assert!(!options.tlsrpt_send);
        let config = options.en_configuration();
        assert!(!config.tlsrpt.compose());
        assert!(!config.tlsrpt.envoie());
    }

    /// **DEUX CRANS, COMME LES RAPPORTS DMARC.**
    #[test]
    fn deposer_et_remettre_sont_deux_crans() {
        let depose = ecrire(&["--tlsrpt-dir", "/var/spool/ams/tlsrpt"]);
        let config = depose.en_configuration();
        assert!(config.tlsrpt.compose());
        assert!(!config.tlsrpt.envoie(), "déposé n'est pas remis");

        // **REMETTRE EXIGE LA FILE** : tout ce qui sort y passe.
        let remet = ecrire(&[
            "--tlsrpt-dir",
            "/var/spool/ams/tlsrpt",
            "--tlsrpt-send",
            "--queue-spool",
            "/var/spool/ams/file",
        ]);
        let config = remet.en_configuration();
        assert!(config.tlsrpt.compose() && config.tlsrpt.envoie());
        assert_eq!(config.tlsrpt.directory, "/var/spool/ams/tlsrpt");
        // Et le tout se relit à l'identique.
        let octets = ams_config::encode(&config).expect("encodable");
        assert_eq!(ams_config::decode(&octets).expect("relisible"), config);
    }

    /// **LE DRAPEAU SANS DOSSIER DE RAPPORTS NE REMET RIEN.**
    ///
    /// Il n'est pas refusé — le refuser interdirait de préparer une
    /// configuration —, mais il ne promet rien à personne : sans rapport
    /// composé, il n'y a rien à remettre. La FILE, elle, est exigée : le
    /// drapeau dit qu'on émettra, et tout ce qui sort passe par elle.
    #[test]
    fn le_drapeau_sans_dossier_de_rapports_ne_remet_rien() {
        let options = ecrire(&["--tlsrpt-send", "--queue-spool", "/var/spool/ams/file"]);
        assert!(options.tlsrpt_send);
        assert!(!options.en_configuration().tlsrpt.envoie());

        // Et sans file, il est refusé : c'est le contrôle qui compte.
        let erreur = parse(["--tlsrpt-send"].as_slice()).expect_err("refusé");
        assert!(
            erreur.message.contains("--queue-spool"),
            "« {} » ne dit pas ce qui manque",
            erreur.message
        );
    }

    /// **`--dmarc-send` AUSSI EXIGE LA FILE.** Un rapport n'est pas moins un
    /// message qu'un autre.
    #[test]
    fn remettre_des_rapports_dmarc_exige_la_file() {
        // DMARC ÉVALUÉ D'ABORD, sans quoi le refus porterait sur la file — et
        // l'on préparerait un dossier pour des rapports qui n'existeraient
        // jamais. Cet essai isole donc bien l'exigence de file.
        let erreur = parse(
            [
                "--dmarc-send",
                "--public-suffix-list",
                "/etc/ams/psl.dat",
                "--resolver",
                "127.0.0.1:53",
            ]
            .as_slice(),
        )
        .expect_err("refusé");
        assert!(
            erreur.message.contains("--queue-spool"),
            "« {} » ne dit pas ce qui manque",
            erreur.message
        );
        assert!(
            ecrire(&[
                "--dmarc-send",
                "--queue-spool",
                "/var/spool/ams/file",
                "--public-suffix-list",
                "/etc/ams/psl.dat",
                "--resolver",
                "127.0.0.1:53",
            ])
            .dmarc_send
        );
    }

    // ── LA QUARANTAINE DMARC ────────────────────────────────────────────────

    /// **SANS L'OPTION, RIEN NE CHANGE.**
    #[test]
    fn sans_dossier_la_quarantaine_n_existe_pas() {
        let config = ecrire(&["--domain", "mail.example.com"]).en_configuration();
        assert!(config.dmarc.quarantine_folder.is_empty());
        assert!(!config.dmarc.met_en_quarantaine(&config.spf));
    }

    #[test]
    fn un_dossier_de_quarantaine_traverse_jusqu_a_la_configuration() {
        let config = ecrire(&[
            "--public-suffix-list",
            "/etc/ams/psl.dat",
            "--resolver",
            "127.0.0.1:53",
            "--dmarc-quarantine-folder",
            "Junk",
        ])
        .en_configuration();
        assert_eq!(config.dmarc.quarantine_folder, "Junk");
        assert!(config.dmarc.met_en_quarantaine(&config.spf));
        // ET SANS `--dmarc enforce` : la quarantaine remet, elle ne refuse pas.
        assert_eq!(config.dmarc.enforcement, ams_config::Enforcement::Observe);
    }

    /// **UN DOSSIER SANS ÉVALUATION NE VERRAIT JAMAIS RIEN**, et le silence
    /// serait pris pour une protection.
    #[test]
    fn un_dossier_de_quarantaine_sans_liste_est_refuse() {
        let erreur = parse(["--dmarc-quarantine-folder", "Junk"].as_slice()).expect_err("refusé");
        // LES DEUX MOITIÉS MANQUENT ICI, et le message les nomme toutes les
        // deux : n'en dire qu'une ferait revenir l'administrateur deux fois.
        assert!(
            erreur.message.contains("--public-suffix-list")
                && erreur.message.contains("--resolver"),
            "« {} » ne dit pas ce qui manque",
            erreur.message
        );
    }

    /// **UNE LISTE SANS RÉSOLVEUR N'ÉVALUE RIEN**, et c'est la moitié de la
    /// règle que ce contrôle ignorait.
    ///
    /// Le serveur n'évalue DMARC que s'il a les DEUX : la liste dit si deux
    /// domaines s'alignent, le résolveur va chercher la politique. Sans l'un des
    /// deux, tout ce qu'on règle par ailleurs ne s'applique à aucun message.
    ///
    /// **LES CINQ OPTIONS SONT REFUSÉES, ET NON LA SEULE QUARANTAINE.** C'est
    /// tout l'objet de la correction : le contrôle précédent ne visait qu'elle,
    /// pendant que `--dmarc enforce` promettait un refus qui n'avait pas lieu.
    #[test]
    fn tout_ce_qui_demande_dmarc_exige_liste_et_resolveur() {
        for option in [
            ["--dmarc", "enforce"].as_slice(),
            &["--dmarc-quarantine-folder", "Junk"],
            &["--dmarc-report-dir", "/var/spool/ams/rapports"],
            &["--dmarc-send", "--queue-spool", "/var/spool/ams/file"],
            &["--dmarc-failure-reports"],
        ] {
            // SANS RIEN : les deux moitiés manquent, et se nomment.
            let erreur = parse(option).expect_err("refusé");
            assert!(
                erreur.message.contains("--public-suffix-list")
                    && erreur.message.contains("--resolver"),
                "« {} » ne dit pas les deux",
                erreur.message
            );
            // AVEC LA SEULE LISTE : il ne manque plus que le résolveur, et le
            // message ne réclame que lui — dire les deux enverrait chercher ce
            // qui est déjà là.
            let avec_liste: Vec<&str> = [option, &["--public-suffix-list", "/etc/ams/psl.dat"]]
                .concat()
                .to_vec();
            let erreur = parse(avec_liste.as_slice()).expect_err("refusé");
            assert!(
                erreur.message.contains("--resolver")
                    && !erreur.message.contains("--public-suffix-list"),
                "« {} » réclame autre chose que le résolveur",
                erreur.message
            );
            // AVEC LE SEUL RÉSOLVEUR : symétriquement.
            let avec_resolveur: Vec<&str> =
                [option, &["--resolver", "127.0.0.1:53"]].concat().to_vec();
            let erreur = parse(avec_resolveur.as_slice()).expect_err("refusé");
            assert!(
                erreur.message.contains("--public-suffix-list")
                    && !erreur.message.contains("--resolver`"),
                "« {} » réclame autre chose que la liste",
                erreur.message
            );
            // AVEC LES DEUX : plus rien à redire.
            let complet: Vec<&str> = [
                option,
                &[
                    "--public-suffix-list",
                    "/etc/ams/psl.dat",
                    "--resolver",
                    "127.0.0.1:53",
                ],
            ]
            .concat()
            .to_vec();
            parse(complet.as_slice()).expect("recevable");
        }
    }

    /// **UNE LISTE SEULE N'EST PAS REFUSÉE**, et c'est délibéré.
    ///
    /// Elle ne promet rien à personne, et permet de la préparer avant — la même
    /// raison qui fait accepter un dossier de file sans rien qui émette. C'est
    /// `config show` qui dit alors que DMARC n'est pas évalué.
    #[test]
    fn une_liste_de_suffixes_seule_se_prepare_sans_etre_refusee() {
        let options = ecrire(&["--public-suffix-list", "/etc/ams/psl.dat"]);
        assert_eq!(
            options.public_suffix_list.as_deref(),
            Some(std::path::Path::new("/etc/ams/psl.dat"))
        );
        let config = options.en_configuration();
        assert!(!config.dmarc.est_configure(&config.spf));
    }

    /// **LE REFUS D'ÉVALUATION PASSE AVANT CELUI DE LA FILE.**
    ///
    /// `--dmarc-send` sans rien d'autre manque des deux : d'une évaluation et
    /// d'une file. Réclamer la file d'abord enverrait préparer un dossier pour
    /// des rapports qui n'existeraient jamais.
    #[test]
    fn ce_qui_ne_s_applique_a_rien_se_dit_avant_ce_qui_manque_pour_le_poser() {
        let erreur = parse(["--dmarc-send"].as_slice()).expect_err("refusé");
        assert!(
            erreur.message.contains("--public-suffix-list"),
            "« {} » parle d'autre chose",
            erreur.message
        );
        assert!(
            !erreur.message.contains("--queue-spool"),
            "« {} » réclame la file trop tôt",
            erreur.message
        );
    }

    /// **TOUTE OPTION QUI ATTEND UNE VALEUR LE DIT QUAND ELLE MANQUE.**
    ///
    /// Une option en fin de ligne dont la valeur manque est la faute de frappe la
    /// plus ordinaire — un `\` oublié, un argument coupé par le shell. Ce qu'il
    /// ne faut surtout pas, c'est qu'elle passe : une option muette laisserait
    /// écrire une configuration qui ne dit pas ce qui a été demandé.
    ///
    /// **CE TABLEAU N'A PAS BESOIN D'ÊTRE TENU À JOUR À LA MAIN**, et c'est ce
    /// qui le rend fiable : chaque `valeur()?` porte sa propre région de code, et
    /// C2 exige qu'elles soient toutes atteintes. Une option ajoutée sans être
    /// inscrite ici laisse sa région découverte, et le gate tombe. La liste ne
    /// peut donc pas dériver en silence.
    #[test]
    fn les_quarante_et_une_options_a_valeur_refusent_de_se_taire() {
        const A_VALEUR: [&str; 41] = [
            "--listen",
            "--maildir",
            "--domain",
            "--hosted",
            "--max-message",
            "--tls-cert",
            "--tls-key",
            "--dkim-selector",
            "--dkim-key",
            "--accounts",
            "--resolver",
            "--spf",
            "--spf-timeout-ms",
            "--dmarc",
            "--dmarc-report-dir",
            "--dmarc-org-name",
            "--dmarc-report-email",
            "--dmarc-report-interval",
            "--dmarc-quarantine-folder",
            "--public-suffix-list",
            "--listen-pop3",
            "--listen-imap",
            "--max-connections",
            "--tlsrpt-dir",
            "--mta-sts-anchors",
            "--mta-sts-cache",
            "--queue-spool",
            "--queue-retry-seconds",
            "--queue-max-retry-seconds",
            "--queue-expire-seconds",
            "--queue-warn-seconds",
            "--connections-per-minute",
            "--commands-per-minute",
            "--invalid-frames-per-minute",
            "--refused-recipients-per-minute",
            "--ban-seconds",
            "--ipv4-prefix-bits",
            "--ipv6-prefix-bits",
            "--tracked-sources",
            "--listen-http",
            "--listen-h3",
        ];
        for option in A_VALEUR {
            let erreur = parse([option].as_slice()).expect_err("refusé");
            assert!(
                erreur.message.contains("attend une valeur"),
                "`{option}` se tait : {}",
                erreur.message
            );
        }
    }

    /// **CE QUI N'EST PAS UN NOMBRE, UNE ADRESSE OU UNE LONGUEUR SE REFUSE.**
    ///
    /// Chaque conversion porte son propre message, et chacun nomme ce qu'il
    /// attendait : « n'est pas une adresse » n'envoie pas chercher au même
    /// endroit que « n'est pas un nombre ».
    #[test]
    fn chaque_conversion_dit_ce_qu_elle_attendait() {
        for (arguments, extrait) in [
            (
                ["--resolver", "pas-une-adresse"].as_slice(),
                "n'est pas une adresse",
            ),
            (&["--ban-seconds", "longtemps"], "n'est pas un nombre"),
            (&["--ipv4-prefix-bits", "beaucoup"], "n'est pas un nombre"),
            // LE RABOTAGE EN SILENCE EST CE QU'ON REFUSE : un `/48` tapé pour de
            // l'IPv4 compterait comme un `/32`, et la configuration dirait autre
            // chose que ce qui a été demandé.
            (&["--ipv4-prefix-bits", "48"], "dépasse 32 bits"),
            (&["--ipv6-prefix-bits", "129"], "dépasse 128 bits"),
            (&["--ipv6-prefix-bits", "0"], "`0` est refusé"),
        ] {
            let erreur = parse(arguments).expect_err("refusé");
            assert!(
                erreur.message.contains(extrait),
                "« {} » n'attendait pas cela",
                erreur.message
            );
        }
        // Et les longueurs recevables traversent, aux deux bornes.
        assert_eq!(
            ecrire(&["--ipv4-prefix-bits", "32"]).guard.ipv4_prefix_bits,
            32
        );
        assert_eq!(
            ecrire(&["--ipv6-prefix-bits", "128"])
                .guard
                .ipv6_prefix_bits,
            128
        );
    }

    /// **CE QU'ON MET DANS UN RAPPORT SE RÈGLE**, et les deux valeurs vides ont
    /// chacune leur substitut : le nom annoncé du serveur, et `postmaster@`.
    #[test]
    fn le_nom_et_l_adresse_des_rapports_traversent() {
        let config = ecrire(&[
            "--domain",
            "mail.example.com",
            "--dmarc-org-name",
            "Example",
            "--dmarc-report-email",
            "dmarc@example.com",
        ])
        .en_configuration();
        assert_eq!(config.dmarc.report_org_name, "Example");
        assert_eq!(config.dmarc.report_email, "dmarc@example.com");
        // SANS EUX, LA CONFIGURATION PORTE DU VIDE, et c'est le serveur qui
        // substitue — l'inventer ici ferait un fichier qui dit autre chose que
        // ce qui a été demandé.
        let sans = ecrire(&["--domain", "mail.example.com"]).en_configuration();
        assert!(sans.dmarc.report_org_name.is_empty());
        assert!(sans.dmarc.report_email.is_empty());
    }

    /// **`observe` RETIENT SANS RIEN OPPOSER**, et c'est le défaut de DMARC.
    #[test]
    fn dmarc_observe_se_demande_comme_enforce() {
        let options = ecrire(&[
            "--dmarc",
            "observe",
            "--public-suffix-list",
            "/etc/ams/psl.dat",
            "--resolver",
            "127.0.0.1:53",
        ]);
        assert!(!options.dmarc_enforce);
    }

    // ── LES NOMBRES DONT ZÉRO NE VEUT RIEN DIRE ─────────────────────────────

    /// **TROIS ZÉROS QUE RIEN N'ARRÊTAIT.**
    ///
    /// La règle est écrite dans ce fichier, au-dessus des seuils du garde : « on
    /// refuse les zéros qui ne veulent rien dire, et on documente ceux qui en
    /// veulent un ». Elle était tenue dans le bloc du garde et dans celui de la
    /// file, et n'avait jamais été portée aux trois nombres qui vivent ailleurs.
    ///
    /// Chacun des trois éteint le serveur d'une façon différente, et aucun ne le
    /// dit : un plafond nul refuse tout message, un compte de connexions nul n'en
    /// sert aucune, un délai nul ajourne chaque message sous `--spf enforce`.
    #[test]
    fn les_zeros_qui_eteignent_le_serveur_sont_refuses() {
        for (option, attendu) in [
            ("--max-message", "SIZE 0"),
            ("--max-connections", "ne sert personne"),
            ("--spf-timeout-ms", "avant qu'elle parte"),
        ] {
            let erreur = parse([option, "0"].as_slice()).expect_err("refusé");
            assert!(
                erreur.message.contains("`0` est refusé") && erreur.message.contains(attendu),
                "« {} » ne dit pas ce que zéro casserait",
                erreur.message
            );
            // ET CE QUI N'EST PAS UN NOMBRE RESTE REFUSÉ COMME AVANT : rendre
            // `pas_zero` générique ne devait pas perdre ce refus-là.
            let erreur = parse([option, "beaucoup"].as_slice()).expect_err("refusé");
            assert!(
                erreur.message.contains("n'est pas un nombre"),
                "« {} »",
                erreur.message
            );
        }
        // Et une valeur non nulle traverse, pour les trois.
        let options = ecrire(&[
            "--max-message",
            "1000",
            "--max-connections",
            "4",
            "--spf-timeout-ms",
            "250",
        ]);
        assert_eq!(options.max_message_octets, 1000);
        assert_eq!(options.max_connections, 4);
        assert_eq!(options.spf_timeout_millis, 250);
    }

    /// **UN SEUIL D'AVERTISSEMENT NUL PRÉVIENDRAIT POUR TOUT.**
    #[test]
    fn un_seuil_d_avertissement_nul_est_refuse() {
        let erreur = parse(["--queue-warn-seconds", "0"].as_slice()).expect_err("refusé");
        assert!(
            erreur.message.contains("dès le premier essai"),
            "{}",
            erreur.message
        );
        assert_eq!(ecrire(&["--queue-warn-seconds", "7200"]).queue_warn, 7_200);
    }

    // ── CE QU'ON FAIT D'UN VERDICT ──────────────────────────────────────────

    /// **`observe` ET `enforce` NE SE DEVINENT PAS**, et tout autre mot se
    /// refuse plutôt que de retomber en silence sur l'un des deux.
    #[test]
    fn spf_et_dmarc_n_acceptent_que_deux_mots() {
        for option in ["--spf", "--dmarc"] {
            let erreur = parse([option, "peut-etre"].as_slice()).expect_err("refusé");
            assert!(
                erreur.message.contains("n'est ni `observe` ni `enforce`"),
                "« {} »",
                erreur.message
            );
        }
        assert!(!ecrire(&["--spf", "observe"]).spf_enforce);
        assert!(ecrire(&["--spf", "enforce"]).spf_enforce);
    }

    /// **CE QUI EST DEMANDÉ SE RETROUVE DANS LE FICHIER**, et pas seulement dans
    /// les options : c'est la conversion qui décide de ce que le serveur lira.
    #[test]
    fn appliquer_traverse_jusqu_a_la_configuration() {
        let config = ecrire(&[
            "--spf",
            "enforce",
            "--dmarc",
            "enforce",
            "--public-suffix-list",
            "/etc/ams/psl.dat",
            "--resolver",
            "127.0.0.1:53",
        ])
        .en_configuration();
        assert_eq!(config.spf.enforcement, ams_config::Enforcement::Enforce);
        assert_eq!(config.dmarc.enforcement, ams_config::Enforcement::Enforce);
        // Et le défaut RETIENT, sans rien opposer : appliquer se demande.
        let defaut = ecrire(&["--domain", "mail.example.com"]).en_configuration();
        assert_eq!(defaut.spf.enforcement, ams_config::Enforcement::Observe);
        assert_eq!(defaut.dmarc.enforcement, ams_config::Enforcement::Observe);
    }

    /// **ZÉRO EST LICITE POUR L'INTERVALLE, ET VAUT UN JOUR** — c'est ce que la
    /// configuration substitue, et ce qui rend le champ ajoutable sans rien
    /// casser.
    #[test]
    fn l_intervalle_des_rapports_se_regle_et_zero_y_est_licite() {
        assert_eq!(
            ecrire(&["--dmarc-report-interval", "3600"]).dmarc_report_interval,
            3_600
        );
        assert_eq!(
            ecrire(&["--dmarc-report-interval", "0"]).dmarc_report_interval,
            0
        );
        let erreur = parse(["--dmarc-report-interval", "souvent"].as_slice()).expect_err("refusé");
        assert!(
            erreur.message.contains("n'est pas un nombre"),
            "{}",
            erreur.message
        );
    }

    // ── DKIM ────────────────────────────────────────────────────────────────

    /// **L'UN SANS L'AUTRE NE VEUT DIRE NI « SIGNE » NI « NE SIGNE PAS ».**
    ///
    /// Un sélecteur sans clé ne peut rien signer ; une clé sans sélecteur ne
    /// saurait pas sous quel nom publier. Les deux se refusent, et le refus dit
    /// lequel manque en les nommant tous les deux.
    #[test]
    fn un_selecteur_dkim_sans_cle_est_refuse_et_reciproquement() {
        for moitie in [
            ["--dkim-selector", "s1"].as_slice(),
            &["--dkim-key", "/etc/ams/dkim.pem"],
        ] {
            let erreur = parse(moitie).expect_err("refusé");
            assert!(
                erreur.message.contains("vont ENSEMBLE"),
                "« {} »",
                erreur.message
            );
        }
        let config = ecrire(&["--dkim-selector", "s1", "--dkim-key", "/etc/ams/dkim.pem"])
            .en_configuration();
        assert!(config.dkim.est_configure());
    }

    // ── L'API REST ──────────────────────────────────────────────────────────

    /// **ELLE NE S'OUVRE PAS EN CLAIR**, et le refus le dit en toutes lettres.
    ///
    /// C'est le refus le plus important de cette crate : l'API porte des jetons
    /// PORTEURS, et qui lit un jeton devient administrateur. Le serveur ferme
    /// déjà ce port sans certificat ; le dire au terminal évite de découvrir au
    /// démarrage qu'on n'a pas ouvert ce qu'on croyait ouvrir.
    #[test]
    fn l_api_ne_s_ouvre_pas_sans_certificat() {
        let erreur = parse(["--listen-http", "127.0.0.1:8443"].as_slice()).expect_err("refusé");
        assert!(
            erreur.message.contains("jeton volé"),
            "« {} » ne dit pas ce qu'on risque",
            erreur.message
        );

        // **LA MOITIÉ D'UN CERTIFICAT N'ARRIVE JAMAIS JUSQU'ICI**, et c'est une
        // bonne nouvelle : la règle qui veut `--tls-cert` et `--tls-key`
        // ENSEMBLE se déclenche d'abord. Ce refus-ci n'a donc à connaître qu'un
        // seul cas — le certificat entièrement absent —, et l'on ne peut pas
        // atteindre l'API avec un chiffrement à moitié réglé.
        for moitie in [
            ["--listen-http", "127.0.0.1:8443", "--tls-cert", "/c.pem"].as_slice(),
            &["--listen-http", "127.0.0.1:8443", "--tls-key", "/k.pem"],
        ] {
            let erreur = parse(moitie).expect_err("refusé");
            assert!(
                erreur.message.contains("vont ENSEMBLE"),
                "« {} » : ce n'est plus la règle du certificat qui tranche",
                erreur.message
            );
        }
        let config = ecrire(&[
            "--listen-http",
            "127.0.0.1:8443",
            "--tls-cert",
            "/c.pem",
            "--tls-key",
            "/k.pem",
        ])
        .en_configuration();
        assert_eq!(config.listen_http, "127.0.0.1:8443");
    }

    /// **UN PORT HTTP/3 SANS HTTP/2 EST UN PORT QUE PERSONNE NE CHERCHE.**
    ///
    /// `Alt-Svc` est le seul moyen par lequel un client découvre un port HTTP/3
    /// (RFC 7838, §3.1 de RFC 9114), et il s'annonce depuis les réponses
    /// HTTP/2. L'ouvrir seul serait la même faute qu'annoncer une alternative
    /// absente, dans l'autre sens.
    #[test]
    fn http3_seul_serait_introuvable() {
        let erreur = parse(
            [
                "--listen-h3",
                "127.0.0.1:8443",
                "--tls-cert",
                "/c.pem",
                "--tls-key",
                "/k.pem",
            ]
            .as_slice(),
        )
        .expect_err("refusé");
        assert!(erreur.message.contains("Alt-Svc"), "{}", erreur.message);

        let config = ecrire(&[
            "--listen-http",
            "127.0.0.1:8443",
            "--listen-h3",
            "127.0.0.1:8443",
            "--tls-cert",
            "/c.pem",
            "--tls-key",
            "/k.pem",
        ])
        .en_configuration();
        assert_eq!(config.listen_h3, "127.0.0.1:8443");
    }

    /// **UNE ROTATION QUI NE RÉVOQUE RIEN NE SE DEMANDE PAS.**
    #[test]
    fn renouveler_un_secret_que_rien_n_emploie_est_refuse() {
        let erreur = parse(["--rotate-token-key"].as_slice()).expect_err("refusé");
        assert!(
            erreur.message.contains("ne révoquerait rien"),
            "{}",
            erreur.message
        );
        assert!(
            ecrire(&[
                "--listen-http",
                "127.0.0.1:8443",
                "--tls-cert",
                "/c.pem",
                "--tls-key",
                "/k.pem",
                "--rotate-token-key",
            ])
            .rotate_token_key
        );
    }

    /// **LE SECRET NE VIENT PAS DES OPTIONS**, et cette structure ne peut pas
    /// l'inventer : le tirer demanderait `/dev/urandom`, le reprendre
    /// demanderait de lire le fichier, et C1 interdit les deux ici. C'est
    /// `air-mail-admin` qui le pose, juste après.
    #[test]
    fn la_configuration_sort_d_ici_sans_secret_de_scellement() {
        let config = ecrire(&[
            "--listen-http",
            "127.0.0.1:8443",
            "--tls-cert",
            "/c.pem",
            "--tls-key",
            "/k.pem",
        ])
        .en_configuration();
        assert!(config.token_key.is_empty());
    }

    /// **SANS OPTION, PAS D'API** : l'absence de valeur est l'absence de
    /// service, comme partout ailleurs ici.
    #[test]
    fn sans_adresse_l_api_n_est_pas_servie() {
        let config = ecrire(&["--domain", "mail.example.com"]).en_configuration();
        assert!(config.listen_http.is_empty());
        assert!(config.listen_h3.is_empty());
    }

    /// **LA RÈGLE EST CELLE D'IMAP, PARCE QUE LE DOSSIER EN EST UN.**
    ///
    /// Un nom que l'administration accepterait et que `LIST` refuserait de
    /// montrer serait un dossier que personne ne pourrait ouvrir.
    #[test]
    fn un_nom_de_dossier_irrecevable_est_refuse() {
        for mauvais in ["", "..", "/", "a.b", "Junk:1", " Junk", "Junk\\x"] {
            let erreur = parse(
                [
                    "--public-suffix-list",
                    "/etc/ams/psl.dat",
                    "--dmarc-quarantine-folder",
                    mauvais,
                ]
                .as_slice(),
            )
            .expect_err("refusé");
            assert!(
                erreur.message.contains("n'est pas un nom de boîte"),
                "« {mauvais} » passe : {}",
                erreur.message
            );
        }
        // Le `/` final est celui qu'IMAP tolère : on l'ôte plutôt que d'en faire
        // un répertoire dont le nom se termine par un point.
        assert_eq!(
            ecrire(&[
                "--public-suffix-list",
                "/etc/ams/psl.dat",
                "--resolver",
                "127.0.0.1:53",
                "--dmarc-quarantine-folder",
                "Junk/",
            ])
            .en_configuration()
            .dmarc
            .quarantine_folder,
            "Junk"
        );
        // Une hiérarchie, elle, est un nom de boîte recevable.
        let config = ecrire(&[
            "--public-suffix-list",
            "/etc/ams/psl.dat",
            "--resolver",
            "127.0.0.1:53",
            "--dmarc-quarantine-folder",
            "Courrier/Junk",
        ])
        .en_configuration();
        assert_eq!(config.dmarc.quarantine_folder, "Courrier/Junk");
    }

    // ── MTA-STS (RFC 8461) ──────────────────────────────────────────────────

    /// **PAS DE DRAPEAU : L'ABSENCE DE VALEUR EST L'ABSENCE DE SERVICE.**
    #[test]
    fn sans_autorites_mtasts_n_est_pas_evalue() {
        let options = ecrire(&["--domain", "mail.example.com"]);
        assert!(options.mtasts_anchors.is_none());
        assert!(!options.en_configuration().mtasts.est_configure());
    }

    /// Les deux chemins traversent jusqu'au fichier.
    #[test]
    fn les_deux_chemins_mtasts_traversent_jusqu_au_fichier() {
        let options = ecrire(&[
            "--domain",
            "mail.example.com",
            "--mta-sts-anchors",
            "/etc/ssl/certs/ca-certificates.crt",
            "--mta-sts-cache",
            "/var/cache/ams/mtasts",
        ]);
        let config = options.en_configuration();
        assert!(config.mtasts.est_configure());
        assert_eq!(config.mtasts.anchors, "/etc/ssl/certs/ca-certificates.crt");
        assert_eq!(config.mtasts.cache, "/var/cache/ams/mtasts");
        // Et le tout se relit à l'identique.
        let octets = ams_config::encode(&config).expect("encodable");
        assert_eq!(ams_config::decode(&octets).expect("relisible"), config);
    }

    /// **LES DEUX VONT ENSEMBLE, OU AUCUNE.**
    ///
    /// Sans autorités, on ne saurait pas à qui l'on parle en allant chercher la
    /// politique ; sans cache, un redémarrage rouvrirait la fenêtre de
    /// déclassement que §5 de RFC 8461 ferme.
    #[test]
    fn l_une_sans_l_autre_est_refusee() {
        for arguments in [
            ["--mta-sts-anchors", "/etc/ssl/certs/ca.crt"].as_slice(),
            &["--mta-sts-cache", "/var/cache/ams/mtasts"],
        ] {
            let erreur = parse(arguments).expect_err("refusé");
            assert!(
                erreur.message.contains("ENSEMBLE"),
                "« {} » ne dit pas qu'elles vont ensemble",
                erreur.message
            );
        }
    }

    // ── La file de réémission sortante ──────────────────────────────────────

    /// **ÉTEINTE PAR DÉFAUT, ET LES DURÉES AU DÉFAUT DE `ams-queue`.**
    #[test]
    fn sans_option_rien_ne_sort() {
        let options = ecrire(&["--domain", "mail.example.com"]);
        assert!(!options.relay);
        assert!(options.queue_spool.is_none());
        let config = options.en_configuration();
        assert!(!config.relay.enabled);
        assert_eq!(config.queue.backoff(), ams_queue::Backoff::DEFAULT);
    }

    /// Les cinq réglages traversent jusqu'au fichier.
    #[test]
    fn les_reglages_de_la_file_traversent_jusqu_au_fichier() {
        let options = ecrire(&[
            "--domain",
            "mail.example.com",
            "--relay",
            "--queue-spool",
            "/var/spool/ams/file",
            "--queue-retry-seconds",
            "60",
            "--queue-max-retry-seconds",
            "3600",
            "--queue-expire-seconds",
            "172800",
        ]);
        assert!(options.relay);
        let config = options.en_configuration();
        assert!(config.relay.enabled);
        assert_eq!(config.queue.spool, "/var/spool/ams/file");
        let reprise = config.queue.backoff();
        assert_eq!(reprise.first, Duration::from_secs(60));
        assert_eq!(reprise.ceiling, Duration::from_secs(3_600));
        assert_eq!(reprise.expiry, Duration::from_secs(172_800));
        // AUCUNE N'EST LE DÉFAUT : un test qui passerait avec `DEFAULT` ne
        // prouverait rien de la traversée.
        assert_ne!(reprise, ams_queue::Backoff::DEFAULT);
        // Et le tout se relit à l'identique.
        let octets = ams_config::encode(&config).expect("encodable");
        assert_eq!(ams_config::decode(&octets).expect("relisible"), config);
    }

    /// **UN RELAIS SANS DOSSIER PERDRAIT LE COURRIER EN SILENCE.**
    ///
    /// On aurait dit `250` à un message qu'on n'a nulle part où poser. Le refus
    /// est devant le terminal, pas au démarrage.
    #[test]
    fn un_relais_sans_dossier_est_refuse() {
        let erreur = parse(["--relay"].as_slice()).expect_err("refusé");
        assert!(
            erreur.message.contains("--queue-spool"),
            "« {} » ne dit pas ce qui manque",
            erreur.message
        );
    }

    /// **L'INVERSE N'EST PAS REFUSÉ**, et c'est délibéré : nommer un dossier
    /// sans rien émettre ne promet rien à personne, et permet de le préparer
    /// avant. Le serveur le dit au démarrage.
    #[test]
    fn un_dossier_sans_emission_est_licite() {
        let options = ecrire(&["--queue-spool", "/var/spool/ams/file"]);
        assert!(!options.relay);
        assert!(!options.en_configuration().relay.enabled);
        assert_eq!(
            options.en_configuration().queue.spool,
            "/var/spool/ams/file"
        );
    }

    // ── Les seuils du garde (C8) ────────────────────────────────────────────

    /// **C8 EXIGE QUE RIEN NE SOIT UNE CONSTANTE**, et c'est ce test qui rend
    /// l'exigence vérifiable : chacun des huit réglages doit traverser la ligne
    /// de commande, la structure, l'encodage, et se relire à l'identique. Tant
    /// que `config write` posait `Thresholds::DEFAULT`, la contrainte était
    /// vraie dans le format et fausse en pratique.
    #[test]
    fn les_huit_seuils_du_garde_traversent_jusqu_au_fichier() {
        let options = ecrire(&[
            "--domain",
            "mail.example.com",
            "--connections-per-minute",
            "7",
            "--commands-per-minute",
            "70",
            "--invalid-frames-per-minute",
            "3",
            "--refused-recipients-per-minute",
            "11",
            "--ban-seconds",
            "1800",
            "--ipv4-prefix-bits",
            "24",
            "--ipv6-prefix-bits",
            "48",
            "--tracked-sources",
            "512",
        ]);
        let attendus = Thresholds {
            connections_per_minute: 7,
            commands_per_minute: 70,
            invalid_frames_per_minute: 3,
            refused_recipients_per_minute: 11,
            ban_duration: Duration::from_secs(1800),
            ipv4_prefix_bits: 24,
            ipv6_prefix_bits: 48,
        };
        assert_eq!(options.guard, attendus);
        assert_eq!(options.tracked_sources, 512);
        // AUCUN N'EST LE DÉFAUT : un test qui passerait avec `DEFAULT` ne
        // prouverait rien de la traversée.
        assert_ne!(attendus, Thresholds::DEFAULT);

        let config = options.en_configuration();
        assert_eq!(config.guard, attendus);
        assert_eq!(config.tracked_sources, 512);
        let octets = ams_config::encode(&config).expect("encodable");
        let relue = ams_config::decode(&octets).expect("relisible");
        assert_eq!(relue.guard, attendus);
        assert_eq!(relue.tracked_sources, 512);
    }

    /// **ZÉRO NE VEUT PAS DIRE LA MÊME CHOSE PARTOUT**, et c'est le seul endroit
    /// du projet où deux options voisines lui donnent des sens opposés. Pour la
    /// récolte d'adresses il ÉTEINT le comptage — sans quoi ce seuil n'aurait
    /// pas pu s'ajouter sans bannir tout le monde chez ceux qui ne réécrivent
    /// pas leur fichier. Pour les trames invalides il bannit au PREMIER écart.
    /// Pour la peine, il dit « ajourne au lieu de bannir ». Les trois sont
    /// licites, et il fallait un test pour que l'un ne devienne pas l'autre.
    #[test]
    fn les_trois_zeros_licites_le_restent() {
        let options = ecrire(&[
            "--refused-recipients-per-minute",
            "0",
            "--invalid-frames-per-minute",
            "0",
            "--ban-seconds",
            "0",
        ]);
        assert_eq!(options.guard.refused_recipients_per_minute, 0);
        assert_eq!(options.guard.invalid_frames_per_minute, 0);
        assert_eq!(options.guard.ban_duration, Duration::ZERO);
        // Et ils traversent le format : un zéro que l'encodage remplacerait par
        // un défaut rallumerait en silence un compteur qu'on a éteint exprès.
        let config = options.en_configuration();
        let octets = ams_config::encode(&config).expect("encodable");
        let relue = ams_config::decode(&octets).expect("relisible");
        assert_eq!(relue.guard.refused_recipients_per_minute, 0);
        assert_eq!(relue.guard.invalid_frames_per_minute, 0);
        assert_eq!(relue.guard.ban_duration, Duration::ZERO);
    }

    /// Les bornes des préfixes sont ACCEPTÉES à leur maximum.
    ///
    /// `ams-guard` rabote ce qui dépasse, ce qu'une bibliothèque doit faire
    /// d'une entrée qu'elle ne choisit pas ; l'outil, lui, refuse plutôt que de
    /// raboter. Il ne fallait pas que ce refus morde la valeur maximale
    /// elle-même — un `/32` en IPv4 est le DÉFAUT.
    #[test]
    fn le_maximum_d_un_prefixe_est_recevable() {
        let options = ecrire(&["--ipv4-prefix-bits", "32", "--ipv6-prefix-bits", "128"]);
        assert_eq!(options.guard.ipv4_prefix_bits, 32);
        assert_eq!(options.guard.ipv6_prefix_bits, 128);
        // Et un seul bit aussi : c'est absurde, mais c'est une décision, pas une
        // faute de frappe qui ne veut rien dire.
        let étroit = ecrire(&["--ipv4-prefix-bits", "1", "--ipv6-prefix-bits", "1"]);
        assert_eq!(étroit.guard.ipv4_prefix_bits, 1);
        assert_eq!(étroit.guard.ipv6_prefix_bits, 1);
    }

    /// Sans une seule option de garde, les seuils sont ceux de `ams-guard`.
    ///
    /// **ILS NE SONT PAS RECOPIÉS ICI** : les recopier ferait deux vérités pour
    /// une seule décision, et la seconde vieillirait en silence.
    #[test]
    fn sans_option_de_garde_les_seuils_viennent_de_la_bibliotheque() {
        let options = ecrire(&["--domain", "mail.example.com"]);
        assert_eq!(options.guard, Thresholds::DEFAULT);
        assert_eq!(options.tracked_sources, 4096);
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
