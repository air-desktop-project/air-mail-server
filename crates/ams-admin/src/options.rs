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
    /// Les seuils du garde — le `x` et le `y` de C8, et le reste.
    ///
    /// **RIEN ICI N'EST UNE CONSTANTE**, dit C8 ; il fallait donc que l'outil
    /// qui écrit la configuration sache les écrire. Tant qu'il posait
    /// `Thresholds::DEFAULT`, la contrainte était vraie dans le format et
    /// fausse en pratique : personne ne pouvait desserrer un seuil qui se
    /// trompe, ni resserrer celui qui ne suffit plus.
    pub guard: Thresholds,
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
            // **L'API REST N'EST PAS SERVIE PAR DÉFAUT**, et ce n'est pas un
            // oubli : elle demande un certificat ET un secret de scellement, et
            // inventer l'un des deux ici donnerait un fichier qui promet ce
            // qu'on n'a pas demandé. `air-mail-admin` gagnera ses options quand
            // on saura ce qu'elles doivent dire.
            listen_http: String::new(),
            listen_h3: String::new(),
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
            },
            dkim: Dkim {
                selector: self.dkim_selector.clone().unwrap_or_default(),
                private_key_path: chemin(self.dkim_key.as_ref()),
            },
            accounts: chemin(self.accounts.as_ref()),
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

    `--dmarc-org-name` est le nom sous lequel ce receveur se présente (défaut :
    le nom annoncé), `--dmarc-report-email` l'adresse où le joindre (défaut :
    `postmaster@` suivi du nom annoncé), `--dmarc-report-interval` le nombre de
    secondes entre deux vidanges du journal (défaut : 86400, un jour).

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
                let brute = valeur()?;
                options.max_message_octets = brute
                    .parse()
                    .map_err(|_| ArgError::new(format!("`{brute}` n'est pas un nombre")))?;
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
            "--listen-imap" => {
                let brute = valeur()?;
                options.listen_imap = Some(
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
    if options.dkim_selector.is_some() != options.dkim_key.is_some() {
        return Err(ArgError::new(
            "`--dkim-selector` et `--dkim-key` vont ENSEMBLE : l'un sans l'autre ne veut dire ni \
             « signe » ni « ne signe pas »",
        ));
    }
    Ok(Demande::Ecrire(Box::new(options)))
}

/// Un nombre, ou ce qui n'en est pas un.
fn nombre(brute: &str) -> Result<u32, ArgError> {
    brute
        .parse()
        .map_err(|_| ArgError::new(format!("`{brute}` n'est pas un nombre")))
}

/// Un nombre dont zéro ne voudrait rien dire, et `pourquoi` le dit.
fn pas_zero(brute: &str, pourquoi: &str) -> Result<u32, ArgError> {
    match nombre(brute)? {
        // ON REFUSE ICI, PAS AU DÉMARRAGE DU SERVEUR : l'administrateur est
        // devant son terminal, et c'est le seul moment où le lui dire coûte une
        // seconde plutôt qu'une astreinte.
        0 => Err(ArgError::new(format!("`0` est refusé : {pourquoi}"))),
        combien => Ok(combien),
    }
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
    u8::try_from(bits).map_err(|_| ArgError::new(format!("`{bits}` n'est pas une longueur")))
}

/// Un chemin, ou la chaîne vide qui dit « rien ».
fn chemin(valeur: Option<&PathBuf>) -> String {
    valeur.map(|c| c.display().to_string()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{ArgError, Demande, Options, Thresholds, parse};
    use core::time::Duration;
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
        let erreur = parse(["--listen-imap", "pas-une-adresse"]).expect_err("refusé");
        assert!(
            erreur.message.contains("n'est pas une adresse"),
            "{}",
            erreur.message
        );
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
