//! Ce que le fichier de configuration porte, et comment il se lit.

use alloc::string::{String, ToString as _};
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use ams_guard::Thresholds;
use ams_proto_smtp::{ClientId, Limits};
use ams_queue::Backoff;
use capnp::message::ReaderOptions;
use capnp::serialize;

use crate::ams_config_capnp::configuration;

/// Le nombre de mots qu'un fichier de configuration peut faire parcourir.
///
/// Un fichier corrompu peut décrire des structures qui se référencent l'une
/// l'autre ; sans borne, le décodeur les suivrait indéfiniment. Huit mille mots
/// — soixante-quatre kilo-octets — laissent une marge considérable à une
/// configuration réelle, et ferment la boucle.
pub const TRAVERSAL_LIMIT_WORDS: u64 = 8_192;

/// Les délais, en secondes.
///
/// Ils vivent ici en nombres et non en `Duration` : cette crate ne connaît pas
/// la boucle, et c'est elle qui en fera des délais.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// Attente d'une ligne de commande.
    pub command_seconds: u32,
    /// Attente d'un morceau de message.
    pub data_seconds: u32,
    /// L'inactivité annoncée aux pairs QUIC, en secondes.
    ///
    /// **ZÉRO PREND LE DÉFAUT** — [`Timeouts::QUIC_IDLE_DEFAUT_SECONDES`] —, et
    /// c'est ce qui rend ce champ ajoutable sans rien casser : un fichier écrit
    /// avant lui décode zéro, et se comporte donc exactement comme avant.
    pub quic_idle_seconds: u32,
}

impl Timeouts {
    /// L'inactivité QUIC quand la configuration n'en nomme aucune.
    ///
    /// **TRENTE SECONDES.** Une connexion qu'on garde ouverte est de la mémoire
    /// qu'on prête, et §10.1 de RFC 9000 fait prendre le PLUS PETIT des deux
    /// délais annoncés : un pair coopératif peut raccourcir le sien, jamais
    /// l'allonger. Contre un attaquant, qui annonce ce qu'il veut, c'est notre
    /// valeur qui plafonne.
    pub const QUIC_IDLE_DEFAUT_SECONDES: u32 = 30;

    /// L'inactivité QUIC à appliquer, zéro valant le défaut.
    ///
    /// **LA SUBSTITUTION VIT ICI, ET NON CHEZ CHAQUE APPELANT** : la recopier
    /// ferait deux vérités pour une seule décision, et la seconde vieillirait en
    /// silence — c'est exactement la forme de défaut que ce dépôt a corrigée
    /// six fois.
    #[must_use]
    pub const fn quic_idle_secondes(&self) -> u32 {
        if self.quic_idle_seconds == 0 {
            Self::QUIC_IDLE_DEFAUT_SECONDES
        } else {
            self.quic_idle_seconds
        }
    }
}

/// DKIM : de quoi SIGNER ce que ce serveur émet.
///
/// # Signer se configure, vérifier ne se configure pas
///
/// La vérification a lieu sur tout ce qui arrive, parce que DMARC en dépend :
/// il n'y a rien à régler. Signer demande une clé qu'un administrateur a
/// publiée dans le DNS — c'est cela seul qui se configure.
///
/// # Il n'y a pas de drapeau, et c'est le même sujet qu'ailleurs
///
/// On signe **si et seulement si** le sélecteur et le chemin sont renseignés.
/// Un drapeau créerait un état où l'on croirait signer sans le faire.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dkim {
    /// `s=` — le sélecteur qui nomme la clé dans le DNS.
    pub selector: String,
    /// La clé privée, au format PEM.
    pub private_key_path: String,
}

impl Dkim {
    /// Ce service sait-il signer ?
    #[must_use]
    pub fn est_configure(&self) -> bool {
        !self.selector.is_empty() && !self.private_key_path.is_empty()
    }
}

/// De quoi chiffrer (C4, C14).
///
/// Deux **chemins**, et pas le matériel lui-même : une clé privée recopiée dans
/// le fichier de configuration hériterait des permissions de celui-ci, et le
/// renouvellement d'un certificat — qui remplace un fichier — obligerait à
/// réécrire la configuration entière.
///
/// # Il n'y a pas de drapeau, et c'est le sujet
///
/// Le chiffrement est offert **si et seulement si** les deux chemins sont
/// renseignés. Un drapeau `enabled` créerait deux états faux : « activé sans
/// certificat », qui ferait mentir la bannière, et « certificat sans
/// activation », qui donnerait le contraire à lire de ce qui se passe. Ici,
/// l'absence de chiffrement se lit à l'absence de chemins.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tls {
    /// La chaîne de certificats, au format PEM.
    pub certificate_chain_path: String,
    /// La clé privée, au format PEM.
    pub private_key_path: String,
}

impl Tls {
    /// Ce service sait-il chiffrer ?
    #[must_use]
    pub fn est_configure(&self) -> bool {
        !self.certificate_chain_path.is_empty() && !self.private_key_path.is_empty()
    }
}

/// Ce qu'on fait d'un verdict SPF (C9).
///
/// Le défaut est [`Enforcement::Observe`] : quand des résolveurs apparaissent
/// dans une configuration, la vérification commence par REGARDER. Une politique
/// mal écrite chez un partenaire refuserait du courrier légitime, et il vaut
/// mieux le découvrir dans un journal que dans un appel téléphonique.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Enforcement {
    /// On vérifie, on retient, on n'oppose rien.
    #[default]
    Observe,
    /// Un `fail` est refusé, une panne de résolution ajournée.
    Enforce,
}

/// SPF (C9) : à qui demander, et ce qu'on fait de la réponse.
///
/// # Il n'y a pas de drapeau, et c'est le même sujet que pour [`Tls`]
///
/// La vérification a lieu **si et seulement si** des résolveurs sont nommés. Un
/// drapeau créerait « activé sans résolveur », qui ajournerait tout le courrier,
/// et « résolveurs sans activation », qui donnerait à lire le contraire de ce
/// qui se passe.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Spf {
    /// Les résolveurs, sous la forme `adresse:port`.
    ///
    /// Cette crate ne les interprète pas, pour la raison qui vaut pour
    /// [`Configuration::listen`] : `core` ne sait pas lire une adresse de
    /// socket.
    pub resolvers: Vec<String>,
    /// Ce qu'on fait d'un `fail`.
    pub enforcement: Enforcement,
    /// Le temps accordé à UNE question, en millisecondes.
    pub timeout_millis: u32,
}

impl Spf {
    /// Ce service vérifie-t-il l'expéditeur ?
    #[must_use]
    pub fn est_configure(&self) -> bool {
        !self.resolvers.is_empty()
    }
}

/// DMARC (C9) : la liste des suffixes publics, et ce qu'on fait du verdict.
///
/// # Il n'y a pas de drapeau, et c'est le même sujet que pour [`Tls`] et [`Spf`]
///
/// DMARC est évalué **si et seulement si** une liste est nommée — et que des
/// résolveurs le sont aussi, puisqu'il faut aller chercher la politique.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dmarc {
    /// Le fichier de la liste des suffixes publics, ou une chaîne vide.
    ///
    /// # Pourquoi un fichier, et non une liste embarquée
    ///
    /// Elle pèse quelques centaines de kibioctets et change toutes les
    /// semaines : embarquée, elle vieillirait avec le binaire, et personne ne
    /// saurait de quand date la sienne. L'alignement relâché en dépend — s'y
    /// tromper fait aligner deux domaines étrangers, ce que DMARC existe
    /// précisément pour empêcher.
    pub public_suffix_list: String,
    /// Ce qu'on fait d'un message que la politique condamne.
    pub enforcement: Enforcement,
    /// Le dossier où déposer les rapports agrégés, ou une chaîne vide.
    ///
    /// **Vide, aucun rapport n'est composé.** Même règle que partout ailleurs
    /// ici : l'absence de valeur EST l'absence de service, et il n'y a pas de
    /// drapeau pour la contredire.
    pub report_directory: String,
    /// Le nom sous lequel ce receveur se présente dans ses rapports.
    ///
    /// Vide, le nom annoncé par le serveur en tient lieu.
    pub report_org_name: String,
    /// L'adresse à laquelle nous joindre à propos d'un rapport.
    ///
    /// Vide, `postmaster@` suivi du nom annoncé en tient lieu.
    pub report_email: String,
    /// Tous les combien vider le journal, en secondes. Zéro vaut un jour.
    pub report_interval_seconds: u32,
    /// Remet-on les rapports, ou se contente-t-on de les déposer ?
    ///
    /// **Émettre du courrier vers des tiers ne se décide pas à la place de celui
    /// qui exploite la machine.** Le défaut dépose et n'envoie rien.
    pub send_reports: bool,
    /// Compose-t-on des rapports d'échec (`ruf=`, RFC 6591) ?
    ///
    /// **Ils portent le courrier de quelqu'un.** Le défaut est faux.
    pub failure_reports: bool,
    /// Le dossier où déposer un message que `p=quarantine` vise, ou une chaîne
    /// vide.
    ///
    /// **Vide, la quarantaine n'existe pas** : le message va dans la boîte de
    /// réception, et le rapport dit `none`, parce que c'est la vérité.
    pub quarantine_folder: String,
}

impl Dmarc {
    /// Ce service évalue-t-il DMARC ?
    ///
    /// # Pourquoi [`Spf`] EST UN ARGUMENT, et non quelque chose qu'on suppose
    ///
    /// Évaluer DMARC demande d'aller chercher le `_dmarc` du domaine de l'en-tête
    /// `From:`, donc un résolveur — et les résolveurs vivent dans [`Spf`]. Cette
    /// structure ne peut PAS répondre seule à la question que porte son nom :
    /// elle n'a pas de quoi.
    ///
    /// Elle a pourtant essayé, et c'est ce qui a coûté. Le prédicat ne regardait
    /// que la liste des suffixes ; chaque appelant devait se rappeler d'ajouter
    /// `&& !resolveurs.is_empty()`. Le serveur y pensait à trois endroits et
    /// l'oubliait au quatrième, et l'outil d'administration n'y pensait nulle
    /// part : `config show` annonçait « DMARC APPLIQUÉ » sur la ligne qui suit
    /// « SPF AUCUN RÉSOLVEUR ».
    ///
    /// En faire un ARGUMENT rend l'oubli inexprimable : on ne peut plus poser la
    /// question sans avoir sous la main de quoi y répondre. C'est le même choix
    /// que `submitter` dans `accepts_recipient`, et pour la même raison — un
    /// champ, quelqu'un finit par oublier de le mettre à jour.
    #[must_use]
    pub fn est_configure(&self, spf: &Spf) -> bool {
        !self.public_suffix_list.is_empty() && spf.est_configure()
    }

    /// Ce service REMET-il les rapports qu'il compose ?
    ///
    /// Composer et remettre sont deux services distincts : le premier n'écrit
    /// que dans un dossier de la machine, le second parle à des tiers.
    #[must_use]
    pub fn envoie(&self, spf: &Spf) -> bool {
        self.rapporte(spf) && self.send_reports
    }

    /// Ce service compose-t-il des rapports d'ÉCHEC ?
    ///
    /// Ils demandent tout ce qu'un rapport agrégé demande, **et une décision de
    /// plus** : un rapport d'échec parle d'un message précis, arrivé chez
    /// quelqu'un.
    #[must_use]
    pub fn rapporte_les_echecs(&self, spf: &Spf) -> bool {
        self.rapporte(spf) && self.failure_reports
    }

    /// Ce service MET-IL DE CÔTÉ ce qu'une politique met en quarantaine ?
    ///
    /// **Cela ne dépend pas de [`Enforcement`]**, qui gouverne le refus d'un
    /// `p=reject` : la quarantaine remet le message, elle ne peut rien perdre,
    /// et il n'y a donc rien à découvrir avant de l'ouvrir.
    #[must_use]
    pub fn met_en_quarantaine(&self, spf: &Spf) -> bool {
        self.est_configure(spf) && !self.quarantine_folder.is_empty()
    }

    /// Ce service compose-t-il des rapports ?
    ///
    /// **Évaluer et rapporter sont deux services distincts.** Un serveur peut
    /// très bien opposer les politiques sans rien rapporter ; l'inverse — des
    /// rapports sans évaluation — n'a rien à écrire, et c'est pourquoi les deux
    /// conditions sont exigées.
    #[must_use]
    pub fn rapporte(&self, spf: &Spf) -> bool {
        self.est_configure(spf) && !self.report_directory.is_empty()
    }
}

/// Tout ce qu'un fichier de configuration porte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Configuration {
    /// Le nom que le serveur annonce.
    pub domain: String,
    /// Où écouter, sous la forme `adresse:port`.
    ///
    /// Cette crate ne l'interprète pas : `core` ne sait pas lire une adresse de
    /// socket, et un second lecteur écrit ici finirait par diverger de celui de
    /// la bibliothèque standard. C'est l'appelant qui la lit.
    pub listen: String,
    /// La racine de la boîte Maildir.
    pub maildir: String,
    /// Les domaines pour lesquels du courrier est accepté.
    pub hosted: Vec<String>,
    /// Le nombre maximal de destinataires par transaction.
    pub max_recipients: u32,
    /// La taille maximale d'un message, annoncée par `SIZE`.
    pub max_message_octets: u64,
    /// Les connexions servies en même temps.
    pub max_connections: u32,
    /// Les bornes du décodeur (C3).
    pub limits: Limits,
    /// Les seuils du garde (C8).
    pub guard: Thresholds,
    /// Le nombre de sources que le garde suit en même temps.
    pub tracked_sources: u32,
    /// Les délais.
    pub timeouts: Timeouts,
    /// De quoi chiffrer, ou deux chaînes vides.
    pub tls: Tls,
    /// Où écouter en POP3, ou une chaîne vide.
    ///
    /// Vide, POP3 n'est pas servi. Comme [`Configuration::listen`], cette crate
    /// ne l'interprète pas : `core` ne sait pas lire une adresse de socket, et
    /// un second lecteur écrit ici finirait par diverger de celui de la
    /// bibliothèque standard.
    pub listen_pop3: String,
    /// Où écouter en IMAP, ou une chaîne vide.
    ///
    /// Vide, IMAP n'est pas servi. Comme les deux autres adresses, cette crate
    /// ne l'interprète pas.
    pub listen_imap: String,
    /// SPF : les résolveurs, et ce qu'on fait du verdict.
    pub spf: Spf,
    /// DMARC : la liste des suffixes publics, et ce qu'on fait du verdict.
    pub dmarc: Dmarc,
    /// DKIM : de quoi signer ce qu'on émet, ou deux chaînes vides.
    pub dkim: Dkim,
    /// Où écouter en HTTP/2, ou une chaîne vide.
    ///
    /// **SANS CERTIFICAT, CE PORT N'EXISTE PAS** : l'API porte des jetons
    /// porteurs, et un jeton qui traverse un réseau en clair est un jeton volé.
    pub listen_http: String,
    /// Le secret qui scelle les jetons de l'API, en hexadécimal.
    ///
    /// Vide, l'API n'est pas servie — sans clé, aucun jeton ne se scelle.
    pub token_key: String,
    /// L'adresse d'écoute de l'API en HTTP/3, sur UDP.
    ///
    /// **UNE ADRESSE À PART, ET NON LE MÊME PORT QUE `listen_http`** : ouvrir un
    /// port UDP que l'exploitant n'a pas demandé serait une surprise, et une
    /// surprise sur un port est un incident.
    pub listen_h3: String,
    /// Le fichier de comptes, ou une chaîne vide.
    ///
    /// Vide, le serveur n'annonce pas `AUTH` : il n'a personne à qui répondre
    /// oui. Séparé de ce fichier-ci — voir `ams-accounts.capnp` pour les trois
    /// raisons.
    pub accounts: String,
    /// La file de réémission sortante.
    pub relay: Relay,
    /// La file d'attente du serveur.
    pub queue: Queue,
    /// MTA-STS (RFC 8461).
    pub mtasts: Mtasts,
    /// TLSRPT (RFC 8460).
    pub tlsrpt: Tlsrpt,
}

/// TLSRPT (RFC 8460) : ce qu'on rend au domaine d'en face.
///
/// # UNE CHAÎNE VIDE VEUT DIRE « AUCUN RAPPORT »
///
/// Pas de drapeau pour composer : l'absence de dossier EST l'absence de service,
/// comme pour les rapports DMARC. Le drapeau, lui, ne gouverne que la REMISE —
/// deux crans, pour qu'un exploitant puisse lire ce qu'il enverrait.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Tlsrpt {
    /// Le dossier où déposer les rapports, ou une chaîne vide.
    pub directory: String,
    /// Remet-on les rapports, ou se contente-t-on de les déposer ?
    pub send: bool,
}

impl Tlsrpt {
    /// Compose-t-on des rapports ?
    #[must_use]
    pub fn compose(&self) -> bool {
        !self.directory.is_empty()
    }

    /// Les remet-on ?
    ///
    /// **IL FAUT LES DEUX** : un drapeau sans dossier ne remettrait rien, faute
    /// d'avoir composé quoi que ce soit.
    #[must_use]
    pub fn envoie(&self) -> bool {
        self.compose() && self.send
    }
}

/// MTA-STS (RFC 8461) : ce qu'un domaine exige de qui lui écrit.
///
/// # DEUX CHAÎNES VIDES VEULENT DIRE « PAS ÉVALUÉ »
///
/// Pas de drapeau : l'absence de valeur EST l'absence de service, comme la liste
/// des suffixes publics pour DMARC. Et parce que ce champ a été ajouté après
/// coup, une configuration écrite avant lui décode deux chaînes vides — elle se
/// comporte donc exactement comme avant.
///
/// **DANE L'EMPORTE** quand un domaine publie les deux (§2 de RFC 8461).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Mtasts {
    /// Le fichier PEM des autorités, ou une chaîne vide.
    pub anchors: String,
    /// Le dossier du cache des politiques, ou une chaîne vide.
    pub cache: String,
}

impl Mtasts {
    /// MTA-STS est-il évalué ?
    ///
    /// **IL FAUT LES DEUX.** Sans autorités, on ne saurait pas à qui l'on parle
    /// en allant chercher la politique ; sans cache, un redémarrage rouvrirait
    /// la fenêtre de déclassement que §5 ferme.
    #[must_use]
    pub fn est_configure(&self) -> bool {
        !self.anchors.is_empty() && !self.cache.is_empty()
    }
}

/// Ce que ce serveur émet POUR SES COMPTES.
///
/// # ÉTEINT PAR DÉFAUT, ET UN FICHIER ANCIEN DÉCODE ÉTEINT
///
/// Émettre du courrier vers des tiers ne se décide pas à la place de celui qui
/// exploite la machine — la même règle que pour les rapports DMARC. Et parce que
/// ce champ a été ajouté après coup, une configuration écrite avant lui décode
/// `enabled: false` : une mise à jour ne transforme personne en relais.
///
/// # LA FILE N'EST PLUS ICI
///
/// Elle est devenue celle du SERVEUR — les rapports DMARC et TLS l'empruntent
/// aussi — et vit dans [`Queue`]. Ne restait ici que le drapeau qui dit si l'on
/// relaie.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Relay {
    /// Relaie-t-on pour les comptes authentifiés ?
    pub enabled: bool,
}

/// La file d'attente du serveur — **tout ce qui sort passe par elle**.
///
/// # POURQUOI ELLE N'APPARTIENT PLUS AU RELAIS
///
/// Il y avait TROIS politiques de reprise dans ce produit : celle-ci, et deux
/// écrites à la main pour les rapports DMARC et TLS. Trois politiques, c'est
/// trois vérités qui divergent, et deux d'entre elles n'avaient jamais été
/// éprouvées. Il n'y en a plus qu'une, couverte à 100 % dans `ams-queue`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Queue {
    /// Le dossier de la file, ou une chaîne vide.
    pub spool: String,
    /// L'attente après le premier échec, en secondes. Zéro prend le défaut.
    pub retry_seconds: u32,
    /// Le plafond de l'attente, en secondes. Zéro prend le défaut.
    pub max_retry_seconds: u32,
    /// Le temps accordé à un message depuis son dépôt. Zéro prend le défaut.
    pub expire_seconds: u32,
    /// Le retard à partir duquel on PRÉVIENT le déposant. Zéro prend le défaut.
    pub warn_seconds: u32,
}

impl Queue {
    /// Les durées que cette configuration décrit.
    ///
    /// **ZÉRO PREND LE DÉFAUT**, à chaque champ séparément : c'est ce qui permet
    /// d'ajouter ces durées sans qu'un fichier ancien ne fasse réessayer aussi
    /// vite que le disque tourne, ni renoncer avant d'avoir essayé.
    #[must_use]
    pub fn backoff(&self) -> Backoff {
        let defaut = Backoff::DEFAULT;
        Backoff {
            first: duree(self.retry_seconds, defaut.first),
            ceiling: duree(self.max_retry_seconds, defaut.ceiling),
            expiry: duree(self.expire_seconds, defaut.expiry),
            warning: duree(self.warn_seconds, defaut.warning),
        }
    }
}

/// `secondes`, ou `defaut` quand elle vaut zéro.
fn duree(secondes: u32, defaut: Duration) -> Duration {
    if secondes == 0 {
        defaut
    } else {
        Duration::from_secs(u64::from(secondes))
    }
}

/// Ce qui rend un fichier de configuration irrecevable.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Les octets ne forment pas un message Cap'n Proto lisible.
    Malformed(String),
    /// Le domaine annoncé n'est pas un domaine.
    ///
    /// Refusé **au chargement** : un serveur qui se nomme mal le fait dans chaque
    /// bannière, et le découvrir en production coûte plus cher que de refuser de
    /// démarrer.
    InvalidDomain(ams_proto_smtp::Error),
    /// Un champ obligatoire est vide.
    Empty(&'static str),
    /// Un seul des deux chemins TLS est renseigné.
    ///
    /// Refusé **au chargement**, parce qu'aucune des deux lectures possibles
    /// n'est sûre : démarrer sans chiffrer trahirait l'intention de
    /// l'administrateur, et démarrer en annonçant `STARTTLS` sans pouvoir le
    /// tenir mentirait à chaque pair.
    TlsIncomplete,
    /// Le fichier porte une valeur d'`enforcement` que ce binaire ne connaît
    /// pas.
    ///
    /// **On refuse plutôt que de choisir.** Un fichier écrit par une version
    /// plus récente peut dire « refuse » dans un mot que celle-ci ne sait pas
    /// lire ; en déduire « observe » ferait laisser passer ce que
    /// l'administrateur avait décidé de refuser, et en silence.
    UnknownEnforcement,
    /// Deux comptes portent le même nom.
    ///
    /// Une question sans réponse : le premier arrivé l'emporterait en silence,
    /// et l'administrateur croirait avoir changé un mot de passe.
    DuplicateLogin(String),

    /// Deux comptes déclarent la même adresse.
    ///
    /// Une question sans réponse : le premier arrivé l'emporterait en silence,
    /// et la moitié du courrier partirait au mauvais endroit.
    DuplicateAddress(String),

    /// L'empreinte d'un compte est refusée.
    ///
    /// Le nom est là **exprès** : un magasin de trente lignes sans nom oblige à
    /// les essayer une par une.
    WeakAccount {
        /// Le compte fautif.
        login: String,
        /// Ce que `ams-auth` en a dit.
        cause: ams_auth::Error,
    },

    /// Un champ texte n'est pas de l'UTF-8.
    ///
    /// Cap'n Proto promet de l'UTF-8 sur ses champs `Text` ; un fichier corrompu
    /// peut néanmoins n'en pas porter, et le supposer ferait paniquer un serveur
    /// au chargement de sa propre configuration.
    NotUtf8,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Malformed(detail) => write!(f, "configuration illisible : {detail}"),
            Error::InvalidDomain(cause) => write!(f, "domaine du serveur : {cause}"),
            Error::Empty(champ) => write!(f, "le champ `{champ}` est vide"),
            Error::TlsIncomplete => {
                f.write_str("TLS demande LES DEUX chemins — certificat et clé — ou aucun des deux")
            }
            Error::UnknownEnforcement => f.write_str(
                "ce fichier dit quelque chose d'`enforcement` que cette version ne sait pas lire",
            ),
            Error::DuplicateLogin(login) => {
                write!(f, "le compte `{login}` figure deux fois")
            }
            Error::DuplicateAddress(adresse) => {
                write!(f, "l'adresse `{adresse}` est déclarée par deux comptes")
            }
            Error::WeakAccount { login, cause } => {
                write!(f, "compte `{login}` : {cause}")
            }
            Error::NotUtf8 => f.write_str("un champ texte n'est pas de l'UTF-8"),
        }
    }
}

impl From<capnp::Error> for Error {
    fn from(cause: capnp::Error) -> Self {
        Error::Malformed(cause.to_string())
    }
}

/// Lit une configuration depuis ses octets.
///
/// # Errors
///
/// [`Error`].
pub fn decode(octets: &[u8]) -> Result<Configuration, Error> {
    let mut reste = octets;
    let message = serialize::read_message_from_flat_slice(
        &mut reste,
        ReaderOptions {
            traversal_limit_in_words: Some(
                usize::try_from(TRAVERSAL_LIMIT_WORDS).unwrap_or(usize::MAX),
            ),
            nesting_limit: 8,
        },
    )?;
    let lu: configuration::Reader<'_> = message.get_root()?;

    let domain = texte(lu.get_domain()?)?;
    if domain.is_empty() {
        return Err(Error::Empty("domain"));
    }
    // Le domaine du SERVEUR franchit la MÊME grammaire que celui d'un client :
    // deux validateurs pour une grammaire finissent par diverger.
    ClientId::parse(domain.as_bytes(), &Limits::DEFAULT).map_err(Error::InvalidDomain)?;

    let listen = texte(lu.get_listen()?)?;
    if listen.is_empty() {
        return Err(Error::Empty("listen"));
    }
    let maildir = texte(lu.get_maildir()?)?;
    if maildir.is_empty() {
        return Err(Error::Empty("maildir"));
    }

    let mut hosted = Vec::new();
    for domaine in lu.get_hosted()?.iter() {
        hosted.push(texte(domaine?)?);
    }

    let bornes = lu.get_limits()?;
    let garde = lu.get_guard()?;
    let delais = lu.get_timeouts()?;

    let comptes = texte(lu.get_accounts()?)?;
    let ecoute_pop3 = texte(lu.get_listen_pop3()?)?;
    let ecoute_imap = texte(lu.get_listen_imap()?)?;
    let ecoute_http = texte(lu.get_listen_http()?)?;
    let ecoute_h3 = texte(lu.get_listen_h3()?)?;
    let clef_de_jeton = texte(lu.get_token_key()?)?;

    // **UN FICHIER ÉCRIT AVANT CE CHAMP DÉCODE DEUX CHAÎNES VIDES**, et deux
    // chaînes vides veulent dire « MTA-STS n'est pas évalué ».
    // **UN FICHIER ÉCRIT AVANT CE CHAMP DÉCODE UNE CHAÎNE VIDE ET UN FAUX**, et
    // cela veut dire « aucun rapport n'est composé, et rien n'est remis ».
    let rapports = lu.get_tlsrpt()?;
    let tlsrpt = Tlsrpt {
        directory: texte(rapports.get_directory()?)?,
        send: rapports.get_send(),
    };

    let sts = lu.get_mtasts()?;
    let mtasts = Mtasts {
        anchors: texte(sts.get_anchors()?)?,
        cache: texte(sts.get_cache()?)?,
    };

    // **UN FICHIER ÉCRIT AVANT CE CHAMP DÉCODE `enabled: false`**, et un serveur
    // qu'on met à jour ne devient donc pas un relais sans que personne l'ait
    // décidé. C'est ce qui rend ce champ ajoutable.
    let emission = lu.get_relay()?;
    let relay = Relay {
        enabled: emission.get_enabled(),
    };

    // **UN FICHIER ÉCRIT AVANT CE CHAMP DÉCODE UN DOSSIER VIDE**, et le serveur
    // refuse alors de démarrer dès que quelque chose doit sortir. Les cinq
    // champs retirés de `Relay` ne sont PAS lus : reprendre l'ancienne valeur en
    // silence ferait déposer des rapports dans un répertoire que l'exploitant
    // croyait réservé au courrier.
    let attente = lu.get_queue()?;
    let queue = Queue {
        spool: texte(attente.get_spool()?)?,
        retry_seconds: attente.get_retry_seconds(),
        max_retry_seconds: attente.get_max_retry_seconds(),
        warn_seconds: attente.get_warn_seconds(),
        expire_seconds: attente.get_expire_seconds(),
    };

    let signature = lu.get_dkim()?;
    let dkim = Dkim {
        selector: texte(signature.get_selector()?)?,
        private_key_path: texte(signature.get_private_key_path()?)?,
    };

    let verification = lu.get_spf()?;
    let mut resolveurs = Vec::new();
    for resolveur in verification.get_resolvers()? {
        resolveurs.push(texte(resolveur?)?);
    }
    let spf = Spf {
        resolvers: resolveurs,
        enforcement: match verification.get_enforcement() {
            Ok(crate::ams_config_capnp::spf::Enforcement::Observe) => Enforcement::Observe,
            Ok(crate::ams_config_capnp::spf::Enforcement::Enforce) => Enforcement::Enforce,
            Err(_) => return Err(Error::UnknownEnforcement),
        },
        timeout_millis: verification.get_timeout_millis(),
    };

    let alignement = lu.get_dmarc()?;
    let dmarc = Dmarc {
        public_suffix_list: texte(alignement.get_public_suffix_list()?)?,
        enforcement: match alignement.get_enforcement() {
            Ok(crate::ams_config_capnp::dmarc::Enforcement::Observe) => Enforcement::Observe,
            Ok(crate::ams_config_capnp::dmarc::Enforcement::Enforce) => Enforcement::Enforce,
            Err(_) => return Err(Error::UnknownEnforcement),
        },
        report_directory: texte(alignement.get_report_directory()?)?,
        report_org_name: texte(alignement.get_report_org_name()?)?,
        report_email: texte(alignement.get_report_email()?)?,
        report_interval_seconds: alignement.get_report_interval_seconds(),
        send_reports: alignement.get_send_reports(),
        failure_reports: alignement.get_failure_reports(),
        // **UN FICHIER ÉCRIT AVANT CE CHAMP DÉCODE UNE CHAÎNE VIDE**, et vide
        // vaut « pas de quarantaine » : une configuration existante se comporte
        // exactement comme avant.
        quarantine_folder: texte(alignement.get_quarantine_folder()?)?,
    };

    let chiffrement = lu.get_tls()?;
    let tls = Tls {
        certificate_chain_path: texte(chiffrement.get_certificate_chain_path()?)?,
        private_key_path: texte(chiffrement.get_private_key_path()?)?,
    };
    // L'un sans l'autre ne veut rien dire — ni « chiffre » ni « ne chiffre pas ».
    if tls.certificate_chain_path.is_empty() != tls.private_key_path.is_empty() {
        return Err(Error::TlsIncomplete);
    }

    Ok(Configuration {
        domain,
        listen,
        maildir,
        hosted,
        max_recipients: lu.get_max_recipients(),
        max_message_octets: lu.get_max_message_octets(),
        max_connections: lu.get_max_connections(),
        limits: Limits {
            max_command_octets: taille(bornes.get_max_command_octets()),
            max_local_part_octets: taille(bornes.get_max_local_part_octets()),
            max_domain_octets: taille(bornes.get_max_domain_octets()),
            max_path_octets: taille(bornes.get_max_path_octets()),
            max_reply_octets: taille(bornes.get_max_reply_octets()),
            max_text_line_octets: taille(bornes.get_max_text_line_octets()),
            max_parameters: taille(bornes.get_max_parameters()),
        },
        guard: Thresholds {
            connections_per_minute: garde.get_connections_per_minute(),
            commands_per_minute: garde.get_commands_per_minute(),
            invalid_frames_per_minute: garde.get_invalid_frames_per_minute(),
            // **UN FICHIER ÉCRIT AVANT CE CHAMP DÉCODE ZÉRO**, et zéro éteint le
            // compteur : une configuration existante se comporte exactement comme
            // avant. C'est ce qui rend ce seuil ajoutable sans rien casser.
            refused_recipients_per_minute: garde.get_refused_recipients_per_minute(),
            ban_duration: core::time::Duration::from_secs(u64::from(garde.get_ban_seconds())),
            ipv4_prefix_bits: garde.get_ipv4_prefix_bits(),
            ipv6_prefix_bits: garde.get_ipv6_prefix_bits(),
        },
        tracked_sources: taille_u32(garde.get_tracked_sources()),
        timeouts: Timeouts {
            command_seconds: delais.get_command_seconds(),
            data_seconds: delais.get_data_seconds(),
            quic_idle_seconds: delais.get_quic_idle_seconds(),
        },
        tls,
        spf,
        dmarc,
        dkim,
        accounts: comptes,
        listen_pop3: ecoute_pop3,
        listen_imap: ecoute_imap,
        listen_http: ecoute_http,
        listen_h3: ecoute_h3,
        token_key: clef_de_jeton,
        relay,
        queue,
        mtasts,
        tlsrpt,
    })
}

/// Écrit une configuration.
///
/// # Errors
///
/// [`Error::Malformed`] si l'encodage échoue — ce qui n'arrive que sur un défaut
/// de la bibliothèque, jamais sur une configuration valide.
pub fn encode(config: &Configuration) -> Result<Vec<u8>, Error> {
    let mut message = capnp::message::Builder::new_default();
    {
        let mut ecrit = message.init_root::<configuration::Builder<'_>>();
        ecrit.set_domain(&config.domain);
        ecrit.set_listen(&config.listen);
        ecrit.set_maildir(&config.maildir);
        ecrit.set_max_recipients(config.max_recipients);
        ecrit.set_max_message_octets(config.max_message_octets);
        ecrit.set_max_connections(config.max_connections);
        {
            let mut heberges = ecrit
                .reborrow()
                .init_hosted(u32::try_from(config.hosted.len()).unwrap_or(u32::MAX));
            for (rang, domaine) in config.hosted.iter().enumerate() {
                heberges.set(u32::try_from(rang).unwrap_or(u32::MAX), domaine);
            }
        }
        {
            let mut bornes = ecrit.reborrow().init_limits();
            bornes.set_max_command_octets(depuis(config.limits.max_command_octets));
            bornes.set_max_local_part_octets(depuis(config.limits.max_local_part_octets));
            bornes.set_max_domain_octets(depuis(config.limits.max_domain_octets));
            bornes.set_max_path_octets(depuis(config.limits.max_path_octets));
            bornes.set_max_reply_octets(depuis(config.limits.max_reply_octets));
            bornes.set_max_text_line_octets(depuis(config.limits.max_text_line_octets));
            bornes.set_max_parameters(depuis(config.limits.max_parameters));
        }
        {
            let mut garde = ecrit.reborrow().init_guard();
            garde.set_connections_per_minute(config.guard.connections_per_minute);
            garde.set_commands_per_minute(config.guard.commands_per_minute);
            garde.set_invalid_frames_per_minute(config.guard.invalid_frames_per_minute);
            garde.set_refused_recipients_per_minute(config.guard.refused_recipients_per_minute);
            garde.set_ban_seconds(
                u32::try_from(config.guard.ban_duration.as_secs()).unwrap_or(u32::MAX),
            );
            garde.set_ipv4_prefix_bits(config.guard.ipv4_prefix_bits);
            garde.set_ipv6_prefix_bits(config.guard.ipv6_prefix_bits);
            garde.set_tracked_sources(config.tracked_sources);
        }
        {
            let mut delais = ecrit.reborrow().init_timeouts();
            delais.set_command_seconds(config.timeouts.command_seconds);
            delais.set_data_seconds(config.timeouts.data_seconds);
            delais.set_quic_idle_seconds(config.timeouts.quic_idle_seconds);
        }
        {
            let mut chiffrement = ecrit.reborrow().init_tls();
            chiffrement.set_certificate_chain_path(&config.tls.certificate_chain_path);
            chiffrement.set_private_key_path(&config.tls.private_key_path);
        }
        {
            let mut signature = ecrit.reborrow().init_dkim();
            signature.set_selector(&config.dkim.selector);
            signature.set_private_key_path(&config.dkim.private_key_path);
        }
        {
            let mut verification = ecrit.reborrow().init_spf();
            verification.set_enforcement(match config.spf.enforcement {
                Enforcement::Observe => crate::ams_config_capnp::spf::Enforcement::Observe,
                Enforcement::Enforce => crate::ams_config_capnp::spf::Enforcement::Enforce,
            });
            verification.set_timeout_millis(config.spf.timeout_millis);
            let combien = u32::try_from(config.spf.resolvers.len()).unwrap_or(u32::MAX);
            let mut liste = verification.init_resolvers(combien);
            for (rang, resolveur) in config.spf.resolvers.iter().enumerate() {
                liste.set(u32::try_from(rang).unwrap_or(u32::MAX), resolveur);
            }
        }
        {
            let mut alignement = ecrit.reborrow().init_dmarc();
            alignement.set_public_suffix_list(&config.dmarc.public_suffix_list);
            alignement.set_enforcement(match config.dmarc.enforcement {
                Enforcement::Observe => crate::ams_config_capnp::dmarc::Enforcement::Observe,
                Enforcement::Enforce => crate::ams_config_capnp::dmarc::Enforcement::Enforce,
            });
            alignement.set_report_directory(&config.dmarc.report_directory);
            alignement.set_report_org_name(&config.dmarc.report_org_name);
            alignement.set_report_email(&config.dmarc.report_email);
            alignement.set_report_interval_seconds(config.dmarc.report_interval_seconds);
            alignement.set_send_reports(config.dmarc.send_reports);
            alignement.set_failure_reports(config.dmarc.failure_reports);
            alignement.set_quarantine_folder(&config.dmarc.quarantine_folder);
        }
        ecrit.set_accounts(&config.accounts);
        ecrit.set_listen_pop3(&config.listen_pop3);
        ecrit.set_listen_imap(&config.listen_imap);
        ecrit.set_listen_http(&config.listen_http);
        ecrit.set_listen_h3(&config.listen_h3);
        ecrit.set_token_key(&config.token_key);
        {
            let mut emission = ecrit.reborrow().init_relay();
            emission.set_enabled(config.relay.enabled);
        }
        {
            let mut attente = ecrit.reborrow().init_queue();
            attente.set_spool(&config.queue.spool);
            attente.set_retry_seconds(config.queue.retry_seconds);
            attente.set_max_retry_seconds(config.queue.max_retry_seconds);
            attente.set_warn_seconds(config.queue.warn_seconds);
            attente.set_expire_seconds(config.queue.expire_seconds);
        }
        {
            let mut sts = ecrit.reborrow().init_mtasts();
            sts.set_anchors(&config.mtasts.anchors);
            sts.set_cache(&config.mtasts.cache);
        }
        {
            let mut rapports = ecrit.reborrow().init_tlsrpt();
            rapports.set_directory(&config.tlsrpt.directory);
            rapports.set_send(config.tlsrpt.send);
        }
    }
    Ok(serialize::write_message_to_words(&message))
}

/// Une chaîne du message, copiée.
pub(crate) fn texte(brut: capnp::text::Reader<'_>) -> Result<String, Error> {
    brut.to_string().map_err(|_| Error::NotUtf8)
}

/// Une borne du schéma vers la borne du décodeur.
fn taille(valeur: u32) -> usize {
    usize::try_from(valeur).unwrap_or(usize::MAX)
}

/// Idem, pour ce qui reste en `u32`.
fn taille_u32(valeur: u32) -> u32 {
    valeur
}

/// Une borne du décodeur vers celle du schéma.
fn depuis(valeur: usize) -> u32 {
    u32::try_from(valeur).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::{
        Configuration, Dkim, Dmarc, Enforcement, Error, Spf, TRAVERSAL_LIMIT_WORDS, Timeouts, Tls,
        decode, encode,
    };
    use super::{Mtasts, Queue, Relay, Tlsrpt};
    use alloc::string::{String, ToString as _};
    use alloc::vec;
    use ams_guard::Thresholds;
    use ams_proto_smtp::Limits;
    use core::time::Duration;

    fn exemple() -> Configuration {
        Configuration {
            domain: String::from("mail.example.com"),
            listen: String::from("127.0.0.1:2525"),
            maildir: String::from("/var/mail/spool"),
            hosted: vec![String::from("example.com"), String::from("example.org")],
            max_recipients: 100,
            max_message_octets: 10_485_760,
            max_connections: 256,
            limits: Limits::DEFAULT,
            guard: Thresholds::DEFAULT,
            tracked_sources: 4096,
            // AUCUNE ÉMISSION dans l'exemple : c'est le défaut, et c'est aussi
            // ce qu'un fichier écrit avant que ce champ n'existe décodera.
            relay: Relay::default(),
            // ET AUCUNE FILE : sans rien à émettre, il n'y a rien à mettre en
            // attente.
            queue: Queue::default(),
            // MTA-STS NON ÉVALUÉ dans l'exemple : c'est le défaut, et c'est
            // aussi ce qu'un fichier antérieur à ce champ décodera.
            mtasts: Mtasts::default(),
            // AUCUN RAPPORT TLS dans l'exemple : c'est le défaut.
            tlsrpt: Tlsrpt::default(),
            timeouts: Timeouts {
                command_seconds: 300,
                data_seconds: 600,
                quic_idle_seconds: 0,
            },
            // L'exemple ne chiffre PAS et n'a AUCUN compte : c'est le défaut, et
            // un défaut qui chiffrerait ou authentifierait nommerait des
            // fichiers qui n'existent pas.
            tls: Tls::default(),
            // Ni résolveur : SPF n'est pas vérifié, et il n'y a pas de drapeau
            // pour dire le contraire.
            spf: Spf::default(),
            // Ni liste de suffixes : DMARC n'est pas évalué, et il n'y a pas de
            // drapeau pour dire le contraire.
            dmarc: Dmarc::default(),
            // Ni sélecteur : rien n'est signé, et il n'y a pas de drapeau pour
            // dire le contraire.
            dkim: Dkim::default(),
            accounts: String::new(),
            listen_pop3: String::new(),
            listen_imap: String::new(),
            listen_http: String::new(),
            listen_h3: String::new(),
            token_key: String::new(),
        }
    }

    fn exemple_chiffrant() -> Configuration {
        Configuration {
            tls: Tls {
                certificate_chain_path: String::from("/etc/ams/chaine.pem"),
                private_key_path: String::from("/etc/ams/cle.pem"),
            },
            accounts: String::from("/etc/ams/comptes.bin"),
            listen_pop3: String::from("127.0.0.1:2110"),
            listen_imap: String::from("127.0.0.1:2143"),
            listen_http: String::from("127.0.0.1:2443"),
            listen_h3: String::from("127.0.0.1:2443"),
            token_key: String::from(
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            // ET DES RÉSOLVEURS : le balayage qui corrompt chaque octet ne
            // traverse une liste de textes que si elle en porte.
            spf: Spf {
                resolvers: vec![String::from("127.0.0.1:53")],
                enforcement: Enforcement::Enforce,
                timeout_millis: 5_000,
            },
            dmarc: Dmarc {
                public_suffix_list: String::from("/etc/ams/public_suffix_list.dat"),
                enforcement: Enforcement::Enforce,
                report_directory: String::from("/var/spool/ams/rapports"),
                report_org_name: String::from("mail.example.com"),
                report_email: String::from("dmarc@example.com"),
                report_interval_seconds: 3_600,
                send_reports: true,
                failure_reports: false,
                quarantine_folder: String::from("Junk"),
            },
            dkim: Dkim {
                selector: String::from("mars2026"),
                private_key_path: String::from("/etc/ams/dkim.pem"),
            },
            ..exemple()
        }
    }

    #[test]
    fn une_configuration_ecrite_se_relit_a_l_identique() {
        // C'EST LA PROPRIÉTÉ QUI COMPTE : `air-mail-admin` écrit, le serveur lit,
        // et les deux doivent voir la même chose. Un écart y serait un serveur
        // réglé autrement que ce que l'administrateur croit avoir demandé.
        let original = exemple();
        let octets = encode(&original).expect("encodable");
        let relue = decode(&octets).expect("relisible");
        assert_eq!(relue, original);
    }

    #[test]
    fn les_chemins_tls_traversent_le_format() {
        let original = exemple_chiffrant();
        let relue = decode(&encode(&original).expect("encodable")).expect("relisible");
        assert_eq!(relue.tls, original.tls);
        assert!(relue.tls.est_configure());
    }

    /// **PAS DE DRAPEAU, ICI NON PLUS** : on signe si et seulement si le
    /// sélecteur ET la clé sont nommés. Un sélecteur sans clé ne veut dire ni
    /// « signe » ni « ne signe pas ».
    #[test]
    fn le_signataire_dkim_traverse_le_format() {
        let original = exemple_chiffrant();
        let relue = decode(&encode(&original).expect("encodable")).expect("relisible");
        assert_eq!(relue.dkim, original.dkim);
        assert!(relue.dkim.est_configure());

        let sans = decode(&encode(&exemple()).expect("encodable")).expect("relisible");
        assert_eq!(sans.dkim, Dkim::default());
        assert!(!sans.dkim.est_configure());
        // Et l'un sans l'autre ne configure rien.
        for boiteux in [
            Dkim {
                selector: String::from("mars2026"),
                private_key_path: String::new(),
            },
            Dkim {
                selector: String::new(),
                private_key_path: String::from("/etc/ams/dkim.pem"),
            },
        ] {
            assert!(!boiteux.est_configure(), "{boiteux:?}");
        }
    }

    #[test]
    fn le_chemin_des_comptes_traverse_le_format() {
        let original = exemple_chiffrant();
        let relue = decode(&encode(&original).expect("encodable")).expect("relisible");
        assert_eq!(relue.accounts, "/etc/ams/comptes.bin");
        assert_eq!(relue.listen_pop3, "127.0.0.1:2110");
        assert_eq!(relue.listen_imap, "127.0.0.1:2143");
        // Et son absence se lit à une chaîne vide, pas à un drapeau.
        let sans = decode(&encode(&exemple()).expect("encodable")).expect("relisible");
        assert!(sans.accounts.is_empty());
        assert!(sans.listen_pop3.is_empty());
        assert!(sans.listen_imap.is_empty());
    }

    #[test]
    fn sans_chemins_le_service_ne_chiffre_pas_et_le_dit() {
        let relue = decode(&encode(&exemple()).expect("encodable")).expect("relisible");
        assert!(!relue.tls.est_configure());
        assert_eq!(relue.tls, Tls::default());
    }

    #[test]
    fn un_seul_des_deux_chemins_est_refuse() {
        // Aucune des deux lectures possibles n'est sûre : démarrer sans chiffrer
        // trahirait l'intention, et annoncer `STARTTLS` sans pouvoir le tenir
        // mentirait à chaque pair. On refuse donc de choisir à sa place.
        for (chaine, cle) in [("/etc/ams/chaine.pem", ""), ("", "/etc/ams/cle.pem")] {
            let mut config = exemple();
            config.tls = Tls {
                certificate_chain_path: String::from(chaine),
                private_key_path: String::from(cle),
            };
            let octets = encode(&config).expect("encodable");
            assert_eq!(decode(&octets), Err(Error::TlsIncomplete));
        }
    }

    #[test]
    fn le_message_de_l_incomplet_dit_quoi_faire() {
        let dit = alloc::format!("{}", Error::TlsIncomplete);
        assert!(dit.contains("LES DEUX"), "{dit}");
    }

    #[test]
    fn le_fichier_est_bien_binaire() {
        // C11 : pas de texte. Un fichier qu'on peut éditer à la main est un
        // fichier qu'on éditera à la main.
        let octets = encode(&exemple()).expect("encodable");
        assert!(
            octets.contains(&0),
            "un fichier sans octet nul n'a rien de binaire"
        );
        // Et il porte tout de même les chaînes, qui ne sont pas chiffrées.
        assert!(
            octets.windows(16).any(|f| f == b"mail.example.com"),
            "le domaine devrait s'y retrouver tel quel"
        );
    }

    #[test]
    fn les_bornes_et_les_seuils_traversent_le_format() {
        let mut original = exemple();
        original.limits = Limits {
            max_command_octets: 1,
            max_local_part_octets: 2,
            max_domain_octets: 3,
            max_path_octets: 4,
            max_reply_octets: 5,
            max_text_line_octets: 6,
            max_parameters: 7,
        };
        original.guard = Thresholds {
            connections_per_minute: 11,
            commands_per_minute: 12,
            invalid_frames_per_minute: 13,
            refused_recipients_per_minute: 17,
            ban_duration: Duration::from_secs(14),
            ipv4_prefix_bits: 24,
            ipv6_prefix_bits: 48,
        };
        original.timeouts = Timeouts {
            command_seconds: 15,
            data_seconds: 16,
            quic_idle_seconds: 17,
        };
        let relue = decode(&encode(&original).expect("encodable")).expect("relisible");
        assert_eq!(relue.limits, original.limits);
        assert_eq!(relue.guard, original.guard);
        assert_eq!(relue.timeouts, original.timeouts);
    }

    #[test]
    fn une_liste_de_domaines_vide_traverse_aussi() {
        // Un serveur qui n'héberge rien est une configuration licite — et c'est
        // le seul défaut qui ne relaie rien.
        let mut original = exemple();
        original.hosted.clear();
        let relue = decode(&encode(&original).expect("encodable")).expect("relisible");
        assert!(relue.hosted.is_empty());
    }

    #[test]
    fn un_domaine_invalide_empeche_de_charger() {
        // Un serveur qui se nomme mal le fait dans CHAQUE bannière.
        let mut original = exemple();
        original.domain = String::from("-pas-un-domaine-");
        let octets = encode(&original).expect("encodable");
        assert_eq!(
            decode(&octets),
            Err(Error::InvalidDomain(ams_proto_smtp::Error::MalformedDomain))
        );
    }

    #[test]
    fn les_champs_obligatoires_vides_sont_refuses() {
        for (champ, vider) in [
            (
                "domain",
                (|c: &mut Configuration| c.domain.clear()) as fn(&mut Configuration),
            ),
            ("listen", |c| c.listen.clear()),
            ("maildir", |c| c.maildir.clear()),
        ] {
            let mut original = exemple();
            vider(&mut original);
            let octets = encode(&original).expect("encodable");
            assert_eq!(decode(&octets), Err(Error::Empty(champ)), "sur `{champ}`");
        }
    }

    #[test]
    fn des_octets_qui_ne_sont_pas_une_configuration_sont_refuses() {
        for mauvais in [
            b"".as_slice(),
            b"pas du tout du cap'n proto",
            b"\x00\x00\x00\x00",
        ] {
            let resultat = decode(mauvais);
            assert!(resultat.is_err(), "{mauvais:?} aurait dû être refusé");
        }
        // Un message tronqué au milieu ne passe pas non plus.
        let octets = encode(&exemple()).expect("encodable");
        let coupe = &octets[..octets.len() / 2];
        assert!(decode(coupe).is_err());
    }

    #[test]
    fn un_fichier_corrompu_ne_fait_jamais_paniquer_le_serveur() {
        // UN SERVEUR QUI PANIQUE EN LISANT SA PROPRE CONFIGURATION NE DÉMARRE
        // PAS, et ne dit pas pourquoi. Un disque qui a mal vieilli, une copie
        // interrompue, un octet retourné : tout cela doit rendre une erreur, pas
        // un arrêt brutal.
        //
        // Le balayage corrompt CHAQUE octet à son tour, plutôt que des positions
        // choisies à la main : les positions choisies vieillissent avec le
        // schéma, le balayage non.
        // On balaie la configuration QUI CHIFFRE : c'est la plus grande, et
        // surtout la seule dont les chemins TLS sont des pointeurs réels. Sur
        // une configuration sans TLS, ces deux champs sont nuls, et les
        // corrompre ne fait rien traverser du tout.
        let sain = encode(&exemple_chiffrant()).expect("encodable");
        let mut refuses = 0_u32;
        let mut acceptes = 0_u32;
        for position in 0..sain.len() {
            for masque in [0xFF_u8, 0x01, 0x80] {
                let mut corrompu = sain.clone();
                corrompu[position] ^= masque;
                match decode(&corrompu) {
                    Ok(_) => acceptes = acceptes.saturating_add(1),
                    Err(_) => refuses = refuses.saturating_add(1),
                }
            }
        }
        // La plupart des corruptions se voient ; certaines tombent dans du
        // remplissage, ou changent un entier en un autre entier tout aussi
        // licite. Les deux cas doivent exister, sans quoi ce test ne mesurerait
        // qu'une moitié du décodeur.
        assert!(refuses > 0, "aucune corruption n'a été détectée");
        assert!(
            acceptes > 0,
            "toutes les corruptions ont été refusées : le balayage ne traverse pas le chemin nominal"
        );
    }

    #[test]
    fn la_limite_de_traversee_est_explicite() {
        // Sans borne, un fichier corrompu ferait suivre au décodeur des
        // structures qui se référencent l'une l'autre.
        assert_eq!(TRAVERSAL_LIMIT_WORDS, 8_192);
    }

    #[test]
    fn les_types_se_deboguent_et_les_erreurs_disent_quelque_chose() {
        let config = exemple();
        assert_eq!(config.clone(), config);
        assert!(!std::format!("{config:?}").is_empty());
        for erreur in [
            Error::Malformed(String::from("détail")),
            Error::InvalidDomain(ams_proto_smtp::Error::MalformedDomain),
            Error::Empty("domain"),
            Error::NotUtf8,
        ] {
            assert!(erreur.to_string().len() > 10, "{erreur:?}");
            assert!(!std::format!("{erreur:?}").is_empty());
        }
        assert_ne!(Error::NotUtf8, Error::Empty("domain"));
        assert!(!std::format!("{:?}", config.timeouts).is_empty());
    }

    #[test]
    fn la_section_spf_traverse_le_format() {
        let mut original = exemple();
        assert!(!original.spf.est_configure());
        original.spf = Spf {
            resolvers: vec![String::from("127.0.0.1:53"), String::from("[::1]:53")],
            enforcement: Enforcement::Enforce,
            timeout_millis: 3_000,
        };
        let octets = encode(&original).expect("encodable");
        let relue = decode(&octets).expect("relisible");
        assert_eq!(relue.spf, original.spf);
        assert!(relue.spf.est_configure());
    }

    #[test]
    fn sans_resolveur_spf_n_est_pas_configure() {
        // PAS DE DRAPEAU : l'absence de résolveur EST l'absence de vérification.
        // Un `enforcement` réglé sans résolveur ne vérifie rien, et ne prétend
        // rien vérifier.
        let mut original = exemple();
        original.spf.enforcement = Enforcement::Enforce;
        let octets = encode(&original).expect("encodable");
        let relue = decode(&octets).expect("relisible");
        assert!(!relue.spf.est_configure());
        assert_eq!(relue.spf.enforcement, Enforcement::Enforce);
        assert_eq!(Enforcement::default(), Enforcement::Observe);
        assert_ne!(Enforcement::Observe, Enforcement::Enforce);
        assert!(!alloc::format!("{:?}", relue.spf).is_empty());
    }

    #[test]
    fn une_valeur_d_enforcement_inconnue_est_refusee() {
        // Un fichier écrit par une version plus récente peut dire « refuse »
        // dans un mot que celle-ci ne sait pas lire. EN DÉDUIRE « observe »
        // ferait laisser passer, en silence, ce que l'administrateur avait
        // décidé de refuser.
        let mut octets = encode(&exemple()).expect("encodable");
        let motif = Enforcement::Observe;
        let _ = motif;
        // On retrouve l'entier de l'énumération dans les octets et on le pousse
        // hors du schéma. Le champ vaut zéro : on cherche donc un seizième
        // d'octet précis, ce qui n'est pas praticable — on passe par le
        // décodage, qui doit refuser tout ce qui n'est ni 0 ni 1.
        //
        // Le message porte l'énumération sur deux octets ; on les met à 0xFFFF
        // partout où cela ne casse pas le reste, et on vérifie qu'AU MOINS une
        // de ces mutations est refusée pour cette raison-là.
        let mut refusee = false;
        for rang in 0..octets.len() {
            let sauvegarde = octets[rang];
            octets[rang] = 0xFF;
            if decode(&octets) == Err(Error::UnknownEnforcement) {
                refusee = true;
            }
            octets[rang] = sauvegarde;
        }
        assert!(
            refusee,
            "aucune mutation n'a produit un `enforcement` inconnu"
        );
        let dit = alloc::format!("{}", Error::UnknownEnforcement);
        assert!(dit.contains("enforcement"), "{dit}");
    }

    /// **ZÉRO PREND LE DÉFAUT, ET C'EST CE QUI REND LE CHAMP AJOUTABLE.**
    ///
    /// Un fichier écrit avant que `quicIdleSeconds` n'existe décode zéro. Sans
    /// cette substitution, il annoncerait une inactivité NULLE, et chaque
    /// connexion QUIC expirerait à l'instant où elle s'établit — une
    /// configuration parfaitement valable deviendrait un serveur qui ne sert
    /// plus rien en HTTP/3, à la seule faveur d'une mise à jour.
    #[test]
    fn une_inactivite_quic_nulle_prend_le_defaut() {
        let mut delais = Timeouts {
            command_seconds: 300,
            data_seconds: 600,
            quic_idle_seconds: 0,
        };
        assert_eq!(
            delais.quic_idle_secondes(),
            Timeouts::QUIC_IDLE_DEFAUT_SECONDES
        );
        // ET CE QUI EST NOMMÉ EST PRIS TEL QUEL : le défaut ne s'impose qu'à
        // l'absence, jamais à un choix.
        delais.quic_idle_seconds = 5;
        assert_eq!(delais.quic_idle_secondes(), 5);
    }

    /// **LES TROIS DÉLAIS TRAVERSENT LE FORMAT.**
    #[test]
    fn les_trois_delais_traversent_le_format() {
        let mut original = exemple();
        original.timeouts = Timeouts {
            command_seconds: 61,
            data_seconds: 62,
            quic_idle_seconds: 63,
        };
        let octets = encode(&original).expect("encodable");
        let relue = decode(&octets).expect("relisible");
        assert_eq!(relue.timeouts, original.timeouts);
        assert_eq!(relue.timeouts.quic_idle_secondes(), 63);
    }

    #[test]
    fn la_section_dmarc_traverse_le_format() {
        let mut original = exemple();
        assert!(!original.dmarc.est_configure(&original.spf));
        assert!(!original.dmarc.rapporte(&original.spf));
        // LE RÉSOLVEUR FAIT PARTIE DE L'ÉVALUATION, et cette section ne le
        // porte pas : sans lui, tout ce qu'on règle ci-dessous ne s'appliquerait
        // à aucun message.
        original.spf.resolvers = vec![String::from("127.0.0.1:53")];
        original.dmarc = Dmarc {
            public_suffix_list: String::from("/etc/ams/psl.dat"),
            enforcement: Enforcement::Enforce,
            report_directory: String::from("/var/spool/ams/rapports"),
            report_org_name: String::from("mail.example.com"),
            report_email: String::from("dmarc@example.com"),
            report_interval_seconds: 3_600,
            send_reports: true,
            failure_reports: true,
            quarantine_folder: String::from("Junk"),
        };
        let octets = encode(&original).expect("encodable");
        let relue = decode(&octets).expect("relisible");
        assert_eq!(relue.dmarc, original.dmarc);
        assert!(relue.dmarc.est_configure(&relue.spf));
        assert!(relue.dmarc.rapporte(&relue.spf));
        assert!(relue.dmarc.met_en_quarantaine(&relue.spf));
        assert!(!alloc::format!("{:?}", relue.dmarc).is_empty());
    }

    /// **Évaluer et rapporter sont deux services distincts.** Un dossier sans
    /// liste de suffixes ne rapporterait rien, puisqu'il n'y aurait rien à
    /// rapporter — et une liste sans dossier évalue sans rien écrire.
    /// **Composer et remettre sont deux services distincts** : le premier
    /// n'écrit que dans un dossier de la machine, le second parle à des tiers.
    /// **LA QUARANTAINE NE DÉPEND PAS DE `enforcement`.**
    ///
    /// `observe` et `enforce` gouvernent le REFUS d'un `p=reject` ; la
    /// quarantaine, elle, remet. Sans nom de dossier, elle n'existe pas — et
    /// sans liste de suffixes non plus, puisque rien ne serait évalué.
    #[test]
    fn la_quarantaine_ne_tient_qu_au_dossier_et_a_l_evaluation() {
        let mut config = exemple();
        config.spf.resolvers = vec![String::from("127.0.0.1:53")];
        config.dmarc.quarantine_folder = String::from("Junk");
        assert!(
            !config.dmarc.met_en_quarantaine(&config.spf),
            "rien n'est évalué : rien n'est mis de côté"
        );
        config.dmarc.public_suffix_list = String::from("/etc/ams/psl.dat");
        assert!(config.dmarc.met_en_quarantaine(&config.spf));
        assert_eq!(config.dmarc.enforcement, Enforcement::Observe);
        config.dmarc.quarantine_folder.clear();
        assert!(!config.dmarc.met_en_quarantaine(&config.spf));
    }

    #[test]
    fn remettre_se_demande_en_plus_de_composer() {
        let mut config = exemple();
        config.spf.resolvers = vec![String::from("127.0.0.1:53")];
        config.dmarc.public_suffix_list = String::from("/etc/ams/psl.dat");
        config.dmarc.report_directory = String::from("/var/spool/ams/rapports");
        assert!(config.dmarc.rapporte(&config.spf));
        assert!(
            !config.dmarc.envoie(&config.spf),
            "le défaut dépose et n'envoie rien"
        );
        config.dmarc.send_reports = true;
        assert!(config.dmarc.envoie(&config.spf));
        config.dmarc.report_directory.clear();
        assert!(
            !config.dmarc.envoie(&config.spf),
            "rien à remettre sans dossier"
        );
    }

    /// **Les rapports d'échec demandent une décision de plus** : ils parlent
    /// d'un message précis, arrivé chez quelqu'un.
    #[test]
    fn les_rapports_d_echec_se_demandent_a_part() {
        let mut config = exemple();
        config.spf.resolvers = vec![String::from("127.0.0.1:53")];
        config.dmarc.public_suffix_list = String::from("/etc/ams/psl.dat");
        config.dmarc.report_directory = String::from("/var/spool/ams/rapports");
        assert!(config.dmarc.rapporte(&config.spf));
        assert!(
            !config.dmarc.rapporte_les_echecs(&config.spf),
            "le défaut n'en compose pas"
        );
        config.dmarc.failure_reports = true;
        assert!(config.dmarc.rapporte_les_echecs(&config.spf));
        config.dmarc.report_directory.clear();
        assert!(
            !config.dmarc.rapporte_les_echecs(&config.spf),
            "sans dossier, rien"
        );
    }

    #[test]
    fn rapporter_demande_les_deux() {
        let mut config = exemple();
        config.spf.resolvers = vec![String::from("127.0.0.1:53")];
        config.dmarc.report_directory = String::from("/var/spool/ams/rapports");
        assert!(!config.dmarc.est_configure(&config.spf));
        assert!(!config.dmarc.rapporte(&config.spf));
        config.dmarc.public_suffix_list = String::from("/etc/ams/psl.dat");
        assert!(config.dmarc.rapporte(&config.spf));
        config.dmarc.report_directory.clear();
        assert!(config.dmarc.est_configure(&config.spf));
        assert!(!config.dmarc.rapporte(&config.spf));
    }

    /// **SANS RÉSOLVEUR, RIEN N'EST ÉVALUÉ — ET DONC RIEN N'EST FAIT.**
    ///
    /// C'est la moitié de la règle que ce prédicat ignorait. La documentation de
    /// [`Dmarc`] l'écrivait déjà — « si et seulement si une liste est nommée ET
    /// que des résolveurs le sont aussi » —, mais le code n'en appliquait que la
    /// première partie, et chaque appelant devait se rappeler du reste.
    ///
    /// Les CINQ prédicats tombent ensemble, parce qu'ils reposent tous sur
    /// l'évaluation : un dossier de quarantaine que rien ne remplit, des
    /// rapports qui n'ont rien à dire, une remise qui n'a rien à remettre.
    #[test]
    fn sans_resolveur_aucun_service_dmarc_ne_tourne() {
        let mut config = exemple();
        config.dmarc = Dmarc {
            public_suffix_list: String::from("/etc/ams/psl.dat"),
            enforcement: Enforcement::Enforce,
            report_directory: String::from("/var/spool/ams/rapports"),
            report_org_name: String::new(),
            report_email: String::new(),
            report_interval_seconds: 3_600,
            send_reports: true,
            failure_reports: true,
            quarantine_folder: String::from("Junk"),
        };
        // TOUT EST DEMANDÉ, et il ne manque QUE le résolveur.
        assert!(config.spf.resolvers.is_empty());
        assert!(!config.dmarc.est_configure(&config.spf));
        assert!(!config.dmarc.met_en_quarantaine(&config.spf));
        assert!(!config.dmarc.rapporte(&config.spf));
        assert!(!config.dmarc.rapporte_les_echecs(&config.spf));
        assert!(!config.dmarc.envoie(&config.spf));
        // Et le résolveur seul les rallume tous les cinq : c'est bien LUI qui
        // manquait, et non autre chose que ce test aurait réglé sans le dire.
        config.spf.resolvers = vec![String::from("127.0.0.1:53")];
        assert!(config.dmarc.est_configure(&config.spf));
        assert!(config.dmarc.met_en_quarantaine(&config.spf));
        assert!(config.dmarc.rapporte(&config.spf));
        assert!(config.dmarc.rapporte_les_echecs(&config.spf));
        assert!(config.dmarc.envoie(&config.spf));
    }

    #[test]
    fn sans_liste_de_suffixes_dmarc_n_est_pas_configure() {
        // PAS DE DRAPEAU : l'absence de liste EST l'absence d'évaluation. Un
        // `enforcement` réglé sans liste n'évalue rien, et ne prétend rien
        // évaluer.
        let mut original = exemple();
        original.dmarc.enforcement = Enforcement::Enforce;
        let octets = encode(&original).expect("encodable");
        let relue = decode(&octets).expect("relisible");
        assert!(!relue.dmarc.est_configure(&relue.spf));
        assert_eq!(relue.dmarc.enforcement, Enforcement::Enforce);
    }

    // ── La file de réémission sortante ──────────────────────────────────────

    /// **UN FICHIER ANCIEN DÉCODE « AUCUNE ÉMISSION ».**
    ///
    /// C'est ce qui rend ce champ ajoutable : un serveur qu'on met à jour ne
    /// devient pas un relais sans que personne l'ait décidé.
    #[test]
    fn sans_champ_de_relais_rien_ne_sort() {
        assert!(!Relay::default().enabled);
        assert!(!exemple().relay.enabled);
    }

    /// **ET UN FICHIER ANCIEN DÉCODE AUSSI UNE FILE VIDE.**
    ///
    /// Les réglages ont déménagé de `Relay` vers `Queue`, sous de NOUVEAUX
    /// numéros de champ. Reprendre l'ancienne valeur en silence ferait déposer
    /// des rapports dans un répertoire que l'exploitant croyait réservé au
    /// courrier ; le serveur refuse de démarrer et le dit.
    #[test]
    fn sans_champ_de_file_le_dossier_est_vide() {
        let attente = Queue::default();
        assert!(attente.spool.is_empty());
        assert!(exemple().queue.spool.is_empty());
        // Et les durées prennent le défaut de `ams-queue`.
        assert_eq!(attente.backoff(), ams_queue::Backoff::DEFAULT);
    }

    /// Les six réglages traversent l'encodage et la relecture.
    #[test]
    fn la_file_traverse_le_format() {
        let voulue = Queue {
            spool: String::from("/var/spool/ams/file"),
            retry_seconds: 60,
            max_retry_seconds: 3_600,
            expire_seconds: 172_800,
            warn_seconds: 7_200,
        };
        let config = Configuration {
            relay: Relay { enabled: true },
            queue: voulue.clone(),
            ..exemple()
        };
        let octets = encode(&config).expect("encodable");
        let relue = decode(&octets).expect("relisible");
        assert!(relue.relay.enabled);
        assert_eq!(relue.queue, voulue);
        assert_eq!(relue, config);
    }

    /// **ZÉRO PREND LE DÉFAUT, CHAMP PAR CHAMP.**
    #[test]
    fn un_zero_prend_le_defaut_champ_par_champ() {
        let defaut = ams_queue::Backoff::DEFAULT;
        assert_eq!(Queue::default().backoff(), defaut);

        // Un seul champ nommé : les trois autres restent au défaut.
        let partielle = Queue {
            retry_seconds: 42,
            ..Queue::default()
        };
        let reprise = partielle.backoff();
        assert_eq!(reprise.first, Duration::from_secs(42));
        assert_eq!(reprise.ceiling, defaut.ceiling);
        assert_eq!(reprise.expiry, defaut.expiry);
        // **UN FICHIER ÉCRIT AVANT CE CHAMP GARDE LES QUATRE HEURES DE
        // §4.5.4.1**, et n'avertit donc pas dès le premier essai.
        assert_eq!(reprise.warning, defaut.warning);

        // Et les quatre nommés : plus rien du défaut.
        let entiere = Queue {
            retry_seconds: 1,
            max_retry_seconds: 2,
            expire_seconds: 3,
            warn_seconds: 4,
            ..Queue::default()
        };
        assert_eq!(
            entiere.backoff(),
            ams_queue::Backoff {
                first: Duration::from_secs(1),
                ceiling: Duration::from_secs(2),
                expiry: Duration::from_secs(3),
                warning: Duration::from_secs(4),
            }
        );
    }

    /// **UN DOSSIER DE FILE QUI N'EST PAS DE L'UTF-8 FAIT REFUSER LE FICHIER.**
    ///
    /// Le refus vaut pour tous les champs texte, mais celui-ci se décode parmi
    /// les DERNIERS : des octets au hasard échouent toujours plus tôt, et sa
    /// garde n'était donc jamais éprouvée. On écrit le message à la main pour
    /// l'atteindre — un chemin illisible ferait poser du courrier dans un
    /// répertoire qui n'est pas celui que l'administrateur a nommé.
    #[test]
    fn un_dossier_de_file_illisible_fait_refuser() {
        use crate::ams_config_capnp::configuration;

        let bon = encode(&Configuration {
            queue: Queue {
                spool: String::from("/var/spool/ams/file"),
                ..Queue::default()
            },
            ..exemple()
        })
        .expect("encodable");
        assert!(decode(&bon).is_ok(), "le témoin doit se relire");

        let mut message = capnp::message::Builder::new_default();
        {
            let lu = capnp::serialize::read_message(
                &mut bon.as_slice(),
                capnp::message::ReaderOptions::new(),
            )
            .expect("relisible");
            message
                .set_root(lu.get_root::<configuration::Reader<'_>>().expect("racine"))
                .expect("recopiable");
            let mut ecrit = message
                .get_root::<configuration::Builder<'_>>()
                .expect("racine");
            let mut attente = ecrit.reborrow().init_queue();
            attente.set_spool(capnp::text::Reader(b"/var/\xff/file"));
        }
        let octets = capnp::serialize::write_message_to_words(&message);
        assert_eq!(decode(&octets), Err(Error::NotUtf8));
    }

    #[test]
    fn la_file_se_debogue_et_se_compare() {
        let relais = Relay { enabled: true };
        assert!(!std::format!("{relais:?}").is_empty());
        assert_ne!(relais, Relay::default());
        assert_eq!(relais.clone(), relais);

        let attente = Queue {
            spool: String::from("/x"),
            ..Queue::default()
        };
        assert!(!std::format!("{attente:?}").is_empty());
        assert_ne!(attente, Queue::default());
        assert_eq!(attente.clone(), attente);
    }

    // ── MTA-STS (RFC 8461) ──────────────────────────────────────────────────

    /// **UN FICHIER ANCIEN DÉCODE « PAS ÉVALUÉ ».**
    #[test]
    fn sans_champ_mtasts_rien_n_est_evalue() {
        let sts = Mtasts::default();
        assert!(!sts.est_configure());
        assert!(sts.anchors.is_empty() && sts.cache.is_empty());
        assert!(!exemple().mtasts.est_configure());
    }

    /// **IL FAUT LES DEUX**, et l'un sans l'autre n'évalue rien.
    #[test]
    fn l_un_sans_l_autre_n_evalue_rien() {
        let sans_cache = Mtasts {
            anchors: String::from("/etc/ssl/certs/ca-certificates.crt"),
            cache: String::new(),
        };
        assert!(!sans_cache.est_configure());
        let sans_racines = Mtasts {
            anchors: String::new(),
            cache: String::from("/var/cache/ams/mtasts"),
        };
        assert!(!sans_racines.est_configure());
        let les_deux = Mtasts {
            anchors: String::from("/etc/ssl/certs/ca-certificates.crt"),
            cache: String::from("/var/cache/ams/mtasts"),
        };
        assert!(les_deux.est_configure());
    }

    #[test]
    fn mtasts_traverse_le_format() {
        let voulu = Mtasts {
            anchors: String::from("/etc/ssl/certs/ca-certificates.crt"),
            cache: String::from("/var/cache/ams/mtasts"),
        };
        let config = Configuration {
            mtasts: voulu.clone(),
            ..exemple()
        };
        let octets = encode(&config).expect("encodable");
        let relue = decode(&octets).expect("relisible");
        assert_eq!(relue.mtasts, voulu);
        assert_eq!(relue, config);
    }

    /// **UN CHEMIN QUI N'EST PAS DE L'UTF-8 FAIT REFUSER LE FICHIER.**
    ///
    /// Ces deux champs se décodent parmi les DERNIERS : des octets au hasard
    /// échouent toujours plus tôt, et leurs gardes n'étaient donc jamais
    /// éprouvées. On écrit le message à la main pour les atteindre — un chemin
    /// illisible ferait ouvrir un fichier qui n'est pas celui qu'on a nommé,
    /// et c'est un magasin d'autorités.
    #[test]
    fn un_chemin_mtasts_illisible_fait_refuser() {
        use crate::ams_config_capnp::configuration;

        let bon = encode(&Configuration {
            mtasts: Mtasts {
                anchors: String::from("/etc/ssl/certs/ca.crt"),
                cache: String::from("/var/cache/ams/mtasts"),
            },
            ..exemple()
        })
        .expect("encodable");
        assert!(decode(&bon).is_ok(), "le témoin doit se relire");

        // Chacun des deux, à son tour.
        for quel in [0_u8, 1] {
            let mut message = capnp::message::Builder::new_default();
            {
                let lu = capnp::serialize::read_message(
                    &mut bon.as_slice(),
                    capnp::message::ReaderOptions::new(),
                )
                .expect("relisible");
                message
                    .set_root(lu.get_root::<configuration::Reader<'_>>().expect("racine"))
                    .expect("recopiable");
                let mut ecrit = message
                    .get_root::<configuration::Builder<'_>>()
                    .expect("racine");
                let mut sts = ecrit.reborrow().init_mtasts();
                if quel == 0 {
                    sts.set_anchors(capnp::text::Reader(b"/etc/\xff/ca.crt"));
                    sts.set_cache("/var/cache/ams/mtasts");
                } else {
                    sts.set_anchors("/etc/ssl/certs/ca.crt");
                    sts.set_cache(capnp::text::Reader(b"/var/\xff/mtasts"));
                }
            }
            let octets = capnp::serialize::write_message_to_words(&message);
            assert_eq!(decode(&octets), Err(Error::NotUtf8), "champ {quel}");
        }
    }

    // ── TLSRPT (RFC 8460) ───────────────────────────────────────────────────

    /// **UN FICHIER ANCIEN DÉCODE « AUCUN RAPPORT ».**
    #[test]
    fn sans_champ_tlsrpt_rien_n_est_compose() {
        let rapports = Tlsrpt::default();
        assert!(!rapports.compose());
        assert!(!rapports.envoie());
        assert!(!exemple().tlsrpt.compose());
    }

    /// **LE DRAPEAU NE GOUVERNE QUE LA REMISE**, et il faut les deux pour
    /// qu'elle ait lieu : un drapeau sans dossier ne remettrait rien, faute
    /// d'avoir composé quoi que ce soit.
    #[test]
    fn le_drapeau_seul_ne_remet_rien() {
        let sans_dossier = Tlsrpt {
            directory: String::new(),
            send: true,
        };
        assert!(!sans_dossier.compose());
        assert!(!sans_dossier.envoie());

        let depose = Tlsrpt {
            directory: String::from("/var/spool/ams/tlsrpt"),
            send: false,
        };
        assert!(depose.compose());
        assert!(!depose.envoie(), "déposé n'est pas remis");

        let remet = Tlsrpt {
            directory: String::from("/var/spool/ams/tlsrpt"),
            send: true,
        };
        assert!(remet.compose() && remet.envoie());
    }

    #[test]
    fn tlsrpt_traverse_le_format() {
        let voulu = Tlsrpt {
            directory: String::from("/var/spool/ams/tlsrpt"),
            send: true,
        };
        let config = Configuration {
            tlsrpt: voulu.clone(),
            ..exemple()
        };
        let octets = encode(&config).expect("encodable");
        let relue = decode(&octets).expect("relisible");
        assert_eq!(relue.tlsrpt, voulu);
        assert_eq!(relue, config);
    }

    /// **UN DOSSIER QUI N'EST PAS DE L'UTF-8 FAIT REFUSER LE FICHIER**, comme
    /// les autres chemins — et celui-ci se décode parmi les derniers.
    #[test]
    fn un_dossier_tlsrpt_illisible_fait_refuser() {
        use crate::ams_config_capnp::configuration;

        let bon = encode(&Configuration {
            tlsrpt: Tlsrpt {
                directory: String::from("/var/spool/ams/tlsrpt"),
                send: true,
            },
            ..exemple()
        })
        .expect("encodable");
        assert!(decode(&bon).is_ok(), "le témoin doit se relire");

        let mut message = capnp::message::Builder::new_default();
        {
            let lu = capnp::serialize::read_message(
                &mut bon.as_slice(),
                capnp::message::ReaderOptions::new(),
            )
            .expect("relisible");
            message
                .set_root(lu.get_root::<configuration::Reader<'_>>().expect("racine"))
                .expect("recopiable");
            let mut ecrit = message
                .get_root::<configuration::Builder<'_>>()
                .expect("racine");
            let mut rapports = ecrit.reborrow().init_tlsrpt();
            rapports.set_directory(capnp::text::Reader(b"/var/\xff/tlsrpt"));
            rapports.set_send(true);
        }
        let octets = capnp::serialize::write_message_to_words(&message);
        assert_eq!(decode(&octets), Err(Error::NotUtf8));
    }

    #[test]
    fn tlsrpt_se_debogue_et_se_compare() {
        let rapports = Tlsrpt {
            directory: String::from("/x"),
            send: false,
        };
        assert!(!std::format!("{rapports:?}").is_empty());
        assert_ne!(rapports, Tlsrpt::default());
        assert_eq!(rapports.clone(), rapports);
    }

    #[test]
    fn mtasts_se_debogue_et_se_compare() {
        let sts = Mtasts {
            anchors: String::from("/x"),
            cache: String::new(),
        };
        assert!(!std::format!("{sts:?}").is_empty());
        assert_ne!(sts, Mtasts::default());
        assert_eq!(sts.clone(), sts);
    }
}
