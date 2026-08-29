//! Ce que le fichier de configuration porte, et comment il se lit.

use alloc::string::{String, ToString as _};
use alloc::vec::Vec;
use core::fmt;

use ams_guard::Thresholds;
use ams_proto_smtp::{ClientId, Limits};
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
}

impl Dmarc {
    /// Ce service évalue-t-il DMARC ?
    #[must_use]
    pub fn est_configure(&self) -> bool {
        !self.public_suffix_list.is_empty()
    }

    /// Ce service compose-t-il des rapports ?
    ///
    /// **Évaluer et rapporter sont deux services distincts.** Un serveur peut
    /// très bien opposer les politiques sans rien rapporter ; l'inverse — des
    /// rapports sans évaluation — n'a rien à écrire, et c'est pourquoi les deux
    /// conditions sont exigées.
    #[must_use]
    pub fn rapporte(&self) -> bool {
        self.est_configure() && !self.report_directory.is_empty()
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
    /// SPF : les résolveurs, et ce qu'on fait du verdict.
    pub spf: Spf,
    /// DMARC : la liste des suffixes publics, et ce qu'on fait du verdict.
    pub dmarc: Dmarc,
    /// Le fichier de comptes, ou une chaîne vide.
    ///
    /// Vide, le serveur n'annonce pas `AUTH` : il n'a personne à qui répondre
    /// oui. Séparé de ce fichier-ci — voir `ams-accounts.capnp` pour les trois
    /// raisons.
    pub accounts: String,
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
            ban_duration: core::time::Duration::from_secs(u64::from(garde.get_ban_seconds())),
            ipv4_prefix_bits: garde.get_ipv4_prefix_bits(),
            ipv6_prefix_bits: garde.get_ipv6_prefix_bits(),
        },
        tracked_sources: taille_u32(garde.get_tracked_sources()),
        timeouts: Timeouts {
            command_seconds: delais.get_command_seconds(),
            data_seconds: delais.get_data_seconds(),
        },
        tls,
        spf,
        dmarc,
        accounts: comptes,
        listen_pop3: ecoute_pop3,
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
        }
        {
            let mut chiffrement = ecrit.reborrow().init_tls();
            chiffrement.set_certificate_chain_path(&config.tls.certificate_chain_path);
            chiffrement.set_private_key_path(&config.tls.private_key_path);
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
        }
        ecrit.set_accounts(&config.accounts);
        ecrit.set_listen_pop3(&config.listen_pop3);
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
        Configuration, Dmarc, Enforcement, Error, Spf, TRAVERSAL_LIMIT_WORDS, Timeouts, Tls,
        decode, encode,
    };
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
            timeouts: Timeouts {
                command_seconds: 300,
                data_seconds: 600,
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
            accounts: String::new(),
            listen_pop3: String::new(),
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

    #[test]
    fn le_chemin_des_comptes_traverse_le_format() {
        let original = exemple_chiffrant();
        let relue = decode(&encode(&original).expect("encodable")).expect("relisible");
        assert_eq!(relue.accounts, "/etc/ams/comptes.bin");
        assert_eq!(relue.listen_pop3, "127.0.0.1:2110");
        // Et son absence se lit à une chaîne vide, pas à un drapeau.
        let sans = decode(&encode(&exemple()).expect("encodable")).expect("relisible");
        assert!(sans.accounts.is_empty());
        assert!(sans.listen_pop3.is_empty());
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
            ban_duration: Duration::from_secs(14),
            ipv4_prefix_bits: 24,
            ipv6_prefix_bits: 48,
        };
        original.timeouts = Timeouts {
            command_seconds: 15,
            data_seconds: 16,
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

    #[test]
    fn la_section_dmarc_traverse_le_format() {
        let mut original = exemple();
        assert!(!original.dmarc.est_configure());
        assert!(!original.dmarc.rapporte());
        original.dmarc = Dmarc {
            public_suffix_list: String::from("/etc/ams/psl.dat"),
            enforcement: Enforcement::Enforce,
            report_directory: String::from("/var/spool/ams/rapports"),
            report_org_name: String::from("mail.example.com"),
            report_email: String::from("dmarc@example.com"),
            report_interval_seconds: 3_600,
        };
        let octets = encode(&original).expect("encodable");
        let relue = decode(&octets).expect("relisible");
        assert_eq!(relue.dmarc, original.dmarc);
        assert!(relue.dmarc.est_configure());
        assert!(relue.dmarc.rapporte());
        assert!(!alloc::format!("{:?}", relue.dmarc).is_empty());
    }

    /// **Évaluer et rapporter sont deux services distincts.** Un dossier sans
    /// liste de suffixes ne rapporterait rien, puisqu'il n'y aurait rien à
    /// rapporter — et une liste sans dossier évalue sans rien écrire.
    #[test]
    fn rapporter_demande_les_deux() {
        let mut config = exemple();
        config.dmarc.report_directory = String::from("/var/spool/ams/rapports");
        assert!(!config.dmarc.est_configure());
        assert!(!config.dmarc.rapporte());
        config.dmarc.public_suffix_list = String::from("/etc/ams/psl.dat");
        assert!(config.dmarc.rapporte());
        config.dmarc.report_directory.clear();
        assert!(config.dmarc.est_configure());
        assert!(!config.dmarc.rapporte());
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
        assert!(!relue.dmarc.est_configure());
        assert_eq!(relue.dmarc.enforcement, Enforcement::Enforce);
    }
}
