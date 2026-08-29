//! Le vocabulaire des commandes (RFC 9051 §6).
//!
//! # Ce module RECONNAÎT ; il ne décide de rien
//!
//! Savoir qu'un verbe existe et savoir qu'il est permis à cet instant sont deux
//! choses. `SELECT` avant authentification est une commande parfaitement
//! formée : c'est la SESSION qui la refuse, parce qu'elle seule connaît l'état.
//! Mélanger les deux ferait un analyseur qui doit connaître l'état, et un état
//! qui doit connaître la grammaire.
//!
//! # Les verbes retirés par IMAP4rev2 sont RECONNUS, pas servis
//!
//! `LSUB` et `CHECK` ont disparu de la RFC 9051 (§A), et les clients déployés
//! les envoient encore. Les reconnaître permet de répondre « je sais ce que
//! c'est, et je ne le fais pas » plutôt que « je ne comprends pas » — la
//! différence entre un client qui se rabat et un client qui abandonne.

use crate::{Error, Limits, Tag};

/// Un verbe d'IMAP4rev2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Command {
    /// `CAPABILITY` — ce que ce serveur sait faire.
    Capability,
    /// `NOOP` — rien, et l'occasion d'envoyer ce qui a changé.
    Noop,
    /// `LOGOUT` — la fin.
    Logout,
    /// `STARTTLS` — monter en chiffrement.
    StartTls,
    /// `AUTHENTICATE` — s'authentifier par SASL.
    Authenticate,
    /// `LOGIN` — s'authentifier en clair.
    ///
    /// **Sans chiffrement, c'est un mot de passe sur le fil.** La RFC 9051
    /// §6.2.3 impose de l'annoncer indisponible (`LOGINDISABLED`) tant que la
    /// connexion n'est pas protégée ; la session s'en charge.
    Login,
    /// `ENABLE` — activer une extension.
    Enable,
    /// `SELECT` — ouvrir une boîte en lecture et écriture.
    Select,
    /// `EXAMINE` — l'ouvrir en lecture seule.
    Examine,
    /// `CREATE` — créer une boîte.
    Create,
    /// `DELETE` — en supprimer une.
    Delete,
    /// `RENAME` — la renommer.
    Rename,
    /// `SUBSCRIBE` — s'abonner.
    Subscribe,
    /// `UNSUBSCRIBE` — se désabonner.
    Unsubscribe,
    /// `LIST` — énumérer les boîtes.
    List,
    /// `NAMESPACE` — dire où elles vivent.
    Namespace,
    /// `STATUS` — l'état d'une boîte sans l'ouvrir.
    Status,
    /// `APPEND` — y déposer un message.
    Append,
    /// `IDLE` — attendre que quelque chose arrive.
    Idle,
    /// `CLOSE` — fermer la boîte, en purgeant les effacés.
    Close,
    /// `UNSELECT` — la fermer sans purger.
    Unselect,
    /// `EXPUNGE` — purger les effacés.
    Expunge,
    /// `SEARCH` — chercher.
    Search,
    /// `FETCH` — lire.
    Fetch,
    /// `STORE` — marquer.
    Store,
    /// `COPY` — recopier ailleurs.
    Copy,
    /// `MOVE` — déplacer.
    Move,
    /// `UID` — les mêmes, mais par UID.
    Uid,
    /// `LSUB` — **retiré par IRFC 9051 §A**, encore envoyé par les clients.
    Lsub,
    /// `CHECK` — **retiré par la RFC 9051 §A**, encore envoyé par les clients.
    Check,
}

impl Command {
    /// Lit un verbe.
    ///
    /// Les verbes sont insensibles à la casse (RFC 9051 §9, `command`).
    ///
    /// # Errors
    ///
    /// [`Error::UnknownCommand`].
    pub fn parse(verbe: &[u8]) -> Result<Self, Error> {
        const VOCABULAIRE: &[(&[u8], Command)] = &[
            (b"CAPABILITY", Command::Capability),
            (b"NOOP", Command::Noop),
            (b"LOGOUT", Command::Logout),
            (b"STARTTLS", Command::StartTls),
            (b"AUTHENTICATE", Command::Authenticate),
            (b"LOGIN", Command::Login),
            (b"ENABLE", Command::Enable),
            (b"SELECT", Command::Select),
            (b"EXAMINE", Command::Examine),
            (b"CREATE", Command::Create),
            (b"DELETE", Command::Delete),
            (b"RENAME", Command::Rename),
            (b"SUBSCRIBE", Command::Subscribe),
            (b"UNSUBSCRIBE", Command::Unsubscribe),
            (b"LIST", Command::List),
            (b"NAMESPACE", Command::Namespace),
            (b"STATUS", Command::Status),
            (b"APPEND", Command::Append),
            (b"IDLE", Command::Idle),
            (b"CLOSE", Command::Close),
            (b"UNSELECT", Command::Unselect),
            (b"EXPUNGE", Command::Expunge),
            (b"SEARCH", Command::Search),
            (b"FETCH", Command::Fetch),
            (b"STORE", Command::Store),
            (b"COPY", Command::Copy),
            (b"MOVE", Command::Move),
            (b"UID", Command::Uid),
            (b"LSUB", Command::Lsub),
            (b"CHECK", Command::Check),
        ];
        VOCABULAIRE
            .iter()
            .find(|(mot, _)| mot.eq_ignore_ascii_case(verbe))
            .map(|(_, verbe)| *verbe)
            .ok_or(Error::UnknownCommand)
    }

    /// Ce verbe a-t-il été retiré par IMAP4rev2 ?
    ///
    /// La session en fait ce qu'elle veut ; la grammaire se contente de le
    /// savoir.
    #[must_use]
    pub fn is_obsolete(self) -> bool {
        matches!(self, Self::Lsub | Self::Check)
    }
}

/// Une commande lue : son tag, son verbe, et ses arguments **bruts**.
///
/// Les arguments ne sont pas analysés ici : `FETCH`, `SEARCH` et `STORE` ont
/// chacun leur grammaire, et les mêler ferait un module que personne ne relit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Line<'a> {
    /// Le tag, vérifié.
    pub tag: Tag<'a>,
    /// Le verbe.
    pub command: Command,
    /// Ce qui suit le verbe, `CRLF` final retiré. Vide s'il n'y a rien.
    pub arguments: &'a [u8],
}

impl<'a> Line<'a> {
    /// Lit une commande entière, telle que
    /// [`CommandReader`](crate::CommandReader) l'a délimitée.
    ///
    /// # Errors
    ///
    /// Voir [`Error`] : tag absent ou irrecevable, verbe absent ou inconnu.
    pub fn parse(entree: &'a [u8], limits: &Limits) -> Result<Self, Error> {
        let corps = entree.strip_suffix(b"\r\n").unwrap_or(entree);
        let (mot, reste) = decouper(corps);
        let tag = Tag::parse(mot, limits)?;
        let (verbe, arguments) = decouper(reste);
        if verbe.is_empty() {
            return Err(Error::MissingCommand);
        }
        Ok(Self {
            tag,
            command: Command::parse(verbe)?,
            arguments,
        })
    }
}

/// Coupe au premier espace, et rend les deux morceaux.
fn decouper(entree: &[u8]) -> (&[u8], &[u8]) {
    match entree.iter().position(|octet| *octet == b' ') {
        Some(rang) => (
            entree.get(..rang).unwrap_or_default(),
            entree.get(rang.saturating_add(1)..).unwrap_or_default(),
        ),
        None => (entree, &[]),
    }
}

#[cfg(test)]
mod tests;
