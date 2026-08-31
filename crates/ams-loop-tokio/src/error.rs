//! Ce qui peut arrêter une connexion.

use core::fmt;

/// Ce qui peut arrêter une connexion, ou empêcher le serveur de démarrer.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Le processus s'exécute avec les privilèges du superutilisateur.
    ///
    /// **Refusé, et ce n'est pas un réglage** (C10). Les ports privilégiés
    /// s'atteignent par une règle de redirection du pare-feu, posée par
    /// l'administrateur hors du serveur. Il n'y a donc aucun code d'abandon de
    /// privilèges ici — et le chemin le plus sûr est celui qui n'existe pas.
    RunningAsRoot,

    /// La configuration annonce une extension que cette boucle ne sait pas
    /// conduire.
    ///
    /// Refusé **au démarrage**, et pas au milieu d'une conversation : un serveur
    /// qui annoncerait `STARTTLS` puis refuserait de chiffrer aurait déjà menti à
    /// son pair.
    CapabilityNotSupported,

    /// Le pair n'a rien envoyé dans le délai imparti.
    Timeout,

    /// Une erreur d'entrée-sortie.
    Io(std::io::Error),

    /// La session a refusé quelque chose à l'appelant — donc à cette boucle.
    Session(ams_session::Error),

    /// La session POP3 a refusé quelque chose à cette boucle.
    ///
    /// Un vocabulaire séparé, comme du côté de la session : celui de SMTP parle
    /// de phase de données et de destinataires, dont POP3 n'a que faire.
    Pop3(ams_session::pop3::Error),

    /// La session IMAP a refusé quelque chose à cette boucle.
    ///
    /// Un vocabulaire séparé, comme les deux autres : celui d'IMAP parle
    /// d'échange SASL et de session close, dont SMTP et POP3 n'ont que faire.
    Imap(ams_session::imap::Error),

    /// Le pair n'a pas annoncé `h2` par ALPN.
    ///
    /// §3.4 de RFC 9113 : un client qui veut parler HTTP/2 sur TLS l'annonce.
    /// **On refuse ici plutôt qu'après**, parce que refuser après obligerait à
    /// répondre dans un cadrage qu'on ne sait pas écrire.
    Alpn,

    /// Le pair parle mal HTTP/2.
    ///
    /// Une seule variante pour toutes les fautes de cadrage : ce que la boucle
    /// en fait est toujours le même — un `GOAWAY`, puis on s'en va. Le code
    /// exact est parti au pair, qui est le seul à en avoir l'usage.
    Http,

    /// Le videur a banni cette source (C8).
    Refused,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::RunningAsRoot => f.write_str(
                "le serveur refuse de s'exécuter en tant que superutilisateur (C10) ; \
                 les ports privilégiés s'atteignent par une redirection de pare-feu",
            ),
            Error::CapabilityNotSupported => f.write_str(
                "la configuration annonce une extension que cette boucle ne sait pas conduire",
            ),
            Error::Timeout => f.write_str("le pair n'a rien envoyé dans le délai imparti"),
            Error::Alpn => f.write_str("le pair n'a pas annoncé `h2` par ALPN (§3.4 de RFC 9113)"),
            Error::Http => f.write_str("le pair parle mal HTTP/2"),
            Error::Refused => f.write_str("le videur a banni cette source"),
            Error::Io(cause) => write!(f, "entrée-sortie : {cause}"),
            Error::Session(cause) => write!(f, "session : {cause}"),
            Error::Pop3(cause) => write!(f, "session POP3 : {cause}"),
            Error::Imap(cause) => write!(f, "session IMAP : {cause}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(cause) => Some(cause),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(cause: std::io::Error) -> Self {
        Error::Io(cause)
    }
}

impl From<ams_session::Error> for Error {
    fn from(cause: ams_session::Error) -> Self {
        Error::Session(cause)
    }
}

impl From<ams_session::pop3::Error> for Error {
    fn from(cause: ams_session::pop3::Error) -> Self {
        Error::Pop3(cause)
    }
}

impl From<ams_session::imap::Error> for Error {
    fn from(cause: ams_session::imap::Error) -> Self {
        Error::Imap(cause)
    }
}
