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
            Error::Io(cause) => write!(f, "entrée-sortie : {cause}"),
            Error::Session(cause) => write!(f, "session : {cause}"),
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
