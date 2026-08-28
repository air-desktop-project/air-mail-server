//! Ce qui peut empêcher un message d'atterrir.

use core::fmt;

use ams_index::NameError;

/// Ce qui peut empêcher un message d'atterrir.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Le système de fichiers a refusé.
    Io(std::io::Error),
    /// Un nom de fichier composé ou relu est irrecevable.
    Name(NameError),
    /// La boîte n'a plus d'UID à attribuer.
    ///
    /// Il n'y en a que `u32::MAX`. Au-delà, c'est l'`UIDVALIDITY` qui doit
    /// changer — et réattribuer un numéro déjà servi montrerait à un client un
    /// message pour un autre.
    UidExhausted,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(cause) => write!(f, "système de fichiers : {cause}"),
            Error::Name(cause) => write!(f, "nom de fichier : {cause}"),
            Error::UidExhausted => {
                f.write_str("la boîte n'a plus d'UID à attribuer ; son `UIDVALIDITY` doit changer")
            }
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

impl From<NameError> for Error {
    fn from(cause: NameError) -> Self {
        Error::Name(cause)
    }
}
