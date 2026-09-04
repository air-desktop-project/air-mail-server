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
    /// L'index de la boîte n'a pas pu être encodé.
    ///
    /// Un défaut de la bibliothèque, jamais une configuration : les deux
    /// nombres qu'il porte sont non nuls par construction. Il est tout de même
    /// nommé plutôt que supposé impossible — c'est une remise qui échoue, et le
    /// pair doit l'apprendre.
    IndexUnwritable,

    /// La boîte n'a plus d'UID à attribuer.
    ///
    /// Il n'y en a que `u32::MAX`. Au-delà, c'est l'`UIDVALIDITY` qui doit
    /// changer — et réattribuer un numéro déjà servi montrerait à un client un
    /// message pour un autre.
    UidExhausted,

    /// Ce chemin n'est pas une boîte, et [`crate::Maildir::open_existing`] a
    /// refusé de la créer.
    ///
    /// # Pourquoi ce n'est pas un `Io(NotFound)`
    ///
    /// « Le fichier manque » et « ce n'est pas une boîte » n'appellent pas la
    /// même réponse. Un répertoire peut exister sans `cur/` — §6.3.5 de RFC 9051
    /// en laisse derrière un effacement —, et un chemin tapé de travers désigne
    /// souvent un répertoire bien réel. Les confondre enverrait chercher au
    /// mauvais endroit.
    NotAMailbox,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(cause) => write!(f, "système de fichiers : {cause}"),
            Error::Name(cause) => write!(f, "nom de fichier : {cause}"),
            Error::IndexUnwritable => f.write_str("l'index de la boîte n'a pas pu être encodé"),
            Error::NotAMailbox => {
                f.write_str("ce chemin n'est pas une boîte : aucun `cur/` ne s'y trouve")
            }
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
