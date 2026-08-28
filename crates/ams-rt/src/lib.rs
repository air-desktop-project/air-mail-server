//! Traits d'exécution : écoute, flux, horloge.
//!
//! Cette crate est la **couture** du projet. Elle ne contient aucune
//! implémentation : elle décrit ce que le serveur attend de son environnement —
//! accepter une connexion, lire et écrire des octets, lire l'heure — pour que ce
//! qui fournit ces services soit remplaçable.
//!
//! Aujourd'hui la seule implémentation est [`ams-rt-std`], adossée à la
//! bibliothèque standard. Le portage vers le stack Air consistera à en écrire une
//! seconde ; aucune crate `ams-proto-*` ni le serveur lui-même n'auront à changer.
//!
//! Les traits sont volontairement décrits en `&[u8]` / `&mut [u8]` et non en
//! [`std::io::Read`] / [`std::io::Write`] : `std::io` n'existe pas sur la cible
//! Air. C'est le prix — modeste — de la couture.
//!
//! [`ams-rt-std`]: https://github.com/air-desktop-project/air-mail-server

#![no_std]

use core::fmt;

/// Ce qui peut échouer dans une opération d'exécution.
///
/// La liste est **délibérément courte** : elle ne dit que ce sur quoi l'appelant
/// peut agir différemment. Le détail propre à une implémentation appartient à
/// cette implémentation, pas à la couture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Le pair a fermé la connexion.
    Closed,
    /// L'opération aurait bloqué et l'appelant a demandé à ne pas bloquer.
    WouldBlock,
    /// L'opération a été interrompue avant d'avoir rien fait ; la réessayer est
    /// licite.
    Interrupted,
    /// L'environnement a refusé l'opération, pour une raison qui lui est propre.
    Refused,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let texte = match self {
            Error::Closed => "connexion fermée par le pair",
            Error::WouldBlock => "l'opération aurait bloqué",
            Error::Interrupted => "opération interrompue",
            Error::Refused => "opération refusée par l'environnement",
        };
        f.write_str(texte)
    }
}

/// Résultat d'une opération d'exécution.
pub type Result<T> = core::result::Result<T, Error>;

/// Un flux d'octets bidirectionnel — une connexion acceptée.
pub trait Stream {
    /// Lit au plus `buf.len()` octets. Un retour de `0` signifie que le pair a
    /// fermé son côté en écriture ; ce n'est pas une erreur.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Écrit au plus `buf.len()` octets et rend le nombre effectivement écrit.
    /// Une écriture partielle est normale : l'appelant rappelle.
    fn write(&mut self, buf: &[u8]) -> Result<usize>;

    /// Pousse vers le pair ce qui aurait été retenu en tampon.
    fn flush(&mut self) -> Result<()>;
}

/// Une source de connexions entrantes.
pub trait Listener {
    /// Le type de flux que cet écouteur produit.
    type Stream: Stream;

    /// Attend la prochaine connexion et la rend.
    fn accept(&mut self) -> Result<Self::Stream>;
}

/// L'heure murale, en secondes depuis l'époque Unix.
///
/// Un serveur de courrier horodate — en-têtes `Received`, dates `INTERNALDATE`,
/// expiration des jetons. Passer l'horloge par un trait rend ces chemins
/// testables sans attendre, et sans dépendre de l'heure de la machine de test.
pub trait Clock {
    /// Secondes écoulées depuis 1970-01-01T00:00:00Z, hors secondes
    /// intercalaires.
    fn now_unix_seconds(&self) -> i64;
}
