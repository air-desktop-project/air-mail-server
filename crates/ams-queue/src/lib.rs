//! La file de réémission sortante : **quand réessayer, et quand renoncer** —
//! sans entrée-sortie (C1).
//!
//! # Ce que cette crate décide, et ce qu'elle ne fait pas
//!
//! Elle ne lit ni n'écrit aucun fichier, n'ouvre aucune connexion et ne lit pas
//! l'heure : on la lui donne. Elle répond à trois questions, et à elles seules :
//!
//! 1. **Comment s'appelle une entrée de file** — [`Entry`], et son nom de
//!    fichier, qui porte tout l'état de la reprise. Il n'y a pas de base de
//!    données : ce que le nom ne dit pas, un redémarrage l'oublie.
//! 2. **Quand réessayer après un échec** — [`Backoff`], une attente qui DOUBLE
//!    jusqu'à un plafond.
//! 3. **Quand renoncer** — la péremption, et le rapport de non-remise qui suit.
//!
//! # POURQUOI L'ÉTAT TIENT DANS UN NOM DE FICHIER
//!
//! Une file d'attente qui perd son état perd du courrier, ou le remet deux fois.
//! Un index séparé — une base, un journal — serait un second endroit à tenir
//! cohérent avec le premier, et une panne au mauvais moment les ferait diverger.
//!
//! Le nom, lui, change par un `rename()` : **une opération que le système de
//! fichiers rend atomique**. Une entrée existe sous exactement un nom à tout
//! instant, et ce nom dit combien de fois elle a échoué et quand la reprendre.
//! C'est la même discipline que Maildir, pour la même raison.
//!
//! # LA PÉREMPTION SE JUGE APRÈS L'ESSAI, PAS AVANT
//!
//! [`Backoff::after_failure`] est le SEUL endroit qui décide d'abandonner, et il
//! n'est consulté qu'une fois l'essai fait. Un message qui a dormi pendant une
//! panne du serveur a donc droit à un dernier essai, plutôt qu'à un rapport de
//! non-remise écrit sans avoir rien tenté — le pair était peut-être revenu.
//!
//! Deux règles auraient fini par se contredire : celle qui refuse d'essayer et
//! celle qui décide d'abandonner. Il n'y en a qu'une.
//!
//! # Exemple
//!
//! ```
//! use ams_queue::{Backoff, Decision};
//!
//! let reprise = Backoff::DEFAULT;
//! let depot = 1_000_000_u64;
//!
//! // Le premier échec fait attendre le quart d'heure de départ.
//! assert_eq!(
//!     reprise.after_failure(depot, 1, depot),
//!     Decision::Retry { at: depot + 900 }
//! );
//! // Le quatrième attend huit fois plus.
//! assert_eq!(
//!     reprise.after_failure(depot, 4, depot),
//!     Decision::Retry { at: depot + 7_200 }
//! );
//! // Et cinq jours après le dépôt, on renonce.
//! assert_eq!(
//!     reprise.after_failure(depot, 12, depot + 5 * 86_400),
//!     Decision::GiveUp
//! );
//! ```

#![no_std]

// La crate livrée n'a ni `std` ni `alloc`. Les tests, eux, ont le droit d'allouer.
#[cfg(test)]
extern crate std;

mod backoff;
mod envelope;
mod name;

pub use backoff::{Backoff, Decision};
pub use envelope::{
    Envelope, RECIPIENTS_MAX, Report, envelope_max, parse_envelope, write_envelope,
};
pub use name::{Entry, NAME_MAX, parse_name, write_name};

/// Ce qui rend une entrée de file irrecevable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// L'identifiant porte autre chose que des lettres, des chiffres ou un
    /// tiret — ou il est vide, ou trop long.
    ///
    /// **IL DEVIENT UN NOM DE FICHIER**, et c'est pourquoi le jeu est aussi
    /// étroit : un `/` y désignerait un autre répertoire, un `.` en tête le
    /// cacherait, et un `!` casserait le découpage du nom.
    BadIdentifier,
    /// Une adresse est vide, trop longue, ou porte un octet qui n'a rien à faire
    /// dans un fichier de ligne à ligne — un `CR`, un `LF`, un octet non ASCII.
    BadAddress,
    /// Aucun destinataire, ou plus que [`RECIPIENTS_MAX`].
    BadRecipients,
    /// Le tampon de sortie ne suffit pas.
    BufferTooSmall,
}
