//! MTA-STS (RFC 8461) : **ce qu'un domaine exige de qui lui écrit**, sans
//! entrée-sortie (C1).
//!
//! # LE MÊME PROBLÈME QUE DANE, RÉSOLU AUTREMENT
//!
//! Le serveur qu'on joint est désigné par un `MX`, c'est-à-dire par quiconque
//! peut répondre à cette question. DANE fait signer la réponse par le domaine
//! lui-même ; MTA-STS, lui, **déplace la question hors du DNS** : le domaine
//! publie une politique sur `https://mta-sts.<domaine>/`, et c'est la WebPKI qui
//! atteste que cette politique vient bien de lui.
//!
//! Le DNS n'y sert plus qu'à une chose : dire que la politique A CHANGÉ, par un
//! identifiant dans un `TXT`. **Cet identifiant n'a pas besoin d'être
//! authentique** — au pire, un tiers nous fait re-télécharger une politique
//! qu'on a déjà, ou nous cache un changement dont le cache nous protège.
//!
//! # CE QUE CETTE CRATE FAIT, ET CE QU'ELLE NE PEUT PAS FAIRE
//!
//! Elle lit un `TXT`, lit une politique, dit si un `MX` y correspond, et nomme
//! une entrée de cache. Elle n'ouvre aucune connexion, ne valide aucun
//! certificat et ne lit pas l'heure : **c'est l'appelant qui garantit que la
//! politique vient d'un `https://` vérifié**, et c'est le point le plus
//! important de tout ce module.
//!
//! Une politique récupérée sans vérifier le certificat ne vaut RIEN : n'importe
//! qui l'aurait écrite, et il l'aurait écrite pour désigner ses propres
//! serveurs.
//!
//! # LE CACHE EST LA PROTECTION, PAS UNE OPTIMISATION
//!
//! §5 : un attaquant qui peut bloquer le `https://` obtiendrait, sans cache, une
//! remise sans politique — c'est-à-dire exactement le déclassement que MTA-STS
//! existe pour fermer. **Une politique en cache reste valable jusqu'à sa
//! péremption, quoi qu'il arrive au réseau** : ni un `TXT` disparu, ni un
//! `https://` injoignable ne la retirent.
//!
//! C'est pourquoi [`Entry`] existe ici : ce qu'un nom de fichier porte est une
//! décision, pas un détail d'implémentation.
//!
//! # DANE L'EMPORTE
//!
//! §2 : quand un domaine publie les deux, c'est DANE qui décide. Cette crate ne
//! le sait pas — c'est l'appelant qui n'appelle pas — mais cela vaut d'être écrit
//! là où on lit MTA-STS.
//!
//! # Exemple
//!
//! ```
//! use ams_mtasts::{Mode, parse_policy};
//!
//! let texte = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.net\nmax_age: 604800\n";
//! let mut place = [""; 8];
//! let politique = parse_policy(texte, &mut place).expect("lisible");
//!
//! assert_eq!(politique.mode(), Mode::Enforce);
//! assert_eq!(politique.max_age(), 604_800);
//! assert!(politique.allows("mail.example.com"));
//! // Un joker couvre EXACTEMENT une étiquette.
//! assert!(politique.allows("mx1.example.net"));
//! assert!(!politique.allows("a.b.example.net"));
//! assert!(!politique.allows("mail.ailleurs.test"));
//! ```

#![no_std]

// La crate livrée n'a ni `std` ni `alloc`. Les tests, eux, ont le droit d'allouer.
#[cfg(test)]
extern crate std;

mod entry;
mod policy;
mod record;

pub use entry::{Entry, NAME_MAX, parse_name, write_name};
pub use policy::{MX_MAX, Mode, Policy, parse_policy};
pub use record::parse_id;

/// Le préfixe du `TXT` qui porte l'identifiant de politique (§3.1).
pub const TXT_PREFIX: &str = "_mta-sts.";

/// Le préfixe de l'hôte qui sert la politique (§3.2).
pub const HOST_PREFIX: &str = "mta-sts.";

/// Le chemin où la politique se trouve (§3.2).
pub const POLICY_PATH: &str = "/.well-known/mta-sts.txt";

/// Ce qui rend une politique ou un cache irrecevable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// La politique ne porte pas `version: STSv1`.
    ///
    /// **Une version qu'on ne connaît pas se refuse**, et ne se devine pas : une
    /// politique de demain pourrait dire l'inverse de celle d'aujourd'hui.
    BadVersion,
    /// Le mode manque, ou n'est aucun des trois.
    BadMode,
    /// Aucun `mx`, ou plus que [`MX_MAX`], ou un motif qui n'en est pas un.
    BadMx,
    /// `max_age` manque, vaut zéro, ou dépasse ce que §3.2 permet.
    BadMaxAge,
    /// Une ligne qui n'est ni vide, ni `clef: valeur`.
    Malformed,
    /// Le nom d'une entrée de cache ne peut pas devenir un nom de fichier.
    BadName,
    /// Le tampon de sortie ne suffit pas.
    BufferTooSmall,
}
