//! TLSRPT (RFC 8460) : **ce qu'on rapporte du chiffrement sortant**, sans
//! entrée-sortie (C1).
//!
//! # POURQUOI CE RAPPORT EXISTE
//!
//! Un domaine qui publie `mode: testing` dit « je m'installe, ne refusez pas
//! encore ». Sans rapport, il n'apprend rien : ses remises passent, et il ne
//! saura qu'en durcissant sa politique que la moitié du monde échouait. TLSRPT
//! est ce qui lui rend cette information — **c'est le seul mécanisme de ce
//! dépôt dont le bénéficiaire est quelqu'un d'autre.**
//!
//! Il rapporte aussi DANE : un `TLSA` mal renouvelé fait échouer les remises en
//! silence, et le domaine ne le voit qu'à son courrier qui n'arrive plus.
//!
//! # CE QUE CETTE CRATE FAIT, ET CE QU'ELLE NE PEUT PAS FAIRE
//!
//! Elle lit un `TXT`, écrit du JSON, nomme un fichier et compose un sujet. Elle
//! n'observe rien, ne compte rien et n'émet rien : **c'est l'appelant qui tient
//! le journal**, et c'est lui qui décide d'envoyer.
//!
//! # UN RAPPORT PART CHEZ UN TIERS, ET CELA SE VÉRIFIE
//!
//! §3 : quand la destination `rua` est d'un autre domaine que celui qu'on
//! rapporte, ce tiers doit avoir DIT qu'il l'accepte, en publiant
//! `<rapporté>._report._smtp._tls.<destination>`. Sans cette vérification,
//! n'importe qui publierait `rua=mailto:victime@banque.test` et ferait bombarder
//! cette adresse par tous les émetteurs du monde.
//!
//! C'est le même mécanisme que §7.1 de RFC 7489 pour DMARC, et il n'est pas plus
//! facultatif ici que là-bas.
//!
//! # CE QU'ON DIT DE NOUS-MÊMES
//!
//! `sending-mta-ip` décrit notre machine, et il est facultatif (§4.3). Il est
//! écrit tout de même : **le destinataire le connaît déjà** — c'est nous qui
//! l'avons appelé — et il lui permet de corréler avec ses propres journaux, ce
//! qui est précisément ce qu'il attend d'un rapport de diagnostic.
//!
//! # Exemple
//!
//! ```
//! use ams_tlsrpt::{Destination, Transport, parse_record};
//!
//! let mut place = [Destination::EMPTY; 4];
//! let destinations = parse_record(
//!     "v=TLSRPTv1; rua=mailto:tls@example.com,https://reports.example.net/v1",
//!     &mut place,
//! )
//! .expect("lisible");
//!
//! assert_eq!(destinations.len(), 2);
//! assert_eq!(destinations[0].transport(), Transport::Mailto);
//! assert_eq!(destinations[0].domain(), Some("example.com"));
//! assert_eq!(destinations[1].transport(), Transport::Https);
//! assert_eq!(destinations[1].domain(), Some("reports.example.net"));
//! ```

#![no_std]

// La crate livrée n'a ni `std` ni `alloc`. Les tests, eux, ont le droit d'allouer.
#[cfg(test)]
extern crate std;

mod external;
mod naming;
mod record;
mod report;

pub use external::{VERIFICATION_MAX, authorizes, needs_verification, verification_name};
pub use naming::{FILENAME_MAX, SUBJECT_MAX, filename, subject};
pub use record::{Destination, RUA_MAX, Transport, parse_record};
pub use report::{Failure, Policy, PolicyType, Report, ResultType, Summary, Writing, begin};

/// Le nom sous lequel un domaine publie sa demande de rapports (§3).
pub const TXT_PREFIX: &str = "_smtp._tls.";

/// Ce qui rend un enregistrement ou un rapport irrecevable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// L'enregistrement ne porte pas `v=TLSRPTv1`, ou aucune destination.
    BadRecord,
    /// Une valeur porte un octet qu'on refuse d'écrire dans un rapport.
    ///
    /// **Un guillemet ou une barre oblique inverse dans une chaîne JSON**
    /// écrirait une structure à notre place, dans un fichier qu'on compose et
    /// qu'on remet nous-mêmes.
    NotPrintable,
    /// Le tampon de sortie ne suffit pas.
    BufferTooSmall,
}
