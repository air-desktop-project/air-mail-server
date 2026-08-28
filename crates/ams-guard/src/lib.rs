//! Détection de flooding et bannissement par source, **sans entrée-sortie** (C1,
//! C8).
//!
//! Le garde reçoit `(source, événement, instant)` et rend un verdict. Il ne lit
//! pas l'heure : on la lui donne. C'est ce qui permet d'éprouver une fenêtre de
//! douze heures en quelques microsecondes — indispensable pour un composant dont
//! un faux positif coupe du courrier légitime.
//!
//! # Trois décisions qui ne se devinent pas
//!
//! 1. **La clé est un préfixe, pas une adresse.** Bannir une adresse IPv6 seule
//!    ne sert à rien : le plus petit bloc qu'un fournisseur attribue est un
//!    `/64`, et le pair banni revient à l'adresse suivante. La longueur du
//!    préfixe vient de la configuration (C8).
//! 2. **La mémoire du garde est bornée par construction.** Une table qui grandit
//!    avec le nombre de sources est un épuisement de mémoire offert à qui dispose
//!    d'un `/64`. L'appelant fournit le tableau ; le garde n'alloue pas et n'en
//!    sort jamais.
//! 3. **Ce qu'on oublie est choisi.** Oublier au hasard rendrait l'attaque
//!    triviale — inonder depuis mille sources ferait disparaître son propre
//!    bannissement. Un bannissement ne s'efface jamais au profit d'un simple
//!    compteur ; voir [`Guard`].
//!
//! # La fenêtre est FIXE, et ce que cela implique
//!
//! C8 dit « x trames invalides par minute » : les compteurs se remettent à zéro
//! toutes les soixante secondes. C'est littéralement ce qui est demandé, et c'est
//! entièrement en entiers, donc éprouvable sans approximation.
//!
//! Le revers est connu : **à cheval sur deux fenêtres, un pair peut atteindre le
//! double du seuil** — `x` à la fin de l'une, `x` au début de la suivante. C'est
//! le prix d'un comptage qui ne ment pas sur ce qu'il fait. Une fenêtre glissante
//! le corrigerait, au prix d'un état plus gros et d'une arithmétique plus
//! difficile à prouver ; ce n'est pas fait, et ce n'est pas caché.
//!
//! # Ce qui n'est pas ici
//!
//! Le garde ne ferme aucune connexion et n'écrit aucun journal : il **répond**.
//! C'est à la boucle d'entrées-sorties d'agir sur ce qu'il dit.
//!
//! ```
//! use ams_guard::{Event, Guard, Instant, Slot, Source, Thresholds, Verdict};
//! use core::time::Duration;
//!
//! let seuils = Thresholds {
//!     invalid_frames_per_minute: 2,
//!     ban_duration: Duration::from_secs(3600),
//!     ..Thresholds::DEFAULT
//! };
//! let mut table = [Slot::EMPTY; 64];
//! let mut garde = Guard::new(&mut table, seuils);
//!
//! let pair = Source::V4([192, 0, 2, 1]);
//! let t0 = Instant::from_millis(0);
//!
//! // Deux trames invalides restent tolérées.
//! assert_eq!(garde.observe(pair, Event::InvalidFrame, t0), Verdict::Allow);
//! assert_eq!(garde.observe(pair, Event::InvalidFrame, t0), Verdict::Allow);
//!
//! // La troisième bannit, pour une heure.
//! assert_eq!(
//!     garde.observe(pair, Event::InvalidFrame, t0),
//!     Verdict::Banned { until: Instant::from_millis(3_600_000) }
//! );
//!
//! // Et le verdict tient, sans qu'il faille recompter.
//! assert!(matches!(
//!     garde.verdict(pair, Instant::from_millis(1_000)),
//!     Verdict::Banned { .. }
//! ));
//! ```

#![no_std]

// La crate livrée n'a ni `std` ni `alloc`. Les tests, eux, ont le droit d'allouer.
#[cfg(test)]
extern crate std;

mod guard;
mod source;
mod thresholds;

pub use guard::{Event, Guard, Instant, Slot, Verdict};
pub use source::{Key, Source};
pub use thresholds::Thresholds;
