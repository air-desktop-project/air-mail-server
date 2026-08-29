//! Les rapports (RFC 7489 §7) : où les envoyer, et ce qu'on y écrit.
//!
//! # Le rapport est ce qui rend DMARC praticable
//!
//! Une politique se durcit en trois temps : `p=none` pour voir, `p=quarantine`
//! pour éprouver, `p=reject` pour fermer. **Le premier temps ne sert à rien
//! sans rapports** — voir, c'est recevoir de la part des receveurs le compte de
//! ce qui a été émis en son nom. Un domaine qui ne reçoit pas de rapports reste
//! à `p=none` pour toujours, ou passe à `p=reject` en espérant ; les deux sont
//! de mauvaises fins.
//!
//! # Quatre choses, et elles sont séparées exprès
//!
//! - [`uri`] lit `rua=` et `ruf=` : *où* envoyer, et jusqu'à quelle taille.
//! - [`external`] répond à *a-t-on le droit* — sans quoi DMARC est une arme.
//! - [`aggregate`] compose le XML : *ce qu'on dit*.
//! - [`failure`] compose un rapport d'échec : *ce qu'on dit d'UN message* — et
//!   c'est celui-là qui porte le courrier de quelqu'un.
//! - [`naming`] écrit le nom du fichier et le sujet : *comment il se range*.
//!
//! Aucune ne fait d'entrée-sortie (C1). Composer un rapport et l'envoyer sont
//! deux gestes, et le second appartient à l'étage 3.

pub mod aggregate;
pub mod external;
pub mod failure;
pub mod naming;
pub mod uri;
