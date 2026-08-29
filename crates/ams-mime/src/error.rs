//! Ce qui rend un message irrecevable.

use core::fmt;

/// Ce qui rend un message irrecevable.
///
/// # Les numéros de ligne sont un DIAGNOSTIC, jamais un index
///
/// Le champ `line` de ces variantes sert à dire *où* à un humain. Il est compté
/// en saturant, et n'est utilisé pour indexer nulle part — sans quoi une
/// saturation deviendrait une lecture au mauvais endroit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Un `CR` non suivi d'un `LF`.
    ///
    /// Refusé, et ce refus est **le cœur du sujet**. Les MTA qui traitent un `CR`
    /// ou un `LF` isolé comme une fin de ligne ne s'accordent pas entre eux sur
    /// lesquels — et c'est exactement la faille qui a rendu la contrebande SMTP
    /// possible en 2023 : un message que deux serveurs découpent différemment
    /// permet d'en faire passer un second, invisible au premier.
    BareCarriageReturn {
        /// Ligne où le `CR` isolé a été vu (diagnostic).
        line: usize,
    },

    /// Un `LF` non précédé d'un `CR`. Refusé pour la même raison.
    BareLineFeed {
        /// Ligne où le `LF` isolé a été vu (diagnostic).
        line: usize,
    },

    /// Une ligne dépasse [`Limits::max_line_octets`](crate::Limits::max_line_octets).
    LineTooLong {
        /// Ligne fautive (diagnostic).
        line: usize,
        /// La borne franchie.
        limit: usize,
    },

    /// Aucune ligne vide ne sépare l'en-tête du corps.
    MissingSeparator,

    /// Un champ d'adresse ne porte pas d'adresse lisible.
    NoAddress,

    /// Un champ d'adresse en porte plusieurs.
    ///
    /// RFC 5322 l'autorise ; RFC 7489 §6.6.1 laisse le receveur refuser. C'est
    /// ce qu'on fait : **avec deux auteurs, il y a deux domaines, deux
    /// politiques, et rien pour dire laquelle s'applique.** Choisir la première
    /// reviendrait à laisser l'expéditeur choisir laquelle on vérifie.
    MultipleAddresses,

    /// Le bloc d'en-tête commence par une continuation, qui ne continue rien.
    FoldedFirstField {
        /// Ligne fautive (diagnostic).
        line: usize,
    },

    /// Une ligne de champ ne porte pas de deux-points.
    MissingColon {
        /// Ligne fautive (diagnostic).
        line: usize,
    },

    /// Une ligne de champ commence par un deux-points : le nom est vide.
    EmptyFieldName {
        /// Ligne fautive (diagnostic).
        line: usize,
    },

    /// Un nom de champ porte un octet hors de `%d33-126`.
    ///
    /// L'espace en fait partie : `From : x` est irrecevable, et le refuser ferme
    /// une divergence d'interprétation de plus entre implémentations.
    InvalidFieldName {
        /// Ligne fautive (diagnostic).
        line: usize,
    },

    /// Plus de champs que [`Limits::max_fields`](crate::Limits::max_fields).
    TooManyFields {
        /// La borne franchie.
        limit: usize,
    },

    /// Bloc d'en-tête plus gros que
    /// [`Limits::max_header_octets`](crate::Limits::max_header_octets).
    HeaderTooLong {
        /// La borne franchie.
        limit: usize,
    },

    /// Le tampon offert ne suffit pas à ce qu'on veut y écrire.
    ///
    /// Ce n'est pas une faute de format : c'est l'appelant qui n'a pas donné
    /// assez de place. Voir `base64_max` et `report_mail_max`.
    BufferTooSmall,

    /// Une valeur porte un octet qu'on refuse d'écrire dans un message.
    ///
    /// **Un `CRLF` dans une adresse ou dans un sujet écrirait des en-têtes à
    /// notre place** — dans un message qu'on compose et qu'on remet nous-mêmes.
    /// Seul l'ASCII imprimable passe, et pour les en-têtes seulement lui.
    NotPrintable,

    /// Le délimiteur de parties figure dans une partie.
    ///
    /// Un `multipart` dont le délimiteur apparaît dans le contenu ne se découpe
    /// plus là où son auteur croyait : le destinataire lit une pièce jointe
    /// tronquée, ou une partie de plus. On refuse de composer plutôt que
    /// d'émettre un message dont on ne sait pas ce qu'il sera lu.
    BoundaryInContent,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BareCarriageReturn { line } => {
                write!(f, "ligne {line} : CR isolé, non suivi d'un LF")
            }
            Error::BareLineFeed { line } => {
                write!(f, "ligne {line} : LF isolé, non précédé d'un CR")
            }
            Error::LineTooLong { line, limit } => {
                write!(f, "ligne {line} : plus de {limit} octets")
            }
            Error::BufferTooSmall => f.write_str("le tampon offert ne suffit pas"),
            Error::NotPrintable => {
                f.write_str("une valeur porte un octet qu'on refuse d'écrire dans un message")
            }
            Error::BoundaryInContent => {
                f.write_str("le délimiteur de parties figure dans une partie")
            }
            Error::MissingSeparator => {
                f.write_str("aucune ligne vide ne sépare l'en-tête du corps")
            }
            Error::NoAddress => f.write_str("ce champ ne porte pas d'adresse lisible"),
            Error::MultipleAddresses => {
                f.write_str("ce champ porte plusieurs adresses (RFC 7489 §6.6.1)")
            }
            Error::FoldedFirstField { line } => {
                write!(f, "ligne {line} : continuation en tête d'en-tête")
            }
            Error::MissingColon { line } => write!(f, "ligne {line} : champ sans deux-points"),
            Error::EmptyFieldName { line } => write!(f, "ligne {line} : nom de champ vide"),
            Error::InvalidFieldName { line } => {
                write!(f, "ligne {line} : nom de champ hors de %d33-126")
            }
            Error::TooManyFields { limit } => write!(f, "plus de {limit} champs d'en-tête"),
            Error::HeaderTooLong { limit } => {
                write!(f, "bloc d'en-tête de plus de {limit} octets")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Error;

    /// Toutes les variantes, pour que rien ne s'ajoute sans être affiché.
    const TOUTES: &[Error] = &[
        Error::BareCarriageReturn { line: 1 },
        Error::BareLineFeed { line: 2 },
        Error::LineTooLong {
            line: 3,
            limit: 998,
        },
        Error::MissingSeparator,
        Error::FoldedFirstField { line: 4 },
        Error::MissingColon { line: 5 },
        Error::EmptyFieldName { line: 6 },
        Error::InvalidFieldName { line: 7 },
        Error::TooManyFields { limit: 8 },
        Error::HeaderTooLong { limit: 9 },
        Error::NoAddress,
        Error::MultipleAddresses,
        Error::BufferTooSmall,
        Error::NotPrintable,
        Error::BoundaryInContent,
    ];

    #[test]
    fn chaque_variante_s_affiche_et_dit_quelque_chose() {
        for erreur in TOUTES {
            let texte = std::format!("{erreur}");
            assert!(!texte.is_empty(), "{erreur:?} s'affiche vide");
            // Un message qui ne nomme pas ce qui cloche ne sert à personne.
            assert!(
                texte.len() > 10,
                "{erreur:?} : « {texte} » est trop laconique"
            );
        }
    }

    #[test]
    fn les_variantes_sont_deux_a_deux_distinctes() {
        for (rang, erreur) in TOUTES.iter().enumerate() {
            for (autre_rang, autre) in TOUTES.iter().enumerate() {
                if rang == autre_rang {
                    assert_eq!(erreur, autre);
                } else {
                    assert_ne!(erreur, autre, "deux variantes se confondent");
                }
            }
        }
    }

    #[test]
    fn une_erreur_se_copie_et_se_debogue() {
        let erreur = Error::MissingSeparator;
        let copie = erreur;
        assert_eq!(copie, erreur);
        assert!(!std::format!("{erreur:?}").is_empty());
    }
}
