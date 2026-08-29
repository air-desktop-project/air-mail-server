//! Ce qui rend une commande IMAP irrecevable.

use core::fmt;

/// Ce qui rend une commande IMAP irrecevable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Une ligne dépasse [`Limits::max_line_octets`](crate::Limits::max_line_octets).
    LineTooLong {
        /// La borne franchie.
        limit: usize,
    },

    /// Une ligne porte un `CR` ou un `LF` isolé.
    ///
    /// Même refus que dans les trois autres grammaires de ce dépôt, et pour la
    /// même raison : c'est le désaccord entre implémentations sur ce qui termine
    /// une ligne qui a rendu la contrebande possible.
    MalformedLineEnding,

    /// La commande ne commence pas par un tag.
    MissingTag,

    /// Le tag porte un octet que la grammaire n'admet pas.
    ///
    /// **LE TAG EST RECOPIÉ DANS LA RÉPONSE** (RFC 9051 §7). Un `CRLF` dedans
    /// écrirait donc une réponse de notre part, à la place du serveur : c'est
    /// une injection de réponse, et elle se ferme ici, à la lecture.
    MalformedTag,

    /// Le tag dépasse [`Limits::max_tag_octets`](crate::Limits::max_tag_octets).
    TagTooLong {
        /// La borne franchie.
        limit: usize,
    },

    /// Le tag est `+`, que la grammaire réserve (RFC 9051 §9, `tag`).
    ReservedTag,

    /// La commande ne porte pas de verbe.
    MissingCommand,

    /// Le verbe n'appartient pas au vocabulaire d'IMAP4rev2.
    UnknownCommand,

    /// Un argument n'est ni un atome, ni une chaîne close, ni un littéral.
    MalformedArgument,

    /// Un littéral annonce une longueur qui n'est pas un nombre.
    MalformedLiteral,

    /// Un littéral dépasse
    /// [`Limits::max_literal_octets`](crate::Limits::max_literal_octets).
    ///
    /// `{4294967295}` est une ligne de treize octets qui demande quatre
    /// gibioctets. On la refuse **avant** de lire quoi que ce soit.
    LiteralTooLong {
        /// La borne franchie.
        limit: u64,
    },

    /// Un littéral **non synchronisant** dépasse
    /// [`Limits::NON_SYNCHRONIZING_MAX`](crate::Limits::NON_SYNCHRONIZING_MAX).
    ///
    /// Celui-là part sans que le serveur ait rien dit : la RFC 9051 §6.3.11 le
    /// borne à quatre kibioctets, et cette borne n'est pas la nôtre à choisir.
    NonSynchronizingTooLong {
        /// La borne franchie.
        limit: u64,
    },

    /// La commande porte plus de littéraux que
    /// [`Limits::max_literals`](crate::Limits::max_literals).
    TooManyLiterals {
        /// La borne franchie.
        limit: usize,
    },

    /// Un ensemble de numéros n'a pas la forme de §9.
    ///
    /// Zéro n'est pas un numéro de message — la grammaire dit `nz-number` — et
    /// un nombre qui déborde n'est pas un grand nombre.
    MalformedSequence,

    /// Un ensemble de numéros porte plus d'éléments que
    /// [`Limits::max_sequence_items`](crate::Limits::max_sequence_items).
    TooManySequenceItems {
        /// La borne franchie.
        limit: usize,
    },

    /// Les arguments d'un `FETCH` n'ont pas la forme de §6.4.5.
    MalformedFetch,

    /// Un élément de `FETCH` est reconnu, mais non servi.
    ///
    /// **Ce n'est pas une erreur de syntaxe** : le client sait alors qu'il doit
    /// demander autrement, au lieu de chercher la faute dans ce qu'il a écrit.
    UnsupportedFetchItem,

    /// Une commande `FETCH` porte plus d'éléments que
    /// [`Limits::max_fetch_items`](crate::Limits::max_fetch_items).
    TooManyFetchItems {
        /// La borne franchie.
        limit: usize,
    },

    /// Les arguments d'un `STORE` n'ont pas la forme de §6.4.6.
    MalformedStore,

    /// Un `STORE` porte un drapeau qu'on ne sait pas écrire.
    ///
    /// **Le refuser vaut mieux que le taire** : un client à qui l'on répond `OK`
    /// croit son étiquette posée, et ne la reverra jamais.
    UnknownFlag,

    /// Un texte de réponse porte un octet qu'on refuse d'écrire.
    ResponseTextNotPrintable,

    /// Le tampon fourni ne peut pas contenir la réponse.
    BufferTooSmall {
        /// Le nombre d'octets qu'il aurait fallu.
        needed: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::LineTooLong { limit } => {
                write!(f, "ligne de commande de plus de {limit} octets")
            }
            Error::MalformedLineEnding => f.write_str("CR ou LF isolé dans une ligne de commande"),
            Error::MissingTag => f.write_str("la commande ne commence pas par un tag"),
            Error::MalformedTag => {
                f.write_str("le tag porte un octet que la grammaire n'admet pas")
            }
            Error::TagTooLong { limit } => write!(f, "tag de plus de {limit} octets"),
            Error::ReservedTag => f.write_str("`+` est réservé et ne peut pas être un tag"),
            Error::MissingCommand => f.write_str("la commande ne porte pas de verbe"),
            Error::UnknownCommand => f.write_str("verbe inconnu du vocabulaire IMAP4rev2"),
            Error::MalformedArgument => {
                f.write_str("un argument n'est ni un atome, ni une chaîne close, ni un littéral")
            }
            Error::MalformedLiteral => {
                f.write_str("un littéral annonce une longueur qui n'est pas un nombre")
            }
            Error::LiteralTooLong { limit } => {
                write!(f, "littéral de plus de {limit} octets")
            }
            Error::NonSynchronizingTooLong { limit } => write!(
                f,
                "littéral non synchronisant de plus de {limit} octets (RFC 9051 §6.3.11)"
            ),
            Error::TooManyLiterals { limit } => {
                write!(f, "plus de {limit} littéraux dans une commande")
            }
            Error::MalformedSequence => {
                f.write_str("un ensemble de numéros n'a pas la forme attendue")
            }
            Error::TooManySequenceItems { limit } => {
                write!(f, "plus de {limit} éléments dans un ensemble de numéros")
            }
            Error::MalformedFetch => {
                f.write_str("les arguments d'un `FETCH` n'ont pas la forme attendue")
            }
            Error::UnsupportedFetchItem => {
                f.write_str("cet élément de `FETCH` est reconnu, mais ce serveur ne le sert pas")
            }
            Error::TooManyFetchItems { limit } => {
                write!(f, "plus de {limit} éléments dans un `FETCH`")
            }
            Error::MalformedStore => {
                f.write_str("les arguments d'un `STORE` n'ont pas la forme attendue")
            }
            Error::UnknownFlag => {
                f.write_str("ce drapeau n'est pas un de ceux que ce serveur sait écrire")
            }
            Error::ResponseTextNotPrintable => {
                f.write_str("un texte de réponse porte un octet qu'on refuse d'écrire")
            }
            Error::BufferTooSmall { needed } => {
                write!(f, "tampon trop petit : il en fallait {needed} octets")
            }
        }
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests;
