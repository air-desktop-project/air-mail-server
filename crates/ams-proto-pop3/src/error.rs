//! Ce qui rend une ligne POP3 irrecevable.

use core::fmt;

/// Ce qui rend une ligne POP3 irrecevable.
///
/// # Elles disent CE QUI ne va pas, jamais QUOI RÉPONDRE
///
/// POP3 n'a que deux réponses possibles, `+OK` et `-ERR` : le texte qui les
/// accompagne est une décision de session, pas de grammaire. Cette énumération
/// ne porte donc aucun message destiné au pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// La ligne dépasse la borne, ou ne se termine pas par un `CRLF`.
    ///
    /// Les deux sont regroupés **exprès** : dans les deux cas, ce que le pair a
    /// envoyé n'est pas une ligne, et le distinguer lui apprendrait la valeur de
    /// notre borne.
    MalformedLine,
    /// Le verbe n'est pas connu.
    UnknownCommand,
    /// Le verbe est connu, mais ses arguments ne conviennent pas.
    MalformedArguments,
    /// Un argument dépasse [`Limits::max_argument_octets`](crate::Limits).
    ArgumentTooLong,
    /// Un numéro de message est absent, nul, ou n'est pas un nombre.
    ///
    /// **Zéro n'est pas un numéro de message** : la RFC 1939 §5 les numérote à
    /// partir de un, et accepter zéro obligerait chaque appelant à s'en méfier.
    MalformedMessageNumber,
    /// La réponse ne tient pas dans la borne.
    ReplyTooLong {
        /// La borne qui n'a pas été tenue.
        limit: usize,
    },
    /// Le tampon fourni à l'encodeur est trop petit.
    BufferTooSmall {
        /// Ce qu'il aurait fallu.
        needed: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MalformedLine => f.write_str("la ligne n'est pas une ligne POP3"),
            Error::UnknownCommand => f.write_str("verbe inconnu"),
            Error::MalformedArguments => f.write_str("arguments irrecevables"),
            Error::ArgumentTooLong => f.write_str("argument trop long"),
            Error::MalformedMessageNumber => {
                f.write_str("numéro de message absent, nul ou illisible")
            }
            Error::ReplyTooLong { limit } => {
                write!(f, "réponse plus longue que la borne de {limit} octets")
            }
            Error::BufferTooSmall { needed } => {
                write!(f, "tampon trop petit : il en faut {needed} octets")
            }
        }
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::Error;

    const TOUTES: &[Error] = &[
        Error::MalformedLine,
        Error::UnknownCommand,
        Error::MalformedArguments,
        Error::ArgumentTooLong,
        Error::MalformedMessageNumber,
        Error::ReplyTooLong { limit: 512 },
        Error::BufferTooSmall { needed: 40 },
    ];

    #[test]
    fn chaque_variante_dit_quelque_chose() {
        for erreur in TOUTES {
            let mut tampon = Tampon::new();
            core::fmt::write(&mut tampon, format_args!("{erreur}")).expect("formatable");
            assert!(tampon.ecrits > 10, "{erreur:?} est trop laconique");
        }
    }

    #[test]
    fn les_variantes_sont_deux_a_deux_distinctes() {
        for (rang, erreur) in TOUTES.iter().enumerate() {
            for (autre_rang, autre) in TOUTES.iter().enumerate() {
                if rang == autre_rang {
                    assert_eq!(erreur, autre);
                } else {
                    assert_ne!(erreur, autre);
                }
            }
        }
    }

    /// Un `Write` qui compte, pour formater sans `alloc`.
    struct Tampon {
        ecrits: usize,
    }

    impl Tampon {
        const fn new() -> Self {
            Self { ecrits: 0 }
        }
    }

    impl core::fmt::Write for Tampon {
        fn write_str(&mut self, morceau: &str) -> core::fmt::Result {
            self.ecrits = self.ecrits.saturating_add(morceau.len());
            Ok(())
        }
    }
}
