//! Chaque faute dit ce qui cloche.

use super::Error;

const TOUTES: &[Error] = &[
    Error::LineTooLong { limit: 8192 },
    Error::MalformedLineEnding,
    Error::MissingTag,
    Error::MalformedTag,
    Error::TagTooLong { limit: 32 },
    Error::ReservedTag,
    Error::MissingCommand,
    Error::UnknownCommand,
    Error::MalformedArgument,
    Error::MalformedLiteral,
    Error::LiteralTooLong { limit: 1_048_576 },
    Error::NonSynchronizingTooLong { limit: 4096 },
    Error::TooManyLiterals { limit: 8 },
    Error::MalformedSequence,
    Error::TooManySequenceItems { limit: 1024 },
    Error::MalformedFetch,
    Error::UnsupportedFetchItem,
    Error::TooManyFetchItems { limit: 64 },
    Error::ResponseTextNotPrintable,
    Error::BufferTooSmall { needed: 40 },
];

#[test]
fn chaque_variante_s_affiche_et_dit_quelque_chose() {
    for erreur in TOUTES {
        let texte = std::format!("{erreur}");
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
