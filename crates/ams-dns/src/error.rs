//! Ce qui rend un message DNS irrecevable.

use core::fmt;

/// Ce qui rend un message DNS irrecevable.
///
/// # Aucune n'est une réponse
///
/// Toutes disent la même chose à l'appelant : **ce message ne répond pas**. La
/// distinction sert à l'administrateur qui relira ses journaux — un message
/// tronqué et un pointeur de compression hostile ne se corrigent pas de la même
/// façon — jamais à la décision, qui n'a qu'une issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Le message s'arrête au milieu de ce qu'il annonce.
    Truncated,
    /// Un octet de longueur porte les bits `01` ou `10`, réservés depuis 1987 et
    /// jamais attribués.
    Malformed,
    /// Un pointeur de compression ne vise pas strictement en arrière.
    ///
    /// **C'est la garde qui empêche la boucle infinie**, et elle est
    /// structurelle : les cibles décroissent, donc la lecture s'arrête. Voir la
    /// documentation du module.
    BadPointer,
    /// Un nom dépasse 255 octets, ou une étiquette 63 (RFC 1035 §2.3.4).
    NameTooLong,
    /// Une étiquette est vide au milieu d'un nom : `a..b` ne désigne rien.
    EmptyLabel,
    /// Le tampon d'encodage est trop petit.
    BufferTooSmall,
    /// Le message n'a pas le bit de réponse.
    ///
    /// Une question qui nous revient n'est pas une réponse — et la traiter comme
    /// telle laisserait un pair injecter les siennes.
    NotAResponse,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let texte = match self {
            Self::Truncated => "message tronqué",
            Self::Malformed => "octet de longueur réservé",
            Self::BadPointer => "pointeur de compression qui ne recule pas",
            Self::NameTooLong => "nom ou étiquette trop long",
            Self::EmptyLabel => "étiquette vide au milieu d'un nom",
            Self::BufferTooSmall => "tampon trop petit",
            Self::NotAResponse => "ce message n'est pas une réponse",
        };
        f.write_str(texte)
    }
}

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn chaque_erreur_se_dit() {
        // Un message d'erreur vide ferait un journal muet le jour où il compte.
        for erreur in [
            Error::Truncated,
            Error::Malformed,
            Error::BadPointer,
            Error::NameTooLong,
            Error::EmptyLabel,
            Error::BufferTooSmall,
            Error::NotAResponse,
        ] {
            let rendu = std::format!("{erreur}");
            assert!(!rendu.is_empty(), "{erreur:?}");
            assert!(!std::format!("{erreur:?}").is_empty());
        }
        assert_eq!(Error::Truncated, Error::Truncated);
        assert_ne!(Error::Truncated, Error::Malformed);
    }
}
