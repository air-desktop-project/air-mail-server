//! Ce qui rend un enregistrement DMARC irrecevable.

use core::fmt;

/// Ce qui rend un enregistrement DMARC irrecevable.
///
/// # Un enregistrement qu'on ne sait pas lire N'EST PAS une politique
///
/// RFC 7489 §6.6.3 : un enregistrement dont la syntaxe est fautive est **écarté**
/// — le receveur fait comme s'il n'y en avait pas. Ce n'est pas une indulgence :
/// appliquer « ce qu'on en a compris » ferait rejeter du courrier au nom d'une
/// politique que personne n'a écrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Une liste `tag=valeur` est mal formée.
    MalformedTagList,
    /// Un nom d'étiquette n'en est pas un.
    MalformedTagName,
    /// Une valeur porte un octet que la grammaire n'admet pas.
    MalformedTagValue,
    /// La même étiquette figure deux fois.
    DuplicateTag,
    /// L'enregistrement ne commence pas par `v=DMARC1`.
    ///
    /// **La version vient EN PREMIER** (§6.3), et ce n'est pas une coquetterie :
    /// c'est ce qui permet à un receveur de distinguer un enregistrement DMARC
    /// d'un `TXT` qui parle d'autre chose, sans lire le reste.
    NotDmarc,
    /// L'étiquette `p=` manque.
    ///
    /// §6.6.3 : un enregistrement sans politique est écarté. Sans elle, il ne
    /// demande rien — et un enregistrement qui ne demande rien n'est pas une
    /// politique.
    MissingPolicy,
    /// Une politique demandée n'est ni `none`, ni `quarantine`, ni `reject`.
    UnknownPolicy,
    /// Un mode d'alignement n'est ni `r` ni `s`.
    UnknownAlignment,
    /// Un pourcentage n'est pas un nombre de 0 à 100.
    MalformedPercent,
    /// Un intervalle de rapport n'est pas un nombre.
    MalformedInterval,
    /// Le tampon offert ne suffit pas.
    BufferTooSmall,
    /// Le domaine est trop long pour qu'on puisse en nommer la politique.
    DomainTooLong,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let texte = match self {
            Self::MalformedTagList => "liste `tag=valeur` mal formée",
            Self::MalformedTagName => "nom d'étiquette irrecevable",
            Self::MalformedTagValue => "valeur d'étiquette irrecevable",
            Self::DuplicateTag => "la même étiquette figure deux fois",
            Self::NotDmarc => "l'enregistrement ne commence pas par `v=DMARC1`",
            Self::MissingPolicy => "l'étiquette `p=` manque (§6.6.3)",
            Self::UnknownPolicy => "politique inconnue : ni `none`, ni `quarantine`, ni `reject`",
            Self::UnknownAlignment => "mode d'alignement inconnu : ni `r` ni `s`",
            Self::MalformedPercent => "le pourcentage n'est pas un nombre de 0 à 100",
            Self::MalformedInterval => "l'intervalle de rapport n'est pas un nombre",
            Self::BufferTooSmall => "le tampon offert ne suffit pas",
            Self::DomainTooLong => "le domaine est trop long pour qu'on en nomme la politique",
        };
        f.write_str(texte)
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::Error;

    /// Un `Write` qui compte : la crate est `no_std` SANS `alloc`.
    struct Compteur(usize);

    impl core::fmt::Write for Compteur {
        fn write_str(&mut self, morceau: &str) -> core::fmt::Result {
            self.0 = self.0.saturating_add(morceau.len());
            Ok(())
        }
    }

    #[test]
    fn chaque_variante_dit_quelque_chose() {
        for erreur in [
            Error::MalformedTagList,
            Error::MalformedTagName,
            Error::MalformedTagValue,
            Error::DuplicateTag,
            Error::NotDmarc,
            Error::MissingPolicy,
            Error::UnknownPolicy,
            Error::UnknownAlignment,
            Error::MalformedPercent,
            Error::MalformedInterval,
            Error::BufferTooSmall,
            Error::DomainTooLong,
        ] {
            let mut compteur = Compteur(0);
            core::fmt::write(&mut compteur, format_args!("{erreur}")).expect("formatable");
            assert!(compteur.0 > 10, "{erreur:?} est trop laconique");
            assert!(!std::format!("{erreur:?}").is_empty());
        }
        assert_eq!(Error::NotDmarc, Error::NotDmarc);
        assert_ne!(Error::NotDmarc, Error::MissingPolicy);
    }
}
