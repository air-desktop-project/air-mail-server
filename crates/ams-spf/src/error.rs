//! Ce qui rend un enregistrement SPF irrecevable.

use core::fmt;

/// Ce qui rend un enregistrement SPF irrecevable.
///
/// # Toutes valent `permerror`, et c'est le sujet
///
/// RFC 7208 §4.6 : un enregistrement mal formé ne s'évalue pas « au mieux ». La
/// distinction faite ici sert à **l'administrateur** qui relira ses journaux,
/// jamais à l'évaluation — qui, elle, n'a qu'une réponse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// L'enregistrement ne commence pas par `v=spf1`.
    ///
    /// Ce n'est pas forcément une faute : un TXT qui parle d'autre chose n'est
    /// pas un enregistrement SPF, et l'appelant doit le passer plutôt que le
    /// refuser.
    NotSpf,
    /// L'enregistrement dépasse [`Limits::max_record_octets`](crate::Limits).
    TooLong,
    /// L'enregistrement porte plus de [`Limits::max_terms`](crate::Limits).
    TooManyTerms,
    /// Un terme n'est ni un mécanisme connu ni un modificateur.
    UnknownTerm,
    /// Un mécanisme porte un argument qu'il n'admet pas, ou en manque un.
    MalformedArgument,
    /// Un préfixe CIDR est absent, hors bornes, ou n'est pas un nombre.
    MalformedPrefix,
    /// Une adresse littérale n'en est pas une.
    MalformedAddress,
    /// Une macro est mal formée (RFC 7208 §7.1).
    MalformedMacro,
    /// Une expansion dépasse la taille d'un nom de domaine.
    ///
    /// La tronquer désignerait un AUTRE nom, et l'interroger serait pire que de
    /// refuser.
    MacroTooLong,
    /// Un modificateur `redirect=` ou `exp=` figure deux fois.
    ///
    /// RFC 7208 §6 : ils sont uniques. Deux `redirect=` désigneraient deux
    /// politiques, et rien ne dirait laquelle s'applique.
    DuplicateModifier,
    /// L'en-tête `Received-SPF` ne tient pas, ou une de ses lignes dépasserait
    /// 998 octets (RFC 5322 §2.1.1).
    ///
    /// **On refuse plutôt que de couper** : un en-tête tronqué se lit comme un
    /// en-tête entier qui dit autre chose, et les analyseurs en aval le coupent
    /// où ils veulent.
    HeaderTooLong,
    /// Une valeur à écrire dans un en-tête porte un octet hors de l'ASCII
    /// imprimable.
    ///
    /// L'expéditeur d'enveloppe et le `HELO` sont CHOISIS PAR LE PAIR. Un
    /// `CR LF` recopié tel quel dans un en-tête lui laisserait écrire les
    /// en-têtes qu'il veut dans le message qu'on remet.
    NotPrintable,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotSpf => f.write_str("l'enregistrement ne commence pas par `v=spf1`"),
            Error::TooLong => f.write_str("l'enregistrement dépasse la borne de taille"),
            Error::TooManyTerms => f.write_str("l'enregistrement porte trop de termes"),
            Error::UnknownTerm => f.write_str("terme inconnu"),
            Error::MalformedArgument => f.write_str("argument absent ou irrecevable"),
            Error::MalformedPrefix => f.write_str("préfixe CIDR absent ou hors bornes"),
            Error::MalformedAddress => f.write_str("adresse littérale irrecevable"),
            Error::MalformedMacro => f.write_str("macro mal formée (RFC 7208 §7.1)"),
            Error::MacroTooLong => f.write_str("l'expansion dépasse la taille d'un nom de domaine"),
            Error::DuplicateModifier => {
                f.write_str("`redirect=` ou `exp=` figure deux fois (RFC 7208 §6)")
            }
            Error::HeaderTooLong => {
                f.write_str("l'en-tête `Received-SPF` ne tient pas dans une ligne")
            }
            Error::NotPrintable => {
                f.write_str("une valeur porte un octet hors de l'ASCII imprimable")
            }
        }
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::Error;

    const TOUTES: &[Error] = &[
        Error::NotSpf,
        Error::TooLong,
        Error::TooManyTerms,
        Error::UnknownTerm,
        Error::MalformedArgument,
        Error::MalformedPrefix,
        Error::MalformedAddress,
        Error::MalformedMacro,
        Error::MacroTooLong,
        Error::DuplicateModifier,
        Error::HeaderTooLong,
        Error::NotPrintable,
    ];

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
        for erreur in TOUTES {
            let mut compteur = Compteur(0);
            core::fmt::write(&mut compteur, format_args!("{erreur}")).expect("formatable");
            assert!(compteur.0 > 10, "{erreur:?} est trop laconique");
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
}
