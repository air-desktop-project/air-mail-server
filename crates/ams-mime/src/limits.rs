//! Les bornes qu'un message ne doit pas franchir.

/// Ce qu'un message n'a pas le droit de dépasser.
///
/// Ces bornes sont la première ligne de défense de [C3] : elles sont vérifiées
/// **avant** que la moindre longueur venue du réseau serve à quoi que ce soit.
/// Elles voyagent en paramètre plutôt qu'en constante, parce que C8 exige que ce
/// qui borne une source vienne de la configuration.
///
/// [C3]: https://github.com/air-desktop-project/air-mail-server/blob/main/docs/contraintes.md
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Longueur maximale d'une ligne, **CRLF non compris**.
    ///
    /// La RFC 5322 §2.1.1 fixe 998 caractères, et c'est la seule des trois
    /// bornes qui vienne d'une référence.
    pub max_line_octets: usize,

    /// Nombre maximal de champs d'en-tête.
    ///
    /// **Aucune RFC ne le borne.** C'est une limite défensive, décidée ici : sans
    /// elle, un en-tête de dix millions de champs valides serait recevable, et le
    /// coût de son parcours serait offert à qui l'envoie.
    pub max_fields: usize,

    /// Taille maximale du bloc d'en-tête entier, CRLF compris.
    ///
    /// **Aucune RFC ne le borne** non plus. Même raison que ci-dessus : la somme
    /// de champs individuellement licites doit rester bornée.
    pub max_header_octets: usize,
}

impl Limits {
    /// Les bornes par défaut.
    ///
    /// Le nom ne dit **pas** « RFC 5322 » : une seule des trois valeurs en vient
    /// (`max_line_octets`), les deux autres sont des décisions de ce projet.
    /// Baptiser l'ensemble d'après une référence lui prêterait une autorité
    /// qu'elle n'a pas.
    pub const DEFAULT: Self = Self {
        max_line_octets: 998,
        max_fields: 1024,
        max_header_octets: 256 * 1024,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::Limits;

    #[test]
    fn le_defaut_est_la_constante() {
        assert_eq!(Limits::default(), Limits::DEFAULT);
    }

    #[test]
    fn seule_la_longueur_de_ligne_vient_de_la_rfc() {
        // RFC 5322 §2.1.1. Les deux autres bornes sont des décisions de ce
        // projet ; ce test fige la valeur qui, elle, est opposable.
        assert_eq!(Limits::DEFAULT.max_line_octets, 998);
    }

    #[test]
    fn les_bornes_se_copient_et_se_comparent() {
        let bornes = Limits {
            max_fields: 7,
            ..Limits::DEFAULT
        };
        let copie = bornes;
        assert_eq!(copie, bornes);
        assert_ne!(copie, Limits::DEFAULT);
        assert!(!std::format!("{bornes:?}").is_empty());
    }
}
