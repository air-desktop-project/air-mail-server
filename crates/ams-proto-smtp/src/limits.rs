//! Les bornes qu'une commande ne doit pas franchir.

/// Ce qu'une commande SMTP n'a pas le droit de dépasser.
///
/// Six de ces sept bornes viennent de la RFC 5321 §4.5.3.1, qui les nomme
/// « minimums qu'une implémentation DOIT accepter ». On les emploie ici comme
/// **maximums**, et c'est un choix : accepter plus, c'est accepter ce qu'aucun
/// pair conforme n'a besoin d'envoyer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Longueur maximale d'une ligne de commande, **CRLF compris**.
    ///
    /// RFC 5321 §4.5.3.1.4 : 512 octets.
    pub max_command_octets: usize,

    /// Longueur maximale de la partie locale d'une boîte.
    ///
    /// RFC 5321 §4.5.3.1.1 : 64 octets.
    pub max_local_part_octets: usize,

    /// Longueur maximale d'un nom de domaine ou d'un littéral d'adresse.
    ///
    /// RFC 5321 §4.5.3.1.2 : 255 octets.
    pub max_domain_octets: usize,

    /// Longueur maximale d'un chemin, **chevrons compris**.
    ///
    /// RFC 5321 §4.5.3.1.3 : 256 octets.
    pub max_path_octets: usize,

    /// Longueur maximale d'une ligne de réponse, **CRLF compris**.
    ///
    /// RFC 5321 §4.5.3.1.5 : 512 octets.
    pub max_reply_octets: usize,

    /// Longueur maximale d'une ligne de **message**, CRLF compris.
    ///
    /// RFC 5321 §4.5.3.1.6 : 1000 octets.
    pub max_text_line_octets: usize,

    /// Nombre maximal de paramètres ESMTP sur une commande.
    ///
    /// **Aucune RFC ne le borne.** Limite défensive, décidée ici : la ligne est
    /// déjà bornée à 512 octets, mais rien n'empêcherait d'y loger cent
    /// paramètres d'un octet, et de faire payer leur parcours à chaque commande.
    pub max_parameters: usize,
}

impl Limits {
    /// Les bornes par défaut.
    ///
    /// Le nom ne dit pas « RFC 5321 » : `max_parameters` n'en vient pas, et
    /// baptiser l'ensemble d'après une référence lui prêterait une autorité que
    /// l'une de ses valeurs n'a pas.
    pub const DEFAULT: Self = Self {
        max_command_octets: 512,
        max_local_part_octets: 64,
        max_domain_octets: 255,
        max_path_octets: 256,
        max_reply_octets: 512,
        max_text_line_octets: 1000,
        max_parameters: 16,
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
    fn les_six_bornes_de_la_rfc_sont_figees() {
        // RFC 5321 §4.5.3.1. Elles sont opposables ; `max_parameters` ne l'est pas.
        assert_eq!(Limits::DEFAULT.max_command_octets, 512);
        assert_eq!(Limits::DEFAULT.max_local_part_octets, 64);
        assert_eq!(Limits::DEFAULT.max_domain_octets, 255);
        assert_eq!(Limits::DEFAULT.max_path_octets, 256);
        assert_eq!(Limits::DEFAULT.max_reply_octets, 512);
        assert_eq!(Limits::DEFAULT.max_text_line_octets, 1000);
    }

    #[test]
    fn les_bornes_se_copient_et_se_comparent() {
        let bornes = Limits {
            max_parameters: 3,
            ..Limits::DEFAULT
        };
        let copie = bornes;
        assert_eq!(copie, bornes);
        assert_ne!(copie, Limits::DEFAULT);
        assert!(!std::format!("{bornes:?}").is_empty());
    }
}
