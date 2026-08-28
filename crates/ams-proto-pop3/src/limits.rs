//! Les bornes qu'une ligne POP3 ne doit pas franchir.

/// Ce qu'une ligne POP3 n'a pas le droit de dépasser.
///
/// # La RFC en donne deux, et la troisième vient de nous
///
/// La RFC 1939 §3 borne les commandes et les réponses à 512 octets. Elle ne dit
/// rien de la longueur d'un ARGUMENT, et un argument de cinq cents octets est
/// aussi inutile qu'il est coûteux à parcourir : la borne est donc décidée ici,
/// et le nom du champ ne prétend pas le contraire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Longueur maximale d'une ligne de commande, **CRLF compris**.
    ///
    /// RFC 1939 §3 : 512 octets.
    pub max_command_octets: usize,

    /// Longueur maximale d'une ligne de réponse, **CRLF compris**.
    ///
    /// RFC 1939 §3 : 512 octets pour la première ligne. Les lignes d'un corps
    /// multiligne, elles, transportent un message et suivent la borne de la RFC
    /// 5322 — ce n'est pas la même chose, et ce n'est pas le rôle de ce champ.
    pub max_reply_octets: usize,

    /// Longueur maximale d'un argument de commande.
    ///
    /// **Aucune RFC ne le borne** : décidé ici. Le seul argument qui puisse être
    /// long est un nom d'utilisateur, et soixante-quatre octets suffisent à tous
    /// ceux que ce serveur peut connaître (`ams_auth` n'en accepte pas de plus
    /// grands).
    pub max_argument_octets: usize,
}

impl Limits {
    /// Les bornes par défaut.
    ///
    /// Le nom ne dit pas « RFC 1939 » : `max_argument_octets` n'en vient pas, et
    /// baptiser l'ensemble d'après une référence lui prêterait une autorité que
    /// l'une de ses valeurs n'a pas.
    pub const DEFAULT: Self = Self {
        max_command_octets: 512,
        max_reply_octets: 512,
        max_argument_octets: 64,
    };
}

#[cfg(test)]
mod tests {
    use super::Limits;

    #[test]
    fn les_bornes_par_defaut_sont_celles_de_la_rfc() {
        assert_eq!(Limits::DEFAULT.max_command_octets, 512);
        assert_eq!(Limits::DEFAULT.max_reply_octets, 512);
        // Celle-ci vient de nous, et le nom du champ ne prétend pas autre chose.
        assert_eq!(Limits::DEFAULT.max_argument_octets, 64);
    }

    #[test]
    fn elles_se_copient_et_se_comparent() {
        let bornes = Limits::DEFAULT;
        let copie = bornes;
        assert_eq!(copie, bornes);
        assert_ne!(
            bornes,
            Limits {
                max_command_octets: 8,
                ..bornes
            }
        );
    }
}
