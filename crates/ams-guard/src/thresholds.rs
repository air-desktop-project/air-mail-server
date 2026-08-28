//! Ce que la configuration dit du flooding.

use core::time::Duration;

/// Les seuils au-delà desquels une source cesse d'être servie.
///
/// **Rien ici n'est une constante** : C8 exige que ce qui borne une source vienne
/// de la configuration. Un seuil gravé dans le code est un seuil qu'on ne peut
/// pas desserrer le jour où il se trompe — ni resserrer le jour où il ne suffit
/// plus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Thresholds {
    /// Connexions acceptées par minute et par source.
    pub connections_per_minute: u32,
    /// Commandes acceptées par minute et par source.
    pub commands_per_minute: u32,
    /// Trames invalides tolérées par minute avant bannissement — le `x` de C8.
    pub invalid_frames_per_minute: u32,
    /// Durée du bannissement — le `y` de C8.
    pub ban_duration: Duration,
    /// Longueur du préfixe sous lequel une source IPv4 est comptée.
    ///
    /// `32` par défaut : en IPv4 le bloc d'un abonné EST souvent une adresse, et
    /// élargir y punirait des voisins.
    pub ipv4_prefix_bits: u8,
    /// Longueur du préfixe sous lequel une source IPv6 est comptée.
    ///
    /// `64` par défaut, et **ce n'est pas un détail** : le plus petit bloc qu'un
    /// fournisseur attribue est un `/64`. Bannir une adresse exacte laisserait le
    /// pair revenir à la suivante.
    pub ipv6_prefix_bits: u8,
}

impl Thresholds {
    /// Des seuils de départ.
    ///
    /// **Aucune RFC ne les fixe** : ce sont des décisions de ce projet, et le nom
    /// ne prétend pas autre chose. Ils sont volontairement généreux — un seuil
    /// trop serré coupe du courrier légitime, et un faux positif se remarque bien
    /// plus tard qu'un vrai négatif.
    pub const DEFAULT: Self = Self {
        connections_per_minute: 60,
        commands_per_minute: 600,
        invalid_frames_per_minute: 20,
        ban_duration: Duration::from_secs(3600),
        ipv4_prefix_bits: 32,
        ipv6_prefix_bits: 64,
    };

    /// La durée du bannissement en millisecondes, bornée.
    pub(crate) fn ban_millis(&self) -> u64 {
        u64::try_from(self.ban_duration.as_millis()).unwrap_or(u64::MAX)
    }
}

impl Default for Thresholds {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::Thresholds;
    use core::time::Duration;

    #[test]
    fn le_defaut_est_la_constante() {
        assert_eq!(Thresholds::default(), Thresholds::DEFAULT);
    }

    #[test]
    fn le_prefixe_ipv6_par_defaut_est_un_soixante_quatre() {
        // Le plus petit bloc qu'un fournisseur attribue.
        assert_eq!(Thresholds::DEFAULT.ipv6_prefix_bits, 64);
        assert_eq!(Thresholds::DEFAULT.ipv4_prefix_bits, 32);
    }

    #[test]
    fn une_duree_absurde_est_bornee_plutot_que_de_deborder() {
        let sans_fin = Thresholds {
            ban_duration: Duration::MAX,
            ..Thresholds::DEFAULT
        };
        assert_eq!(sans_fin.ban_millis(), u64::MAX);
        assert_eq!(Thresholds::DEFAULT.ban_millis(), 3_600_000);
    }

    #[test]
    fn les_seuils_se_copient_et_se_deboguent() {
        let seuils = Thresholds {
            invalid_frames_per_minute: 1,
            ..Thresholds::DEFAULT
        };
        let copie = seuils;
        assert_eq!(copie, seuils);
        assert_ne!(copie, Thresholds::DEFAULT);
        assert!(!std::format!("{seuils:?}").is_empty());
    }
}
