//! Les bornes qu'un enregistrement SPF ne doit pas franchir.

/// Ce qu'un enregistrement SPF n'a pas le droit de dépasser.
///
/// # Aucune ne vient de la RFC, et c'est dit
///
/// La RFC 7208 borne le nombre de **résolutions** (§4.6.4), pas la taille d'un
/// enregistrement ni son nombre de termes. Ces deux bornes-là sont décidées ici,
/// contre un enregistrement hostile : un nom de domaine qu'on interroge peut
/// répondre ce qu'il veut, et rien n'oblige un serveur à parcourir un mégaoctet
/// de mécanismes pour découvrir qu'ils sont tous inutiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Longueur maximale d'un enregistrement, en octets.
    ///
    /// Une chaîne TXT du DNS fait au plus 255 octets, mais un enregistrement
    /// peut en concaténer plusieurs (RFC 7208 §3.3). Mille octets laissent une
    /// marge considérable à un enregistrement réel — les plus gros connus en
    /// font trois cents — et ferment la porte au reste.
    pub max_record_octets: usize,

    /// Nombre maximal de termes.
    ///
    /// La RFC borne les résolutions à dix ; un enregistrement conforme n'a donc
    /// aucune raison d'aligner cent `ip4:`. Quarante en laissent largement
    /// assez, y compris aux services qui publient une liste d'adresses.
    pub max_terms: usize,
}

impl Limits {
    /// Les bornes par défaut.
    ///
    /// Le nom ne dit pas « RFC 7208 » : **aucune** de ces deux valeurs n'en
    /// vient, et baptiser l'ensemble d'après une référence lui prêterait une
    /// autorité qu'il n'a pas.
    pub const DEFAULT: Self = Self {
        max_record_octets: 1000,
        max_terms: 40,
    };
}

#[cfg(test)]
mod tests {
    use super::Limits;

    #[test]
    fn les_bornes_par_defaut_sont_les_notres() {
        assert_eq!(Limits::DEFAULT.max_record_octets, 1000);
        assert_eq!(Limits::DEFAULT.max_terms, 40);
    }

    #[test]
    fn elles_se_copient_et_se_comparent() {
        let bornes = Limits::DEFAULT;
        assert_eq!(bornes, Limits::DEFAULT);
        assert_ne!(
            bornes,
            Limits {
                max_terms: 1,
                ..bornes
            }
        );
    }
}
