//! D'où vient un pair, et jusqu'où on le tient pour responsable.

/// L'adresse d'un pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// IPv4.
    V4([u8; 4]),
    /// IPv6.
    V6([u8; 16]),
}

/// La clé sous laquelle une source est comptée.
///
/// # Ce n'est pas l'adresse, et c'est tout le sujet
///
/// **Bannir une adresse IPv6 seule ne sert à rien.** Le plus petit bloc qu'un
/// fournisseur attribue est un `/64` — soit dix-huit milliards de milliards
/// d'adresses. Un pair banni sur son adresse exacte revient à la suivante sans
/// rien changer d'autre, et la table du garde se remplit de bannissements
/// inutiles pendant qu'il continue.
///
/// La clé est donc un **préfixe**, dont la longueur vient de la configuration
/// (C8) : `/64` en IPv6 par défaut, `/32` en IPv4 — une adresse exacte, parce
/// qu'en IPv4 le bloc d'un abonné EST souvent une adresse, et qu'élargir y
/// punirait des voisins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key {
    octets: [u8; 16],
    v6: bool,
}

impl Key {
    /// La clé d'une case libre. Elle ne désigne personne : une case n'est
    /// consultée que si elle est occupée.
    pub(crate) const ZERO: Self = Self {
        octets: [0; 16],
        v6: false,
    };

    /// Réduit une source au préfixe sous lequel elle sera comptée.
    #[must_use]
    pub fn from_source(source: Source, v4_bits: u8, v6_bits: u8) -> Self {
        let (mut octets, v6, bits) = match source {
            Source::V4(adresse) => {
                let mut plein = [0_u8; 16];
                plein[..4].copy_from_slice(&adresse);
                (plein, false, u32::from(v4_bits.min(32)))
            }
            Source::V6(adresse) => (adresse, true, u32::from(v6_bits.min(128))),
        };
        masquer(&mut octets, bits);
        Self { octets, v6 }
    }

    /// Les octets du préfixe, les bits hors préfixe mis à zéro.
    #[must_use]
    pub fn octets(&self) -> [u8; 16] {
        self.octets
    }

    /// La clé désigne-t-elle un préfixe IPv6 ?
    #[must_use]
    pub fn is_v6(&self) -> bool {
        self.v6
    }
}

/// Met à zéro tout ce qui dépasse `bits`.
fn masquer(octets: &mut [u8; 16], bits: u32) {
    for (rang, octet) in octets.iter_mut().enumerate() {
        let deja = u32::try_from(rang).unwrap_or(u32::MAX).saturating_mul(8);
        let restants = bits.saturating_sub(deja);
        if restants == 0 {
            *octet = 0;
        } else if restants < 8 {
            // On garde les `restants` bits de poids fort.
            let a_jeter = 8_u32.saturating_sub(restants);
            *octet &= 0xFF_u8.wrapping_shl(a_jeter);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Key, Source};

    fn cle(source: Source, v4: u8, v6: u8) -> [u8; 16] {
        Key::from_source(source, v4, v6).octets()
    }

    #[test]
    fn une_adresse_ipv4_entiere_se_garde_telle_quelle() {
        let attendu = [192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(cle(Source::V4([192, 0, 2, 1]), 32, 64), attendu);
    }

    #[test]
    fn un_prefixe_ipv4_plus_court_efface_la_fin() {
        assert_eq!(
            cle(Source::V4([192, 0, 2, 200]), 24, 64),
            [192, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        // Un préfixe qui ne tombe pas sur un octet coupe DANS l'octet.
        assert_eq!(
            cle(Source::V4([192, 0, 2, 200]), 30, 64),
            [192, 0, 2, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            cle(Source::V4([192, 0, 2, 203]), 30, 64),
            [192, 0, 2, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn deux_adresses_du_meme_soixante_quatre_ipv6_ont_la_meme_cle() {
        // C'EST LA RAISON D'ÊTRE DU PRÉFIXE. Un pair banni sur son adresse
        // exacte reviendrait à la suivante sans rien changer d'autre.
        let un = Source::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let autre = Source::V6([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        ]);
        assert_eq!(cle(un, 32, 64), cle(autre, 32, 64));
        // Sous un préfixe complet, elles se distinguent à nouveau.
        assert_ne!(cle(un, 32, 128), cle(autre, 32, 128));
    }

    #[test]
    fn une_ipv4_et_une_ipv6_ne_se_confondent_jamais() {
        // `::c000:0201` n'est pas `192.0.2.1`, et les compter ensemble
        // punirait un pair pour ce qu'un autre a fait.
        let quatre = Key::from_source(Source::V4([0, 0, 0, 0]), 32, 128);
        let six = Key::from_source(Source::V6([0; 16]), 32, 128);
        assert_eq!(quatre.octets(), six.octets());
        assert_ne!(quatre, six);
        assert!(!quatre.is_v6());
        assert!(six.is_v6());
    }

    #[test]
    fn un_prefixe_absurde_est_ramene_a_sa_borne() {
        // Une configuration peut porter n'importe quoi (C8) : `/255` vaut « tout ».
        assert_eq!(
            cle(Source::V4([1, 2, 3, 4]), 255, 255),
            cle(Source::V4([1, 2, 3, 4]), 32, 128)
        );
        // Et `/0` met tout le monde dans le même sac.
        assert_eq!(cle(Source::V4([1, 2, 3, 4]), 0, 0), [0_u8; 16]);
    }

    #[test]
    fn les_cles_se_copient_et_se_deboguent() {
        let cle = Key::from_source(Source::V4([1, 2, 3, 4]), 32, 64);
        let copie = cle;
        assert_eq!(copie, cle);
        assert!(!std::format!("{cle:?}").is_empty());
        assert!(!std::format!("{:?}", Source::V6([0; 16])).is_empty());
        assert_ne!(Source::V4([1, 2, 3, 4]), Source::V4([1, 2, 3, 5]));
    }
}
