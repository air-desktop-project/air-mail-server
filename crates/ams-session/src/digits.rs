//! Écriture décimale d'un entier, sans allouer.

/// Le nombre de chiffres décimaux de `u64::MAX`.
pub const MAX_DIGITS: usize = 20;

/// Écrit `value` en décimal dans `scratch`, **par la fin**, et rend l'indice où
/// les chiffres commencent.
///
/// Les chiffres occupent `scratch[début..]`. Écrire par la fin évite de compter
/// les chiffres d'abord, puis de les inverser.
pub fn decimal(value: u64, scratch: &mut [u8; MAX_DIGITS]) -> usize {
    let mut reste = value;
    let mut debut = MAX_DIGITS;
    loop {
        debut = debut.saturating_sub(1);
        let chiffre = u8::try_from(reste.wrapping_rem(10)).unwrap_or(0);
        scratch[debut] = b'0'.wrapping_add(chiffre);
        reste = reste.wrapping_div(10);
        if reste == 0 {
            return debut;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_DIGITS, decimal};

    fn rendu(value: u64) -> std::string::String {
        let mut scratch = [0_u8; MAX_DIGITS];
        let debut = decimal(value, &mut scratch);
        std::string::String::from_utf8(scratch[debut..].to_vec()).expect("des chiffres")
    }

    #[test]
    fn les_valeurs_ordinaires_s_ecrivent() {
        assert_eq!(rendu(0), "0");
        assert_eq!(rendu(9), "9");
        assert_eq!(rendu(10), "10");
        assert_eq!(rendu(10_485_760), "10485760");
    }

    #[test]
    fn la_plus_grande_valeur_tient_dans_le_tampon() {
        // Vingt chiffres, et le tampon en fait vingt : la borne n'est pas
        // approximative, elle est exacte.
        assert_eq!(rendu(u64::MAX), "18446744073709551615");
        assert_eq!(rendu(u64::MAX).len(), MAX_DIGITS);
    }
}
