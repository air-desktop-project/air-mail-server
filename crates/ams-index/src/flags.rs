//! Les drapeaux d'un message, tels que Maildir les écrit.
//!
//! # LES MINUSCULES SONT DES MOTS-CLEFS, ET LEUR SENS EST FIXÉ ICI
//!
//! Maildir ne définit que six lettres majuscules. Les mots-clefs d'IMAP — RFC
//! 9051 §2.3.2 — n'ont pas de place réservée : la convention répandue est
//! d'employer `a` à `z`, dont un fichier annexe dit le sens. **Ce serveur ne sert
//! qu'un ensemble FERMÉ de cinq mots-clefs** — ceux que RFC 9051 §E.15
//! recommande —, et leur correspondance est donc écrite ici, dans le code, une
//! fois pour toutes. Un fichier annexe ne servirait qu'à la rendre variable, donc
//! à la rendre fausse le jour où il manque.
//!
//! Les minuscules viennent APRÈS les majuscules dans l'ordre ASCII, si bien que
//! la règle d'ordre du format tient sans rien changer.

use core::fmt;

/// Les drapeaux d'un message.
///
/// Maildir les porte dans le NOM DU FICHIER, après `:2,`, par lettres et **dans
/// l'ordre ASCII**. C'est ce qui permet de changer l'état d'un message par un
/// simple `rename()`, donc sans verrou et sans réécrire son contenu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags(u16);

/// Les lettres, dans l'ordre ASCII, et le bit de chacune.
const LETTRES: [(u8, u16); 11] = [
    (b'D', 0b0000_0000_0000_0001),
    (b'F', 0b0000_0000_0000_0010),
    (b'P', 0b0000_0000_0000_0100),
    (b'R', 0b0000_0000_0000_1000),
    (b'S', 0b0000_0000_0001_0000),
    (b'T', 0b0000_0000_0010_0000),
    (b'a', 0b0000_0000_0100_0000),
    (b'b', 0b0000_0000_1000_0000),
    (b'c', 0b0000_0001_0000_0000),
    (b'd', 0b0000_0010_0000_0000),
    (b'e', 0b0000_0100_0000_0000),
];

impl Flags {
    /// Aucun drapeau.
    pub const NONE: Self = Self(0);
    /// `D` — brouillon.
    pub const DRAFT: Self = Self(0b0000_0000_0000_0001);
    /// `F` — marqué.
    pub const FLAGGED: Self = Self(0b0000_0000_0000_0010);
    /// `P` — transmis.
    pub const PASSED: Self = Self(0b0000_0000_0000_0100);
    /// `R` — répondu.
    pub const REPLIED: Self = Self(0b0000_0000_0000_1000);
    /// `S` — lu.
    pub const SEEN: Self = Self(0b0000_0000_0001_0000);
    /// `T` — supprimé.
    pub const TRASHED: Self = Self(0b0000_0000_0010_0000);
    /// `a` — le mot-clef `$MDNSent`.
    pub const MDN_SENT: Self = Self(0b0000_0000_0100_0000);
    /// `b` — le mot-clef `$Forwarded`.
    pub const FORWARDED: Self = Self(0b0000_0000_1000_0000);
    /// `c` — le mot-clef `$Junk`.
    pub const JUNK: Self = Self(0b0000_0001_0000_0000);
    /// `d` — le mot-clef `$NonJunk`.
    pub const NON_JUNK: Self = Self(0b0000_0010_0000_0000);
    /// `e` — le mot-clef `$Phishing`.
    pub const PHISHING: Self = Self(0b0000_0100_0000_0000);

    /// Le nombre maximal d'octets qu'écrit [`Flags::write_into`].
    pub const MAX_OCTETS: usize = LETTRES.len();

    /// Lit une suite de lettres.
    ///
    /// Une lettre inconnue fait échouer : Maildir en réserve d'autres, et les
    /// ignorer en silence ferait perdre au premier `rename()` un état qu'un autre
    /// outil avait posé.
    ///
    /// # Errors
    ///
    /// [`FlagError`].
    pub fn parse(lettres: &[u8]) -> Result<Self, FlagError> {
        let mut bits = 0_u16;
        let mut precedente = 0_u8;
        for &lettre in lettres {
            let Some(&(_, bit)) = LETTRES.iter().find(|&&(connue, _)| connue == lettre) else {
                return Err(FlagError::UnknownLetter);
            };
            // L'ORDRE ASCII EST NORMATIF, et le vérifier attrape le doublon par
            // la même occasion : une lettre déjà vue n'est pas strictement
            // supérieure à elle-même.
            if lettre <= precedente {
                return Err(FlagError::OutOfOrder);
            }
            precedente = lettre;
            bits |= bit;
        }
        Ok(Self(bits))
    }

    /// Écrit les lettres dans l'ordre ASCII, et rend le nombre d'octets écrits.
    ///
    /// **Cette écriture ne peut pas échouer** : le tampon est un tableau de la
    /// taille exacte. Rendre un `Result` ici ouvrirait une branche que rien ne
    /// pourrait exercer — et l'appelant devrait la traiter pour rien.
    #[must_use]
    pub fn write_into(self, out: &mut [u8; Self::MAX_OCTETS]) -> usize {
        let mut ecrits = 0_usize;
        for &(lettre, bit) in &LETTRES {
            if self.0 & bit != 0 {
                // `ecrits` est borné par le nombre de lettres, donc par `out`.
                out[ecrits] = lettre;
                ecrits = ecrits.saturating_add(1);
            }
        }
        ecrits
    }

    /// Ces drapeaux contiennent-ils tous ceux de `autres` ?
    #[must_use]
    pub fn contains(self, autres: Self) -> bool {
        self.0 & autres.0 == autres.0
    }

    /// L'union.
    #[must_use]
    pub fn with(self, autres: Self) -> Self {
        Self(self.0 | autres.0)
    }

    /// La différence.
    #[must_use]
    pub fn without(self, autres: Self) -> Self {
        Self(self.0 & !autres.0)
    }

    /// Aucun drapeau n'est posé ?
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Ce qui rend une suite de drapeaux irrecevable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagError {
    /// Une lettre qui n'est pas un drapeau connu.
    UnknownLetter,
    /// Les lettres ne sont pas dans l'ordre ASCII, ou l'une est répétée.
    OutOfOrder,
}

impl fmt::Display for FlagError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlagError::UnknownLetter => f.write_str("lettre de drapeau inconnue"),
            FlagError::OutOfOrder => f.write_str("drapeaux hors de l'ordre ASCII, ou répétés"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FlagError, Flags};

    fn rendu(drapeaux: Flags) -> std::string::String {
        let mut tampon = [0_u8; Flags::MAX_OCTETS];
        let ecrits = drapeaux.write_into(&mut tampon);
        std::string::String::from_utf8(tampon[..ecrits].to_vec()).expect("des lettres")
    }

    #[test]
    fn les_lettres_s_ecrivent_dans_l_ordre_ascii() {
        // L'ORDRE EST NORMATIF : deux noms qui ne diffèrent que par l'ordre des
        // lettres désigneraient le même message sous deux noms.
        let tout = Flags::SEEN
            .with(Flags::DRAFT)
            .with(Flags::TRASHED)
            .with(Flags::FLAGGED);
        assert_eq!(rendu(tout), "DFST");
        assert_eq!(rendu(Flags::NONE), "");
    }

    #[test]
    fn l_aller_retour_est_une_identite() {
        for lettres in ["", "S", "DFPRST", "RS", "T"] {
            let drapeaux = Flags::parse(lettres.as_bytes()).expect("recevable");
            assert_eq!(rendu(drapeaux), lettres);
        }
    }

    #[test]
    fn les_suites_mal_formees_sont_refusees() {
        assert_eq!(Flags::parse(b"X"), Err(FlagError::UnknownLetter));
        assert_eq!(Flags::parse(b"s"), Err(FlagError::UnknownLetter));
        // Hors ordre.
        assert_eq!(Flags::parse(b"SD"), Err(FlagError::OutOfOrder));
        // Répétée : elle n'est pas strictement supérieure à elle-même.
        assert_eq!(Flags::parse(b"SS"), Err(FlagError::OutOfOrder));
    }

    #[test]
    fn l_appartenance_et_les_combinaisons() {
        let lu_et_repondu = Flags::SEEN.with(Flags::REPLIED);
        assert!(lu_et_repondu.contains(Flags::SEEN));
        assert!(lu_et_repondu.contains(Flags::REPLIED));
        assert!(!lu_et_repondu.contains(Flags::TRASHED));
        assert!(lu_et_repondu.contains(Flags::NONE));
        assert_eq!(lu_et_repondu.without(Flags::SEEN), Flags::REPLIED);
        assert!(Flags::NONE.is_empty());
        assert!(!Flags::SEEN.is_empty());
    }

    #[test]
    fn les_types_se_copient_et_se_deboguent() {
        let drapeaux = Flags::SEEN;
        let copie = drapeaux;
        assert_eq!(copie, drapeaux);
        assert_ne!(copie, Flags::TRASHED);
        assert!(!std::format!("{drapeaux:?}").is_empty());
        assert_eq!(Flags::default(), Flags::NONE);
        for erreur in [FlagError::UnknownLetter, FlagError::OutOfOrder] {
            assert!(std::format!("{erreur}").len() > 10);
            assert!(!std::format!("{erreur:?}").is_empty());
        }
        assert_ne!(FlagError::OutOfOrder, FlagError::UnknownLetter);
    }
}
