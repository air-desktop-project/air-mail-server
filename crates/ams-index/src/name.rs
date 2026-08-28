//! Le nom d'un fichier Maildir, et l'UID qu'il porte.

use core::fmt;

use crate::{FlagError, Flags};

/// L'identifiant stable d'un message dans une boîte (IMAP `UID`).
///
/// **Il vaut au moins un** : la RFC 9051 §2.3.1.1 réserve le zéro, et un UID nul
/// désignerait un message qui n'existe pas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Uid(u32);

impl Uid {
    /// Le premier UID d'une boîte neuve.
    pub const FIRST: Self = Self(1);

    /// Construit un UID. Rend `None` pour zéro.
    #[must_use]
    pub const fn new(valeur: u32) -> Option<Self> {
        if valeur == 0 {
            None
        } else {
            Some(Self(valeur))
        }
    }

    /// La valeur.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }

    /// L'UID suivant, s'il en reste.
    ///
    /// Rend `None` à `u32::MAX` : c'est à ce moment-là que la boîte doit changer
    /// d'`UIDVALIDITY`, et le taire ferait réattribuer un UID déjà servi — donc
    /// montrer à un client un message pour un autre.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(suivant) => Some(Self(suivant)),
            None => None,
        }
    }
}

/// Le nom d'un fichier Maildir, décomposé.
///
/// # Ce que ce projet écrit
///
/// ```text
/// <unique>,U=<uid>,S=<taille>[:2,<drapeaux>]
/// ```
///
/// Le `,U=` n'est pas une fantaisie : **c'est ce qui rend l'index
/// reconstructible** (C13). Un UID déduit d'un ordre — date de modification,
/// ordre de lecture du répertoire — change au premier fichier restauré depuis une
/// sauvegarde, et tous les clients resynchronisent alors la boîte entière.
///
/// La partie unique d'un nom Maildir est opaque et libre — hors `:` et `/` —,
/// ce qui suffit à y loger le nôtre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageName<'a> {
    base: &'a [u8],
    uid: Option<Uid>,
    size: Option<u64>,
    flags: Flags,
    has_info: bool,
}

impl<'a> MessageName<'a> {
    /// Décompose un nom de fichier.
    ///
    /// # Errors
    ///
    /// [`NameError`].
    pub fn parse(nom: &'a [u8]) -> Result<Self, NameError> {
        if nom.is_empty() {
            return Err(NameError::Empty);
        }
        // Un `/` dans un nom de fichier n'est pas un nom de fichier : le refuser
        // ici ferme une traversée de répertoire avant qu'elle n'atteigne le
        // système de fichiers.
        if nom.contains(&b'/') {
            return Err(NameError::PathSeparator);
        }

        let (unique, info) = match nom.iter().position(|&octet| octet == b':') {
            Some(at) => {
                let (unique, reste) = nom.split_at(at);
                (unique, Some(reste.get(1..).unwrap_or_default()))
            }
            None => (nom, None),
        };

        let (flags, has_info) = match info {
            None => (Flags::NONE, false),
            Some(info) => {
                // La RFC de fait ne définit que la version `2` de l'information.
                let Some(lettres) = info.strip_prefix(b"2,") else {
                    return Err(NameError::UnsupportedInfo);
                };
                (Flags::parse(lettres)?, true)
            }
        };

        let mut champs = unique.split(|&octet| octet == b',');
        let base = champs.next().unwrap_or_default();
        if base.is_empty() {
            return Err(NameError::Empty);
        }
        let mut uid = None;
        let mut size = None;
        for champ in champs {
            if let Some(valeur) = champ.strip_prefix(b"U=") {
                uid = Some(Uid::new(lire_u32(valeur)?).ok_or(NameError::ZeroUid)?);
            } else if let Some(valeur) = champ.strip_prefix(b"S=") {
                size = Some(lire_u64(valeur)?);
            }
            // Les autres champs sont IGNORÉS et PRÉSERVÉS : un autre outil peut
            // y avoir posé le sien, et le jeter au premier `rename()` lui ferait
            // perdre ce qu'il y avait mis.
        }

        Ok(Self {
            base: unique,
            uid,
            size,
            flags,
            has_info,
        })
    }

    /// La partie unique, champs compris, sans l'information de drapeaux.
    #[must_use]
    pub fn unique(&self) -> &'a [u8] {
        self.base
    }

    /// L'UID, si le nom en porte un.
    #[must_use]
    pub fn uid(&self) -> Option<Uid> {
        self.uid
    }

    /// La taille annoncée, si le nom en porte une.
    #[must_use]
    pub fn size(&self) -> Option<u64> {
        self.size
    }

    /// Les drapeaux.
    #[must_use]
    pub fn flags(&self) -> Flags {
        self.flags
    }

    /// Le nom porte-t-il l'information de drapeaux — donc vit-il dans `cur/` ?
    #[must_use]
    pub fn has_info(&self) -> bool {
        self.has_info
    }
}

/// Compose un nom de fichier, et rend le nombre d'octets écrits.
///
/// `flags` à `None` compose un nom pour `new/` — sans information de drapeaux,
/// comme l'exige la convention Maildir pour un message jamais vu.
///
/// # Errors
///
/// [`NameError::BufferTooSmall`] si `out` ne suffit pas, et
/// [`NameError::PathSeparator`] si `unique` porte un `/` ou un `:`.
pub fn compose(
    out: &mut [u8],
    unique: &[u8],
    uid: Uid,
    size: u64,
    flags: Option<Flags>,
) -> Result<usize, NameError> {
    if unique.iter().any(|&octet| octet == b'/' || octet == b':') {
        return Err(NameError::PathSeparator);
    }
    // LA BASE — ce qui précède le premier `,` — DOIT ÊTRE NON VIDE, sans quoi le
    // nom composé serait illisible par `parse`. Un composeur qui fabrique de
    // l'illisible n'en est pas un : le défaut ne se verrait qu'au parcours
    // suivant, quand l'UID redeviendrait introuvable. Trouvé par
    // `fuzz_ams_index_name`.
    let base = unique
        .split(|&octet| octet == b',')
        .next()
        .unwrap_or_default();
    if base.is_empty() {
        return Err(NameError::Empty);
    }
    let mut curseur = Curseur::new(out);
    curseur.pousser(unique)?;
    curseur.pousser(b",U=")?;
    curseur.pousser_nombre(u64::from(uid.value()))?;
    curseur.pousser(b",S=")?;
    curseur.pousser_nombre(size)?;
    if let Some(flags) = flags {
        curseur.pousser(b":2,")?;
        curseur.pousser_drapeaux(flags)?;
    }
    Ok(curseur.ecrits())
}

/// Écrit dans un tampon sans jamais en sortir.
struct Curseur<'a> {
    out: &'a mut [u8],
    ecrits: usize,
}

impl<'a> Curseur<'a> {
    fn new(out: &'a mut [u8]) -> Self {
        Self { out, ecrits: 0 }
    }

    fn ecrits(&self) -> usize {
        self.ecrits
    }

    fn pousser(&mut self, octets: &[u8]) -> Result<(), NameError> {
        let fin = self.ecrits.saturating_add(octets.len());
        let cible = self
            .out
            .get_mut(self.ecrits..fin)
            .ok_or(NameError::BufferTooSmall)?;
        cible.copy_from_slice(octets);
        self.ecrits = fin;
        Ok(())
    }

    fn pousser_nombre(&mut self, valeur: u64) -> Result<(), NameError> {
        let mut chiffres = [0_u8; 20];
        let mut debut = chiffres.len();
        let mut reste = valeur;
        loop {
            debut = debut.saturating_sub(1);
            let chiffre = u8::try_from(reste.wrapping_rem(10)).unwrap_or(0);
            chiffres[debut] = b'0'.wrapping_add(chiffre);
            reste = reste.wrapping_div(10);
            if reste == 0 {
                break;
            }
        }
        self.pousser(chiffres.get(debut..).unwrap_or_default())
    }

    fn pousser_drapeaux(&mut self, flags: Flags) -> Result<(), NameError> {
        let mut lettres = [0_u8; Flags::MAX_OCTETS];
        let ecrits = flags.write_into(&mut lettres);
        self.pousser(lettres.get(..ecrits).unwrap_or_default())
    }
}

/// Ce qui rend un nom de fichier irrecevable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameError {
    /// Le nom, ou sa partie unique, est vide.
    Empty,
    /// Le nom porte un `/` ou un `:` là où il ne peut pas y en avoir.
    ///
    /// Refusé ici, c'est-à-dire **avant** que le nom n'atteigne le système de
    /// fichiers : une traversée de répertoire ne se rattrape pas après coup.
    PathSeparator,
    /// L'information après `:` n'est pas de la version `2`.
    UnsupportedInfo,
    /// Un champ `U=` ou `S=` ne porte pas un nombre décimal.
    MalformedField,
    /// Un champ `U=0` : la RFC 9051 §2.3.1.1 réserve le zéro.
    ZeroUid,
    /// Le tampon de sortie ne suffit pas.
    BufferTooSmall,
    /// Les drapeaux sont irrecevables.
    Flags(FlagError),
}

impl From<FlagError> for NameError {
    fn from(cause: FlagError) -> Self {
        NameError::Flags(cause)
    }
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NameError::Empty => f.write_str("nom de fichier vide"),
            NameError::PathSeparator => f.write_str("nom de fichier portant un `/` ou un `:`"),
            NameError::UnsupportedInfo => f.write_str("information de nom autre que la version 2"),
            NameError::MalformedField => f.write_str("champ `U=` ou `S=` non décimal"),
            NameError::ZeroUid => f.write_str("UID nul, réservé par la RFC 9051"),
            NameError::BufferTooSmall => f.write_str("tampon de nom trop petit"),
            NameError::Flags(cause) => write!(f, "drapeaux : {cause}"),
        }
    }
}

/// Lit un décimal, sans zéro de tête et sans débordement.
fn lire_u64(octets: &[u8]) -> Result<u64, NameError> {
    // Un zéro de tête ferait de `010` un nombre que deux lecteurs pourraient lire
    // différemment — même divergence qu'un littéral IPv4 octal.
    let refus = match octets {
        [] => true,
        [b'0'] => false,
        [b'0', ..] => true,
        _ => false,
    };
    if refus {
        return Err(NameError::MalformedField);
    }
    let mut valeur = 0_u64;
    for &octet in octets {
        if !octet.is_ascii_digit() {
            return Err(NameError::MalformedField);
        }
        valeur = valeur
            .checked_mul(10)
            .and_then(|dix| dix.checked_add(u64::from(octet.wrapping_sub(b'0'))))
            .ok_or(NameError::MalformedField)?;
    }
    Ok(valeur)
}

/// Idem, borné à `u32`.
fn lire_u32(octets: &[u8]) -> Result<u32, NameError> {
    u32::try_from(lire_u64(octets)?).map_err(|_| NameError::MalformedField)
}

#[cfg(test)]
mod tests {
    use super::{MessageName, NameError, Uid, compose};
    use crate::{FlagError, Flags};

    fn compose_dans(tampon: &mut [u8], flags: Option<Flags>) -> Result<usize, NameError> {
        compose(
            tampon,
            b"1724832000.M1.mail.example.com",
            Uid::new(42).expect("non nul"),
            1024,
            flags,
        )
    }

    // ── L'aller-retour ──────────────────────────────────────────────────────

    #[test]
    fn un_nom_compose_se_relit_a_l_identique() {
        for (flags, attendu) in [
            (
                None,
                b"1724832000.M1.mail.example.com,U=42,S=1024".as_slice(),
            ),
            (
                Some(Flags::NONE),
                b"1724832000.M1.mail.example.com,U=42,S=1024:2,",
            ),
            (
                Some(Flags::SEEN.with(Flags::REPLIED)),
                b"1724832000.M1.mail.example.com,U=42,S=1024:2,RS",
            ),
        ] {
            let mut tampon = [0_u8; 128];
            let ecrits = compose_dans(&mut tampon, flags).expect("composable");
            assert_eq!(&tampon[..ecrits], attendu);

            let lu = MessageName::parse(&tampon[..ecrits]).expect("relisible");
            assert_eq!(lu.uid().map(Uid::value), Some(42));
            assert_eq!(lu.size(), Some(1024));
            assert_eq!(lu.flags(), flags.unwrap_or(Flags::NONE));
            assert_eq!(lu.has_info(), flags.is_some());
            assert_eq!(lu.unique(), b"1724832000.M1.mail.example.com,U=42,S=1024");
        }
    }

    #[test]
    fn un_nom_depose_par_un_autre_outil_se_lit_sans_uid() {
        let lu = MessageName::parse(b"1724832000.M1.hote:2,S").expect("relisible");
        assert_eq!(lu.uid(), None);
        assert_eq!(lu.size(), None);
        assert!(lu.flags().contains(Flags::SEEN));
    }

    #[test]
    fn les_champs_inconnus_sont_preserves_dans_la_partie_unique() {
        // Un autre outil peut y avoir posé le sien ; le jeter au premier
        // `rename()` lui ferait perdre ce qu'il y avait mis.
        let lu = MessageName::parse(b"1724832000.M1.hote,W=99,U=7,X=zz").expect("relisible");
        assert_eq!(lu.uid().map(Uid::value), Some(7));
        assert_eq!(lu.unique(), b"1724832000.M1.hote,W=99,U=7,X=zz");
    }

    // ── Les refus ───────────────────────────────────────────────────────────

    #[test]
    fn un_separateur_de_chemin_est_refuse_avant_le_systeme_de_fichiers() {
        // Une traversée de répertoire ne se rattrape pas après coup.
        assert_eq!(
            MessageName::parse(b"../../etc/passwd"),
            Err(NameError::PathSeparator)
        );
        let mut tampon = [0_u8; 128];
        assert_eq!(
            compose(&mut tampon, b"a/b", Uid::FIRST, 0, None),
            Err(NameError::PathSeparator)
        );
        assert_eq!(
            compose(&mut tampon, b"a:b", Uid::FIRST, 0, None),
            Err(NameError::PathSeparator)
        );
    }

    #[test]
    fn les_noms_mal_formes_sont_refuses() {
        for (nom, attendu) in [
            (b"".as_slice(), NameError::Empty),
            (b":2,S", NameError::Empty),
            (b"base:3,S", NameError::UnsupportedInfo),
            (b"base:", NameError::UnsupportedInfo),
            (b"base,U=", NameError::MalformedField),
            (b"base,U=x", NameError::MalformedField),
            (b"base,U=07", NameError::MalformedField),
            (b"base,U=0", NameError::ZeroUid),
            (b"base,U=4294967296", NameError::MalformedField),
            (b"base,S=99999999999999999999999", NameError::MalformedField),
            (b"base:2,x", NameError::Flags(FlagError::UnknownLetter)),
        ] {
            assert_eq!(MessageName::parse(nom), Err(attendu), "sur {nom:?}");
        }
    }

    #[test]
    fn une_partie_unique_sans_base_est_refusee() {
        // Le nom composé serait illisible, et le défaut ne se verrait qu'au
        // parcours suivant — quand l'UID redeviendrait introuvable.
        let mut tampon = [0_u8; 128];
        for unique in [b"".as_slice(), b",", b",deja=un-champ"] {
            assert_eq!(
                compose(&mut tampon, unique, Uid::FIRST, 0, None),
                Err(NameError::Empty),
                "sur {unique:?}"
            );
        }
    }

    #[test]
    fn un_zero_seul_reste_une_taille_licite() {
        let lu = MessageName::parse(b"base,S=0").expect("relisible");
        assert_eq!(lu.size(), Some(0));
    }

    #[test]
    fn un_tampon_trop_petit_est_refuse_a_chaque_etape() {
        // Le nom composé fait 46 octets : 30 pour la partie unique, puis `,U=`,
        // `42`, `,S=`, `1024`, `:2,` et `S`. Chacune de ces additions est un
        // endroit où le tampon peut manquer, et une borne vérifiée à un seul
        // endroit se contourne par les autres.
        for taille in [0_usize, 8, 32, 34, 37, 41, 44, 45] {
            let mut tampon = std::vec![0_u8; taille];
            assert_eq!(
                compose_dans(&mut tampon, Some(Flags::SEEN)),
                Err(NameError::BufferTooSmall),
                "un tampon de {taille} octets ne devrait pas suffire"
            );
        }
        // Quarante-six suffisent exactement.
        let mut juste = [0_u8; 46];
        assert_eq!(compose_dans(&mut juste, Some(Flags::SEEN)), Ok(46));
    }

    // ── L'UID ───────────────────────────────────────────────────────────────

    #[test]
    fn le_zero_n_est_pas_un_uid() {
        // RFC 9051 §2.3.1.1 : il désignerait un message qui n'existe pas.
        assert_eq!(Uid::new(0), None);
        assert_eq!(Uid::new(1), Some(Uid::FIRST));
        assert_eq!(Uid::FIRST.value(), 1);
    }

    #[test]
    fn le_dernier_uid_n_a_pas_de_suivant() {
        // C'est à ce moment-là que l'`UIDVALIDITY` doit changer.
        let dernier = Uid::new(u32::MAX).expect("non nul");
        assert_eq!(dernier.next(), None);
        assert_eq!(Uid::FIRST.next().map(Uid::value), Some(2));
    }

    #[test]
    fn un_gros_uid_traverse_la_composition() {
        let mut tampon = [0_u8; 128];
        let ecrits = compose(
            &mut tampon,
            b"base",
            Uid::new(u32::MAX).expect("non nul"),
            u64::MAX,
            None,
        )
        .expect("composable");
        let lu = MessageName::parse(&tampon[..ecrits]).expect("relisible");
        assert_eq!(lu.uid().map(Uid::value), Some(u32::MAX));
        assert_eq!(lu.size(), Some(u64::MAX));
    }

    #[test]
    fn les_types_se_copient_et_se_deboguent() {
        let lu = MessageName::parse(b"base,U=1").expect("relisible");
        let copie = lu;
        assert_eq!(copie, lu);
        assert!(!std::format!("{lu:?}").is_empty());
        assert!(Uid::FIRST < Uid::new(2).expect("non nul"));
        assert!(!std::format!("{:?}", Uid::FIRST).is_empty());
        for erreur in [
            NameError::Empty,
            NameError::PathSeparator,
            NameError::UnsupportedInfo,
            NameError::MalformedField,
            NameError::ZeroUid,
            NameError::BufferTooSmall,
            NameError::Flags(FlagError::OutOfOrder),
        ] {
            assert!(std::format!("{erreur}").len() > 10, "{erreur:?}");
            assert!(!std::format!("{erreur:?}").is_empty());
        }
        assert_ne!(NameError::Empty, NameError::ZeroUid);
    }
}
