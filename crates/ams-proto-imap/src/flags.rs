//! Les DRAPEAUX d'un message (RFC 9051 §2.3.2), et la date d'arrivée.
//!
//! # Cinq drapeaux, et un seul compte vraiment
//!
//! `\Seen` est le seul que le protocole modifie tout seul : lire un message le
//! pose (§6.4.5), et c'est pourquoi `BODY.PEEK[]` existe. Les quatre autres —
//! `\Answered`, `\Flagged`, `\Deleted`, `\Draft` — ne bougent que sur un
//! `STORE`.
//!
//! `\Recent` n'est pas ici : la RFC 9051 §2.3.2 l'a retiré d'IMAP4rev2, avec
//! toute la machinerie de session qu'il traînait.
//!
//! # CINQ MOTS-CLEFS, ET L'ENSEMBLE EST FERMÉ
//!
//! §2.3.2 admet des mots-clefs propres à chaque serveur, et §E.15 en recommande
//! cinq : `$MDNSent`, `$Forwarded`, `$Junk`, `$NonJunk`, `$Phishing`. Ce serveur
//! sert ceux-là, et **refuse les autres** plutôt que d'en accepter n'importe
//! lequel.
//!
//! Le refus est la partie qui compte. Un serveur qui accepte un mot-clef qu'il ne
//! sait pas faire survivre répond `OK` à un client qui pose une étiquette — et
//! cette étiquette ne se reverra jamais, sans que personne sache pourquoi. C'est
//! aussi pourquoi `PERMANENTFLAGS` n'annonce PAS `\*` : `\*` promet qu'on
//! accepte tout mot-clef nouveau, et cette promesse-là, on ne la tient pas.
//!
//! # La date d'arrivée n'est pas la date du message
//!
//! `INTERNALDATE` dit quand le message est arrivé ICI ; le `Date:` du message
//! dit ce que son auteur a écrit. Les deux diffèrent, parfois de beaucoup, et
//! un client qui trie par l'un ne trie pas par l'autre. Son écriture n'est pas
//! non plus celle de la RFC 5322 : `"29-Aug-2026 09:08:31 +0000"`, guillemets
//! compris. Deux formats, deux écrivains.

use crate::Error;

/// Les drapeaux d'un message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags(u16);

/// Les dix drapeaux servis, avec leur bit et leur nom.
///
/// **L'ORDRE EST CELUI DE LA RÉPONSE** : les cinq systèmes d'abord, les cinq
/// mots-clefs ensuite. Rien ne l'exige, mais un ordre stable rend une réponse
/// comparable d'une fois sur l'autre.
const CONNUS: [(u16, &[u8]); 10] = [
    (0b0000_0000_0000_0001, b"\\Seen"),
    (0b0000_0000_0000_0010, b"\\Answered"),
    (0b0000_0000_0000_0100, b"\\Flagged"),
    (0b0000_0000_0000_1000, b"\\Deleted"),
    (0b0000_0000_0001_0000, b"\\Draft"),
    (0b0000_0000_0010_0000, b"$MDNSent"),
    (0b0000_0000_0100_0000, b"$Forwarded"),
    (0b0000_0000_1000_0000, b"$Junk"),
    (0b0000_0001_0000_0000, b"$NonJunk"),
    (0b0000_0010_0000_0000, b"$Phishing"),
];

impl Flags {
    /// Aucun drapeau.
    pub const NONE: Self = Self(0);
    /// `\Seen` — le message a été lu.
    pub const SEEN: Self = Self(0b0000_0000_0000_0001);
    /// `\Answered` — on y a répondu.
    pub const ANSWERED: Self = Self(0b0000_0000_0000_0010);
    /// `\Flagged` — marqué comme important.
    pub const FLAGGED: Self = Self(0b0000_0000_0000_0100);
    /// `\Deleted` — marqué pour effacement.
    pub const DELETED: Self = Self(0b0000_0000_0000_1000);
    /// `\Draft` — brouillon.
    pub const DRAFT: Self = Self(0b0000_0000_0001_0000);
    /// `$MDNSent` — un accusé de réception a été envoyé.
    pub const MDN_SENT: Self = Self(0b0000_0000_0010_0000);
    /// `$Forwarded` — le message a été transmis.
    pub const FORWARDED: Self = Self(0b0000_0000_0100_0000);
    /// `$Junk` — le destinataire le tient pour indésirable.
    pub const JUNK: Self = Self(0b0000_0000_1000_0000);
    /// `$NonJunk` — le destinataire le tient pour désirable.
    ///
    /// **CE N'EST PAS L'INVERSE DE `$Junk`** : les deux peuvent manquer, et cela
    /// veut dire « personne n'a tranché ». Les traiter comme un seul drapeau
    /// perdrait cette troisième réponse, qui est la plus fréquente.
    pub const NON_JUNK: Self = Self(0b0000_0001_0000_0000);
    /// `$Phishing` — le message tente d'usurper une identité.
    pub const PHISHING: Self = Self(0b0000_0010_0000_0000);

    /// Ce drapeau est-il posé ?
    #[must_use]
    pub const fn contains(self, autre: Self) -> bool {
        self.0 & autre.0 == autre.0
    }

    /// Les deux réunis.
    #[must_use]
    pub const fn with(self, autre: Self) -> Self {
        Self(self.0 | autre.0)
    }

    /// Le premier sans le second.
    #[must_use]
    pub const fn without(self, autre: Self) -> Self {
        Self(self.0 & !autre.0)
    }

    /// Écrit les drapeaux séparés par des espaces, sans parenthèses.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] si `out` ne suffit pas.
    pub fn write(self, out: &mut [u8]) -> Result<&[u8], Error> {
        /// Les dix, leurs espaces comprises.
        const BESOIN: usize = 92;
        let mut ecrits = 0_usize;
        for (bit, nom) in CONNUS {
            if self.0 & bit == 0 {
                continue;
            }
            if ecrits > 0 {
                ecrits = pousser(out, ecrits, b" ")?;
            }
            ecrits = pousser(out, ecrits, nom)?;
        }
        out.get(..ecrits)
            .ok_or(Error::BufferTooSmall { needed: BESOIN })
    }

    /// Lit un nom de drapeau. Rend `None` pour ce qu'on ne sert pas.
    ///
    /// # UN MOT-CLEF QU'ON NE SAIT PAS FAIRE SURVIVRE SE REFUSE
    ///
    /// §2.3.2 admet des mots-clefs propres à chaque serveur, et n'oblige aucun
    /// serveur à en accepter. **Ce serveur en sert cinq** — ceux de §E.15 — et
    /// rend `None` pour tout le reste, ce que l'appelant traduit en refus. Le
    /// taire ferait répondre `OK` à un client qui pose une étiquette, et cette
    /// étiquette ne se reverrait jamais.
    #[must_use]
    pub fn parse_one(nom: &[u8]) -> Option<Self> {
        CONNUS
            .iter()
            .find(|(_, connu)| connu.eq_ignore_ascii_case(nom))
            .map(|(bit, _)| Self(*bit))
    }
}

/// La longueur d'une date d'arrivée, guillemets compris.
pub const INTERNALDATE_MAX: usize = 32;

/// Écrit une date d'arrivée : `"29-Aug-2026 09:08:31 +0000"`.
///
/// # Errors
///
/// [`Error::BufferTooSmall`] si `out` ne suffit pas.
pub fn write_internal_date(epoch_seconds: u64, out: &mut [u8]) -> Result<&[u8], Error> {
    const MOIS: [&[u8]; 12] = [
        b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov",
        b"Dec",
    ];
    let jours = epoch_seconds / 86_400;
    let dans_le_jour = epoch_seconds % 86_400;
    let (annee, mois, jour) = civil(jours);

    let mut ecrits = pousser(out, 0, b"\"")?;
    ecrits = nombre(out, ecrits, jour, 2)?;
    ecrits = pousser(out, ecrits, b"-")?;
    let rang = usize::try_from(mois.saturating_sub(1)).unwrap_or(0);
    ecrits = pousser(out, ecrits, MOIS.get(rang).copied().unwrap_or(b"Jan"))?;
    ecrits = pousser(out, ecrits, b"-")?;
    ecrits = nombre(out, ecrits, annee, 4)?;
    ecrits = pousser(out, ecrits, b" ")?;
    ecrits = nombre(out, ecrits, dans_le_jour / 3_600, 2)?;
    ecrits = pousser(out, ecrits, b":")?;
    ecrits = nombre(out, ecrits, (dans_le_jour / 60) % 60, 2)?;
    ecrits = pousser(out, ecrits, b":")?;
    ecrits = nombre(out, ecrits, dans_le_jour % 60, 2)?;
    ecrits = pousser(out, ecrits, b" +0000\"")?;
    out.get(..ecrits).ok_or(Error::BufferTooSmall {
        needed: INTERNALDATE_MAX,
    })
}

/// La date civile d'un nombre de jours depuis l'époque.
///
/// L'algorithme de Howard Hinnant, comme dans `ams-mime` : il déplace l'origine
/// au 1er mars, ce qui met le jour bissextile là où il ne décale plus rien.
/// **Il est écrit ici et là-bas** parce que les deux crates ne se connaissent
/// pas — et qu'un serveur de courrier n'est pas l'endroit où l'on crée une
/// dépendance pour trente lignes d'arithmétique vérifiable.
fn civil(jours: u64) -> (u64, u64, u64) {
    let z = jours.saturating_add(719_468);
    let ere = z / 146_097;
    let jour_de_l_ere = z % 146_097;
    let an_de_l_ere = jour_de_l_ere
        .saturating_sub(jour_de_l_ere / 1_460)
        .saturating_add(jour_de_l_ere / 36_524)
        .saturating_sub(jour_de_l_ere / 146_096)
        / 365;
    let annee = an_de_l_ere.saturating_add(ere.saturating_mul(400));
    let jour_de_l_an = jour_de_l_ere.saturating_sub(
        an_de_l_ere
            .saturating_mul(365)
            .saturating_add(an_de_l_ere / 4)
            .saturating_sub(an_de_l_ere / 100),
    );
    let mois_decale = jour_de_l_an.saturating_mul(5).saturating_add(2) / 153;
    let jour = jour_de_l_an
        .saturating_sub(mois_decale.saturating_mul(153).saturating_add(2) / 5)
        .saturating_add(1);
    if mois_decale < 10 {
        (annee, mois_decale.saturating_add(3), jour)
    } else {
        (annee.saturating_add(1), mois_decale.saturating_sub(9), jour)
    }
}

/// Écrit un nombre décimal sur `largeur` chiffres au moins.
fn nombre(out: &mut [u8], ecrits: usize, valeur: u64, largeur: usize) -> Result<usize, Error> {
    let mut chiffres = [b'0'; 20];
    let mut reste = valeur;
    let mut significatifs = largeur.max(1);
    for (rang, place) in chiffres.iter_mut().rev().enumerate() {
        *place = b'0'.wrapping_add(u8::try_from(reste % 10).unwrap_or_default());
        reste /= 10;
        if reste != 0 {
            significatifs = significatifs.max(rang.saturating_add(2));
        }
    }
    let debut = chiffres.len().saturating_sub(significatifs);
    pousser(out, ecrits, chiffres.get(debut..).unwrap_or_default())
}

/// Recopie `morceau`, et rend le nouveau compte.
fn pousser(out: &mut [u8], ecrits: usize, morceau: &[u8]) -> Result<usize, Error> {
    let fin = ecrits.saturating_add(morceau.len());
    let place = out
        .get_mut(ecrits..fin)
        .ok_or(Error::BufferTooSmall { needed: fin })?;
    place.copy_from_slice(morceau);
    Ok(fin)
}

#[cfg(test)]
mod tests;
