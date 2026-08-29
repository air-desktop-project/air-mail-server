//! Le nom du fichier et la ligne de sujet (RFC 7489 §7.2.1.1).
//!
//! # Pourquoi ces deux chaînes sont normalisées
//!
//! Un rapport arrive chez son destinataire par courrier, au milieu d'un flux
//! qu'aucun humain ne lit. Ce qui le trie est son **nom de fichier** et sa
//! **ligne de sujet** — et un domaine qui reçoit des rapports de dix mille
//! receveurs ne peut les trier que si tous écrivent pareil. C'est la seule
//! raison pour laquelle la RFC impose une forme exacte à deux chaînes de
//! caractères, et c'est une bonne raison.
//!
//! # CE NOM DEVIENT UN FICHIER CHEZ AUTRUI
//!
//! Le domaine qui publie la politique est choisi par celui qu'on rapporte. Le
//! recopier tel quel dans un nom de fichier serait offrir à n'importe qui
//! d'écrire `../../etc/` dans l'arborescence de tous ses correspondants.
//! **Seules les lettres, les chiffres, le tiret et le point passent** ici — ce
//! qui est exactement ce qu'un nom de domaine a le droit de porter.

use crate::Error;

/// La longueur d'un nom de fichier : deux domaines, deux dates, un identifiant.
pub const FILENAME_MAX: usize = 255 + 1 + 255 + 1 + 20 + 1 + 20 + 1 + 64 + 7;

/// La longueur d'une ligne de sujet.
pub const SUBJECT_MAX: usize = 64 + 255 + 255 + 64;

/// Écrit le nom du fichier joint (§7.2.1.1).
///
/// La forme est `receveur!domaine!début!fin[!identifiant].xml.gz`. L'extension
/// n'est pas un choix : §7.2.1 impose la compression `gzip` pour les rapports
/// remis par courrier, et un nom qui mentirait sur son contenu ferait rejeter
/// le rapport par l'outil qui l'ouvre.
///
/// # Errors
///
/// [`Error::NotPrintable`] si un domaine ou l'identifiant porte autre chose que
/// des lettres, des chiffres, un tiret ou un point ; [`Error::DomainTooLong`] si
/// un domaine dépasse 255 octets ; [`Error::BufferTooSmall`] si `out` ne suffit
/// pas.
pub fn filename<'b>(
    receiver: &[u8],
    policy_domain: &[u8],
    begin: u64,
    end: u64,
    unique: Option<&[u8]>,
    out: &'b mut [u8],
) -> Result<&'b [u8], Error> {
    let mut plume = Plume::neuve(out);
    plume.nom(receiver)?;
    plume.pousser(b"!")?;
    plume.nom(policy_domain)?;
    plume.pousser(b"!")?;
    plume.nombre(begin)?;
    plume.pousser(b"!")?;
    plume.nombre(end)?;
    if let Some(identifiant) = unique {
        plume.pousser(b"!")?;
        plume.nom(identifiant)?;
    }
    plume.pousser(b".xml.gz")?;
    Ok(plume.fini())
}

/// Écrit la ligne de sujet, sans le `Subject: ` ni le `CRLF` (§7.2.1.1).
///
/// La forme est `Report Domain: <domaine> Submitter: <receveur> Report-ID:
/// <identifiant>`. Elle se lit à l'œil et se trie à la machine ; c'est tout ce
/// qu'on lui demande.
///
/// # Errors
///
/// Comme [`filename`].
pub fn subject<'b>(
    policy_domain: &[u8],
    receiver: &[u8],
    report_id: &[u8],
    out: &'b mut [u8],
) -> Result<&'b [u8], Error> {
    let mut plume = Plume::neuve(out);
    plume.pousser(b"Report Domain: ")?;
    plume.nom(policy_domain)?;
    plume.pousser(b" Submitter: ")?;
    plume.nom(receiver)?;
    plume.pousser(b" Report-ID: ")?;
    plume.nom(report_id)?;
    Ok(plume.fini())
}

/// De quoi écrire une chaîne dont chaque octet a été regardé.
struct Plume<'a> {
    out: &'a mut [u8],
    ecrits: usize,
}

impl<'a> Plume<'a> {
    fn neuve(out: &'a mut [u8]) -> Self {
        Self { out, ecrits: 0 }
    }

    fn pousser(&mut self, morceau: &[u8]) -> Result<(), Error> {
        let fin = self.ecrits.saturating_add(morceau.len());
        let place = self
            .out
            .get_mut(self.ecrits..fin)
            .ok_or(Error::BufferTooSmall)?;
        place.copy_from_slice(morceau);
        self.ecrits = fin;
        Ok(())
    }

    /// Écrit un nom, après avoir vérifié qu'il n'en est pas un autre.
    ///
    /// # L'ÉTIQUETTE VIDE EST REFUSÉE, et c'est le fuzzer qui l'a demandé
    ///
    /// La première écriture n'admettait que des lettres, des chiffres, un
    /// tiret, un point et un souligné — ce qui laissait passer `a..b`, et donc
    /// un `..` dans un nom de fichier. Aucune barre oblique ne pouvait
    /// l'accompagner, donc rien n'était exploitable ; mais `a..b` n'est pas un
    /// domaine, et laisser entrer ce qui n'est pas un domaine pour se reposer
    /// sur l'absence d'un second octet est exactement le raisonnement qui finit
    /// par céder. **Chaque étiquette doit porter quelque chose.**
    fn nom(&mut self, valeur: &[u8]) -> Result<(), Error> {
        if valeur.len() > 255 {
            return Err(Error::DomainTooLong);
        }
        let etiquettes_pleines = !valeur.is_empty()
            && !valeur.split(|o| *o == b'.').any(<[u8]>::is_empty)
            && valeur
                .iter()
                .all(|o| o.is_ascii_alphanumeric() || matches!(*o, b'-' | b'.' | b'_'));
        if !etiquettes_pleines {
            return Err(Error::NotPrintable);
        }
        self.pousser(valeur)
    }

    /// Écrit un entier décimal, sans passer par `core::fmt`.
    ///
    /// # Vingt tours, toujours
    ///
    /// Vingt chiffres majorent tout `u64`, et la boucle les parcourt TOUS —
    /// même pour écrire zéro. S'arrêter plus tôt demanderait un indice, donc
    /// une borne, donc une garde qu'aucun appel ne peut faire céder : une garde
    /// inatteignable n'est pas une garde, c'est une affirmation non vérifiée.
    fn nombre(&mut self, valeur: u64) -> Result<(), Error> {
        let mut chiffres = [b'0'; 20];
        let mut reste = valeur;
        let mut significatifs = 1_usize;
        for (rang, place) in chiffres.iter_mut().rev().enumerate() {
            *place = b'0'.wrapping_add(u8::try_from(reste % 10).unwrap_or_default());
            reste /= 10;
            if reste != 0 {
                significatifs = rang.saturating_add(2);
            }
        }
        let debut = chiffres.len().saturating_sub(significatifs);
        for octet in chiffres.iter().skip(debut) {
            self.pousser(core::slice::from_ref(octet))?;
        }
        Ok(())
    }

    fn fini(self) -> &'a [u8] {
        self.out.get(..self.ecrits).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests;
