//! Les listes `tag=valeur` (RFC 6376 §3.2), communes à la signature et à la clé.

use crate::Error;

/// Une étiquette et sa valeur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag<'a> {
    /// Le nom, tel qu'il a été écrit — **sensible à la casse** (§3.2).
    pub name: &'a [u8],
    /// La valeur, blancs de tête et de queue retirés. Elle peut encore porter
    /// des blancs INTERNES : la grammaire les admet entre deux morceaux, et
    /// c'est à chaque étiquette de dire ce qu'elle en fait.
    pub value: &'a [u8],
}

/// Les étiquettes d'une liste, dans l'ordre.
///
/// # Elle rend des `Result`, et l'appelant les consomme TOUS
///
/// Une liste dont la queue est illisible n'est pas une liste dont on prend le
/// début : RFC 6376 §3.9 veut qu'une signature mal formée échoue, pas qu'elle
/// s'applique à moitié. Les analyseurs de cette crate parcourent donc la liste
/// entière avant de rendre quoi que ce soit.
#[derive(Debug, Clone)]
pub struct Tags<'a> {
    reste: &'a [u8],
    /// A-t-on déjà rendu la dernière étiquette ?
    fini: bool,
}

impl<'a> Tags<'a> {
    /// Ouvre la lecture d'une liste.
    #[must_use]
    pub fn new(liste: &'a [u8]) -> Self {
        Self {
            reste: liste,
            fini: false,
        }
    }
}

impl<'a> Iterator for Tags<'a> {
    type Item = Result<Tag<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.fini {
            return None;
        }
        let (morceau, suite) = match position(self.reste, b';') {
            Some(rang) => {
                let (avant, apres) = self.reste.split_at(rang);
                (avant, apres.get(1..).unwrap_or_default())
            }
            None => {
                self.fini = true;
                (self.reste, &[][..])
            }
        };
        self.reste = suite;

        let morceau = elaguer(morceau);
        if morceau.is_empty() {
            // Le point-virgule final est permis, et lui seul : `tag-list` finit
            // par `[ ";" ]`. Une étiquette vide AU MILIEU est une faute — on ne
            // devine pas ce que son auteur voulait écrire.
            if self.fini || elaguer(self.reste).is_empty() {
                self.fini = true;
                return None;
            }
            return Some(Err(Error::MalformedTagList));
        }

        Some(lire_une(morceau))
    }
}

/// Lit une étiquette, blancs déjà retirés aux deux bouts.
fn lire_une(morceau: &[u8]) -> Result<Tag<'_>, Error> {
    let rang = position(morceau, b'=').ok_or(Error::MalformedTagList)?;
    let (nom, apres) = morceau.split_at(rang);
    let valeur = elaguer(apres.get(1..).unwrap_or_default());
    let nom = elaguer(nom);

    let (&premier, suite) = nom.split_first().ok_or(Error::MalformedTagName)?;
    if !premier.is_ascii_alphabetic() {
        return Err(Error::MalformedTagName);
    }
    if !suite
        .iter()
        .all(|octet| octet.is_ascii_alphanumeric() || *octet == b'_')
    {
        return Err(Error::MalformedTagName);
    }
    if !valeur
        .iter()
        .all(|octet| est_valchar(*octet) || est_blanc(*octet))
    {
        return Err(Error::MalformedTagValue);
    }
    Ok(Tag {
        name: nom,
        value: valeur,
    })
}

/// Un octet de valeur (§3.2, `VALCHAR`).
///
/// # L'ABNF de la RFC dit une chose, son commentaire en dit une autre
///
/// `VALCHAR = %x21-3A / %x3C / %x3E-7E` exclut le point-virgule (`3B`) **et le
/// signe égal** (`3D`), alors que le commentaire qui la suit dit « de `!` à `~`
/// sauf le point-virgule ». Les deux ne peuvent pas être vrais : un `b=` en
/// base64 se termine par des `=` de remplissage, et aucune signature ne se
/// lirait sous la première lecture. C'est l'erratum 3192, et c'est le
/// commentaire qui a raison.
pub(crate) fn est_valchar(octet: u8) -> bool {
    (0x21..=0x7E).contains(&octet) && octet != b';'
}

/// Un blanc, plié ou non (`FWS` de la RFC 5322).
fn est_blanc(octet: u8) -> bool {
    matches!(octet, b' ' | b'\t' | b'\r' | b'\n')
}

/// Retire les blancs des deux bouts.
fn elaguer(mut morceau: &[u8]) -> &[u8] {
    while let Some((premier, suite)) = morceau.split_first() {
        if !est_blanc(*premier) {
            break;
        }
        morceau = suite;
    }
    while let Some((dernier, debut)) = morceau.split_last() {
        if !est_blanc(*dernier) {
            break;
        }
        morceau = debut;
    }
    morceau
}

/// Le rang du premier `cherche`, s'il y en a un.
fn position(morceau: &[u8], cherche: u8) -> Option<usize> {
    morceau.iter().position(|octet| *octet == cherche)
}

/// Retire TOUS les blancs d'une valeur, y compris internes.
///
/// C'est ce que demandent `b=` et `bh=` (§3.5) : leur base64 peut être plié
/// n'importe où, et les blancs n'en font pas partie. `h=` s'en sert aussi, dont
/// les deux-points admettent des blancs de part et d'autre.
///
/// # Errors
///
/// [`Error::BufferTooSmall`] si `sortie` ne suffit pas.
pub fn sans_blancs<'b>(valeur: &[u8], sortie: &'b mut [u8]) -> Result<&'b [u8], Error> {
    let mut ecrits = 0_usize;
    for octet in valeur.iter().filter(|octet| !est_blanc(**octet)) {
        let case = sortie.get_mut(ecrits).ok_or(Error::BufferTooSmall)?;
        *case = *octet;
        ecrits = ecrits.saturating_add(1);
    }
    sortie.get(..ecrits).ok_or(Error::BufferTooSmall)
}

#[cfg(test)]
mod tests;
