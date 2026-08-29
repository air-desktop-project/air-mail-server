//! Les listes `tag=valeur` de DMARC (RFC 7489 §6.4).
//!
//! # Pourquoi ce n'est pas la grammaire de DKIM
//!
//! Les deux se ressemblent — `tag=valeur`, séparées par des points-virgules —
//! et elles ne sont pas les mêmes. DKIM (RFC 6376 §3.2) admet des blancs entre
//! deux morceaux d'une valeur ; DMARC ne le prévoit pas, et sa liste de
//! rapports (`rua=`) porte des virgules et des URI que DKIM n'attend nulle part.
//!
//! Partager un analyseur entre les deux ferait qu'un jour, en corrigeant l'un,
//! on casserait l'autre — et rien ne le dirait avant qu'un domaine ne soit mal
//! lu. Deux RFC, deux grammaires, deux analyseurs.

use crate::Error;

/// Une étiquette et sa valeur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag<'a> {
    /// Le nom, en minuscules d'origine — la comparaison, elle, ignore la casse.
    pub name: &'a [u8],
    /// La valeur, blancs de tête et de queue retirés.
    pub value: &'a [u8],
}

/// Les étiquettes d'un enregistrement, dans l'ordre.
#[derive(Debug, Clone)]
pub struct Tags<'a> {
    reste: &'a [u8],
    fini: bool,
}

impl<'a> Tags<'a> {
    /// Ouvre la lecture.
    #[must_use]
    pub fn new(enregistrement: &'a [u8]) -> Self {
        Self {
            reste: enregistrement,
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
        let (morceau, suite) = match self.reste.iter().position(|octet| *octet == b';') {
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

        let morceau = morceau.trim_ascii();
        if morceau.is_empty() {
            // Le point-virgule final est permis — bien des enregistrements
            // l'écrivent — et lui seul. Une étiquette vide AU MILIEU est une
            // faute : on ne devine pas ce que son auteur voulait écrire.
            if self.fini || self.reste.trim_ascii().is_empty() {
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
    let rang = morceau
        .iter()
        .position(|octet| *octet == b'=')
        .ok_or(Error::MalformedTagList)?;
    let (nom, apres) = morceau.split_at(rang);
    let nom = nom.trim_ascii();
    let valeur = apres.get(1..).unwrap_or_default().trim_ascii();

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
    // La valeur est de l'ASCII imprimable, point-virgule exclu — il sépare. Un
    // octet de contrôle dans un enregistrement DNS n'est pas une valeur, c'est
    // un enregistrement qu'on ne sait pas lire.
    if !valeur
        .iter()
        .all(|octet| (0x20..=0x7E).contains(octet) && *octet != b';')
    {
        return Err(Error::MalformedTagValue);
    }
    Ok(Tag {
        name: nom,
        value: valeur,
    })
}

#[cfg(test)]
mod tests;
