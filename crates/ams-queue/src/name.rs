//! Le nom de fichier d'une entrée de file, qui porte tout son état.

use crate::Error;

/// La longueur maximale d'un identifiant d'entrée.
///
/// Assez pour un compteur et de l'aléa ; assez peu pour qu'un nom de fichier
/// reste sous la borne de tous les systèmes de fichiers usuels.
const ID_MAX: usize = 64;

/// La largeur du champ d'instant, en chiffres.
///
/// **ON COMPLÈTE PAR DES ZÉROS À GAUCHE**, et pas pour faire joli : sans cela,
/// `9999999999` se trierait avant `100000000000`, et un `ls` du répertoire
/// mentirait sur l'ordre des reprises. Douze chiffres portent les instants
/// jusqu'à l'an 33 658.
const LARGEUR: usize = 12;

/// Ce qu'il faut au plus pour écrire un nom.
pub const NAME_MAX: usize = LARGEUR + 1 + 20 + 1 + 10 + 1 + ID_MAX + 4;

/// Ce qu'un nom d'entrée porte.
///
/// # TOUT L'ÉTAT DE LA REPRISE EST ICI
///
/// Il n'y a pas d'index. Un `rename()` change le nom, donc l'état, en une
/// opération que le système de fichiers rend atomique — et une entrée existe
/// sous exactement un nom à tout instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry<'a> {
    /// L'instant du prochain essai, en secondes depuis l'époque.
    pub due: u64,
    /// L'instant du dépôt. C'est de lui que court la péremption.
    pub deposited: u64,
    /// Combien d'essais ont déjà échoué.
    pub attempts: u32,
    /// Ce qui distingue cette entrée des autres déposées à la même seconde.
    pub id: &'a str,
}

/// Écrit `<prochain>!<dépôt>!<essais>!<identifiant>.eml` dans `sortie`.
///
/// # Errors
///
/// [`Error::BadIdentifier`] si l'identifiant ne peut pas devenir un nom de
/// fichier, [`Error::BufferTooSmall`] si `sortie` fait moins de [`NAME_MAX`].
pub fn write_name<'b>(entry: &Entry<'_>, sortie: &'b mut [u8]) -> Result<&'b str, Error> {
    if !identifiant_recevable(entry.id) {
        return Err(Error::BadIdentifier);
    }
    let mut ecrits = 0_usize;
    ecrits = nombre(sortie, ecrits, entry.due, LARGEUR)?;
    ecrits = pousser(sortie, ecrits, b"!")?;
    ecrits = nombre(sortie, ecrits, entry.deposited, LARGEUR)?;
    ecrits = pousser(sortie, ecrits, b"!")?;
    ecrits = nombre(sortie, ecrits, u64::from(entry.attempts), 1)?;
    ecrits = pousser(sortie, ecrits, b"!")?;
    ecrits = pousser(sortie, ecrits, entry.id.as_bytes())?;
    ecrits = pousser(sortie, ecrits, b".eml")?;
    // `pousser` a déjà écrit jusqu'à `ecrits` : la découpe ne peut pas manquer,
    // et `unwrap_or_default` porte cette impossibilité dans la bibliothèque
    // standard plutôt que dans une garde que rien n'atteindrait.
    let ecrit = sortie.get(..ecrits).unwrap_or_default();
    // TOUT CE QU'ON VIENT D'ÉCRIRE EST DE L'ASCII : des chiffres, des points
    // d'exclamation, un identifiant dont `identifiant_recevable` a vérifié
    // chaque octet, et un suffixe littéral. Il n'y a pas d'entrée capable de
    // faire échouer cette conversion.
    Ok(core::str::from_utf8(ecrit).unwrap_or_default())
}

/// Découpe `<prochain>!<dépôt>!<essais>!<identifiant>.eml`.
///
/// **Rien de ce qui n'a pas cette forme n'est touché.** Un répertoire qu'on
/// partage avec autre chose ne se reprend pas au jugé, et ne s'efface pas non
/// plus.
#[must_use]
pub fn parse_name(nom: &str) -> Option<Entry<'_>> {
    let corps = nom.strip_suffix(".eml")?;
    let mut parts = corps.split('!');
    // `split` rend TOUJOURS au moins un morceau, même sur une chaîne vide : ce
    // premier appel ne peut pas manquer.
    let due = parts.next().unwrap_or_default().parse().ok()?;
    let deposited = parts.next()?.parse().ok()?;
    let attempts = parts.next()?.parse().ok()?;
    let id = parts.next()?;
    // **UN QUATRIÈME SÉPARATEUR REND `None`**, et ne se laisse pas absorber dans
    // l'identifiant : sans cela, un nom qu'on écrirait ne se relirait pas
    // toujours à l'identique, et la file oublierait des essais.
    if parts.next().is_some() || !identifiant_recevable(id) {
        return None;
    }
    Some(Entry {
        due,
        deposited,
        attempts,
        id,
    })
}

/// Cet identifiant peut-il devenir un nom de fichier ?
///
/// Lettres, chiffres et tirets, et rien d'autre. **Un `/` désignerait un autre
/// répertoire, un `.` en tête cacherait le fichier, et un `!` casserait le
/// découpage du nom** — les trois sont des façons de sortir de la file.
fn identifiant_recevable(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= ID_MAX
        && id
            .bytes()
            .all(|octet| octet.is_ascii_alphanumeric() || octet == b'-')
}

/// Combien de chiffres décimaux `valeur` occupe.
fn largeur_de(valeur: u64) -> usize {
    let mut combien = 1_usize;
    let mut reste = valeur;
    while reste >= 10 {
        reste /= 10;
        combien = combien.saturating_add(1);
    }
    combien
}

/// Écrit `valeur` en décimal, complété par des zéros jusqu'à `largeur`.
///
/// **UNE VALEUR PLUS LARGE QUE `largeur` ALLONGE LE NOM**, elle ne se tronque
/// pas : un instant tronqué ferait mentir le nom sur la date de la reprise, et
/// un nom qui ment est pire qu'un nom long.
fn nombre(sortie: &mut [u8], ecrits: usize, valeur: u64, largeur: usize) -> Result<usize, Error> {
    let largeur = largeur.max(largeur_de(valeur));
    let fin = ecrits.saturating_add(largeur);
    let place = sortie.get_mut(ecrits..fin).ok_or(Error::BufferTooSmall)?;
    let mut reste = valeur;
    // Des unités vers le poids fort : `rev()` écrit à l'endroit sans qu'aucun
    // index ne soit calculé, et remplit de zéros ce qui reste devant.
    for octet in place.iter_mut().rev() {
        *octet = b'0'.saturating_add(u8::try_from(reste % 10).unwrap_or(0));
        reste /= 10;
    }
    Ok(fin)
}

/// Recopie `morceau`, et rend le nouveau compte.
fn pousser(sortie: &mut [u8], ecrits: usize, morceau: &[u8]) -> Result<usize, Error> {
    let fin = ecrits.saturating_add(morceau.len());
    let place = sortie.get_mut(ecrits..fin).ok_or(Error::BufferTooSmall)?;
    place.copy_from_slice(morceau);
    Ok(fin)
}

#[cfg(test)]
mod tests;
