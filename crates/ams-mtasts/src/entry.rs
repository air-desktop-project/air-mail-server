//! Le nom d'une entrée de cache, qui porte tout son état.
//!
//! # LA MÊME DISCIPLINE QUE LA FILE DE RÉÉMISSION, POUR LA MÊME RAISON
//!
//! Il n'y a pas de base de données. Ce que le nom ne dit pas, un redémarrage
//! l'oublie — et un cache MTA-STS qui s'oublie rouvre exactement la fenêtre que
//! MTA-STS existe pour fermer (§5).
//!
//! Le nom porte donc les trois choses qui décident : **de quel domaine** il
//! s'agit, **quelle version** de la politique on a, et **quand** on l'a
//! récupérée. Le contenu du fichier est la politique, telle qu'elle a été servie,
//! octet pour octet.

use crate::Error;

/// La longueur maximale d'un nom de domaine (§3.1 de RFC 1035).
const DOMAIN_MAX: usize = 253;

/// La longueur maximale d'un identifiant de politique (§3.1 de RFC 8461).
const ID_MAX: usize = 32;

/// La largeur du champ d'instant, en chiffres.
///
/// **ON COMPLÈTE PAR DES ZÉROS À GAUCHE**, comme la file : sans cela, un `ls` du
/// répertoire mentirait sur l'ordre des récupérations.
const LARGEUR: usize = 12;

/// Ce qu'il faut au plus pour écrire un nom.
pub const NAME_MAX: usize = LARGEUR + 1 + ID_MAX + 1 + DOMAIN_MAX + 7;

/// Ce qu'un nom d'entrée de cache porte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry<'a> {
    /// Quand la politique a été récupérée, en secondes depuis l'époque.
    pub fetched: u64,
    /// L'identifiant que le `TXT` portait alors.
    pub id: &'a str,
    /// Le domaine dont c'est la politique.
    pub domain: &'a str,
}

impl Entry<'_> {
    /// Cette politique est-elle encore valable à `now` ?
    ///
    /// # LE CACHE NE SE PÉRIME QUE PAR LE TEMPS
    ///
    /// Ni un `TXT` disparu, ni un `https://` injoignable ne le retirent : §5 en
    /// fait la protection contre le déclassement, et un attaquant qui peut
    /// couper le réseau obtiendrait sinon une remise sans politique.
    ///
    /// **L'HORLOGE QUI RECULE NE PROLONGE RIEN.** Une entrée récupérée « dans le
    /// futur » — l'horloge a été remise à l'heure — est traitée comme périmée,
    /// plutôt que de valoir jusqu'à ce futur-là.
    #[must_use]
    pub fn fresh(&self, max_age: u32, now: u64) -> bool {
        let Some(age) = now.checked_sub(self.fetched) else {
            return false;
        };
        age < u64::from(max_age)
    }
}

/// Écrit `<récupérée>!<identifiant>!<domaine>.mtasts` dans `sortie`.
///
/// # Errors
///
/// [`Error::BadName`] si l'identifiant ou le domaine ne peut pas devenir un nom
/// de fichier, [`Error::BufferTooSmall`] si `sortie` fait moins de [`NAME_MAX`].
pub fn write_name<'b>(entry: &Entry<'_>, sortie: &'b mut [u8]) -> Result<&'b str, Error> {
    if !identifiant_recevable(entry.id) || !domaine_recevable(entry.domain) {
        return Err(Error::BadName);
    }
    let mut ecrits = nombre(sortie, 0, entry.fetched)?;
    ecrits = pousser(sortie, ecrits, b"!")?;
    ecrits = pousser(sortie, ecrits, entry.id.as_bytes())?;
    ecrits = pousser(sortie, ecrits, b"!")?;
    ecrits = pousser(sortie, ecrits, entry.domain.as_bytes())?;
    ecrits = pousser(sortie, ecrits, b".mtasts")?;
    // Tout ce qu'on vient d'écrire est de l'ASCII : des chiffres, des points
    // d'exclamation, un identifiant et un domaine dont chaque octet a été
    // vérifié, et un suffixe littéral.
    let ecrit = sortie.get(..ecrits).unwrap_or_default();
    Ok(core::str::from_utf8(ecrit).unwrap_or_default())
}

/// Découpe `<récupérée>!<identifiant>!<domaine>.mtasts`.
///
/// **Rien de ce qui n'a pas cette forme n'est touché.** Un répertoire qu'on
/// partage avec autre chose ne se lit pas au jugé, et ne s'efface pas non plus.
#[must_use]
pub fn parse_name(nom: &str) -> Option<Entry<'_>> {
    let corps = nom.strip_suffix(".mtasts")?;
    let mut parts = corps.split('!');
    // `split` rend TOUJOURS au moins un morceau : ce premier appel ne peut pas
    // manquer.
    let fetched = parts.next().unwrap_or_default().parse().ok()?;
    let id = parts.next()?;
    let domain = parts.next()?;
    // **UN QUATRIÈME SÉPARATEUR REND `None`** : sans cela, un nom qu'on écrit ne
    // se relirait pas toujours à l'identique.
    if parts.next().is_some() || !identifiant_recevable(id) || !domaine_recevable(domain) {
        return None;
    }
    Some(Entry {
        fetched,
        id,
        domain,
    })
}

/// Cet identifiant peut-il devenir un morceau de nom de fichier ?
fn identifiant_recevable(id: &str) -> bool {
    !id.is_empty() && id.len() <= ID_MAX && id.bytes().all(|octet| octet.is_ascii_alphanumeric())
}

/// Ce domaine peut-il devenir un morceau de nom de fichier ?
///
/// **UN `/` DÉSIGNERAIT UN AUTRE RÉPERTOIRE, UN `.` EN TÊTE CACHERAIT LE
/// FICHIER**, et un `!` casserait le découpage du nom. Un nom de domaine ne
/// porte de toute façon que des lettres, des chiffres, des tirets et des points.
fn domaine_recevable(domaine: &str) -> bool {
    !domaine.is_empty()
        && domaine.len() <= DOMAIN_MAX
        && !domaine.starts_with('.')
        && !domaine.ends_with('.')
        && domaine
            .bytes()
            .all(|octet| octet.is_ascii_alphanumeric() || octet == b'-' || octet == b'.')
}

/// Écrit `valeur` en décimal, complété par des zéros jusqu'à [`LARGEUR`].
///
/// **UNE VALEUR PLUS LARGE ALLONGE LE NOM**, elle ne se tronque pas : un instant
/// tronqué ferait mentir le nom sur l'âge du cache.
fn nombre(sortie: &mut [u8], ecrits: usize, valeur: u64) -> Result<usize, Error> {
    let largeur = LARGEUR.max(largeur_de(valeur));
    let fin = ecrits.saturating_add(largeur);
    let place = sortie.get_mut(ecrits..fin).ok_or(Error::BufferTooSmall)?;
    let mut reste = valeur;
    for octet in place.iter_mut().rev() {
        *octet = b'0'.saturating_add(u8::try_from(reste % 10).unwrap_or(0));
        reste /= 10;
    }
    Ok(fin)
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

/// Recopie `morceau`, et rend le nouveau compte.
fn pousser(sortie: &mut [u8], ecrits: usize, morceau: &[u8]) -> Result<usize, Error> {
    let fin = ecrits.saturating_add(morceau.len());
    let place = sortie.get_mut(ecrits..fin).ok_or(Error::BufferTooSmall)?;
    place.copy_from_slice(morceau);
    Ok(fin)
}

#[cfg(test)]
mod tests;
