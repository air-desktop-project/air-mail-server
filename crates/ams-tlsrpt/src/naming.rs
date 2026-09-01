//! Le nom d'un rapport, et le sujet du message qui le porte (§5.3).

use crate::Error;

/// Ce qu'il faut au plus pour un nom de fichier.
pub const FILENAME_MAX: usize = 253 + 1 + 253 + 1 + 20 + 1 + 20 + 8;

/// Ce qu'il faut au plus pour un sujet.
pub const SUBJECT_MAX: usize = 64 + 253 + 253 + 64;

/// Le nom du fichier d'un rapport (§5.3).
///
/// `<émetteur>!<rapporté>!<début>!<fin>.json.gz`
///
/// **LE FORMAT EST IMPOSÉ, PAS CHOISI** : c'est ainsi que le destinataire
/// reconnaît un rapport parmi ce qu'il reçoit, et un nom qui s'en écarterait
/// serait un rapport que personne ne traiterait.
///
/// # Errors
///
/// [`Error::NotPrintable`] si l'un des deux domaines n'en est pas un,
/// [`Error::BufferTooSmall`] si `sortie` fait moins de [`FILENAME_MAX`].
pub fn filename<'b>(
    sender: &str,
    policy_domain: &str,
    debut: u64,
    fin: u64,
    sortie: &'b mut [u8],
) -> Result<&'b str, Error> {
    if !nom_recevable(sender) || !nom_recevable(policy_domain) {
        return Err(Error::NotPrintable);
    }
    let mut ecrits = pousser(sortie, 0, sender.as_bytes())?;
    ecrits = pousser(sortie, ecrits, b"!")?;
    ecrits = pousser(sortie, ecrits, policy_domain.as_bytes())?;
    ecrits = pousser(sortie, ecrits, b"!")?;
    ecrits = nombre(sortie, ecrits, debut)?;
    ecrits = pousser(sortie, ecrits, b"!")?;
    ecrits = nombre(sortie, ecrits, fin)?;
    ecrits = pousser(sortie, ecrits, b".json.gz")?;
    let ecrit = sortie.get(..ecrits).unwrap_or_default();
    Ok(core::str::from_utf8(ecrit).unwrap_or_default())
}

/// Le sujet du message qui porte un rapport (§5.3).
///
/// `Report Domain: <rapporté> Submitter: <émetteur> Report-ID: <identifiant>`
///
/// # Errors
///
/// Comme [`filename`] ; l'identifiant doit être de l'ASCII imprimable sans
/// espace — c'est lui qui distingue deux rapports d'une même journée.
pub fn subject<'b>(
    policy_domain: &str,
    sender: &str,
    report_id: &str,
    sortie: &'b mut [u8],
) -> Result<&'b str, Error> {
    if !nom_recevable(policy_domain) || !nom_recevable(sender) || !identifiant(report_id) {
        return Err(Error::NotPrintable);
    }
    let mut ecrits = pousser(sortie, 0, b"Report Domain: ")?;
    ecrits = pousser(sortie, ecrits, policy_domain.as_bytes())?;
    ecrits = pousser(sortie, ecrits, b" Submitter: ")?;
    ecrits = pousser(sortie, ecrits, sender.as_bytes())?;
    ecrits = pousser(sortie, ecrits, b" Report-ID: ")?;
    ecrits = pousser(sortie, ecrits, report_id.as_bytes())?;
    let ecrit = sortie.get(..ecrits).unwrap_or_default();
    Ok(core::str::from_utf8(ecrit).unwrap_or_default())
}

/// Ce nom peut-il s'écrire dans un nom de fichier et dans un sujet ?
fn nom_recevable(nom: &str) -> bool {
    !nom.is_empty()
        && nom.len() <= 253
        && !nom.starts_with('.')
        && !nom.contains('!')
        && !nom.contains('/')
        && nom
            .bytes()
            .all(|octet| octet.is_ascii_alphanumeric() || octet == b'-' || octet == b'.')
}

/// Cet identifiant peut-il s'écrire dans un sujet ?
///
/// **Un `CRLF` y écrirait des en-têtes à notre place** dans un message qu'on
/// compose et qu'on remet nous-mêmes.
fn identifiant(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.bytes().all(|octet| octet.is_ascii_graphic())
}

/// Écrit `valeur` en décimal.
fn nombre(sortie: &mut [u8], ecrits: usize, valeur: u64) -> Result<usize, Error> {
    let largeur = largeur_de(valeur);
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
