//! Le message qui porte un rapport (RFC 7489 §7.2.1.1), composé sans allouer.
//!
//! # Ce que ce module compose, et ce qu'il ne compose pas
//!
//! Un seul message, d'une forme précise : un `multipart/mixed` avec un texte
//! d'explication et une pièce jointe compressée. Ce n'est pas un composeur MIME
//! général — il n'y a ici ni encodage de mots (RFC 2047), ni parties
//! imbriquées, ni jeu de caractères autre que l'ASCII. **Écrire ce qu'on
//! n'utilise pas serait écrire du code que rien n'éprouve**, dans une crate qui
//! se veut portable telle quelle.
//!
//! # CE QU'ON ÉCRIT DANS UN EN-TÊTE VIENT PARFOIS D'AILLEURS
//!
//! L'adresse du destinataire d'un rapport est publiée par le domaine qu'on
//! rapporte — c'est-à-dire, quand cela compte, par celui qui usurpe. Un `CRLF`
//! glissé dedans écrirait des en-têtes à notre place, dans un message que nous
//! composons et que nous remettons nous-mêmes.
//!
//! Deux règles ferment cela, et aucune n'est facultative :
//!
//! 1. **Tout octet hors de l'ASCII imprimable fait refuser le message.** Pas de
//!    remplacement silencieux : un message dont on ne sait pas ce qu'il dit ne
//!    vaut pas mieux que pas de message.
//! 2. **Le délimiteur de parties ne doit figurer dans aucune partie.** Un
//!    `multipart` dont le délimiteur apparaît dans le contenu ne se découpe plus
//!    là où son auteur croyait, et le destinataire lit autre chose que ce qu'on
//!    a écrit.

use crate::Error;
use crate::base64::{base64_max, encode_base64};
use crate::date::write_date;

/// Ce qu'un message de rapport doit dire.
#[derive(Debug, Clone, Copy)]
pub struct ReportMail<'a> {
    /// L'adresse qui émet — la nôtre.
    pub from: &'a [u8],
    /// L'adresse à qui le rapport revient.
    pub to: &'a [u8],
    /// La ligne de sujet, telle que §7.2.1.1 la veut.
    pub subject: &'a [u8],
    /// L'identifiant du message, sans les chevrons.
    pub message_id: &'a [u8],
    /// La date, en secondes depuis l'époque.
    pub date: u64,
    /// Le délimiteur de parties.
    ///
    /// **Il vient de l'appelant** : il doit être imprévisible, et l'aléa
    /// appartient à l'étage 3 (C1).
    pub boundary: &'a [u8],
    /// Le texte que lira l'humain qui ouvrira ce message.
    pub text: &'a [u8],
    /// Le nom du fichier joint.
    pub filename: &'a [u8],
    /// Le rapport compressé.
    pub attachment: &'a [u8],
}

/// Ce qu'il faut au plus pour composer ce message.
#[must_use]
pub fn report_mail_max(mail: &ReportMail<'_>) -> usize {
    // Les en-têtes, leurs noms, les deux préambules de partie et le délimiteur
    // trois fois : quelques centaines d'octets suffisent, et l'on majore.
    const ENVELOPPE: usize = 512;
    ENVELOPPE
        .saturating_add(mail.from.len())
        .saturating_add(mail.to.len())
        .saturating_add(mail.subject.len())
        .saturating_add(mail.message_id.len())
        .saturating_add(mail.filename.len())
        .saturating_add(mail.boundary.len().saturating_mul(3))
        .saturating_add(mail.text.len())
        .saturating_add(base64_max(mail.attachment.len()))
}

/// Compose le message, en-têtes compris, lignes terminées par `CRLF`.
///
/// # Errors
///
/// [`Error::NotPrintable`] si une valeur porte un octet hors de l'ASCII
/// imprimable, [`Error::BoundaryInContent`] si le délimiteur figure dans une
/// partie, [`Error::BufferTooSmall`] si `sortie` ne suffit pas — voir
/// [`report_mail_max`].
pub fn write_report_mail<'b>(
    sortie: &'b mut [u8],
    mail: &ReportMail<'_>,
) -> Result<&'b [u8], Error> {
    // UNE ADRESSE N'A PAS D'ESPACE, un sujet en a. La distinction n'est pas
    // cosmétique : `<a b@x.test>` n'est pas une adresse, et l'écrire ferait lire
    // au destinataire autre chose que ce qu'on croit avoir écrit.
    for valeur in [
        mail.from,
        mail.to,
        mail.message_id,
        mail.boundary,
        mail.filename,
    ] {
        if valeur.is_empty() || !valeur.iter().all(u8::is_ascii_graphic) {
            return Err(Error::NotPrintable);
        }
    }
    if mail.subject.is_empty()
        || !mail
            .subject
            .iter()
            .all(|octet| octet.is_ascii_graphic() || *octet == b' ')
    {
        return Err(Error::NotPrintable);
    }
    // Le texte, lui, a le droit d'avoir des espaces et des lignes — mais pas un
    // `CR` ni un `LF` isolé, pour la raison qui vaut partout dans cette crate.
    if !texte_recevable(mail.text) {
        return Err(Error::NotPrintable);
    }
    // LE DÉLIMITEUR NE DOIT FIGURER DANS AUCUNE PARTIE. Le base64 ne peut pas
    // le porter — son alphabet ne contient pas de tiret — mais le texte, lui,
    // vient d'ailleurs, et l'on ne suppose pas.
    if contient(mail.text, mail.boundary) || contient(mail.attachment, mail.boundary) {
        return Err(Error::BoundaryInContent);
    }

    let mut ecrits = 0_usize;
    ecrits = pousser(sortie, ecrits, b"From: <")?;
    ecrits = pousser(sortie, ecrits, mail.from)?;
    ecrits = pousser(sortie, ecrits, b">\r\nTo: <")?;
    ecrits = pousser(sortie, ecrits, mail.to)?;
    ecrits = pousser(sortie, ecrits, b">\r\nSubject: ")?;
    ecrits = pousser(sortie, ecrits, mail.subject)?;
    ecrits = pousser(sortie, ecrits, b"\r\nDate: ")?;
    // La date s'écrit DIRECTEMENT dans la sortie. Passer par un tampon
    // intermédiaire dimensionné pour elle ajouterait une garde qu'aucune entrée
    // ne pourrait faire céder — et une garde inatteignable n'est pas une garde.
    // `unwrap_or_default` porte l'autre impossibilité dans la bibliothèque
    // standard : `ecrits` ne dépasse jamais la longueur écrite.
    let ecrits_date = {
        let place = sortie.get_mut(ecrits..).unwrap_or_default();
        write_date(mail.date, place)?.len()
    };
    ecrits = ecrits.saturating_add(ecrits_date);
    ecrits = pousser(sortie, ecrits, b"\r\nMessage-ID: <")?;
    ecrits = pousser(sortie, ecrits, mail.message_id)?;
    ecrits = pousser(sortie, ecrits, b">\r\nMIME-Version: 1.0\r\n")?;
    ecrits = pousser(sortie, ecrits, b"Auto-Submitted: auto-generated\r\n")?;
    ecrits = pousser(
        sortie,
        ecrits,
        b"Content-Type: multipart/mixed; boundary=\"",
    )?;
    ecrits = pousser(sortie, ecrits, mail.boundary)?;
    ecrits = pousser(sortie, ecrits, b"\"\r\n\r\n")?;

    // ── La partie que lit l'humain ──────────────────────────────────────────
    ecrits = pousser(sortie, ecrits, b"--")?;
    ecrits = pousser(sortie, ecrits, mail.boundary)?;
    ecrits = pousser(
        sortie,
        ecrits,
        b"\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n",
    )?;
    ecrits = pousser(sortie, ecrits, mail.text)?;
    if !mail.text.ends_with(b"\r\n") {
        ecrits = pousser(sortie, ecrits, b"\r\n")?;
    }

    // ── La partie que lit la machine ────────────────────────────────────────
    ecrits = pousser(sortie, ecrits, b"\r\n--")?;
    ecrits = pousser(sortie, ecrits, mail.boundary)?;
    ecrits = pousser(sortie, ecrits, b"\r\nContent-Type: application/gzip\r\n")?;
    ecrits = pousser(
        sortie,
        ecrits,
        b"Content-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"",
    )?;
    ecrits = pousser(sortie, ecrits, mail.filename)?;
    ecrits = pousser(sortie, ecrits, b"\"\r\n\r\n")?;
    let ecrits_base64 = {
        let place = sortie.get_mut(ecrits..).unwrap_or_default();
        encode_base64(mail.attachment, place)?.len()
    };
    ecrits = ecrits.saturating_add(ecrits_base64);

    ecrits = pousser(sortie, ecrits, b"\r\n--")?;
    ecrits = pousser(sortie, ecrits, mail.boundary)?;
    ecrits = pousser(sortie, ecrits, b"--\r\n")?;
    sortie.get(..ecrits).ok_or(Error::BufferTooSmall)
}

/// Le texte d'explication est-il émettable tel quel ?
///
/// De l'ASCII imprimable, des espaces, des tabulations, et des fins de ligne
/// **complètes**. Un `CR` ou un `LF` isolé est refusé : c'est le désaccord entre
/// implémentations sur ce qui termine une ligne qui a rendu la contrebande SMTP
/// possible, et un message qu'on compose soi-même n'a aucune excuse.
fn texte_recevable(texte: &[u8]) -> bool {
    let mut attend_lf = false;
    for octet in texte {
        if attend_lf {
            if *octet != b'\n' {
                return false;
            }
            attend_lf = false;
            continue;
        }
        match *octet {
            b'\r' => attend_lf = true,
            b'\n' => return false,
            b'\t' => {}
            autre if autre.is_ascii_graphic() || autre == b' ' => {}
            _ => return false,
        }
    }
    !attend_lf
}

/// `aiguille` figure-t-elle dans `botte` ?
fn contient(botte: &[u8], aiguille: &[u8]) -> bool {
    botte
        .windows(aiguille.len().max(1))
        .any(|fenetre| fenetre == aiguille)
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
