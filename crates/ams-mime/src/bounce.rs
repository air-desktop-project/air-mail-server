//! Le rapport de non-remise (RFC 3464), composé sans allouer.
//!
//! # CE QU'ON REND À L'EXPÉDITEUR QUAND ON A RENONCÉ
//!
//! Une file de réémission qui abandonne en silence perd du courrier sans le
//! dire : l'expéditeur croit avoir écrit, et personne n'a rien reçu. Le rapport
//! de non-remise est ce qui rend cette perte visible, et il doit dire trois
//! choses qu'un humain ET une machine sachent lire — à qui, pourquoi, et de quel
//! message il s'agit.
//!
//! D'où la forme normalisée : un `multipart/report` (RFC 6522) à trois parties.
//! Un texte pour l'humain, un `message/delivery-status` pour le client qui
//! classe, et les en-têtes du message d'origine pour le retrouver.
//!
//! # POURQUOI LES EN-TÊTES SEULS, ET PAS LE MESSAGE ENTIER
//!
//! RFC 3462 permet les deux. Renvoyer le corps doublerait le volume d'un rapport
//! écrit précisément parce qu'on n'arrivait pas à émettre — et un message de dix
//! mégaoctets qu'on ne pouvait pas remettre ne se remet pas mieux quand il
//! revient. Les en-têtes suffisent à identifier le message : leur `Message-ID`,
//! leur `Subject`, leur `Date`.
//!
//! # CE QUI VIENT DE L'EXTÉRIEUR, ET QUI EST ÉCRIT ICI
//!
//! Le `Diagnostic-Code` porte **le texte de refus d'un serveur inconnu**. C'est
//! une entrée hostile comme une autre : un `CRLF` glissé dedans écrirait des
//! champs de statut à notre place dans un rapport que nous composons et que nous
//! remettons nous-mêmes, dans la boîte d'un de nos comptes. Il est donc soumis à
//! la même règle que tout le reste — ASCII imprimable, et rien d'autre.

use crate::Error;
use crate::compose::{contient, pousser, texte_recevable};
use crate::date::write_date;

/// Ce qu'un destinataire en échec fait consigner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure<'a> {
    /// L'adresse qui n'a pas été servie.
    pub recipient: &'a [u8],
    /// Le code d'état étendu (RFC 3463), par exemple `5.1.1`.
    ///
    /// **Chiffres et points, et rien d'autre** : c'est ce que lit la machine, et
    /// une valeur libre y écrirait ce qu'elle veut.
    pub status: &'a [u8],
    /// Ce que le serveur d'en face a répondu, sans les fins de ligne.
    ///
    /// Vide quand il n'a rien répondu — une panne de réseau, un `MX` nul. Le
    /// champ est alors **omis** plutôt que rempli d'un texte inventé : un
    /// diagnostic qu'on aurait écrit soi-même se lirait comme celui du pair.
    pub diagnostic: &'a [u8],
}

/// Ce qu'un rapport de non-remise doit dire.
#[derive(Debug, Clone, Copy)]
pub struct Bounce<'a, 'f> {
    /// L'adresse qui émet — le `postmaster` de ce serveur.
    pub from: &'a [u8],
    /// L'expéditeur du message perdu, à qui le rapport revient.
    pub to: &'a [u8],
    /// Le nom de ce serveur, tel qu'il s'annonce.
    pub reporting_mta: &'a [u8],
    /// La ligne de sujet.
    pub subject: &'a [u8],
    /// L'identifiant du rapport, sans les chevrons.
    pub message_id: &'a [u8],
    /// La date du rapport, en secondes depuis l'époque.
    pub date: u64,
    /// L'instant où le message perdu avait été déposé.
    pub arrival: u64,
    /// Le délimiteur de parties.
    ///
    /// **Il vient de l'appelant** : il doit être imprévisible, et l'aléa
    /// appartient à l'étage 3 (C1).
    pub boundary: &'a [u8],
    /// Le texte que lira l'humain.
    pub text: &'a [u8],
    /// Ce qui a échoué, et pour qui.
    pub failures: &'f [Failure<'a>],
    /// Les en-têtes du message perdu, terminés par `CRLF`.
    ///
    /// **Le corps n'y est pas**, et c'est délibéré : voir l'en-tête du module.
    pub original_headers: &'a [u8],
}

/// Ce qu'il faut au plus pour composer ce rapport.
#[must_use]
pub fn bounce_max(bounce: &Bounce<'_, '_>) -> usize {
    // Les en-têtes, les trois préambules de partie, le délimiteur quatre fois :
    // quelques centaines d'octets suffisent, et l'on majore.
    const ENVELOPPE: usize = 768;
    // Ce qu'un groupe de destinataire occupe au plus, hors ses valeurs.
    const PAR_ECHEC: usize = 80;
    let echecs = bounce.failures.iter().fold(0_usize, |total, echec| {
        total
            .saturating_add(PAR_ECHEC)
            .saturating_add(echec.recipient.len())
            .saturating_add(echec.status.len())
            .saturating_add(echec.diagnostic.len())
    });
    ENVELOPPE
        .saturating_add(bounce.from.len())
        .saturating_add(bounce.to.len())
        .saturating_add(bounce.reporting_mta.len())
        .saturating_add(bounce.subject.len())
        .saturating_add(bounce.message_id.len())
        .saturating_add(bounce.boundary.len().saturating_mul(4))
        .saturating_add(bounce.text.len())
        .saturating_add(bounce.original_headers.len())
        .saturating_add(echecs)
}

/// Compose le rapport, en-têtes compris, lignes terminées par `CRLF`.
///
/// # Errors
///
/// [`Error::EmptyReport`] si aucun destinataire n'est nommé,
/// [`Error::NotPrintable`] si une valeur porte un octet qu'on refuse d'écrire,
/// [`Error::BoundaryInContent`] si le délimiteur figure dans une partie,
/// [`Error::BufferTooSmall`] si `sortie` ne suffit pas — voir [`bounce_max`].
pub fn write_bounce<'b>(sortie: &'b mut [u8], bounce: &Bounce<'_, '_>) -> Result<&'b [u8], Error> {
    if bounce.failures.is_empty() {
        return Err(Error::EmptyReport);
    }
    // UNE ADRESSE N'A PAS D'ESPACE, un sujet en a — la même distinction que pour
    // les rapports agrégés, et pour la même raison.
    for valeur in [
        bounce.from,
        bounce.to,
        bounce.reporting_mta,
        bounce.message_id,
        bounce.boundary,
    ] {
        if valeur.is_empty() || !valeur.iter().all(u8::is_ascii_graphic) {
            return Err(Error::NotPrintable);
        }
    }
    if bounce.subject.is_empty() || !ligne_recevable(bounce.subject) {
        return Err(Error::NotPrintable);
    }
    if !texte_recevable(bounce.text) || !texte_recevable(bounce.original_headers) {
        return Err(Error::NotPrintable);
    }
    for echec in bounce.failures {
        if echec.recipient.is_empty() || !echec.recipient.iter().all(u8::is_ascii_graphic) {
            return Err(Error::NotPrintable);
        }
        // LE STATUT EST LU PAR UNE MACHINE : chiffres et points, et rien
        // d'autre. Une valeur libre y écrirait ce qu'elle veut.
        if echec.status.is_empty()
            || !echec
                .status
                .iter()
                .all(|octet| octet.is_ascii_digit() || *octet == b'.')
        {
            return Err(Error::NotPrintable);
        }
        // LE DIAGNOSTIC VIENT D'UN SERVEUR INCONNU. Vide, il sera omis.
        if !ligne_recevable(echec.diagnostic) {
            return Err(Error::NotPrintable);
        }
    }
    // LE DÉLIMITEUR NE DOIT FIGURER DANS AUCUNE PARTIE.
    if contient(bounce.text, bounce.boundary) || contient(bounce.original_headers, bounce.boundary)
    {
        return Err(Error::BoundaryInContent);
    }

    let mut ecrits = 0_usize;
    // **LE CHEMIN DE RETOUR EST NUL, ET CE N'EST PAS UN DÉTAIL** : §6.1 de
    // RFC 5321 l'exige pour tout message de notification. Un rapport dont le
    // rebond rebondirait ferait tourner deux serveurs l'un contre l'autre.
    ecrits = pousser(sortie, ecrits, b"Return-Path: <>\r\nFrom: <")?;
    ecrits = pousser(sortie, ecrits, bounce.from)?;
    ecrits = pousser(sortie, ecrits, b">\r\nTo: <")?;
    ecrits = pousser(sortie, ecrits, bounce.to)?;
    ecrits = pousser(sortie, ecrits, b">\r\nSubject: ")?;
    ecrits = pousser(sortie, ecrits, bounce.subject)?;
    ecrits = pousser(sortie, ecrits, b"\r\nDate: ")?;
    ecrits = date(sortie, ecrits, bounce.date)?;
    ecrits = pousser(sortie, ecrits, b"\r\nMessage-ID: <")?;
    ecrits = pousser(sortie, ecrits, bounce.message_id)?;
    ecrits = pousser(sortie, ecrits, b">\r\nMIME-Version: 1.0\r\n")?;
    // §5 de RFC 3834 : un répondeur automatique ne doit pas répondre à ceci.
    ecrits = pousser(sortie, ecrits, b"Auto-Submitted: auto-replied\r\n")?;
    ecrits = pousser(
        sortie,
        ecrits,
        b"Content-Type: multipart/report; report-type=delivery-status;\r\n\tboundary=\"",
    )?;
    ecrits = pousser(sortie, ecrits, bounce.boundary)?;
    ecrits = pousser(sortie, ecrits, b"\"\r\n\r\n")?;

    // ── La partie que lit l'humain ──────────────────────────────────────────
    ecrits = pousser(sortie, ecrits, b"--")?;
    ecrits = pousser(sortie, ecrits, bounce.boundary)?;
    ecrits = pousser(
        sortie,
        ecrits,
        b"\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n",
    )?;
    ecrits = pousser(sortie, ecrits, bounce.text)?;
    if !bounce.text.ends_with(b"\r\n") {
        ecrits = pousser(sortie, ecrits, b"\r\n")?;
    }

    // ── La partie que lit la machine (§2 de RFC 3464) ───────────────────────
    ecrits = pousser(sortie, ecrits, b"\r\n--")?;
    ecrits = pousser(sortie, ecrits, bounce.boundary)?;
    ecrits = pousser(
        sortie,
        ecrits,
        b"\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; ",
    )?;
    ecrits = pousser(sortie, ecrits, bounce.reporting_mta)?;
    ecrits = pousser(sortie, ecrits, b"\r\nArrival-Date: ")?;
    ecrits = date(sortie, ecrits, bounce.arrival)?;
    ecrits = pousser(sortie, ecrits, b"\r\n")?;
    for echec in bounce.failures {
        ecrits = pousser(sortie, ecrits, b"\r\nFinal-Recipient: rfc822; ")?;
        ecrits = pousser(sortie, ecrits, echec.recipient)?;
        ecrits = pousser(sortie, ecrits, b"\r\nAction: failed\r\nStatus: ")?;
        ecrits = pousser(sortie, ecrits, echec.status)?;
        ecrits = pousser(sortie, ecrits, b"\r\n")?;
        if !echec.diagnostic.is_empty() {
            ecrits = pousser(sortie, ecrits, b"Diagnostic-Code: smtp; ")?;
            ecrits = pousser(sortie, ecrits, echec.diagnostic)?;
            ecrits = pousser(sortie, ecrits, b"\r\n")?;
        }
    }

    // ── Les en-têtes du message perdu ───────────────────────────────────────
    ecrits = pousser(sortie, ecrits, b"\r\n--")?;
    ecrits = pousser(sortie, ecrits, bounce.boundary)?;
    ecrits = pousser(
        sortie,
        ecrits,
        b"\r\nContent-Type: text/rfc822-headers\r\n\r\n",
    )?;
    ecrits = pousser(sortie, ecrits, bounce.original_headers)?;
    if !bounce.original_headers.is_empty() && !bounce.original_headers.ends_with(b"\r\n") {
        ecrits = pousser(sortie, ecrits, b"\r\n")?;
    }

    ecrits = pousser(sortie, ecrits, b"\r\n--")?;
    ecrits = pousser(sortie, ecrits, bounce.boundary)?;
    ecrits = pousser(sortie, ecrits, b"--\r\n")?;
    // `pousser` a écrit jusqu'à `ecrits` : la découpe ne peut pas manquer.
    Ok(sortie.get(..ecrits).unwrap_or_default())
}

/// Écrit la date DIRECTEMENT dans la sortie, et rend le nouveau compte.
fn date(sortie: &mut [u8], ecrits: usize, quand: u64) -> Result<usize, Error> {
    // `unwrap_or_default` porte l'impossibilité dans la bibliothèque standard :
    // `ecrits` ne dépasse jamais la longueur déjà écrite.
    let place = sortie.get_mut(ecrits..).unwrap_or_default();
    let combien = write_date(quand, place)?.len();
    Ok(ecrits.saturating_add(combien))
}

/// Cette valeur tient-elle sur UNE ligne d'en-tête ?
///
/// De l'ASCII imprimable et des espaces. Vide passe — un diagnostic absent est
/// une information, et le champ est alors omis.
fn ligne_recevable(valeur: &[u8]) -> bool {
    valeur
        .iter()
        .all(|octet| octet.is_ascii_graphic() || *octet == b' ')
}

#[cfg(test)]
mod tests;
