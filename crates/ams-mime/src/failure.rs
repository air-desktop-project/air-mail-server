//! Le message qui porte un rapport d'ÉCHEC (RFC 6591, sur RFC 5965).
//!
//! # CE MESSAGE PORTE LE COURRIER DE QUELQU'UN, ET C'EST TOUT LE SUJET
//!
//! Un rapport agrégé est un dénombrement : il ne dit rien d'un message en
//! particulier. Celui-ci dit tout d'un message précis, et il part chez le
//! domaine qu'on rapporte — c'est-à-dire, quand cela compte, **chez celui qui
//! usurpe**. Ce qu'on y met, on le lui donne.
//!
//! La RFC 6591 §4.3 demande de caviarder. Ce module va plus loin qu'elle
//! n'exige, et de deux façons.
//!
//! ## On ne recopie pas le corps
//!
//! La partie jointe est un `text/rfc822-headers` (RFC 6522 §4), pas un
//! `message/rfc822`. Le corps d'un message est ce qu'une personne a écrit ; il
//! n'apprend rien sur une authentification, et il ne sortira pas d'ici.
//!
//! ## ON NE RECOPIE MÊME PAS TOUS LES EN-TÊTES
//!
//! [`EXPOSES`] est une liste **blanche**, et le reste tombe. Ce qui reste est ce
//! qui sert à comprendre un échec d'authentification : ce que le message
//! prétendait être, et les traces de ce qu'on a vérifié. Ce qui tombe est ce qui
//! parle de tiers — `To`, `Cc`, `Bcc` — ou de nos machines : chaque `Received`
//! décrit un chemin interne que personne n'a demandé à publier.
//!
//! Une liste noire aurait été plus douce et se serait trompée : le jour où un
//! en-tête nouveau porte une donnée personnelle, une liste noire le laisse
//! passer, et une liste blanche l'arrête sans qu'on ait rien à faire.

use crate::base64::base64_max;
use crate::date::write_date;
use crate::message::Message;
use crate::{Error, Limits};

/// Les en-têtes qu'un rapport d'échec a le droit de recopier.
///
/// Le `Subject:` en fait partie, et il faut dire pourquoi : le rapport part chez
/// le domaine du `From:`. Si le message est légitime et mal configuré, ce sujet
/// est **le sien** ; s'il est usurpé, ce sujet est celui de l'attaquant. Dans
/// les deux cas il n'appartient pas à celui qui a reçu le message — et il est ce
/// qui permet à un domaine de reconnaître son propre flux de courrier.
///
/// `To:` en revanche n'y est pas, et ne peut pas y être : c'est la seule ligne
/// qui nomme le tiers qu'on protège.
pub const EXPOSES: &[&[u8]] = &[
    b"From",
    b"Sender",
    b"Reply-To",
    b"Return-Path",
    b"Date",
    b"Subject",
    b"Message-ID",
    b"MIME-Version",
    b"Content-Type",
    b"DKIM-Signature",
    b"Received-SPF",
    b"Authentication-Results",
];

/// Ce qu'un message de rapport d'échec doit dire.
#[derive(Debug, Clone, Copy)]
pub struct FailureMail<'a> {
    /// L'adresse qui émet — la nôtre.
    pub from: &'a [u8],
    /// L'adresse à qui le rapport revient.
    pub to: &'a [u8],
    /// La ligne de sujet.
    pub subject: &'a [u8],
    /// L'identifiant du message, sans les chevrons.
    pub message_id: &'a [u8],
    /// La date, en secondes depuis l'époque.
    pub date: u64,
    /// Le délimiteur de parties, tiré au sort par l'appelant (C1).
    pub boundary: &'a [u8],
    /// Le texte que lira l'humain.
    pub text: &'a [u8],
    /// Les champs du rapport (`message/feedback-report`), déjà composés.
    pub feedback: &'a [u8],
    /// Le bloc d'en-tête du message rapporté, **tel qu'il est arrivé**.
    ///
    /// Il est filtré ici par [`EXPOSES`] : l'appelant n'a pas à s'en charger, et
    /// ne peut donc pas oublier de le faire.
    pub reported_headers: &'a [u8],
}

/// Ce qu'il faut au plus pour composer ce message.
#[must_use]
pub fn failure_mail_max(mail: &FailureMail<'_>) -> usize {
    /// Les en-têtes, les trois préambules de partie, les délimiteurs.
    const ENVELOPPE: usize = 640;
    ENVELOPPE
        .saturating_add(mail.from.len())
        .saturating_add(mail.to.len())
        .saturating_add(mail.subject.len())
        .saturating_add(mail.message_id.len())
        .saturating_add(mail.boundary.len().saturating_mul(4))
        .saturating_add(mail.text.len())
        .saturating_add(mail.feedback.len())
        // Le filtrage ne peut que raccourcir le bloc d'en-tête ; on majore par
        // sa longueur d'origine. `base64_max` n'a rien à faire ici — rien n'est
        // encodé — mais la borne du texte, si.
        .saturating_add(mail.reported_headers.len())
        .saturating_add(base64_max(0))
}

/// Compose le message, en-têtes compris, lignes terminées par `CRLF`.
///
/// # Errors
///
/// [`Error::NotPrintable`] si une valeur porte un octet qu'on refuse d'écrire,
/// [`Error::BoundaryInContent`] si le délimiteur figure dans une partie,
/// [`Error::BufferTooSmall`] si `sortie` ne suffit pas, ou les erreurs de
/// lecture du bloc d'en-tête rapporté.
pub fn write_failure_mail<'b>(
    sortie: &'b mut [u8],
    mail: &FailureMail<'_>,
    limits: &Limits,
) -> Result<&'b [u8], Error> {
    for valeur in [mail.from, mail.to, mail.message_id, mail.boundary] {
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
    for partie in [mail.text, mail.feedback] {
        if !crate::compose::texte_recevable(partie) {
            return Err(Error::NotPrintable);
        }
        if crate::compose::contient(partie, mail.boundary) {
            return Err(Error::BoundaryInContent);
        }
    }

    let mut ecrits = 0_usize;
    ecrits = pousser(sortie, ecrits, b"From: <")?;
    ecrits = pousser(sortie, ecrits, mail.from)?;
    ecrits = pousser(sortie, ecrits, b">\r\nTo: <")?;
    ecrits = pousser(sortie, ecrits, mail.to)?;
    ecrits = pousser(sortie, ecrits, b">\r\nSubject: ")?;
    ecrits = pousser(sortie, ecrits, mail.subject)?;
    ecrits = pousser(sortie, ecrits, b"\r\nDate: ")?;
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
        b"Content-Type: multipart/report; report-type=feedback-report;\r\n\tboundary=\"",
    )?;
    ecrits = pousser(sortie, ecrits, mail.boundary)?;
    ecrits = pousser(sortie, ecrits, b"\"\r\n\r\n")?;

    // ── Ce que lit l'humain ─────────────────────────────────────────────────
    ecrits = partie(
        sortie,
        ecrits,
        mail.boundary,
        b"text/plain; charset=us-ascii",
    )?;
    ecrits = pousser(sortie, ecrits, mail.text)?;
    if !mail.text.ends_with(b"\r\n") {
        ecrits = pousser(sortie, ecrits, b"\r\n")?;
    }

    // ── Ce que lit la machine ───────────────────────────────────────────────
    ecrits = pousser(sortie, ecrits, b"\r\n")?;
    ecrits = partie(sortie, ecrits, mail.boundary, b"message/feedback-report")?;
    ecrits = pousser(sortie, ecrits, mail.feedback)?;

    // ── Ce qui reste du message rapporté ────────────────────────────────────
    ecrits = pousser(sortie, ecrits, b"\r\n")?;
    ecrits = partie(sortie, ecrits, mail.boundary, b"text/rfc822-headers")?;
    let ecrits_entetes = {
        let place = sortie.get_mut(ecrits..).unwrap_or_default();
        write_reported_headers(place, mail.reported_headers, limits, mail.boundary)?.len()
    };
    ecrits = ecrits.saturating_add(ecrits_entetes);

    ecrits = pousser(sortie, ecrits, b"\r\n--")?;
    ecrits = pousser(sortie, ecrits, mail.boundary)?;
    ecrits = pousser(sortie, ecrits, b"--\r\n")?;
    sortie.get(..ecrits).ok_or(Error::BufferTooSmall)
}

/// Ouvre une partie : le délimiteur, son type, et la ligne vide.
fn partie(
    sortie: &mut [u8],
    ecrits: usize,
    delimiteur: &[u8],
    genre: &[u8],
) -> Result<usize, Error> {
    let mut ecrits = pousser(sortie, ecrits, b"--")?;
    ecrits = pousser(sortie, ecrits, delimiteur)?;
    ecrits = pousser(sortie, ecrits, b"\r\nContent-Type: ")?;
    ecrits = pousser(sortie, ecrits, genre)?;
    pousser(sortie, ecrits, b"\r\n\r\n")
}

/// Recopie les en-têtes que [`EXPOSES`] autorise, et rien d'autre.
///
/// # Errors
///
/// Les erreurs de lecture du bloc d'en-tête, [`Error::BoundaryInContent`] si un
/// champ retenu porte le délimiteur, [`Error::BufferTooSmall`] si `sortie` ne
/// suffit pas.
pub fn write_reported_headers<'b>(
    sortie: &'b mut [u8],
    headers: &[u8],
    limits: &Limits,
    boundary: &[u8],
) -> Result<&'b [u8], Error> {
    let message = Message::parse(headers, limits)?;
    let mut ecrits = 0_usize;
    for champ in message.fields() {
        if !EXPOSES.iter().any(|nom| champ.name_is(nom)) {
            continue;
        }
        // Le délimiteur ne peut pas venir de là : il est tiré au sort. On le
        // vérifie quand même — c'est le seul contenu de ce message qui vienne
        // d'un pair, et supposer serait exactement ce qu'on ne fait pas.
        if crate::compose::contient(champ.raw_value(), boundary) {
            return Err(Error::BoundaryInContent);
        }
        ecrits = pousser(sortie, ecrits, champ.name())?;
        ecrits = pousser(sortie, ecrits, b":")?;
        ecrits = pousser(sortie, ecrits, champ.raw_value())?;
        ecrits = pousser(sortie, ecrits, b"\r\n")?;
    }
    sortie.get(..ecrits).ok_or(Error::BufferTooSmall)
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
