//! Le rapport d'ÉCHEC (RFC 7489 §7.3, format RFC 6591 sur RFC 5965).
//!
//! # CE RAPPORT-LÀ PORTE LE COURRIER DE QUELQU'UN
//!
//! Un rapport agrégé est un dénombrement : il ne dit rien d'un message en
//! particulier. Un rapport d'échec dit tout d'un message précis — d'où il vient,
//! ce qu'il prétendait être, et ce qu'on en a fait. C'est la différence qui rend
//! celui-ci délicat, et c'est pourquoi la RFC 6591 §4.3 demande de **caviarder**
//! plutôt que de tout recopier.
//!
//! Deux décisions découlent de là, et elles sont prises ici plutôt que laissées
//! à l'appelant :
//!
//! 1. **Le destinataire du message n'est jamais nommé.** RFC 6591 §3.2 prévoit
//!    un champ `Original-Rcpt-To` ; on ne l'écrit pas. Le rapport part chez le
//!    domaine qu'on rapporte — c'est-à-dire, quand cela compte, chez celui qui
//!    usurpe — et lui dire QUI a reçu son message serait lui livrer ce qu'il
//!    cherchait. L'expéditeur d'enveloppe, lui, est écrit : il est de sa main.
//! 2. **On ne recopie pas le corps.** Le message joint se réduit à une sélection
//!    de ses en-têtes ; voir `ams_mime::write_reported_headers`, qui décide
//!    lesquels.
//!
//! # Un rapport d'échec ne s'envoie que s'il est DEMANDÉ
//!
//! `fo=` dit quand, et son défaut est le plus étroit : sans lui, un domaine n'en
//! reçoit que si rien n'a réussi. Un receveur qui en enverrait davantage
//! enverrait du courrier que personne n'attend — et, sous une usurpation en
//! masse, il en enverrait beaucoup.

use core::net::IpAddr;

use crate::Error;

/// Ce qui a échoué (RFC 6591 §3.2, `Auth-Failure`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailure {
    /// L'alignement DMARC.
    Dmarc,
    /// Une signature DKIM.
    Dkim,
    /// L'autorisation SPF.
    Spf,
}

impl AuthFailure {
    fn name(self) -> &'static [u8] {
        match self {
            Self::Dmarc => b"dmarc",
            Self::Dkim => b"dkim",
            Self::Spf => b"spf",
        }
    }
}

/// Ce qu'on a fait du message (RFC 6591 §3.2, `Delivery-Result`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryResult {
    /// Remis à son destinataire.
    Delivered,
    /// Refusé.
    Rejected,
    /// Traité selon une politique locale.
    Policy,
    /// Autre chose.
    Other,
}

impl DeliveryResult {
    fn name(self) -> &'static [u8] {
        match self {
            Self::Delivered => b"delivered",
            Self::Rejected => b"reject",
            Self::Policy => b"policy",
            Self::Other => b"other",
        }
    }
}

/// Ce qu'un rapport d'échec dit du message.
#[derive(Debug, Clone, Copy)]
pub struct FeedbackReport<'a> {
    /// Le programme qui rapporte, avec sa version.
    pub user_agent: &'a [u8],
    /// La date d'arrivée, déjà écrite (RFC 5322 §3.3).
    ///
    /// **Elle vient de l'appelant** : cette crate n'a pas d'horloge (C1).
    pub arrival_date: &'a [u8],
    /// D'où le message est venu.
    pub source_ip: IpAddr,
    /// Le domaine rapporté — celui du `From:`.
    pub reported_domain: &'a [u8],
    /// L'expéditeur d'enveloppe, s'il y en avait un.
    pub original_mail_from: Option<&'a [u8]>,
    /// Le domaine d'une signature DKIM examinée.
    pub dkim_domain: Option<&'a [u8]>,
    /// Son sélecteur.
    pub dkim_selector: Option<&'a [u8]>,
    /// Le domaine que SPF a examiné.
    pub spf_dns: Option<&'a [u8]>,
    /// Ce qui a échoué.
    pub auth_failure: AuthFailure,
    /// Ce qu'on a fait du message.
    pub delivery_result: DeliveryResult,
    /// DKIM s'alignait-il ?
    pub aligned_dkim: bool,
    /// SPF s'alignait-il ?
    pub aligned_spf: bool,
}

/// Ce qu'il faut au plus pour écrire ce rapport.
#[must_use]
pub fn feedback_report_max(report: &FeedbackReport<'_>) -> usize {
    /// Les noms de champs, les fins de ligne, l'adresse, les mots fixes.
    const ENVELOPPE: usize = 384;
    ENVELOPPE
        .saturating_add(report.user_agent.len())
        .saturating_add(report.arrival_date.len())
        .saturating_add(report.reported_domain.len())
        .saturating_add(report.original_mail_from.unwrap_or_default().len())
        .saturating_add(report.dkim_domain.unwrap_or_default().len())
        .saturating_add(report.dkim_selector.unwrap_or_default().len())
        .saturating_add(report.spf_dns.unwrap_or_default().len())
}

/// Écrit le corps d'une partie `message/feedback-report`.
///
/// # Errors
///
/// [`Error::NotPrintable`] si une valeur porte un octet hors de l'ASCII
/// imprimable — un `CRLF` y écrirait des champs à notre place ;
/// [`Error::BufferTooSmall`] si `out` ne suffit pas.
pub fn write_feedback_report<'b>(
    out: &'b mut [u8],
    report: &FeedbackReport<'_>,
) -> Result<&'b [u8], Error> {
    for valeur in [
        report.user_agent,
        report.arrival_date,
        report.reported_domain,
        report.original_mail_from.unwrap_or(b"-"),
        report.dkim_domain.unwrap_or(b"-"),
        report.dkim_selector.unwrap_or(b"-"),
        report.spf_dns.unwrap_or(b"-"),
    ] {
        if valeur.is_empty()
            || !valeur
                .iter()
                .all(|octet| octet.is_ascii_graphic() || *octet == b' ')
        {
            return Err(Error::NotPrintable);
        }
    }

    let mut plume = Plume::neuve(out);
    plume.champ(b"Feedback-Type", b"auth-failure")?;
    plume.champ(b"User-Agent", report.user_agent)?;
    plume.champ(b"Version", b"1")?;
    plume.champ(
        b"Original-Mail-From",
        report.original_mail_from.unwrap_or(b"<>"),
    )?;
    plume.champ(b"Arrival-Date", report.arrival_date)?;
    plume.pousser(b"Source-IP: ")?;
    plume.adresse(report.source_ip)?;
    plume.pousser(b"\r\n")?;
    plume.champ(b"Reported-Domain", report.reported_domain)?;
    plume.champ(b"Auth-Failure", report.auth_failure.name())?;
    plume.champ(b"Delivery-Result", report.delivery_result.name())?;
    if let Some(domaine) = report.dkim_domain {
        plume.champ(b"DKIM-Domain", domaine)?;
    }
    if let Some(selecteur) = report.dkim_selector {
        plume.champ(b"DKIM-Selector", selecteur)?;
    }
    if let Some(domaine) = report.spf_dns {
        plume.champ(b"SPF-DNS", domaine)?;
    }
    // `Identity-Alignment` dit LEQUEL s'alignait, et « none » quand aucun. C'est
    // le champ que la RFC 7489 §7.3 ajoute à la RFC 6591, et c'est celui qui
    // rend le rapport lisible : « rien ne s'aligne » et « DKIM s'alignait mais
    // pas SPF » ne se corrigent pas de la même façon.
    plume.pousser(b"Identity-Alignment: ")?;
    match (report.aligned_dkim, report.aligned_spf) {
        (false, false) => plume.pousser(b"none")?,
        (true, false) => plume.pousser(b"dkim")?,
        (false, true) => plume.pousser(b"spf")?,
        (true, true) => plume.pousser(b"dkim, spf")?,
    }
    plume.pousser(b"\r\n")?;
    Ok(plume.fini())
}

/// De quoi écrire des champs dans le tampon d'autrui.
struct Plume<'a> {
    out: &'a mut [u8],
    ecrits: usize,
    /// Ce qui a fait échouer une écriture passée par `core::fmt`, qui ne rend
    /// qu'une erreur sans cause.
    faute: Option<Error>,
}

impl core::fmt::Write for Plume<'_> {
    fn write_str(&mut self, morceau: &str) -> core::fmt::Result {
        match self.pousser(morceau.as_bytes()) {
            Ok(()) => Ok(()),
            Err(cause) => {
                self.faute = Some(cause);
                Err(core::fmt::Error)
            }
        }
    }
}

impl<'a> Plume<'a> {
    fn neuve(out: &'a mut [u8]) -> Self {
        Self {
            out,
            ecrits: 0,
            faute: None,
        }
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

    fn champ(&mut self, nom: &[u8], valeur: &[u8]) -> Result<(), Error> {
        self.pousser(nom)?;
        self.pousser(b": ")?;
        self.pousser(valeur)?;
        self.pousser(b"\r\n")
    }

    /// Écrit l'adresse par le `Display` de la bibliothèque standard.
    ///
    /// La forme abrégée d'une adresse IPv6 a ses règles (RFC 5952) ; en écrire
    /// une seconde ferait deux écritures d'une même adresse dans un dépôt qui en
    /// compare.
    fn adresse(&mut self, source: IpAddr) -> Result<(), Error> {
        use core::fmt::Write as _;

        match write!(self, "{source}") {
            Ok(()) => Ok(()),
            // `fmt::Error` ne dit rien ; la cause, elle, a été retenue.
            Err(_) => Err(self.faute.unwrap_or(Error::BufferTooSmall)),
        }
    }

    fn fini(self) -> &'a [u8] {
        self.out.get(..self.ecrits).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests;
