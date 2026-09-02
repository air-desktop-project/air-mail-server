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
    /// Ce que ce serveur a FAIT du message pour ce destinataire (§2.3.3).
    ///
    /// # POURQUOI CE CHAMP, ALORS QUE CE RAPPORT S'APPELAIT « NON-REMISE »
    ///
    /// RFC 3461 §4.1 permet au déposant de demander un rapport de SUCCÈS. C'est
    /// le même document que celui d'un échec — §2 de RFC 3464 ne connaît qu'un
    /// format — et seul ce mot le distingue. Deux composeurs pour un même
    /// document auraient fini par écrire deux documents.
    pub action: Action,
    /// L'adresse d'origine, telle que le déposant l'a écrite (RFC 3461 §4.2).
    ///
    /// Vide : le champ `Original-Recipient` est **omis**. Le remplir avec
    /// l'adresse finale ferait croire que le déposant l'avait écrite, alors que
    /// c'est nous qui l'aurions devinée.
    pub original: &'a [u8],
}

/// Ce qu'un serveur a fait d'un message, pour un destinataire (§2.3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Action {
    /// Il n'a pas été remis, et ne le sera pas.
    #[default]
    Failed,
    /// Il a été remis.
    Delivered,
}

impl Action {
    /// Le mot que §2.3.3 emploie.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Failed => "failed",
            Self::Delivered => "delivered",
        }
    }
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
    /// L'identifiant d'enveloppe du déposant (RFC 3461 §4.4), ou vide.
    pub envelope_id: &'a [u8],
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
            // `Original-Recipient: rfc822; ` et sa valeur, quand le déposant
            // l'a écrite.
            .saturating_add(echec.original.len())
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
        .saturating_add(bounce.envelope_id.len())
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
    // **L'IDENTIFIANT D'ENVELOPPE VIENT DU DÉPOSANT** (RFC 3461 §4.4), et il
    // ressort ici dans un en-tête. Vide, il n'est pas écrit ; non vide, il doit
    // pouvoir l'être — la session le vérifie déjà, et cette crate ne suppose pas
    // ce que son appelant a fait. Le fuzz l'a rappelé.
    if !bounce.envelope_id.is_empty() && !bounce.envelope_id.iter().all(u8::is_ascii_graphic) {
        return Err(Error::NotPrintable);
    }
    for echec in bounce.failures {
        if echec.recipient.is_empty() || !echec.recipient.iter().all(u8::is_ascii_graphic) {
            return Err(Error::NotPrintable);
        }
        // **L'ADRESSE D'ORIGINE AUSSI VIENT DU DÉPOSANT** (§4.2), et l'écrire
        // sans la vérifier ouvrirait un champ entier sous notre nom.
        if !echec.original.is_empty() && !echec.original.iter().all(u8::is_ascii_graphic) {
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
    // **L'IDENTIFIANT D'ENVELOPPE DU DÉPOSANT** (RFC 3461 §6.1), s'il en a
    // donné un : c'est ce qui lui permet de rattacher ce rapport à son envoi
    // sans avoir à lire le message qu'il contient.
    if !bounce.envelope_id.is_empty() {
        ecrits = pousser(sortie, ecrits, b"\r\nOriginal-Envelope-Id: ")?;
        ecrits = pousser(sortie, ecrits, bounce.envelope_id)?;
    }
    ecrits = pousser(sortie, ecrits, b"\r\nArrival-Date: ")?;
    ecrits = date(sortie, ecrits, bounce.arrival)?;
    ecrits = pousser(sortie, ecrits, b"\r\n")?;
    for echec in bounce.failures {
        // **`Original-Recipient` VIENT EN PREMIER** (§2.3.2), et seulement si le
        // déposant l'a écrit : c'est SON adresse, pas celle que nous avons
        // résolue.
        if !echec.original.is_empty() {
            ecrits = pousser(sortie, ecrits, b"\r\nOriginal-Recipient: rfc822; ")?;
            ecrits = pousser(sortie, ecrits, echec.original)?;
            ecrits = pousser(sortie, ecrits, b"\r\nFinal-Recipient: rfc822; ")?;
        } else {
            ecrits = pousser(sortie, ecrits, b"\r\nFinal-Recipient: rfc822; ")?;
        }
        ecrits = pousser(sortie, ecrits, echec.recipient)?;
        ecrits = pousser(sortie, ecrits, b"\r\nAction: ")?;
        ecrits = pousser(sortie, ecrits, echec.action.name().as_bytes())?;
        ecrits = pousser(sortie, ecrits, b"\r\nStatus: ")?;
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
