//! L'encodage des réponses (RFC 9051 §7).
//!
//! # Trois formes, et le client les distingue au premier octet
//!
//! - `*` — une réponse **non sollicitée** : ce que le serveur dit sans qu'on
//!   le lui ait demandé, et ce dont il répond à une commande en cours.
//! - `+` — une **demande de continuation** : « envoyez la suite ».
//! - un tag — la **conclusion** d'une commande, et c'est ce tag qui dit
//!   laquelle.
//!
//! Ces trois octets sont donc le squelette du protocole. **Un texte qui en
//! porterait un après un `CRLF` écrirait une réponse de plus** — voir
//! [`texte_recevable`], qui ne le laisse pas passer.

use crate::{Error, Limits, Tag};

/// La conclusion d'une commande (RFC 9051 §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// `OK` — la commande a abouti.
    Ok,
    /// `NO` — elle a échoué, mais elle était compréhensible.
    ///
    /// **La distinction avec `BAD` n'est pas cosmétique** : un `NO` dit au
    /// client que sa commande était correcte et que la réponse est non ; un
    /// `BAD` lui dit qu'il l'a mal écrite. Confondre les deux fait qu'un client
    /// réessaie ce qui ne marchera jamais, ou renonce à ce qui aurait marché.
    No,
    /// `BAD` — elle est mal formée, ou hors de propos à cet instant.
    Bad,
}

impl Status {
    /// Le mot, tel qu'il s'écrit.
    #[must_use]
    pub fn name(self) -> &'static [u8] {
        match self {
            Self::Ok => b"OK",
            Self::No => b"NO",
            Self::Bad => b"BAD",
        }
    }
}

/// Écrit la conclusion d'une commande : `<tag> <STATUS> <texte>`.
///
/// # Errors
///
/// [`Error::ResponseTextNotPrintable`] si `texte` porte un octet qu'on refuse
/// d'écrire, [`Error::BufferTooSmall`] si `out` ne suffit pas,
/// [`Error::LineTooLong`] au-delà de
/// [`Limits::max_response_octets`](crate::Limits::max_response_octets).
pub fn encode_tagged<'b>(
    out: &'b mut [u8],
    tag: Tag<'_>,
    status: Status,
    texte: &[u8],
    limits: &Limits,
) -> Result<&'b [u8], Error> {
    ecrire(
        out,
        &[tag.as_bytes(), b" ", status.name(), b" ", texte],
        limits,
    )
}

/// Écrit une réponse non sollicitée : `* <texte>`.
///
/// # Errors
///
/// Comme [`encode_tagged`].
pub fn encode_untagged<'b>(
    out: &'b mut [u8],
    texte: &[u8],
    limits: &Limits,
) -> Result<&'b [u8], Error> {
    ecrire(out, &[b"*", b" ", texte], limits)
}

/// Écrit une demande de continuation : `+ <texte>`.
///
/// # Errors
///
/// Comme [`encode_tagged`].
pub fn encode_continuation<'b>(
    out: &'b mut [u8],
    texte: &[u8],
    limits: &Limits,
) -> Result<&'b [u8], Error> {
    ecrire(out, &[b"+", b" ", texte], limits)
}

/// Écrit une ligne de réponse, `CRLF` compris.
fn ecrire<'b>(out: &'b mut [u8], morceaux: &[&[u8]], limits: &Limits) -> Result<&'b [u8], Error> {
    let longueur = morceaux.iter().fold(0_usize, |total, morceau| {
        total.saturating_add(morceau.len())
    });
    if longueur > limits.max_response_octets {
        return Err(Error::LineTooLong {
            limit: limits.max_response_octets,
        });
    }
    let besoin = longueur.saturating_add(2);
    let mut ecrits = 0_usize;
    for morceau in morceaux {
        if !texte_recevable(morceau) {
            return Err(Error::ResponseTextNotPrintable);
        }
        let fin = ecrits.saturating_add(morceau.len());
        let place = out
            .get_mut(ecrits..fin)
            .ok_or(Error::BufferTooSmall { needed: besoin })?;
        place.copy_from_slice(morceau);
        ecrits = fin;
    }
    let fin = ecrits.saturating_add(2);
    let place = out
        .get_mut(ecrits..fin)
        .ok_or(Error::BufferTooSmall { needed: besoin })?;
    place.copy_from_slice(b"\r\n");
    out.get(..fin)
        .ok_or(Error::BufferTooSmall { needed: besoin })
}

/// Ce texte peut-il s'écrire dans une réponse ?
///
/// De l'ASCII imprimable et des espaces, et rien d'autre. **Pas de `CRLF`** :
/// un texte qui en porterait un écrirait une réponse de plus, du choix de celui
/// qui a fourni le texte — et ce texte vient souvent d'un nom de boîte, donc
/// d'un client.
fn texte_recevable(texte: &[u8]) -> bool {
    texte
        .iter()
        .all(|octet| octet.is_ascii_graphic() || *octet == b' ')
}

#[cfg(test)]
mod tests;
