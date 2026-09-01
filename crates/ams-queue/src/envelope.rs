//! L'enveloppe d'une entrée : d'où vient le message, et à qui il va.
//!
//! # POURQUOI ELLE EST À CÔTÉ DU MESSAGE, ET PAS DEDANS
//!
//! Les en-têtes d'un message ne disent pas à qui le remettre. `To:` peut nommer
//! une liste, `Bcc:` a disparu à la composition (§3.6.3 de RFC 5322), et un
//! `Received:` ajouté en route ne change pas l'enveloppe. **Ce qui décide de la
//! remise, c'est ce que `MAIL FROM:` et `RCPT TO:` ont dit** — et cela ne se
//! retrouve pas en relisant le message.
//!
//! Le fichier voisin porte donc l'enveloppe, une adresse par ligne : le chemin
//! de retour d'abord, les destinataires ensuite.

use crate::Error;

/// Combien de destinataires une entrée peut porter.
///
/// **C'EST UNE BORNE DE C3, PAS UN CONFORT** : ce fichier se relit à chaque
/// reprise, et une ligne par destinataire sans borne serait une lecture sans
/// borne. La valeur suit celle des destinataires d'une transaction SMTP.
pub const RECIPIENTS_MAX: usize = 100;

/// La longueur maximale d'une adresse d'enveloppe.
///
/// §4.5.3.1.3 de RFC 5321 borne un chemin à 256 octets.
const ADDRESS_MAX: usize = 256;

/// Ce qu'une entrée de file doit remettre, et à qui.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Envelope<'a, 'r> {
    /// Le chemin de retour — ce que `MAIL FROM:` a dit.
    ///
    /// **C'EST AUSSI L'ADRESSE DU RAPPORT DE NON-REMISE.** Ce serveur ne relaie
    /// que pour un compte authentifié, si bien que cette adresse est toujours
    /// l'une des siennes : le rapport se remet donc LOCALEMENT, et ce serveur
    /// n'émet jamais de rebond vers un inconnu. C'est ce qui le tient hors de la
    /// rétro-diffusion — envoyer un rebond à une adresse qu'un tiers a écrite
    /// dans un `MAIL FROM:` usurpé fait de nous l'instrument de son envoi.
    pub return_path: &'a str,
    /// Les destinataires restant à servir.
    ///
    /// **Ceux qui ont été remis en sortent** : réécrire l'enveloppe après une
    /// remise partielle est ce qui empêche un destinataire de recevoir deux
    /// fois le même message parce qu'un autre a échoué.
    pub recipients: &'r [&'a str],
}

/// Ce qu'il faut au plus pour écrire cette enveloppe.
#[must_use]
pub fn envelope_max(envelope: &Envelope<'_, '_>) -> usize {
    envelope.recipients.iter().fold(
        envelope.return_path.len().saturating_add(1),
        |total, une| total.saturating_add(une.len()).saturating_add(1),
    )
}

/// Écrit l'enveloppe, une adresse par ligne.
///
/// # Errors
///
/// [`Error::BadAddress`] si une adresse est vide, trop longue, ou porte autre
/// chose que de l'ASCII imprimable ; [`Error::BadRecipients`] s'il n'y en a
/// aucun ou plus de [`RECIPIENTS_MAX`] ; [`Error::BufferTooSmall`] si `sortie`
/// ne suffit pas — voir [`envelope_max`].
pub fn write_envelope<'b>(
    envelope: &Envelope<'_, '_>,
    sortie: &'b mut [u8],
) -> Result<&'b str, Error> {
    if envelope.recipients.is_empty() || envelope.recipients.len() > RECIPIENTS_MAX {
        return Err(Error::BadRecipients);
    }
    if !adresse_recevable(envelope.return_path) {
        return Err(Error::BadAddress);
    }
    let mut ecrits = pousser(sortie, 0, envelope.return_path.as_bytes())?;
    ecrits = pousser(sortie, ecrits, b"\n")?;
    for adresse in envelope.recipients {
        if !adresse_recevable(adresse) {
            return Err(Error::BadAddress);
        }
        ecrits = pousser(sortie, ecrits, adresse.as_bytes())?;
        ecrits = pousser(sortie, ecrits, b"\n")?;
    }
    // `pousser` a déjà écrit jusqu'à `ecrits`.
    let ecrit = sortie.get(..ecrits).unwrap_or_default();
    // CHAQUE ADRESSE A ÉTÉ VÉRIFIÉE ASCII IMPRIMABLE, et le séparateur est un
    // saut de ligne : il n'y a pas d'entrée capable de faire échouer cette
    // conversion.
    Ok(core::str::from_utf8(ecrit).unwrap_or_default())
}

/// Relit une enveloppe, et refuse tout ce qui n'en est pas une.
///
/// Les destinataires sont écrits dans `place`, dont la longueur borne ce que
/// cette fonction accepte de lire. **Un fichier plus garni que `place` est
/// REFUSÉ**, et non tronqué : remettre à une partie des destinataires en
/// oubliant les autres est exactement ce qu'une file ne doit pas faire.
///
/// # Errors
///
/// [`Error::BadAddress`], [`Error::BadRecipients`].
pub fn parse_envelope<'a, 'r>(
    texte: &'a str,
    place: &'r mut [&'a str],
) -> Result<Envelope<'a, 'r>, Error> {
    let mut lignes = texte.lines().filter(|ligne| !ligne.is_empty());
    let return_path = lignes.next().ok_or(Error::BadAddress)?;
    if !adresse_recevable(return_path) {
        return Err(Error::BadAddress);
    }
    let mut combien = 0_usize;
    for adresse in lignes {
        if !adresse_recevable(adresse) {
            return Err(Error::BadAddress);
        }
        let case = place.get_mut(combien).ok_or(Error::BadRecipients)?;
        *case = adresse;
        combien = combien.saturating_add(1);
    }
    // `combien` n'a grandi qu'une fois par case effectivement écrite : il ne
    // peut pas dépasser la longueur de `place`.
    let recipients = place.get(..combien).unwrap_or_default();
    if recipients.is_empty() {
        return Err(Error::BadRecipients);
    }
    Ok(Envelope {
        return_path,
        recipients,
    })
}

/// Cette adresse peut-elle s'écrire, et se relire, ligne à ligne ?
///
/// De l'ASCII imprimable sans espace, et rien d'autre. **Un `LF` glissé dedans
/// ajouterait un destinataire** au fichier qu'on écrit nous-mêmes, et c'est
/// exactement l'injection que cette crate doit fermer.
fn adresse_recevable(adresse: &str) -> bool {
    !adresse.is_empty()
        && adresse.len() <= ADDRESS_MAX
        && adresse.bytes().all(|octet| octet.is_ascii_graphic())
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
