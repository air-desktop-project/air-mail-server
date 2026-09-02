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
    /// L'identifiant d'enveloppe que le déposant a donné (RFC 3461 §4.4), ou
    /// une chaîne vide.
    ///
    /// **Il ressort dans le rapport**, en `Original-Envelope-Id` : c'est ce qui
    /// permet au déposant de rattacher le rapport à son envoi sans lire le
    /// message.
    pub envelope_id: &'a str,
    /// Ce que chaque destinataire a demandé (§4.1), et d'où il vient (§4.2).
    ///
    /// **Vide est licite**, et c'est le cas ordinaire : sans DSN, chacun prend
    /// le défaut de §4.1 — un rapport en cas d'échec, et rien d'autre.
    pub reports: &'r [Report<'a>],
}

/// Ce qu'un destinataire a demandé du sort de son message (RFC 3461).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Report<'a> {
    /// Le pair demande qu'on se TAISE, quoi qu'il arrive (§4.1).
    ///
    /// # C'EST LA SEULE VALEUR QUI FAIT PERDRE UN RAPPORT
    ///
    /// Un `NEVER` mal lu supprime un rapport que quelqu'un attendait, et rien
    /// ne le dira : ni le déposant, qui croit son message parti, ni nous.
    pub never: bool,
    /// Un rapport est demandé en cas de SUCCÈS (§4.1).
    pub on_success: bool,
    /// L'adresse d'origine, telle que le déposant l'a écrite (§4.2), ou une
    /// chaîne vide.
    pub original: &'a str,
}

/// Ce qu'il faut au plus pour écrire cette enveloppe.
#[must_use]
pub fn envelope_max(envelope: &Envelope<'_, '_>) -> usize {
    // **LA BORNE EST EXACTE, ET NON GÉNÉREUSE.** Une borne qui majore de deux
    // octets rend l'essai de troncature complaisant : il ne verrait pas qu'un
    // tampon d'un octet de moins que le nécessaire suffit encore.
    let mut total = envelope.return_path.len().saturating_add(1);
    if !envelope.envelope_id.is_empty() {
        // La tabulation, puis l'identifiant.
        total = total
            .saturating_add(1)
            .saturating_add(envelope.envelope_id.len());
    }
    for (rang, adresse) in envelope.recipients.iter().enumerate() {
        total = total.saturating_add(adresse.len()).saturating_add(1);
        let Some(rapport) = envelope.reports.get(rang) else {
            continue;
        };
        if !rapport.never && !rapport.on_success && rapport.original.is_empty() {
            continue;
        }
        // La tabulation, puis les deux lettres au plus.
        total = total
            .saturating_add(1)
            .saturating_add(usize::from(rapport.never))
            .saturating_add(usize::from(rapport.on_success));
        if !rapport.original.is_empty() {
            // L'espace, puis l'adresse d'origine.
            total = total
                .saturating_add(1)
                .saturating_add(rapport.original.len());
        }
    }
    total
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
    // ── CE QUE RFC 3461 AJOUTE, APRÈS UNE TABULATION ────────────────────────
    //
    // **UN FICHIER ÉCRIT AVANT CETTE TRANCHE SE RELIT SANS RIEN PERDRE** : une
    // adresse est de l'ASCII VISIBLE, donc elle ne porte jamais de tabulation.
    // Ce qui suit la première tabulation est donc, par construction, ce que
    // cette tranche a ajouté — et son absence vaut le défaut de §4.1.
    if !envelope.envelope_id.is_empty() {
        if !adresse_recevable(envelope.envelope_id) {
            return Err(Error::BadAddress);
        }
        ecrits = pousser(sortie, ecrits, b"\t")?;
        ecrits = pousser(sortie, ecrits, envelope.envelope_id.as_bytes())?;
    }
    ecrits = pousser(sortie, ecrits, b"\n")?;
    for (rang, adresse) in envelope.recipients.iter().enumerate() {
        if !adresse_recevable(adresse) {
            return Err(Error::BadAddress);
        }
        ecrits = pousser(sortie, ecrits, adresse.as_bytes())?;
        if let Some(rapport) = envelope.reports.get(rang)
            && (rapport.never || rapport.on_success || !rapport.original.is_empty())
        {
            if !rapport.original.is_empty() && !adresse_recevable(rapport.original) {
                return Err(Error::BadAddress);
            }
            ecrits = pousser(sortie, ecrits, b"\t")?;
            // Deux lettres qui se lisent à l'œil : `N` pour le silence, `S`
            // pour le succès. L'échec est le défaut, et ne s'écrit pas.
            if rapport.never {
                ecrits = pousser(sortie, ecrits, b"N")?;
            }
            if rapport.on_success {
                ecrits = pousser(sortie, ecrits, b"S")?;
            }
            if !rapport.original.is_empty() {
                ecrits = pousser(sortie, ecrits, b" ")?;
                ecrits = pousser(sortie, ecrits, rapport.original.as_bytes())?;
            }
        }
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
/// [`Error::BadAddress`] ; [`Error::BadRecipients`] s'il n'y a aucun
/// destinataire, ou si `place` ou `rapports` en portent moins que le fichier.
pub fn parse_envelope<'a, 'r>(
    texte: &'a str,
    place: &'r mut [&'a str],
    rapports: &'r mut [Report<'a>],
) -> Result<Envelope<'a, 'r>, Error> {
    let mut lignes = texte.lines().filter(|ligne| !ligne.is_empty());
    let tete = lignes.next().ok_or(Error::BadAddress)?;
    let (return_path, envelope_id) = couper(tete);
    if !adresse_recevable(return_path)
        || (!envelope_id.is_empty() && !adresse_recevable(envelope_id))
    {
        return Err(Error::BadAddress);
    }
    let mut combien = 0_usize;
    for ligne in lignes {
        let (adresse, suite) = couper(ligne);
        if !adresse_recevable(adresse) {
            return Err(Error::BadAddress);
        }
        let case = place.get_mut(combien).ok_or(Error::BadRecipients)?;
        *case = adresse;
        let rapport = lire_le_rapport(suite)?;
        // **UN TABLEAU DE RAPPORTS TROP COURT EST UN REFUS**, et non un
        // silence. Rendre les destinataires sans leurs rapports ferait retomber
        // chacun sur le défaut de §4.1 — c'est-à-dire enverrait un rapport de
        // non-remise à qui avait demandé le silence, et personne ne le saurait.
        let case = rapports.get_mut(combien).ok_or(Error::BadRecipients)?;
        *case = rapport;
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
        envelope_id,
        // La tranche existe : chaque case a été écrite ci-dessus, ou la
        // lecture a échoué.
        reports: rapports.get(..combien).unwrap_or_default(),
    })
}

/// Coupe une ligne à sa PREMIÈRE tabulation.
///
/// Une adresse est de l'ASCII visible : elle n'en porte jamais. Ce qui suit est
/// donc, par construction, ce que RFC 3461 a ajouté — et son absence est le cas
/// ordinaire.
fn couper(ligne: &str) -> (&str, &str) {
    match ligne.find('\t') {
        Some(rang) => {
            let (avant, apres) = ligne.split_at(rang);
            // `split_at` garde la tabulation en tête du reste.
            (avant, apres.get(1..).unwrap_or_default())
        }
        None => (ligne, ""),
    }
}

/// Relit ce que RFC 3461 a ajouté à une ligne de destinataire.
///
/// # Errors
///
/// [`Error::BadAddress`] si une lettre est inconnue, répétée, ou si l'adresse
/// d'origine n'est pas recevable.
fn lire_le_rapport(suite: &str) -> Result<Report<'_>, Error> {
    if suite.is_empty() {
        return Ok(Report::default());
    }
    let (lettres, original) = match suite.find(' ') {
        Some(rang) => {
            let (avant, apres) = suite.split_at(rang);
            (avant, apres.get(1..).unwrap_or_default())
        }
        None => (suite, ""),
    };
    let mut rapport = Report {
        never: false,
        on_success: false,
        original,
    };
    for lettre in lettres.bytes() {
        // **UNE LETTRE RÉPÉTÉE EST UNE FAUTE** : c'est un fichier qu'on a écrit
        // soi-même, et deux lectures d'un même fichier doivent s'accorder.
        let place = match lettre {
            b'N' => &mut rapport.never,
            b'S' => &mut rapport.on_success,
            _ => return Err(Error::BadAddress),
        };
        if *place {
            return Err(Error::BadAddress);
        }
        *place = true;
    }
    if !original.is_empty() && !adresse_recevable(original) {
        return Err(Error::BadAddress);
    }
    Ok(rapport)
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
