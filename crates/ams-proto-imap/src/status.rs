// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un `STATUS` demande (RFC 9051 §6.3.11).
//!
//! # LA RÉPONSE DOIT PORTER CE QUI A ÉTÉ DEMANDÉ
//!
//! §7.3.3 : la réponse non sollicitée porte les éléments demandés. Rendre
//! toujours les mêmes trois est commode, et faux — un client qui demande
//! `UNSEEN` pour afficher un compte de non-lus ne le trouve pas, et n'a aucun
//! moyen de savoir si la boîte n'en a aucun ou si le serveur ne sait pas
//! compter.
//!
//! # ILS SORTENT DANS L'ORDRE OÙ ILS ONT ÉTÉ DEMANDÉS
//!
//! Rien ne l'exige. Mais une réponse dont l'ordre suit la question se compare
//! d'une fois sur l'autre, et se lit à côté de la commande qui l'a produite.
//!
//! # SIX, ET PAS UN DE PLUS
//!
//! `status-att` est une énumération FERMÉE de six mots. Un septième serait une
//! extension, et ce serveur n'en sert pas — la borne du tableau est donc celle
//! de la grammaire elle-même, et non un choix qu'il faudrait justifier.

use crate::error::Error;

/// Ce qu'un `STATUS` peut demander (§6.3.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusAtt {
    /// Combien de messages la boîte porte.
    Messages,
    /// Le prochain UID qu'elle attribuera.
    UidNext,
    /// L'identifiant de sa numérotation.
    UidValidity,
    /// Combien de messages n'ont pas `\Seen`.
    Unseen,
    /// Combien portent `\Deleted`.
    Deleted,
    /// La somme des tailles, en octets.
    Size,
    /// Combien de messages sont RÉCENTS (RFC 3501 §6.3.10).
    ///
    /// **RETIRÉ PAR IMAP4rev2** (§A) avec le drapeau `\Recent` qu'il comptait.
    /// La GRAMMAIRE l'admet quand même : ce serveur annonce `IMAP4rev1`, et un
    /// client qui n'a pas activé rev2 a le droit de le demander. C'est la
    /// SESSION qui refuse ce mot une fois rev2 activé — la grammaire ne sait pas
    /// ce qui a été activé, et prétendre le savoir ici mettrait la décision à
    /// deux endroits.
    Recent,
}

/// Combien d'éléments un `STATUS` peut demander.
///
/// Sept : les six mots que §6.3.11 définit, plus le `RECENT` de RFC 3501
/// §6.3.10 que ce serveur admet tant que rev2 n'est pas activé. Les doublons se
/// réduisent — `(MESSAGES MESSAGES)` ne demande qu'une chose.
pub const STATUS_ATTS_MAX: usize = 7;

/// Les éléments d'un `STATUS`, dans l'ordre où ils ont été demandés.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusItems {
    /// Les éléments, sans doublon.
    atts: [StatusAtt; STATUS_ATTS_MAX],
    /// Combien d'`atts` valent.
    combien: usize,
}

impl StatusItems {
    /// Les éléments demandés, dans l'ordre.
    #[must_use]
    pub fn items(&self) -> &[StatusAtt] {
        self.atts.get(..self.combien).unwrap_or_default()
    }

    /// Cet élément a-t-il été demandé ?
    #[must_use]
    pub fn wants(&self, att: StatusAtt) -> bool {
        self.items().contains(&att)
    }

    /// Lit la liste d'éléments d'un `STATUS`, parenthèses comprises.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedStatus`] si la forme n'est pas celle de §6.3.11, ou si
    /// l'on y nomme un élément qui n'en est pas un.
    pub fn parse(arguments: &[u8]) -> Result<Self, Error> {
        let arguments = arguments.trim_ascii();
        let corps = arguments
            .strip_prefix(b"(")
            .and_then(|reste| reste.strip_suffix(b")"))
            .ok_or(Error::MalformedStatus)?;
        let mut atts = [StatusAtt::Messages; STATUS_ATTS_MAX];
        let mut combien = 0_usize;
        for mot in corps.split(|octet| *octet == b' ') {
            if mot.is_empty() {
                continue;
            }
            let att = un_element(mot)?;
            // UN DOUBLON NE DEMANDE RIEN DE PLUS, et n'est pas une faute : le
            // client a écrit deux fois la même chose, ce qui ne rend pas sa
            // commande incompréhensible.
            if atts.get(..combien).unwrap_or_default().contains(&att) {
                continue;
            }
            // LE TABLEAU NE PEUT PAS DÉBORDER : six mots distincts au plus, et
            // les doublons viennent d'être écartés. On écrit donc par `zip`, qui
            // s'arrête de lui-même — plutôt que par une garde qu'aucune entrée
            // ne peut emprunter, et qu'aucun test ne pourrait donc atteindre.
            for (place, valeur) in atts.iter_mut().skip(combien).zip([att]) {
                *place = valeur;
            }
            combien = combien.saturating_add(1);
        }
        // §9 : `status-att *(SP status-att)` — il en faut AU MOINS un. Une liste
        // vide ne demande rien, et une réponse vide ne dirait pas au client si
        // c'est lui qui n'a rien demandé ou nous qui n'avons rien su.
        if combien == 0 {
            return Err(Error::MalformedStatus);
        }
        Ok(Self { atts, combien })
    }
}

/// Lit un `status-att`.
fn un_element(mot: &[u8]) -> Result<StatusAtt, Error> {
    for (nom, att) in [
        (&b"MESSAGES"[..], StatusAtt::Messages),
        (b"UIDNEXT", StatusAtt::UidNext),
        (b"UIDVALIDITY", StatusAtt::UidValidity),
        (b"UNSEEN", StatusAtt::Unseen),
        (b"DELETED", StatusAtt::Deleted),
        (b"SIZE", StatusAtt::Size),
        (b"RECENT", StatusAtt::Recent),
    ] {
        if mot.eq_ignore_ascii_case(nom) {
            return Ok(att);
        }
    }
    // Tout autre mot tombe ici. Le refuser dit au client qu'on ne le connaît
    // pas, là où rendre zéro lui ferait croire à une réponse.
    Err(Error::MalformedStatus)
}

#[cfg(test)]
mod tests;
