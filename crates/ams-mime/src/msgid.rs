// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les identifiants de message : `Message-ID:`, `In-Reply-To:`, `References:`
//! (RFC 5322 §3.6.4).
//!
//! # CE QUI SE REND, C'EST CE QUI EST ENTRE LES CHEVRONS
//!
//! `<abc@example.test>` rend `abc@example.test` : les chevrons appartiennent à
//! la syntaxe, pas à l'identifiant, et un client qui compare deux fils ne doit
//! pas avoir à les retirer lui-même — ni à deviner si l'autre côté l'a fait.
//!
//! # CE QUI NE PEUT PAS ÊTRE UN IDENTIFIANT EST SAUTÉ
//!
//! Un identifiant porte de l'ASCII imprimable, sans blanc. Ce qui en porte
//! d'autres — un blanc, un octet de contrôle, de l'UTF-8 — n'identifie rien
//! qu'un client saurait retrouver, et le rendre lui ferait chercher un fil qui
//! n'existe pas. `In-Reply-To:` écrit en texte libre (§4.5.4 l'a longtemps
//! admis) ne rend donc rien, ce qui est vrai : il ne désigne aucun message.

/// Les identifiants d'un champ, dans l'ordre où il les porte.
#[must_use]
pub fn message_ids(value: &[u8]) -> MessageIds<'_> {
    MessageIds { reste: value }
}

/// Les identifiants d'un champ, un par un.
#[derive(Debug, Clone, Copy)]
pub struct MessageIds<'a> {
    /// Ce qu'il reste à parcourir.
    reste: &'a [u8],
}

impl<'a> Iterator for MessageIds<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        loop {
            let ouvrant = self.reste.iter().position(|octet| *octet == b'<')?;
            let apres = self
                .reste
                .get(ouvrant.saturating_add(1)..)
                .unwrap_or_default();
            // Le chevron fermant, ou le bout : un identifiant que rien ne ferme
            // n'en est pas un, et tout ce qui suit est perdu avec lui.
            let Some(fermant) = apres.iter().position(|octet| *octet == b'>') else {
                self.reste = &[];
                return None;
            };
            let dedans = apres.get(..fermant).unwrap_or_default();
            self.reste = apres.get(fermant.saturating_add(1)..).unwrap_or_default();
            if !dedans.is_empty() && dedans.iter().all(|octet| matches!(*octet, b'!'..=b'~')) {
                return Some(dedans);
            }
        }
    }
}

#[cfg(test)]
mod tests;
