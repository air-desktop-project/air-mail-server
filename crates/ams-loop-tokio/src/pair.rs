// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le pair d'une connexion de courrier, pour le journal d'audit (phase 6).
//!
//! # POURQUOI UNE VARIABLE DE TÂCHE, ET NON UN ARGUMENT
//!
//! SMTP, IMAP et POP3 authentifient dans leurs machines à états
//! (`ams-session`), qui ne connaissent pas le réseau — c'est ce qui les rend
//! vérifiables sans lui (C1). La politique qui tranche, elle, est PARTAGÉE
//! entre toutes les connexions. Ni l'une ni l'autre ne sait donc d'où vient
//! le pair ; seule la boucle le sait.
//!
//! Faire descendre l'adresse dans les trois machines à états changerait leur
//! API pour une question qui ne les regarde pas. La boucle la pose donc ici,
//! pour la durée de la connexion, et la politique la LIT quand elle écrit au
//! journal d'audit — et pour rien d'autre : **aucune décision ne dépend de ce
//! qui est rangé ici.** Une politique appelée hors d'une connexion y trouve
//! `None`, et le journal écrit alors une source nulle.

use core::future::Future;

use ams_guard::Source;

/// Le protocole par lequel le pair est arrivé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Porte {
    /// SMTP — la soumission, et `AUTH` où qu'il soit offert.
    Smtp,
    /// IMAP.
    Imap,
    /// POP3.
    Pop3,
}

impl Porte {
    /// Son nom, tel que le journal d'audit l'écrit.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Smtp => "smtp",
            Self::Imap => "imap",
            Self::Pop3 => "pop3",
        }
    }
}

tokio::task_local! {
    /// Le pair de la connexion que cette tâche conduit.
    static PAIR: (Source, Porte);
}

/// Le pair de la connexion en cours, s'il y en a une.
#[must_use]
pub fn current_peer() -> Option<(Source, Porte)> {
    PAIR.try_with(|pair| *pair).ok()
}

/// Conduit `connexion` avec ce pair rangé pour elle.
///
/// **L'APPELANT LA DONNE EN BOÎTE.** Le futur d'une connexion porte ses
/// tampons, et il est gros ; le déplacer par valeur dans cette enveloppe puis
/// dans celle de `task_local` le recopiait sur la pile à chaque étage — assez
/// pour faire déborder la pile de deux mébioctets d'un fil d'essai. Une boîte
/// ne déplace qu'un pointeur, pour une allocation par connexion.
pub(crate) async fn sous<F: Future>(source: Source, porte: Porte, connexion: F) -> F::Output {
    PAIR.scope((source, porte), connexion).await
}

#[cfg(test)]
mod tests {
    use super::{Porte, current_peer, sous};
    use ams_guard::Source;

    #[tokio::test]
    async fn le_pair_ne_vaut_que_pour_sa_connexion() {
        assert_eq!(current_peer(), None);
        let source = Source::V4([192, 0, 2, 1]);
        let vu = sous(source, Porte::Imap, async { current_peer() }).await;
        assert_eq!(vu, Some((source, Porte::Imap)));
        assert_eq!(current_peer(), None);
        assert_eq!(
            [Porte::Smtp.name(), Porte::Imap.name(), Porte::Pop3.name()],
            ["smtp", "imap", "pop3"]
        );
    }
}
