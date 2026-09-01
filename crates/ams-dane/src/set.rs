//! Un jeu d'enregistrements `TLSA`, et ce qu'il engage.

use alloc::vec::Vec;

use crate::record::{Match, Tlsa};

/// Tout ce que le DNS a rendu pour un serveur, et ce qu'on en fait.
///
/// # C'EST ICI QUE L'AUTHENTICITÉ ENTRE, ET ELLE VIENT DE L'APPELANT
///
/// Cette crate ne valide aucune signature DNSSEC. Elle exige de l'appelant qu'il
/// DISE si la réponse était authentifiée — le bit `AD` d'un résolveur valideur —
/// et elle refuse de s'appliquer sans cela.
///
/// **Un `TLSA` lu dans une réponse non authentifiée ne vaut rien.** Pire qu'un
/// mensonge : un tiers qui détourne la résolution le RETIRE, et l'on retomberait
/// sur le chiffrement opportuniste en croyant être protégé. Le seul refus qui
/// tienne est de ne pas s'appliquer du tout.
#[derive(Debug, Clone)]
pub struct Set<'a> {
    records: Vec<Tlsa<'a>>,
    authentic: bool,
}

impl<'a> Set<'a> {
    /// Rassemble ce que le DNS a rendu.
    ///
    /// `authentic` dit si la réponse était **authentifiée** — voir la
    /// documentation du type, qui dit ce que cela veut dire et ce que cela ne
    /// veut pas dire.
    #[must_use]
    pub fn from_records(records: Vec<Tlsa<'a>>, authentic: bool) -> Self {
        Self { records, authentic }
    }

    /// Un jeu qui n'engage à rien : aucun `TLSA`, ou une réponse non
    /// authentifiée.
    #[must_use]
    pub fn none() -> Self {
        Self {
            records: Vec::new(),
            authentic: false,
        }
    }

    /// Ce jeu OBLIGE-t-il à authentifier la remise ?
    ///
    /// Il faut les deux : une réponse authentifiée, et **au moins un
    /// enregistrement utilisable**. §2.2 de RFC 7672 : un jeu dont aucun
    /// enregistrement n'est utilisable se traite comme un jeu vide — chiffrement
    /// opportuniste, et le courrier passe.
    ///
    /// C'est la bonne façon d'échouer : un domaine qui publie un algorithme de
    /// demain ne doit pas voir son courrier s'arrêter aujourd'hui.
    #[must_use]
    pub fn engage(&self) -> bool {
        self.authentic && self.records.iter().any(|record| record.usable())
    }

    /// La réponse était-elle authentifiée ?
    #[must_use]
    pub fn authentic(&self) -> bool {
        self.authentic
    }

    /// Les enregistrements UTILISABLES, et eux seuls.
    pub fn usable(&self) -> impl Iterator<Item = &Tlsa<'a>> {
        self.records.iter().filter(|record| record.usable())
    }

    /// Ce que ce certificat satisfait, s'il satisfait quelque chose.
    ///
    /// # UN SEUL ENREGISTREMENT SUFFIT, ET C'EST LA RFC
    ///
    /// §2.1 de RFC 7671 : le jeu est une DISJONCTION. Un domaine qui renouvelle
    /// publie l'ancienne et la nouvelle empreinte en même temps, et exiger les
    /// deux rendrait tout renouvellement impossible.
    ///
    /// Rend `None` quand aucun ne correspond — et c'est alors un échec
    /// d'authentification, pas une absence de DANE : voir [`Set::engage`].
    #[must_use]
    pub fn matching(&self, certificate: &[u8]) -> Option<Match> {
        // **L'ENTITÉ FINALE D'ABORD**, et ce n'est pas une optimisation : elle ne
        // demande ni chaîne, ni nom, ni date, et la trouver dispense de tout le
        // reste. Prendre l'autorité en premier ferait vérifier un nom là où le
        // domaine avait nommé un certificat exact.
        let mut ancre = None;
        for record in &self.records {
            // **UN INUTILISABLE NE SATISFAIT RIEN**, même quand ses octets
            // correspondent. C'est ici qu'on l'écarte, et non par un bras que
            // rien n'atteindrait plus bas.
            let Some(exigence) = record.requirement() else {
                continue;
            };
            if !record.matches(certificate) {
                continue;
            }
            match exigence {
                Match::LeafOnly => return Some(Match::LeafOnly),
                Match::Anchor => ancre = Some(Match::Anchor),
            }
        }
        ancre
    }
}

impl Default for Set<'_> {
    fn default() -> Self {
        Self::none()
    }
}

#[cfg(test)]
mod tests;
