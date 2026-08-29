//! Le verdict (RFC 7489 §6.6.2).

use crate::alignment::{PublicSuffix, aligned};
use crate::record::{Policy, Record};

/// Ce que DMARC conclut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Au moins un mécanisme a réussi **et** s'aligne.
    Pass,
    /// Aucun ne l'a fait.
    ///
    /// **Ce n'est pas « le message est faux »** : c'est « rien ne prouve qu'il
    /// vient de là où il dit venir ». Ce que le receveur en fait est ce que le
    /// domaine a demandé, et rien de plus.
    Fail,
}

/// Ce que les deux mécanismes ont donné.
///
/// # Un seul suffit (§6.6.2)
///
/// DMARC réussit si SPF **ou** DKIM réussit ET s'aligne. C'est ce qui laisse un
/// message survivre à une liste de diffusion — qui casse la signature mais
/// réémet depuis un domaine qu'elle contrôle — ou à une redirection, qui casse
/// SPF mais laisse la signature intacte.
#[derive(Debug, Clone, Copy)]
pub struct Authentication<'a> {
    /// Le domaine que SPF a autorisé, s'il a rendu `pass`.
    ///
    /// C'est le domaine de l'**enveloppe** — celui du `MAIL FROM:`, ou celui du
    /// `HELO` quand l'enveloppe est nulle (RFC 7208 §2.4).
    pub spf: Option<&'a [u8]>,
    /// Les domaines dont une signature DKIM a été **vérifiée**.
    ///
    /// Un message en porte souvent plusieurs ; il suffit qu'une s'aligne.
    pub dkim: &'a [&'a [u8]],
}

/// Ce qu'on conclut, et ce qu'on en fait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Assessment {
    /// Le verdict.
    pub verdict: Verdict,
    /// DKIM a-t-il réussi **et** s'est-il aligné ?
    ///
    /// # Pourquoi le détail, quand le verdict suffit à décider
    ///
    /// Il ne sert à rien pour décider — un seul mécanisme suffit — et il est
    /// indispensable pour RAPPORTER (§7.2, `policy_evaluated`). Un domaine qui
    /// lit ses rapports veut savoir LEQUEL de ses deux mécanismes tient : celui
    /// dont la signature casse chez un relais, ou celui dont l'enveloppe change
    /// à chaque redirection. Le verdict combiné ne le lui dirait jamais.
    pub dkim: Verdict,
    /// SPF a-t-il réussi **et** s'est-il aligné ?
    pub spf: Verdict,
    /// La politique demandée, si le verdict est un échec.
    pub policy: Policy,
    /// La part des messages à laquelle elle s'applique (`pct=`).
    ///
    /// **L'appelant tire au sort** : choisir demande de l'aléa, et cette crate
    /// n'en a pas (C1). Cent veut dire « toujours », zéro « jamais ».
    pub percent: u8,
}

/// Évalue un message contre la politique de son domaine d'auteur.
///
/// `from` est le domaine de l'en-tête `From:`, et `from_is_subdomain` dit s'il
/// est un sous-domaine de celui qui publie la politique — auquel cas `sp=`
/// s'applique.
#[must_use]
pub fn evaluate(
    record: &Record<'_>,
    from: &[u8],
    from_is_subdomain: bool,
    authentication: &Authentication<'_>,
    suffixes: &impl PublicSuffix,
) -> Assessment {
    // UNE SEULE RÉUSSITE SUFFIT, et on regarde DKIM d'abord : c'est le
    // mécanisme qui survit aux relais, et le plus souvent celui qui aligne.
    let par_dkim = authentication
        .dkim
        .iter()
        .any(|signe| aligned(record.dkim_alignment, signe, from, suffixes));
    let par_spf = authentication
        .spf
        .is_some_and(|enveloppe| aligned(record.spf_alignment, enveloppe, from, suffixes));

    let dit = |aligne: bool| {
        if aligne { Verdict::Pass } else { Verdict::Fail }
    };
    Assessment {
        verdict: dit(par_dkim || par_spf),
        dkim: dit(par_dkim),
        spf: dit(par_spf),
        policy: record.applicable(from_is_subdomain),
        percent: record.percent,
    }
}

#[cfg(test)]
mod tests;
