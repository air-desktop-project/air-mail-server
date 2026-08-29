//! La vérification des destinations externes (RFC 7489 §7.1).
//!
//! # SANS CE CONTRÔLE, DMARC EST UN AMPLIFICATEUR
//!
//! Un enregistrement DMARC est public, et personne ne vérifie qui le publie
//! pour son propre domaine. Rien n'empêche donc quiconque d'écrire, sous un
//! domaine qu'il détient :
//!
//! ```text
//! _dmarc.appat.example.  IN TXT  "v=DMARC1; p=none; rua=mailto:victime@banque.test"
//! ```
//!
//! puis d'émettre en masse du courrier prétendant venir de là. Chaque receveur
//! du monde qui applique DMARC composera alors un rapport et l'enverra — à la
//! victime. **Le coût est payé par des tiers de bonne foi, et le volume est
//! multiplié par le nombre de receveurs.** C'est une attaque par réflexion, et
//! elle se monte avec un seul enregistrement DNS.
//!
//! La parade tient en une phrase : *quand la destination n'est pas dans le
//! domaine qui l'a demandée, c'est à la DESTINATION de dire qu'elle accepte*.
//! Elle le dit en publiant, sous son propre domaine, un enregistrement nommé
//! d'après celui qui la désigne :
//!
//! ```text
//! appat.example._report._dmarc.banque.test.  IN TXT  "v=DMARC1"
//! ```
//!
//! Ce nom n'est pas publiable par l'attaquant : il est sous le domaine de la
//! victime. C'est tout ce qui sépare un rapport d'une nuisance.
//!
//! # Ce module ne résout pas, il nomme et il conclut
//!
//! C1 : l'entrée-sortie appartient à l'étage 3. [`verification_name`] écrit le
//! nom à interroger, [`authorizes`] lit ce qui en revient, et
//! [`needs_verification`] dit s'il fallait demander.

use crate::Error;
use crate::tag::Tags;

/// La longueur d'un nom de vérification : deux domaines et `._report._dmarc.`.
pub const VERIFICATION_NAME_MAX: usize = 255 + 16 + 255;

/// Faut-il demander son consentement à cette destination ?
///
/// # On compare les domaines, PAS leurs domaines organisationnels
///
/// Le domaine organisationnel demanderait la liste des suffixes publics, et
/// surtout il élargirait : `a.example.com` et `b.example.com` seraient tenus
/// pour un seul consentement. C'est peut-être ce que la RFC tolère ; ce n'est
/// pas ce qui protège le mieux. **Se tromper ici dans le sens strict coûte une
/// interrogation DNS ; se tromper dans l'autre autorise un envoi que personne
/// n'a accepté.** Le choix se fait tout seul (C13 : la sûreté avant la vitesse).
#[must_use]
pub fn needs_verification(policy_domain: &[u8], destination: &[u8]) -> bool {
    !policy_domain.eq_ignore_ascii_case(destination)
}

/// Écrit `<domaine-de-la-politique>._report._dmarc.<domaine-de-destination>`.
///
/// # Errors
///
/// [`Error::DomainTooLong`] si l'un des deux dépasse 255 octets,
/// [`Error::BufferTooSmall`] si `out` ne suffit pas.
pub fn verification_name<'b>(
    policy_domain: &[u8],
    destination: &[u8],
    out: &'b mut [u8],
) -> Result<&'b [u8], Error> {
    if policy_domain.len() > 255 || destination.len() > 255 {
        return Err(Error::DomainTooLong);
    }
    const MILIEU: &[u8] = b"._report._dmarc.";
    let fin = policy_domain
        .len()
        .saturating_add(MILIEU.len())
        .saturating_add(destination.len());
    let place = out.get_mut(..fin).ok_or(Error::BufferTooSmall)?;
    let (debut, reste) = place.split_at_mut(policy_domain.len());
    debut.copy_from_slice(policy_domain);
    let (milieu, queue) = reste.split_at_mut(MILIEU.len());
    milieu.copy_from_slice(MILIEU);
    queue.copy_from_slice(destination);
    out.get(..fin).ok_or(Error::BufferTooSmall)
}

/// Cet enregistrement autorise-t-il l'envoi ?
///
/// # Pourquoi `v=DMARC1` SEUL suffit, et pourquoi ce n'est pas [`crate::Record`]
///
/// §7.1 : l'enregistrement de consentement n'a pas à porter de politique — il ne
/// dit rien de ce qu'on fait du courrier, seulement « oui, envoyez-moi ces
/// rapports ». Le passer à [`crate::Record::parse`] le ferait donc écarter pour
/// `p=` manquant, et le consentement d'un domaine correctement configuré serait
/// lu comme un refus.
///
/// Ce qui reste vérifié est ce qui compte : la version, **en première position**,
/// pour qu'un `TXT` qui parle d'autre chose ne passe jamais pour un accord.
#[must_use]
pub fn authorizes(txt: &[u8]) -> bool {
    Tags::new(txt).next().is_some_and(|premiere| {
        premiere.is_ok_and(|tag| {
            tag.name.eq_ignore_ascii_case(b"v") && tag.value.eq_ignore_ascii_case(b"DMARC1")
        })
    })
}

#[cfg(test)]
mod tests;
