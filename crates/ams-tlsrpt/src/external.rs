//! La vérification d'une destination externe (§3 de RFC 8460).
//!
//! # SANS ELLE, TLSRPT SERAIT UN AMPLIFICATEUR
//!
//! N'importe qui publierait `rua=mailto:victime@banque.test` dans son propre
//! `_smtp._tls`, et **tous les émetteurs du monde** enverraient un rapport
//! quotidien à cette adresse. Le domaine rapporté n'a pas à pouvoir désigner une
//! victime.
//!
//! La règle est donc : quand la destination n'est pas du domaine rapporté, ce
//! tiers doit avoir DIT qu'il l'accepte, en publiant
//! `<rapporté>._report._smtp._tls.<destination>` avec `v=TLSRPTv1`.
//!
//! C'est le même mécanisme que §7.1 de RFC 7489 pour DMARC, et il n'est pas plus
//! facultatif ici que là-bas.

/// Ce qu'il faut au plus pour écrire un nom de vérification.
///
/// Deux noms de domaine, le préfixe, et les points.
pub const VERIFICATION_MAX: usize = 253 + 1 + 20 + 253 + 1;

/// Le suffixe sous lequel une destination dit qu'elle accepte.
const SUFFIXE: &str = "._report._smtp._tls.";

/// Cette destination demande-t-elle une vérification ?
///
/// Non quand elle est du domaine rapporté LUI-MÊME, ou d'un de ses
/// sous-domaines : un domaine a le droit de se rapporter à soi sans se donner
/// d'autorisation.
///
/// **LA COMPARAISON EST SUR LES ÉTIQUETTES, PAS SUR LES OCTETS.**
/// `mauvaisexample.com` se termine par `example.com` sans en être un
/// sous-domaine, et le lire ainsi laisserait n'importe qui se dispenser de la
/// vérification en achetant le bon nom.
#[must_use]
pub fn needs_verification(policy_domain: &str, destination: &str) -> bool {
    if destination.eq_ignore_ascii_case(policy_domain) {
        return false;
    }
    // Un sous-domaine : `<quelque chose>.<rapporté>`.
    let Some(prefixe) = destination
        .len()
        .checked_sub(policy_domain.len())
        .and_then(|rang| destination.get(..rang))
    else {
        return true;
    };
    let suffixe = destination.get(prefixe.len()..).unwrap_or_default();
    !(prefixe.ends_with('.') && suffixe.eq_ignore_ascii_case(policy_domain))
}

/// Le nom à interroger pour savoir si cette destination accepte.
///
/// `<rapporté>._report._smtp._tls.<destination>`
///
/// # Errors
///
/// [`Error::NotPrintable`](crate::Error::NotPrintable) si l'un des deux n'est
/// pas un nom de domaine, [`Error::BufferTooSmall`](crate::Error::BufferTooSmall)
/// si `sortie` fait moins de [`VERIFICATION_MAX`].
pub fn verification_name<'b>(
    policy_domain: &str,
    destination: &str,
    sortie: &'b mut [u8],
) -> Result<&'b str, crate::Error> {
    if !nom_recevable(policy_domain) || !nom_recevable(destination) {
        return Err(crate::Error::NotPrintable);
    }
    let mut ecrits = pousser(sortie, 0, policy_domain.as_bytes())?;
    ecrits = pousser(sortie, ecrits, SUFFIXE.as_bytes())?;
    ecrits = pousser(sortie, ecrits, destination.as_bytes())?;
    // Tout ce qu'on vient d'écrire est de l'ASCII : deux noms de domaine dont
    // chaque octet a été vérifié, et un suffixe littéral.
    let ecrit = sortie.get(..ecrits).unwrap_or_default();
    Ok(core::str::from_utf8(ecrit).unwrap_or_default())
}

/// Cette réponse `TXT` autorise-t-elle l'envoi ?
///
/// §3 : elle doit porter `v=TLSRPTv1`. **Rien d'autre n'est exigé**, et rien
/// d'autre n'est lu : un `rua=` dans une réponse de vérification ne redirige
/// pas le rapport ailleurs.
#[must_use]
pub fn authorizes(txt: &str) -> bool {
    txt.split(';')
        .map(str::trim)
        .next()
        .is_some_and(|premier| premier == "v=TLSRPTv1")
}

/// Ce nom peut-il s'écrire dans une question DNS ?
fn nom_recevable(nom: &str) -> bool {
    !nom.is_empty()
        && nom.len() <= 253
        && !nom.starts_with('.')
        && !nom.ends_with('.')
        && nom
            .bytes()
            .all(|octet| octet.is_ascii_alphanumeric() || octet == b'-' || octet == b'.')
}

/// Recopie `morceau`, et rend le nouveau compte.
fn pousser(sortie: &mut [u8], ecrits: usize, morceau: &[u8]) -> Result<usize, crate::Error> {
    let fin = ecrits.saturating_add(morceau.len());
    let place = sortie
        .get_mut(ecrits..fin)
        .ok_or(crate::Error::BufferTooSmall)?;
    place.copy_from_slice(morceau);
    Ok(fin)
}

#[cfg(test)]
mod tests;
