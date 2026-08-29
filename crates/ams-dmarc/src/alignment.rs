//! L'alignement (RFC 7489 §3.1).
//!
//! # Ce qu'aligner veut dire, et pourquoi c'est tout le sujet
//!
//! SPF autorise un domaine d'enveloppe ; DKIM en fait signer un autre. DMARC
//! demande que l'un des deux soit **celui du `From:`** — la seule ligne que
//! l'humain lira. Sans cette exigence, il suffirait d'émettre depuis un domaine
//! qu'on détient, de le signer, et d'écrire ce qu'on veut dans le `From:`.

use crate::Error;

/// Comment deux domaines doivent se ressembler pour s'aligner (§3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Alignment {
    /// Le même **domaine organisationnel** suffit : `mail.example.com`
    /// s'aligne avec `example.com`.
    ///
    /// **C'est le défaut de la RFC**, et il est plus large qu'on ne croit : il
    /// aligne tout ce qui partage un domaine organisationnel, sous-domaines
    /// compris, dans les deux sens.
    #[default]
    Relaxed,
    /// Le même domaine, exactement.
    Strict,
}

impl Alignment {
    /// Lit un `adkim=` ou un `aspf=`.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownAlignment`].
    pub fn parse(valeur: &[u8]) -> Result<Self, Error> {
        if valeur.eq_ignore_ascii_case(b"r") {
            return Ok(Self::Relaxed);
        }
        if valeur.eq_ignore_ascii_case(b"s") {
            return Ok(Self::Strict);
        }
        Err(Error::UnknownAlignment)
    }

    /// La lettre, telle qu'elle s'écrit.
    #[must_use]
    pub fn name(self) -> &'static [u8] {
        match self {
            Self::Relaxed => b"r",
            Self::Strict => b"s",
        }
    }
}

/// Qui sait trouver le **domaine organisationnel** d'un nom.
///
/// # Pourquoi c'est demandé, et non déduit
///
/// Il n'existe aucune règle syntaxique pour le trouver. `example.com` et
/// `example.co.uk` sont tous deux des domaines organisationnels ; `co.uk` n'en
/// est pas un, et `com` non plus. La seule réponse est **la liste des suffixes
/// publics** — une donnée qui change, qui vit hors du code, et qui pèse.
///
/// Une implémentation naïve — « les deux dernières étiquettes » — ferait aligner
/// `attaquant.co.uk` avec `victime.co.uk`, c'est-à-dire exactement l'usurpation
/// que DMARC existe pour empêcher. C'est pourquoi cette crate n'en fournit
/// aucune : celui qui répond doit savoir ce qu'il répond.
pub trait PublicSuffix {
    /// Le domaine organisationnel de `domain`, qui en est toujours un suffixe.
    ///
    /// Rend `domain` lui-même quand il n'y a rien à retirer.
    fn organizational_domain<'a>(&self, domain: &'a [u8]) -> &'a [u8];
}

impl<T: PublicSuffix + ?Sized> PublicSuffix for &T {
    fn organizational_domain<'a>(&self, domain: &'a [u8]) -> &'a [u8] {
        (**self).organizational_domain(domain)
    }
}

/// `authenticated` s'aligne-t-il avec `from` ?
///
/// La comparaison est **insensible à la casse** (RFC 4343) : un domaine écrit en
/// majuscules est le même domaine, et un alignement qui l'ignorerait échouerait
/// sur la seule fantaisie d'un signataire.
#[must_use]
pub fn aligned(
    alignment: Alignment,
    authenticated: &[u8],
    from: &[u8],
    suffixes: &impl PublicSuffix,
) -> bool {
    if authenticated.is_empty() || from.is_empty() {
        return false;
    }
    if authenticated.eq_ignore_ascii_case(from) {
        return true;
    }
    match alignment {
        // Strict : rien d'autre que l'égalité. Un sous-domaine ne s'aligne pas.
        Alignment::Strict => false,
        Alignment::Relaxed => suffixes
            .organizational_domain(authenticated)
            .eq_ignore_ascii_case(suffixes.organizational_domain(from)),
    }
}

#[cfg(test)]
mod tests;
