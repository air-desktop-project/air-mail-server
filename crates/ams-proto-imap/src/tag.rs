//! Le tag d'une commande (RFC 9051 §2.2.1 et §9).
//!
//! # LE TAG EST RECOPIÉ DANS LA RÉPONSE, ET C'EST TOUT LE SUJET
//!
//! IMAP entrelace les commandes : le client en envoie plusieurs sans attendre,
//! et c'est le tag qui dit à quelle commande une réponse répond. Le serveur
//! **recopie donc verbatim** un mot que le client a choisi (§7).
//!
//! Un `CRLF` dans ce mot écrirait une réponse entière de la main du client. Un
//! `*` en ferait une réponse non sollicitée. Un `+` en ferait une demande de
//! continuation, à laquelle le client répondrait par des octets que le serveur
//! lirait comme une commande. **Ces trois-là ne sont pas des cas particuliers :
//! ce sont les trois formes que prend une réponse IMAP.**
//!
//! La grammaire de la RFC les exclut déjà — `tag = 1*<any ASTRING-CHAR except
//! "+">` — et ce module l'applique à la lettre plutôt que de faire confiance.

use crate::{Error, Limits};

/// Le tag d'une commande, vérifié.
///
/// C'est un type, et non un `&[u8]`, pour une raison précise : l'encodeur de
/// réponses ne peut pas recevoir un tag invalide, donc n'a pas à s'en défendre.
/// La validation a lieu une fois, à la lecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag<'a>(&'a [u8]);

impl Tag<'static> {
    /// Un tag valide, à écrire quand la commande n'en a pas fourni.
    ///
    /// Le point est le plus court des `ATOM-CHAR`, et il ne peut désigner
    /// aucune commande en cours — ce qui est exactement ce qu'on veut dire.
    pub const PLACEHOLDER: Self = Self(b".");
}

impl<'a> Tag<'a> {
    /// Lit un tag.
    ///
    /// # Errors
    ///
    /// [`Error::MissingTag`] s'il est vide, [`Error::ReservedTag`] si c'est
    /// `+`, [`Error::TagTooLong`] au-delà de
    /// [`Limits::max_tag_octets`](crate::Limits::max_tag_octets),
    /// [`Error::MalformedTag`] si un octet n'appartient pas à la grammaire.
    pub fn parse(valeur: &'a [u8], limits: &Limits) -> Result<Self, Error> {
        if valeur.is_empty() {
            return Err(Error::MissingTag);
        }
        if valeur == b"+" {
            return Err(Error::ReservedTag);
        }
        if valeur.len() > limits.max_tag_octets {
            return Err(Error::TagTooLong {
                limit: limits.max_tag_octets,
            });
        }
        if !valeur.iter().all(|octet| est_de_tag(*octet)) {
            return Err(Error::MalformedTag);
        }
        Ok(Self(valeur))
    }

    /// Les octets du tag.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }
}

/// Cet octet a-t-il le droit de figurer dans un tag ?
///
/// `tag = 1*<any ASTRING-CHAR except "+">` (§9), où `ASTRING-CHAR` est
/// `ATOM-CHAR` ou `resp-specials`, c'est-à-dire tout caractère sauf :
///
/// - les octets de contrôle et l'espace — dont `CR` et `LF` ;
/// - `(`, `)`, `{` — la ponctuation des listes et des littéraux ;
/// - `%` et `*` — les jokers de `LIST` ;
/// - `"` et `\` — la ponctuation des chaînes ;
/// - `+` — que la définition du tag retire explicitement.
///
/// `]` reste admis : c'est un `resp-specials`, et `ASTRING-CHAR` l'inclut.
fn est_de_tag(octet: u8) -> bool {
    octet.is_ascii_graphic()
        && !matches!(
            octet,
            b'(' | b')' | b'{' | b'%' | b'*' | b'"' | b'\\' | b'+'
        )
}

#[cfg(test)]
mod tests;
