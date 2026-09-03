//! Ce qu'un serveur de SOUMISSION doit compléter (RFC 6409 §8).
//!
//! # CE N'EST PAS LE TRAVAIL D'UN RELAIS
//!
//! §6.4 de RFC 5321 déconseille à un relais de toucher aux en-têtes d'un message
//! qui n'est pas le sien. Ces champs-ci ne s'écrivent donc que sur une
//! SOUMISSION — un message qu'un de nos comptes nous confie —, et jamais sur du
//! courrier de tiers qu'on fait suivre.
//!
//! # POURQUOI `Date:` COMPTE PLUS QU'IL N'EN A L'AIR
//!
//! §3.6 de RFC 5322 ne rend obligatoires que DEUX champs : `From:` et `Date:`.
//! Un message qui sort sans est malformé, et les filtres en aval le pénalisent
//! lourdement — certains le refusent d'emblée. Le déposant, lui, ne saura jamais
//! pourquoi son message n'arrive pas.
//!
//! # ET `Message-ID:` EST CE QUI RATTACHE LE RESTE
//!
//! Sans lui, le fil de discussion se casse chez le destinataire, la détection de
//! doublons ne fonctionne plus, et un rapport de non-remise ne se rattache à
//! rien : c'est `Message-ID` qu'un rapport recopie pour dire DE QUEL message il
//! parle.

use crate::Error;
use crate::date::{DATE_MAX, write_date};
use crate::message::Message;

/// Ce qu'une valeur d'unicité peut peser dans un `Message-ID:`.
///
/// Deux entiers de soixante-quatre bits en hexadécimal, et leur séparateur.
pub const UNIQUE_MAX: usize = 33;

/// Ce qu'un nom de domaine peut peser (RFC 1035 §2.3.4).
const DOMAINE_MAX: usize = 255;

/// La place que les champs de soumission peuvent demander.
///
/// `Date: ` et sa date, puis `Message-ID: <` avec son unicité, son domaine et
/// ses chevrons. La somme est EXACTE : une borne approximative laisserait une
/// branche que rien n'atteint, et une garde inatteignable n'est pas une garde.
pub const SUBMISSION_FIELDS_MAX: usize =
    6 + DATE_MAX + 2 + 13 + UNIQUE_MAX + 1 + DOMAINE_MAX + 1 + 2;

/// Ce qu'un message de soumission ne porte pas encore (RFC 6409 §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Missing {
    /// `Date:` manque (§8.1). **C'est celui des deux qui rend le message
    /// malformé** au sens de §3.6 de RFC 5322.
    pub date: bool,
    /// `Message-ID:` manque (§8.3).
    pub message_id: bool,
}

impl Missing {
    /// N'y a-t-il rien à ajouter ?
    #[must_use]
    pub const fn rien(self) -> bool {
        !self.date && !self.message_id
    }
}

/// Dit ce qui manque à ce message pour être soumis.
///
/// **ON NE REGARDE QUE LA PRÉSENCE, JAMAIS LA VALEUR.** Une date que le déposant
/// a écrite de travers reste la sienne : la corriger serait décider à sa place,
/// et §8.1 ne demande que de combler une absence.
#[must_use]
pub fn missing_submission_fields(message: &Message<'_>) -> Missing {
    let mut manque = Missing {
        date: true,
        message_id: true,
    };
    for champ in message.fields() {
        if champ.name_is(b"date") {
            manque.date = false;
        }
        if champ.name_is(b"message-id") {
            manque.message_id = false;
        }
    }
    manque
}

/// Écrit les champs manquants, à poser À LA FIN du bloc d'en-tête.
///
/// # POURQUOI À LA FIN, ET NON EN TÊTE
///
/// `Date:` et `Message-ID:` appartiennent à l'AUTEUR, pas au saut. Les poser
/// au-dessus de notre `Received:` mettrait deux champs qui ne sont pas de la
/// trace au-dessus de la trace, et §4.4 de RFC 5321 veut celle-ci « at the
/// beginning of the message content ».
///
/// # Errors
///
/// [`Error::NotPrintable`] si l'unicité ou le domaine porte autre chose que de
/// l'ASCII visible, ou des chevrons, ou un `@` — ces valeurs ressortent dans un
/// en-tête que nous composons, et cette crate ne croit pas son appelant ;
/// [`Error::BufferTooSmall`] si `sortie` ne suffit pas.
pub fn write_submission_fields<'b>(
    sortie: &'b mut [u8],
    manquants: Missing,
    date: u64,
    unique: &[u8],
    domaine: &[u8],
) -> Result<&'b [u8], Error> {
    let mut ecrits = 0_usize;
    if manquants.date {
        ecrits = pousser(sortie, ecrits, b"Date: ")?;
        let mut place = [0_u8; DATE_MAX];
        // **CETTE ÉCRITURE NE PEUT PAS ÉCHOUER**, et un `?` y serait une garde
        // que rien n'atteindrait — la même que dans `write_received`, et pour la
        // même raison : `write_date` ne refuse que par manque de place, et
        // `DATE_MAX` est SA borne.
        let ecrite =
            write_date(date, &mut place).expect("DATE_MAX majore toute date qu'un u64 désigne");
        ecrits = pousser(sortie, ecrits, ecrite)?;
        ecrits = pousser(sortie, ecrits, b"\r\n")?;
    }
    if manquants.message_id {
        if !partie_recevable(unique, UNIQUE_MAX) || !partie_recevable(domaine, DOMAINE_MAX) {
            return Err(Error::NotPrintable);
        }
        ecrits = pousser(sortie, ecrits, b"Message-ID: <")?;
        ecrits = pousser(sortie, ecrits, unique)?;
        ecrits = pousser(sortie, ecrits, b"@")?;
        ecrits = pousser(sortie, ecrits, domaine)?;
        ecrits = pousser(sortie, ecrits, b">\r\n")?;
    }
    sortie.get(..ecrits).ok_or(Error::BufferTooSmall)
}

/// Cette valeur peut-elle s'écrire dans un `Message-ID:` sans rien y ajouter ?
///
/// De l'ASCII visible, ni vide, ni trop longue, et sans les trois caractères qui
/// structurent le champ : un `@` de trop en ferait deux identifiants, et un
/// chevron le fermerait avant la fin.
fn partie_recevable(valeur: &[u8], borne: usize) -> bool {
    !valeur.is_empty()
        && valeur.len() <= borne
        && valeur
            .iter()
            .all(|octet| octet.is_ascii_graphic() && !matches!(*octet, b'<' | b'>' | b'@'))
}

/// Écrit `morceau` à la suite, et rend le total.
fn pousser(sortie: &mut [u8], ecrits: usize, morceau: &[u8]) -> Result<usize, Error> {
    let fin = ecrits.saturating_add(morceau.len());
    let place = sortie.get_mut(ecrits..fin).ok_or(Error::BufferTooSmall)?;
    place.copy_from_slice(morceau);
    Ok(fin)
}

#[cfg(test)]
mod tests;
