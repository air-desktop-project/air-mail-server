//! La LECTURE des réponses (RFC 5321 §4.2) — le côté client de la grammaire.
//!
//! # Pourquoi lire une réponse est un travail à part
//!
//! Le reste de cette crate sert un serveur : elle lit des commandes et écrit des
//! réponses. Émettre du courrier demande l'inverse — écrire des commandes et
//! **lire** des réponses — et ce n'est pas la même grammaire. Une réponse tient
//! sur plusieurs lignes, toutes porteuses du même code, et c'est le tiret qui
//! dit qu'il en vient une autre.
//!
//! ```text
//! 250-mail.example.com vous salue
//! 250-STARTTLS
//! 250 SIZE 10485760
//! ```
//!
//! # CES OCTETS VIENNENT D'UN SERVEUR QU'ON A CHOISI DE CROIRE, PAS D'UN AMI
//!
//! Le serveur auquel on remet du courrier est désigné par le DNS du domaine
//! destinataire. C'est-à-dire par le destinataire — qui peut être quiconque. Une
//! réponse est donc une entrée hostile comme une autre, et trois bornes la
//! tiennent :
//!
//! 1. **Chaque ligne est bornée** par [`Limits::max_reply_octets`]. Sans cela,
//!    un pair qui n'envoie jamais de `CRLF` ferait croître un tampon sans fin.
//! 2. **Le nombre de lignes est borné** ([`REPLY_LINES_MAX`]). Une réponse de
//!    trois cent mille lignes serait bien formée et coûterait tout autant.
//! 3. **Toutes les lignes portent le MÊME code.** §4.2.1 l'exige, et ce n'est
//!    pas une formalité : un bloc dont le code change en route se lit
//!    différemment selon l'implémentation — celui de la première ligne pour les
//!    uns, de la dernière pour les autres — et c'est exactement la matière d'une
//!    contrebande.

use crate::{Code, Error, Limits};

/// Le nombre de lignes qu'une réponse peut porter.
///
/// Une réponse à `EHLO` en porte une par extension annoncée ; les serveurs les
/// plus bavards en annoncent une quinzaine. Soixante-quatre laisse la place et
/// ferme la porte.
pub const REPLY_LINES_MAX: usize = 64;

/// La longueur d'une réponse complète, si elle est là tout entière.
///
/// Rend `Ok(None)` tant qu'il en manque — l'appelant lit et rappelle.
///
/// # Errors
///
/// [`Error::LineTooLong`] si une ligne dépasse [`Limits::max_reply_octets`] ou
/// si la réponse dépasse [`REPLY_LINES_MAX`] lignes ; [`Error::MalformedReply`]
/// si ce qui arrive n'est pas une réponse.
pub fn reply_len(octets: &[u8], limits: &Limits) -> Result<Option<usize>, Error> {
    Ok(verifier(octets, limits)?.map(|(longueur, _)| longueur))
}

/// Vérifie un bloc de bout en bout, et rend sa longueur et son code.
///
/// # Une seule traversée, et c'est délibéré
///
/// La longueur et le code se lisent du même parcours. Les séparer ferait
/// relire le bloc à [`Reply::parse`] — donc redemander à des découpages qui ont
/// déjà réussi s'ils réussissent — et chacune de ces questions serait une garde
/// qu'aucune entrée ne peut faire céder. Une garde inatteignable n'est pas une
/// garde : c'est une affirmation non vérifiée.
fn verifier(octets: &[u8], limits: &Limits) -> Result<Option<(usize, Code)>, Error> {
    let mut lu = 0_usize;
    let mut premier: Option<Code> = None;
    for _ in 0..REPLY_LINES_MAX {
        let reste = octets.get(lu..).unwrap_or_default();
        let Some(fin) = fin_de_ligne(reste, limits)? else {
            return Ok(None);
        };
        let ligne = reste.get(..fin).unwrap_or_default();
        let (code, suite) = decouper(ligne)?;
        // §4.2.1 : le code est le même sur toutes les lignes. Un bloc qui en
        // change en route se lit différemment selon l'implémentation — la
        // première ligne pour les uns, la dernière pour les autres — et c'est
        // la matière d'une contrebande.
        if *premier.get_or_insert(code) != code {
            return Err(Error::MalformedReply);
        }
        lu = lu.saturating_add(fin).saturating_add(2);
        if suite != Suite::Encore {
            return Ok(premier.map(|code| (lu, code)));
        }
    }
    Err(Error::TooManyReplyLines {
        limit: REPLY_LINES_MAX,
    })
}

/// Où se termine la ligne courante, `CRLF` non compris.
fn fin_de_ligne(reste: &[u8], limits: &Limits) -> Result<Option<usize>, Error> {
    match reste.windows(2).position(|paire| paire == b"\r\n") {
        Some(rang) if rang > limits.max_reply_octets => Err(Error::LineTooLong {
            limit: limits.max_reply_octets,
        }),
        Some(rang) => Ok(Some(rang)),
        // RIEN NE DIT QUE LA SUITE VIENDRA. Tant qu'aucun `CRLF` n'est arrivé,
        // on borne ce qu'on a déjà : sans cela, un pair muet ferait croître le
        // tampon de son correspondant jusqu'à ce que celui-ci cède.
        None if reste.len() > limits.max_reply_octets => Err(Error::LineTooLong {
            limit: limits.max_reply_octets,
        }),
        None => Ok(None),
    }
}

/// Ce qu'une ligne dit de celles qui la suivent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Suite {
    /// Un tiret : il en vient une autre.
    Encore,
    /// Une espace, ou rien : c'est la dernière.
    Derniere,
}

/// Lit le code d'une ligne et dit si une autre suit.
fn decouper(ligne: &[u8]) -> Result<(Code, Suite), Error> {
    // AUCUN OCTET DE CONTRÔLE DANS LE TEXTE, et surtout pas un `CR` ou un `LF`
    // isolé. Trouvé par le fuzzer : `250 a\nb\r\n` passait, et ce qui suivait le
    // saut de ligne était du texte pour nous et une ligne pour tout ce qui lira
    // ce texte ensuite — un journal, un rapport, un message de non-remise. C'est
    // la même faute que la contrebande SMTP, prise par l'autre bout.
    //
    // Les octets HAUTS, eux, passent : la RFC 5321 §4.2 ne les prévoit pas, mais
    // des serveurs en émettent dans leur bannière, et refuser une remise pour un
    // accent coûterait du courrier sans rien protéger. On ne les interprète
    // jamais.
    if ligne
        .iter()
        .any(|octet| (*octet < 0x20 && *octet != b'\t') || *octet == 0x7F)
    {
        return Err(Error::ReplyTextNotPrintable);
    }
    let chiffres = ligne.get(..3).ok_or(Error::MalformedReply)?;
    if !chiffres.iter().all(u8::is_ascii_digit) {
        return Err(Error::MalformedReply);
    }
    let valeur = chiffres.iter().fold(0_u16, |total, octet| {
        total
            .wrapping_mul(10)
            .wrapping_add(u16::from(octet.wrapping_sub(b'0')))
    });
    // UN CODE `1yz` EST REFUSÉ. La RFC 5321 §4.2.1 le définit et ajoute que SMTP
    // n'en émet aucun ; en accepter un laisserait attendre une seconde réponse
    // qui ne viendrait jamais.
    let code = Code::new(valeur).ok_or(Error::MalformedReply)?;
    match ligne.get(3) {
        Some(b'-') => Ok((code, Suite::Encore)),
        Some(b' ') => Ok((code, Suite::Derniere)),
        // Trois chiffres et rien d'autre : la RFC l'admet pour la dernière
        // ligne, et bien des serveurs l'écrivent.
        None => Ok((code, Suite::Derniere)),
        Some(_) => Err(Error::MalformedReply),
    }
}

/// Une réponse complète, lue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reply<'a> {
    octets: &'a [u8],
    code: Code,
}

impl<'a> Reply<'a> {
    /// Lit une réponse **complète**, telle que [`reply_len`] l'a délimitée.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedReply`] si ce n'est pas une réponse, si son bloc n'est
    /// pas terminé, ou si **deux lignes ne portent pas le même code** ;
    /// [`Error::LineTooLong`] aux mêmes bornes que [`reply_len`].
    pub fn parse(octets: &'a [u8], limits: &Limits) -> Result<Self, Error> {
        match verifier(octets, limits)? {
            Some((longueur, code)) if longueur == octets.len() => Ok(Self { octets, code }),
            // Un bloc incomplet, ou suivi d'un autre, n'est pas UNE réponse.
            _ => Err(Error::MalformedReply),
        }
    }

    /// Le code de la réponse.
    #[must_use]
    pub fn code(&self) -> Code {
        self.code
    }

    /// Le texte de chaque ligne, code et séparateur retirés.
    #[must_use]
    pub fn lines(&self) -> ReplyLines<'a> {
        ReplyLines {
            lignes: Lignes::new(self.octets),
        }
    }

    /// Ce serveur annonce-t-il cette extension (RFC 5321 §4.1.1.1) ?
    ///
    /// La comparaison ignore la casse : `STARTTLS` et `StartTls` sont le même
    /// mot-clé (§4.1.1.1), et un serveur qui l'écrit autrement l'annonce quand
    /// même.
    #[must_use]
    pub fn offers(&self, keyword: &[u8]) -> bool {
        self.lines()
            .any(|ligne| premier_mot(ligne).eq_ignore_ascii_case(keyword))
    }

    /// Ce qui suit un mot-clé annoncé — `SIZE 10485760` rend `10485760`.
    #[must_use]
    pub fn parameter(&self, keyword: &[u8]) -> Option<&'a [u8]> {
        self.lines().find_map(|ligne| {
            let mot = premier_mot(ligne);
            if !mot.eq_ignore_ascii_case(keyword) {
                return None;
            }
            Some(ligne.get(mot.len()..).unwrap_or_default().trim_ascii())
        })
    }
}

/// Le premier mot d'une ligne, blancs de tête retirés.
fn premier_mot(ligne: &[u8]) -> &[u8] {
    let ligne = ligne.trim_ascii_start();
    let fin = ligne
        .iter()
        .position(u8::is_ascii_whitespace)
        .unwrap_or(ligne.len());
    ligne.get(..fin).unwrap_or_default()
}

/// Les lignes d'un bloc, `CRLF` retirés.
#[derive(Debug, Clone)]
struct Lignes<'a> {
    reste: &'a [u8],
}

impl<'a> Lignes<'a> {
    fn new(octets: &'a [u8]) -> Self {
        Self { reste: octets }
    }
}

impl<'a> Iterator for Lignes<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.reste.is_empty() {
            return None;
        }
        let fin = self
            .reste
            .windows(2)
            .position(|paire| paire == b"\r\n")
            .unwrap_or(self.reste.len());
        // `fin` vient de `position` ou vaut la longueur : le découpage existe,
        // et il n'y a pas de garde à écrire pour cela.
        let ligne = self.reste.get(..fin).unwrap_or_default();
        self.reste = self.reste.get(fin.saturating_add(2)..).unwrap_or_default();
        Some(ligne)
    }
}

/// Le texte des lignes d'une réponse, code et séparateur retirés.
#[derive(Debug, Clone)]
pub struct ReplyLines<'a> {
    lignes: Lignes<'a>,
}

impl<'a> Iterator for ReplyLines<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        // Les quatre premiers octets sont le code et son séparateur ; une ligne
        // de trois octets n'a pas de texte, et rend le vide.
        self.lignes
            .next()
            .map(|ligne| ligne.get(4..).unwrap_or_default())
    }
}

#[cfg(test)]
mod tests;
