//! Le DÉCOUPAGE d'une commande (RFC 9051 §2.2.1 et §4.3).
//!
//! # IMAP N'EST PAS UN PROTOCOLE DE LIGNES, ET C'EST CE QUI LE REND DÉLICAT
//!
//! SMTP et POP3 se lisent ligne par ligne : un `CRLF`, une commande. IMAP non.
//! Une commande peut porter un **littéral** — `{42}` suivi d'un `CRLF`, puis
//! quarante-deux octets bruts qui peuvent contenir tout ce qu'on veut, `CRLF`
//! compris — et la commande continue après. Chercher le premier `CRLF` pour
//! découper une commande IMAP, c'est offrir à un client de faire lire n'importe
//! quoi comme une commande.
//!
//! ```text
//! a001 LOGIN {5}
//! toto\r\n MOT DE PASSE
//! ```
//!
//! Ce module fait donc le seul découpage juste : il suit la syntaxe, littéraux
//! compris, et ne rend une commande que lorsqu'elle est entière.
//!
//! # DEUX FORMES DE LITTÉRAL, ET UNE SEULE EST SÛRE PAR CONSTRUCTION
//!
//! `{42}` est **synchronisant** : le client attend que le serveur réponde `+`
//! avant d'envoyer les octets. Le serveur peut donc refuser avant de rien lire.
//!
//! `{42+}` (RFC 7888) ne l'est pas : les octets suivent immédiatement, et le
//! serveur n'a aucun moyen de dire non. C'est pourquoi la RFC 9051 §6.3.11 les
//! borne à quatre kibioctets, et pourquoi cette borne-là n'est pas la nôtre à
//! choisir.
//!
//! # Le contrat avec l'appelant
//!
//! [`CommandReader::poll`] examine un tampon qui **ne fait que croître** : il
//! retient où il en était, et ne relit pas ce qu'il a déjà vu. Après un
//! [`Need::Complete`], l'appelant consomme les octets annoncés et appelle
//! [`CommandReader::reset`]. Lui donner un tampon qui a rétréci entre deux
//! appels ferait relire autre chose que ce qu'il croit.

use crate::{Error, Limits};

/// Ce qu'il manque pour tenir une commande entière.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    /// Il en manque : lire davantage, puis rappeler.
    More,
    /// Un littéral **synchronisant** est annoncé.
    ///
    /// Il faut écrire une demande de continuation (`+ …`) : le client attend, et
    /// n'enverra rien avant.
    ///
    /// **C'est un ÉVÉNEMENT, pas un état.** Il se dit une fois par littéral, et
    /// le lecteur qui l'a déjà dit ne le redira pas : l'appel suivant compte les
    /// octets. Un appelant qui le traiterait comme un état attendrait une
    /// seconde continuation qui ne viendra jamais.
    Continuation,
    /// La commande occupe les `n` premiers octets du tampon, `CRLF` compris.
    Complete(usize),
}

/// De quoi suivre une commande jusqu'à son terme.
#[derive(Debug, Clone, Copy, Default)]
pub struct CommandReader {
    /// Jusqu'où le tampon a déjà été examiné.
    examine: usize,
    /// Octets de littéral encore attendus.
    attendus: u64,
    /// Combien de littéraux cette commande a déjà annoncés.
    litteraux: usize,
}

impl CommandReader {
    /// Ouvre la lecture d'une commande.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            examine: 0,
            attendus: 0,
            litteraux: 0,
        }
    }

    /// Repart pour la commande suivante.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Examine le tampon, sans rien consommer.
    ///
    /// # Errors
    ///
    /// Voir [`Error`] : ligne trop longue, fin de ligne isolée, littéral
    /// démesuré ou mal formé, littéraux trop nombreux.
    pub fn poll(&mut self, buffer: &[u8], limits: &Limits) -> Result<Need, Error> {
        loop {
            // ── Un littéral est en cours : on compte les octets ──────────────
            if self.attendus > 0 {
                let disponibles = buffer.len().saturating_sub(self.examine);
                let disponibles = u64::try_from(disponibles).unwrap_or(u64::MAX);
                if disponibles < self.attendus {
                    return Ok(Need::More);
                }
                let consommes = usize::try_from(self.attendus).unwrap_or(usize::MAX);
                self.examine = self.examine.saturating_add(consommes);
                self.attendus = 0;
                continue;
            }

            // ── Sinon, on cherche la fin de la ligne courante ────────────────
            let reste = buffer.get(self.examine..).unwrap_or_default();
            let Some(rang) = reste.windows(2).position(|paire| paire == b"\r\n") else {
                // RIEN NE DIT QUE LA SUITE VIENDRA. On borne ce qu'on a déjà :
                // sans cela, un client muet ferait croître le tampon du serveur
                // jusqu'à ce que celui-ci cède.
                if reste.len() > limits.max_line_octets {
                    return Err(Error::LineTooLong {
                        limit: limits.max_line_octets,
                    });
                }
                return Ok(Need::More);
            };
            if rang > limits.max_line_octets {
                return Err(Error::LineTooLong {
                    limit: limits.max_line_octets,
                });
            }
            let ligne = reste.get(..rang).unwrap_or_default();
            if ligne.iter().any(|octet| matches!(*octet, b'\r' | b'\n')) {
                return Err(Error::MalformedLineEnding);
            }

            match annonce_de_litteral(ligne, limits)? {
                None => {
                    return Ok(Need::Complete(
                        self.examine.saturating_add(rang).saturating_add(2),
                    ));
                }
                Some((longueur, synchronisant)) => {
                    self.litteraux = self.litteraux.saturating_add(1);
                    if self.litteraux > limits.max_literals {
                        return Err(Error::TooManyLiterals {
                            limit: limits.max_literals,
                        });
                    }
                    self.examine = self.examine.saturating_add(rang).saturating_add(2);
                    self.attendus = longueur;
                    if synchronisant {
                        // On ne le dit QU'UNE FOIS : `examine` a dépassé
                        // l'annonce, et le prochain appel comptera les octets.
                        return Ok(Need::Continuation);
                    }
                }
            }
        }
    }
}

/// Cette ligne se termine-t-elle par l'annonce d'un littéral ?
///
/// Rend la longueur annoncée et si le littéral est synchronisant.
///
/// # L'accolade se cherche EN DEHORS DES GUILLEMETS
///
/// `a001 LOGIN "toto{5}" motdepasse` ne porte aucun littéral : l'accolade y est
/// dans une chaîne. Chercher la dernière accolade sans suivre les guillemets
/// ferait lire cinq octets de la commande suivante comme un argument — et
/// laisserait le client choisir où l'on découpe.
fn annonce_de_litteral(ligne: &[u8], limits: &Limits) -> Result<Option<(u64, bool)>, Error> {
    if ligne.last() != Some(&b'}') {
        return Ok(None);
    }
    let Some(ouvrante) = derniere_accolade(ligne) else {
        return Ok(None);
    };
    let corps = ligne
        .get(ouvrante.saturating_add(1)..ligne.len().saturating_sub(1))
        .unwrap_or_default();
    let (chiffres, synchronisant) = match corps.split_last() {
        Some((b'+', avant)) => (avant, false),
        _ => (corps, true),
    };
    if chiffres.is_empty() || !chiffres.iter().all(u8::is_ascii_digit) {
        return Err(Error::MalformedLiteral);
    }
    let mut longueur = 0_u64;
    for octet in chiffres {
        // UNE LONGUEUR QUI DÉBORDE N'EST PAS UNE PETITE LONGUEUR. Repartie de
        // zéro, elle ferait lire la commande suivante comme un argument.
        longueur = longueur
            .checked_mul(10)
            .and_then(|dizaines| dizaines.checked_add(u64::from(octet.wrapping_sub(b'0'))))
            .ok_or(Error::MalformedLiteral)?;
    }
    if longueur > limits.max_literal_octets {
        return Err(Error::LiteralTooLong {
            limit: limits.max_literal_octets,
        });
    }
    if !synchronisant && longueur > Limits::NON_SYNCHRONIZING_MAX {
        return Err(Error::NonSynchronizingTooLong {
            limit: Limits::NON_SYNCHRONIZING_MAX,
        });
    }
    Ok(Some((longueur, synchronisant)))
}

/// La position de la dernière accolade ouvrante hors guillemets, s'il y en a une.
fn derniere_accolade(ligne: &[u8]) -> Option<usize> {
    let mut dans_une_chaine = false;
    let mut echappe = false;
    let mut trouvee = None;
    for (rang, octet) in ligne.iter().enumerate() {
        if echappe {
            echappe = false;
            continue;
        }
        match *octet {
            b'\\' if dans_une_chaine => echappe = true,
            b'"' => dans_une_chaine = !dans_une_chaine,
            b'{' if !dans_une_chaine => trouvee = Some(rang),
            _ => {}
        }
    }
    trouvee
}

#[cfg(test)]
mod tests;
