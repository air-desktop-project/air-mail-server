// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qui précède le message dans un `APPEND` (RFC 9051 §6.3.12).
//!
//! # `APPEND` N'EST PAS UNE LIGNE
//!
//! C'est la seule commande dont un argument est un MESSAGE. Toutes les autres
//! tiennent dans ce qu'une connexion peut retenir ; celle-ci porte ce que le
//! client veut, et la retenir en mémoire lui donnerait le droit de choisir
//! combien le serveur en consomme. Elle se lit donc en deux temps : cette
//! grammaire lit **ce qui précède le littéral**, et l'appelant écoule le reste
//! vers le magasin, comme le `DATA` de SMTP.
//!
//! # UN NOM DE BOÎTE DONNÉ COMME LITTÉRAL N'EST PAS SERVI
//!
//! `APPEND {5}\r\nINBOX …` est une commande légale, et elle ferait de la
//! première annonce de littéral un nom de boîte plutôt qu'un message : l'écouler
//! vers un fichier écrirait le nom de la boîte dans le courrier. On ne la lit
//! donc pas ici, et l'appelant la traitera par le chemin ordinaire — qui la
//! refusera en le disant.

use crate::error::Error;
use crate::flags::Flags;
use crate::frame::literal_announcement;

/// Ce qu'un `APPEND` annonce avant son message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Append<'a> {
    mailbox: &'a [u8],
    flags: Flags,
    date: Option<u64>,
    octets: u64,
    synchronizing: bool,
}

impl<'a> Append<'a> {
    /// La boîte visée, telle qu'écrite.
    #[must_use]
    pub fn mailbox(&self) -> &'a [u8] {
        self.mailbox
    }

    /// Les drapeaux demandés, s'il y en a.
    #[must_use]
    pub fn flags(&self) -> Flags {
        self.flags
    }

    /// La date d'arrivée demandée, en secondes depuis l'époque.
    #[must_use]
    pub fn date(&self) -> Option<u64> {
        self.date
    }

    /// La longueur du message annoncé.
    #[must_use]
    pub fn octets(&self) -> u64 {
        self.octets
    }

    /// Le littéral attend-il une demande de continuation ?
    #[must_use]
    pub fn synchronizing(&self) -> bool {
        self.synchronizing
    }

    /// Lit la ligne d'un `APPEND`, `CRLF` compris.
    ///
    /// Rend `Ok(None)` si ce n'est pas un `APPEND` que l'on sache écouler : ni
    /// une faute, ni un refus, mais « pas ce chemin-ci ». L'appelant le traitera
    /// par le chemin ordinaire.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedAppend`] si la forme n'est pas celle de §6.3.12,
    /// [`Error::UnknownFlag`] pour un drapeau qu'on ne sait pas écrire, ou les
    /// erreurs d'annonce de littéral.
    pub fn parse(ligne: &'a [u8], max_octets: u64) -> Result<Option<Self>, Error> {
        let ligne = ligne.strip_suffix(b"\r\n").unwrap_or(ligne);
        let Some((ouvrante, octets, synchronizing)) = literal_announcement(ligne, max_octets)?
        else {
            return Ok(None);
        };
        // Ce qui précède l'annonce : `<tag> APPEND <boîte> [(drapeaux)] [date]`.
        let avant = ligne.get(..ouvrante).unwrap_or_default().trim_ascii();

        // Le tag, puis le verbe. On ne recoupe pas la suite en mots : les
        // arguments portent des espaces entre parenthèses et guillemets, et les
        // recouper les perdrait.
        let apres_tag = apres_le_premier_mot(avant);
        let (verbe, apres_verbe) = un_mot(apres_tag);
        if !verbe.eq_ignore_ascii_case(b"APPEND") {
            return Ok(None);
        }
        let (mailbox, apres_boite) = un_mot(apres_verbe);
        if mailbox.is_empty() {
            // Rien entre le verbe et l'accolade : LE LITTÉRAL EST LE NOM DE LA
            // BOÎTE, pas le message. Ce n'est pas une faute — c'est une commande
            // légale qu'on ne sait pas écouler.
            return Ok(None);
        }

        let apres_boite = apres_boite.trim_ascii_start();
        let (flags, apres_drapeaux) = if apres_boite.first() == Some(&b'(') {
            let fin = apres_boite
                .iter()
                .position(|octet| *octet == b')')
                .ok_or(Error::MalformedAppend)?;
            let liste = apres_boite.get(1..fin).unwrap_or_default();
            let mut drapeaux = Flags::NONE;
            for mot in liste.split(|octet| *octet == b' ') {
                if mot.is_empty() {
                    continue;
                }
                drapeaux = drapeaux.with(Flags::parse_one(mot).ok_or(Error::UnknownFlag)?);
            }
            (
                drapeaux,
                apres_boite
                    .get(fin.saturating_add(1)..)
                    .unwrap_or_default()
                    .trim_ascii_start(),
            )
        } else {
            (Flags::NONE, apres_boite)
        };

        // La date-heure est entre guillemets (§9, `date-time`), et elle est
        // facultative.
        let date = if apres_drapeaux.is_empty() {
            None
        } else {
            Some(crate::date::parse_date_time(apres_drapeaux).ok_or(Error::MalformedAppend)?)
        };

        Ok(Some(Self {
            mailbox,
            flags,
            date,
            octets,
            synchronizing,
        }))
    }
}

/// Ce qui suit le premier mot.
fn apres_le_premier_mot(texte: &[u8]) -> &[u8] {
    let fin = texte
        .iter()
        .position(|octet| *octet == b' ')
        .unwrap_or(texte.len());
    texte.get(fin..).unwrap_or_default().trim_ascii_start()
}

/// Le premier mot — atome ou chaîne entre guillemets — et ce qui suit.
///
/// **Elle ne peut pas échouer** : un guillemet qui ne ferme pas rend tout ce qui
/// suit comme un seul mot, ce qui est ce qu'un lecteur en fait de mieux. Rendre
/// une option ferait porter à l'appelant un cas dont il ne saurait rien faire de
/// plus.
fn un_mot(texte: &[u8]) -> (&[u8], &[u8]) {
    let texte = texte.trim_ascii_start();
    let Some(corps) = texte.strip_prefix(b"\"") else {
        let fin = texte
            .iter()
            .position(|octet| *octet == b' ')
            .unwrap_or(texte.len());
        return (
            texte.get(..fin).unwrap_or_default(),
            texte.get(fin..).unwrap_or_default(),
        );
    };
    let mut morceaux = corps.splitn(2, |octet| *octet == b'"');
    let mot = morceaux.next().unwrap_or_default();
    let reste = morceaux.next().unwrap_or_default();
    (mot, reste)
}

#[cfg(test)]
mod tests;
