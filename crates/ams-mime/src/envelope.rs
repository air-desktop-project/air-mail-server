// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! L'`ENVELOPE` d'un message, telle qu'IMAP la rend (RFC 9051 §7.5.2).
//!
//! ```text
//! (date subject from sender reply-to to cc bcc in-reply-to message-id)
//! ```
//!
//! # ON NE DÉCODE RIEN, ET C'EST LA RÈGLE
//!
//! §7.5.2 : les champs de l'enveloppe portent le TEXTE DE L'EN-TÊTE, tel quel.
//! Un `Subject:` en mots encodés (`=?utf-8?B?…?=`) se recopie encodé ; c'est au
//! client de le lire. Décoder ici rendrait au client autre chose que ce que le
//! message porte, et lui ôterait le moyen de le vérifier.
//!
//! # UN NOM D'AFFICHAGE N'EST PAS UNE ADRESSE
//!
//! `"Jean Dupont" <jean@example.test>` donne `("Jean Dupont" NIL "jean"
//! "example.test")`. Les guillemets d'une chaîne citée sont retirés et ses
//! échappements défaits — c'est ce que le nom VAUT —, puis le tout est recité
//! aux règles d'IMAP, qui ne sont pas celles de la RFC 5322.
//!
//! # UNE CHAÎNE NE PORTE PAS DE FIN DE LIGNE
//!
//! Le pliage de la RFC 5322 disparaît, partout, y compris **à l'intérieur d'un
//! nom cité** — c'est le cas qu'on oublie. Une chaîne IMAP ne peut porter ni
//! `CR` ni `LF` : le client lirait la fin de la réponse au milieu d'un nom, puis
//! la suite du dialogue comme du protocole. Ce n'est pas une laideur
//! d'affichage, c'est une désynchronisation.
//!
//! Le pli s'**efface** au lieu de devenir un blanc : le blanc qui suit un `CRLF`
//! appartient déjà à la chaîne. `"Jean<CRLF> Dupont"` vaut `"Jean Dupont"`, et
//! un nom qui n'est qu'un pli ne vaut rien — `NIL`, et non `""`.
//!
//! # CE QUI EST DÉLIBÉRÉMENT ABSENT
//!
//! - **Les routes source** (`adl`) sont toujours `NIL` : la RFC 5322 les a
//!   retirées, et les rendre serait rendre une syntaxe que plus personne
//!   n'écrit.
//! - **Les commentaires** se traversent et ne se recopient pas : ils ne font
//!   partie ni du nom ni de l'adresse.

use crate::error::Error;
use crate::limits::Limits;
use crate::message::Message;

/// Combien d'adresses au plus par champ.
///
/// **Aucune RFC ne le borne.** C'est le nombre de structures qu'un client
/// recevra pour un seul champ, et sans borne un message unique en ferait écrire
/// autant que sa taille le permet.
pub const ENVELOPE_ADDRESSES_MAX: usize = 256;

/// Les six champs d'adresse de l'enveloppe, dans l'ordre de §7.5.2.
const CHAMPS_D_ADRESSE: [&[u8]; 6] = [b"from", b"sender", b"reply-to", b"to", b"cc", b"bcc"];

/// Écrit l'`ENVELOPE` d'un message dans `out`, et rend ce qu'elle occupe.
///
/// `entete` est le bloc d'en-tête, tel que [`Message::header_block`] le rend.
///
/// # Errors
///
/// [`Error::BufferTooSmall`] si `out` ne suffit pas, ou les erreurs de lecture
/// de l'en-tête.
pub fn write_envelope(entete: &[u8], out: &mut [u8], limits: &Limits) -> Result<usize, Error> {
    let message = Message::parse(entete, limits)?;
    let mut plume = Plume { out, ecrits: 0 };
    plume.pousser(b"(")?;

    // `Date:` et `Subject:` : le texte, tel quel.
    for nom in [&b"date"[..], b"subject"] {
        ecrire_chaine(&mut plume, valeur_de(&message, nom))?;
        plume.pousser(b" ")?;
    }

    // §7.5.2 : SI `Sender` OU `Reply-To` MANQUE, C'EST `From` QUI VAUT. Rendre
    // `NIL` ferait croire au client qu'il n'y a personne à qui répondre.
    let de = valeur_de(&message, b"from");
    for (rang, nom) in CHAMPS_D_ADRESSE.iter().enumerate() {
        let valeur = match valeur_de(&message, nom) {
            Some(valeur) if !valeur.trim_ascii().is_empty() => Some(valeur),
            // `sender` est en position 1, `reply-to` en position 2.
            _ if rang == 1 || rang == 2 => de,
            _ => None,
        };
        ecrire_liste(&mut plume, valeur)?;
        plume.pousser(b" ")?;
    }

    // `In-Reply-To:` et `Message-Id:` : le texte, tel quel.
    ecrire_chaine(&mut plume, valeur_de(&message, b"in-reply-to"))?;
    plume.pousser(b" ")?;
    ecrire_chaine(&mut plume, valeur_de(&message, b"message-id"))?;
    plume.pousser(b")")?;
    Ok(plume.ecrits)
}

/// La valeur brute du PREMIER champ portant ce nom.
///
/// **Le premier, et pas le dernier** : un message qui porte deux `From:` est
/// mal formé, et prendre le dernier laisserait qui l'a fabriqué choisir lequel
/// on montre.
fn valeur_de<'a>(message: &Message<'a>, nom: &[u8]) -> Option<&'a [u8]> {
    message
        .fields()
        .find(|champ| champ.name_is(nom))
        .map(|champ| champ.raw_value())
}

/// De quoi écrire dans un tampon fixe, sans jamais déborder.
struct Plume<'a> {
    out: &'a mut [u8],
    ecrits: usize,
}

impl Plume<'_> {
    fn pousser(&mut self, morceau: &[u8]) -> Result<(), Error> {
        let fin = self.ecrits.saturating_add(morceau.len());
        let place = self
            .out
            .get_mut(self.ecrits..fin)
            .ok_or(Error::BufferTooSmall)?;
        place.copy_from_slice(morceau);
        self.ecrits = fin;
        Ok(())
    }

    /// Écrit un octet, échappé comme une chaîne IMAP l'exige.
    fn octet_de_chaine(&mut self, octet: u8) -> Result<(), Error> {
        if matches!(octet, b'"' | b'\\') {
            self.pousser(b"\\")?;
        }
        self.pousser(&[octet])
    }
}

/// Écrit une chaîne IMAP, ou `NIL` si la valeur est absente ou vide.
///
/// Le pliage de la RFC 5322 disparaît : un `CRLF` suivi d'un blanc n'est pas du
/// texte, c'est une commodité d'écriture. Le rendre au client lui ferait lire
/// une fin de ligne au milieu d'un sujet.
fn ecrire_chaine(plume: &mut Plume<'_>, valeur: Option<&[u8]>) -> Result<(), Error> {
    let Some(valeur) = valeur.map(<[u8]>::trim_ascii).filter(|v| !v.is_empty()) else {
        return plume.pousser(b"NIL");
    };
    plume.pousser(b"\"")?;
    let mut blanc = false;
    for octet in valeur {
        if matches!(*octet, b' ' | b'\t' | b'\r' | b'\n') {
            blanc = true;
            continue;
        }
        if blanc {
            plume.pousser(b" ")?;
            blanc = false;
        }
        plume.octet_de_chaine(*octet)?;
    }
    plume.pousser(b"\"")
}

/// Écrit une liste d'adresses, ou `NIL`.
fn ecrire_liste(plume: &mut Plume<'_>, valeur: Option<&[u8]>) -> Result<(), Error> {
    let Some(valeur) = valeur else {
        return plume.pousser(b"NIL");
    };
    let mut ecrites = 0_usize;
    let mut debut = 0_usize;
    let mut ouverte = false;
    let mut i = 0_usize;

    // ON PARCOURT UNE FOIS, ET L'ON DÉLIMITE EN CHEMIN. Découper d'abord sur les
    // virgules ferait couper un groupe en deux, et une virgule entre guillemets
    // n'en est pas une.
    while i < valeur.len() {
        let octet = valeur.get(i).copied().unwrap_or(0);
        match octet {
            b'"' => i = fin_de_chaine(valeur, i),
            b'(' => i = fin_de_commentaire(valeur, i),
            b'<' => i = fin_d_angle(valeur, i),
            b':' => {
                // Un groupe s'ouvre : son nom est ce qui précède.
                debuter(plume, &mut ouverte)?;
                ecrire_groupe(plume, valeur.get(debut..i).unwrap_or_default())?;
                ecrites = ecrites.saturating_add(1);
                debut = i.saturating_add(1);
                i = i.saturating_add(1);
            }
            b',' | b';' => {
                let element = valeur.get(debut..i).unwrap_or_default();
                if !element.trim_ascii().is_empty() && ecrites < ENVELOPE_ADDRESSES_MAX {
                    debuter(plume, &mut ouverte)?;
                    ecrire_adresse(plume, element)?;
                    ecrites = ecrites.saturating_add(1);
                }
                if octet == b';' {
                    // Un groupe se ferme, et cela se dit par une adresse vide.
                    debuter(plume, &mut ouverte)?;
                    plume.pousser(b"(NIL NIL NIL NIL)")?;
                    ecrites = ecrites.saturating_add(1);
                }
                debut = i.saturating_add(1);
                i = i.saturating_add(1);
            }
            _ => i = i.saturating_add(1),
        }
    }
    let dernier = valeur.get(debut..).unwrap_or_default();
    if !dernier.trim_ascii().is_empty() && ecrites < ENVELOPE_ADDRESSES_MAX {
        debuter(plume, &mut ouverte)?;
        ecrire_adresse(plume, dernier)?;
    }

    if ouverte {
        plume.pousser(b")")
    } else {
        // Un champ présent mais sans aucune adresse lisible ne désigne personne.
        plume.pousser(b"NIL")
    }
}

/// Ouvre la parenthèse de la liste à la première adresse, et pas avant.
fn debuter(plume: &mut Plume<'_>, ouverte: &mut bool) -> Result<(), Error> {
    if *ouverte {
        return Ok(());
    }
    *ouverte = true;
    plume.pousser(b"(")
}

/// Écrit l'ouverture d'un groupe : `(NIL NIL "nom" NIL)`.
fn ecrire_groupe(plume: &mut Plume<'_>, nom: &[u8]) -> Result<(), Error> {
    plume.pousser(b"(NIL NIL ")?;
    ecrire_texte_cite(plume, nom)?;
    plume.pousser(b" NIL)")
}

/// Écrit une structure d'adresse : `(nom adl boîte hôte)`.
fn ecrire_adresse(plume: &mut Plume<'_>, element: &[u8]) -> Result<(), Error> {
    let (nom, adresse) = match debut_d_angle(element) {
        Some(rang) => (
            element.get(..rang).unwrap_or_default(),
            element
                .get(rang.saturating_add(1)..fin_d_angle(element, rang).saturating_sub(1))
                .unwrap_or_default(),
        ),
        None => (&b""[..], element),
    };
    plume.pousser(b"(")?;
    ecrire_texte_cite(plume, nom)?;
    // Les routes source ont disparu de la RFC 5322 : `adl` est toujours `NIL`.
    plume.pousser(b" NIL ")?;
    let arobase = dernier_arobase(adresse);
    match arobase {
        Some(rang) => {
            ecrire_texte_cite(plume, adresse.get(..rang).unwrap_or_default())?;
            plume.pousser(b" ")?;
            ecrire_texte_cite(
                plume,
                adresse.get(rang.saturating_add(1)..).unwrap_or_default(),
            )?;
        }
        None => {
            // Une adresse sans arobase n'a pas d'hôte : le dire par `NIL` vaut
            // mieux que d'en inventer un.
            ecrire_texte_cite(plume, adresse)?;
            plume.pousser(b" NIL")?;
        }
    }
    plume.pousser(b")")
}

/// Écrit un texte d'adresse : guillemets retirés, échappements défaits,
/// commentaires sautés, puis recité aux règles d'IMAP.
fn ecrire_texte_cite(plume: &mut Plume<'_>, texte: &[u8]) -> Result<(), Error> {
    let texte = texte.trim_ascii();
    // ON REGARDE AVANT D'ÉCRIRE. Un texte qui n'est QUE commentaire ne vaut
    // rien, et l'on ne s'en aperçoit qu'après l'avoir traversé : ouvrir les
    // guillemets d'abord rendrait `""` là où il faut `NIL`, c'est-à-dire une
    // chaîne vide là où il n'y a rien.
    if !porte_du_texte(texte) {
        return plume.pousser(b"NIL");
    }
    plume.pousser(b"\"")?;
    let mut i = 0_usize;
    let mut blanc = false;
    let mut ecrit = false;
    while i < texte.len() {
        let octet = texte.get(i).copied().unwrap_or(0);
        match octet {
            b'(' => {
                i = fin_de_commentaire(texte, i);
                blanc = true;
            }
            b' ' | b'\t' | b'\r' | b'\n' => {
                blanc = true;
                i = i.saturating_add(1);
            }
            b'"' => {
                // Une chaîne citée : son CONTENU est le texte, échappements
                // défaits. Les guillemets, eux, appartiennent à la RFC 5322 et
                // pas à ce que le nom vaut.
                let fin = fin_de_chaine(texte, i);
                let mut j = i.saturating_add(1);
                while j.saturating_add(1) < fin {
                    let dedans = texte.get(j).copied().unwrap_or(0);
                    let (a_ecrire, saut) = if dedans == b'\\' {
                        (texte.get(j.saturating_add(1)).copied().unwrap_or(b'\\'), 2)
                    } else {
                        (dedans, 1)
                    };
                    // UNE FIN DE LIGNE N'EST PAS DU TEXTE, MÊME ENTRE
                    // GUILLEMETS. La RFC 5322 n'admet dans une chaîne citée que
                    // le pliage ; et une chaîne IMAP ne peut porter ni `CR` ni
                    // `LF` — le client lirait la fin de la réponse au milieu
                    // d'un nom, puis la suite du dialogue comme du protocole.
                    //
                    // Le pli s'EFFACE, il ne devient pas un blanc : le blanc qui
                    // suit un `CRLF` est déjà dans la chaîne, et le compter une
                    // seconde fois écarterait les deux mots d'un espace de trop.
                    if matches!(a_ecrire, b'\r' | b'\n') {
                        j = j.saturating_add(saut);
                        continue;
                    }
                    if blanc && ecrit {
                        plume.pousser(b" ")?;
                    }
                    blanc = false;
                    plume.octet_de_chaine(a_ecrire)?;
                    ecrit = true;
                    j = j.saturating_add(saut);
                }
                i = fin;
            }
            _ => {
                if blanc && ecrit {
                    plume.pousser(b" ")?;
                }
                blanc = false;
                plume.octet_de_chaine(octet)?;
                ecrit = true;
                i = i.saturating_add(1);
            }
        }
    }
    plume.pousser(b"\"")
}

/// Ce texte porte-t-il autre chose que du blanc et des commentaires ?
fn porte_du_texte(texte: &[u8]) -> bool {
    let mut i = 0_usize;
    while i < texte.len() {
        match texte.get(i).copied().unwrap_or(0) {
            b'(' => i = fin_de_commentaire(texte, i),
            b' ' | b'\t' | b'\r' | b'\n' => i = i.saturating_add(1),
            b'"' => {
                // Une chaîne citée ne porte du texte que si elle porte autre
                // chose qu'un pli. CE TEST DOIT DIRE CE QUE LA PLUME ÉCRIRA :
                // s'il comptait le pli pour du texte, un nom qui n'est qu'un
                // pli ouvrirait des guillemets que rien ne viendrait remplir,
                // et rendrait `""` là où il faut `NIL`.
                let fin = fin_de_chaine(texte, i);
                if chaine_porte_du_texte(texte.get(i..fin).unwrap_or_default()) {
                    return true;
                }
                i = fin;
            }
            _ => return true,
        }
    }
    false
}

/// Le contenu d'une chaîne citée porte-t-il autre chose que du pliage ?
///
/// On défait les échappements comme la plume les défait, pour que les deux
/// lectures d'une même chaîne ne puissent pas diverger.
fn chaine_porte_du_texte(chaine: &[u8]) -> bool {
    // `chaine` porte ses guillemets : le contenu s'arrête un octet avant la fin,
    // exactement là où la plume s'arrête elle aussi.
    let mut j = 1_usize;
    while j.saturating_add(1) < chaine.len() {
        let dedans = chaine.get(j).copied().unwrap_or(0);
        let (octet, saut) = if dedans == b'\\' {
            (chaine.get(j.saturating_add(1)).copied().unwrap_or(b'\\'), 2)
        } else {
            (dedans, 1)
        };
        if !matches!(octet, b'\r' | b'\n') {
            return true;
        }
        j = j.saturating_add(saut);
    }
    false
}

/// Le rang qui suit la chaîne citée commençant en `debut`.
fn fin_de_chaine(texte: &[u8], debut: usize) -> usize {
    let mut i = debut.saturating_add(1);
    while i < texte.len() {
        match texte.get(i).copied().unwrap_or(0) {
            b'\\' => i = i.saturating_add(2),
            b'"' => return i.saturating_add(1),
            _ => i = i.saturating_add(1),
        }
    }
    texte.len()
}

/// Le rang qui suit le commentaire commençant en `debut`, imbrications
/// comprises.
fn fin_de_commentaire(texte: &[u8], debut: usize) -> usize {
    let mut profondeur = 0_usize;
    let mut i = debut;
    while i < texte.len() {
        match texte.get(i).copied().unwrap_or(0) {
            b'\\' => i = i.saturating_add(2),
            b'(' => {
                profondeur = profondeur.saturating_add(1);
                i = i.saturating_add(1);
            }
            b')' => {
                profondeur = profondeur.saturating_sub(1);
                i = i.saturating_add(1);
                if profondeur == 0 {
                    return i;
                }
            }
            _ => i = i.saturating_add(1),
        }
    }
    texte.len()
}

/// Le rang qui suit l'adresse entre chevrons commençant en `debut`.
fn fin_d_angle(texte: &[u8], debut: usize) -> usize {
    let mut i = debut.saturating_add(1);
    while i < texte.len() {
        match texte.get(i).copied().unwrap_or(0) {
            b'"' => i = fin_de_chaine(texte, i),
            b'>' => return i.saturating_add(1),
            _ => i = i.saturating_add(1),
        }
    }
    texte.len()
}

/// Le rang du chevron ouvrant, hors chaîne et hors commentaire.
fn debut_d_angle(texte: &[u8]) -> Option<usize> {
    let mut i = 0_usize;
    while i < texte.len() {
        match texte.get(i).copied().unwrap_or(0) {
            b'"' => i = fin_de_chaine(texte, i),
            b'(' => i = fin_de_commentaire(texte, i),
            b'<' => return Some(i),
            _ => i = i.saturating_add(1),
        }
    }
    None
}

/// Le rang du dernier arobase hors chaîne et hors commentaire.
///
/// **Le dernier, et pas le premier** : `"a@b" <c@d.test>` a un arobase dans son
/// nom, et couper au premier donnerait un hôte qui n'en est pas un.
fn dernier_arobase(texte: &[u8]) -> Option<usize> {
    let mut trouve = None;
    let mut i = 0_usize;
    while i < texte.len() {
        match texte.get(i).copied().unwrap_or(0) {
            b'"' => i = fin_de_chaine(texte, i),
            b'(' => i = fin_de_commentaire(texte, i),
            b'@' => {
                trouve = Some(i);
                i = i.saturating_add(1);
            }
            _ => i = i.saturating_add(1),
        }
    }
    trouve
}

#[cfg(test)]
mod tests;
