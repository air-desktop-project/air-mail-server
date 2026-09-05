// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! L'UTF-7 modifié de RFC 3501 §5.1.3, dans les deux sens.
//!
//! # POURQUOI CE CODEC EXISTE, ET POURQUOI MAINTENANT
//!
//! Les deux versions d'IMAP n'écrivent pas les noms de boîtes de la même façon.
//! RFC 9051 §5.1 les veut **en UTF-8** ; RFC 3501 §5.1.3 les veut en **UTF-7
//! modifié**, une transcription qui ne laisse passer que de l'ASCII imprimable.
//! Ce serveur annonce les deux versions : il doit donc savoir passer de l'une à
//! l'autre.
//!
//! Sans lui, deux voies s'offraient, et toutes deux étaient fausses. Refuser
//! l'UTF-8 — ce que ce serveur faisait — c'est annoncer `IMAP4rev2` et refuser
//! ce que §5.1 rend obligatoire. L'accepter sans transcrire, c'est envoyer des
//! octets bruts à un client rev1, qui n'attend que de l'ASCII et affichera du
//! charabia.
//!
//! # LE DISQUE PORTE DE L'UTF-8, ET C'EST UN CHOIX QU'ON NE POUVAIT FAIRE
//! # QU'AUJOURD'HUI
//!
//! Le nom retenu est celui de rev2, et la transcription se fait AU BORD du
//! protocole : ce qui descend vers le magasin est toujours de l'UTF-8. Un
//! serveur déjà en service dont un client rev1 aurait créé `Créations` porterait
//! sur son disque `.Cr&AOk-ations` et ne le retrouverait plus. **Aucune
//! installation de production n'existe encore** — la première remise reste à
//! faire — et c'est donc le dernier moment où ce choix ne coûte rien.
//!
//! # LA FORME, EN TROIS RÈGLES
//!
//! - l'ASCII imprimable — `0x20` à `0x7E` — se représente lui-même, sauf `&` ;
//! - `&` s'écrit `&-` ;
//! - tout le reste passe en **UTF-16BE**, puis en base64 MODIFIÉ — celui de
//!   RFC 2045 où `/` devient `,`, et sans remplissage —, entre un `&` et un `-`.
//!
//! # CE QU'UN CODEC DE NOMS DOIT REFUSER, ET POURQUOI
//!
//! Un nom vient du réseau et finit dans un nom de répertoire. Tout ce qui suit
//! est donc une ERREUR, et non une approximation qu'on corrigerait en silence :
//!
//! - une séquence base64 qui ne se ferme pas ;
//! - des bits de remplissage non nuls — deux écritures pour un même nom, donc
//!   deux boîtes que le client croirait une seule ;
//! - un demi-substitut isolé, qui ne désigne aucun caractère ;
//! - une séquence `&…-` qui ne code que de l'ASCII, que §5.1.3 interdit
//!   d'écrire ainsi — même raison : deux écritures pour un seul nom.
//!
//! **Transformer plutôt que refuser rendrait au client un nom qui n'est pas
//! celui qu'il a demandé**, et le ferait chercher longtemps.

use crate::error::Error;

/// L'alphabet du base64 modifié : celui de RFC 2045, `/` remplacé par `,`.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

/// Le rang d'un octet dans l'alphabet, ou `None` s'il n'en est pas.
fn rang(octet: u8) -> Option<u8> {
    let mut i = 0_usize;
    while i < ALPHABET.len() {
        // BOUCLE PLUTÔT QUE `position` : voir C2. Une fermeture ne s'instancie
        // pas de la même façon dans les deux compilations d'une crate, et l'une
        // présente d'un côté, absente de l'autre, ne peut pas être appariée.
        if ALPHABET[i] == octet {
            return u8::try_from(i).ok();
        }
        i = i.saturating_add(1);
    }
    None
}

/// Cet octet se représente-t-il lui-même ?
///
/// §5.1.3 : l'ASCII imprimable, `&` excepté. **`0x7F` n'en est pas** — c'est
/// `DEL`, qui n'est pas imprimable.
const fn direct(octet: u8) -> bool {
    octet >= 0x20 && octet <= 0x7E && octet != b'&'
}

/// Transcrit un nom d'UTF-7 modifié vers UTF-8.
///
/// Rend combien d'octets ont été écrits dans `sortie`.
///
/// # Errors
///
/// [`Error::MalformedMailbox`] si l'entrée n'est pas de l'UTF-7 modifié bien
/// formé, ou si `sortie` ne suffit pas.
pub fn decode(entree: &[u8], sortie: &mut [u8]) -> Result<usize, Error> {
    let mut ecrits = 0_usize;
    let mut rang_lu = 0_usize;
    while rang_lu < entree.len() {
        let octet = entree[rang_lu];
        if octet != b'&' {
            // **HORS SÉQUENCE, SEUL L'ASCII IMPRIMABLE A COURS.** Un octet
            // au-delà de `0x7E` dans un nom rev1 n'est pas de l'UTF-7 modifié :
            // le laisser passer ferait accepter deux écritures pour un nom.
            if !direct(octet) {
                return Err(Error::MalformedMailbox);
            }
            *sortie.get_mut(ecrits).ok_or(Error::MalformedMailbox)? = octet;
            ecrits = ecrits.saturating_add(1);
            rang_lu = rang_lu.saturating_add(1);
            continue;
        }
        rang_lu = rang_lu.saturating_add(1);
        // `&-` est un `&` littéral.
        if entree.get(rang_lu) == Some(&b'-') {
            *sortie.get_mut(ecrits).ok_or(Error::MalformedMailbox)? = b'&';
            ecrits = ecrits.saturating_add(1);
            rang_lu = rang_lu.saturating_add(1);
            continue;
        }
        let (lus, poses) = decode_une_sequence(entree, rang_lu, sortie, ecrits)?;
        rang_lu = lus;
        ecrits = poses;
    }
    Ok(ecrits)
}

/// Lit une séquence `&…-`, à partir de l'octet qui suit le `&`.
///
/// Rend le rang qui suit le `-`, et le nombre d'octets écrits en tout.
fn decode_une_sequence(
    entree: &[u8],
    debut: usize,
    sortie: &mut [u8],
    deja: usize,
) -> Result<(usize, usize), Error> {
    let mut rang_lu = debut;
    let mut ecrits = deja;
    // L'accumulateur de bits, et combien il en porte.
    let mut reserve = 0_u32;
    let mut bits = 0_u32;
    // Le demi-substitut haut en attente, s'il y en a un.
    let mut haut: Option<u16> = None;
    // A-t-on écrit au moins un caractère ? Une séquence vide — `&-` mise à part,
    // traitée par l'appelant — ne désigne rien.
    let mut au_moins_un = false;

    loop {
        let Some(octet) = entree.get(rang_lu).copied() else {
            // **UNE SÉQUENCE QUI NE SE FERME PAS** : le nom est tronqué, et
            // deviner sa fin, c'est inventer un nom.
            return Err(Error::MalformedMailbox);
        };
        if octet == b'-' {
            rang_lu = rang_lu.saturating_add(1);
            break;
        }
        let valeur = rang(octet).ok_or(Error::MalformedMailbox)?;
        reserve = (reserve << 6) | u32::from(valeur);
        bits = bits.saturating_add(6);
        rang_lu = rang_lu.saturating_add(1);
        if bits < 16 {
            continue;
        }
        bits = bits.saturating_sub(16);
        // **AUCUNE CONVERSION FAILLIBLE ICI** : les quatre octets d'un `u32` se
        // destructurent, et l'on ne garde que les deux du bas. Un
        // `u16::try_from` porterait une erreur qu'aucune entrée ne peut
        // produire — le décalage l'a déjà rendue impossible —, donc une garde
        // qu'aucun essai ne pourrait atteindre.
        let [_, _, poids_fort, poids_faible] = (reserve >> bits).to_be_bytes();
        let unite = u16::from_be_bytes([poids_fort, poids_faible]);
        ecrits = poser_une_unite(&mut haut, unite, sortie, ecrits)?;
        au_moins_un = true;
    }

    // **LES BITS QUI RESTENT DOIVENT ÊTRE NULS**, et il ne peut y en avoir plus
    // de cinq : au-delà, c'est une unité qu'on aurait dû écrire. Des bits de
    // remplissage non nuls donneraient deux écritures pour un même nom, donc
    // deux boîtes que le client croirait une seule.
    if bits >= 6 || (reserve & ((1_u32 << bits).saturating_sub(1))) != 0 {
        return Err(Error::MalformedMailbox);
    }
    // Un demi-substitut haut sans son bas ne désigne aucun caractère.
    if haut.is_some() || !au_moins_un {
        return Err(Error::MalformedMailbox);
    }
    Ok((rang_lu, ecrits))
}

/// Écrit une unité UTF-16, en appariant les substituts.
fn poser_une_unite(
    haut: &mut Option<u16>,
    unite: u16,
    sortie: &mut [u8],
    deja: usize,
) -> Result<usize, Error> {
    if let Some(precedent) = haut.take() {
        // On attendait un demi-substitut BAS.
        if !(0xDC00..=0xDFFF).contains(&unite) {
            return Err(Error::MalformedMailbox);
        }
        let point = 0x1_0000_u32
            .saturating_add(u32::from(precedent.saturating_sub(0xD800)) << 10)
            .saturating_add(u32::from(unite.saturating_sub(0xDC00)));
        // **UNE PAIRE DE SUBSTITUTS DÉSIGNE TOUJOURS UN CARACTÈRE** : les deux
        // moitiés viennent d'être vérifiées, et leur composition tombe entre
        // `0x10000` et `0x10FFFF`. Un `ok_or` porterait ici une erreur
        // qu'aucune entrée ne peut produire.
        let caractere = char::from_u32(point).expect("une paire de substituts est un caractère");
        return poser_un_caractere(caractere, sortie, deja);
    }
    if (0xD800..=0xDBFF).contains(&unite) {
        *haut = Some(unite);
        return Ok(deja);
    }
    // Un demi-substitut BAS qui arrive seul ne désigne rien.
    let caractere = char::from_u32(u32::from(unite)).ok_or(Error::MalformedMailbox)?;
    // **UNE SÉQUENCE NE DOIT PAS CODER DE L'ASCII IMPRIMABLE** : §5.1.3 veut
    // qu'il s'écrive directement, et l'admettre ici donnerait deux écritures
    // pour un même nom.
    // LA CONVERSION NE PEUT PAS TRONQUER PARCE QU'ON A TESTÉ D'ABORD : au-delà
    // de `0x7F`, la question ne se pose pas, et `u8::try_from` la referme sans
    // qu'aucune garde ne reste inatteignable.
    if u8::try_from(unite).is_ok_and(direct) {
        return Err(Error::MalformedMailbox);
    }
    poser_un_caractere(caractere, sortie, deja)
}

/// Écrit un caractère en UTF-8, et rend le nouveau nombre d'octets écrits.
fn poser_un_caractere(caractere: char, sortie: &mut [u8], deja: usize) -> Result<usize, Error> {
    // `deja` COMPTE CE QU'ON A ÉCRIT, et chaque écriture a vérifié sa place :
    // il ne peut donc pas dépasser la longueur. Un `ok_or` y porterait une
    // erreur qu'aucune entrée ne peut produire.
    let place = sortie
        .get_mut(deja..)
        .expect("ce qui est écrit ne dépasse pas ce qui est écrivable");
    let combien = caractere.len_utf8();
    if place.len() < combien {
        return Err(Error::MalformedMailbox);
    }
    caractere.encode_utf8(place);
    Ok(deja.saturating_add(combien))
}

/// Transcrit un nom d'UTF-8 vers l'UTF-7 modifié.
///
/// Rend combien d'octets ont été écrits dans `sortie`.
///
/// # Errors
///
/// [`Error::MalformedMailbox`] si l'entrée n'est pas de l'UTF-8 valide, ou si
/// `sortie` ne suffit pas.
pub fn encode(entree: &[u8], sortie: &mut [u8]) -> Result<usize, Error> {
    let texte = core::str::from_utf8(entree).map_err(|_| Error::MalformedMailbox)?;
    let mut ecrits = 0_usize;
    let mut reserve = 0_u32;
    let mut bits = 0_u32;
    // Est-on DANS une séquence `&…` ?
    let mut dedans = false;

    for caractere in texte.chars() {
        if caractere.is_ascii() && direct(caractere as u8) {
            if dedans {
                ecrits = fermer(&mut reserve, &mut bits, sortie, ecrits)?;
                dedans = false;
            }
            ecrits = pousser(sortie, ecrits, caractere as u8)?;
            continue;
        }
        if caractere == '&' {
            if dedans {
                ecrits = fermer(&mut reserve, &mut bits, sortie, ecrits)?;
                dedans = false;
            }
            ecrits = pousser(sortie, ecrits, b'&')?;
            ecrits = pousser(sortie, ecrits, b'-')?;
            continue;
        }
        if !dedans {
            ecrits = pousser(sortie, ecrits, b'&')?;
            dedans = true;
        }
        // UTF-16, substituts compris.
        let mut unites = [0_u16; 2];
        for unite in caractere.encode_utf16(&mut unites).iter() {
            reserve = (reserve << 16) | u32::from(*unite);
            bits = bits.saturating_add(16);
            while bits >= 6 {
                bits = bits.saturating_sub(6);
                let rang = u8::try_from((reserve >> bits) & 0x3F).unwrap_or(0);
                ecrits = pousser(sortie, ecrits, ALPHABET[usize::from(rang)])?;
            }
        }
    }
    if dedans {
        ecrits = fermer(&mut reserve, &mut bits, sortie, ecrits)?;
    }
    Ok(ecrits)
}

/// Vide les bits qui restent, puis ferme la séquence par un `-`.
fn fermer(
    reserve: &mut u32,
    bits: &mut u32,
    sortie: &mut [u8],
    deja: usize,
) -> Result<usize, Error> {
    let mut ecrits = deja;
    if *bits != 0 {
        // **LE REMPLISSAGE EST NUL**, et le décodeur l'exige : c'est ce qui
        // fait qu'un nom n'a qu'une écriture.
        let manque = 6_u32.saturating_sub(*bits);
        let rang = u8::try_from((*reserve << manque) & 0x3F).unwrap_or(0);
        ecrits = pousser(sortie, ecrits, ALPHABET[usize::from(rang)])?;
        *bits = 0;
    }
    *reserve = 0;
    pousser(sortie, ecrits, b'-')
}

/// Écrit un octet, ou dit que la place manque.
fn pousser(sortie: &mut [u8], deja: usize, octet: u8) -> Result<usize, Error> {
    *sortie.get_mut(deja).ok_or(Error::MalformedMailbox)? = octet;
    Ok(deja.saturating_add(1))
}

#[cfg(test)]
#[path = "utf7/tests.rs"]
mod tests;
