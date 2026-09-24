// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! L'invitation : ce qu'un administrateur remet à quelqu'un pour que son
//! **premier** appareil s'enrôle sans mot de passe.
//!
//! # ELLE SE SCELLE COMME UN JETON, ET NE S'Y CONFOND PAS
//!
//! Même discipline que [`crate::token`] : un sceau HMAC-SHA-256, aucun champ
//! d'algorithme, et la vérification AVANT la lecture. Ce qui change est l'octet
//! de version — [`VERSION`] vaut `0x02`, là où un jeton vaut `0x01`.
//!
//! **CET OCTET EST LA SÉPARATION, ET IL EST DANS LE SCEAU.** Les deux objets
//! sont scellés par la MÊME clé : sans lui, un jeton porteur présenté à la place
//! d'une invitation se vérifierait, et l'on enrôlerait un appareil sur la foi
//! d'un objet émis pour autre chose. Le lire APRÈS le sceau ne suffirait pas
//! davantage si les deux formats se recouvraient — ils ne se recouvrent pas,
//! parce que la version est le premier octet du clair, donc couverte.
//!
//! # CE QU'ELLE NE PORTE PAS, ET POURQUOI
//!
//! **Pas de portée.** Une invitation n'ouvre rien : elle autorise UN geste,
//! l'enrôlement d'une clef sur un compte. Lui donner une portée la ferait
//! ressembler à un jeton, et quelqu'un finirait par l'employer comme tel.
//!
//! **Pas d'identifiant.** Un jeton en porte un pour être révocable ; une
//! invitation n'a pas de registre où être révoquée — voir ci-dessous — et un
//! champ qui ne sert à rien est un champ qu'on finit par croire utile.
//!
//! **Pas les adresses du compte.** Le client en a besoin pour se configurer,
//! mais elles lui sont rendues À L'ENRÔLEMENT, par le serveur qui les lit alors
//! dans le magasin. Les sceller ici les figerait au moment de l'émission : un
//! administrateur qui corrige une adresse entre-temps verrait l'application se
//! configurer avec l'ancienne.
//!
//! # L'USAGE UNIQUE NE VIT PAS ICI
//!
//! Rien dans ces octets n'empêche de les présenter deux fois — un sceau ne se
//! consomme pas. **C'est le magasin d'appareils qui borne l'usage** : une
//! invitation ne vaut que tant que le compte n'a AUCUN appareil enrôlé, et le
//! premier enrôlement la tue.
//!
//! Ce choix évite un troisième fichier, et il survit aux redémarrages — l'état
//! qui décide est le magasin, qui est sur disque. Sa contrepartie est dite :
//! réinviter quelqu'un exige de révoquer ses appareils d'abord.

use crate::base64url;
use crate::error::{Error, Reason};
use ams_sasl::{egales, hmac_sha256};

pub use crate::token::{Key, LOGIN_OCTETS_MAX, MAC_OCTETS};

/// La seule version d'invitation qui existe.
///
/// **ELLE LA SÉPARE DU JETON**, qui vaut `0x01`. Voir l'en-tête du module : les
/// deux sont scellés par la même clé, et c'est cet octet qui empêche de prendre
/// l'un pour l'autre.
pub const VERSION: u8 = 0x02;

/// La plus longue vie qu'on accorde à une invitation, en microsecondes.
///
/// Quarante-huit heures. **PLUS LONGUE QUE CELLE D'UN JETON, ET C'EST
/// DÉLIBÉRÉ** : une invitation voyage par un canal humain — un courriel, un
/// message —, et son porteur doit avoir le temps d'installer une application.
/// Un jeton, lui, se renouvelle tout seul.
///
/// Ce qu'une vie longue coûte est borné par ailleurs : l'invitation meurt au
/// premier enrôlement, et ne vaut que pour un compte qui n'a encore aucun
/// appareil.
pub const LIFETIME_MAX_US: u64 = 48 * 3_600 * 1_000_000;

/// Ce que la partie en clair occupe, sans le nom de compte.
///
/// Version, expiration, longueur du nom.
const ENTETE_OCTETS: usize = 1 + 8 + 1;

/// La plus grande invitation binaire possible.
pub const INVITATION_OCTETS_MAX: usize = ENTETE_OCTETS + LOGIN_OCTETS_MAX + MAC_OCTETS;

/// Ce que la même invitation occupe une fois écrite.
pub const ENCODED_OCTETS_MAX: usize = base64url::encoded_len(INVITATION_OCTETS_MAX);

/// Ce qu'une invitation dit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invitation<'o> {
    /// Le compte dont elle enrôle le premier appareil.
    pub login: &'o str,
    /// Quand elle cesse de valoir, en microsecondes depuis l'époque.
    pub expiry: u64,
}

/// Écrit une invitation scellée, en base64url.
///
/// # Errors
///
/// [`Reason::BadToken`] pour un nom de compte vide ou trop long, ou une
/// expiration qui dépasse [`LIFETIME_MAX_US`] ; [`Reason::BufferTooSmall`] si
/// `sortie` ne suffit pas.
pub fn issue<'o>(
    key: &Key,
    invitation: &Invitation<'_>,
    maintenant: u64,
    sortie: &'o mut [u8],
) -> Result<&'o str, Error> {
    let login = invitation.login.as_bytes();
    if login.is_empty() || login.len() > LOGIN_OCTETS_MAX {
        return Err(Error::new(Reason::BadToken));
    }
    // **UNE VIE PLUS LONGUE QUE LA BORNE SE REFUSE À L'ÉMISSION**, comme pour un
    // jeton : la vérifier seulement à la lecture laisserait circuler des
    // invitations qu'on refuserait ensuite sans que personne ne comprenne.
    if invitation.expiry > maintenant.saturating_add(LIFETIME_MAX_US) {
        return Err(Error::new(Reason::BadToken));
    }

    let mut brut = [0_u8; INVITATION_OCTETS_MAX];
    // Le nom tient sous sa borne, donc ce total tient sous celle de
    // l'invitation : la découpe est bornée par construction.
    let longueur = ENTETE_OCTETS
        .saturating_add(login.len())
        .saturating_add(MAC_OCTETS);
    let (place, _) = brut.split_at_mut(longueur);
    ecrire_le_clair(place, invitation, login);

    let (clair, sceau) = place.split_at_mut(longueur.saturating_sub(MAC_OCTETS));
    let calcule = hmac_sha256(key.octets(), clair);
    for (ou, lu) in sceau.iter_mut().zip(calcule.iter()) {
        *ou = *lu;
    }
    let ecrit = base64url::encode(place, sortie)?;
    // **C'EST DE L'ASCII PAR CONSTRUCTION** : chaque octet sort de l'alphabet de
    // §5 de RFC 4648, qui n'en contient pas d'autre.
    Ok(core::str::from_utf8(ecrit).unwrap_or_default())
}

/// Écrit la partie en clair d'une invitation.
fn ecrire_le_clair(place: &mut [u8], invitation: &Invitation<'_>, login: &[u8]) {
    // Les tableaux sont NOMMÉS : les enchaîner sans les lier les ferait détruire
    // avant que la chaîne ne les lise.
    let expiration = invitation.expiry.to_be_bytes();
    let tete = [VERSION];
    let queue = [u8::try_from(login.len()).unwrap_or(0)];
    let tout = tete.iter().chain(&expiration).chain(&queue).chain(login);
    for (ou, lu) in place.iter_mut().zip(tout) {
        *ou = *lu;
    }
}

/// Vérifie une invitation, et rend ce qu'elle dit.
///
/// `sortie` reçoit l'invitation décodée, et le nom de compte rendu y pointe.
///
/// # L'ORDRE EST TOUT, COMME POUR UN JETON
///
/// 1. on décode le base64url — et l'on refuse ce qui a plusieurs écritures ;
/// 2. on découpe la structure, **sans rien en croire** ;
/// 3. on vérifie le sceau, à temps constant ;
/// 4. **et alors seulement** on interprète les champs, version comprise.
///
/// # Errors
///
/// [`Reason::BadToken`] pour tout ce qui ne se vérifie pas — **y compris un
/// jeton porteur authentique présenté ici** : sa version le trahit, et le refus
/// est le même pour ne rien apprendre à qui essaie ;
/// [`Reason::TokenExpired`] pour une invitation authentique dont l'heure est
/// passée ; [`Reason::BufferTooSmall`] si `sortie` ne suffit pas.
pub fn verify<'o>(
    key: &Key,
    presentee: &[u8],
    maintenant: u64,
    sortie: &'o mut [u8],
) -> Result<Invitation<'o>, Error> {
    // 1. Le décodage refuse déjà les écritures multiples.
    if presentee.len() > ENCODED_OCTETS_MAX {
        return Err(Error::new(Reason::BadToken));
    }
    let brut = base64url::decode(presentee, sortie)?;

    // 2. On découpe, sans rien croire.
    let coupe = brut
        .len()
        .checked_sub(MAC_OCTETS)
        .filter(|clair| *clair > ENTETE_OCTETS)
        .ok_or(Error::new(Reason::BadToken))?;
    let (clair, sceau) = brut.split_at(coupe);

    // 3. Le sceau, à temps constant — et AVANT de croire quoi que ce soit.
    match egales(&hmac_sha256(key.octets(), clair), sceau) {
        true => {}
        false => return Err(Error::new(Reason::BadToken)),
    }

    // 4. Maintenant, et seulement maintenant, on lit.
    lire_le_clair(clair, maintenant)
}

/// Interprète la partie en clair d'une invitation dont le sceau est vérifié.
fn lire_le_clair(clair: &[u8], maintenant: u64) -> Result<Invitation<'_>, Error> {
    let mauvaise = Error::new(Reason::BadToken);
    // L'appelant a vérifié que la partie en clair dépasse l'en-tête : le nom de
    // compte fait donc au moins un octet.
    let (entete, login) = clair.split_at(ENTETE_OCTETS);
    // **LA VERSION D'ABORD** : c'est elle qui sépare une invitation d'un jeton,
    // et les deux portent le même sceau.
    if entete.first() != Some(&VERSION) {
        return Err(mauvaise);
    }
    let expiry = lire_huit(entete.get(1..9).unwrap_or_default());
    // **LA LONGUEUR ANNONCÉE DOIT ÊTRE CELLE QU'ON A** : le sceau la couvre, donc
    // elle est authentique — mais un émetteur qui se tromperait produirait deux
    // invitations scellées désignant le même compte de deux façons.
    let annoncee = usize::from(entete.get(9).copied().unwrap_or(0));
    if annoncee != login.len() {
        return Err(mauvaise);
    }
    let login = core::str::from_utf8(login).map_err(|_| mauvaise)?;

    if maintenant >= expiry {
        return Err(Error::new(Reason::TokenExpired));
    }
    Ok(Invitation { login, expiry })
}

/// Le nombre gros-boutiste que portent ces huit octets.
fn lire_huit(octets: &[u8]) -> u64 {
    let mut valeur = 0_u64;
    for octet in octets {
        valeur = (valeur << 8) | u64::from(*octet);
    }
    valeur
}

#[cfg(test)]
mod tests;
