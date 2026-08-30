// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les en-têtes de paquet de RFC 9000 §17.
//!
//! # ON NE LIT QUE CE QUI N'EST PAS PROTÉGÉ, ET C'EST LA MOITIÉ DE L'EN-TÊTE
//!
//! La protection d'en-tête (RFC 9001 §5.4) masque **les bits réservés, la
//! longueur du numéro de paquet, et le numéro lui-même**. Ils ne sont donc pas
//! lisibles ici : ce module s'arrête exactement là où le masque commence, et
//! rend l'endroit où il commence.
//!
//! Cette coupure n'est pas une commodité de mise en œuvre. C'est l'ordre imposé
//! par le protocole : pour ôter le masque, il faut la clé ; pour trouver la clé,
//! il faut l'identifiant de destination ; pour lire l'identifiant, il faut avoir
//! lu l'en-tête jusque-là. **Un module qui prétendrait tout lire d'un coup
//! mentirait sur ce qu'il sait.**
//!
//! # LA LONGUEUR DE L'IDENTIFIANT COURT N'EST PAS SUR LE FIL
//!
//! Un en-tête long annonce la longueur de chaque identifiant. Un en-tête COURT
//! n'annonce rien : le receveur connaît la longueur parce que c'est LUI qui a
//! choisi cet identifiant et l'a donné au pair.
//!
//! C'est pour cela que [`ShortHeader::parse`] la demande en argument, et non
//! parce qu'on aurait oublié de la lire. Un serveur qui ne se souviendrait pas
//! des longueurs qu'il émet ne saurait pas lire un seul paquet court.

use crate::connection_id::ConnectionId;
use crate::error::{Error, Reason};
use crate::varint;

/// La version que ce serveur parle (RFC 9000 §15).
pub const VERSION_1: u32 = 0x0000_0001;

/// La version qui n'en est pas une : elle marque une négociation (§17.2.1).
pub const VERSION_NEGOTIATION: u32 = 0x0000_0000;

/// Le bit de forme : un en-tête long l'a à un (§17.2).
const BIT_FORME_LONGUE: u8 = 0x80;

/// Le bit fixe, que §17.2 veut à un — sinon le paquet se jette.
const BIT_FIXE: u8 = 0x40;

/// Où se trouve le type, dans un premier octet d'en-tête long.
const MASQUE_TYPE_LONG: u8 = 0x30;

/// Ce qu'un jeton d'authentification de `Retry` occupe (§17.2.5).
pub const RETRY_TAG_OCTETS: usize = 16;

/// Le type d'un paquet à en-tête long (§17.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LongKind {
    /// `Initial` — celui qui ouvre, et qui porte le jeton.
    Initial,
    /// `0-RTT` — des données avant la fin de la poignée de main.
    ///
    /// **ELLES NE SONT PAS PROTÉGÉES CONTRE LE REJEU** (§17.2.3), et une
    /// requête rejouée est une requête traitée deux fois. Ce qu'on en accepte
    /// est une décision de la couche du dessus, pas de la grammaire.
    ZeroRtt,
    /// `Handshake` — la suite de la poignée de main.
    Handshake,
    /// `Retry` — le serveur renvoie le client avec un jeton (§17.2.5).
    Retry,
}

impl LongKind {
    /// Le type que ces deux bits désignent.
    #[must_use]
    pub const fn from_bits(octet: u8) -> Self {
        match octet & MASQUE_TYPE_LONG {
            0x00 => Self::Initial,
            0x10 => Self::ZeroRtt,
            0x20 => Self::Handshake,
            // Il ne reste que 0x30 : le classement est TOTAL, et un bras
            // « sinon » serait une branche qu'aucun octet ne peut emprunter.
            _ => Self::Retry,
        }
    }

    /// Les deux bits de ce type.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            Self::Initial => 0x00,
            Self::ZeroRtt => 0x10,
            Self::Handshake => 0x20,
            Self::Retry => 0x30,
        }
    }
}

/// Un en-tête long, lu jusqu'où la protection commence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LongHeader<'a> {
    /// Le type.
    kind: LongKind,
    /// La version annoncée.
    version: u32,
    /// L'identifiant de destination.
    destination: ConnectionId,
    /// L'identifiant de source.
    source: ConnectionId,
    /// Le jeton d'un `Initial`, vide pour les autres.
    token: &'a [u8],
    /// Ce que le reste du paquet occupe : numéro de paquet ET charge.
    length: u64,
    /// Où commence le numéro de paquet, depuis le début du paquet.
    ///
    /// **C'EST AUSSI OÙ LE MASQUE COMMENCE** : la protection d'en-tête
    /// s'applique à partir de là, et l'échantillon qui la fabrique se prend
    /// quatre octets plus loin (RFC 9001 §5.4.2).
    number_offset: usize,
}

impl<'a> LongHeader<'a> {
    /// Le type.
    #[must_use]
    pub const fn kind(&self) -> LongKind {
        self.kind
    }

    /// La version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// L'identifiant de destination.
    #[must_use]
    pub const fn destination(&self) -> ConnectionId {
        self.destination
    }

    /// L'identifiant de source.
    #[must_use]
    pub const fn source(&self) -> ConnectionId {
        self.source
    }

    /// Le jeton, vide hors d'un `Initial`.
    #[must_use]
    pub const fn token(&self) -> &'a [u8] {
        self.token
    }

    /// Ce que le numéro de paquet et la charge occupent ensemble.
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// Où commence le numéro de paquet, et donc la protection d'en-tête.
    #[must_use]
    pub const fn number_offset(&self) -> usize {
        self.number_offset
    }
}

/// Un `Retry` : le serveur renvoie le client avec un jeton (§17.2.5).
///
/// **IL N'A NI LONGUEUR NI NUMÉRO DE PAQUET.** Tout ce qui suit les
/// identifiants est le jeton, sauf les seize derniers octets, qui
/// l'authentifient. C'est pour cela qu'il ne se lit pas comme les autres.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retry<'a> {
    /// L'identifiant de destination.
    pub destination: ConnectionId,
    /// L'identifiant de source, celui que le serveur veut désormais.
    pub source: ConnectionId,
    /// Le jeton à réémettre.
    pub token: &'a [u8],
    /// Les seize octets qui prouvent que le `Retry` vient bien du serveur.
    pub tag: [u8; RETRY_TAG_OCTETS],
}

/// Une négociation de version (§17.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionNegotiation<'a> {
    /// L'identifiant de destination.
    pub destination: ConnectionId,
    /// L'identifiant de source.
    pub source: ConnectionId,
    /// Les versions annoncées, quatre octets chacune.
    pub versions: &'a [u8],
}

/// Ce qu'un en-tête long s'est trouvé être.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Long<'a> {
    /// Un `Initial`, un `0-RTT` ou un `Handshake`.
    Numbered(LongHeader<'a>),
    /// Un `Retry`, qui n'a ni longueur ni numéro.
    Retry(Retry<'a>),
    /// Une négociation de version.
    ///
    /// **UN SERVEUR N'EN REÇOIT JAMAIS**, et §6.1 lui demande de la jeter : il
    /// est celui qui les émet. On la lit quand même, parce qu'un paquet qu'on
    /// ne sait pas nommer se jette sans qu'on puisse dire pourquoi.
    Negotiation(VersionNegotiation<'a>),
}

/// Lit un en-tête long.
///
/// # LE BIT FIXE SE VÉRIFIE, ET LE PAQUET SE JETTE S'IL MANQUE
///
/// §17.2 : « Fixed Bit: The next bit (0x40) of byte 0 is set to 1. Packets
/// containing a zero value for this bit are not valid packets in this version
/// and MUST be discarded. » C'est ce qui permet de distinguer QUIC d'autres
/// protocoles sur le même port — et le refuser tôt évite de déchiffrer ce qui
/// n'est pas à nous.
///
/// # Errors
///
/// [`Reason::Truncated`], [`Reason::ConnectionIdTooLong`],
/// [`Reason::NotAPacket`] si la forme ou le bit fixe ne conviennent pas.
pub fn parse_long(paquet: &[u8]) -> Result<Long<'_>, Error> {
    let tronque = || Error::new(Reason::Truncated);
    let premier = *paquet.first().ok_or_else(tronque)?;
    if premier & BIT_FORME_LONGUE == 0 || premier & BIT_FIXE == 0 {
        return Err(Error::new(Reason::NotAPacket));
    }
    let quatre: [u8; 4] = paquet
        .get(1..5)
        .and_then(|lus| lus.try_into().ok())
        .ok_or_else(tronque)?;
    let version = u32::from_be_bytes(quatre);
    let mut rang = 5_usize;
    let destination = lire_identifiant(paquet, &mut rang)?;
    let source = lire_identifiant(paquet, &mut rang)?;

    // §17.2.1 : LA VERSION ZÉRO N'EST PAS UNE VERSION. Le reste du paquet est
    // une liste de versions, et non un type de paquet — les bits de type du
    // premier octet ne veulent alors rien dire.
    if version == VERSION_NEGOTIATION {
        return Ok(Long::Negotiation(VersionNegotiation {
            destination,
            source,
            versions: paquet.get(rang..).unwrap_or_default(),
        }));
    }

    let kind = LongKind::from_bits(premier);
    if kind == LongKind::Retry {
        // §17.2.5 : tout ce qui suit est le jeton, sauf les seize derniers
        // octets. Un `Retry` plus court que ces seize octets n'en est pas un.
        let corps = paquet.get(rang..).unwrap_or_default();
        // **LE JETON EST TOUT CE QUI PRÉCÈDE LES SEIZE DERNIERS OCTETS.** Prendre
        // la queue d'abord est la seule façon de n'avoir qu'une garde : couper
        // puis convertir en aurait fait deux, dont la seconde qu'aucun `Retry`
        // ne peut emprunter — une tranche de seize octets se convertit toujours.
        let tag = *corps.last_chunk::<RETRY_TAG_OCTETS>().ok_or_else(tronque)?;
        let coupure = corps.len().saturating_sub(RETRY_TAG_OCTETS);
        let token = corps.get(..coupure).unwrap_or_default();
        return Ok(Long::Retry(Retry {
            destination,
            source,
            token,
            tag,
        }));
    }

    // §17.2.2 : seul un `Initial` porte un jeton.
    let token = match kind {
        LongKind::Initial => lire_jeton(paquet, &mut rang)?,
        _ => &[][..],
    };
    // Le rang a été validé par chaque lecture qui précède : la tranche existe
    // toujours, fût-elle vide. `unwrap_or_default` porte cela dans la
    // bibliothèque — et si elle est vide, c'est la lecture de la longueur qui
    // dira que le paquet est tronqué.
    let suite = paquet.get(rang..).unwrap_or_default();
    let (length, lus) = varint::decode(suite)?;
    rang = rang.saturating_add(lus);
    Ok(Long::Numbered(LongHeader {
        kind,
        version,
        destination,
        source,
        token,
        length,
        number_offset: rang,
    }))
}

/// Un en-tête court, celui des paquets `1-RTT` (§17.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShortHeader {
    /// L'identifiant de destination.
    destination: ConnectionId,
    /// Où commence le numéro de paquet, et donc la protection d'en-tête.
    number_offset: usize,
}

impl ShortHeader {
    /// Lit un en-tête court, sachant la longueur de l'identifiant qu'on a émis.
    ///
    /// # LA LONGUEUR VIENT DE NOUS, PAS DU FIL
    ///
    /// C'est nous qui avons choisi cet identifiant et l'avons donné au pair : il
    /// ne nous le réapprend pas. Un serveur qui ne se souviendrait pas des
    /// longueurs qu'il émet ne saurait lire aucun paquet court.
    ///
    /// # Errors
    ///
    /// [`Reason::Truncated`] ; [`Reason::ConnectionIdTooLong`] ;
    /// [`Reason::NotAPacket`] si la forme ou le bit fixe ne conviennent pas.
    pub fn parse(paquet: &[u8], longueur: usize) -> Result<Self, Error> {
        let tronque = || Error::new(Reason::Truncated);
        let premier = *paquet.first().ok_or_else(tronque)?;
        if premier & BIT_FORME_LONGUE != 0 || premier & BIT_FIXE == 0 {
            return Err(Error::new(Reason::NotAPacket));
        }
        let fin = longueur.saturating_add(1);
        let octets = paquet.get(1..fin).ok_or_else(tronque)?;
        let destination = ConnectionId::new(octets)?;
        Ok(Self {
            destination,
            number_offset: fin,
        })
    }

    /// L'identifiant de destination.
    #[must_use]
    pub const fn destination(&self) -> ConnectionId {
        self.destination
    }

    /// Où commence le numéro de paquet, et donc la protection d'en-tête.
    #[must_use]
    pub const fn number_offset(&self) -> usize {
        self.number_offset
    }
}

/// Ce paquet a-t-il un en-tête long ?
///
/// **C'EST LA SEULE CHOSE QU'ON PUISSE SAVOIR SANS RIEN D'AUTRE** : le premier
/// bit, et rien de plus. Tout le reste dépend de la version, ou de ce qu'on a
/// soi-même émis.
#[must_use]
pub fn is_long(paquet: &[u8]) -> bool {
    paquet
        .first()
        .is_some_and(|premier| premier & BIT_FORME_LONGUE != 0)
}

/// Lit un identifiant précédé de sa longueur, et avance le rang.
fn lire_identifiant(paquet: &[u8], rang: &mut usize) -> Result<ConnectionId, Error> {
    let tronque = || Error::new(Reason::Truncated);
    let longueur = usize::from(*paquet.get(*rang).ok_or_else(tronque)?);
    let debut = rang.saturating_add(1);
    let fin = debut.saturating_add(longueur);
    let octets = paquet.get(debut..fin).ok_or_else(tronque)?;
    *rang = fin;
    ConnectionId::new(octets)
}

/// Lit le jeton d'un `Initial`, et avance le rang.
fn lire_jeton<'a>(paquet: &'a [u8], rang: &mut usize) -> Result<&'a [u8], Error> {
    let tronque = || Error::new(Reason::Truncated);
    let suite = paquet.get(*rang..).unwrap_or_default();
    let (longueur, lus) = varint::decode(suite)?;
    let debut = rang.saturating_add(lus);
    // **LA LONGUEUR VIENT DU FIL, ET ELLE PEUT ANNONCER 2^62 OCTETS.** La borne
    // réelle est celle du paquet, deux lignes plus bas : `usize::MAX` la fait
    // manquer à coup sûr, là où un `try_from` fautif ouvrirait une branche
    // qu'aucune cible de ce projet ne peut emprunter.
    let taille = usize::try_from(longueur).unwrap_or(usize::MAX);
    let fin = debut.saturating_add(taille);
    let jeton = paquet.get(debut..fin).ok_or_else(tronque)?;
    *rang = fin;
    Ok(jeton)
}

#[cfg(test)]
mod tests;
