// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les trames d'HTTP/3 (RFC 9114 §7.2).
//!
//! # UNE TRAME PORTE SA LONGUEUR, ET C'EST L'INVERSE DE QUIC
//!
//! Une trame QUIC se lit jusqu'au bout ou pas du tout : son type dit sa forme,
//! et sa forme dit sa fin. Une trame HTTP/3, elle, annonce un type PUIS une
//! longueur, comme un cadre HTTP/2.
//!
//! La raison tient à ce qu'elles servent : QUIC cadre ce qu'il comprend, HTTP/3
//! cadre ce qu'il TRANSPORTE. Un type inconnu doit pouvoir être SAUTÉ, et l'on
//! ne saute que ce dont on connaît la taille.
//!
//! # ET UN TYPE INCONNU S'IGNORE — TROISIÈME RÈGLE, TROISIÈME PROTOCOLE
//!
//! §9 : « Implementations MUST discard frames […] that have unknown or
//! unsupported types. » HTTP/2 ignore, QUIC refuse, HTTP/3 ignore à nouveau.
//! Ce n'est pas de l'inconstance : QUIC refuse parce que ses extensions se
//! négocient dans les paramètres de transport, et qu'une trame inconnue y
//! signale une négociation manquée. HTTP/3 ignore parce que ses trames portent
//! leur longueur, et qu'une extension peut donc traverser un pair qui ne la
//! connaît pas.
//!
//! # LES TYPES RÉSERVÉS SONT UN PIÈGE, ET IL EST VOULU
//!
//! §11.2.1 réserve 0x02, 0x06, 0x08 et 0x09 — les types que RFC 7540 donnait à
//! `PRIORITY`, `PING`, `WINDOW_UPDATE` et `CONTINUATION`. Les recevoir n'est pas
//! une trame inconnue qu'on ignore : c'est un pair qui parle HTTP/2 sur une
//! connexion HTTP/3, et **ce qui suit ne sera pas ce qu'on croit**. La RFC en
//! fait donc une faute, et non un silence.

use ams_proto_quic::varints;

use crate::error::{Error, Reason};

/// La longueur qu'une trame peut annoncer au plus, en octets.
///
/// C'est celle d'un entier de §16 de RFC 9000 : 2^62 - 1. **La borne utile n'est
/// pas là** — elle est dans ce que l'appelant accepte d'accumuler, et il n'y a
/// pas de nombre que la RFC impose ici.
pub const FRAME_LENGTH_MAX: u64 = (1 << 62) - 1;

/// Un type de trame (§7.2, §11.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// `DATA` (0x00) — le corps d'un message.
    Data,
    /// `HEADERS` (0x01) — un bloc de champs comprimé par QPACK.
    Headers,
    /// `CANCEL_PUSH` (0x03).
    CancelPush,
    /// `SETTINGS` (0x04) — la première trame du flux de contrôle, et une seule.
    Settings,
    /// `PUSH_PROMISE` (0x05).
    PushPromise,
    /// `GOAWAY` (0x07).
    GoAway,
    /// `MAX_PUSH_ID` (0x0d).
    MaxPushId,
    /// Un type qu'on ne connaît pas, et qu'on saute (§9).
    Unknown(u64),
}

impl FrameKind {
    /// Les types que §11.2.1 a réservés pour écarter HTTP/2.
    pub const RESERVES_PAR_HTTP2: [u64; 4] = [0x02, 0x06, 0x08, 0x09];

    /// Le type que cet identifiant désigne.
    ///
    /// # Errors
    ///
    /// [`Reason::ReservedH2Frame`] pour un type que §11.2.1 a réservé.
    pub fn from_wire(identifiant: u64) -> Result<Self, Error> {
        if Self::RESERVES_PAR_HTTP2.contains(&identifiant) {
            return Err(Error::new(Reason::ReservedH2Frame));
        }
        Ok(match identifiant {
            0x00 => Self::Data,
            0x01 => Self::Headers,
            0x03 => Self::CancelPush,
            0x04 => Self::Settings,
            0x05 => Self::PushPromise,
            0x07 => Self::GoAway,
            0x0d => Self::MaxPushId,
            autre => Self::Unknown(autre),
        })
    }

    /// L'identifiant sur le fil.
    #[must_use]
    pub const fn value(self) -> u64 {
        match self {
            Self::Data => 0x00,
            Self::Headers => 0x01,
            Self::CancelPush => 0x03,
            Self::Settings => 0x04,
            Self::PushPromise => 0x05,
            Self::GoAway => 0x07,
            Self::MaxPushId => 0x0d,
            Self::Unknown(autre) => autre,
        }
    }

    /// Cette trame a-t-elle sa place sur un flux de requête (§7.2) ?
    #[must_use]
    pub const fn sur_une_requete(self) -> bool {
        matches!(self, Self::Data | Self::Headers | Self::Unknown(_))
    }

    /// Cette trame a-t-elle sa place sur le flux de contrôle (§7.2) ?
    #[must_use]
    pub const fn sur_le_controle(self) -> bool {
        matches!(
            self,
            Self::Settings | Self::CancelPush | Self::GoAway | Self::MaxPushId | Self::Unknown(_)
        )
    }
}

/// L'en-tête d'une trame : son type et sa longueur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Le type.
    kind: FrameKind,
    /// Ce que la charge occupe.
    length: u64,
    /// Ce que l'en-tête lui-même a occupé.
    header_len: usize,
}

impl FrameHeader {
    /// Lit un en-tête de trame.
    ///
    /// # ON REND LA LONGUEUR SANS EXIGER QUE LA CHARGE SOIT LÀ
    ///
    /// Une trame `DATA` peut faire des mébioctets, et un flux QUIC les livre par
    /// morceaux. Exiger la charge entière pour lire l'en-tête obligerait à
    /// accumuler tout un corps avant d'en connaître la taille — c'est-à-dire à
    /// accumuler ce qu'on n'a pas encore décidé d'accepter.
    ///
    /// # Errors
    ///
    /// [`Reason::Truncated`] si l'en-tête n'est pas complet ;
    /// [`Reason::ReservedH2Frame`] pour un type que §11.2.1 écarte.
    pub fn parse(octets: &[u8]) -> Result<Self, Error> {
        let tronque = || Error::new(Reason::Truncated);
        let (identifiant, lus) = varints::decode(octets).map_err(|_| tronque())?;
        let suite = octets.get(lus..).unwrap_or_default();
        let (length, encore) = varints::decode(suite).map_err(|_| tronque())?;
        Ok(Self {
            kind: FrameKind::from_wire(identifiant)?,
            length,
            header_len: lus.saturating_add(encore),
        })
    }

    /// Le type.
    #[must_use]
    pub const fn kind(&self) -> FrameKind {
        self.kind
    }

    /// Ce que la charge occupe.
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// Ce que l'en-tête a occupé.
    #[must_use]
    pub const fn header_len(&self) -> usize {
        self.header_len
    }

    /// Ce que la trame entière occupe, en octets.
    ///
    /// # ELLE REND UN `u64`, ET NON UN `usize`
    ///
    /// Une trame peut annoncer 2^62 octets là où un `usize` de trente-deux bits
    /// en tient 2^32. Rendre un `usize` obligerait à choisir entre mentir sur la
    /// taille et rendre une option qu'aucune cible de soixante-quatre bits ne
    /// peut voir manquer — c'est-à-dire une garde inatteignable ici, et une
    /// troncature ailleurs. Le `u64` dit la vérité partout, et c'est à
    /// l'appelant de décider ce qu'il en fait.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.length
            .saturating_add(u64::try_from(self.header_len).unwrap_or(u64::MAX))
    }

    /// Cette trame a-t-elle sa place ici ?
    ///
    /// # Errors
    ///
    /// [`Reason::FrameOnWrongStream`] — §7.2 attache chaque type à un flux, et
    /// une trame ailleurs veut dire que le pair a perdu le fil.
    pub fn check_stream(&self, ou: Placement) -> Result<(), Error> {
        let admise = match ou {
            Placement::Request => self.kind.sur_une_requete(),
            Placement::Control => self.kind.sur_le_controle(),
        };
        match admise {
            true => Ok(()),
            false => Err(Error::new(Reason::FrameOnWrongStream)),
        }
    }
}

/// Où une trame est arrivée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// Un flux de requête, bidirectionnel.
    Request,
    /// Le flux de contrôle, unidirectionnel.
    Control,
}

/// Écrit l'en-tête d'une trame : son type, puis sa longueur (§7.1).
///
/// Rend combien d'octets ont été écrits.
///
/// # POURQUOI L'EN-TÊTE SEUL, ET NON LA TRAME ENTIÈRE
///
/// Une trame `DATA` porte un corps qui peut faire des mébioctets, et qu'on
/// n'a aucune raison de recopier pour l'envoyer. L'appelant écrit donc l'en-tête
/// ici, puis pousse sa charge derrière — c'est ce qui permet de servir un fichier
/// sans le tenir deux fois en mémoire.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`] si la place manque.
pub fn write_header(kind: FrameKind, length: u64, out: &mut [u8]) -> Result<usize, Error> {
    let ecrits =
        varints::encode(kind.value(), out).map_err(|_| Error::new(Reason::BufferTooSmall))?;
    // `encode` vient d'écrire `ecrits` octets dans `out` : la tranche existe,
    // fût-elle vide. Un `?` ici serait une garde qu'aucun essai n'atteindrait —
    // et si elle est vide, c'est l'écriture suivante qui dira que la place
    // manque.
    let reste = out.get_mut(ecrits..).unwrap_or_default();
    let puis = varints::encode(length, reste).map_err(|_| Error::new(Reason::BufferTooSmall))?;
    Ok(ecrits.saturating_add(puis))
}

#[cfg(test)]
mod tests;
