// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les flux d'HTTP/3 (RFC 9114 §6).
//!
//! # UN SEUL FLUX PAR REQUÊTE, ET IL N'Y A PLUS DE MULTIPLEXAGE À ÉCRIRE
//!
//! En HTTP/2, un flux était une abstraction que le protocole devait construire
//! au-dessus d'une connexion TCP unique — d'où les numéros, les états, le
//! contrôle de flux par flux, et le blocage de tête de ligne qu'on n'a jamais
//! pu retirer. En HTTP/3, le flux vient de QUIC : une requête est un flux
//! bidirectionnel, et c'est tout.
//!
//! **Ce qui disparaît ainsi est considérable** : la perte d'un paquet ne bloque
//! plus que le flux auquel il appartenait, et non tous les autres.
//!
//! # LES FLUX UNIDIRECTIONNELS DISENT LEUR TYPE, UNE FOIS, EN TÊTE
//!
//! §6.2 : le premier entier d'un flux unidirectionnel dit ce qu'il est. Il n'y a
//! pas de renégociation, pas de changement en cours de route : un flux est ce
//! qu'il a annoncé être, du premier octet au dernier.
//!
//! Et **un type inconnu ne condamne pas la connexion** : §6.2 demande d'ABANDONNER
//! le flux, pas la connexion. C'est ce qui permet à une extension d'ouvrir ses
//! propres flux sans casser les pairs qui ne la connaissent pas.

use ams_proto_quic::varints;

use crate::error::{Error, Reason};

/// Ce qu'un flux unidirectionnel a annoncé être (§6.2, §11.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    /// Le flux de contrôle (0x00).
    ///
    /// **IL Y EN A UN SEUL PAR SENS, ET IL NE SE FERME PAS.** §6.2.1 : le
    /// fermer est une faute `H3_CLOSED_CRITICAL_STREAM` — la connexion
    /// n'aurait plus par où s'entendre.
    Control,
    /// Un flux de poussée (0x01).
    Push,
    /// Le flux d'encodeur QPACK (0x02).
    QpackEncoder,
    /// Le flux de décodeur QPACK (0x03).
    QpackDecoder,
    /// Un type qu'on ne connaît pas.
    ///
    /// **ON ABANDONNE LE FLUX, PAS LA CONNEXION** (§6.2) : c'est ce qui permet
    /// à une extension d'ouvrir ses propres flux sans casser les pairs qui ne la
    /// connaissent pas.
    Unknown(u64),
}

impl StreamKind {
    /// Le type que cet identifiant désigne.
    #[must_use]
    pub const fn from_wire(identifiant: u64) -> Self {
        match identifiant {
            0x00 => Self::Control,
            0x01 => Self::Push,
            0x02 => Self::QpackEncoder,
            0x03 => Self::QpackDecoder,
            autre => Self::Unknown(autre),
        }
    }

    /// L'identifiant sur le fil.
    #[must_use]
    pub const fn value(self) -> u64 {
        match self {
            Self::Control => 0x00,
            Self::Push => 0x01,
            Self::QpackEncoder => 0x02,
            Self::QpackDecoder => 0x03,
            Self::Unknown(autre) => autre,
        }
    }

    /// Ce flux est-il critique, au sens de §6.2.1 ?
    ///
    /// Un flux critique ne se ferme pas : sa fermeture est une faute de
    /// connexion, parce que la connexion n'aurait plus par où s'entendre.
    #[must_use]
    pub const fn est_critique(self) -> bool {
        matches!(
            self,
            Self::Control | Self::QpackEncoder | Self::QpackDecoder
        )
    }

    /// Ce serveur sait-il conduire ce flux ?
    ///
    /// # LA POUSSÉE N'EST PAS SERVIE, ET C'EST UNE DÉCISION
    ///
    /// Un flux de poussée est ouvert par le SERVEUR (§4.6). Un client qui en
    /// ouvrirait un prétendrait pousser vers nous — ce qui n'existe pas. Et ce
    /// serveur n'en émet pas : la poussée serveur a été retirée d'HTTP/2 faute
    /// d'usage, et rien ne justifie de la réintroduire.
    #[must_use]
    pub const fn servi(self) -> bool {
        matches!(
            self,
            Self::Control | Self::QpackEncoder | Self::QpackDecoder
        )
    }
}

/// Ce que la lecture de la tête d'un flux unidirectionnel a donné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamHead {
    /// Il en manque : lire davantage, puis rappeler.
    ///
    /// **UN TYPE PEUT S'ÉTALER SUR HUIT OCTETS**, et un flux QUIC les livre par
    /// morceaux. Refuser tant qu'ils ne sont pas tous là serait refuser un pair
    /// qui n'a rien fait de mal.
    More,
    /// Il est là, et occupe `read` octets.
    Ready {
        /// Ce que le flux a annoncé être.
        kind: StreamKind,
        /// Ce que l'annonce a occupé.
        read: usize,
    },
}

/// Lit le type d'un flux unidirectionnel.
///
/// # Errors
///
/// Aucune : un type inconnu est un type, et c'est à l'appelant d'abandonner le
/// flux. Le seul cas où l'on ne rend rien est celui d'un tampon incomplet, et
/// [`StreamHead::More`] le dit.
#[must_use]
pub fn read_stream_head(octets: &[u8]) -> StreamHead {
    match varints::decode(octets) {
        Ok((identifiant, read)) => StreamHead::Ready {
            kind: StreamKind::from_wire(identifiant),
            read,
        },
        Err(_) => StreamHead::More,
    }
}

/// Vérifie qu'on sait conduire ce flux.
///
/// # Errors
///
/// [`Reason::UnknownStreamType`] pour ce qu'on ne conduit pas, et
/// [`Reason::PushRefused`] pour une poussée — que ce serveur n'accepte ni
/// n'émet.
pub fn accept_stream(kind: StreamKind) -> Result<(), Error> {
    match kind {
        _ if kind.servi() => Ok(()),
        StreamKind::Push => Err(Error::new(Reason::PushRefused)),
        _ => Err(Error::new(Reason::UnknownStreamType)),
    }
}

#[cfg(test)]
mod tests;
