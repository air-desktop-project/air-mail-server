// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que la réception d'un paquet peut refuser.
//!
//! # DEUX FAÇONS DE REFUSER, ET ELLES NE SE VALENT PAS
//!
//! Un paquet peut se JETER, ou condamner la connexion. La distinction n'est pas
//! de degré : le port est ouvert au monde entier, et **fermer une connexion sur
//! un paquet qu'on n'a pas pu authentifier l'offrirait à qui sait envoyer un
//! datagramme**.
//!
//! On ne condamne donc que ce qui vient d'un pair AUTHENTIFIÉ — c'est-à-dire ce
//! qu'on découvre APRÈS avoir déchiffré.

use ams_proto_quic::TransportError;

/// Ce qui a mal tourné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Ce n'est pas un paquet qu'on sache lire : forme, version, ou troncature.
    ///
    /// **IL SE JETTE, EN SILENCE.**
    NotForUs,
    /// Le paquet ne s'authentifie pas. **Il se jette aussi.**
    NotAuthentic,
    /// Les bits réservés ne sont pas nuls (§17.2, §17.3.1).
    ///
    /// **CELLE-CI CONDAMNE**, parce qu'on ne la découvre qu'après avoir
    /// déchiffré : le pair est authentifié, et il parle mal.
    ReservedBitsSet,
    /// Le numéro de paquet ne se reconstruit pas.
    ///
    /// §12.3 : l'espace des numéros s'épuise, et la connexion doit être fermée
    /// avant d'y arriver. Qu'on nous demande de reconstruire quand même veut
    /// dire qu'on a manqué cette fermeture.
    BadPacketNumber,
    /// Le pair a dépassé ce qu'on lui avait ouvert (§4.1).
    FlowControl,
    /// La taille finale d'un flux a changé, ou des octets arrivent au-delà
    /// (§4.5).
    ///
    /// **C'EST LA MÊME CONTRADICTION QU'UNE DOUBLE LONGUEUR EN HTTP/1.1** : deux
    /// façons de savoir où un flux s'arrête, et rien pour les départager. QUIC
    /// la refuse plutôt que de choisir.
    FinalSize,
    /// Un flux arrive dans un désordre plus grand que ce qu'on retient.
    ///
    /// **ON NE PEUT PAS RETIRER UN ACQUITTEMENT.** Un réassembleur qui jetterait
    /// ce qu'il ne peut pas ranger perdrait des octets en silence, et le flux se
    /// figerait sans que rien ne l'explique. On le dit, et l'on ferme.
    TooManyHoles,
    /// On a voulu émettre sur un flux qui n'émet plus (§3.1).
    ///
    /// **C'EST NOTRE FAUTE, ET NON CELLE DU PAIR.**
    SendClosed,
    /// On a voulu émettre au-delà de ce que le pair nous a ouvert (§4.1).
    ///
    /// **C'EST NOTRE FAUTE AUSSI**, et c'est celle qui compte : le pair
    /// fermerait la connexion sans autre explication. La rendre ici la fait voir
    /// en essai plutôt qu'en production.
    SendOverflow,
    /// Le pair a ouvert plus de flux qu'on ne lui en avait ouvert (§4.6).
    StreamLimit,
    /// Le pair écrit sur un flux où il n'a pas le droit d'écrire (§2.1).
    ///
    /// **UN FLUX UNIDIRECTIONNEL NE VA QUE DANS UN SENS**, et c'est celui de son
    /// auteur. Y écrire à contresens veut dire que le pair a mal compris à qui
    /// appartient le flux — donc que la suite ne sera pas ce qu'on croit.
    WrongStreamDirection,
    /// Le pair parle d'un flux que NOUS devions ouvrir, et que nous n'avons pas
    /// ouvert (§19.8).
    ///
    /// **CE N'EST PAS UN FLUX EN AVANCE, C'EST UN FLUX QUI N'EXISTE PAS.** §2.1
    /// donne à chaque côté ses propres numéros : celui qui ouvre est le seul à
    /// choisir quand. Un pair qui parle d'un numéro à nous qu'on n'a pas encore
    /// pris n'a pas pris de l'avance sur nous — il désigne quelque chose dont
    /// nous n'avons aucune idée, et la suite de la connexion ne sera pas ce
    /// qu'il croit.
    StreamNotCreated,
    /// Une trame est arrivée à un niveau de chiffrement qui ne l'admet pas
    /// (§12.4).
    ///
    /// **§12.4 EST UN TABLEAU, ET NON UNE INDICATION.** « An endpoint MUST treat
    /// receipt of a frame in a packet type that is not permitted as a connection
    /// error of type PROTOCOL_VIOLATION. » Une trame de flux dans un paquet de
    /// poignée de main veut dire que le pair croit la connexion ailleurs qu'elle
    /// n'est — et la servir quand même la ferait travailler sur des limites qui
    /// n'existent pas encore.
    FrameNotAllowed,
    /// La fenêtre de réassemblage ne fait pas la taille qu'on a annoncée.
    ///
    /// **C'EST NOTRE FAUTE, ET LA PIRE DE TOUTES** : sans ce refus, les octets
    /// qui ne tiennent pas disparaîtraient en silence, et le flux se figerait
    /// sans que rien ne l'explique.
    WindowTooSmall,
    /// Une trame `CRYPTO` dans un paquet `0-RTT` (§8.3 de RFC 9001).
    ///
    /// **C'EST PAR LÀ QU'UN `EndOfEarlyData` ENTRERAIT** dans la transcription
    /// de la poignée de main sans que personne ne l'ait autorisé. La RFC nomme
    /// ce cas, et elle le condamne.
    CryptoInZeroRtt,
    /// De la matière NOUVELLE à un niveau de chiffrement déjà dépassé (§4.1.3).
    ///
    /// Une retransmission de ce qu'on a déjà vu reste licite — elle est même
    /// attendue, puisque les acquittements se croisent. Ce qui est refusé, c'est
    /// ce qui étend le flux d'un niveau que TLS a quitté : cela entrerait dans
    /// une transcription que le pair croit close.
    CryptoAfterLevel,
    /// Des clés d'un niveau supérieur alors qu'un niveau inférieur a encore des
    /// octets non consommés (§4.1.3).
    ///
    /// **CE QUE LES DEUX CÔTÉS ONT HACHÉ DIFFÉRERAIT** — précisément ce que la
    /// poignée de main est censée rendre impossible.
    CryptoNotConsumed,
    /// Plus d'octets `CRYPTO` hors d'ordre qu'on ne peut en retenir (§7.5 de
    /// RFC 9000).
    ///
    /// **ET CE N'EST PAS UNE FAUTE INTERNE**, contrairement à
    /// [`Reason::WindowTooSmall`] : il n'y a pas de contrôle de flux sur
    /// `CRYPTO`, donc rien n'avait annoncé de limite au pair — mais la RFC lui a
    /// quand même donné un code, parce que la borne devait bien exister quelque
    /// part.
    CryptoBufferExceeded,
    /// On a voulu émettre deux fois le même numéro de paquet (§12.3 de
    /// RFC 9000).
    ///
    /// **C'EST NOTRE FAUTE, ET ELLE SE TAIRAIT SANS CE REFUS.** « A QUIC
    /// endpoint MUST NOT reuse a packet number within the same packet number
    /// space. » Deux entrées pour un même numéro font compter deux fois les
    /// mêmes octets à l'acquittement, et la comptabilité des octets en vol
    /// dérive — ce qui se voit dans un débit qui s'écroule, jamais dans un
    /// journal.
    PacketNumberReused,
}

impl Reason {
    /// Le code qu'on écrirait en fermant — `None` pour ce qui se jette.
    ///
    /// # UN PAQUET QU'ON JETTE N'A PAS DE CODE
    ///
    /// Il n'y a personne à qui l'imputer : il peut venir de n'importe qui, et
    /// le port est ouvert au monde entier. Rendre `None` le dit ; rendre un code
    /// qu'on n'enverra jamais laisserait croire le contraire.
    #[must_use]
    pub const fn code(self) -> Option<TransportError> {
        match self {
            Self::NotForUs | Self::NotAuthentic => None,
            // §17.2 et §12.3 les nomment : ce sont des pairs authentifiés qui
            // parlent mal.
            Self::ReservedBitsSet | Self::BadPacketNumber | Self::FrameNotAllowed => {
                Some(TransportError::ProtocolViolation)
            }
            Self::FlowControl => Some(TransportError::FlowControlError),
            Self::FinalSize => Some(TransportError::FinalSizeError),
            // **CELLE-CI EST NOTRE BORNE, PAS LA SIENNE.** Un pair honnête ne
            // l'atteint pas ; le lui reprocher comme une faute de contrôle de
            // flux serait lui imputer une limite qu'on ne lui a pas annoncée.
            Self::TooManyHoles | Self::SendClosed | Self::SendOverflow | Self::WindowTooSmall => {
                Some(TransportError::InternalError)
            }
            Self::StreamLimit => Some(TransportError::StreamLimitError),
            Self::WrongStreamDirection | Self::StreamNotCreated => {
                Some(TransportError::StreamStateError)
            }
            // §4.1.3 et §8.3 de RFC 9001 : trois façons de parler mal entre les
            // niveaux, et la même sanction.
            Self::CryptoInZeroRtt | Self::CryptoAfterLevel | Self::CryptoNotConsumed => {
                Some(TransportError::ProtocolViolation)
            }
            Self::CryptoBufferExceeded => Some(TransportError::CryptoBufferExceeded),
            // §12.3 nous l'interdit à NOUS : le pair n'y est pour rien.
            Self::PacketNumberReused => Some(TransportError::InternalError),
        }
    }

    /// Ce paquet se jette-t-il sans rien dire ?
    ///
    /// §5.3 de RFC 9001 : « An endpoint MUST discard packets that cannot be
    /// authenticated. » Jeter n'est pas une indulgence : c'est ce qui empêche un
    /// tiers de fermer une connexion qui ne lui appartient pas.
    ///
    /// **C'EST LA MÊME QUESTION QUE `code`**, posée autrement : une faute qui se
    /// jette est exactement une faute sans code. Deux réponses séparées auraient
    /// pu diverger.
    #[must_use]
    pub const fn se_jette(self) -> bool {
        self.code().is_none()
    }
}

/// Une faute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    /// Ce qui a mal tourné.
    reason: Reason,
}

impl Error {
    /// La faute qui va avec cette raison.
    #[must_use]
    pub const fn new(reason: Reason) -> Self {
        Self { reason }
    }

    /// Ce qui a mal tourné.
    #[must_use]
    pub const fn reason(self) -> Reason {
        self.reason
    }

    /// Ce paquet se jette-t-il sans rien dire ?
    #[must_use]
    pub const fn se_jette(self) -> bool {
        self.reason.se_jette()
    }

    /// Le code qu'on écrirait en fermant — `None` pour ce qui se jette.
    #[must_use]
    pub const fn code(self) -> Option<TransportError> {
        self.reason.code()
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let quoi = match self.reason {
            Reason::NotForUs => "ce n'est pas un paquet qu'on sache lire",
            Reason::NotAuthentic => "le paquet ne s'authentifie pas",
            Reason::ReservedBitsSet => "les bits réservés ne sont pas nuls",
            Reason::BadPacketNumber => "le numéro de paquet ne se reconstruit pas",
            Reason::FlowControl => "le pair a dépassé ce qu'on lui avait ouvert",
            Reason::FinalSize => "la taille finale d'un flux se contredit",
            Reason::TooManyHoles => "un flux arrive dans un désordre qu'on ne retient pas",
            Reason::SendClosed => "on a voulu émettre sur un flux qui n'émet plus",
            Reason::SendOverflow => "on a voulu émettre au-delà de ce qui nous est ouvert",
            Reason::StreamLimit => "le pair a ouvert plus de flux qu'on ne lui en a ouvert",
            Reason::WrongStreamDirection => "le pair écrit sur un flux à contresens",
            Reason::FrameNotAllowed => "une trame est arrivée à un niveau qui ne l'admet pas",
            Reason::StreamNotCreated => "le pair parle d'un flux qu'on n'a pas ouvert",
            Reason::WindowTooSmall => "la fenêtre ne fait pas la taille annoncée",
            Reason::CryptoInZeroRtt => "une trame CRYPTO dans un paquet 0-RTT",
            Reason::CryptoAfterLevel => "du neuf à un niveau de chiffrement déjà dépassé",
            Reason::CryptoNotConsumed => "des clés plus hautes, et des octets non lus plus bas",
            Reason::CryptoBufferExceeded => "plus de CRYPTO hors d'ordre qu'on n'en retient",
            Reason::PacketNumberReused => "on a voulu réemployer un numéro de paquet",
        };
        let suite = match self.se_jette() {
            true => "on le jette",
            false => "on ferme",
        };
        write!(f, "{quoi} — {suite}")
    }
}

#[cfg(test)]
mod tests;
