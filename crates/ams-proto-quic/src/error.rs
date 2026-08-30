// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les fautes, et les codes que RFC 9000 §20 leur donne.
//!
//! # UN CODE PAR FAUTE, ET IL NE SE CHOISIT PAS À L'APPEL
//!
//! Chaque raison porte le code que la RFC lui donne, et l'appelant ne le choisit
//! pas. Laisser le choix au site d'appel, c'est laisser deux endroits nommer
//! deux codes différents pour la même faute — et le pair, lui, n'en verra qu'un.

/// Un code d'erreur de transport (§20.1).
///
/// **Ce sont ceux qu'on ÉCRIT SUR LE FIL**, dans un `CONNECTION_CLOSE`. Les
/// codes applicatifs (§20.2) sont d'un autre espace, et viennent de la couche
/// du dessus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// `NO_ERROR` (0x00) — on ferme, et tout allait bien.
    NoError,
    /// `INTERNAL_ERROR` (0x01) — **notre** faute, pas celle du pair.
    InternalError,
    /// `CONNECTION_REFUSED` (0x02).
    ConnectionRefused,
    /// `FLOW_CONTROL_ERROR` (0x03) — le pair a dépassé ce qu'on lui a ouvert.
    FlowControlError,
    /// `STREAM_LIMIT_ERROR` (0x04) — plus de flux qu'on n'en a permis.
    StreamLimitError,
    /// `STREAM_STATE_ERROR` (0x05) — une trame sur un flux qui ne pouvait pas la
    /// recevoir.
    StreamStateError,
    /// `FINAL_SIZE_ERROR` (0x06) — la taille finale d'un flux a changé.
    ///
    /// C'est la contradiction que QUIC refuse pour la même raison qu'HTTP/2
    /// refuse deux longueurs : **une seule source dit où un flux s'arrête.**
    FinalSizeError,
    /// `FRAME_ENCODING_ERROR` (0x07) — une trame mal écrite.
    FrameEncodingError,
    /// `TRANSPORT_PARAMETER_ERROR` (0x08).
    TransportParameterError,
    /// `CONNECTION_ID_LIMIT_ERROR` (0x09).
    ConnectionIdLimitError,
    /// `PROTOCOL_VIOLATION` (0x0a) — tout ce qui n'a pas de nom plus précis.
    ProtocolViolation,
    /// `INVALID_TOKEN` (0x0b).
    InvalidToken,
    /// `APPLICATION_ERROR` (0x0c).
    ApplicationError,
    /// `CRYPTO_BUFFER_EXCEEDED` (0x0d).
    CryptoBufferExceeded,
    /// `KEY_UPDATE_ERROR` (0x0e).
    KeyUpdateError,
    /// `AEAD_LIMIT_REACHED` (0x0f) — on a chiffré autant qu'il est prudent.
    AeadLimitReached,
    /// `NO_VIABLE_PATH` (0x10).
    NoViablePath,
}

impl TransportError {
    /// Le code sur le fil.
    #[must_use]
    pub const fn value(self) -> u64 {
        match self {
            Self::NoError => 0x00,
            Self::InternalError => 0x01,
            Self::ConnectionRefused => 0x02,
            Self::FlowControlError => 0x03,
            Self::StreamLimitError => 0x04,
            Self::StreamStateError => 0x05,
            Self::FinalSizeError => 0x06,
            Self::FrameEncodingError => 0x07,
            Self::TransportParameterError => 0x08,
            Self::ConnectionIdLimitError => 0x09,
            Self::ProtocolViolation => 0x0a,
            Self::InvalidToken => 0x0b,
            Self::ApplicationError => 0x0c,
            Self::CryptoBufferExceeded => 0x0d,
            Self::KeyUpdateError => 0x0e,
            Self::AeadLimitReached => 0x0f,
            Self::NoViablePath => 0x10,
        }
    }
}

/// Ce qui a mal tourné, précisément.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Les octets annoncés ne sont pas tous là.
    Truncated,
    /// Un entier dépasse 2^62 - 1, que §16 ne peut pas écrire.
    VarintTooLarge,
    /// Le tampon de sortie ne suffit pas. **Notre faute, pas celle du pair.**
    BufferTooSmall,
    /// Une longueur de numéro de paquet hors de un..=quatre (§17.1).
    BadPacketNumberLength,
    /// Un numéro de paquet dépasse 2^62 - 1.
    PacketNumberTooLarge,
    /// Un identifiant de connexion dépasse vingt octets (§17.2).
    ConnectionIdTooLong,
    /// Ce n'est pas un paquet QUIC de cette version : forme ou bit fixe.
    NotAPacket,
    /// Un type de trame que §19 ne définit pas, et qu'on n'a pas négocié.
    UnknownFrame,
    /// Un champ de trame hors de ses bornes.
    BadFrameField,
    /// Un intervalle d'acquittement qui descend sous zéro (§19.3.1).
    BadAckRange,
    /// L'espace des numéros de paquet est épuisé (§12.3).
    ///
    /// **§12.3 EXIGE QUE LA CONNEXION SOIT FERMÉE AVANT D'EN ARRIVER LÀ.** Un
    /// numéro doit tenir dans le champ `Largest Acknowledged` d'un `ACK`, et il
    /// n'y a donc pas de suivant. Qu'on nous demande quand même de reconstruire
    /// veut dire que quelqu'un a manqué cette fermeture — chez nous.
    PacketNumberSpaceExhausted,
}

impl Reason {
    /// Le code de §20.1 qui va avec.
    ///
    /// # POURQUOI IL EST ATTACHÉ ICI, ET NON AU SITE D'APPEL
    ///
    /// Une même faute rencontrée à deux endroits doit porter le même code : le
    /// pair n'en verra qu'un, et deux noms pour une faute rendraient ses
    /// journaux illisibles. L'attacher à la raison, c'est n'avoir qu'un endroit
    /// à corriger le jour où la RFC en change.
    #[must_use]
    pub const fn code(self) -> TransportError {
        match self {
            // §12.4 : une trame qu'on ne peut pas lire jusqu'au bout.
            Self::Truncated
            | Self::BadPacketNumberLength
            | Self::UnknownFrame
            | Self::BadFrameField
            | Self::BadAckRange => TransportError::FrameEncodingError,
            // §17.2 dit de JETER le paquet, pas de fermer la connexion — il
            // peut venir de n'importe qui, et une connexion qu'on ferme sur un
            // paquet égaré est une connexion qu'un tiers peut fermer.
            Self::ConnectionIdTooLong | Self::NotAPacket => TransportError::ProtocolViolation,
            // **CELLES-CI SONT LES NÔTRES.** Un tampon trop court est un défaut
            // de dimensionnement chez nous, et un entier hors borne est une
            // valeur que notre code a fabriquée : le pair n'a rien fait de mal,
            // et lui imputer la faute rendrait son journal mensonger.
            Self::BufferTooSmall
            | Self::VarintTooLarge
            | Self::PacketNumberTooLarge
            | Self::PacketNumberSpaceExhausted => TransportError::InternalError,
        }
    }
}

/// Une faute, avec ce qu'on en dira au pair.
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

    /// Le code qu'on écrira dans un `CONNECTION_CLOSE`.
    #[must_use]
    pub const fn code(self) -> TransportError {
        self.reason.code()
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let quoi = match self.reason {
            Reason::Truncated => "les octets annoncés ne sont pas tous là",
            Reason::VarintTooLarge => "un entier dépasse ce que §16 peut écrire",
            Reason::BufferTooSmall => "le tampon de sortie ne suffit pas",
            Reason::BadPacketNumberLength => "une longueur de numéro de paquet hors de un à quatre",
            Reason::PacketNumberTooLarge => "un numéro de paquet dépasse 2^62 - 1",
            Reason::ConnectionIdTooLong => "un identifiant de connexion dépasse vingt octets",
            Reason::NotAPacket => "ce n'est pas un paquet QUIC de cette version",
            Reason::UnknownFrame => "un type de trame qu'on n'a pas négocié",
            Reason::BadFrameField => "un champ de trame hors de ses bornes",
            Reason::BadAckRange => "un intervalle d'acquittement descend sous zéro",
            Reason::PacketNumberSpaceExhausted => {
                "l'espace des numéros de paquet est épuisé, et §12.3 veut qu'on ferme"
            }
        };
        write!(f, "{quoi} (code 0x{:02x})", self.code().value())
    }
}

#[cfg(test)]
mod tests;
