// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les codes d'erreur d'HTTP/3 (RFC 9114 §8.1) et de QPACK (RFC 9204 §6).
//!
//! # ILS VIVENT DANS L'ESPACE APPLICATIF DE QUIC, ET NON DANS LE SIEN
//!
//! QUIC a ses propres codes (§20.1 de RFC 9000) ; ceux-ci voyagent dans un
//! `CONNECTION_CLOSE` de type applicatif, ou dans un `RESET_STREAM`. Les deux
//! espaces se recouvrent entièrement — c'est le TYPE de la trame qui dit
//! lequel on lit, jamais la valeur.

/// Un code d'erreur HTTP/3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3Error {
    /// `H3_NO_ERROR` (0x0100) — on ferme, et tout allait bien.
    NoError,
    /// `H3_GENERAL_PROTOCOL_ERROR` (0x0101) — ce qui n'a pas de nom plus précis.
    GeneralProtocolError,
    /// `H3_INTERNAL_ERROR` (0x0102) — **notre** faute, pas celle du pair.
    InternalError,
    /// `H3_STREAM_CREATION_ERROR` (0x0103).
    StreamCreationError,
    /// `H3_CLOSED_CRITICAL_STREAM` (0x0104) — un flux qu'on ne peut pas perdre
    /// a été fermé.
    ClosedCriticalStream,
    /// `H3_FRAME_UNEXPECTED` (0x0105) — une trame sur un flux qui ne peut pas la
    /// porter.
    FrameUnexpected,
    /// `H3_FRAME_ERROR` (0x0106) — une trame mal formée.
    FrameError,
    /// `H3_EXCESSIVE_LOAD` (0x0107) — le pair en fait trop.
    ExcessiveLoad,
    /// `H3_ID_ERROR` (0x0108) — un identifiant hors de ses bornes.
    IdError,
    /// `H3_SETTINGS_ERROR` (0x0109).
    SettingsError,
    /// `H3_MISSING_SETTINGS` (0x010a) — le flux de contrôle n'a pas commencé par
    /// ses réglages.
    MissingSettings,
    /// `H3_REQUEST_REJECTED` (0x010b) — **une promesse** : rien n'a été
    /// commencé, et le client peut réémettre ailleurs.
    RequestRejected,
    /// `H3_REQUEST_CANCELLED` (0x010c).
    RequestCancelled,
    /// `H3_REQUEST_INCOMPLETE` (0x010d).
    RequestIncomplete,
    /// `H3_MESSAGE_ERROR` (0x010e) — la requête ne fait pas un message.
    MessageError,
    /// `H3_CONNECT_ERROR` (0x010f).
    ConnectError,
    /// `H3_VERSION_FALLBACK` (0x0110) — « reprends en HTTP/1.1 ».
    VersionFallback,
    /// `QPACK_DECOMPRESSION_FAILED` (0x0200) — la table n'est plus la même des
    /// deux côtés, et plus rien ne se lira.
    QpackDecompressionFailed,
    /// `QPACK_ENCODER_STREAM_ERROR` (0x0201).
    QpackEncoderStreamError,
    /// `QPACK_DECODER_STREAM_ERROR` (0x0202).
    QpackDecoderStreamError,
}

impl H3Error {
    /// Le code sur le fil.
    #[must_use]
    pub const fn value(self) -> u64 {
        match self {
            Self::NoError => 0x0100,
            Self::GeneralProtocolError => 0x0101,
            Self::InternalError => 0x0102,
            Self::StreamCreationError => 0x0103,
            Self::ClosedCriticalStream => 0x0104,
            Self::FrameUnexpected => 0x0105,
            Self::FrameError => 0x0106,
            Self::ExcessiveLoad => 0x0107,
            Self::IdError => 0x0108,
            Self::SettingsError => 0x0109,
            Self::MissingSettings => 0x010a,
            Self::RequestRejected => 0x010b,
            Self::RequestCancelled => 0x010c,
            Self::RequestIncomplete => 0x010d,
            Self::MessageError => 0x010e,
            Self::ConnectError => 0x010f,
            Self::VersionFallback => 0x0110,
            Self::QpackDecompressionFailed => 0x0200,
            Self::QpackEncoderStreamError => 0x0201,
            Self::QpackDecoderStreamError => 0x0202,
        }
    }
}

/// Ce qui a mal tourné, précisément.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Les octets annoncés ne sont pas tous là.
    Truncated,
    /// Le tampon de sortie ne suffit pas. **Notre faute, pas celle du pair.**
    BufferTooSmall,
    /// Un type de trame que RFC 9114 a RÉSERVÉ pour empêcher qu'on confonde
    /// HTTP/2 et HTTP/3 (§11.2.1).
    ReservedH2Frame,
    /// Une trame sur un flux qui ne peut pas la porter (§7.2).
    FrameOnWrongStream,
    /// Une trame mal formée : longueur, ou champ hors borne.
    MalformedFrame,
    /// Un réglage que RFC 9114 a réservé, ou répété (§7.2.4).
    BadSetting,
    /// Un type de flux qu'on ne sait pas conduire.
    UnknownStreamType,
    /// Un identifiant de poussée, alors qu'on n'en accepte aucune.
    PushRefused,
    /// Un compte d'insertions QPACK qui ne se reconstruit pas (§4.5.1.1).
    BadInsertCount,
    /// Une représentation de champ QPACK mal formée (§4.5).
    BadFieldLine,
    /// Un index QPACK qui ne désigne aucune entrée.
    BadIndex,
    /// Une instruction de flux d'encodeur mal formée (§4.3).
    BadEncoderInstruction,
    /// Une instruction de flux de décodeur qu'on ne peut pas écrire (§4.4).
    BadDecoderInstruction,
    /// Un accusé de décodeur que ce qu'on a envoyé ne justifie pas (§4.4.1,
    /// §4.4.3).
    ///
    /// **CE N'EST PAS UNE FAUTE DE FORME** : l'instruction se lit très bien.
    /// Elle accuse réception de ce que nous n'avons jamais émis, et les deux
    /// tables ne décrivent donc plus le même état.
    UnexpectedDecoderInstruction,
    /// Une insertion dans une table dynamique qu'on a annoncée nulle (§3.2.3).
    DynamicTableRefused,
    /// Une section de champs qui ne fait pas une requête (§4.1.2 de RFC 9114).
    MalformedRequest,
    /// Un champ de réponse que ce serveur refuse d'écrire.
    BadResponseField,
    /// Un second flux critique du même type (§6.2.1, §4.2 de RFC 9204).
    ///
    /// **DEUX FLUX DE CONTRÔLE PRÉTENDRAIENT DÉCRIRE LE MÊME ÉTAT**, et rien ne
    /// dirait lequel croire.
    DuplicateCriticalStream,
    /// Un flux critique s'est fermé (§6.2.1, §4.2 de RFC 9204).
    CriticalStreamClosed,
    /// Le flux de contrôle n'a pas commencé par ses réglages (§6.2.1).
    MissingSettings,
    /// Un second `SETTINGS` sur le flux de contrôle (§7.2.4).
    RepeatedSettings,
    /// Une suite de trames que §4.1 interdit sur un flux de requête.
    FrameOutOfOrder,
    /// Un `GOAWAY` dont l'identifiant MONTE (§5.2).
    ///
    /// **UN CLIENT A PU RÉÉMETTRE AILLEURS** les requêtes qu'un `GOAWAY`
    /// précédent avait déclarées perdues ; les réaccepter les ferait exécuter
    /// deux fois.
    GoAwayIncreased,
    /// Le pair n'envoie plus que des trames qui ne font rien avancer.
    ServiceFlood,
    /// Un flux de requête s'est fermé avant de faire un message (§4.1).
    IncompleteRequest,
}

impl Reason {
    /// Le code de §8.1 qui va avec.
    #[must_use]
    pub const fn code(self) -> H3Error {
        match self {
            Self::Truncated | Self::MalformedFrame => H3Error::FrameError,
            // **NOTRE TAMPON, NOTRE FAUTE** : le pair n'a rien fait de mal, et
            // lui imputer la faute rendrait son journal mensonger.
            Self::BufferTooSmall => H3Error::InternalError,
            Self::ReservedH2Frame | Self::FrameOnWrongStream => H3Error::FrameUnexpected,
            Self::BadSetting => H3Error::SettingsError,
            Self::UnknownStreamType => H3Error::StreamCreationError,
            Self::PushRefused => H3Error::IdError,
            // §6 de RFC 9204 : quand la table n'est plus la même des deux
            // côtés, plus rien ne se lira — et il n'y a pas de reprise
            // possible, seulement une fermeture.
            Self::BadInsertCount | Self::BadFieldLine | Self::BadIndex => {
                H3Error::QpackDecompressionFailed
            }
            // §6 nomme un code par FLUX : le pair doit savoir lequel de ses deux
            // flux QPACK a fauté, et non seulement que l'un des deux l'a fait.
            Self::BadEncoderInstruction | Self::DynamicTableRefused => {
                H3Error::QpackEncoderStreamError
            }
            Self::BadDecoderInstruction | Self::UnexpectedDecoderInstruction => {
                H3Error::QpackDecoderStreamError
            }
            // §4.1.2 : une requête bien décomprimée qui ne fait pas un message
            // ne condamne que son flux. La connexion, elle, n'a rien perdu.
            Self::MalformedRequest => H3Error::MessageError,
            // **NOTRE CODE A PROPOSÉ CE CHAMP, PAS LE PAIR.**
            Self::BadResponseField => H3Error::InternalError,
            Self::DuplicateCriticalStream => H3Error::StreamCreationError,
            Self::CriticalStreamClosed => H3Error::ClosedCriticalStream,
            Self::MissingSettings => H3Error::MissingSettings,
            // §7.2.4 et §4.1 emploient le même code pour deux fautes de même
            // nature : une trame là où la suite n'en attendait pas.
            Self::RepeatedSettings | Self::FrameOutOfOrder => H3Error::FrameUnexpected,
            Self::GoAwayIncreased => H3Error::IdError,
            Self::ServiceFlood => H3Error::ExcessiveLoad,
            // §4.1 : celle-ci ne condamne que le flux. Un client qui abandonne
            // sa requête en route n'a pas cassé la connexion.
            Self::IncompleteRequest => H3Error::RequestIncomplete,
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

    /// Le code applicatif qu'on écrira.
    #[must_use]
    pub const fn code(self) -> H3Error {
        self.reason.code()
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let quoi = match self.reason {
            Reason::Truncated => "les octets annoncés ne sont pas tous là",
            Reason::BufferTooSmall => "le tampon de sortie ne suffit pas",
            Reason::ReservedH2Frame => "un type de trame réservé pour écarter HTTP/2",
            Reason::FrameOnWrongStream => "une trame sur un flux qui ne peut pas la porter",
            Reason::MalformedFrame => "une trame mal formée",
            Reason::BadSetting => "un réglage réservé, ou répété",
            Reason::UnknownStreamType => "un type de flux qu'on ne sait pas conduire",
            Reason::PushRefused => "une poussée, alors qu'on n'en accepte aucune",
            Reason::BadInsertCount => "un compte d'insertions qui ne se reconstruit pas",
            Reason::BadFieldLine => "une représentation de champ mal formée",
            Reason::BadIndex => "un index qui ne désigne aucune entrée",
            Reason::BadEncoderInstruction => "une instruction d'encodeur mal formée",
            Reason::BadDecoderInstruction => "une instruction de décodeur qu'on ne peut pas écrire",
            Reason::UnexpectedDecoderInstruction => {
                "un accusé de décodeur que ce qu'on a envoyé ne justifie pas"
            }
            Reason::DynamicTableRefused => "une insertion dans une table qu'on a annoncée nulle",
            Reason::MalformedRequest => "une section de champs qui ne fait pas une requête",
            Reason::BadResponseField => "un champ de réponse qu'on refuse d'écrire",
            Reason::DuplicateCriticalStream => "un second flux critique du même type",
            Reason::CriticalStreamClosed => "un flux critique s'est fermé",
            Reason::MissingSettings => "le flux de contrôle n'a pas commencé par ses réglages",
            Reason::RepeatedSettings => "un second `SETTINGS` sur le flux de contrôle",
            Reason::FrameOutOfOrder => "une suite de trames que §4.1 interdit",
            Reason::GoAwayIncreased => "un `GOAWAY` dont l'identifiant monte",
            Reason::ServiceFlood => "le pair n'envoie plus que ce qui ne fait rien avancer",
            Reason::IncompleteRequest => "un flux de requête fermé avant de faire un message",
        };
        write!(f, "{quoi} (code 0x{:04x})", self.code().value())
    }
}

#[cfg(test)]
mod tests;
