// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les codes d'erreur de §7, et ce qui rend un cadre irrecevable.

use core::fmt;

/// Un code d'erreur HTTP/2 (§7).
///
/// # CES CODES PARTENT SUR LE FIL, ET ILS SONT PEU BAVARDS
///
/// Un `GOAWAY` ou un `RST_STREAM` porte un de ces nombres, et rien d'autre que
/// ce que l'on choisit d'y ajouter en texte libre. Le pair n'apprend donc que la
/// FAMILLE de la faute — ce qui est voulu : lui dire précisément ce qui a raté
/// serait lui apprendre comment s'y prendre autrement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    /// `NO_ERROR` — arrêt ordinaire.
    NoError = 0x0,
    /// `PROTOCOL_ERROR` — le pair n'a pas respecté le protocole.
    ProtocolError = 0x1,
    /// `INTERNAL_ERROR` — c'est nous.
    InternalError = 0x2,
    /// `FLOW_CONTROL_ERROR` — une fenêtre a été franchie.
    FlowControlError = 0x3,
    /// `SETTINGS_TIMEOUT` — un `SETTINGS` n'a jamais été acquitté.
    SettingsTimeout = 0x4,
    /// `STREAM_CLOSED` — un cadre est arrivé sur un flux fermé.
    StreamClosed = 0x5,
    /// `FRAME_SIZE_ERROR` — la longueur annoncée n'est pas celle qu'il faut.
    FrameSizeError = 0x6,
    /// `REFUSED_STREAM` — le flux n'a pas été traité, et peut être rejoué.
    ///
    /// **CE CODE EST UNE PROMESSE** : §8.7 dit qu'un client peut réémettre sans
    /// risque ce qui a reçu `REFUSED_STREAM`. Le rendre pour un flux qu'on a
    /// commencé à traiter ferait exécuter deux fois ce qui ne devait l'être
    /// qu'une.
    RefusedStream = 0x7,
    /// `CANCEL` — le flux n'est plus nécessaire.
    Cancel = 0x8,
    /// `COMPRESSION_ERROR` — l'état HPACK est perdu.
    ///
    /// **CELUI-CI TUE LA CONNEXION, JAMAIS UN SEUL FLUX** : la table dynamique
    /// est partagée par tous, et un décodeur qui s'est trompé une fois ne saura
    /// plus lire aucun en-tête. Ne fermer que le flux laisserait la connexion
    /// vivante avec un état faux.
    CompressionError = 0x9,
    /// `CONNECT_ERROR` — un tunnel a échoué. Ce serveur n'en ouvre pas.
    ConnectError = 0xa,
    /// `ENHANCE_YOUR_CALM` — le pair en demande trop.
    EnhanceYourCalm = 0xb,
    /// `INADEQUATE_SECURITY` — la connexion sous-jacente ne suffit pas.
    InadequateSecurity = 0xc,
    /// `HTTP_1_1_REQUIRED` — il faudrait HTTP/1.1.
    ///
    /// Ce serveur ne le rend jamais : il ne sert pas HTTP/1.1, et l'annoncer
    /// enverrait le client vers une porte qui n'existe pas.
    Http11Required = 0xd,
}

impl ErrorCode {
    /// La valeur sur le fil.
    #[must_use]
    pub const fn value(self) -> u32 {
        self as u32
    }

    /// Lit un code reçu.
    ///
    /// # UN CODE INCONNU DEVIENT `INTERNAL_ERROR`, ET NE FAIT PAS ÉCHOUER
    ///
    /// §7 : « Unknown or unsupported error codes MUST NOT trigger any special
    /// behavior. These MAY be treated by an implementation as being equivalent
    /// to INTERNAL_ERROR. » Refuser un code inconnu ferait d'une extension une
    /// panne.
    #[must_use]
    pub const fn from_wire(valeur: u32) -> Self {
        match valeur {
            0x0 => Self::NoError,
            0x1 => Self::ProtocolError,
            0x3 => Self::FlowControlError,
            0x4 => Self::SettingsTimeout,
            0x5 => Self::StreamClosed,
            0x6 => Self::FrameSizeError,
            0x7 => Self::RefusedStream,
            0x8 => Self::Cancel,
            0x9 => Self::CompressionError,
            0xa => Self::ConnectError,
            0xb => Self::EnhanceYourCalm,
            0xc => Self::InadequateSecurity,
            0xd => Self::Http11Required,
            _ => Self::InternalError,
        }
    }
}

/// Ce qui rend un cadre ou un réglage irrecevable.
///
/// Chaque faute porte le code qu'il faudra écrire sur le fil, et la PORTÉE de ce
/// qu'elle condamne : un flux, ou la connexion entière. Les confondre coûte
/// cher dans les deux sens — fermer la connexion pour une faute de flux coupe
/// des requêtes innocentes, et ne fermer qu'un flux pour une faute de connexion
/// laisse vivre un état faux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    /// Ce qu'on écrira sur le fil.
    code: ErrorCode,
    /// La faute condamne-t-elle la connexion entière ?
    fatal: bool,
    /// Ce qui s'est passé, pour le journal.
    cause: Cause,
}

/// Ce qui s'est passé, pour qui lit le journal ou le code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    /// La longueur annoncée dépasse `SETTINGS_MAX_FRAME_SIZE`.
    FrameTooLong,
    /// Un cadre de taille fixe n'a pas sa taille.
    WrongFixedSize,
    /// Un cadre qui exige un flux est arrivé sur le flux zéro, ou l'inverse.
    WrongStream,
    /// Le remplissage déborde du cadre.
    PaddingTooLong,
    /// Le remplissage n'est pas nul.
    ///
    /// §6.1 n'oblige pas à le vérifier — et le vérifier ferme un canal caché.
    /// C7 tranche : la sécurité prime.
    PaddingNotZero,
    /// La longueur d'un `SETTINGS` n'est pas un multiple de six.
    SettingsNotAligned,
    /// Un `SETTINGS` acquitté porte des octets.
    SettingsAckNotEmpty,
    /// Un réglage connu porte une valeur que §6.5.2 exclut.
    SettingValueOutOfRange,
    /// Le préambule n'est pas celui de §3.4.
    BadPreface,
    /// Un `WINDOW_UPDATE` de zéro, que §6.9 interdit.
    ZeroWindowUpdate,
    /// Un entier HPACK déborde, n'est pas terminé, ou s'écrit trop long.
    BadInteger,
    /// Une chaîne HPACK déborde de ce qui reste, ou de ce qu'on retient.
    BadString,
    /// Un code de Huffman inconnu, un remplissage fautif, ou `EOS`.
    BadHuffman,
    /// Le tampon de sortie ne suffit pas. **C'est notre faute, pas celle du
    /// pair** : d'où `INTERNAL_ERROR`.
    BufferTooSmall,
    /// Une mise à jour de taille de table dépasse ce qu'on a annoncé.
    TableSizeTooLarge,
    /// Un index HPACK ne désigne aucune entrée — zéro compris.
    BadIndex,
    /// Une mise à jour de taille de table ailleurs qu'au début d'un bloc.
    TableUpdateTooLate,
}

impl Error {
    /// Une faute qui condamne la connexion.
    #[must_use]
    pub const fn connection(code: ErrorCode, cause: Cause) -> Self {
        Self {
            code,
            fatal: true,
            cause,
        }
    }

    /// Une faute qui ne condamne qu'un flux.
    #[must_use]
    pub const fn stream(code: ErrorCode, cause: Cause) -> Self {
        Self {
            code,
            fatal: false,
            cause,
        }
    }

    /// Le code à écrire sur le fil.
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        self.code
    }

    /// La connexion entière est-elle condamnée ?
    #[must_use]
    pub const fn is_fatal(self) -> bool {
        self.fatal
    }

    /// Ce qui s'est passé.
    #[must_use]
    pub const fn cause(self) -> Cause {
        self.cause
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let quoi = match self.cause {
            Cause::FrameTooLong => "un cadre dépasse la taille annoncée",
            Cause::WrongFixedSize => "un cadre de taille fixe n'a pas sa taille",
            Cause::WrongStream => "ce cadre n'a pas sa place sur ce flux",
            Cause::PaddingTooLong => "le remplissage déborde du cadre",
            Cause::PaddingNotZero => "le remplissage n'est pas nul",
            Cause::SettingsNotAligned => "un `SETTINGS` n'est pas un multiple de six octets",
            Cause::SettingsAckNotEmpty => "un `SETTINGS` acquitté porte des octets",
            Cause::SettingValueOutOfRange => "un réglage porte une valeur exclue",
            Cause::BadPreface => "le préambule n'est pas celui de §3.4",
            Cause::ZeroWindowUpdate => "un `WINDOW_UPDATE` de zéro",
            Cause::BadInteger => "un entier HPACK déborde ou ne se termine pas",
            Cause::BadString => "une chaîne HPACK déborde",
            Cause::BadHuffman => "un code de Huffman fautif",
            Cause::BufferTooSmall => "le tampon de sortie ne suffit pas",
            Cause::TableSizeTooLarge => "une table plus grande que ce qu'on a annoncé",
            Cause::BadIndex => "un index HPACK qui ne désigne rien",
            Cause::TableUpdateTooLate => "une mise à jour de table ailleurs qu'au début d'un bloc",
        };
        let portee = match self.fatal {
            true => "connexion",
            false => "flux",
        };
        write!(f, "{quoi} ({portee}, {:?})", self.code)
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests;
