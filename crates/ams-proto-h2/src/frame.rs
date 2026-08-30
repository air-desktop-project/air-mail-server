// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le cadrage (§4), et les règles que chaque type de cadre porte.

use crate::error::{Cause, Error, ErrorCode};

/// Les neuf octets d'un en-tête de cadre.
pub const FRAME_HEADER_OCTETS: usize = 9;

/// Le type d'un cadre (§6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// `DATA` — le corps d'un message.
    Data,
    /// `HEADERS` — un bloc d'en-têtes comprimé.
    Headers,
    /// `PRIORITY` — **DÉPRÉCIÉ** par §5.3.2.
    ///
    /// Il se lit encore, et ne fait rien. Le refuser casserait des clients qui
    /// l'envoient toujours ; l'honorer demanderait de construire un arbre de
    /// priorités que la RFC a retiré, et dont la complexité a produit sa part
    /// de failles.
    Priority,
    /// `RST_STREAM` — ce flux s'arrête là.
    RstStream,
    /// `SETTINGS` — les réglages de la connexion.
    Settings,
    /// `PUSH_PROMISE` — **DÉPRÉCIÉ** par §8.4, et refusé.
    ///
    /// Un client n'a jamais eu le droit d'en envoyer ; ce serveur n'en envoie
    /// pas, et annonce `SETTINGS_ENABLE_PUSH` à zéro.
    PushPromise,
    /// `PING` — mesure de latence, et preuve de vie.
    Ping,
    /// `GOAWAY` — la connexion se ferme, et voici jusqu'où on a traité.
    GoAway,
    /// `WINDOW_UPDATE` — du crédit de contrôle de flux.
    WindowUpdate,
    /// `CONTINUATION` — la suite d'un bloc d'en-têtes.
    Continuation,
    /// Un type qu'on ne connaît pas.
    ///
    /// **IL S'IGNORE, IL NE SE REFUSE PAS** (§4.1). C'est ce qui permet aux
    /// extensions d'exister sans casser les serveurs déployés — et un serveur
    /// qui refuserait ce qu'il ne connaît pas serait le maillon par lequel toute
    /// évolution devient impossible.
    Unknown(u8),
}

impl FrameKind {
    /// Lit un type depuis son octet.
    #[must_use]
    pub const fn from_wire(octet: u8) -> Self {
        match octet {
            0x0 => Self::Data,
            0x1 => Self::Headers,
            0x2 => Self::Priority,
            0x3 => Self::RstStream,
            0x4 => Self::Settings,
            0x5 => Self::PushPromise,
            0x6 => Self::Ping,
            0x7 => Self::GoAway,
            0x8 => Self::WindowUpdate,
            0x9 => Self::Continuation,
            autre => Self::Unknown(autre),
        }
    }

    /// L'octet sur le fil.
    #[must_use]
    pub const fn value(self) -> u8 {
        match self {
            Self::Data => 0x0,
            Self::Headers => 0x1,
            Self::Priority => 0x2,
            Self::RstStream => 0x3,
            Self::Settings => 0x4,
            Self::PushPromise => 0x5,
            Self::Ping => 0x6,
            Self::GoAway => 0x7,
            Self::WindowUpdate => 0x8,
            Self::Continuation => 0x9,
            Self::Unknown(octet) => octet,
        }
    }
}

/// Les fanions, par leur bit (§6).
///
/// **LE MÊME BIT NE VEUT PAS DIRE LA MÊME CHOSE SELON LE CADRE** : `0x1` est
/// `END_STREAM` sur un `DATA` et `ACK` sur un `SETTINGS`. Les lire sans savoir
/// de quel cadre il s'agit, c'est se tromper une fois sur deux — d'où des
/// accesseurs qui portent le type dans leur nom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameFlags(u8);

impl FrameFlags {
    /// `END_STREAM` (`DATA`, `HEADERS`).
    const END_STREAM: u8 = 0x1;
    /// `ACK` (`SETTINGS`, `PING`).
    const ACK: u8 = 0x1;
    /// `END_HEADERS` (`HEADERS`, `CONTINUATION`, `PUSH_PROMISE`).
    const END_HEADERS: u8 = 0x4;
    /// `PADDED` (`DATA`, `HEADERS`, `PUSH_PROMISE`).
    const PADDED: u8 = 0x8;
    /// `PRIORITY` (`HEADERS`).
    const PRIORITY: u8 = 0x20;

    /// Les fanions bruts.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Le message se termine-t-il ici ?
    #[must_use]
    pub const fn end_stream(self) -> bool {
        self.0 & Self::END_STREAM != 0
    }

    /// Est-ce un acquittement ?
    #[must_use]
    pub const fn ack(self) -> bool {
        self.0 & Self::ACK != 0
    }

    /// Le bloc d'en-têtes se termine-t-il ici ?
    #[must_use]
    pub const fn end_headers(self) -> bool {
        self.0 & Self::END_HEADERS != 0
    }

    /// Le cadre porte-t-il du remplissage ?
    #[must_use]
    pub const fn padded(self) -> bool {
        self.0 & Self::PADDED != 0
    }

    /// Le `HEADERS` porte-t-il une priorité, que §5.3.2 a dépréciée ?
    #[must_use]
    pub const fn priority(self) -> bool {
        self.0 & Self::PRIORITY != 0
    }
}

/// Les neuf octets d'en-tête, lus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// La longueur de la charge, en octets.
    length: u32,
    /// Le type.
    kind: FrameKind,
    /// Les fanions.
    flags: FrameFlags,
    /// Le flux, ou zéro pour la connexion.
    stream: u32,
}

impl FrameHeader {
    /// Lit les neuf octets.
    ///
    /// # CETTE LECTURE NE PEUT PAS ÉCHOUER, ET C'EST VOULU
    ///
    /// Neuf octets quelconques FORMENT un en-tête : il n'y a pas de motif à
    /// reconnaître. Ce qui peut être faux, c'est ce que l'en-tête ANNONCE — et
    /// cela se juge dans [`FrameHeader::check`], qui a besoin de connaître les
    /// réglages en vigueur. Mêler les deux obligerait à passer les réglages à
    /// une lecture qui n'en a que faire.
    ///
    /// **LE BIT RÉSERVÉ EST IGNORÉ** (§4.1) : « The value of the reserved bit is
    /// undefined and MUST be ignored when receiving. » Le refuser casserait une
    /// extension future qui s'en servirait.
    #[must_use]
    pub const fn parse(octets: &[u8; FRAME_HEADER_OCTETS]) -> Self {
        // `from_be_bytes` PLUTÔT QUE DES DÉCALAGES : la composition est totale
        // et sans conversion muette — le workspace refuse celles-ci, et une
        // longueur mal élargie serait une borne mal appliquée. Le zéro de tête
        // dit à lui seul que la longueur tient sur vingt-quatre bits.
        let length = u32::from_be_bytes([0, octets[0], octets[1], octets[2]]);
        let stream = u32::from_be_bytes([octets[5], octets[6], octets[7], octets[8]]) & 0x7fff_ffff;
        Self {
            length,
            kind: FrameKind::from_wire(octets[3]),
            flags: FrameFlags(octets[4]),
            stream,
        }
    }

    /// Écrit les neuf octets.
    #[must_use]
    pub const fn write(self) -> [u8; FRAME_HEADER_OCTETS] {
        // LE BIT RÉSERVÉ S'ÉCRIT À ZÉRO (§4.1), et le masque du flux garantit
        // qu'aucun numéro ne peut l'allumer par accident.
        let stream = (self.stream & 0x7fff_ffff).to_be_bytes();
        // `to_be_bytes` PLUTÔT QU'UN DÉCALAGE SUIVI D'UN `as` : la découpe est
        // totale, et il n'y a pas de troncature à autoriser — donc pas de lint
        // à faire taire, donc pas d'endroit où une troncature réelle passerait
        // inaperçue plus tard.
        let longueur = self.length.to_be_bytes();
        [
            longueur[1],
            longueur[2],
            longueur[3],
            self.kind.value(),
            self.flags.0,
            stream[0],
            stream[1],
            stream[2],
            stream[3],
        ]
    }

    /// Compose un en-tête.
    #[must_use]
    pub const fn new(kind: FrameKind, flags: u8, stream: u32, length: u32) -> Self {
        Self {
            length,
            kind,
            flags: FrameFlags(flags),
            stream,
        }
    }

    /// La longueur de la charge.
    #[must_use]
    pub const fn length(self) -> u32 {
        self.length
    }

    /// Le type.
    #[must_use]
    pub const fn kind(self) -> FrameKind {
        self.kind
    }

    /// Les fanions.
    #[must_use]
    pub const fn flags(self) -> FrameFlags {
        self.flags
    }

    /// Le flux, ou zéro.
    #[must_use]
    pub const fn stream(self) -> u32 {
        self.stream
    }

    /// Ce que le cadre entier occupe, en-tête compris.
    #[must_use]
    pub const fn total(self) -> usize {
        // LA LONGUEUR TIENT SUR VINGT-QUATRE BITS, et neuf de plus ne peuvent
        // pas déborder un `usize` de trente-deux. La conversion est donc totale.
        (self.length as usize).saturating_add(FRAME_HEADER_OCTETS)
    }

    /// Vérifie ce que l'en-tête annonce.
    ///
    /// # Errors
    ///
    /// [`Cause::FrameTooLong`], [`Cause::WrongFixedSize`], [`Cause::WrongStream`]
    /// ou [`Cause::SettingsNotAligned`] selon ce qui cloche.
    pub const fn check(self, max_frame_size: u32) -> Result<(), Error> {
        // **LA LONGUEUR D'ABORD, ET POUR TOUS LES TYPES.** C'est la seule borne
        // qui protège la mémoire, et un type inconnu n'en est pas dispensé : ce
        // qu'on ignore, on doit quand même le sauter, donc le retenir ou le
        // lire.
        if self.length > max_frame_size {
            return Err(Error::connection(
                ErrorCode::FrameSizeError,
                Cause::FrameTooLong,
            ));
        }
        // Un type inconnu s'arrête là : §4.1 veut qu'on l'ignore, et lui
        // appliquer les règles d'un autre reviendrait à deviner lequel.
        let (taille_fixe, sur_un_flux) = match self.kind {
            FrameKind::Data
            | FrameKind::Headers
            | FrameKind::PushPromise
            | FrameKind::Continuation => (None, Some(true)),
            FrameKind::Priority => (Some(5), Some(true)),
            FrameKind::RstStream => (Some(4), Some(true)),
            FrameKind::Settings => (None, Some(false)),
            FrameKind::Ping => (Some(8), Some(false)),
            FrameKind::GoAway => (None, Some(false)),
            // §6.9 : un `WINDOW_UPDATE` vaut sur la connexion comme sur un flux.
            FrameKind::WindowUpdate => (Some(4), None),
            FrameKind::Unknown(_) => (None, None),
        };
        if let Some(attendue) = taille_fixe
            && self.length != attendue
        {
            return Err(Error::connection(
                ErrorCode::FrameSizeError,
                Cause::WrongFixedSize,
            ));
        }
        if let Some(exige) = sur_un_flux
            && exige != (self.stream != 0)
        {
            return Err(Error::connection(
                ErrorCode::ProtocolError,
                Cause::WrongStream,
            ));
        }
        // §6.5 : un `SETTINGS` porte des entrées de six octets, et un `SETTINGS`
        // acquitté n'en porte aucune.
        if matches!(self.kind, FrameKind::Settings) {
            if self.flags.ack() && self.length != 0 {
                return Err(Error::connection(
                    ErrorCode::FrameSizeError,
                    Cause::SettingsAckNotEmpty,
                ));
            }
            if !self.length.is_multiple_of(6) {
                return Err(Error::connection(
                    ErrorCode::FrameSizeError,
                    Cause::SettingsNotAligned,
                ));
            }
        }
        Ok(())
    }
}

/// Ce qu'il manque pour tenir un cadre entier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    /// Il en manque : lire davantage, puis rappeler.
    More,
    /// Le cadre occupe les `n` premiers octets du tampon, en-tête compris.
    Complete(FrameHeader),
}

/// Suit un cadre jusqu'à ce qu'il soit entier.
///
/// # LE CONTRAT AVEC L'APPELANT
///
/// Le tampon ne fait que CROÎTRE entre deux appels. Après un [`Need::Complete`],
/// l'appelant consomme [`FrameHeader::total`] octets et rappelle. Lui donner un
/// tampon qui a rétréci ferait lire autre chose que ce qu'il croit.
#[derive(Debug, Clone, Copy, Default)]
pub struct FrameReader;

impl FrameReader {
    /// Ce que le tampon contient.
    ///
    /// # Errors
    ///
    /// Ce que [`FrameHeader::check`] refuse — dès que l'en-tête est là, et sans
    /// attendre la charge. **Refuser tôt est le point** : un cadre qui annonce
    /// seize mébioctets n'a pas à être accumulé avant d'être refusé.
    pub fn poll(tampon: &[u8], max_frame_size: u32) -> Result<Need, Error> {
        let Some(debut) = tampon.get(..FRAME_HEADER_OCTETS) else {
            return Ok(Need::More);
        };
        let mut octets = [0_u8; FRAME_HEADER_OCTETS];
        for (place, lu) in octets.iter_mut().zip(debut) {
            *place = *lu;
        }
        let entete = FrameHeader::parse(&octets);
        entete.check(max_frame_size)?;
        match tampon.len() >= entete.total() {
            true => Ok(Need::Complete(entete)),
            false => Ok(Need::More),
        }
    }
}

/// Une charge dont le remplissage a été retiré.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Padded<'a> {
    /// Ce qui reste une fois le remplissage ôté.
    data: &'a [u8],
}

impl<'a> Padded<'a> {
    /// Retire le remplissage d'une charge (§6.1).
    ///
    /// # DEUX FAUTES DIFFÉRENTES, ET LA SECONDE EST UN CHOIX
    ///
    /// Un remplissage plus long que ce qui reste est une faute de protocole que
    /// §6.1 nomme. Un remplissage NON NUL, lui, n'a pas à être vérifié — la RFC
    /// dit qu'un récepteur « MAY » le traiter comme une faute. **On le vérifie**,
    /// parce que des octets qu'un pair choisit et qu'on ne regarde pas sont un
    /// canal caché, et que C7 tranche en faveur de la sécurité.
    ///
    /// # Errors
    ///
    /// [`Cause::PaddingTooLong`] ou [`Cause::PaddingNotZero`].
    pub fn strip(charge: &'a [u8], padded: bool) -> Result<Self, Error> {
        if !padded {
            return Ok(Self { data: charge });
        }
        let Some((longueur, reste)) = charge.split_first() else {
            // Le fanion annonce un octet de longueur, et la charge est vide :
            // c'est déjà un débordement.
            return Err(Error::connection(
                ErrorCode::ProtocolError,
                Cause::PaddingTooLong,
            ));
        };
        let bourrage = usize::from(*longueur);
        let Some(garde) = reste.len().checked_sub(bourrage) else {
            return Err(Error::connection(
                ErrorCode::ProtocolError,
                Cause::PaddingTooLong,
            ));
        };
        let (data, remplissage) = reste.split_at(garde);
        if remplissage.iter().any(|octet| *octet != 0) {
            return Err(Error::connection(
                ErrorCode::ProtocolError,
                Cause::PaddingNotZero,
            ));
        }
        Ok(Self { data })
    }

    /// Ce qui reste une fois le remplissage ôté.
    #[must_use]
    pub const fn data(self) -> &'a [u8] {
        self.data
    }
}

#[cfg(test)]
mod tests;
