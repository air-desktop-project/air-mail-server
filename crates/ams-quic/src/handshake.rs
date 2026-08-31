// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La poignée de main TLS, du côté QUIC — §4 de RFC 9001.
//!
//! # CE MODULE NE FAIT PAS DE TLS, ET C'EST TOUT L'INTÉRÊT
//!
//! TLS sait produire et consommer des octets de poignée de main. Il ne sait pas
//! qu'ils voyagent en trames `CRYPTO`, qu'ils arrivent dans le désordre, ni
//! qu'ils appartiennent à quatre niveaux de chiffrement dont trois seulement en
//! portent. **C'est exactement le partage que §4.1.3 énonce** : « TLS is
//! responsible for buffering handshake bytes that have arrived in order. QUIC is
//! responsible for buffering handshake bytes that arrive out of order or for
//! encryption levels that are not yet ready. »
//!
//! Ce module est la moitié QUIC de ce partage. Il ne connaît ni certificat, ni
//! suite, ni `rustls` : il range des octets, et il applique les quatre règles
//! que §4 impose entre les niveaux.
//!
//! # QUATRE NIVEAUX, TROIS FLUX, TROIS ESPACES — ET LES TROIS COMPTES DIFFÈRENT
//!
//! §4.1.3 : « Four encryption levels are used […] CRYPTO frames are carried in
//! just three of these levels, omitting the 0-RTT level. These four levels
//! correspond to three packet number spaces. »
//!
//! Trois vocabulaires voisins qu'il serait facile de confondre :
//!
//! | Ce dont on parle | Combien | Où c'est écrit |
//! | --- | --- | --- |
//! | Niveaux de chiffrement | 4 | ici, [`Level`] |
//! | Flux `CRYPTO` | 3 | ici, un par niveau sauf `0-RTT` |
//! | Espaces de numérotation | 3 | `ams_proto_quic::Space` |
//!
//! Les confondre serait accepter une trame `CRYPTO` dans un paquet `0-RTT`, ce
//! que §8.3 nomme explicitement comme une faute de protocole — parce qu'un
//! `EndOfEarlyData` glissé là déplacerait la transcription de la poignée de main
//! sans que personne ne l'ait autorisé.
//!
//! # ET LE TAMPON N'EST PAS ICI
//!
//! Comme [`crate::Recv`], ce module tient les DÉCALAGES et laisse les OCTETS à
//! l'appelant. `ams-quic` n'alloue pas : une connexion qui déciderait seule de
//! réserver quatre kibioctets par niveau prendrait une décision qui n'est pas la
//! sienne.

use ams_proto_quic::{LongKind, Space};

use crate::error::{Error, Reason};
use crate::plages::Plages;
use crate::receive::PacketKind;

/// Ce qu'un niveau doit pouvoir retenir hors d'ordre (§7.5 de RFC 9000).
///
/// **C'EST UN PLANCHER DE LA RFC, PAS UN CHOIX D'ARCHITECTE** : « Implementations
/// MUST support buffering at least 4096 bytes of data received in out-of-order
/// CRYPTO frames. » En deçà, une poignée de main honnête peut échouer sur un
/// simple réordonnancement du réseau.
///
/// C'est la taille que l'appelant doit donner à chaque fenêtre. **IL N'Y A PAS
/// DE CONTRÔLE DE FLUX SUR `CRYPTO`** (§7.5) : rien n'empêche un pair d'en
/// envoyer plus, et c'est cette borne-là — la nôtre — qui l'arrête.
pub const CRYPTO_OCTETS_MAX: usize = 4096;

/// Les quatre niveaux de chiffrement (§4.1 de RFC 9001).
///
/// L'ordre est celui de l'installation, et il est total : c'est ce qui permet de
/// dire « un niveau inférieur » sans avoir à l'écrire trois fois.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// `Initial` — des clés que tout le monde peut dériver.
    Initial,
    /// `0-RTT` — **ET IL NE PORTE PAS DE `CRYPTO`** (§8.3).
    ZeroRtt,
    /// `Handshake`.
    Handshake,
    /// `1-RTT` — et il en porte encore, pour les tickets de session (§4.6.1).
    OneRtt,
}

impl Level {
    /// Le niveau de chiffrement de ce paquet — `None` pour un `Retry`.
    ///
    /// # POURQUOI UN `Retry` N'A PAS DE NIVEAU
    ///
    /// §17.2.5 : un `Retry` ne porte **aucune trame**. Il n'a pas de charge à
    /// déchiffrer, donc pas de niveau où la déchiffrer. Lui en donner un
    /// laisserait croire qu'on pourrait y lire un `CRYPTO`.
    #[must_use]
    pub const fn of(kind: PacketKind) -> Option<Self> {
        match kind {
            PacketKind::Long(LongKind::Initial) => Some(Self::Initial),
            PacketKind::Long(LongKind::ZeroRtt) => Some(Self::ZeroRtt),
            PacketKind::Long(LongKind::Handshake) => Some(Self::Handshake),
            PacketKind::Long(LongKind::Retry) => None,
            PacketKind::Short => Some(Self::OneRtt),
        }
    }

    /// L'espace de numérotation de ce niveau (§12.3).
    ///
    /// **DEUX NIVEAUX PARTAGENT UN ESPACE** : `0-RTT` et `1-RTT`. C'est la seule
    /// exception, et elle vient de ce qu'une donnée envoyée en `0-RTT` peut être
    /// retransmise en `1-RTT` — c'est la même donnée, sous une autre protection.
    #[must_use]
    pub const fn space(self) -> Space {
        match self {
            Self::Initial => Space::Initial,
            Self::Handshake => Space::Handshake,
            Self::ZeroRtt | Self::OneRtt => Space::Application,
        }
    }

    /// Le rang du flux `CRYPTO` de ce niveau — `None` pour `0-RTT` (§4.1.3).
    const fn flux(self) -> Option<usize> {
        match self {
            Self::Initial => Some(0),
            Self::ZeroRtt => None,
            Self::Handshake => Some(1),
            Self::OneRtt => Some(2),
        }
    }
}

/// Le flux `CRYPTO` d'un niveau.
///
/// # POURQUOI PAS UN [`crate::Recv`]
///
/// Il fait presque la même chose : ranger des octets à des décalages, dire ce
/// qui est contigu. Mais un `Recv` porte aussi une limite de contrôle de flux,
/// une taille finale et six états — **et aucun des trois n'a de sens ici**. Un
/// flux `CRYPTO` n'a pas de limite (§7.5 : « QUIC does not provide any means of
/// flow control for CRYPTO frames »), ne se termine jamais par un `FIN`, et ne
/// s'annule pas.
///
/// Un `Recv` employé ici serait donc un objet dont les deux tiers des champs
/// sont figés à une valeur que rien ne peut changer. C'est la même faute que
/// celle qu'on a refusée pour les clés de paquet : un type qui SAIT faire une
/// chose qu'il ne doit jamais faire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Flux {
    /// Jusqu'où TLS a consommé — c'est le début de la fenêtre.
    lu: u64,
    /// Le plus grand décalage reçu, exclusif.
    vu: u64,
    /// Ce qui est arrivé, en intervalles.
    plages: Plages,
}

impl Flux {
    /// Un flux neuf.
    const fn new() -> Self {
        Self {
            lu: 0,
            vu: 0,
            plages: Plages::new(),
        }
    }

    /// Combien d'octets contigus attendent d'être remis à TLS.
    fn prets(&self) -> u64 {
        self.plages.contiguous_from(self.lu)
    }

    /// Reste-t-il quoi que ce soit que TLS n'ait pas pris ?
    ///
    /// **CE N'EST PAS « DES OCTETS CONTIGUS »** : un trou compte aussi. §4.1.3
    /// parle de « data […] that TLS has not consumed », et une donnée reçue
    /// derrière un trou n'a pas davantage été consommée.
    const fn en_attente(&self) -> bool {
        self.vu > self.lu
    }
}

/// La poignée de main, vue par QUIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handshake {
    /// Les trois flux `CRYPTO`, indexés par [`Level::flux`].
    flux: [Flux; 3],
    /// Le niveau où TLS lit en ce moment.
    lecture: Level,
    /// Le niveau où TLS écrit en ce moment.
    ecriture: Level,
    /// La poignée de main est-elle terminée (§4.1.1) ?
    terminee: bool,
    /// Et confirmée (§4.1.2) ?
    confirmee: bool,
}

impl Default for Handshake {
    fn default() -> Self {
        Self::new()
    }
}

impl Handshake {
    /// Une poignée de main qui commence.
    ///
    /// **ON COMMENCE EN `Initial` DES DEUX CÔTÉS**, parce que c'est le seul
    /// niveau dont les clés existent avant tout échange : §5.2 les dérive de
    /// l'identifiant de destination, que le client choisit et que le serveur
    /// lit en clair.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            flux: [Flux::new(), Flux::new(), Flux::new()],
            lecture: Level::Initial,
            ecriture: Level::Initial,
            terminee: false,
            confirmee: false,
        }
    }

    /// Le niveau où TLS lit.
    #[must_use]
    pub const fn read_level(&self) -> Level {
        self.lecture
    }

    /// Le niveau où TLS écrit.
    ///
    /// §4.9 : « new data MUST be sent at the highest currently available
    /// encryption level ». C'est celui-ci.
    #[must_use]
    pub const fn write_level(&self) -> Level {
        self.ecriture
    }

    /// La poignée de main est-elle terminée (§4.1.1) ?
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.terminee
    }

    /// Et confirmée (§4.1.2) ?
    #[must_use]
    pub const fn is_confirmed(&self) -> bool {
        self.confirmee
    }

    /// Range les octets d'une trame `CRYPTO`.
    ///
    /// `fenetre` porte les octets à partir de [`Handshake::read_offset`] pour ce
    /// niveau, et fait [`CRYPTO_OCTETS_MAX`] octets.
    ///
    /// # LES TROIS REFUS DE §4.1.3, DANS L'ORDRE OÙ LA RFC LES POSE
    ///
    /// 1. **Un `CRYPTO` dans un paquet `0-RTT`** (§8.3) : faute de protocole.
    /// 2. **Un niveau déjà dépassé qui reçoit du NEUF** : « If the packet is
    ///    from a previously installed encryption level, it MUST NOT contain data
    ///    that extends past the end of previously received data in that flow. »
    ///    Une retransmission de ce qu'on a déjà vu reste licite — c'est même
    ///    attendu, puisque les acquittements se croisent.
    /// 3. **Plus d'octets qu'on ne peut en retenir** : §7.5 de RFC 9000 nomme
    ///    `CRYPTO_BUFFER_EXCEEDED` pour ce cas précis.
    ///
    /// # Errors
    ///
    /// [`Reason::CryptoInZeroRtt`], [`Reason::CryptoAfterLevel`],
    /// [`Reason::CryptoBufferExceeded`], [`Reason::TooManyHoles`].
    pub fn on_crypto(
        &mut self,
        level: Level,
        decalage: u64,
        octets: &[u8],
        fenetre: &mut [u8],
    ) -> Result<(), Error> {
        // RÈGLE 1 — et elle passe avant tout le reste, y compris avant de
        // regarder les octets : il n'y a pas de flux où les ranger.
        let Some(rang) = level.flux() else {
            return Err(Error::new(Reason::CryptoInZeroRtt));
        };
        let longueur = u64::try_from(octets.len()).unwrap_or(u64::MAX);
        let bout = decalage.saturating_add(longueur);

        // RÈGLE 2 — un niveau dépassé ne reçoit plus rien de neuf.
        if level < self.lecture && bout > self.flux[rang].vu {
            return Err(Error::new(Reason::CryptoAfterLevel));
        }

        self.ranger(rang, decalage, octets, fenetre)?;
        self.flux[rang].vu = self.flux[rang].vu.max(bout);
        Ok(())
    }

    /// Jusqu'où TLS a consommé, à ce niveau.
    #[must_use]
    pub fn read_offset(&self, level: Level) -> u64 {
        level.flux().map_or(0, |rang| self.flux[rang].lu)
    }

    /// Combien d'octets contigus attendent d'être remis à TLS, à ce niveau.
    #[must_use]
    pub fn readable(&self, level: Level) -> u64 {
        level.flux().map_or(0, |rang| self.flux[rang].prets())
    }

    /// TLS prend ce qui est prêt, dans l'ordre.
    ///
    /// Rend combien d'octets ont été pris, et fait glisser la fenêtre d'autant.
    ///
    /// **RIEN NE SORT D'UN NIVEAU QUI N'A PAS DE FLUX** : `0-RTT` rend zéro, et
    /// la fenêtre ne bouge pas.
    pub fn take(&mut self, level: Level, fenetre: &mut [u8], vers: &mut [u8]) -> usize {
        let Some(rang) = level.flux() else {
            return 0;
        };
        let prets = self.flux[rang].prets();
        let combien = usize::try_from(prets)
            .unwrap_or(usize::MAX)
            .min(vers.len())
            .min(fenetre.len());
        let pris = fenetre.get(..combien).unwrap_or_default();
        vers.get_mut(..combien)
            .unwrap_or_default()
            .copy_from_slice(pris);
        // La fenêtre glisse : ce qu'on vient de prendre s'en va, et le reste
        // remonte.
        fenetre.copy_within(combien.., 0);
        let flux = &mut self.flux[rang];
        flux.lu = flux.lu.saturating_add(u64::try_from(combien).unwrap_or(0));
        flux.plages.trim_below(flux.lu);
        combien
    }

    /// TLS annonce qu'il lit désormais à ce niveau (§4.1.4).
    ///
    /// # LA RÈGLE QUI DONNE SON PRIX À CET APPEL
    ///
    /// §4.1.3 : « When TLS provides keys for a higher encryption level, if there
    /// is data from a previous encryption level that TLS has not consumed, this
    /// MUST be treated as a connection error of type PROTOCOL_VIOLATION. »
    ///
    /// **CE N'EST PAS UNE POINTILLERIE.** Des octets laissés derrière au niveau
    /// précédent sont des octets que le pair a fait entrer dans la transcription
    /// et que nous n'avons pas lus : ce que les deux côtés ont haché diffère, et
    /// c'est précisément ce que la poignée de main est censée rendre impossible.
    ///
    /// **UN NIVEAU NE REDESCEND PAS**, et cela n'a pas de garde : le niveau
    /// retenu est le plus haut des deux. Une garde ici refuserait quelque chose
    /// que rien n'émet.
    ///
    /// # Errors
    ///
    /// [`Reason::CryptoNotConsumed`].
    pub fn install_read(&mut self, level: Level) -> Result<(), Error> {
        // **LES RANGS SONT ÉCRITS ICI, ET NON REDEMANDÉS À `flux()`.** Il n'y a
        // que deux niveaux inférieurs qui portent un flux, et l'on sait
        // lesquels : repasser par l'`Option` rendrait une variante vide que rien
        // ne peut atteindre.
        for (bas, rang) in [(Level::Initial, 0), (Level::Handshake, 1)] {
            if bas < level && self.flux[rang].en_attente() {
                return Err(Error::new(Reason::CryptoNotConsumed));
            }
        }
        self.lecture = self.lecture.max(level);
        Ok(())
    }

    /// TLS annonce qu'il écrit désormais à ce niveau (§4.1.4).
    ///
    /// Aucune règle ne s'y attache : c'est TLS qui décide quand ses clés
    /// d'émission changent, et il ne les rend qu'une fois.
    pub fn install_write(&mut self, level: Level) {
        self.ecriture = self.ecriture.max(level);
    }

    /// La poignée de main est terminée (§4.1.1).
    pub const fn complete(&mut self) {
        self.terminee = true;
    }

    /// La poignée de main est confirmée (§4.1.2).
    ///
    /// **POUR UN SERVEUR, C'EST LE MÊME MOMENT** : §4.1.2 dit « the TLS
    /// handshake is considered confirmed at the server when the handshake
    /// completes ». Le client, lui, attend un `HANDSHAKE_DONE`.
    ///
    /// C'est ce moment-là, et pas un autre, qui autorise à jeter les clés de
    /// `Handshake` (§4.9.2).
    pub const fn confirm(&mut self) {
        self.terminee = true;
        self.confirmee = true;
    }

    /// Écrit les octets dans la fenêtre, et note l'intervalle.
    fn ranger(
        &mut self,
        rang: usize,
        decalage: u64,
        octets: &[u8],
        fenetre: &mut [u8],
    ) -> Result<(), Error> {
        let flux = &mut self.flux[rang];
        // Ce que TLS a déjà pris ne se réécrit pas : la fenêtre commence à `lu`.
        let saut = flux.lu.saturating_sub(decalage);
        let depuis = usize::try_from(saut).unwrap_or(usize::MAX);
        let utiles = octets.get(depuis..).unwrap_or_default();
        if utiles.is_empty() {
            return Ok(());
        }
        let debut = decalage.max(flux.lu);
        let ou = usize::try_from(debut.saturating_sub(flux.lu)).unwrap_or(usize::MAX);
        let fin = ou.saturating_add(utiles.len());
        // **ET C'EST ICI QUE §7.5 SE PAIE.** Un pair peut envoyer autant de
        // `CRYPTO` qu'il veut : rien ne l'en empêche, puisqu'il n'y a pas de
        // contrôle de flux. La borne est la nôtre, et la RFC lui a donné un
        // code — ce n'est donc PAS une faute interne, contrairement à la fenêtre
        // trop courte d'un flux ordinaire.
        let place = fenetre
            .get_mut(ou..fin)
            .ok_or(Error::new(Reason::CryptoBufferExceeded))?;
        for (place, lu) in place.iter_mut().zip(utiles) {
            *place = *lu;
        }
        let fin = debut.saturating_add(u64::try_from(utiles.len()).unwrap_or(0));
        flux.plages
            .insert(debut, fin)
            .map_err(|_| Error::new(Reason::TooManyHoles))
    }
}

/// Le code de connexion que porte cette alerte TLS (§4.8).
///
/// # UNE ALERTE N'EST PAS UN CODE, ET LA COMPOSITION EST UN `OU`
///
/// §4.8 : « The AlertDescription value is added to 0x0100 to produce a QUIC
/// error code from the range reserved for CRYPTO_ERROR. » La RFC dit « added »,
/// mais une description d'alerte tient sur huit bits et `0x0100` a ses huit bits
/// bas nuls : **l'addition et le OU donnent le même résultat, et le OU ne peut
/// pas déborder**. Ce qui était une arithmétique à surveiller devient une
/// composition qui n'a rien à surveiller.
///
/// §4.8 encore : « QUIC is only able to convey an alert level of "fatal" ». Il
/// n'y a donc pas de niveau à passer — toute alerte ferme la connexion.
#[must_use]
pub fn crypto_error(alert: u8) -> u64 {
    0x0100 | u64::from(alert)
}

#[cfg(test)]
mod tests;
