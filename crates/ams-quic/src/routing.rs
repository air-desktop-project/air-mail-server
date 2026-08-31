// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! À qui appartient ce datagramme — §5.2 de RFC 9000.
//!
//! # LE PORT EST OUVERT AU MONDE ENTIER, ET C'EST ICI QU'ON TRIE
//!
//! Un serveur QUIC reçoit sur un seul port ce que n'importe qui lui envoie :
//! des connexions en cours, des clients neufs, des versions qu'il ne sert pas,
//! des octets qui ne sont pas du QUIC, et des paquets forgés avec une adresse
//! source qui n'est pas celle de l'expéditeur.
//!
//! **AUCUN DE CES OCTETS N'EST ENCORE AUTHENTIFIÉ.** Les clés d'un `Initial` se
//! dérivent d'un identifiant que le paquet porte en clair (§5.2 de RFC 9001) :
//! tout le monde peut en fabriquer un. Ce module décide donc avant de savoir
//! qui parle, et chacune de ses décisions doit être sûre pour un menteur.
//!
//! # CE MODULE NE TIENT PAS DE TABLE, ET C'EST DÉLIBÉRÉ
//!
//! Associer un identifiant à une connexion demande une carte, qui grandit et
//! rétrécit — `ams-quic` n'alloue pas. Mais une carte n'est pas une décision :
//! c'est du rangement. Ce qui est une décision, c'est ce qu'on fait d'un
//! datagramme SELON ce que la carte répond, et ce sont les règles de §5.2.2,
//! §6.1 et §14.1.
//!
//! On lit donc d'abord ce que le datagramme dit de lui-même ([`Incoming::read`]),
//! l'appelant interroge sa carte, puis [`Incoming::route`] tranche. Le même
//! partage que [`crate::Recv`], qui tient les décalages et laisse les octets.
//!
//! # ET SEUL LE PREMIER PAQUET DÉCIDE
//!
//! §12.2 : plusieurs paquets peuvent tenir dans un datagramme. Ils vont tous à
//! la même connexion — celle du premier —, parce qu'un datagramme n'a qu'une
//! adresse source et qu'un `Initial` peut être suivi d'un `Handshake` que rien
//! ne route à lui seul.

use ams_proto_quic::{ConnectionId, Long, LongKind, VERSION_1, is_long, parse_long};

use crate::receive::PacketKind;

/// La taille minimale d'un datagramme portant un `Initial` (§14.1).
///
/// **CE N'EST PAS UNE PRÉCAUTION DE TAILLE, C'EST UNE DÉFENSE.** Un client qui
/// remplit ses datagrammes à 1200 octets borne ce qu'un attaquant obtient en
/// usurpant son adresse : le serveur ne répondra jamais plus de trois fois ce
/// qu'il a reçu (§8.1), et cette règle-ci fixe le plancher de ce « reçu ».
///
/// §14.1 : « A server MUST discard an Initial packet that is carried in a UDP
/// datagram with a payload that is smaller than the smallest allowed maximum
/// datagram size of 1200 bytes. »
pub const INITIAL_DATAGRAM_OCTETS_MIN: usize = 1200;

/// La longueur des identifiants de connexion que NOUS choisissons.
///
/// # POURQUOI UNE CONSTANTE, ET POURQUOI HUIT
///
/// §5.1 : la longueur de l'identifiant de destination n'est PAS sur le fil dans
/// un en-tête court. Un serveur ne peut donc lire ces paquets-là que s'il sait
/// d'avance combien d'octets il a distribués. **Une longueur qui varierait d'une
/// connexion à l'autre rendrait ses propres paquets illisibles.**
///
/// Huit octets, c'est-à-dire soixante-quatre bits. §8.1 : un pair qui emploie un
/// identifiant que nous avons choisi et qui porte « at least 64 bits of
/// entropy » peut être tenu pour validé — c'est le minimum qui ouvre cette
/// porte, et la prendre plus courte la fermerait.
pub const LOCAL_CONNECTION_ID_OCTETS: usize = 8;

/// Ce qu'on fait d'un datagramme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Le remettre à cette connexion — le rang que l'appelant lui avait donné.
    Connection(usize),
    /// Un client neuf : la poignée de main peut commencer.
    New,
    /// Répondre par une négociation de version (§6.1).
    Negotiate,
    /// Le jeter, et voici pourquoi.
    ///
    /// **EN SILENCE.** §5.2.2 : « Servers MUST drop incoming packets under all
    /// other circumstances. » Répondre quoi que ce soit à un datagramme qu'on
    /// n'attribue à personne ferait de ce port un amplificateur.
    Drop(Discard),
}

/// Pourquoi un datagramme se jette.
///
/// # POURQUOI NOMMER CE QU'ON JETTE
///
/// Le résultat est le même — rien ne part. Mais un compteur par raison est la
/// seule façon de distinguer, en exploitation, un réseau qui perd des paquets
/// d'un balayage de port, et un client mal réglé d'une attaque. Un unique
/// compteur « jetés » ne dirait rien de tout cela.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Discard {
    /// Ce ne sont pas des octets qu'on sache lire : forme, bit fixe, ou
    /// troncature.
    NotAPacket,
    /// Un `Initial` dans un datagramme de moins de 1200 octets (§14.1).
    ///
    /// **C'EST LA GARDE D'AMPLIFICATION AU PLUS TÔT** : accepter ce paquet
    /// laisserait un attaquant obtenir trois fois un tout petit datagramme,
    /// autant de fois qu'il le veut.
    InitialTooSmall,
    /// Une version qu'on ne sert pas, dans un datagramme trop court pour
    /// mériter une réponse (§5.2.2).
    ///
    /// « Servers MUST drop smaller packets that specify unsupported versions. »
    /// Répondre à ceux-là ferait un amplificateur.
    UnknownVersionTooSmall,
    /// Un paquet de négociation de version.
    ///
    /// §6.1 : « An endpoint MUST NOT send a Version Negotiation packet in
    /// response to receiving a Version Negotiation packet. » Et un serveur n'en
    /// reçoit pas : c'est lui qui les émet.
    VersionNegotiation,
    /// Un `Retry`. §17.2.5 : c'est un serveur qui l'émet, jamais qui le reçoit.
    Retry,
    /// Un `Handshake` sans connexion connue.
    ///
    /// §5.2.2 : « Clients are not able to send Handshake packets prior to
    /// receiving a server response, so servers SHOULD ignore any such packets. »
    HandshakeWithoutConnection,
    /// Un `0-RTT` sans connexion connue.
    ///
    /// §5.2.2 permet d'en retenir quelques-uns en attendant un `Initial` en
    /// retard. **On ne le fait pas** : nous n'offrons pas le `0-RTT` (C6), donc
    /// l'`Initial` qui suivrait ne les rendrait pas plus lisibles.
    EarlyDataWithoutConnection,
    /// Un en-tête court dont l'identifiant n'est à personne.
    ///
    /// C'est ce qui arrive quand une connexion vient de s'éteindre, et c'est
    /// aussi ce qui arrive quand quelqu'un cherche à voir ce qui répond.
    UnknownConnection,
}

/// Ce qu'un datagramme dit de lui-même, avant tout déchiffrement.
///
/// **TOUT CECI EST EN CLAIR, ET DONC INVÉRIFIÉ.** Un menteur choisit ces
/// champs-là comme il veut ; ce type ne les croit pas, il les rapporte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Incoming {
    /// Ce que le premier paquet du datagramme se dit être.
    ///
    /// **`None` POUR UNE NÉGOCIATION DE VERSION, QUI N'A PAS DE TYPE.** §17.2.1 :
    /// la version zéro n'est pas une version, et les bits de type du premier
    /// octet ne veulent alors rien dire. Leur donner une valeur ici laisserait
    /// croire le contraire, et un `match` sur ce type-là mènerait à une décision
    /// prise sur des bits qui ne décrivent rien.
    kind: Option<PacketKind>,
    /// La version qu'il annonce — celle de §17.2, ou [`VERSION_1`] pour un
    /// en-tête court, qui n'en porte pas.
    version: u32,
    /// L'identifiant de destination qu'il porte.
    destination: ConnectionId,
    /// L'identifiant de source, **c'est-à-dire celui qu'on doit lui adresser**.
    ///
    /// Vide pour un en-tête court, qui n'en porte pas (§17.3) : à ce moment-là,
    /// la connexion est établie et l'on sait déjà à qui l'on parle.
    source: ConnectionId,
    /// Ce que le datagramme ENTIER occupe.
    ///
    /// **ET NON CE QUE LE PAQUET OCCUPE** : §14.1 borne le datagramme, parce
    /// que c'est lui que le réseau transporte et lui qui sert de mesure à
    /// l'anti-amplification.
    datagram: usize,
}

impl Incoming {
    /// Lit ce qu'il faut pour router, et rien de plus.
    ///
    /// `local_cid_len` est la longueur des identifiants qu'on distribue —
    /// voir [`LOCAL_CONNECTION_ID_OCTETS`].
    ///
    /// # Errors
    ///
    /// [`Discard::NotAPacket`] si ces octets ne portent pas d'en-tête lisible.
    /// **On ne dit pas mieux, et c'est voulu** : distinguer un bit fixe absent
    /// d'une troncature apprendrait, à qui balaie le port, ce qu'on sait lire.
    pub fn read(datagram: &[u8], local_cid_len: usize) -> Result<Self, Discard> {
        let taille = datagram.len();
        if !is_long(datagram) {
            // §17.3 : un en-tête court ne porte pas la longueur de son
            // identifiant. C'est nous qui la savons.
            let court = ams_proto_quic::ShortHeader::parse(datagram, local_cid_len)
                .map_err(|_| Discard::NotAPacket)?;
            return Ok(Self {
                kind: Some(PacketKind::Short),
                version: VERSION_1,
                destination: court.destination(),
                source: ConnectionId::EMPTY,
                datagram: taille,
            });
        }
        // **UN EN-TÊTE QU'ON NE SAIT PAS LIRE SE JETTE, MÊME POUR NÉGOCIER.**
        // §6.1 demande d'échouer en renvoyant les deux identifiants du paquet
        // reçu ; on ne peut pas les renvoyer si on ne sait pas les lire. Une
        // version future dont les identifiants dépasseraient vingt octets
        // tomberait ici — c'est une limite, et elle est écrite.
        let (kind, version, destination, source) = match parse_long(datagram) {
            Ok(Long::Numbered(entete)) => (
                Some(PacketKind::Long(entete.kind())),
                entete.version(),
                entete.destination(),
                entete.source(),
            ),
            Ok(Long::Retry(retry)) => (
                Some(PacketKind::Long(LongKind::Retry)),
                VERSION_1,
                retry.destination,
                retry.source,
            ),
            // §17.2.1 : pas de type, parce qu'il n'y en a pas.
            Ok(Long::Negotiation(negociation)) => {
                (None, 0, negociation.destination, negociation.source)
            }
            Err(_) => return Err(Discard::NotAPacket),
        };
        Ok(Self {
            kind,
            version,
            destination,
            source,
            datagram: taille,
        })
    }

    /// Ce que le premier paquet se dit être — `None` pour une négociation de
    /// version, qui n'a pas de type (§17.2.1).
    #[must_use]
    pub const fn kind(&self) -> Option<PacketKind> {
        self.kind
    }

    /// La version annoncée.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// L'identifiant de destination — **c'est LUI qu'on cherche dans sa carte**.
    #[must_use]
    pub const fn destination(&self) -> ConnectionId {
        self.destination
    }

    /// L'identifiant de source — **c'est LUI qu'on lui adresse en retour**.
    ///
    /// §7.2 : le premier paquet du client porte l'identifiant qu'il veut voir en
    /// destination des nôtres. Le confondre avec celui de destination ferait
    /// répondre à un identifiant que le client a lui-même choisi au hasard, et
    /// qu'il ne reconnaîtrait pas.
    #[must_use]
    pub const fn source(&self) -> ConnectionId {
        self.source
    }

    /// Ce que le datagramme entier occupe.
    #[must_use]
    pub const fn datagram_len(&self) -> usize {
        self.datagram
    }

    /// Ce datagramme peut-il porter une nouvelle connexion (§14.1) ?
    #[must_use]
    pub const fn big_enough_for_initial(&self) -> bool {
        self.datagram >= INITIAL_DATAGRAM_OCTETS_MIN
    }

    /// Ce qu'on fait de ce datagramme, sachant ce que la carte a répondu.
    ///
    /// `known` est le rang de la connexion à qui cet identifiant appartient,
    /// ou `None` s'il n'est à personne.
    ///
    /// # L'ORDRE DES QUESTIONS EST CELUI DE §5.2.2, ET IL N'EST PAS LIBRE
    ///
    /// La version se juge **avant** la carte : « Packets with a supported
    /// version, or no Version field, are matched to a connection using the
    /// connection ID ». Interroger la carte d'abord ferait remettre à une
    /// connexion en cours un paquet d'une version qu'elle ne parle pas.
    ///
    /// Et le `Retry` se juge avant tout le reste : c'est le seul paquet dont la
    /// seule présence est déjà une faute côté serveur, et le laisser filer
    /// jusqu'à la carte lui donnerait une chance d'être remis à quelqu'un.
    #[must_use]
    pub fn route(&self, known: Option<usize>) -> Route {
        // §6.1 : on n'y répond pas, et un serveur n'en reçoit pas. C'est
        // l'ABSENCE de type qui le dit, et non la version — les deux vont
        // ensemble, mais une seule des deux est structurelle.
        let Some(kind) = self.kind else {
            return Route::Drop(Discard::VersionNegotiation);
        };
        // §17.2.5 : c'est un serveur qui l'émet.
        if kind == PacketKind::Long(LongKind::Retry) {
            return Route::Drop(Discard::Retry);
        }
        // §5.2.2, et l'ordre compte : la version d'abord.
        if self.version != VERSION_1 {
            return match self.big_enough_for_initial() {
                true => Route::Negotiate,
                false => Route::Drop(Discard::UnknownVersionTooSmall),
            };
        }
        if let Some(rang) = known {
            return Route::Connection(rang);
        }
        match kind {
            // §14.1 : le plancher se vérifie AVANT d'accepter, pas après.
            PacketKind::Long(LongKind::Initial) => match self.big_enough_for_initial() {
                true => Route::New,
                false => Route::Drop(Discard::InitialTooSmall),
            },
            PacketKind::Long(LongKind::Handshake) => {
                Route::Drop(Discard::HandshakeWithoutConnection)
            }
            PacketKind::Long(LongKind::ZeroRtt) => Route::Drop(Discard::EarlyDataWithoutConnection),
            // Le `Retry` est déjà parti plus haut ; il ne reste que l'en-tête
            // court, dont l'identifiant n'est à personne.
            PacketKind::Long(LongKind::Retry) | PacketKind::Short => {
                Route::Drop(Discard::UnknownConnection)
            }
        }
    }
}

#[cfg(test)]
mod tests;
