// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les trames de RFC 9000 §19.
//!
//! # CE QU'ON NE CONNAÎT PAS EST UNE FAUTE — ET C'EST L'INVERSE D'HTTP/2
//!
//! §12.4 : « An endpoint MUST treat the receipt of a frame of unknown type as a
//! connection error of type FRAME_ENCODING_ERROR. » En HTTP/2, un cadre inconnu
//! s'IGNORE ; ici, il condamne la connexion.
//!
//! Ce n'est pas une incohérence entre deux protocoles voisins : c'est deux
//! façons différentes d'étendre. HTTP/2 laisse un émetteur essayer et voir ; QUIC
//! exige que toute extension soit NÉGOCIÉE d'abord, par un paramètre de
//! transport. Un type inconnu veut donc dire qu'on n'a pas négocié ce qu'on
//! croyait — et continuer à lire un flux qu'on ne comprend plus serait deviner.
//!
//! # LES TRAMES NE PORTENT PAS LEUR LONGUEUR, ET C'EST VOULU
//!
//! Une trame se lit jusqu'au bout ou pas du tout : son type dit sa forme, et sa
//! forme dit sa fin. Rien n'annonce « la trame suivante commence à tel octet ».
//! Un décodeur qui se tromperait d'un octet lirait donc le reste du paquet comme
//! des trames imaginaires — et c'est exactement pourquoi tout se refuse au
//! premier doute plutôt que de tenter de se rattraper.
//!
//! # CE QUI N'EST PAS ICI
//!
//! §12.4 dit aussi QUELLES trames ont le droit d'apparaître dans quel type de
//! paquet — un `STREAM` n'a rien à faire dans un `Initial`. C'est une règle de
//! CONNEXION, pas de grammaire : elle demande de savoir d'où vient la trame, et
//! elle vivra avec la machine d'état.

use crate::connection_id::ConnectionId;
use crate::error::{Error, Reason};
use crate::varint::{self, VARINT_MAX};

/// Ce qu'un jeton de réinitialisation sans état occupe (§19.16).
pub const STATELESS_RESET_TOKEN_OCTETS: usize = 16;

/// Ce que porte un `PATH_CHALLENGE` ou un `PATH_RESPONSE` (§19.17).
pub const PATH_DATA_OCTETS: usize = 8;

/// La plus grande valeur qu'un compte de flux puisse prendre (§19.11).
///
/// **2^60, ET NON 2^62.** Un numéro de flux est fait d'un compte et de deux bits
/// de type ; permettre un compte plus grand ferait un numéro qui ne tient plus
/// dans l'espace des entiers.
pub const MAX_STREAMS_LIMIT: u64 = 1 << 60;

/// Le sens d'un flux, pour les trames qui en comptent (§19.11, §19.14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Directional {
    /// Les deux côtés peuvent envoyer.
    Bidirectional,
    /// Un seul côté envoie.
    Unidirectional,
}

/// Les comptes ECN d'un `ACK` (§19.3.2).
///
/// **ILS DISENT QUE LE RÉSEAU A EU CHAUD**, et non qu'il a perdu. Un routeur
/// encombré marque plutôt que de jeter, et le compte de marques permet de
/// ralentir AVANT la perte — c'est tout l'intérêt, et c'est ce qui distingue
/// ECN d'un simple compteur de pertes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcnCounts {
    /// Paquets marqués `ECT(0)`.
    pub ect0: u64,
    /// Paquets marqués `ECT(1)`.
    pub ect1: u64,
    /// Paquets marqués « congestion rencontrée ».
    pub ce: u64,
}

/// Un `ACK` (§19.3).
///
/// # LES INTERVALLES NE SONT PAS DÉCODÉS D'AVANCE
///
/// Leur nombre vient du fil, et rien ne le borne d'utile : les retenir tous
/// demanderait une table dont le pair choisirait la taille. On garde donc les
/// octets, et [`Ack::ranges`] les parcourt à la demande — l'appelant décide
/// combien il en veut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ack<'a> {
    /// Le plus grand numéro que le pair a reçu.
    pub largest: u64,
    /// Ce qu'il a attendu avant d'acquitter, en unités de §18.2.
    pub delay: u64,
    /// Combien de paquets sous `largest` sont acquittés d'affilée.
    pub first_range: u64,
    /// Combien d'intervalles suivent.
    pub range_count: u64,
    /// Les intervalles, non décodés.
    pub encoded_ranges: &'a [u8],
    /// Les comptes ECN, si la trame était de type 0x03.
    pub ecn: Option<EcnCounts>,
}

impl<'a> Ack<'a> {
    /// Parcourt les intervalles, à la demande.
    #[must_use]
    pub const fn ranges(&self) -> AckRanges<'a> {
        AckRanges {
            reste: self.encoded_ranges,
            restants: self.range_count,
        }
    }

    /// Le plus petit numéro que le premier intervalle acquitte.
    ///
    /// # Errors
    ///
    /// [`Reason::BadAckRange`] si l'intervalle descend sous zéro — §19.3.1 en
    /// fait une faute de cadrage, et non un intervalle qu'on raccourcirait en
    /// silence.
    pub fn smallest(&self) -> Result<u64, Error> {
        self.largest
            .checked_sub(self.first_range)
            .ok_or_else(|| Error::new(Reason::BadAckRange))
    }
}

/// Un intervalle acquitté, du plus grand au plus petit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckRange {
    /// Combien de numéros séparent cet intervalle du précédent.
    pub gap: u64,
    /// Combien de numéros cet intervalle acquitte, moins un.
    pub length: u64,
}

/// Le parcours des intervalles d'un `ACK`.
#[derive(Debug, Clone, Copy)]
pub struct AckRanges<'a> {
    /// Ce qui reste à lire.
    reste: &'a [u8],
    /// Combien d'intervalles restent annoncés.
    restants: u64,
}

impl Iterator for AckRanges<'_> {
    type Item = Result<AckRange, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.restants == 0 {
            return None;
        }
        self.restants = self.restants.saturating_sub(1);
        let mut lire = || -> Result<u64, Error> {
            let (valeur, lus) = varint::decode(self.reste)?;
            self.reste = self.reste.get(lus..).unwrap_or_default();
            Ok(valeur)
        };
        let intervalle = lire().and_then(|gap| {
            Ok(AckRange {
                gap,
                length: lire()?,
            })
        });
        // **UNE FAUTE ARRÊTE LE PARCOURS.** Continuer après un intervalle
        // illisible lirait les octets suivants comme des intervalles, et il n'y
        // a plus aucune raison de croire qu'ils en sont.
        if intervalle.is_err() {
            self.restants = 0;
        }
        Some(intervalle)
    }
}

/// Une trame (§19).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    /// `PADDING` (§19.1), et combien d'octets consécutifs.
    ///
    /// **ELLES SE COMPTENT PLUTÔT QU'ELLES NE SE RENDENT UNE À UNE.** Un
    /// `Initial` fait au moins 1200 octets (§14.1), et l'essentiel est souvent
    /// du remplissage : en rendre mille deux cents ferait mille deux cents tours
    /// de boucle pour ne rien dire.
    Padding {
        /// Combien d'octets de remplissage se suivaient.
        count: usize,
    },
    /// `PING` (§19.2) — il ne dit rien, et c'est ce qui le rend utile : il
    /// oblige le pair à acquitter, donc à prouver qu'il est là.
    Ping,
    /// `ACK` (§19.3).
    Ack(Ack<'a>),
    /// `RESET_STREAM` (§19.4).
    ResetStream {
        /// Le flux.
        stream: u64,
        /// Ce que l'application en dit.
        code: u64,
        /// Où le flux s'arrête, définitivement.
        final_size: u64,
    },
    /// `STOP_SENDING` (§19.5) — « arrête d'envoyer », et non « j'arrête de lire ».
    StopSending {
        /// Le flux.
        stream: u64,
        /// Ce que l'application en dit.
        code: u64,
    },
    /// `CRYPTO` (§19.6) — la poignée de main, dans son propre flux ordonné.
    Crypto {
        /// Où ces octets se placent.
        offset: u64,
        /// Les octets.
        data: &'a [u8],
    },
    /// `NEW_TOKEN` (§19.7) — un jeton pour la prochaine connexion.
    NewToken {
        /// Le jeton.
        token: &'a [u8],
    },
    /// `STREAM` (§19.8) — les données d'un flux.
    Stream {
        /// Le flux.
        stream: u64,
        /// Où ces octets se placent dans le flux.
        offset: u64,
        /// Les octets.
        data: &'a [u8],
        /// Le flux se termine-t-il ici ?
        fin: bool,
    },
    /// `MAX_DATA` (§19.9) — le crédit de la connexion.
    MaxData {
        /// Le total qu'on peut envoyer, tous flux confondus.
        maximum: u64,
    },
    /// `MAX_STREAM_DATA` (§19.10) — le crédit d'un flux.
    MaxStreamData {
        /// Le flux.
        stream: u64,
        /// Le total qu'on peut y envoyer.
        maximum: u64,
    },
    /// `MAX_STREAMS` (§19.11) — combien de flux on peut ouvrir.
    MaxStreams {
        /// De quel sens.
        directional: Directional,
        /// Combien.
        maximum: u64,
    },
    /// `DATA_BLOCKED` (§19.12) — « je voudrais envoyer, et tu ne m'as rien
    /// ouvert ».
    DataBlocked {
        /// La limite atteinte.
        limit: u64,
    },
    /// `STREAM_DATA_BLOCKED` (§19.13).
    StreamDataBlocked {
        /// Le flux.
        stream: u64,
        /// La limite atteinte.
        limit: u64,
    },
    /// `STREAMS_BLOCKED` (§19.14).
    StreamsBlocked {
        /// De quel sens.
        directional: Directional,
        /// La limite atteinte.
        limit: u64,
    },
    /// `NEW_CONNECTION_ID` (§19.15) — un identifiant de plus, pour changer de
    /// chemin sans se faire suivre.
    NewConnectionId {
        /// Son rang.
        sequence: u64,
        /// En deçà de quel rang tout est à retirer.
        retire_prior_to: u64,
        /// L'identifiant.
        id: ConnectionId,
        /// Le jeton qui permettra de dire « je ne connais plus cette connexion ».
        token: [u8; STATELESS_RESET_TOKEN_OCTETS],
    },
    /// `RETIRE_CONNECTION_ID` (§19.16).
    RetireConnectionId {
        /// Le rang à retirer.
        sequence: u64,
    },
    /// `PATH_CHALLENGE` (§19.17) — « prouve que tu es bien à cette adresse ».
    PathChallenge {
        /// Les huit octets à renvoyer.
        data: [u8; PATH_DATA_OCTETS],
    },
    /// `PATH_RESPONSE` (§19.18).
    PathResponse {
        /// Les huit octets renvoyés.
        data: [u8; PATH_DATA_OCTETS],
    },
    /// `CONNECTION_CLOSE` (§19.19).
    ConnectionClose {
        /// Le code, de transport ou d'application selon `frame_type`.
        code: u64,
        /// La trame qui a fâché — `None` pour une fermeture d'APPLICATION.
        ///
        /// **C'EST CE CHAMP QUI DIT DE QUEL ESPACE VIENT LE CODE**, et non le
        /// code lui-même : les deux espaces se recouvrent entièrement.
        frame_type: Option<u64>,
        /// Ce que le pair en dit, en clair.
        reason: &'a [u8],
    },
    /// `HANDSHAKE_DONE` (§19.20) — le serveur, et lui seul, dit que c'est fini.
    HandshakeDone,
}

impl<'a> Frame<'a> {
    /// Lit une trame, et rend ce qu'elle a consommé.
    ///
    /// # Errors
    ///
    /// [`Reason::Truncated`] ; [`Reason::UnknownFrame`] ;
    /// [`Reason::BadFrameField`] pour un champ hors de ses bornes.
    pub fn parse(octets: &'a [u8]) -> Result<(Self, usize), Error> {
        let (type_de_trame, lus) = varint::decode(octets)?;
        let suite = octets.get(lus..).unwrap_or_default();
        let mut lecteur = Lecteur::new(suite);
        let trame = match type_de_trame {
            // §19.1 : ON LES COMPTE. Elles se suivent par milliers.
            0x00 => {
                let mut compte = 1_usize;
                while lecteur.reste().first() == Some(&0x00) {
                    lecteur.avancer(1);
                    compte = compte.saturating_add(1);
                }
                Self::Padding { count: compte }
            }
            0x01 => Self::Ping,
            0x02 | 0x03 => Self::lire_ack(&mut lecteur, type_de_trame == 0x03)?,
            0x04 => Self::ResetStream {
                stream: lecteur.varint()?,
                code: lecteur.varint()?,
                final_size: lecteur.varint()?,
            },
            0x05 => Self::StopSending {
                stream: lecteur.varint()?,
                code: lecteur.varint()?,
            },
            0x06 => {
                let offset = lecteur.varint()?;
                let data = lecteur.tranche_annoncee()?;
                borner_la_fin(offset, data.len())?;
                Self::Crypto { offset, data }
            }
            0x07 => Self::NewToken {
                token: lecteur.tranche_annoncee()?,
            },
            0x08..=0x0f => Self::lire_stream(&mut lecteur, type_de_trame)?,
            0x10 => Self::MaxData {
                maximum: lecteur.varint()?,
            },
            0x11 => Self::MaxStreamData {
                stream: lecteur.varint()?,
                maximum: lecteur.varint()?,
            },
            0x12 | 0x13 => Self::MaxStreams {
                directional: sens(type_de_trame == 0x13),
                maximum: borner_les_flux(lecteur.varint()?)?,
            },
            0x14 => Self::DataBlocked {
                limit: lecteur.varint()?,
            },
            0x15 => Self::StreamDataBlocked {
                stream: lecteur.varint()?,
                limit: lecteur.varint()?,
            },
            0x16 | 0x17 => Self::StreamsBlocked {
                directional: sens(type_de_trame == 0x17),
                limit: borner_les_flux(lecteur.varint()?)?,
            },
            0x18 => Self::lire_nouvel_identifiant(&mut lecteur)?,
            0x19 => Self::RetireConnectionId {
                sequence: lecteur.varint()?,
            },
            0x1a => Self::PathChallenge {
                data: lecteur.huit()?,
            },
            0x1b => Self::PathResponse {
                data: lecteur.huit()?,
            },
            0x1c | 0x1d => Self::lire_fermeture(&mut lecteur, type_de_trame == 0x1c)?,
            0x1e => Self::HandshakeDone,
            // §12.4 : CE QU'ON NE CONNAÎT PAS EST UNE FAUTE, et non quelque
            // chose qu'on saute. Une extension se négocie AVANT d'être employée.
            _ => return Err(Error::new(Reason::UnknownFrame)),
        };
        Ok((trame, lus.saturating_add(lecteur.consommes())))
    }

    /// `ACK` (§19.3).
    fn lire_ack(lecteur: &mut Lecteur<'a>, avec_ecn: bool) -> Result<Self, Error> {
        let largest = lecteur.varint()?;
        let delay = lecteur.varint()?;
        let range_count = lecteur.varint()?;
        let first_range = lecteur.varint()?;
        // **LES INTERVALLES RESTENT SUR LE FIL.** Leur nombre vient du pair, et
        // les retenir tous demanderait une table dont il choisirait la taille.
        let debut = lecteur.consommes();
        for _ in 0..range_count {
            lecteur.varint()?;
            lecteur.varint()?;
        }
        let encoded_ranges = lecteur.depuis(debut);
        let ecn = match avec_ecn {
            true => Some(EcnCounts {
                ect0: lecteur.varint()?,
                ect1: lecteur.varint()?,
                ce: lecteur.varint()?,
            }),
            false => None,
        };
        Ok(Self::Ack(Ack {
            largest,
            delay,
            first_range,
            range_count,
            encoded_ranges,
            ecn,
        }))
    }

    /// `STREAM` (§19.8), dont les trois bits de bas disent la forme.
    fn lire_stream(lecteur: &mut Lecteur<'a>, type_de_trame: u64) -> Result<Self, Error> {
        // §19.8 : `OFF` en 0x04, `LEN` en 0x02, `FIN` en 0x01.
        let avec_offset = type_de_trame & 0x04 != 0;
        let avec_longueur = type_de_trame & 0x02 != 0;
        let fin = type_de_trame & 0x01 != 0;
        let stream = lecteur.varint()?;
        let offset = match avec_offset {
            true => lecteur.varint()?,
            false => 0,
        };
        // **SANS `LEN`, LA TRAME VA JUSQU'AU BOUT DU PAQUET.** C'est ce qui
        // permet de n'écrire aucune longueur pour la dernière trame — et c'est
        // pourquoi l'appelant doit ne présenter QUE le paquet, et rien après.
        let data = match avec_longueur {
            true => lecteur.tranche_annoncee()?,
            false => lecteur.tout_le_reste(),
        };
        borner_la_fin(offset, data.len())?;
        Ok(Self::Stream {
            stream,
            offset,
            data,
            fin,
        })
    }

    /// `NEW_CONNECTION_ID` (§19.15).
    fn lire_nouvel_identifiant(lecteur: &mut Lecteur<'a>) -> Result<Self, Error> {
        let sequence = lecteur.varint()?;
        let retire_prior_to = lecteur.varint()?;
        // §19.15 : « The value in the Retire Prior To field MUST be less than or
        // equal to the value in the Sequence Number field. » Un rang de retrait
        // au-delà du rang qu'on annonce retirerait l'identifiant qu'on donne.
        if retire_prior_to > sequence {
            return Err(Error::new(Reason::BadFrameField));
        }
        let longueur = usize::from(lecteur.octet()?);
        // §19.15 : de UN à vingt. **LE ZÉRO EST REFUSÉ ICI ALORS QU'IL EST
        // LICITE DANS UN EN-TÊTE** : un identifiant qu'on donne au pair pour
        // qu'il s'en serve doit désigner quelque chose. La borne HAUTE, elle,
        // n'est pas redite — c'est `ConnectionId::new` qui la porte, et la
        // redire ici ferait deux vérités pour une règle.
        if longueur == 0 {
            return Err(Error::new(Reason::ConnectionIdTooLong));
        }
        let id = ConnectionId::new(lecteur.tranche(longueur)?)?;
        Ok(Self::NewConnectionId {
            sequence,
            retire_prior_to,
            id,
            token: lecteur.seize()?,
        })
    }

    /// `CONNECTION_CLOSE` (§19.19).
    fn lire_fermeture(lecteur: &mut Lecteur<'a>, de_transport: bool) -> Result<Self, Error> {
        let code = lecteur.varint()?;
        // §19.19 : seule la fermeture de TRANSPORT dit quelle trame a fâché.
        let frame_type = match de_transport {
            true => Some(lecteur.varint()?),
            false => None,
        };
        Ok(Self::ConnectionClose {
            code,
            frame_type,
            reason: lecteur.tranche_annoncee()?,
        })
    }
}

/// Le sens d'un flux, depuis le bit de bas du type.
const fn sens(unidirectionnel: bool) -> Directional {
    match unidirectionnel {
        true => Directional::Unidirectional,
        false => Directional::Bidirectional,
    }
}

/// **UN FLUX NE PEUT PAS DÉPASSER 2^60** (§19.11) : son numéro est fait d'un
/// compte et de deux bits de type, et un compte plus grand ferait un numéro hors
/// de l'espace des entiers.
fn borner_les_flux(compte: u64) -> Result<u64, Error> {
    match compte <= MAX_STREAMS_LIMIT {
        true => Ok(compte),
        false => Err(Error::new(Reason::BadFrameField)),
    }
}

/// **LA FIN D'UN FLUX TIENT DANS L'ESPACE DES ENTIERS** (§19.8) : la somme du
/// décalage et de la longueur ne peut pas dépasser 2^62 - 1, sans quoi le flux
/// désignerait des octets qu'aucun décalage ne pourrait nommer.
fn borner_la_fin(offset: u64, longueur: usize) -> Result<(), Error> {
    let fin = offset.saturating_add(u64::try_from(longueur).unwrap_or(u64::MAX));
    match fin <= VARINT_MAX {
        true => Ok(()),
        false => Err(Error::new(Reason::BadFrameField)),
    }
}

/// Un curseur sur les octets d'une trame.
///
/// Il retient ce qu'il a consommé, pour que l'appelant sache où la trame
/// s'arrête sans avoir à le recalculer.
struct Lecteur<'a> {
    /// Tous les octets, depuis le début de la trame.
    tout: &'a [u8],
    /// Combien ont été lus.
    lus: usize,
}

impl<'a> Lecteur<'a> {
    /// Un curseur au début.
    const fn new(octets: &'a [u8]) -> Self {
        Self {
            tout: octets,
            lus: 0,
        }
    }

    /// Combien d'octets ont été consommés.
    const fn consommes(&self) -> usize {
        self.lus
    }

    /// Ce qui n'a pas encore été lu.
    fn reste(&self) -> &'a [u8] {
        self.tout.get(self.lus..).unwrap_or_default()
    }

    /// Avance sans rien lire.
    fn avancer(&mut self, combien: usize) {
        self.lus = self.lus.saturating_add(combien);
    }

    /// Ce qui a été lu depuis ce rang.
    fn depuis(&self, rang: usize) -> &'a [u8] {
        self.tout.get(rang..self.lus).unwrap_or_default()
    }

    /// Un entier de §16.
    fn varint(&mut self) -> Result<u64, Error> {
        let (valeur, lus) = varint::decode(self.reste())?;
        self.avancer(lus);
        Ok(valeur)
    }

    /// Un octet.
    fn octet(&mut self) -> Result<u8, Error> {
        let octet = *self
            .reste()
            .first()
            .ok_or_else(|| Error::new(Reason::Truncated))?;
        self.avancer(1);
        Ok(octet)
    }

    /// Une tranche de longueur connue.
    fn tranche(&mut self, combien: usize) -> Result<&'a [u8], Error> {
        let lue = self
            .reste()
            .get(..combien)
            .ok_or_else(|| Error::new(Reason::Truncated))?;
        self.avancer(combien);
        Ok(lue)
    }

    /// Une tranche précédée de sa longueur.
    fn tranche_annoncee(&mut self) -> Result<&'a [u8], Error> {
        let longueur = self.varint()?;
        // La longueur vient du fil, et un entier de §16 en annonce jusqu'à
        // 2^62. La borne réelle est celle du paquet, ligne suivante :
        // `usize::MAX` la fait manquer à coup sûr.
        self.tranche(usize::try_from(longueur).unwrap_or(usize::MAX))
    }

    /// Tout ce qui reste.
    fn tout_le_reste(&mut self) -> &'a [u8] {
        let reste = self.reste();
        self.avancer(reste.len());
        reste
    }

    /// Huit octets.
    fn huit(&mut self) -> Result<[u8; PATH_DATA_OCTETS], Error> {
        let lus = self.tranche(PATH_DATA_OCTETS)?;
        // La tranche fait exactement huit octets : la conversion aboutit
        // toujours, et `unwrap_or_default` porte cela dans la bibliothèque.
        Ok(lus.try_into().unwrap_or_default())
    }

    /// Seize octets.
    fn seize(&mut self) -> Result<[u8; STATELESS_RESET_TOKEN_OCTETS], Error> {
        let lus = self.tranche(STATELESS_RESET_TOKEN_OCTETS)?;
        Ok(lus.try_into().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests;
