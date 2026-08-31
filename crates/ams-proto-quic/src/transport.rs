// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les paramètres de transport de RFC 9000 §18.
//!
//! # C'EST ICI QUE LES EXTENSIONS SE NÉGOCIENT, ET CELA EXPLIQUE §12.4
//!
//! §18.1 : « An endpoint MUST ignore transport parameters that it does not
//! understand. » Les paramètres inconnus s'IGNORENT — c'est exactement
//! l'inverse des trames, où §12.4 fait d'un type inconnu une faute de
//! connexion.
//!
//! Les deux règles vont ensemble, et ne se comprennent qu'ensemble : **on
//! ignore ce qu'on ne connaît pas là où l'on NÉGOCIE, et on refuse ce qu'on ne
//! connaît pas là où l'on EXÉCUTE.** Un pair qui veut une extension l'annonce
//! ici ; s'il n'obtient pas de réponse, il sait qu'il ne doit pas s'en servir.
//! Une trame inconnue veut donc dire que cette négociation n'a pas eu lieu, ou
//! qu'elle a été mal comprise — et continuer serait deviner.
//!
//! # LES DÉFAUTS SONT DES VALEURS, PAS DES ABSENCES
//!
//! §18.2 donne à presque chaque paramètre une valeur par défaut, qui vaut dès le
//! premier paquet — avant même que les paramètres du pair n'arrivent. Traiter un
//! paramètre absent comme « pas de limite » plutôt que comme sa valeur par
//! défaut ouvrirait exactement les portes que ces défauts ferment.
//!
//! # UN PARAMÈTRE DEUX FOIS EST UNE FAUTE, ET CE N'EST PAS DE LA PÉDANTERIE
//!
//! §7.4 : « An endpoint MUST treat receipt of a transport parameter more than
//! once as a connection error of type TRANSPORT_PARAMETER_ERROR. » Sans cette
//! règle, deux valeurs pour un même paramètre laisseraient chaque mise en œuvre
//! choisir la sienne — et deux pairs n'auraient plus les mêmes limites.

use crate::connection_id::ConnectionId;
use crate::error::{Error, Reason};
use crate::frame::MAX_STREAMS_LIMIT;
use crate::rtt::ACK_DELAY_EXPONENT_MAX;
use crate::varint;

/// La plus petite charge UDP qu'un pair puisse annoncer accepter (§18.2).
///
/// Mille deux cents : c'est ce que §14.1 exige, et un pair qui annoncerait moins
/// ne pourrait pas recevoir la poignée de main elle-même.
pub const MIN_UDP_PAYLOAD_SIZE: u64 = 1_200;

/// Ce qu'un pair accepte par défaut, faute de l'avoir dit (§18.2).
pub const DEFAULT_MAX_UDP_PAYLOAD_SIZE: u64 = 65_527;

/// L'exposant de délai d'acquittement par défaut (§18.2).
pub const DEFAULT_ACK_DELAY_EXPONENT: u32 = 3;

/// Le délai d'acquittement maximal par défaut, en millisecondes (§18.2).
pub const DEFAULT_MAX_ACK_DELAY_MS: u64 = 25;

/// Le plus grand délai d'acquittement qu'on puisse annoncer (§18.2), en
/// millisecondes.
pub const MAX_ACK_DELAY_LIMIT_MS: u64 = 1 << 14;

/// Combien d'identifiants de connexion un pair doit au moins accepter (§18.2).
///
/// Deux. En deçà, on ne pourrait pas changer d'identifiant sans en retirer un
/// d'abord — et changer de chemin sans se faire suivre deviendrait impossible.
pub const MIN_ACTIVE_CONNECTION_ID_LIMIT: u64 = 2;

/// Le nombre d'identifiants actifs par défaut (§18.2).
pub const DEFAULT_ACTIVE_CONNECTION_ID_LIMIT: u64 = 2;

/// Qui a envoyé ces paramètres.
///
/// **CERTAINS PARAMÈTRES N'APPARTIENNENT QU'AU SERVEUR** (§18.2), et un client
/// qui les enverrait prétendrait avoir émis un `Retry` ou choisi l'identifiant
/// d'origine. Les accepter de lui, c'est le laisser réécrire ce qui prouve que
/// la poignée de main n'a pas été détournée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sender {
    /// Le client.
    Client,
    /// Le serveur.
    Server,
}

/// Les paramètres qu'un pair annonce (§18.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportParameters {
    /// Après combien de millisecondes de silence la connexion s'éteint.
    /// Zéro : jamais.
    pub max_idle_timeout_ms: u64,
    /// La plus grande charge UDP que le pair accepte.
    pub max_udp_payload_size: u64,
    /// Le crédit initial de la connexion, en octets.
    pub initial_max_data: u64,
    /// Le crédit initial d'un flux bidirectionnel que NOUS ouvrons.
    pub initial_max_stream_data_bidi_local: u64,
    /// Le crédit initial d'un flux bidirectionnel que LE PAIR ouvre.
    pub initial_max_stream_data_bidi_remote: u64,
    /// Le crédit initial d'un flux unidirectionnel.
    pub initial_max_stream_data_uni: u64,
    /// Combien de flux bidirectionnels on peut ouvrir.
    pub initial_max_streams_bidi: u64,
    /// Combien de flux unidirectionnels on peut ouvrir.
    pub initial_max_streams_uni: u64,
    /// L'exposant du délai d'acquittement.
    pub ack_delay_exponent: u32,
    /// Le délai maximal avant acquittement, en millisecondes.
    pub max_ack_delay_ms: u64,
    /// Le pair refuse-t-il qu'on change d'adresse ?
    pub disable_active_migration: bool,
    /// Combien d'identifiants de connexion il accepte de tenir.
    pub active_connection_id_limit: u64,
    /// L'identifiant de source du premier paquet, qui prouve l'origine.
    pub initial_source_connection_id: Option<ConnectionId>,
    /// L'identifiant de destination d'origine — le serveur seul l'annonce.
    pub original_destination_connection_id: Option<ConnectionId>,
    /// L'identifiant de source d'un `Retry` — le serveur seul l'annonce.
    pub retry_source_connection_id: Option<ConnectionId>,
}

impl Default for TransportParameters {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl TransportParameters {
    /// Les valeurs par défaut de §18.2, celles qui valent AVANT toute annonce.
    pub const DEFAULT: Self = Self {
        max_idle_timeout_ms: 0,
        max_udp_payload_size: DEFAULT_MAX_UDP_PAYLOAD_SIZE,
        initial_max_data: 0,
        initial_max_stream_data_bidi_local: 0,
        initial_max_stream_data_bidi_remote: 0,
        initial_max_stream_data_uni: 0,
        initial_max_streams_bidi: 0,
        initial_max_streams_uni: 0,
        ack_delay_exponent: DEFAULT_ACK_DELAY_EXPONENT,
        max_ack_delay_ms: DEFAULT_MAX_ACK_DELAY_MS,
        disable_active_migration: false,
        active_connection_id_limit: DEFAULT_ACTIVE_CONNECTION_ID_LIMIT,
        initial_source_connection_id: None,
        original_destination_connection_id: None,
        retry_source_connection_id: None,
    };

    /// Écrit ces paramètres, tels que §18 les veut, et rend ce qu'ils occupent.
    ///
    /// # POURQUOI LES ENTIERS S'ÉCRIVENT TOUS, MÊME ÉGAUX À LEUR DÉFAUT
    ///
    /// §18 permet d'omettre un paramètre dont la valeur est celle par défaut :
    /// le pair l'assume. L'omettre demanderait de comparer chaque champ à
    /// `DEFAULT` — **et une comparaison de ce genre se tait le jour où le défaut
    /// change**, en laissant croire qu'on a annoncé ce qu'on n'a pas annoncé.
    /// Les écrire tous coûte une quarantaine d'octets, une fois par connexion.
    ///
    /// Les booléens et les identifiants, eux, se déclarent PAR LEUR PRÉSENCE
    /// (§18.2) : `disable_active_migration` n'a pas de valeur, et l'écrire
    /// vaudrait « vrai ». Ceux-là ne peuvent donc pas s'écrire inconditionnellement.
    ///
    /// # Errors
    ///
    /// [`Reason::BufferTooSmall`] si `out` ne suffit pas ;
    /// [`Reason::BadTransportParameter`] si l'on demande d'écrire un paramètre
    /// qui n'appartient pas à celui qui l'envoie (§18.2) — c'est une faute de
    /// l'appelant, et la taire ferait rejeter la poignée de main par le pair,
    /// très loin d'ici.
    pub fn write(&self, de: Sender, out: &mut [u8]) -> Result<usize, Error> {
        let faute = || Error::new(Reason::BadTransportParameter);
        let mut plume = Plume { out, rang: 0 };

        // §18.2 : ces deux-là ne viennent que d'un serveur, et ils disent ce
        // que LUI a fait de la poignée de main.
        for (identifiant, identite) in [
            (0x00_u64, self.original_destination_connection_id),
            (0x10, self.retry_source_connection_id),
        ] {
            let Some(identite) = identite else {
                continue;
            };
            if !appartient_a(identifiant, de) {
                return Err(faute());
            }
            plume.octets(identifiant, identite.as_bytes())?;
        }

        plume.entier(0x01, self.max_idle_timeout_ms)?;
        plume.entier(0x03, self.max_udp_payload_size)?;
        plume.entier(0x04, self.initial_max_data)?;
        plume.entier(0x05, self.initial_max_stream_data_bidi_local)?;
        plume.entier(0x06, self.initial_max_stream_data_bidi_remote)?;
        plume.entier(0x07, self.initial_max_stream_data_uni)?;
        plume.entier(0x08, self.initial_max_streams_bidi)?;
        plume.entier(0x09, self.initial_max_streams_uni)?;
        plume.entier(0x0a, u64::from(self.ack_delay_exponent))?;
        plume.entier(0x0b, self.max_ack_delay_ms)?;
        // §18.2 : il ne porte AUCUNE valeur. Sa présence est ce qu'il dit.
        if self.disable_active_migration {
            plume.octets(0x0c, &[])?;
        }
        plume.entier(0x0e, self.active_connection_id_limit)?;
        if let Some(identite) = self.initial_source_connection_id {
            plume.octets(0x0f, identite.as_bytes())?;
        }
        Ok(plume.rang)
    }

    /// Lit les paramètres qu'un pair a envoyés.
    ///
    /// # Errors
    ///
    /// [`Reason::Truncated`] ; [`Reason::BadTransportParameter`] pour une valeur
    /// hors borne, un paramètre répété, ou un paramètre qui n'appartient pas à
    /// celui qui l'envoie.
    pub fn read(octets: &[u8], de: Sender) -> Result<Self, Error> {
        let faute = || Error::new(Reason::BadTransportParameter);
        let mut lus = Self::DEFAULT;
        // **UN BIT PAR PARAMÈTRE CONNU**, pour refuser les répétitions sans
        // retenir la liste : dix-sept paramètres tiennent dans un `u32`.
        let mut vus = 0_u32;
        let mut reste = octets;
        while !reste.is_empty() {
            let (identifiant, avance) = varint::decode(reste)?;
            reste = reste.get(avance..).unwrap_or_default();
            let (longueur, avance) = varint::decode(reste)?;
            reste = reste.get(avance..).unwrap_or_default();
            let taille = usize::try_from(longueur).unwrap_or(usize::MAX);
            let valeur = reste
                .get(..taille)
                .ok_or_else(|| Error::new(Reason::Truncated))?;
            reste = reste.get(taille..).unwrap_or_default();

            // §18.1 : CE QU'ON NE CONNAÎT PAS S'IGNORE. C'est le mécanisme
            // d'extension, et il n'y en a pas d'autre.
            let Some(rang) = rang_connu(identifiant) else {
                continue;
            };
            let bit = 1_u32.checked_shl(rang).unwrap_or(0);
            if vus & bit != 0 {
                return Err(faute());
            }
            vus |= bit;
            if !appartient_a(identifiant, de) {
                return Err(faute());
            }
            lus.appliquer(identifiant, valeur)?;
        }
        Ok(lus)
    }

    /// Range un paramètre connu.
    fn appliquer(&mut self, identifiant: u64, valeur: &[u8]) -> Result<(), Error> {
        let faute = || Error::new(Reason::BadTransportParameter);
        let entier = || -> Result<u64, Error> {
            let (lu, avance) = varint::decode(valeur)?;
            // **LA VALEUR OCCUPE TOUT CE QU'ELLE ANNONCE, ET RIEN DE PLUS.** Des
            // octets en trop derrière un entier voudraient dire qu'on n'a pas
            // lu ce que le pair a écrit — et l'on prendrait sa limite pour une
            // autre.
            match avance == valeur.len() {
                true => Ok(lu),
                false => Err(faute()),
            }
        };
        match identifiant {
            0x00 => self.original_destination_connection_id = Some(ConnectionId::new(valeur)?),
            0x01 => self.max_idle_timeout_ms = entier()?,
            // §18.2 : le jeton de réinitialisation vit avec les identifiants, et
            // la poignée de main le porte séparément. On le lit pour vérifier sa
            // taille, et l'on n'en fait rien ici.
            0x02 => {
                if valeur.len() != crate::frame::STATELESS_RESET_TOKEN_OCTETS {
                    return Err(faute());
                }
            }
            0x03 => {
                let taille = entier()?;
                // §18.2 : au moins 1200, sans quoi le pair ne pourrait pas
                // recevoir la poignée de main elle-même.
                if taille < MIN_UDP_PAYLOAD_SIZE {
                    return Err(faute());
                }
                self.max_udp_payload_size = taille;
            }
            0x04 => self.initial_max_data = entier()?,
            0x05 => self.initial_max_stream_data_bidi_local = entier()?,
            0x06 => self.initial_max_stream_data_bidi_remote = entier()?,
            0x07 => self.initial_max_stream_data_uni = entier()?,
            0x08 => self.initial_max_streams_bidi = borner_les_flux(entier()?)?,
            0x09 => self.initial_max_streams_uni = borner_les_flux(entier()?)?,
            0x0a => {
                let exposant = entier()?;
                if exposant > u64::from(ACK_DELAY_EXPONENT_MAX) {
                    return Err(faute());
                }
                // L'exposant tient dans un `u32` : on vient de le borner à vingt.
                self.ack_delay_exponent = u32::try_from(exposant).unwrap_or(0);
            }
            0x0b => {
                let delai = entier()?;
                if delai >= MAX_ACK_DELAY_LIMIT_MS {
                    return Err(faute());
                }
                self.max_ack_delay_ms = delai;
            }
            0x0c => {
                // §18.2 : il ne porte aucune valeur. Des octets derrière lui
                // voudraient dire qu'on ne parle pas du même paramètre.
                if !valeur.is_empty() {
                    return Err(faute());
                }
                self.disable_active_migration = true;
            }
            // §18.2 : l'adresse préférée, que ce serveur n'annonce pas et dont
            // il ne fait rien. On la lit pour ne pas décaler la suite.
            0x0d => {}
            0x0e => {
                let combien = entier()?;
                if combien < MIN_ACTIVE_CONNECTION_ID_LIMIT {
                    return Err(faute());
                }
                self.active_connection_id_limit = combien;
            }
            0x0f => self.initial_source_connection_id = Some(ConnectionId::new(valeur)?),
            // Il ne reste que 0x10 : `rang_connu` n'a laissé passer que ceux-là.
            _ => self.retry_source_connection_id = Some(ConnectionId::new(valeur)?),
        }
        Ok(())
    }
}

/// Ce qui pose des paramètres dans un tampon, l'un après l'autre.
///
/// **CHAQUE PARAMÈTRE EST UN TRIPLET** (§18) : identifiant, longueur, valeur —
/// les trois en entiers de longueur variable pour les deux premiers. Les écrire
/// à la main à chaque fois inviterait à en oublier un.
struct Plume<'a> {
    /// Où l'on écrit.
    out: &'a mut [u8],
    /// Jusqu'où l'on a écrit.
    rang: usize,
}

impl Plume<'_> {
    /// Pose un paramètre dont la valeur est un entier de longueur variable.
    fn entier(&mut self, identifiant: u64, valeur: u64) -> Result<(), Error> {
        let mut place = [0_u8; 8];
        let ecrits = varint::encode(valeur, &mut place)?;
        self.octets(identifiant, place.get(..ecrits).unwrap_or_default())
    }

    /// Pose un paramètre dont la valeur est une suite d'octets.
    fn octets(&mut self, identifiant: u64, valeur: &[u8]) -> Result<(), Error> {
        let court = || Error::new(Reason::BufferTooSmall);
        // **PAS DE GARDE SUR LA CONVERSION** : une valeur de paramètre est un
        // identifiant de connexion ou rien, donc au plus vingt octets (§17.2).
        // Un `map_err` ici ouvrirait une branche qu'aucune valeur ne peut
        // emprunter, et C2 les refuse.
        let longueur =
            u64::try_from(valeur.len()).expect("une valeur de paramètre tient dans un u64");
        for entier in [identifiant, longueur] {
            // **PAS DE GARDE ICI NON PLUS** : `rang` ne dépasse jamais la
            // longueur du tampon, puisque chaque écriture réussit entièrement ou
            // échoue. Une tranche vide suffit à ce que l'écriture refuse, et
            // c'est ce refus-là qui est éprouvé — plutôt qu'un `None` que rien
            // ne peut produire.
            let place = self.out.get_mut(self.rang..).unwrap_or_default();
            let ecrits = varint::encode(entier, place)?;
            self.rang = self.rang.saturating_add(ecrits);
        }
        let fin = self.rang.saturating_add(valeur.len());
        self.out
            .get_mut(self.rang..fin)
            .ok_or_else(court)?
            .copy_from_slice(valeur);
        self.rang = fin;
        Ok(())
    }
}

/// Le rang d'un paramètre connu, pour le bit qui dit qu'on l'a vu.
///
/// Dix-sept paramètres, de zéro à seize : le rang tient dans le dernier octet de
/// l'identifiant, et `to_be_bytes` le prend sans conversion à refuser. Écrire un
/// `try_from` ici ouvrirait une branche qu'aucun identifiant connu ne peut
/// emprunter.
fn rang_connu(identifiant: u64) -> Option<u32> {
    match identifiant {
        0x00..=0x10 => Some(u32::from(identifiant.to_be_bytes()[7])),
        _ => None,
    }
}

/// Ce paramètre appartient-il à celui qui l'envoie (§18.2) ?
const fn appartient_a(identifiant: u64, de: Sender) -> bool {
    match identifiant {
        // Ceux que seul un serveur peut annoncer : ils décrivent ce que LUI a
        // fait de la poignée de main.
        0x00 | 0x02 | 0x0d | 0x10 => matches!(de, Sender::Server),
        _ => true,
    }
}

/// La borne de 2^60 de §19.11, vue depuis les paramètres.
fn borner_les_flux(compte: u64) -> Result<u64, Error> {
    match compte <= MAX_STREAMS_LIMIT {
        true => Ok(compte),
        false => Err(Error::new(Reason::BadTransportParameter)),
    }
}

#[cfg(test)]
mod tests;
