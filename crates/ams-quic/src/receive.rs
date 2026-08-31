// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! L'ouverture d'un paquet : de l'en-tête aux trames (RFC 9000 §12, RFC 9001
//! §5).
//!
//! # L'ORDRE DES OPÉRATIONS N'EST PAS NÉGOCIABLE
//!
//! 1. lire l'en-tête EN CLAIR — jusqu'à l'identifiant de destination ;
//! 2. y trouver les clés ;
//! 3. ôter la protection d'en-tête, ce qui découvre la longueur du numéro ;
//! 4. reconstruire le numéro, qui entre dans le nonce ;
//! 5. déchiffrer, l'en-tête servant de données associées ;
//! 6. **alors seulement**, vérifier les bits réservés.
//!
//! Chaque étape a besoin de la précédente, et la sixième est la plus facile à
//! mettre au mauvais endroit : §17.2 dit « after removing both packet and header
//! protection », et §9.5 de RFC 9001 explique pourquoi — refuser un paquet
//! après n'avoir ôté que la protection d'EN-TÊTE dit à un attaquant que son
//! masque était bon, et lui donne un oracle.
//!
//! # UN DATAGRAMME PORTE PLUSIEURS PAQUETS
//!
//! §12.2 : les paquets à en-tête long portent une longueur, et se suivent dans
//! un même datagramme. Celui à en-tête court n'en porte pas — **il ne peut donc
//! être que le dernier**, et va jusqu'au bout du datagramme.
//!
//! On rend donc ce que chaque paquet occupe, et l'appelant avance. Un paquet
//! qu'on ne sait pas lire arrête le parcours : la suite du datagramme n'a plus
//! de frontière connue.
//!
//! # LES CHARGES SE RENDENT PAR LEURS RANGS, ET NON PAR DES TRANCHES
//!
//! Le déchiffrement se fait EN PLACE. Rendre une tranche du datagramme
//! emprunterait celui-ci pour toute la durée du paquet, et l'appelant ne
//! pourrait plus ouvrir le suivant. Des rangs le laissent libre — et c'est lui
//! qui découpe, puisque c'est lui qui possède le tampon.

use ams_proto_quic::{
    Long, LongKind, PACKET_NUMBER_OCTETS_MAX, ShortHeader, is_long, packet_numbers, parse_long,
};
use ams_quic_crypto::{Keys, unprotect};

use crate::error::{Error, Reason};

/// Les deux bits réservés d'un en-tête long (§17.2).
const RESERVES_LONG: u8 = 0x0c;

/// Les deux bits réservés d'un en-tête court (§17.3.1).
const RESERVES_COURT: u8 = 0x18;

/// Le bit de phase de clé d'un en-tête court (§17.3.1).
const BIT_PHASE: u8 = 0x04;

/// Ce qu'un paquet s'est trouvé être.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    /// `Initial`, `0-RTT` ou `Handshake`.
    Long(LongKind),
    /// `1-RTT`, l'en-tête court.
    Short,
}

/// Un paquet ouvert, décrit par des rangs dans le datagramme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opened {
    /// Ce qu'il s'est trouvé être.
    pub kind: PacketKind,
    /// Son numéro, reconstruit.
    pub number: u64,
    /// Où commence sa charge déchiffrée, dans le datagramme.
    pub payload_at: usize,
    /// Ce que sa charge déchiffrée occupe.
    pub payload_len: usize,
    /// Ce que le paquet entier occupe dans le datagramme.
    ///
    /// **C'EST DE CELA QUE L'APPELANT AVANCE** pour lire le paquet suivant
    /// (§12.2).
    pub total: usize,
    /// La phase de clé, pour un en-tête court (§17.3.1).
    ///
    /// **ELLE NE SE LIT QU'APRÈS LE DÉMASQUAGE** : le bit est protégé, comme le
    /// numéro. Un observateur ne peut donc pas compter les mises à jour de clé.
    pub key_phase: bool,
}

/// Ouvre le premier paquet d'un datagramme, en place.
///
/// `plus_grand` est le plus grand numéro déjà traité dans l'espace de ce paquet,
/// et `identifiant` la longueur des identifiants de connexion qu'on émet — que
/// seul un en-tête court exige, puisqu'il ne l'annonce pas.
///
/// # Errors
///
/// [`Reason::NotForUs`] et [`Reason::NotAuthentic`] se JETTENT ;
/// [`Reason::ReservedBitsSet`] et [`Reason::BadPacketNumber`] condamnent.
pub fn open_packet(
    datagramme: &mut [u8],
    clefs: &Keys,
    plus_grand: Option<u64>,
    identifiant: usize,
) -> Result<Opened, Error> {
    match is_long(datagramme) {
        true => ouvrir_long(datagramme, clefs, plus_grand),
        false => ouvrir_court(datagramme, clefs, plus_grand, identifiant),
    }
}

/// Ouvre un paquet à en-tête long.
fn ouvrir_long(
    datagramme: &mut [u8],
    clefs: &Keys,
    plus_grand: Option<u64>,
) -> Result<Opened, Error> {
    let jeter = || Error::new(Reason::NotForUs);
    // **ON RECOPIE CE QU'ON RETIENT AVANT D'ÉCRIRE.** L'en-tête lu EMPRUNTE le
    // datagramme — il porte le jeton et les identifiants —, et le déchiffrement
    // veut ce même datagramme en écriture. Trois nombres suffisent à la suite :
    // on les prend, et l'emprunt se referme.
    let (kind, numero_a, longueur) = match parse_long(datagramme).map_err(|_| jeter())? {
        Long::Numbered(entete) => (
            entete.kind(),
            entete.number_offset(),
            usize::try_from(entete.length()).unwrap_or(usize::MAX),
        ),
        // §17.2.1 et §17.2.5 : ni l'un ni l'autre ne se déchiffre, et un SERVEUR
        // n'a rien à en faire. On les jette plutôt que de prétendre les ouvrir.
        Long::Negotiation(_) | Long::Retry(_) => return Err(jeter()),
    };
    // §12.2 : la longueur dit où le paquet s'arrête — c'est elle qui permet d'en
    // coaliser plusieurs dans un datagramme.
    let fin = numero_a.saturating_add(longueur);
    let paquet = datagramme.get_mut(..fin).ok_or_else(jeter)?;
    let ouvert = ouvrir(paquet, clefs, plus_grand, numero_a, RESERVES_LONG)?;
    Ok(Opened {
        kind: PacketKind::Long(kind),
        total: fin,
        key_phase: false,
        ..ouvert
    })
}

/// Ouvre un paquet à en-tête court.
fn ouvrir_court(
    datagramme: &mut [u8],
    clefs: &Keys,
    plus_grand: Option<u64>,
    identifiant: usize,
) -> Result<Opened, Error> {
    let jeter = || Error::new(Reason::NotForUs);
    let entete = ShortHeader::parse(datagramme, identifiant).map_err(|_| jeter())?;
    // §12.2 : un en-tête court ne porte pas de longueur, et ne peut donc être
    // que le DERNIER paquet du datagramme. Il va jusqu'au bout.
    let total = datagramme.len();
    let ouvert = ouvrir(
        datagramme,
        clefs,
        plus_grand,
        entete.number_offset(),
        RESERVES_COURT,
    )?;
    let phase = datagramme
        .first()
        .is_some_and(|premier| premier & BIT_PHASE != 0);
    Ok(Opened {
        kind: PacketKind::Short,
        total,
        key_phase: phase,
        ..ouvert
    })
}

/// Démasque, reconstruit, déchiffre, puis vérifie les bits réservés.
fn ouvrir(
    paquet: &mut [u8],
    clefs: &Keys,
    plus_grand: Option<u64>,
    numero_a: usize,
    reserves: u8,
) -> Result<Opened, Error> {
    let jeter = || Error::new(Reason::NotForUs);
    // 3. La protection d'en-tête découvre la longueur du numéro.
    let longueur = unprotect(clefs, paquet, numero_a).map_err(|_| jeter())?;
    let fin_du_numero = numero_a.saturating_add(longueur);
    let tronque = lire_numero(paquet, numero_a, longueur);
    // 4. Le numéro se reconstruit à partir de ce qu'on a déjà traité.
    let number = packet_numbers::decode(plus_grand, tronque, longueur)
        .map_err(|_| Error::new(Reason::BadPacketNumber))?;
    // 5. **L'EN-TÊTE ENTIER EST LES DONNÉES ASSOCIÉES** (§5.3 de RFC 9001) : du
    // premier octet à la fin du numéro. Un en-tête modifié en chemin fait donc
    // échouer l'authentification, et cela protège la longueur et l'identifiant
    // autant que la charge.
    // **LA COUPURE TIENT TOUJOURS** : le démasquage a déjà exigé seize octets
    // d'échantillon quatre octets après le numéro, donc bien au-delà de sa fin.
    // Le `min` rend la coupure totale — elle paniquerait au-delà, et une panique
    // vaut moins qu'une borne.
    let (aad, chiffre) = paquet.split_at_mut(fin_du_numero.min(paquet.len()));
    let clair = clefs
        .open(number, aad, chiffre)
        .map_err(|_| Error::new(Reason::NotAuthentic))?;
    // 6. **ET SEULEMENT MAINTENANT, LES BITS RÉSERVÉS.** §9.5 de RFC 9001 :
    // refuser plus tôt dirait à un attaquant que son masque d'en-tête était bon,
    // et lui donnerait un oracle pour le deviner octet par octet.
    let premier = paquet.first().copied().unwrap_or(0);
    if premier & reserves != 0 {
        return Err(Error::new(Reason::ReservedBitsSet));
    }
    Ok(Opened {
        kind: PacketKind::Short,
        number,
        payload_at: fin_du_numero,
        payload_len: clair,
        total: 0,
        key_phase: false,
    })
}

/// Lit les octets du numéro de paquet, démasqués.
///
/// # ELLE NE PEUT PAS MANQUER SA CIBLE
///
/// La longueur vient de [`unprotect`], qui ne rend que un à quatre ; et le
/// démasquage a déjà exigé que le paquet porte seize octets quatre octets APRÈS
/// le numéro. La tranche existe donc toujours. `unwrap_or_default` porte cette
/// impossibilité plutôt que deux gardes qu'aucun paquet ne peut emprunter.
fn lire_numero(paquet: &[u8], numero_a: usize, longueur: usize) -> u64 {
    let fin = numero_a.saturating_add(longueur.min(PACKET_NUMBER_OCTETS_MAX));
    let octets = paquet.get(numero_a..fin).unwrap_or_default();
    let mut valeur = 0_u64;
    for lu in octets {
        valeur = valeur.saturating_mul(256).saturating_add(u64::from(*lu));
    }
    valeur
}

#[cfg(test)]
mod tests;
