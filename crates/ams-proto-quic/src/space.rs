// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les espaces de numéros de paquet, et les acquittements (RFC 9000 §12.3,
//! §13.2).
//!
//! # TROIS ESPACES, ET ILS NE SE MÉLANGENT JAMAIS
//!
//! §12.3 : `Initial`, `Handshake` et les données applicatives ont chacun leur
//! numérotation, qui repart de zéro. Ce n'est pas une commodité : les trois
//! emploient des CLÉS DIFFÉRENTES, et un numéro de paquet entre dans le nonce.
//! Partager la numérotation ferait réemployer un nonce entre deux espaces — et
//! un nonce réemployé livre la clé d'authentification de GCM.
//!
//! C'est aussi pourquoi un `ACK` ne peut acquitter que des paquets de SON
//! espace : le numéro 3 de l'espace `Initial` et le numéro 3 des données
//! applicatives sont deux paquets différents, et rien ne les distingue qu'à
//! l'espace où on les lit.
//!
//! # ON NE RÉPOND PAS À UN ACQUITTEMENT PAR UN ACQUITTEMENT
//!
//! §13.2.1 : « An endpoint MUST NOT send a non-ack-eliciting packet in response
//! to a non-ack-eliciting packet, even if there are packet gaps that precede
//! the received packet. » Sans cette règle, deux pairs qui n'ont plus rien à se
//! dire s'acquitteraient mutuellement sans fin, et la connexion ne deviendrait
//! jamais oisive.
//!
//! # ET L'ON NE RETIENT PAS TOUS LES INTERVALLES
//!
//! §13.2.3 permet d'en oublier : un pair qui enverrait des paquets aux numéros
//! très espacés obligerait sinon à retenir autant d'intervalles qu'il en
//! choisit. **On oublie les PLUS ANCIENS**, jamais les plus récents : ce sont
//! les récents qui empêchent une retransmission inutile.

use crate::error::{Error, Reason};
use crate::frame::{Ack, Frame};
use crate::packet_number::PACKET_NUMBER_MAX;

/// Combien d'intervalles reçus on retient (§13.2.3).
///
/// Trente-deux. Un réseau ordinaire n'en produit qu'un ou deux ; trente-deux
/// laissent la place à un chemin qui réordonne beaucoup, et refusent le millier
/// qu'un pair choisirait pour nous faire retenir.
pub const RANGES_MAX: usize = 32;

/// Après combien de paquets sollicitant un acquittement on répond sans attendre
/// (§13.2.2).
///
/// Deux. C'est ce que la RFC suggère, et ce que fait tout le monde : un
/// acquittement tous les deux paquets donne à l'émetteur assez de signal pour sa
/// détection de perte, sans doubler le nombre de paquets sur le fil.
pub const ELICITING_BEFORE_ACK: u32 = 2;

/// Un espace de numéros de paquet (§12.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Space {
    /// Les paquets `Initial`, chiffrés avec des clés que tout le monde connaît.
    Initial,
    /// Les paquets `Handshake`.
    Handshake,
    /// Les données applicatives — `0-RTT` et `1-RTT` PARTAGENT cet espace.
    ///
    /// **ET C'EST LA SEULE EXCEPTION À LA SÉPARATION** (§12.3) : les données
    /// précoces et les données ordinaires se numérotent ensemble, parce qu'un
    /// paquet `0-RTT` peut être retransmis en `1-RTT` — c'est la même donnée,
    /// sous une autre protection.
    Application,
}

/// Un intervalle de numéros reçus, du plus grand au plus petit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Intervalle {
    /// Le plus grand numéro de l'intervalle.
    haut: u64,
    /// Le plus petit.
    bas: u64,
}

/// Ce qu'on a reçu dans un espace, et ce qu'on doit en acquitter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Received {
    /// Les intervalles, du plus récent au plus ancien.
    intervalles: [Option<Intervalle>; RANGES_MAX],
    /// Quand le plus grand numéro a été reçu.
    plus_grand_a: u64,
    /// Y a-t-il quelque chose de nouveau à acquitter ?
    a_dire: bool,
    /// Combien de paquets sollicitant un acquittement depuis le dernier envoyé.
    sollicitants: u32,
    /// Faut-il acquitter sans attendre ?
    sans_attendre: bool,
}

impl Default for Received {
    fn default() -> Self {
        Self::new()
    }
}

impl Received {
    /// Un espace où rien n'est encore arrivé.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            intervalles: [None; RANGES_MAX],
            plus_grand_a: 0,
            a_dire: false,
            sollicitants: 0,
            sans_attendre: false,
        }
    }

    /// Le plus grand numéro reçu, s'il y en a un.
    #[must_use]
    pub fn largest(&self) -> Option<u64> {
        self.intervalles.first().copied().flatten().map(|i| i.haut)
    }

    /// Quand le plus grand numéro a été reçu.
    #[must_use]
    pub const fn largest_at(&self) -> u64 {
        self.plus_grand_a
    }

    /// Combien d'intervalles sont retenus.
    #[must_use]
    pub fn len(&self) -> usize {
        self.intervalles.iter().flatten().count()
    }

    /// N'a-t-on rien reçu ?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Ce numéro a-t-il déjà été reçu ?
    ///
    /// # UN DOUBLON N'EST PAS UNE FAUTE, MAIS IL NE SE TRAITE PAS DEUX FOIS
    ///
    /// Le réseau duplique, et un pair peut retransmettre un paquet qu'on avait
    /// déjà. Traiter ses trames deux fois compterait deux fois ses données dans
    /// le contrôle de flux — et fermerait la connexion pour une faute que
    /// personne n'a commise.
    #[must_use]
    pub fn contains(&self, numero: u64) -> bool {
        self.intervalles
            .iter()
            .flatten()
            .any(|i| numero >= i.bas && numero <= i.haut)
    }

    /// Range un paquet reçu.
    ///
    /// `sollicite` dit si le paquet portait autre chose que des `ACK`, du
    /// remplissage et des `CONNECTION_CLOSE` — c'est ce que §13.2.1 appelle
    /// « ack-eliciting ».
    ///
    /// # Errors
    ///
    /// [`Reason::PacketNumberTooLarge`] au-delà de 2^62 - 1.
    pub fn on_received(&mut self, numero: u64, sollicite: bool, instant: u64) -> Result<(), Error> {
        if numero > PACKET_NUMBER_MAX {
            return Err(Error::new(Reason::PacketNumberTooLarge));
        }
        if self.contains(numero) {
            return Ok(());
        }
        // §13.2.1 : on acquitte SANS ATTENDRE un paquet sollicitant qui arrive
        // dans le désordre — c'est ce qui évite au pair de croire à une perte.
        let desordre = self
            .largest()
            .is_some_and(|vu| numero < vu || numero > vu.saturating_add(1));
        let plus_grand = self.largest().is_none_or(|vu| numero > vu);
        self.inserer(numero);
        if plus_grand {
            self.plus_grand_a = instant;
        }
        self.a_dire = true;
        if sollicite {
            self.sollicitants = self.sollicitants.saturating_add(1);
            if desordre {
                self.sans_attendre = true;
            }
        }
        Ok(())
    }

    /// Faut-il acquitter sans attendre ?
    ///
    /// # ON NE RÉPOND PAS À UN ACQUITTEMENT PAR UN ACQUITTEMENT
    ///
    /// §13.2.1. Un paquet qui ne sollicite rien ne fait rien envoyer — même s'il
    /// laisse un trou. Sans cela, deux pairs qui n'ont plus rien à se dire
    /// s'acquitteraient mutuellement sans fin.
    #[must_use]
    pub const fn should_ack_now(&self) -> bool {
        self.sans_attendre || self.sollicitants >= ELICITING_BEFORE_ACK
    }

    /// Y a-t-il quelque chose à acquitter ?
    #[must_use]
    pub const fn has_pending(&self) -> bool {
        self.a_dire
    }

    /// Un paquet sollicitant attend-il un acquittement ?
    ///
    /// C'est lui, et lui seul, qui autorise à envoyer un paquet qui ne porte
    /// qu'un `ACK`.
    #[must_use]
    pub const fn owes_ack(&self) -> bool {
        self.sollicitants > 0
    }

    /// L'instant au plus tard où l'acquittement doit partir, en microsecondes.
    ///
    /// `delai_max` est ce qu'on a annoncé dans `max_ack_delay`. `None` s'il n'y
    /// a rien à acquitter — ou si ce qu'il y a ne sollicite pas d'acquittement.
    ///
    /// # LE DÉLAI EST UN CONTRAT, ET LE DÉPASSER COÛTE AU PAIR
    ///
    /// §13.2.1 : « max_ack_delay declares an explicit contract ». Ce qu'on
    /// attend au-delà s'ajoute à l'estimation d'aller-retour du pair, et lui
    /// fait retransmettre ce qui était en route.
    #[must_use]
    pub fn ack_deadline(&self, delai_max: u64) -> Option<u64> {
        match self.owes_ack() {
            true => Some(self.plus_grand_a.saturating_add(delai_max)),
            false => None,
        }
    }

    /// Écrit un `ACK` couvrant ce qu'on a reçu.
    ///
    /// `instant` sert à mesurer le délai qu'on annonce ; `exposant` est celui
    /// qu'on a annoncé dans `ack_delay_exponent`.
    ///
    /// Rend ce que la trame occupe, ou `None` s'il n'y a rien à acquitter.
    ///
    /// # Errors
    ///
    /// [`Reason::BufferTooSmall`].
    pub fn write_ack(
        &self,
        instant: u64,
        exposant: u32,
        out: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        let Some(plus_grand) = self.largest() else {
            return Ok(None);
        };
        // §19.3 : le délai s'écrit en unités de 2^exposant microsecondes.
        let attendu = instant.saturating_sub(self.plus_grand_a);
        let delay = attendu.checked_shr(exposant).unwrap_or(0);
        // Les intervalles s'écrivent dans un tampon à part, puis se recopient :
        // la trame les porte APRÈS des champs dont la longueur dépend d'eux.
        let mut ecrits = [0_u8; RANGES_MAX * 16];
        let (compte, poses) = self.ecrire_intervalles(&mut ecrits);
        let premier = self.premier_intervalle().unwrap_or(0);
        let trame = Frame::Ack(Ack {
            largest: plus_grand,
            delay,
            first_range: premier,
            range_count: compte,
            encoded_ranges: ecrits.get(..poses).unwrap_or_default(),
            // **ON N'ANNONCE PAS D'ECN**, parce qu'on ne le lit pas : annoncer
            // des comptes qu'on ne tient pas ferait croire au pair que le réseau
            // va bien quand il ne va pas.
            ecn: None,
        });
        Ok(Some(trame.write(out)?))
    }

    /// Un `ACK` vient d'être envoyé.
    ///
    /// **LES INTERVALLES RESTENT** : §13.2.3 veut qu'un `ACK` acquitte à nouveau
    /// ce qu'il a déjà acquitté, au cas où le précédent se serait perdu. Seul le
    /// compte des sollicitants repart.
    pub const fn on_ack_sent(&mut self) {
        self.a_dire = false;
        self.sollicitants = 0;
        self.sans_attendre = false;
    }

    /// Combien de numéros le premier intervalle acquitte, sous le plus grand.
    fn premier_intervalle(&self) -> Option<u64> {
        self.intervalles
            .first()
            .copied()
            .flatten()
            .map(|i| i.haut.saturating_sub(i.bas))
    }

    /// Écrit les intervalles qui suivent le premier, et rend leur nombre.
    ///
    /// # ELLE NE PEUT PAS MANQUER DE PLACE
    ///
    /// Le tampon fait `RANGES_MAX * 16` octets, et chaque intervalle en occupe
    /// au plus seize — deux entiers de §16 de huit octets chacun. Il y a au plus
    /// `RANGES_MAX - 1` intervalles à écrire ici, le premier voyageant à part.
    /// `unwrap_or` porte cette impossibilité plutôt qu'une garde qu'aucune liste
    /// ne peut emprunter.
    fn ecrire_intervalles(&self, out: &mut [u8]) -> (u64, usize) {
        let mut compte = 0_u64;
        let mut ecrits = 0_usize;
        let mut precedent = self
            .intervalles
            .first()
            .copied()
            .flatten()
            .map_or(0, |premier| premier.bas);
        for intervalle in self.intervalles.iter().skip(1).flatten() {
            // §19.3.1 : l'écart compte les numéros MANQUANTS, moins un — et le
            // « moins un » est ce qu'on oublie en le réécrivant de mémoire.
            let ecart = precedent.saturating_sub(intervalle.haut).saturating_sub(2);
            let longueur = intervalle.haut.saturating_sub(intervalle.bas);
            for valeur in [ecart, longueur] {
                let place = out.get_mut(ecrits..).unwrap_or_default();
                let poses = crate::varint::encode(valeur, place).unwrap_or(0);
                ecrits = ecrits.saturating_add(poses);
            }
            compte = compte.saturating_add(1);
            precedent = intervalle.bas;
        }
        (compte, ecrits)
    }

    /// Range un numéro dans les intervalles.
    fn inserer(&mut self, numero: u64) {
        // Le numéro prolonge-t-il un intervalle existant ?
        for place in &mut self.intervalles {
            let Some(intervalle) = place.as_mut() else {
                continue;
            };
            if numero == intervalle.haut.saturating_add(1) {
                intervalle.haut = numero;
                self.fusionner();
                return;
            }
            if numero.saturating_add(1) == intervalle.bas {
                intervalle.bas = numero;
                self.fusionner();
                return;
            }
        }
        // Non : il en ouvre un nouveau, qu'on range à sa place.
        self.ranger(Intervalle {
            haut: numero,
            bas: numero,
        });
    }

    /// Range un intervalle neuf, du plus récent au plus ancien.
    ///
    /// **ON OUBLIE LE PLUS ANCIEN, JAMAIS LE PLUS RÉCENT** (§13.2.3) : ce sont
    /// les récents qui empêchent une retransmission inutile.
    fn ranger(&mut self, neuf: Intervalle) {
        let mut a_placer = Some(neuf);
        for place in &mut self.intervalles {
            let Some(courant) = a_placer else {
                return;
            };
            match *place {
                // Une place libre : on y met ce qu'on porte.
                None => {
                    *place = Some(courant);
                    a_placer = None;
                }
                // Un intervalle plus ancien : le neuf passe devant, et l'on
                // continue avec celui qu'on vient de déloger.
                Some(existant) if existant.haut < courant.haut => {
                    *place = Some(courant);
                    a_placer = Some(existant);
                }
                Some(_) => {}
            }
        }
        // Ce qui reste à placer était le plus ancien : il tombe.
    }

    /// Réunit les intervalles devenus contigus.
    ///
    /// # AUCUNE INDEXATION, ET C'EST VOULU
    ///
    /// Une première écriture décalait la table par rangs, avec un `get_mut` à
    /// chaque pas. Ces accès ne pouvaient pas manquer — le rang venait de la
    /// boucle — et ouvraient donc quatre branches qu'aucune liste ne pouvait
    /// emprunter. `zip` s'arrête à la plus courte des deux suites, et n'a rien à
    /// refuser.
    ///
    /// # L'ORDRE DES DEUX CÔTÉS DU `zip` DÉCIDE LEQUEL PERD UN ÉLÉMENT
    ///
    /// `Zip::next` interroge le PREMIER itérateur, puis le second ; si le second
    /// est épuisé, **l'élément déjà tiré du premier est jeté**. Une première
    /// écriture mettait la destination en premier : chaque écriture consommait
    /// donc DEUX places de la table et n'en remplissait qu'une, laissant un trou.
    ///
    /// La table restait triée, les trous ne se voyaient pas, et l'on continuait
    /// d'y ranger — jusqu'à ce qu'un intervalle se retrouve du mauvais côté d'un
    /// autre. L'`ACK` acquittait alors un paquet jamais reçu, et l'émetteur ne le
    /// retransmettait jamais. **Le fuzz l'a trouvé ; aucun test écrit à la main
    /// ne l'aurait fait**, parce qu'il faut cinq numéros dans un ordre précis.
    ///
    /// La source de ces quelques octets est donc en premier, et la destination
    /// en second.
    fn fusionner(&mut self) {
        let mut reunis = [None; RANGES_MAX];
        let mut sortie = reunis.iter_mut();
        let mut porte: Option<Intervalle> = None;
        for courant in self.intervalles.iter().flatten().copied() {
            let Some(avant) = porte else {
                porte = Some(courant);
                continue;
            };
            // Ils se touchent — ou se recouvrent — : on les réunit.
            if courant.haut.saturating_add(1) >= avant.bas {
                porte = Some(Intervalle {
                    haut: avant.haut,
                    bas: courant.bas,
                });
                continue;
            }
            for (lu, place) in core::iter::once(avant).zip(sortie.by_ref()) {
                *place = Some(lu);
            }
            porte = Some(courant);
        }
        for (lu, place) in porte.into_iter().zip(sortie) {
            *place = Some(lu);
        }
        self.intervalles = reunis;
    }
}

#[cfg(test)]
mod tests;
