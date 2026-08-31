// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les clés que `rustls` rend, vues comme une protection de paquet.
//!
//! # POURQUOI CETTE COUTURE EXISTE
//!
//! Les clés des paquets `Initial` se dérivent de l'identifiant de destination
//! (§5.2 de RFC 9001) : `ams-quic-crypto` les fabrique, et elles sont à nous.
//! Celles de `Handshake` et de `1-RTT` viennent de la poignée de main, et
//! `rustls` ne les rend que dans des `Box<dyn PacketKey>` dont rien n'extrait la
//! matière.
//!
//! Le PLACEMENT des octets, lui, est le même : c'est §17 de RFC 9000 qui le
//! décrit. [`ams_quic::Protection`] est la couture qui permet à
//! `ams_quic::seal_packet` de s'appliquer aux deux — **la disposition écrite une
//! fois, la cryptographie branchée**.
//!
//! # ET LE DÉMASQUAGE SE FAIT EN DEUX APPELS, POUR UNE BONNE RAISON
//!
//! §5.4.1 ne démasque QUE la longueur réelle du numéro de paquet — et cette
//! longueur est dans le premier octet, qui est lui-même masqué. L'interface de
//! `rustls` démasque le premier octet et les octets de numéro qu'on lui donne,
//! en un seul appel : lui en donner quatre en démasquerait quatre, alors que le
//! numéro peut n'en faire qu'un. **Les trois de trop appartiennent à la charge
//! chiffrée**, et les toucher la rendrait indéchiffrable.
//!
//! On appelle donc deux fois : une pour découvrir la longueur, une pour
//! démasquer exactement ce qu'elle annonce.

use ams_quic::Protection;
use ams_quic_crypto::{Error, Reason};
use rustls::quic::{HeaderProtectionKey, PacketKey};

/// Ce que la protection d'en-tête échantillonne (§5.4.2).
const ECHANTILLON_OCTETS: usize = 16;

/// De combien d'octets l'échantillon suit le début du numéro (§5.4.2).
const ECHANTILLON_APRES: usize = 4;

/// Les deux bits qui portent la longueur du numéro, moins un (§17.2, §17.3).
const BITS_DE_LONGUEUR: u8 = 0x03;

/// Les clés d'un sens, telles que `rustls` les rend.
pub struct Clefs {
    /// Ce qui chiffre la charge.
    paquet: Box<dyn PacketKey>,
    /// Ce qui masque l'en-tête.
    entete: Box<dyn HeaderProtectionKey>,
}

impl Clefs {
    /// Les clés d'un sens, telles qu'un changement de `rustls` les donne.
    #[must_use]
    pub fn new(paquet: Box<dyn PacketKey>, entete: Box<dyn HeaderProtectionKey>) -> Self {
        Self { paquet, entete }
    }

    /// L'échantillon de §5.4.2, s'il tient.
    fn echantillon(
        &self,
        paquet: &[u8],
        numero_a: usize,
    ) -> Result<[u8; ECHANTILLON_OCTETS], Error> {
        let court = || Error::new(Reason::TooShortToSample);
        // §5.4.2 : quatre octets après le début du numéro, **comme si celui-ci
        // en faisait toujours quatre** — le pair qui démasque ne connaît pas
        // encore sa longueur réelle.
        let debut = numero_a.saturating_add(ECHANTILLON_APRES);
        let fin = debut.saturating_add(self.entete.sample_len());
        paquet
            .get(debut..fin)
            .and_then(|lus| lus.try_into().ok())
            .ok_or_else(court)
    }
}

impl core::fmt::Debug for Clefs {
    /// **RIEN DE CE QUI EST SECRET NE S'IMPRIME.**
    ///
    /// Ces objets portent de quoi lire toute la suite de la connexion. Un
    /// `Debug` qui les détaillerait les ferait entrer dans le premier message
    /// de diagnostic venu, puis dans un journal, puis dans un ticket.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Clefs").finish_non_exhaustive()
    }
}

impl Protection for Clefs {
    fn tag_len(&self) -> usize {
        self.paquet.tag_len()
    }

    fn seal(
        &self,
        numero: u64,
        aad: &[u8],
        tampon: &mut [u8],
        clair: usize,
    ) -> Result<usize, Error> {
        let court = || Error::new(Reason::BufferTooSmall);
        let total = clair.saturating_add(self.tag_len());
        if tampon.len() < total {
            return Err(court());
        }
        // **`rustls` REND LE TAG À PART** quand `ams-quic-crypto` l'écrit à la
        // suite du clair. On chiffre donc la partie claire, puis on pose le tag
        // derrière — à la place que l'appelant a déjà réservée.
        let (corps, queue) = tampon.split_at_mut(clair);
        let tag = self
            .paquet
            .encrypt_in_place(numero, aad, corps)
            .map_err(|_| Error::new(Reason::NotAuthentic))?;
        // **PAS DE GARDE ICI** : la vérification ci-dessus a réservé la place
        // du tag, et `tag_len` est celle que `rustls` annonce. Un `get_mut`
        // rendrait une variante vide que rien ne peut atteindre.
        queue[..tag.as_ref().len()].copy_from_slice(tag.as_ref());
        Ok(total)
    }

    fn open(&self, numero: u64, aad: &[u8], tampon: &mut [u8]) -> Result<usize, Error> {
        let faux = || Error::new(Reason::NotAuthentic);
        let clair = self
            .paquet
            .decrypt_in_place(numero, aad, tampon)
            .map_err(|_| faux())?
            .len();
        Ok(clair)
    }

    fn protect(&self, paquet: &mut [u8], numero_a: usize, longueur: usize) -> Result<(), Error> {
        let court = || Error::new(Reason::TooShortToSample);
        let echantillon = self.echantillon(paquet, numero_a)?;
        // **L'ÉCHANTILLON A DÉJÀ TOUT GARANTI.** Il exige que le paquet
        // atteigne `numero_a + 4 + 16` octets, donc le premier octet existe et
        // le numéro — quatre octets au plus (§17.1) — tient largement. Les
        // découpes ci-dessous sont donc des index : une garde inatteignable
        // n'est pas une garde.
        let (tete, suite) = paquet.split_at_mut(1);
        let debut = numero_a.saturating_sub(1);
        let fin = debut.saturating_add(longueur);
        self.entete
            .encrypt_in_place(&echantillon, &mut tete[0], &mut suite[debut..fin])
            .map_err(|_| court())
    }

    fn unprotect(&self, paquet: &mut [u8], numero_a: usize) -> Result<usize, Error> {
        let court = || Error::new(Reason::TooShortToSample);
        let echantillon = self.echantillon(paquet, numero_a)?;

        // **PREMIER APPEL : rien que l'octet de tête.** Une tranche de numéro
        // vide ne démasque que lui, et c'est lui qui porte la longueur.
        let (tete, suite) = paquet.split_at_mut(1);
        self.entete
            .decrypt_in_place(&echantillon, &mut tete[0], &mut [])
            .map_err(|_| court())?;
        let longueur = usize::from(tete[0] & BITS_DE_LONGUEUR).saturating_add(1);

        // **SECOND APPEL : exactement la longueur annoncée.** L'octet de tête
        // qu'on donne ici est un leurre — il serait démasqué une seconde fois,
        // et l'on ne veut pas cela. Le masque du numéro, lui, ne dépend pas de
        // lui : §5.4.1 ne s'en sert que pour choisir combien de bits de tête
        // masquer.
        let debut = numero_a.saturating_sub(1);
        let fin = debut.saturating_add(longueur);
        let mut leurre = tete[0];
        self.entete
            .decrypt_in_place(&echantillon, &mut leurre, &mut suite[debut..fin])
            .map_err(|_| court())?;
        Ok(longueur)
    }
}

#[cfg(test)]
mod tests;
