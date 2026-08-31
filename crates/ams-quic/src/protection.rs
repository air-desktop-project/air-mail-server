// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'il faut pour protéger un paquet — §5 de RFC 9001, vu comme un contrat.
//!
//! # POURQUOI UN TRAIT PLUTÔT QU'UN TYPE
//!
//! Les clés d'un paquet viennent de deux endroits, et ce n'est pas un choix :
//!
//! - **celles des paquets `Initial` se dérivent de l'identifiant de
//!   destination** (§5.2), en clair, avant toute poignée de main. C'est
//!   `ams-quic-crypto` qui les fabrique, et personne d'autre ne le peut ;
//! - **celles de `Handshake` et de `1-RTT` viennent de la poignée de main**, et
//!   `rustls` ne les rend que dans des objets à lui — `Box<dyn PacketKey>` —
//!   dont rien n'extrait la matière.
//!
//! Le PLACEMENT des octets, lui, est le même dans les deux cas : c'est §17 qui
//! le décrit, et il ne dépend pas de qui a fabriqué la clé. Écrire deux fois
//! [`crate::seal_packet`] — une par source — donnerait deux implémentations de
//! §17 qui finiraient par diverger sur le cas que personne n'a éprouvé.
//!
//! Ce trait est donc la couture : **la disposition est écrite une fois, et la
//! cryptographie se branche**.
//!
//! # CE N'EST PAS UNE ABSTRACTION SPÉCULATIVE
//!
//! Elle a exactement deux implémentations, et toutes deux existent : celle
//! d'[`ams_quic_crypto::Keys`], juste en dessous, et celle d'`ams-quic-tls` qui
//! enveloppe les clés de `rustls`. Le trait est né du câblage, pas d'un plan.
//!
//! # IL EST UTILISABLE DERRIÈRE UN POINTEUR, ET IL LE FAUT
//!
//! Une connexion tient trois jeux de clés — un par espace — et **ils ne sont pas
//! du même type** : celui de l'espace `Initial` vient de nous, les deux autres de
//! `rustls`. Les ranger côte à côte demande un objet de trait, et c'est pourquoi
//! [`crate::seal_packet`] et [`crate::open_packet`] acceptent un
//! `&(impl Protection + ?Sized)`.

use ams_quic_crypto::{Error, Keys, protect, unprotect};

/// Ce qu'il faut savoir faire pour protéger un paquet (§5 de RFC 9001).
///
/// # LES DEUX MOITIÉS SONT SÉPARÉES, ET §5.4 LES SÉPARE AUSSI
///
/// Chiffrer la charge et masquer l'en-tête sont deux opérations, avec deux clés
/// et deux moments. Les réunir en une seule méthode obligerait chaque
/// implémentation à connaître l'ordre — alors que c'est [`crate::seal_packet`]
/// qui le connaît, et lui seul.
pub trait Protection {
    /// Ce qu'un tag d'authentification occupe.
    fn tag_len(&self) -> usize;

    /// Chiffre en place, et rend ce que le chiffré occupe, tag compris.
    ///
    /// `tampon` porte `clair` octets de clair puis la place du tag ; `aad` est
    /// l'en-tête entier, du premier octet à la fin du numéro (§5.3).
    ///
    /// # Errors
    ///
    /// Quand la charge dépasse ce qu'un datagramme porte, ou que le tampon ne
    /// laisse pas la place du tag.
    fn seal(
        &self,
        numero: u64,
        aad: &[u8],
        tampon: &mut [u8],
        clair: usize,
    ) -> Result<usize, Error>;

    /// Déchiffre en place, et rend la longueur du clair.
    ///
    /// # Errors
    ///
    /// Quand le paquet ne s'authentifie pas. **CELLE-LÀ SE JETTE EN SILENCE**
    /// (§5.3) : le port est ouvert au monde entier, et fermer une connexion sur
    /// un paquet qu'on n'a pas pu authentifier l'offrirait à qui sait envoyer un
    /// datagramme.
    fn open(&self, numero: u64, aad: &[u8], tampon: &mut [u8]) -> Result<usize, Error>;

    /// Pose la protection d'en-tête (§5.4.1), sachant la longueur du numéro.
    ///
    /// # Errors
    ///
    /// Quand le paquet est trop court pour porter un échantillon (§5.4.2).
    fn protect(&self, paquet: &mut [u8], numero_a: usize, longueur: usize) -> Result<(), Error>;

    /// L'ôte, et rend la longueur du numéro.
    ///
    /// # L'ORDRE EST INVERSE, ET C'EST TOUTE LA DIFFÉRENCE
    ///
    /// §5.4.1 : « Removing header protection only differs in the order in which
    /// the packet number length is determined. » À l'écriture on connaît la
    /// longueur et l'on masque ; à la lecture on démasque le premier octet, on Y
    /// LIT la longueur, puis on démasque le numéro.
    ///
    /// # Errors
    ///
    /// Quand le paquet est trop court pour porter un échantillon.
    fn unprotect(&self, paquet: &mut [u8], numero_a: usize) -> Result<usize, Error>;
}

impl Protection for Keys {
    fn tag_len(&self) -> usize {
        ams_quic_crypto::TAG_OCTETS
    }

    fn seal(
        &self,
        numero: u64,
        aad: &[u8],
        tampon: &mut [u8],
        clair: usize,
    ) -> Result<usize, Error> {
        Self::seal(self, numero, aad, tampon, clair)
    }

    fn open(&self, numero: u64, aad: &[u8], tampon: &mut [u8]) -> Result<usize, Error> {
        Self::open(self, numero, aad, tampon)
    }

    fn protect(&self, paquet: &mut [u8], numero_a: usize, longueur: usize) -> Result<(), Error> {
        protect(self, paquet, numero_a, longueur)
    }

    fn unprotect(&self, paquet: &mut [u8], numero_a: usize) -> Result<usize, Error> {
        unprotect(self, paquet, numero_a)
    }
}
