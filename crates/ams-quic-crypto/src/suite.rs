// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les suites de chiffrement que ce serveur emploie (RFC 9001 §5.3).
//!
//! # TROIS, ET NON QUATRE
//!
//! §5.4.3 mentionne aussi `AEAD_AES_128_CCM`. On ne la sert pas : la suite TLS
//! qui l'emploie est `TLS_AES_128_CCM_8_SHA256`, dont §5.4 dit explicitement
//! qu'aucun schéma de protection d'en-tête n'est défini pour elle — et aucune
//! des bibliothèques TLS de cet arbre ne la propose. Écrire ce chemin serait
//! écrire une branche qu'aucune négociation ne peut atteindre.
//!
//! # LA SUITE DIT LA TAILLE DE LA CLÉ, ET AUSSI CELLE DU HACHAGE
//!
//! `TLS_AES_256_GCM_SHA384` emploie SHA-384 là où les deux autres emploient
//! SHA-256. Le hachage n'est pas un détail de dérivation : il fixe la longueur
//! du secret, et donc celle de tout ce qui en découle. Se tromper de hachage
//! donne des clés valides, de la bonne taille, et fausses.

/// Une suite de chiffrement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    /// `AEAD_AES_128_GCM` avec SHA-256.
    ///
    /// **C'est la seule que §5.3 rend OBLIGATOIRE**, et c'est celle des paquets
    /// `Initial` : ils sont chiffrés avant toute négociation, avec des clés que
    /// tout le monde peut calculer.
    Aes128Gcm,
    /// `AEAD_AES_256_GCM` avec SHA-384.
    Aes256Gcm,
    /// `AEAD_CHACHA20_POLY1305` avec SHA-256.
    ///
    /// Celle qu'on préfère sans accélération matérielle : AES en logiciel est
    /// à la fois plus lent et plus difficile à écrire en temps constant.
    ChaCha20Poly1305,
}

/// Ce que la clé d'un AEAD occupe, au plus.
pub const KEY_OCTETS_MAX: usize = 32;

/// Ce qu'un vecteur d'initialisation occupe (§5.3).
pub const IV_OCTETS: usize = 12;

/// Ce qu'un secret occupe, au plus — la longueur de SHA-384.
pub const SECRET_OCTETS_MAX: usize = 48;

/// Ce qu'un tag d'authentification occupe.
pub const TAG_OCTETS: usize = 16;

/// Ce qu'un échantillon de protection d'en-tête occupe (§5.4.2).
pub const SAMPLE_OCTETS: usize = 16;

/// Ce qu'un masque de protection d'en-tête occupe (§5.4.1).
pub const MASK_OCTETS: usize = 5;

impl Suite {
    /// La longueur de la clé, en octets.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    /// La longueur de la clé de protection d'en-tête, en octets.
    ///
    /// **ELLE SUIT CELLE DE L'AEAD**, et ce n'est pas une coïncidence : §5.4.3
    /// emploie AES avec la même taille de clé que le chiffrement, et §5.4.4
    /// emploie ChaCha20, qui n'en a qu'une.
    #[must_use]
    pub const fn header_key_len(self) -> usize {
        self.key_len()
    }

    /// La longueur du secret, c'est-à-dire celle du hachage.
    #[must_use]
    pub const fn secret_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::ChaCha20Poly1305 => 32,
            Self::Aes256Gcm => 48,
        }
    }

    /// Combien de paquets on peut chiffrer avec une même clé (§6.6).
    ///
    /// # CE N'EST PAS UNE PRÉCAUTION, C'EST UNE BORNE DÉMONTRÉE
    ///
    /// L'annexe B de RFC 9001 la calcule : au-delà, un adversaire distingue
    /// l'AEAD d'une permutation aléatoire avec une probabilité qui cesse d'être
    /// négligeable. Pour ChaCha20-Poly1305, la borne dépasse le nombre de
    /// paquets qu'une connexion peut porter — 2^62 —, et §6.6 dit alors qu'on
    /// peut l'ignorer. On la pose quand même à 2^62 : « ignorer » et « ne pas
    /// compter » ne sont pas la même chose, et un compteur qui déborde en
    /// silence vaut moins qu'un compteur qui bute.
    #[must_use]
    pub const fn confidentiality_limit(self) -> u64 {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm => 1 << 23,
            Self::ChaCha20Poly1305 => 1 << 62,
        }
    }

    /// Combien de paquets peuvent échouer à s'authentifier avant qu'on ferme
    /// (§6.6).
    ///
    /// # ELLE EXISTE PARCE QUE QUIC JETTE AU LIEU DE FERMER
    ///
    /// TLS ferme la connexion au premier enregistrement qui ne s'authentifie
    /// pas. QUIC, lui, JETTE le paquet et continue — sans quoi n'importe qui
    /// pourrait fermer une connexion en envoyant un datagramme. Mais cela donne
    /// à un adversaire autant d'essais qu'il veut, et c'est cette borne-là qui
    /// les compte.
    #[must_use]
    pub const fn integrity_limit(self) -> u64 {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm => 1 << 52,
            Self::ChaCha20Poly1305 => 1 << 36,
        }
    }
}

#[cfg(test)]
mod tests;
