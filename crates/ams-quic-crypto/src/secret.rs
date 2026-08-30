// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les secrets dont les clés se dérivent (RFC 9001 §5.1, §5.2, §6.1).
//!
//! # POURQUOI LE SECRET SE GARDE, ET PAS SEULEMENT LES CLÉS
//!
//! La mise à jour de clé (§6.1) dérive le secret SUIVANT du secret courant, et
//! non des clés. Un état qui n'aurait retenu que les clés ne saurait pas se
//! mettre à jour — et §6.6 impose de le faire avant d'avoir chiffré 2^23
//! paquets avec une même clé AES.

use crate::error::{Error, Reason};
use crate::keys::{INITIAL_SALT, Keys};
use crate::label::{expand_sha256, expand_sha384, extract_sha256};
use crate::suite::{SECRET_OCTETS_MAX, Suite};

/// De quel côté de la connexion on se place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Le client — celui qui a choisi l'identifiant de destination.
    Client,
    /// Le serveur.
    Server,
}

impl Role {
    /// L'étiquette de §5.2 qui va avec.
    const fn etiquette(self) -> &'static [u8] {
        match self {
            Self::Client => b"client in",
            Self::Server => b"server in",
        }
    }
}

/// Un secret de chiffrement.
#[derive(Debug, Clone, Copy)]
pub struct Secret {
    /// La suite, qui dit sa longueur.
    suite: Suite,
    /// Les octets, dont seuls les premiers valent.
    octets: [u8; SECRET_OCTETS_MAX],
}

impl Secret {
    /// Retient ce secret.
    ///
    /// # Errors
    ///
    /// [`Reason::BadSecretLength`] si sa longueur n'est pas celle du hachage de
    /// la suite.
    pub fn new(suite: Suite, octets: &[u8]) -> Result<Self, Error> {
        if octets.len() != suite.secret_len() {
            return Err(Error::new(Reason::BadSecretLength));
        }
        let mut secret = Self {
            suite,
            octets: [0; SECRET_OCTETS_MAX],
        };
        for (place, lu) in secret.octets.iter_mut().zip(octets) {
            *place = *lu;
        }
        Ok(secret)
    }

    /// Le secret d'un paquet `Initial` (§5.2).
    ///
    /// # CES CLÉS SONT PUBLIQUES, ET C'EST ASSUMÉ
    ///
    /// Le sel est dans la RFC, et l'identifiant de destination voyage en clair
    /// dans le premier paquet. N'importe qui peut donc calculer ces clés. Elles
    /// ne cachent rien : elles empêchent un intermédiaire de MODIFIER un paquet
    /// sans que cela se voie — ce que l'histoire de TCP a montré être un
    /// problème réel, et non théorique.
    ///
    /// # Errors
    ///
    /// [`Reason::BufferTooSmall`] — que la dérivation ne peut pas rendre ici.
    pub fn initial(destination: &[u8], role: Role) -> Result<Self, Error> {
        // **AUCUNE DE CES DEUX DÉRIVATIONS NE PEUT ÉCHOUER** : l'extraction
        // écrit exactement la taille de SHA-256, l'expansion part d'un secret de
        // cette taille et rend trente-deux octets. `unwrap_or_default` porte ces
        // impossibilités plutôt que deux branches qu'aucun identifiant ne peut
        // emprunter — et si l'une survenait, le secret resterait nul, donc
        // aucune connexion ne s'ouvrirait : un échec bruyant, non un
        // affaiblissement silencieux.
        let mut extrait = [0_u8; 32];
        extract_sha256(&INITIAL_SALT, destination, &mut extrait).unwrap_or_default();
        let mut octets = [0_u8; 32];
        expand_sha256(&extrait, role.etiquette(), &mut octets).unwrap_or_default();
        // §5.2 : les paquets `Initial` emploient toujours AES-128-GCM.
        Self::new(Suite::Aes128Gcm, &octets)
    }

    /// La suite.
    #[must_use]
    pub const fn suite(&self) -> Suite {
        self.suite
    }

    /// Les octets qui comptent.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.octets
            .get(..self.suite.secret_len())
            .unwrap_or_default()
    }

    /// Les clés qui s'en dérivent.
    ///
    /// # Errors
    ///
    /// [`Reason::BadSecretLength`], que la construction a déjà écartée.
    pub fn keys(&self) -> Result<Keys, Error> {
        Keys::from_secret(self.suite, self.as_bytes())
    }

    /// Le secret suivant, après une mise à jour de clé (§6.1).
    ///
    /// # LA MISE À JOUR NE VA QUE DANS UN SENS
    ///
    /// `secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic ku", "", Hash.length)`.
    /// On ne peut pas revenir en arrière, et c'est le point : un adversaire qui
    /// obtiendrait le secret courant n'apprend rien des paquets déjà passés.
    ///
    /// # Errors
    ///
    /// [`Reason::BufferTooSmall`].
    pub fn next(&self) -> Result<Self, Error> {
        let mut octets = [0_u8; SECRET_OCTETS_MAX];
        let taille = self.suite.secret_len();
        let place = octets.get_mut(..taille).unwrap_or_default();
        // Même raison qu'à l'ouverture : le secret a la longueur du hachage —
        // la construction l'a vérifié —, et la sortie aussi.
        match self.suite {
            Suite::Aes128Gcm | Suite::ChaCha20Poly1305 => {
                expand_sha256(self.as_bytes(), b"quic ku", place).unwrap_or_default();
            }
            Suite::Aes256Gcm => {
                expand_sha384(self.as_bytes(), b"quic ku", place).unwrap_or_default();
            }
        }
        Self::new(self.suite, octets.get(..taille).unwrap_or_default())
    }
}

#[cfg(test)]
mod tests;
