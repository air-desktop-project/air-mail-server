// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les clés d'un sens de chiffrement, et ce qu'elles font (RFC 9001 §5).
//!
//! # LE NONCE EST L'IV OU-EXCLUSIF LE NUMÉRO DE PAQUET
//!
//! §5.3 : le vecteur d'initialisation ne change pas ; c'est le numéro de paquet,
//! aligné à droite, qui le fait varier. **Réemployer un nonce avec une même clé
//! est catastrophique en GCM** — cela ne révèle pas seulement les deux clairs,
//! cela livre la clé d'authentification, et donc la capacité de forger
//! n'importe quel message.
//!
//! C'est pour cela que l'espace des numéros de paquet ne se réemploie jamais, et
//! que §6.6 impose une mise à jour de clé bien avant qu'il ne s'épuise.
//!
//! # LES DONNÉES ASSOCIÉES SONT L'EN-TÊTE ENTIER
//!
//! §5.3 : de son premier octet à la fin du numéro de paquet. Un en-tête modifié
//! en chemin fait donc échouer l'authentification, et le paquet se jette — ce
//! qui protège aussi bien la longueur et l'identifiant de connexion que la
//! charge.

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use aes_gcm::{AeadInOut, Aes128Gcm, Aes256Gcm};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20poly1305::ChaCha20Poly1305;

use crate::error::{Error, Reason};
use crate::label::{expand_sha256, expand_sha384};
use crate::suite::{IV_OCTETS, KEY_OCTETS_MAX, MASK_OCTETS, SAMPLE_OCTETS, Suite, TAG_OCTETS};

/// Ce qu'un paquet QUIC peut porter de clair, en octets.
///
/// C'est la plus grande charge UDP que §18.2 de RFC 9000 permet d'annoncer.
/// **Elle sert ici de borne de sûreté** : elle met les AEAD hors d'atteinte de
/// leurs propres limites de longueur, et rend leur refus impossible.
pub const PACKET_OCTETS_MAX: usize = 65_527;

/// Le sel de §5.2, celui dont se dérivent les clés des paquets `Initial`.
///
/// **IL EST DANS LA RFC, ET DONC PUBLIC.** Les clés `Initial` ne cachent rien à
/// qui sait lire : elles protègent contre les intermédiaires qui modifieraient
/// les paquets sans le savoir, non contre ceux qui les lisent.
pub const INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// Les clés d'un sens, dérivées d'un secret.
#[derive(Debug, Clone, Copy)]
pub struct Keys {
    /// La suite.
    suite: Suite,
    /// La clé de l'AEAD, dont seuls les premiers octets valent.
    cle: [u8; KEY_OCTETS_MAX],
    /// Le vecteur d'initialisation.
    iv: [u8; IV_OCTETS],
    /// La clé de protection d'en-tête.
    hp: [u8; KEY_OCTETS_MAX],
}

impl Keys {
    /// Dérive les clés d'un secret (§5.1).
    ///
    /// # Errors
    ///
    /// [`Reason::BadSecretLength`] si le secret n'a pas la longueur du hachage
    /// de la suite.
    pub fn from_secret(suite: Suite, secret: &[u8]) -> Result<Self, Error> {
        // **ON NE REFUSE ICI QUE LE TROP LONG.** Le trop court, c'est la
        // dérivation qui le dit — `HKDF-Expand` connaît la longueur exacte du
        // hachage, et la redire ici ferait deux vérités pour une règle. Les deux
        // chemins sont donc empruntés par de vraies entrées, et non l'un
        // seulement.
        if secret.len() > suite.secret_len() {
            return Err(Error::new(Reason::BadSecretLength));
        }
        let mut clefs = Self {
            suite,
            cle: [0; KEY_OCTETS_MAX],
            iv: [0; IV_OCTETS],
            hp: [0; KEY_OCTETS_MAX],
        };
        let taille = suite.key_len();
        deriver(
            suite,
            secret,
            b"quic key",
            clefs.cle.get_mut(..taille).unwrap_or_default(),
        )?;
        // **LA PREMIÈRE DÉRIVATION VALIDE LE SECRET**, et c'est elle qui refuse
        // un secret trop court — `HKDF-Expand` connaît la longueur exacte du
        // hachage. Les deux suivantes partent du MÊME secret, avec des sorties
        // de douze et trente-deux octets : elles ne peuvent plus échouer, et
        // leur donner une branche en ferait deux qu'aucun secret ne peut
        // emprunter.
        deriver(suite, secret, b"quic iv", &mut clefs.iv).unwrap_or_default();
        deriver(
            suite,
            secret,
            b"quic hp",
            clefs
                .hp
                .get_mut(..suite.header_key_len())
                .unwrap_or_default(),
        )
        .unwrap_or_default();
        Ok(clefs)
    }

    /// La suite.
    #[must_use]
    pub const fn suite(&self) -> Suite {
        self.suite
    }

    /// La clé de l'AEAD.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        self.cle.get(..self.suite.key_len()).unwrap_or_default()
    }

    /// Le vecteur d'initialisation.
    #[must_use]
    pub const fn iv(&self) -> &[u8; IV_OCTETS] {
        &self.iv
    }

    /// La clé de protection d'en-tête.
    #[must_use]
    pub fn header_key(&self) -> &[u8] {
        self.hp
            .get(..self.suite.header_key_len())
            .unwrap_or_default()
    }

    /// Le nonce d'un numéro de paquet (§5.3).
    ///
    /// **LE NUMÉRO EST ALIGNÉ À DROITE**, sur les huit derniers octets des
    /// douze. L'aligner à gauche donnerait des nonces qui se répètent tous les
    /// 2^32 paquets au lieu de 2^62 — et le nonce répété est ce qui casse GCM.
    #[must_use]
    pub fn nonce(&self, numero: u64) -> [u8; IV_OCTETS] {
        let mut nonce = self.iv;
        let huit = numero.to_be_bytes();
        // Les quatre premiers octets ne sont jamais touchés : le numéro tient
        // sur huit, et l'IV en fait douze.
        let queue = nonce.get_mut(IV_OCTETS.saturating_sub(huit.len())..);
        for (place, lu) in queue.unwrap_or_default().iter_mut().zip(huit) {
            *place ^= lu;
        }
        nonce
    }

    /// Chiffre en place les `clair` premiers octets de `tampon`, et écrit les
    /// seize octets d'authentification juste après.
    ///
    /// Rend ce que le tout occupe.
    ///
    /// # Errors
    ///
    /// [`Reason::BufferTooSmall`] si `tampon` ne peut pas porter le tag.
    pub fn seal(
        &self,
        numero: u64,
        aad: &[u8],
        tampon: &mut [u8],
        clair: usize,
    ) -> Result<usize, Error> {
        let court = || Error::new(Reason::BufferTooSmall);
        // **UN PAQUET NE DÉPASSE PAS CE QU'UN DATAGRAMME PORTE** (§18.2 de
        // RFC 9000). Cette borne-ci n'est pas décorative : c'est elle qui met
        // l'AEAD hors d'atteinte de ses propres limites — GCM refuse au-delà de
        // soixante-quatre gibioctets, quatre ordres de grandeur plus haut.
        if clair > PACKET_OCTETS_MAX {
            return Err(court());
        }
        let total = clair.saturating_add(TAG_OCTETS);
        let place = tampon.get_mut(..total).ok_or_else(court)?;
        let (corps, queue) = place.split_at_mut(clair);
        let nonce = self.nonce(numero);
        let tag = chiffrer(self.suite, self.key(), &nonce, aad, corps);
        queue.copy_from_slice(&tag);
        Ok(total)
    }

    /// Déchiffre en place, et rend la longueur du clair.
    ///
    /// `tampon` porte le chiffré SUIVI de son tag.
    ///
    /// # Errors
    ///
    /// [`Reason::NotAuthentic`] — **et le paquet se JETTE**, il ne ferme pas la
    /// connexion ; [`Reason::BufferTooSmall`] si le tampon ne porte même pas un
    /// tag.
    pub fn open(&self, numero: u64, aad: &[u8], tampon: &mut [u8]) -> Result<usize, Error> {
        let court = || Error::new(Reason::BufferTooSmall);
        if tampon.len() > PACKET_OCTETS_MAX.saturating_add(TAG_OCTETS) {
            return Err(court());
        }
        let clair = tampon.len().checked_sub(TAG_OCTETS).ok_or_else(court)?;
        let (corps, queue) = tampon.split_at_mut(clair);
        let mut tag = [0_u8; TAG_OCTETS];
        for (place, lu) in tag.iter_mut().zip(queue.iter()) {
            *place = *lu;
        }
        let nonce = self.nonce(numero);
        dechiffrer(self.suite, self.key(), &nonce, aad, corps, &tag)?;
        Ok(clair)
    }

    /// Le masque de protection d'en-tête d'un échantillon (§5.4.3, §5.4.4).
    ///
    /// # Errors
    ///
    /// [`Reason::TooShortToSample`] si l'échantillon n'a pas ses seize octets.
    pub fn header_mask(&self, echantillon: &[u8]) -> Result<[u8; MASK_OCTETS], Error> {
        let court = || Error::new(Reason::TooShortToSample);
        let seize: [u8; SAMPLE_OCTETS] = echantillon
            .get(..SAMPLE_OCTETS)
            .and_then(|lus| lus.try_into().ok())
            .ok_or_else(court)?;
        let mut masque = [0_u8; MASK_OCTETS];
        match self.suite {
            // §5.4.3 : le masque est le chiffré du bloc, par AES en mode ECB.
            // **UN SEUL BLOC, ET SANS CHAÎNAGE** — c'est ce qui rend ECB
            // acceptable ici, et nulle part ailleurs.
            Suite::Aes128Gcm => {
                let mut bloc = seize;
                let mut cle = [0_u8; 16];
                for (place, lu) in cle.iter_mut().zip(self.header_key()) {
                    *place = *lu;
                }
                Aes128::new(&cle.into()).encrypt_block((&mut bloc).into());
                copier(&bloc, &mut masque);
            }
            Suite::Aes256Gcm => {
                let mut bloc = seize;
                let mut cle = [0_u8; 32];
                for (place, lu) in cle.iter_mut().zip(self.header_key()) {
                    *place = *lu;
                }
                Aes256::new(&cle.into()).encrypt_block((&mut bloc).into());
                copier(&bloc, &mut masque);
            }
            // §5.4.4 : les quatre premiers octets sont le compteur de bloc, en
            // PETIT-BOUTIEN, et les douze suivants le nonce. Le masque est
            // alors les cinq premiers octets du flot.
            Suite::ChaCha20Poly1305 => {
                let mut cle = [0_u8; 32];
                for (place, lu) in cle.iter_mut().zip(self.header_key()) {
                    *place = *lu;
                }
                let mut compteur = [0_u8; 4];
                copier(&seize, &mut compteur);
                let mut nonce = [0_u8; 12];
                for (place, lu) in nonce.iter_mut().zip(seize.iter().skip(4)) {
                    *place = *lu;
                }
                let mut flux = ChaCha20::new(&cle.into(), &nonce.into());
                // Un bloc de ChaCha20 fait soixante-quatre octets : se placer au
                // bloc `n` demande de sauter `64n` octets.
                let saut = u64::from(u32::from_le_bytes(compteur)).saturating_mul(64);
                flux.seek(saut);
                flux.apply_keystream(&mut masque);
            }
        }
        Ok(masque)
    }
}

/// Recopie ce qui tient, sans se soucier de ce qui dépasse.
fn copier(source: &[u8], vers: &mut [u8]) {
    for (place, lu) in vers.iter_mut().zip(source) {
        *place = *lu;
    }
}

/// Dérive une valeur avec le hachage de la suite.
fn deriver(suite: Suite, secret: &[u8], etiquette: &[u8], out: &mut [u8]) -> Result<(), Error> {
    match suite {
        Suite::Aes128Gcm | Suite::ChaCha20Poly1305 => expand_sha256(secret, etiquette, out),
        Suite::Aes256Gcm => expand_sha384(secret, etiquette, out),
    }
}

/// Chiffre en place, et rend le tag.
///
/// # ELLE NE PEUT PAS ÉCHOUER, ET C'EST LA BORNE DU PAQUET QUI LE DIT
///
/// Les trois AEAD ne refusent qu'au-delà de leur propre limite de longueur —
/// soixante-quatre gibioctets pour GCM, deux cent cinquante-six pour
/// ChaCha20-Poly1305. [`Keys::seal`] borne le clair à [`PACKET_OCTETS_MAX`],
/// quatre ordres de grandeur plus bas. `unwrap_or_default` porte cette
/// impossibilité dans la bibliothèque plutôt que dans une branche qu'aucun
/// paquet ne peut emprunter.
fn chiffrer(
    suite: Suite,
    cle: &[u8],
    nonce: &[u8; IV_OCTETS],
    aad: &[u8],
    corps: &mut [u8],
) -> [u8; TAG_OCTETS] {
    let tag = match suite {
        Suite::Aes128Gcm => {
            let mut fixe = [0_u8; 16];
            copier(cle, &mut fixe);
            Aes128Gcm::new(&fixe.into())
                .encrypt_inout_detached(nonce.into(), aad, corps.into())
                .unwrap_or_default()
        }
        Suite::Aes256Gcm => {
            let mut fixe = [0_u8; 32];
            copier(cle, &mut fixe);
            Aes256Gcm::new(&fixe.into())
                .encrypt_inout_detached(nonce.into(), aad, corps.into())
                .unwrap_or_default()
        }
        Suite::ChaCha20Poly1305 => {
            let mut fixe = [0_u8; 32];
            copier(cle, &mut fixe);
            ChaCha20Poly1305::new(&fixe.into())
                .encrypt_inout_detached(nonce.into(), aad, corps.into())
                .unwrap_or_default()
        }
    };
    tag.into()
}

/// Déchiffre en place, ou refuse.
fn dechiffrer(
    suite: Suite,
    cle: &[u8],
    nonce: &[u8; IV_OCTETS],
    aad: &[u8],
    corps: &mut [u8],
    tag: &[u8; TAG_OCTETS],
) -> Result<(), Error> {
    let faux = || Error::new(Reason::NotAuthentic);
    match suite {
        Suite::Aes128Gcm => {
            let mut fixe = [0_u8; 16];
            copier(cle, &mut fixe);
            Aes128Gcm::new(&fixe.into())
                .decrypt_inout_detached(nonce.into(), aad, corps.into(), tag.into())
                .map_err(|_| faux())
        }
        Suite::Aes256Gcm => {
            let mut fixe = [0_u8; 32];
            copier(cle, &mut fixe);
            Aes256Gcm::new(&fixe.into())
                .decrypt_inout_detached(nonce.into(), aad, corps.into(), tag.into())
                .map_err(|_| faux())
        }
        Suite::ChaCha20Poly1305 => {
            let mut fixe = [0_u8; 32];
            copier(cle, &mut fixe);
            ChaCha20Poly1305::new(&fixe.into())
                .decrypt_inout_detached(nonce.into(), aad, corps.into(), tag.into())
                .map_err(|_| faux())
        }
    }
}

#[cfg(test)]
mod tests;
