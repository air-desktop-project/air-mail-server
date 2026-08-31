// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qui rend le fournisseur TLS capable de QUIC.
//!
//! # LE FOURNISSEUR PUR RUST N'EN SAVAIT RIEN, ET CELA BLOQUAIT HTTP/3
//!
//! `rustls` conduit la poignée de main TLS 1.3 de QUIC, mais il ne le fait que
//! pour les suites dont le fournisseur déclare savoir chiffrer un PAQUET QUIC —
//! ce qui n'est pas la même chose que chiffrer un enregistrement TLS. Les trois
//! suites de `rustls-rustcrypto` (C14 : pur Rust, sans une ligne de C)
//! déclaraient `quic: None`, et `rustls::quic::ServerConnection` refusait donc
//! de se construire.
//!
//! Ce module comble ce trou. Il ne réimplémente rien : il branche les traits de
//! `rustls::quic` sur `ams-quic-crypto`, qui est **vérifié contre les vecteurs de
//! l'annexe A de RFC 9001** et couvert à 100 %.
//!
//! # POURQUOI PAS UNE SECONDE IMPLÉMENTATION
//!
//! Écrire ici la protection de paquet à partir des mêmes primitives aurait été
//! plus court. Ce serait aussi la deuxième fois qu'on l'écrit — et deux
//! implémentations de la même chose finissent par diverger sur le cas que
//! personne n'a éprouvé. Celle d'`ams-quic-crypto` a des vecteurs ; celle-ci
//! n'en aurait pas eu.
//!
//! # ET LE MASQUAGE D'EN-TÊTE N'EST PAS LE CHIFFREMENT
//!
//! §5.4 de RFC 9001 les sépare, et `rustls` aussi : deux clés, deux objets, deux
//! moments. C'est pourquoi `ams-quic-crypto` expose [`PacketKeys`] et
//! [`HeaderKeys`] plutôt qu'un seul objet à moitié rempli — un objet qui saurait
//! masquer avec une clé de zéros appliquerait bien un masque, et aucun essai ne
//! le verrait.

use alloc::boxed::Box;
use alloc::vec::Vec;

use ams_quic_crypto::{HeaderKeys, PacketKeys, Suite};
use rustls::Error;
use rustls::crypto::CryptoProvider;
use rustls::crypto::cipher::{AeadKey, Iv, Nonce};
use rustls::quic::{Algorithm, HeaderProtectionKey, PacketKey, Tag};

/// Le protocole applicatif d'HTTP/3 (§3.1 de RFC 9114).
///
/// **`h3`, ET RIEN D'AUTRE**, pour la même raison que `h2` sur TCP : annoncer un
/// protocole qu'on refuse de servir est pire que de ne pas l'annoncer.
pub const ALPN_H3: &[u8] = b"h3";

/// Les protocoles qu'on annonce sur QUIC.
#[must_use]
pub fn alpn_h3() -> Vec<Vec<u8>> {
    alloc::vec![ALPN_H3.to_vec()]
}

/// Combien d'octets un échantillon de protection d'en-tête occupe (§5.4.2).
const ECHANTILLON_OCTETS: usize = 16;

/// Ce que le masque de protection d'en-tête occupe (§5.4.1).
const MASQUE_OCTETS: usize = 5;

/// Ce qu'un tag d'authentification occupe.
const TAG_OCTETS: usize = 16;

/// L'algorithme QUIC d'une suite.
#[derive(Debug, Clone, Copy)]
struct Algorithme(Suite);

impl Algorithm for Algorithme {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn PacketKey> {
        // **LE VECTEUR VIENT DE `Iv`, QUI NE SE PRÊTE PAS.** On le reconstruit
        // en fabriquant le nonce du paquet zéro : `Nonce::new` applique un
        // OU-exclusif avec le numéro, et zéro le laisse intact.
        let iv = Nonce::new(&iv, 0).0;
        let clefs = PacketKeys::new(self.0, key.as_ref(), &iv).ok();
        Box::new(ClefDePaquet(clefs))
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn HeaderProtectionKey> {
        Box::new(ClefDEnTete(HeaderKeys::new(self.0, key.as_ref()).ok()))
    }

    fn aead_key_len(&self) -> usize {
        self.0.key_len()
    }
}

/// Les clés de paquet d'une suite.
///
/// # POURQUOI UN `Option`, ET CE QU'IL SIGNIFIE
///
/// `rustls` demande un objet, pas un `Result` : sa signature ne prévoit pas
/// qu'une clé puisse être refusée. Une clé de la mauvaise longueur ne peut
/// venir que d'un désaccord entre `aead_key_len` et ce que `rustls` envoie,
/// c'est-à-dire d'une faute de NOTRE côté.
///
/// On la retient donc plutôt que de paniquer, et chaque opération refuse
/// ensuite. **Un serveur qui s'arrête est plus grave qu'une connexion qui
/// échoue** — et cette connexion-là échouera, franchement, à sa première
/// authentification.
struct ClefDePaquet(Option<PacketKeys>);

impl PacketKey for ClefDePaquet {
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<Tag, Error> {
        let clefs = self.0.as_ref().ok_or(Error::EncryptError)?;
        // `ams-quic-crypto` écrit le tag DANS le tampon, à la suite du clair ;
        // `rustls` le veut à part. On chiffre donc dans un tampon local dont la
        // queue portera le tag.
        //
        // **LES DÉCOUPES CI-DESSOUS NE SONT PAS GARDÉES, ET C'EST EXPRÈS** : le
        // tampon est fabriqué juste au-dessus, à `clair + TAG_OCTETS`. Un
        // `get(..clair)` y rendrait un `Option` dont la variante vide serait
        // inatteignable — une branche que nul essai n'éprouverait jamais.
        let clair = payload.len();
        let mut place = alloc::vec![0_u8; clair.saturating_add(TAG_OCTETS)];
        place[..clair].copy_from_slice(payload);
        clefs
            .seal(packet_number, header, &mut place, clair)
            .map_err(|_| Error::EncryptError)?;
        let (corps, tag) = place.split_at(clair);
        payload.copy_from_slice(corps);
        Ok(Tag::from(tag))
    }

    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let clefs = self.0.as_ref().ok_or(Error::DecryptError)?;
        let clair = clefs
            .open(packet_number, header, payload)
            .map_err(|_| Error::DecryptError)?;
        // `open` rend la longueur du clair, qui est celle de la charge moins le
        // tag : la découpe tient par construction, et une garde ici serait morte.
        Ok(&payload[..clair])
    }

    fn tag_len(&self) -> usize {
        TAG_OCTETS
    }

    /// Combien de paquets on peut CHIFFRER avec ces clés (§6.6 de RFC 9001).
    ///
    /// **CE N'EST PAS UNE PRÉCAUTION D'ARCHITECTE** : au-delà, l'AEAD cesse de
    /// garantir la confidentialité, et la RFC impose alors de renouveler les
    /// clés — ou de fermer la connexion.
    fn confidentiality_limit(&self) -> u64 {
        match self.0.as_ref().map(PacketKeys::suite) {
            // §6.6 : 2^23 pour ChaCha20-Poly1305 n'est pas borné par la RFC, qui
            // ne pose de limite que pour les modes GCM. On prend malgré tout la
            // plus basse des deux : ce qui n'a pas de limite connue n'est pas ce
            // qui a une limite prouvée haute.
            Some(Suite::Aes128Gcm | Suite::Aes256Gcm) | None => 1 << 23,
            Some(Suite::ChaCha20Poly1305) => 1 << 23,
        }
    }

    /// Combien de paquets on peut REFUSER avant de fermer (§6.6).
    ///
    /// Un attaquant qui essaie des paquets forgés apprend, à chaque refus, un
    /// peu de la clé. La limite est ce qui borne ce qu'il apprend.
    fn integrity_limit(&self) -> u64 {
        match self.0.as_ref().map(PacketKeys::suite) {
            Some(Suite::Aes128Gcm | Suite::Aes256Gcm) | None => 1 << 52,
            Some(Suite::ChaCha20Poly1305) => 1 << 36,
        }
    }
}

/// La clé de protection d'en-tête d'une suite.
struct ClefDEnTete(Option<HeaderKeys>);

impl ClefDEnTete {
    /// Applique le masque de §5.4.1 : cinq bits du premier octet, puis le
    /// numéro.
    ///
    /// # LES BITS MASQUÉS NE SONT PAS LES MÊMES DES DEUX CÔTÉS
    ///
    /// §5.4.1 : quatre bits pour un en-tête long, cinq pour un en-tête court.
    /// Le premier bit dit lequel — et il n'est PAS masqué, précisément pour
    /// qu'on puisse le lire avant de démasquer.
    fn appliquer(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        let clefs = self.0.as_ref().ok_or(Error::DecryptError)?;
        // **LA LONGUEUR DE L'ÉCHANTILLON DEVIENT UN TYPE, ET NON UNE GARDE** :
        // `HeaderKeys::mask` prend un tableau de seize octets et ne peut donc
        // pas échouer. Le refus est ici, une fois, et il est éprouvé.
        let seize: &[u8; ECHANTILLON_OCTETS] =
            sample.try_into().map_err(|_| Error::DecryptError)?;
        if packet_number.len() > 4 {
            return Err(Error::DecryptError);
        }
        let masque = clefs.mask(seize);
        let tete = masque.first().copied().unwrap_or(0);
        let bits = match *first & 0x80 == 0x80 {
            true => 0x0f,
            false => 0x1f,
        };
        *first ^= tete & bits;
        for (place, lu) in packet_number
            .iter_mut()
            .zip(masque.get(1..MASQUE_OCTETS).unwrap_or_default())
        {
            *place ^= *lu;
        }
        Ok(())
    }
}

impl HeaderProtectionKey for ClefDEnTete {
    /// # LE MASQUE EST LE MÊME DANS LES DEUX SENS
    ///
    /// C'est un OU-exclusif : l'appliquer deux fois rend l'original. Les deux
    /// méthodes ne diffèrent donc pas par le calcul, mais par le MOMENT — le
    /// chiffrement masque après avoir chiffré la charge, le déchiffrement
    /// démasque avant de la déchiffrer, parce que l'échantillon se prend dans le
    /// chiffré.
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.appliquer(sample, first, packet_number)
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.appliquer(sample, first, packet_number)
    }

    fn sample_len(&self) -> usize {
        ECHANTILLON_OCTETS
    }
}

/// Les trois algorithmes, un par suite.
static AES128: Algorithme = Algorithme(Suite::Aes128Gcm);
static AES256: Algorithme = Algorithme(Suite::Aes256Gcm);
static CHACHA: Algorithme = Algorithme(Suite::ChaCha20Poly1305);

/// La suite TLS 1.3 que cette constante d'amont décrit.
///
/// # POURQUOI UNE FONCTION `const`, ET NON UN `.tls13()`
///
/// `SupportedCipherSuite::tls13` n'est pas `const`, et les suites ci-dessous
/// sont des **constantes de compilation** : il faut donc ouvrir la variante à la
/// compilation. C'est ce que fait ce filtrage.
///
/// **S'IL CESSAIT D'ÊTRE EXHAUSTIF, LA COMPILATION ÉCHOUERAIT** — ce qui est
/// exactement le comportement voulu : une variante TLS 1.2 apparue dans le
/// graphe de dépendances contredirait C4, et doit se voir au build, pas à
/// l'exécution.
const fn tls13_de(suite: rustls::SupportedCipherSuite) -> &'static rustls::Tls13CipherSuite {
    match suite {
        rustls::SupportedCipherSuite::Tls13(tls13) => tls13,
    }
}

/// La même suite qu'en amont, mais capable de QUIC.
///
/// # POURQUOI DES `static`, ET NON UNE FUITE À L'EXÉCUTION
///
/// `rustls` veut des références `'static`. La première version les obtenait par
/// `Box::leak`, une fois par appel de [`provider_quic`] — **et le fuzz l'a dit
/// tout de suite** : `LeakSanitizer` a compté les octets perdus. Un serveur
/// n'appelle cette fonction qu'au démarrage, donc la fuite était sans
/// conséquence chez lui ; elle en aurait eu chez quiconque l'appellerait en
/// boucle, et une fonction publique ne choisit pas ses appelants.
///
/// Ici, rien n'est alloué : les trois suites existent à la compilation, et leur
/// adresse est `'static` parce qu'elles sont dans le binaire.
macro_rules! suite_quic {
    ($nom:ident, $amont:path, $algorithme:expr) => {
        static $nom: rustls::Tls13CipherSuite = {
            let amont = tls13_de($amont);
            rustls::Tls13CipherSuite {
                common: rustls::crypto::CipherSuiteCommon {
                    suite: amont.common.suite,
                    hash_provider: amont.common.hash_provider,
                    confidentiality_limit: amont.common.confidentiality_limit,
                },
                hkdf_provider: amont.hkdf_provider,
                aead_alg: amont.aead_alg,
                quic: Some($algorithme),
            }
        };
    };
}

suite_quic!(
    SUITE_AES128,
    rustls_rustcrypto::TLS13_AES_128_GCM_SHA256,
    &AES128
);
suite_quic!(
    SUITE_AES256,
    rustls_rustcrypto::TLS13_AES_256_GCM_SHA384,
    &AES256
);
suite_quic!(
    SUITE_CHACHA,
    rustls_rustcrypto::TLS13_CHACHA20_POLY1305_SHA256,
    &CHACHA
);

/// Le fournisseur, rendu capable de QUIC.
///
/// C'est [`crate::provider`], dont chaque suite TLS 1.3 porte en plus de quoi
/// chiffrer un paquet QUIC. Les suites que ce module ne sait pas conduire sont
/// **écartées** plutôt que laissées sans QUIC : les laisser passer sans `quic`
/// les ferait échouer APRÈS la poignée de main, au premier paquet — un symptôme
/// très loin de sa cause.
///
/// # POURQUOI UN SECOND FOURNISSEUR, ET NON UN SEUL
///
/// Rien n'empêcherait d'ajouter QUIC au fournisseur ordinaire : une suite
/// capable de QUIC sert aussi TCP. Mais les deux écoutes n'offrent pas les mêmes
/// suites — celle-ci écarte ce qu'elle ne sait pas conduire —, et un fournisseur
/// unique ferait dépendre l'offre TCP d'une capacité qui ne la concerne pas.
#[must_use]
pub fn provider_quic() -> CryptoProvider {
    let ordinaire = crate::provider();
    // **L'ORDRE EST CELUI DU FOURNISSEUR ORDINAIRE, ET NON LE NÔTRE** : c'est
    // lui qui exprime la préférence de suites, et QUIC n'a pas à la refaire.
    let suites = ordinaire
        .cipher_suites
        .iter()
        .filter_map(|suite| avec_quic(suite.suite()))
        .collect();
    CryptoProvider {
        cipher_suites: suites,
        ..ordinaire
    }
}

/// La suite capable de QUIC que ce nom désigne — ou rien.
fn avec_quic(nom: rustls::CipherSuite) -> Option<rustls::SupportedCipherSuite> {
    let suite: &'static rustls::Tls13CipherSuite = match nom {
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256 => &SUITE_AES128,
        rustls::CipherSuite::TLS13_AES_256_GCM_SHA384 => &SUITE_AES256,
        rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => &SUITE_CHACHA,
        _ => return None,
    };
    Some(rustls::SupportedCipherSuite::Tls13(suite))
}

#[cfg(test)]
mod tests;
