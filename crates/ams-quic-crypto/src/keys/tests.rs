// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que les clés doivent produire, d'après RFC 9001 annexe A.

use super::{INITIAL_SALT, Keys};
use crate::error::Reason;
use crate::label::{expand_sha256, extract_sha256};
use crate::suite::Suite;

/// Lit une suite d'octets écrite en hexadécimal.
fn hexa(texte: &str) -> std::vec::Vec<u8> {
    let propre: std::vec::Vec<char> = texte.chars().filter(|c| !c.is_whitespace()).collect();
    propre
        .chunks(2)
        .map(|paire| {
            let s: std::string::String = paire.iter().collect();
            u8::from_str_radix(&s, 16).expect("hexadécimal")
        })
        .collect()
}

/// Les clés `Initial` de l'annexe A.1, dérivées de l'identifiant du client.
fn clefs_initiales(etiquette: &[u8]) -> Keys {
    let cid = hexa("8394c8f03e515708");
    let mut initial = [0_u8; 32];
    extract_sha256(&INITIAL_SALT, &cid, &mut initial).expect("extractible");
    let mut secret = [0_u8; 32];
    expand_sha256(&initial, etiquette, &mut secret).expect("dérivable");
    Keys::from_secret(Suite::Aes128Gcm, &secret).expect("dérivable")
}

/// **LES CLÉS DE L'ANNEXE A.1**, dérivées d'un bout à l'autre.
#[test]
fn les_clefs_initiales_de_l_annexe_se_retrouvent() {
    let client = clefs_initiales(b"client in");
    assert_eq!(client.suite(), Suite::Aes128Gcm);
    assert_eq!(
        client.key(),
        hexa("1f369613dd76d5467730efcbe3b1a22d").as_slice()
    );
    assert_eq!(
        client.iv().as_slice(),
        hexa("fa044b2f42a3fd3b46fb255c").as_slice()
    );
    assert_eq!(
        client.header_key(),
        hexa("9f50449e04a0e810283a1e9933adedd2").as_slice()
    );

    let serveur = clefs_initiales(b"server in");
    assert_eq!(
        serveur.key(),
        hexa("cf3a5331653c364c88f0f379b6067e37").as_slice()
    );
    assert_eq!(
        serveur.iv().as_slice(),
        hexa("0ac1493ca1905853b0bba03e").as_slice()
    );
    assert_eq!(
        serveur.header_key(),
        hexa("c206b8d9b9f0f37644430b490eeaa314").as_slice()
    );
}

/// **LE NONCE DE L'ANNEXE A.5**, où le numéro de paquet 654 360 564 modifie les
/// quatre derniers octets de l'IV, et eux seuls.
#[test]
fn le_nonce_de_l_annexe_se_retrouve() {
    let secret = hexa("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    let clefs = Keys::from_secret(Suite::ChaCha20Poly1305, &secret).expect("dérivable");
    assert_eq!(
        clefs.iv().as_slice(),
        hexa("e0459b3474bdd0e44a41c144").as_slice()
    );
    assert_eq!(
        clefs.nonce(654_360_564).as_slice(),
        hexa("e0459b3474bdd0e46d417eb0").as_slice()
    );
}

/// **LE NUMÉRO EST ALIGNÉ À DROITE**, sur les huit derniers octets des douze.
/// L'aligner à gauche donnerait des nonces qui se répètent tous les 2^32
/// paquets — et le nonce répété est ce qui casse GCM.
#[test]
fn le_numero_est_aligne_a_droite() {
    let clefs = clefs_initiales(b"client in");
    let iv = *clefs.iv();
    // Le numéro zéro ne change rien.
    assert_eq!(clefs.nonce(0), iv);
    // Les quatre premiers octets ne bougent jamais.
    for numero in [1_u64, 0xffff_ffff, u64::MAX, 654_360_564] {
        let nonce = clefs.nonce(numero);
        assert_eq!(
            nonce.get(..4),
            iv.get(..4),
            "le numéro {numero} a débordé sur la tête de l'IV"
        );
    }
    // Et deux numéros différents donnent deux nonces différents.
    assert_ne!(clefs.nonce(1), clefs.nonce(2));
    assert_ne!(clefs.nonce(1), clefs.nonce(1_u64 << 32));
}

/// **LE MASQUE DE L'ANNEXE A.2**, celui du paquet `Initial` du client.
#[test]
fn le_masque_de_l_annexe_se_retrouve() {
    let clefs = clefs_initiales(b"client in");
    let echantillon = hexa("d1b1c98dd7689fb8ec11d242b123dc9b");
    let masque = clefs.header_mask(&echantillon).expect("calculable");
    assert_eq!(masque.as_slice(), hexa("437b9aec36").as_slice());
}

/// **LE MASQUE DE L'ANNEXE A.3**, celui du serveur.
#[test]
fn le_masque_du_serveur_de_l_annexe_se_retrouve() {
    let clefs = clefs_initiales(b"server in");
    let echantillon = hexa("2cd0991cd25b0aac406a5816b6394100");
    let masque = clefs.header_mask(&echantillon).expect("calculable");
    assert_eq!(masque.as_slice(), hexa("2ec0d8356a").as_slice());
}

/// **LE MASQUE CHACHA20 DE L'ANNEXE A.5** : les quatre premiers octets de
/// l'échantillon sont le compteur de bloc, en PETIT-BOUTIEN.
#[test]
fn le_masque_de_chacha_de_l_annexe_se_retrouve() {
    let secret = hexa("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    let clefs = Keys::from_secret(Suite::ChaCha20Poly1305, &secret).expect("dérivable");
    let echantillon = hexa("5e5cd55c41f69080575d7999c25a5bfb");
    let masque = clefs.header_mask(&echantillon).expect("calculable");
    assert_eq!(masque.as_slice(), hexa("aefefe7d03").as_slice());
}

/// **LE CHIFFRÉ DE L'ANNEXE A.5** : une trame `PING` seule, chiffrée par
/// ChaCha20-Poly1305, avec l'en-tête pour données associées.
#[test]
fn le_chiffre_de_l_annexe_se_retrouve() {
    let secret = hexa("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    let clefs = Keys::from_secret(Suite::ChaCha20Poly1305, &secret).expect("dérivable");
    let aad = hexa("4200bff4");
    let mut tampon = [0_u8; 32];
    tampon[0] = 0x01;
    let ecrits = clefs
        .seal(654_360_564, &aad, &mut tampon, 1)
        .expect("chiffrable");
    assert_eq!(
        tampon.get(..ecrits).unwrap_or_default(),
        hexa("655e5cd55c41f69080575d7999c25a5bfb").as_slice()
    );

    // Et il se déchiffre.
    let mut relu = tampon;
    let clair = clefs
        .open(654_360_564, &aad, relu.get_mut(..ecrits).expect("écrit"))
        .expect("déchiffrable");
    assert_eq!(clair, 1);
    assert_eq!(relu.first(), Some(&0x01));
}

/// **CE QU'ON CHIFFRE SE DÉCHIFFRE, DANS LES TROIS SUITES.**
#[test]
fn les_trois_suites_font_un_aller_retour() {
    for suite in [Suite::Aes128Gcm, Suite::Aes256Gcm, Suite::ChaCha20Poly1305] {
        let secret = std::vec![0x5a_u8; suite.secret_len()];
        let clefs = Keys::from_secret(suite, &secret).expect("dérivable");
        assert_eq!(clefs.key().len(), suite.key_len(), "{suite:?}");
        assert_eq!(
            clefs.header_key().len(),
            suite.header_key_len(),
            "{suite:?}"
        );

        let clair = b"une trame quelconque";
        let mut tampon = [0_u8; 64];
        tampon
            .get_mut(..clair.len())
            .expect("place")
            .copy_from_slice(clair);
        let ecrits = clefs
            .seal(42, b"en-tete", &mut tampon, clair.len())
            .expect("chiffrable");
        assert_eq!(ecrits, clair.len() + 16, "{suite:?}");
        assert_ne!(
            tampon.get(..clair.len()),
            Some(clair.as_slice()),
            "{suite:?} n'a rien chiffré"
        );

        let relu = clefs
            .open(42, b"en-tete", tampon.get_mut(..ecrits).expect("écrit"))
            .expect("déchiffrable");
        assert_eq!(relu, clair.len(), "{suite:?}");
        assert_eq!(tampon.get(..relu), Some(clair.as_slice()), "{suite:?}");
    }
}

/// **UN PAQUET QUI NE S'AUTHENTIFIE PAS SE JETTE** — et il ne ferme pas la
/// connexion : il peut venir de n'importe qui, c'est de l'UDP.
#[test]
fn ce_qui_ne_s_authentifie_pas_se_jette() {
    let clefs = clefs_initiales(b"client in");
    let clair = b"quelque chose";
    let mut origine = [0_u8; 64];
    origine
        .get_mut(..clair.len())
        .expect("place")
        .copy_from_slice(clair);
    let ecrits = clefs
        .seal(7, b"aad", &mut origine, clair.len())
        .expect("chiffrable");

    // Un octet de charge changé.
    let mut abime = origine;
    abime[0] ^= 0x01;
    let issue = clefs
        .open(7, b"aad", abime.get_mut(..ecrits).expect("écrit"))
        .expect_err("abîmé");
    assert_eq!(issue.reason(), Reason::NotAuthentic);

    // Un octet de TAG changé.
    let mut abime = origine;
    abime[ecrits - 1] ^= 0x01;
    assert!(
        clefs
            .open(7, b"aad", abime.get_mut(..ecrits).expect("écrit"))
            .is_err()
    );

    // Les données associées changées : c'est l'en-tête qui a bougé en chemin.
    let mut copie = origine;
    let issue = clefs
        .open(7, b"autre", copie.get_mut(..ecrits).expect("écrit"))
        .expect_err("en-tête modifié");
    assert_eq!(issue.reason(), Reason::NotAuthentic);

    // **ET LE NUMÉRO DE PAQUET AUSSI** : il entre par le nonce, et non par les
    // données associées. Se tromper de numéro fait échouer l'authentification.
    let mut copie = origine;
    let issue = clefs
        .open(8, b"aad", copie.get_mut(..ecrits).expect("écrit"))
        .expect_err("mauvais numéro");
    assert_eq!(issue.reason(), Reason::NotAuthentic);
}

/// Un secret d'une longueur que la suite n'emploie pas.
#[test]
fn un_secret_de_la_mauvaise_taille_se_refuse() {
    for suite in [Suite::Aes128Gcm, Suite::Aes256Gcm, Suite::ChaCha20Poly1305] {
        for taille in [0_usize, 16, 31, 33, 47, 49] {
            if taille == suite.secret_len() {
                continue;
            }
            let secret = std::vec![0_u8; taille];
            let issue = Keys::from_secret(suite, &secret).expect_err("mauvaise taille");
            assert_eq!(
                issue.reason(),
                Reason::BadSecretLength,
                "{suite:?} {taille}"
            );
        }
    }
}

/// Un échantillon incomplet, et un tampon qui ne suffit pas.
#[test]
fn les_bornes_se_disent() {
    let clefs = clefs_initiales(b"client in");
    for taille in 0..16_usize {
        let echantillon = std::vec![0_u8; taille];
        let issue = clefs.header_mask(&echantillon).expect_err("trop court");
        assert_eq!(issue.reason(), Reason::TooShortToSample, "{taille}");
    }

    // Le tampon ne peut pas porter le tag.
    let issue = clefs
        .seal(1, b"", &mut [0_u8; 8], 4)
        .expect_err("pas la place");
    assert_eq!(issue.reason(), Reason::BufferTooSmall);

    // Et un tampon plus court qu'un tag ne porte pas de paquet.
    for taille in 0..16_usize {
        let mut court = [0_u8; 16];
        let issue = clefs
            .open(1, b"", court.get_mut(..taille).expect("court"))
            .expect_err("pas un paquet");
        assert_eq!(issue.reason(), Reason::BufferTooSmall, "{taille}");
    }
}

/// **AES-256 MASQUE AUSSI**, et avec sa propre taille de clé. L'annexe n'en
/// donne pas de vecteur : on éprouve donc que le masque n'est pas nul, et qu'il
/// n'est pas celui d'AES-128.
#[test]
fn aes256_masque_avec_sa_propre_cle() {
    let secret = std::vec![0x7c_u8; 48];
    let clefs = Keys::from_secret(Suite::Aes256Gcm, &secret).expect("dérivables");
    assert_eq!(clefs.header_key().len(), 32);

    let echantillon = [0x11_u8; 16];
    let masque = clefs.header_mask(&echantillon).expect("calculable");
    assert_ne!(masque, [0_u8; 5]);
    let court = std::vec![0x7c_u8; 32];
    let autres = Keys::from_secret(Suite::Aes128Gcm, &court).expect("dérivables");
    assert_ne!(
        masque,
        autres.header_mask(&echantillon).expect("calculable")
    );
}

/// **LES TROIS SUITES REFUSENT CE QUI NE S'AUTHENTIFIE PAS**, et pas seulement
/// celle des paquets `Initial`.
#[test]
fn les_trois_suites_refusent_ce_qui_est_abime() {
    for suite in [Suite::Aes128Gcm, Suite::Aes256Gcm, Suite::ChaCha20Poly1305] {
        let secret = std::vec![0x21_u8; suite.secret_len()];
        let clefs = Keys::from_secret(suite, &secret).expect("dérivables");
        let mut tampon = [0_u8; 64];
        tampon[0] = 0xaa;
        let ecrits = clefs.seal(3, b"aad", &mut tampon, 1).expect("chiffrable");
        tampon[0] ^= 0x01;
        let issue = clefs
            .open(3, b"aad", tampon.get_mut(..ecrits).expect("écrit"))
            .expect_err("abîmé");
        assert_eq!(issue.reason(), Reason::NotAuthentic, "{suite:?}");
    }
}

/// **UN PAQUET NE DÉPASSE PAS CE QU'UN DATAGRAMME PORTE** (§18.2 de RFC 9000).
/// Cette borne met les AEAD hors d'atteinte de leurs propres limites.
#[test]
fn un_paquet_hors_borne_se_refuse() {
    let clefs = clefs_initiales(b"client in");
    let borne = crate::keys::PACKET_OCTETS_MAX;
    let mut enorme = std::vec![0_u8; borne + 64];
    let issue = clefs
        .seal(1, b"", &mut enorme, borne + 1)
        .expect_err("hors borne");
    assert_eq!(issue.reason(), Reason::BufferTooSmall);

    let issue = clefs.open(1, b"", &mut enorme).expect_err("hors borne");
    assert_eq!(issue.reason(), Reason::BufferTooSmall);

    // La borne elle-même passe.
    let mut pile = std::vec![0_u8; borne + 16];
    assert!(clefs.seal(1, b"", &mut pile, borne).is_ok());
}

/// **UN SECRET PLUS LONG QUE LE HACHAGE SE REFUSE ICI ; PLUS COURT, C'EST LA
/// DÉRIVATION QUI LE DIT.** Deux chemins, deux vraies entrées — et une seule
/// vérité sur ce qu'est « trop court ».
#[test]
fn le_trop_long_et_le_trop_court_ne_se_disent_pas_au_meme_endroit() {
    let issue = Keys::from_secret(Suite::Aes128Gcm, &[0_u8; 48]).expect_err("trop long");
    assert_eq!(issue.reason(), Reason::BadSecretLength);
    let issue = Keys::from_secret(Suite::Aes128Gcm, &[0_u8; 16]).expect_err("trop court");
    assert_eq!(issue.reason(), Reason::BadSecretLength);
}
