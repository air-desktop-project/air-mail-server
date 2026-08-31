// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que le pont vers l'interface QUIC de rustls doit rendre.
//!
//! # LES VECTEURS TRAVERSENT LE PONT, ET NON LA CRATE EN DESSOUS
//!
//! `ams-quic-crypto` a ses propres essais contre l'annexe A de RFC 9001. Ceux-ci
//! passent par les TRAITS de `rustls` : ils éprouvent le branchement — l'ordre
//! des arguments, la place du tag, le sens du masque —, c'est-à-dire tout ce que
//! la crate en dessous ne peut pas vérifier pour nous.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use ams_quic_crypto::{PacketKeys, Suite};
use rustls::crypto::cipher::{AeadKey, Iv};
use rustls::quic::Algorithm as _;

use super::{ALPN_H3, Algorithme, alpn_h3, provider_quic};
use rustls::crypto::CryptoProvider;

/// Les octets que décrit cette écriture hexadécimale.
fn octets(hexa: &str) -> Vec<u8> {
    hexa.as_bytes()
        .chunks(2)
        .map(|paire| {
            let texte = core::str::from_utf8(paire).expect("de l'hexadécimal");
            u8::from_str_radix(texte, 16).expect("deux chiffres")
        })
        .collect()
}

/// **LE FOURNISSEUR ORDINAIRE NE SAIT PAS CHIFFRER QUIC, CELUI-CI SI.**
///
/// C'est exactement ce qui bloquait HTTP/3 : `rustls::quic::ServerConnection`
/// refuse de se construire quand aucune suite ne porte de `quic`.
#[test]
fn le_fournisseur_quic_sait_ce_que_l_autre_ignore() {
    let ordinaire = crate::provider();
    let avec_quic = ordinaire
        .cipher_suites
        .iter()
        .filter_map(rustls::SupportedCipherSuite::tls13)
        .filter(|suite| suite.quic.is_some())
        .count();
    assert_eq!(
        avec_quic, 0,
        "le fournisseur ordinaire n'a pas à savoir chiffrer QUIC"
    );

    let quic = provider_quic();
    assert!(!quic.cipher_suites.is_empty(), "aucune suite n'a survécu");
    for suite in &quic.cipher_suites {
        let tls13 = suite.tls13().expect("TLS 1.3 seul (C4)");
        assert!(
            tls13.quic.is_some(),
            "{:?} est offerte sans savoir chiffrer QUIC",
            tls13.common.suite
        );
    }
}

/// Le fournisseur QUIC offre les mêmes suites que l'autre — ni plus, ni moins.
///
/// **SI CELA CHANGE, C'EST QU'UNE SUITE A ÉTÉ ÉCARTÉE EN SILENCE**, et un
/// serveur qui offre moins que ce qu'on croit est un serveur qu'on ne comprend
/// plus.
#[test]
fn le_fournisseur_quic_n_ecarte_aucune_suite() {
    let ordinaire: Vec<_> = crate::provider()
        .cipher_suites
        .iter()
        .filter_map(rustls::SupportedCipherSuite::tls13)
        .map(|suite| suite.common.suite)
        .collect();
    let quic: Vec<_> = provider_quic()
        .cipher_suites
        .iter()
        .filter_map(rustls::SupportedCipherSuite::tls13)
        .map(|suite| suite.common.suite)
        .collect();
    assert_eq!(quic, ordinaire);
}

/// **`h3`, ET RIEN D'AUTRE.**
#[test]
fn on_n_annonce_que_http3() {
    let dits = alpn_h3();
    assert_eq!(dits.len(), 1, "{dits:?}");
    assert_eq!(dits.first().map(Vec::as_slice), Some(ALPN_H3));
    assert_eq!(ALPN_H3, b"h3");
    for refuse in [&b"h2"[..], b"http/1.1", b"hq-interop", b"h3-29"] {
        assert!(
            !dits.iter().any(|dit| dit.as_slice() == refuse),
            "{refuse:?} est annoncé"
        );
    }
}

// # POURQUOI CES ESSAIS N'EMPLOIENT QUE DES CLÉS DE TRENTE-DEUX OCTETS
//
// `rustls::crypto::cipher::AeadKey` ne se construit, hors de `rustls`, qu'à
// partir d'un tableau de trente-deux octets : le constructeur qui prend une
// longueur est `pub(crate)`. C'est exactement ce que `rustls` fournit à
// AES-256 et à ChaCha20 — leurs chemins nominaux sont donc éprouvés ici.
//
// **AES-128 en reçoit seize, et seize seulement.** Une clé de trente-deux
// octets ne peut donc lui venir que d'un désaccord entre `aead_key_len` et ce
// que `rustls` envoie : c'est le chemin de refus, et c'est lui qu'on éprouve
// avec cette suite. Le chemin nominal d'AES-128, lui, est le même code — la
// suite n'est qu'une valeur — et une vraie poignée de main le traverse dans
// `tests/quic.rs`.

/// Des clés de paquet pour une suite qui accepte trente-deux octets.
fn clefs_de_paquet(suite: Suite) -> Box<dyn rustls::quic::PacketKey> {
    Algorithme(suite).packet_key(AeadKey::from([0x2a_u8; 32]), Iv::from([0x0b_u8; 12]))
}

/// Une clé de protection d'en-tête pour une suite qui accepte trente-deux
/// octets.
fn clefs_d_en_tete(suite: Suite) -> Box<dyn rustls::quic::HeaderProtectionKey> {
    Algorithme(suite).header_protection_key(AeadKey::from([0x3c_u8; 32]))
}

/// **CE QUI TRAVERSE LE PONT REVIENT INTACT.**
///
/// Le pont place le tag à part quand `ams-quic-crypto` l'écrit à la suite du
/// clair ; l'aller-retour est ce qui prouve que ce déplacement est juste.
#[test]
fn ce_qui_traverse_le_pont_revient_intact() {
    for suite in [Suite::Aes256Gcm, Suite::ChaCha20Poly1305] {
        let paquet = clefs_de_paquet(suite);
        assert_eq!(paquet.tag_len(), 16, "{suite:?}");

        let entete = octets("c300000001088394c8f03e515708000044");
        let clair = b"une charge de paquet".to_vec();
        let mut charge = clair.clone();
        let tag = paquet
            .encrypt_in_place(2, &entete, &mut charge)
            .expect("chiffrable");
        assert_ne!(charge, clair, "{suite:?} n'a pas chiffré");
        assert_eq!(tag.as_ref().len(), 16, "{suite:?}");

        let mut avec_tag = charge.clone();
        avec_tag.extend_from_slice(tag.as_ref());
        let relu = paquet
            .decrypt_in_place(2, &entete, &mut avec_tag)
            .expect("déchiffrable");
        assert_eq!(relu, clair.as_slice(), "{suite:?}");
    }
}

/// **LE PONT CHIFFRE COMME LA CRATE EN DESSOUS**, sinon il aurait sa propre
/// implémentation — et ses propres fautes.
#[test]
fn le_pont_chiffre_comme_la_crate_en_dessous() {
    let paquet = clefs_de_paquet(Suite::Aes256Gcm);
    let dessous =
        PacketKeys::new(Suite::Aes256Gcm, &[0x2a_u8; 32], &[0x0b_u8; 12]).expect("constructible");

    let entete = octets("c30000000108");
    let clair = b"une charge de paquet".to_vec();

    let mut par_le_pont = clair.clone();
    let tag = paquet
        .encrypt_in_place(9, &entete, &mut par_le_pont)
        .expect("chiffrable");
    par_le_pont.extend_from_slice(tag.as_ref());

    let mut par_dessous = clair.clone();
    par_dessous.resize(clair.len().saturating_add(16), 0);
    dessous
        .seal(9, &entete, &mut par_dessous, clair.len())
        .expect("chiffrable");

    assert_eq!(par_le_pont, par_dessous);
}

/// **LE VECTEUR D'INITIALISATION TRAVERSE LE PONT INTACT.**
///
/// `Iv` ne se prête pas : le pont le reconstruit en fabriquant le nonce du
/// paquet zéro. Si cette reconstruction était fausse, le chiffré différerait de
/// celui de la crate en dessous — c'est ce que l'essai précédent surveille — et
/// le nonce d'un autre numéro le dirait aussi.
#[test]
fn le_vecteur_traverse_le_pont_intact() {
    let dessous =
        PacketKeys::new(Suite::Aes256Gcm, &[0x2a_u8; 32], &[0x0b_u8; 12]).expect("constructible");
    // Le nonce du paquet zéro EST le vecteur : c'est ce que le pont exploite.
    assert_eq!(dessous.nonce(0), [0x0b_u8; 12]);
    assert_ne!(dessous.nonce(1), [0x0b_u8; 12]);
}

/// **UN AUTRE NUMÉRO DE PAQUET NE DÉCHIFFRE PAS**, parce que le nonce en dépend
/// (§5.3). C'est ce qui lie un paquet à sa place dans la suite.
#[test]
fn le_numero_de_paquet_entre_dans_le_nonce() {
    let paquet = clefs_de_paquet(Suite::Aes256Gcm);
    let entete = octets("c300000001");
    let mut charge = b"la charge".to_vec();
    let tag = paquet
        .encrypt_in_place(7, &entete, &mut charge)
        .expect("chiffrable");
    let mut avec_tag = charge;
    avec_tag.extend_from_slice(tag.as_ref());
    assert!(
        paquet.decrypt_in_place(8, &entete, &mut avec_tag).is_err(),
        "un paquet doit être lié à son numéro"
    );
}

/// **L'EN-TÊTE EST AUTHENTIFIÉ, PAS CHIFFRÉ** : le changer d'un bit fait échouer
/// l'authentification, parce qu'il sert de données associées.
#[test]
fn l_entete_est_authentifie() {
    let paquet = clefs_de_paquet(Suite::Aes256Gcm);
    let entete = octets("c300000001");
    let mut charge = b"la charge".to_vec();
    let tag = paquet
        .encrypt_in_place(1, &entete, &mut charge)
        .expect("chiffrable");
    let mut avec_tag = charge;
    avec_tag.extend_from_slice(tag.as_ref());
    let mut autre = entete.clone();
    autre[0] ^= 0x01;
    assert!(
        paquet.decrypt_in_place(1, &autre, &mut avec_tag).is_err(),
        "un en-tête modifié doit faire échouer l'authentification"
    );
}

/// Une charge trop courte pour porter un tag se refuse plutôt que de déborder.
#[test]
fn une_charge_sans_tag_se_refuse() {
    let paquet = clefs_de_paquet(Suite::Aes256Gcm);
    for taille in [0_usize, 1, 15] {
        let mut charge = vec![0_u8; taille];
        assert!(
            paquet.decrypt_in_place(0, b"entete", &mut charge).is_err(),
            "{taille} octets ne peuvent pas porter un tag de seize"
        );
    }
}

/// **LE MASQUE EST LE MÊME DANS LES DEUX SENS** : c'est un OU-exclusif, donc
/// l'appliquer deux fois rend l'original.
#[test]
fn le_masque_se_defait_de_lui_meme() {
    for suite in [Suite::Aes256Gcm, Suite::ChaCha20Poly1305] {
        let entete = clefs_d_en_tete(suite);
        assert_eq!(entete.sample_len(), 16, "{suite:?}");
        let echantillon = octets("d1b1c98dd7689fb8ec11d242b123dc9b");

        for (premier, longueur) in [(0xc3_u8, 4_usize), (0x43, 1), (0x40, 2), (0xc0, 3)] {
            let mut octet = premier;
            let mut numero = vec![0x12_u8; longueur];
            let avant = (octet, numero.clone());
            entete
                .encrypt_in_place(&echantillon, &mut octet, &mut numero)
                .expect("masquable");
            assert_ne!((octet, numero.clone()), avant, "{suite:?} n'a rien masqué");
            entete
                .decrypt_in_place(&echantillon, &mut octet, &mut numero)
                .expect("démasquable");
            assert_eq!(
                (octet, numero),
                avant,
                "{suite:?} : l'aller-retour a changé"
            );
        }
    }
}

/// **QUATRE BITS POUR UN EN-TÊTE LONG, CINQ POUR UN COURT** (§5.4.1), et le
/// premier bit — celui qui dit lequel — n'est jamais masqué.
///
/// Sans quoi le pair ne pourrait pas savoir combien de bits démasquer.
#[test]
fn le_premier_bit_reste_lisible() {
    let entete = clefs_d_en_tete(Suite::Aes256Gcm);
    let echantillon = octets("d1b1c98dd7689fb8ec11d242b123dc9b");
    for premier in [0xc3_u8, 0x43, 0xff, 0x7f] {
        let mut octet = premier;
        let mut numero = vec![0_u8; 1];
        entete
            .encrypt_in_place(&echantillon, &mut octet, &mut numero)
            .expect("masquable");
        assert_eq!(
            octet & 0x80,
            premier & 0x80,
            "le bit de forme doit rester lisible"
        );
        // Et un en-tête long ne laisse jamais toucher le cinquième bit.
        if premier & 0x80 == 0x80 {
            assert_eq!(
                octet & 0xf0,
                premier & 0xf0,
                "un en-tête long masque 4 bits"
            );
        }
    }
}

/// Un échantillon de la mauvaise taille se refuse, et un numéro trop long aussi.
#[test]
fn ce_qui_n_a_pas_la_bonne_taille_se_refuse() {
    let entete = clefs_d_en_tete(Suite::Aes256Gcm);
    let mut octet = 0xc3_u8;
    let mut numero = vec![0_u8; 4];
    for taille in [0_usize, 15, 17, 32] {
        let court = vec![0_u8; taille];
        assert!(
            entete
                .encrypt_in_place(&court, &mut octet, &mut numero)
                .is_err(),
            "{taille} octets d'échantillon"
        );
        assert!(
            entete
                .decrypt_in_place(&court, &mut octet, &mut numero)
                .is_err(),
            "{taille} octets d'échantillon"
        );
    }
    let bon = octets("d1b1c98dd7689fb8ec11d242b123dc9b");
    let mut trop = vec![0_u8; 5];
    assert!(
        entete
            .encrypt_in_place(&bon, &mut octet, &mut trop)
            .is_err(),
        "un numéro de paquet ne fait jamais plus de quatre octets"
    );
    // Zéro octet de numéro est licite : il n'y a rien à masquer.
    let mut rien: Vec<u8> = Vec::new();
    assert!(entete.encrypt_in_place(&bon, &mut octet, &mut rien).is_ok());
}

/// **UNE CLÉ DE LA MAUVAISE LONGUEUR NE PANIQUE PAS, ELLE REFUSE.**
///
/// `rustls` ne prévoit pas qu'une clé soit refusée : sa signature rend un objet,
/// pas un `Result`. Un serveur qui s'arrête est plus grave qu'une connexion qui
/// échoue — et celle-là échouera, franchement, dès son premier paquet.
#[test]
fn une_clef_impossible_refuse_plutot_que_de_paniquer() {
    // AES-128 attend seize octets ; `AeadKey` n'en sait construire que
    // trente-deux hors de `rustls`. C'est donc, ici, la clé impossible.
    let algorithme = Algorithme(Suite::Aes128Gcm);
    assert_eq!(algorithme.aead_key_len(), 16);

    let paquet = algorithme.packet_key(AeadKey::from([0_u8; 32]), Iv::from([0_u8; 12]));
    let mut charge = b"rien".to_vec();
    assert!(paquet.encrypt_in_place(0, b"", &mut charge).is_err());
    assert_eq!(charge, b"rien", "une charge refusée reste intacte");
    let mut avec_tag = vec![0_u8; 20];
    assert!(paquet.decrypt_in_place(0, b"", &mut avec_tag).is_err());
    assert_eq!(paquet.tag_len(), 16);
    // Les limites ne dépendent pas de la clé : un refus ne doit pas les rendre
    // infinies, sinon une connexion sans clé chiffrerait sans borne.
    assert_eq!(paquet.confidentiality_limit(), 1 << 23);
    assert_eq!(paquet.integrity_limit(), 1 << 52);

    let entete = algorithme.header_protection_key(AeadKey::from([0_u8; 32]));
    assert_eq!(entete.sample_len(), 16);
    let mut octet = 0xc3_u8;
    let mut numero = vec![0_u8; 4];
    let bon = octets("d1b1c98dd7689fb8ec11d242b123dc9b");
    assert!(
        entete
            .encrypt_in_place(&bon, &mut octet, &mut numero)
            .is_err()
    );
    assert_eq!(octet, 0xc3, "un en-tête refusé reste intact");
}

/// **CHAQUE SUITE PORTE SES PROPRES LIMITES** (§6.6 de RFC 9001) : ChaCha20 n'a
/// pas la même borne d'intégrité que les modes GCM.
#[test]
fn chaque_suite_porte_ses_limites() {
    let cas = [
        (Suite::Aes128Gcm, 16_usize, 1_u64 << 23, 1_u64 << 52),
        (Suite::Aes256Gcm, 32, 1 << 23, 1 << 52),
        (Suite::ChaCha20Poly1305, 32, 1 << 23, 1 << 36),
    ];
    for (suite, longueur, confidentialite, integrite) in cas {
        let algorithme = Algorithme(suite);
        assert_eq!(algorithme.aead_key_len(), longueur, "{suite:?}");
        let paquet = algorithme.packet_key(AeadKey::from([0_u8; 32]), Iv::from([0_u8; 12]));
        assert_eq!(paquet.confidentiality_limit(), confidentialite, "{suite:?}");
        assert_eq!(paquet.integrity_limit(), integrite, "{suite:?}");
    }
}

/// L'identifiant de destination du client, annexe A.1 de RFC 9001.
const DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

/// La suite AES-128 du fournisseur QUIC, telle que `rustls` la voit.
///
/// **RIEN N'EST FUITÉ ICI** : les suites vivent dans le binaire, donc
/// `tls13()` rend une référence qui survit au fournisseur qu'on jette.
fn suite_aes128() -> &'static rustls::Tls13CipherSuite {
    provider_quic()
        .cipher_suites
        .iter()
        .filter_map(rustls::SupportedCipherSuite::tls13)
        .find(|suite| suite.common.suite == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256)
        .expect("AES-128-GCM est la suite obligatoire de QUIC (§5.1 de RFC 9001)")
}

/// **RUSTLS ET NOUS DÉRIVONS LES MÊMES CLÉS INITIALES.**
///
/// C'est ce qu'aucun essai de `ams-quic-crypto` ne peut établir : là-bas, notre
/// dérivation dialogue avec elle-même. Ici, `rustls` dérive les clés à sa façon,
/// les remet au pont, et le chiffré doit être celui que notre dérivation à nous
/// produit. **Si les deux divergeaient, les paquets seraient illisibles**, et
/// aucune poignée de main QUIC n'aboutirait.
///
/// C'est aussi le seul essai unitaire qui traverse le chemin NOMINAL d'AES-128 :
/// `AeadKey` ne se construit pas à seize octets hors de `rustls`.
#[test]
fn rustls_et_nous_derivons_les_memes_clefs_initiales() {
    let suite = suite_aes128();
    let quic = suite.quic.expect("le fournisseur QUIC en porte un");
    let clefs = rustls::quic::Keys::initial(
        rustls::quic::Version::V1,
        suite,
        quic,
        &DCID,
        rustls::Side::Client,
    );

    // Ce que notre dérivation à nous produit, pour le même identifiant.
    let secret =
        ams_quic_crypto::Secret::initial(&DCID, ams_quic_crypto::Role::Client).expect("dérivable");
    let nous = secret.keys().expect("dérivables");

    let entete = octets("c300000001088394c8f03e5157080000449e00000002");
    let clair = octets("060040f1010000ed0303ebf8fa56f129");

    let mut par_rustls = clair.clone();
    let tag = clefs
        .local
        .packet
        .encrypt_in_place(2, &entete, &mut par_rustls)
        .expect("chiffrable");
    par_rustls.extend_from_slice(tag.as_ref());

    let mut par_nous = clair.clone();
    par_nous.resize(clair.len().saturating_add(16), 0);
    nous.seal(2, &entete, &mut par_nous, clair.len())
        .expect("chiffrable");

    assert_eq!(
        par_rustls, par_nous,
        "rustls et ams-quic-crypto doivent dériver la même clé initiale"
    );
}

/// **LE MASQUE DE L'ANNEXE A.2, PAR LE CHEMIN QUE PRENDRA UN VRAI PAQUET.**
///
/// Masquer un octet de tête nul et quatre octets de numéro nuls REND le masque :
/// un OU-exclusif avec zéro est l'identité. On lit donc directement, dans ce que
/// le pont a écrit, les octets que la RFC annonce.
#[test]
fn le_masque_de_l_annexe_traverse_le_pont() {
    let suite = suite_aes128();
    let quic = suite.quic.expect("le fournisseur QUIC en porte un");
    let clefs = rustls::quic::Keys::initial(
        rustls::quic::Version::V1,
        suite,
        quic,
        &DCID,
        rustls::Side::Client,
    );

    let echantillon = octets("d1b1c98dd7689fb8ec11d242b123dc9b");
    let mut premier = 0_u8;
    let mut numero = vec![0_u8; 4];
    clefs
        .local
        .header
        .encrypt_in_place(&echantillon, &mut premier, &mut numero)
        .expect("masquable");

    // §A.2 : le masque est `437b9aec36`. Un octet de tête nul est un en-tête
    // COURT — cinq bits masqués —, donc `0x43 & 0x1f`.
    assert_eq!(premier, 0x43 & 0x1f);
    assert_eq!(numero, octets("7b9aec36"));
}

/// **CE QUI BLOQUAIT HTTP/3 : `quic::ServerConnection` REFUSAIT DE SE
/// CONSTRUIRE.**
///
/// `rustls` exige qu'au moins une suite sache chiffrer un paquet QUIC. Le
/// fournisseur pur Rust n'en avait aucune, et le message était « at least one
/// ciphersuite must support QUIC ». Cet essai est le constat que ce n'est plus
/// le cas — et il échouera le jour où quelqu'un retirera les `quic` des suites.
#[test]
fn une_connexion_quic_se_construit_desormais() {
    let sans_quic = rustls::ServerConfig::builder_with_provider(crate::provider().into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3");
    // Le fournisseur ordinaire ne passe même pas la construction du bâtisseur
    // côté QUIC ; on le constate sur la propriété que `rustls` interroge.
    assert!(
        !sans_quic
            .clone()
            .with_no_client_auth()
            .crypto_provider()
            .cipher_suites
            .iter()
            .filter_map(rustls::SupportedCipherSuite::tls13)
            .any(|suite| suite.quic.is_some()),
        "le fournisseur ordinaire ne doit pas savoir chiffrer QUIC"
    );

    let avec_quic = rustls::ServerConfig::builder_with_provider(provider_quic().into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth();
    assert!(
        avec_quic
            .crypto_provider()
            .cipher_suites
            .iter()
            .filter_map(rustls::SupportedCipherSuite::tls13)
            .all(|suite| suite.quic.is_some()),
        "chaque suite offerte doit savoir chiffrer QUIC"
    );
}

/// **UNE CHARGE PLUS GRANDE QU'UN DATAGRAMME SE REFUSE**, plutôt que de partir.
///
/// `ams-quic-crypto` borne ce qu'il chiffre à ce qu'un datagramme UDP peut
/// porter. Le pont doit rendre ce refus à `rustls` au lieu de le traduire en
/// succès — c'est la seule cause d'échec du chiffrement qui ne vienne pas d'une
/// clé absente.
#[test]
fn une_charge_plus_grande_qu_un_datagramme_se_refuse() {
    let paquet = clefs_de_paquet(Suite::Aes256Gcm);
    let mut enorme = vec![0_u8; ams_quic_crypto::PACKET_OCTETS_MAX.saturating_add(1)];
    assert!(
        paquet.encrypt_in_place(0, b"entete", &mut enorme).is_err(),
        "une charge hors borne doit être refusée"
    );
    // Et la borne elle-même passe.
    let mut pile = vec![0_u8; ams_quic_crypto::PACKET_OCTETS_MAX];
    assert!(paquet.encrypt_in_place(0, b"entete", &mut pile).is_ok());
}

/// **UNE SUITE QU'ON NE SAIT PAS CONDUIRE EST ÉCARTÉE, PAS OFFERTE SANS QUIC.**
///
/// La laisser passer avec `quic: None` la ferait échouer APRÈS la poignée de
/// main, au premier paquet — un symptôme très loin de sa cause.
#[test]
fn une_suite_inconnue_est_ecartee() {
    assert!(
        super::avec_quic(rustls::CipherSuite::TLS13_AES_128_CCM_SHA256).is_none(),
        "une suite qu'on ne sait pas conduire ne doit pas être offerte"
    );
    // Et les trois qu'on sait conduire portent bien leur algorithme.
    for nom in [
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
        rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
        rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    ] {
        let suite = super::avec_quic(nom).expect("connue");
        let tls13 = suite.tls13().expect("TLS 1.3");
        assert_eq!(tls13.common.suite, nom);
        assert!(tls13.quic.is_some(), "{nom:?}");
    }
}

/// **DEUX APPELS RENDENT LES MÊMES SUITES, À LA MÊME ADRESSE.**
///
/// La première version fuitait un objet par suite et par appel ; le fuzz l'a dit
/// en comptant les octets perdus. Les suites sont désormais des constantes du
/// binaire, et cet essai le CONSTATE au lieu de le supposer.
#[test]
fn deux_appels_ne_fabriquent_rien_de_neuf() {
    let une = provider_quic();
    let deux = provider_quic();
    let adresses = |fournisseur: &CryptoProvider| -> Vec<usize> {
        fournisseur
            .cipher_suites
            .iter()
            .filter_map(rustls::SupportedCipherSuite::tls13)
            .map(|suite| core::ptr::from_ref(suite) as usize)
            .collect()
    };
    assert_eq!(adresses(&une), adresses(&deux));
    assert_eq!(adresses(&une).len(), une.cipher_suites.len());
}

/// **NOS SUITES SONT CELLES D'AMONT, PLUS L'ALGORITHME QUIC — RIEN D'AUTRE.**
///
/// C'est ce qui garantit qu'ajouter QUIC ne change pas le chiffrement : même
/// hachage, même dérivation, même AEAD. Si l'un de ces trois divergeait, une
/// connexion TLS et une connexion QUIC ne parleraient plus la même langue.
#[test]
fn nos_suites_sont_celles_d_amont() {
    let cas = [
        (
            rustls_rustcrypto::TLS13_AES_128_GCM_SHA256,
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
        ),
        (
            rustls_rustcrypto::TLS13_AES_256_GCM_SHA384,
            rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
        ),
        (
            rustls_rustcrypto::TLS13_CHACHA20_POLY1305_SHA256,
            rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        ),
    ];
    for (amont, nom) in cas {
        let amont = super::tls13_de(amont);
        assert_eq!(amont.common.suite, nom);
        assert!(amont.quic.is_none(), "l'amont n'en porte pas, {nom:?}");

        let notre = super::avec_quic(nom)
            .and_then(|suite| suite.tls13())
            .expect("connue");
        assert_eq!(notre.common.suite, amont.common.suite);
        assert_eq!(
            notre.common.confidentiality_limit,
            amont.common.confidentiality_limit
        );
        // **ON COMPARE CE QUE LES OBJETS FONT, ET NON LEUR ADRESSE** : une
        // constante peut être dupliquée d'un site d'emploi à l'autre, et
        // l'égalité de pointeurs serait alors fausse sans que rien ne cloche.
        assert_eq!(
            notre.common.hash_provider.algorithm(),
            amont.common.hash_provider.algorithm(),
            "{nom:?} : le hachage doit être celui d'amont"
        );
        assert_eq!(
            notre.common.hash_provider.hash(b"air-mail-server").as_ref(),
            amont.common.hash_provider.hash(b"air-mail-server").as_ref(),
            "{nom:?} : le hachage doit rendre la même chose qu'en amont"
        );
        assert_eq!(
            notre
                .hkdf_provider
                .extract_from_secret(None, b"secret")
                .expand_block(&[b"quic key"])
                .as_ref(),
            amont
                .hkdf_provider
                .extract_from_secret(None, b"secret")
                .expand_block(&[b"quic key"])
                .as_ref(),
            "{nom:?} : la dérivation doit être celle d'amont"
        );
        assert_eq!(
            notre.aead_alg.key_len(),
            amont.aead_alg.key_len(),
            "{nom:?} : l'AEAD doit être celui d'amont"
        );
        assert!(
            notre.quic.is_some(),
            "{nom:?} : et l'algorithme QUIC en plus"
        );
    }
}
