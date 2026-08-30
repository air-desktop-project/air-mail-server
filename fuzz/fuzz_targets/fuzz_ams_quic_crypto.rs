// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : la protection des paquets QUIC** (RFC 9001).
//!
//! # Pourquoi celle-ci
//!
//! C'est le seul endroit du serveur où une erreur ne se traduit pas par un
//! refus, mais par une FUITE. Un nonce réemployé livre la clé
//! d'authentification de GCM ; un masque d'en-tête mal calculé laisse le numéro
//! de paquet en clair ; un déchiffrement qui accepte ce qu'il ne devrait pas
//! ouvre la connexion à qui sait envoyer un datagramme.
//!
//! Les vecteurs de l'annexe A prouvent que le calcul est JUSTE sur cinq
//! exemples. Cette cible prouve qu'il reste juste, ou refuse proprement, sur
//! tout le reste.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **CE QU'ON CHIFFRE SE DÉCHIFFRE**, et rend exactement le clair qu'on avait.
//! 3. **CE QU'ON ABÎME NE SE DÉCHIFFRE PAS.** Un octet changé — dans la charge,
//!    dans le tag, dans les données associées, ou dans le numéro de paquet —
//!    fait échouer l'authentification. Sans cela, le chiffrement
//!    n'authentifierait rien.
//! 4. **DEUX NUMÉROS DE PAQUET DONNENT DEUX NONCES.** Un nonce réemployé avec
//!    une même clé livre la clé d'authentification de GCM, et donc la capacité
//!    de forger n'importe quel message.
//! 5. **LA PROTECTION D'EN-TÊTE FAIT UN ALLER-RETOUR**, et ne touche jamais les
//!    bits que §5.4.1 laisse en clair.
//! 6. **UN JETON DE `Retry` NE SE VÉRIFIE QU'AVEC LE BON IDENTIFIANT
//!    D'ORIGINE**, celui que seul un témoin du paquet `Initial` connaît.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_quic_crypto::{Keys, Role, Secret, Suite, protect, retry_tag, unprotect, verify_retry};

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// L'identifiant de destination, tel qu'un client le choisirait.
    destination: &'a [u8],
    /// Un clair quelconque.
    clair: &'a [u8],
    /// Les données associées, c'est-à-dire l'en-tête.
    entete: &'a [u8],
    /// Deux numéros de paquet.
    numero: u64,
    autre: u64,
    /// De quel côté l'on se place.
    du_serveur: bool,
    /// Quelle suite éprouver.
    suite: u8,
    /// Un secret pour les suites qui ne sont pas celle des `Initial`.
    secret: &'a [u8],
}

/// La suite que ce rang désigne.
fn suite_de(rang: u8) -> Suite {
    match rang % 3 {
        0 => Suite::Aes128Gcm,
        1 => Suite::Aes256Gcm,
        _ => Suite::ChaCha20Poly1305,
    }
}

fuzz_target!(|entree: Entree| {
    // Un identifiant de plus de vingt octets n'existe pas, et le chiffrement
    // n'a pas à s'en soucier : c'est la grammaire qui l'a déjà refusé.
    let destination = entree.destination.get(..20.min(entree.destination.len()));
    let Some(destination) = destination else {
        return;
    };
    let role = match entree.du_serveur {
        true => Role::Server,
        false => Role::Client,
    };
    let Ok(secret) = Secret::initial(destination, role) else {
        return;
    };
    let Ok(clefs) = secret.keys() else {
        return;
    };

    // PROPRIÉTÉ 4 : deux numéros différents donnent deux nonces différents.
    if entree.numero != entree.autre {
        assert_ne!(
            clefs.nonce(entree.numero),
            clefs.nonce(entree.autre),
            "deux numéros ont donné le même nonce"
        );
    }

    // La borne de §18.2 : au-delà, le chiffrement refuse, et c'est tout.
    let clair = entree
        .clair
        .get(..4096.min(entree.clair.len()))
        .unwrap_or(&[]);
    let mut tampon = std::vec![0_u8; clair.len() + 16];
    tampon
        .get_mut(..clair.len())
        .unwrap_or_default()
        .copy_from_slice(clair);
    let Ok(ecrits) = clefs.seal(entree.numero, entree.entete, &mut tampon, clair.len()) else {
        return;
    };
    assert_eq!(ecrits, clair.len() + 16, "le tag fait seize octets");

    // PROPRIÉTÉ 2 : ce qu'on chiffre se déchiffre.
    let mut relu = tampon.clone();
    let rendu = clefs
        .open(entree.numero, entree.entete, &mut relu)
        .expect("ce qu'on chiffre se déchiffre");
    assert_eq!(rendu, clair.len());
    assert_eq!(relu.get(..rendu), Some(clair), "le clair a changé");

    // PROPRIÉTÉ 3 : ce qu'on abîme ne se déchiffre pas.
    for rang in 0..tampon.len().min(8) {
        let mut abime = tampon.clone();
        abime[rang] ^= 0x01;
        assert!(
            clefs
                .open(entree.numero, entree.entete, &mut abime)
                .is_err(),
            "un octet changé au rang {rang} est passé"
        );
    }
    if entree.numero != entree.autre {
        let mut copie = tampon.clone();
        assert!(
            clefs.open(entree.autre, entree.entete, &mut copie).is_err(),
            "un autre numéro de paquet est passé"
        );
    }
    if !entree.entete.is_empty() {
        let mut autre_entete = std::vec::Vec::from(entree.entete);
        autre_entete[0] ^= 0x01;
        let mut copie = tampon.clone();
        assert!(
            clefs
                .open(entree.numero, &autre_entete, &mut copie)
                .is_err(),
            "un en-tête modifié est passé"
        );
    }

    // PROPRIÉTÉ 5 : la protection d'en-tête fait un aller-retour.
    let suite = suite_de(entree.suite);
    if let Ok(autres) = Secret::new(suite, entree.secret).and_then(|s| s.keys()) {
        for forme in [0xc0_u8, 0x40] {
            for longueur in 1..=4_usize {
                let mut paquet = std::vec![0_u8; 64];
                paquet[0] = forme | u8::try_from(longueur - 1).unwrap_or(0);
                for (rang, place) in paquet.iter_mut().enumerate().skip(1) {
                    *place = u8::try_from(rang % 251).unwrap_or(0);
                }
                let origine = paquet.clone();
                if protect(&autres, &mut paquet, 1, longueur).is_err() {
                    continue;
                }
                // §5.4.1 : les bits de tête ne bougent jamais.
                let garde = match forme {
                    0xc0 => 0xf0,
                    _ => 0xe0,
                };
                assert_eq!(
                    paquet[0] & garde,
                    origine[0] & garde,
                    "des bits en clair ont bougé"
                );
                let relue = unprotect(&autres, &mut paquet, 1).expect("démasquable");
                assert_eq!(relue, longueur);
                assert_eq!(paquet, origine, "l'aller-retour a changé le paquet");
            }
        }
    }

    // PROPRIÉTÉ 6 : un `Retry` ne se vérifie qu'avec le bon identifiant.
    let corps = entree
        .entete
        .get(..64.min(entree.entete.len()))
        .unwrap_or(&[]);
    let mut atelier = std::vec![0_u8; 1 + destination.len() + corps.len() + 16];
    if let Ok(jeton) = retry_tag(destination, corps, &mut atelier) {
        let mut paquet = std::vec::Vec::from(corps);
        paquet.extend_from_slice(&jeton);
        verify_retry(destination, &paquet, &mut atelier).expect("ce qu'on calcule se vérifie");
        // Un autre identifiant ne convient pas — sauf s'il est le même.
        let autre = b"un-autre-identifiant";
        if autre.as_slice() != destination {
            assert!(
                verify_retry(autre, &paquet, &mut atelier).is_err(),
                "un autre identifiant d'origine est passé"
            );
        }
    }
});
