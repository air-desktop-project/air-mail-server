// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que `HMAC-SHA-256` doit rendre, et ce que la comparaison doit faire.

use std::vec::Vec;

use super::{MAC_OCTETS, egales, hmac_sha256};

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

/// **LES VECTEURS DE §4 DE RFC 4231**, qui prouvent le résultat et non la
/// provenance.
///
/// # LES MOTIFS SE CONSTRUISENT, ILS NE SE TRANSCRIVENT PAS
///
/// Les clés et les messages de ces cas sont des octets répétés — vingt fois
/// `0xaa`, cent trente et une fois, cinquante fois `0xdd`. Les recopier à la
/// main, c'est se donner une chance de compter faux, et un vecteur mal transcrit
/// ne prouve plus rien : il fait échouer un code juste, ou passer un code faux.
///
/// Le premier jet les transcrivait. Deux des sept étaient faux.
#[test]
fn les_vecteurs_de_la_rfc_4231() {
    /// Un octet répété.
    fn repete(octet: u8, combien: usize) -> Vec<u8> {
        std::vec![octet; combien]
    }

    let cas: [(Vec<u8>, Vec<u8>, &str); 7] = [
        // Cas 1 : clé de vingt octets.
        (
            repete(0x0b, 20),
            b"Hi There".to_vec(),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        ),
        // Cas 2 : clé plus courte que le condensé.
        (
            b"Jefe".to_vec(),
            b"what do ya want for nothing?".to_vec(),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        ),
        // Cas 3 : clé de vingt octets, message de cinquante.
        (
            repete(0xaa, 20),
            repete(0xdd, 50),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        ),
        // Cas 4 : clé de vingt-cinq octets.
        (
            (1..=25_u8).collect(),
            repete(0xcd, 50),
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
        ),
        // Cas 5 : la RFC tronque le résultat à seize octets ; on vérifie le
        // condensé entier, dont il est le préfixe.
        (
            repete(0x0c, 20),
            b"Test With Truncation".to_vec(),
            "a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5",
        ),
        // **CAS 6 : CLÉ DE 131 OCTETS**, plus longue qu'un bloc — c'est ce cas
        // qui exerce le hachage préalable de §2 de RFC 2104, et sans lui cette
        // branche ne serait jamais parcourue.
        (
            repete(0xaa, 131),
            b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        ),
        // Cas 7 : la même clé longue, avec un long message.
        (
            repete(0xaa, 131),
            b"This is a test using a larger than block-size key and a larger \
than block-size data. The key needs to be hashed before being used by the HMAC \
algorithm."
                .to_vec(),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
        ),
    ];
    for (rang, (clef, message, attendu)) in cas.into_iter().enumerate() {
        let obtenu = hmac_sha256(&clef, &message);
        assert_eq!(
            obtenu.as_slice(),
            octets(attendu).as_slice(),
            "cas {rang} de RFC 4231 (numéroté depuis zéro)"
        );
    }
}

/// **UNE CLÉ PLUS LONGUE QU'UN BLOC SE HACHE** (§2 de RFC 2104) : sans cela,
/// deux clés qui ne diffèrent qu'au-delà du soixante-quatrième octet donneraient
/// le même sceau.
#[test]
fn une_clef_longue_ne_perd_pas_sa_queue() {
    let une = std::vec![0xaa_u8; 200];
    let mut autre = une.clone();
    // Elles ne diffèrent qu'au centième octet, bien au-delà d'un bloc.
    autre[100] = 0xbb;
    assert_ne!(
        hmac_sha256(&une, b"message"),
        hmac_sha256(&autre, b"message"),
        "la queue de la clé ne compte pas"
    );
}

/// Un sceau fait toujours trente-deux octets, et change avec le message.
#[test]
fn le_sceau_depend_de_tout() {
    let sceau = hmac_sha256(b"clef", b"message");
    assert_eq!(sceau.len(), MAC_OCTETS);
    assert_ne!(hmac_sha256(b"clef", b"messagf"), sceau);
    assert_ne!(hmac_sha256(b"cleg", b"message"), sceau);
    // Une clé vide et un message vide restent licites.
    assert_eq!(hmac_sha256(b"", b"").len(), MAC_OCTETS);
}

/// **LA COMPARAISON NE S'ARRÊTE JAMAIS PLUS TÔT**, et elle dit vrai.
#[test]
fn la_comparaison_dit_vrai() {
    assert!(egales(b"", b""));
    assert!(egales(b"abc", b"abc"));
    assert!(!egales(b"abc", b"abd"), "le dernier octet diffère");
    assert!(!egales(b"abc", b"bbc"), "le premier octet diffère");
    assert!(!egales(b"abc", b"ab"), "une longueur diffère");
    assert!(!egales(b"ab", b"abc"), "l'autre longueur diffère");
    assert!(!egales(b"", b"a"));
    assert!(!egales(b"a", b""));
    // Un préfixe commun ne suffit pas : c'est exactement ce qu'une comparaison
    // qui s'arrête tôt laisserait deviner.
    assert!(!egales(
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"
    ));
}
