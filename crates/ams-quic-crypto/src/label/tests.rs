// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que `HKDF-Expand-Label` doit produire, d'après RFC 9001 annexe A.1.

use super::{expand_sha256, expand_sha384, extract_sha256, hkdf_label};
use crate::error::Reason;

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

/// **LES CINQ STRUCTURES DE L'ANNEXE A.1, À L'OCTET PRÈS.**
///
/// Ce sont elles qu'on compare, et non le résultat de la dérivation : une
/// structure fausse avec un secret faux pourrait donner un résultat juste par
/// accident, et l'on ne saurait pas lequel des deux est en cause.
#[test]
fn les_structures_de_l_annexe_sont_a_l_octet_pres() {
    let cas: [(u16, &[u8], &str); 5] = [
        (32, b"client in", "00200f746c73313320636c69656e7420696e00"),
        (32, b"server in", "00200f746c7331332073657276657220696e00"),
        (16, b"quic key", "00100e746c7331332071756963206b657900"),
        (12, b"quic iv", "000c0d746c733133207175696320697600"),
        (16, b"quic hp", "00100d746c733133207175696320687000"),
    ];
    for (longueur, etiquette, attendue) in cas {
        let mut place = [0_u8; 64];
        let ecrits = hkdf_label(longueur, etiquette, &mut place).expect("composable");
        assert_eq!(
            place.get(..ecrits).unwrap_or_default(),
            hexa(attendue).as_slice(),
            "{}",
            std::str::from_utf8(etiquette).expect("utf8")
        );
    }
}

/// **LE PRÉFIXE `tls13 ` EST CE QUI SÉPARE LES UNIVERS.** Sans lui, deux
/// protocoles qui partagent un secret partageraient des clés.
#[test]
fn le_prefixe_tls13_est_dans_la_structure() {
    let mut place = [0_u8; 64];
    let ecrits = hkdf_label(16, b"quic key", &mut place).expect("composable");
    let structure = place.get(..ecrits).unwrap_or_default();
    let cherche = b"tls13 quic key";
    assert!(
        structure
            .windows(cherche.len())
            .any(|fenetre| fenetre == cherche),
        "la structure ne porte pas le préfixe : {structure:02x?}"
    );
}

/// **LE CONTEXTE EST VIDE, ET SA LONGUEUR S'ÉCRIT QUAND MÊME.** L'omettre ferait
/// une structure d'un octet plus courte, donc une clé différente.
#[test]
fn le_contexte_vide_s_ecrit_quand_meme() {
    let mut place = [0_u8; 64];
    let ecrits = hkdf_label(16, b"quic hp", &mut place).expect("composable");
    assert_eq!(place.get(ecrits.saturating_sub(1)), Some(&0));
    // Deux de longueur, un de compte, six de préfixe, sept d'étiquette, un de
    // contexte.
    assert_eq!(ecrits, 2 + 1 + 6 + 7 + 1);
}

/// **LE SECRET INITIAL DE L'ANNEXE A.1**, dérivé du sel de §5.2 et de
/// l'identifiant que le client a choisi.
#[test]
fn le_secret_initial_de_l_annexe_se_retrouve() {
    let sel = hexa("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
    let cid = hexa("8394c8f03e515708");
    let mut secret = [0_u8; 32];
    extract_sha256(&sel, &cid, &mut secret).expect("extractible");
    assert_eq!(
        secret.as_slice(),
        hexa("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44").as_slice()
    );
}

/// **LES DEUX SECRETS ET LES SIX CLÉS DE L'ANNEXE A.1.** C'est le seul test qui
/// prouve que la chaîne entière — extraction, structure, expansion — est juste :
/// chaque morceau pris séparément pourrait l'être sans que le tout le soit.
#[test]
fn les_cles_de_l_annexe_se_retrouvent() {
    let sel = hexa("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
    let cid = hexa("8394c8f03e515708");
    let mut initial = [0_u8; 32];
    extract_sha256(&sel, &cid, &mut initial).expect("extractible");

    let cas: [(&[u8], &str, &str, &str, &str); 2] = [
        (
            b"client in",
            "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
            "1f369613dd76d5467730efcbe3b1a22d",
            "fa044b2f42a3fd3b46fb255c",
            "9f50449e04a0e810283a1e9933adedd2",
        ),
        (
            b"server in",
            "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
            "cf3a5331653c364c88f0f379b6067e37",
            "0ac1493ca1905853b0bba03e",
            "c206b8d9b9f0f37644430b490eeaa314",
        ),
    ];
    for (etiquette, secret_attendu, cle_attendue, iv_attendu, hp_attendue) in cas {
        let mut secret = [0_u8; 32];
        expand_sha256(&initial, etiquette, &mut secret).expect("dérivable");
        assert_eq!(
            secret.as_slice(),
            hexa(secret_attendu).as_slice(),
            "{}",
            std::str::from_utf8(etiquette).expect("utf8")
        );

        let mut cle = [0_u8; 16];
        expand_sha256(&secret, b"quic key", &mut cle).expect("dérivable");
        assert_eq!(cle.as_slice(), hexa(cle_attendue).as_slice());

        let mut iv = [0_u8; 12];
        expand_sha256(&secret, b"quic iv", &mut iv).expect("dérivable");
        assert_eq!(iv.as_slice(), hexa(iv_attendu).as_slice());

        let mut hp = [0_u8; 16];
        expand_sha256(&secret, b"quic hp", &mut hp).expect("dérivable");
        assert_eq!(hp.as_slice(), hexa(hp_attendue).as_slice());
    }
}

/// **LES QUATRE VALEURS DE L'ANNEXE A.5**, dérivées d'un secret applicatif — et
/// avec des clés de trente-deux octets, là où l'annexe A.1 en dérivait seize.
#[test]
fn les_cles_de_chacha_de_l_annexe_se_retrouvent() {
    let secret = hexa("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");

    let mut cle = [0_u8; 32];
    expand_sha256(&secret, b"quic key", &mut cle).expect("dérivable");
    assert_eq!(
        cle.as_slice(),
        hexa("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8").as_slice()
    );

    let mut iv = [0_u8; 12];
    expand_sha256(&secret, b"quic iv", &mut iv).expect("dérivable");
    assert_eq!(iv.as_slice(), hexa("e0459b3474bdd0e44a41c144").as_slice());

    let mut hp = [0_u8; 32];
    expand_sha256(&secret, b"quic hp", &mut hp).expect("dérivable");
    assert_eq!(
        hp.as_slice(),
        hexa("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4").as_slice()
    );

    // **LA MISE À JOUR DE CLÉ** (§6.1) : le secret suivant se dérive du
    // précédent, et l'annexe le donne aussi.
    let mut suivant = [0_u8; 32];
    expand_sha256(&secret, b"quic ku", &mut suivant).expect("dérivable");
    assert_eq!(
        suivant.as_slice(),
        hexa("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9").as_slice()
    );
}

/// SHA-384 dérive aussi, et ne donne pas la même chose que SHA-256.
///
/// **CE N'EST PAS UN DÉTAIL DE DÉRIVATION** : `TLS_AES_256_GCM_SHA384` emploie
/// SHA-384, et se tromper de hachage donne des clés valides, de la bonne taille,
/// et fausses.
#[test]
fn sha384_ne_donne_pas_la_meme_chose_que_sha256() {
    let secret = [0x42_u8; 48];
    let mut avec_384 = [0_u8; 32];
    expand_sha384(&secret, b"quic key", &mut avec_384).expect("dérivable");
    let mut avec_256 = [0_u8; 32];
    expand_sha256(&secret, b"quic key", &mut avec_256).expect("dérivable");
    assert_ne!(avec_384, avec_256, "les deux hachages se confondraient");
}

/// La place manque, et le secret n'a pas la bonne taille.
#[test]
fn les_fautes_se_disent() {
    // Une étiquette qui ne tient pas dans la structure.
    let longue = [b'a'; 64];
    let issue = hkdf_label(16, &longue, &mut [0_u8; 16]).expect_err("trop longue");
    assert_eq!(issue.reason(), Reason::BufferTooSmall);

    // Un secret plus court que le hachage.
    let issue = expand_sha256(&[0_u8; 8], b"quic key", &mut [0_u8; 16]).expect_err("trop court");
    assert_eq!(issue.reason(), Reason::BadSecretLength);
    let issue = expand_sha384(&[0_u8; 8], b"quic key", &mut [0_u8; 16]).expect_err("trop court");
    assert_eq!(issue.reason(), Reason::BadSecretLength);

    // **UNE ÉTIQUETTE DONT LA LONGUEUR NE TIENT PAS SUR UN OCTET.** §7.1 lui
    // donne un octet, et deux cent cinquante-six ne s'y écrivent pas.
    let enorme = [b'a'; 250];
    let mut assez = [0_u8; 512];
    let issue = hkdf_label(16, &enorme, &mut assez).expect_err("hors borne");
    assert_eq!(issue.reason(), Reason::BufferTooSmall);
    for expansion in [
        expand_sha256(&[0_u8; 32], &enorme, &mut [0_u8; 16]),
        expand_sha384(&[0_u8; 48], &enorme, &mut [0_u8; 16]),
    ] {
        assert_eq!(
            expansion.expect_err("hors borne").reason(),
            Reason::BufferTooSmall
        );
    }

    // **UNE SORTIE QUE DEUX OCTETS DE LONGUEUR NE SAURAIENT PAS ANNONCER.**
    let mut immense = std::vec![0_u8; 70_000];
    for expansion in [
        expand_sha256(&[0_u8; 32], b"quic key", &mut immense),
        expand_sha384(&[0_u8; 48], b"quic key", &mut immense),
    ] {
        assert_eq!(
            expansion.expect_err("hors borne").reason(),
            Reason::BufferTooSmall
        );
    }

    // `HKDF-Expand` ne rend pas plus de 255 fois la taille du hachage.
    let issue =
        expand_sha256(&[0_u8; 32], b"quic key", &mut [0_u8; 32 * 256]).expect_err("trop long");
    assert_eq!(issue.reason(), Reason::BufferTooSmall);
    let issue =
        expand_sha384(&[0_u8; 48], b"quic key", &mut [0_u8; 48 * 256]).expect_err("trop long");
    assert_eq!(issue.reason(), Reason::BufferTooSmall);

    // Un tampon d'extraction plus court que le hachage.
    let issue = extract_sha256(&[0_u8; 4], &[0_u8; 4], &mut [0_u8; 16]).expect_err("trop court");
    assert_eq!(issue.reason(), Reason::BufferTooSmall);
}
