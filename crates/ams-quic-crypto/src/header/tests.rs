// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que la protection d'en-tête doit produire, d'après RFC 9001 annexe A.

use super::{longueur_du_numero, protect, unprotect};
use crate::error::Reason;
use crate::keys::Keys;
use crate::secret::{Role, Secret};
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

/// Les clés `Initial` de l'annexe A.
fn clefs(role: Role) -> Keys {
    let cid = hexa("8394c8f03e515708");
    Secret::initial(&cid, role)
        .expect("dérivable")
        .keys()
        .expect("dérivables")
}

/// **L'EN-TÊTE PROTÉGÉ DE L'ANNEXE A.2**, à l'octet près.
///
/// L'en-tête en clair est `c300000001088394c8f03e5157080000449e00000002`, le
/// numéro commence au rang 18 et fait quatre octets, et l'échantillon est celui
/// que l'annexe donne.
#[test]
fn l_entete_du_client_de_l_annexe_se_protege() {
    let clair = hexa("c300000001088394c8f03e5157080000449e00000002");
    // Le paquet entier : l'en-tête, puis le chiffré dont l'annexe donne le
    // premier bloc — c'est de lui que sort l'échantillon.
    let chiffre = hexa("d1b1c98dd7689fb8ec11d242b123dc9b");
    let mut paquet = clair.clone();
    paquet.extend_from_slice(&chiffre);

    protect(&clefs(Role::Client), &mut paquet, 18, 4).expect("protégeable");
    assert_eq!(
        paquet.get(..clair.len()).unwrap_or_default(),
        hexa("c000000001088394c8f03e5157080000449e7b9aec34").as_slice()
    );

    // Et l'on revient exactement d'où l'on vient.
    let longueur = unprotect(&clefs(Role::Client), &mut paquet, 18).expect("démasquable");
    assert_eq!(longueur, 4);
    assert_eq!(
        paquet.get(..clair.len()).unwrap_or_default(),
        clair.as_slice()
    );
}

/// **L'EN-TÊTE PROTÉGÉ DE L'ANNEXE A.3**, celui du serveur, avec un numéro de
/// DEUX octets — l'échantillon se prend quand même à quatre.
#[test]
fn l_entete_du_serveur_de_l_annexe_se_protege() {
    let clair = hexa("c1000000010008f067a5502a4262b50040750001");
    let chiffre = hexa("5a482cd0991cd25b0aac406a5816b6394100");
    let mut paquet = clair.clone();
    paquet.extend_from_slice(&chiffre);

    protect(&clefs(Role::Server), &mut paquet, 18, 2).expect("protégeable");
    assert_eq!(
        paquet.get(..clair.len()).unwrap_or_default(),
        hexa("cf000000010008f067a5502a4262b5004075c0d9").as_slice()
    );

    let longueur = unprotect(&clefs(Role::Server), &mut paquet, 18).expect("démasquable");
    assert_eq!(longueur, 2);
    assert_eq!(
        paquet.get(..clair.len()).unwrap_or_default(),
        clair.as_slice()
    );
}

/// **L'EN-TÊTE COURT DE L'ANNEXE A.5**, où CINQ bits sont masqués au lieu de
/// quatre.
#[test]
fn l_entete_court_de_l_annexe_se_protege() {
    let secret = hexa("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    let clefs = Keys::from_secret(Suite::ChaCha20Poly1305, &secret).expect("dérivables");
    // En-tête `4200bff4` : forme courte, identifiant vide, numéro sur trois
    // octets au rang 1.
    let mut paquet = hexa("4200bff4655e5cd55c41f69080575d7999c25a5bfb");
    protect(&clefs, &mut paquet, 1, 3).expect("protégeable");
    assert_eq!(
        paquet.get(..4).unwrap_or_default(),
        hexa("4cfe4189").as_slice()
    );
    assert_eq!(
        paquet.as_slice(),
        hexa("4cfe4189655e5cd55c41f69080575d7999c25a5bfb").as_slice()
    );

    let longueur = unprotect(&clefs, &mut paquet, 1).expect("démasquable");
    assert_eq!(longueur, 3);
    assert_eq!(
        paquet.get(..4).unwrap_or_default(),
        hexa("4200bff4").as_slice()
    );
}

/// **QUATRE BITS SUR UN EN-TÊTE LONG, CINQ SUR UN COURT** (§5.4.1). Se tromper
/// laisse le bit de phase de clé en clair, ce qui permet à un observateur de
/// compter les mises à jour.
#[test]
fn le_nombre_de_bits_masques_suit_la_forme() {
    let clefs = clefs(Role::Client);
    // Un en-tête long : le bit 0x10 ne doit jamais bouger.
    let mut long = std::vec![0xc3_u8];
    long.extend_from_slice(&[0_u8; 40]);
    let avant = long[0];
    protect(&clefs, &mut long, 1, 4).expect("protégeable");
    assert_eq!(
        long[0] & 0xf0,
        avant & 0xf0,
        "les quatre bits de tête ont bougé"
    );

    // Un en-tête court : le bit 0x10 PEUT bouger, et les trois de tête non.
    let mut court = std::vec![0x43_u8];
    court.extend_from_slice(&[0_u8; 40]);
    let avant = court[0];
    protect(&clefs, &mut court, 1, 4).expect("protégeable");
    assert_eq!(
        court[0] & 0xe0,
        avant & 0xe0,
        "les trois bits de tête ont bougé"
    );
}

/// **LES DEUX BITS DE BAS DISENT LA LONGUEUR**, et elle vaut toujours de un à
/// quatre : il n'y a rien à refuser ici.
#[test]
fn la_longueur_du_numero_vaut_toujours_de_un_a_quatre() {
    for bits in 0..4_u8 {
        let paquet = [0xc0 | bits];
        assert_eq!(longueur_du_numero(&paquet), usize::from(bits) + 1);
    }
    // Un paquet vide n'a pas de premier octet : on rend un, faute de mieux, et
    // c'est l'appelant qui aura déjà refusé le paquet.
    assert_eq!(longueur_du_numero(&[]), 1);
}

/// **UN ALLER-RETOUR, POUR LES QUATRE LONGUEURS ET LES DEUX FORMES.**
#[test]
fn la_protection_fait_un_aller_retour() {
    let clefs = clefs(Role::Client);
    for forme in [0xc0_u8, 0x40] {
        for longueur in 1..=4_usize {
            let mut paquet = std::vec![0_u8; 64];
            // Les deux bits de bas disent la longueur.
            paquet[0] = forme | u8::try_from(longueur - 1).expect("court");
            // Un numéro de paquet quelconque, et de quoi échantillonner.
            for (rang, place) in paquet.iter_mut().enumerate().skip(1) {
                *place = u8::try_from(rang % 251).expect("petit");
            }
            let origine = paquet.clone();
            protect(&clefs, &mut paquet, 1, longueur).expect("protégeable");
            assert_ne!(paquet, origine, "rien n'a été masqué");
            let relue = unprotect(&clefs, &mut paquet, 1).expect("démasquable");
            assert_eq!(relue, longueur, "forme {forme:#x}");
            assert_eq!(paquet, origine, "forme {forme:#x}, longueur {longueur}");
        }
    }
}

/// **UN PAQUET TROP COURT POUR UN ÉCHANTILLON SE JETTE** (§5.4.2) : il faut
/// seize octets à quatre octets du numéro, quelle que soit la longueur réelle de
/// celui-ci.
#[test]
fn un_paquet_trop_court_pour_un_echantillon_se_jette() {
    let clefs = clefs(Role::Client);
    // Le numéro commence au rang 1 : il faut donc au moins 1 + 4 + 16 = 21
    // octets.
    for taille in 0..21_usize {
        let mut paquet = std::vec![0xc3_u8; taille];
        let issue = protect(&clefs, &mut paquet, 1, 4).expect_err("trop court");
        assert_eq!(issue.reason(), Reason::TooShortToSample, "{taille}");
        let issue = unprotect(&clefs, &mut paquet, 1).expect_err("trop court");
        assert_eq!(issue.reason(), Reason::TooShortToSample, "{taille}");
    }
    // Vingt et un suffisent.
    let mut paquet = std::vec![0xc3_u8; 21];
    assert!(protect(&clefs, &mut paquet, 1, 4).is_ok());
}
