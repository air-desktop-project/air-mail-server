// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que le jeton d'intégrité d'un `Retry` doit valoir (RFC 9001 annexe A.4).

use super::{retry_tag, verify_retry};
use crate::error::Reason;
use crate::suite::TAG_OCTETS;

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

/// Le paquet `Retry` de l'annexe A.4, jeton compris.
fn paquet_de_l_annexe() -> std::vec::Vec<u8> {
    hexa("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba")
}

/// L'identifiant de destination d'origine, celui du paquet `Initial`.
fn origine() -> std::vec::Vec<u8> {
    hexa("8394c8f03e515708")
}

/// **LE JETON DE L'ANNEXE A.4**, à l'octet près.
#[test]
fn le_jeton_de_l_annexe_se_retrouve() {
    let paquet = paquet_de_l_annexe();
    let coupure = paquet.len().saturating_sub(TAG_OCTETS);
    let corps = paquet.get(..coupure).expect("le corps");
    let mut atelier = [0_u8; 128];
    let jeton = retry_tag(&origine(), corps, &mut atelier).expect("calculable");
    assert_eq!(
        jeton.as_slice(),
        hexa("04a265ba2eff4d829058fb3f0f2496ba").as_slice()
    );
}

/// Et il se vérifie sur le paquet entier.
#[test]
fn le_paquet_de_l_annexe_se_verifie() {
    let mut atelier = [0_u8; 128];
    verify_retry(&origine(), &paquet_de_l_annexe(), &mut atelier).expect("authentique");
}

/// **CE QUI REND LA FORGE IMPOSSIBLE N'EST PAS LE SECRET DE LA CLÉ**, mais le
/// fait que le calcul inclue l'identifiant d'origine — que seul quelqu'un ayant
/// VU le paquet `Initial` connaît.
#[test]
fn un_autre_identifiant_d_origine_donne_un_autre_jeton() {
    let mut atelier = [0_u8; 128];
    let issue = verify_retry(
        &hexa("0000000000000000"),
        &paquet_de_l_annexe(),
        &mut atelier,
    )
    .expect_err("ce n'est pas le bon");
    assert_eq!(issue.reason(), Reason::NotAuthentic);

    // Un identifiant d'une autre LONGUEUR, aussi : elle entre dans le calcul.
    let issue = verify_retry(&hexa("8394c8f03e5157"), &paquet_de_l_annexe(), &mut atelier)
        .expect_err("ce n'est pas le bon");
    assert_eq!(issue.reason(), Reason::NotAuthentic);
}

/// Un paquet abîmé en chemin ne s'authentifie pas.
#[test]
fn un_paquet_abime_ne_s_authentifie_pas() {
    let mut atelier = [0_u8; 128];
    for rang in [0_usize, 5, 20, 30] {
        let mut abime = paquet_de_l_annexe();
        abime[rang] ^= 0x01;
        let issue =
            verify_retry(&origine(), &abime, &mut atelier).expect_err("abîmé au rang {rang}");
        assert_eq!(issue.reason(), Reason::NotAuthentic, "rang {rang}");
    }
    // Le jeton lui-même abîmé.
    let mut abime = paquet_de_l_annexe();
    let dernier = abime.len().saturating_sub(1);
    abime[dernier] ^= 0x01;
    assert!(verify_retry(&origine(), &abime, &mut atelier).is_err());
}

/// **UN JETON VIDE SE CALCULE AUSSI** : un `Retry` peut n'en porter aucun, et
/// c'est un `Retry` licite.
#[test]
fn un_retry_sans_jeton_se_calcule() {
    let mut atelier = [0_u8; 128];
    let corps = hexa("ff000000010008f067a5502a4262b5");
    let jeton = retry_tag(&origine(), &corps, &mut atelier).expect("calculable");
    // Et le paquet entier se vérifie.
    let mut paquet = corps.clone();
    paquet.extend_from_slice(&jeton);
    verify_retry(&origine(), &paquet, &mut atelier).expect("authentique");
}

/// **UN IDENTIFIANT D'ORIGINE VIDE EST LICITE** : un client qui n'a rien à
/// router n'en choisit pas.
#[test]
fn un_identifiant_vide_se_calcule() {
    let mut atelier = [0_u8; 128];
    let corps = hexa("ff00000001000000");
    let jeton = retry_tag(&[], &corps, &mut atelier).expect("calculable");
    let mut paquet = corps;
    paquet.extend_from_slice(&jeton);
    verify_retry(&[], &paquet, &mut atelier).expect("authentique");
    // Et l'identifiant vide n'est pas le même que l'autre.
    assert!(verify_retry(&origine(), &paquet, &mut atelier).is_err());
}

/// L'atelier ne suffit pas, et le paquet ne porte même pas un jeton.
#[test]
fn les_bornes_se_disent() {
    let paquet = paquet_de_l_annexe();
    let coupure = paquet.len().saturating_sub(TAG_OCTETS);
    let corps = paquet.get(..coupure).expect("le corps");
    let voulu = 1 + origine().len() + corps.len();
    for taille in 0..voulu {
        let mut petit = [0_u8; 128];
        let issue = retry_tag(&origine(), corps, petit.get_mut(..taille).expect("court"))
            .expect_err("pas la place");
        assert_eq!(issue.reason(), Reason::BufferTooSmall, "{taille}");
    }

    // Un identifiant de plus de deux cent cinquante-cinq octets ne s'annonce
    // pas sur un octet.
    let mut atelier = [0_u8; 1024];
    let enorme = std::vec![0_u8; 256];
    let issue = retry_tag(&enorme, corps, &mut atelier).expect_err("hors borne");
    assert_eq!(issue.reason(), Reason::BufferTooSmall);

    // **ET LA VÉRIFICATION VEUT LE MÊME ATELIER** : elle recalcule le jeton, et
    // ne peut donc pas s'en passer.
    let mut petit = [0_u8; 8];
    let issue = verify_retry(&origine(), &paquet, &mut petit).expect_err("pas la place");
    assert_eq!(issue.reason(), Reason::BufferTooSmall);

    // Un paquet plus court qu'un jeton n'en porte pas.
    for taille in 0..TAG_OCTETS {
        let court = std::vec![0_u8; taille];
        let issue = verify_retry(&origine(), &court, &mut atelier).expect_err("pas un Retry");
        assert_eq!(issue.reason(), Reason::BufferTooSmall, "{taille}");
    }
}
