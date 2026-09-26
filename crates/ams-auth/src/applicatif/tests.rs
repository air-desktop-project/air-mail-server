// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un mot de passe applicatif ouvre, et surtout ce qu'il n'ouvre pas.

use super::{
    ALEA_OCTETS, AppPassword, ID_CHIFFRES, LONGUEUR, Ouverture, PREFIXE, SECRET_CHIFFRES,
    authenticate_all, fabriquer, hexadecimal, identifiant,
};
use crate::store::{Account, hash_password};
use alloc::string::{String, ToString as _};
use alloc::vec;
use alloc::vec::Vec;
use ams_sasl::Credentials;

const ALEA: [u8; ALEA_OCTETS] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
];

/// Un compte, son mot de passe principal, et un mot de passe applicatif.
fn monde() -> (Vec<Account>, Vec<AppPassword>, String) {
    let comptes = vec![
        Account {
            login: "marie".to_string(),
            hash: hash_password(b"principal", b"seize octets ici").expect("hachable"),
            addresses: vec!["marie@example.com".to_string()],
        },
        Account {
            login: "paul".to_string(),
            hash: hash_password(b"autre", b"seize octets ici").expect("hachable"),
            addresses: Vec::new(),
        },
    ];
    let (id, mot, condensat) = fabriquer(&ALEA);
    let applicatifs = vec![AppPassword {
        login: "marie".to_string(),
        id,
        name: "Thunderbird".to_string(),
        created: 1_790_000_000,
        last_used: 0,
        digest: condensat,
    }];
    (comptes, applicatifs, mot)
}

fn identifiants<'a>(qui: &'a str, secret: &'a str) -> Credentials<'a> {
    Credentials {
        authorization_identity: b"",
        authentication_identity: qui.as_bytes(),
        password: secret.as_bytes(),
    }
}

#[test]
fn un_mot_de_passe_fabrique_a_la_forme_annoncee() {
    let (id, mot, condensat) = fabriquer(&ALEA);
    assert_eq!(id, "0123456789abcdef");
    assert_eq!(
        mot,
        "amsp-0123456789abcdef-fedcba98765432100011223344556677"
    );
    assert_eq!(mot.len(), LONGUEUR);
    assert!(mot.starts_with(PREFIXE));
    assert_eq!(condensat, ams_sasl::sha256(mot.as_bytes()));
    assert_eq!(identifiant(mot.as_bytes()), Some(id.as_str()));
    const { assert!(ID_CHIFFRES + SECRET_CHIFFRES == ALEA_OCTETS * 2) };
    assert_eq!(hexadecimal(&[0x00, 0x9f, 0xff]), "009fff");
}

/// **SEULE LA FORME EXACTE EST UN MOT DE PASSE APPLICATIF** : tout le reste
/// prend le chemin du mot de passe principal.
#[test]
fn seule_la_forme_exacte_est_reconnue() {
    let (_, mot, _) = fabriquer(&ALEA);
    let juste = mot.as_bytes();
    assert!(identifiant(juste).is_some());
    // Trop court, trop long.
    assert_eq!(identifiant(&juste[..LONGUEUR - 1]), None);
    let mut long = juste.to_vec();
    long.push(b'0');
    assert_eq!(identifiant(&long), None);
    // Un autre préfixe.
    let mut autre = juste.to_vec();
    autre[0] = b'x';
    assert_eq!(identifiant(&autre), None);
    // Pas de tiret à sa place.
    let mut sans_tiret = juste.to_vec();
    sans_tiret[PREFIXE.len() + ID_CHIFFRES] = b'_';
    assert_eq!(identifiant(&sans_tiret), None);
    // Une majuscule — dans l'identifiant, puis dans le secret : deux écritures
    // d'un même secret donneraient deux condensats.
    for rang in [PREFIXE.len(), LONGUEUR - 1] {
        let mut majuscule = juste.to_vec();
        majuscule[rang] = b'A';
        assert_eq!(identifiant(&majuscule), None, "rang {rang}");
    }
    // Un caractère qui n'est pas hexadécimal.
    let mut pas_hexa = juste.to_vec();
    pas_hexa[LONGUEUR - 1] = b'g';
    assert_eq!(identifiant(&pas_hexa), None);
}

#[test]
fn un_mot_de_passe_applicatif_ouvre_son_compte_et_se_nomme() {
    let (comptes, applicatifs, mot) = monde();
    assert_eq!(
        authenticate_all(&comptes, &applicatifs, &identifiants("marie", &mot)),
        Ouverture::Applicatif("0123456789abcdef".to_string())
    );
    // Par une adresse du compte aussi, comme le mot de passe principal.
    assert_eq!(
        authenticate_all(
            &comptes,
            &applicatifs,
            &identifiants("MARIE@example.com", &mot)
        ),
        Ouverture::Applicatif("0123456789abcdef".to_string())
    );
}

#[test]
fn le_mot_de_passe_principal_ouvre_toujours() {
    let (comptes, applicatifs, _) = monde();
    assert_eq!(
        authenticate_all(&comptes, &applicatifs, &identifiants("marie", "principal")),
        Ouverture::Principal
    );
    assert_eq!(
        authenticate_all(&comptes, &applicatifs, &identifiants("marie", "faux")),
        Ouverture::Refusee
    );
}

/// **LE MOT DE PASSE APPLICATIF D'UN AUTRE N'OUVRE PAS** : l'entrée est
/// cherchée sous le compte qui se présente, pas sous l'identifiant seul.
#[test]
fn le_mot_de_passe_applicatif_d_un_autre_n_ouvre_pas() {
    let (comptes, applicatifs, mot) = monde();
    assert_eq!(
        authenticate_all(&comptes, &applicatifs, &identifiants("paul", &mot)),
        Ouverture::Refusee
    );
}

#[test]
fn un_secret_faux_un_compte_inconnu_ou_une_entree_revoquee_n_ouvrent_pas() {
    let (comptes, applicatifs, mot) = monde();
    // Le même identifiant, un autre secret.
    let mut faux = mot.clone().into_bytes();
    faux[LONGUEUR - 1] = if faux[LONGUEUR - 1] == b'0' {
        b'1'
    } else {
        b'0'
    };
    let faux = String::from_utf8(faux).expect("ascii");
    assert_eq!(
        authenticate_all(&comptes, &applicatifs, &identifiants("marie", &faux)),
        Ouverture::Refusee
    );
    // Un compte qui n'existe pas.
    assert_eq!(
        authenticate_all(&comptes, &applicatifs, &identifiants("fantome", &mot)),
        Ouverture::Refusee
    );
    // Révoqué : l'entrée n'est plus là.
    assert_eq!(
        authenticate_all(&comptes, &[], &identifiants("marie", &mot)),
        Ouverture::Refusee
    );
}

/// **UN MOT DE PASSE APPLICATIF N'EST JAMAIS ESSAYÉ COMME PRINCIPAL** : même
/// si le compte avait choisi exactement cette chaîne comme mot de passe
/// principal, elle ne l'ouvrirait pas par ce chemin-là.
#[test]
fn la_forme_applicative_ne_prend_jamais_le_chemin_principal() {
    let (_, mot, _) = fabriquer(&ALEA);
    let comptes = vec![Account {
        login: "marie".to_string(),
        hash: hash_password(mot.as_bytes(), b"seize octets ici").expect("hachable"),
        addresses: Vec::new(),
    }];
    assert_eq!(
        authenticate_all(&comptes, &[], &identifiants("marie", &mot)),
        Ouverture::Refusee
    );
}

#[test]
fn ce_serveur_ne_delegue_pas_davantage_par_ce_chemin() {
    let (comptes, applicatifs, mot) = monde();
    let pour_un_autre = Credentials {
        authorization_identity: b"paul",
        authentication_identity: b"marie",
        password: mot.as_bytes(),
    };
    assert_eq!(
        authenticate_all(&comptes, &applicatifs, &pour_un_autre),
        Ouverture::Refusee
    );
    // Se nommer soi-même comme identité d'autorisation est licite.
    let soi = Credentials {
        authorization_identity: b"marie",
        ..pour_un_autre
    };
    assert_eq!(
        authenticate_all(&comptes, &applicatifs, &soi),
        Ouverture::Applicatif("0123456789abcdef".to_string())
    );
}

#[test]
fn les_types_se_comparent_se_clonent_et_se_deboguent() {
    let (_, applicatifs, _) = monde();
    let entree = applicatifs.first().expect("une entrée").clone();
    assert_eq!(entree.clone(), entree);
    assert!(!alloc::format!("{entree:?}").is_empty());
    let ouverture = Ouverture::Applicatif(entree.id);
    assert_eq!(ouverture.clone(), ouverture);
    assert!(!alloc::format!("{ouverture:?}").is_empty());
    assert_ne!(Ouverture::Principal, Ouverture::Refusee);
}
