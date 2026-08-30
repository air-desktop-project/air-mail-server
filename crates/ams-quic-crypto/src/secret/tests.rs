// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un secret doit valoir, d'après RFC 9001 annexes A.1 et A.5.

use super::{Role, Secret};
use crate::error::Reason;
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

/// **LES DEUX SECRETS `Initial` DE L'ANNEXE A.1**, dérivés de l'identifiant que
/// le client a choisi.
#[test]
fn les_secrets_initiaux_de_l_annexe_se_retrouvent() {
    let cid = hexa("8394c8f03e515708");
    let client = Secret::initial(&cid, Role::Client).expect("dérivable");
    assert_eq!(client.suite(), Suite::Aes128Gcm);
    assert_eq!(
        client.as_bytes(),
        hexa("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea").as_slice()
    );

    let serveur = Secret::initial(&cid, Role::Server).expect("dérivable");
    assert_eq!(
        serveur.as_bytes(),
        hexa("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b").as_slice()
    );

    // Et les clés s'en dérivent.
    let clefs = client.keys().expect("dérivables");
    assert_eq!(
        clefs.key(),
        hexa("1f369613dd76d5467730efcbe3b1a22d").as_slice()
    );
}

/// **UN IDENTIFIANT VIDE DONNE UN SECRET AUSSI** : un client qui n'a rien à
/// router n'en choisit pas, et sa connexion doit quand même s'ouvrir.
#[test]
fn un_identifiant_vide_donne_un_secret() {
    let client = Secret::initial(&[], Role::Client).expect("dérivable");
    let serveur = Secret::initial(&[], Role::Server).expect("dérivable");
    assert_ne!(client.as_bytes(), serveur.as_bytes());
    assert_eq!(client.as_bytes().len(), 32);
}

/// **DEUX IDENTIFIANTS DIFFÉRENTS DONNENT DEUX SECRETS DIFFÉRENTS.** C'est tout
/// ce qui distingue les clés `Initial` de deux connexions.
#[test]
fn deux_identifiants_donnent_deux_secrets() {
    let un = Secret::initial(&hexa("8394c8f03e515708"), Role::Client).expect("dérivable");
    let deux = Secret::initial(&hexa("8394c8f03e515709"), Role::Client).expect("dérivable");
    assert_ne!(un.as_bytes(), deux.as_bytes());
}

/// **LA MISE À JOUR DE CLÉ DE L'ANNEXE A.5**, et elle ne va que dans un sens.
#[test]
fn la_mise_a_jour_de_l_annexe_se_retrouve() {
    let octets = hexa("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    let secret = Secret::new(Suite::ChaCha20Poly1305, &octets).expect("licite");
    let suivant = secret.next().expect("dérivable");
    assert_eq!(
        suivant.as_bytes(),
        hexa("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9").as_slice()
    );
    assert_eq!(suivant.suite(), Suite::ChaCha20Poly1305);

    // Le suivant du suivant n'est ni l'un ni l'autre : on ne revient pas en
    // arrière, et c'est le point — un adversaire qui obtiendrait le secret
    // courant n'apprend rien des paquets déjà passés.
    let encore = suivant.next().expect("dérivable");
    assert_ne!(encore.as_bytes(), secret.as_bytes());
    assert_ne!(encore.as_bytes(), suivant.as_bytes());
}

/// La mise à jour marche pour les trois suites, y compris celle qui emploie
/// SHA-384.
#[test]
fn la_mise_a_jour_marche_pour_les_trois_suites() {
    for suite in [Suite::Aes128Gcm, Suite::Aes256Gcm, Suite::ChaCha20Poly1305] {
        let octets = std::vec![0x33_u8; suite.secret_len()];
        let secret = Secret::new(suite, &octets).expect("licite");
        let suivant = secret.next().expect("dérivable");
        assert_eq!(suivant.as_bytes().len(), suite.secret_len(), "{suite:?}");
        assert_ne!(suivant.as_bytes(), secret.as_bytes(), "{suite:?}");
        // Et les clés du suivant ne sont pas celles du précédent.
        assert_ne!(
            suivant.keys().expect("dérivables").key(),
            secret.keys().expect("dérivables").key(),
            "{suite:?}"
        );
    }
}

/// Un secret d'une longueur que la suite n'emploie pas.
#[test]
fn un_secret_de_la_mauvaise_taille_se_refuse() {
    for suite in [Suite::Aes128Gcm, Suite::Aes256Gcm, Suite::ChaCha20Poly1305] {
        for taille in [0_usize, 16, 31, 33, 47, 49] {
            if taille == suite.secret_len() {
                continue;
            }
            let octets = std::vec![0_u8; taille];
            let issue = Secret::new(suite, &octets).expect_err("mauvaise taille");
            assert_eq!(
                issue.reason(),
                Reason::BadSecretLength,
                "{suite:?} {taille}"
            );
        }
    }
}
