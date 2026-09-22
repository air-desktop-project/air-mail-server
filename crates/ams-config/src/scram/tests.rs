// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce banc éprouve l'aller-retour et **chacun des refus du chargement**.
//!
//! Un magasin qu'on ne relit pas ne prouve rien ; un refus qu'aucun essai ne
//! déclenche n'est pas un refus, c'est une affirmation.

use super::{decode_scram, encode_scram};
use crate::codec::Error;
use alloc::string::{String, ToString as _};
use alloc::vec;
use alloc::vec::Vec;
use ams_auth::{NONCE_OCTETS, SEL_OCTETS, ScramVerifier};

/// Un vérificateur plausible — le contenu scellé n'a pas à être vrai : ce
/// module ne l'ouvre pas, et ne le peut pas.
fn verificateur(login: &str) -> ScramVerifier {
    ScramVerifier {
        login: String::from(login),
        sel: [1; SEL_OCTETS],
        iterations: 32_768,
        nonce: [2; NONCE_OCTETS],
        scelle: vec![3; 80],
    }
}

#[test]
fn l_aller_retour_rend_ce_qu_on_a_ecrit() {
    let ecrits = vec![verificateur("jean"), verificateur("contact")];
    let octets = encode_scram(&ecrits).expect("encodage");
    assert_eq!(decode_scram(&octets).expect("décodage"), ecrits);
}

#[test]
fn un_magasin_vide_se_lit_sans_broncher() {
    // Un serveur qui vient d'ouvrir SCRAM n'a encore aucun vérificateur, et
    // cela ne doit pas ressembler à une erreur.
    let octets = encode_scram(&[]).expect("encodage");
    assert_eq!(decode_scram(&octets).expect("décodage"), Vec::new());
}

#[test]
fn un_login_refuse_par_check_login_est_refuse_ici_aussi() {
    // Le même contrôle que pour `comptes.bin`, et pour la même raison : ce nom
    // désigne un RÉPERTOIRE.
    for mauvais in ["", "../ailleurs", ".cache", "a/b"] {
        let octets = encode_scram(&[verificateur(mauvais)]).expect("encodage");
        assert!(
            matches!(decode_scram(&octets), Err(Error::WeakAccount { .. })),
            "« {mauvais} » aurait dû être refusé"
        );
    }
}

#[test]
fn un_login_en_double_est_refuse() {
    let octets = encode_scram(&[verificateur("jean"), verificateur("jean")]).expect("encodage");
    assert_eq!(
        decode_scram(&octets),
        Err(Error::DuplicateLogin("jean".to_string()))
    );
    // Et la comparaison ignore la casse : `Jean` et `jean` sont le même compte
    // pour qui cherche un vérificateur, et deux entrées seraient une question
    // sans réponse.
    let octets = encode_scram(&[verificateur("jean"), verificateur("Jean")]).expect("encodage");
    assert!(matches!(
        decode_scram(&octets),
        Err(Error::DuplicateLogin(_))
    ));
}

#[test]
fn un_sel_ou_un_nonce_de_mauvaise_taille_est_refuse() {
    // **UN NONCE TRONQUÉ N'EST PAS UNE MALADRESSE** : `ChaCha20-Poly1305` en
    // veut douze, et onze ferait échouer une ouverture de session sans dire
    // pourquoi. On le refuse au chargement, là où l'exploitant regarde.
    // Le type Rust impose les deux tailles : on écrit donc le message à la main.
    for (champ, longueur) in [
        ("nonce", NONCE_OCTETS.saturating_sub(1)),
        ("nonce", NONCE_OCTETS.saturating_add(1)),
        ("salt", SEL_OCTETS.saturating_sub(1)),
        ("salt", 0),
    ] {
        let abime = message_avec_champ_court(champ, longueur);
        assert_eq!(
            decode_scram(&abime),
            Err(Error::Empty(champ)),
            "{champ} de {longueur} octets aurait dû être refusé"
        );
    }
}

#[test]
fn un_compte_d_iterations_sous_le_minimum_est_refuse() {
    // Le nombre est lu DANS le fichier, jamais pris du code : sans ce contrôle,
    // un vérificateur posé à mille tours serait vérifié à mille tours, et le
    // magasin paraîtrait sain.
    let mut faible = verificateur("jean");
    faible.iterations = ams_sasl::ITERATIONS_MIN.saturating_sub(1);
    let octets = encode_scram(&[faible]).expect("encodage");
    assert_eq!(decode_scram(&octets), Err(Error::Empty("iterations")));
}

#[test]
fn un_scelle_vide_est_refuse() {
    let mut vide = verificateur("jean");
    vide.scelle = Vec::new();
    let octets = encode_scram(&[vide]).expect("encodage");
    assert_eq!(decode_scram(&octets), Err(Error::Empty("sealed")));
}

#[test]
fn des_octets_qui_ne_sont_pas_un_message_sont_refuses() {
    assert!(decode_scram(b"ceci n'est pas du capnp").is_err());
    assert!(decode_scram(&[]).is_err());
}

#[test]
fn un_fichier_corrompu_ne_fait_jamais_paniquer_le_serveur() {
    // **LE MÊME BALAYAGE QUE POUR `comptes.bin`** : chaque octet, trois
    // masques. Ce qu'il éprouve n'est pas qu'une corruption soit détectée — un
    // format binaire en laisse toujours passer — mais que **rien ne panique**,
    // et que chaque `?` des accesseurs capnp soit un chemin PRIS plutôt qu'une
    // promesse. Un magasin de comptes se lit au démarrage : une panique y
    // serait un serveur qui ne démarre pas, sans dire pourquoi.
    let sain = encode_scram(&[verificateur("jean")]).expect("encodable");
    let mut refuses = 0_u32;
    let mut acceptes = 0_u32;
    for position in 0..sain.len() {
        for masque in [0xFF_u8, 0x01, 0x80] {
            let mut corrompu = sain.clone();
            if let Some(octet) = corrompu.get_mut(position) {
                *octet ^= masque;
            }
            match decode_scram(&corrompu) {
                Ok(_) => acceptes = acceptes.saturating_add(1),
                Err(_) => refuses = refuses.saturating_add(1),
            }
        }
    }
    assert!(refuses > 0, "aucune corruption n'a été détectée");
    assert!(
        acceptes > 0,
        "toutes les corruptions ont été refusées : le balayage ne traverse pas le chemin nominal"
    );
}

/// Un message où le sel OU le nonce a une longueur choisie.
///
/// **ON N'ALTÈRE PAS LES OCTETS D'UN MESSAGE ENCODÉ**, et c'est délibéré :
/// capnp range la longueur d'un `Data` dans le mot de pointeur qui le précède.
/// Changer les octets sans changer ce mot ne produirait pas un champ court,
/// seulement un message illisible — qui échouerait pour une autre raison que
/// celle qu'on cherche à éprouver, en donnant l'illusion du contraire. On écrit
/// donc le message directement avec la mauvaise longueur.
fn message_avec_champ_court(champ: &'static str, longueur: usize) -> Vec<u8> {
    use crate::ams_scram_capnp::scram_store;
    let mut message = capnp::message::Builder::new_default();
    {
        let ecrit = message.init_root::<scram_store::Builder<'_>>();
        let mut liste = ecrit.init_verifiers(1);
        let mut case = liste.reborrow().get(0);
        case.set_login("jean");
        let court = vec![9_u8; longueur];
        if champ == "salt" {
            case.set_salt(&court);
            case.set_nonce(&[2; NONCE_OCTETS]);
        } else {
            case.set_salt(&[1; SEL_OCTETS]);
            case.set_nonce(&court);
        }
        case.set_iterations(32_768);
        case.set_sealed(&[3; 80]);
    }
    capnp::serialize::write_message_to_words(&message)
}
