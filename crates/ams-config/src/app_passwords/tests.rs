// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que le magasin des mots de passe applicatifs accepte, et ce qu'il refuse
//! au chargement.

use super::{APP_NOM_OCTETS_MAX, decode_app_passwords, encode_app_passwords};
use crate::ams_app_passwords_capnp::app_passwords;
use crate::codec::Error;
use alloc::string::{String, ToString as _};
use alloc::vec::Vec;
use ams_auth::AppPassword;

fn entree(login: &str, id: &str) -> AppPassword {
    AppPassword {
        login: login.to_string(),
        id: id.to_string(),
        name: "Thunderbird du bureau".to_string(),
        created: 1_790_000_000,
        last_used: 1_790_003_600,
        digest: [7; 32],
    }
}

/// Écrit un magasin **brut**, sans passer par l'encodeur — le seul moyen de
/// fabriquer ce qu'il refuserait d'écrire.
fn brut(cas: &[(&str, &str, &str, &[u8])]) -> Vec<u8> {
    let mut message = capnp::message::Builder::new_default();
    {
        let ecrit = message.init_root::<app_passwords::Builder<'_>>();
        let mut liste = ecrit.init_app_passwords(u32::try_from(cas.len()).unwrap_or(u32::MAX));
        for (rang, (login, id, nom, condensat)) in cas.iter().enumerate() {
            let mut case = liste
                .reborrow()
                .get(u32::try_from(rang).unwrap_or(u32::MAX));
            case.set_login(login);
            case.set_id(id);
            case.set_name(nom);
            case.set_digest(condensat);
        }
    }
    capnp::serialize::write_message_to_words(&message)
}

const ID: &str = "0123456789abcdef";

#[test]
fn un_magasin_ecrit_se_relit_a_l_identique() {
    let ecrites = [entree("jean", ID), entree("marie", "fedcba9876543210")];
    let octets = encode_app_passwords(&ecrites).expect("encodable");
    assert_eq!(decode_app_passwords(&octets).expect("relisible"), ecrites);
}

#[test]
fn un_magasin_vide_se_relit() {
    let octets = encode_app_passwords(&[]).expect("encodable");
    assert!(decode_app_passwords(&octets).expect("relisible").is_empty());
}

#[test]
fn un_identifiant_en_double_est_refuse() {
    let octets = brut(&[
        ("jean", ID, "un", &[1; 32]),
        ("marie", ID, "deux", &[2; 32]),
    ]);
    assert_eq!(
        decode_app_passwords(&octets).err(),
        Some(Error::DuplicateAppPassword(ID.to_string()))
    );
}

/// **UN IDENTIFIANT QUI N'A PAS SA FORME N'OUVRIRAIT JAMAIS** : il est refusé
/// au chargement, et non découvert au premier client qui échoue.
#[test]
fn un_identifiant_de_mauvaise_forme_est_refuse() {
    for mauvais in [
        "",
        "0123456789abcde",
        "0123456789abcdef0",
        "0123456789ABCDEF",
        "0123456789abcdeg",
    ] {
        let octets = brut(&[("jean", mauvais, "nom", &[1; 32])]);
        assert_eq!(
            decode_app_passwords(&octets).err(),
            Some(Error::BadAppPassword(mauvais.to_string())),
            "`{mauvais}`"
        );
    }
}

#[test]
fn un_condensat_de_mauvaise_taille_est_refuse() {
    for taille in [0_usize, 31, 33] {
        let condensat = alloc::vec![1_u8; taille];
        let octets = brut(&[("jean", ID, "nom", &condensat)]);
        assert_eq!(
            decode_app_passwords(&octets).err(),
            Some(Error::BadAppPassword(ID.to_string())),
            "{taille} octets"
        );
    }
}

#[test]
fn le_nom_est_borne_et_ne_peut_pas_etre_vide() {
    let octets = brut(&[("jean", ID, "", &[1; 32])]);
    assert_eq!(
        decode_app_passwords(&octets).err(),
        Some(Error::Empty("app password name"))
    );
    let juste = "n".repeat(APP_NOM_OCTETS_MAX);
    assert!(decode_app_passwords(&brut(&[("jean", ID, &juste, &[1; 32])])).is_ok());
    let trop = "n".repeat(APP_NOM_OCTETS_MAX + 1);
    assert_eq!(
        decode_app_passwords(&brut(&[("jean", ID, &trop, &[1; 32])])).err(),
        Some(Error::TooLong("app password name"))
    );
}

#[test]
fn un_compte_irrecevable_est_refuse() {
    let octets = brut(&[("../etc", ID, "nom", &[1; 32])]);
    assert!(matches!(
        decode_app_passwords(&octets),
        Err(Error::WeakAccount { .. })
    ));
}

#[test]
fn des_octets_quelconques_sont_refuses() {
    assert!(decode_app_passwords(b"ceci n'est pas un message Cap'n Proto").is_err());
    assert!(decode_app_passwords(&[]).is_err());
}

#[test]
fn un_texte_hors_utf8_fait_refuser() {
    let mut message = capnp::message::Builder::new_default();
    {
        let ecrit = message.init_root::<app_passwords::Builder<'_>>();
        let mut liste = ecrit.init_app_passwords(1);
        let mut case = liste.reborrow().get(0);
        case.set_login(capnp::text::Reader(b"je\xffan"));
        case.set_id(ID);
        case.set_name("nom");
        case.set_digest(&[1; 32]);
    }
    let octets = capnp::serialize::write_message_to_words(&message);
    assert_eq!(decode_app_passwords(&octets).err(), Some(Error::NotUtf8));
}

#[test]
fn les_refus_se_lisent() {
    let double = Error::DuplicateAppPassword(ID.to_string()).to_string();
    assert!(double.contains(ID), "{double}");
    let forme = Error::BadAppPassword(String::from("zz")).to_string();
    assert!(forme.contains("zz"), "{forme}");
}

/// **LES DEUX COMPTES IMPORTENT**, comme pour les appareils : zéro refus dirait
/// que la corruption passe inaperçue, zéro acceptation que le balayage
/// n'atteint pas le chemin nominal.
#[test]
fn un_fichier_corrompu_ne_fait_jamais_paniquer_le_serveur() {
    let sain = encode_app_passwords(&[entree("jean", ID)]).expect("encodable");
    let mut refuses = 0_u32;
    let mut acceptes = 0_u32;
    for position in 0..sain.len() {
        for masque in [0xFF_u8, 0x01, 0x80] {
            let mut corrompu = sain.clone();
            corrompu[position] ^= masque;
            match decode_app_passwords(&corrompu) {
                Ok(_) => acceptes = acceptes.saturating_add(1),
                Err(_) => refuses = refuses.saturating_add(1),
            }
        }
    }
    assert!(refuses > 0, "aucune corruption n'a été détectée");
    assert!(
        acceptes > 0,
        "le balayage ne traverse pas le chemin nominal"
    );
}
