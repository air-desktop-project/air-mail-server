// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une délégation peut être, et ce que son magasin refuse de relire.

use super::{Delegation, Rights, decode_delegations, encode_delegations};
use crate::ams_delegations_capnp::delegations;
use crate::codec::Error;
use alloc::string::ToString as _;
use alloc::vec::Vec;

fn delegation(delegate: &str, owner: &str, rights: Rights) -> Delegation {
    Delegation {
        delegate: delegate.to_string(),
        owner: owner.to_string(),
        rights,
    }
}

/// Un magasin brut, pour fabriquer ce que l'encodeur n'écrirait pas.
fn brut(cas: &[(&str, &str, u8)]) -> Vec<u8> {
    let mut message = capnp::message::Builder::new_default();
    {
        let ecrit = message.init_root::<delegations::Builder<'_>>();
        let mut liste = ecrit.init_delegations(u32::try_from(cas.len()).unwrap_or(u32::MAX));
        for (rang, (delegate, owner, rights)) in cas.iter().enumerate() {
            let mut case = liste
                .reborrow()
                .get(u32::try_from(rang).unwrap_or(u32::MAX));
            case.set_delegate(delegate);
            case.set_owner(owner);
            case.set_rights(*rights);
        }
    }
    capnp::serialize::write_message_to_words(&message)
}

/// **ÉCRIRE ET ENVOYER IMPLIQUENT LIRE**, et les trois se reconnaissent par
/// leur nom.
#[test]
fn les_droits_s_impliquent_et_se_nomment() {
    assert!(Rights::WRITE.contains(Rights::READ));
    assert!(Rights::SEND.contains(Rights::READ));
    assert!(!Rights::READ.contains(Rights::WRITE));
    assert!(!Rights::WRITE.contains(Rights::SEND));
    let tous = Rights::WRITE.with(Rights::SEND);
    assert_eq!(tous.names(), ["read", "write", "send"]);
    assert_eq!(Rights::READ.names(), ["read"]);
    assert_eq!(tous.bits(), 7);
    for (nom, droit) in [
        ("read", Rights::READ),
        ("write", Rights::WRITE),
        ("send", Rights::SEND),
    ] {
        assert_eq!(Rights::from_name(nom), Some(droit));
    }
    assert_eq!(Rights::from_name("admin"), None);
    assert_eq!(Rights::from_name("READ"), None);
}

/// **DES BITS QUI NE SONT PAS DES DROITS NE SE LISENT PAS** : aucun droit, un
/// bit inconnu, l'écriture ou l'envoi sans la lecture.
#[test]
fn des_bits_qui_ne_sont_pas_des_droits_se_refusent() {
    for bits in [0_u8, 2, 4, 6, 8, 9, 0xFF] {
        assert_eq!(Rights::from_bits(bits), None, "{bits}");
    }
    for bits in [1_u8, 3, 5, 7] {
        assert_eq!(Rights::from_bits(bits).map(Rights::bits), Some(bits));
    }
}

#[test]
fn un_magasin_ecrit_se_relit_a_l_identique() {
    let ecrites = [
        delegation("thierry", "support", Rights::WRITE.with(Rights::SEND)),
        delegation("marie", "support", Rights::READ),
        delegation("thierry", "contact", Rights::READ),
    ];
    let octets = encode_delegations(&ecrites).expect("encodable");
    assert_eq!(decode_delegations(&octets).expect("relisible"), ecrites);
    assert!(
        decode_delegations(&encode_delegations(&[]).expect("encodable"))
            .expect("relisible")
            .is_empty()
    );
}

#[test]
fn ce_qu_une_delegation_ne_peut_pas_etre_se_refuse() {
    // Le témoin passe : chaque refus qui suit tient à sa seule faute.
    assert!(decode_delegations(&brut(&[("thierry", "support", 1)])).is_ok());
    assert_eq!(
        decode_delegations(&brut(&[("thierry", "thierry", 1)])).err(),
        Some(Error::BadDelegation("thierry → thierry".to_string()))
    );
    assert_eq!(
        decode_delegations(&brut(&[("thierry", "support", 2)])).err(),
        Some(Error::BadDelegation("thierry → support".to_string()))
    );
    assert_eq!(
        decode_delegations(&brut(&[
            ("thierry", "support", 1),
            ("thierry", "support", 3)
        ]))
        .err(),
        Some(Error::DuplicateDelegation("thierry → support".to_string()))
    );
    for (delegate, owner) in [("../etc", "support"), ("thierry", "")] {
        assert!(matches!(
            decode_delegations(&brut(&[(delegate, owner, 1)])),
            Err(Error::WeakAccount { .. })
        ));
    }
    assert!(decode_delegations(b"ceci n'est pas un magasin").is_err());
}

#[test]
fn un_texte_hors_utf8_fait_refuser() {
    let mut message = capnp::message::Builder::new_default();
    {
        let ecrit = message.init_root::<delegations::Builder<'_>>();
        let mut liste = ecrit.init_delegations(1);
        let mut case = liste.reborrow().get(0);
        case.set_delegate(capnp::text::Reader(b"thi\xffrry"));
        case.set_owner("support");
        case.set_rights(1);
    }
    let octets = capnp::serialize::write_message_to_words(&message);
    assert_eq!(decode_delegations(&octets).err(), Some(Error::NotUtf8));
    // Le titulaire aussi.
    let mut message = capnp::message::Builder::new_default();
    {
        let ecrit = message.init_root::<delegations::Builder<'_>>();
        let mut liste = ecrit.init_delegations(1);
        let mut case = liste.reborrow().get(0);
        case.set_delegate("thierry");
        case.set_owner(capnp::text::Reader(b"sup\xffport"));
        case.set_rights(1);
    }
    let octets = capnp::serialize::write_message_to_words(&message);
    assert_eq!(decode_delegations(&octets).err(), Some(Error::NotUtf8));
}

#[test]
fn les_refus_se_lisent_et_les_types_se_deboguent() {
    assert!(
        Error::BadDelegation("a → b".to_string())
            .to_string()
            .contains("a → b")
    );
    assert!(
        Error::DuplicateDelegation("a → b".to_string())
            .to_string()
            .contains("a → b")
    );
    let tenue = delegation("a", "b", Rights::READ);
    assert_eq!(tenue.clone(), tenue);
    assert!(!alloc::format!("{tenue:?}").is_empty());
}

#[test]
fn un_magasin_corrompu_ne_fait_jamais_paniquer() {
    let sain =
        encode_delegations(&[delegation("thierry", "support", Rights::WRITE)]).expect("encodable");
    let (mut refuses, mut acceptes) = (0_u32, 0_u32);
    for position in 0..sain.len() {
        for masque in [0xFF_u8, 0x01, 0x80] {
            let mut corrompu = sain.clone();
            corrompu[position] ^= masque;
            match decode_delegations(&corrompu) {
                Ok(_) => acceptes += 1,
                Err(_) => refuses += 1,
            }
        }
    }
    assert!(refuses > 0 && acceptes > 0);
}
