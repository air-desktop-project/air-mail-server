// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que le préambule a le droit d'être.

use super::{PREFACE, Preface, read_preface};
use crate::error::Cause;

/// Le préambule se reconnaît, et se reconnaît par morceaux.
#[test]
fn le_preambule_se_reconnait_par_morceaux() {
    for vus in 0..PREFACE.len() {
        assert_eq!(
            read_preface(PREFACE.get(..vus).unwrap_or_default()),
            Ok(Preface::More),
            "{vus} octets"
        );
    }
    assert_eq!(read_preface(PREFACE), Ok(Preface::Complete));
    // Ce qui suit ne le regarde pas : l'appelant consomme les vingt-quatre
    // octets et passe aux cadres.
    let mut suite = std::vec::Vec::from(&PREFACE[..]);
    suite.extend_from_slice(b"\x00\x00\x00\x04\x00\x00\x00\x00\x00");
    assert_eq!(read_preface(&suite), Ok(Preface::Complete));
}

/// **ON REFUSE DÈS LE PREMIER OCTET QUI DIFFÈRE.** Attendre les vingt-quatre
/// laisserait un pair en envoyer vingt-trois et se taire, en occupant une
/// connexion.
#[test]
fn on_refuse_des_le_premier_octet_qui_differe() {
    // Une requête HTTP/1.1 se refuse au quatrième octet : `GET ` contre `PRI `.
    let issue = read_preface(b"GET ").expect_err("refusé");
    assert_eq!(issue.cause(), Cause::BadPreface);
    assert!(issue.is_fatal(), "sans préambule, rien ne peut être lu");

    // Et un seul octet suffit quand c'est le premier qui diffère.
    assert!(read_preface(b"G").is_err());
    // Le dernier octet aussi.
    let mut presque = std::vec::Vec::from(&PREFACE[..]);
    let dernier = presque.len().saturating_sub(1);
    presque[dernier] = b'x';
    assert!(read_preface(&presque).is_err());
}

/// Un tampon vide n'est pas une faute : il n'y a rien à comparer.
#[test]
fn un_tampon_vide_attend() {
    assert_eq!(read_preface(b""), Ok(Preface::More));
    assert!(std::format!("{:?}", Preface::Complete).contains("Complete"));
}
