// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : Web Push** — chiffrer pour une clef de navigateur quelconque, et
//! signer des revendications quelconques.
//!
//! La clef du navigateur et son secret viennent de l'abonné ; le contact et
//! l'audience, de la configuration et de l'URL d'abonnement.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique.**
//! 2. **UN MESSAGE CHIFFRÉ A LA TAILLE ANNONCÉE** : le clair, plus l'en-tête,
//!    le délimiteur et l'étiquette — et son en-tête porte le sel et la clef
//!    éphémère.
//! 3. **UN JETON VAPID OU APNS EST DE L'ASCII IMPRIMABLE**, sans fin de
//!    ligne : il devient un champ HTTP.
//! 4. **UNE CLEF `.p8` LUE EST UN SCALAIRE** qui signe.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    clair: &'a [u8],
    navigateur: [u8; 65],
    auth: [u8; 16],
    ephemere: [u8; 32],
    sel: [u8; 16],
    audience: &'a str,
    contact: &'a str,
    expiration: u64,
    cle: [u8; 32],
}

fuzz_target!(|entree: Entree<'_>| {
    let mut out = vec![0_u8; 8192];
    if let Ok(n) = ams_push::encrypt(
        entree.clair,
        &entree.navigateur,
        &entree.auth,
        &entree.ephemere,
        &entree.sel,
        &mut out,
    ) {
        // PROPRIÉTÉ 2.
        assert_eq!(n, entree.clair.len() + ams_push::OVERHEAD_OCTETS);
        assert_eq!(&out[..16], &entree.sel);
        assert_eq!(out[20], 65);
    }
    let mut jeton = vec![0_u8; 2048];
    if let Ok(n) = ams_push::write_vapid(
        entree.audience,
        entree.expiration,
        entree.contact,
        &entree.cle,
        &mut jeton,
    ) {
        // PROPRIÉTÉ 3.
        assert!(jeton[..n].iter().all(|octet| (b' '..=b'~').contains(octet)));
        assert!(jeton[..n].starts_with(b"vapid t="));
    }
    if let Ok(n) = ams_push::write_apns_token(
        entree.audience,
        entree.contact,
        entree.expiration,
        &entree.cle,
        &mut jeton,
    ) {
        // PROPRIÉTÉ 3.
        assert!(jeton[..n].iter().all(|octet| (b' '..=b'~').contains(octet)));
        assert!(jeton[..n].starts_with(b"bearer "));
    }
    // PROPRIÉTÉ 4.
    if let Ok(cle) = ams_push::decode_p8(entree.clair) {
        assert!(ams_push::vapid_public_key(&cle).is_ok());
    }
});
