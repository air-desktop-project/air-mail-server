// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : défaire ce que MIME a encodé** (RFC 2047, RFC 2045 §6).
//!
//! # `decoded_max` DOIT MAJORER, SANS LIRE L'ENTRÉE
//!
//! C'est la propriété qui compte. L'appelant réserve `decoded_max(n)` octets
//! AVANT de décoder : si le décodage pouvait rendre davantage, il découvrirait le
//! manque à l'écriture — ou, dans un code moins prudent, l'écrirait quand même.
//! Le décodage GRANDIT — quatre caractères de base64 rendent trois octets
//! `iso-8859-1`, qui font six octets d'UTF-8 —, et c'est justement pourquoi la
//! borne se vérifie plutôt qu'elle ne se suppose.
//!
//! # Les autres propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **UN ENCODAGE INCONNU EST L'IDENTITÉ** : `7bit`, `8bit`, `binary` et tout
//!    ce qu'on ne connaît pas rendent le corps tel quel. Un décodeur qui
//!    « améliorerait » au passage rendrait autre chose que le message.
//! 3. **UN TAMPON TROP COURT LE DIT** au lieu d'écrire à moitié.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_mime::{Error, decode_encoded_words, decode_transfer, decoded_max};

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// Une valeur d'en-tête, telle qu'elle arriverait d'un message.
    valeur: &'a [u8],
    /// Le nom d'un encodage de transfert.
    encodage: &'a [u8],
    /// Un corps à décoder.
    corps: &'a [u8],
    /// La place qu'on laisse, pour éprouver le manque.
    place: u16,
}

fuzz_target!(|entree: Entree<'_>| {
    // ── Les mots encodés ───────────────────────────────────────────────────
    let mut assez = vec![0_u8; decoded_max(entree.valeur.len()).max(1)];
    let ecrits = decode_encoded_words(entree.valeur, &mut assez).expect("la borne majore");
    assert!(
        ecrits <= decoded_max(entree.valeur.len()),
        "le décodage dépasse sa borne"
    );

    let court = usize::from(entree.place).min(ecrits);
    let mut petit = vec![0_u8; court];
    match decode_encoded_words(entree.valeur, &mut petit) {
        Ok(refait) => {
            assert_eq!(refait, ecrits, "deux décodages de la même valeur diffèrent");
            assert_eq!(petit.get(..refait), assez.get(..ecrits));
        }
        Err(erreur) => assert_eq!(erreur, Error::BufferTooSmall),
    }

    // ── Les encodages de transfert ─────────────────────────────────────────
    let mut sortie = vec![0_u8; decoded_max(entree.corps.len()).max(1)];
    let rendus =
        decode_transfer(entree.encodage, entree.corps, &mut sortie).expect("la borne majore");
    assert!(rendus <= decoded_max(entree.corps.len()));

    // PROPRIÉTÉ 2 : ce qu'on ne connaît pas ne se touche pas.
    let connu = entree.encodage.eq_ignore_ascii_case(b"base64")
        || entree.encodage.eq_ignore_ascii_case(b"quoted-printable");
    if !connu {
        assert_eq!(
            sortie.get(..rendus),
            Some(entree.corps),
            "un encodage inconnu a changé le corps"
        );
    }
});
