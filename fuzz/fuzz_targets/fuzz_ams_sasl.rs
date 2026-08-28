// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : la réponse SASL d'un pair qui n'a encore rien prouvé.**
//!
//! Ces octets-là arrivent d'un inconnu — chiffrés, oui, mais le chiffrement
//! n'authentifie personne. C'est la dernière grammaire que le serveur lit avant
//! de savoir à qui il parle.
//!
//! # Les trois propriétés
//!
//! 1. **Rien ne panique.** Ni le décodeur base64, ni la lecture de `PLAIN`.
//! 2. **La sortie est bornée par l'entrée** (C3) : ce qui est décodé tient
//!    toujours dans ce que `decoded_len` annonce, et jamais un octet de plus.
//! 3. **Le décodage est CANONIQUE** : deux chaînes différentes ne peuvent pas
//!    décoder vers les mêmes octets. C'est cette propriété-là qui empêche un
//!    même identifiant de s'écrire de plusieurs façons, et donc de passer à côté
//!    d'un filtre ou d'un comptage qui compare les formes encodées.

#![no_main]

use libfuzzer_sys::fuzz_target;

use ams_sasl::{decode_base64, decoded_len, parse_plain};

/// L'alphabet, plus le remplissage : de quoi fabriquer des entrées que le
/// décodeur a une chance d'accepter, plutôt que des octets rejetés d'emblée.
const ALPHABET: &[u8; 65] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

fuzz_target!(|data: &[u8]| {
    // ── 1. N'IMPORTE QUELS OCTETS ───────────────────────────────────────────
    let mut brut = [0_u8; 4096];
    if let Ok(ecrits) = decode_base64(data, &mut brut) {
        assert!(
            ecrits <= decoded_len(data.len()),
            "le décodage a écrit plus que ce que `decoded_len` annonce"
        );
        assert!(ecrits <= brut.len());
        let _ = parse_plain(&brut[..ecrits]);
    }

    // ── 2. DES ENTRÉES QUI RESSEMBLENT À DU BASE64 ──────────────────────────
    //
    // Muter des octets au hasard produit surtout des refus. En les repliant sur
    // l'alphabet, le fuzzer atteint le décodage lui-même, ses remplissages et
    // ses cas limites — c'est là que sont les défauts intéressants.
    let mut plausible = [0_u8; 1024];
    let utiles = data.len().min(plausible.len());
    for (case, &octet) in plausible.iter_mut().zip(data.iter()).take(utiles) {
        *case = ALPHABET[usize::from(octet) % ALPHABET.len()];
    }
    let plausible = &plausible[..utiles];

    let mut clair = [0_u8; 1024];
    let Ok(ecrits) = decode_base64(plausible, &mut clair) else {
        return;
    };
    assert!(ecrits <= decoded_len(plausible.len()));

    // ── 3. LE DÉCODAGE EST CANONIQUE ────────────────────────────────────────
    //
    // Changer UN caractère doit changer ce qui sort — ou faire refuser. Si deux
    // écritures rendaient les mêmes octets, un identifiant aurait plusieurs
    // formes sur le fil.
    if let Some((rang, &caractere)) = plausible.iter().enumerate().next() {
        let mut variante = [0_u8; 1024];
        variante[..utiles].copy_from_slice(plausible);
        // Le caractère suivant dans l'alphabet, en bouclant.
        let position = ALPHABET
            .iter()
            .position(|&c| c == caractere)
            .unwrap_or_default();
        variante[rang] = ALPHABET[(position + 1) % ALPHABET.len()];
        let mut autre = [0_u8; 1024];
        if let Ok(autres_ecrits) = decode_base64(&variante[..utiles], &mut autre) {
            assert!(
                autres_ecrits != ecrits || autre[..autres_ecrits] != clair[..ecrits],
                "deux écritures base64 distinctes ont rendu les mêmes octets"
            );
        }
    }

    // ── 4. CE QUI SORT DU DÉCODEUR TRAVERSE `PLAIN` SANS PANIQUER ───────────
    if let Ok(identifiants) = parse_plain(&clair[..ecrits]) {
        // Le nom de compte n'est jamais vide : le format le refuse, pour que la
        // politique n'ait pas à comparer une chaîne vide à ses comptes.
        assert!(!identifiants.authentication_identity.is_empty());
        // Et les trois champs, remis bout à bout avec leurs séparateurs, font
        // exactement ce qui a été lu.
        let total = identifiants.authorization_identity.len()
            + identifiants.authentication_identity.len()
            + identifiants.password.len()
            + 2;
        assert_eq!(total, ecrits, "les trois champs ne recouvrent pas l'entrée");
    }
});
