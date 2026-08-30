// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : les primitives HPACK** — l'entier à préfixe, le codage de Huffman,
//! la chaîne littérale.
//!
//! # Pourquoi celle-ci
//!
//! C'est le décodeur le plus exposé d'HTTP/2 : il lit des longueurs venues du
//! réseau, il a un état partagé par toute la connexion, et il décomprime. Un
//! entier qui déborde en silence — ce qui est ARRIVÉ ici, à l'écriture — fait
//! lire une longueur pour une autre, donc une chaîne pour une autre, donc un
//! en-tête que personne n'a envoyé.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **UN ENTIER ACCEPTÉ SE RÉÉCRIT ET SE RELIT À L'IDENTIQUE**, et n'a
//!    consommé que ce qu'on lui a donné. C'est la propriété qui aurait attrapé
//!    le débordement silencieux : la valeur relue n'aurait pas été celle qu'on
//!    croyait avoir lue.
//! 3. **CE QU'ON ÉCRIT SE RELIT** : entier, chaîne comprimée, chaîne en clair.
//! 4. **UNE CHAÎNE DÉCODÉE NE DÉBORDE PAS DE CE QU'ON A DONNÉ** : ni de
//!    l'entrée, ni du tampon de sortie.
//! 5. **LE DÉCODAGE DE HUFFMAN EST DÉTERMINISTE** : deux lectures des mêmes
//!    octets rendent les mêmes octets.
//! 6. **CE QUE HUFFMAN REND SE RECOMPRIME EN LUI-MÊME.** L'encodage est
//!    canonique : il n'y a qu'une façon d'écrire une chaîne, et c'est ce qui
//!    interdit d'en écrire deux qu'un pair lirait différemment.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_proto_h2::hpack::{
    decode_huffman, decode_integer, decode_string, encode_huffman, encode_integer, encode_string,
    encoded_huffman_len,
};

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// Des octets à lire comme un entier à préfixe.
    entier: &'a [u8],
    /// La largeur du préfixe, ramenée entre un et huit.
    bits: u8,
    /// Des octets à lire comme une chaîne littérale.
    chaine: &'a [u8],
    /// Des octets à lire comme un corps comprimé.
    comprime: &'a [u8],
    /// Des octets à comprimer.
    clair: &'a [u8],
}

fuzz_target!(|entree: Entree<'_>| {
    let bits = u32::from(entree.bits % 8 + 1);

    // ── L'entier ────────────────────────────────────────────────────────────
    if let Ok((valeur, lus)) = decode_integer(entree.entier, bits) {
        // PROPRIÉTÉ 2 : on n'a pas consommé plus qu'on n'a reçu.
        assert!(
            lus <= entree.entier.len(),
            "un entier a mangé trop d'octets"
        );
        assert!(lus >= 1, "un entier accepté sans octet");

        // Et il se réécrit à l'identique. C'est ici que le débordement
        // silencieux se serait vu : la valeur relue n'aurait pas été celle-ci.
        let mut ecrit = [0_u8; 8];
        if let Ok(ecrits) = encode_integer(valeur, bits, 0, &mut ecrit) {
            assert_eq!(
                decode_integer(ecrit.get(..ecrits).unwrap_or_default(), bits),
                Ok((valeur, ecrits)),
                "un entier réécrit ne se relit pas pareil"
            );
        }
    }

    // ── La chaîne littérale ─────────────────────────────────────────────────
    let mut sortie = vec![0_u8; 64 * 1024];
    if let Ok((texte, lus)) = decode_string(entree.chaine, &mut sortie) {
        // PROPRIÉTÉ 4.
        assert!(
            lus <= entree.chaine.len(),
            "une chaîne a mangé trop d'octets"
        );
        let taille = texte.len();
        assert!(taille <= 64 * 1024, "une chaîne déborde du tampon");

        // PROPRIÉTÉ 3 : ce qu'on a lu se réécrit et se relit.
        let mut ecrit = vec![0_u8; taille.saturating_mul(2).saturating_add(16)];
        let clair = texte.to_vec();
        if let Ok(ecrits) = encode_string(&clair, &mut ecrit) {
            let mut relu = vec![0_u8; taille.saturating_add(16)];
            let (retour, consommes) =
                decode_string(ecrit.get(..ecrits).unwrap_or_default(), &mut relu)
                    .expect("ce qu'on écrit se relit");
            assert_eq!(retour, clair.as_slice(), "une chaîne réécrite a changé");
            assert_eq!(consommes, ecrits, "on relit exactement ce qu'on a écrit");
        }
    }

    // ── Huffman seul ────────────────────────────────────────────────────────
    let mut premier = vec![0_u8; 64 * 1024];
    if let Ok(ecrits) = decode_huffman(entree.comprime, &mut premier) {
        // PROPRIÉTÉ 5 : deux lectures, le même résultat.
        let mut second = vec![0_u8; 64 * 1024];
        assert_eq!(
            decode_huffman(entree.comprime, &mut second),
            Ok(ecrits),
            "deux lectures ne s'accordent pas"
        );
        assert_eq!(
            premier.get(..ecrits),
            second.get(..ecrits),
            "deux lectures ne rendent pas les mêmes octets"
        );

        // PROPRIÉTÉ 6 : ce qui sort se recomprime en ce qui est entré.
        // L'encodage est CANONIQUE : il n'y a qu'une façon de l'écrire.
        let decode = premier.get(..ecrits).unwrap_or_default().to_vec();
        let attendu = encoded_huffman_len(&decode);
        let mut recomprime = vec![0_u8; attendu.saturating_add(8)];
        let refait = encode_huffman(&decode, &mut recomprime).expect("recomprimable");
        assert_eq!(
            refait, attendu,
            "la longueur annoncée n'est pas celle écrite"
        );
        assert_eq!(
            recomprime.get(..refait),
            Some(entree.comprime),
            "une chaîne acceptée n'est pas celle qu'on aurait écrite"
        );
    }

    // ── La compression, dans l'autre sens ───────────────────────────────────
    let attendu = encoded_huffman_len(entree.clair);
    let mut serre = vec![0_u8; attendu.saturating_add(8)];
    let ecrits = encode_huffman(entree.clair, &mut serre).expect("comprimable");
    assert_eq!(
        ecrits, attendu,
        "la longueur annoncée n'est pas celle écrite"
    );
    let mut retour = vec![0_u8; entree.clair.len().saturating_add(8)];
    let relus = decode_huffman(serre.get(..ecrits).unwrap_or_default(), &mut retour)
        .expect("ce qu'on comprime se décomprime");
    assert_eq!(
        retour.get(..relus),
        Some(entree.clair),
        "un aller-retour de compression a changé les octets"
    );
});
