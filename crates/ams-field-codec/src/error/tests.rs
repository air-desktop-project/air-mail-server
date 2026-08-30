// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une faute dit d'elle-même.

use super::{Error, Fault};

/// Chaque faute se retient, et se dit en français.
#[test]
fn chaque_faute_se_retient_et_se_dit() {
    let cas = [
        (Fault::BadInteger, "entier"),
        (Fault::BadString, "chaîne"),
        (Fault::BadHuffman, "Huffman"),
        (Fault::BufferTooSmall, "tampon"),
    ];
    for (faute, morceau) in cas {
        let erreur = Error::new(faute);
        assert_eq!(erreur.fault(), faute);
        let dit = std::format!("{erreur}");
        assert!(dit.contains(morceau), "{faute:?} dit « {dit} »");
    }
}
