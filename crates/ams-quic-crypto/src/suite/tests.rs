// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que chaque suite dit d'elle-même.

use super::{
    IV_OCTETS, KEY_OCTETS_MAX, MASK_OCTETS, SAMPLE_OCTETS, SECRET_OCTETS_MAX, Suite, TAG_OCTETS,
};

/// **CHAQUE SUITE DIT SA TAILLE DE CLÉ, ET AUSSI SON HACHAGE.** Se tromper de
/// hachage donne des clés valides, de la bonne taille, et fausses.
#[test]
fn chaque_suite_dit_ses_tailles() {
    let cas = [
        (Suite::Aes128Gcm, 16_usize, 32_usize),
        (Suite::Aes256Gcm, 32, 48),
        (Suite::ChaCha20Poly1305, 32, 32),
    ];
    for (suite, cle, secret) in cas {
        assert_eq!(suite.key_len(), cle, "{suite:?}");
        assert_eq!(suite.secret_len(), secret, "{suite:?}");
        // §5.4.3 et §5.4.4 : la clé de protection d'en-tête suit celle de
        // l'AEAD.
        assert_eq!(suite.header_key_len(), cle, "{suite:?}");
        // Et tout tient dans les tampons qu'on dimensionne.
        assert!(suite.key_len() <= KEY_OCTETS_MAX, "{suite:?}");
        assert!(suite.secret_len() <= SECRET_OCTETS_MAX, "{suite:?}");
    }
}

/// Les tailles fixes du protocole sont celles que §5 donne.
#[test]
fn les_tailles_fixes_sont_celles_de_la_rfc() {
    assert_eq!(IV_OCTETS, 12, "§5.3");
    assert_eq!(TAG_OCTETS, 16, "l'expansion des AEAD de TLS 1.3");
    assert_eq!(SAMPLE_OCTETS, 16, "§5.4.2");
    assert_eq!(MASK_OCTETS, 5, "§5.4.1");
}
