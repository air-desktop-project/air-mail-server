// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La traduction des fautes du socle en fautes HTTP/2.

use super::{decode_integer, decode_string, encode_integer, encode_string};
use crate::error::{Cause, ErrorCode};

/// **LE SOCLE NE CONNAÎT PAS HTTP/2**, et c'est ce qui lui permet de servir
/// aussi à QPACK. La traduction est ici, et chaque faute garde son code.
#[test]
fn chaque_faute_du_socle_a_son_code_http2() {
    // Un entier qui déborde : la table est perdue, la connexion aussi.
    let issue = decode_integer(&[0xff, 0xff, 0xff, 0xff, 0xff, 0x7f], 8).expect_err("il déborde");
    assert_eq!(issue.cause(), Cause::BadInteger);
    assert_eq!(issue.code(), ErrorCode::CompressionError);
    assert!(issue.is_fatal(), "l'état HPACK est perdu");

    // Une chaîne qui annonce plus que le bloc ne porte.
    let issue = decode_string(&[0x7f, 0xff, 0xff, 0x03], &mut [0_u8; 64]).expect_err("elle ment");
    assert_eq!(issue.cause(), Cause::BadString);
    assert_eq!(issue.code(), ErrorCode::CompressionError);

    // **UN CODE DE HUFFMAN QU'AUCUN SYMBOLE N'EMPLOIE.** C'est la faute qui
    // traverse le plus de couches : le socle la voit, HPACK la nomme, et la
    // connexion se ferme dessus.
    let issue =
        decode_string(&[0x82, 0xff, 0xff], &mut [0_u8; 64]).expect_err("un code impossible");
    assert_eq!(issue.cause(), Cause::BadHuffman);
    assert_eq!(issue.code(), ErrorCode::CompressionError);

    // **NOTRE TAMPON, NOTRE FAUTE** : le pair n'a rien fait de mal.
    let issue = encode_integer(1_000, 5, 0, &mut []).expect_err("pas la place");
    assert_eq!(issue.cause(), Cause::BufferTooSmall);
    assert_eq!(issue.code(), ErrorCode::InternalError);
    let issue =
        encode_string(b"assez long pour ne pas tenir", &mut [0_u8; 2]).expect_err("pas la place");
    assert_eq!(issue.cause(), Cause::BufferTooSmall);
    assert_eq!(issue.code(), ErrorCode::InternalError);
}
