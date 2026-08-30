// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le socle commun de HPACK (RFC 7541) et de QPACK (RFC 9204),
//! **sans entrée-sortie** (C1, C3).
//!
//! # POURQUOI CE CRATE EXISTE
//!
//! QPACK réemploie **la table de Huffman de RFC 7541 Appendice B** et **les
//! entiers à préfixe de son §5.1**, à l'identique. RFC 9204 §4.1.1 se contente
//! de renvoyer à RFC 7541 plutôt que de les redéfinir.
//!
//! Les recopier dans deux crates ferait deux vérités pour une table de deux cent
//! cinquante-sept entrées — et surtout, **deux occasions d'écrire le même
//! défaut**. Le décodeur d'entiers de ce dépôt en a déjà eu un : `checked_shl`
//! ne dit rien du débordement de VALEUR, et faisait lire
//! `ff ff ff ff ff 7f` comme la valeur 255. Il a été trouvé, corrigé, et écrit
//! une fois. Le réimplémenter pour QPACK serait offrir l'occasion de le
//! réécrire.
//!
//! # CE QU'IL NE SAIT PAS
//!
//! Il ne connaît ni HTTP/2 ni HTTP/3, et ne nomme donc aucun code de fil : HPACK
//! ferme avec `COMPRESSION_ERROR`, QPACK avec `QPACK_DECOMPRESSION_FAILED`. La
//! traduction est le travail de celui qui a une connexion à fermer.
//!
//! Il ne connaît pas non plus les TABLES : la statique de HPACK a soixante et
//! une entrées, celle de QPACK quatre-vingt-dix-neuf, et leurs tables dynamiques
//! n'ont ni les mêmes règles ni le même ordre. Seul ce qui est vraiment commun
//! vit ici.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

// LES TESTS, EUX, ONT LE DROIT D'ALLOUER.
#[cfg(test)]
extern crate std;

mod error;
mod huffman;
mod integer;
mod string;
mod table_huffman;

pub use error::{Error, Fault};
pub use huffman::{decode_huffman, encode_huffman, encoded_huffman_len};
pub use integer::{decode_integer, encode_integer};
pub use string::{decode_string, encode_string};
pub use table_huffman::{CODE_EOS, CODE_MIN_BITS, code_d_octet, symbole_de};
