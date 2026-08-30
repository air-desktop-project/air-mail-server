// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! HPACK (RFC 7541) : la compression des en-têtes.
//!
//! # LE DÉCOMPRESSEUR EST LA SURFACE D'ATTAQUE LA PLUS EXPOSÉE D'HTTP/2
//!
//! Trois raisons, et chacune a produit ses failles :
//!
//! 1. **Il alloue à partir d'un nombre venu du réseau.** Un entier HPACK
//!    s'écrit sur autant d'octets qu'on veut ; une longueur de chaîne aussi. Un
//!    décodeur qui ne borne pas est un décodeur qu'on met à genoux avec une
//!    dizaine d'octets.
//! 2. **Il a un ÉTAT partagé par toute la connexion.** La table dynamique est
//!    commune à tous les flux : une erreur qu'on ne remarque pas ne corrompt pas
//!    une requête, elle corrompt toutes les suivantes. C'est pourquoi une faute
//!    de compression tue la connexion, jamais un seul flux.
//! 3. **Il décomprime.** Mille champs identiques tiennent en quelques octets sur
//!    le fil. Aucune borne PAR CHAMP n'arrête cela ; seule celle du total le
//!    fait, et elle vit dans [`ams_proto_http::HeadBuilder`].

mod decoder;
mod dynamique;
mod huffman;
mod integer;
mod string;
mod table_huffman;
mod table_statique;

pub use decoder::{Decoder, Field, Sensitivity};
pub use dynamique::{Dynamique, TABLE_SIZE_MAX};
pub use huffman::{decode_huffman, encode_huffman, encoded_huffman_len};
pub use integer::{decode_integer, encode_integer};
pub use string::{decode_string, encode_string};
pub use table_statique::{STATIQUE, STATIQUE_LEN, entree_statique};
