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

//! # LES ENTIERS, HUFFMAN ET LES CHAÎNES VIVENT AILLEURS
//!
//! QPACK les réemploie à l'identique — RFC 9204 §4.1.1 renvoie à RFC 7541
//! plutôt que de les redéfinir —, et les recopier dans deux crates ferait deux
//! occasions d'écrire le même défaut. Le décodeur d'entiers en a déjà eu un ;
//! il vit maintenant dans [`ams_field_codec`], corrigé une fois pour les deux.
//!
//! Les TABLES, elles, restent ici : la statique de HPACK a soixante et une
//! entrées, celle de QPACK quatre-vingt-dix-neuf, et leurs tables dynamiques
//! n'ont ni les mêmes règles ni le même ordre.

mod decoder;
mod dynamique;
mod encoder;
mod table_statique;

pub use decoder::{Decoded, Decoder, Field, Sensitivity};
pub use dynamique::{Dynamique, TABLE_SIZE_MAX};
pub use encoder::{encode_field, encode_status};
pub use table_statique::{STATIQUE, STATIQUE_LEN, entree_statique};

/// Traduit une faute du socle en faute HTTP/2.
///
/// # POURQUOI LA TRADUCTION EST ICI, ET NON LÀ-BAS
///
/// Le socle ne connaît pas HTTP/2 : il rend ce qui a mal tourné, et rien de
/// plus. C'est ce qui lui permet de servir aussi à QPACK, qui ferme avec un
/// autre code. **Un socle qui nommerait `COMPRESSION_ERROR` obligerait QPACK à
/// le traduire, ou pire, à s'en accommoder.**
///
/// Toutes ces fautes sont FATALES : la table dynamique est partagée par toute
/// la connexion, et un décodeur qui s'est trompé une fois ne saura plus rien
/// lire.
fn traduire(faute: ams_field_codec::Error) -> crate::Error {
    use ams_field_codec::Fault;
    let (code, cause) = match faute.fault() {
        Fault::BadInteger => (ErrorCode::CompressionError, Cause::BadInteger),
        Fault::BadString => (ErrorCode::CompressionError, Cause::BadString),
        Fault::BadHuffman => (ErrorCode::CompressionError, Cause::BadHuffman),
        // **NOTRE TAMPON, NOTRE FAUTE** : le pair n'a rien fait de mal.
        Fault::BufferTooSmall => (ErrorCode::InternalError, Cause::BufferTooSmall),
    };
    crate::Error::connection(code, cause)
}

/// Lit un entier à préfixe, et traduit la faute.
///
/// # Errors
///
/// [`Cause::BadInteger`].
pub fn decode_integer(octets: &[u8], bits: u32) -> Result<(u32, usize), crate::Error> {
    ams_field_codec::decode_integer(octets, bits).map_err(traduire)
}

/// Écrit un entier à préfixe, et traduit la faute.
///
/// # Errors
///
/// [`Cause::BufferTooSmall`].
pub fn encode_integer(
    valeur: u32,
    bits: u32,
    drapeaux: u8,
    out: &mut [u8],
) -> Result<usize, crate::Error> {
    ams_field_codec::encode_integer(valeur, bits, drapeaux, out).map_err(traduire)
}

/// Lit une chaîne littérale, et traduit la faute.
///
/// # Errors
///
/// [`Cause::BadString`], [`Cause::BadHuffman`], [`Cause::BufferTooSmall`].
pub fn decode_string<'o>(
    entree: &[u8],
    out: &'o mut [u8],
) -> Result<(&'o [u8], usize), crate::Error> {
    ams_field_codec::decode_string(entree, out).map_err(traduire)
}

/// Écrit une chaîne littérale, et traduit la faute.
///
/// # Errors
///
/// [`Cause::BufferTooSmall`].
pub fn encode_string(clair: &[u8], out: &mut [u8]) -> Result<usize, crate::Error> {
    ams_field_codec::encode_string(clair, out).map_err(traduire)
}

// **HUFFMAN NE SE RÉEXPORTE PAS ICI.** HPACK ne l'emploie qu'à travers les
// chaînes, et un enrobage que personne n'appelle serait une interface qu'on
// entretient sans s'en servir. Qui veut Huffman prend `ams-field-codec`.

use crate::error::{Cause, ErrorCode};

#[cfg(test)]
mod tests;
