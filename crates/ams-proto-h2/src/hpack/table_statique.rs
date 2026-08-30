// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La table statique de RFC 7541, annexe A.
//!
//! # ELLE EST EXTRAITE DE LA RFC, COMME CELLE DE HUFFMAN
//!
//! Soixante et une entrées, et l'index de chacune est un NOMBRE QUE LE PAIR
//! ENVOIE. Se tromper d'une ligne, c'est décoder `:method` là où le client a
//! écrit `:path` — et router une requête vers autre chose que ce qu'elle
//! demandait. Ces entrées ont donc été tirées du texte, et leur nombre vérifié.
//!
//! # LES DEUX TABLES SE LISENT COMME UNE SEULE
//!
//! §2.3.3 : les index de un à soixante et un désignent la table statique, ceux
//! au-delà la table dynamique, la plus RÉCEMMENT insérée d'abord. Ce n'est pas
//! un détail d'implémentation — c'est ce qui fait qu'insérer une entrée décale
//! l'index de toutes les précédentes, et qu'un décodeur qui se désynchronise
//! d'une seule insertion lit tout le reste de travers.

/// Les soixante et une entrées, dans l'ordre de leurs index.
///
/// L'index HPACK d'une entrée est son rang PLUS UN : l'index zéro ne désigne
/// rien, et §6.1 en fait une faute.
pub const STATIQUE: [(&[u8], &[u8]); 61] = [
    (b":authority", b""),
    (b":method", b"GET"),
    (b":method", b"POST"),
    (b":path", b"/"),
    (b":path", b"/index.html"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"200"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"304"),
    (b":status", b"400"),
    (b":status", b"404"),
    (b":status", b"500"),
    (b"accept-charset", b""),
    (b"accept-encoding", b"gzip, deflate"),
    (b"accept-language", b""),
    (b"accept-ranges", b""),
    (b"accept", b""),
    (b"access-control-allow-origin", b""),
    (b"age", b""),
    (b"allow", b""),
    (b"authorization", b""),
    (b"cache-control", b""),
    (b"content-disposition", b""),
    (b"content-encoding", b""),
    (b"content-language", b""),
    (b"content-length", b""),
    (b"content-location", b""),
    (b"content-range", b""),
    (b"content-type", b""),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"expect", b""),
    (b"expires", b""),
    (b"from", b""),
    (b"host", b""),
    (b"if-match", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"if-range", b""),
    (b"if-unmodified-since", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"max-forwards", b""),
    (b"proxy-authenticate", b""),
    (b"proxy-authorization", b""),
    (b"range", b""),
    (b"referer", b""),
    (b"refresh", b""),
    (b"retry-after", b""),
    (b"server", b""),
    (b"set-cookie", b""),
    (b"strict-transport-security", b""),
    (b"transfer-encoding", b""),
    (b"user-agent", b""),
    (b"vary", b""),
    (b"via", b""),
    (b"www-authenticate", b""),
];

/// Combien d'entrées la table statique porte.
pub const STATIQUE_LEN: u32 = 61;

/// L'entrée d'un index de table statique, ou `None` hors de la table.
#[must_use]
pub fn entree_statique(index: u32) -> Option<(&'static [u8], &'static [u8])> {
    // §6.1 : L'INDEX ZÉRO NE DÉSIGNE RIEN. `checked_sub` le refuse, plutôt
    // qu'une soustraction qui ferait pointer sur la dernière entrée.
    let rang = index.checked_sub(1)? as usize;
    STATIQUE.get(rang).copied()
}

#[cfg(test)]
mod tests;
