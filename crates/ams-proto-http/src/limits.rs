// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les bornes qu'une requête ne doit pas franchir.

/// Ce qu'une requête n'a pas le droit de dépasser.
///
/// # LA RFC NE BORNE RIEN, ET C'EST LE SUJET
///
/// RFC 9110 §2.3 se contente de dire qu'un serveur « devrait » être robuste
/// face à des champs démesurés. HTTP/2 offre bien `SETTINGS_MAX_HEADER_LIST_SIZE`
/// — mais c'est un RENSEIGNEMENT donné au pair, pas une garde : rien n'oblige un
/// client à le respecter, et un serveur qui n'aurait que ce réglage pour se
/// protéger n'aurait rien du tout.
///
/// Ces bornes-là sont donc DÉCIDÉES ici, et vérifiées à la lecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Longueur maximale d'un nom de champ.
    ///
    /// Les noms sont un vocabulaire, pas de la donnée : les plus longs des
    /// registres IANA tiennent en une soixantaine d'octets.
    pub max_field_name: usize,

    /// Longueur maximale d'une valeur de champ.
    ///
    /// Un jeton d'autorisation, un `cookie`, un `user-agent` bavard : quatre
    /// kibioctets couvrent largement, et au-delà c'est de la donnée qui a pris
    /// le chemin d'un en-tête.
    pub max_field_value: usize,

    /// Nombre maximal de champs ordinaires, pseudo-en-têtes non compris.
    pub max_fields: usize,

    /// Taille maximale de la liste ENTIÈRE, décomprimée.
    ///
    /// # POURQUOI CELLE-CI EN PLUS DES AUTRES
    ///
    /// HPACK et QPACK compriment : mille champs identiques tiennent en quelques
    /// octets sur le fil et en plusieurs mébioctets une fois décomprimés. C'est
    /// la « bombe de décompression », et aucune borne par champ ne l'arrête —
    /// seule la borne du TOTAL le fait. §10.5 de RFC 9113 la nomme.
    ///
    /// Le compte suit RFC 9113 §6.5.2 : nom, valeur, plus trente-deux octets par
    /// champ. Ces trente-deux-là ne sont pas sur le fil ; ils représentent ce
    /// qu'une entrée coûte à retenir, et les omettre ferait passer pour gratuits
    /// dix mille champs vides.
    pub max_header_list: usize,

    /// Longueur maximale d'un `:path`.
    pub max_path: usize,

    /// Longueur maximale d'une `:authority`.
    pub max_authority: usize,
}

impl Limits {
    /// Les bornes du produit.
    pub const DEFAULT: Self = Self {
        max_field_name: 64,
        max_field_value: 4 * 1024,
        max_fields: 64,
        max_header_list: 16 * 1024,
        max_path: 2048,
        max_authority: 256,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}
