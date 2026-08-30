// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un champ a le droit d'être sur le fil binaire.
//!
//! # C'EST ICI QUE LA CONTREBANDE S'ARRÊTE
//!
//! Un serveur HTTP reçoit ses champs d'un décompresseur — HPACK ou QPACK — qui,
//! lui, ne juge rien : il rend les octets qu'on lui a donnés à comprimer. Si l'un
//! d'eux porte un `\r\n`, et qu'un intermédiaire réécrit la requête en HTTP/1.1,
//! ce `\r\n` devient une COUPURE DE LIGNE, et la moitié de la valeur devient une
//! requête que personne n'a envoyée. RFC 9113 §8.2.1 l'interdit donc à la
//! source, et c'est cette interdiction-là qu'on applique.
//!
//! C'est le même raisonnement, mot pour mot, que celui qui a fermé la
//! contrebande SMTP dans ce dépôt : **un octet de structure ne se transporte pas
//! dans de la donnée**.

/// Ce qu'un octet a le droit d'être dans un nom de champ.
///
/// C'est le `token` de RFC 9110 §5.6.2, **privé des majuscules** : RFC 9113
/// §8.2.1 exige que les noms soient en minuscules sur le fil.
///
/// # POURQUOI ON NE NORMALISE PAS
///
/// Ramener `Content-Length` à `content-length` serait accueillant, et ce serait
/// une faute : deux écritures du même nom passeraient alors, là où un
/// intermédiaire n'en accepte qu'une. Deux analyseurs qui ne s'accordent pas sur
/// ce qui est un champ, c'est exactement la faille qu'on ferme. **Un nom en
/// majuscules est donc MAL FORMÉ**, pas corrigé.
const fn octet_de_nom_est_valide(octet: u8) -> bool {
    octet.is_ascii_lowercase()
        || octet.is_ascii_digit()
        || matches!(
            octet,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Ce nom de champ est-il recevable ?
///
/// Non vide, en minuscules, et sans octet qui ne soit pas un `tchar`. Un nom qui
/// commence par `:` est un pseudo-en-tête : il ne passe pas par ici, et
/// [`field_kind`] est là pour les distinguer.
#[must_use]
pub fn field_name_is_valid(nom: &[u8]) -> bool {
    !nom.is_empty() && nom.iter().copied().all(octet_de_nom_est_valide)
}

/// Cette valeur de champ est-elle recevable ?
///
/// # TROIS OCTETS INTERDITS, ET DEUX BORDS
///
/// `NUL`, `CR` et `LF` sont exclus (RFC 9113 §8.2.1) : ce sont les octets qui
/// fabriquent une ligne là où il n'y en avait pas. Une valeur ne peut pas non
/// plus commencer ni finir par une espace ou une tabulation — le repliement
/// d'en-tête d'HTTP/1.1 (`obs-fold`) s'écrivait ainsi, et un intermédiaire qui
/// réécrirait la requête le reconstituerait.
///
/// Le reste passe, `obs-text` compris (0x80–0xFF) : §5.5 l'admet, et le refuser
/// casserait des valeurs légitimes que d'autres serveurs acceptent.
#[must_use]
pub fn field_value_is_valid(valeur: &[u8]) -> bool {
    if valeur
        .iter()
        .any(|octet| matches!(*octet, 0x00 | b'\r' | b'\n'))
    {
        return false;
    }
    // LES DEUX BORDS, ET LE CAS VIDE QUI PASSE. Une valeur vide est licite
    // (§5.5) ; `first`/`last` rendent alors `None`, et `is_some_and` est faux.
    let au_bord = |octet: Option<&u8>| octet.is_some_and(|o| matches!(*o, b' ' | b'\t'));
    !au_bord(valeur.first()) && !au_bord(valeur.last())
}

/// Les champs que RFC 9113 §8.2.2 interdit, et le cas particulier de `te`.
///
/// **CE NE SONT PAS DES CHAMPS ORDINAIRES QU'ON N'AIME PAS** : ils décrivent la
/// connexion d'HTTP/1.1, qui n'existe plus ici. `transfer-encoding` en
/// particulier est la moitié de la contradiction dont vit la contrebande de
/// requête ; le laisser passer, c'est la rouvrir pour l'intermédiaire suivant.
const PROPRES_A_LA_CONNEXION: [&[u8]; 5] = [
    b"connection",
    b"proxy-connection",
    b"keep-alive",
    b"transfer-encoding",
    b"upgrade",
];

/// Ce nom désigne-t-il un champ propre à la connexion ?
#[must_use]
pub fn is_connection_specific(nom: &[u8]) -> bool {
    PROPRES_A_LA_CONNEXION.contains(&nom)
}

/// Ce qu'un nom de champ décodé se trouve être.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    /// Un pseudo-en-tête : le nom commence par `:`.
    Pseudo,
    /// Un champ ordinaire, recevable.
    Ordinary,
    /// Rien de recevable.
    Invalid,
}

/// Classe un nom de champ décodé.
///
/// # LE `:` EST LE SEUL SÉPARATEUR DES DEUX MONDES
///
/// §8.3 : les pseudo-en-têtes commencent par `:`, les champs ordinaires jamais.
/// Un nom comme `:chose` est donc un pseudo-en-tête — inconnu, mais un
/// pseudo-en-tête —, et le traiter comme un champ ordinaire mal formé ferait
/// rendre la mauvaise faute.
#[must_use]
pub fn field_kind(nom: &[u8]) -> FieldKind {
    match nom.split_first() {
        Some((b':', reste)) if field_name_is_valid(reste) => FieldKind::Pseudo,
        Some(_) if field_name_is_valid(nom) => FieldKind::Ordinary,
        _ => FieldKind::Invalid,
    }
}

/// Ce champ peut-il figurer dans une réponse qu'on ÉCRIT ?
///
/// # CE QU'ON REFUSE DE RECEVOIR, ON REFUSE DE L'ÉCRIRE
///
/// §8.2.2 de RFC 9113 interdit les champs propres à la connexion, et §8.3
/// réserve le `:` aux pseudo-en-têtes — que la couche de transport écrit
/// elle-même. Un serveur qui vérifie ces règles à la RÉCEPTION mais pas à
/// l'ÉMISSION laisse l'intermédiaire suivant recevoir ce qu'il vient de
/// refuser, et la contrebande repart de là.
///
/// # ELLE VIT ICI, ET NON DANS HTTP/2 NI DANS HTTP/3
///
/// RFC 9114 §4.2 reprend la règle mot pour mot pour HTTP/3. L'écrire dans les
/// deux crates ferait deux vérités pour une règle — et le jour où l'une
/// changerait, l'autre laisserait passer ce que la première refuse.
#[must_use]
pub fn response_field_is_serviceable(nom: &[u8], valeur: &[u8]) -> bool {
    field_kind(nom) == FieldKind::Ordinary
        && !is_connection_specific(nom)
        && field_value_is_valid(valeur)
}

#[cfg(test)]
mod tests;
