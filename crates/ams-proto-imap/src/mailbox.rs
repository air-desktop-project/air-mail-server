// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un nom de boîte a le droit d'être (RFC 9051 §5.1).
//!
//! # C'EST ICI QUE LE NOM DEVIENT DANGEREUX
//!
//! Tant qu'une seule boîte existait, un nom de boîte était comparé à une
//! constante et ne devenait jamais un morceau de chemin. `CREATE` change cela :
//! **le nom vient du client et finit dans un nom de répertoire**. C'est la
//! frontière la plus délicate du serveur, et elle se tient ici, en un seul
//! endroit, avec des règles qu'on peut lire.
//!
//! La RFC autorise beaucoup plus que ce qui suit — de l'UTF-8, des points, des
//! caractères que le système de fichiers accepte mal. **Ce serveur en accepte
//! moins, et le dit** : un nom qu'on ne saurait pas transcrire sans risque est
//! refusé, pas transformé. Transformer, c'est rendre au client un nom qui n'est
//! pas celui qu'il a demandé, et lui faire chercher longtemps.
//!
//! # Les règles, et ce que chacune ferme
//!
//! - **Non vide, et pas plus long que ce qu'on retient.** Un nom qui ne tient
//!   pas dans les tampons de la session serait tronqué, donc un autre nom.
//! - **Découpé sur `/`, sans composant vide.** `a//b` et `/a` n'ont pas de sens,
//!   et `a/` est admis mais ignoré (§6.3.4 le prévoit pour les boîtes qui ne
//!   portent que des filles).
//! - **Pas de `.` du tout.** C'est ce qui ferme `..`, donc la remontée de
//!   répertoire — et c'est aussi le séparateur que Maildir++ emploie sur le
//!   disque : un point dans un nom y fabriquerait un niveau de hiérarchie que
//!   personne n'a demandé.
//! - **Que de l'ASCII imprimable, espace compris**, sans `\`, `%`, `*`, `"`, ni
//!   `:`. Les deux premiers sont les jokers de `LIST` ; les autres cassent soit
//!   le protocole, soit le nom de fichier Maildir.
//! - **Une profondeur bornée.** Sans quoi un client choisirait la longueur des
//!   chemins que le serveur fabrique.

/// La plus grande longueur d'un nom de boîte, séparateurs compris.
pub const MAILBOX_NAME_MAX: usize = 255;

/// La plus grande longueur d'un composant.
pub const MAILBOX_COMPONENT_MAX: usize = 64;

/// Le plus grand nombre de niveaux.
pub const MAILBOX_DEPTH_MAX: usize = 8;

/// Le séparateur de hiérarchie que ce serveur annonce.
pub const MAILBOX_SEPARATOR: u8 = b'/';

/// Ce nom peut-il devenir un chemin sans danger ?
///
/// **Un `/` final est ignoré** : §6.3.4 l'admet, et il ne change pas la boîte
/// désignée.
#[must_use]
pub fn mailbox_name_is_safe(nom: &[u8]) -> bool {
    let nom = nom.strip_suffix(&[MAILBOX_SEPARATOR]).unwrap_or(nom);
    if nom.is_empty() || nom.len() > MAILBOX_NAME_MAX {
        return false;
    }
    let mut composants = 0_usize;
    for composant in nom.split(|octet| *octet == MAILBOX_SEPARATOR) {
        composants = composants.saturating_add(1);
        if composants > MAILBOX_DEPTH_MAX
            || composant.is_empty()
            || composant.len() > MAILBOX_COMPONENT_MAX
            || !composant.iter().all(|octet| octet_admis(*octet))
        {
            return false;
        }
        // Un composant fait d'espaces ne se voit pas, et deux d'entre eux ne se
        // distinguent pas.
        if composant.trim_ascii().is_empty() || composant != composant.trim_ascii() {
            return false;
        }
    }
    true
}

/// Le nom, privé de son `/` final s'il en a un.
#[must_use]
pub fn mailbox_name_trimmed(nom: &[u8]) -> &[u8] {
    nom.strip_suffix(&[MAILBOX_SEPARATOR]).unwrap_or(nom)
}

/// Cet octet a-t-il le droit de figurer dans un composant ?
fn octet_admis(octet: u8) -> bool {
    if !octet.is_ascii_graphic() && octet != b' ' {
        return false;
    }
    !matches!(octet, b'.' | b'\\' | b'%' | b'*' | b'"' | b':' | b'/')
}

#[cfg(test)]
mod tests;
