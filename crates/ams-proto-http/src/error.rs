// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qui rend une requête irrecevable.
//!
//! # UNE SEULE FAMILLE, ET ELLE DIT CE QUI CLOCHE
//!
//! HTTP/2 comme HTTP/3 traduisent tout cela en une seule chose sur le fil — un
//! flux remis à zéro avec `PROTOCOL_ERROR` (RFC 9113 §8.3, RFC 9114 §4.1.2) —
//! et le client n'apprend donc rien du détail. **Le détail sert au JOURNAL**, et
//! à qui lit le code : « champ mal formé » et « pseudo-en-tête après un champ
//! ordinaire » sont deux fautes différentes, et les confondre ferait chercher
//! au mauvais endroit.

use core::fmt;

/// Ce qui rend une requête irrecevable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Un nom de champ n'est pas un `token` en minuscules (RFC 9113 §8.2.1).
    MalformedFieldName,

    /// Une valeur de champ porte un octet qu'elle n'a pas le droit de porter,
    /// ou une espace en tête ou en queue.
    MalformedFieldValue,

    /// Un champ propre à la connexion — `connection`, `transfer-encoding`… —
    /// que §8.2.2 interdit.
    ConnectionSpecificField,

    /// Un pseudo-en-tête est apparu APRÈS un champ ordinaire.
    ///
    /// §8.3 : ils viennent tous en tête. L'ordre n'est pas une convention de
    /// présentation — c'est ce qui permet de décider qu'une liste est complète
    /// sans l'avoir lue en entier.
    PseudoAfterField,

    /// Un pseudo-en-tête inconnu, ou qui n'a pas sa place ici.
    UnknownPseudo,

    /// Un pseudo-en-tête est apparu deux fois.
    DuplicatePseudo,

    /// Il manque un pseudo-en-tête obligatoire.
    MissingPseudo,

    /// La méthode n'est pas une de celles que ce serveur sert.
    UnsupportedMethod,

    /// `content-length` est illisible, ou apparaît deux fois avec deux valeurs.
    MalformedContentLength,

    /// `:scheme` désigne un schéma que ce serveur ne sert pas.
    UnsupportedScheme,

    /// `:path` n'a pas une forme qu'on sache router.
    MalformedPath,

    /// `:authority` et `host` sont là tous les deux, et ne disent pas la même
    /// chose (RFC 9113 §8.3.1).
    ///
    /// **Deux autorités, c'est deux serveurs d'origine possibles** : celui que
    /// nous croyons servir et celui qu'un intermédiaire croira. C'est la
    /// contrebande, déplacée dans le nom d'hôte.
    AuthorityMismatch,

    /// La liste porte plus de champs que ce qu'on accepte de retenir.
    TooManyFields {
        /// La borne franchie.
        limit: usize,
    },

    /// Un nom, une valeur ou la liste entière dépasse ce qu'on accepte.
    FieldTooLong,

    /// Le tampon de sortie ne suffit pas.
    BufferTooSmall {
        /// Ce qu'il aurait fallu.
        needed: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MalformedFieldName => {
                f.write_str("un nom de champ n'est pas un jeton en minuscules")
            }
            Error::MalformedFieldValue => {
                f.write_str("une valeur de champ porte un octet interdit, ou une espace au bord")
            }
            Error::ConnectionSpecificField => {
                f.write_str("un champ propre à la connexion, que §8.2.2 interdit")
            }
            Error::PseudoAfterField => f.write_str("un pseudo-en-tête après un champ ordinaire"),
            Error::UnknownPseudo => f.write_str("un pseudo-en-tête inconnu"),
            Error::DuplicatePseudo => f.write_str("un pseudo-en-tête répété"),
            Error::MissingPseudo => f.write_str("un pseudo-en-tête obligatoire manque"),
            Error::UnsupportedMethod => f.write_str("cette méthode n'est pas servie"),
            Error::MalformedContentLength => f.write_str("`content-length` est illisible"),
            Error::UnsupportedScheme => f.write_str("ce schéma n'est pas servi"),
            Error::MalformedPath => f.write_str("`:path` n'a pas une forme qu'on sache router"),
            Error::AuthorityMismatch => {
                f.write_str("`:authority` et `host` ne disent pas la même chose")
            }
            Error::TooManyFields { limit } => write!(f, "plus de {limit} champs"),
            Error::FieldTooLong => f.write_str("un champ dépasse ce qu'on accepte de retenir"),
            Error::BufferTooSmall { needed } => write!(f, "il faudrait {needed} octets"),
        }
    }
}

impl core::error::Error for Error {}
