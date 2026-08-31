// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qui peut mal tourner, et ce que le client en lira.
//!
//! # LE CODE D'ÉTAT EST UNE RÉPONSE, ET IL EN DIT PLUS QU'ON NE CROIT
//!
//! Répondre 404 à une ressource existante qu'on n'a pas le droit de voir, ou 403
//! à une ressource qui n'existe pas : le choix n'est pas cosmétique. La
//! différence entre les deux réponses **est** l'information « cette ressource
//! existe », et un client qui n'a aucun droit peut la collecter en balayant.
//!
//! Cette API répond donc 404 dans les deux cas dès que la portée manque, et
//! réserve 403 à ce qui est visible mais interdit.

use ams_proto_http::StatusCode;

/// Ce qui a mal tourné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Un chemin qu'on refuse d'interpréter (segment vide, `.`, `..`, octet de
    /// contrôle, pourcentage mal écrit, UTF-8 invalide).
    BadPath,
    /// Un chemin qui porte plus de segments qu'on n'en retient.
    PathTooLong,
    /// Aucune ressource de cette API ne porte ce chemin.
    NoSuchResource,
    /// La ressource existe, mais pas avec cette méthode (§15.5.6 de RFC 9110).
    ///
    /// **CELLE-CI SE RÉPOND AVEC UN `Allow`**, et §15.5.6 en fait une
    /// obligation : sans lui, le client sait qu'il s'est trompé mais pas de quoi.
    MethodNotAllowed,
    /// Le jeton présenté n'ouvre pas cette portée.
    Forbidden,
    /// Le jeton présenté ne se vérifie pas — sceau, structure, ou écriture.
    ///
    /// **UNE SEULE RAISON POUR TOUTES CES FAUTES** : dire laquelle apprendrait à
    /// qui forge jusqu'où il est allé.
    BadToken,
    /// Le jeton est authentique, et son heure est passée.
    ///
    /// **LE DISTINGUER N'APPREND RIEN À QUI FORGE** : on ne l'atteint qu'après
    /// un sceau valide. Et cela apprend au client honnête qu'il doit se
    /// réauthentifier plutôt que de croire son jeton refusé.
    TokenExpired,
    /// La clé de scellement n'est pas acceptable. **Notre faute** : c'est la
    /// configuration du serveur qui la fournit.
    BadKey,
    /// Le corps reçu n'est pas un JSON que ce serveur accepte.
    ///
    /// **UNE SEULE RAISON POUR TOUT** : profondeur, clé répétée, virgule finale,
    /// nombre à virgule, moitié de paire d'indirection. Dire laquelle
    /// apprendrait à qui sonde quelle règle il a touchée.
    BadJsonBody,
    /// L'écrivain JSON a reçu une suite impossible. **Notre faute.**
    BadJson,
    /// Une représentation plus profonde que ce qu'on écrit. **Notre faute.**
    JsonTooDeep,
    /// Le tampon de sortie ne suffit pas. **Notre faute, pas celle du client.**
    BufferTooSmall,
}

impl Reason {
    /// Le code d'état qui va avec.
    #[must_use]
    pub const fn status(self) -> StatusCode {
        match self {
            Self::BadPath | Self::BadJsonBody => StatusCode::BAD_REQUEST,
            // §15.5.15 : celui-ci existe exactement pour un chemin trop long, et
            // le distinguer d'un 400 dit au client que c'est la LONGUEUR qui
            // gêne — donc qu'il peut réessayer plus court.
            Self::PathTooLong => StatusCode::URI_TOO_LONG,
            // **LA MÊME RÉPONSE POUR « CELA N'EXISTE PAS » ET « VOUS N'AVEZ PAS
            // LE DROIT DE SAVOIR »** : la différence entre les deux serait
            // l'information elle-même.
            Self::NoSuchResource | Self::Forbidden => StatusCode::NOT_FOUND,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            // §11.6.1 de RFC 9110 : « the request has not been applied because
            // it lacks valid authentication credentials ». Un jeton qui ne se
            // vérifie pas et un jeton périmé sont tous deux cela.
            Self::BadToken | Self::TokenExpired => StatusCode::UNAUTHORIZED,
            Self::BadKey | Self::BadJson | Self::JsonTooDeep | Self::BufferTooSmall => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    /// Ce qu'on dit au client.
    ///
    /// # ON NE DIT JAMAIS CE QU'ON A REFUSÉ, NI POURQUOI PRÉCISÉMENT
    ///
    /// « le chemin est refusé » et non « le segment 3 contient un `..` » : la
    /// seconde formulation apprend à qui sonde exactement quelle règle il a
    /// touchée, et donc laquelle contourner. Le journal du serveur, lui, a le
    /// droit d'être précis — il ne va pas au client.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::BadPath => "le chemin est refusé",
            Self::BadJsonBody => "le corps de la requête est refusé",
            Self::PathTooLong => "le chemin est trop long",
            Self::NoSuchResource | Self::Forbidden => "aucune ressource ici",
            Self::MethodNotAllowed => "cette méthode n'est pas servie ici",
            Self::BadToken => "l'authentification n'est pas recevable",
            Self::TokenExpired => "l'authentification a expiré",
            // **CE QUI EST NÔTRE SE DIT D'UNE SEULE FAÇON.** Distinguer nos
            // fautes internes apprendrait au client ce que notre code a fait de
            // travers, et ne lui servirait à rien : il n'y peut rien. Le journal
            // du serveur, lui, garde la raison exacte.
            Self::BadKey | Self::BadJson | Self::JsonTooDeep | Self::BufferTooSmall => {
                "le serveur n'a pas pu produire la réponse"
            }
        }
    }
}

/// Une faute, avec ce que le client en lira.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    /// Ce qui a mal tourné.
    reason: Reason,
}

impl Error {
    /// La faute qui va avec cette raison.
    #[must_use]
    pub const fn new(reason: Reason) -> Self {
        Self { reason }
    }

    /// Ce qui a mal tourné.
    #[must_use]
    pub const fn reason(self) -> Reason {
        self.reason
    }

    /// Le code d'état qui va avec.
    #[must_use]
    pub const fn status(self) -> StatusCode {
        self.reason.status()
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} ({})",
            self.reason.message(),
            self.reason.status().value()
        )
    }
}

#[cfg(test)]
mod tests;
