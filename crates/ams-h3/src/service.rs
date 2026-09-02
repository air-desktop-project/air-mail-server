// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qui sert une requête, et ce qu'il rend.
//!
//! # POURQUOI HTTP/3 NE DÉCIDE PAS LUI-MÊME
//!
//! Ce crate sait découper un flux en trames, décomprimer une section de champs
//! et réécrire une réponse. **Il ne sait pas ce qu'une requête veut dire**, et
//! n'a ni compte, ni jeton, ni magasin. C'est le même partage qu'entre
//! `ams-session::http` et `ams-loop-tokio::http`, où la boucle conduit et la
//! session décide — ici, le conducteur encadre et le service décide.
//!
//! L'étage qui assemble branche `ams-session::http` derrière cette interface,
//! exactement comme il le fait pour HTTP/2.

use ams_proto_http::{RequestHead, StatusCode};

/// Combien de champs une réponse porte au plus.
///
/// **C'EST UNE RÉPONSE DE SERVEUR DE COURRIER, PAS UNE PAGE** : un type de
/// média, une longueur, ce que toute réponse de l'API porte, et de quoi décrire
/// une portée. La borne évite d'avoir à décider quoi jeter en écrivant.
///
/// # POURQUOI HUIT, ET COMMENT LE SAVOIR
///
/// La plus chargée est un `206` refusé sur une ressource divisible, alors
/// qu'HTTP/3 est annoncé : `content-type`, `content-length`, `cache-control`,
/// `x-content-type-options`, `www-authenticate`, `alt-svc`, `accept-ranges`,
/// `content-range`. Huit exactement.
///
/// **CETTE BORNE A DÉJÀ ÉTÉ TROP PETITE**, et personne ne l'aurait vu :
/// [`Reponse::avec_champ`] perd en silence ce qui dépasse. C'est pourquoi
/// l'appelant en pose une assertion de compilation plutôt que de s'y fier.
pub const CHAMPS_MAX: usize = 8;

/// Ce qu'un service rend pour une requête.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reponse<'o> {
    /// Le code d'état.
    status: StatusCode,
    /// Les champs, dans l'ordre où ils ont été posés.
    champs: [Option<(&'o [u8], &'o [u8])>; CHAMPS_MAX],
    /// Le corps.
    corps: &'o [u8],
}

impl<'o> Reponse<'o> {
    /// Une réponse de ce code, avec ce corps et aucun champ.
    #[must_use]
    pub const fn new(status: StatusCode, corps: &'o [u8]) -> Self {
        Self {
            status,
            champs: [None; CHAMPS_MAX],
            corps,
        }
    }

    /// La même, avec ce champ de plus.
    ///
    /// **AU-DELÀ DE [`CHAMPS_MAX`], LE CHAMP EST PERDU EN SILENCE.** C'est une
    /// borne à nous, que l'appelant tient : une réponse de ce serveur n'a jamais
    /// six champs, et rendre une faute ici obligerait à traiter un cas qui
    /// n'arrive pas.
    #[must_use]
    pub fn avec_champ(mut self, nom: &'o [u8], valeur: &'o [u8]) -> Self {
        if let Some(place) = self.champs.iter_mut().find(|place| place.is_none()) {
            *place = Some((nom, valeur));
        }
        self
    }

    /// Le code d'état.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// Les champs, dans l'ordre.
    pub fn fields(&self) -> impl Iterator<Item = (&'o [u8], &'o [u8])> + '_ {
        self.champs.iter().flatten().copied()
    }

    /// Le corps.
    #[must_use]
    pub const fn body(&self) -> &'o [u8] {
        self.corps
    }
}

/// Ce qui sert les requêtes.
pub trait Service {
    /// Sert cette requête, et écrit ce qu'il faut dans `sortie`.
    ///
    /// `corps` porte ce que le client a envoyé, entier : le conducteur ne livre
    /// une requête qu'une fois sa section terminale reçue (§4.1). **Une requête
    /// tronquée n'arrive donc jamais ici**, et le service n'a pas à s'en
    /// défendre.
    fn serve<'o>(
        &mut self,
        tete: &RequestHead<'_>,
        corps: &[u8],
        sortie: &'o mut [u8],
    ) -> Reponse<'o>;
}

#[cfg(test)]
mod tests {
    use ams_proto_http::StatusCode;

    use super::{CHAMPS_MAX, Reponse};

    /// **AU-DELÀ DE SIX CHAMPS, LE SEPTIÈME EST PERDU** (C3).
    ///
    /// C'est une borne à nous, que l'appelant tient : une réponse de ce serveur
    /// n'a jamais six champs. Rendre une faute ici obligerait à traiter un cas
    /// qui n'arrive pas, et le taire est ce qui garde la réponse écrivable.
    #[test]
    fn au_dela_de_six_champs_le_septieme_est_perdu() {
        let mut reponse = Reponse::new(StatusCode::OK, b"corps");
        for _ in 0..CHAMPS_MAX {
            reponse = reponse.avec_champ(b"x-essai", b"1");
        }
        assert_eq!(reponse.fields().count(), CHAMPS_MAX);

        let pleine = reponse.avec_champ(b"x-de-trop", b"2");
        assert_eq!(pleine.fields().count(), CHAMPS_MAX, "le septième est perdu");
        assert!(
            !pleine.fields().any(|(nom, _)| nom == b"x-de-trop"),
            "et c'est bien celui-là"
        );
        assert_eq!(pleine.status(), StatusCode::OK);
        assert_eq!(pleine.body(), b"corps");
    }
}
