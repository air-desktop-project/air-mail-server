// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les méthodes servies (RFC 9110 §9), et celles qu'on refuse.

/// Une méthode HTTP.
///
/// # L'ÉNUMÉRATION EST FERMÉE, ET CE N'EST PAS UNE PARESSE
///
/// RFC 9110 §9.1 laisse le jeu des méthodes ouvert : n'importe quel `token` en
/// est une, et un serveur répond `501` à celles qu'il ne connaît pas. Retenir le
/// texte de la méthode pour le rendre ensuite obligerait à le borner, à le
/// valider, et à décider ce qu'on en fait — pour un mot qu'on refusera de toute
/// façon.
///
/// **Ce qui n'est pas dans cette liste reçoit `501`**, et la liste dit lesquelles
/// manquent et pourquoi.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `GET` — lire.
    Get,
    /// `HEAD` — lire les en-têtes seuls.
    ///
    /// **Ce n'est pas une commodité** : §9.3.2 exige qu'un serveur qui sert
    /// `GET` serve `HEAD`, avec les MÊMES en-têtes. Un client s'en sert pour
    /// savoir s'il doit télécharger.
    Head,
    /// `POST` — soumettre.
    Post,
    /// `PUT` — remplacer.
    Put,
    /// `DELETE` — effacer.
    Delete,
    /// `PATCH` (RFC 5789) — modifier une partie.
    Patch,
    /// `OPTIONS` — ce que la cible accepte.
    Options,
}

/// Les méthodes reconnues, avec leur nom sur le fil.
///
/// **Les noms sont sensibles à la casse** (§9.1) : `get` n'est pas `GET`, et
/// l'accepter ferait diverger ce serveur de tout intermédiaire qui, lui, ne
/// l'accepte pas.
const CONNUES: [(&[u8], Method); 7] = [
    (b"GET", Method::Get),
    (b"HEAD", Method::Head),
    (b"POST", Method::Post),
    (b"PUT", Method::Put),
    (b"DELETE", Method::Delete),
    (b"PATCH", Method::Patch),
    (b"OPTIONS", Method::Options),
];

impl Method {
    /// Lit une méthode. `None` pour ce qu'on ne sert pas.
    ///
    /// # CE QU'ON REFUSE, ET POURQUOI CHACUN
    ///
    /// - **`CONNECT`** (§9.3.6) demande un tunnel : c'est la méthode d'un
    ///   mandataire, et ce serveur n'en est pas un. Sa forme est d'ailleurs à
    ///   part — ni `:scheme` ni `:path` (RFC 9113 §8.5) —, si bien que
    ///   l'accepter ouvrirait un second jeu de règles pour une fonction qu'on ne
    ///   rend pas. Le `CONNECT` étendu de RFC 8441, qui porte WebSocket, tombe
    ///   par la même porte.
    /// - **`TRACE`** (§9.3.8) demande au serveur de renvoyer la requête telle
    ///   qu'il l'a reçue, en-têtes compris. C'est un miroir à jetons et à
    ///   cookies, et la raison pour laquelle on l'a désactivé partout depuis
    ///   vingt ans.
    #[must_use]
    pub fn parse(nom: &[u8]) -> Option<Self> {
        CONNUES
            .iter()
            .find(|(connu, _)| *connu == nom)
            .map(|(_, methode)| *methode)
    }

    /// Le nom sur le fil.
    #[must_use]
    pub fn as_bytes(self) -> &'static [u8] {
        // LA TABLE EST LA MÊME DANS LES DEUX SENS. Deux tables se
        // contrediraient un jour, et l'on écrirait alors une méthode qu'on ne
        // saurait pas relire.
        CONNUES
            .iter()
            .find(|(_, connue)| *connue == self)
            .map_or(b"GET", |(nom, _)| *nom)
    }

    /// Cette méthode peut-elle porter un corps de réponse ?
    ///
    /// §9.3.2 : la réponse à `HEAD` n'en porte jamais, quel que soit ce que
    /// `content-length` annonce. Écrire un corps là ferait lire ce corps comme
    /// la réponse suivante.
    #[must_use]
    pub fn allows_response_body(self) -> bool {
        self != Method::Head
    }
}

#[cfg(test)]
mod tests;
