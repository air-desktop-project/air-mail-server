// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les documents d'erreur (RFC 9457).
//!
//! # UNE SEULE FORME POUR TOUTES LES FAUTES
//!
//! Un client qui doit deviner la forme d'une erreur selon le point d'entrée
//! finit par ne plus les lire du tout. RFC 9457 en fixe une : un `type`, un
//! `title`, un `status`. Toutes les fautes de cette API passent par ici, sans
//! exception — et c'est ce qui rend vraie la phrase « le client peut brancher
//! sur le type ».
//!
//! # LE TYPE VIENT DU CODE D'ÉTAT, ET NON DE LA RAISON
//!
//! C'est la décision qui compte ici. `NoSuchResource` et `Forbidden` répondent
//! toutes deux 404, précisément pour que « cette ressource existe » ne se lise
//! pas dans la réponse. Si le `type` venait de la raison, il rendrait
//! immédiatement la distinction qu'on venait d'effacer — et le document
//! d'erreur défferait le travail du code d'état.
//!
//! En le dérivant du code, l'indiscernabilité devient **structurelle** : deux
//! raisons qui partagent un code partagent nécessairement un type. Il n'y a plus
//! de règle à maintenir, seulement une fonction.

use ams_proto_http::StatusCode;

use crate::error::{Error, Reason};
use crate::json::Json;

/// Le type de média d'une représentation ordinaire.
pub const JSON_MEDIA_TYPE: &str = "application/json";

/// Le type de média d'un document d'erreur (§3 de RFC 9457).
///
/// **CE N'EST PAS `application/json`**, et la différence sert : un
/// intermédiaire ou un client peut reconnaître une erreur sans lire le corps.
pub const PROBLEM_MEDIA_TYPE: &str = "application/problem+json";

/// Écrit le document d'erreur qui va avec cette faute.
///
/// # Errors
///
/// [`Reason::BufferTooSmall`] si `sortie` ne suffit pas.
pub fn problem(reason: Reason, sortie: &mut [u8]) -> Result<&[u8], Error> {
    let status = reason.status();
    let mut json = Json::new(sortie);
    json.begin_object()?;
    json.field_str("type", type_de(status))?;
    // §3.1.2 : « a short, human-readable summary of the problem type ». Le nôtre
    // ne nomme jamais la règle qu'on a touchée — voir [`Reason::message`].
    json.field_str("title", reason.message())?;
    json.field_u64("status", u64::from(status.value()))?;
    json.end_object()?;
    json.finish()
}

/// Le type de problème que désigne ce code d'état.
///
/// **CE SONT DES RÉFÉRENCES RELATIVES**, et §4.2.1 de RFC 9457 les autorise :
/// « If the type URI is a relative reference, it MUST be resolved against the
/// document's base URI ». Les écrire absolues obligerait ce serveur à connaître
/// le nom sous lequel on l'atteint — qu'un mandataire peut changer sans le lui
/// dire.
fn type_de(status: StatusCode) -> &'static str {
    match status.value() {
        400 => "/problems/bad-request",
        401 => "/problems/unauthorized",
        404 => "/problems/not-found",
        405 => "/problems/method-not-allowed",
        414 => "/problems/uri-too-long",
        // Tout ce qui est nôtre se dit d'une seule façon : le client n'a rien à
        // en tirer, et le détailler dirait ce que notre code a fait de travers.
        _ => "/problems/internal",
    }
}

#[cfg(test)]
mod tests;
