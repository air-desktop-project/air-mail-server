// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La table de routage : ce que cette API met à disposition.
//!
//! # UNE RESSOURCE, PUIS UNE MÉTHODE — ET NON L'INVERSE
//!
//! Le chemin dit CE QU'ON DÉSIGNE ; la méthode dit CE QU'ON EN FAIT. Les
//! confondre en une seule table donnerait autant d'entrées que de couples, et
//! rendrait impossible la distinction que §15.5.6 de RFC 9110 exige : un 404
//! quand la ressource n'existe pas, un 405 avec un `Allow` quand elle existe
//! mais pas avec cette méthode.
//!
//! Cette distinction n'est pas de la politesse. Un client qui reçoit 404 sur un
//! `PATCH` ne sait pas s'il s'est trompé de chemin ou de verbe, et réessaiera
//! les deux — ce qui double le trafic pour rien.
//!
//! # CHAQUE RESSOURCE PORTE SA PORTÉE, DANS LE MÊME `match`
//!
//! [`Resource::scope`] est un `match` exhaustif sur le même type que la table.
//! Ajouter une ressource sans lui donner de portée **ne compile pas**.
//!
//! C'est l'inverse d'une liste de contrôle tenue à part, qui se désynchronise au
//! premier ajout — et dont le premier symptôme est une ressource servie sans
//! droit.
//!
//! # LA VERSION EST DANS LE CHEMIN, ET ELLE EST OBLIGATOIRE
//!
//! `/v1/…`. Sans elle, la première rupture de compatibilité n'aurait nulle part
//! où se dire, et se dirait donc en silence — chez le client, à l'exécution.

use ams_proto_http::Method;

use crate::error::{Error, Reason};
use crate::path::{Segments, decode};
use crate::scope::{Area, Rights, Scope};

/// La version d'API que porte le chemin.
pub const VERSION: &str = "v1";

/// Ce qu'un chemin désigne.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource<'o> {
    /// `/v1/tokens` — l'échange d'identifiants contre un jeton.
    ///
    /// **LA SEULE RESSOURCE QUI N'EXIGE AUCUNE PORTÉE**, puisque c'est celle où
    /// l'on n'en a pas encore.
    Tokens,
    /// `/v1/tokens/current` — le jeton qu'on présente, pour le révoquer.
    CurrentToken,

    /// `/v1/mailboxes` — les boîtes du compte.
    Mailboxes,
    /// `/v1/mailboxes/{boite}` — une boîte, et son état.
    Mailbox {
        /// Le nom de la boîte.
        boite: &'o str,
    },
    /// `/v1/mailboxes/{boite}/messages` — les messages qu'elle porte.
    Messages {
        /// Le nom de la boîte.
        boite: &'o str,
    },
    /// `/v1/mailboxes/{boite}/messages/{uid}` — un message, enveloppe et
    /// structure.
    Message {
        /// Le nom de la boîte.
        boite: &'o str,
        /// L'identifiant unique du message dans cette boîte.
        uid: u64,
    },
    /// `/v1/mailboxes/{boite}/messages/{uid}/raw` — le message tel qu'il est
    /// arrivé.
    ///
    /// **UNE RESSOURCE À PART, ET NON UNE NÉGOCIATION DE CONTENU** : le message
    /// brut et son enveloppe décodée ne sont pas deux représentations d'une même
    /// chose — l'un est ce qui a été reçu, l'autre notre lecture. Les confondre
    /// ferait dépendre d'un en-tête `Accept` la question « qu'est-ce que le
    /// serveur a vraiment reçu ? », qui doit avoir une réponse stable.
    MessageRaw {
        /// Le nom de la boîte.
        boite: &'o str,
        /// L'identifiant unique.
        uid: u64,
    },
    /// `/v1/mailboxes/{boite}/messages/{uid}/parts/{partie}` — une partie MIME.
    MessagePart {
        /// Le nom de la boîte.
        boite: &'o str,
        /// L'identifiant unique.
        uid: u64,
        /// Le chemin de la partie, tel que §6.4.5 de RFC 9051 le numérote.
        partie: &'o str,
    },
    /// `/v1/mailboxes/{boite}/search` — une recherche dans une boîte.
    Search {
        /// Le nom de la boîte.
        boite: &'o str,
    },

    /// `/v1/accounts` — les comptes.
    Accounts,
    /// `/v1/accounts/{compte}` — un compte.
    Account {
        /// Le nom du compte.
        compte: &'o str,
    },
    /// `/v1/accounts/{compte}/password` — son secret.
    ///
    /// **UNE RESSOURCE À PART, QUI NE SE LIT PAS.** La séparer du compte est ce
    /// qui permet à `GET /v1/accounts/{compte}` d'exister sans jamais rendre une
    /// empreinte : il n'y a pas de représentation du compte qui la contienne.
    AccountPassword {
        /// Le nom du compte.
        compte: &'o str,
    },
    /// `/v1/accounts/{compte}/addresses` — les adresses qu'il déclare.
    AccountAddresses {
        /// Le nom du compte.
        compte: &'o str,
    },
    /// `/v1/domains` — les domaines qu'on héberge.
    Domains,
    /// `/v1/bans` — les sources bannies (C8).
    Bans,
    /// `/v1/bans/{source}` — un bannissement, pour le lever.
    Ban {
        /// La source, telle qu'`ams-guard` la nomme.
        source: &'o str,
    },

    /// `/v1/submissions` — déposer un message.
    Submissions,

    /// `/v1/health` — le serveur répond-il ?
    Health,
    /// `/v1/metrics` — les compteurs.
    Metrics,
}

impl Resource<'_> {
    /// La portée qu'il faut pour l'atteindre avec cette méthode.
    ///
    /// `None` pour ce qui ne demande aucune portée — c'est-à-dire l'échange de
    /// jeton, et lui seul.
    ///
    /// # LA MÉTHODE DÉCIDE DU DROIT, LA RESSOURCE DU DOMAINE
    ///
    /// C'est ce qui évite d'écrire quatre-vingts lignes de table : le domaine ne
    /// dépend que du chemin, et le droit ne dépend que du verbe. Une ressource
    /// qui aurait besoin d'échapper à cette règle serait le signe qu'elle en
    /// mélange deux.
    #[must_use]
    pub const fn scope(self, method: Method) -> Option<Scope> {
        let domaine = match self {
            // **CELLE-CI N'EXIGE RIEN** : c'est là qu'on obtient de quoi exiger.
            Self::Tokens => return None,
            // Révoquer son propre jeton ne demande que de l'avoir.
            Self::CurrentToken => return Some(Scope::none()),
            Self::Mailboxes
            | Self::Mailbox { .. }
            | Self::Messages { .. }
            | Self::Message { .. }
            | Self::MessageRaw { .. }
            | Self::MessagePart { .. }
            | Self::Search { .. } => Area::Mail,
            Self::Accounts
            | Self::Account { .. }
            | Self::AccountPassword { .. }
            | Self::AccountAddresses { .. }
            | Self::Domains
            | Self::Bans
            | Self::Ban { .. } => Area::Admin,
            Self::Submissions => Area::Submit,
            Self::Health | Self::Metrics => Area::Observe,
        };
        Some(Scope::one(domaine, droit(method)))
    }

    /// Les méthodes que cette ressource sert.
    ///
    /// **C'EST CE QU'ON ÉCRIT DANS `Allow`**, et §15.5.6 de RFC 9110 en fait une
    /// obligation sur un 405 : sans lui, le client sait qu'il s'est trompé mais
    /// pas de quoi.
    #[must_use]
    pub const fn allowed(self) -> &'static [Method] {
        match self {
            Self::Tokens | Self::Submissions => &[Method::Post],
            Self::CurrentToken => &[Method::Delete],
            // La recherche est un `POST` : ses critères ne tiennent pas dans une
            // chaîne de requête sans ambiguïté, et les y mettre les ferait
            // journaliser par tout intermédiaire.
            Self::Search { .. } => &[Method::Post],
            Self::Mailboxes | Self::Domains | Self::Bans | Self::Health | Self::Metrics => {
                &[Method::Get, Method::Head]
            }
            Self::Mailbox { .. } => &[Method::Get, Method::Head, Method::Put, Method::Delete],
            Self::Messages { .. } => &[Method::Get, Method::Head, Method::Post],
            Self::Message { .. } => &[Method::Get, Method::Head, Method::Patch, Method::Delete],
            Self::MessageRaw { .. } | Self::MessagePart { .. } => &[Method::Get, Method::Head],
            Self::Accounts => &[Method::Get, Method::Head, Method::Post],
            Self::Account { .. } => &[Method::Get, Method::Head, Method::Put, Method::Delete],
            // **CELLE-CI NE SE LIT PAS** : il n'existe aucune méthode qui rende
            // une empreinte, et c'est la raison d'être de cette ressource.
            Self::AccountPassword { .. } => &[Method::Put],
            Self::AccountAddresses { .. } => &[Method::Get, Method::Head, Method::Put],
            Self::Ban { .. } => &[Method::Delete],
        }
    }

    /// Cette ressource sert-elle cette méthode ?
    #[must_use]
    pub fn serves(self, method: Method) -> bool {
        // `OPTIONS` s'applique à toute ressource qui existe (§9.3.7) : c'est le
        // moyen normalisé de demander ce que `allowed` rend.
        matches!(method, Method::Options) || self.allowed().contains(&method)
    }
}

/// Le droit qu'une méthode demande.
///
/// **`HEAD` DEMANDE LE MÊME DROIT QUE `GET`** (§9.3.2) : il rend les mêmes
/// en-têtes, et le laisser passer plus facilement rendrait lisible par sa
/// longueur ce qu'on refusait de rendre.
const fn droit(method: Method) -> Rights {
    match method {
        Method::Get | Method::Head | Method::Options => Rights::Read,
        Method::Post | Method::Put | Method::Delete | Method::Patch => Rights::Write,
    }
}

/// Une requête résolue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolved<'o> {
    /// Ce qu'elle désigne.
    pub resource: Resource<'o>,
    /// Ce qu'elle en fait.
    pub method: Method,
    /// Ce qu'il faut pour y avoir droit, ou `None` si rien n'est exigé.
    pub scope: Option<Scope>,
}

/// Résout une requête.
///
/// `chemin` est la partie du chemin, sans la chaîne de requête — voir
/// [`split_query`]. `sortie` reçoit les segments décodés, et les emprunts du
/// résultat y pointent.
///
/// [`split_query`]: crate::split_query
///
/// # Errors
///
/// [`Reason::BadPath`] et [`Reason::PathTooLong`] pour ce que le chemin ne peut
/// pas être ; [`Reason::NoSuchResource`] pour un chemin bien formé qui ne
/// désigne rien ; [`Reason::MethodNotAllowed`] pour une ressource qui existe
/// mais pas avec ce verbe.
pub fn resolve<'o>(
    method: Method,
    chemin: &[u8],
    sortie: &'o mut [u8],
) -> Result<Resolved<'o>, Error> {
    let segments = decode(chemin, sortie)?;
    // **LA VERSION D'ABORD** : sans elle, la première rupture de compatibilité
    // n'aurait nulle part où se dire.
    if segments.get(0) != VERSION {
        return Err(Error::new(Reason::NoSuchResource));
    }
    let resource = designer(&segments)?;
    if !resource.serves(method) {
        return Err(Error::new(Reason::MethodNotAllowed));
    }
    Ok(Resolved {
        resource,
        method,
        scope: resource.scope(method),
    })
}

/// Ce que ces segments désignent, la version déjà vérifiée.
///
/// **AUCUNE GARDE SUR L'ABSENCE D'UN SEGMENT** : [`Segments::get`] rend la
/// chaîne vide hors des bornes, et aucun segment valide n'est vide. La longueur
/// suffit donc à discriminer, et une garde de plus serait une branche qu'aucun
/// chemin ne peut emprunter.
fn designer<'o>(segments: &Segments<'o>) -> Result<Resource<'o>, Error> {
    let manque = Error::new(Reason::NoSuchResource);
    match (segments.get(1), segments.len()) {
        ("tokens", 2) => Ok(Resource::Tokens),
        ("tokens", 3) if segments.get(2) == "current" => Ok(Resource::CurrentToken),
        ("mailboxes", _) => boites(segments),
        ("accounts", 2) => Ok(Resource::Accounts),
        ("accounts", 3) => Ok(Resource::Account {
            compte: segments.get(2),
        }),
        ("accounts", 4) => {
            let compte = segments.get(2);
            match segments.get(3) {
                "password" => Ok(Resource::AccountPassword { compte }),
                "addresses" => Ok(Resource::AccountAddresses { compte }),
                _ => Err(manque),
            }
        }
        ("domains", 2) => Ok(Resource::Domains),
        ("bans", 2) => Ok(Resource::Bans),
        ("bans", 3) => Ok(Resource::Ban {
            source: segments.get(2),
        }),
        ("submissions", 2) => Ok(Resource::Submissions),
        ("health", 2) => Ok(Resource::Health),
        ("metrics", 2) => Ok(Resource::Metrics),
        _ => Err(manque),
    }
}

/// Ce que désigne un chemin sous `/v1/mailboxes`.
fn boites<'o>(segments: &Segments<'o>) -> Result<Resource<'o>, Error> {
    let manque = Error::new(Reason::NoSuchResource);
    if segments.len() == 2 {
        return Ok(Resource::Mailboxes);
    }
    let boite = segments.get(2);
    match (segments.len(), segments.get(3)) {
        (3, _) => Ok(Resource::Mailbox { boite }),
        (4, "search") => Ok(Resource::Search { boite }),
        (4, "messages") => Ok(Resource::Messages { boite }),
        (5, "messages") => Ok(Resource::Message {
            boite,
            uid: uid(segments.get(4))?,
        }),
        (6, "messages") if segments.get(5) == "raw" => Ok(Resource::MessageRaw {
            boite,
            uid: uid(segments.get(4))?,
        }),
        (7, "messages") if segments.get(5) == "parts" => Ok(Resource::MessagePart {
            boite,
            uid: uid(segments.get(4))?,
            partie: segments.get(6),
        }),
        _ => Err(manque),
    }
}

/// L'identifiant unique que porte ce segment.
///
/// # UN SEUL FORMAT, ET PAS DE SIGNE
///
/// « 12 », et ni « +12 », ni « 012 », ni « 0x0c ». Chacune de ces écritures
/// désigne le même message, et chacune est une seconde clé pour un cache ou pour
/// un journal. Refuser coûte moins cher que de garantir que tout le monde
/// normalise pareil.
///
/// # ET ZÉRO NE PEUT PAS SORTIR D'ICI
///
/// §2.3.1.1 de RFC 9051 : un identifiant vaut au moins un. Il n'y a pourtant
/// aucune garde pour l'écarter, parce qu'aucune n'est atteignable : un zéro de
/// tête est refusé, et un segment vide l'a été au décodage. Toute valeur qui
/// sort d'ici commence donc par un chiffre non nul.
fn uid(segment: &str) -> Result<u64, Error> {
    let mauvais = Error::new(Reason::NoSuchResource);
    let octets = segment.as_bytes();
    // Un zéro de tête est une seconde écriture — et ici, la seule façon d'écrire
    // zéro.
    if octets.first() == Some(&b'0') {
        return Err(mauvais);
    }
    let mut valeur = 0_u64;
    for octet in octets {
        let chiffre = octet.checked_sub(b'0').filter(|c| *c <= 9).ok_or(mauvais)?;
        valeur = valeur
            .checked_mul(10)
            .and_then(|dix| dix.checked_add(u64::from(chiffre)))
            .ok_or(mauvais)?;
    }
    Ok(valeur)
}

#[cfg(test)]
mod tests;
