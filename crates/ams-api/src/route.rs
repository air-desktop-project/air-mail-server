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

    /// `/v1/me/password` — **le secret de qui appelle**, et de personne d'autre.
    ///
    /// # POURQUOI `/v1/me/…` ET NON `/v1/accounts/me/password`
    ///
    /// Le second aurait rendu INATTEIGNABLE, par la route d'administration, un
    /// compte réellement nommé `me` : `check_login` l'accepte, et rien
    /// n'interdit à quelqu'un de le choisir. Réserver un nom de compte pour
    /// faire tenir une route est un prix qu'on ne paie pas quand un segment de
    /// tête libre existe.
    ///
    /// # ELLE N'EXIGE AUCUNE PORTÉE, ET CE N'EST PAS UN OUBLI
    ///
    /// Comme `/v1/tokens/current`, elle agit sur SOI et non sur une ressource
    /// du serveur : le jeton présenté dit déjà de qui il s'agit. Exiger `Admin`
    /// en ferait une route que seul un administrateur peut emprunter, ce qui
    /// est très exactement ce qu'elle existe pour éviter.
    ///
    /// **LE MOT DE PASSE ACTUEL EST EXIGÉ DANS LE CORPS**, lui. Sans cela, un
    /// jeton volé permettrait de verrouiller le propriétaire légitime hors de
    /// sa boîte, définitivement — un vol de jeton deviendrait un vol de compte.
    OwnPassword,

    /// `/v1/me/devices` — **les appareils de qui appelle**, et de personne
    /// d'autre.
    ///
    /// # POURQUOI SOUS `/v1/me/…` ET NON SOUS `/v1/accounts/…`
    ///
    /// Pour la même raison que le mot de passe : elle agit sur SOI, et le jeton
    /// présenté dit déjà de qui il s'agit. La ranger sous l'administration en
    /// ferait une route que seul un administrateur peut emprunter — or c'est
    /// l'utilisateur qui doit pouvoir voir ses propres appareils, et surtout en
    /// révoquer un, sans demander à personne.
    ///
    /// **C'EST LA RÉVOCATION QUI PRESSE** : un téléphone perdu se retire dans la
    /// minute, pas au prochain jour ouvré.
    ///
    /// # ELLE S'ÉCRIT AUSSI, ET C'EST L'APPAIRAGE CROISÉ
    ///
    /// Un `POST` y enrôle un SECOND appareil, approuvé par un premier. Sans
    /// cela, ajouter une tablette exigerait une invitation de l'exploitant, et
    /// donc de révoquer le téléphone d'abord.
    ///
    /// **LE JETON NE SUFFIT PAS À CE `POST`** : il faut un défi signé par un
    /// appareil DÉJÀ enrôlé. Un jeton vaut quinze minutes, une clef vaut jusqu'à
    /// sa révocation — laisser un porteur créer une clef ferait d'un vol de
    /// quinze minutes un accès permanent, que fermer la session ne retirerait
    /// pas.
    OwnDevices,
    /// `/v1/me/devices/{id}` — un appareil à soi, pour le révoquer.
    ///
    /// **L'IDENTIFIANT NE SUFFIT PAS À DÉSIGNER** : le compte de qui appelle
    /// entre dans la recherche. Sans cela, deviner un identifiant permettrait de
    /// révoquer l'appareil d'un autre, et un déni de service tiendrait en une
    /// boucle.
    OwnDevice {
        /// L'identifiant de l'appareil, tel que le serveur l'a tiré.
        id: &'o str,
    },

    /// `/v1/devices` — **enrôler un appareil, sans jeton.**
    ///
    /// # LA SEULE AUTRE RESSOURCE QUI N'EXIGE AUCUN JETON
    ///
    /// Comme `/v1/tokens`, et pour la même raison : c'est une porte d'entrée.
    /// Celui qui s'enrôle n'a encore rien — ni mot de passe qu'il veuille
    /// donner, ni appareil déjà connu. **C'est l'invitation, dans le corps, qui
    /// l'autorise**, et elle se vérifie avec la même clé qu'un jeton.
    ///
    /// Elle n'est PAS sous `/v1/me` : « moi » n'a pas de sens sans jeton, et
    /// c'est l'invitation qui dit de quel compte il s'agit.
    Devices,

    /// `/v1/sessions/challenge` — **obtenir un défi à signer.**
    ///
    /// # ELLE N'EXIGE AUCUN JETON, ET N'APPREND RIEN
    ///
    /// C'est la troisième porte d'entrée. Un défi est émis pour **n'importe
    /// quel** couple compte-appareil, connu ou non : refuser d'en émettre pour
    /// un inconnu ferait de cette route un oracle d'énumération des appareils.
    ///
    /// Ce qu'elle rend est scellé, borné à soixante secondes, et ne vaut que
    /// pour l'appareil qui tient la clef correspondante.
    SessionChallenge,

    /// `/v1/sessions` — **ouvrir une session avec la clef d'un appareil.**
    ///
    /// Le pendant de `/v1/tokens` pour l'authentification par clef : on y
    /// présente un défi signé au lieu d'un mot de passe, et l'on en ressort avec
    /// le même jeton.
    Sessions,

    /// `/v1/invitations` — frapper une invitation.
    ///
    /// **CELLE-CI EXIGE `admin`**, et c'est toute la dissymétrie : inviter est
    /// un geste d'exploitant, s'enrôler est un geste d'utilisateur.
    Invitations,

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
            // **NI L'UNE NI L'AUTRE N'EXIGE DE JETON** : ce sont les deux
            // portes d'entrée. Ce qui autorise est dans le corps — des
            // identifiants pour l'une, une invitation scellée pour l'autre.
            Self::Tokens | Self::Devices | Self::SessionChallenge | Self::Sessions => {
                return None;
            }
            // Révoquer son propre jeton ne demande que de l'avoir.
            Self::CurrentToken | Self::OwnPassword | Self::OwnDevices | Self::OwnDevice { .. } => {
                return Some(Scope::none());
            }
            Self::Mailboxes
            | Self::Mailbox { .. }
            | Self::Messages { .. }
            | Self::Message { .. }
            | Self::MessageRaw { .. }
            | Self::MessagePart { .. }
            | Self::Search { .. } => Area::Mail,
            Self::Invitations
            | Self::Accounts
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
            Self::Tokens
            | Self::Submissions
            | Self::Devices
            | Self::Invitations
            | Self::SessionChallenge
            | Self::Sessions => &[Method::Post],
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
            Self::AccountPassword { .. } | Self::OwnPassword => &[Method::Put],
            Self::AccountAddresses { .. } => &[Method::Get, Method::Head, Method::Put],
            Self::Ban { .. } | Self::OwnDevice { .. } => &[Method::Delete],
            // **ELLE NE S'ÉCRIT PAS ICI** : un appareil s'enrôle par le
            // chemin d'enrôlement, qui prouve la possession de la clef. Un
            // `POST` de liste laisserait déclarer une clef sans rien prouver.
            Self::OwnDevices => &[Method::Get, Method::Head, Method::Post],
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
    ///
    /// **QUAND LA MÉTHODE N'EST PAS SERVIE, C'EST LA PORTÉE DE LECTURE.** Un
    /// `405` nomme la ressource et énumère ses méthodes dans `Allow` : c'est une
    /// confidence sur la ressource, et le droit d'y avoir part est celui de la
    /// lire. Exiger la portée de la méthode DEMANDÉE — écrire, pour un `PATCH` —
    /// rendrait `404` à un lecteur légitime qui s'est trompé de verbe, alors
    /// qu'il peut déjà lire la ressource.
    pub scope: Option<Scope>,
    /// Cette ressource sert-elle cette méthode ?
    ///
    /// **C'EST L'APPELANT QUI EN TIRE LE `405`, ET APRÈS L'AUTORISATION.** Voir
    /// [`resolve`] : le rendre ici le rendait avant, et c'était une fuite.
    pub serves: bool,
}

/// Résout une requête.
///
/// `chemin` est la partie du chemin, sans la chaîne de requête — voir
/// [`split_query`]. `sortie` reçoit les segments décodés, et les emprunts du
/// résultat y pointent.
///
/// [`split_query`]: crate::split_query
///
/// # LE VERBE NE SE JUGE PAS ICI, ET C'EST UN CORRECTIF
///
/// Cette fonction rendait `MethodNotAllowed` — donc un `405` — avant que
/// personne n'ait vérifié le moindre jeton. [`Reason::status`] déclare pourtant,
/// onze lignes plus bas dans le même `match`, que « cela n'existe pas » et
/// « vous n'avez pas le droit de savoir » se répondent PAREIL, « la différence
/// entre les deux serait l'information elle-même ».
///
/// Le `405` rendait cette différence, et à qui n'avait rien présenté :
/// `PATCH /v1/bans` répondait `405` avec un `Allow`, `PATCH /v1/inconnu`
/// répondait `404`. L'arbre entier des ressources s'énumérait ainsi, verbe par
/// verbe, sans jeton — et un jeton de courrier y lisait la surface
/// d'administration qu'il n'ouvre pas.
///
/// On rend donc [`Resolved::serves`], et **c'est l'appelant qui en tire le `405`
/// une fois l'autorisation acquise**.
///
/// # Errors
///
/// [`Reason::BadPath`] et [`Reason::PathTooLong`] pour ce que le chemin ne peut
/// pas être ; [`Reason::NoSuchResource`] pour un chemin bien formé qui ne
/// désigne rien.
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
    let serves = resource.serves(method);
    Ok(Resolved {
        resource,
        method,
        // Voir [`Resolved::scope`] : ce qu'il faut pour APPRENDRE qu'un verbe
        // n'est pas servi, c'est ce qu'il faut pour lire la ressource.
        scope: resource.scope(if serves { method } else { Method::Get }),
        serves,
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
        ("devices", 2) => Ok(Resource::Devices),
        ("invitations", 2) => Ok(Resource::Invitations),
        ("sessions", 2) => Ok(Resource::Sessions),
        ("sessions", 3) if segments.get(2) == "challenge" => Ok(Resource::SessionChallenge),
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
        ("me", 3) if segments.get(2) == "password" => Ok(Resource::OwnPassword),
        ("me", 3) if segments.get(2) == "devices" => Ok(Resource::OwnDevices),
        ("me", 4) if segments.get(2) == "devices" => Ok(Resource::OwnDevice {
            id: segments.get(3),
        }),
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
