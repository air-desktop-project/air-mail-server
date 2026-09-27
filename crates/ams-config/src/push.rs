// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! L'abonnement d'un appareil aux notifications : par quel canal, et à quelle
//! adresse.
//!
//! # UNE SEULE RÈGLE, À L'ENTRÉE ET AU CHARGEMENT
//!
//! Un abonnement se construit par [`Push::new`], et par rien d'autre : l'API qui
//! le reçoit et le fichier qui le relit passent par la même porte. Deux
//! validations finiraient par ne pas refuser la même chose, et un abonnement
//! accepté par l'une serait rejeté au redémarrage par l'autre — le magasin
//! entier avec lui.
//!
//! # WEB PUSH FAIT ÉCRIRE LE SERVEUR VERS UNE URL CHOISIE PAR LE CLIENT
//!
//! C'est le seul canal où le client désigne la machine que le serveur va
//! contacter. Sans garde, un compte ferait poster notre serveur vers
//! `https://10.0.0.1/…` ou `https://localhost:8443/…` : une requête qui part de
//! l'intérieur, vers l'intérieur (SSRF). On n'admet donc qu'une URL `https`,
//! sur le port 443, vers un NOM — ni adresse IP littérale, ni nom local. Ce
//! n'est que la première moitié : à l'envoi, les adresses résolues seront
//! vérifiées à leur tour, puisqu'un nom public peut pointer n'importe où.

use alloc::string::String;
use alloc::vec::Vec;

use ams_auth::{CLE_OCTETS, Cle};

/// Ce qu'un jeton APNs peut faire de long, en chiffres hexadécimaux.
///
/// Trente-deux octets aujourd'hui, soit soixante-quatre chiffres ; Apple a
/// prévenu que la longueur pouvait changer, et deux cents laissent la marge.
pub const APNS_TOKEN_MAX: usize = 200;

/// Ce qu'un jeton d'enregistrement FCM peut faire de long.
pub const FCM_TOKEN_MAX: usize = 4096;

/// Ce qu'une URL Web Push peut faire de long.
pub const ENDPOINT_MAX: usize = 2048;

/// Le secret d'authentification de Web Push : seize octets (§3.2 de RFC 8291).
pub const WEBPUSH_AUTH_OCTETS: usize = 16;

/// Le canal par lequel un appareil se réveille.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushChannel {
    /// Apple Push Notification service : iPhone, iPad, Mac.
    Apns,
    /// Firebase Cloud Messaging : Android.
    Fcm,
    /// Web Push (RFC 8030) : navigateurs, UnifiedPush.
    WebPush,
}

impl PushChannel {
    /// Son nom dans l'API : `apns`, `fcm`, `webpush`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Apns => "apns",
            Self::Fcm => "fcm",
            Self::WebPush => "webpush",
        }
    }

    /// Le canal de ce nom, s'il en est un.
    #[must_use]
    pub fn from_name(nom: &str) -> Option<Self> {
        [Self::Apns, Self::Fcm, Self::WebPush]
            .into_iter()
            .find(|canal| canal.name() == nom)
    }
}

/// Pourquoi un abonnement ne se construit pas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushFault {
    /// Le jeton n'a pas la forme que son canal lui donne.
    BadToken,
    /// L'URL Web Push n'est pas une URL `https` vers un nom public, port 443.
    BadEndpoint,
    /// La clef Web Push n'est pas un point P-256 non compressé.
    BadKey,
    /// Le secret Web Push ne fait pas seize octets.
    BadAuth,
    /// Une clef ou un secret pour un canal qui n'en prend pas.
    Unexpected,
}

/// L'abonnement d'un appareil.
///
/// **IL NE SE CONSTRUIT QUE PAR [`Push::new`]** : un `Push` tenu est un
/// abonnement qui a passé la règle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Push {
    channel: PushChannel,
    token: String,
    key: Vec<u8>,
    auth: Vec<u8>,
    since: u64,
}

impl Push {
    /// Construit un abonnement, ou dit pourquoi il n'en est pas un.
    ///
    /// # Errors
    ///
    /// [`PushFault`].
    pub fn new(
        channel: PushChannel,
        token: String,
        key: Vec<u8>,
        auth: Vec<u8>,
        since: u64,
    ) -> Result<Self, PushFault> {
        match channel {
            PushChannel::Apns => {
                let bien_forme = (64..=APNS_TOKEN_MAX).contains(&token.len())
                    && token.bytes().all(|octet| octet.is_ascii_hexdigit());
                if !bien_forme {
                    return Err(PushFault::BadToken);
                }
            }
            PushChannel::Fcm => {
                let bien_forme = (1..=FCM_TOKEN_MAX).contains(&token.len())
                    && token.bytes().all(|octet| {
                        octet.is_ascii_alphanumeric() || matches!(octet, b'_' | b'-' | b':')
                    });
                if !bien_forme {
                    return Err(PushFault::BadToken);
                }
            }
            PushChannel::WebPush => {
                if !endpoint_is_acceptable(&token) {
                    return Err(PushFault::BadEndpoint);
                }
                // UNE CLEF QUI N'EST PAS UN POINT N'EST PAS UNE CLEF : chiffrer
                // vers elle ouvrirait les attaques par courbe invalide.
                if key.len() != CLE_OCTETS || Cle::lire(&key).is_err() {
                    return Err(PushFault::BadKey);
                }
                if auth.len() != WEBPUSH_AUTH_OCTETS {
                    return Err(PushFault::BadAuth);
                }
            }
        }
        if channel != PushChannel::WebPush && !(key.is_empty() && auth.is_empty()) {
            return Err(PushFault::Unexpected);
        }
        Ok(Self {
            channel,
            token,
            key,
            auth,
            since,
        })
    }

    /// Le canal.
    #[must_use]
    pub const fn channel(&self) -> PushChannel {
        self.channel
    }

    /// Le jeton APNs, le jeton FCM ou l'URL Web Push.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// La clef publique Web Push ; vide pour les autres canaux.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Le secret d'authentification Web Push ; vide pour les autres canaux.
    #[must_use]
    pub fn auth(&self) -> &[u8] {
        &self.auth
    }

    /// Quand l'abonnement a été posé, en secondes depuis l'époque.
    #[must_use]
    pub const fn since(&self) -> u64 {
        self.since
    }
}

/// Une URL Web Push que ce serveur accepte de contacter.
///
/// `https://` suivi d'un NOM — au moins deux étiquettes, la dernière portant
/// une lettre, ce qui écarte toute adresse IPv4 écrite en chiffres —, d'un port
/// `443` facultatif, puis d'un chemin en ASCII imprimable. Ni identifiants
/// (`user@`), ni adresse IPv6 entre crochets, ni nom local (`localhost`,
/// `.local`, `.internal`, `.home.arpa`…).
#[must_use]
pub fn endpoint_is_acceptable(url: &str) -> bool {
    let Some(reste) = url.strip_prefix("https://") else {
        return false;
    };
    if url.len() > ENDPOINT_MAX {
        return false;
    }
    let (autorite, chemin) = reste.split_at(reste.find('/').unwrap_or(reste.len()));
    let hote = match autorite.split_once(':') {
        Some((hote, "443")) => hote,
        Some(_) => return false,
        None => autorite,
    };
    let chemin_propre =
        chemin.starts_with('/') && chemin.bytes().all(|octet| (b'!'..=b'~').contains(&octet));
    chemin_propre && nom_public(hote)
}

/// Un nom d'hôte public : des étiquettes de lettres, chiffres et tirets, au
/// moins deux, la dernière avec une lettre, et rien de local.
fn nom_public(hote: &str) -> bool {
    const LOCAUX: [&str; 6] = [
        "localhost",
        ".localhost",
        ".local",
        ".internal",
        ".home.arpa",
        ".lan",
    ];
    let minuscule = hote.to_ascii_lowercase();
    let etiquettes_valables = minuscule.split('.').all(|etiquette| {
        (1..=63).contains(&etiquette.len())
            && etiquette
                .bytes()
                .all(|o| o.is_ascii_alphanumeric() || o == b'-')
            && !etiquette.starts_with('-')
            && !etiquette.ends_with('-')
    });
    let derniere_lettree = minuscule
        .rsplit('.')
        .next()
        .is_some_and(|derniere| derniere.bytes().any(|o| o.is_ascii_alphabetic()));
    let local = LOCAUX.iter().any(|suffixe| {
        minuscule == suffixe.trim_start_matches('.') || minuscule.ends_with(suffixe)
    });
    etiquettes_valables && minuscule.contains('.') && derniere_lettree && !local
}

#[cfg(test)]
mod tests;
