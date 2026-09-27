// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! L'envoyeur APNs : réveiller un iPhone, un iPad ou un Mac.
//!
//! # UNE NOTIFICATION SILENCIEUSE
//!
//! `{"aps":{"content-available":1},"account":"<boîte>"}`, en
//! `apns-push-type: background` et `apns-priority: 5` : rien ne s'affiche,
//! rien ne sonne — l'application est réveillée pour se synchroniser, et c'est
//! ELLE qui décide de montrer quelque chose, depuis ce qu'elle relit sous son
//! jeton. Apple ne voit ni sujet ni expéditeur. Il limite ces réveils selon
//! l'état de l'appareil : c'est son droit, et l'application se synchronise de
//! toute façon à l'ouverture.
//!
//! # LE JETON DE FOURNISSEUR SE GARDE
//!
//! Apple refuse un jeton renouvelé plus souvent que toutes les vingt minutes,
//! et un jeton de plus d'une heure. On le garde trente minutes ; un refus qui
//! dit qu'il a expiré le fait renouveler au prochain envoi.

use std::sync::Mutex;

use crate::reveil::{Envoi, EnvoiEnCours, Envoyeur};

/// Combien de temps un jeton de fournisseur se garde, en secondes.
const JETON_SECONDES: u64 = 30 * 60;

/// Combien de temps APNs garde un réveil pour un appareil éteint.
const EXPIRATION_SECONDES: u64 = 3600;

/// L'identité APNs d'un serveur : sa clef, et qui il est chez Apple.
#[derive(Debug, Clone)]
pub struct Identite {
    /// La clef privée P-256 tirée du `.p8`.
    pub cle: [u8; ams_push::PRIVATE_KEY_OCTETS],
    /// Le Key ID.
    pub identifiant: String,
    /// Le Team ID.
    pub equipe: String,
    /// L'identifiant de l'application.
    pub sujet: String,
    /// L'environnement de développement plutôt que la production.
    pub developpement: bool,
}

/// L'envoyeur APNs.
pub struct Apns {
    transport: ams_loop_tokio::PushTransport,
    identite: Identite,
    /// Le jeton en cours, et quand il a été émis.
    jeton: Mutex<Option<(u64, Vec<u8>)>>,
}

impl Apns {
    /// Un envoyeur APNs.
    #[must_use]
    pub fn new(transport: ams_loop_tokio::PushTransport, identite: Identite) -> Self {
        Self {
            transport,
            identite,
            jeton: Mutex::new(None),
        }
    }

    /// Le jeton de fournisseur : celui qu'on garde, ou un neuf s'il a vécu.
    fn jeton(&self, maintenant: u64) -> Option<Vec<u8>> {
        let mut garde = self
            .jeton
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((emis, valeur)) = garde.as_ref()
            && maintenant.saturating_sub(*emis) < JETON_SECONDES
        {
            return Some(valeur.clone());
        }
        let mut place = vec![0_u8; 512];
        let n = ams_push::write_apns_token(
            &self.identite.identifiant,
            &self.identite.equipe,
            maintenant,
            &self.identite.cle,
            &mut place,
        )
        .ok()?;
        place.truncate(n);
        *garde = Some((maintenant, place.clone()));
        Some(place)
    }

    /// Oublie le jeton : Apple l'a refusé.
    fn oublier_le_jeton(&self) {
        *self
            .jeton
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    async fn poster(&self, push: &ams_config::Push, compte: &str) -> Envoi {
        let maintenant = crate::maintenant();
        let Some(jeton) = self.jeton(maintenant) else {
            return Envoi::Echec;
        };
        let requete = composer(&self.identite, push, compte, maintenant);
        let champs: [(&[u8], &[u8]); 5] = [
            (b"authorization", &jeton),
            (b"apns-topic", self.identite.sujet.as_bytes()),
            (b"apns-push-type", b"background"),
            // Une notification d'arrière-plan DOIT être de priorité 5.
            (b"apns-priority", b"5"),
            (b"apns-expiration", requete.expiration.as_bytes()),
        ];
        match self
            .transport
            .post(&requete.url, &champs, requete.corps.as_bytes())
            .await
        {
            Ok(reponse) => {
                let envoi = verdict(reponse.status, &reponse.body);
                // UN REFUS SE DIT : le statut, et la raison qu'Apple donne —
                // un mot de son vocabulaire, jamais du courrier.
                if envoi != Envoi::Transmis {
                    eprintln!(
                        "air-mail-server : APNs — Apple a répondu {} {}",
                        reponse.status,
                        raison(&reponse.body)
                    );
                }
                if reponse.status == 403 {
                    self.oublier_le_jeton();
                }
                envoi
            }
            Err(faute) => {
                eprintln!("air-mail-server : APNs — {faute:?}");
                Envoi::Echec
            }
        }
    }
}

impl Envoyeur for Apns {
    fn envoyer<'a>(
        &'a self,
        _: &'a ams_config::Device,
        push: &'a ams_config::Push,
        compte: &'a str,
    ) -> EnvoiEnCours<'a> {
        Box::pin(self.poster(push, compte))
    }
}

/// Ce qui part vers APNs, hors du jeton.
#[derive(Debug, PartialEq, Eq)]
pub struct Requete {
    /// `https://api.push.apple.com/3/device/<jeton>`.
    pub url: String,
    /// La notification silencieuse.
    pub corps: String,
    /// `apns-expiration`, en secondes depuis l'époque.
    pub expiration: String,
}

/// Compose une notification silencieuse pour cet appareil.
#[must_use]
pub fn composer(
    identite: &Identite,
    push: &ams_config::Push,
    compte: &str,
    maintenant: u64,
) -> Requete {
    let hote = match identite.developpement {
        true => "api.sandbox.push.apple.com",
        false => "api.push.apple.com",
    };
    Requete {
        url: format!("https://{hote}/3/device/{}", push.token()),
        // Un compte est un nom de connexion : il s'écrit sans échappement.
        corps: format!(r#"{{"aps":{{"content-available":1}},"account":"{compte}"}}"#),
        expiration: maintenant.saturating_add(EXPIRATION_SECONDES).to_string(),
    }
}

/// Ce que la réponse d'APNs dit de l'envoi.
///
/// `410` : l'appareil ne tient plus ce jeton. `400` avec `BadDeviceToken` ou
/// `DeviceTokenNotForTopic` : ce jeton n'a jamais valu pour nous. Les deux font
/// retirer l'abonnement. Le reste — un jeton de fournisseur refusé, un débit
/// trop haut, Apple indisponible — est un échec, et l'abonnement reste.
#[must_use]
pub fn verdict(statut: u16, corps: &[u8]) -> Envoi {
    let dit = |raison: &[u8]| corps.windows(raison.len()).any(|fenetre| fenetre == raison);
    match statut {
        200 => Envoi::Transmis,
        410 => Envoi::Perime,
        400 if dit(b"\"BadDeviceToken\"") || dit(b"\"DeviceTokenNotForTopic\"") => Envoi::Perime,
        _ => Envoi::Echec,
    }
}

/// La raison qu'Apple donne d'un refus (`{"reason":"BadDeviceToken"}`), si elle
/// est faite de lettres — rien d'autre ne s'écrit au journal.
#[must_use]
pub fn raison(corps: &[u8]) -> &str {
    const CLE: &[u8] = br#""reason":""#;
    corps
        .windows(CLE.len())
        .position(|fenetre| fenetre == CLE)
        .and_then(|rang| corps.get(rang.saturating_add(CLE.len())..))
        .and_then(|reste| reste.split(|octet| *octet == b'"').next())
        .filter(|mot| !mot.is_empty() && mot.len() <= 64 && mot.iter().all(u8::is_ascii_alphabetic))
        .and_then(|mot| core::str::from_utf8(mot).ok())
        .unwrap_or("")
}

#[cfg(test)]
mod tests;
