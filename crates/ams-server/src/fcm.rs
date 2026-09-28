// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! L'envoyeur FCM (Firebase Cloud Messaging) : réveiller un téléphone Android.
//!
//! # DEUX ÉCHANGES
//!
//! FCM (API HTTP v1) n'accepte qu'un jeton d'accès OAuth2. On l'obtient de
//! Google en présentant une ASSERTION — un JWT RS256 signé par la clef du compte
//! de service du projet Firebase (RFC 7523) — ; il vaut une heure, et se garde
//! jusqu'à une minute de sa fin. Puis chaque réveil est un `POST` vers
//! `…/v1/projects/<projet>/messages:send`.
//!
//! # UN MESSAGE DE DONNÉES
//!
//! `{"message":{"token":…,"data":{"account":"<boîte>"},"android":{"priority":
//! "normal"}}}` : pas de `notification`, donc rien ne s'affiche — l'application
//! reçoit la boîte qui a changé, et relit sous son jeton. Google ne voit ni
//! sujet ni expéditeur.
//!
//! # LA SIGNATURE RSA EST CELLE DE DKIM
//!
//! RS256, c'est RSASSA-PKCS1-v1_5 sur SHA-256 : exactement ce que DKIM
//! (`rsa-sha256`) sait faire, avec l'aveuglement. On réemploie
//! `ams_dkim::SigningKey`, plutôt qu'une seconde arithmétique RSA à auditer.

use std::sync::Mutex;

use crate::reveil::{Envoi, EnvoiEnCours, Envoyeur};

/// Ce que l'assertion demande : envoyer des messages FCM, et rien d'autre.
const PORTEE: &str = "https://www.googleapis.com/auth/firebase.messaging";

/// Combien de temps avant sa fin un jeton d'accès se renouvelle.
const MARGE_SECONDES: u64 = 60;

/// Ce qu'un fichier de compte de service peut peser.
const COMPTE_MAX: usize = 16 * 1024;

/// Le compte de service d'un projet Firebase, lu de son fichier JSON.
pub struct CompteDeService {
    /// `client_email`.
    pub email: String,
    /// `project_id`.
    pub projet: String,
    /// `token_uri`.
    pub adresse_du_jeton: String,
    /// `private_key`.
    pub cle: ams_dkim::SigningKey,
}

/// Lit un fichier de compte de service.
///
/// # Errors
///
/// Ce qui manque ou n'a pas sa forme, dit en clair — sans jamais la clef.
pub fn lire_compte_de_service(json: &[u8]) -> Result<CompteDeService, String> {
    use ams_api::{Event, Reader};
    if json.len() > COMPTE_MAX {
        return Err(String::from("fichier démesuré pour un compte de service"));
    }
    let mut lecteur = Reader::new(json);
    let mut place = vec![0_u8; json.len()];
    let (mut genre, mut email, mut projet, mut adresse, mut pem) = (None, None, None, None, None);
    let mut cle_courante = String::new();
    loop {
        match lecteur.read().map_err(|_| String::from("JSON illisible"))? {
            None => break,
            Some(Event::Key(cle)) => {
                cle_courante = cle.unescape(&mut place).unwrap_or_default().to_owned();
            }
            Some(Event::Text(texte)) => {
                let valeur = texte
                    .unescape(&mut place)
                    .map_err(|_| String::from("JSON illisible"))?
                    .to_owned();
                match cle_courante.as_str() {
                    "type" => genre = Some(valeur),
                    "client_email" => email = Some(valeur),
                    "project_id" => projet = Some(valeur),
                    "token_uri" => adresse = Some(valeur),
                    "private_key" => pem = Some(valeur),
                    _ => {}
                }
            }
            Some(_) => {}
        }
    }
    if genre.as_deref() != Some("service_account") {
        return Err(String::from("ce n'est pas un compte de service (`type`)"));
    }
    let email = email.ok_or("`client_email` manque")?;
    let projet = projet
        .filter(|p| !p.is_empty() && p.bytes().all(|o| o.is_ascii_alphanumeric() || o == b'-'))
        .ok_or("`project_id` manque, ou n'est pas fait de lettres, chiffres et tirets")?;
    let adresse_du_jeton = adresse
        .filter(|a| a.starts_with("https://"))
        .ok_or("`token_uri` manque, ou n'est pas une URL https")?;
    let pem = pem.ok_or("`private_key` manque")?;
    let cle = ams_dkim::SigningKey::from_pem(pem.as_bytes())
        .map_err(|_| String::from("`private_key` n'est pas une clef RSA lisible"))?;
    if !matches!(cle, ams_dkim::SigningKey::Rsa(_)) {
        return Err(String::from("`private_key` n'est pas une clef RSA"));
    }
    Ok(CompteDeService {
        email,
        projet,
        adresse_du_jeton,
        cle,
    })
}

/// L'assertion RS256 (RFC 7523) qui s'échange contre un jeton d'accès.
#[must_use]
pub fn assertion(compte: &CompteDeService, maintenant: u64) -> Option<String> {
    let entete = br#"{"alg":"RS256","typ":"JWT"}"#;
    let revendications = format!(
        r#"{{"iss":"{}","scope":"{PORTEE}","aud":"{}","iat":{maintenant},"exp":{}}}"#,
        echapper(&compte.email),
        echapper(&compte.adresse_du_jeton),
        maintenant.saturating_add(3600)
    );
    let mut signe = en_base64url(entete)?;
    signe.push('.');
    signe.push_str(&en_base64url(revendications.as_bytes())?);
    let condensat = ams_sasl::sha256(signe.as_bytes());
    let mut alea = ams_loop_tokio::Urandom::ouvrir()?;
    let signature = compte.cle.sign_with(&condensat, &mut alea).ok()?;
    signe.push('.');
    signe.push_str(&en_base64url(&signature)?);
    Some(signe)
}

/// Échappe ce qui ne peut pas aller tel quel dans une chaîne JSON.
fn echapper(texte: &str) -> String {
    texte.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Du base64url sans remplissage.
fn en_base64url(octets: &[u8]) -> Option<String> {
    let mut place = vec![0_u8; octets.len().saturating_mul(2).saturating_add(4)];
    let n = ams_push::encode_base64url(octets, &mut place).ok()?;
    place.truncate(n);
    String::from_utf8(place).ok()
}

/// Le jeton d'accès que rend Google, et pour combien de secondes.
#[must_use]
pub fn lire_le_jeton(corps: &[u8]) -> Option<(String, u64)> {
    use ams_api::{Event, Reader};
    let mut lecteur = Reader::new(corps);
    let mut place = vec![0_u8; corps.len()];
    let mut cle = String::new();
    let (mut jeton, mut duree) = (None, None);
    while let Some(evenement) = lecteur.read().ok()? {
        match evenement {
            Event::Key(nom) => cle = nom.unescape(&mut place).ok()?.to_owned(),
            Event::Text(texte) if cle == "access_token" => {
                jeton = Some(texte.unescape(&mut place).ok()?.to_owned());
            }
            Event::Number(nombre) if cle == "expires_in" => duree = nombre.as_u64(),
            _ => {}
        }
    }
    // Un jeton qui ira dans un champ HTTP : de l'ASCII imprimable, sans blanc.
    let jeton = jeton.filter(|j| !j.is_empty() && j.bytes().all(|o| (b'!'..=b'~').contains(&o)))?;
    Some((jeton, duree.unwrap_or(3600)))
}

/// Le message de données d'un réveil.
#[must_use]
pub fn message(push: &ams_config::Push, compte: &str) -> String {
    // Un jeton FCM et un nom de compte s'écrivent sans échappement :
    // `ams_config::Push::new` et `ams_auth::check_login` l'ont vérifié.
    format!(
        r#"{{"message":{{"token":"{}","data":{{"account":"{compte}"}},"android":{{"priority":"normal"}}}}}}"#,
        push.token()
    )
}

/// Ce que la réponse de FCM dit de l'envoi.
///
/// `UNREGISTERED` (404) : l'application a été désinstallée, ou le jeton a
/// tourné — l'abonnement se retire. Le reste est un échec, et reste.
#[must_use]
pub fn verdict(statut: u16, corps: &[u8]) -> Envoi {
    let dit = |mot: &[u8]| corps.windows(mot.len()).any(|fenetre| fenetre == mot);
    match statut {
        200 => Envoi::Transmis,
        404 if dit(b"UNREGISTERED") => Envoi::Perime,
        _ => Envoi::Echec,
    }
}

/// L'envoyeur FCM.
pub struct Fcm {
    transport: ams_loop_tokio::PushTransport,
    compte: CompteDeService,
    /// Le jeton d'accès en cours, et jusqu'à quand il vaut.
    jeton: Mutex<Option<(u64, String)>>,
}

impl Fcm {
    /// Un envoyeur FCM.
    #[must_use]
    pub fn new(transport: ams_loop_tokio::PushTransport, compte: CompteDeService) -> Self {
        Self {
            transport,
            compte,
            jeton: Mutex::new(None),
        }
    }

    /// Le jeton gardé, s'il vaut encore.
    fn jeton_garde(&self, maintenant: u64) -> Option<String> {
        let garde = self
            .jeton
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        garde
            .as_ref()
            .filter(|(fin, _)| maintenant.saturating_add(MARGE_SECONDES) < *fin)
            .map(|(_, jeton)| jeton.clone())
    }

    /// Un jeton d'accès : le gardé, ou un neuf demandé à Google.
    async fn jeton_d_acces(&self, maintenant: u64) -> Option<String> {
        if let Some(jeton) = self.jeton_garde(maintenant) {
            return Some(jeton);
        }
        let assertion = tokio::task::block_in_place(|| assertion(&self.compte, maintenant))?;
        let corps = format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={assertion}"
        );
        let champs: [(&[u8], &[u8]); 1] = [(b"content-type", b"application/x-www-form-urlencoded")];
        let reponse = match self
            .transport
            .post(&self.compte.adresse_du_jeton, &champs, corps.as_bytes())
            .await
        {
            Ok(reponse) => reponse,
            Err(faute) => {
                eprintln!("air-mail-server : FCM — jeton d'accès : {faute:?}");
                return None;
            }
        };
        if reponse.status != 200 {
            eprintln!(
                "air-mail-server : FCM — Google a refusé l'assertion ({})",
                reponse.status
            );
            return None;
        }
        let (jeton, duree) = lire_le_jeton(&reponse.body)?;
        *self
            .jeton
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some((maintenant.saturating_add(duree), jeton.clone()));
        Some(jeton)
    }

    async fn poster(&self, push: &ams_config::Push, compte: &str) -> Envoi {
        let Some(jeton) = self.jeton_d_acces(crate::maintenant()).await else {
            return Envoi::Echec;
        };
        let url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            self.compte.projet
        );
        let autorisation = format!("Bearer {jeton}");
        let champs: [(&[u8], &[u8]); 2] = [
            (b"authorization", autorisation.as_bytes()),
            (b"content-type", b"application/json"),
        ];
        match self
            .transport
            .post(&url, &champs, message(push, compte).as_bytes())
            .await
        {
            Ok(reponse) => {
                let envoi = verdict(reponse.status, &reponse.body);
                if reponse.status == 401 {
                    *self
                        .jeton
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
                }
                if envoi != Envoi::Transmis {
                    eprintln!(
                        "air-mail-server : FCM — Google a répondu {}",
                        reponse.status
                    );
                }
                envoi
            }
            Err(faute) => {
                eprintln!("air-mail-server : FCM — {faute:?}");
                Envoi::Echec
            }
        }
    }
}

impl Envoyeur for Fcm {
    fn envoyer<'a>(
        &'a self,
        _: &'a ams_config::Device,
        push: &'a ams_config::Push,
        compte: &'a str,
    ) -> EnvoiEnCours<'a> {
        Box::pin(self.poster(push, compte))
    }
}

#[cfg(test)]
mod tests;
