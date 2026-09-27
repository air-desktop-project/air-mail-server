// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! L'envoyeur Web Push (RFC 8030) : chiffrer (RFC 8291), s'annoncer (VAPID,
//! RFC 8292), poster.
//!
//! # CE QUI PART
//!
//! `{"account":"<boîte>"}` — le nom de la boîte qui a changé, rien d'autre —,
//! chiffré pour le navigateur seul. Le service de push voit une adresse, une
//! taille et une heure.
//!
//! # L'ALÉA, À CHAQUE MESSAGE
//!
//! La clef éphémère et le sel sont tirés du noyau NEUFS à chaque envoi : les
//! réemployer défait AES-GCM. S'ils ne se tirent pas, rien ne part — un
//! message chiffré avec un aléa douteux vaut moins que pas de message.

use std::sync::Arc;

use crate::reveil::{Envoi, EnvoiEnCours, Envoyeur};

/// Combien de temps le service garde un réveil pour un appareil éteint.
///
/// Une heure : au-delà, l'appareil qui se rallume se synchronise de lui-même,
/// et le réveil ne dirait plus rien de neuf.
const TTL: &[u8] = b"3600";

/// Pour combien de temps le jeton VAPID vaut : douze heures, la moitié du
/// plafond de §2 de RFC 8292.
const VAPID_SECONDES: u64 = 12 * 3600;

/// L'envoyeur Web Push, et à qui passer les autres canaux.
pub struct WebPush {
    transport: ams_loop_tokio::PushTransport,
    cle: [u8; ams_push::PRIVATE_KEY_OCTETS],
    contact: String,
    autres: Arc<dyn Envoyeur>,
}

impl WebPush {
    /// Un envoyeur Web Push, qui confie APNs et FCM à `autres`.
    #[must_use]
    pub fn new(
        transport: ams_loop_tokio::PushTransport,
        cle: [u8; ams_push::PRIVATE_KEY_OCTETS],
        contact: String,
        autres: Arc<dyn Envoyeur>,
    ) -> Self {
        Self {
            transport,
            cle,
            contact,
            autres,
        }
    }

    /// Chiffre, signe et poste un réveil.
    async fn poster(&self, push: &ams_config::Push, compte: &str) -> Envoi {
        let Some(requete) = preparer(push, compte, &self.cle, &self.contact, crate::maintenant())
        else {
            return Envoi::Echec;
        };
        let champs: [(&[u8], &[u8]); 5] = [
            (b"authorization", &requete.vapid),
            (b"content-encoding", b"aes128gcm"),
            (b"content-type", b"application/octet-stream"),
            (b"ttl", TTL),
            // Un courrier qui arrive n'est pas une alarme : `normal` laisse le
            // téléphone grouper ses réveils avec les autres (§5.3).
            (b"urgency", b"normal"),
        ];
        match self
            .transport
            .post(push.token(), &champs, &requete.corps)
            .await
        {
            Ok(reponse) => verdict(reponse.status),
            Err(faute) => {
                eprintln!("air-mail-server : Web Push — {faute:?}");
                Envoi::Echec
            }
        }
    }
}

impl Envoyeur for WebPush {
    fn envoyer<'a>(
        &'a self,
        appareil: &'a ams_config::Device,
        push: &'a ams_config::Push,
        compte: &'a str,
    ) -> EnvoiEnCours<'a> {
        match push.channel() {
            ams_config::PushChannel::WebPush => Box::pin(self.poster(push, compte)),
            _ => self.autres.envoyer(appareil, push, compte),
        }
    }
}

/// Ce qui part : le corps chiffré, et la valeur du champ `Authorization`.
#[derive(Debug)]
pub struct Requete {
    /// Le corps `aes128gcm`.
    pub corps: Vec<u8>,
    /// `vapid t=…, k=…`.
    pub vapid: Vec<u8>,
}

/// Chiffre et signe un réveil, avec un aléa tiré du noyau.
///
/// `None` si l'abonnement n'est pas Web Push, si l'aléa ne se tire pas, ou si
/// l'URL n'a pas d'origine lisible.
#[must_use]
pub fn preparer(
    push: &ams_config::Push,
    compte: &str,
    cle: &[u8; ams_push::PRIVATE_KEY_OCTETS],
    contact: &str,
    maintenant: u64,
) -> Option<Requete> {
    let mut ephemere = [0_u8; ams_push::PRIVATE_KEY_OCTETS];
    let mut sel = [0_u8; ams_push::SALT_OCTETS];
    // UN SCALAIRE QUI N'EN EST PAS UN SE RETIRE — une chance sur 2^32.
    loop {
        alea(&mut ephemere)?;
        if ams_push::vapid_public_key(&ephemere).is_ok() {
            break;
        }
    }
    alea(&mut sel)?;
    chiffrer_et_signer(push, compte, cle, contact, maintenant, &ephemere, &sel)
}

/// La même chose, avec l'aléa donné : c'est ce que les essais éprouvent.
#[must_use]
pub fn chiffrer_et_signer(
    push: &ams_config::Push,
    compte: &str,
    cle: &[u8; ams_push::PRIVATE_KEY_OCTETS],
    contact: &str,
    maintenant: u64,
    ephemere: &[u8; ams_push::PRIVATE_KEY_OCTETS],
    sel: &[u8; ams_push::SALT_OCTETS],
) -> Option<Requete> {
    let navigateur: &[u8; ams_push::PUBLIC_KEY_OCTETS] = push.key().try_into().ok()?;
    let auth: &[u8; ams_push::AUTH_OCTETS] = push.auth().try_into().ok()?;
    // Un compte est un nom de connexion : il s'écrit dans du JSON sans
    // échappement (`ams_auth::check_login` n'admet ni guillemet ni barre).
    let clair = format!(r#"{{"account":"{compte}"}}"#);
    let mut corps = vec![0_u8; clair.len().saturating_add(ams_push::OVERHEAD_OCTETS)];
    let n = ams_push::encrypt(
        clair.as_bytes(),
        navigateur,
        auth,
        ephemere,
        sel,
        &mut corps,
    )
    .ok()?;
    corps.truncate(n);

    // §2 de RFC 8292 : l'audience est l'ORIGINE du service de push.
    let reste = push.token().strip_prefix("https://")?;
    let hote = reste.split('/').next()?.trim_end_matches(":443");
    let audience = format!("https://{hote}");
    let mut vapid = vec![0_u8; 1024];
    let n = ams_push::write_vapid(
        &audience,
        maintenant.saturating_add(VAPID_SECONDES),
        contact,
        cle,
        &mut vapid,
    )
    .ok()?;
    vapid.truncate(n);
    Some(Requete { corps, vapid })
}

/// Ce que le statut du service dit de l'envoi (§5 de RFC 8030).
#[must_use]
pub fn verdict(statut: u16) -> Envoi {
    match statut {
        200..=299 => Envoi::Transmis,
        // L'abonnement n'existe plus : le navigateur s'est désabonné, ou a
        // expiré. Frapper encore serait inutile, et mal vu.
        404 | 410 => Envoi::Perime,
        _ => Envoi::Echec,
    }
}

/// Remplit `place` depuis le noyau.
fn alea(place: &mut [u8]) -> Option<()> {
    use std::io::Read as _;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(place))
        .ok()
}

#[cfg(test)]
mod tests;
