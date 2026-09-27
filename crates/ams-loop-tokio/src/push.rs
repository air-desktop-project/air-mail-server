// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le transport des réveils : un `POST` HTTP/2, en TLS 1.3 vérifié, vers un
//! service de notifications — Web Push, APNs, FCM.
//!
//! # LE CLIENT DÉSIGNE LA MACHINE, ET C'EST UNE PORTE VERS L'INTÉRIEUR
//!
//! Pour Web Push, c'est l'abonné qui donne l'URL que le serveur contactera. Le
//! nom a déjà été filtré à l'abonnement (`ams_config::endpoint_is_acceptable`) ;
//! ici, ce sont les ADRESSES qu'il résout : un nom public peut pointer vers
//! `10.0.0.1`, vers `127.0.0.1`, vers la passerelle du centre de données. Une
//! adresse qui n'est pas publique n'est jamais contactée (SSRF), et la
//! connexion part vers l'adresse VÉRIFIÉE — pas vers un nom qu'on résoudrait une
//! seconde fois, et qui pourrait entre-temps dire autre chose.
//!
//! # CE QUI EST VÉRIFIÉ
//!
//! TLS 1.3, le post-quantique proposé en premier (C4, C14), le certificat
//! contre les autorités que l'exploitant a nommées et pour CE nom, et HTTP/2
//! négocié par ALPN : APNs n'accepte rien d'autre, et un pair qui ne le parle
//! pas n'est pas un service de push qu'on connaît.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::resolver::Resolver;

/// Ce que le corps d'une réponse peut occuper. APNs et FCM y disent pourquoi
/// ils refusent ; seize kibioctets, c'est cent fois cela.
pub const RESPONSE_BODY_MAX: usize = 16 * 1024;

/// Ce qu'on retient au plus de cadres pas encore consommés.
const RECU_MAX: usize = 256 * 1024;

/// Pourquoi un envoi n'a pas eu de réponse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushFault {
    /// L'URL n'est pas `https://hôte[:443]/chemin`.
    BadUrl,
    /// Le nom ne résout vers aucune adresse publique.
    NoPublicAddress,
    /// La connexion, TLS ou HTTP/2 a échoué, ou n'a pas répondu à temps.
    Unreachable,
    /// Le pair n'a pas négocié HTTP/2.
    NotHttp2,
    /// Le pair a enfreint HTTP/2, ou la réponse ne tient pas dans ses bornes.
    Protocol,
}

/// Une réponse : son statut, et son corps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushResponse {
    /// Le statut HTTP.
    pub status: u16,
    /// Le corps, borné à [`RESPONSE_BODY_MAX`].
    pub body: Vec<u8>,
}

/// Le transport : un résolveur, des autorités, un délai.
#[derive(Clone)]
pub struct PushTransport {
    resolveur: Resolver,
    tls: Arc<rustls::ClientConfig>,
    delai: Duration,
}

impl core::fmt::Debug for PushTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PushTransport")
            .field("delai", &self.delai)
            .finish_non_exhaustive()
    }
}

impl PushTransport {
    /// Un transport qui vérifie les certificats contre `ancres`.
    #[must_use]
    pub fn new(resolveur: Resolver, ancres: Arc<rustls::RootCertStore>, delai: Duration) -> Self {
        Self {
            resolveur,
            tls: Arc::new(config_h2(ancres)),
            delai,
        }
    }

    /// Envoie un `POST` à cette URL, et rend la réponse.
    ///
    /// `fields` sont les champs de la requête, noms en minuscules.
    ///
    /// # Errors
    ///
    /// [`PushFault`].
    pub async fn post(
        &self,
        url: &str,
        fields: &[(&[u8], &[u8])],
        body: &[u8],
    ) -> Result<PushResponse, PushFault> {
        let (hote, chemin) = decouper(url).ok_or(PushFault::BadUrl)?;
        let adresse = self
            .resolveur
            .addresses(hote.as_bytes())
            .await
            .into_iter()
            .find(|adresse| is_public(*adresse))
            .ok_or(PushFault::NoPublicAddress)?;
        echanger(
            &self.tls,
            self.delai,
            SocketAddr::new(adresse, 443),
            hote,
            chemin,
            fields,
            body,
        )
        .await
    }
}

/// La configuration TLS : vérifiante, TLS 1.3, post-quantique en tête, et
/// `h2` par ALPN.
fn config_h2(ancres: Arc<rustls::RootCertStore>) -> rustls::ClientConfig {
    let mut config = ams_tls::webpki_config(ancres);
    config.alpn_protocols = ams_tls::alpn();
    config
}

/// `https://hôte[:443]/chemin` → (hôte, chemin).
fn decouper(url: &str) -> Option<(&str, &str)> {
    let reste = url.strip_prefix("https://")?;
    let barre = reste.find('/')?;
    let (autorite, chemin) = reste.split_at(barre);
    let hote = match autorite.split_once(':') {
        Some((hote, "443")) => hote,
        Some(_) => return None,
        None => autorite,
    };
    (!hote.is_empty()).then_some((hote, chemin))
}

/// Une adresse que le serveur a le droit de contacter pour le compte d'un
/// abonné : ni privée, ni locale, ni réservée.
#[must_use]
pub fn is_public(adresse: IpAddr) -> bool {
    match adresse {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                // 0.0.0.0/8, 100.64.0.0/10 (CGNAT), 192.0.0.0/24,
                // 198.18.0.0/15 (bancs d'essai), 240.0.0.0/4 (réservé).
                || a == 0
                || (a == 100 && (64..128).contains(&b))
                || (a == 192 && b == 0 && v4.octets()[2] == 0)
                || (a == 198 && (b == 18 || b == 19))
                || a >= 240)
        }
        IpAddr::V6(v6) => {
            // Une adresse IPv4 déguisée se juge comme IPv4.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let premier = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                // 2001:db8::/32 (documentation), 64:ff9b::/96 (NAT64, qui
                // mènerait vers n'importe quelle adresse IPv4).
                || (premier == 0x2001 && v6.segments()[1] == 0x0db8)
                || premier == 0x0064)
        }
    }
}

/// Un échange entier, vers une adresse DÉJÀ VÉRIFIÉE.
pub(crate) async fn echanger(
    tls: &Arc<rustls::ClientConfig>,
    delai: Duration,
    adresse: SocketAddr,
    hote: &str,
    chemin: &str,
    fields: &[(&[u8], &[u8])],
    body: &[u8],
) -> Result<PushResponse, PushFault> {
    let injoignable = |_| PushFault::Unreachable;
    let nom = ServerName::try_from(hote.to_owned()).map_err(|_| PushFault::BadUrl)?;
    let flux = timeout(delai, TcpStream::connect(adresse))
        .await
        .map_err(injoignable)?
        .map_err(|_| PushFault::Unreachable)?;
    let mut chiffre = timeout(
        delai,
        TlsConnector::from(Arc::clone(tls)).connect(nom, flux),
    )
    .await
    .map_err(injoignable)?
    .map_err(|_| PushFault::Unreachable)?;
    if chiffre.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
        return Err(PushFault::NotHttp2);
    }

    let mut client = Box::new(ams_proto_h2::Client::new());
    let requete = ams_proto_h2::Request {
        method: b"POST",
        authority: hote.as_bytes(),
        path: chemin.as_bytes(),
        fields,
        body,
    };
    let mut sortie =
        vec![0_u8; ams_proto_h2::START_OCTETS_MAX.max(body.len().saturating_add(64 * 1024))];
    let debut = client
        .start(&requete, &mut sortie)
        .map_err(|_| PushFault::Protocol)?;
    ecrire(&mut chiffre, sortie.get(..debut).unwrap_or_default(), delai).await?;

    let mut recu: Vec<u8> = Vec::new();
    let mut reponse = vec![0_u8; RESPONSE_BODY_MAX];
    let mut morceau = [0_u8; 16 * 1024];
    loop {
        let lus = timeout(delai, chiffre.read(&mut morceau))
            .await
            .map_err(injoignable)?
            .map_err(|_| PushFault::Unreachable)?;
        if lus == 0 {
            return Err(PushFault::Unreachable);
        }
        recu.extend_from_slice(morceau.get(..lus).unwrap_or_default());
        if recu.len() > RECU_MAX {
            return Err(PushFault::Protocol);
        }
        let progres = client
            .receive(&recu, body, &mut sortie, &mut reponse)
            .map_err(|_| PushFault::Protocol)?;
        recu.drain(..progres.consumed);
        ecrire(
            &mut chiffre,
            sortie.get(..progres.written).unwrap_or_default(),
            delai,
        )
        .await?;
        if progres.done {
            break;
        }
    }
    let status = client.status().ok_or(PushFault::Protocol)?;
    reponse.truncate(client.body_len());
    Ok(PushResponse {
        status,
        body: reponse,
    })
}

/// Écrit, dans le délai.
async fn ecrire<S>(flux: &mut S, octets: &[u8], delai: Duration) -> Result<(), PushFault>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    if octets.is_empty() {
        return Ok(());
    }
    timeout(delai, async {
        flux.write_all(octets).await?;
        flux.flush().await
    })
    .await
    .map_err(|_| PushFault::Unreachable)?
    .map_err(|_| PushFault::Unreachable)
}

#[cfg(test)]
mod tests;
