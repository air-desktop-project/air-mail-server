//! La remise SORTANTE : trouver le serveur d'un domaine, et lui parler.
//!
//! # C'est le premier endroit où ce serveur PARLE À UN INCONNU
//!
//! Jusqu'ici, tout venait à lui : des pairs frappaient à la porte, et il
//! répondait. Émettre inverse la relation, et avec elle toutes les questions de
//! confiance. **Le serveur qu'on va joindre est désigné par le destinataire** —
//! c'est-à-dire par quiconque publie un `MX` — et ce qu'il répondra est une
//! entrée hostile comme une autre.
//!
//! # Trois refus qui ont l'air d'être le même, et qui ne le sont pas
//!
//! - **`4yz`** : réessayer plus tard a un sens. Jeter le message ici, c'est
//!   perdre du courrier qui serait passé.
//! - **`5yz`** : réessayer n'en a aucun. Insister, c'est harceler un serveur qui
//!   a dit non, et remplir une file qui ne se videra jamais.
//! - **Le `MX` nul** (RFC 7505) : le domaine déclare ne recevoir AUCUN courrier.
//!   C'est un refus définitif publié à l'avance, et le confondre avec une panne
//!   ferait réessayer des jours durant ce qu'un domaine a explicitement fermé.
//!
//! # LE CHIFFREMENT EST OPPORTUNISTE, ET IL N'AUTHENTIFIE PERSONNE
//!
//! Voir `ams_tls::relay_config` : le `MX` vient d'un DNS non validé, et vérifier
//! un certificat contre un nom qu'un attaquant vient de choisir ne prouverait
//! rien. Ce qui est acquis est réel et limité — un espion passif ne lit plus
//! rien — et ce qui ne l'est pas est écrit plutôt que tu.
//!
//! **Le repli, lui, n'est pas opportuniste** : un serveur qui annonce `STARTTLS`
//! puis refuse la poignée de main ne nous fera pas parler en clair. C'est
//! exactement le levier d'une attaque par déclassement.

use core::time::Duration;
use std::net::SocketAddr;
use std::string::{String, ToString as _};
use std::sync::Arc;
use std::vec::Vec;

use ams_proto_smtp::{Limits, Reply, Stuffer, reply_len, stuffed_max};
use ams_session::{CLIENT_COMMAND_MAX, ClientConfig, ClientOutcome, ClientStep, SmtpClient};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::connection::lire;
use crate::resolver::{Mx, Resolver};

/// Le port de la remise entre serveurs (RFC 5321 §4.1.1).
///
/// **Ce n'est pas 587**, qui est celui de la SOUMISSION — là où un humain
/// authentifié dépose son courrier. Les confondre ferait frapper à une porte qui
/// exige une authentification qu'on n'a pas.
pub const SMTP_PORT: u16 = 25;

/// Ce qu'une remise a donné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayOutcome {
    /// Le message est parti, et le pair l'a pris en charge.
    Delivered {
        /// Destinataires acceptés.
        accepted: usize,
        /// Destinataires refusés — la remise a eu lieu pour les autres.
        refused: usize,
        /// La conversation était-elle chiffrée ?
        encrypted: bool,
    },
    /// Refus **définitif**. Ne pas réessayer.
    Rejected(u16),
    /// Refus **temporaire**. Réessayer plus tard.
    Deferred(u16),
    /// Le domaine déclare ne recevoir aucun courrier (RFC 7505). Définitif.
    NullMx,
    /// Aucun serveur n'a pu être joint. **Temporaire** : une panne de réseau
    /// n'est pas un refus, et la traiter comme tel perdrait du courrier.
    Unreachable,
    /// Le pair ne sait pas chiffrer, et on l'exigeait.
    NoEncryption,
    /// Ce que le pair a dit n'est pas du SMTP, ou pas à cet endroit.
    Protocol,
    /// Le message ou une adresse ne peut pas être émis tel quel.
    ///
    /// Un `LF` isolé dans le corps, un `CRLF` dans une adresse : ce sont des
    /// fautes **de notre côté**, et les envoyer serait pire que de les voir.
    Unsendable,
}

/// Un message à remettre.
#[derive(Debug, Clone, Copy)]
pub struct Outgoing<'a> {
    /// L'expéditeur d'enveloppe. **Vide vaut `<>`**.
    pub sender: &'a str,
    /// Les destinataires, chez le même domaine.
    pub recipients: &'a [String],
    /// Le message, en-têtes compris, lignes terminées par `CRLF`.
    pub body: &'a [u8],
}

/// De quoi remettre du courrier à d'autres serveurs.
#[derive(Debug, Clone)]
pub struct Relay {
    resolveur: Resolver,
    tls: Arc<rustls::ClientConfig>,
    /// Le nom qu'on annonce à l'`EHLO`.
    nom: String,
    /// Le port où l'on frappe. Toujours 25, sauf sous test.
    port: u16,
    /// Exige-t-on le chiffrement ?
    exige_tls: bool,
    /// Le temps accordé à chaque lecture.
    delai: Duration,
}

impl Relay {
    /// Prépare un remetteur.
    #[must_use]
    pub fn new(
        resolveur: Resolver,
        tls: Arc<rustls::ClientConfig>,
        nom: String,
        exige_tls: bool,
        delai: Duration,
    ) -> Self {
        Self {
            resolveur,
            tls,
            nom,
            port: SMTP_PORT,
            exige_tls,
            delai,
        }
    }

    /// Change le port. **Réservé aux tests** : en production c'est 25, et un
    /// autre port ne joindrait personne.
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Remet un message au domaine d'un destinataire.
    ///
    /// # L'ordre des serveurs est celui du domaine, pas le nôtre
    ///
    /// On essaie les `MX` par préférence croissante, et pour chacun toutes ses
    /// adresses. **Un refus arrête la tournée** : un `5yz` du premier serveur
    /// n'est pas une invitation à demander au suivant s'il est plus complaisant.
    /// Seul ce qui n'a pas abouti — machine injoignable — fait passer au suivant.
    pub async fn send(&self, domaine: &str, message: &Outgoing<'_>) -> RelayOutcome {
        let serveurs = match self.resolveur.mx(domaine.as_bytes()).await {
            Mx::Trouves(serveurs) => serveurs
                .into_iter()
                .map(|(_, nom)| String::from_utf8_lossy(&nom).into_owned())
                .collect(),
            // RFC 5321 §5.1 : sans `MX`, c'est le nom lui-même qui reçoit.
            Mx::Absent => std::vec![domaine.to_string()],
            Mx::Nul => return RelayOutcome::NullMx,
            Mx::Panne => return RelayOutcome::Unreachable,
        };

        let mut issue = RelayOutcome::Unreachable;
        for hote in &serveurs {
            for adresse in self.resolveur.addresses(hote.as_bytes()).await {
                issue = self
                    .send_to(hote, SocketAddr::new(adresse, self.port), message)
                    .await;
                if issue != RelayOutcome::Unreachable {
                    return issue;
                }
            }
        }
        issue
    }

    /// Remet un message à un serveur nommé, à une adresse donnée.
    ///
    /// `hote` sert au `SNI` de la poignée de main ; l'adresse dit où frapper.
    /// Les séparer permet d'essayer chaque adresse d'un même nom, et c'est aussi
    /// ce qui rend cette fonction éprouvable sans DNS.
    pub async fn send_to(
        &self,
        hote: &str,
        adresse: SocketAddr,
        message: &Outgoing<'_>,
    ) -> RelayOutcome {
        let Some(corps) = farcir(message.body) else {
            return RelayOutcome::Unsendable;
        };
        let destinataires: Vec<&[u8]> = message
            .recipients
            .iter()
            .map(|adresse| adresse.as_bytes())
            .collect();
        let Ok(mut client) = SmtpClient::new(ClientConfig {
            name: self.nom.as_bytes(),
            sender: message.sender.as_bytes(),
            recipients: &destinataires,
            require_tls: self.exige_tls,
        }) else {
            return RelayOutcome::Unsendable;
        };

        let Ok(Ok(mut flux)) = timeout(self.delai, TcpStream::connect(adresse)).await else {
            return RelayOutcome::Unreachable;
        };
        let mut tampon = Vec::new();
        match self
            .dialoguer(&mut flux, &mut client, &corps, &mut tampon)
            .await
        {
            Suite::Fini(issue) => issue,
            Suite::Monter => self.monter(flux, hote, &mut client, &corps, tampon).await,
        }
    }

    /// Monte en chiffrement, puis reprend la conversation.
    async fn monter(
        &self,
        flux: TcpStream,
        hote: &str,
        client: &mut SmtpClient<'_>,
        corps: &[u8],
        mut tampon: Vec<u8>,
    ) -> RelayOutcome {
        let Ok(nom) = ServerName::try_from(hote.to_string()) else {
            // Un `MX` qui n'est pas un nom de domaine ne se joint pas en TLS, et
            // l'on ne se rabat pas sur le clair pour autant.
            return RelayOutcome::NoEncryption;
        };
        let connecteur = TlsConnector::from(Arc::clone(&self.tls));
        let Ok(Ok(mut chiffre)) = timeout(self.delai, connecteur.connect(nom, flux)).await else {
            // LA POIGNÉE DE MAIN A ÉCHOUÉ APRÈS UN `STARTTLS` ACCEPTÉ. On ne
            // recommence pas en clair : un échec qu'un tiers peut provoquer
            // serait alors le levier d'un déclassement.
            return RelayOutcome::NoEncryption;
        };

        let mut sortie = [0_u8; CLIENT_COMMAND_MAX];
        let geste = match client.on_secured(&mut sortie) {
            Ok(ClientStep::Send(ecrits)) => ecrits,
            // `on_secured` n'écrit qu'un `EHLO` dans un tampon dimensionné pour
            // lui : le seul autre chemin est un tampon trop court, qui n'existe
            // pas ici.
            _ => return RelayOutcome::Protocol,
        };
        if chiffre
            .write_all(sortie.get(..geste).unwrap_or_default())
            .await
            .is_err()
            || chiffre.flush().await.is_err()
        {
            return RelayOutcome::Unreachable;
        }

        match self
            .dialoguer(&mut chiffre, client, corps, &mut tampon)
            .await
        {
            Suite::Fini(issue) => issue,
            // On ne monte pas deux fois : `SmtpClient` n'offre `STARTTLS` que
            // tant que la conversation est en clair.
            Suite::Monter => RelayOutcome::Protocol,
        }
    }

    /// Conduit la conversation jusqu'à son terme, ou jusqu'au chiffrement.
    async fn dialoguer<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        flux: &mut S,
        client: &mut SmtpClient<'_>,
        corps: &[u8],
        tampon: &mut Vec<u8>,
    ) -> Suite {
        let mut lecture = std::vec![0_u8; 4096];
        loop {
            let longueur = match self.attendre(flux, tampon, &mut lecture).await {
                Ok(longueur) => longueur,
                Err(issue) => return Suite::Fini(issue),
            };
            let mut sortie = [0_u8; CLIENT_COMMAND_MAX];
            let geste = {
                let Ok(reponse) =
                    Reply::parse(tampon.get(..longueur).unwrap_or_default(), &Limits::DEFAULT)
                else {
                    return Suite::Fini(RelayOutcome::Protocol);
                };
                match client.on_reply(&reponse, &mut sortie) {
                    Ok(geste) => geste,
                    Err(_) => return Suite::Fini(RelayOutcome::Protocol),
                }
            };
            tampon.drain(..longueur.min(tampon.len()));

            match geste {
                ClientStep::Send(ecrits) => {
                    if ecrire(flux, sortie.get(..ecrits).unwrap_or_default())
                        .await
                        .is_err()
                    {
                        return Suite::Fini(RelayOutcome::Unreachable);
                    }
                }
                ClientStep::Secure => return Suite::Monter,
                ClientStep::SendBody => {
                    if ecrire(flux, corps).await.is_err() {
                        return Suite::Fini(RelayOutcome::Unreachable);
                    }
                }
                ClientStep::Done { sent, outcome } => {
                    // LE `QUIT` PART, ET L'ON N'ATTEND PAS SA RÉPONSE : elle
                    // n'apprend rien, et l'attendre offrirait à un pair muet de
                    // nous retenir une connexion aussi longtemps qu'il lui plaît.
                    let _ = ecrire(flux, sortie.get(..sent).unwrap_or_default()).await;
                    return Suite::Fini(issue_du_client(outcome, client));
                }
            }
        }
    }

    /// Lit jusqu'à tenir une réponse entière, et rend sa longueur.
    async fn attendre<S: AsyncRead + Unpin>(
        &self,
        flux: &mut S,
        tampon: &mut Vec<u8>,
        lecture: &mut [u8],
    ) -> Result<usize, RelayOutcome> {
        loop {
            match reply_len(tampon, &Limits::DEFAULT) {
                Ok(Some(longueur)) => return Ok(longueur),
                Ok(None) => {}
                // Une réponse qui n'en est pas une, ou qui n'en finit pas.
                Err(_) => return Err(RelayOutcome::Protocol),
            }
            let lus = lire(flux, lecture, self.delai)
                .await
                .map_err(|_| RelayOutcome::Unreachable)?;
            if lus == 0 {
                // Le pair a raccroché au milieu d'une réponse. Ce n'est pas un
                // refus : on n'a pas de code, donc pas de raison de renoncer.
                return Err(RelayOutcome::Unreachable);
            }
            tampon.extend_from_slice(lecture.get(..lus).unwrap_or_default());
        }
    }
}

/// Où en est la conversation quand `dialoguer` rend la main.
enum Suite {
    /// C'est terminé.
    Fini(RelayOutcome),
    /// Il faut monter en chiffrement, puis reprendre.
    Monter,
}

/// Traduit l'issue de la session en issue de remise.
fn issue_du_client(outcome: ClientOutcome, client: &SmtpClient<'_>) -> RelayOutcome {
    match outcome {
        ClientOutcome::Delivered => RelayOutcome::Delivered {
            accepted: client.accepted(),
            refused: client.refused(),
            encrypted: client.is_encrypted(),
        },
        ClientOutcome::Rejected(code) => RelayOutcome::Rejected(code.value()),
        ClientOutcome::Deferred(code) => RelayOutcome::Deferred(code.value()),
        ClientOutcome::NoEncryption => RelayOutcome::NoEncryption,
        ClientOutcome::Unexpected(_) => RelayOutcome::Protocol,
    }
}

/// Point-farcit un corps, une fois pour toutes.
fn farcir(corps: &[u8]) -> Option<Vec<u8>> {
    let mut sortie = std::vec![0_u8; stuffed_max(corps.len())];
    let mut plume = Stuffer::new();
    let ecrits = plume.push(corps, &mut sortie).ok()?;
    let fin = plume.finish(sortie.get_mut(ecrits..)?).ok()?;
    sortie.truncate(ecrits.saturating_add(fin));
    Some(sortie)
}

/// Écrit et pousse, en une fois.
async fn ecrire<S: AsyncWrite + Unpin>(flux: &mut S, octets: &[u8]) -> std::io::Result<()> {
    flux.write_all(octets).await?;
    flux.flush().await
}
