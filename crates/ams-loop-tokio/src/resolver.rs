//! Le transport DNS : poser une question, attendre une réponse.
//!
//! # Pourquoi il vit à part
//!
//! SPF (C9) et DKIM (C9) posent des questions au DNS. Ce ne sont pas les mêmes
//! questions — l'un veut des politiques et des adresses, l'autre une clé
//! publique — mais c'est le même fil, le même délai, la même défense contre qui
//! voudrait répondre à notre place. Deux copies de ce transport finiraient par
//! diverger, et la première qui divergerait serait celle qu'on ne relit plus.
//!
//! # L'identifiant d'une requête vient de `/dev/urandom`
//!
//! Un identifiant prévisible laisse un tiers répondre à notre place : il lui
//! suffit d'envoyer sa réponse avant le vrai serveur. Deux défenses se cumulent
//! ici et ne coûtent presque rien : **un identifiant tiré de `/dev/urandom`** et
//! **un port source neuf par question** — une socket par requête, dont le noyau
//! choisit le port. Trente-deux bits à deviner valent mieux que seize.
//!
//! Ce n'est pas DNSSEC, et cela ne prétend pas l'être : un résolveur joint par
//! un réseau hostile reste un résolveur qu'on croit sur parole. **Le résolveur
//! doit être local, ou joint par un lien de confiance** — la configuration le
//! dit, et le serveur le répète au démarrage.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ams_dns::{Kind, Message, QUERY_MAX, Status, encode_query};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpStream, UdpSocket};

/// La plus grande réponse qu'on accepte de lire, en TCP comme en UDP.
///
/// Un serveur peut en principe rendre 65 535 octets. On n'en veut pas : une
/// politique SPF comme une clé DKIM tiennent dans un enregistrement, et lire un
/// mégaoctet par question offrirait à qui contrôle une zone de faire allouer ce
/// qu'il veut.
const REPONSE_MAX: usize = 4096;

/// De quoi poser des questions au DNS.
#[derive(Clone)]
pub struct Resolver {
    serveurs: Arc<[SocketAddr]>,
    delai: Duration,
    alea: Arc<Alea>,
}

impl Resolver {
    /// Prépare un résolveur.
    ///
    /// # Errors
    ///
    /// Si la liste est vide, ou si `/dev/urandom` ne s'ouvre pas. **On ne se
    /// rabat sur rien** : un identifiant prévisible est une faiblesse
    /// silencieuse, et refuser de démarrer la rend visible.
    pub fn new(serveurs: Vec<SocketAddr>, delai: Duration) -> io::Result<Self> {
        if serveurs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "aucun résolveur : il n'y aurait personne à qui demander",
            ));
        }
        Ok(Self {
            serveurs: serveurs.into(),
            delai,
            alea: Arc::new(Alea::ouvrir()?),
        })
    }

    /// Les résolveurs interrogés, dans l'ordre.
    #[must_use]
    pub fn servers(&self) -> &[SocketAddr] {
        &self.serveurs
    }

    /// Le temps accordé à une question.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.delai
    }

    /// Les `TXT` d'un nom, chaînes recollées.
    ///
    /// **RFC 6376 §3.6.2.1 comme RFC 7208 §3.3 veulent qu'on les concatène SANS
    /// séparateur** : un enregistrement de plus de 255 octets — une clé DKIM de
    /// 2048 bits en fait 400 — arrive en plusieurs chaînes, et les joindre par
    /// une espace en ferait autre chose.
    pub(crate) async fn txt(&self, nom: &[u8]) -> Txt {
        let octets = match self.interroger(nom, Kind::Txt).await {
            Issue::Reponse(octets) => octets,
            Issue::Absent => return Txt::Absent,
            Issue::Panne => return Txt::Panne,
        };
        let Ok(message) = Message::parse(&octets) else {
            return Txt::Panne;
        };
        let trouves: Vec<Vec<u8>> = message
            .answers()
            .filter(|enregistrement| enregistrement.kind() == Kind::Txt.code())
            .map(|enregistrement| enregistrement.strings().flatten().copied().collect())
            .collect();
        if trouves.is_empty() {
            return Txt::Absent;
        }
        Txt::Trouves(trouves)
    }

    pub(crate) async fn interroger(&self, nom: &[u8], kind: Kind) -> Issue {
        let mut derniere = Issue::Panne;
        for serveur in self.serveurs.iter() {
            derniere = self.interroger_un(*serveur, nom, kind).await;
            // Un serveur qui répond — même « ce nom n'existe pas » — a répondu.
            // On ne demande pas au suivant : deux résolveurs qui ne disent pas
            // la même chose ne se départagent pas en prenant celui qui plaît.
            if !matches!(derniere, Issue::Panne) {
                return derniere;
            }
        }
        derniere
    }

    async fn interroger_un(&self, serveur: SocketAddr, nom: &[u8], kind: Kind) -> Issue {
        let Ok(id) = self.alea.identifiant().await else {
            return Issue::Panne;
        };
        let mut tampon = [0_u8; QUERY_MAX];
        let Ok(question) = encode_query(&mut tampon, id, nom, kind) else {
            // Un nom qu'on ne sait pas écrire n'est pas une panne du réseau :
            // c'est un nom qui ne désigne rien. SPF le comptera comme vide.
            return Issue::Absent;
        };
        let echeance = tokio::time::Instant::now()
            .checked_add(self.delai)
            .unwrap_or_else(tokio::time::Instant::now);
        let reponse = tokio::time::timeout_at(echeance, self.echanger(serveur, question, id)).await;
        let Ok(Ok(octets)) = reponse else {
            return Issue::Panne;
        };
        let Ok(message) = Message::parse(&octets) else {
            return Issue::Panne;
        };
        if message.truncated() {
            // RFC 1035 §4.2.1 : ce qui est arrivé NE S'UTILISE PAS. On reprend
            // en TCP, où la réponse tient entière.
            let reprise = tokio::time::timeout_at(echeance, self.reprendre(serveur, question, id));
            let Ok(Ok(octets)) = reprise.await else {
                return Issue::Panne;
            };
            return issue_du_message(octets);
        }
        issue_du_message(octets)
    }

    /// Un aller-retour UDP, avec une socket neuve — donc un port source neuf.
    async fn echanger(&self, serveur: SocketAddr, question: &[u8], id: u16) -> io::Result<Vec<u8>> {
        let locale = match serveur {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let socket = UdpSocket::bind(locale).await?;
        // `connect` fait REFUSER PAR LE NOYAU tout datagramme d'une autre
        // source. C'est la moitié gratuite de la défense contre l'injection.
        socket.connect(serveur).await?;
        socket.send(question).await?;
        let mut recu = vec![0_u8; REPONSE_MAX];
        loop {
            let lus = socket.recv(&mut recu).await?;
            let arrivee = recu.get(..lus).unwrap_or_default();
            // UN IDENTIFIANT QUI NE CORRESPOND PAS N'EST PAS UNE RÉPONSE. On
            // continue d'écouter jusqu'au délai plutôt que d'abandonner : celui
            // qui injecte n'a pas gagné en arrivant le premier.
            if Message::parse(arrivee).is_ok_and(|message| message.id() == id) {
                return Ok(arrivee.to_vec());
            }
        }
    }

    /// La reprise en TCP (RFC 1035 §4.2.2) : deux octets de longueur, puis le
    /// message.
    async fn reprendre(
        &self,
        serveur: SocketAddr,
        question: &[u8],
        id: u16,
    ) -> io::Result<Vec<u8>> {
        let mut flux = TcpStream::connect(serveur).await?;
        let longueur = u16::try_from(question.len()).unwrap_or(u16::MAX);
        flux.write_all(&longueur.to_be_bytes()).await?;
        flux.write_all(question).await?;
        flux.flush().await?;

        let mut entete = [0_u8; 2];
        flux.read_exact(&mut entete).await?;
        let annoncee = usize::from(u16::from_be_bytes(entete));
        if annoncee > REPONSE_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "réponse plus longue que ce qu'on accepte de lire",
            ));
        }
        let mut recu = vec![0_u8; annoncee];
        flux.read_exact(&mut recu).await?;
        if !Message::parse(&recu).is_ok_and(|message| message.id() == id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "la réponse ne répond pas à la question posée",
            ));
        }
        Ok(recu)
    }
}

impl core::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // On nomme les résolveurs et le délai — ce qu'un administrateur veut
        // relire — et rien de la source d'aléa : un descripteur de fichier
        // n'apprend rien à personne, et ce qu'il rend ne doit apparaître nulle
        // part.
        f.debug_struct("Resolver")
            .field("serveurs", &self.serveurs)
            .field("delai", &self.delai)
            .finish_non_exhaustive()
    }
}

/// Ce qu'une question `TXT` a rendu.
pub(crate) enum Txt {
    /// Un enregistrement par réponse, chaînes recollées.
    Trouves(Vec<Vec<u8>>),
    /// Le nom n'existe pas, ou ne porte pas de `TXT`.
    Absent,
    /// On n'a pas su demander, ou pas su lire.
    Panne,
}

/// Ce qu'un résolveur a répondu.
pub(crate) enum Issue {
    /// Un message exploitable.
    Reponse(Vec<u8>),
    /// Le nom n'existe pas. **C'est une réponse.**
    Absent,
    /// On n'a pas su demander, ou on n'a pas su lire.
    Panne,
}

fn issue_du_message(octets: Vec<u8>) -> Issue {
    let statut = Message::parse(&octets).map_or(Status::ServerFailure, |message| message.status());
    match statut {
        Status::NoError => Issue::Reponse(octets),
        // « Ce nom n'existe pas » est une réponse, que SPF compte comme une
        // résolution vide (RFC 7208 §4.6.4).
        Status::NameError => Issue::Absent,
        Status::ServerFailure | Status::Other(_) => Issue::Panne,
    }
}

/// La source d'aléa des identifiants de requête.
///
/// **Le fichier s'ouvre au démarrage**, pas à la première question : un serveur
/// qui découvrirait à la première connexion qu'il n'a pas d'aléa n'aurait plus
/// que de mauvaises options.
struct Alea {
    source: tokio::sync::Mutex<tokio::fs::File>,
}

impl Alea {
    fn ouvrir() -> io::Result<Self> {
        let fichier = std::fs::File::open("/dev/urandom")?;
        Ok(Self {
            source: tokio::sync::Mutex::new(tokio::fs::File::from_std(fichier)),
        })
    }

    /// Seize bits imprévisibles.
    ///
    /// # Errors
    ///
    /// Si la lecture échoue. **On ne se rabat sur aucune valeur** : un
    /// identifiant prévisible est exactement ce qu'attend celui qui veut
    /// répondre à notre place, et une question qu'on ne sait pas poser
    /// sûrement vaut mieux non posée.
    async fn identifiant(&self) -> io::Result<u16> {
        let mut octets = [0_u8; 2];
        let mut source = self.source.lock().await;
        source.read_exact(&mut octets).await?;
        Ok(u16::from_be_bytes(octets))
    }
}

#[cfg(test)]
mod tests;
