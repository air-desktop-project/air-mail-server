//! La résolution des questions que SPF pose (C9).
//!
//! # C'est ICI que le DNS est parlé, et nulle part ailleurs
//!
//! `ams-spf` conduit l'évaluation sans résoudre quoi que ce soit : il rend des
//! **questions**. Ce module y répond, et c'est tout ce qu'il fait — il ne décide
//! d'aucun verdict, il n'écrit aucune réponse SMTP. Le partage est celui de C1 :
//! ce qui attend vit à l'étage 3, ce qui décide vit à l'étage 2.
//!
//! # Ce qu'une question recouvre, et pourquoi c'est ici que ça se déplie
//!
//! `MxAddresses` veut « les adresses des serveurs de courrier de ce domaine » :
//! une résolution `MX`, puis une résolution d'adresses par serveur rendu. La RFC
//! 7208 §4.6.4 compte tout cela comme **une seule** des dix résolutions, et
//! borne séparément ce qui se déplie : **dix enregistrements `MX` au plus, dix
//! noms au plus** pour une résolution inverse. Ces deux bornes-là sont tenues
//! ici, parce que c'est ici qu'on sait combien de messages sont partis.
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

use ams_dns::{Kind, Message, Name, QUERY_MAX, Status, encode_query};
use ams_session::SenderIdentity;
use ams_spf::{Answer, Context, Evaluator, Limits, Query, Step, Verdict};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpStream, UdpSocket};

/// Le nombre d'enregistrements `MX` qu'on déplie (RFC 7208 §4.6.4).
const MX_MAX: usize = 10;

/// Le nombre de noms qu'on retient d'une résolution inverse (§4.6.4).
const PTR_MAX: usize = 10;

/// La plus grande réponse qu'on accepte de lire, en TCP comme en UDP.
///
/// Un serveur peut en principe rendre 65 535 octets. On n'en veut pas : une
/// politique SPF tient dans un enregistrement, et lire un mégaoctet par question
/// offrirait à qui contrôle une zone de faire allouer ce qu'il veut.
const REPONSE_MAX: usize = 4096;

/// De quoi répondre aux questions de SPF.
///
/// Le `Debug` nomme les résolveurs et le délai — ce qu'un administrateur veut
/// relire — et rien de la source d'aléa : un descripteur de fichier n'apprend
/// rien à personne, et ce qu'il rend ne doit apparaître nulle part.
#[derive(Clone)]
pub struct SenderChecker {
    serveurs: Arc<[SocketAddr]>,
    delai: Duration,
    alea: Arc<Alea>,
}

impl SenderChecker {
    /// Prépare un vérificateur.
    ///
    /// # Errors
    ///
    /// Si la liste de résolveurs est vide, ou si `/dev/urandom` ne s'ouvre pas.
    /// **On ne se rabat sur rien** : un identifiant prévisible est une faiblesse
    /// silencieuse, et refuser de démarrer la rend visible.
    pub fn new(serveurs: Vec<SocketAddr>, delai: Duration) -> io::Result<Self> {
        if serveurs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "aucun résolveur : SPF ne saurait rien demander",
            ));
        }
        Ok(Self {
            serveurs: serveurs.into(),
            delai,
            alea: Arc::new(Alea::ouvrir()?),
        })
    }

    /// Conduit une évaluation SPF jusqu'à son verdict.
    ///
    /// Ne rend jamais d'erreur : une résolution qui échoue vaut
    /// [`Verdict::TempError`], et c'est la session qui décide ce qu'elle en
    /// fait.
    pub async fn verdict(&self, client: IpAddr, identite: &SenderIdentity<'_>) -> Verdict {
        let contexte = Context {
            client,
            sender: identite.sender,
            helo: identite.helo,
        };
        let mut evaluateur = Evaluator::new(contexte, identite.domain, Limits::DEFAULT);
        loop {
            let question = match evaluateur.poll() {
                Step::Done(verdict) => return verdict,
                Step::Ask(question) => question,
            };
            let reponse = self
                .repondre(question.kind(), question.name(), client)
                .await;
            match &reponse {
                Reponse::Txt(textes) => {
                    let empruntes: Vec<&[u8]> = textes.iter().map(Vec::as_slice).collect();
                    evaluateur.answer(Answer::Txt(&empruntes));
                }
                Reponse::Adresses(adresses) => evaluateur.answer(Answer::Addresses(adresses)),
                Reponse::Noms(noms) => {
                    let empruntes: Vec<&[u8]> = noms.iter().map(Vec::as_slice).collect();
                    evaluateur.answer(Answer::Names(&empruntes));
                }
                Reponse::Existe(trouve) => evaluateur.answer(Answer::Exists(*trouve)),
                Reponse::Absent => evaluateur.answer(Answer::NotFound),
                Reponse::Panne => evaluateur.answer(Answer::TempError),
            }
        }
    }

    /// Répond à une question, en autant de résolutions qu'il faut.
    async fn repondre(&self, genre: Query, nom: &[u8], client: IpAddr) -> Reponse {
        match genre {
            Query::Txt => self.textes(nom).await,
            Query::Addresses => self.adresses(nom).await,
            Query::MxAddresses => self.adresses_des_mx(nom).await,
            Query::Exists => self.existe(nom).await,
            Query::PtrNames => self.noms_confirmes(client).await,
        }
    }

    /// Les `TXT` d'un nom, chaînes recollées.
    async fn textes(&self, nom: &[u8]) -> Reponse {
        let octets = match self.interroger(nom, Kind::Txt).await {
            Issue::Reponse(octets) => octets,
            Issue::Absent => return Reponse::Absent,
            Issue::Panne => return Reponse::Panne,
        };
        let Ok(message) = Message::parse(&octets) else {
            return Reponse::Panne;
        };
        let mut textes = Vec::new();
        for enregistrement in message.answers() {
            if enregistrement.kind() != Kind::Txt.code() {
                continue;
            }
            // RFC 7208 §3.3 : les chaînes se concatènent SANS séparateur. Les
            // joindre par une espace ferait une politique différente.
            let recollee: Vec<u8> = enregistrement.strings().flatten().copied().collect();
            textes.push(recollee);
        }
        if textes.is_empty() {
            return Reponse::Absent;
        }
        Reponse::Txt(textes)
    }

    /// Les adresses d'un nom, dans les deux familles.
    ///
    /// `A` **et** `AAAA` : un pair qui arrive en IPv6 ne correspondrait à rien
    /// si l'on n'interrogeait que les `A`, et la RFC 7208 §5.3 veut les deux.
    async fn adresses(&self, nom: &[u8]) -> Reponse {
        let mut adresses = Vec::new();
        let mut panne = false;
        let mut absent = 0_u8;
        for kind in [Kind::A, Kind::Aaaa] {
            match self.interroger(nom, kind).await {
                Issue::Reponse(octets) => match Message::parse(&octets) {
                    Ok(message) => adresses.extend(
                        message
                            .answers()
                            .filter(|enregistrement| enregistrement.kind() == kind.code())
                            .filter_map(|enregistrement| enregistrement.address()),
                    ),
                    Err(_) => panne = true,
                },
                Issue::Absent => absent = absent.saturating_add(1),
                Issue::Panne => panne = true,
            }
        }
        if !adresses.is_empty() {
            return Reponse::Adresses(adresses);
        }
        // AUCUNE ADRESSE, ET UNE PANNE : on ne conclut pas. Dire « ce nom n'a
        // pas d'adresse » alors qu'on n'a pas su demander ferait échouer un
        // mécanisme qui aurait correspondu.
        if panne {
            return Reponse::Panne;
        }
        Reponse::Absent
    }

    /// Les adresses des serveurs de courrier d'un nom.
    async fn adresses_des_mx(&self, nom: &[u8]) -> Reponse {
        let octets = match self.interroger(nom, Kind::Mx).await {
            Issue::Reponse(octets) => octets,
            Issue::Absent => return Reponse::Absent,
            Issue::Panne => return Reponse::Panne,
        };
        let Ok(message) = Message::parse(&octets) else {
            return Reponse::Panne;
        };
        let echanges: Vec<Name> = message
            .answers()
            .filter(|enregistrement| enregistrement.kind() == Kind::Mx.code())
            .filter_map(|enregistrement| enregistrement.exchange().ok())
            .map(|(_, nom)| nom)
            // DIX AU PLUS (RFC 7208 §4.6.4) : sans cette borne, une zone
            // hostile publie mille `MX` et fait faire mille résolutions.
            .take(MX_MAX)
            .collect();
        if echanges.is_empty() {
            return Reponse::Absent;
        }
        let mut adresses = Vec::new();
        let mut panne = false;
        for echange in echanges {
            match self.adresses(echange.as_bytes()).await {
                Reponse::Adresses(trouvees) => adresses.extend(trouvees),
                Reponse::Panne => panne = true,
                _ => {}
            }
        }
        if adresses.is_empty() && panne {
            return Reponse::Panne;
        }
        Reponse::Adresses(adresses)
    }

    /// Ce nom existe-t-il ? (RFC 7208 §5.7 : c'est l'existence qui répond.)
    async fn existe(&self, nom: &[u8]) -> Reponse {
        match self.interroger(nom, Kind::A).await {
            Issue::Reponse(octets) => match Message::parse(&octets) {
                Ok(message) => Reponse::Existe(
                    message
                        .answers()
                        .any(|enregistrement| enregistrement.kind() == Kind::A.code()),
                ),
                Err(_) => Reponse::Panne,
            },
            Issue::Absent => Reponse::Existe(false),
            Issue::Panne => Reponse::Panne,
        }
    }

    /// Les noms que la résolution inverse **confirme** (RFC 7208 §5.5).
    ///
    /// Un `PTR` ne prouve rien : il est publié par qui détient le bloc
    /// d'adresses, et il peut nommer n'importe quoi. La RFC exige donc de
    /// **revérifier en avant** — le nom rendu doit résoudre vers l'adresse du
    /// pair. Sans cela, qui contrôle une zone inverse se ferait passer pour
    /// n'importe quel domaine.
    async fn noms_confirmes(&self, client: IpAddr) -> Reponse {
        let inverse = nom_inverse(client);
        let octets = match self.interroger(inverse.as_bytes(), Kind::Ptr).await {
            Issue::Reponse(octets) => octets,
            Issue::Absent => return Reponse::Absent,
            Issue::Panne => return Reponse::Panne,
        };
        let Ok(message) = Message::parse(&octets) else {
            return Reponse::Panne;
        };
        let candidats: Vec<Name> = message
            .answers()
            .filter(|enregistrement| enregistrement.kind() == Kind::Ptr.code())
            .filter_map(|enregistrement| enregistrement.target().ok())
            .take(PTR_MAX)
            .collect();

        let mut confirmes = Vec::new();
        for candidat in candidats {
            if let Reponse::Adresses(adresses) = self.adresses(candidat.as_bytes()).await
                && adresses.contains(&client)
            {
                confirmes.push(candidat.as_bytes().to_vec());
            }
        }
        if confirmes.is_empty() {
            return Reponse::Absent;
        }
        Reponse::Noms(confirmes)
    }

    /// Pose une question à un résolveur, et rend ce qu'il répond.
    async fn interroger(&self, nom: &[u8], kind: Kind) -> Issue {
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

impl core::fmt::Debug for SenderChecker {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SenderChecker")
            .field("serveurs", &self.serveurs)
            .field("delai", &self.delai)
            .finish_non_exhaustive()
    }
}

/// Ce qu'un résolveur a répondu.
enum Issue {
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

/// Ce qu'on a fini par savoir, sous une forme que l'évaluateur emprunte.
enum Reponse {
    Txt(Vec<Vec<u8>>),
    Adresses(Vec<IpAddr>),
    Noms(Vec<Vec<u8>>),
    Existe(bool),
    Absent,
    Panne,
}

/// Le nom de la résolution inverse d'une adresse (RFC 1035 §3.5, RFC 3596 §2.5).
fn nom_inverse(client: IpAddr) -> String {
    match client {
        IpAddr::V4(adresse) => {
            let [a, b, c, d] = adresse.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa")
        }
        IpAddr::V6(adresse) => {
            let mut nom = String::with_capacity(72);
            for octet in adresse.octets().iter().rev() {
                nom.push(quartet(octet & 0x0F));
                nom.push('.');
                nom.push(quartet(octet >> 4));
                nom.push('.');
            }
            nom.push_str("ip6.arpa");
            nom
        }
    }
}

fn quartet(valeur: u8) -> char {
    char::from_digit(u32::from(valeur), 16).unwrap_or('0')
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
