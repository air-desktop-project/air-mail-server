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
    /// Le lien jusqu'aux résolveurs DISTANTS est-il déclaré de confiance ?
    ///
    /// La boucle locale n'a pas besoin de ce champ : rien ne peut se placer
    /// entre elle et nous.
    lien_declare: bool,
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
            // **NON DÉCLARÉ PAR DÉFAUT**, et le défaut va dans le sens sûr :
            // un appelant qui oublie de le dire PERD DANE sur un résolveur
            // distant, il n'ouvre pas une brèche. L'oubli inverse en ouvrirait
            // une.
            lien_declare: false,
        })
    }

    /// Déclare que le lien jusqu'aux résolveurs distants est de confiance.
    ///
    /// # CE QUE L'EXPLOITANT DÉCLARE ICI
    ///
    /// Qu'aucun tiers ne peut se placer entre ce serveur et ses résolveurs :
    /// un réseau privé, un tunnel, une machine voisine sur un lien qu'il
    /// maîtrise. §2.1 de RFC 7672 permet cette branche — c'est la seule autre
    /// que la validation DNSSEC en propre.
    ///
    /// **CE N'EST PAS UN RÉGLAGE DE CONFORT.** Il décide si le bit `AD` est
    /// cru, donc si DANE s'engage ; et DANE qui s'engage ÉCARTE MTA-STS.
    #[must_use]
    pub fn avec_lien_de_confiance(mut self, declare: bool) -> Self {
        self.lien_declare = declare;
        self
    }

    /// Ce résolveur-ci est-il joint par un canal de confiance ?
    ///
    /// **LA BOUCLE LOCALE L'EST SANS RIEN DÉCLARER.** Un résolveur sur
    /// `127.0.0.0/8` ou `::1` ne se joint par aucun réseau : il n'y a pas de
    /// chemin où se placer. Tout le reste demande une déclaration.
    #[must_use]
    fn de_confiance(&self, serveur: SocketAddr) -> bool {
        serveur.ip().is_loopback() || self.lien_declare
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

    /// Un octet imprévisible.
    ///
    /// La même source que les identifiants de requête : `/dev/urandom`, ouvert
    /// au démarrage. DMARC s'en sert pour le tirage de `pct=`.
    ///
    /// # Errors
    ///
    /// Si la lecture échoue.
    pub(crate) async fn octet(&self) -> io::Result<u8> {
        self.alea
            .identifiant()
            .await
            .map(|paire| u8::try_from(paire & 0xFF).unwrap_or(0))
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

    /// Les serveurs de courrier d'un domaine, du plus préféré au moins
    /// (RFC 5321 §5.1).
    ///
    /// # Le `MX` nul veut dire « n'écrivez pas ici » (RFC 7505)
    ///
    /// Un domaine qui publie **un seul** `MX`, de préférence zéro et de cible
    /// racine (`.`), déclare qu'il ne reçoit aucun courrier. Ce n'est pas une
    /// absence de `MX` : c'est un refus, et il vaut un échec DÉFINITIF. Le
    /// confondre avec une panne ferait réessayer pendant des jours ce qu'un
    /// domaine a explicitement fermé.
    /// Les `TLSA` d'un nom, et si la réponse était AUTHENTIFIÉE.
    ///
    /// # LE SECOND MEMBRE DÉCIDE DE TOUT
    ///
    /// Un `TLSA` lu dans une réponse non authentifiée ne vaut rien : un tiers
    /// qui détourne la résolution le retire, et l'on retomberait sur le
    /// chiffrement opportuniste en croyant être protégé. C'est le bit `AD` d'un
    /// résolveur valideur qui le dit — voir `ams_dns::Message::authentic_data`,
    /// qui dit aussi ce que ce bit vaut et ce qu'il ne vaut pas.
    ///
    /// **Une absence et une panne se rendent de la même façon** : un jeu vide et
    /// non authentifié. Les distinguer ne servirait à rien — dans les deux cas,
    /// DANE ne s'applique pas, et la remise est opportuniste.
    pub(crate) async fn tlsa(&self, nom: &[u8]) -> (Vec<Vec<u8>>, bool) {
        let Issue::Reponse(octets) = self.interroger(nom, Kind::Tlsa).await else {
            return (Vec::new(), false);
        };
        let Ok(message) = Message::parse(&octets) else {
            return (Vec::new(), false);
        };
        let records = message
            .answers()
            .filter(|enregistrement| enregistrement.kind() == Kind::Tlsa.code())
            .map(|enregistrement| enregistrement.rdata().to_vec())
            .collect();
        (records, message.authentic_data())
    }

    pub(crate) async fn mx(&self, domaine: &[u8]) -> Mx {
        let octets = match self.interroger(domaine, Kind::Mx).await {
            Issue::Reponse(octets) => octets,
            Issue::Absent => return Mx::Absent,
            Issue::Panne => return Mx::Panne,
        };
        let Ok(message) = Message::parse(&octets) else {
            return Mx::Panne;
        };
        // **L'AUTHENTICITÉ DU `MX` COMPTE AUTANT QUE CELLE DU `TLSA`** (§2.2 de
        // RFC 7672) : un `MX` qu'un tiers a pu réécrire désignerait un serveur
        // qu'il a choisi, dont le `TLSA` serait le sien. La chaîne doit être
        // signée d'un bout à l'autre, ou elle ne vaut rien.
        let authentique = message.authentic_data();
        let mut serveurs: Vec<(u16, Vec<u8>)> = message
            .answers()
            .filter(|enregistrement| enregistrement.kind() == Kind::Mx.code())
            .filter_map(|enregistrement| enregistrement.exchange().ok())
            .map(|(preference, nom)| (preference, nom.as_bytes().to_vec()))
            .collect();
        if serveurs.len() == 1
            && serveurs
                .first()
                .is_some_and(|(preference, nom)| *preference == 0 && nom.is_empty())
        {
            return Mx::Nul;
        }
        // Les cibles racines qui ne sont PAS seules s'écartent : elles ne
        // désignent aucune machine, et rien ne dit ce que leur auteur voulait.
        serveurs.retain(|(_, nom)| !nom.is_empty());
        if serveurs.is_empty() {
            return Mx::Absent;
        }
        // À préférence égale, la RFC 5321 §5.1 demande un ordre ALÉATOIRE, pour
        // répartir la charge entre serveurs équivalents. On s'en tient à l'ordre
        // du serveur : mélanger demanderait de l'aléa à chaque remise, et
        // l'équilibrage d'un serveur qui n'émet que des rapports n'intéresse
        // personne.
        serveurs.sort_by_key(|(preference, _)| *preference);
        Mx::Trouves {
            serveurs,
            authentique,
        }
    }

    /// Les adresses d'un nom, IPv4 puis IPv6.
    ///
    /// **L'ordre n'est pas une préférence de protocole** : c'est celui qui rate
    /// le moins souvent depuis une machine dont on ne sait pas si elle a une
    /// route IPv6. Chacune sera essayée à son tour.
    pub(crate) async fn addresses(&self, nom: &[u8]) -> Vec<IpAddr> {
        let mut trouvees = Vec::new();
        for genre in [Kind::A, Kind::Aaaa] {
            let Issue::Reponse(octets) = self.interroger(nom, genre).await else {
                continue;
            };
            let Ok(message) = Message::parse(&octets) else {
                continue;
            };
            trouvees.extend(
                message
                    .answers()
                    .filter(|enregistrement| enregistrement.kind() == genre.code())
                    .filter_map(|enregistrement| enregistrement.address()),
            );
        }
        trouvees
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
            return issue_du_message(self.depouiller(serveur, octets));
        }
        issue_du_message(self.depouiller(serveur, octets))
    }

    /// Efface le bit `AD` d'une réponse venue d'un canal qu'on n'a pas déclaré.
    ///
    /// # POURQUOI ICI, ET NULLE PART AILLEURS
    ///
    /// C'est le SEUL endroit qui sache de quel serveur une réponse vient : plus
    /// haut, `interroger` ne rend que des octets. Le faire ici rend impossible
    /// d'oublier — `txt`, `mx`, `tlsa` et tout type qu'on ajoutera un jour
    /// lisent un bit déjà dépouillé, sans avoir à y penser.
    ///
    /// # CE QU'ON EFFACE EST UNE AFFIRMATION QU'ON NE PEUT PAS PORTER
    ///
    /// Le bit dit « j'ai validé ». Venant d'un résolveur qu'un tiers peut
    /// atteindre, il dit seulement « quelqu'un a écrit que quelqu'un a validé ».
    /// Le transporter tel quel ferait s'engager DANE sur la parole d'un
    /// inconnu — et DANE qui s'engage ÉCARTE MTA-STS (§2 de RFC 8461), donc
    /// désarme la protection qui aurait arrêté ce même inconnu.
    ///
    /// **Croire ce bit à tort est donc PIRE que de l'ignorer**, et c'est
    /// pourquoi l'effacer est le comportement sûr : on retombe sur MTA-STS, qui
    /// ne passe pas par le DNS.
    fn depouiller(&self, serveur: SocketAddr, mut octets: Vec<u8>) -> Vec<u8> {
        if self.de_confiance(serveur) {
            return octets;
        }
        // Le bit `AD` est le sixième du second octet de drapeaux (RFC 4035
        // §3.2.3) — `0x0020` dans le `u16` lu à l'offset 2, donc `0x20` dans
        // l'octet 3. Une réponse trop courte pour en avoir un n'en a pas.
        if let Some(drapeaux) = octets.get_mut(3) {
            *drapeaux &= !0x20;
        }
        octets
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

/// Ce qu'une question `MX` a rendu.
pub(crate) enum Mx {
    /// Des serveurs, du plus préféré au moins.
    Trouves {
        /// Les serveurs, par préférence croissante.
        serveurs: Vec<(u16, Vec<u8>)>,
        /// Le résolveur dit-il avoir VALIDÉ cette réponse ?
        ///
        /// **DANE en dépend** (§2.2 de RFC 7672) : un `MX` qu'un tiers a pu
        /// réécrire désignerait un serveur qu'il a choisi, dont le `TLSA` serait
        /// le sien.
        authentique: bool,
    },
    /// Le domaine ne publie pas de `MX` : c'est le nom lui-même qui reçoit
    /// (RFC 5321 §5.1, « `MX` implicite »).
    Absent,
    /// Le domaine déclare ne recevoir aucun courrier (RFC 7505).
    Nul,
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

#[cfg(test)]
mod confiance {
    use super::*;

    fn resolveur(serveur: &str) -> Resolver {
        Resolver::new(
            std::vec![serveur.parse().expect("adresse")],
            Duration::from_secs(1),
        )
        .expect("résolveur")
    }

    /// Une réponse qui porte `AD`, réduite à son en-tête.
    fn reponse_authentifiee() -> Vec<u8> {
        // ID, puis les drapeaux : réponse, récursion, `AD` (0x20) posé — et des
        // sections VIDES, car ce qu'on éprouve ici est l'en-tête, pas le corps.
        std::vec![0x12, 0x34, 0x81, 0xa0, 0, 0, 0, 0, 0, 0, 0, 0]
    }

    /// **LA BOUCLE LOCALE GARDE SON BIT** : rien ne peut se placer entre elle
    /// et nous.
    #[test]
    fn la_boucle_locale_garde_le_bit() {
        for local in ["127.0.0.1:53", "[::1]:53", "127.0.0.53:53"] {
            let garde = resolveur(local)
                .depouiller(local.parse().expect("adresse"), reponse_authentifiee());
            let message = Message::parse(&garde).expect("lisible");
            assert!(message.authentic_data(), "{local} : le bit a été jeté");
        }
    }

    /// **UN RÉSOLVEUR DISTANT NON DÉCLARÉ PERD LE SIEN.** C'est tout l'objet de
    /// cette tranche : le bit dirait « j'ai validé » sur la parole d'un
    /// inconnu, et DANE écarterait MTA-STS sur cette parole.
    #[test]
    fn un_resolveur_distant_non_declare_perd_le_bit() {
        let loin: SocketAddr = "8.8.8.8:53".parse().expect("adresse");
        let jete = resolveur("8.8.8.8:53").depouiller(loin, reponse_authentifiee());
        let message = Message::parse(&jete).expect("lisible");
        assert!(!message.authentic_data(), "le bit d'un inconnu a été cru");
    }

    /// **DÉCLARÉ, IL EST CRU** : §2.1 de RFC 7672 laisse cette branche, et
    /// c'est l'exploitant qui l'engage.
    #[test]
    fn un_lien_declare_garde_le_bit() {
        let loin: SocketAddr = "10.0.0.53:53".parse().expect("adresse");
        let garde = resolveur("10.0.0.53:53")
            .avec_lien_de_confiance(true)
            .depouiller(loin, reponse_authentifiee());
        let message = Message::parse(&garde).expect("lisible");
        assert!(message.authentic_data(), "une déclaration n'a pas suffi");
    }

    /// **ON N'EFFACE QUE CE BIT-LÀ.** Le reste de la réponse doit traverser
    /// intact : un dépouillement qui abîmerait un autre drapeau ferait lire
    /// autre chose que ce que le résolveur a dit.
    #[test]
    fn le_reste_de_la_reponse_traverse_intact() {
        let loin: SocketAddr = "8.8.8.8:53".parse().expect("adresse");
        let avant = reponse_authentifiee();
        let apres = resolveur("8.8.8.8:53").depouiller(loin, avant.clone());
        assert_eq!(apres.len(), avant.len(), "la longueur a changé");
        for (rang, (a, b)) in avant.iter().zip(&apres).enumerate() {
            // Seul l'octet 3 change, et seulement de son bit 0x20.
            if rang == 3 {
                assert_eq!(*a ^ *b, 0x20, "l'octet de drapeaux a bougé d'autre chose");
            } else {
                assert_eq!(a, b, "l'octet {rang} a changé");
            }
        }
    }

    /// L'adresse NON LOCALE de cette machine, s'il y en a une.
    ///
    /// **AUCUN PAQUET NE PART** : `connect` sur une socket UDP ne fait que fixer
    /// la destination, et le noyau choisit alors l'adresse source qu'il aurait
    /// prise. C'est le moyen le plus court de savoir par où l'on sortirait.
    fn adresse_non_locale() -> Option<std::net::IpAddr> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        socket.connect("203.0.113.1:53").ok()?;
        let adresse = socket.local_addr().ok()?.ip();
        (!adresse.is_loopback()).then_some(adresse)
    }

    /// Un faux résolveur qui pose `AD` sur tout, à l'adresse qu'on lui donne.
    async fn resolveur_qui_ment(sur: std::net::IpAddr) -> Option<SocketAddr> {
        let socket = tokio::net::UdpSocket::bind(SocketAddr::new(sur, 0))
            .await
            .ok()?;
        let adresse = socket.local_addr().ok()?;
        tokio::spawn(async move {
            let mut recu = std::vec![0_u8; 2048];
            while let Ok((lus, pair)) = socket.recv_from(&mut recu).await {
                let question = recu.get(..lus).unwrap_or_default().to_vec();
                let mut reponse = Vec::new();
                reponse.extend_from_slice(question.get(..2).unwrap_or_default());
                // Réponse, récursion disponible, **et `AD` posé** (0x0020).
                reponse.extend_from_slice(&0x81a0_u16.to_be_bytes());
                for compte in [1_u16, 0, 0, 0] {
                    reponse.extend_from_slice(&compte.to_be_bytes());
                }
                reponse.extend_from_slice(question.get(12..).unwrap_or_default());
                let _ = socket.send_to(&reponse, pair).await;
            }
        });
        Some(adresse)
    }

    /// **LA CHAÎNE ENTIÈRE**, contre un résolveur qui pose `AD` sur tout.
    ///
    /// Cet essai s'abstient là où la machine n'a que la boucle locale — une
    /// machine de construction cloisonnée, par exemple. Ce qu'il éprouve alors
    /// est éprouvé par les essais unitaires au-dessus ; ce qu'il ajoute, c'est
    /// que le dépouillement a bien lieu SUR LE CHEMIN RÉEL, et pas seulement
    /// dans une fonction qu'on appellerait à la main.
    #[tokio::test]
    async fn un_resolveur_menteur_est_depouille_de_bout_en_bout() {
        let Some(non_locale) = adresse_non_locale() else {
            return;
        };
        let Some(adresse) = resolveur_qui_ment(non_locale).await else {
            return;
        };

        // Non déclaré : le bit tombe, et DANE ne s'engagera pas.
        let strict = Resolver::new(std::vec![adresse], Duration::from_secs(2)).expect("résolveur");
        let (_, authentique) = strict.tlsa(b"_25._tcp.exemple.test").await;
        assert!(
            !authentique,
            "le bit `AD` d'un résolveur distant non déclaré a été cru"
        );

        // Déclaré : l'exploitant l'engage, et le bit est cru.
        let declare = Resolver::new(std::vec![adresse], Duration::from_secs(2))
            .expect("résolveur")
            .avec_lien_de_confiance(true);
        let (_, authentique) = declare.tlsa(b"_25._tcp.exemple.test").await;
        assert!(authentique, "une déclaration explicite n'a pas suffi");
    }

    /// **UNE RÉPONSE TROP COURTE NE PANIQUE PAS.** Elle n'a pas de bit à
    /// effacer, et `get_mut` le dit sans indexer.
    #[test]
    fn une_reponse_trop_courte_ne_panique_pas() {
        let loin: SocketAddr = "8.8.8.8:53".parse().expect("adresse");
        for taille in 0..4_usize {
            let courte = std::vec![0_u8; taille];
            let rendue = resolveur("8.8.8.8:53").depouiller(loin, courte);
            assert_eq!(rendue.len(), taille);
        }
    }
}
