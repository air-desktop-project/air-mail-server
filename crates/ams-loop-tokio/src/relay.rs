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
use ams_session::{
    CLIENT_COMMAND_MAX, ClientConfig, ClientDsn, ClientOutcome, ClientStep, SmtpClient,
};
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
        /// Le pair a-t-il été AUTHENTIFIÉ par DANE (RFC 7672) ?
        ///
        /// # CE N'EST PAS LA MÊME CHOSE QUE `encrypted`, ET LA NUANCE EST TOUT
        ///
        /// Chiffré sans authentifié, c'est le chiffrement opportuniste : un
        /// espion passif ne lit rien, un attaquant actif lit tout. Authentifié,
        /// c'est le domaine lui-même qui a dit dans son DNS signé quel
        /// certificat il présenterait — il n'y a plus de tiers à croire.
        ///
        /// **Il est rendu pour être COMPTÉ.** Une protection qu'on ne voit pas
        /// est une protection qu'on croit avoir.
        authenticated: bool,
        /// Le pair a-t-il pris en charge les demandes de RFC 3461 ?
        ///
        /// Vrai, c'est LUI qui rendra compte, et nous n'émettons rien : deux
        /// rapports pour un même envoi laisseraient le déposant sans savoir
        /// lequel croire (§5.2.1).
        dsn_forwarded: bool,
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
    /// **Le serveur n'est pas dans la politique MTA-STS du domaine.**
    ///
    /// §5 de RFC 8461 : une politique `enforce` qui ne nomme pas ce serveur
    /// interdit d'y remettre. C'est TEMPORAIRE — le domaine corrige sa politique
    /// ou son `MX`, et le message repartira — et surtout, ce n'est **pas** un
    /// refus du pair : on ne lui a rien demandé.
    PolicyMismatch,
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
    /// Ce que le déposant a demandé du sort de son message (RFC 3461 §5.2.1).
    ///
    /// **CE N'EST PAS À NOUS DE LE GARDER.** Un serveur intermédiaire qui lit
    /// `NOTIFY=NEVER` et ne le transmet pas laisse le saut suivant émettre le
    /// rapport que le déposant avait explicitement refusé. La demande suit le
    /// message aussi loin que des serveurs savent la lire.
    pub dsn: Option<ClientDsn<'a>>,
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
    /// Où consigner ce qu'on rapportera aux domaines qui le demandent.
    ///
    /// **`None` NE CHANGE AUCUNE REMISE** : un serveur qui ne rapporte pas remet
    /// exactement comme avant. Il laisse simplement les domaines d'en face
    /// découvrir leurs pannes de chiffrement à leur courrier qui n'arrive plus.
    rapports: Option<Arc<crate::tlsreports::TlsReports>>,
    /// De quoi évaluer MTA-STS, si l'exploitant l'a demandé.
    ///
    /// **`None` NE REFUSE RIEN** : sans magasin de racines ni cache, MTA-STS
    /// n'est pas évalué, et la remise est ce qu'elle était — DANE si le domaine
    /// publie un `TLSA`, opportuniste sinon.
    sts: Option<Arc<crate::mtasts::Sts>>,
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
            // **ON N'ÉVALUE PAS MTA-STS, SAUF DEMANDE EXPRESSE.** Le
            // constructeur ne le prend pas : un argument de plus dans une liste
            // qui en compte cinq se passe à l'envers sans que le compilateur
            // bronche, et celui-ci décide de remises.
            sts: None,
            rapports: None,
        }
    }

    /// Lui donne de quoi consigner ce qu'il rapportera (RFC 8460).
    #[must_use]
    pub fn with_tls_reports(mut self, rapports: Arc<crate::tlsreports::TlsReports>) -> Self {
        self.rapports = Some(rapports);
        self
    }

    /// Lui donne de quoi évaluer MTA-STS (RFC 8461).
    ///
    /// **C'est la seule façon de l'activer**, et elle laisse une ligne à lire au
    /// démarrage du serveur.
    #[must_use]
    pub fn with_mtasts(mut self, sts: Arc<crate::mtasts::Sts>) -> Self {
        self.sts = Some(sts);
        self
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
        let (serveurs, mx_authentique): (Vec<String>, bool) =
            match self.resolveur.mx(domaine.as_bytes()).await {
                Mx::Trouves {
                    serveurs,
                    authentique,
                } => (
                    serveurs
                        .into_iter()
                        .map(|(_, nom)| String::from_utf8_lossy(&nom).into_owned())
                        .collect(),
                    authentique,
                ),
                // RFC 5321 §5.1 : sans `MX`, c'est le nom lui-même qui reçoit.
                //
                // **ET DANE NE S'Y APPLIQUE PAS.** §2.2 de RFC 7672 demande que
                // la ABSENCE de `MX` soit elle-même prouvée par DNSSEC, ce que
                // ce résolveur ne rend pas : le bit `AD` d'une réponse vide ne
                // dit pas de quoi il parle. Retomber sur l'opportuniste est le
                // seul refus honnête — on ne prétend pas ce qu'on n'a pas.
                Mx::Absent => (std::vec![domaine.to_string()], false),
                Mx::Nul => return RelayOutcome::NullMx,
                Mx::Panne => return RelayOutcome::Unreachable,
            };

        // **MTA-STS SE CHERCHE PAR DOMAINE, ET UNE SEULE FOIS** (§3.1 de
        // RFC 8461) : c'est le domaine du destinataire qui publie, et sa
        // politique vaut pour tous ses serveurs.
        let politique = self.politique_pour(domaine).await;

        let mut issue = RelayOutcome::Unreachable;
        for hote in &serveurs {
            // **LE `TLSA` SE CHERCHE PAR SERVEUR, PAS PAR DOMAINE** (§3.1 de
            // RFC 7672) : c'est le nom du `MX` qui publie, et deux serveurs d'un
            // même domaine peuvent porter deux certificats.
            let dane = self.dane_pour(hote, mx_authentique).await;
            // **DANE L'EMPORTE** (§2 de RFC 8461). Quand un domaine publie les
            // deux, c'est celui dont la confiance ne passe par aucun tiers qui
            // décide, et MTA-STS n'est même pas consulté.
            let sts = match dane {
                Some(_) => Consigne::Aucune,
                None => self.consigne(politique.as_deref(), hote),
            };
            if sts == Consigne::Interdit {
                // **CE SERVEUR N'EST PAS DANS LA POLITIQUE.** On n'y remet pas,
                // et l'on essaie le suivant : le domaine a peut-être publié une
                // liste dont celui-ci a été retiré.
                issue = RelayOutcome::PolicyMismatch;
                continue;
            }
            let exige = sts == Consigne::Exige;
            for adresse in self.resolveur.addresses(hote.as_bytes()).await {
                issue = self
                    .send_to_avec(
                        hote,
                        SocketAddr::new(adresse, self.port),
                        message,
                        dane.as_ref(),
                        exige,
                    )
                    .await;
                // **ON CONSIGNE CHAQUE ESSAI, RÉUSSI COMME MANQUÉ.** §4.2 exige
                // les DEUX comptes : un rapport qui ne dirait que les échecs ne
                // permettrait pas de savoir s'ils sont l'exception ou la règle.
                self.consigner(domaine, hote, dane.is_some(), politique.as_deref(), issue);
                if issue != RelayOutcome::Unreachable {
                    return issue;
                }
            }
        }
        // Un serveur qu'aucune politique n'autorise n'a jamais été essayé : on
        // le consigne ici, puisque la boucle ci-dessus ne l'a pas vu.
        if issue == RelayOutcome::PolicyMismatch {
            for hote in &serveurs {
                self.consigner(domaine, hote, false, politique.as_deref(), issue);
            }
        }
        issue
    }

    /// Consigne ce qu'un essai a appris, pour le rapport TLS (RFC 8460).
    ///
    /// **RIEN NE SE FAIT SI PERSONNE NE RAPPORTE** : le journal n'existe que si
    /// l'exploitant a nommé un dossier, et la question « ce domaine demande-t-il
    /// un rapport ? » se pose au dépôt, pas ici — une résolution DNS de plus par
    /// message doublerait le trafic pour une réponse qui ne change pas d'une
    /// heure à l'autre.
    fn consigner(
        &self,
        domaine: &str,
        hote: &str,
        dane: bool,
        politique: Option<&str>,
        issue: RelayOutcome,
    ) {
        let Some(rapports) = self.rapports.as_ref() else {
            return;
        };
        let (genre, lignes, serveurs) = match (dane, politique) {
            (true, _) => (ams_tlsrpt::PolicyType::Tlsa, Vec::new(), Vec::new()),
            (false, Some(texte)) => {
                let mut place = [""; ams_mtasts::MX_MAX];
                let serveurs = ams_mtasts::parse_policy(texte, &mut place)
                    .map(|lue| lue.mx().iter().map(|un| String::from(*un)).collect())
                    .unwrap_or_default();
                (
                    ams_tlsrpt::PolicyType::Sts,
                    texte.lines().map(String::from).collect(),
                    serveurs,
                )
            }
            (false, None) => (
                ams_tlsrpt::PolicyType::NoPolicyFound,
                Vec::new(),
                Vec::new(),
            ),
        };
        rapports.observer(&crate::tlsreports::TlsObservation {
            domain: String::from(domaine),
            mx_host: String::from(hote),
            policy_type: genre,
            policy_strings: lignes,
            mx_hosts: serveurs,
            failure: cause_de(issue, dane),
        });
    }

    /// Ce que la politique MTA-STS du domaine dit de ce serveur.
    ///
    /// # `testing` CONSIGNE, ET REMET QUAND MÊME
    ///
    /// §5.2 : `testing` dit « je m'installe, ne refusez pas encore ». On évalue,
    /// on écrit ce qui aurait échoué, et l'on remet. L'ignorer priverait
    /// l'exploitant de la seule trace qui lui dirait que ses remises vers ce
    /// domaine échoueront une fois la politique durcie.
    fn consigne(&self, politique: Option<&str>, hote: &str) -> Consigne {
        let Some(texte) = politique else {
            return Consigne::Aucune;
        };
        let mut place = [""; ams_mtasts::MX_MAX];
        let Ok(lue) = ams_mtasts::parse_policy(texte, &mut place) else {
            // Une politique qu'on ne sait pas lire ne dit rien : §5 ne demande
            // pas de refuser sur ce qu'on n'a pas compris.
            return Consigne::Aucune;
        };
        let permis = lue.allows(hote);
        match (lue.mode(), permis) {
            (ams_mtasts::Mode::Enforce, true) => Consigne::Exige,
            (ams_mtasts::Mode::Enforce, false) => Consigne::Interdit,
            (ams_mtasts::Mode::Testing, permis) => {
                if !permis {
                    std::eprintln!(
                        "air-mail-server : MTA-STS en `testing` — `{hote}` n'est pas dans la \
                         politique de ce domaine, et la remise SERAIT REFUSÉE si elle passait \
                         en `enforce`. On remet tout de même."
                    );
                }
                Consigne::Aucune
            }
            // `none` : le domaine retire sa politique.
            (ams_mtasts::Mode::None, _) => Consigne::Aucune,
        }
    }

    /// La politique MTA-STS de ce domaine, si l'on sait l'évaluer.
    async fn politique_pour(&self, domaine: &str) -> Option<String> {
        let sts = self.sts.as_ref()?;
        let maintenant = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |depuis| depuis.as_secs());
        sts.policy_for(domaine, maintenant).await
    }

    /// Ce que DANE exige de ce serveur, s'il exige quelque chose.
    ///
    /// `None` veut dire « rien » : pas de `TLSA`, une réponse non authentifiée,
    /// ou un jeu dont aucun enregistrement n'est utilisable (§2.2 de RFC 7672).
    /// La remise est alors opportuniste, exactement comme avant.
    ///
    /// **LES DEUX RÉPONSES DOIVENT ÊTRE AUTHENTIQUES**, celle du `MX` comme
    /// celle du `TLSA`. Un `MX` qu'un tiers a pu réécrire désignerait un serveur
    /// qu'il a choisi, dont le `TLSA` serait le sien : la chaîne doit être signée
    /// d'un bout à l'autre, ou elle ne vaut rien.
    async fn dane_pour(
        &self,
        hote: &str,
        mx_authentique: bool,
    ) -> Option<Arc<rustls::ClientConfig>> {
        if !mx_authentique {
            return None;
        }
        let nom = std::format!("{}{hote}", ams_dane::SMTP_PREFIX);
        let (rdata, authentique) = self.resolveur.tlsa(nom.as_bytes()).await;
        if !authentique {
            return None;
        }
        let records: Vec<ams_dane::Tlsa<'_>> = rdata
            .iter()
            .filter_map(|octets| ams_dane::Tlsa::parse(octets))
            .collect();
        if !ams_dane::Set::from_records(records, true).engage() {
            return None;
        }
        Some(Arc::new(ams_tls::dane_config(rdata)))
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
        self.send_to_avec(hote, adresse, message, None, false).await
    }

    /// Le corps de [`Relay::send_to`], avec ce que DANE exige.
    ///
    /// `dane` porte la configuration TLS qui EXIGE un `TLSA` satisfait. Sa
    /// présence rend le chiffrement obligatoire : §2.2 de RFC 7672 ne laisse pas
    /// le choix, et il n'y a aucun réglage pour l'affaiblir.
    async fn send_to_avec(
        &self,
        hote: &str,
        adresse: SocketAddr,
        message: &Outgoing<'_>,
        dane: Option<&Arc<rustls::ClientConfig>>,
        sts: bool,
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
            dsn: message.dsn,
            // **UN DOMAINE QUI PUBLIE UN `TLSA` EXIGE LE CHIFFREMENT.** Un pair
            // qui n'annonce pas `STARTTLS` alors que son domaine a publié est
            // soit en panne, soit déclassé par un tiers ; dans les deux cas on
            // n'émet pas.
            require_tls: self.exige_tls || dane.is_some() || sts,
        }) else {
            return RelayOutcome::Unsendable;
        };

        let Ok(Ok(mut flux)) = timeout(self.delai, TcpStream::connect(adresse)).await else {
            return RelayOutcome::Unreachable;
        };
        let mut tampon = Vec::new();
        let issue = match self
            .dialoguer(&mut flux, &mut client, &corps, &mut tampon)
            .await
        {
            Suite::Fini(issue) => issue,
            Suite::Monter => {
                self.monter(flux, hote, &mut client, &corps, tampon, dane, sts)
                    .await
            }
        };
        // **LA POIGNÉE DE MAIN A RÉUSSI SOUS DANE, DONC LE PAIR EST AUTHENTIFIÉ.**
        //
        // Il n'y a pas d'autre chemin : la configuration DANE refuse tout
        // certificat qu'aucun `TLSA` ne nomme, et un refus de poignée de main ne
        // rend jamais `Delivered`. C'est ici qu'on le dit, parce que c'est ici
        // qu'on sait sous quelle configuration on a parlé.
        match (dane.is_some(), issue) {
            (
                true,
                RelayOutcome::Delivered {
                    accepted,
                    refused,
                    encrypted,
                    dsn_forwarded,
                    ..
                },
            ) => RelayOutcome::Delivered {
                accepted,
                refused,
                encrypted,
                authenticated: true,
                dsn_forwarded,
            },
            (_, issue) => issue,
        }
    }

    /// Monte en chiffrement, puis reprend la conversation.
    #[expect(
        clippy::too_many_arguments,
        reason = "les trois configurations TLS possibles — opportuniste, DANE et \
                  MTA-STS — se décident ici, et les rassembler dans une structure \
                  ne dirait rien de plus qu'un booléen et une option"
    )]
    async fn monter(
        &self,
        flux: TcpStream,
        hote: &str,
        client: &mut SmtpClient<'_>,
        corps: &[u8],
        mut tampon: Vec<u8>,
        dane: Option<&Arc<rustls::ClientConfig>>,
        sts: bool,
    ) -> RelayOutcome {
        let Ok(nom) = ServerName::try_from(hote.to_string()) else {
            // Un `MX` qui n'est pas un nom de domaine ne se joint pas en TLS, et
            // l'on ne se rabat pas sur le clair pour autant.
            return RelayOutcome::NoEncryption;
        };
        // **LE VÉRIFICATEUR VIENT DU DNS.** Un domaine qui publie un `TLSA`
        // authentique est joint avec la configuration qui l'EXIGE ; tous les
        // autres, avec l'opportuniste. Il n'y a pas de troisième cas, et pas de
        // réglage pour en fabriquer un.
        //
        // **ET MTA-STS EN EXIGE UNE TROISIÈME**, quand un domaine l'applique :
        // la vérification ORDINAIRE de la WebPKI, contre les autorités que
        // l'exploitant a nommées et pour le nom du `MX`. DANE passe avant.
        let sous_politique = if sts { self.sts.as_ref() } else { None };
        let configuration = match (dane, sous_politique) {
            (Some(dane), _) => Arc::clone(dane),
            (None, Some(sts)) => Arc::clone(sts.tls()),
            (None, None) => Arc::clone(&self.tls),
        };
        let connecteur = TlsConnector::from(configuration);
        let Ok(Ok(mut chiffre)) = timeout(self.delai, connecteur.connect(nom, flux)).await else {
            // LA POIGNÉE DE MAIN A ÉCHOUÉ APRÈS UN `STARTTLS` ACCEPTÉ. On ne
            // recommence pas en clair : un échec qu'un tiers peut provoquer
            // serait alors le levier d'un déclassement.
            //
            // **ET EN DANE, C'EST AUSSI LE REFUS D'AUTHENTIFICATION** : le pair
            // n'a satisfait aucun `TLSA`. La remise est ajournée, le message
            // reste en file, et il repartira quand le domaine aura réparé. C'est
            // ce que §2.2 de RFC 7672 demande, et il n'y a rien pour l'affaiblir.
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

/// Pourquoi cet essai a échoué, dans les mots de §4.3 de RFC 8460.
///
/// `None` quand il a abouti — c'est alors une session réussie, qu'on compte
/// aussi.
///
/// **ON NE DEVINE PAS PLUS QUE CE QU'ON SAIT.** Un pair injoignable n'est pas un
/// échec de chiffrement : c'est une panne de réseau, et la rapporter comme un
/// problème de certificat enverrait le domaine chercher au mauvais endroit.
fn cause_de(issue: RelayOutcome, dane: bool) -> Option<ams_tlsrpt::ResultType> {
    match issue {
        RelayOutcome::Delivered { .. } => None,
        RelayOutcome::NoEncryption if dane => Some(ams_tlsrpt::ResultType::ValidationFailureDane),
        // La poignée de main a échoué, ou le pair n'a pas annoncé `STARTTLS`.
        // Les deux se rendent par la même issue, et l'on nomme celle qui
        // n'accuse personne à tort.
        RelayOutcome::NoEncryption => Some(ams_tlsrpt::ResultType::ValidationFailure),
        RelayOutcome::PolicyMismatch => Some(ams_tlsrpt::ResultType::StsPolicyInvalid),
        // Un refus SMTP, une panne de réseau, un message qu'on ne sait pas
        // émettre : rien de tout cela ne dit quoi que ce soit du chiffrement.
        RelayOutcome::Rejected(_)
        | RelayOutcome::Deferred(_)
        | RelayOutcome::NullMx
        | RelayOutcome::Unreachable
        | RelayOutcome::Protocol
        | RelayOutcome::Unsendable => None,
    }
}

/// Ce que la politique MTA-STS d'un domaine dit d'un de ses serveurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Consigne {
    /// Rien : pas de politique, `none`, `testing`, ou DANE qui l'emporte.
    Aucune,
    /// `enforce`, et ce serveur y figure : la remise doit être authentifiée.
    Exige,
    /// `enforce`, et ce serveur n'y figure PAS : on n'y remet pas.
    Interdit,
}

/// Traduit l'issue de la session en issue de remise.
fn issue_du_client(outcome: ClientOutcome, client: &SmtpClient<'_>) -> RelayOutcome {
    match outcome {
        // **`authenticated` SE POSE PLUS HAUT**, dans `send_to_avec`, qui est le
        // seul à savoir si la poignée de main s'est faite sous DANE. Ici on ne
        // voit que la conversation SMTP, et elle est la même dans les deux cas.
        ClientOutcome::Delivered => RelayOutcome::Delivered {
            accepted: client.accepted(),
            refused: client.refused(),
            encrypted: client.is_encrypted(),
            authenticated: false,
            dsn_forwarded: client.dsn_forwarded(),
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
