//! TLSRPT (RFC 8460) : observer, composer, déposer, remettre.
//!
//! # LE SEUL MÉCANISME DE CE DÉPÔT DONT LE BÉNÉFICIAIRE EST QUELQU'UN D'AUTRE
//!
//! DANE et MTA-STS protègent NOTRE courrier. TLSRPT, lui, rend au domaine d'en
//! face ce que nous seuls savons : que ses `TLSA` sont mal renouvelés, que sa
//! politique nomme un serveur qui a disparu, que son certificat a expiré. Un
//! domaine en `mode: testing` publie précisément pour l'apprendre.
//!
//! # CE QUE CE MODULE FAIT, ET CE QU'IL NE DÉCIDE PAS
//!
//! Il tient un journal, écrit des fichiers, résout et remet — c'est l'étage 3.
//! Ce qu'il ne décide pas : la forme du rapport, ce qu'un `_smtp._tls` demande,
//! et ce qui autorise un envoi chez un tiers. Tout cela vit dans `ams-tlsrpt`,
//! couvert à 100 %.
//!
//! # DEUX CRANS, COMME LES RAPPORTS DMARC
//!
//! `vider` COMPOSE et DÉPOSE ; `envoyer` REMET. Un exploitant peut lire ce
//! qu'il enverrait avant de l'envoyer — émettre du courrier vers des tiers ne se
//! décide pas à sa place.
//!
//! # LE JOURNAL EST BORNÉ, ET C'EST UNE BORNE DE C3
//!
//! Il grandit avec le nombre de domaines à qui l'on écrit. Sans borne, un compte
//! compromis qui émettrait vers un million de domaines ferait croître la mémoire
//! du serveur sans fin. Au-delà, on cesse d'observer plutôt que d'oublier : un
//! rapport incomplet vaut mieux qu'un serveur qui tombe.

use core::time::Duration;
use std::collections::HashMap;
use std::path::PathBuf;
use std::string::String;
use std::sync::{Arc, Mutex};
use std::vec::Vec;

use ams_tlsrpt::{
    Destination, FILENAME_MAX, Failure, Policy, PolicyType, RUA_MAX, Report, ResultType,
    SUBJECT_MAX, Summary, TXT_PREFIX, Transport, VERIFICATION_MAX, authorizes, filename,
    needs_verification, parse_record, subject, verification_name,
};

use crate::dkim::DkimSigner;
use crate::relay::{Outgoing, Relay, RelayOutcome};
use crate::resolver::{Resolver, Txt};

/// Combien de domaines le journal retient à la fois.
pub const DOMAINES_MAX: usize = 4096;

/// Combien de sortes d'échec on retient par domaine.
///
/// Il y a huit types d'échec dans §4.3, et un nom de serveur par `MX` : le
/// produit est petit, et cette borne le dit plutôt que de l'espérer.
const ECHECS_MAX: usize = 64;

/// Ce qu'une taille de rapport peut atteindre.
const RAPPORT_MAX: usize = 256 * 1024;

/// Au-delà, un rapport ne vaut plus la peine d'être remis : sept jours.
const PEREMPTION: u64 = 7 * 86_400;

/// Ce qu'une remise apprend, et qu'on rapportera peut-être.
#[derive(Debug, Clone)]
pub struct TlsObservation {
    /// Le domaine du destinataire — celui qui recevra le rapport.
    pub domain: String,
    /// Le serveur qu'on cherchait à joindre.
    pub mx_host: String,
    /// D'où venait la politique appliquée.
    pub policy_type: PolicyType,
    /// Les lignes de la politique, s'il y en avait une.
    pub policy_strings: Vec<String>,
    /// Les serveurs que la politique nomme.
    pub mx_hosts: Vec<String>,
    /// Pourquoi la session a échoué, ou `None` si elle a abouti.
    pub failure: Option<ResultType>,
}

/// Ce qu'un dépôt a donné.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TlsSpoolTally {
    /// Rapports composés et déposés.
    pub reports: usize,
    /// Domaines écartés faute d'en avoir demandé.
    pub unasked: usize,
    /// Rapports qu'on n'a pas su composer ou écrire.
    pub errors: usize,
}

/// Ce qu'une remise a donné.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TlsSendTally {
    /// Rapports remis.
    pub sent: usize,
    /// Rapports remis à plus tard.
    pub deferred: usize,
    /// Rapports abandonnés — refusés, ou trop vieux.
    pub dropped: usize,
    /// Destinations écartées faute de consentement (§3).
    pub unauthorized: usize,
}

/// Ce qu'on a observé d'un domaine, sur la période.
#[derive(Debug, Clone)]
struct Journal {
    policy_type: PolicyType,
    policy_strings: Vec<String>,
    mx_hosts: Vec<String>,
    successful: u64,
    failed: u64,
    /// `(type d'échec, serveur)` vers le nombre de sessions.
    echecs: HashMap<(ResultType, String), u64>,
}

/// Le journal des rapports TLSRPT, et ce qu'on en fait.
pub struct TlsReports {
    /// Le nom sous lequel ce receveur se présente.
    org_name: String,
    /// L'adresse à laquelle le joindre.
    email: String,
    /// Notre adresse d'émission, telle qu'elle figurera dans les rapports.
    sending_ip: String,
    /// Le dossier où les rapports sont déposés.
    directory: PathBuf,
    resolveur: Resolver,
    /// De quoi remettre par courrier, si l'exploitant l'a demandé.
    relay: Option<Relay>,
    /// De quoi remettre par `https:`, si l'exploitant a nommé des autorités.
    https: Option<Arc<rustls::ClientConfig>>,
    /// De quoi signer ce qu'on émet.
    signataire: Option<DkimSigner>,
    /// Le temps accordé à chaque lecture.
    delai: Duration,
    /// Ce qu'on a observé, par domaine.
    journal: Mutex<HashMap<String, Journal>>,
    /// Ce qui distingue deux rapports d'une même seconde.
    suite: std::sync::atomic::AtomicU64,
}

impl core::fmt::Debug for TlsReports {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // **PAS DE JOURNAL DANS UNE TRACE.** Il porte la liste des domaines à
        // qui ce serveur écrit, ce qui n'a rien à faire dans un rapport
        // d'incident.
        f.debug_struct("TlsReports")
            .field("org_name", &self.org_name)
            .field("directory", &self.directory)
            .finish_non_exhaustive()
    }
}

impl TlsReports {
    /// Prépare le journal.
    #[must_use]
    pub fn new(
        org_name: String,
        email: String,
        sending_ip: String,
        directory: PathBuf,
        resolveur: Resolver,
        delai: Duration,
    ) -> Self {
        Self {
            org_name,
            email,
            sending_ip,
            directory,
            resolveur,
            // **ON NE REMET PAS, SAUF DEMANDE EXPRESSE**, et le constructeur ne
            // le prend pas : émettre du courrier vers des tiers ne se décide pas
            // à la place de qui exploite la machine.
            relay: None,
            https: None,
            signataire: None,
            delai,
            journal: Mutex::new(HashMap::new()),
            suite: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Lui donne de quoi remettre par courrier.
    #[must_use]
    pub fn with_relay(mut self, relay: Relay) -> Self {
        self.relay = Some(relay);
        self
    }

    /// Lui donne de quoi remettre par `https:`.
    ///
    /// **Les mêmes autorités que MTA-STS** : un rapport qu'on POSTE va chez un
    /// serveur qu'un domaine a nommé, et il faut savoir à qui l'on parle.
    #[must_use]
    pub fn with_https(mut self, tls: Arc<rustls::ClientConfig>) -> Self {
        self.https = Some(tls);
        self
    }

    /// Lui donne de quoi signer ce qu'il émet.
    #[must_use]
    pub fn with_dkim(mut self, signataire: DkimSigner) -> Self {
        self.signataire = Some(signataire);
        self
    }

    /// Retient ce qu'une remise a appris.
    ///
    /// **ON NE DEMANDE PAS ENCORE SI LE DOMAINE RAPPORTE.** Le `TXT` se lit au
    /// dépôt, une fois par période et par domaine, plutôt qu'à chaque message :
    /// une question DNS de plus par remise doublerait le trafic de résolution
    /// pour une réponse qui ne change pas d'une heure à l'autre.
    pub fn observer(&self, observation: &TlsObservation) {
        let Ok(mut journal) = self.journal.lock() else {
            // Un verrou empoisonné veut dire qu'un fil a paniqué en le tenant.
            // On perd cette observation ; on ne perd pas le service.
            return;
        };
        // **AU-DELÀ DE LA BORNE, ON CESSE D'OBSERVER** plutôt que d'oublier : un
        // rapport incomplet vaut mieux qu'un serveur qui tombe, et oublier
        // laisserait choisir CE qu'on oublie à celui qui inonde.
        if journal.len() >= DOMAINES_MAX && !journal.contains_key(&observation.domain) {
            return;
        }
        let domaine = journal
            .entry(observation.domain.clone())
            .or_insert_with(|| Journal {
                policy_type: observation.policy_type,
                policy_strings: observation.policy_strings.clone(),
                mx_hosts: observation.mx_hosts.clone(),
                successful: 0,
                failed: 0,
                echecs: HashMap::new(),
            });
        // LA DERNIÈRE POLITIQUE VUE FAIT FOI : un domaine qui change la sienne
        // en cours de période veut voir la nouvelle, pas celle d'hier matin.
        domaine.policy_type = observation.policy_type;
        domaine
            .policy_strings
            .clone_from(&observation.policy_strings);
        domaine.mx_hosts.clone_from(&observation.mx_hosts);

        match observation.failure {
            None => domaine.successful = domaine.successful.saturating_add(1),
            Some(cause) => {
                domaine.failed = domaine.failed.saturating_add(1);
                let cle = (cause, observation.mx_host.clone());
                if domaine.echecs.len() < ECHECS_MAX || domaine.echecs.contains_key(&cle) {
                    let compte = domaine.echecs.entry(cle).or_insert(0);
                    *compte = compte.saturating_add(1);
                }
            }
        }
    }

    /// Y a-t-il quelque chose à déposer ?
    #[must_use]
    pub fn en_attente(&self) -> bool {
        self.journal.lock().is_ok_and(|journal| !journal.is_empty())
    }

    /// Compose, nomme, compresse et dépose tout ce qui a été retenu.
    ///
    /// La période se referme ici : ce qui arrivera ensuite comptera pour la
    /// suivante.
    pub async fn vider(&self) -> TlsSpoolTally {
        let mut compte = TlsSpoolTally::default();
        // **LE VERROU NE TRAVERSE AUCUN `await`.** On prend le journal, on le
        // relâche, et l'on travaille sur ce qu'on a pris : tenir un verrou
        // synchrone pendant une résolution DNS bloquerait chaque remise en
        // cours pendant tout le dépôt.
        let journal = {
            let Ok(mut verrou) = self.journal.lock() else {
                return compte;
            };
            core::mem::take(&mut *verrou)
        };
        if journal.is_empty() {
            return compte;
        }
        if tokio::fs::create_dir_all(&self.directory).await.is_err() {
            compte.errors = compte.errors.saturating_add(journal.len());
            return compte;
        }

        let fin = maintenant();
        // La période commence au dernier dépôt ; faute de le retenir, on prend
        // les vingt-quatre heures que §4 nomme.
        let debut = fin.saturating_sub(86_400);
        for (domaine, vu) in journal {
            // **ON NE RAPPORTE QU'À QUI A DEMANDÉ.** §3 : sans `_smtp._tls`, le
            // domaine n'attend rien, et lui écrire serait du courrier qu'il n'a
            // pas sollicité.
            let Some(destinations) = self.destinations(&domaine).await else {
                compte.unasked = compte.unasked.saturating_add(1);
                continue;
            };
            if self.deposer(&domaine, &vu, &destinations, debut, fin).await {
                compte.reports = compte.reports.saturating_add(1);
            } else {
                compte.errors = compte.errors.saturating_add(1);
            }
        }
        compte
    }

    /// Les destinations que ce domaine a publiées, si elles nous autorisent.
    async fn destinations(&self, domaine: &str) -> Option<Vec<String>> {
        let nom = std::format!("{TXT_PREFIX}{domaine}");
        let Txt::Trouves(chaines) = self.resolveur.txt(nom.as_bytes()).await else {
            return None;
        };
        let mut retenues = Vec::new();
        for octets in &chaines {
            let Ok(texte) = core::str::from_utf8(octets) else {
                continue;
            };
            let mut place = [Destination::EMPTY; RUA_MAX];
            let Ok(lues) = parse_record(texte, &mut place) else {
                continue;
            };
            for une in lues {
                let Some(cible) = une.domain() else {
                    continue;
                };
                // **LA VÉRIFICATION DE §3 N'EST PAS FACULTATIVE.** Sans elle,
                // n'importe qui publierait `rua=mailto:victime@banque.test` et
                // ferait bombarder cette adresse par tous les émetteurs du monde.
                if needs_verification(domaine, cible) && !self.consent(domaine, cible).await {
                    continue;
                }
                retenues.push(match une.transport() {
                    Transport::Mailto => std::format!("mailto:{}", une.target()),
                    Transport::Https => String::from(une.target()),
                });
            }
        }
        (!retenues.is_empty()).then_some(retenues)
    }

    /// Cette destination a-t-elle publié son consentement (§3) ?
    async fn consent(&self, domaine: &str, cible: &str) -> bool {
        let mut place = [0_u8; VERIFICATION_MAX];
        let Ok(nom) = verification_name(domaine, cible, &mut place) else {
            return false;
        };
        match self.resolveur.txt(nom.as_bytes()).await {
            Txt::Trouves(textes) => textes
                .iter()
                .any(|octets| core::str::from_utf8(octets).is_ok_and(authorizes)),
            // UNE PANNE N'EST PAS UN CONSENTEMENT. Envoyer « au cas où » est
            // exactement ce que §3 existe pour empêcher.
            Txt::Absent | Txt::Panne => false,
        }
    }

    /// Compose un rapport, le compresse et le dépose avec ses destinations.
    async fn deposer(
        &self,
        domaine: &str,
        vu: &Journal,
        destinations: &[String],
        debut: u64,
        fin: u64,
    ) -> bool {
        let identifiant = std::format!("{}.{}@{}", fin, self.suivant(), self.org_name);
        let mut place = std::vec![0_u8; RAPPORT_MAX];
        let Some(json) = self.composer(&mut place, domaine, vu, &identifiant, debut, fin) else {
            return false;
        };
        let Ok(comprime) = comprimer(json) else {
            return false;
        };
        let mut nom = [0_u8; FILENAME_MAX];
        let Ok(nom) = filename(&self.org_name, domaine, debut, fin, &mut nom) else {
            return false;
        };
        let chemin = self.directory.join(nom);
        if tokio::fs::write(&chemin, &comprime).await.is_err() {
            return false;
        }
        // **LE VOISIN DIT À QUI IL REVIENT**, comme pour les rapports DMARC :
        // sans lui, un rapport déposé serait un fichier dont plus personne ne
        // saurait quoi faire après un redémarrage.
        let mut voisin = chemin.clone().into_os_string();
        voisin.push(".destinations");
        let liste = destinations.join("\n");
        tokio::fs::write(PathBuf::from(voisin), std::format!("{liste}\n"))
            .await
            .is_ok()
    }

    /// Écrit le JSON d'un rapport.
    fn composer<'b>(
        &self,
        place: &'b mut [u8],
        domaine: &str,
        vu: &Journal,
        identifiant: &str,
        debut: u64,
        fin: u64,
    ) -> Option<&'b [u8]> {
        let mut ecriture = ams_tlsrpt::begin(
            place,
            &Report {
                organization_name: &self.org_name,
                contact_info: &self.email,
                report_id: identifiant,
                start: debut,
                end: fin,
            },
        )
        .ok()?;
        let lignes: Vec<&str> = vu.policy_strings.iter().map(String::as_str).collect();
        let serveurs: Vec<&str> = vu.mx_hosts.iter().map(String::as_str).collect();
        ecriture
            .policy(
                &Policy {
                    policy_type: vu.policy_type,
                    policy_domain: domaine,
                    policy_strings: &lignes,
                    mx_hosts: &serveurs,
                },
                &Summary {
                    successful: vu.successful,
                    failed: vu.failed,
                },
            )
            .ok()?;
        // L'ORDRE EST CELUI DE LA TABLE, donc arbitraire. On le trie pour qu'un
        // même jeu d'observations donne toujours le même rapport : deux fichiers
        // qui ne diffèrent que par l'ordre se comparent mal.
        let mut echecs: Vec<(&(ResultType, String), &u64)> = vu.echecs.iter().collect();
        echecs.sort_by_key(|((cause, serveur), _)| (cause.name(), serveur.as_str()));
        for ((cause, serveur), combien) in echecs {
            ecriture
                .failure(&Failure {
                    result_type: *cause,
                    sending_mta_ip: &self.sending_ip,
                    receiving_mx_hostname: serveur,
                    failed_session_count: *combien,
                })
                .ok()?;
        }
        ecriture.finish().ok()
    }

    /// Le prochain numéro de la suite.
    fn suivant(&self) -> u64 {
        self.suite
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Remet ce qui a été déposé.
    ///
    /// **DEUX TRANSPORTS, ET §3 LES PERMET TOUS LES DEUX.** `mailto:` passe par
    /// le client sortant — donc par DANE et MTA-STS comme n'importe quel
    /// message ; `https:` POSTE le rapport, en vérifiant le certificat contre
    /// les mêmes autorités que MTA-STS.
    ///
    /// **UN RAPPORT REMIS EST EFFACÉ**, un rapport refusé DÉFINITIVEMENT aussi,
    /// et un rapport trop vieux également : le compte d'une journée qu'on
    /// remettrait un mois plus tard n'apprend plus rien à personne, et sans cette
    /// borne un domaine injoignable ferait croître le dossier sans fin.
    pub async fn envoyer(&self) -> TlsSendTally {
        let mut compte = TlsSendTally::default();
        let Ok(mut dossier) = tokio::fs::read_dir(&self.directory).await else {
            return compte;
        };
        let maintenant = maintenant();
        let mut a_faire = Vec::new();
        while let Ok(Some(entree)) = dossier.next_entry().await {
            let nom = entree.file_name();
            let Some(nom) = nom.to_str() else {
                continue;
            };
            // **RIEN DE CE QUI N'A PAS CETTE FORME N'EST TOUCHÉ.** Un dossier
            // qu'on partage avec autre chose ne se remet pas au jugé.
            if nom.ends_with(".json.gz") {
                a_faire.push(String::from(nom));
            }
        }
        for nom in a_faire {
            self.remettre(&nom, maintenant, &mut compte).await;
        }
        compte
    }

    /// Remet UN rapport.
    async fn remettre(&self, nom: &str, maintenant: u64, compte: &mut TlsSendTally) {
        let chemin = self.directory.join(nom);
        let mut voisin = chemin.clone().into_os_string();
        voisin.push(".destinations");
        let voisin = PathBuf::from(voisin);

        // §5.3 : `<émetteur>!<rapporté>!<début>!<fin>.json.gz`.
        let Some((domaine, fin)) = decouper(nom) else {
            compte.dropped = compte.dropped.saturating_add(1);
            let _ = tokio::fs::remove_file(&chemin).await;
            let _ = tokio::fs::remove_file(&voisin).await;
            return;
        };
        if maintenant.saturating_sub(fin) > PEREMPTION {
            let _ = tokio::fs::remove_file(&chemin).await;
            let _ = tokio::fs::remove_file(&voisin).await;
            compte.dropped = compte.dropped.saturating_add(1);
            return;
        }
        let (Ok(rapport), Ok(destinations)) = (
            tokio::fs::read(&chemin).await,
            tokio::fs::read_to_string(&voisin).await,
        ) else {
            // Sans destination, il n'y a personne à qui l'envoyer. On le laisse :
            // c'est peut-être l'écriture du voisin qui n'a pas abouti.
            compte.deferred = compte.deferred.saturating_add(1);
            return;
        };

        let mut tout_est_regle = true;
        for cible in destinations.lines().filter(|ligne| !ligne.is_empty()) {
            match self.remettre_a(cible, &domaine, nom, &rapport).await {
                Some(true) => compte.sent = compte.sent.saturating_add(1),
                Some(false) => compte.dropped = compte.dropped.saturating_add(1),
                None => {
                    compte.deferred = compte.deferred.saturating_add(1);
                    tout_est_regle = false;
                }
            }
        }
        if tout_est_regle {
            let _ = tokio::fs::remove_file(&chemin).await;
            let _ = tokio::fs::remove_file(&voisin).await;
        }
    }

    /// Remet un rapport à UNE destination.
    ///
    /// `Some(true)` : remis. `Some(false)` : refusé définitivement, inutile
    /// d'insister. `None` : à réessayer.
    async fn remettre_a(
        &self,
        cible: &str,
        domaine: &str,
        nom: &str,
        rapport: &[u8],
    ) -> Option<bool> {
        if let Some(adresse) = cible.strip_prefix("mailto:") {
            return self.par_courrier(adresse, domaine, nom, rapport).await;
        }
        self.par_https(cible, rapport).await
    }

    /// Remet un rapport par courrier (§5.3).
    async fn par_courrier(
        &self,
        adresse: &str,
        domaine: &str,
        nom: &str,
        rapport: &[u8],
    ) -> Option<bool> {
        let relay = self.relay.as_ref()?;
        let cible = adresse.rsplit_once('@').map(|(_, apres)| apres)?;

        let identifiant = std::format!("{}.{}@{}", maintenant(), self.suivant(), self.org_name);
        let mut place = [0_u8; SUBJECT_MAX];
        // **LE SUJET EST CELUI QUE §5.3 IMPOSE**, et non un texte de notre choix :
        // c'est ainsi que le destinataire reconnaît un rapport parmi ce qu'il
        // reçoit.
        let sujet = subject(domaine, &self.org_name, &identifiant, &mut place).ok()?;
        let delimiteur = std::format!("----ams-tlsrpt-{}", self.jeton().await);
        let courrier = ams_mime::ReportMail {
            from: self.email.as_bytes(),
            to: adresse.as_bytes(),
            subject: sujet.as_bytes(),
            message_id: identifiant.as_bytes(),
            date: maintenant(),
            boundary: delimiteur.as_bytes(),
            text: TEXTE,
            filename: nom.as_bytes(),
            attachment: rapport,
        };
        let mut message = std::vec![0_u8; ams_mime::report_mail_max(&courrier)];
        let ecrit = ams_mime::write_report_mail(&mut message, &courrier)
            .ok()?
            .len();
        message.truncate(ecrit);
        let message = self.signer(message).await;

        let destinataires = std::vec![String::from(adresse)];
        let issue = relay
            .send(
                cible,
                &Outgoing {
                    // L'expéditeur d'enveloppe est une VRAIE adresse : c'est par
                    // là qu'un refus nous reviendra, et un rapport dont on ignore
                    // qu'il n'arrive jamais ne vaut pas mieux que pas de rapport.
                    sender: &self.email,
                    recipients: &destinataires,
                    body: &message,
                },
            )
            .await;
        match issue {
            RelayOutcome::Delivered { .. } => Some(true),
            // Un refus définitif RETIRE le rapport : insister remplirait le
            // dossier de messages que personne ne veut.
            RelayOutcome::Rejected(_) | RelayOutcome::NullMx | RelayOutcome::Unsendable => {
                Some(false)
            }
            _ => None,
        }
    }

    /// Remet un rapport par `https:` (§3).
    ///
    /// # LE CERTIFICAT EST VÉRIFIÉ, ET C'EST TOUT L'INTÉRÊT DE CE TRANSPORT
    ///
    /// Un rapport dit ce qui a échoué en joignant un domaine, et à qui. Le POSTER
    /// chez qui l'on n'a pas identifié reviendrait à confier ce diagnostic au
    /// premier venu — et les autorités sont celles que l'exploitant a nommées
    /// pour MTA-STS, parce qu'il n'y a aucune raison d'en avoir deux jeux.
    async fn par_https(&self, url: &str, rapport: &[u8]) -> Option<bool> {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let tls = self.https.as_ref()?;
        let apres = url.strip_prefix("https://")?;
        // Le chemin garde sa barre oblique : `apres` est `hôte/chemin`, et
        // c'est à partir de la barre que le chemin commence.
        let (hote, chemin) = match apres.find('/') {
            Some(rang) => (
                apres.get(..rang).unwrap_or(apres),
                apres.get(rang..).unwrap_or("/"),
            ),
            None => (apres, "/"),
        };
        let nom = rustls::pki_types::ServerName::try_from(std::string::String::from(hote)).ok()?;
        let adresse = self
            .resolveur
            .addresses(hote.as_bytes())
            .await
            .into_iter()
            .next()?;

        let flux = tokio::time::timeout(
            self.delai,
            tokio::net::TcpStream::connect(std::net::SocketAddr::new(adresse, 443)),
        )
        .await
        .ok()?
        .ok()?;
        let connecteur = tokio_rustls::TlsConnector::from(Arc::clone(tls));
        let mut chiffre = tokio::time::timeout(self.delai, connecteur.connect(nom, flux))
            .await
            .ok()?
            .ok()?;

        let entete = std::format!(
            "POST {chemin} HTTP/1.1\r\nHost: {hote}\r\nContent-Type: application/tlsrpt+gzip\r\n\
             Content-Length: {}\r\nConnection: close\r\nUser-Agent: air-mail-server\r\n\r\n",
            rapport.len()
        );
        tokio::time::timeout(self.delai, chiffre.write_all(entete.as_bytes()))
            .await
            .ok()?
            .ok()?;
        tokio::time::timeout(self.delai, chiffre.write_all(rapport))
            .await
            .ok()?
            .ok()?;
        tokio::time::timeout(self.delai, chiffre.flush())
            .await
            .ok()?
            .ok()?;

        let mut recu = Vec::new();
        let mut morceau = [0_u8; 4096];
        loop {
            let lus = tokio::time::timeout(self.delai, chiffre.read(&mut morceau))
                .await
                .ok()?
                .ok()?;
            if lus == 0 {
                break;
            }
            recu.extend_from_slice(morceau.get(..lus).unwrap_or_default());
            if recu.len() > REPONSE_MAX {
                return None;
            }
        }
        let tete = ams_proto_http::parse_response(&recu, REPONSE_MAX).ok()??;
        let classe = tete.status().value() / 100;
        match classe {
            // Accepté.
            2 => Some(true),
            // **UN REFUS DÉFINITIF RETIRE LE RAPPORT.** Une redirection en fait
            // partie : §3 n'en prévoit pas, et la suivre mènerait le rapport là
            // où on ne l'a pas adressé.
            3 | 4 => Some(false),
            // Une panne du serveur : on réessaiera.
            _ => None,
        }
    }

    /// Signe ce qu'on émet, si une clef est là.
    async fn signer(&self, message: Vec<u8>) -> Vec<u8> {
        let Some(signataire) = self.signataire.clone() else {
            return message;
        };
        let de = self.email.clone();
        let quand = maintenant();
        // La signature bloque — c'est un calcul de clef — et l'exécuteur peut
        // être en train de s'arrêter. Un rapport perdu à l'arrêt ne vaut pas
        // qu'on garde une copie du message pour le cas.
        tokio::task::spawn_blocking(move || signataire.sign(message, &de, quand))
            .await
            .unwrap_or_default()
    }

    /// Huit octets d'aléa, en hexadécimal.
    ///
    /// Le délimiteur de parties doit être imprévisible : un tiers qui saurait le
    /// deviner pourrait le glisser dans un contenu et faire découper le message
    /// ailleurs.
    async fn jeton(&self) -> String {
        let mut texte = String::new();
        for _ in 0..8_u8 {
            let octet = self.resolveur.octet().await.unwrap_or(0);
            texte.push(char::from(chiffre_hexa(octet >> 4)));
            texte.push(char::from(chiffre_hexa(octet & 0x0F)));
        }
        texte
    }
}

/// Ce qu'une réponse à un POST peut peser.
const REPONSE_MAX: usize = 16 * 1024;

/// Le texte que lira l'humain qui ouvrira un rapport.
///
/// **Il est en anglais, et c'est délibéré** — la même raison que pour les
/// rapports DMARC : ce message part vers des opérateurs du monde entier, dont la
/// seule langue commune est celle-là, et le composeur n'admet que de l'ASCII.
const TEXTE: &[u8] = b"This is an SMTP TLS report (RFC 8460).\r\n\
    The attached file is the report itself, gzipped JSON.\r\n\
    \r\n\
    This message was generated automatically; replies are not read.\r\n";

/// Un chiffre hexadécimal minuscule.
fn chiffre_hexa(quartet: u8) -> u8 {
    match quartet & 0x0F {
        petit @ 0..=9 => b'0'.wrapping_add(petit),
        grand => b'a'.wrapping_add(grand.wrapping_sub(10)),
    }
}

/// Le domaine rapporté et la fin de période, tirés d'un nom de fichier.
///
/// `<émetteur>!<rapporté>!<début>!<fin>.json.gz` (§5.3).
fn decouper(nom: &str) -> Option<(String, u64)> {
    let corps = nom.strip_suffix(".json.gz")?;
    let mut parts = corps.split('!');
    let _emetteur = parts.next()?;
    let rapporte = parts.next()?;
    let _debut = parts.next()?;
    let fin = parts.next()?.parse().ok()?;
    if parts.next().is_some() || rapporte.is_empty() {
        return None;
    }
    Some((String::from(rapporte), fin))
}

/// Compresse en gzip.
fn comprimer(json: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::io::Write as _;

    let mut encodeur = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encodeur.write_all(json)?;
    encodeur.finish()
}

/// Le nombre de secondes depuis l'époque.
fn maintenant() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |depuis| depuis.as_secs())
}
