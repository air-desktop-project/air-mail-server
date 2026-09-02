//! Le journal des rapports DMARC (RFC 7489 §7.2) : ce qu'on a vu, et où le dire.
//!
//! # Un rapport est ce qui permet à un domaine de durcir sans casser
//!
//! `p=none` demande à voir avant d'agir. **Voir, c'est recevoir des receveurs le
//! compte de ce qui a été émis en son nom** : quelle adresse, combien de
//! messages, et ce que SPF et DKIM en ont dit. Sans cela, un domaine qui passe à
//! `p=reject` découvre ses propres prestataires oubliés en même temps que ses
//! correspondants découvrent que son courrier ne passe plus.
//!
//! # Deux gestes, et un dossier entre les deux
//!
//! Les rapports sont **comptés, composés, nommés, compressés et déposés** dans
//! un dossier ; puis, dans un second temps, **remis**. Le dossier n'est pas une
//! commodité : c'est ce qui fait qu'un rapport composé survit à un redémarrage,
//! à une panne de réseau, à un serveur d'en face qui ne répond pas ce jour-là.
//!
//! Chaque rapport y porte le nom exact qu'exige §7.2.1.1, il est gzippé comme
//! §7.2.1 l'impose, et un second fichier `.destinations` dit à qui il revient —
//! après la vérification de §7.1.
//!
//! # CE QUI EST REMIS EST RETIRÉ, ET CE QUI EST REFUSÉ AUSSI
//!
//! Un rapport remis n'a plus lieu d'être ; un rapport qu'un domaine refuse
//! définitivement (`5yz`) non plus — insister remplirait le dossier de messages
//! que personne ne veut, et harcèlerait un serveur qui a dit non. Un refus
//! TEMPORAIRE, lui, laisse le fichier en place : c'est tout l'intérêt de l'avoir
//! écrit sur un disque.
//!
//! Et **un rapport vieilli s'efface**. Sans cette borne, un domaine injoignable
//! ferait croître le dossier sans fin, et l'on réessaierait des années durant
//! d'envoyer le compte d'une journée que plus personne ne peut exploiter.
//!
//! # LES DESTINATIONS SONT VÉRIFIÉES AVANT D'ÊTRE ÉCRITES
//!
//! Un `rua=` est publié par le domaine qu'on rapporte, c'est-à-dire, quand cela
//! compte, par celui qui usurpe. Sans le contrôle de §7.1, DMARC devient un
//! amplificateur : un enregistrement, et tous les receveurs du monde envoient
//! des rapports à une victime qui n'a rien demandé. Le contrôle a lieu **une
//! fois par période et par domaine**, au moment de la vidange — pas à chaque
//! message, qui multiplierait les interrogations sans rien apprendre de plus.

use std::collections::HashMap;
use std::format;
use std::net::IpAddr;
use std::path::PathBuf;
use std::string::String;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use std::vec::Vec;

use ams_dmarc::report::aggregate::{
    DkimAuth, DkimAuthResult, Metadata, Published, Row, SpfAuth, SpfAuthResult, SpfScope, begin,
};
use ams_dmarc::report::external::{
    VERIFICATION_NAME_MAX, authorizes, needs_verification, verification_name,
};
use ams_dmarc::report::failure::{
    AuthFailure, DeliveryResult, FeedbackReport, feedback_report_max, write_feedback_report,
};
use ams_dmarc::report::naming::{FILENAME_MAX, SUBJECT_MAX, filename, subject};
use ams_dmarc::report::uri::{Uris, decode};
use ams_dmarc::{Alignment, Policy, Verdict};
use ams_mime::{
    DATE_MAX, FailureMail, Limits as MimeLimits, ReportMail, failure_mail_max, report_mail_max,
    write_date, write_failure_mail, write_report_mail,
};

use crate::delivery::DeliveryFailure;
use crate::dkim::DkimSigner;
use crate::resolver::{Resolver, Txt};

/// La politique telle qu'elle a été LUE — pas celle qu'on croit qu'elle est.
///
/// Le domaine compare ce bloc à ce qu'il a publié. S'ils diffèrent, c'est sa
/// zone qui ne dit pas ce qu'il pense, et c'est précisément ce qu'il veut
/// apprendre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolitiqueLue {
    /// `adkim=`.
    pub dkim_alignment: Alignment,
    /// `aspf=`.
    pub spf_alignment: Alignment,
    /// `p=`.
    pub policy: Policy,
    /// `sp=`, s'il était là.
    pub subdomain_policy: Option<Policy>,
    /// `pct=`.
    pub percent: u8,
}

/// Une signature examinée, telle que le rapport la nommera.
#[derive(Debug, Clone)]
pub struct SignatureVue {
    /// Le domaine signataire (`d=`).
    pub domain: String,
    /// Le sélecteur (`s=`) — vide s'il n'a pas pu être lu.
    pub selector: String,
    /// Ce que la vérification a donné.
    pub result: DkimAuthResult,
}

/// Ce que SPF a donné, tel que le rapport le nommera.
#[derive(Debug, Clone)]
pub struct SpfVu {
    /// Le domaine vérifié.
    pub domain: String,
    /// Laquelle des deux identités.
    pub scope: SpfScope,
    /// Le résultat.
    pub result: SpfAuthResult,
}

/// Un message, tel qu'un rapport le décrira.
#[derive(Debug, Clone)]
pub struct Observation {
    /// Le domaine du `From:`, qui publie la politique.
    pub domain: String,
    /// Ce que sa politique disait.
    pub published: PolitiqueLue,
    /// Sa liste `rua=`, telle quelle.
    pub destinations: String,
    /// D'où le message est venu.
    pub source: IpAddr,
    /// Ce qu'on a **fait** — qui n'est pas toujours ce qui était demandé.
    pub disposition: Policy,
    /// DKIM s'alignait-il ?
    pub dkim: Verdict,
    /// SPF s'alignait-il ?
    pub spf: Verdict,
    /// Le domaine de l'enveloppe.
    pub envelope_from: Option<String>,
    /// Les signatures examinées.
    pub signatures: Vec<SignatureVue>,
    /// L'évaluation SPF.
    pub spf_auth: SpfVu,
}

/// Ce qu'une vidange a produit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SpoolTally {
    /// Rapports déposés.
    pub reports: u64,
    /// Lignes qu'ils portent, toutes périodes confondues.
    pub rows: u64,
    /// Destinations retenues après vérification.
    pub destinations: u64,
    /// Destinations ÉCARTÉES faute de consentement (§7.1).
    ///
    /// **Ce nombre n'est pas un incident** : c'est le compte des envois qu'on
    /// n'a pas faits vers quelqu'un qui ne les avait pas demandés.
    pub refused: u64,
    /// Rapports qu'on n'a pas su écrire.
    pub errors: u64,
}

/// Un message dont l'authentification a échoué, tel qu'un rapport le décrira.
///
/// **Celui-ci parle d'UN message, pas d'un compte.** C'est ce qui le rend
/// délicat : voir `ams_mime::EXPOSES`, qui décide de ce qui sort d'ici.
#[derive(Debug, Clone)]
pub struct FailureObservation {
    /// Le domaine du `From:`, qui publie la politique.
    pub domain: String,
    /// Sa liste `ruf=`, telle quelle.
    pub destinations: String,
    /// D'où le message est venu.
    pub source: IpAddr,
    /// Quand il est arrivé, en secondes depuis l'époque.
    pub arrival: u64,
    /// Le domaine de l'enveloppe.
    pub envelope_from: Option<String>,
    /// Le domaine d'une signature examinée.
    pub dkim_domain: Option<String>,
    /// Son sélecteur.
    pub dkim_selector: Option<String>,
    /// Le domaine que SPF a examiné.
    pub spf_domain: Option<String>,
    /// Le message a-t-il été refusé ?
    pub rejected: bool,
    /// DKIM s'alignait-il ?
    pub aligned_dkim: bool,
    /// SPF s'alignait-il ?
    pub aligned_spf: bool,
    /// Le bloc d'en-tête du message, **tel qu'il est arrivé**.
    pub headers: Vec<u8>,
}

/// Ce qu'une tournée de remise a produit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SendTally {
    /// Rapports remis, et retirés du dossier.
    pub sent: u64,
    /// Rapports qu'un domaine a refusés définitivement, et retirés eux aussi.
    pub rejected: u64,
    /// Rapports laissés en place pour une prochaine fois.
    pub deferred: u64,
    /// Rapports trop vieux, effacés sans avoir été remis.
    pub expired: u64,
    /// Rapports qu'on n'a pas su composer ou lire.
    pub unsendable: u64,
}

/// Le journal des observations, et le dossier où leurs rapports se déposent.
#[derive(Debug)]
pub struct ReportSpool {
    /// Le nom du receveur — le nôtre — tel qu'il figurera dans les rapports.
    org_name: String,
    /// L'adresse à laquelle nous joindre à propos d'un rapport.
    email: String,
    /// Où déposer.
    directory: PathBuf,
    /// De quoi vérifier les destinations externes (§7.1), et tirer un
    /// délimiteur de parties imprévisible.
    resolveur: Resolver,
    /// De quoi remettre les rapports, si ce serveur les envoie.
    /// La file d'attente du serveur, si l'exploitant a demandé la remise.
    ///
    /// **CE N'EST PLUS UN REMETTEUR.** Un rapport n'est pas moins un message
    /// qu'un autre : il passe par la même file, la même attente qui double, la
    /// même péremption, et le même rapport de non-remise quand on renonce.
    /// Trois politiques de reprise dans un produit, c'est trois vérités qui
    /// divergent — et deux d'entre elles n'avaient jamais été éprouvées.
    file: Option<std::sync::Arc<crate::queue::Spool>>,
    /// De quoi les SIGNER, si ce serveur a une clé.
    ///
    /// **Ce qu'on émet vaut ce que vaut son authentification** : un rapport
    /// DMARC non signé arrive chez un domaine qui, précisément, se méfie de ce
    /// qui n'est pas authentifié. Sans clé, on émet quand même — un rapport non
    /// signé vaut mieux qu'aucun rapport.
    dkim: Option<DkimSigner>,
    /// Compose-t-on des rapports d'ÉCHEC ?
    ///
    /// **Ils portent le courrier de quelqu'un** — voir `ams_mime::EXPOSES` —
    /// et ce n'est pas une décision qu'on prend à la place de celui qui exploite
    /// la machine.
    echecs_actifs: bool,
    journal: Mutex<HashMap<String, Domaine>>,
    /// Le début de la période courante, en secondes depuis l'époque.
    debut: Mutex<u64>,
    /// De quoi distinguer deux rapports d'une même seconde.
    numero: AtomicU64,
    /// Combien de rapports d'échec ce domaine a déjà valus, sur la période.
    echecs: Mutex<HashMap<String, u32>>,
}

/// Ce qu'on a retenu d'un domaine sur la période.
#[derive(Debug)]
struct Domaine {
    published: PolitiqueLue,
    destinations: String,
    /// Les lignes, par ce qui les rend identiques, et leur compte.
    lignes: HashMap<String, (Observation, u32)>,
}

impl ReportSpool {
    /// Ouvre un journal.
    #[must_use]
    pub fn new(org_name: String, email: String, directory: PathBuf, resolveur: Resolver) -> Self {
        Self {
            org_name,
            email,
            directory,
            resolveur,
            file: None,
            dkim: None,
            echecs_actifs: false,
            journal: Mutex::new(HashMap::new()),
            debut: Mutex::new(maintenant()),
            numero: AtomicU64::new(0),
            echecs: Mutex::new(HashMap::new()),
        }
    }

    /// Donne à ce journal de quoi SIGNER ce qu'il compose.
    ///
    /// Sans signataire, les rapports partent non signés : ils restent
    /// recevables, et l'absence de clé n'est pas une raison de se taire.
    #[must_use]
    pub fn with_dkim(mut self, signataire: DkimSigner) -> Self {
        self.dkim = Some(signataire);
        self
    }

    /// Donne à ce journal de quoi remettre ce qu'il compose.
    ///
    /// **Sans remetteur, les rapports sont déposés et rien de plus.** C'est un
    /// état parfaitement défendable — un opérateur peut les relever lui-même —
    /// et c'est le défaut : émettre du courrier vers des tiers ne se décide pas
    /// à la place de celui qui exploite la machine.
    #[must_use]
    pub fn with_queue(mut self, file: std::sync::Arc<crate::queue::Spool>) -> Self {
        self.file = Some(file);
        self
    }

    /// Autorise ce journal à composer des rapports d'ÉCHEC.
    ///
    /// **Sans cela, aucun n'est composé, et c'est le défaut.** Un rapport
    /// d'échec parle d'un message précis, arrivé chez quelqu'un ; l'envoyer est
    /// une décision, pas un réglage.
    #[must_use]
    pub fn with_failure_reports(mut self) -> Self {
        self.echecs_actifs = true;
        self
    }

    /// Retient un message de plus.
    ///
    /// # Deux messages qui se ressemblent ne font qu'une ligne
    ///
    /// C'est ce qui fait tenir une journée en quelques lignes, et c'est aussi ce
    /// qui garantit qu'un rapport ne dit jamais rien d'un message en
    /// particulier : il ne porte que des comptes.
    pub fn observer(&self, observation: Observation) {
        let cle = cle_de(&observation);
        let Ok(mut journal) = self.journal.lock() else {
            // Un verrou empoisonné veut dire qu'un fil a paniqué en le tenant.
            // On perd ce message-là pour le journal ; on ne perd pas le service.
            return;
        };
        let domaine = journal
            .entry(observation.domain.clone())
            .or_insert_with(|| Domaine {
                published: observation.published,
                destinations: observation.destinations.clone(),
                lignes: HashMap::new(),
            });
        // LA DERNIÈRE POLITIQUE LUE FAIT FOI : un domaine qui change la sienne
        // en cours de période veut voir la nouvelle, pas celle d'hier matin.
        domaine.published = observation.published;
        domaine.destinations.clone_from(&observation.destinations);
        let ligne = domaine
            .lignes
            .entry(cle)
            .or_insert_with(|| (observation, 0));
        ligne.1 = ligne.1.saturating_add(1);
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
    pub async fn vider(&self) -> SpoolTally {
        let mut compte = SpoolTally::default();
        let fin = maintenant();
        let debut = match self.debut.lock() {
            Ok(mut depart) => core::mem::replace(&mut *depart, fin),
            Err(_) => return compte,
        };
        let domaines = match self.journal.lock() {
            Ok(mut journal) => core::mem::take(&mut *journal),
            Err(_) => return compte,
        };
        // La période se referme aussi pour les rapports d'échec : leur plafond
        // repart à zéro.
        if let Ok(mut echecs) = self.echecs.lock() {
            echecs.clear();
        }
        if domaines.is_empty() {
            return compte;
        }
        if tokio::fs::create_dir_all(&self.directory).await.is_err() {
            compte.errors = u64::try_from(domaines.len()).unwrap_or(u64::MAX);
            return compte;
        }
        for (nom, domaine) in domaines {
            self.deposer(&nom, &domaine, debut, fin, &mut compte).await;
        }
        compte
    }

    /// Dépose le rapport d'un domaine.
    async fn deposer(
        &self,
        domaine: &str,
        retenu: &Domaine,
        debut: u64,
        fin: u64,
        compte: &mut SpoolTally,
    ) {
        let numero = self.numero.fetch_add(1, Ordering::Relaxed);
        let identifiant = format!("{fin}.{numero}");
        let lignes: Vec<&(Observation, u32)> = retenu.lignes.values().collect();

        let metadata = Metadata {
            org_name: self.org_name.as_bytes(),
            email: self.email.as_bytes(),
            extra_contact: None,
            report_id: identifiant.as_bytes(),
            begin: debut,
            end: fin,
        };
        let publiee = Published {
            domain: domaine.as_bytes(),
            dkim_alignment: retenu.published.dkim_alignment,
            spf_alignment: retenu.published.spf_alignment,
            policy: retenu.published.policy,
            subdomain_policy: retenu.published.subdomain_policy,
            percent: retenu.published.percent,
        };

        let Some(xml) = composer_en_grandissant(&metadata, &publiee, &lignes) else {
            compte.errors = compte.errors.saturating_add(1);
            return;
        };
        let Ok(comprime) = comprimer(&xml) else {
            compte.errors = compte.errors.saturating_add(1);
            return;
        };

        let mut place = [0_u8; FILENAME_MAX];
        let Ok(nom) = filename(
            self.org_name.as_bytes(),
            domaine.as_bytes(),
            debut,
            fin,
            Some(identifiant.as_bytes()),
            &mut place,
        ) else {
            compte.errors = compte.errors.saturating_add(1);
            return;
        };
        let Ok(nom) = core::str::from_utf8(nom) else {
            compte.errors = compte.errors.saturating_add(1);
            return;
        };

        let chemin = self.directory.join(nom);
        if tokio::fs::write(&chemin, &comprime).await.is_err() {
            compte.errors = compte.errors.saturating_add(1);
            return;
        }
        compte.reports = compte.reports.saturating_add(1);
        compte.rows = compte
            .rows
            .saturating_add(u64::try_from(lignes.len()).unwrap_or(0));

        let (adresses, ecartees) = self.destinations(domaine, &retenu.destinations).await;
        compte.refused = compte.refused.saturating_add(ecartees);
        compte.destinations = compte
            .destinations
            .saturating_add(u64::try_from(adresses.len()).unwrap_or(0));
        if !adresses.is_empty() {
            let liste = adresses.join("\n");
            let mut voisin = chemin.clone().into_os_string();
            voisin.push(".destinations");
            let _ = tokio::fs::write(voisin, format!("{liste}\n")).await;
        }
    }

    /// Les destinations qu'on a le droit d'employer, et le compte des autres.
    async fn destinations(&self, domaine: &str, brutes: &str) -> (Vec<String>, u64) {
        let mut retenues = Vec::new();
        let mut ecartees = 0_u64;
        for destination in Uris::new(brutes.as_bytes()) {
            let Ok(uri) = destination else {
                ecartees = ecartees.saturating_add(1);
                continue;
            };
            // Un schéma qu'on ne sait pas servir s'ignore (§6.2) : ce serveur
            // ne remet que du courrier.
            let Some(cible) = uri.domain() else { continue };
            let mut clair = [0_u8; 512];
            let Ok(adresse) = decode(uri.target, &mut clair) else {
                ecartees = ecartees.saturating_add(1);
                continue;
            };
            let Ok(adresse) = core::str::from_utf8(adresse) else {
                ecartees = ecartees.saturating_add(1);
                continue;
            };
            if needs_verification(domaine.as_bytes(), cible)
                && !self.consent(domaine.as_bytes(), cible).await
            {
                ecartees = ecartees.saturating_add(1);
                continue;
            }
            retenues.push(String::from(adresse));
        }
        (retenues, ecartees)
    }

    /// Cette destination a-t-elle publié son consentement (§7.1) ?
    async fn consent(&self, domaine: &[u8], cible: &[u8]) -> bool {
        let mut place = [0_u8; VERIFICATION_NAME_MAX];
        let Ok(nom) = verification_name(domaine, cible, &mut place) else {
            return false;
        };
        match self.resolveur.txt(nom).await {
            Txt::Trouves(textes) => textes.iter().any(|texte| authorizes(texte)),
            // UNE PANNE N'EST PAS UN CONSENTEMENT. Envoyer « au cas où » est
            // exactement ce que §7.1 existe pour empêcher.
            Txt::Absent | Txt::Panne => false,
        }
    }
}

/// Le texte que lira l'humain qui ouvrira un rapport.
///
/// **Il est en anglais, et c'est délibéré.** Ce message part vers des systèmes
/// et des opérateurs du monde entier, dont la seule langue commune est
/// celle-là ; et le composeur n'admet que de l'ASCII, ce qui exclut d'écrire un
/// français correct. Un texte sans accents serait une troisième langue, que
/// personne ne parle.
const TEXTE: &[u8] = b"This is a DMARC aggregate report (RFC 7489).\r\n    The attached file is the report itself, gzipped XML.\r\n    \r\n    This message was generated automatically; replies are not read.\r\n";

impl ReportSpool {
    /// Remet ce qui attend dans le dossier.
    ///
    /// **ELLE NE REMET PLUS ELLE-MÊME** : elle DÉPOSE EN FILE. La reprise, la
    /// péremption et le rapport de non-remise appartiennent à `ams-queue`, où
    /// ils sont couverts à 100 % — il n'y a plus qu'une politique dans ce
    /// produit.
    ///
    /// Ne fait rien sans file : voir [`ReportSpool::with_queue`].
    pub async fn envoyer(&self) -> SendTally {
        let mut compte = SendTally::default();
        let Some(file) = self.file.as_ref() else {
            return compte;
        };
        let Ok(mut entrees) = tokio::fs::read_dir(&self.directory).await else {
            return compte;
        };
        let maintenant = maintenant();
        while let Ok(Some(entree)) = entrees.next_entry().await {
            let chemin = entree.path();
            let Some(nom) = chemin.file_name().and_then(|brut| brut.to_str()) else {
                continue;
            };
            // DEUX FORMES DE FICHIER, UNE SEULE TOURNÉE. Un rapport agrégé se
            // compose au moment de partir — il faut sa date de départ ; un
            // rapport d'échec, lui, a été composé au moment des faits, parce
            // qu'il parle d'un message qu'on n'a plus.
            if let Some(parts) = decouper_le_nom(nom) {
                let nom = String::from(nom);
                self.remettre(file, &parts, &chemin, &nom, maintenant, &mut compte)
                    .await;
            } else if let Some(parts) = decouper_un_echec(nom) {
                self.remettre_tel_quel(file, &parts, &chemin, maintenant, &mut compte)
                    .await;
            }
            // Ce qui n'a ni l'une ni l'autre forme n'est pas à nous : on n'y
            // touche pas. Un dossier qu'on partage avec autre chose ne se
            // nettoie pas au jugé.
        }
        compte
    }

    /// Dépose un rapport en file, et décide de ce qu'on fait du fichier.
    async fn remettre(
        &self,
        file: &crate::queue::Spool,
        parts: &Nomme,
        chemin: &std::path::Path,
        nom: &str,
        maintenant: u64,
        compte: &mut SendTally,
    ) {
        let voisin = {
            let mut voisin = chemin.to_path_buf().into_os_string();
            voisin.push(".destinations");
            PathBuf::from(voisin)
        };
        let (Ok(piece), Ok(destinations)) = (
            tokio::fs::read(chemin).await,
            tokio::fs::read_to_string(&voisin).await,
        ) else {
            // Sans destination vérifiée, il n'y a personne à qui l'envoyer. On
            // le laisse : c'est peut-être la vérification qui n'a pas abouti.
            compte.deferred = compte.deferred.saturating_add(1);
            return;
        };

        let mut tout_est_regle = true;
        for adresse in destinations.lines().filter(|ligne| !ligne.is_empty()) {
            match self
                .deposer_pour(file, parts, nom, &piece, adresse, maintenant)
                .await
            {
                // **LE RAPPORT EST EN FILE : IL EST PARTI, POUR CE MODULE.** Ce
                // qu'il advient ensuite — les essais, la péremption, l'avis de
                // non-remise dans la boîte du postmaster — appartient à la file.
                Ok(()) => compte.sent = compte.sent.saturating_add(1),
                // Ce qu'aucune reprise n'arrangerait : une adresse qu'on refuse
                // d'écrire, un message qu'on n'a pas su composer.
                Err(DeliveryFailure::Permanent) => {
                    compte.unsendable = compte.unsendable.saturating_add(1);
                }
                // Une écriture qui a échoué : le fichier reste, et c'est tout
                // l'intérêt de l'avoir écrit sur un disque.
                Err(DeliveryFailure::Temporary) => {
                    compte.deferred = compte.deferred.saturating_add(1);
                    tout_est_regle = false;
                }
            }
        }
        if tout_est_regle {
            let _ = tokio::fs::remove_file(chemin).await;
            let _ = tokio::fs::remove_file(&voisin).await;
        }
    }

    /// Dépose en file un message DÉJÀ COMPOSÉ, tel qu'il est sur le disque.
    async fn remettre_tel_quel(
        &self,
        file: &crate::queue::Spool,
        _parts: &Nomme,
        chemin: &std::path::Path,
        maintenant: u64,
        compte: &mut SendTally,
    ) {
        let voisin = {
            let mut voisin = chemin.to_path_buf().into_os_string();
            voisin.push(".destinations");
            PathBuf::from(voisin)
        };
        let (Ok(message), Ok(destinations)) = (
            tokio::fs::read(chemin).await,
            tokio::fs::read_to_string(&voisin).await,
        ) else {
            compte.deferred = compte.deferred.saturating_add(1);
            return;
        };
        let Some(adresse) = destinations.lines().find(|ligne| !ligne.is_empty()) else {
            compte.unsendable = compte.unsendable.saturating_add(1);
            return;
        };
        let destinataires = std::vec![String::from(adresse)];
        match file.deposer(&self.email, &destinataires, &[], "", &message, maintenant) {
            Ok(()) => compte.sent = compte.sent.saturating_add(1),
            Err(DeliveryFailure::Permanent) => {
                compte.unsendable = compte.unsendable.saturating_add(1);
            }
            Err(DeliveryFailure::Temporary) => {
                compte.deferred = compte.deferred.saturating_add(1);
                return;
            }
        }
        let _ = tokio::fs::remove_file(chemin).await;
        let _ = tokio::fs::remove_file(&voisin).await;
    }

    /// Compose le message, et le DÉPOSE EN FILE pour cette adresse.
    ///
    /// # Errors
    ///
    /// [`DeliveryFailure::Permanent`] pour ce qu'aucune reprise n'arrangerait —
    /// une adresse qu'on refuse d'écrire, un message qu'on n'a pas su composer ;
    /// [`DeliveryFailure::Temporary`] pour une écriture qui a échoué.
    async fn deposer_pour(
        &self,
        file: &crate::queue::Spool,
        parts: &Nomme,
        nom: &str,
        piece: &[u8],
        adresse: &str,
        maintenant: u64,
    ) -> Result<(), DeliveryFailure> {
        let mut sujet = [0_u8; SUBJECT_MAX];
        let sujet = subject(
            parts.domaine.as_bytes(),
            self.org_name.as_bytes(),
            parts.identifiant.as_bytes(),
            &mut sujet,
        )
        .map_err(|_| DeliveryFailure::Permanent)?;
        let identifiant = format!("{}.{}@{}", parts.identifiant, parts.debut, self.org_name);
        let delimiteur = format!("----ams-{}", self.jeton().await);
        let courrier = ReportMail {
            from: self.email.as_bytes(),
            to: adresse.as_bytes(),
            subject: sujet,
            message_id: identifiant.as_bytes(),
            date: maintenant,
            boundary: delimiteur.as_bytes(),
            text: TEXTE,
            filename: nom.as_bytes(),
            attachment: piece,
        };
        let mut message = std::vec![0_u8; report_mail_max(&courrier)];
        // **UN MESSAGE QU'ON NE SAIT PAS COMPOSER NE SE COMPOSERA PAS MIEUX
        // DEMAIN** : c'est définitif, et le laisser sur le disque ne ferait que
        // le relire tous les jours.
        let ecrit = write_report_mail(&mut message, &courrier)
            .map_err(|_| DeliveryFailure::Permanent)?
            .len();
        message.truncate(ecrit);
        // **ON SIGNE UNE FOIS, ET LA FILE RÉÉMET LES MÊMES OCTETS.** Signer à
        // chaque essai donnerait des signatures différentes pour un même
        // rapport, et rendrait insoluble la question de savoir laquelle est
        // arrivée.
        let message = self.signer(message).await;

        // L'expéditeur d'enveloppe est une VRAIE adresse, et non l'expéditeur
        // nul : c'est par là qu'un refus nous reviendra, et c'est aussi là que
        // la file déposera son rapport de non-remise si elle renonce.
        let destinataires = std::vec![String::from(adresse)];
        file.deposer(&self.email, &destinataires, &[], "", &message, maintenant)
    }

    /// Huit octets d'aléa, en hexadécimal.
    ///
    /// Le délimiteur de parties doit être imprévisible : un tiers qui saurait le
    /// deviner pourrait le glisser dans un contenu et faire découper le message
    /// ailleurs. Le composeur refuse déjà un délimiteur qui figure dans une
    /// partie ; l'aléa ferme la porte de l'autre côté.
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

/// Un chiffre hexadécimal minuscule.
fn chiffre_hexa(quartet: u8) -> u8 {
    match quartet & 0x0F {
        petit @ 0..=9 => b'0'.wrapping_add(petit),
        grand => b'a'.wrapping_add(grand.wrapping_sub(10)),
    }
}

/// Ce qu'un nom de fichier de rapport porte (§7.2.1.1).
#[derive(Debug, PartialEq, Eq)]
struct Nomme {
    domaine: String,
    debut: u64,
    fin: u64,
    identifiant: String,
}

/// Découpe `failure!domaine!date!identifiant.eml`.
fn decouper_un_echec(nom: &str) -> Option<Nomme> {
    let corps = nom.strip_suffix(".eml")?;
    let mut parts = corps.split('!');
    if parts.next()? != "failure" {
        return None;
    }
    let domaine = parts.next()?;
    let date = parts.next()?.parse().ok()?;
    let identifiant = parts.next()?;
    if parts.next().is_some() || domaine.is_empty() || identifiant.is_empty() {
        return None;
    }
    Some(Nomme {
        domaine: String::from(domaine),
        debut: date,
        fin: date,
        identifiant: String::from(identifiant),
    })
}

/// Découpe `receveur!domaine!début!fin!identifiant.xml.gz`.
///
/// **Rien de ce qui n'a pas cette forme n'est touché.** Un dossier qu'on partage
/// avec autre chose ne se nettoie pas au jugé.
fn decouper_le_nom(nom: &str) -> Option<Nomme> {
    let corps = nom.strip_suffix(".xml.gz")?;
    let mut parts = corps.split('!');
    let _receveur = parts.next()?;
    let domaine = parts.next()?;
    let debut = parts.next()?.parse().ok()?;
    let fin = parts.next()?.parse().ok()?;
    let identifiant = parts.next()?;
    if parts.next().is_some() || domaine.is_empty() || identifiant.is_empty() {
        return None;
    }
    Some(Nomme {
        domaine: String::from(domaine),
        debut,
        fin,
        identifiant: String::from(identifiant),
    })
}

/// Ce qui fait que deux messages ne comptent que pour une ligne.
fn cle_de(observation: &Observation) -> String {
    let mut cle = format!(
        "{}|{:?}|{:?}|{:?}|{}|{:?}|{:?}|{}",
        observation.source,
        observation.disposition,
        observation.dkim,
        observation.spf,
        observation.envelope_from.as_deref().unwrap_or_default(),
        observation.spf_auth.scope,
        observation.spf_auth.result,
        observation.spf_auth.domain,
    );
    for signature in &observation.signatures {
        cle.push_str(&format!(
            "|{}:{}:{:?}",
            signature.domain, signature.selector, signature.result
        ));
    }
    cle
}

/// Compose le rapport, en agrandissant le tampon tant qu'il ne suffit pas.
///
/// # Pourquoi on double, et pourquoi on s'arrête
///
/// La crate `ams-dmarc` n'alloue pas (C1) : elle écrit dans le tampon qu'on lui
/// donne et dit quand il déborde. C'est donc ici qu'on décide de la mémoire —
/// et **on en décide une borne** : un domaine très visé pourrait faire croître
/// ce tampon sans fin, et un rapport qu'on ne peut pas écrire vaut mieux qu'un
/// serveur qui s'épuise à l'écrire.
fn composer_en_grandissant(
    metadata: &Metadata<'_>,
    publiee: &Published<'_>,
    lignes: &[&(Observation, u32)],
) -> Option<Vec<u8>> {
    /// Huit mébioctets : quelques dizaines de milliers de lignes.
    const PLAFOND: usize = 8 * 1024 * 1024;
    let mut taille = 16 * 1024;
    loop {
        let mut tampon = std::vec![0_u8; taille];
        match composer(&mut tampon, metadata, publiee, lignes) {
            Ok(ecrits) => {
                tampon.truncate(ecrits);
                return Some(tampon);
            }
            Err(ams_dmarc::Error::BufferTooSmall) if taille < PLAFOND => {
                taille = taille.saturating_mul(2);
            }
            Err(_) => return None,
        }
    }
}

/// Écrit le rapport, et rend sa longueur.
fn composer(
    tampon: &mut [u8],
    metadata: &Metadata<'_>,
    publiee: &Published<'_>,
    lignes: &[&(Observation, u32)],
) -> Result<usize, ams_dmarc::Error> {
    let mut rapport = begin(tampon, metadata, publiee)?;
    for (observation, compte) in lignes {
        let signatures: Vec<DkimAuth<'_>> = observation
            .signatures
            .iter()
            .map(|signature| DkimAuth {
                domain: signature.domain.as_bytes(),
                selector: (!signature.selector.is_empty()).then_some(signature.selector.as_bytes()),
                result: signature.result,
            })
            .collect();
        rapport.record(&Row {
            source_ip: observation.source,
            count: *compte,
            disposition: observation.disposition,
            dkim: observation.dkim,
            spf: observation.spf,
            header_from: observation.domain.as_bytes(),
            envelope_from: observation.envelope_from.as_deref().map(str::as_bytes),
            envelope_to: None,
            dkim_auth: &signatures,
            spf_auth: SpfAuth {
                domain: observation.spf_auth.domain.as_bytes(),
                scope: observation.spf_auth.scope,
                result: observation.spf_auth.result,
            },
        })?;
    }
    Ok(rapport.finish()?.len())
}

/// Compresse le rapport comme §7.2.1 l'exige.
fn comprimer(xml: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::io::Write as _;

    let mut encodeur = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encodeur.write_all(xml)?;
    encodeur.finish()
}

/// Le nombre de secondes depuis l'époque.
///
/// Une horloge avant 1970 rendrait zéro : un rapport daté de l'époque se
/// remarque, là où une soustraction qui déborde ne se remarquerait pas.
fn maintenant() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |ecoule| ecoule.as_secs())
}

/// Combien de rapports d'échec un même domaine peut valoir, par période.
///
/// # SANS CE PLAFOND, UNE USURPATION EN MASSE DEVIENT UN DÉLUGE
///
/// Un rapport d'échec part par message. Quelqu'un qui usurpe un domaine cent
/// mille fois nous ferait donc écrire cent mille messages à ce domaine — qui n'a
/// rien demandé de tel, et qui en subirait les conséquences à notre place. La
/// RFC 6591 §5 le dit, et c'est une des raisons pour lesquelles tant de
/// receveurs n'envoient aucun rapport d'échec.
///
/// Cent par période et par domaine : assez pour comprendre un flux mal
/// configuré, trop peu pour nuire.
const ECHECS_MAX_PAR_DOMAINE: u32 = 100;

/// Le texte que lira l'humain qui ouvrira un rapport d'échec.
const TEXTE_ECHEC: &[u8] = b"This is a DMARC authentication failure report (RFC 6591).\r\n\
    The message headers below have been filtered: recipients and internal\r\n\
    routing are never included, and no message body is ever sent.\r\n\
    \r\n\
    This message was generated automatically; replies are not read.\r\n";

impl ReportSpool {
    /// Compose et dépose un rapport d'échec.
    ///
    /// Ne fait rien si le domaine a déjà atteint son plafond sur la période, ni
    /// si aucune destination n'a consenti (§7.1).
    pub async fn echec(&self, observation: &FailureObservation) {
        if !self.echecs_actifs {
            return;
        }
        if !self.sous_le_plafond(&observation.domain) {
            return;
        }
        let (adresses, _) = self
            .destinations(&observation.domain, &observation.destinations)
            .await;
        if adresses.is_empty() {
            return;
        }
        if tokio::fs::create_dir_all(&self.directory).await.is_err() {
            return;
        }
        // UN MESSAGE PAR DESTINATION, et non un message pour plusieurs. Le
        // `To:` d'un rapport doit nommer celui qui le reçoit ; en composer un
        // seul pour deux adresses ferait qu'au moins l'un des deux lirait le nom
        // de l'autre.
        for adresse in &adresses {
            let Some(message) = self.composer_echec(observation, adresse).await else {
                continue;
            };
            let numero = self.numero.fetch_add(1, Ordering::Relaxed);
            let nom = format!(
                "failure!{}!{}!{}.{}.eml",
                observation.domain, observation.arrival, observation.arrival, numero
            );
            let chemin = self.directory.join(&nom);
            if tokio::fs::write(&chemin, &message).await.is_err() {
                continue;
            }
            let mut voisin = chemin.into_os_string();
            voisin.push(".destinations");
            let _ = tokio::fs::write(voisin, format!("{adresse}\n")).await;
        }
    }

    /// Ce domaine a-t-il encore droit à un rapport d'échec sur cette période ?
    fn sous_le_plafond(&self, domaine: &str) -> bool {
        let Ok(mut echecs) = self.echecs.lock() else {
            // Un verrou empoisonné veut dire qu'un fil a paniqué en le tenant.
            // On n'envoie rien plutôt que d'envoyer sans compter.
            return false;
        };
        let compte = echecs.entry(String::from(domaine)).or_insert(0);
        if *compte >= ECHECS_MAX_PAR_DOMAINE {
            return false;
        }
        *compte = compte.saturating_add(1);
        true
    }

    /// Compose le message d'un rapport d'échec, prêt à partir.
    async fn composer_echec(
        &self,
        observation: &FailureObservation,
        destinataire: &str,
    ) -> Option<Vec<u8>> {
        let mut date = [0_u8; DATE_MAX];
        let date = write_date(observation.arrival, &mut date).ok()?;
        let agent = concat!("air-mail-server/", env!("CARGO_PKG_VERSION"));
        let rapport = FeedbackReport {
            user_agent: agent.as_bytes(),
            arrival_date: date,
            source_ip: observation.source,
            reported_domain: observation.domain.as_bytes(),
            original_mail_from: observation.envelope_from.as_deref().map(str::as_bytes),
            dkim_domain: observation.dkim_domain.as_deref().map(str::as_bytes),
            dkim_selector: observation.dkim_selector.as_deref().map(str::as_bytes),
            spf_dns: observation.spf_domain.as_deref().map(str::as_bytes),
            auth_failure: AuthFailure::Dmarc,
            delivery_result: if observation.rejected {
                DeliveryResult::Rejected
            } else {
                DeliveryResult::Delivered
            },
            aligned_dkim: observation.aligned_dkim,
            aligned_spf: observation.aligned_spf,
        };
        let mut champs = std::vec![0_u8; feedback_report_max(&rapport)];
        let ecrits = write_feedback_report(&mut champs, &rapport).ok()?.len();
        champs.truncate(ecrits);

        let sujet = format!("DMARC failure report for {}", observation.domain);
        let identifiant = format!(
            "{}.{}@{}",
            observation.arrival,
            self.numero.load(Ordering::Relaxed),
            self.org_name
        );
        let delimiteur = format!("----ams-{}", self.jeton().await);
        let courrier = FailureMail {
            from: self.email.as_bytes(),
            to: destinataire.as_bytes(),
            subject: sujet.as_bytes(),
            message_id: identifiant.as_bytes(),
            date: observation.arrival,
            boundary: delimiteur.as_bytes(),
            text: TEXTE_ECHEC,
            feedback: &champs,
            reported_headers: &observation.headers,
        };
        let mut message = std::vec![0_u8; failure_mail_max(&courrier)];
        let ecrit = write_failure_mail(&mut message, &courrier, &MimeLimits::DEFAULT)
            .ok()?
            .len();
        message.truncate(ecrit);
        Some(self.signer(message).await)
    }

    /// Signe un message, s'il y a de quoi.
    ///
    /// # LA SIGNATURE SORT DE LA BOUCLE
    ///
    /// Une exponentiation RSA privée occupe le fil des millisecondes durant, et
    /// l'aveuglement lit `/dev/urandom`. Les deux sont bloquants ; les laisser
    /// dans une tâche asynchrone ferait attendre toutes celles qui la
    /// partagent, pour un travail qui n'attend rien.
    async fn signer(&self, message: Vec<u8>) -> Vec<u8> {
        let Some(signataire) = self.dkim.clone() else {
            return message;
        };
        let de = self.email.clone();
        let quand = maintenant();
        // La tâche ne panique pas — la signature ne panique pas —, mais
        // l'exécuteur peut être en train de s'arrêter. Un rapport perdu à
        // l'arrêt ne vaut pas qu'on garde une copie du message pour le cas.
        tokio::task::spawn_blocking(move || signataire.sign(message, &de, quand))
            .await
            .unwrap_or_default()
    }
}
