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
//! # Ce qui est fait ici, et ce qui ne l'est pas
//!
//! Les rapports sont **comptés, composés, nommés, compressés et déposés** dans
//! un dossier. Ils ne sont pas ENVOYÉS : envoyer demande un client SMTP sortant,
//! que ce serveur n'a pas encore. Le dire ainsi vaut mieux que de laisser croire
//! qu'un `rua=` publié suffit à recevoir quelque chose.
//!
//! Ce qui est déposé est néanmoins **prêt à partir** : le fichier porte le nom
//! exact qu'exige §7.2.1.1, il est gzippé comme §7.2.1 l'impose, et un second
//! fichier `.destinations` dit à qui il revient — après vérification.
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
use ams_dmarc::report::naming::{FILENAME_MAX, filename};
use ams_dmarc::report::uri::{Uris, decode};
use ams_dmarc::{Alignment, Policy, Verdict};

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

/// Le journal des observations, et le dossier où leurs rapports se déposent.
#[derive(Debug)]
pub struct ReportSpool {
    /// Le nom du receveur — le nôtre — tel qu'il figurera dans les rapports.
    org_name: String,
    /// L'adresse à laquelle nous joindre à propos d'un rapport.
    email: String,
    /// Où déposer.
    directory: PathBuf,
    /// De quoi vérifier les destinations externes (§7.1).
    resolveur: Resolver,
    journal: Mutex<HashMap<String, Domaine>>,
    /// Le début de la période courante, en secondes depuis l'époque.
    debut: Mutex<u64>,
    /// De quoi distinguer deux rapports d'une même seconde.
    numero: AtomicU64,
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
            journal: Mutex::new(HashMap::new()),
            debut: Mutex::new(maintenant()),
            numero: AtomicU64::new(0),
        }
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
