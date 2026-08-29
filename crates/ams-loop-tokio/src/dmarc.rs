//! DMARC : l'alignement d'un message qui arrive, et ce qu'on en fait (C9).
//!
//! # C'est ici qu'un message peut être REFUSÉ pour ce qu'il prétend être
//!
//! SPF et DKIM ne refusent rien par eux-mêmes : le premier parle de
//! l'enveloppe, le second d'une signature, et aucun des deux ne dit quoi que ce
//! soit de l'auteur affiché. DMARC les rapproche du `From:` — et c'est le seul
//! endroit du serveur où un message est refusé **pour ce qu'il prétend être**.
//!
//! # Trois choses doivent être réunies, et l'absence d'une seule suffit
//!
//! Le domaine du `From:`, une liste de suffixes publics, et un résolveur. Si
//! l'une manque, DMARC n'évalue rien — et le serveur le dit au démarrage plutôt
//! que de laisser croire à une protection qui n'existe pas.
//!
//! # La quarantaine n'est pas encore un endroit
//!
//! `p=quarantine` demande de traiter le message comme suspect. Ce serveur n'a
//! pas de dossier pour cela : il le REMET, et consigne la demande. Le refuser
//! serait faire plus que ce que le domaine a demandé ; le taire serait faire
//! moins que ce qu'on sait.

use std::string::String;
use std::vec::Vec;

use ams_dmarc::{
    Assessment, Authentication, POLICY_NAME_MAX, Policy, PublicSuffix, Record, Suffixes, Verdict,
    evaluate, policy_name,
};
use ams_mime::{Limits as MimeLimits, Message, author_domain};

use crate::reports::PolitiqueLue;
use crate::resolver::{Resolver, Txt};

/// Ce que DMARC a conclu d'un message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcVerdict {
    /// Un mécanisme a réussi **et** s'aligne.
    Pass,
    /// Aucun ne l'a fait.
    Fail,
    /// Le domaine ne publie pas de politique — la moitié d'internet.
    NoPolicy,
    /// La politique n'a pas pu être résolue. Le pair peut réessayer.
    TempError,
    /// Le `From:` est illisible, ou porte plusieurs auteurs.
    ///
    /// RFC 7489 §6.6.1 : avec deux auteurs, il y a deux politiques, et rien
    /// pour dire laquelle s'applique.
    Unusable,
}

/// Ce qu'on a conclu, et ce qu'on en fait.
#[derive(Debug, Clone)]
pub struct DmarcResult {
    /// Le domaine du `From:`, s'il a pu être lu.
    pub domain: String,
    /// Le verdict.
    pub verdict: DmarcVerdict,
    /// Ce que le domaine demande pour un message non aligné.
    pub policy: Policy,
    /// La politique doit-elle s'appliquer à CE message ?
    ///
    /// Faux quand le verdict passe, quand le domaine ne demande rien, ou quand
    /// le tirage de `pct=` a désigné ce message pour être épargné.
    pub applies: bool,
    /// De quoi rapporter ce message, quand il y avait une politique à lire.
    ///
    /// **`None` veut dire qu'il n'y a rien à rapporter** : un domaine qui ne
    /// publie pas de politique n'attend pas de rapport, et lui en envoyer un
    /// serait du courrier qu'il n'a pas demandé.
    pub report: Option<PourRapport>,
}

/// Ce qu'un rapport dira de la politique qu'on a lue, et à qui.
#[derive(Debug, Clone)]
pub struct PourRapport {
    /// La politique **telle qu'elle a été lue**.
    pub published: PolitiqueLue,
    /// La liste `rua=`, telle quelle. Vide s'il n'y en avait pas.
    pub destinations: String,
    /// DKIM s'alignait-il ?
    pub dkim: Verdict,
    /// SPF s'alignait-il ?
    pub spf: Verdict,
}

/// Ce qu'un message a obtenu de SPF et de DKIM.
#[derive(Debug, Clone, Default)]
pub struct Authenticated {
    /// Le domaine de l'enveloppe, si SPF a rendu `pass`.
    pub spf: Option<String>,
    /// Les domaines dont une signature a été vérifiée.
    pub dkim: Vec<String>,
}

/// De quoi évaluer DMARC.
#[derive(Debug, Clone)]
pub struct DmarcChecker {
    resolveur: Resolver,
    /// La liste des suffixes publics, telle qu'un fichier la porte.
    ///
    /// Partagée par toutes les connexions : elle ne change pas pendant qu'on
    /// sert, et la recopier par message coûterait quelques centaines de
    /// kibioctets à chaque fois.
    suffixes: std::sync::Arc<Vec<u8>>,
    /// Faut-il opposer la politique, ou seulement la consigner ?
    enforce: bool,
}

impl DmarcChecker {
    /// Prépare un évaluateur.
    #[must_use]
    pub fn new(resolveur: Resolver, suffixes: std::sync::Arc<Vec<u8>>, enforce: bool) -> Self {
        Self {
            resolveur,
            suffixes,
            enforce,
        }
    }

    /// Évalue un message.
    ///
    /// `entetes` est le bloc d'en-tête retenu pendant que le corps s'écoulait.
    pub async fn verdict(&self, entetes: &[u8], auth: &Authenticated) -> DmarcResult {
        let mut resultat = DmarcResult {
            domain: String::new(),
            verdict: DmarcVerdict::Unusable,
            policy: Policy::None,
            applies: false,
            report: None,
        };

        let Some(from) = domaine_de_l_auteur(entetes) else {
            return resultat;
        };
        resultat.domain = String::from_utf8_lossy(&from).into_owned();

        // ── La politique se cherche en DEUX temps (§6.6.3) ──────────────────
        //
        // Sous le domaine du `From:` d'abord ; s'il n'y a rien, sous son
        // domaine organisationnel — et c'est alors `sp=` qui décide, puisque le
        // message vient d'un sous-domaine.
        let liste = Suffixes::new(&self.suffixes);
        let (texte, sous_domaine) = match self.politique(&from).await {
            Trouvee::Absente => {
                let organisationnel = liste.organizational_domain(&from);
                if organisationnel == from.as_slice() {
                    resultat.verdict = DmarcVerdict::NoPolicy;
                    return resultat;
                }
                match self.politique(organisationnel).await {
                    Trouvee::Absente => {
                        resultat.verdict = DmarcVerdict::NoPolicy;
                        return resultat;
                    }
                    Trouvee::Panne => {
                        resultat.verdict = DmarcVerdict::TempError;
                        return resultat;
                    }
                    Trouvee::Politique(texte) => (texte, true),
                }
            }
            Trouvee::Panne => {
                resultat.verdict = DmarcVerdict::TempError;
                return resultat;
            }
            Trouvee::Politique(texte) => (texte, false),
        };

        let Ok(enregistrement) = Record::parse(&texte) else {
            // Un enregistrement qu'on ne sait pas lire n'est pas une politique
            // (§6.6.3) : on fait comme s'il n'y en avait pas.
            resultat.verdict = DmarcVerdict::NoPolicy;
            return resultat;
        };

        let signataires: Vec<&[u8]> = auth.dkim.iter().map(|nom| nom.as_bytes()).collect();
        let authentification = Authentication {
            spf: auth.spf.as_ref().map(|nom| nom.as_bytes()),
            dkim: &signataires,
        };
        let juge: Assessment = evaluate(
            &enregistrement,
            &from,
            sous_domaine,
            &authentification,
            &liste,
        );

        resultat.report = Some(PourRapport {
            published: PolitiqueLue {
                dkim_alignment: enregistrement.dkim_alignment,
                spf_alignment: enregistrement.spf_alignment,
                policy: enregistrement.policy,
                subdomain_policy: enregistrement.subdomain_policy,
                percent: enregistrement.percent,
            },
            destinations: enregistrement
                .aggregate_reports
                .map(|brut| String::from_utf8_lossy(brut).into_owned())
                .unwrap_or_default(),
            dkim: juge.dkim,
            spf: juge.spf,
        });
        resultat.policy = juge.policy;
        resultat.verdict = match juge.verdict {
            Verdict::Pass => DmarcVerdict::Pass,
            Verdict::Fail => DmarcVerdict::Fail,
        };
        resultat.applies = juge.verdict == Verdict::Fail
            && juge.policy != Policy::None
            && self.enforce
            && self.tire_au_sort(juge.percent).await;
        resultat
    }

    /// Cherche la politique d'un domaine.
    async fn politique(&self, domaine: &[u8]) -> Trouvee {
        let mut nom = [0_u8; POLICY_NAME_MAX];
        let Ok(nom) = policy_name(domaine, &mut nom) else {
            return Trouvee::Absente;
        };
        match self.resolveur.txt(nom).await {
            // Un domaine publie des `TXT` pour bien des raisons : on prend le
            // premier qui commence par `v=DMARC1`, et l'on ignore les autres
            // (§6.6.3).
            Txt::Trouves(textes) => textes
                .into_iter()
                .find(|texte| texte.trim_ascii_start().starts_with(b"v=DMARC1"))
                .map_or(Trouvee::Absente, Trouvee::Politique),
            Txt::Absent => Trouvee::Absente,
            Txt::Panne => Trouvee::Panne,
        }
    }

    /// Ce message fait-il partie des `pct` % auxquels la politique s'applique ?
    ///
    /// # Le tirage est UNIFORME, et il le reste
    ///
    /// Prendre un octet modulo cent biaiserait le tirage : deux cent
    /// cinquante-six ne se divise pas par cent, et les vingt-huit premières
    /// valeurs sortiraient plus souvent. On rejette donc ce qui dépasse deux
    /// cents. Un domaine qui demande `pct=10` a le droit d'obtenir dix pour
    /// cent, pas onze.
    async fn tire_au_sort(&self, pourcent: u8) -> bool {
        if pourcent >= 100 {
            return true;
        }
        if pourcent == 0 {
            return false;
        }
        for _ in 0..8_u8 {
            let Ok(octet) = self.resolveur.octet().await else {
                // Sans aléa, on n'invente pas : la politique s'applique, ce qui
                // est ce que le domaine a demandé pour la part qu'il vise.
                return true;
            };
            if octet < 200 {
                return octet % 100 < pourcent;
            }
        }
        true
    }
}

/// Ce qu'une recherche de politique a rendu.
enum Trouvee {
    /// Un enregistrement qui se présente comme du DMARC.
    Politique(Vec<u8>),
    /// Le domaine n'en publie pas.
    Absente,
    /// On n'a pas su demander.
    Panne,
}

/// Le domaine du `From:`, s'il y en a un et un seul.
fn domaine_de_l_auteur(entetes: &[u8]) -> Option<Vec<u8>> {
    let message = Message::parse(entetes, &MimeLimits::DEFAULT).ok()?;
    // §6.6.1 : DEUX champs `From:` valent un message inutilisable, tout comme
    // deux adresses dans un seul champ. La RFC 5322 §3.6 n'en admet qu'un.
    let mut trouves = message.fields().filter(|champ| champ.name_is(b"From"));
    let champ = trouves.next()?;
    if trouves.next().is_some() {
        return None;
    }
    author_domain(champ.raw_value()).ok().map(<[u8]>::to_vec)
}
