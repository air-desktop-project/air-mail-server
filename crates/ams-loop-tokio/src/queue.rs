//! La file de réémission sortante : ce que ce serveur émet POUR SES COMPTES.
//!
//! # CE QUE CE MODULE FAIT, ET CE QU'IL NE DÉCIDE PAS
//!
//! Il écrit, il relit, il renomme et il efface — c'est l'étage 3. Ce qu'il ne
//! décide pas : quand réessayer, quand renoncer, et comment s'appelle une entrée.
//! Tout cela vit dans `ams-queue`, qui est couvert à 100 % parce qu'une
//! arithmétique qui se trompe ici PERD DU COURRIER.
//!
//! # DEUX FICHIERS, ET LEURS NOMS NE CHANGENT PAS ENSEMBLE
//!
//! - `<prochain>!<dépôt>!<essais>!<identifiant>.eml` — le message. **Son nom
//!   porte tout l'état de la reprise**, et un `rename()` le fait passer d'un
//!   état à l'autre en une opération que le système de fichiers rend atomique.
//! - `<identifiant>.enveloppe` — d'où vient le message et à qui il va.
//!
//! **Le nom de l'enveloppe ne dépend QUE de l'identifiant**, et c'est ce qui
//! rend la reprise atomique : renommer le message ne demande pas de renommer
//! l'enveloppe, si bien qu'il n'y a jamais deux renommages à réussir ensemble.
//!
//! L'ordre d'écriture suit : **l'enveloppe d'abord, le message ensuite**. Le
//! parcours ne regarde que les `.eml`, donc il ne peut pas voir un message sans
//! son enveloppe. L'inverse — une enveloppe sans message, après une coupure
//! entre les deux — est inerte, et ramassée par l'âge (voir `parcourir`).
//!
//! # UN ENVOI PAR DESTINATAIRE, ET C'EST DÉLIBÉRÉ
//!
//! `RelayOutcome::Delivered` compte les destinataires refusés ; il ne les NOMME
//! pas. Or un rapport de non-remise doit dire QUI n'a pas été servi, et pourquoi.
//! Grouper par domaine rendrait donc un rapport qui devrait deviner, et un
//! rapport qui devine se trompe sur l'adresse d'un tiers.
//!
//! Le coût est réel — une transaction par destinataire au lieu d'une par
//! domaine — et il est assumé : il se paie en connexions, tandis que l'autre se
//! paierait en rapports faux. Le jour où `RelayOutcome` nommera les refusés,
//! le groupement redeviendra possible sans rien perdre.

use std::path::{Path, PathBuf};
use std::string::{String, ToString as _};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use std::vec::Vec;

use ams_mime::{Action as MimeAction, Bounce, Failure, bounce_max, write_bounce};
use ams_queue::{
    Backoff, Decision, Entry, Envelope, NAME_MAX, RECIPIENTS_MAX, Report, envelope_max,
    parse_envelope, parse_name, write_envelope, write_name,
};

use ams_session::{ClientDsn, ClientReport};

use crate::delivery::DeliveryFailure;
use crate::relay::{Outgoing, Refus, Relay, RelayOutcome};

/// Combien d'en-tête d'un message perdu part dans son rapport.
///
/// **LE CORPS N'Y EST PAS** (voir `ams_mime::bounce`), et l'en-tête lui-même est
/// borné : un message dont l'en-tête ferait un mégaoctet donnerait un rapport
/// qu'aucun client n'ouvrirait, écrit précisément parce qu'on n'arrivait pas à
/// émettre.
const ENTETES_MAX: usize = 16 * 1024;

/// Ce qu'un parcours de la file a donné.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueueTally {
    /// Messages entièrement remis.
    pub sent: usize,
    /// Remises dont le pair a été AUTHENTIFIÉ par DANE (RFC 7672).
    ///
    /// **Ce n'est pas « chiffrées ».** Le chiffrement opportuniste écarte
    /// l'espion passif ; DANE écarte l'attaquant actif, parce que le domaine a
    /// dit lui-même, dans son DNS signé, quel certificat il présenterait. Le
    /// compte est rendu pour qu'on voie la différence — une protection qu'on ne
    /// voit pas est une protection qu'on croit avoir.
    pub authenticated: usize,
    /// Messages abandonnés, avec un rapport de non-remise.
    pub bounced: usize,
    /// Messages remis à plus tard.
    pub deferred: usize,
    /// Entrées qu'on n'a pas su relire, et qui ont été retirées.
    pub unreadable: usize,
    /// Rapports qu'on n'a PAS pu remettre à leur destinataire.
    ///
    /// # C'EST LE COMPTE QUI DIT UNE PERTE SÈCHE
    ///
    /// Les autres disent ce qu'on a fait ; celui-ci dit ce qu'on n'a pas su
    /// faire savoir. Quand il monte, quelqu'un croit avoir écrit et personne ne
    /// le détrompera : le message est déjà effacé, et le rapport qui devait
    /// l'annoncer n'est pas arrivé.
    ///
    /// **IL EXISTE PARCE QUE `bounced` MENTAIT.** Ce dernier comptait un
    /// abandon « avec un rapport de non-remise » — et il l'incrémentait aussi
    /// quand le rapport s'était perdu. Une supervision branchée dessus voyait un
    /// serveur en parfaite santé pendant qu'il perdait du courrier en silence,
    /// et la seule trace était une ligne sur la sortie d'erreur qu'il fallait
    /// lire au bon moment.
    ///
    /// Les trois rapports y sont comptés — non-remise, relais, retard —, parce
    /// que les trois se perdent de la même façon et coûtent la même chose : une
    /// nouvelle que son destinataire attendait.
    pub reports_lost: usize,
}

/// Ce qui remet un rapport de non-remise, LOCALEMENT.
///
/// # POURQUOI CE N'EST PAS `Relay`
///
/// Ce serveur ne relaie que pour ses propres comptes, si bien que le chemin de
/// retour est TOUJOURS l'une de ses adresses. Le rapport se dépose donc dans une
/// boîte, et **aucun rebond ne part vers un inconnu** : c'est ce qui tient ce
/// serveur hors de la rétro-diffusion — émettre un rebond vers une adresse qu'un
/// tiers a écrite dans un `MAIL FROM:` usurpé ferait de nous l'instrument de son
/// envoi.
///
/// Le routage vers une boîte appartient au serveur, pas à cette boucle : d'où le
/// trait.
pub trait Bounced {
    /// Dépose ce rapport dans la boîte de `recipient`.
    ///
    /// Rend `false` quand l'adresse ne mène nulle part ou que l'écriture a
    /// échoué. **Le rapport est alors perdu**, et l'appelant le journalise : il
    /// n'y a rien de plus à faire — un rapport dont le rapport échouerait ne
    /// finirait jamais.
    fn deliver(&self, recipient: &str, message: &[u8]) -> bool;
}

/// La file, et ce qu'elle décide de ses entrées.
#[derive(Debug, Clone)]
pub struct Spool {
    dossier: PathBuf,
    reprise: Backoff,
    /// Le nom que ce serveur annonce — le `Reporting-MTA` des rapports.
    mta: String,
    /// L'adresse qui émet les rapports de non-remise.
    postmaster: String,
    /// Ce qui distingue deux dépôts de la même nanoseconde.
    suite: Arc<AtomicU64>,
}

impl Spool {
    /// Prépare une file.
    #[must_use]
    pub fn new(dossier: PathBuf, reprise: Backoff, mta: String, postmaster: String) -> Self {
        Self {
            dossier,
            reprise,
            mta,
            postmaster,
            suite: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Le dossier de la file.
    #[must_use]
    pub fn dossier(&self) -> &Path {
        &self.dossier
    }

    /// Dépose un message à émettre.
    ///
    /// **Appelée depuis la tâche de connexion**, donc synchrone et brève : un
    /// tampon, deux `rename()`. C'est la même discipline que la remise Maildir.
    ///
    /// # Errors
    ///
    /// [`DeliveryFailure::Permanent`] pour ce qu'aucune reprise n'arrangerait —
    /// une adresse qu'on refuse d'écrire, plus de destinataires que la borne ;
    /// [`DeliveryFailure::Temporary`] pour une écriture qui a échoué.
    pub fn deposer(
        &self,
        return_path: &str,
        recipients: &[String],
        reports: &[Report<'_>],
        envelope_id: &str,
        message: &[u8],
        now: u64,
    ) -> Result<(), DeliveryFailure> {
        if recipients.is_empty() || recipients.len() > RECIPIENTS_MAX {
            return Err(DeliveryFailure::Permanent);
        }
        let identifiant = self.identifiant(now);
        let adresses: Vec<&str> = recipients.iter().map(String::as_str).collect();
        let enveloppe = Envelope {
            return_path,
            recipients: &adresses,
            envelope_id,
            reports,
        };
        let mut tampon = std::vec![0_u8; envelope_max(&enveloppe)];
        // UNE ADRESSE QU'ON REFUSE D'ÉCRIRE EST UN REFUS DÉFINITIF : un `LF`
        // glissé dedans ajouterait un destinataire au fichier, et aucune reprise
        // ne le rendrait acceptable.
        let ecrite =
            write_envelope(&enveloppe, &mut tampon).map_err(|_| DeliveryFailure::Permanent)?;

        // L'ENVELOPPE D'ABORD : le parcours ne regarde que les `.eml`, si bien
        // qu'il ne peut pas voir un message dont l'enveloppe manque.
        poser(&self.chemin_d_enveloppe(&identifiant), ecrite.as_bytes())
            .map_err(|()| DeliveryFailure::Temporary)?;

        let entree = Entry {
            // **DÛ TOUT DE SUITE** : le premier essai n'attend pas. Une attente
            // avant le premier essai retarderait tout le courrier légitime pour
            // ménager les pannes, qui sont l'exception.
            due: now,
            deposited: now,
            attempts: 0,
            id: &identifiant,
        };
        let mut nom = [0_u8; NAME_MAX];
        let nom = write_name(&entree, &mut nom).map_err(|_| DeliveryFailure::Permanent)?;
        poser(&self.dossier.join(nom), message).map_err(|()| DeliveryFailure::Temporary)?;
        Ok(())
    }

    /// Reprend tout ce qui est dû, et rend ce que le passage a donné.
    ///
    /// `now` est l'heure en secondes depuis l'époque. Rien n'est touché de ce qui
    /// n'a pas la forme d'une entrée : un dossier qu'on partage avec autre chose
    /// ne se reprend pas au jugé, et ne s'efface pas non plus.
    pub async fn parcourir<B: Bounced>(&self, relay: &Relay, rendre: &B, now: u64) -> QueueTally {
        let mut compte = QueueTally::default();
        let Ok(mut dossier) = tokio::fs::read_dir(&self.dossier).await else {
            return compte;
        };
        // On rassemble les noms AVANT de travailler : renommer pendant qu'on
        // parcourt ferait revoir la même entrée sous son nouveau nom, et donc
        // réessayer sans attendre.
        let mut a_faire = Vec::new();
        let mut enveloppes = Vec::new();
        while let Ok(Some(entree)) = dossier.next_entry().await {
            let nom = entree.file_name();
            let Some(nom) = nom.to_str() else {
                continue;
            };
            if let Some(part) = parse_name(nom) {
                if part.due <= now {
                    a_faire.push((
                        String::from(nom),
                        part.deposited,
                        part.attempts,
                        String::from(part.id),
                    ));
                }
            } else if let Some(orphelin) = nom.strip_suffix(".enveloppe") {
                enveloppes.push((String::from(orphelin), entree));
            }
        }

        for (nom, depot, essais, identifiant) in a_faire {
            self.reprendre(
                relay,
                rendre,
                &nom,
                depot,
                essais,
                &identifiant,
                now,
                &mut compte,
            )
            .await;
        }
        self.ramasser_les_orphelines(enveloppes, now).await;
        compte
    }

    /// Reprend UNE entrée.
    #[expect(
        clippy::too_many_arguments,
        reason = "les quatre morceaux du nom se lisent une fois, au parcours ; les \
                  rassembler dans une structure ne dirait rien de plus et ferait un \
                  type de plus à tenir"
    )]
    async fn reprendre<B: Bounced>(
        &self,
        relay: &Relay,
        rendre: &B,
        nom: &str,
        depot: u64,
        essais: u32,
        identifiant: &str,
        now: u64,
        compte: &mut QueueTally,
    ) {
        let chemin = self.dossier.join(nom);
        let voisin = self.chemin_d_enveloppe(identifiant);
        let (Ok(message), Ok(fichier)) = (
            tokio::fs::read(&chemin).await,
            tokio::fs::read_to_string(&voisin).await,
        ) else {
            // **SANS ENVELOPPE, ON NE SAIT NI À QUI REMETTRE NI À QUI RENDRE
            // COMPTE.** Garder l'entrée ne servirait qu'à relire indéfiniment un
            // fichier qui ne dira jamais rien de plus.
            let _ = tokio::fs::remove_file(&chemin).await;
            let _ = tokio::fs::remove_file(&voisin).await;
            compte.unreadable = compte.unreadable.saturating_add(1);
            return;
        };
        let mut cases = [""; RECIPIENTS_MAX];
        let mut rapports = [Report::default(); RECIPIENTS_MAX];
        let Ok(enveloppe) = parse_envelope(&fichier, &mut cases, &mut rapports) else {
            let _ = tokio::fs::remove_file(&chemin).await;
            let _ = tokio::fs::remove_file(&voisin).await;
            compte.unreadable = compte.unreadable.saturating_add(1);
            return;
        };

        // ── L'essai, UN DESTINATAIRE À LA FOIS ──────────────────────────────
        let mut restants: Vec<String> = Vec::new();
        let mut rapports_restants: Vec<Report<'_>> = Vec::new();
        let mut echecs: Vec<Sort> = Vec::new();
        let mut succes: Vec<(String, String)> = Vec::new();
        let mut retards: Vec<Sort> = Vec::new();
        // **UN SEUL APPEL À L'HORLOGE POUR TOUTE LA REPRISE.** Deux lectures
        // pourraient tomber de part et d'autre du seuil, et le même message
        // serait tantôt en retard, tantôt non, pour deux destinataires voisins.
        let en_retard = self.reprise.is_late(depot, now);
        for (rang, adresse) in enveloppe.recipients.iter().enumerate() {
            // **CE QUE CE DESTINATAIRE-LÀ A DEMANDÉ**, et non ce que le premier
            // a demandé pour tout le monde (RFC 3461 §4.1).
            let rapport = enveloppe.reports.get(rang).copied().unwrap_or_default();
            let a_passer = [ClientReport {
                never: rapport.never,
                on_success: rapport.on_success,
                original: rapport.original.as_bytes(),
            }];
            match self
                .remettre_a(
                    relay,
                    enveloppe.return_path,
                    adresse,
                    &message,
                    demande_a_passer(enveloppe.envelope_id, &a_passer),
                )
                .await
            {
                Issue::Remis {
                    authentifie,
                    dsn_transmis,
                } => {
                    if authentifie {
                        compte.authenticated = compte.authenticated.saturating_add(1);
                    }
                    // §4.1 : un rapport de SUCCÈS ne part que s'il est demandé.
                    // `NEVER` l'emporte sur tout, y compris sur lui-même.
                    //
                    // **ET PAS SI LE SAUT SUIVANT S'EN CHARGE** (§5.2.1) : deux
                    // rapports pour un même envoi laisseraient le déposant sans
                    // savoir lequel croire, et le nôtre serait le moins informé
                    // des deux — nous ne savons pas ce qu'il adviendra ensuite.
                    if rapport.on_success && !rapport.never && !dsn_transmis {
                        succes.push(((*adresse).to_string(), rapport.original.to_owned()));
                    }
                }
                Issue::Definitif(statut, dit_par_le_pair, observe) => {
                    // **`NEVER` FAIT PERDRE LE RAPPORT, ET C'EST CE QU'ON A
                    // DEMANDÉ.** Un déposant qui l'écrit sait que l'échec lui
                    // échappera ; le lui envoyer quand même serait lui refuser
                    // ce qu'il a explicitement demandé.
                    if !rapport.never {
                        echecs.push(Sort {
                            adresse: (*adresse).to_string(),
                            statut,
                            dit_par_le_pair,
                            observe,
                            origine: rapport.original.to_owned(),
                        });
                    }
                }
                Issue::Ajourne(statut, dit_par_le_pair, observe) => {
                    // **L'AVIS DE RETARD PART UNE FOIS, ET SEULEMENT SI ON L'A
                    // DEMANDÉ** (§4.1). `NEVER` l'emporte, comme partout, et le
                    // bit `delay_sent` — écrit dans l'enveloppe juste après —
                    // est ce qui empêche la reprise suivante d'en envoyer un de
                    // plus. Sans lui, un pair en panne une journée vaudrait
                    // deux cents avis vers un chemin de retour que personne n'a
                    // authentifié.
                    let mut rapport = rapport;
                    if en_retard && rapport.on_delay && !rapport.never && !rapport.delay_sent {
                        retards.push(Sort {
                            adresse: (*adresse).to_string(),
                            statut,
                            dit_par_le_pair,
                            observe,
                            origine: rapport.original.to_owned(),
                        });
                        rapport.delay_sent = true;
                    }
                    restants.push((*adresse).to_string());
                    rapports_restants.push(rapport);
                }
            }
        }

        // **L'AVIS DE RETARD PART AVANT LA RÉÉCRITURE DE L'ENVELOPPE.**
        //
        // L'ordre est le seul qui perde peu. Émettre puis écrire risque un avis
        // envoyé deux fois si la machine s'arrête entre les deux ; écrire puis
        // émettre risque un avis JAMAIS envoyé. Un avis de retard en double est
        // une gêne ; un avis perdu est la promesse de §4.1 rompue, sans que
        // personne l'apprenne.
        if !retards.is_empty()
            && !self.rendre_le_retard(
                rendre,
                enveloppe.return_path,
                &message,
                &retards,
                enveloppe.envelope_id,
                depot,
                now,
            )
        {
            compte.reports_lost = compte.reports_lost.saturating_add(1);
            std::eprintln!(
                "air-mail-server : AVIS DE RETARD PERDU pour `{}` — le message attend \
                 toujours, et son expéditeur ne le saura pas",
                enveloppe.return_path
            );
        }

        // **LE RAPPORT DE SUCCÈS PART AVANT TOUTE DÉCISION DE REPRISE.** Ceux
        // qui sont remis le sont, quoi qu'il advienne des autres : attendre la
        // fin de la file ferait dépendre un rapport de succès de l'échec d'un
        // voisin.
        if !succes.is_empty()
            && !self.rendre_le_succes(
                rendre,
                enveloppe.return_path,
                &message,
                &succes,
                enveloppe.envelope_id,
                depot,
                now,
            )
        {
            compte.reports_lost = compte.reports_lost.saturating_add(1);
            std::eprintln!(
                "air-mail-server : RAPPORT DE REMISE PERDU pour `{}` — le message est bien \
                 parti, et son expéditeur ne le saura pas",
                enveloppe.return_path
            );
        }

        let essais = essais.saturating_add(1);
        let decision = if restants.is_empty() {
            // Plus rien à réessayer : la décision ne se pose pas.
            Decision::GiveUp
        } else {
            self.reprise.after_failure(depot, essais, now)
        };

        match decision {
            Decision::Retry { at } if !restants.is_empty() => {
                // ON RÉÉCRIT L'ENVELOPPE AVANT DE RENOMMER : un destinataire déjà
                // servi qui y resterait recevrait le message une seconde fois si
                // la machine s'arrêtait entre les deux.
                if !self.reecrire(
                    &voisin,
                    enveloppe.return_path,
                    &restants,
                    &rapports_restants,
                    enveloppe.envelope_id,
                ) {
                    compte.deferred = compte.deferred.saturating_add(1);
                    return;
                }
                let suivante = Entry {
                    due: at,
                    deposited: depot,
                    attempts: essais,
                    id: identifiant,
                };
                let mut place = [0_u8; NAME_MAX];
                if let Ok(nouveau) = write_name(&suivante, &mut place) {
                    let _ = tokio::fs::rename(&chemin, self.dossier.join(nouveau)).await;
                }
                compte.deferred = compte.deferred.saturating_add(1);
            }
            // Renoncer : ce qui restait à réessayer devient un échec définitif.
            Decision::Retry { .. } | Decision::GiveUp => {
                for (rang, adresse) in restants.iter().enumerate() {
                    // **CE QUE CE DESTINATAIRE-LÀ AVAIT DEMANDÉ**, jusqu'au
                    // bout : un `NEVER` vaut aussi pour la péremption.
                    let rapport = rapports_restants.get(rang).copied().unwrap_or_default();
                    if rapport.never {
                        continue;
                    }
                    echecs.push(Sort {
                        adresse: adresse.clone(),
                        statut: String::from("4.4.7"),
                        // **LA PÉREMPTION EST NOTRE DÉCISION**, pas celle du
                        // pair : il n'a rien dit qu'on puisse lui attribuer.
                        dit_par_le_pair: String::new(),
                        observe: String::from("delivery time expired"),
                        origine: rapport.original.to_owned(),
                    });
                }
                let _ = tokio::fs::remove_file(&chemin).await;
                let _ = tokio::fs::remove_file(&voisin).await;
                if echecs.is_empty() {
                    compte.sent = compte.sent.saturating_add(1);
                } else {
                    // **UN RAPPORT QUI NE PART PAS SE DIT.** Le message est déjà
                    // effacé ; si personne ne l'apprend, l'expéditeur croira
                    // avoir écrit. C'est la seule chose qu'il reste à faire — un
                    // rapport dont le rapport échouerait ne finirait jamais.
                    if self.rendre_compte(
                        rendre,
                        enveloppe.return_path,
                        &message,
                        &echecs,
                        enveloppe.envelope_id,
                        depot,
                        now,
                    ) {
                        compte.bounced = compte.bounced.saturating_add(1);
                    } else {
                        // **`bounced` NE COMPTE QUE CE QUI A ÉTÉ ANNONCÉ.** Il
                        // l'incrémentait aussi quand le rapport se perdait, si
                        // bien qu'une supervision voyait un abandon proprement
                        // rapporté là où personne n'avait rien reçu.
                        compte.reports_lost = compte.reports_lost.saturating_add(1);
                        std::eprintln!(
                            "air-mail-server : RAPPORT DE NON-REMISE PERDU pour `{}` — le \
                             message est abandonné, et son expéditeur ne le saura pas",
                            enveloppe.return_path
                        );
                    }
                }
            }
        }
    }

    /// Remet le message à UN destinataire, et classe ce qui s'est passé.
    ///
    /// `dsn` est ce que CE destinataire-là avait demandé (RFC 3461 §4.1) : la
    /// demande est par destinataire, et en passer une seule pour toute la
    /// transaction ferait honorer celle du dernier pour tout le monde.
    async fn remettre_a(
        &self,
        relay: &Relay,
        retour: &str,
        adresse: &str,
        message: &[u8],
        dsn: Option<ClientDsn<'_>>,
    ) -> Issue {
        let Some((_, domaine)) = adresse.rsplit_once('@') else {
            // Une adresse sans domaine n'a pas de serveur : rien ne l'arrangera.
            return Issue::Definitif(
                String::from("5.1.3"),
                // **LE PAIR N'A RIEN DIT** : on n'a même pas su à qui parler.
                String::new(),
                String::from("bad destination address"),
            );
        };
        let destinataires = std::vec![String::from(adresse)];
        let issue = relay
            .send(
                domaine,
                &Outgoing {
                    sender: retour,
                    recipients: &destinataires,
                    body: message,
                    dsn,
                },
            )
            .await;
        match issue {
            // `refused` ne peut valoir que zéro : il n'y avait qu'un destinataire,
            // et un refus l'aurait rendu par `Rejected`.
            RelayOutcome::Delivered {
                authenticated,
                dsn_forwarded,
                ..
            } => Issue::Remis {
                authentifie: authenticated,
                dsn_transmis: dsn_forwarded,
            },
            RelayOutcome::Rejected(refus) => {
                let (statut, dit) = ce_qu_a_dit_le_pair(&refus, true);
                let observe = std::format!("{} rejected by remote server", refus.code);
                Issue::Definitif(statut, dit, observe)
            }
            // §RFC 7505 : le domaine déclare ne recevoir AUCUN courrier. C'est un
            // refus publié à l'avance, et le confondre avec une panne ferait
            // réessayer des jours durant ce qu'un domaine a explicitement fermé.
            RelayOutcome::NullMx => Issue::Definitif(
                String::from("5.1.2"),
                String::new(),
                String::from("destination domain accepts no mail (null MX)"),
            ),
            // **CE QUI VIENT DE NOUS EST DÉFINITIF.** Un message qu'on ne sait pas
            // émettre — un `LF` isolé dans le corps — ne s'émettra pas mieux dans
            // six heures, et le réessayer cinq jours durant ne ferait que retarder
            // la nouvelle.
            RelayOutcome::Unsendable => Issue::Definitif(
                String::from("5.6.0"),
                String::new(),
                String::from("message cannot be transmitted as written"),
            ),
            // **UNE POLITIQUE QUI NE NOMME PAS CE SERVEUR AJOURNE**, et ne
            // refuse pas : c'est le domaine qui se trompe, ou qui vient de
            // changer de `MX`, et il corrigera. Rendre le message à son
            // expéditeur pour cela le punirait d'une faute qui n'est pas la
            // sienne.
            RelayOutcome::PolicyMismatch => Issue::Ajourne(
                String::from("4.7.0"),
                String::new(),
                String::from("destination policy does not list this server"),
            ),
            RelayOutcome::Deferred(refus) => {
                let (statut, dit) = ce_qu_a_dit_le_pair(&refus, false);
                let observe = std::format!("{} deferred by remote server", refus.code);
                Issue::Ajourne(statut, dit, observe)
            }
            RelayOutcome::Unreachable => Issue::Ajourne(
                String::from("4.4.1"),
                String::new(),
                String::from("no answer from destination server"),
            ),
            RelayOutcome::NoEncryption => Issue::Ajourne(
                String::from("4.7.4"),
                String::new(),
                String::from("destination server offers no encryption, and it is required"),
            ),
            RelayOutcome::Protocol => Issue::Ajourne(
                String::from("4.5.0"),
                String::new(),
                String::from("destination server did not follow the protocol"),
            ),
        }
    }

    /// Compose le rapport de RELAIS, et le dépose LOCALEMENT (RFC 3461 §6.2).
    ///
    /// # UN RAPPORT DE SUCCÈS N'EST PAS UN REBOND À L'ENVERS
    ///
    /// C'est le MÊME document — §2 de RFC 3464 n'en connaît qu'un —, et seuls le
    /// mot de `Action:` et le code d'état le distinguent. Deux composeurs pour un
    /// même format auraient fini par écrire deux formats.
    ///
    /// **IL NE PART QUE S'IL A ÉTÉ DEMANDÉ**, et jamais autrement : §4.1 est
    /// clair, et un rapport de succès qu'on n'a pas demandé est du courrier en
    /// plus pour rien.
    #[expect(
        clippy::too_many_arguments,
        reason = "chaque argument est une pièce distincte du rapport ; les \
                  grouper dans une structure n'ajouterait qu'un nom à retenir"
    )]
    fn rendre_le_succes<B: Bounced>(
        &self,
        rendre: &B,
        retour: &str,
        message: &[u8],
        succes: &[(String, String)],
        envelope_id: &str,
        depot: u64,
        now: u64,
    ) -> bool {
        let remis: Vec<Failure<'_>> = succes
            .iter()
            .map(|(adresse, origine)| Failure {
                recipient: adresse.as_bytes(),
                // `2.0.0` : remis, sans autre précision (RFC 3463 §3.3).
                status: b"2.0.0",
                // **AUCUN DIAGNOSTIC** : le pair n'a rien dit d'autre que oui,
                // et écrire un texte à sa place le ferait passer pour le sien.
                diagnostic: b"",
                // **`relayed`, ET NON `delivered`** (RFC 3464 §2.3.3). Cette
                // file passe le message au saut suivant ; elle ne le remet pas.
                // Dire « remis » affirmerait ce qu'on ignore — le saut suivant
                // peut encore le refuser —, et un expéditeur qui lit un rapport
                // de succès cesse de s'inquiéter.
                action: MimeAction::Relayed,
                original: origine.as_bytes(),
            })
            .collect();
        let identifiant = std::format!("dsn-{}-{}@{}", now, self.suivant(), self.mta);
        let delimiteur = std::format!("----ams-dsn-{}-{}", now, self.suivant());
        let mut texte = String::from(
            "Ce message a bien ete transmis au serveur charge des destinataires\r\n             suivants, comme vous l'aviez demande. Ce serveur ne rend pas compte\r\n             de ses propres remises : ceci dit qu'il l'a accepte, non qu'il l'a\r\n             distribue.\r\n\r\n",
        );
        for (adresse, _) in succes {
            texte.push_str("  ");
            texte.push_str(adresse);
            texte.push_str("\r\n");
        }
        let rapport = Bounce {
            from: self.postmaster.as_bytes(),
            to: retour.as_bytes(),
            reporting_mta: self.mta.as_bytes(),
            subject: b"Mail Relayed Successfully",
            message_id: identifiant.as_bytes(),
            date: now,
            arrival: depot,
            boundary: delimiteur.as_bytes(),
            text: texte.as_bytes(),
            failures: &remis,
            envelope_id: envelope_id.as_bytes(),
            original_headers: entetes(message),
        };
        let mut place = std::vec![0_u8; bounce_max(&rapport)];
        let Ok(compose) = write_bounce(&mut place, &rapport) else {
            return false;
        };
        rendre.deliver(retour, compose)
    }

    /// Compose l'AVIS DE RETARD, et le dépose LOCALEMENT (RFC 3461 §4.1).
    ///
    /// # CE N'EST PAS UN RAPPORT DE NON-REMISE
    ///
    /// Le message n'est pas perdu : il attend, et on essaie toujours. Un
    /// expéditeur qui lirait « Undelivered » cesserait d'attendre et renverrait
    /// par un autre chemin — donc deux fois le même courrier. Le sujet, le texte
    /// et le mot d'`Action:` disent donc tous les trois la même chose, qui est
    /// « pas encore ».
    #[expect(
        clippy::too_many_arguments,
        reason = "chaque argument est une pièce distincte du rapport ; les \
                  grouper dans une structure n'ajouterait qu'un nom à retenir"
    )]
    fn rendre_le_retard<B: Bounced>(
        &self,
        rendre: &B,
        retour: &str,
        message: &[u8],
        retards: &[Sort],
        envelope_id: &str,
        depot: u64,
        now: u64,
    ) -> bool {
        // **JUSQU'À QUAND ON ESSAIE** (RFC 3464 §2.3.9), calculé là où la
        // péremption est connue plutôt que recopié : deux vérités sur la même
        // échéance finiraient par diverger.
        let echeance = self.reprise.deadline(depot);
        let attentes: Vec<Failure<'_>> = retards
            .iter()
            .map(|sort| Failure {
                recipient: sort.adresse.as_bytes(),
                status: sort.statut.as_bytes(),
                diagnostic: sort.dit_par_le_pair.as_bytes(),
                action: MimeAction::Delayed {
                    retry_until: echeance,
                },
                original: sort.origine.as_bytes(),
            })
            .collect();
        let identifiant = std::format!("delay-{}-{}@{}", now, self.suivant(), self.mta);
        let delimiteur = std::format!("----ams-delay-{}-{}", now, self.suivant());
        let mut texte = String::from(
            "Ce message n'a pas encore pu etre remis, et les tentatives se\r\n\
             poursuivent. IL N'EST PAS PERDU : cet avis vous parvient parce\r\n\
             que vous aviez demande a etre prevenu d'un retard.\r\n\r\n",
        );
        for sort in retards {
            texte.push_str("  ");
            texte.push_str(&sort.adresse);
            texte.push_str(" : ");
            texte.push_str(&sort.statut);
            // Le nôtre puis le sien, dans cet ordre : le lecteur voit lequel est
            // notre constat et lequel est la parole du serveur distant.
            for dire in [&sort.observe, &sort.dit_par_le_pair] {
                if dire.is_empty() {
                    continue;
                }
                texte.push_str(" (");
                texte.push_str(dire);
                texte.push(')');
            }
            texte.push_str("\r\n");
        }
        let rapport = Bounce {
            from: self.postmaster.as_bytes(),
            to: retour.as_bytes(),
            reporting_mta: self.mta.as_bytes(),
            subject: b"Delivery Delayed - Message Still Being Retried",
            message_id: identifiant.as_bytes(),
            date: now,
            arrival: depot,
            boundary: delimiteur.as_bytes(),
            text: texte.as_bytes(),
            failures: &attentes,
            envelope_id: envelope_id.as_bytes(),
            original_headers: entetes(message),
        };
        let mut place = std::vec![0_u8; bounce_max(&rapport)];
        let Ok(compose) = write_bounce(&mut place, &rapport) else {
            return false;
        };
        rendre.deliver(retour, compose)
    }

    /// Compose le rapport de non-remise, et le dépose LOCALEMENT.
    #[expect(
        clippy::too_many_arguments,
        reason = "chaque argument est une pièce distincte du rapport ; les \
                  grouper dans une structure n'ajouterait qu'un nom à retenir"
    )]
    fn rendre_compte<B: Bounced>(
        &self,
        rendre: &B,
        retour: &str,
        message: &[u8],
        echecs: &[Sort],
        envelope_id: &str,
        depot: u64,
        now: u64,
    ) -> bool {
        let pannes: Vec<Failure<'_>> = echecs
            .iter()
            .map(|sort| Failure {
                recipient: sort.adresse.as_bytes(),
                status: sort.statut.as_bytes(),
                // **SEULE LA PAROLE DU PAIR VA ICI** (§2.3.6 de RFC 3464). Notre
                // propre constat part dans le texte lisible, où personne ne le
                // prendra pour le sien.
                diagnostic: sort.dit_par_le_pair.as_bytes(),
                action: MimeAction::Failed,
                original: sort.origine.as_bytes(),
            })
            .collect();
        let identifiant = std::format!("bounce-{}-{}@{}", now, self.suivant(), self.mta);
        let delimiteur = std::format!("----ams-bounce-{}-{}", now, self.suivant());
        let texte = texte_du_rapport(echecs);
        let rapport = Bounce {
            from: self.postmaster.as_bytes(),
            to: retour.as_bytes(),
            reporting_mta: self.mta.as_bytes(),
            subject: b"Undelivered Mail Returned to Sender",
            message_id: identifiant.as_bytes(),
            date: now,
            arrival: depot,
            boundary: delimiteur.as_bytes(),
            text: texte.as_bytes(),
            failures: &pannes,
            envelope_id: envelope_id.as_bytes(),
            original_headers: entetes(message),
        };
        let mut place = std::vec![0_u8; bounce_max(&rapport)];
        let Ok(compose) = write_bounce(&mut place, &rapport) else {
            return false;
        };
        rendre.deliver(retour, compose)
    }

    /// Réécrit l'enveloppe avec les seuls destinataires qui restent.
    fn reecrire(
        &self,
        voisin: &Path,
        retour: &str,
        restants: &[String],
        rapports: &[Report<'_>],
        envelope_id: &str,
    ) -> bool {
        let adresses: Vec<&str> = restants.iter().map(String::as_str).collect();
        let enveloppe = Envelope {
            return_path: retour,
            recipients: &adresses,
            envelope_id,
            // **CE QU'UN DESTINATAIRE A DEMANDÉ LE SUIT.** L'oublier à la
            // réécriture ferait rendre compte d'un échec à qui avait demandé le
            // silence — au deuxième essai, pas au premier, ce qui est le pire
            // des deux.
            reports: rapports,
        };
        let mut tampon = std::vec![0_u8; envelope_max(&enveloppe)];
        let Ok(ecrite) = write_envelope(&enveloppe, &mut tampon) else {
            return false;
        };
        poser(voisin, ecrite.as_bytes()).is_ok()
    }

    /// Efface les enveloppes que plus aucun message ne réclame.
    ///
    /// **SEULEMENT CELLES QUI ONT PASSÉ LA PÉREMPTION.** Une enveloppe vient
    /// d'être écrite quand son message est en train de l'être : l'effacer alors
    /// perdrait le destinataire d'un message qui allait apparaître. Passé le
    /// délai qu'on accorde à un message entier, aucun dépôt ne peut plus être en
    /// cours.
    async fn ramasser_les_orphelines(
        &self,
        enveloppes: Vec<(String, tokio::fs::DirEntry)>,
        now: u64,
    ) {
        for (identifiant, entree) in enveloppes {
            let Ok(metadonnees) = entree.metadata().await else {
                continue;
            };
            let age = metadonnees
                .modified()
                .ok()
                .and_then(|quand| quand.duration_since(UNIX_EPOCH).ok())
                .map_or(0, |depuis| now.saturating_sub(depuis.as_secs()));
            if age <= self.reprise.expiry.as_secs() {
                continue;
            }
            // Une dernière vérification : le message a pu réapparaître entre le
            // parcours et maintenant.
            if self.a_encore_un_message(&identifiant).await {
                continue;
            }
            let _ = tokio::fs::remove_file(entree.path()).await;
        }
    }

    /// Reste-t-il un message pour cet identifiant ?
    async fn a_encore_un_message(&self, identifiant: &str) -> bool {
        let Ok(mut dossier) = tokio::fs::read_dir(&self.dossier).await else {
            // On ne sait pas : on ne touche à rien.
            return true;
        };
        while let Ok(Some(entree)) = dossier.next_entry().await {
            let nom = entree.file_name();
            if let Some(nom) = nom.to_str()
                && let Some(part) = parse_name(nom)
                && part.id == identifiant
            {
                return true;
            }
        }
        false
    }

    /// Le chemin de l'enveloppe d'une entrée.
    fn chemin_d_enveloppe(&self, identifiant: &str) -> PathBuf {
        self.dossier.join(std::format!("{identifiant}.enveloppe"))
    }

    /// Un identifiant qu'aucun autre dépôt ne portera.
    fn identifiant(&self, now: u64) -> String {
        std::format!("{:x}-{:x}", now, self.suivant())
    }

    /// Le prochain numéro de la suite, mêlé à l'heure fine.
    fn suivant(&self) -> u64 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |depuis| u64::from(depuis.subsec_nanos()));
        let rang = self.suite.fetch_add(1, Ordering::Relaxed);
        nanos.rotate_left(24) ^ rang
    }
}

/// Ce qu'un destinataire a subi, tel qu'on le rapportera.
///
/// # POURQUOI DEUX TEXTES ET NON UN
///
/// `Diagnostic-Code` veut **le code rendu par le transport** (§2.3.6 de
/// RFC 3464) : c'est la parole du pair, et rien d'autre. Y écrire notre propre
/// constat — « aucune réponse du serveur de destination » — le ferait passer
/// pour la sienne, ce que le composeur de rapport interdit en toutes lettres.
///
/// Notre constat a sa place : le texte LISIBLE du rapport, qui est le nôtre et
/// que personne ne prend pour autre chose. Les deux ne se mélangent pas.
#[derive(Debug, Clone)]
struct Sort {
    /// L'adresse qui n'a pas été servie.
    adresse: String,
    /// L'état étendu — celui du pair s'il l'a écrit, le nôtre sinon.
    statut: String,
    /// Ce que le PAIR a dit. **Vide s'il n'a rien dit qu'on puisse rendre** : le
    /// champ est alors OMIS.
    dit_par_le_pair: String,
    /// Ce que NOUS avons observé, pour le lecteur humain.
    observe: String,
    /// L'adresse d'origine que le déposant avait écrite (RFC 3461 §4.2).
    origine: String,
}

/// Ce qu'un essai vers UN destinataire a donné.
enum Issue {
    /// Le pair l'a pris en charge, et s'est ou non authentifié.
    Remis {
        /// Le pair a-t-il été authentifié par DANE ?
        authentifie: bool,
        /// Le pair a-t-il pris en charge les demandes de RFC 3461 ?
        ///
        /// Vrai, **c'est lui qui rendra compte**, et nous nous taisons.
        dsn_transmis: bool,
    },
    /// Refus définitif : l'état étendu, ce que le PAIR a dit, et ce qu'on a
    /// observé soi-même. Les deux textes ne se confondent pas.
    Definitif(String, String, String),
    /// Refus temporaire, ou personne à qui parler.
    ///
    /// **ELLE PORTE LA RAISON**, comme le refus définitif : un avis de retard
    /// qui dirait un code inventé vaudrait moins que pas d'avis du tout, parce
    /// qu'on le croirait.
    Ajourne(String, String, String),
}

/// Y a-t-il quelque chose à passer au saut suivant (RFC 3461 §5.2.1) ?
///
/// # NE RIEN DEMANDER N'EST PAS UNE DEMANDE
///
/// Un déposant qui n'a écrit ni `ENVID`, ni `NOTIFY`, ni `ORCPT` n'a rien
/// demandé : lui inventer un `NOTIFY=FAILURE` explicite dirait la même chose
/// sur le fil, mais ferait croire au reste du code qu'une demande a été
/// transmise, et donc qu'un rapport de relais est superflu. Or il n'y en avait
/// aucun à faire. La distinction ne se voit que là où elle compte : dans ce que
/// l'on décide de ne PAS émettre.
fn demande_a_passer<'a>(
    identifiant: &'a str,
    rapports: &'a [ClientReport<'a>],
) -> Option<ClientDsn<'a>> {
    let quelque_chose = !identifiant.is_empty()
        || rapports
            .iter()
            .any(|un| un.never || un.on_success || !un.original.is_empty());
    quelque_chose.then_some(ClientDsn {
        envelope_id: identifiant.as_bytes(),
        reports: rapports,
    })
}

/// Écrit `contenu` dans `chemin`, ATOMIQUEMENT.
///
/// Un fichier temporaire dans LE MÊME dossier — un `rename()` ne traverse pas
/// les systèmes de fichiers —, puis `sync_all`, puis le renommage. Un lecteur ne
/// voit jamais un fichier à moitié écrit ; il voit l'ancien, ou le nouveau.
fn poser(chemin: &Path, contenu: &[u8]) -> Result<(), ()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut temporaire = chemin.to_path_buf().into_os_string();
    temporaire.push(".tmp");
    let temporaire = PathBuf::from(temporaire);
    let ecriture = (|| -> std::io::Result<()> {
        let mut fichier = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            // **`0600` À L'OUVERTURE, PAS APRÈS.** Un `chmod` qui suit laisse une
            // fenêtre pendant laquelle le courrier de quelqu'un est lisible par
            // tout le monde.
            .mode(0o600)
            .open(&temporaire)?;
        fichier.write_all(contenu)?;
        fichier.sync_all()?;
        drop(fichier);
        std::fs::rename(&temporaire, chemin)?;
        if let Some(parent) = chemin.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if ecriture.is_err() {
        let _ = std::fs::remove_file(&temporaire);
        return Err(());
    }
    Ok(())
}

/// Les en-têtes du message, bornés.
fn entetes(message: &[u8]) -> &[u8] {
    let fin = message
        .windows(4)
        .position(|fenetre| fenetre == b"\r\n\r\n")
        .map_or(message.len(), |rang| rang.saturating_add(2));
    message.get(..fin.min(ENTETES_MAX)).unwrap_or_default()
}

/// Le statut étendu (RFC 3463) qu'un code de réponse porte.
/// Ce qu'un rapport doit dire d'un refus : son état étendu, et son diagnostic.
///
/// # ON RECOPIE CE QUE LE PAIR A DIT, ET L'ON NE DEVINE QUE S'IL S'EST TU
///
/// Un serveur qui annonce `ENHANCEDSTATUSCODES` (RFC 2034) écrit son état en
/// tête de sa réponse, et c'est LUI qui sait pourquoi il refuse. Le deviner à
/// partir du code écrivait `5.1.1` — « adresse de destination erronée » — sur un
/// `550 5.7.1` qui refusait pour une raison de politique : le déposant corrigeait
/// alors une adresse qui était juste.
///
/// Le diagnostic suit la même règle. **Vide, il sera OMIS** : le composeur de
/// rapport l'exige, parce qu'un texte qu'on aurait écrit soi-même se lirait
/// comme celui du pair.
fn ce_qu_a_dit_le_pair(refus: &Refus, definitif: bool) -> (String, String) {
    let statut = match refus.status {
        Some(dit) => {
            let mut place = [0_u8; 16];
            dit.write(&mut place).map_or_else(
                |_| statut_etendu(refus.code, definitif),
                |ecrit| String::from_utf8_lossy(ecrit).into_owned(),
            )
        }
        None => statut_etendu(refus.code, definitif),
    };
    (statut, refus.diagnostic.clone())
}

/// L'état étendu qu'on DEVINE d'un code, faute que le pair l'ait écrit.
fn statut_etendu(code: u16, definitif: bool) -> String {
    let classe = if definitif { '5' } else { '4' };
    // On ne prétend pas lire dans le code plus qu'il ne dit : `550` peut être
    // une boîte inconnue comme un refus de politique, et deviner écrirait dans
    // le rapport une cause que le pair n'a pas donnée.
    match code {
        550 | 551 | 553 => std::format!("{classe}.1.1"),
        552 => std::format!("{classe}.2.2"),
        _ => std::format!("{classe}.0.0"),
    }
}

/// Ce que lira l'humain qui ouvrira le rapport.
fn texte_du_rapport(echecs: &[Sort]) -> String {
    let mut texte = String::from(
        "Ce message n'a pas pu etre remis a un ou plusieurs destinataires.\r\n\
         \r\n\
         Aucune autre tentative n'aura lieu ; les en-tetes du message d'origine\r\n\
         sont joints ci-dessous.\r\n\r\n",
    );
    for sort in echecs {
        texte.push_str("  ");
        texte.push_str(&sort.adresse);
        texte.push_str(" : ");
        texte.push_str(&sort.statut);
        // **NOTRE CONSTAT D'ABORD, LA PAROLE DU PAIR ENSUITE**, et le lecteur
        // voit laquelle est laquelle. C'est ici que va ce qu'on a observé
        // soi-même : le champ `Diagnostic-Code`, lui, est réservé au pair.
        for dire in [&sort.observe, &sort.dit_par_le_pair] {
            if dire.is_empty() {
                continue;
            }
            // **DE L'ASCII, ET RIEN D'AUTRE.** Ce texte traverse
            // `write_bounce`, qui refuse tout octet hors de l'ASCII imprimable —
            // et il a raison : un rapport composé sans jeu de caractères déclaré
            // ne se lit pas de la même façon chez tout le monde. Un tiret
            // cadratin écrit ici a fait refuser le rapport entier, donc perdre
            // la nouvelle que l'expéditeur attendait.
            texte.push_str(" - ");
            texte.push_str(dire);
        }
        texte.push_str("\r\n");
    }
    texte
}
