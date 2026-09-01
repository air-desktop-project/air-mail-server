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

use ams_mime::{Bounce, Failure, bounce_max, write_bounce};
use ams_queue::{
    Backoff, Decision, Entry, Envelope, NAME_MAX, RECIPIENTS_MAX, envelope_max, parse_envelope,
    parse_name, write_envelope, write_name,
};

use crate::delivery::DeliveryFailure;
use crate::relay::{Outgoing, Relay, RelayOutcome};

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
    /// Messages abandonnés, avec un rapport de non-remise.
    pub bounced: usize,
    /// Messages remis à plus tard.
    pub deferred: usize,
    /// Entrées qu'on n'a pas su relire, et qui ont été retirées.
    pub unreadable: usize,
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
        let Ok(enveloppe) = parse_envelope(&fichier, &mut cases) else {
            let _ = tokio::fs::remove_file(&chemin).await;
            let _ = tokio::fs::remove_file(&voisin).await;
            compte.unreadable = compte.unreadable.saturating_add(1);
            return;
        };

        // ── L'essai, UN DESTINATAIRE À LA FOIS ──────────────────────────────
        let mut restants: Vec<String> = Vec::new();
        let mut echecs: Vec<(String, String, String)> = Vec::new();
        for adresse in enveloppe.recipients {
            match self
                .remettre_a(relay, enveloppe.return_path, adresse, &message)
                .await
            {
                Issue::Remis => {}
                Issue::Definitif(statut, diagnostic) => {
                    echecs.push(((*adresse).to_string(), statut, diagnostic));
                }
                Issue::Ajourne => restants.push((*adresse).to_string()),
            }
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
                if !self.reecrire(&voisin, enveloppe.return_path, &restants) {
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
                for adresse in &restants {
                    echecs.push((
                        adresse.clone(),
                        String::from("4.4.7"),
                        String::from("delivery time expired"),
                    ));
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
                    if !self.rendre_compte(
                        rendre,
                        enveloppe.return_path,
                        &message,
                        &echecs,
                        depot,
                        now,
                    ) {
                        std::eprintln!(
                            "air-mail-server : RAPPORT DE NON-REMISE PERDU pour `{}` — le \
                             message est abandonné, et son expéditeur ne le saura pas",
                            enveloppe.return_path
                        );
                    }
                    compte.bounced = compte.bounced.saturating_add(1);
                }
            }
        }
    }

    /// Remet le message à UN destinataire, et classe ce qui s'est passé.
    async fn remettre_a(
        &self,
        relay: &Relay,
        retour: &str,
        adresse: &str,
        message: &[u8],
    ) -> Issue {
        let Some((_, domaine)) = adresse.rsplit_once('@') else {
            // Une adresse sans domaine n'a pas de serveur : rien ne l'arrangera.
            return Issue::Definitif(
                String::from("5.1.3"),
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
                },
            )
            .await;
        match issue {
            // `refused` ne peut valoir que zéro : il n'y avait qu'un destinataire,
            // et un refus l'aurait rendu par `Rejected`.
            RelayOutcome::Delivered { .. } => Issue::Remis,
            RelayOutcome::Rejected(code) => Issue::Definitif(
                statut_etendu(code, true),
                std::format!("{code} rejected by remote server"),
            ),
            // §RFC 7505 : le domaine déclare ne recevoir AUCUN courrier. C'est un
            // refus publié à l'avance, et le confondre avec une panne ferait
            // réessayer des jours durant ce qu'un domaine a explicitement fermé.
            RelayOutcome::NullMx => Issue::Definitif(
                String::from("5.1.2"),
                String::from("destination domain accepts no mail (null MX)"),
            ),
            // **CE QUI VIENT DE NOUS EST DÉFINITIF.** Un message qu'on ne sait pas
            // émettre — un `LF` isolé dans le corps — ne s'émettra pas mieux dans
            // six heures, et le réessayer cinq jours durant ne ferait que retarder
            // la nouvelle.
            RelayOutcome::Unsendable => Issue::Definitif(
                String::from("5.6.0"),
                String::from("message cannot be transmitted as written"),
            ),
            RelayOutcome::Deferred(_)
            | RelayOutcome::Unreachable
            | RelayOutcome::NoEncryption
            | RelayOutcome::Protocol => Issue::Ajourne,
        }
    }

    /// Compose le rapport de non-remise, et le dépose LOCALEMENT.
    fn rendre_compte<B: Bounced>(
        &self,
        rendre: &B,
        retour: &str,
        message: &[u8],
        echecs: &[(String, String, String)],
        depot: u64,
        now: u64,
    ) -> bool {
        let pannes: Vec<Failure<'_>> = echecs
            .iter()
            .map(|(adresse, statut, diagnostic)| Failure {
                recipient: adresse.as_bytes(),
                status: statut.as_bytes(),
                diagnostic: diagnostic.as_bytes(),
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
            original_headers: entetes(message),
        };
        let mut place = std::vec![0_u8; bounce_max(&rapport)];
        let Ok(compose) = write_bounce(&mut place, &rapport) else {
            return false;
        };
        rendre.deliver(retour, compose)
    }

    /// Réécrit l'enveloppe avec les seuls destinataires qui restent.
    fn reecrire(&self, voisin: &Path, retour: &str, restants: &[String]) -> bool {
        let adresses: Vec<&str> = restants.iter().map(String::as_str).collect();
        let enveloppe = Envelope {
            return_path: retour,
            recipients: &adresses,
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

/// Ce qu'un essai vers UN destinataire a donné.
enum Issue {
    /// Le pair l'a pris en charge.
    Remis,
    /// Refus définitif : le statut étendu, et ce que le pair a dit.
    Definitif(String, String),
    /// Refus temporaire, ou personne à qui parler.
    Ajourne,
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
fn texte_du_rapport(echecs: &[(String, String, String)]) -> String {
    let mut texte = String::from(
        "Ce message n'a pas pu etre remis a un ou plusieurs destinataires.\r\n\
         \r\n\
         Aucune autre tentative n'aura lieu ; les en-tetes du message d'origine\r\n\
         sont joints ci-dessous.\r\n\r\n",
    );
    for (adresse, statut, diagnostic) in echecs {
        texte.push_str("  ");
        texte.push_str(adresse);
        texte.push_str(" : ");
        texte.push_str(statut);
        if !diagnostic.is_empty() {
            // **DE L'ASCII, ET RIEN D'AUTRE.** Ce texte traverse
            // `write_bounce`, qui refuse tout octet hors de l'ASCII imprimable —
            // et il a raison : un rapport composé sans jeu de caractères déclaré
            // ne se lit pas de la même façon chez tout le monde. Un tiret
            // cadratin écrit ici a fait refuser le rapport entier, donc perdre
            // la nouvelle que l'expéditeur attendait.
            texte.push_str(" - ");
            texte.push_str(diagnostic);
        }
        texte.push_str("\r\n");
    }
    texte
}
