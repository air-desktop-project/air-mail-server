//! Les boîtes, vues par le service IMAP.
//!
//! # Ce que ce module ajoute à ce que POP3 savait déjà
//!
//! POP3 ouvre UNE boîte, celle du compte, et n'en sort pas. IMAP en nomme
//! plusieurs, et il faut donc décider ce qu'un nom de boîte désigne. **Ce
//! serveur en a une par compte, et elle s'appelle `INBOX`** — le nom que la
//! RFC 9051 §5.1 réserve précisément pour cela.
//!
//! Créer des dossiers demanderait `CREATE`, un endroit où les mettre, et une
//! règle pour ce qu'un nom de dossier a le droit d'être ; rien de tout cela
//! n'est écrit, et prétendre en avoir plusieurs en attendant ferait mentir
//! `LIST`.
//!
//! # AUCUN CHEMIN N'EST CONSTRUIT À PARTIR D'UN NOM DE BOÎTE
//!
//! Le nom vient du client. `INBOX` est comparé à une constante, et la boîte
//! qu'il désigne est celle que la table des comptes a déjà ouverte au
//! démarrage. Un nom qui n'est pas `INBOX` n'ouvre rien — il ne devient jamais
//! un morceau de chemin, et il n'y a donc aucune traversée de répertoire à
//! empêcher.
//!
//! # IMAP NE VERROUILLE PAS, ET C'EST LE NOM DU FICHIER QUI FAIT FOI
//!
//! POP3 prend le verrou exclusif de la boîte, et RFC 1939 §3 le lui demande :
//! ses numéros de message ne doivent pas bouger de toute la session. Une session
//! IMAP, elle, dure des heures. Lui donner le même verrou reviendrait à
//! interdire toute relève POP3 pendant ces heures — et, plus bêtement encore, à
//! s'interdire à lui-même : `STATUS INBOX` sur une boîte déjà sélectionnée
//! heurtait son propre verrou et répondait qu'elle n'existe pas. Il prend donc
//! une [`MailboxView`], qui relève sans verrouiller.
//!
//! Ce qui remplace le verrou n'est pas rien : **le nom du fichier fait foi**. Il
//! porte les drapeaux, et on le relit à l'instant d'écrire — pour un `STORE`
//! comme pour un `EXPUNGE`. C'est ce qui permet à deux sessions de marquer la
//! même boîte sans se perdre l'une l'autre, et surtout de **ne jamais effacer un
//! message dont la marque a été retirée entre-temps** : un courrier perdu ne se
//! retrouve pas.

use std::collections::BTreeMap;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::PathBuf;
use std::sync::Arc;

use ams_index::{MessageName, Uid};
use ams_proto_imap::{Flags, StoreMode};
use ams_session::imap::{Creation, Deposit, Mailbox, Mailboxes, MessageInfo};
use ams_store::{Incoming, MailboxView, Maildir, fresh_uid_validity};

/// Le seul nom de boîte que ce serveur connaisse (RFC 9051 §5.1).
const INBOX: &[u8] = b"INBOX";

/// Une boîte relevée, vue par IMAP.
pub struct BoiteImap {
    vue: MailboxView,
    /// La boîte elle-même, pour ce qui s'écrit : une COPIE y dépose un message
    /// neuf, et l'UID vient de son compteur.
    maildir: Arc<Maildir>,
    uid_validity: u32,
    /// Les drapeaux, un par message, lus à l'ouverture depuis les noms de
    /// fichiers. Les relire à chaque `FETCH` rouvrirait le répertoire.
    drapeaux: Vec<Flags>,
    /// Les dates d'arrivée, une par message.
    dates: Vec<u64>,
    /// Le chemin COURANT de chaque message.
    ///
    /// # Pourquoi il ne suffit pas de garder celui de l'instantané
    ///
    /// Dans un Maildir, les drapeaux vivent DANS LE NOM DU FICHIER : les écrire,
    /// c'est renommer. Le chemin relevé à l'ouverture cesse donc d'être valide
    /// au premier `STORE` — le nôtre comme celui d'une autre session.
    chemins: Vec<PathBuf>,
}

impl BoiteImap {
    fn rang(&self, sequence: u32) -> Option<usize> {
        let rang = usize::try_from(sequence.checked_sub(1)?).ok()?;
        (rang < self.vue.messages().len()).then_some(rang)
    }
}

impl Mailbox for BoiteImap {
    fn exists(&self) -> u32 {
        u32::try_from(self.vue.messages().len()).unwrap_or(u32::MAX)
    }

    fn uid_validity(&self) -> u32 {
        self.uid_validity
    }

    fn uid_next(&self) -> u32 {
        self.vue
            .messages()
            .last()
            .map_or(1, |dernier| dernier.uid.value().saturating_add(1))
    }

    fn info(&self, sequence: u32) -> Option<MessageInfo> {
        let rang = self.rang(sequence)?;
        let message = self.vue.messages().get(rang)?;
        Some(MessageInfo {
            uid: message.uid.value(),
            size: message.size,
            flags: self.drapeaux.get(rang).copied().unwrap_or_default(),
            internal_date: self.dates.get(rang).copied().unwrap_or(0),
        })
    }

    fn header_octets(&self, sequence: u32) -> u64 {
        let Some(rang) = self.rang(sequence) else {
            return 0;
        };
        let (Some(chemin), Some(message)) = (self.chemins.get(rang), self.vue.messages().get(rang))
        else {
            return 0;
        };
        fin_de_l_entete(chemin).unwrap_or(message.size)
    }

    fn read(&self, sequence: u32, offset: u64, out: &mut [u8]) -> usize {
        let Some(rang) = self.rang(sequence) else {
            return 0;
        };
        let Some(chemin) = self.chemins.get(rang) else {
            return 0;
        };
        // ON ROUVRE LE FICHIER À CHAQUE MORCEAU, plutôt que de garder un
        // descripteur par message : une table de descripteurs épuisée arrête le
        // serveur entier, et une ouverture coûte moins que cela. Ce qu'on ne
        // refait PAS, c'est chercher le message — l'instantané le tient.
        let Ok(mut fichier) = std::fs::File::open(chemin) else {
            return 0;
        };
        if fichier.seek(SeekFrom::Start(offset)).is_err() {
            return 0;
        }
        fichier.read(out).unwrap_or(0)
    }

    fn permanent_flags(&self) -> Flags {
        // `\Deleted` N'EST PAS DE LA LISTE, ET C'EST VOULU. Le poser n'aurait de
        // sens que si quelque chose l'honorait : §6.4.2 veut qu'un `CLOSE`
        // efface les messages qui le portent, et rien n'efface encore. Un client
        // qui marque son courrier pour la corbeille et le retrouve intact au
        // relevé suivant a été trompé ; mieux vaut lui dire non tout de suite.
        Flags::SEEN
            .with(Flags::ANSWERED)
            .with(Flags::FLAGGED)
            .with(Flags::DELETED)
            .with(Flags::DRAFT)
    }

    fn copy_to(&mut self, sequence: u32, mailbox: &[u8]) -> Option<u32> {
        // AUCUN CHEMIN N'EST CONSTRUIT À PARTIR D'UN NOM DE BOÎTE, ici non plus :
        // le nom est comparé à une constante, et la seule destination possible
        // est la boîte qu'on tient déjà.
        if !mailbox.eq_ignore_ascii_case(INBOX) {
            return None;
        }
        let rang = self.rang(sequence)?;
        let chemin = self.chemins.get(rang)?.clone();
        let drapeaux = self.drapeaux.get(rang).copied().unwrap_or_default();

        // ON ÉCRIT DANS `tmp/`, PUIS ON RENOMME. C'est la danse que Maildir
        // impose, et `Incoming` la connaît : tant que le message n'est pas
        // validé, personne ne le voit.
        let mut source = std::fs::File::open(&chemin).ok()?;
        let mut entrant = self.maildir.deliver().ok()?;
        let mut tampon = [0_u8; 8192];
        loop {
            let lus = source.read(&mut tampon).ok()?;
            if lus == 0 {
                break;
            }
            if entrant
                .write(tampon.get(..lus).unwrap_or_default())
                .is_err()
            {
                entrant.abort();
                return None;
            }
        }
        // §6.4.7 : les drapeaux du message d'origine sont préservés — en UN
        // renommage, pour qu'aucun client ne voie la copie sans eux.
        let uid = if drapeaux == Flags::NONE {
            entrant.commit().ok()?
        } else {
            entrant.commit_with_flags(drapeaux_maildir(drapeaux)).ok()?
        };
        Some(uid.value())
    }

    fn undo_copies(&mut self, mailbox: &[u8], premier: u32, dernier: u32) {
        if !mailbox.eq_ignore_ascii_case(INBOX) {
            return;
        }
        // On ne défait QUE ce qu'on vient de faire : les UID de la plage sont
        // ceux que `deliver` vient d'attribuer, et personne d'autre ne les a.
        for sous in ["new", "cur"] {
            let Ok(entrees) = std::fs::read_dir(self.maildir.root().join(sous)) else {
                continue;
            };
            for entree in entrees.flatten() {
                let nom = entree.file_name();
                let Ok(lu) = MessageName::parse(nom.as_bytes()) else {
                    continue;
                };
                let Some(uid) = lu.uid() else {
                    continue;
                };
                if uid.value() >= premier && uid.value() <= dernier {
                    let _ = std::fs::remove_file(entree.path());
                }
            }
        }
    }

    fn remove(&mut self, sequence: u32) -> bool {
        let Some(rang) = self.rang(sequence) else {
            return false;
        };
        // RETIRER NE RELIT PAS LA MARQUE, et c'est toute la différence avec
        // `expunge` : il n'y a pas de marque à relire. Le message vient d'être
        // copié, à l'instant, et le client a demandé qu'il ne reste pas ici.
        // On le cherche quand même par son UID si son nom a changé — un
        // renommage concurrent ne doit pas laisser un doublon derrière un `MOVE`.
        for _ in 0..3_u32 {
            let Some(chemin) = self.chemins.get(rang).cloned() else {
                return false;
            };
            match std::fs::remove_file(&chemin) {
                Ok(()) => {
                    self.oublier(rang);
                    return true;
                }
                Err(erreur) if erreur.kind() == std::io::ErrorKind::NotFound => {
                    let uid = chemin
                        .file_name()
                        .and_then(|nom| MessageName::parse(nom.as_bytes()).ok())
                        .and_then(|lu| lu.uid());
                    match uid.and_then(|uid| retrouver(self.vue.root(), uid)) {
                        Some(actuel) => {
                            self.poser_le_chemin(rang, actuel);
                            continue;
                        }
                        None => break,
                    }
                }
                Err(_) => return false,
            }
        }
        // Introuvable sous son UID : il est bien parti, ce qui est ce qu'on
        // voulait.
        self.oublier(rang);
        true
    }

    fn expunge(&mut self, sequence: u32) -> bool {
        let Some(rang) = self.rang(sequence) else {
            return false;
        };
        // TROIS TENTATIVES, comme pour `store_flags` : chaque échec vient d'un
        // renommage concurrent, et trois de suite ne sont plus une course.
        for _ in 0..3_u32 {
            let Some(chemin) = self.chemins.get(rang).cloned() else {
                return false;
            };
            let Some(lu) = chemin
                .file_name()
                .and_then(|nom| MessageName::parse(nom.as_bytes()).ok())
            else {
                return false;
            };

            // ON NE VÉRIFIE PAS QU'ON PEUT EFFACER, ON VÉRIFIE QU'ON DOIT.
            //
            // La session demande d'effacer ce que SON instantané dit marqué
            // `\Deleted` — un instantané pris à l'ouverture, il y a peut-être
            // des heures. Entre-temps, une autre session a pu retirer la
            // marque. Effacer sur cette croyance-là, c'est perdre du courrier
            // que personne n'a demandé de perdre, et un courrier perdu ne se
            // retrouve pas. On relit donc le nom, qui porte les lettres.
            if !lu.flags().contains(ams_index::Flags::TRASHED) {
                // Deux causes possibles, et elles ne se valent pas : ou bien la
                // marque a vraiment été retirée, ou bien c'est NOTRE nom qui est
                // périmé. Le disque tranche.
                if chemin.symlink_metadata().is_ok() {
                    return false;
                }
                match lu.uid().and_then(|uid| retrouver(self.vue.root(), uid)) {
                    Some(actuel) => {
                        self.poser_le_chemin(rang, actuel);
                        continue;
                    }
                    None => break,
                }
            }

            match std::fs::remove_file(&chemin) {
                Ok(()) => {
                    self.oublier(rang);
                    return true;
                }
                // `NotFound` NE VEUT PAS DIRE « DÉJÀ PARTI ». Dans un Maildir,
                // un message qu'on ne trouve plus sous son nom a le plus souvent
                // simplement changé de nom — quelqu'un a écrit ses drapeaux. Le
                // prendre pour une disparition ferait oublier de la boîte un
                // message bien vivant, et pire : on l'aurait « effacé » sur la
                // foi de lettres lues dans un nom qui n'existe plus. Constaté
                // sur le binaire, en retirant la marque sous ses pieds.
                Err(erreur) if erreur.kind() == std::io::ErrorKind::NotFound => {
                    match lu.uid().and_then(|uid| retrouver(self.vue.root(), uid)) {
                        Some(actuel) => {
                            self.poser_le_chemin(rang, actuel);
                            continue;
                        }
                        None => break,
                    }
                }
                Err(_) => return false,
            }
        }
        // Introuvable sous son UID : celui-là est bien parti, et le client
        // demandait justement qu'il n'y soit plus.
        self.oublier(rang);
        true
    }

    fn store_flags(&mut self, sequence: u32, mode: StoreMode, flags: Flags) -> Option<Flags> {
        let rang = self.rang(sequence)?;
        // TROIS TENTATIVES, ET PAS UNE BOUCLE SANS FIN. Chaque échec vient d'un
        // renommage concurrent ; s'il s'en produit trois de suite pendant qu'on
        // écrit une ligne, ce n'est plus une course, c'est un autre programme qui
        // remue la boîte, et insister ne fera que l'accompagner.
        for _ in 0..3_u32 {
            let chemin = self.chemins.get(rang)?.clone();
            let nom = chemin.file_name()?.as_bytes();
            let lu = MessageName::parse(nom).ok()?;
            // ON PART DE CE QU'ON VIENT DE LIRE, PAS DE CE QU'ON CROYAIT SAVOIR.
            // Les drapeaux sont relus dans le nom du fichier à l'instant où l'on
            // écrit : deux `+FLAGS` concurrents se composent alors, au lieu que
            // le second efface ce que le premier venait de poser. Un `FLAGS` nu,
            // lui, écrase — mais c'est ce que le client a demandé.
            let voulus = maildir_apres(lu.flags(), mode, flags);
            if voulus == lu.flags() && lu.has_info() {
                // RIEN À ÉCRIRE — ENCORE FAUT-IL QUE CE « RIEN » PORTE SUR UN
                // FICHIER QUI EXISTE. Les drapeaux qu'on vient de lire sont
                // ceux d'un NOM, et ce nom peut être celui que quelqu'un a
                // renommé pendant qu'on le tenait : croire qu'il n'y a rien à
                // faire reviendrait alors à répondre `OK` sans avoir rien écrit,
                // ce qui est exactement le mensonge qu'un `STORE` ne doit pas
                // faire. Constaté sur le binaire : un message renommé sous nos
                // pieds recevait `* 2 FETCH (FLAGS (\Seen \Flagged))` et un
                // `OK`, pendant que le fichier gardait ses anciennes lettres.
                if chemin.symlink_metadata().is_ok() {
                    return Some(drapeaux_imap(voulus));
                }
                *self.chemins.get_mut(rang)? = retrouver(self.vue.root(), lu.uid()?)?;
                continue;
            }
            let cible = self.vue.root().join("cur").join(nom_avec(nom, voulus));
            if std::fs::rename(&chemin, &cible).is_ok() {
                *self.chemins.get_mut(rang)? = cible;
                let nouveaux = drapeaux_imap(voulus);
                if let Some(place) = self.drapeaux.get_mut(rang) {
                    *place = nouveaux;
                }
                return Some(nouveaux);
            }
            // Le renommage a échoué : le message a bougé sous nos pieds. On le
            // retrouve par son UID — le seul identifiant qui survive à un
            // changement de drapeaux — et l'on recommence sur son nom actuel.
            *self.chemins.get_mut(rang)? = retrouver(self.vue.root(), lu.uid()?)?;
        }
        None
    }
}

/// Où finit le bloc d'en-tête, ligne vide comprise.
///
/// # On lit par morceaux, et l'on s'arrête
///
/// Un message dont on ne trouverait pas la ligne vide n'a pas d'en-tête — c'est
/// un fichier que quelqu'un a déposé là. On rend alors `None`, et l'appelant
/// prend le message entier : mieux vaut rendre trop que de prétendre découper ce
/// qu'on n'a pas su lire.
fn fin_de_l_entete(chemin: &std::path::Path) -> Option<u64> {
    let mut fichier = std::fs::File::open(chemin).ok()?;
    let mut tampon = [0_u8; 8192];
    let mut lus_en_tout = 0_u64;
    // Trois octets de recouvrement : la ligne vide peut être à cheval sur deux
    // morceaux, et la chercher morceau par morceau sans recouvrement la
    // manquerait une fois sur deux mille.
    let mut queue = [0_u8; 3];
    let mut queue_len = 0_usize;
    loop {
        let lus = fichier.read(&mut tampon).ok()?;
        if lus == 0 {
            return None;
        }
        let mut fenetre = Vec::with_capacity(queue_len.saturating_add(lus));
        fenetre.extend_from_slice(queue.get(..queue_len).unwrap_or_default());
        fenetre.extend_from_slice(tampon.get(..lus).unwrap_or_default());
        if let Some(rang) = fenetre
            .windows(4)
            .position(|fenetre| fenetre == b"\r\n\r\n")
        {
            let avant = lus_en_tout.saturating_sub(queue_len as u64);
            return Some(avant.saturating_add(rang as u64).saturating_add(4));
        }
        lus_en_tout = lus_en_tout.saturating_add(lus as u64);
        let reste = fenetre.len().min(3);
        queue_len = reste;
        queue.get_mut(..reste).unwrap_or_default().copy_from_slice(
            fenetre
                .get(fenetre.len().saturating_sub(reste)..)
                .unwrap_or_default(),
        );
    }
}

/// Les boîtes du serveur, telles qu'IMAP les ouvre.
pub struct BoitesImap {
    /// La boîte d'arrivée de chaque compte, ouverte au démarrage.
    boites: Arc<BTreeMap<String, Arc<Maildir>>>,
    /// Le nom d'hôte, qui entre dans les noms de fichiers Maildir.
    hote: Vec<u8>,
    /// Les dossiers déjà ouverts, par compte et par nom.
    ///
    /// # POURQUOI UN CACHE, ET POURQUOI IL EST BORNÉ PAR CE QUI EXISTE
    ///
    /// Ouvrir un Maildir relit son index, adopte les messages sans UID et
    /// réécrit l'index : le refaire à chaque `LIST` ou chaque `SELECT`
    /// coûterait un parcours de répertoire par commande. Le cache ne grandit
    /// que d'une entrée par dossier RÉELLEMENT créé — un client ne peut donc
    /// pas le faire enfler en nommant des boîtes au hasard.
    dossiers: std::sync::Mutex<BTreeMap<(String, String), Arc<Maildir>>>,
}

impl BoitesImap {
    /// Monte le service à partir des boîtes déjà ouvertes par le serveur.
    #[must_use]
    pub fn new(boites: Arc<BTreeMap<String, Arc<Maildir>>>, hote: &[u8]) -> Self {
        Self {
            boites,
            hote: hote.to_vec(),
            dossiers: std::sync::Mutex::new(BTreeMap::new()),
        }
    }

    /// La racine de la boîte d'arrivée d'un compte.
    fn racine(&self, user: &[u8]) -> Option<PathBuf> {
        let nom = core::str::from_utf8(user).ok()?;
        Some(self.boites.get(nom)?.root().to_path_buf())
    }

    /// Le répertoire d'un dossier, à la façon de Maildir++.
    ///
    /// # C'EST ICI QU'UN NOM DE CLIENT DEVIENT UN CHEMIN
    ///
    /// Et c'est pourquoi la règle est vérifiée UNE SECONDE FOIS, alors que la
    /// session l'a déjà appliquée : c'est ce code-ci qui touche le système de
    /// fichiers, et une vérification faite ailleurs est une vérification qu'on
    /// ne voit pas en lisant l'endroit qui en dépend. Elle ne coûte rien, et
    /// elle survivra à un appelant qui l'oublierait.
    ///
    /// `Archives/2026` devient `.Archives.2026` DANS la racine du compte : un
    /// seul niveau de répertoires, comme Maildir++ le veut, et donc aucun
    /// chemin composé de plusieurs morceaux venus du client.
    fn chemin_du_dossier(&self, user: &[u8], name: &[u8]) -> Option<PathBuf> {
        let name = ams_proto_imap::mailbox_name_trimmed(name);
        if !ams_proto_imap::mailbox_name_is_safe(name) {
            return None;
        }
        let racine = self.racine(user)?;
        let mut repertoire = std::vec::Vec::with_capacity(name.len().saturating_add(1));
        repertoire.push(b'.');
        for octet in name {
            repertoire.push(if *octet == b'/' { b'.' } else { *octet });
        }
        // Le nom composé ne porte ni `/` ni `..` : la vérification l'a exclu, et
        // la transcription ne peut pas en introduire.
        Some(racine.join(std::ffi::OsString::from_vec(repertoire)))
    }

    /// La boîte d'un compte : `INBOX`, ou un dossier qui existe déjà.
    fn maildir(&self, user: &[u8], name: &[u8]) -> Option<Arc<Maildir>> {
        if name.eq_ignore_ascii_case(INBOX) {
            let nom = core::str::from_utf8(user).ok()?;
            return self.boites.get(nom).map(Arc::clone);
        }
        let name = ams_proto_imap::mailbox_name_trimmed(name);
        let clef = (
            core::str::from_utf8(user).ok()?.to_owned(),
            core::str::from_utf8(name).ok()?.to_owned(),
        );
        let mut ouverts = self.dossiers.lock().ok()?;
        if let Some(deja) = ouverts.get(&clef) {
            return Some(Arc::clone(deja));
        }
        let chemin = self.chemin_du_dossier(user, name)?;
        // ON N'OUVRE QUE CE QUI EXISTE. `Maildir::open` crée l'arborescence
        // qu'on lui nomme : l'appeler sans regarder ferait de chaque `SELECT`
        // sur une faute de frappe une boîte de plus.
        if !chemin.is_dir() {
            return None;
        }
        let boite = Arc::new(Maildir::open(&chemin, &self.hote, fresh_uid_validity()).ok()?);
        ouverts.insert(clef, Arc::clone(&boite));
        Some(boite)
    }

    /// Les dossiers d'un compte, par ordre de nom.
    fn dossiers_de(&self, user: &[u8]) -> Vec<Vec<u8>> {
        let mut noms = std::vec![INBOX.to_vec()];
        let Some(racine) = self.racine(user) else {
            return noms;
        };
        let Ok(entrees) = std::fs::read_dir(&racine) else {
            return noms;
        };
        let mut dossiers = std::vec::Vec::new();
        for entree in entrees.flatten() {
            if !entree.path().is_dir() {
                continue;
            }
            let nom = entree.file_name();
            let Some(reste) = nom.as_bytes().strip_prefix(b".") else {
                continue;
            };
            // ON NE REND QUE CE QU'ON SAURAIT RELIRE. Un répertoire déposé là
            // par autre chose que nous — un point d'accueil, un `.git` — n'a pas
            // à devenir une boîte que le client croira sienne.
            let imap: Vec<u8> = reste
                .iter()
                .map(|octet| if *octet == b'.' { b'/' } else { *octet })
                .collect();
            if ams_proto_imap::mailbox_name_is_safe(&imap) {
                dossiers.push(imap);
            }
        }
        dossiers.sort_unstable();
        noms.extend(dossiers);
        noms
    }
}

/// Un message en cours de dépôt, vu par IMAP.
///
/// Ce n'est qu'une [`Incoming`] : la danse Maildir — écrire dans `tmp/`,
/// synchroniser, renommer — est la même qu'une remise SMTP, et il n'y a aucune
/// raison d'en avoir deux.
pub struct DepotImap {
    entrant: Option<Incoming>,
}

impl Deposit for DepotImap {
    fn write(&mut self, chunk: &[u8]) -> bool {
        let Some(entrant) = self.entrant.as_mut() else {
            return false;
        };
        entrant.write(chunk).is_ok()
    }

    fn commit(mut self, flags: Flags, date: Option<u64>) -> Option<u32> {
        let entrant = self.entrant.take()?;
        let quand = date.map(|secondes| {
            std::time::UNIX_EPOCH
                .checked_add(std::time::Duration::from_secs(secondes))
                .unwrap_or(std::time::UNIX_EPOCH)
        });
        // Sans drapeaux ET sans date, c'est une arrivée ordinaire : elle va dans
        // `new/`, là où Maildir met ce qu'on n'a pas encore vu.
        let uid = if flags == Flags::NONE && quand.is_none() {
            entrant.commit().ok()?
        } else {
            entrant.commit_with(drapeaux_maildir(flags), quand).ok()?
        };
        Some(uid.value())
    }

    fn abort(mut self) {
        // On parcourt une tranche plutôt que de tester une option : un dépôt
        // ouvert n'est pas une condition, c'est une chose qu'on a ou qu'on n'a
        // pas. Ici il faut le CONSOMMER, d'où le `take` puis le `if let` — et
        // le « et sinon » est bien atteignable : un dépôt abandonné deux fois.
        if let Some(entrant) = self.entrant.take() {
            entrant.abort();
        }
    }
}

impl Mailboxes for BoitesImap {
    type Open = BoiteImap;
    type Deposit = DepotImap;

    fn append(&self, user: &[u8], name: &[u8]) -> Option<DepotImap> {
        let maildir = self.maildir(user, name)?;
        Some(DepotImap {
            entrant: Some(maildir.deliver().ok()?),
        })
    }

    fn name<'n>(&self, user: &[u8], index: usize, out: &'n mut [u8]) -> Option<&'n [u8]> {
        // Le compte d'abord : sans lui, il n'y a pas de boîte à nommer.
        let nom = core::str::from_utf8(user).ok()?;
        self.boites.get(nom)?;
        let noms = self.dossiers_de(user);
        let nom = noms.get(index)?;
        let longueur = nom.len().min(out.len());
        for (place, octet) in out.iter_mut().zip(nom) {
            *place = *octet;
        }
        out.get(..longueur)
    }

    fn create(&self, user: &[u8], name: &[u8]) -> Creation {
        let name = ams_proto_imap::mailbox_name_trimmed(name);
        // §6.3.4 : `INBOX` existe toujours. La session le dit déjà ; on ne s'y
        // fie pas, puisque c'est ici qu'un répertoire naîtrait.
        if name.eq_ignore_ascii_case(INBOX) {
            return Creation::DejaLa;
        }
        let Some(chemin) = self.chemin_du_dossier(user, name) else {
            return Creation::Refusee;
        };
        if chemin.is_dir() {
            return Creation::DejaLa;
        }
        // §6.3.4 : CRÉER `A/B` CRÉE AUSSI `A`. En Maildir++ il n'y a qu'un
        // niveau de répertoires, et les parents sont donc des répertoires
        // frères — il faut les faire, sans quoi `LIST` montrerait une fille
        // sans sa mère.
        let mut parcouru = std::vec::Vec::new();
        for composant in name.split(|octet| *octet == b'/') {
            if !parcouru.is_empty() {
                parcouru.push(b'/');
            }
            parcouru.extend_from_slice(composant);
            let Some(chemin) = self.chemin_du_dossier(user, &parcouru) else {
                return Creation::Refusee;
            };
            if chemin.is_dir() {
                continue;
            }
            if Maildir::open(&chemin, &self.hote, fresh_uid_validity()).is_err() {
                return Creation::Refusee;
            }
        }
        Creation::Faite
    }

    fn open(&self, user: &[u8], name: &[u8]) -> Option<Self::Open> {
        let maildir = self.maildir(user, name)?;
        let vue = MailboxView::open(&maildir).ok()?;
        let (drapeaux, dates) = vue
            .messages()
            .iter()
            .map(|message| (drapeaux_de(&message.path), date_de(&message.path)))
            .unzip();
        let chemins = vue
            .messages()
            .iter()
            .map(|message| message.path.clone())
            .collect();
        Some(BoiteImap {
            vue,
            maildir: Arc::clone(&maildir),
            uid_validity: maildir.uid_validity().value(),
            drapeaux,
            dates,
            chemins,
        })
    }
}

impl BoiteImap {
    /// Note où vit désormais le message de rang `rang`.
    fn poser_le_chemin(&mut self, rang: usize, chemin: PathBuf) {
        if let Some(place) = self.chemins.get_mut(rang) {
            *place = chemin;
        }
    }

    /// Retire un message de l'instantané, et de tout ce qui le suit rang par
    /// rang. **Les quatre listes descendent ensemble** : en oublier une ferait
    /// lire les drapeaux d'un message dans ceux d'un autre.
    fn oublier(&mut self, rang: usize) {
        self.vue.forget(rang);
        for liste in [&mut self.chemins] {
            if rang < liste.len() {
                liste.remove(rang);
            }
        }
        if rang < self.drapeaux.len() {
            self.drapeaux.remove(rang);
        }
        if rang < self.dates.len() {
            self.dates.remove(rang);
        }
    }
}

/// Ce que deviennent les lettres Maildir d'un message après un `STORE`.
///
/// # `P` N'EST PAS DANS LE VOCABULAIRE D'IMAP, DONC IMAP NE PEUT PAS LE RETIRER
///
/// Maildir a six lettres, IMAP cinq drapeaux, et `P` (*passed*, transmis) n'a
/// pas d'équivalent. Un `FLAGS (\Seen)` demande « exactement `\Seen` » — mais
/// exactement dans le vocabulaire du client, qui ne sait pas dire `P`. Le lui
/// faire effacer serait lui prêter une intention qu'il ne pouvait pas former.
fn maildir_apres(actuels: ams_index::Flags, mode: StoreMode, demandes: Flags) -> ams_index::Flags {
    let demandes = drapeaux_maildir(demandes);
    match mode {
        StoreMode::Add => actuels.with(demandes),
        StoreMode::Remove => actuels.without(demandes),
        // Ce qu'IMAP ne sait pas nommer, il ne le remplace pas.
        StoreMode::Replace => {
            let hors_du_vocabulaire = actuels.contains(ams_index::Flags::PASSED);
            if hors_du_vocabulaire {
                demandes.with(ams_index::Flags::PASSED)
            } else {
                demandes
            }
        }
    }
}

/// Le nom d'un message, avec d'autres lettres.
///
/// **On recopie tout ce qui précède le `:`**, champs étrangers compris : un
/// autre outil a pu y poser le sien, et le recomposer à partir de ce qu'on en
/// comprend lui ferait perdre ce qu'il y avait mis.
fn nom_avec(nom: &[u8], drapeaux: ams_index::Flags) -> std::ffi::OsString {
    let unique = nom.split(|octet| *octet == b':').next().unwrap_or_default();
    let mut lettres = [0_u8; ams_index::Flags::MAX_OCTETS];
    let ecrites = drapeaux.write_into(&mut lettres);
    let mut compose = Vec::with_capacity(unique.len().saturating_add(3).saturating_add(ecrites));
    compose.extend_from_slice(unique);
    compose.extend_from_slice(b":2,");
    compose.extend_from_slice(lettres.get(..ecrites).unwrap_or_default());
    std::ffi::OsString::from_vec(compose)
}

/// Retrouve un message par son UID, quand son nom a changé sous nos pieds.
fn retrouver(racine: &std::path::Path, uid: Uid) -> Option<PathBuf> {
    for sous in ["cur", "new"] {
        let Ok(entrees) = std::fs::read_dir(racine.join(sous)) else {
            continue;
        };
        for entree in entrees.flatten() {
            let nom = entree.file_name();
            let Ok(lu) = MessageName::parse(nom.as_bytes()) else {
                continue;
            };
            if lu.uid() == Some(uid) {
                return Some(entree.path());
            }
        }
    }
    None
}

/// Les lettres Maildir d'un jeu de drapeaux IMAP.
fn drapeaux_maildir(drapeaux: Flags) -> ams_index::Flags {
    let mut maildir = ams_index::Flags::NONE;
    for (present, lettre) in [
        (drapeaux.contains(Flags::SEEN), ams_index::Flags::SEEN),
        (
            drapeaux.contains(Flags::ANSWERED),
            ams_index::Flags::REPLIED,
        ),
        (drapeaux.contains(Flags::FLAGGED), ams_index::Flags::FLAGGED),
        (drapeaux.contains(Flags::DELETED), ams_index::Flags::TRASHED),
        (drapeaux.contains(Flags::DRAFT), ams_index::Flags::DRAFT),
    ] {
        if present {
            maildir = maildir.with(lettre);
        }
    }
    maildir
}

/// Les drapeaux IMAP d'un jeu de lettres Maildir.
fn drapeaux_imap(maildir: ams_index::Flags) -> Flags {
    let mut drapeaux = Flags::NONE;
    // LES LETTRES DE MAILDIR NE SONT PAS LES DRAPEAUX D'IMAP, et la
    // correspondance n'est pas totale : `P` (transmis) n'a pas d'équivalent, et
    // `T` (trashed) est ce qu'IMAP appelle `\Deleted`.
    for (present, drapeau) in [
        (maildir.contains(ams_index::Flags::SEEN), Flags::SEEN),
        (maildir.contains(ams_index::Flags::REPLIED), Flags::ANSWERED),
        (maildir.contains(ams_index::Flags::FLAGGED), Flags::FLAGGED),
        (maildir.contains(ams_index::Flags::TRASHED), Flags::DELETED),
        (maildir.contains(ams_index::Flags::DRAFT), Flags::DRAFT),
    ] {
        if present {
            drapeaux = drapeaux.with(drapeau);
        }
    }
    drapeaux
}

/// Les drapeaux d'un message, lus dans son nom de fichier.
fn drapeaux_de(chemin: &std::path::Path) -> Flags {
    let Some(nom) = chemin.file_name().and_then(|brut| brut.to_str()) else {
        return Flags::NONE;
    };
    let Ok(lu) = MessageName::parse(nom.as_bytes()) else {
        return Flags::NONE;
    };
    drapeaux_imap(lu.flags())
}

/// La date d'arrivée d'un message : celle du fichier.
///
/// **Ce n'est pas la date du message** : `INTERNALDATE` dit quand il est arrivé
/// ici, et c'est bien ce que la date de modification du fichier raconte.
fn date_de(chemin: &std::path::Path) -> u64 {
    std::fs::metadata(chemin)
        .and_then(|donnees| donnees.modified())
        .ok()
        .and_then(|instant| instant.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |ecoule| ecoule.as_secs())
}
