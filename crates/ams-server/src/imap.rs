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
//! # IMAP NE VERROUILLE PAS, PARCE QU'IL N'ÉCRIT PAS
//!
//! POP3 prend le verrou exclusif de la boîte : il efface, et RFC 1939 §3 le lui
//! demande. Ce service-ci ne fait que lire, et une session IMAP dure des heures.
//! Lui donner le même verrou reviendrait à interdire toute relève POP3 de la
//! boîte pendant ces heures — et, plus bêtement encore, à s'interdire à
//! lui-même : `STATUS INBOX` sur une boîte déjà sélectionnée aurait heurté son
//! propre verrou et répondu qu'elle n'existe pas. Il prend donc une
//! [`MailboxView`], qui relève sans verrouiller.

use std::collections::BTreeMap;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::sync::Arc;

use ams_index::MessageName;
use ams_proto_imap::Flags;
use ams_session::imap::{Mailbox, Mailboxes, MessageInfo};
use ams_store::{MailboxView, Maildir};

/// Le seul nom de boîte que ce serveur connaisse (RFC 9051 §5.1).
const INBOX: &[u8] = b"INBOX";

/// Une boîte relevée, vue par IMAP.
pub struct BoiteImap {
    vue: MailboxView,
    uid_validity: u32,
    /// Les drapeaux, un par message, lus à l'ouverture depuis les noms de
    /// fichiers. Les relire à chaque `FETCH` rouvrirait le répertoire.
    drapeaux: Vec<Flags>,
    /// Les dates d'arrivée, une par message.
    dates: Vec<u64>,
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
        let Some(message) = self.vue.messages().get(rang) else {
            return 0;
        };
        fin_de_l_entete(&message.path).unwrap_or(message.size)
    }

    fn writable(&self) -> bool {
        // RIEN NE S'ÉCRIT ENCORE : ni `STORE`, ni `APPEND`, ni `EXPUNGE`, et
        // `mark_seen` ne fait rien. Annoncer `[READ-WRITE]` promettrait au
        // client des modifications qu'il n'obtiendrait qu'en `BAD`. Ce sera
        // vrai le jour où les écritures le seront.
        false
    }

    fn read(&self, sequence: u32, offset: u64, out: &mut [u8]) -> usize {
        let Some(rang) = self.rang(sequence) else {
            return 0;
        };
        let Some(message) = self.vue.messages().get(rang) else {
            return 0;
        };
        // ON ROUVRE LE FICHIER À CHAQUE MORCEAU, plutôt que de garder un
        // descripteur par message : une table de descripteurs épuisée arrête le
        // serveur entier, et une ouverture coûte moins que cela. Ce qu'on ne
        // refait PAS, c'est chercher le message — l'instantané le tient.
        let Ok(mut fichier) = std::fs::File::open(&message.path) else {
            return 0;
        };
        if fichier.seek(SeekFrom::Start(offset)).is_err() {
            return 0;
        }
        fichier.read(out).unwrap_or(0)
    }

    fn mark_seen(&mut self, _sequence: u32) {
        // RIEN N'EST ÉCRIT ENCORE. Marquer un message comme lu veut dire le
        // renommer dans le Maildir, et renommer sous un verrou partagé demande
        // de décider ce qui arrive quand deux sessions le font en même temps.
        // `STORE` n'est pas servi non plus : les deux viendront ensemble.
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
    boites: Arc<BTreeMap<String, Arc<Maildir>>>,
}

impl BoitesImap {
    /// Monte le service à partir des boîtes déjà ouvertes par le serveur.
    #[must_use]
    pub fn new(boites: Arc<BTreeMap<String, Arc<Maildir>>>) -> Self {
        Self { boites }
    }

    /// La boîte d'un compte, si le nom demandé est `INBOX`.
    fn maildir(&self, user: &[u8], name: &[u8]) -> Option<&Arc<Maildir>> {
        if !name.eq_ignore_ascii_case(INBOX) {
            return None;
        }
        let nom = core::str::from_utf8(user).ok()?;
        self.boites.get(nom)
    }
}

impl Mailboxes for BoitesImap {
    type Open = BoiteImap;

    fn name(&self, user: &[u8], index: usize) -> Option<&[u8]> {
        // Une seule boîte par compte, et seulement si le compte existe.
        let nom = core::str::from_utf8(user).ok()?;
        self.boites.get(nom)?;
        (index == 0).then_some(INBOX)
    }

    fn open(&self, user: &[u8], name: &[u8]) -> Option<Self::Open> {
        let maildir = self.maildir(user, name)?;
        let vue = MailboxView::open(maildir).ok()?;
        let (drapeaux, dates) = vue
            .messages()
            .iter()
            .map(|message| (drapeaux_de(&message.path), date_de(&message.path)))
            .unzip();
        Some(BoiteImap {
            vue,
            uid_validity: maildir.uid_validity().value(),
            drapeaux,
            dates,
        })
    }
}

/// Les drapeaux d'un message, lus dans son nom de fichier.
fn drapeaux_de(chemin: &std::path::Path) -> Flags {
    let Some(nom) = chemin.file_name().and_then(|brut| brut.to_str()) else {
        return Flags::NONE;
    };
    let Ok(lu) = MessageName::parse(nom.as_bytes()) else {
        return Flags::NONE;
    };
    let maildir = lu.flags();
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
