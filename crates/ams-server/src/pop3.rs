//! Les boîtes, vues par le service POP3.

use std::collections::BTreeMap;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::sync::{Arc, Mutex};

use ams_loop_tokio::pop3::Mailboxes;
use ams_proto_pop3::MessageNumber;
use ams_session::pop3::Mailbox;
use ams_store::{LockedMailbox, Maildir};

/// Une boîte verrouillée, avec les marques d'effacement de la session.
///
/// # Les marques vivent ICI, et pas dans la session
///
/// La session dit `mark_deleted` ; ce qui les retient est un tableau de booléens
/// aussi long que la boîte, donc une allocation — que l'étage 2 s'interdit. Elles
/// vivent donc du côté qui alloue, et la session ne fait que les demander.
pub struct BoiteOuverte {
    verrouillee: LockedMailbox,
    marques: Vec<bool>,
}

impl BoiteOuverte {
    fn rang(&self, message: MessageNumber) -> Option<usize> {
        let rang = usize::try_from(message.value().saturating_sub(1)).unwrap_or(usize::MAX);
        (rang < self.verrouillee.messages().len()).then_some(rang)
    }

    /// Vivant : présent, et non marqué.
    fn vivant(&self, message: MessageNumber) -> Option<usize> {
        let rang = self.rang(message)?;
        self.marques
            .get(rang)
            .copied()
            .and_then(|marque| if marque { None } else { Some(rang) })
    }
}

impl Mailbox for BoiteOuverte {
    fn highest(&self) -> u32 {
        u32::try_from(self.verrouillee.messages().len()).unwrap_or(u32::MAX)
    }

    fn size(&self, message: MessageNumber) -> Option<u64> {
        let rang = self.vivant(message)?;
        self.verrouillee
            .messages()
            .get(rang)
            .map(|message| message.size)
    }

    fn uid(&self, message: MessageNumber) -> Option<u32> {
        let rang = self.vivant(message)?;
        self.verrouillee
            .messages()
            .get(rang)
            .map(|message| message.uid.value())
    }

    fn mark_deleted(&mut self, message: MessageNumber) -> bool {
        let Some(rang) = self.vivant(message) else {
            return false;
        };
        let Some(marque) = self.marques.get_mut(rang) else {
            return false;
        };
        *marque = true;
        true
    }

    fn reset_deletions(&mut self) {
        self.marques.fill(false);
    }
}

/// Les boîtes du serveur, telles que POP3 les ouvre.
pub struct BoitesPop3 {
    boites: Arc<BTreeMap<String, Arc<Maildir>>>,
    /// Les tampons de lecture, un par message en cours d'émission.
    ///
    /// Un `Mutex` parce que [`Mailboxes::read`] reçoit `&self` : elle est
    /// appelée depuis une tâche, une seule à la fois par connexion, et la
    /// section critique est un `read` de fichier.
    lecteurs: Mutex<()>,
}

impl BoitesPop3 {
    /// Monte le service à partir des boîtes déjà ouvertes par le serveur.
    #[must_use]
    pub fn new(boites: Arc<BTreeMap<String, Arc<Maildir>>>) -> Self {
        Self {
            boites,
            lecteurs: Mutex::new(()),
        }
    }
}

impl Mailboxes for BoitesPop3 {
    type Open = BoiteOuverte;

    fn open(&self, user: &[u8]) -> Option<Self::Open> {
        // Le nom vient d'un `PASS` accepté : c'est donc un compte connu, et sa
        // boîte a été ouverte au démarrage. On ne construit AUCUN chemin à
        // partir du nom — la table le fait pour nous, et un nom qui n'y est pas
        // n'ouvre rien.
        let nom = core::str::from_utf8(user).ok()?;
        let boite = self.boites.get(nom)?;
        let verrouillee = LockedMailbox::open(boite).ok().flatten()?;
        let marques = vec![false; verrouillee.messages().len()];
        Some(BoiteOuverte {
            verrouillee,
            marques,
        })
    }

    fn commit(&self, mailbox: Self::Open) -> usize {
        mailbox.verrouillee.expunge(&mailbox.marques)
    }

    fn read(
        &self,
        mailbox: &Self::Open,
        message: MessageNumber,
        offset: u64,
        buffer: &mut [u8],
    ) -> std::io::Result<usize> {
        let Some(rang) = mailbox.rang(message) else {
            return Ok(0);
        };
        let Some(entree) = mailbox.verrouillee.messages().get(rang) else {
            return Ok(0);
        };
        let _garde = self
            .lecteurs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Ouvrir à chaque morceau plutôt que de garder un descripteur : un
        // descripteur par connexion en cours de `RETR` finirait par épuiser la
        // table du processus, et l'ouverture est le moins cher des deux maux.
        let mut fichier = std::fs::File::open(&entree.path)?;
        fichier.seek(SeekFrom::Start(offset))?;
        fichier.read(buffer)
    }
}
