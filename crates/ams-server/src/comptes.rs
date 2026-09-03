// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le magasin de comptes, **modifiable pendant que le serveur sert**.
//!
//! # CE QU'IL REMPLACE, ET POURQUOI IL A FALLU LE REMPLACER
//!
//! Les comptes étaient un `Arc<Vec<Account>>` lu une fois au démarrage. C'était
//! juste tant que rien ne les changeait : SMTP, IMAP, POP3 et l'API lisaient la
//! même tranche, sans verrou, sans coût. Ouvrir l'administration en écriture le
//! rend faux — il faut que ce qu'un administrateur change soit vu par les quatre,
//! tout de suite, sans arrêter le service.
//!
//! # UN INSTANTANÉ PAR OPÉRATION, ET NON UN VERROU TENU
//!
//! [`Comptes::vue`] rend un `Arc` et relâche le verrou aussitôt. Une remise en
//! cours garde donc la vue qu'elle avait au début — c'est ce qu'on veut : un
//! `RCPT` accepté ne doit pas devenir un `RCPT` refusé au milieu du `DATA` parce
//! qu'un administrateur passait par là. La modification suivante sera vue par
//! l'opération suivante, et c'est assez.
//!
//! Tenir le verrou pendant toute une transaction SMTP ferait l'inverse : une
//! écriture d'administration attendrait qu'un pair lent finisse de parler.
//!
//! # ON ÉCRIT D'ABORD, ON PUBLIE ENSUITE
//!
//! L'ordre n'est pas un détail. Si l'écriture échoue — disque plein, permissions
//! changées sous nos pieds — la vue en mémoire n'a pas bougé, et le serveur
//! continue de servir la vérité qui est sur le disque. L'ordre inverse ferait
//! servir un compte qui disparaîtrait au prochain démarrage, sans que rien ne
//! l'ait dit.
//!
//! # ET CE QU'ON PUBLIE EST CE QU'ON A RELU
//!
//! Toute modification est réencodée, puis **relue par le décodeur du démarrage**.
//! S'il la refuse, la modification est refusée : il devient impossible d'écrire
//! un magasin sur lequel le serveur refuserait de redémarrer.
//!
//! C'est aussi ce qui donne gratuitement toutes les invariantes du magasin — nom
//! licite, pas de nom en double, empreinte au-dessus du plancher, pas d'adresse
//! partagée entre deux comptes. Les redire ici en ferait une seconde liste, qui
//! divergerait le jour où l'une changerait.
//!
//! # LE DISQUE FAIT FOI, ET NON NOTRE MÉMOIRE
//!
//! Ce magasin n'est pas le seul à écrire son fichier : `air-mail-admin` écrit le
//! MÊME, depuis un terminal, pendant que le serveur tourne. Deux conséquences,
//! qui étaient toutes deux fausses avant :
//!
//!   - **On relit quand le fichier a changé.** Un compte ajouté au terminal
//!     était sinon invisible jusqu'au redémarrage : ni authentification, ni
//!     remise, et l'outil disait « compte ajouté ».
//!   - **On repart du disque avant de modifier.** Muter l'instantané mémoire et
//!     le reposer réécrirait le fichier entier depuis un état périmé, effaçant
//!     ce qu'un autre y avait mis.
//!
//! Ce qui reste, un verrou le ferme : `ams_fichier::verrouiller` sérialise la
//! lecture-modification-écriture entre les deux programmes.

use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock, RwLockWriteGuard};
use std::time::{Duration, Instant};

use ams_auth::Account;

/// Ce qui peut empêcher une modification.
///
/// **CHAQUE VARIANTE PORTE SA CAUSE, ET ELLE VA AU JOURNAL** : ce que l'API rend
/// au client est volontairement pauvre — un code, une phrase —, mais
/// l'exploitant qui lit le journal du serveur a droit à la raison exacte. Sans
/// elle, « ce compte n'est pas acceptable » l'enverrait chercher au hasard.
#[derive(Debug)]
pub enum Faute {
    /// Le magasin qui en résulterait n'en serait pas un.
    ///
    /// **C'EST LE DÉCODEUR DU DÉMARRAGE QUI LE DIT**, et non une règle écrite
    /// ici : ce qu'on refuse d'écrire est exactement ce qu'on refuserait de
    /// relire.
    Refuse(ams_config::Error),
    /// Ce compte n'existe pas.
    ///
    /// **IL N'Y A PAS DE VARIANTE « IL EXISTE DÉJÀ »** : ce cas-là se décide
    /// AVANT d'ouvrir le magasin — un `POST` sur un compte existant se refuse
    /// sans rien modifier —, et une variante qu'aucun chemin ne construit serait
    /// une garde inatteignable.
    Introuvable,
    /// Le disque n'a pas voulu. **Ce n'est pas la faute du demandeur.**
    Ecriture(String),
}

impl core::fmt::Display for Faute {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Refuse(cause) => write!(
                f,
                "le magasin qui en résulterait n'en serait pas un : {cause}"
            ),
            Self::Introuvable => write!(f, "ce compte n'existe pas"),
            Self::Ecriture(cause) => write!(f, "le disque n'a pas voulu : {cause}"),
        }
    }
}

/// Les comptes du serveur, et le fichier dont ils sont la vue.
#[derive(Debug)]
pub struct Comptes {
    /// Le fichier qui fait foi.
    chemin: PathBuf,
    /// Ce qu'on sert en ce moment.
    ///
    /// **UN `Arc` DANS UN VERROU, ET NON UN `Vec`** : un lecteur clone le
    /// pointeur et s'en va. Rendre une référence obligerait à tenir le verrou
    /// aussi longtemps qu'on s'en sert, c'est-à-dire pendant une transaction
    /// entière.
    vue: RwLock<Arc<Vec<Account>>>,
    /// Ce qu'on sait du fichier, et quand on l'a regardé pour la dernière fois.
    veille: Mutex<Veille>,
}

/// De quoi savoir si le disque a bougé, sans le relire à chaque fois.
#[derive(Debug)]
struct Veille {
    /// L'empreinte du fichier tel qu'on l'a lu, ou `None` s'il n'existait pas.
    marque: Option<Marque>,
    /// Quand on a regardé, pour ne pas interroger le système à chaque `AUTH`.
    dernier_regard: Instant,
}

/// Ce qui distingue une version du fichier d'une autre.
///
/// # L'INODE SUFFIRAIT PRESQUE SEUL, ET CE N'EST PAS UN HASARD
///
/// Toute écriture de ce dépôt passe par [`ams_fichier::poser`], qui REMPLACE le
/// fichier par renommage : chaque version porte donc un inode neuf. La date et
/// la taille sont là pour le cas d'un fichier posé autrement — restauré d'une
/// sauvegarde, par exemple —, où l'inode pourrait se répéter.
///
/// La date SEULE ne suffirait pas : deux écritures dans la même granularité
/// d'horodatage porteraient la même, et la seconde passerait inaperçue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Marque {
    inode: u64,
    date: i64,
    date_nanos: i64,
    taille: u64,
}

/// Le temps minimal entre deux interrogations du système de fichiers.
///
/// **`vue()` EST SUR LE CHEMIN CHAUD** : elle est consultée à chaque `AUTH` et à
/// chaque destinataire. Un appel système par destinataire serait un coût qu'on
/// paierait pour une réponse qui ne change presque jamais. Une seconde est assez
/// courte pour qu'un `account add` prenne effet le temps de rebasculer sur son
/// client, et assez longue pour que le coût disparaisse dans le bruit.
const REGARD: Duration = Duration::from_secs(1);

impl Comptes {
    /// Ouvre le magasin sur ce fichier, avec ce qu'on vient d'y lire.
    #[must_use]
    pub fn new(chemin: PathBuf, comptes: Vec<Account>) -> Self {
        let marque = marque_de(&chemin);
        Self {
            chemin,
            vue: RwLock::new(Arc::new(comptes)),
            veille: Mutex::new(Veille {
                marque,
                // ON DATE LA VEILLE DU DÉMARRAGE, et non de l'époque : sans
                // cela, le tout premier `vue()` relirait un fichier qu'on vient
                // de lire.
                dernier_regard: Instant::now(),
            }),
        }
    }

    /// Les comptes tels qu'ils sont maintenant.
    ///
    /// **LE VERROU EST RELÂCHÉ AVANT QUE VOUS NE LISIEZ** : ce qu'on rend est un
    /// instantané, et il ne changera pas sous vos pieds.
    #[must_use]
    pub fn vue(&self) -> Arc<Vec<Account>> {
        self.relire_si_le_disque_a_bouge();
        Arc::clone(&self.lire())
    }

    /// Applique cette modification, l'écrit, puis la publie.
    ///
    /// # ON REPART DU DISQUE, ET JAMAIS DE L'INSTANTANÉ
    ///
    /// L'instantané en mémoire date du dernier regard ; `air-mail-admin` a pu
    /// écrire depuis. Muter la copie mémoire et la reposer RÉÉCRIRAIT le fichier
    /// entier depuis un état périmé : un compte ajouté au terminal disparaîtrait
    /// à la première modification passée par l'API, sans un mot.
    ///
    /// # Errors
    ///
    /// [`Faute`] — la modification elle-même, le magasin qu'elle produirait, ou
    /// le disque.
    pub fn modifier<F>(&self, quoi: F) -> Result<(), Faute>
    where
        F: FnOnce(&mut Vec<Account>) -> Result<(), Faute>,
    {
        // **`block_in_place` DÈS LE VERROU** : il attend qu'un autre écrivain
        // ait fini, et les deux `fsync` de la pose bloquent aussi. Les faire
        // dans une tâche asynchrone bloquerait l'ordonnanceur, comme pour la
        // validation d'un message remis.
        tokio::task::block_in_place(|| {
            // L'ORDRE EST TOUJOURS LE MÊME — `veille`, puis `vue` — sans quoi
            // deux fils qui les prennent en sens inverse s'attendraient l'un
            // l'autre pour toujours.
            let mut veille = self.veille();
            let _verrou = ams_fichier::verrouiller(&self.chemin)
                .map_err(|erreur| Faute::Ecriture(erreur.to_string()))?;
            let mut vue = self.ecrire();

            let mut suite = match lire_le_disque(&self.chemin) {
                Ok(comptes) => comptes,
                // ABSENT : notre mémoire fait foi, et l'écriture le recréera.
                Err(erreur) if erreur.kind() == std::io::ErrorKind::NotFound => (**vue).clone(),
                // TOUTE AUTRE PANNE FAIT RENONCER. Écrire notre instantané sur
                // un fichier qu'on n'a pas su lire risquerait d'effacer ce qu'il
                // contenait ; refuser ne perd rien.
                Err(erreur) => {
                    return Err(Faute::Ecriture(format!(
                        "`{}` ne se relit pas avant d'être modifié : {erreur}",
                        self.chemin.display()
                    )));
                }
            };
            quoi(&mut suite)?;

            // 1. PROUVER QUE CE QU'ON ÉCRIRA SE RELIRA.
            let octets = ams_config::encode_accounts(&suite).map_err(Faute::Refuse)?;
            let relu = ams_config::decode_accounts(&octets).map_err(Faute::Refuse)?;

            // 2. Écrire.
            poser(&self.chemin, &octets).map_err(Faute::Ecriture)?;

            // 3. Publier CE QU'ON A RELU, et non ce qu'on avait construit. Les
            //    deux sont égaux ; publier le relu rend la mémoire et le disque
            //    identiques par construction plutôt que par raisonnement.
            *vue = Arc::new(relu);
            // 4. Et retenir l'empreinte de ce qu'on vient de poser, pour ne pas
            //    le relire à la première consultation venue.
            veille.marque = marque_de(&self.chemin);
            veille.dernier_regard = Instant::now();
            Ok(())
        })
    }

    /// Relit le fichier s'il a changé depuis le dernier regard.
    ///
    /// # Ce qu'elle ne fait PAS, et pourquoi
    ///
    /// Elle n'échoue jamais. Un fichier momentanément illisible — effacé, en
    /// cours de remplacement, un disque qui tousse — laisse la vue en place :
    /// c'est la dernière chose qu'on ait su lire, et servir cela vaut mieux que
    /// de refuser toute authentification parce qu'un `stat` a échoué.
    ///
    /// Elle n'attend jamais non plus. Un `try_lock` : si un autre fil regarde
    /// déjà, ou modifie, celui-ci passe son chemin et sert l'instantané. Faire
    /// la queue derrière une écriture pour un simple `RCPT` serait payer une
    /// attente pour une réponse qu'on a déjà.
    fn relire_si_le_disque_a_bouge(&self) {
        let Ok(mut veille) = self.veille.try_lock() else {
            return;
        };
        if veille.dernier_regard.elapsed() < REGARD {
            return;
        }
        veille.dernier_regard = Instant::now();
        let marque = marque_de(&self.chemin);
        if marque == veille.marque {
            return;
        }
        // ON NE RETIENT L'EMPREINTE QUE SI LA LECTURE ABOUTIT : la noter avant
        // ferait passer un fichier illisible pour un fichier lu, et l'on
        // n'essaierait plus jamais.
        if let Ok(comptes) = lire_le_disque(&self.chemin) {
            veille.marque = marque;
            *self.ecrire() = Arc::new(comptes);
        }
    }

    /// La veille, empoisonnement compris — même raison que pour les autres.
    fn veille(&self) -> std::sync::MutexGuard<'_, Veille> {
        self.veille
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Le verrou de lecture, empoisonnement compris.
    ///
    /// **UN VERROU EMPOISONNÉ N'ARRÊTE PAS LE SERVICE** : il dit qu'un fil a
    /// paniqué en le tenant, et la donnée qu'il protège est un `Arc` qu'aucune
    /// panique ne peut laisser à moitié écrit.
    fn lire(&self) -> std::sync::RwLockReadGuard<'_, Arc<Vec<Account>>> {
        self.vue
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Le verrou d'écriture, empoisonnement compris.
    fn ecrire(&self) -> RwLockWriteGuard<'_, Arc<Vec<Account>>> {
        self.vue
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// L'empreinte du fichier, ou `None` s'il n'est pas là.
///
/// **UN FICHIER ABSENT EST UNE EMPREINTE, ET NON UNE PANNE** : `None` se compare
/// comme le reste, si bien qu'un magasin effacé puis recréé se voit.
fn marque_de(chemin: &Path) -> Option<Marque> {
    let etat = std::fs::metadata(chemin).ok()?;
    Some(Marque {
        inode: etat.ino(),
        date: etat.mtime(),
        date_nanos: etat.mtime_nsec(),
        taille: etat.size(),
    })
}

/// Lit le magasin depuis le disque.
///
/// # Errors
///
/// L'erreur du système, ou [`std::io::ErrorKind::InvalidData`] si le fichier
/// n'est pas un magasin. Les deux se distinguent : l'appelant traite l'absence
/// autrement qu'une panne.
fn lire_le_disque(chemin: &Path) -> std::io::Result<Vec<Account>> {
    let octets = std::fs::read(chemin)?;
    ams_config::decode_accounts(&octets)
        .map_err(|erreur| std::io::Error::new(std::io::ErrorKind::InvalidData, erreur.to_string()))
}

/// Pose les octets du magasin, atomiquement et durablement.
///
/// La discipline elle-même vit dans [`ams_fichier`] : elle était écrite ici, et
/// quatre autres fois ailleurs, chacune un peu différemment. C'est ce qui avait
/// laissé l'outil d'administration — qui écrit ce MÊME fichier — la perdre
/// entièrement.
fn poser(chemin: &Path, octets: &[u8]) -> Result<(), String> {
    ams_fichier::poser(chemin, octets)
        .map_err(|erreur| format!("`{}` : {erreur}", chemin.display()))
}

#[cfg(test)]
mod tests;
