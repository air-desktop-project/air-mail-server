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

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, RwLockWriteGuard};

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
}

impl Comptes {
    /// Ouvre le magasin sur ce fichier, avec ce qu'on vient d'y lire.
    #[must_use]
    pub fn new(chemin: PathBuf, comptes: Vec<Account>) -> Self {
        Self {
            chemin,
            vue: RwLock::new(Arc::new(comptes)),
        }
    }

    /// Les comptes tels qu'ils sont maintenant.
    ///
    /// **LE VERROU EST RELÂCHÉ AVANT QUE VOUS NE LISIEZ** : ce qu'on rend est un
    /// instantané, et il ne changera pas sous vos pieds.
    #[must_use]
    pub fn vue(&self) -> Arc<Vec<Account>> {
        Arc::clone(&self.lire())
    }

    /// Applique cette modification, l'écrit, puis la publie.
    ///
    /// # Errors
    ///
    /// [`Faute`] — la modification elle-même, le magasin qu'elle produirait, ou
    /// le disque.
    pub fn modifier<F>(&self, quoi: F) -> Result<(), Faute>
    where
        F: FnOnce(&mut Vec<Account>) -> Result<(), Faute>,
    {
        let mut vue = self.ecrire();
        let mut suite = (**vue).clone();
        quoi(&mut suite)?;

        // 1. PROUVER QUE CE QU'ON ÉCRIRA SE RELIRA.
        let octets = ams_config::encode_accounts(&suite).map_err(Faute::Refuse)?;
        let relu = ams_config::decode_accounts(&octets).map_err(Faute::Refuse)?;

        // 2. Écrire. **`block_in_place` PARCE QU'IL Y A DEUX `fsync`** : les
        //    faire dans une tâche asynchrone bloquerait l'ordonnanceur, comme
        //    pour la validation d'un message remis.
        tokio::task::block_in_place(|| poser(&self.chemin, &octets)).map_err(Faute::Ecriture)?;

        // 3. Publier CE QU'ON A RELU, et non ce qu'on avait construit. Les deux
        //    sont égaux ; publier le relu rend la mémoire et le disque
        //    identiques par construction plutôt que par raisonnement.
        *vue = Arc::new(relu);
        Ok(())
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
