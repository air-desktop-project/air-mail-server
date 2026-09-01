//! Le fil entre la boucle et les boîtes.

use std::collections::BTreeMap;
use std::sync::Arc;

use ams_loop_tokio::{Delivery, DeliveryFailure, Spool};
use ams_store::{Incoming, Maildir};

/// Les boîtes du serveur, une par compte, partagées par toutes les connexions.
///
/// # ELLE EST MODIFIABLE, PARCE QUE LES COMPTES LE SONT
///
/// Un compte créé par l'administration n'a pas de boîte : la carte était lue une
/// fois au démarrage, et un compte neuf aurait pu s'authentifier sans jamais rien
/// recevoir. Un demi-compte est pire qu'un refus, parce que rien ne le dit.
///
/// # UN `Arc<Maildir>` SORT, PAS UNE RÉFÉRENCE
///
/// Chaque lecture clone le pointeur et relâche le verrou. Rendre une référence
/// obligerait à tenir le verrou aussi longtemps qu'on s'en sert — c'est-à-dire
/// pendant une session IMAP entière, pendant laquelle aucun compte ne pourrait
/// être créé.
#[derive(Default)]
pub struct Boites {
    /// Une boîte par compte, par son nom.
    carte: std::sync::RwLock<BTreeMap<String, Arc<Maildir>>>,
}

impl Boites {
    /// La carte telle qu'elle est au démarrage.
    #[must_use]
    pub fn new(carte: BTreeMap<String, Arc<Maildir>>) -> Self {
        Self {
            carte: std::sync::RwLock::new(carte),
        }
    }

    /// La boîte de ce compte, s'il en a une.
    #[must_use]
    pub fn get(&self, nom: &str) -> Option<Arc<Maildir>> {
        self.lire().get(nom).map(Arc::clone)
    }

    /// Ajoute cette boîte à la carte, ou remplace celle qui portait ce nom.
    pub fn poser(&self, nom: String, boite: Arc<Maildir>) {
        self.ecrire().insert(nom, boite);
    }

    /// Retire la boîte de ce compte de la carte.
    ///
    /// **LE RÉPERTOIRE RESTE SUR LE DISQUE**, et c'est délibéré : voir
    /// `ApiMaildir::supprimer_un_compte`.
    pub fn retirer(&self, nom: &str) {
        self.ecrire().remove(nom);
    }

    /// Le verrou de lecture, empoisonnement compris.
    fn lire(&self) -> std::sync::RwLockReadGuard<'_, BTreeMap<String, Arc<Maildir>>> {
        self.carte
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Le verrou d'écriture, empoisonnement compris.
    fn ecrire(&self) -> std::sync::RwLockWriteGuard<'_, BTreeMap<String, Arc<Maildir>>> {
        self.carte
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Remet un message dans **les boîtes de ses destinataires**.
///
/// # Pourquoi cette pièce vit dans le binaire
///
/// `ams-store` n'implémente pas [`Delivery`] : le trait appartient à la boucle,
/// et l'implémenter dans un écrivain de fichiers l'aurait fait dépendre de tokio.
/// L'adaptation appartient donc à qui connaît les deux — c'est-à-dire ici.
///
/// # Un message, plusieurs boîtes : ON ÉCRIT N FOIS
///
/// Un `RCPT` par destinataire, un seul `DATA`. Le message est donc écrit dans
/// chaque boîte, en parallèle, morceau par morceau.
///
/// **Un lien matériel serait moins cher** — un seul contenu sur le disque au
/// lieu de N — et c'est ce que font les serveurs qui optimisent. Il suppose en
/// revanche que toutes les boîtes vivent sur le même système de fichiers, ce que
/// rien ici ne garantit ni ne vérifie ; et il fait partager une inode entre des
/// comptes qui n'ont, par ailleurs, rien à partager. Le choix est fait dans ce
/// sens, il coûte de la place, et il est écrit ici plutôt que découvert.
///
/// # `block_in_place`, et pourquoi il n'est appelé QUE sur `finish`
///
/// Valider un message fait deux `fsync` par boîte — le fichier, puis le
/// répertoire — et un `fsync` peut prendre le temps d'une écriture disque.
/// L'appeler dans une tâche asynchrone bloquerait l'ordonnanceur ;
/// `block_in_place` sort le fil courant du bassin le temps de l'attente.
///
/// `append`, lui, ne fait qu'écrire dans le cache de pages : l'y envelopper
/// coûterait un déménagement de fil par morceau de message, pour rien.
///
/// **Cela exige l'ordonnanceur multi-fils** : `block_in_place` panique sur le
/// mono-fil. Le binaire le choisit, et c'est pour cela qu'il le choisit.
///
/// # ET CE QUI N'EST PAS D'ICI VA DANS LA FILE
///
/// Depuis que l'émission existe, une adresse qu'aucun compte ne déclare peut
/// avoir été acceptée au `RCPT` — mais seulement pour une session AUTHENTIFIÉE,
/// et seulement si l'exploitant a demandé l'émission (voir
/// `BoitesConnues::qui_relaie`). Elle arrive donc ici sans boîte, et c'est le
/// signe qu'il faut la mettre en file plutôt que de la refuser.
///
/// **Cette remise ne redécide RIEN de tout cela.** Elle ne sait pas si la
/// session était authentifiée, et elle n'a pas à le savoir : sans file
/// configurée, une adresse sans boîte est refusée, et c'est tout ce qu'elle a
/// besoin de vérifier. Deux endroits qui décideraient d'ouvrir un relais
/// finiraient par ne plus dire la même chose.
pub struct MaildirDelivery {
    boites: Arc<Boites>,
    comptes: Arc<crate::comptes::Comptes>,
    arrivees: Vec<Incoming>,
    /// La file, quand l'émission est ouverte.
    file: Option<Spool>,
    /// Le `MAIL FROM:` de cette transaction — voir [`Delivery::begin`].
    retour: Option<String>,
    /// Les destinataires qui ne sont pas d'ici.
    sortants: Vec<String>,
    /// Le message, RASSEMBLÉ, et seulement s'il y a un sortant.
    ///
    /// **On ne rassemble rien pour une remise purement locale** : une boîte
    /// s'écrit au fil de l'eau, et garder le message en mémoire ferait payer à
    /// chaque courrier reçu le prix d'une émission qui n'a pas lieu.
    corps: Vec<u8>,
    /// Ce qu'un message peut peser, pour que `corps` ne croisse pas sans fin.
    corps_max: usize,
}

impl MaildirDelivery {
    /// Ouvre une remise vers ce jeu de boîtes. **Elle n'émet pas.**
    #[must_use]
    pub fn new(boites: Arc<Boites>, comptes: Arc<crate::comptes::Comptes>) -> Self {
        Self {
            boites,
            comptes,
            arrivees: Vec::new(),
            file: None,
            retour: None,
            sortants: Vec::new(),
            corps: Vec::new(),
            corps_max: 0,
        }
    }

    /// Lui donne de quoi mettre en file ce qui n'est pas d'ici.
    ///
    /// **C'est la seule façon d'ouvrir l'émission de ce côté**, et elle se voit :
    /// une remise se construit sans file, et l'appelant doit écrire une ligne
    /// pour la lui donner.
    #[must_use]
    pub fn avec_file(mut self, file: Spool, corps_max: usize) -> Self {
        self.file = Some(file);
        self.corps_max = corps_max;
        self
    }

    /// L'heure, en secondes depuis l'époque.
    fn maintenant() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |depuis| depuis.as_secs())
    }
}

impl Delivery for MaildirDelivery {
    fn begin(&mut self, return_path: Option<&[u8]>) {
        // Une nouvelle transaction n'hérite RIEN de la précédente : ni son
        // chemin de retour, ni ses sortants, ni son corps. Sans cela, un second
        // message émis sur la même connexion partirait à qui l'avait précédé.
        self.retour = return_path.map(|octets| String::from_utf8_lossy(octets).into_owned());
        self.sortants.clear();
        self.corps.clear();
    }

    fn add_recipient(&mut self, address: &[u8]) -> Result<(), DeliveryFailure> {
        // **UN INSTANTANÉ PAR DESTINATAIRE** : ce qu'un administrateur change
        // pendant une transaction sera vu par la suivante, et non au milieu de
        // celle-ci.
        let comptes = self.comptes.vue();
        let Some(compte) = ams_auth::route(&comptes, address) else {
            return self.mettre_en_file(address);
        };
        let boite = self
            .boites
            .get(&compte.login)
            .ok_or(DeliveryFailure::Temporary)?;
        // Un `deliver` qui échoue — plus d'UID, disque plein — est TEMPORAIRE :
        // lui répondre « définitivement non » ferait jeter au pair un message
        // qui pourrait passer dans une heure.
        let arrivee = boite.deliver().map_err(|_| DeliveryFailure::Temporary)?;
        self.arrivees.push(arrivee);
        Ok(())
    }

    fn append(&mut self, chunk: &[u8]) -> Result<(), DeliveryFailure> {
        for arrivee in &mut self.arrivees {
            arrivee
                .write(chunk)
                .map_err(|_| DeliveryFailure::Temporary)?;
        }
        if !self.sortants.is_empty() {
            // LA BORNE EST CELLE DU MESSAGE, et elle est vérifiée ici aussi
            // plutôt que supposée : la session la tient déjà, mais un tampon qui
            // croît en mémoire au rythme d'un pair est exactement ce que C3
            // interdit de laisser sans garde.
            if self.corps.len().saturating_add(chunk.len()) > self.corps_max {
                return Err(DeliveryFailure::Permanent);
            }
            self.corps.extend_from_slice(chunk);
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), DeliveryFailure> {
        // AUCUN DESTINATAIRE, AUCUNE REMISE. La session n'accepte pas de `DATA`
        // sans `RCPT`, et accepter un message qui ne va nulle part reviendrait à
        // répondre `250` pour une boîte qui n'existe pas.
        if self.arrivees.is_empty() && self.sortants.is_empty() {
            return Err(DeliveryFailure::Temporary);
        }
        let arrivees = core::mem::take(&mut self.arrivees);
        // **LES BOÎTES D'ABORD, LA FILE ENSUITE**, et l'ordre n'est pas
        // indifférent. Si le second échoue après le premier, le pair réessaie et
        // le message arrive deux fois quelque part : dans cet ordre, ce
        // « quelque part » est une boîte d'ici. L'ordre inverse ferait partir un
        // doublon chez un tiers, que personne ne peut plus rattraper.
        tokio::task::block_in_place(|| {
            for arrivee in arrivees {
                // TOUT OU RIEN N'EST PAS TENABLE ICI : les `rename` sont
                // atomiques un par un, pas ensemble. Un échec au milieu laisse
                // les premiers remis, et le pair réessaiera — il recevra alors
                // le message en double dans ces boîtes-là. C'est le compromis
                // que fait tout serveur sans file d'attente, et le doublon est
                // moins grave que la perte.
                arrivee
                    .commit()
                    .map(|_uid| ())
                    .map_err(|_| DeliveryFailure::Temporary)?;
            }
            Ok(())
        })?;
        self.deposer_les_sortants()
    }

    fn abort(&mut self) {
        for arrivee in core::mem::take(&mut self.arrivees) {
            arrivee.abort();
        }
        // RIEN N'EST ENCORE EN FILE : le dépôt n'a lieu qu'au `finish`. Il n'y a
        // donc qu'à oublier ce qu'on avait rassemblé.
        self.sortants.clear();
        self.corps.clear();
    }
}

impl MaildirDelivery {
    /// Retient une adresse qui n'est pas d'ici, pour la file.
    fn mettre_en_file(&mut self, address: &[u8]) -> Result<(), DeliveryFailure> {
        // **SANS FILE, UNE ADRESSE SANS BOÎTE EST UN REFUS**, et il est
        // TEMPORAIRE : la politique l'avait acceptée, donc le magasin a changé
        // sous nos pieds, et le pair a le droit de réessayer.
        let Some(_) = self.file.as_ref() else {
            return Err(DeliveryFailure::Temporary);
        };
        // **SANS CHEMIN DE RETOUR, ON NE MET RIEN EN FILE.** Un `MAIL FROM:<>`
        // ne désigne personne à qui rendre compte d'un échec, et §6.1 de
        // RFC 5321 interdit qu'une notification en engendre une autre. C'est
        // DÉFINITIF : aucune reprise ne donnera un expéditeur à ce message.
        if self.retour.is_none() {
            return Err(DeliveryFailure::Permanent);
        }
        self.sortants
            .push(String::from_utf8_lossy(address).into_owned());
        Ok(())
    }

    /// Dépose en file ce qui n'était pas d'ici.
    fn deposer_les_sortants(&mut self) -> Result<(), DeliveryFailure> {
        if self.sortants.is_empty() {
            return Ok(());
        }
        // Les deux `else` sont structurels : `mettre_en_file` a déjà refusé une
        // transaction qui n'aurait ni file ni chemin de retour, et rien ne peut
        // remplir `sortants` sans passer par elle.
        let (Some(file), Some(retour)) = (self.file.as_ref(), self.retour.as_ref()) else {
            return Err(DeliveryFailure::Permanent);
        };
        let sortants = core::mem::take(&mut self.sortants);
        let corps = core::mem::take(&mut self.corps);
        tokio::task::block_in_place(|| file.deposer(retour, &sortants, &corps, Self::maintenant()))
    }
}
