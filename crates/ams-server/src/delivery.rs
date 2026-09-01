//! Le fil entre la boucle et les boîtes.

use std::collections::BTreeMap;
use std::sync::Arc;

use ams_loop_tokio::{Delivery, DeliveryFailure};
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
pub struct MaildirDelivery {
    boites: Arc<Boites>,
    comptes: Arc<crate::comptes::Comptes>,
    arrivees: Vec<Incoming>,
}

impl MaildirDelivery {
    /// Ouvre une remise vers ce jeu de boîtes.
    #[must_use]
    pub fn new(boites: Arc<Boites>, comptes: Arc<crate::comptes::Comptes>) -> Self {
        Self {
            boites,
            comptes,
            arrivees: Vec::new(),
        }
    }
}

impl Delivery for MaildirDelivery {
    fn add_recipient(&mut self, address: &[u8]) -> Result<(), DeliveryFailure> {
        // La politique a déjà accepté cette adresse au `RCPT` ; si elle ne mène
        // plus nulle part, c'est que le magasin a changé sous nos pieds. C'est
        // TEMPORAIRE : le pair a le droit de réessayer.
        // **UN INSTANTANÉ PAR DESTINATAIRE** : ce qu'un administrateur change
        // pendant une transaction sera vu par la suivante, et non au milieu de
        // celle-ci.
        let comptes = self.comptes.vue();
        let compte = ams_auth::route(&comptes, address).ok_or(DeliveryFailure::Temporary)?;
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
        Ok(())
    }

    fn finish(&mut self) -> Result<(), DeliveryFailure> {
        // AUCUN DESTINATAIRE, AUCUNE REMISE. La session n'accepte pas de `DATA`
        // sans `RCPT`, et accepter un message qui ne va nulle part reviendrait à
        // répondre `250` pour une boîte qui n'existe pas.
        if self.arrivees.is_empty() {
            return Err(DeliveryFailure::Temporary);
        }
        let arrivees = core::mem::take(&mut self.arrivees);
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
        })
    }

    fn abort(&mut self) {
        for arrivee in core::mem::take(&mut self.arrivees) {
            arrivee.abort();
        }
    }
}
