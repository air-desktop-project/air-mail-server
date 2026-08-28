//! Le fil entre la boucle et la boîte.

use std::sync::Arc;

use ams_loop_tokio::{Delivery, DeliveryFailure};
use ams_store::{Incoming, Maildir};

/// Remet les messages dans une boîte Maildir.
///
/// # Pourquoi cette pièce vit dans le binaire
///
/// `ams-store` n'implémente pas [`Delivery`] : le trait appartient à la boucle,
/// et l'implémenter dans un écrivain de fichiers l'aurait fait dépendre de tokio.
/// L'adaptation appartient donc à qui connaît les deux — c'est-à-dire ici.
///
/// # `block_in_place`, et pourquoi il n'est appelé QUE sur `finish`
///
/// Valider un message fait deux `fsync` — le fichier, puis le répertoire — et un
/// `fsync` peut prendre le temps d'une écriture disque. L'appeler dans une tâche
/// asynchrone bloquerait l'ordonnanceur ; `block_in_place` sort le fil courant du
/// bassin le temps de l'attente.
///
/// `append`, lui, ne fait qu'écrire dans le cache de pages : l'y envelopper
/// coûterait un déménagement de fil par morceau de message, pour rien.
///
/// **Cela exige l'ordonnanceur multi-fils** : `block_in_place` panique sur le
/// mono-fil. Le binaire le choisit, et c'est pour cela qu'il le choisit.
pub struct MaildirDelivery {
    boite: Arc<Maildir>,
    arrivee: Option<Incoming>,
    echoue: bool,
}

impl MaildirDelivery {
    /// Ouvre une remise vers cette boîte.
    #[must_use]
    pub fn new(boite: Arc<Maildir>) -> Self {
        Self {
            boite,
            arrivee: None,
            echoue: false,
        }
    }

    /// La remise en cours, ouverte à la demande.
    fn arrivee(&mut self) -> Result<&mut Incoming, DeliveryFailure> {
        if self.arrivee.is_none() {
            // Un `deliver` qui échoue — plus d'UID, disque plein — est
            // TEMPORAIRE : le pair a le droit de réessayer, et lui répondre
            // « définitivement non » lui ferait jeter un message qui pourrait
            // passer dans une heure.
            self.arrivee = Some(
                self.boite
                    .deliver()
                    .map_err(|_| DeliveryFailure::Temporary)?,
            );
        }
        self.arrivee.as_mut().ok_or(DeliveryFailure::Temporary)
    }
}

impl Delivery for MaildirDelivery {
    fn append(&mut self, chunk: &[u8]) -> Result<(), DeliveryFailure> {
        let arrivee = self.arrivee()?;
        arrivee.write(chunk).map_err(|_| {
            self.echoue = true;
            DeliveryFailure::Temporary
        })
    }

    fn finish(&mut self) -> Result<(), DeliveryFailure> {
        // Un message vide est un message : le pair a pu envoyer `DATA` puis
        // `.` aussitôt, et il attend un verdict comme les autres.
        let arrivee = match self.arrivee.take() {
            Some(arrivee) => arrivee,
            None => self
                .boite
                .deliver()
                .map_err(|_| DeliveryFailure::Temporary)?,
        };
        tokio::task::block_in_place(|| arrivee.commit())
            .map(|_uid| ())
            .map_err(|_| DeliveryFailure::Temporary)
    }

    fn abort(&mut self) {
        if let Some(arrivee) = self.arrivee.take() {
            arrivee.abort();
        }
    }
}
