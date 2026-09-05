// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le certificat que le serveur PRÉSENTE, et qui change sous lui.
//!
//! # LE PROBLÈME QUE CE MODULE RÉSOUT
//!
//! Un certificat Let's Encrypt vit **trois mois**, et se renouvelle tous les
//! deux. Un serveur qui lit son matériel au démarrage et jamais plus cesse de
//! servir le TLS quatre-vingt-dix jours après son installation — et
//! **silencieusement** : rien dans son fonctionnement ne change jusqu'à
//! l'expiration, où tout s'arrête d'un coup.
//!
//! C'est le genre de panne qui se produit une nuit, trois mois après que la
//! personne qui a installé le serveur a cessé d'y penser.
//!
//! # POURQUOI ON NE RELIT PAS SUR UN SIGNAL, MAIS SUR LA DATE DU FICHIER
//!
//! `SIGHUP` est la convention, et elle se câble en une ligne dans un
//! `--deploy-hook` de certbot. **C'est justement le problème** : une ligne qu'il
//! faut penser à écrire, dont l'oubli ne se voit pas, et dont le prix se paie
//! quatre-vingt-dix jours plus tard.
//!
//! Regarder la date des deux fichiers ne demande rien à personne. Un
//! renouvellement les réécrit ; le serveur s'en aperçoit au battement suivant.
//!
//! # UN RECHARGEMENT QUI RATE NE CASSE RIEN
//!
//! C'est la règle qui gouverne ce module. `certbot` écrit ses fichiers l'un
//! après l'autre, et un renouvellement surpris à mi-chemin donne une chaîne
//! neuve avec une clé ancienne — qui ne correspondent pas.
//!
//! **On garde alors l'ancien matériel, et on le dit.** Servir un certificat
//! périmé quelques minutes de plus est sans commune mesure avec ne plus rien
//! servir du tout ; et le battement suivant retrouvera la paire complète.

use std::sync::{Arc, RwLock};

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

/// Le matériel courant, qu'une poignée de main lit et qu'un rechargement change.
///
/// # POURQUOI UN `RwLock` ET NON UN `Mutex`
///
/// Chaque poignée de main LIT ; seul un rechargement écrit, et il a lieu une
/// fois tous les deux mois. Un `Mutex` sérialiserait toutes les poignées de main
/// derrière un verrou que personne ne dispute.
#[derive(Debug)]
pub struct Certificat {
    actuel: RwLock<Arc<CertifiedKey>>,
}

impl Certificat {
    /// Prend le matériel de départ.
    #[must_use]
    pub fn neuf(materiel: CertifiedKey) -> Self {
        Self {
            actuel: RwLock::new(Arc::new(materiel)),
        }
    }

    /// Remplace le matériel présenté.
    ///
    /// **Les poignées de main EN COURS gardent l'ancien** : elles en tiennent un
    /// `Arc`, et il vit aussi longtemps qu'elles. Seules les suivantes verront
    /// le neuf, ce qui est exactement ce qu'on veut — une connexion ne change
    /// pas de certificat au milieu.
    pub fn remplacer(&self, materiel: CertifiedKey) {
        // **UN VERROU EMPOISONNÉ NE FAIT PAS PERDRE LE CERTIFICAT.** Il ne
        // signifierait qu'une chose : un fil a paniqué en le tenant. La donnée
        // qu'il protège est un `Arc` — rien ne peut l'avoir laissée à moitié
        // écrite — et refuser de la remplacer condamnerait le serveur à servir
        // un certificat périmé pour une panique qui n'a rien à voir.
        let mut place = self
            .actuel
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *place = Arc::new(materiel);
    }
}

impl ResolvesServerCert for Certificat {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // **AUCUN CHOIX SELON LE `ClientHello`**, et c'est délibéré : ce serveur
        // sert UN nom, celui que sa configuration annonce. Choisir selon le SNI
        // demanderait plusieurs certificats, donc une règle pour dire lequel
        // répond à quoi — et une règle qui n'a qu'un cas est une règle qu'on
        // écrira mal le jour où elle en aura deux.
        Some(Arc::clone(
            &self
                .actuel
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        ))
    }
}

#[cfg(test)]
#[path = "certificat/tests.rs"]
mod tests;
