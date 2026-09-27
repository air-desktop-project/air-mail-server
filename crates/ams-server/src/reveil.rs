// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le réveil des appareils : quand du courrier arrive, dire aux appareils
//! abonnés de se synchroniser.
//!
//! # CE QUI PART NE DIT RIEN DU COURRIER
//!
//! Ni sujet, ni expéditeur, ni nombre de messages : seulement **quelle boîte a
//! changé**. Une notification traverse Apple ou Google, et y laisse une trace ;
//! ce qu'elle porterait du courrier y serait lu. L'appareil, réveillé, relit ce
//! qui a changé par l'API, sous son jeton, comme il le ferait à l'ouverture.
//!
//! # DÉCOUPLÉ DE LA REMISE
//!
//! La remise ne fait que SIGNALER, sans attendre : un service de notifications
//! lent ou injoignable ne doit jamais retenir un message ni faire répondre
//! `451` à un pair SMTP. Le signal part dans une file BORNÉE (C3) ; une tâche de
//! fond la vide, regroupe, et envoie. File pleine, le signal se perd, et cela se
//! dit : un réveil manqué coûte une synchronisation différée, pas un message.
//!
//! # REGROUPÉ
//!
//! Dix messages en une minute ne font pas sonner dix fois un téléphone, ni
//! frapper dix fois à la porte d'Apple — qui l'étranglerait. Le [`Carnet`]
//! réveille tout de suite au premier signal, puis au plus une fois par
//! [`INTERVALLE`] pour la même destination : ce qui arrive entre deux réveils
//! en fait un seul, à la fin de l'intervalle. Rien ne se perd — le dernier
//! signal a toujours son réveil.
//!
//! # QUI SE RÉVEILLE
//!
//! Le titulaire de la boîte, et chaque délégué qui peut la LIRE : un secrétariat
//! qui partage `support` veut savoir qu'un message y est arrivé. Un délégué qui
//! ne peut qu'envoyer n'a rien à y relire.

use std::collections::BTreeMap;
use std::string::String;
use std::sync::{Arc, Mutex, PoisonError};
use std::vec::Vec;

/// L'intervalle minimal entre deux réveils d'une même destination, en
/// secondes.
///
/// Trente secondes : assez court pour qu'un message paraisse arriver « tout de
/// suite », assez long pour qu'une rafale ne fasse qu'un réveil de plus.
pub const INTERVALLE: u64 = 30;

/// Combien de signaux la file retient au plus avant d'en perdre.
pub const FILE_MAX: usize = 1024;

/// Combien de destinations le carnet suit au plus.
///
/// **UNE BORNE, PARCE QUE LA MÉMOIRE SERAIT SINON CE QU'UN PAIR DÉCIDE** :
/// chaque boîte qui reçoit ouvre une entrée pour son titulaire et ses délégués.
/// Au-delà, les entrées les plus anciennes sans réveil en attente s'oublient ;
/// oublier une entrée ne perd rien — elle ne sert qu'à espacer.
pub const DESTINATIONS_MAX: usize = 4096;

/// Une destination : QUI réveiller, pour QUELLE boîte.
///
/// Un délégué de `support` reçoit un réveil pour `support` distinct du sien :
/// son application relit l'une ou l'autre, pas les deux.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Destination {
    /// Le compte dont les appareils se réveillent.
    pub destinataire: String,
    /// Le compte dont la boîte a changé.
    pub compte: String,
}

/// Ce que le carnet sait d'une destination.
#[derive(Debug, Clone, Copy)]
struct Etat {
    /// Avant quand on ne la réveille plus, en secondes.
    permis: u64,
    /// Un signal est arrivé depuis le dernier réveil.
    en_attente: bool,
}

/// Le carnet des réveils : qui réveiller maintenant, qui plus tard.
///
/// **IL NE FAIT AUCUNE ENTRÉE-SORTIE ET NE LIT AUCUNE HORLOGE** : l'heure lui
/// est donnée. C'est ce qui permet d'éprouver le regroupement seconde par
/// seconde, sans attendre.
#[derive(Debug, Default)]
pub struct Carnet {
    etats: BTreeMap<Destination, Etat>,
    prets: Vec<Destination>,
}

impl Carnet {
    /// Un carnet vide.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Un signal pour cette destination, à l'instant `maintenant`.
    pub fn signaler(&mut self, destination: Destination, maintenant: u64) {
        match self.etats.get_mut(&destination) {
            // Dans l'intervalle : un réveil viendra à sa fin.
            Some(etat) if maintenant < etat.permis => etat.en_attente = true,
            _ => {
                self.oublier_si_plein(maintenant);
                self.etats.insert(
                    destination.clone(),
                    Etat {
                        permis: maintenant.saturating_add(INTERVALLE),
                        en_attente: false,
                    },
                );
                if !self.prets.contains(&destination) {
                    self.prets.push(destination);
                }
            }
        }
    }

    /// Les destinations à réveiller maintenant.
    pub fn a_reveiller(&mut self, maintenant: u64) -> Vec<Destination> {
        let mut prets = core::mem::take(&mut self.prets);
        for (destination, etat) in &mut self.etats {
            if etat.en_attente && maintenant >= etat.permis {
                etat.en_attente = false;
                etat.permis = maintenant.saturating_add(INTERVALLE);
                prets.push(destination.clone());
            }
        }
        prets
    }

    /// Quand le prochain réveil en attente sera dû, s'il y en a un.
    #[must_use]
    pub fn prochain(&self) -> Option<u64> {
        self.etats
            .values()
            .filter(|etat| etat.en_attente)
            .map(|etat| etat.permis)
            .min()
    }

    /// Combien de destinations le carnet suit.
    #[cfg(test)]
    #[must_use]
    pub fn suivies(&self) -> usize {
        self.etats.len()
    }

    /// Au plein, oublie ce qui n'attend plus rien — l'expiré d'abord, puis le
    /// plus ancien.
    fn oublier_si_plein(&mut self, maintenant: u64) {
        if self.etats.len() < DESTINATIONS_MAX {
            return;
        }
        self.etats
            .retain(|_, etat| etat.en_attente || etat.permis > maintenant);
        while self.etats.len() >= DESTINATIONS_MAX {
            let ancienne = self
                .etats
                .iter()
                .filter(|(_, etat)| !etat.en_attente)
                .min_by_key(|(_, etat)| etat.permis)
                .map(|(destination, _)| destination.clone());
            match ancienne {
                Some(destination) => {
                    self.etats.remove(&destination);
                }
                // Tout attend un réveil : on garde, et l'on grandit d'un. La
                // borne de la file limite déjà ce qui peut arriver.
                None => break,
            }
        }
    }
}

/// Ce qu'un envoi a donné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Envoi {
    /// Parti vers le service de notifications.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "le premier transport arrive en 0.2.33")
    )]
    Transmis,
    /// Préparé, mais aucun transport ne le porte encore pour ce canal.
    NonTransmis,
    /// Le service l'a refusé, ou ne répond pas.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "le premier transport arrive en 0.2.33")
    )]
    Echec,
}

/// Ce qui porte un réveil jusqu'au service de notifications.
///
/// **UN SEUL APPEL, SANS ÉTAT PARTAGÉ** : c'est ce qui permet de le remplacer
/// par un témoin dans les essais, et de brancher APNs, FCM et Web Push un par
/// un, chacun derrière la même porte.
pub trait Envoyeur: Send + Sync {
    /// Réveille cet appareil pour cette boîte.
    fn envoyer(
        &self,
        appareil: &ams_config::Device,
        push: &ams_config::Push,
        compte: &str,
    ) -> Envoi;
}

/// L'envoyeur de la 0.2.32 : il n'a encore aucun transport, et le dit.
#[derive(Debug, Default)]
pub struct SansTransport;

impl Envoyeur for SansTransport {
    fn envoyer(&self, _: &ams_config::Device, _: &ams_config::Push, _: &str) -> Envoi {
        Envoi::NonTransmis
    }
}

/// Ce que le réveil a fait pour un compte : des nombres, pour `/v1/metrics`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Bilan {
    /// Les réveils décidés pour ses appareils.
    pub prepares: u64,
    /// Ceux qu'un service de notifications a acceptés.
    pub transmis: u64,
    /// Ceux qui ont échoué.
    pub echoues: u64,
}

/// Le réveil : la file que la remise alimente, et ce qu'elle a fait.
#[derive(Debug)]
pub struct Reveil {
    file: tokio::sync::mpsc::Sender<String>,
    bilans: Mutex<BTreeMap<String, Bilan>>,
    perdus: std::sync::atomic::AtomicU64,
}

impl Reveil {
    /// Signale qu'une boîte a reçu du courrier. **NE BLOQUE JAMAIS** : file
    /// pleine, le signal se perd, et se compte.
    pub fn signaler(&self, compte: &str) {
        if self.file.try_send(String::from(compte)).is_err() {
            let avant = self
                .perdus
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // On le dit une fois par millier : un journal inondé ne dit plus
            // rien.
            if avant.is_multiple_of(1000) {
                eprintln!(
                    "air-mail-server : réveil — file pleine, signal perdu ({avant} jusqu'ici)"
                );
            }
        }
    }

    /// Ce que le réveil a fait pour ce compte.
    #[must_use]
    pub fn bilan(&self, compte: &str) -> Bilan {
        self.bilans
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(compte)
            .copied()
            .unwrap_or_default()
    }

    /// Compte un envoi.
    fn noter(&self, compte: &str, envoi: Envoi) {
        let mut bilans = self.bilans.lock().unwrap_or_else(PoisonError::into_inner);
        let bilan = bilans.entry(String::from(compte)).or_default();
        bilan.prepares = bilan.prepares.saturating_add(1);
        match envoi {
            Envoi::Transmis => bilan.transmis = bilan.transmis.saturating_add(1),
            Envoi::Echec => bilan.echoues = bilan.echoues.saturating_add(1),
            Envoi::NonTransmis => {}
        }
    }
}

/// Ce que la tâche de fond lit pour décider.
pub struct Sources {
    /// Les appareils, et leurs abonnements.
    pub appareils: Arc<crate::appareils::Appareils>,
    /// Les délégations, pour réveiller aussi qui lit la boîte d'autrui.
    pub delegations: Option<Arc<crate::delegations::Delegations>>,
    /// Ce qui envoie.
    pub envoyeur: Arc<dyn Envoyeur>,
}

/// Démarre le réveil : rend la poignée que la remise alimente, et lance la
/// tâche qui vide la file.
#[must_use]
pub fn demarrer(sources: Sources) -> Arc<Reveil> {
    let (emetteur, recepteur) = tokio::sync::mpsc::channel(FILE_MAX);
    let reveil = Arc::new(Reveil {
        file: emetteur,
        bilans: Mutex::new(BTreeMap::new()),
        perdus: std::sync::atomic::AtomicU64::new(0),
    });
    tokio::spawn(tourner(Arc::clone(&reveil), recepteur, sources));
    reveil
}

/// La tâche de fond : attendre un signal ou l'échéance du prochain réveil.
async fn tourner(
    reveil: Arc<Reveil>,
    mut recepteur: tokio::sync::mpsc::Receiver<String>,
    sources: Sources,
) {
    let mut carnet = Carnet::new();
    loop {
        let attente = carnet.prochain().map(|echeance| {
            std::time::Duration::from_secs(echeance.saturating_sub(crate::maintenant()))
        });
        let signal = match attente {
            Some(duree) => match tokio::time::timeout(duree, recepteur.recv()).await {
                Ok(signal) => signal.map(Some),
                // L'échéance est venue sans signal : on réveille ce qui attend.
                Err(_) => Some(None),
            },
            None => recepteur.recv().await.map(Some),
        };
        // La file est fermée : le serveur s'arrête.
        let Some(signal) = signal else {
            return;
        };
        let maintenant = crate::maintenant();
        if let Some(compte) = signal {
            for destination in destinations(&compte, sources.delegations.as_deref()) {
                carnet.signaler(destination, maintenant);
            }
        }
        for destination in carnet.a_reveiller(maintenant) {
            reveiller(&reveil, &sources, &destination);
        }
    }
}

/// Qui réveiller quand la boîte de `compte` reçoit : son titulaire, et qui
/// peut la lire.
#[must_use]
pub fn destinations(
    compte: &str,
    delegations: Option<&crate::delegations::Delegations>,
) -> Vec<Destination> {
    let mut toutes = std::vec![Destination {
        destinataire: String::from(compte),
        compte: String::from(compte),
    }];
    if let Some(table) = delegations {
        toutes.extend(
            table
                .accordees_par(compte)
                .into_iter()
                .filter(|tenue| tenue.rights.contains(ams_config::Rights::READ))
                .map(|tenue| Destination {
                    destinataire: tenue.delegate,
                    compte: String::from(compte),
                }),
        );
    }
    toutes
}

/// Réveille les appareils abonnés d'une destination.
///
/// **BLOQUANT, ET HORS DE LA TÂCHE ASYNCHRONE** : l'envoi fera du réseau, et le
/// magasin d'appareils lit un fichier.
fn reveiller(reveil: &Arc<Reveil>, sources: &Sources, destination: &Destination) {
    let abonnes: Vec<(ams_config::Device, ams_config::Push)> = sources
        .appareils
        .du_compte(&destination.destinataire)
        .into_iter()
        .filter_map(|appareil| {
            let push = appareil.push.clone()?;
            Some((appareil, push))
        })
        .collect();
    for (appareil, push) in abonnes {
        let envoi = tokio::task::block_in_place(|| {
            sources
                .envoyeur
                .envoyer(&appareil, &push, &destination.compte)
        });
        reveil.noter(&destination.destinataire, envoi);
    }
}

#[cfg(test)]
mod tests;
