// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le côté SERVEUR de SCRAM : ce que la session lui demande, et ce qu'il sait.
//!
//! # POURQUOI CE CALCUL VIT ICI, ET NON DANS LA SESSION
//!
//! La session encadre : elle décode du base64, retient deux messages, et
//! répond. Tout ce qui demande à SAVOIR quelque chose — le magasin des
//! vérificateurs, la clé qui les ouvre, un nonce tiré du noyau — est une
//! entrée-sortie ou un secret, et C1 les garde hors des machines à états.
//!
//! # LE MAGASIN PEUT ÊTRE ABSENT, ET C'EST LE CAS ORDINAIRE
//!
//! Sans `--scram-key` et `--scram`, ce module n'existe pas : [`Verificateurs`]
//! est `None`, la politique rend `None`, et la session n'annonce pas le
//! mécanisme. Un serveur qui n'a pas de vérificateurs ne doit pas promettre
//! SCRAM — un client qui sait faire les deux renoncerait à `PLAIN` pour rien.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use ams_auth::{CLE_SCELLEMENT_OCTETS, ScramVerifier};

/// Ce que le serveur tient pour conduire SCRAM.
///
/// **LE `Debug` NE DIT PAS LA CLÉ**, et c'est écrit à la main pour cela : un
/// `derive` l'imprimerait dans le premier message d'erreur venu, et une clé de
/// scellement dans un journal est une clé perdue.
pub struct Verificateurs {
    /// Le magasin, relu à chaud comme le fichier de comptes.
    ///
    /// **UN `Arc` DANS UN VERROU**, la même forme que `Comptes` : un lecteur
    /// clone le pointeur et s'en va, plutôt que de tenir le verrou pendant tout
    /// un échange SCRAM.
    magasin: RwLock<Arc<Vec<ScramVerifier>>>,
    /// Le chemin, pour la relecture.
    chemin: PathBuf,
    /// Ce qu'on sait du fichier, et quand on l'a regardé.
    ///
    /// **LA MÊME VEILLE QUE `Comptes`**, et pour la même raison : `air-mail-admin
    /// account passwd` réécrit le magasin pendant que le serveur tourne, et un
    /// mot de passe changé doit valoir tout de suite. Interroger le système à
    /// chaque `AUTH` coûterait un appel par connexion ; une seconde de latence
    /// ne coûte rien à personne.
    veille: std::sync::Mutex<Veille>,
    /// La clé de scellement, lue une fois au démarrage.
    ///
    /// **ELLE RESTE EN MÉMOIRE**, et c'est écrit plutôt que tu : sans elle, pas
    /// un vérificateur ne s'ouvre, donc personne ne se connecte. Qui lit la
    /// mémoire de ce processus a les deux clés de chaque compte — le scellement
    /// protège de la fuite d'un fichier, pas de la compromission d'une machine.
    clef: [u8; CLE_SCELLEMENT_OCTETS],
}

/// De quoi savoir si le disque a bougé, sans le relire à chaque fois.
#[derive(Debug)]
struct Veille {
    /// La taille et la date du fichier tel qu'on l'a lu, ou `None` s'il était
    /// absent — un magasin absent est licite, et le devenir ne l'est pas moins.
    marque: Option<(u64, std::time::SystemTime)>,
    /// Quand on a regardé pour la dernière fois.
    dernier_regard: std::time::Instant,
}

/// Le temps minimal entre deux interrogations du système de fichiers.
const REGARD: std::time::Duration = std::time::Duration::from_secs(1);

/// La taille et la date de modification d'un fichier, s'il existe.
fn marque_de(chemin: &std::path::Path) -> Option<(u64, std::time::SystemTime)> {
    let etat = std::fs::metadata(chemin).ok()?;
    Some((etat.len(), etat.modified().ok()?))
}

impl Verificateurs {
    /// Lit la clé et le magasin, ou dit pourquoi il ne le peut pas.
    ///
    /// # Errors
    ///
    /// Une clé illisible ou de mauvaise taille, un magasin illisible ou refusé
    /// par son chargement. **Un magasin ABSENT n'est pas une erreur** : c'est
    /// un serveur dont aucun compte n'a encore de vérificateur, et il doit
    /// démarrer.
    pub fn charger(chemin_clef: &PathBuf, chemin: PathBuf) -> Result<Self, String> {
        let lue = std::fs::read(chemin_clef)
            .map_err(|erreur| format!("clé SCRAM `{}` : {erreur}", chemin_clef.display()))?;
        if lue.len() != CLE_SCELLEMENT_OCTETS {
            return Err(format!(
                "clé SCRAM `{}` : {} octet(s) au lieu de {CLE_SCELLEMENT_OCTETS} — \
                 `air-mail-admin scram init` en tire une juste",
                chemin_clef.display(),
                lue.len()
            ));
        }
        let mut clef = [0_u8; CLE_SCELLEMENT_OCTETS];
        for (place, octet) in clef.iter_mut().zip(&lue) {
            *place = *octet;
        }
        let magasin = match std::fs::read(&chemin) {
            Ok(octets) => ams_config::decode_scram(&octets)
                .map_err(|erreur| format!("magasin SCRAM `{}` : {erreur}", chemin.display()))?,
            Err(erreur) if erreur.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(erreur) => {
                return Err(format!("magasin SCRAM `{}` : {erreur}", chemin.display()));
            }
        };
        let marque = marque_de(&chemin);
        Ok(Self {
            magasin: RwLock::new(Arc::new(magasin)),
            chemin,
            veille: std::sync::Mutex::new(Veille {
                marque,
                dernier_regard: std::time::Instant::now(),
            }),
            clef,
        })
    }

    /// Relit le magasin si le fichier a bougé depuis le dernier regard.
    ///
    /// **ON NE RETIENT LA MARQUE QUE SI LA LECTURE ABOUTIT** : la noter avant
    /// ferait passer un fichier illisible pour un fichier lu, et l'on
    /// n'essaierait plus jamais.
    fn relire_si_le_disque_a_bouge(&self) {
        let Ok(mut veille) = self.veille.try_lock() else {
            return;
        };
        if veille.dernier_regard.elapsed() < REGARD {
            return;
        }
        veille.dernier_regard = std::time::Instant::now();
        let marque = marque_de(&self.chemin);
        if marque == veille.marque {
            return;
        }
        if self.relire().is_ok() {
            veille.marque = marque;
        }
    }

    /// Relit le magasin — le même geste que pour le fichier de comptes.
    ///
    /// # Errors
    ///
    /// Le fichier ne se lit pas, ou son contenu est refusé. **L'ancien magasin
    /// reste alors en place** : un fichier à moitié écrit ne doit pas fermer la
    /// porte à tout le monde.
    pub fn relire(&self) -> Result<usize, String> {
        let octets = std::fs::read(&self.chemin)
            .map_err(|erreur| format!("magasin SCRAM `{}` : {erreur}", self.chemin.display()))?;
        let lus = ams_config::decode_scram(&octets)
            .map_err(|erreur| format!("magasin SCRAM `{}` : {erreur}", self.chemin.display()))?;
        let combien = lus.len();
        // Un verrou empoisonné par une panique d'un autre fil ne doit pas
        // empêcher de servir : on reprend la donnée telle qu'elle est.
        match self.magasin.write() {
            Ok(mut place) => *place = Arc::new(lus),
            Err(empoisonne) => *empoisonne.into_inner() = Arc::new(lus),
        }
        Ok(combien)
    }

    /// Combien de comptes ont un vérificateur.
    #[must_use]
    pub fn combien(&self) -> usize {
        self.vue().len()
    }

    /// Un instantané du magasin, qui ne changera pas sous les pieds du lecteur.
    fn vue(&self) -> Arc<Vec<ScramVerifier>> {
        self.relire_si_le_disque_a_bouge();
        match self.magasin.read() {
            Ok(place) => Arc::clone(&place),
            Err(empoisonne) => Arc::clone(&empoisonne.into_inner()),
        }
    }

    /// Le vérificateur d'un compte, s'il en a un.
    fn pour(&self, login: &[u8]) -> Option<ScramVerifier> {
        self.vue()
            .iter()
            .find(|v| v.login.as_bytes() == login)
            .cloned()
    }

    /// Le `server-first` : `r=<nonce>,s=<sel>,i=<n>`.
    ///
    /// # UN COMPTE INCONNU RÉPOND COMME UN AUTRE
    ///
    /// §7 de RFC 5802. Le sel est alors [`ams_auth::scram_sel_factice`] — stable
    /// dans le temps, différent d'un compte à l'autre, imprévisible sans la
    /// clé — et les itérations sont celles du produit. Un compte inconnu qui
    /// rendrait un sel neuf à chaque essai, ou un autre compte d'itérations, se
    /// trahirait par cela seul.
    pub fn server_first(
        &self,
        login: &[u8],
        nonce_client: &[u8],
        nonce_serveur: &[u8],
        sortie: &mut [u8],
    ) -> Option<usize> {
        let (sel, iterations) = match self.pour(login) {
            Some(v) => (v.sel, v.iterations),
            None => (
                ams_auth::scram_sel_factice(login, &self.clef),
                ams_auth::SCRAM_ITERATIONS,
            ),
        };
        let mut sel_encode = [0_u8; 32];
        let sel_b64 = ams_mime::encode_base64_line(&sel, &mut sel_encode).ok()?;

        let mut ecrits = 0_usize;
        let mut poser = |morceau: &[u8]| -> Option<()> {
            let fin = ecrits.checked_add(morceau.len())?;
            sortie.get_mut(ecrits..fin)?.copy_from_slice(morceau);
            ecrits = fin;
            Some(())
        };
        poser(b"r=")?;
        poser(nonce_client)?;
        poser(nonce_serveur)?;
        poser(b",s=")?;
        poser(sel_b64)?;
        poser(b",i=")?;
        let mut chiffres = [0_u8; 10];
        poser(nombre(iterations, &mut chiffres))?;
        Some(ecrits)
    }

    /// Vérifie la preuve, et écrit le `server-final`.
    ///
    /// **AUCUNE DISTINCTION ENTRE « INCONNU » ET « FAUX »** : un `None` unique.
    pub fn server_final(
        &self,
        login: &[u8],
        auth_message: &[u8],
        preuve: &[u8; 32],
        sortie: &mut [u8],
    ) -> Option<usize> {
        let verificateur = self.pour(login)?;
        let cles = ams_auth::scram_ouvrir(&verificateur, &self.clef).ok()?;
        let retrouvee = ams_sasl::client_key_depuis_preuve(&cles.stored, auth_message, preuve);
        if !ams_sasl::egales(&ams_sasl::stored_key(&retrouvee), &cles.stored) {
            return None;
        }
        let signature = ams_sasl::server_signature(&cles.server, auth_message);
        let mut encode = [0_u8; 64];
        let dit = ams_mime::encode_base64_line(&signature, &mut encode).ok()?;
        let fin = 2_usize.checked_add(dit.len())?;
        sortie.get_mut(..2)?.copy_from_slice(b"v=");
        sortie.get_mut(2..fin)?.copy_from_slice(dit);
        Some(fin)
    }
}

impl core::fmt::Debug for Verificateurs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Verificateurs")
            .field("chemin", &self.chemin)
            .field("combien", &self.combien())
            .finish_non_exhaustive()
    }
}

/// Un entier décimal, sans allocation.
fn nombre(mut valeur: u32, place: &mut [u8; 10]) -> &[u8] {
    if valeur == 0 {
        place[0] = b'0';
        return place.get(..1).unwrap_or_default();
    }
    let mut rang = place.len();
    while valeur > 0 && rang > 0 {
        rang = rang.saturating_sub(1);
        if let Some(chiffre) = place.get_mut(rang) {
            *chiffre = b'0'.saturating_add(u8::try_from(valeur % 10).unwrap_or(0));
        }
        valeur /= 10;
    }
    place.get(rang..).unwrap_or_default()
}

#[cfg(test)]
mod tests;
