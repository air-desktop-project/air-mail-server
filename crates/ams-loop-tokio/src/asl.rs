// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! L'annonce tenue vivante auprès d'un annuaire `air-service-locator`.
//!
//! # CE N'EST PAS DU CODE DE ROBUSTESSE, C'EST LE PLAN DE CONTINUITÉ
//!
//! `annuaires.md` §3 du dépôt ASL : l'état vivant n'est **délibérément pas
//! répliqué** entre les deux annuaires racines. Quand l'un tombe, rien ne
//! bascule de leur côté — ce sont les daemons qui se reconnectent à l'autre et
//! se réannoncent, et l'état s'y reconstruit en un keepalive.
//!
//! Il n'y a donc pas d'autre bascule à écrire : c'est celle-ci. Ce fichier est
//! la moitié du plan de haute disponibilité de la découverte, et non un filet
//! qu'on ajoute à la fin.
//!
//! # LA CONNEXION EST LE BAIL
//!
//! `protocole.md` §1.2 : il n'y a aucun verbe « rafraîchir ». Le keepalive de
//! QUIC suffit, et **fermer la connexion EST le retrait**. Tant que ce serveur
//! écoute, cette connexion vit ; quand il s'arrête, l'extinction annoncée
//! distingue un départ volontaire d'une coupure, et l'annuaire rend « parti
//! (volontaire) » au lieu de « parti (inactivité) » — deux choses que celui qui
//! regarde ne traite pas pareil.
//!
//! # LA POLITIQUE N'EST PAS ICI
//!
//! Quel annuaire essayer, dans quel ordre, après quelle attente : tout cela est
//! décidé par [`asl_client::Tournee`], sans une entrée-sortie, et éprouvé
//! là-bas sur des listes littérales. Ce fichier-ci ouvre, attend, recommence.
//!
//! **Le bruit du recul n'est pas du raffinement** : sans lui, mille daemons
//! dont l'annuaire vient de tomber réessaient à la même seconde et le remettent
//! à terre à l'instant où il se relève.
//!
//! # CE QUI N'EST PAS ENCORE FAIT, ET QU'IL FAUT SAVOIR
//!
//! **Le `421` n'est pas suivi.** Un annuaire racine peut renvoyer une machine
//! vers un annuaire LOCAL (`protocole.md` §3 ter) : le corps dit où aller, et
//! `asl_client::renvoi` sait le lire. Ici, un `421` est compté comme un refus
//! et la tournée passe au suivant — ce qui est juste tant que la machine n'est
//! rangée dans aucun domaine confié, et faux le jour où elle l'est. C'est dit
//! plutôt que découvert.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;
use std::net::SocketAddr;
use std::sync::Arc;

use ams_quic_dial::Appel;
use asl_client::{Identite, Reprise, Tournee};
use asl_id::Identifiant;

use crate::error::Error;

/// Combien de temps la boucle d'entretien dort entre deux réveils.
///
/// **CE N'EST PAS LA CADENCE DU KEEPALIVE.** Celle-là appartient à QUIC, qui
/// émet ses `PING` selon ce que l'annuaire a annoncé. Cette constante-ci ne
/// décide que d'une chose : combien de temps un retrait peut mettre à être vu.
const ENTRETIEN_MS: u64 = 500;

/// Combien de temps [`Attache::retirer`] laisse à la tâche pour fermer.
const RETRAIT_MS: u64 = 2_000;

/// Un annuaire à joindre.
#[derive(Debug, Clone, Copy)]
pub struct Annuaire {
    /// Où le joindre. **Une adresse, jamais un nom** : ASL fonctionne sans DNS.
    pub adresse: SocketAddr,
    /// L'identité `n-…` qu'on doit trouver au bout — sa clé est ce que le
    /// certificat présenté doit porter.
    ///
    /// **ELLE N'EST PAS FACULTATIVE** : un annuaire sans identité attendue ne
    /// serait cru par rien, puisqu'il n'y a ni autorité ni nom à vérifier.
    pub identite: Identifiant,
}

/// Ce que l'attache a fait jusqu'ici.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Etat {
    /// Une connexion est-elle en ce moment authentifiée et annoncée ?
    pub attachee: bool,
    /// Combien de fois l'annonce a abouti depuis le démarrage.
    pub attaches: u64,
    /// Combien de fois une connexion attachée s'est rompue.
    pub ruptures: u64,
    /// Combien de refus — y compris les `421` que l'on ne suit pas encore.
    pub refus: u64,
    /// La cadence de keepalive que le dernier annuaire a accordée, en secondes.
    ///
    /// **ELLE VIENT DE L'ANNUAIRE, JAMAIS D'ICI.** Le bon delta se mesure sur
    /// de vrais NAT, et le figer dans ce serveur obligerait à le mettre à jour
    /// pour le corriger.
    pub cadence_s: u16,
}

/// Ce que la tâche et son porteur se partagent.
#[derive(Debug, Default)]
struct Partage {
    attachee: AtomicBool,
    attaches: AtomicU64,
    ruptures: AtomicU64,
    refus: AtomicU64,
    cadence: AtomicU64,
    retrait: AtomicBool,
}

/// Une annonce tenue vivante, quoi qu'il arrive au réseau.
///
/// # ELLE REND LA MAIN TOUT DE SUITE
///
/// `protocole.md` §1.4 : **un annuaire injoignable ne doit pas empêcher un
/// daemon de démarrer.** Un service de découverte en panne rendrait sinon
/// indisponibles tous les daemons qui en dépendent — la faute exacte que ce
/// genre de composant existe pour ne pas commettre. [`Attache::annoncer`] ne
/// fait donc aucune entrée-sortie : elle valide ce qu'elle peut valider, lance
/// la tâche, et rend la main. Ce serveur écoute déjà pendant que l'attache
/// cherche encore.
///
/// # LA LÂCHER, C'EST SE RETIRER
///
/// La connexion EST le bail, et cette structure la possède : sa destruction
/// interrompt la tâche, et l'annonce disparaît. C'est délibéré — cela évite le
/// pire des deux mondes, une annonce que plus personne ne tient et que
/// l'annuaire continue de publier.
///
/// Pour partir proprement, préférez [`Attache::retirer`] : la destruction seule
/// coupe sans prévenir, et l'annuaire ne l'apprend qu'à l'expiration
/// d'inactivité — une minute pendant laquelle il donne une adresse morte.
#[derive(Debug)]
pub struct Attache {
    tache: Option<tokio::task::JoinHandle<()>>,
    partage: Arc<Partage>,
}

impl Attache {
    /// Annonce ces services, et tient l'annonce jusqu'à ce qu'on la retire.
    ///
    /// `annonces` sont **déjà encodées** — par `ams_asl::composer_une_annonce`.
    /// C'est ce qui permet à la tâche de les répéter à chaque reconnexion sans
    /// rien emprunter, et ce qui fait qu'une annonce invalide est refusée dans
    /// la main de l'appelant plutôt que dans une tâche que personne ne regarde.
    ///
    /// Une liste vide est acceptée : une machine peut vouloir une connexion
    /// authentifiée sans rien annoncer elle-même. Le serveur le DIT au
    /// démarrage, parce que c'est presque toujours un oubli.
    ///
    /// # CE QUE LA TÂCHE REFAIT À CHAQUE RECONNEXION
    ///
    /// S'authentifier, puis réannoncer — dans cet ordre, et en entier.
    /// **L'annuaire d'en face n'a rien gardé** : soit il vient de redémarrer,
    /// soit c'est l'autre racine, qui n'a jamais rien su de nous. Reprendre là
    /// où l'on s'était arrêté n'a donc aucun sens — il n'y a pas de « là ».
    ///
    /// # Errors
    ///
    /// [`Error::AslSansAnnuaire`] si la liste est vide — ce n'est pas une
    /// panne, c'est une configuration, et c'est pourquoi elle est rendue ici
    /// plutôt que réessayée : une attache sans annuaire tournerait en rond en
    /// silence, et son porteur croirait qu'elle cherche.
    pub fn annoncer(
        annuaires: Vec<Annuaire>,
        identite: Identite,
        annonces: Vec<Vec<u8>>,
        cadence_plafond_s: u16,
    ) -> Result<Self, Error> {
        if annuaires.is_empty() {
            return Err(Error::AslSansAnnuaire);
        }
        let partage = Arc::new(Partage::default());
        let sienne = Arc::clone(&partage);
        let tache = tokio::spawn(async move {
            tenir_toujours(annuaires, identite, annonces, cadence_plafond_s, sienne).await;
        });
        Ok(Self {
            tache: Some(tache),
            partage,
        })
    }

    /// Ce que l'attache a fait jusqu'ici.
    #[must_use]
    pub fn etat(&self) -> Etat {
        Etat {
            attachee: self.partage.attachee.load(Ordering::Acquire),
            attaches: self.partage.attaches.load(Ordering::Relaxed),
            ruptures: self.partage.ruptures.load(Ordering::Relaxed),
            refus: self.partage.refus.load(Ordering::Relaxed),
            cadence_s: u16::try_from(self.partage.cadence.load(Ordering::Relaxed)).unwrap_or(0),
        }
    }

    /// Retire l'annonce, et laisse à la tâche le temps de le dire.
    ///
    /// **ON ATTEND, ET PAS LONGTEMPS.** Fermer proprement vaut une seconde ;
    /// attendre sans borne donnerait à un pair muet le pouvoir de retarder
    /// l'arrêt de ce serveur.
    pub async fn retirer(mut self) {
        self.partage.retrait.store(true, Ordering::Release);
        if let Some(tache) = self.tache.take() {
            let attente = Duration::from_millis(RETRAIT_MS);
            if tokio::time::timeout(attente, tache).await.is_err() {
                // Le `Drop` qui suit l'abandonne : la socket se ferme, et
                // l'annuaire l'apprendra à l'inactivité. Moins bien qu'une
                // extinction annoncée, mais borné.
            }
        }
    }
}

impl Drop for Attache {
    fn drop(&mut self) {
        if let Some(tache) = self.tache.take() {
            tache.abort();
        }
    }
}

/// La boucle qui n'abandonne jamais.
async fn tenir_toujours(
    annuaires: Vec<Annuaire>,
    identite: Identite,
    annonces: Vec<Vec<u8>>,
    cadence_plafond_s: u16,
    partage: Arc<Partage>,
) {
    // Le plafond du recul est la cadence de keepalive : il ne sert à rien de
    // réessayer plus lentement que le rythme auquel on aurait parlé.
    let plafond_ms = u64::from(cadence_plafond_s.max(1)).saturating_mul(1_000);
    let Ok(reprise) = Reprise::nouvelle(plafond_ms) else {
        // `max(1)` rend le plafond non nul : ce chemin ne s'emprunte pas. On
        // rend la main plutôt que de paniquer dans une tâche de fond.
        return;
    };
    let mut tournee = Tournee::nouvelle(reprise);
    let adresses: Vec<SocketAddr> = annuaires.iter().map(|un| un.adresse).collect();

    loop {
        if partage.retrait.load(Ordering::Acquire) {
            return;
        }
        let Some(etape) = tournee.prochaine(&adresses, alea16()) else {
            return;
        };
        if etape.attendre_ms > 0 {
            tokio::time::sleep(Duration::from_millis(etape.attendre_ms)).await;
            if partage.retrait.load(Ordering::Acquire) {
                return;
            }
        }
        let Some(annuaire) = annuaires.get(etape.place) else {
            return;
        };

        match tenir_une_fois(*annuaire, &identite, &annonces, &partage).await {
            // **LE RECUL NE REPART DE ZÉRO QU'APRÈS L'ANNONCE**, et jamais à
            // l'ouverture. Sans cela, une machine dont la clé a été révoquée
            // rouvrirait une connexion, se ferait refuser, et recommencerait
            // aussitôt — une boucle serrée contre l'annuaire, menée par le
            // daemon qui vient précisément d'être renvoyé.
            Verdict::Tenue => tournee.reussite(),
            Verdict::Refus => {
                partage.refus.fetch_add(1, Ordering::Relaxed);
            }
            Verdict::Injoignable => {}
        }
        partage.attachee.store(false, Ordering::Release);
    }
}

/// Ce qu'un passage auprès d'un annuaire a donné.
enum Verdict {
    /// L'annonce a abouti, et la connexion a été tenue jusqu'à sa rupture.
    Tenue,
    /// L'annuaire a répondu, et il a refusé.
    Refus,
    /// Il n'a pas répondu.
    Injoignable,
}

/// Ouvre, authentifie, annonce, et tient jusqu'à la rupture.
async fn tenir_une_fois(
    annuaire: Annuaire,
    identite: &Identite,
    annonces: &[Vec<u8>],
    partage: &Partage,
) -> Verdict {
    let Ok(confiance) = ams_tls::asl_config(&[annuaire.identite]) else {
        return Verdict::Refus;
    };
    let autorite = annuaire.identite.texte();
    let Ok(mut appel) = Appel::ouvrir(
        annuaire.adresse,
        ams_tls::nom_de_serveur(annuaire.adresse),
        autorite.as_str(),
        confiance,
        &alea16_octets,
    )
    .await
    else {
        return Verdict::Injoignable;
    };

    let Ok(liaison) = appel
        .exporter(asl_client::ETIQUETTE_LIAISON, None)
        .map(asl_cle::LiaisonDeCanal::depuis_octets)
    else {
        return Verdict::Refus;
    };

    if !authentifier(&mut appel, identite, &liaison).await {
        return Verdict::Refus;
    }

    // **TOUTES LES ANNONCES, OU AUCUNE.** Une annonce sur deux publierait la
    // moitié des services de cette machine, et rien ne dirait laquelle manque.
    let mut cadence = 0_u16;
    for annonce in annonces {
        match annoncer_une(&mut appel, annonce).await {
            Some(rendue) => cadence = cadence.max(rendue),
            None => return Verdict::Refus,
        }
    }

    // **LA CADENCE VIENT DE L'ANNUAIRE**, et elle se pose maintenant : avant
    // l'annonce, il n'y avait pas de bail à tenir.
    if cadence > 0 {
        appel.maintenir(cadence);
        partage.cadence.store(u64::from(cadence), Ordering::Relaxed);
    }
    partage.attaches.fetch_add(1, Ordering::Relaxed);
    partage.attachee.store(true, Ordering::Release);

    // ── TENIR ───────────────────────────────────────────────────────────────
    while appel.vivante() {
        if partage.retrait.load(Ordering::Acquire) {
            // L'extinction s'annonce : l'annuaire distingue un départ d'une
            // coupure, et rend « parti (volontaire) ».
            let _ = appel.fermer().await;
            return Verdict::Tenue;
        }
        if appel.entretenir(ENTRETIEN_MS).await.is_err() {
            break;
        }
    }
    partage.ruptures.fetch_add(1, Ordering::Relaxed);
    Verdict::Tenue
}

/// Prouve la clé de cette machine sur CETTE connexion.
///
/// L'authentification est portée par la connexion : la clé est prouvée une
/// fois, et toutes les requêtes en héritent. Il n'y a pas de jeton à joindre,
/// donc pas de jeton à faire fuir.
async fn authentifier(
    appel: &mut Appel,
    identite: &Identite,
    liaison: &asl_cle::LiaisonDeCanal,
) -> bool {
    let Ok(defi) = appel.requete("GET", "/v1/defi", &[], &[]).await else {
        return false;
    };
    if defi.statut.value() != 200 {
        return false;
    }
    let Ok(octets) = <[u8; asl_cle::DEFI_OCTETS]>::try_from(defi.corps) else {
        return false;
    };
    let Ok(signature) = identite.repondre(&asl_cle::Defi::depuis_octets(octets), liaison) else {
        return false;
    };

    let mut preuve = Vec::with_capacity(81);
    preuve.push(asl_id::Genre::Machine.prefixe());
    preuve.extend_from_slice(identite.machine().octets());
    preuve.extend_from_slice(signature.octets());

    appel
        .requete(
            "POST",
            "/v1/defi",
            &[(b"content-type", b"application/octet-stream")],
            &preuve,
        )
        .await
        .is_ok_and(|reponse| reponse.statut.value() == 204)
}

/// Pose une annonce, et rend la cadence que l'annuaire accorde.
async fn annoncer_une(appel: &mut Appel, annonce: &[u8]) -> Option<u16> {
    let reponse = appel
        .requete(
            "POST",
            "/v1/annonce",
            &[(b"content-type", b"application/json")],
            annonce,
        )
        .await
        .ok()?;
    // **UN `421` N'EST PAS UN REFUS ORDINAIRE** : la machine s'annonce
    // ailleurs, et le corps dit où. Nous ne le suivons pas encore — voir
    // l'en-tête de ce module —, et il compte donc comme un refus.
    if reponse.statut.value() != 200 {
        return None;
    }
    ams_asl::lire_la_reponse(&reponse.corps)
        .ok()
        .map(|cadence| cadence.keepalive_secondes)
}

/// Seize octets du noyau, pour les identifiants de connexion QUIC.
///
/// §5.2 de RFC 9001 dérive les clés `Initial` de l'identifiant de destination :
/// un identifiant devinable les rendrait devinables. **Un échec de lecture rend
/// des zéros plutôt que de paniquer dans une tâche de fond** — la connexion
/// serait alors prévisible, ce qui est mauvais mais borné à son `Initial`, là
/// où une panique emporterait l'annonce entière et ne dirait rien.
fn alea16_octets() -> [u8; 16] {
    use std::io::Read as _;
    let mut octets = [0_u8; 16];
    let _ =
        std::fs::File::open("/dev/urandom").and_then(|mut source| source.read_exact(&mut octets));
    octets
}

/// Le bruit du recul, sur deux octets.
fn alea16() -> u16 {
    let octets = alea16_octets();
    u16::from_be_bytes([octets[0], octets[1]])
}
