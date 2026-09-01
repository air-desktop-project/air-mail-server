//! Le garde, partagé entre toutes les connexions.

use std::sync::{Mutex, PoisonError};
use std::time::Instant as SystemInstant;

use ams_guard::{Event, Guard, Instant, Key, Slot, Source, Thresholds, Verdict};

/// L'état que les connexions se partagent.
struct Etat {
    slots: Vec<Slot>,
    thresholds: Thresholds,
}

/// Un [`Guard`] utilisable depuis plusieurs connexions.
///
/// # Un verrou de la bibliothèque standard, et pas celui de tokio
///
/// La section critique est un parcours de table borné, **sans aucun `await`** :
/// un verrou asynchrone n'y apporterait qu'une file d'attente de tâches et un
/// point de suspension de plus. Le verrou standard, lui, ne peut pas être tenu à
/// travers un `await` — le compilateur l'interdit — ce qui est exactement la
/// garantie qu'on veut ici.
///
/// # C'est lui qui lit l'heure
///
/// Le garde ne consulte jamais d'horloge (C1) : on la lui donne. Elle est donc
/// lue ici, à l'étage 3, et elle est **monotone** — `std::time::Instant` ne
/// recule pas, là où une horloge murale le peut. Un pair qui contrôlerait un
/// recul y verrait un moyen de ne jamais franchir un seuil.
pub struct SharedGuard {
    origine: SystemInstant,
    etat: Mutex<Etat>,
}

impl SharedGuard {
    /// Ouvre un garde d'au plus `capacity` sources suivies.
    ///
    /// La capacité borne la mémoire du garde ; au-delà, il cesse d'apprendre
    /// plutôt que d'oublier une peine en cours.
    #[must_use]
    pub fn new(capacity: usize, thresholds: Thresholds) -> Self {
        Self {
            origine: SystemInstant::now(),
            etat: Mutex::new(Etat {
                slots: vec![Slot::EMPTY; capacity],
                thresholds,
            }),
        }
    }

    /// Le verdict pour une source, **sans rien compter**.
    #[must_use]
    pub fn verdict(&self, source: Source) -> Verdict {
        let maintenant = self.maintenant();
        let mut etat = self.verrou();
        let thresholds = etat.thresholds;
        // `Guard::new` N'EFFACE PAS la table : c'est ce qui permet de le rouvrir
        // à chaque appel sur un état qui doit survivre aux connexions.
        Guard::new(&mut etat.slots, thresholds).verdict(source, maintenant)
    }

    /// Enregistre un événement et rend le verdict.
    pub fn observe(&self, source: Source, event: Event) -> Verdict {
        let maintenant = self.maintenant();
        let mut etat = self.verrou();
        let thresholds = etat.thresholds;
        Guard::new(&mut etat.slots, thresholds).observe(source, event, maintenant)
    }

    /// Les sources bannies en ce moment, et pour combien de temps encore.
    ///
    /// **RENDU EN SECONDES RESTANTES, ET NON EN DATE** : l'instant du garde compte
    /// depuis l'ouverture du serveur, et n'a de sens que pour lui. Un exploitant,
    /// lui, veut savoir combien de temps il reste.
    #[must_use]
    pub fn banned(&self) -> Vec<(Key, u64)> {
        let maintenant = self.maintenant();
        let mut etat = self.verrou();
        let thresholds = etat.thresholds;
        Guard::new(&mut etat.slots, thresholds)
            .banned(maintenant)
            .map(|(cle, jusqu_a)| {
                let reste = jusqu_a.as_millis().saturating_sub(maintenant.as_millis());
                (cle, reste.saturating_div(1_000))
            })
            .collect()
    }

    /// Lève le bannissement d'une source, et oublie ce qu'elle a fait.
    ///
    /// Rend `true` s'il y avait quelque chose à lever.
    pub fn lift(&self, source: Source) -> bool {
        let mut etat = self.verrou();
        let thresholds = etat.thresholds;
        Guard::new(&mut etat.slots, thresholds).lift(source)
    }

    /// Le nombre de sources suivies.
    #[must_use]
    pub fn tracked(&self) -> usize {
        let mut etat = self.verrou();
        let thresholds = etat.thresholds;
        Guard::new(&mut etat.slots, thresholds).tracked()
    }

    /// L'instant courant, en millisecondes depuis l'ouverture du garde.
    fn maintenant(&self) -> Instant {
        let ecoule = self.origine.elapsed().as_millis();
        Instant::from_millis(u64::try_from(ecoule).unwrap_or(u64::MAX))
    }

    /// Le verrou, en récupérant d'un empoisonnement.
    ///
    /// Une tâche qui panique en tenant le verrou laisse une table dont les cases
    /// sont, au pire, à demi mises à jour — jamais invalides, puisque ce sont des
    /// entiers et des booléens. Refuser de servir tout le monde parce qu'une
    /// connexion a paniqué serait une panne bien plus grave que la table qu'on
    /// récupère.
    fn verrou(&self) -> std::sync::MutexGuard<'_, Etat> {
        self.etat.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
