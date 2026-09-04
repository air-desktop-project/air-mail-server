//! Ce qui rate à la remise : compté, et dit.
//!
//! # POURQUOI CE MODULE EXISTE
//!
//! Une remise qui échoue rendait un `451` au pair et n'écrivait RIEN. Un disque
//! plein, des droits changés sur le maildir, une boîte qui manque : le serveur
//! refusait tout le courrier, indéfiniment, avec un journal vide. L'exploitant
//! voyait un service en parfaite santé.
//!
//! Ce n'est pas une leçon neuve dans ce dépôt. La file de réémission la porte
//! déjà, dans la documentation de son compteur de rapports perdus :
//!
//! > un serveur en parfaite santé pendant qu'il perdait du courrier en silence,
//! > et la seule trace était une ligne sur la sortie d'erreur qu'il fallait lire
//! > au bon moment.
//!
//! Elle y avait été apprise, et appliquée là seulement. Le chemin ENTRANT n'en a
//! hérité ni la ligne, ni le compteur.
//!
//! # CE MODULE NE FAIT PAS D'ENTRÉE-SORTIE
//!
//! [`Incidents::survenu`] compte et rend la phrase à dire, ou `None` s'il est
//! trop tôt. C'est l'appelant qui écrit. Ce n'est pas une coquetterie : c'est ce
//! qui rend la règle du silence — quand redire, et ce qu'on dit alors —
//! vérifiable par un test plutôt que par la lecture d'un journal.

/// Ce qui a raté, et que l'exploitant ne pouvait pas apprendre autrement.
///
/// # CE QUI N'EST PAS ICI, ET POURQUOI
///
/// Les échecs que le PAIR provoque — un message au-delà de la borne, un message
/// illisible — n'y sont pas : ils ne disent rien de l'état du serveur, et un
/// attaquant les déclenche à volonté. Les compter reviendrait à lui donner la
/// plume du journal.
///
/// [`Cause::Usurpation`] fait exception, et à dessein : elle vient d'un compte
/// AUTHENTIFIÉ, donc d'une identité que l'exploitant connaît et peut suspendre.
/// Un hameçonnage interne refusé est exactement ce qu'il veut voir.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    /// Le magasin connaît ce compte, et sa boîte ne s'ouvre pas.
    BoiteIntrouvable,
    /// Le message ne s'écrit pas sur le disque.
    Ecriture,
    /// Le message était reçu EN ENTIER, et n'a pas pu être validé.
    Validation,
    /// Un destinataire d'ailleurs a été accepté, et rien ne peut le retenir.
    SansFile,
    /// Un compte authentifié a voulu écrire au nom d'un autre.
    Usurpation,
}

/// Toutes les causes, dans l'ordre où le bilan les dit.
pub const TOUTES: [Cause; 5] = [
    Cause::BoiteIntrouvable,
    Cause::Ecriture,
    Cause::Validation,
    Cause::SansFile,
    Cause::Usurpation,
];

impl Cause {
    /// Sa place dans le tableau des états.
    const fn rang(self) -> usize {
        match self {
            Self::BoiteIntrouvable => 0,
            Self::Ecriture => 1,
            Self::Validation => 2,
            Self::SansFile => 3,
            Self::Usurpation => 4,
        }
    }

    /// Ce qu'on dit quand elle survient, et ce qu'elle coûte à qui écrivait.
    #[must_use]
    pub const fn dit(self) -> &'static str {
        match self {
            Self::BoiteIntrouvable => {
                "REMISE IMPOSSIBLE — la boîte d'un compte connu ne s'ouvre pas. Ce compte \
                 accepte le courrier et ne peut pas le recevoir : ses correspondants \
                 réessaieront des jours durant, puis renonceront"
            }
            Self::Ecriture => {
                "REMISE IMPOSSIBLE — le message ne s'écrit pas sous le maildir. Un disque \
                 plein ou des droits changés font ce refus, et il vaut pour TOUT le courrier \
                 entrant tant qu'il dure"
            }
            Self::Validation => {
                "MESSAGE PERDU APRÈS RÉCEPTION COMPLÈTE — il était entièrement reçu, et n'a \
                 pas pu être validé sur le disque. Son expéditeur l'a transmis en entier pour \
                 s'entendre refuser"
            }
            Self::SansFile => {
                "DESTINATAIRE ACCEPTÉ PUIS REFUSÉ — la politique l'a admis, et aucune file ne \
                 peut le retenir. Le magasin de comptes a changé sous les pieds de la \
                 transaction"
            }
            Self::Usurpation => {
                "USURPATION REFUSÉE — un compte AUTHENTIFIÉ a voulu écrire au nom d'un autre \
                 (RFC 6409 §6.1). Le message n'est pas parti, et n'a pas été signé"
            }
        }
    }

    /// Ce qu'on en dit à l'arrêt, après le nombre.
    #[must_use]
    pub const fn bilan(self) -> &'static str {
        match self {
            Self::BoiteIntrouvable => "remise(s) refusée(s) faute d'ouvrir une boîte",
            Self::Ecriture => "message(s) qui n'ont pas pu être écrits sous le maildir",
            Self::Validation => "message(s) reçus EN ENTIER puis perdus à la validation",
            Self::SansFile => "destinataire(s) acceptés par la politique puis refusés",
            Self::Usurpation => "tentative(s) d'écrire au nom d'un autre, refusées",
        }
    }
}

/// Au bout de combien de temps une cause qui dure se redit.
///
/// # POURQUOI UNE REDITE, ET POURQUOI ELLE EST BORNÉE
///
/// Dire chaque échec ferait, sur un disque plein, une ligne par message : c'est
/// le journal qu'on cesse de lire, que ce registre reproche ailleurs. Ne le dire
/// qu'une fois ferait pire — une panne qui dure trois jours n'aurait qu'une ligne,
/// au tout début, et l'exploitant qui regarde aujourd'hui ne verrait rien.
///
/// **LA PREMIÈRE OCCURRENCE SE DIT TOUJOURS**, sans attendre : c'est elle qui
/// avertit. La redite ne sert qu'à montrer que cela DURE, et à donner le nombre
/// de ceux qu'on a taus entre-temps.
///
/// # CE N'EST PAS UN RÉGLAGE, ET C'EST DIT PLUTÔT QUE TU
///
/// [C8] fait des seuils du garde des paramètres de configuration, parce qu'ils
/// dépendent du trafic. Celui-ci en dépend beaucoup moins : ce qui avertit est la
/// PREMIÈRE ligne, qui part toujours, et cet intervalle ne gouverne que la
/// répétition. Le rendre réglable ajouterait un champ au format binaire pour un
/// gain qu'on peine à nommer.
///
/// [C8]: ../../docs/contraintes.md
const REDIRE: u64 = 300;

/// L'état d'une cause : combien de fois, et quand on l'a dite.
#[derive(Debug, Clone, Copy, Default)]
struct Etat {
    /// Combien de fois elle est survenue depuis le démarrage.
    vus: u64,
    /// Combien de fois elle est survenue depuis qu'on l'a dite.
    tus: u64,
    /// Quand on l'a dite pour la dernière fois, en secondes depuis l'époque.
    dernier_dit: Option<u64>,
}

/// Ce qui a raté à la remise, depuis le démarrage.
///
/// # ELLE EST PARTAGÉE, PARCE QUE LA REMISE NE L'EST PAS
///
/// `MaildirDelivery` naît **par connexion** : un compteur qui vivrait dedans
/// dirait la première ligne à chaque connexion, et ne compterait jamais rien.
/// Celle-ci se partage par `Arc`, comme la carte des boîtes.
#[derive(Debug, Default)]
pub struct Incidents {
    /// Un état par cause, rangé par [`Cause::rang`].
    ///
    /// **UN SEUL VERROU POUR LES CINQ** : ils ne se prennent qu'au moment d'un
    /// échec, c'est-à-dire jamais quand tout va bien, et cinq verrous
    /// n'achèteraient de la concurrence que sur un serveur déjà en panne.
    etats: std::sync::Mutex<[Etat; TOUTES.len()]>,
}

impl Incidents {
    /// Rien n'a encore raté.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Retient cet échec, et rend ce qu'il faut dire — ou `None` s'il est trop tôt.
    ///
    /// `maintenant` est en secondes depuis l'époque.
    ///
    /// **`#[must_use]` N'EST PAS DÉCORATIF** : jeter ce que rend cette méthode,
    /// c'est compter l'échec et le taire — précisément le défaut qu'elle existe
    /// pour corriger. Le compilateur le refuse donc.
    #[must_use]
    pub fn survenu(&self, cause: Cause, maintenant: u64) -> Option<String> {
        let mut etats = self.etats();
        // L'indice vient de `Cause::rang`, et le tableau a une case par cause :
        // `get_mut` ne peut pas rendre `None`, et le dire par un `?` vaudrait
        // mieux que de paniquer si jamais les deux cessaient de s'accorder.
        let etat = etats.get_mut(cause.rang())?;
        etat.vus = etat.vus.saturating_add(1);
        etat.tus = etat.tus.saturating_add(1);
        // **L'HORLOGE PEUT RECULER** — un `settimeofday`, un serveur de temps qui
        // corrige. `checked_sub` rend alors `None`, qu'on lit comme « pas encore
        // l'heure » : reculer le temps fait taire, jamais bavarder.
        let assez_attendu = etat
            .dernier_dit
            .is_none_or(|alors| maintenant.checked_sub(alors).is_some_and(|ecart| ecart >= REDIRE));
        if !assez_attendu {
            return None;
        }
        let tus = core::mem::replace(&mut etat.tus, 0);
        let premiere = etat.dernier_dit.is_none();
        etat.dernier_dit = Some(maintenant);
        Some(if premiere {
            cause.dit().to_string()
        } else {
            // `tus` compte celui-ci compris : on nomme donc ce qui a été TU, et
            // non ce qui est survenu, sans quoi le compte serait plus grand d'un
            // que ce que l'exploitant peut vérifier.
            format!(
                "{} — et cela DURE : {} depuis la dernière fois qu'on l'a dit",
                cause.dit(),
                fois(tus.saturating_sub(1))
            )
        })
    }

    /// Ce qu'on a compté, cause par cause, pour le dire à l'arrêt.
    ///
    /// **ZÉRO N'EN EST PAS** : un journal qui répète « rien n'a raté » est un
    /// journal qu'on cesse de lire, et c'est la règle que suivent déjà les autres
    /// compteurs de ce serveur.
    #[must_use]
    pub fn bilan(&self) -> Vec<(Cause, u64)> {
        let etats = self.etats();
        TOUTES
            .iter()
            .filter_map(|cause| {
                let vus = etats.get(cause.rang())?.vus;
                (vus > 0).then_some((*cause, vus))
            })
            .collect()
    }

    /// Les états, empoisonnement compris — même raison que pour les autres.
    fn etats(&self) -> std::sync::MutexGuard<'_, [Etat; TOUTES.len()]> {
        self.etats
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// « une fois », « 3 fois » — parce que « 1 fois » se lit mal.
fn fois(combien: u64) -> String {
    if combien == 1 {
        String::from("une fois")
    } else {
        format!("{combien} fois")
    }
}

#[cfg(test)]
mod tests {
    use super::{Cause, Incidents, REDIRE};

    #[test]
    fn la_premiere_occurrence_se_dit_toujours() {
        let incidents = Incidents::new();

        let dit = incidents
            .survenu(Cause::Ecriture, 1_000)
            .expect("la première avertit");

        assert!(dit.contains("ne s'écrit pas"), "elle dit quoi : {dit}");
        assert!(
            !dit.contains("DURE"),
            "et ne parle pas encore de durée : {dit}"
        );
    }

    #[test]
    fn les_suivantes_se_taisent_jusqu_a_la_redite() {
        let incidents = Incidents::new();
        incidents.survenu(Cause::Ecriture, 1_000).expect("la première");

        for seconde in 1..REDIRE {
            assert!(
                incidents.survenu(Cause::Ecriture, 1_000 + seconde).is_none(),
                "à +{seconde} s, on se tait encore"
            );
        }

        let dit = incidents
            .survenu(Cause::Ecriture, 1_000 + REDIRE)
            .expect("il est temps de redire");
        assert!(dit.contains("DURE"), "la redite dit que cela dure : {dit}");
    }

    #[test]
    fn la_redite_nomme_ce_qui_a_ete_tu() {
        let incidents = Incidents::new();
        incidents.survenu(Cause::Ecriture, 0).expect("la première");
        // Trois de plus, tues.
        for seconde in 1..=3 {
            assert!(incidents.survenu(Cause::Ecriture, seconde).is_none());
        }

        let dit = incidents
            .survenu(Cause::Ecriture, REDIRE)
            .expect("il est temps");

        assert!(
            dit.contains("3 fois depuis"),
            "les trois tues sont nommés, et non les quatre survenus : {dit}"
        );
    }

    #[test]
    fn une_seule_fois_tue_se_dit_en_toutes_lettres() {
        let incidents = Incidents::new();
        incidents.survenu(Cause::Validation, 0).expect("la première");
        assert!(incidents.survenu(Cause::Validation, 1).is_none());

        let dit = incidents
            .survenu(Cause::Validation, REDIRE)
            .expect("il est temps");

        assert!(dit.contains("une fois depuis"), "« 1 fois » se lit mal : {dit}");
    }

    #[test]
    fn les_causes_se_comptent_separement() {
        let incidents = Incidents::new();

        assert!(incidents.survenu(Cause::Ecriture, 0).is_some());
        assert!(
            incidents.survenu(Cause::Validation, 0).is_some(),
            "une autre cause avertit pour son propre compte"
        );
        assert!(
            incidents.survenu(Cause::Ecriture, 1).is_none(),
            "et n'a pas rouvert la bouche de la première"
        );
    }

    #[test]
    fn une_horloge_qui_recule_fait_taire_et_non_bavarder() {
        let incidents = Incidents::new();
        incidents.survenu(Cause::SansFile, 10_000).expect("la première");

        assert!(
            incidents.survenu(Cause::SansFile, 1).is_none(),
            "le temps a reculé : on se tait, on ne redit pas"
        );
    }

    #[test]
    fn le_bilan_ne_dit_pas_zero() {
        let incidents = Incidents::new();
        assert!(incidents.bilan().is_empty(), "rien n'a raté, rien ne se dit");

        assert!(
            incidents.survenu(Cause::Usurpation, 0).is_some(),
            "la première avertit"
        );
        assert!(
            incidents.survenu(Cause::Usurpation, 1).is_none(),
            "la seconde se tait"
        );

        assert_eq!(
            incidents.bilan(),
            vec![(Cause::Usurpation, 2)],
            "le bilan compte TOUT, y compris ce qu'on a tu"
        );
    }

    #[test]
    fn chaque_cause_dit_quelque_chose_de_distinct() {
        let mut vus: Vec<&str> = super::TOUTES.iter().map(|cause| cause.dit()).collect();
        let combien = vus.len();
        vus.sort_unstable();
        vus.dedup();
        assert_eq!(vus.len(), combien, "deux causes qui disent la même chose");

        let mut bilans: Vec<&str> = super::TOUTES.iter().map(|cause| cause.bilan()).collect();
        bilans.sort_unstable();
        bilans.dedup();
        assert_eq!(bilans.len(), combien, "deux bilans identiques");
    }
}
