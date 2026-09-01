//! Ce que la reprise décide, et ce qu'elle refuse de décider.

use super::{Backoff, Decision};
use core::time::Duration;

/// Une reprise dont les nombres sont ronds, pour que les essais se lisent.
const REPRISE: Backoff = Backoff {
    first: Duration::from_secs(100),
    ceiling: Duration::from_secs(1_000),
    expiry: Duration::from_secs(100_000),
};

#[test]
fn l_attente_double_a_chaque_echec() {
    assert_eq!(REPRISE.delay(1), Duration::from_secs(100));
    assert_eq!(REPRISE.delay(2), Duration::from_secs(200));
    assert_eq!(REPRISE.delay(3), Duration::from_secs(400));
    assert_eq!(REPRISE.delay(4), Duration::from_secs(800));
}

#[test]
fn le_plafond_arrete_le_doublement() {
    // Le cinquième doublement passerait à 1600 ; le plafond est à 1000.
    assert_eq!(REPRISE.delay(5), Duration::from_secs(1_000));
    assert_eq!(REPRISE.delay(50), Duration::from_secs(1_000));
    // ET POUR UN NOMBRE D'ESSAIS ABSURDE AUSSI. Le décalage est borné à 31 bits
    // et le produit sature : une file qu'on aurait laissée tourner ne déborde
    // pas, elle plafonne.
    assert_eq!(REPRISE.delay(u32::MAX), Duration::from_secs(1_000));
}

#[test]
fn zero_essai_rend_la_premiere_attente() {
    // Personne ne peut le demander — c'est APRÈS un échec qu'on consulte — mais
    // une fonction totale vaut mieux qu'une panique pour un cas que rien
    // n'atteint.
    assert_eq!(REPRISE.delay(0), REPRISE.delay(1));
}

#[test]
fn une_attente_absurde_sature_au_lieu_de_deborder() {
    // Une configuration qui demanderait des siècles ne déborde pas : elle
    // plafonne, et le plafond est lui-même la valeur rendue.
    let absurde = Backoff {
        first: Duration::from_secs(u64::MAX),
        ceiling: Duration::from_secs(u64::MAX),
        expiry: Duration::from_secs(u64::MAX),
    };
    assert_eq!(absurde.delay(31), Duration::from_secs(u64::MAX));
    assert_eq!(absurde.deadline(10), u64::MAX);
}

#[test]
fn un_echec_repousse_l_essai_suivant() {
    let depot = 1_000_u64;
    assert_eq!(
        REPRISE.after_failure(depot, 1, depot),
        Decision::Retry { at: depot + 100 }
    );
    assert_eq!(
        REPRISE.after_failure(depot, 3, depot + 700),
        Decision::Retry { at: depot + 1_100 }
    );
}

#[test]
fn le_dernier_essai_tombe_sur_la_peremption_pas_avant() {
    // **C'EST LA DÉCISION QUI TIENT LES CINQ JOURS ANNONCÉS.** Renoncer dès que
    // l'attente dépasserait l'échéance raccourcirait le délai en silence, et le
    // pair qui se relève dans la dernière heure n'aurait rien reçu.
    let depot = 0_u64;
    let echeance = REPRISE.deadline(depot);
    assert_eq!(echeance, 100_000);
    // À trois cents secondes de l'échéance, l'attente pleine serait de mille.
    let issue = REPRISE.after_failure(depot, 9, echeance - 300);
    assert_eq!(issue, Decision::Retry { at: echeance });
}

#[test]
fn la_peremption_se_juge_apres_l_essai() {
    let depot = 0_u64;
    let echeance = REPRISE.deadline(depot);
    // Une seconde avant l'échéance, il reste un essai.
    assert_eq!(
        REPRISE.after_failure(depot, 40, echeance - 1),
        Decision::Retry { at: echeance }
    );
    // À l'échéance exacte, c'est fini.
    assert_eq!(REPRISE.after_failure(depot, 40, echeance), Decision::GiveUp);
    // ET APRÈS UNE PANNE DU SERVEUR AUSSI : le message a dormi une semaine, il
    // a eu son dernier essai, celui-ci a échoué, on renonce. Aucune règle ne
    // l'a écarté avant d'avoir essayé.
    assert_eq!(
        REPRISE.after_failure(depot, 1, echeance + 7 * 86_400),
        Decision::GiveUp
    );
}

#[test]
fn le_defaut_tient_cinq_jours() {
    // §4.5.4.1 de RFC 5321 : au moins quatre à cinq jours.
    assert_eq!(Backoff::DEFAULT.expiry, Duration::from_secs(5 * 86_400));
    assert_eq!(Backoff::DEFAULT.first, Duration::from_secs(900));
    assert_eq!(Backoff::DEFAULT.ceiling, Duration::from_secs(21_600));
    assert_eq!(Backoff::default(), Backoff::DEFAULT);
}

#[test]
fn la_reprise_se_copie_et_se_debogue() {
    let copie = REPRISE;
    assert_eq!(copie, REPRISE);
    assert_ne!(copie, Backoff::DEFAULT);
    assert!(!std::format!("{REPRISE:?}").is_empty());
    assert!(!std::format!("{:?}", Decision::GiveUp).is_empty());
    assert_ne!(Decision::GiveUp, Decision::Retry { at: 0 });
    let jumelle = Decision::Retry { at: 7 };
    assert_eq!(jumelle, Decision::Retry { at: 7 });
}
