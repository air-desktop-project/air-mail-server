// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::{Bucket, Rate};
use crate::Instant;

const fn a(millis: u64) -> Instant {
    Instant::from_millis(millis)
}

const PETIT: Rate = Rate {
    burst: 3,
    per_second: 2,
};

#[test]
fn un_seau_plein_laisse_passer_sa_rafale_puis_refuse() {
    let mut seau = Bucket::full(PETIT, a(1000));
    assert!(seau.take(PETIT, a(1000)));
    assert!(seau.take(PETIT, a(1000)));
    assert!(seau.take(PETIT, a(1000)));
    assert!(!seau.take(PETIT, a(1000)));
    assert!(!seau.take(PETIT, a(1000)));
}

#[test]
fn le_debit_soutenu_revient_avec_le_temps() {
    let mut seau = Bucket::full(PETIT, a(0));
    for _ in 0..3 {
        assert!(seau.take(PETIT, a(0)));
    }
    // Deux par seconde : un jeton toutes les cinq cents millisecondes.
    assert!(!seau.take(PETIT, a(499)));
    assert!(seau.take(PETIT, a(500)));
    assert!(!seau.take(PETIT, a(500)));
    // Une seconde rend toujours au moins un jeton : c'est ce que dit le refus.
    assert!(seau.take(PETIT, a(1500)));
}

#[test]
fn les_millièmes_ne_se_perdent_pas_entre_deux_requetes_rapprochees() {
    let mut seau = Bucket::full(PETIT, a(0));
    for _ in 0..3 {
        assert!(seau.take(PETIT, a(0)));
    }
    // Cinq cents fois une milliseconde valent une demi-seconde.
    let mut rendus = 0_u32;
    for instant in 1..=500 {
        if seau.take(PETIT, a(instant)) {
            rendus = rendus.saturating_add(1);
        }
    }
    assert_eq!(rendus, 1);
}

#[test]
fn le_seau_ne_deborde_pas_de_sa_contenance() {
    let mut seau = Bucket::full(PETIT, a(0));
    assert!(seau.take(PETIT, a(0)));
    // Une heure d'absence ne rend que la rafale, pas trois mille jetons.
    for _ in 0..3 {
        assert!(seau.take(PETIT, a(3_600_000)));
    }
    assert!(!seau.take(PETIT, a(3_600_000)));
}

#[test]
fn une_horloge_qui_recule_ne_remplit_rien_et_ne_compte_pas_deux_fois() {
    let mut seau = Bucket::full(PETIT, a(10_000));
    for _ in 0..3 {
        assert!(seau.take(PETIT, a(10_000)));
    }
    assert!(!seau.take(PETIT, a(5_000)));
    // Revenir à l'instant retenu ne rend rien : ce temps a déjà été compté.
    assert!(!seau.take(PETIT, a(10_000)));
    assert!(seau.take(PETIT, a(10_500)));
}

#[test]
fn un_seau_plein_se_reconnait_et_un_seau_entame_aussi() {
    let mut seau = Bucket::full(PETIT, a(0));
    assert!(seau.is_full(PETIT, a(0)));
    assert!(seau.take(PETIT, a(0)));
    assert!(!seau.is_full(PETIT, a(0)));
    assert!(!seau.is_full(PETIT, a(499)));
    assert!(seau.is_full(PETIT, a(500)));
    // Regarder ne remplit pas : le seau reste entamé à l'instant d'avant.
    assert!(!seau.is_full(PETIT, a(0)));
}

#[test]
fn des_valeurs_extremes_saturent_au_lieu_de_deborder() {
    let enorme = Rate {
        burst: u32::MAX,
        per_second: u32::MAX,
    };
    let mut seau = Bucket::full(enorme, a(0));
    assert!(seau.take(enorme, a(u64::MAX)));
    assert!(seau.take(enorme, a(u64::MAX)));
    assert!(!seau.is_full(enorme, a(u64::MAX)));
}

#[test]
fn zero_prend_le_defaut_champ_par_champ() {
    let lu = Rate {
        burst: 0,
        per_second: 0,
    };
    assert_eq!(lu.or_default(), Rate::DEFAULT);
    let rafale = Rate {
        burst: 7,
        per_second: 0,
    };
    assert_eq!(
        rafale.or_default(),
        Rate {
            burst: 7,
            per_second: Rate::DEFAULT.per_second
        }
    );
    let debit = Rate {
        burst: 0,
        per_second: 9,
    };
    assert_eq!(
        debit.or_default(),
        Rate {
            burst: Rate::DEFAULT.burst,
            per_second: 9
        }
    );
    assert_eq!(PETIT.or_default(), PETIT);
    assert_eq!(Rate::default(), Rate::DEFAULT);
}

#[test]
fn le_seau_et_le_debit_se_copient_et_se_deboguent() {
    let seau = Bucket::full(PETIT, a(0));
    let copie = seau;
    assert_eq!(copie, seau);
    assert!(!std::format!("{seau:?}{PETIT:?}").is_empty());
}
