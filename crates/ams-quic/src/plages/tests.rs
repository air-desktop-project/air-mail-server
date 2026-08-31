// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un ensemble d'intervalles a le droit de faire.

use super::{Debordement, HOLES_MAX, Plage, Plages};

/// Un ensemble neuf est vide.
#[test]
fn un_ensemble_neuf_est_vide() {
    let plages = Plages::new();
    assert_eq!(plages.count(), 0);
    assert_eq!(plages.first(), None);
    assert_eq!(plages.contiguous_from(0), 0);
    assert_eq!(Plages::default(), plages);
}

/// **UN INTERVALLE VIDE NE CHANGE RIEN** : une trame `STREAM` sans octet est
/// licite, et n'a rien à ranger.
#[test]
fn un_intervalle_vide_ne_change_rien() {
    let mut plages = Plages::new();
    assert!(plages.insert(5, 5).is_ok());
    assert!(plages.insert(9, 3).is_ok());
    assert_eq!(plages.count(), 0);
}

/// Ce qui se touche ne fait qu'un, quel que soit l'ordre d'arrivée.
#[test]
fn ce_qui_se_touche_ne_fait_qu_un() {
    for ordre in [[(0_u64, 5_u64), (5, 10)], [(5, 10), (0, 5)]] {
        let mut plages = Plages::new();
        for (debut, fin) in ordre {
            plages.insert(debut, fin).expect("de la place");
        }
        assert_eq!(plages.count(), 1, "{ordre:?}");
        assert_eq!(plages.first(), Some(Plage { debut: 0, fin: 10 }));
        assert_eq!(plages.contiguous_from(0), 10);
        assert_eq!(plages.contiguous_from(4), 6);
    }
}

/// Ce qui se recouvre ne fait qu'un, même en avalant plusieurs intervalles.
#[test]
fn ce_qui_se_recouvre_ne_fait_qu_un() {
    let mut plages = Plages::new();
    for (debut, fin) in [(0_u64, 2_u64), (4, 6), (8, 10), (12, 14)] {
        plages.insert(debut, fin).expect("de la place");
    }
    assert_eq!(plages.count(), 4);
    // Un intervalle qui traverse les trois premiers les fond en un seul.
    plages.insert(1, 9).expect("de la place");
    assert_eq!(plages.count(), 2);
    assert_eq!(plages.first(), Some(Plage { debut: 0, fin: 10 }));
    // Et un intervalle entièrement contenu ne change rien.
    plages.insert(3, 4).expect("de la place");
    assert_eq!(plages.count(), 2);
    assert_eq!(plages.first(), Some(Plage { debut: 0, fin: 10 }));
}

/// Un trou laisse deux intervalles, et le combler n'en laisse qu'un.
#[test]
fn combler_un_trou_reunit() {
    let mut plages = Plages::new();
    plages.insert(0, 5).expect("de la place");
    plages.insert(10, 15).expect("de la place");
    assert_eq!(plages.count(), 2);
    assert_eq!(plages.contiguous_from(0), 5, "il manque le milieu");
    assert_eq!(plages.contiguous_from(5), 0, "rien ne couvre cinq");
    plages.insert(5, 10).expect("de la place");
    assert_eq!(plages.count(), 1);
    assert_eq!(plages.contiguous_from(0), 15);
}

/// **LA BORNE EST UN REFUS, ET NON UN OUBLI.**
#[test]
fn la_place_qui_manque_se_dit() {
    let mut plages = Plages::new();
    for rang in 0..HOLES_MAX {
        let debut = u64::try_from(rang).expect("court").saturating_mul(2);
        assert_eq!(
            plages.insert(debut, debut.saturating_add(1)),
            Ok(()),
            "intervalle {rang}"
        );
    }
    assert_eq!(plages.count(), HOLES_MAX);
    let trop = u64::try_from(HOLES_MAX).expect("court").saturating_mul(2);
    assert_eq!(
        plages.insert(trop, trop.saturating_add(1)),
        Err(Debordement)
    );
    // **ET LE REFUS NE DÉTRUIT RIEN** : ce qui était là est toujours là.
    assert_eq!(plages.count(), HOLES_MAX);
    assert_eq!(plages.first(), Some(Plage { debut: 0, fin: 1 }));

    // **COMBLER, EN REVANCHE, PASSE TOUJOURS** : le désordre diminue, et refuser
    // fermerait un flux honnête au moment où il se range.
    plages.insert(1, 2).expect("combler passe");
    assert_eq!(plages.count(), HOLES_MAX - 1);
}

/// Ce qui est sous le seuil s'en va, et ce qui est à cheval se raccourcit.
#[test]
fn le_seuil_rogne_ce_qui_est_dessous() {
    let mut plages = Plages::new();
    plages.insert(0, 5).expect("de la place");
    plages.insert(10, 20).expect("de la place");
    plages.trim_below(12);
    assert_eq!(plages.count(), 1);
    assert_eq!(plages.first(), Some(Plage { debut: 12, fin: 20 }));
    // Un seuil au-delà de tout vide l'ensemble.
    plages.trim_below(20);
    assert_eq!(plages.count(), 0);
    // Et un seuil sous tout ne change rien.
    plages.insert(3, 4).expect("de la place");
    plages.trim_below(0);
    assert_eq!(plages.first(), Some(Plage { debut: 3, fin: 4 }));
}
