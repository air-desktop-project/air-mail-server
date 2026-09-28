// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::Debits;
use ams_guard::Rate;

/// Une seconde, en microsecondes.
const SECONDE: u64 = 1_000_000;

fn petits() -> Debits {
    Debits::new(Rate {
        burst: 2,
        per_second: 1,
    })
}

#[test]
fn chaque_appareil_a_son_seau() {
    let debits = petits();
    assert!(debits.prendre("alice", Some("tel"), 0));
    assert!(debits.prendre("alice", Some("tel"), 0));
    assert!(!debits.prendre("alice", Some("tel"), 0));
    // **UN AUTRE APPAREIL DU MÊME COMPTE N'EST PAS PUNI** : c'est tout l'objet.
    assert!(debits.prendre("alice", Some("tablette"), 0));
    // Ni le même appareil d'un autre compte.
    assert!(debits.prendre("bob", Some("tel"), 0));
    assert_eq!(debits.refusees("alice"), 1);
    assert_eq!(debits.refusees("bob"), 0);
}

#[test]
fn les_sessions_par_mot_de_passe_partagent_le_seau_du_compte() {
    let debits = petits();
    assert!(debits.prendre("alice", None, 0));
    assert!(debits.prendre("alice", None, 0));
    assert!(!debits.prendre("alice", None, 0));
    // Le seau d'un appareil n'est pas celui des mots de passe.
    assert!(debits.prendre("alice", Some("tel"), 0));
}

#[test]
fn le_seau_se_remplit_avec_le_temps() {
    let debits = petits();
    assert!(debits.prendre("alice", Some("tel"), 0));
    assert!(debits.prendre("alice", Some("tel"), 0));
    assert!(!debits.prendre("alice", Some("tel"), SECONDE / 2));
    assert!(debits.prendre("alice", Some("tel"), SECONDE));
}

#[test]
fn un_seau_entame_survit_mais_un_seau_plein_s_oublie() {
    let debits = petits();
    assert!(debits.prendre("alice", Some("tel"), 0));
    assert!(debits.prendre("alice", Some("tel"), 0));
    // Un autre seau naît : celui d'alice, vide, n'est pas oublié.
    assert!(debits.prendre("bob", Some("tel"), 0));
    assert_eq!(debits.retenus(), 2);
    assert!(!debits.prendre("alice", Some("tel"), 0));
    // Trois secondes plus tard, les deux sont pleins : la naissance d'un
    // troisième les purge, et il ne reste que lui.
    assert!(debits.prendre("carol", None, 3 * SECONDE));
    assert_eq!(debits.retenus(), 1);
}

#[test]
fn oublier_un_compte_oublie_ses_seaux_et_ses_refus() {
    let debits = petits();
    assert!(debits.prendre("alice", Some("tel"), 0));
    assert!(debits.prendre("alice", Some("tel"), 0));
    assert!(!debits.prendre("alice", Some("tel"), 0));
    assert!(debits.prendre("bob", None, 0));
    debits.oublier("alice");
    assert_eq!(debits.refusees("alice"), 0);
    assert_eq!(debits.retenus(), 1);
    // Recréé sous le même nom, il repart d'un seau plein.
    assert!(debits.prendre("alice", Some("tel"), 0));
}

#[test]
fn un_debit_a_zero_prend_le_defaut() {
    let debits = Debits::new(Rate {
        burst: 0,
        per_second: 0,
    });
    assert_eq!(debits.debit(), Rate::DEFAULT);
    assert!(!std::format!("{debits:?}").is_empty());
}
