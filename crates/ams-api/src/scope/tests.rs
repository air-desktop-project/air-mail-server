// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une portée ouvre, et ce qu'elle n'ouvre pas.

use super::{Area, Rights, Scope};

/// **UNE PORTÉE VIDE N'OUVRE RIEN, ET C'EST LE DÉFAUT** : la faute
/// d'inattention penche alors du bon côté.
#[test]
fn le_defaut_n_ouvre_rien() {
    let vide = Scope::none();
    assert_eq!(vide, Scope::default());
    assert_eq!(vide.bits(), 0);
    for area in Area::TOUS {
        assert!(!vide.allows(area, Rights::Read), "{area:?}");
        assert!(!vide.allows(area, Rights::Write), "{area:?}");
    }
    // Et elle se contient elle-même : ne rien demander est toujours accordé.
    assert!(vide.contains(Scope::none()));
}

/// **L'ÉCRITURE CONTIENT LA LECTURE**, et non l'inverse.
#[test]
fn l_ecriture_contient_la_lecture() {
    for area in Area::TOUS {
        let ecrire = Scope::one(area, Rights::Write);
        assert!(ecrire.allows(area, Rights::Write), "{area:?}");
        assert!(ecrire.allows(area, Rights::Read), "{area:?}");

        let lire = Scope::one(area, Rights::Read);
        assert!(lire.allows(area, Rights::Read), "{area:?}");
        assert!(
            !lire.allows(area, Rights::Write),
            "{area:?} : lire ne doit pas donner écrire"
        );
    }
}

/// **QUATRE DOMAINES QUI N'ONT RIEN À VOIR ENTRE EUX** : un jeton de client de
/// messagerie qui pourrait créer un compte serait un jeton d'administration
/// déguisé.
#[test]
fn les_domaines_ne_se_debordent_pas() {
    for area in Area::TOUS {
        let portee = Scope::one(area, Rights::Write);
        for autre in Area::TOUS {
            if autre == area {
                continue;
            }
            assert!(
                !portee.allows(autre, Rights::Read),
                "{area:?} en écriture ouvre {autre:?} en lecture"
            );
            assert!(
                !portee.allows(autre, Rights::Write),
                "{area:?} en écriture ouvre {autre:?} en écriture"
            );
        }
    }
}

/// Les portées se cumulent.
#[test]
fn les_portees_se_cumulent() {
    let deux = Scope::one(Area::Mail, Rights::Read).with(Area::Observe, Rights::Read);
    assert!(deux.allows(Area::Mail, Rights::Read));
    assert!(deux.allows(Area::Observe, Rights::Read));
    assert!(!deux.allows(Area::Admin, Rights::Read));
    assert!(!deux.allows(Area::Mail, Rights::Write));
}

/// **LA SEULE QUESTION QUE POSE LE CONTRÔLE D'ACCÈS** : tout bit demandé doit
/// être présent. Une égalité refuserait un jeton plus large que nécessaire.
#[test]
fn contenir_n_est_ni_l_egalite_ni_l_intersection() {
    let large = Scope::one(Area::Mail, Rights::Write).with(Area::Observe, Rights::Read);
    // Plus large que ce qu'on demande : accordé.
    assert!(large.contains(Scope::one(Area::Mail, Rights::Read)));
    assert!(large.contains(Scope::one(Area::Mail, Rights::Write)));
    assert!(large.contains(Scope::one(Area::Observe, Rights::Read)));
    // Plus étroit : refusé.
    assert!(!large.contains(Scope::one(Area::Observe, Rights::Write)));
    assert!(!large.contains(Scope::one(Area::Admin, Rights::Read)));
    // Une demande à cheval, dont une moitié seulement est ouverte.
    let a_cheval = Scope::one(Area::Mail, Rights::Read).with(Area::Admin, Rights::Read);
    assert!(!large.contains(a_cheval));
}

/// Les bits font un aller-retour : c'est ainsi qu'un jeton les portera.
#[test]
fn les_bits_font_un_aller_retour() {
    let portee = Scope::one(Area::Admin, Rights::Write).with(Area::Submit, Rights::Read);
    assert_eq!(Scope::from_bits(portee.bits()), portee);
    // Et tous les motifs possibles se relisent.
    for bits in 0..=u8::MAX {
        assert_eq!(Scope::from_bits(bits).bits(), bits);
    }
}

/// Chaque domaine a un nom, et ils sont tous différents.
#[test]
fn chaque_domaine_a_un_nom_distinct() {
    let mut vus = std::vec::Vec::new();
    for area in Area::TOUS {
        let nom = area.name();
        assert!(!nom.is_empty(), "{area:?}");
        assert!(!vus.contains(&nom), "« {nom} » est employé deux fois");
        vus.push(nom);
    }
    assert_eq!(vus.len(), 4);
}
