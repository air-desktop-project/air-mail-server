// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que la table dynamique garantit.

use super::{Dynamique, TABLE_SIZE_MAX};
use crate::error::Cause;

/// **L'INDEX UN DÉSIGNE LA PLUS RÉCENTE** (§2.3.3), et insérer DÉCALE tout le
/// reste. Un décodeur qui se tromperait d'un cran lirait tous les en-têtes
/// suivants de travers.
#[test]
fn l_index_un_designe_la_plus_recente() {
    let mut table = Dynamique::new();
    assert!(table.is_empty());
    assert_eq!(table.len(), 0);
    assert_eq!(table.get(1), None);

    table.insert(b"premier", b"un");
    assert_eq!(table.get(1), Some((&b"premier"[..], &b"un"[..])));

    table.insert(b"second", b"deux");
    assert_eq!(table.get(1), Some((&b"second"[..], &b"deux"[..])));
    assert_eq!(table.get(2), Some((&b"premier"[..], &b"un"[..])));
    assert_eq!(table.len(), 2);
    assert_eq!(table.get(3), None);
    // L'index zéro ne désigne rien ici non plus.
    assert_eq!(table.get(0), None);
}

/// Le poids se compte comme §4.1 : les octets, plus trente-deux par entrée.
#[test]
fn le_poids_compte_le_surcout() {
    let mut table = Dynamique::new();
    assert_eq!(table.size(), 0);
    table.insert(b"ab", b"cde");
    assert_eq!(table.size(), 2 + 3 + 32);
    table.insert(b"", b"");
    assert_eq!(table.size(), 37 + 32);
}

/// **L'ÉVICTION PART DE LA PLUS ANCIENNE** (§4.4), et va jusqu'à ce que la
/// nouvelle tienne.
#[test]
fn l_eviction_part_de_la_plus_ancienne() {
    let mut table = Dynamique::new();
    // Trois entrées de quarante octets chacune dans une table de cent.
    table.set_max_size(100).expect("sous la borne");
    table.insert(b"aaaa", b"aaaa");
    table.insert(b"bbbb", b"bbbb");
    assert_eq!(table.len(), 2);
    assert_eq!(table.size(), 80);

    // La troisième en évince une.
    table.insert(b"cccc", b"cccc");
    assert_eq!(table.len(), 2, "la plus ancienne est partie");
    assert_eq!(table.get(1), Some((&b"cccc"[..], &b"cccc"[..])));
    assert_eq!(table.get(2), Some((&b"bbbb"[..], &b"bbbb"[..])));
    assert_eq!(table.get(3), None);
}

/// **UNE ENTRÉE PLUS GROSSE QUE LA TABLE LA VIDE, ET N'ENTRE PAS** (§4.4). Ce
/// n'est PAS une faute — un décodeur qui refuserait se désynchroniserait d'un
/// encodeur qui, lui, a vidé.
#[test]
fn une_entree_trop_grosse_vide_la_table() {
    let mut table = Dynamique::new();
    table.set_max_size(100).expect("sous la borne");
    table.insert(b"aaaa", b"aaaa");
    assert_eq!(table.len(), 1);

    let grosse = std::vec![b'x'; 200];
    table.insert(&grosse, b"");
    assert!(table.is_empty(), "la table est vidée");
    assert_eq!(table.size(), 0);
    assert_eq!(table.get(1), None);
    // Et la table reste utilisable.
    table.insert(b"apres", b"oui");
    assert_eq!(table.get(1), Some((&b"apres"[..], &b"oui"[..])));
}

/// **LA BORNE EST CELLE QU'ON A ANNONCÉE, PAS CELLE QU'ON DEMANDE** (§4.2). Un
/// pair qui demande davantage ne demande pas : il se trompe.
#[test]
fn une_taille_au_dela_de_ce_qu_on_annonce_se_refuse() {
    let mut table = Dynamique::new();
    assert_eq!(table.max_size(), TABLE_SIZE_MAX);
    assert!(table.set_max_size(TABLE_SIZE_MAX).is_ok());
    for taille in [
        TABLE_SIZE_MAX.saturating_add(1),
        TABLE_SIZE_MAX.saturating_mul(2),
        u32::MAX,
    ] {
        let issue = table.set_max_size(taille).expect_err("refusé");
        assert_eq!(issue.cause(), Cause::TableSizeTooLarge, "{taille}");
        assert!(issue.is_fatal(), "l'état HPACK est partagé");
    }
    assert_eq!(table.max_size(), TABLE_SIZE_MAX, "rien n'a bougé");
}

/// **RÉDUIRE LA TAILLE ÉVINCE SUR-LE-CHAMP** (§4.3) : la table doit tenir dans
/// sa nouvelle borne avant que le champ suivant n'arrive.
#[test]
fn reduire_la_taille_evince_sur_le_champ() {
    let mut table = Dynamique::new();
    table.insert(b"aaaa", b"aaaa");
    table.insert(b"bbbb", b"bbbb");
    assert_eq!(table.size(), 80);

    table.set_max_size(40).expect("sous la borne");
    assert_eq!(table.len(), 1);
    assert_eq!(table.get(1), Some((&b"bbbb"[..], &b"bbbb"[..])));

    // Zéro vide tout, et c'est la façon convenue de repartir de rien.
    table.set_max_size(0).expect("sous la borne");
    assert!(table.is_empty());
    assert_eq!(table.size(), 0);
    // Une insertion dans une table de taille nulle ne garde rien.
    table.insert(b"a", b"b");
    assert!(table.is_empty());
}

/// **L'ARÈNE SE RECOMPACTE PLUTÔT QUE DE COUPER UNE ENTRÉE EN DEUX.** Un nom
/// coupé au bord ne se comparerait pas ; on déplace les octets vivants, et ce
/// que la table rend reste d'un seul tenant.
#[test]
fn l_arene_se_recompacte_sans_couper() {
    let mut table = Dynamique::new();
    // Des entrées de deux cent quatre-vingt-dix-huit octets, dans une table qui
    // en tient quatre kibioctets : on tourne plusieurs fois autour de l'arène.
    let nom = std::vec![b'n'; 128];
    for tour in 0..200_u32 {
        let valeur = std::vec![
            b'a'.saturating_add(u8::try_from(tour % 26).unwrap_or(0));
            128
        ];
        table.insert(&nom, &valeur);
        // Ce qu'on vient d'insérer se relit, entier.
        let (relu_nom, relu_valeur) = table.get(1).expect("la plus récente");
        assert_eq!(relu_nom, nom.as_slice(), "tour {tour}");
        assert_eq!(relu_valeur, valeur.as_slice(), "tour {tour}");
        assert!(table.size() <= table.max_size(), "tour {tour}");
        // Et toutes les autres aussi.
        for index in 1..=table.len() {
            let (n, v) = table.get(index).expect("dans la table");
            assert_eq!(n.len(), 128, "tour {tour}, index {index}");
            assert_eq!(v.len(), 128, "tour {tour}, index {index}");
        }
    }
}

/// **ON NE MONTRE PAS LE CONTENU** : une table dynamique porte les en-têtes de
/// toutes les requêtes d'une connexion, `authorization` compris.
#[test]
fn le_debug_ne_montre_pas_le_contenu() {
    let mut table = Dynamique::default();
    table.insert(b"authorization", b"Bearer secret");
    let texte = std::format!("{table:?}");
    assert!(!texte.contains("secret"), "{texte}");
    assert!(texte.contains("entrees: 1"), "{texte}");
}
