//! Ce qu'un ensemble de numéros désigne.

use super::SequenceSet;
use crate::{Error, Limits};

const BORNES: Limits = Limits::DEFAULT;

/// Les intervalles d'un ensemble, résolus contre `star`.
fn intervalles(texte: &[u8], star: u32) -> std::vec::Vec<(u32, u32)> {
    SequenceSet::parse(texte, &BORNES)
        .expect("lisible")
        .ranges(star)
        .collect()
}

#[test]
fn les_formes_ordinaires_se_lisent() {
    assert_eq!(intervalles(b"1", 10), std::vec![(1, 1)]);
    assert_eq!(intervalles(b"1:5", 10), std::vec![(1, 5)]);
    assert_eq!(
        intervalles(b"1:5,8,10:12", 20),
        std::vec![(1, 5), (8, 8), (10, 12)]
    );
    assert_eq!(
        intervalles(b"4294967295", 10),
        std::vec![(4_294_967_295, 4_294_967_295)]
    );
}

/// **L'étoile veut dire « le plus grand »**, et sa valeur dépend de la boîte.
#[test]
fn l_etoile_se_resout_contre_la_boite() {
    assert_eq!(intervalles(b"*", 7), std::vec![(7, 7)]);
    assert_eq!(intervalles(b"1:*", 7), std::vec![(1, 7)]);
    assert_eq!(intervalles(b"*:3", 7), std::vec![(3, 7)]);
    assert_eq!(intervalles(b"*:*", 7), std::vec![(7, 7)]);
    // Le même ensemble ne désigne pas la même chose selon la boîte.
    assert_eq!(intervalles(b"1:*", 100), std::vec![(1, 100)]);
}

/// **Une boîte vide fait de `*` un zéro**, et zéro n'est pas un numéro : rien
/// n'est désigné.
#[test]
fn sur_une_boite_vide_l_etoile_ne_designe_rien() {
    assert!(intervalles(b"*", 0).is_empty());
    assert!(intervalles(b"1:*", 0).is_empty());
    assert!(intervalles(b"*:*", 0).is_empty());
    // Mais un numéro explicite reste un intervalle : c'est au magasin de dire
    // qu'il n'existe pas, pas à la grammaire.
    assert_eq!(intervalles(b"3", 0), std::vec![(3, 3)]);
    // Et ce qui suit un élément vide continue d'être lu.
    assert_eq!(intervalles(b"*,4", 0), std::vec![(4, 4)]);
}

/// **Un intervalle n'est pas ordonné** (§9) : `10:5` désigne exactement ce que
/// désigne `5:10`. Un serveur qui prendrait `10:5` pour vide répondrait autre
/// chose que ce que le client a demandé.
#[test]
fn un_intervalle_a_l_envers_designe_la_meme_chose() {
    assert_eq!(intervalles(b"10:5", 20), std::vec![(5, 10)]);
    assert_eq!(intervalles(b"10:5", 20), intervalles(b"5:10", 20));
    assert_eq!(intervalles(b"*:1", 7), intervalles(b"1:*", 7));
}

#[test]
fn l_appartenance_suit_les_intervalles() {
    let ensemble = SequenceSet::parse(b"1:5,8,10:*", &BORNES).expect("lisible");
    for present in [1_u32, 3, 5, 8, 10, 11, 20] {
        assert!(ensemble.contains(present, 20), "{present}");
    }
    for absent in [0_u32, 6, 7, 9, 21] {
        assert!(!ensemble.contains(absent, 20), "{absent}");
    }
}

// ── CE QU'ON REFUSE ─────────────────────────────────────────────────────────

/// **Zéro n'est pas « le premier message »**, c'est une écriture qu'on refuse.
/// Et un numéro qui déborde n'est pas un grand numéro : reparti de zéro, il
/// désignerait un message que le client n'a pas demandé.
#[test]
fn c_est_ici_que_les_ecritures_douteuses_s_arretent() {
    for mechant in [
        &b"0"[..],
        b"0:5",
        b"1:0",
        b"",
        b",",
        b"1,",
        b",1",
        b"1:",
        b":5",
        b"1:2:3",
        b"1 2",
        b"1a",
        b"-1",
        b"+1",
        b"**",
        // 2^32, un de trop.
        b"4294967296",
        b"99999999999999999999",
    ] {
        assert_eq!(
            SequenceSet::parse(mechant, &BORNES),
            Err(Error::MalformedSequence),
            "{mechant:?}"
        );
    }
}

/// **`1,1,1,…` cent mille fois est un ensemble valide**, et le parcourir pour
/// chaque message d'une boîte ferait un travail quadratique offert à qui écrit
/// une ligne.
#[test]
fn un_ensemble_demesure_est_refuse() {
    let mut trop = std::vec::Vec::from(&b"1"[..]);
    for _ in 0..BORNES.max_sequence_items {
        trop.extend_from_slice(b",1");
    }
    assert_eq!(
        SequenceSet::parse(&trop, &BORNES),
        Err(Error::TooManySequenceItems {
            limit: BORNES.max_sequence_items
        })
    );

    // La borne elle-même passe.
    let mut juste = std::vec::Vec::from(&b"1"[..]);
    for _ in 1..BORNES.max_sequence_items {
        juste.extend_from_slice(b",1");
    }
    assert!(SequenceSet::parse(&juste, &BORNES).is_ok());
}

#[test]
fn ce_qui_se_lit_se_montre_et_se_compare() {
    let ensemble = SequenceSet::parse(b"1:5", &BORNES).expect("lisible");
    let copie = ensemble;
    assert_eq!(ensemble, copie);
    assert_ne!(
        ensemble,
        SequenceSet::parse(b"2:5", &BORNES).expect("lisible")
    );
    assert!(!std::format!("{ensemble:?}").is_empty());
    assert!(!std::format!("{:?}", ensemble.ranges(5)).is_empty());
    assert!(!std::format!("{:?}", ensemble.ranges(5).clone()).is_empty());
}

/// **LE MARQUEUR `$` SE LIT, ET NE DÉSIGNE RIEN TANT QU'ON NE L'A PAS RÉSOLU**
/// (§9 et §6.4.4.1). La grammaire n'a pas de session, donc pas de résultat
/// retenu ; le rendre inoffensif est tout ce qu'elle peut faire d'honnête.
#[test]
fn le_marqueur_du_dernier_resultat_se_lit_sans_rien_designer() {
    let lu = SequenceSet::parse(b"$", &BORNES).expect("lisible");
    assert!(lu.saved());
    assert_eq!(lu.as_bytes(), b"$");
    assert_eq!(lu.ranges(10).collect::<std::vec::Vec<_>>(), []);
    // ET SURTOUT PAS LE DERNIER MESSAGE : pris pour une étoile mal lue, ce `$`
    // désignerait n'importe quel message plutôt que ceux qu'on a cherchés.
    assert!(!lu.contains(10, 10));
    assert!(!lu.contains(1, 10));

    // Un ensemble ordinaire n'est pas un marqueur.
    let ordinaire = SequenceSet::parse(b"1:3", &BORNES).expect("lisible");
    assert!(!ordinaire.saved());

    // `$` ne se mélange pas : ce n'est pas une borne.
    for texte in [&b"$:3"[..], b"1,$", b"$$", b"$ "] {
        assert!(SequenceSet::parse(texte, &BORNES).is_err(), "{texte:?}");
    }
}
