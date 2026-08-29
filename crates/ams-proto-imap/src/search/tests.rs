//! Ce qu'une recherche désigne, et ce qu'elle refuse de prétendre.

use super::{Candidate, Search};
use crate::{Error, Flags, Limits};

const BORNES: Limits = Limits::DEFAULT;

/// Un message d'épreuve.
fn message(sequence: u32, uid: u32, size: u64, flags: Flags, date: u64) -> Candidate {
    Candidate {
        sequence,
        uid,
        size,
        flags,
        internal_date: date,
    }
}

/// Le 29 août 2026, à midi UTC.
const AOUT: u64 = 1_788_004_800;
/// Le 1er janvier 2020, à midi UTC.
const JANVIER: u64 = 1_577_880_000;

/// Les rangs qui correspondent, parmi trois messages d'épreuve.
fn trouves(critere: &[u8]) -> std::vec::Vec<u32> {
    let recherche = Search::parse(critere, &BORNES).expect("lisible");
    let messages = [
        message(1, 10, 100, Flags::NONE, JANVIER),
        message(2, 20, 5000, Flags::SEEN, AOUT),
        message(3, 30, 300, Flags::SEEN.with(Flags::DELETED), AOUT),
    ];
    messages
        .iter()
        .filter(|message| recherche.matches(message, 3, 30))
        .map(|message| message.sequence)
        .collect()
}

#[test]
fn all_prend_tout() {
    assert_eq!(trouves(b"ALL"), std::vec![1, 2, 3]);
    assert_eq!(trouves(b"all"), std::vec![1, 2, 3]);
}

#[test]
fn les_drapeaux_se_cherchent_dans_les_deux_sens() {
    assert_eq!(trouves(b"SEEN"), std::vec![2, 3]);
    assert_eq!(trouves(b"UNSEEN"), std::vec![1]);
    assert_eq!(trouves(b"DELETED"), std::vec![3]);
    assert_eq!(trouves(b"UNDELETED"), std::vec![1, 2]);
    assert_eq!(trouves(b"UNFLAGGED"), std::vec![1, 2, 3]);
    assert_eq!(trouves(b"ANSWERED"), std::vec::Vec::<u32>::new());
    assert_eq!(trouves(b"UNDRAFT"), std::vec![1, 2, 3]);
}

#[test]
fn les_tailles_se_comparent_strictement() {
    assert_eq!(trouves(b"LARGER 300"), std::vec![2]);
    assert_eq!(trouves(b"SMALLER 300"), std::vec![1]);
    // Strictement : la taille exacte n'est ni plus grande ni plus petite.
    assert_eq!(trouves(b"LARGER 100 SMALLER 5000"), std::vec![3]);
}

#[test]
fn les_dates_se_comparent_par_jour() {
    assert_eq!(trouves(b"SINCE 29-Aug-2026"), std::vec![2, 3]);
    assert_eq!(trouves(b"BEFORE 29-Aug-2026"), std::vec![1]);
    assert_eq!(trouves(b"ON 29-Aug-2026"), std::vec![2, 3]);
    assert_eq!(trouves(b"ON 1-Jan-2020"), std::vec![1]);
    // Les guillemets sont admis, et la casse du mois ne compte pas.
    assert_eq!(trouves(b"ON \"29-aug-2026\""), std::vec![2, 3]);
}

#[test]
fn les_ensembles_se_cherchent_par_rang_et_par_uid() {
    assert_eq!(trouves(b"1:2"), std::vec![1, 2]);
    assert_eq!(trouves(b"UID 20:*"), std::vec![2, 3]);
    assert_eq!(trouves(b"2,3"), std::vec![2, 3]);
}

/// **Juxtaposer, c'est conjoindre** (§6.4.4).
#[test]
fn deux_criteres_se_conjoignent() {
    assert_eq!(trouves(b"SEEN UNDELETED"), std::vec![2]);
    assert_eq!(trouves(b"SEEN LARGER 1000"), std::vec![2]);
}

#[test]
fn not_et_or_disent_ce_qu_ils_disent() {
    assert_eq!(trouves(b"NOT SEEN"), std::vec![1]);
    assert_eq!(trouves(b"OR SEEN DELETED"), std::vec![2, 3]);
    assert_eq!(trouves(b"OR UNSEEN DELETED"), std::vec![1, 3]);
    // `NOT` porte sur la clef qui suit, et une seule.
    assert_eq!(trouves(b"NOT SEEN UNDELETED"), std::vec![1]);
    // Doublement nié vaut affirmé.
    assert_eq!(trouves(b"NOT NOT SEEN"), std::vec![2, 3]);
}

#[test]
fn les_parentheses_groupent() {
    assert_eq!(trouves(b"OR (SEEN DELETED) UNSEEN"), std::vec![1, 3]);
    assert_eq!(trouves(b"(SEEN)"), std::vec![2, 3]);
    assert_eq!(trouves(b"NOT (SEEN UNDELETED)"), std::vec![1, 3]);
    // Collées, elles se lisent pareil.
    assert_eq!(trouves(b"(SEEN UNDELETED)"), std::vec![2]);
}

/// **Un critère qu'on ne sert pas est refusé, pas rendu faux.** Un
/// `SEARCH SUBJECT "facture"` répondant « aucun résultat » serait un mensonge
/// exact.
#[test]
fn un_critere_non_servi_est_refuse() {
    for critere in [
        &b"SUBJECT facture"[..],
        b"BODY texte",
        b"FROM jean",
        b"TEXT quoi",
        b"HEADER X-Chose valeur",
        b"KEYWORD $Important",
        b"SEEN SUBJECT facture",
        // Le refus traverse les parenthèses et les opérateurs.
        b"(SEEN SUBJECT facture)",
        b"OR SUBJECT facture SEEN",
        b"OR SEEN SUBJECT facture",
        b"NOT SUBJECT facture",
    ] {
        assert_eq!(
            Search::parse(critere, &BORNES).err(),
            Some(Error::UnsupportedSearchKey),
            "{:?}",
            core::str::from_utf8(critere)
        );
    }
}

#[test]
fn les_formes_fautives_sont_des_fautes() {
    for critere in [
        &b""[..],
        b"   ",
        b"NOT",
        b"OR SEEN",
        b"(",
        b"(SEEN",
        b")",
        b"SEEN )",
        b"LARGER",
        b"LARGER x",
        b"SINCE",
        b"SINCE 32-Aug-2026",
        b"SINCE 1-Zzz-2026",
        b"SINCE 1-Jan-1969",
        b"SINCE 1-Jan",
        b"SINCE 1",
        b"SINCE 1-Jan-2026-3",
        // Un nombre qui déborde n'est pas un petit nombre.
        b"LARGER 99999999999999999999999",
        b"SMALLER 18446744073709551616",
        b"UID",
        b"UID x",
        b"1:x",
    ] {
        assert!(
            Search::parse(critere, &BORNES).is_err(),
            "{:?} aurait dû être refusé",
            core::str::from_utf8(critere)
        );
    }
}

/// **La pile n'est pas extensible**, et le client choisit la profondeur.
#[test]
fn une_imbrication_demesuree_est_refusee() {
    let mut profond = std::vec::Vec::new();
    for _ in 0..64 {
        profond.extend_from_slice(b"NOT ");
    }
    profond.extend_from_slice(b"SEEN");
    assert_eq!(
        Search::parse(&profond, &BORNES).err(),
        Some(Error::SearchTooDeep {
            limit: super::SEARCH_DEPTH_MAX
        })
    );
}

/// La borne vaut aussi DANS des parenthèses : elle porte sur l'expression, pas
/// sur sa forme.
#[test]
fn une_expression_demesuree_entre_parentheses_est_refusee_aussi() {
    let mut longue = std::vec::Vec::from(&b"("[..]);
    for _ in 0..super::SEARCH_KEYS_MAX {
        longue.extend_from_slice(b"SEEN ");
    }
    longue.extend_from_slice(b")");
    assert_eq!(
        Search::parse(&longue, &BORNES).err(),
        Some(Error::SearchTooComplex {
            limit: super::SEARCH_KEYS_MAX
        })
    );
}

/// **Le tableau de nœuds est fini**, et une conjonction assez longue le remplit.
#[test]
fn une_expression_demesuree_est_refusee() {
    let mut longue = std::vec::Vec::new();
    for _ in 0..super::SEARCH_KEYS_MAX {
        longue.extend_from_slice(b"SEEN ");
    }
    assert_eq!(
        Search::parse(&longue, &BORNES).err(),
        Some(Error::SearchTooComplex {
            limit: super::SEARCH_KEYS_MAX
        })
    );
}

/// **`Search::NONE` ne désigne rien**, ce qui est la seule réponse qui ne mente
/// pas à qui ne saurait plus lire une expression.
#[test]
fn l_expression_vide_ne_designe_rien() {
    let rien = Search::NONE;
    assert!(!rien.is_empty());
    for sequence in [0_u32, 1, 2, u32::MAX] {
        assert!(!rien.matches(&message(sequence, sequence, 0, Flags::NONE, 0), 3, 30));
    }
}

/// Un nœud ne référence que des nœuds d'indice strictement inférieur : c'est ce
/// qui rend le cycle impossible, et l'évaluation sûre.
#[test]
fn l_arbre_ne_designe_que_vers_le_bas() {
    let recherche = Search::parse(b"OR (SEEN DELETED) NOT UNSEEN", &BORNES).expect("lisible");
    assert!(recherche.len() > 1);
    assert!(!recherche.is_empty());
    for (rang, noeud) in recherche.noeuds.iter().take(recherche.len()).enumerate() {
        let rang = u16::try_from(rang).expect("un indice tient");
        match *noeud {
            super::Noeud::Non(clef) => assert!(clef < rang),
            super::Noeud::Ou(gauche, droite) | super::Noeud::Et(gauche, droite) => {
                assert!(gauche < rang);
                assert!(droite < rang);
            }
            _ => {}
        }
    }
}
