//! Ce que les bornes valent.

use super::Limits;

#[test]
fn les_bornes_par_defaut_sont_celles_qu_on_a_choisies() {
    // Le seul nombre que la RFC 9051 §4 avance.
    assert_eq!(Limits::DEFAULT.max_line_octets, 8192);
    // Les autres viennent d'ici, et les noms de champ ne prétendent pas
    // autrement.
    assert_eq!(Limits::DEFAULT.max_tag_octets, 32);
    assert_eq!(Limits::DEFAULT.max_literal_octets, 65_536);
    assert_eq!(Limits::DEFAULT.max_literals, 8);
    assert_eq!(Limits::DEFAULT.max_response_octets, 8192);
    assert_eq!(Limits::DEFAULT.max_sequence_items, 1024);
    assert_eq!(Limits::DEFAULT.max_fetch_items, 64);
}

/// **Celle-là n'est pas négociable** : c'est elle qui rend le littéral non
/// synchronisant sûr, puisqu'un tel littéral part sans que le serveur ait pu
/// dire non.
#[test]
fn la_borne_du_litteral_non_synchronisant_vient_de_la_rfc() {
    assert_eq!(Limits::NON_SYNCHRONIZING_MAX, 4096);
    // La forme sûre est la plus étroite : le comparer ainsi le dit une fois
    // pour toutes, à la compilation.
    const { assert!(Limits::NON_SYNCHRONIZING_MAX < Limits::DEFAULT.max_literal_octets) };
}

#[test]
fn elles_se_copient_et_se_comparent() {
    let bornes = Limits::DEFAULT;
    let copie = bornes;
    assert_eq!(bornes, copie);
    assert_ne!(
        bornes,
        Limits {
            max_tag_octets: 1,
            ..bornes
        }
    );
    assert!(!std::format!("{bornes:?}").is_empty());
}
