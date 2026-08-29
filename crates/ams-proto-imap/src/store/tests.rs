//! Ce qu'un `STORE` écrit, et ce qu'on refuse d'écrire pour lui.

use super::{Store, StoreMode};
use crate::{Error, Flags, Limits};

const BORNES: Limits = Limits::DEFAULT;

/// Lit un `STORE`, ou panique.
fn lu(arguments: &[u8]) -> Store<'_> {
    Store::parse(arguments, &BORNES).expect("lisible")
}

#[test]
fn les_trois_verbes_se_distinguent() {
    assert_eq!(lu(b"1 FLAGS (\\Seen)").mode(), StoreMode::Replace);
    assert_eq!(lu(b"1 +FLAGS (\\Seen)").mode(), StoreMode::Add);
    assert_eq!(lu(b"1 -FLAGS (\\Seen)").mode(), StoreMode::Remove);
    // Et la casse ne compte pas.
    assert_eq!(lu(b"1 +flags (\\seen)").mode(), StoreMode::Add);
}

#[test]
fn silent_se_lit_sur_les_trois_verbes() {
    assert!(!lu(b"1 FLAGS (\\Seen)").silent());
    assert!(lu(b"1 FLAGS.SILENT (\\Seen)").silent());
    assert!(lu(b"1 +FLAGS.SILENT (\\Seen)").silent());
    assert!(lu(b"1 -FLAGS.SILENT (\\Seen)").silent());
    // Et la casse ne compte pas non plus sur le suffixe.
    assert!(lu(b"1 +FLAGS.silent (\\Seen)").silent());
}

#[test]
fn les_drapeaux_se_lisent_nus_ou_entre_parentheses() {
    let entre = lu(b"1 FLAGS (\\Seen \\Deleted)");
    assert!(entre.flags().contains(Flags::SEEN));
    assert!(entre.flags().contains(Flags::DELETED));
    // §6.4.6 admet la forme nue.
    let nus = lu(b"1 FLAGS \\Seen \\Deleted");
    assert_eq!(nus.flags(), entre.flags());
    // Un seul drapeau, nu.
    assert_eq!(lu(b"1 +FLAGS \\Answered").flags(), Flags::ANSWERED);
    // Les espaces en trop ne changent rien.
    assert_eq!(lu(b"1 FLAGS (  \\Draft   )").flags(), Flags::DRAFT);
}

/// **`FLAGS ()` EFFACE TOUT**, et c'est la seule façon de le demander.
#[test]
fn une_liste_vide_est_une_demande_legitime() {
    let vide = lu(b"1 FLAGS ()");
    assert_eq!(vide.flags(), Flags::NONE);
    assert_eq!(vide.mode(), StoreMode::Replace);
    // `+FLAGS ()` ne demande rien, ce qui n'est pas une faute.
    assert_eq!(lu(b"1 +FLAGS ()").flags(), Flags::NONE);
}

#[test]
fn l_ensemble_est_celui_qu_on_a_ecrit() {
    let lu = lu(b"1:3,7 +FLAGS (\\Seen)");
    assert_eq!(lu.set_text(), b"1:3,7");
    assert_eq!(
        lu.set().ranges(10).collect::<std::vec::Vec<_>>(),
        std::vec![(1, 3), (7, 7)]
    );
}

/// **Un drapeau inconnu est un REFUS.** Un client à qui l'on répond `OK` croit
/// son étiquette posée, et ne la reverra jamais.
#[test]
fn un_drapeau_inconnu_est_refuse() {
    assert_eq!(
        Store::parse(b"1 FLAGS (\\Seen $Important)", &BORNES),
        Err(Error::UnknownFlag)
    );
    assert_eq!(
        Store::parse(b"1 +FLAGS \\Recent", &BORNES),
        Err(Error::UnknownFlag)
    );
}

#[test]
fn les_formes_fautives_sont_des_fautes() {
    for arguments in [
        // Pas d'ensemble.
        &b"FLAGS (\\Seen)"[..],
        // Pas de verbe.
        b"1",
        b"1 ",
        // Un verbe, mais aucun drapeau derrière.
        b"1 FLAGS",
        b"1 +FLAGS.SILENT",
        // Un verbe qui n'en est pas un.
        b"1 MARKS (\\Seen)",
        b"1 +MARKS (\\Seen)",
        b"1 FLAGS.LOUD (\\Seen)",
        b"1 +FLAGS.LOUD (\\Seen)",
        // Un `.SILENT` accroché à un verbe qui n'existe pas.
        b"1 MARKS.SILENT (\\Seen)",
        b"1 +MARKS.SILENT (\\Seen)",
        // Une parenthèse d'un seul côté.
        b"1 FLAGS (\\Seen",
        b"1 FLAGS \\Seen)",
        // Un ensemble illisible.
        b"x FLAGS (\\Seen)",
    ] {
        assert!(
            Store::parse(arguments, &BORNES).is_err(),
            "{:?} aurait dû être refusé",
            core::str::from_utf8(arguments)
        );
    }
}

/// La parenthèse seule — `()` — n'est pas « une parenthèse d'un seul côté ».
#[test]
fn la_liste_vide_n_est_pas_une_parenthese_orpheline() {
    assert_eq!(lu(b"1 FLAGS ()").flags(), Flags::NONE);
    // `(` seul, en revanche, en est une.
    assert_eq!(
        Store::parse(b"1 FLAGS (", &BORNES),
        Err(Error::MalformedStore)
    );
}
