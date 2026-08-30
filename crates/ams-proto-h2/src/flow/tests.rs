// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une fenêtre de contrôle de flux garantit.

use super::{INITIAL_WINDOW_SIZE, WINDOW_MAX, Window};
use crate::error::{Cause, ErrorCode};

/// La fenêtre part à sa taille initiale, et se consomme.
#[test]
fn la_fenetre_se_consomme() {
    let mut fenetre = Window::default();
    assert_eq!(fenetre.available(), i64::from(INITIAL_WINDOW_SIZE));

    fenetre.consume(1_000).expect("il y a la place");
    assert_eq!(fenetre.available(), 64_535);

    // Jusqu'au dernier octet.
    fenetre.consume(64_535).expect("il y a la place");
    assert_eq!(fenetre.available(), 0);
    // Consommer zéro est licite, et ne change rien.
    fenetre.consume(0).expect("rien à prendre");
    assert_eq!(fenetre.available(), 0);
}

/// **ON REFUSE AVANT DE CONSOMMER, JAMAIS APRÈS** : un récepteur qui
/// soustrairait d'abord aurait déjà accepté les octets, et sa fenêtre dirait le
/// contraire de ce qu'il a fait.
#[test]
fn ce_qui_depasse_la_fenetre_se_refuse_avant_d_etre_pris() {
    let mut fenetre = Window::new(10);
    let issue = fenetre.consume(11).expect_err("refusé");
    assert_eq!(issue.cause(), Cause::WindowExceeded);
    assert_eq!(issue.code(), ErrorCode::FlowControlError);
    assert_eq!(fenetre.available(), 10, "rien n'a été pris");
    // La borne exacte passe.
    assert!(fenetre.consume(10).is_ok());
    assert!(fenetre.consume(1).is_err());
}

/// **UNE FENÊTRE PEUT DEVENIR NÉGATIVE, ET C'EST LÉGAL** (§6.9.2) : le pair a
/// réduit sa fenêtre initiale après avoir laissé envoyer. Une fenêtre non signée
/// passerait par zéro, et laisserait alors entrer ce qu'elle devait refuser.
#[test]
fn une_fenetre_peut_devenir_negative() {
    let mut fenetre = Window::new(INITIAL_WINDOW_SIZE);
    fenetre.consume(60_000).expect("il y a la place");
    assert_eq!(fenetre.available(), 5_535);

    // Le pair ramène la fenêtre initiale de 65535 à 1024 : la variation vaut
    // moins soixante-quatre mille cinq cent onze.
    fenetre.adjust(-64_511).expect("l'ajustement passe");
    assert_eq!(fenetre.available(), -58_976, "négative, et c'est correct");

    // Et RIEN ne passe plus tant qu'elle est négative.
    let issue = fenetre.consume(1).expect_err("refusé");
    assert_eq!(issue.cause(), Cause::WindowExceeded);
    // Même zéro octet ne peut pas être « consommé » d'une fenêtre négative :
    // zéro dépasse une valeur négative.
    assert!(fenetre.consume(0).is_err());

    // Il faut du crédit pour repasser au-dessus.
    fenetre.increase(60_000).expect("du crédit");
    assert_eq!(fenetre.available(), 1_024);
    assert!(fenetre.consume(1_024).is_ok());
}

/// **UN `WINDOW_UPDATE` DE ZÉRO EST UNE FAUTE DE FLUX** (§6.9) : un pair qui en
/// envoie en boucle occupe la connexion sans jamais rien débloquer.
#[test]
fn un_credit_nul_se_refuse() {
    let mut fenetre = Window::default();
    let issue = fenetre.increase(0).expect_err("refusé");
    assert_eq!(issue.cause(), Cause::ZeroWindowUpdate);
    assert_eq!(issue.code(), ErrorCode::ProtocolError);
    assert!(
        !issue.is_fatal(),
        "§6.9 en fait une faute de FLUX, pas de connexion"
    );
    assert_eq!(fenetre.available(), i64::from(INITIAL_WINDOW_SIZE));
}

/// **AU-DELÀ DE 2^31-1, C'EST UNE FAUTE** (§6.9.1), dans les deux chemins qui y
/// mènent.
#[test]
fn une_fenetre_qui_deborde_se_refuse() {
    let mut fenetre = Window::new(0);
    // Par le crédit.
    fenetre
        .increase(0x7fff_ffff)
        .expect("jusqu'à la borne exacte");
    assert_eq!(fenetre.available(), WINDOW_MAX);
    let issue = fenetre.increase(1).expect_err("refusé");
    assert_eq!(issue.cause(), Cause::WindowOverflow);
    assert_eq!(issue.code(), ErrorCode::FlowControlError);
    assert!(issue.is_fatal());
    assert_eq!(fenetre.available(), WINDOW_MAX, "rien n'a bougé");

    // Par l'ajustement.
    let mut autre = Window::new(INITIAL_WINDOW_SIZE);
    let issue = autre.adjust(WINDOW_MAX).expect_err("refusé");
    assert_eq!(issue.cause(), Cause::WindowOverflow);
    assert_eq!(
        autre.available(),
        i64::from(INITIAL_WINDOW_SIZE),
        "rien n'a bougé"
    );
    // L'ajustement qui atteint exactement la borne passe.
    let mut juste = Window::new(0);
    assert!(juste.adjust(WINDOW_MAX).is_ok());
    assert_eq!(juste.available(), WINDOW_MAX);
}

/// **LA BORNE EST TENUE ICI, PAS SUPPOSÉE AILLEURS** : une structure qui
/// garantit son invariant vaut mieux qu'une qui le suppose.
#[test]
fn une_fenetre_ne_nait_jamais_hors_borne() {
    assert_eq!(Window::new(0x7fff_ffff).available(), WINDOW_MAX);
    assert_eq!(Window::new(0x8000_0000).available(), WINDOW_MAX);
    assert_eq!(Window::new(u32::MAX).available(), WINDOW_MAX);
}

/// Une fenêtre se montre et se compare.
#[test]
fn une_fenetre_se_montre() {
    let fenetre = Window::new(42);
    assert_eq!(fenetre, Window::new(42));
    assert_ne!(fenetre, Window::default());
    assert!(std::format!("{fenetre:?}").contains("42"));
}
