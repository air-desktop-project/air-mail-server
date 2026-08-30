// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que le contrôle de congestion a le droit de faire.

use super::{
    Congestion, INITIAL_WINDOW, MAX_DATAGRAM_SIZE, MINIMUM_WINDOW, PACKET_THRESHOLD,
    PERSISTENT_CONGESTION_THRESHOLD, is_lost, time_threshold,
};
use crate::rtt::{GRANULARITY_US, Rtt};

/// Une estimation avec un aller-retour connu de cent millisecondes.
fn rtt_de(microsecondes: u64) -> Rtt {
    let mut rtt = Rtt::new();
    rtt.sample(microsecondes, 0, 0);
    rtt
}

/// **LA FENÊTRE DE DÉPART EST CELLE DE §7.2** : dix datagrammes, bornés à
/// quatorze kibioctets et demi.
#[test]
fn la_fenetre_de_depart_est_celle_de_la_rfc() {
    assert_eq!(INITIAL_WINDOW, 12_000, "dix fois mille deux cents");
    assert_eq!(MINIMUM_WINDOW, 2_400);
    let controle = Congestion::new();
    assert_eq!(controle.window(), INITIAL_WINDOW);
    assert_eq!(controle.in_flight(), 0);
    assert_eq!(controle.available(), INITIAL_WINDOW);
    assert!(controle.in_slow_start(), "rien n'est encore arrivé");
    assert_eq!(Congestion::default(), controle);
}

/// **ZÉRO N'EST PAS UNE FAUTE** : c'est une fenêtre pleine, et l'émetteur attend
/// un acquittement.
#[test]
fn une_fenetre_pleine_ne_laisse_rien_passer() {
    let mut controle = Congestion::new();
    controle.on_sent(INITIAL_WINDOW);
    assert_eq!(controle.available(), 0);
    assert_eq!(controle.in_flight(), INITIAL_WINDOW);
    // Un envoi de plus ne rend pas la fenêtre négative.
    controle.on_sent(10_000);
    assert_eq!(controle.available(), 0);
}

/// **EN DÉMARRAGE LENT, LA FENÊTRE DOUBLE À CHAQUE ALLER-RETOUR** : on trouve la
/// capacité du chemin en quelques allers-retours plutôt qu'en quelques minutes.
#[test]
fn le_demarrage_lent_double_la_fenetre() {
    let mut controle = Congestion::new();
    controle.on_sent(INITIAL_WINDOW);
    controle.on_acked(INITIAL_WINDOW, 1_000);
    assert_eq!(controle.window(), INITIAL_WINDOW.saturating_mul(2));
    assert_eq!(controle.in_flight(), 0);
    assert!(controle.in_slow_start());
}

/// **APRÈS UNE PERTE, ON CROÎT D'UN DATAGRAMME PAR ALLER-RETOUR.** C'est lent
/// exprès : l'augmentation additive contre la diminution multiplicative est ce
/// qui fait converger plusieurs émetteurs vers une part équitable.
#[test]
fn apres_une_perte_la_croissance_devient_additive() {
    let mut controle = Congestion::new();
    controle.on_sent(INITIAL_WINDOW);
    controle.on_lost(1_200, 500, 1_000);
    let apres = controle.window();
    assert_eq!(apres, INITIAL_WINDOW / 2, "la moitié");
    assert!(!controle.in_slow_start(), "le seuil est posé");

    // Un aller-retour complet acquitté fait gagner un datagramme, pas plus.
    let mut acquitte = 0_u64;
    while acquitte < apres {
        controle.on_acked(1_200, 10_000);
        acquitte = acquitte.saturating_add(1_200);
    }
    let gagne = controle.window().saturating_sub(apres);
    assert!(
        gagne >= MAX_DATAGRAM_SIZE / 2 && gagne <= MAX_DATAGRAM_SIZE.saturating_mul(2),
        "un aller-retour a fait gagner {gagne} octets"
    );
}

/// **UNE RAFALE PERDUE EST UN ÉVÉNEMENT DE CONGESTION, PAS DIX** (§7.3.2).
/// Diviser une fois par paquet ramènerait la fenêtre au minimum sur la première
/// rafale venue.
#[test]
fn une_rafale_perdue_ne_divise_qu_une_fois() {
    let mut controle = Congestion::new();
    controle.on_sent(INITIAL_WINDOW);
    // Dix paquets envoyés avant l'instant 1 000, tous perdus.
    for _ in 0..10_u8 {
        controle.on_lost(1_200, 500, 1_000);
    }
    assert_eq!(
        controle.window(),
        INITIAL_WINDOW / 2,
        "une seule division pour toute la rafale"
    );

    // Une perte d'un paquet envoyé APRÈS la période, en revanche, en est une
    // autre.
    controle.on_sent(1_200);
    controle.on_lost(1_200, 2_000, 3_000);
    assert_eq!(controle.window(), INITIAL_WINDOW / 4);
}

/// **LA FENÊTRE NE DESCEND PAS SOUS DEUX DATAGRAMMES** : en deçà, on ne pourrait
/// plus envoyer un paquet plein, et le contrôle deviendrait un arrêt de service.
#[test]
fn la_fenetre_ne_descend_pas_sous_le_minimum() {
    let mut controle = Congestion::new();
    let mut instant = 1_000_u64;
    for _ in 0..20_u8 {
        controle.on_sent(1_200);
        controle.on_lost(1_200, instant, instant.saturating_add(1));
        instant = instant.saturating_add(10_000);
    }
    assert_eq!(controle.window(), MINIMUM_WINDOW);
}

/// **UN PAQUET ACQUITTÉ ENVOYÉ AVANT LA FIN DE LA RÉCUPÉRATION NE FAIT PAS
/// CROÎTRE LA FENÊTRE** (§7.3.2) : il était déjà en vol quand la congestion
/// s'est produite, et ne prouve rien du nouveau régime.
#[test]
fn un_acquittement_pendant_la_recuperation_ne_fait_pas_croitre() {
    let mut controle = Congestion::new();
    controle.on_sent(INITIAL_WINDOW);
    controle.on_lost(1_200, 500, 1_000);
    let apres = controle.window();

    // Acquittement daté DANS la période de récupération.
    controle.on_acked(1_200, 1_000);
    assert_eq!(controle.window(), apres, "rien n'a bougé");
    assert!(controle.in_flight() < INITIAL_WINDOW, "le vol a diminué");

    // Et un acquittement d'après la période, lui, compte.
    controle.on_acked(1_200, 1_001);
    assert!(controle.window() > apres);
}

/// **UNE CONGESTION PERSISTANTE N'EST PAS UNE PERTE DE PLUS** (§7.6) : rien
/// n'est passé pendant plusieurs allers-retours, le chemin a changé ou il est
/// coupé.
#[test]
fn une_congestion_persistante_repart_de_zero() {
    let mut controle = Congestion::new();
    controle.on_sent(INITIAL_WINDOW);
    controle.on_acked(INITIAL_WINDOW, 1_000);
    controle.on_lost(1_200, 2_000, 3_000);
    assert!(!controle.in_slow_start());

    controle.on_persistent_congestion();
    assert_eq!(controle.window(), MINIMUM_WINDOW);
    assert!(
        controle.in_slow_start(),
        "on ne sait plus rien du chemin : on recommence à chercher"
    );

    // Et la durée est trois délais de retransmission.
    let rtt = rtt_de(100_000);
    assert_eq!(
        Congestion::persistent_congestion_duration(&rtt, 25_000),
        rtt.pto(25_000, 0)
            .saturating_mul(PERSISTENT_CONGESTION_THRESHOLD)
    );
}

/// **NEUF HUITIÈMES, ET NON UN** (§6.1.2) : le huitième de marge paie le
/// réordonnancement ordinaire.
#[test]
fn le_seuil_de_temps_laisse_un_huitieme_de_marge() {
    let rtt = rtt_de(80_000);
    assert_eq!(time_threshold(&rtt), 90_000, "neuf huitièmes de 80 ms");

    // Le plancher de granularité empêche un seuil plus court que l'horloge.
    let court = rtt_de(1);
    assert_eq!(time_threshold(&court), GRANULARITY_US);

    // Et c'est le PLUS GRAND des deux aller-retours qui compte : un pic récent
    // ne doit pas faire déclarer perdu ce qui vient de traverser.
    let mut pic = Rtt::new();
    pic.sample(10_000, 0, 0);
    pic.sample(400_000, 0, 0);
    assert!(
        time_threshold(&pic) >= 400_000_u64.saturating_mul(9).saturating_div(8),
        "le dernier échantillon compte s'il est le plus grand"
    );
}

/// **TROIS PAQUETS D'ÉCART** (§6.1.1) : en deçà, le réordonnancement ordinaire
/// passerait pour une perte.
#[test]
fn le_seuil_de_paquets_tolere_le_reordonnancement() {
    let rtt = rtt_de(100_000);
    // Deux d'écart : c'est du désordre, pas une perte.
    assert!(!is_lost(8, 1_000, 10, 1_001, &rtt));
    // Trois d'écart : c'en est une.
    assert!(is_lost(7, 1_000, 10, 1_001, &rtt));
    assert_eq!(PACKET_THRESHOLD, 3);

    // Un paquet PLUS RÉCENT que le plus grand acquitté n'est pas en cause.
    assert!(!is_lost(11, 1_000, 10, 1_001, &rtt));
}

/// **LE SEUIL DE TEMPS VOIT CE QUE LE SEUIL DE PAQUETS NE VOIT PAS** : le
/// dernier paquet d'un échange n'a aucun successeur pour le déclarer perdu.
#[test]
fn le_seuil_de_temps_voit_le_dernier_paquet() {
    let rtt = rtt_de(80_000);
    let seuil = time_threshold(&rtt);
    // Un seul paquet d'écart : le seuil de paquets ne dit rien.
    assert!(!is_lost(
        9,
        1_000,
        10,
        1_000_u64.saturating_add(seuil / 2),
        &rtt
    ));
    // Mais passé le seuil de temps, il est perdu.
    assert!(is_lost(9, 1_000, 10, 1_000_u64.saturating_add(seuil), &rtt));
}
