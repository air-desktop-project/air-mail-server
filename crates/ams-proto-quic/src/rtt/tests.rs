// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que l'estimation du temps d'aller-retour a le droit de faire.

use super::{ACK_DELAY_EXPONENT_MAX, GRANULARITY_US, INITIAL_RTT_US, Rtt, decode_ack_delay};
use crate::error::Reason;

/// **AVANT TOUTE MESURE, ON SUPPOSE TRENTE-TROIS CENTIÈMES DE SECONDE** (§6.2.2)
/// — long exprès : la première retransmission est celle dont on sait le moins.
#[test]
fn sans_mesure_on_suppose_ce_que_la_rfc_prescrit() {
    let rtt = Rtt::new();
    assert!(!rtt.has_sample());
    assert_eq!(rtt.smoothed(), INITIAL_RTT_US);
    assert_eq!(rtt.variance(), INITIAL_RTT_US / 2);
    assert_eq!(rtt.latest(), 0);
    assert_eq!(rtt.min(), 0);
    assert_eq!(Rtt::default(), rtt);
}

/// **LE PREMIER ÉCHANTILLON FONDE TOUT, ET NE SE CORRIGE PAS** : il n'y a pas
/// encore de minimum pour juger sa correction (§5.3).
#[test]
fn le_premier_echantillon_fonde_tout() {
    let mut rtt = Rtt::new();
    // On annonce un délai énorme : il est ignoré, faute de minimum.
    rtt.sample(100_000, 90_000, 1_000_000);
    assert!(rtt.has_sample());
    assert_eq!(rtt.latest(), 100_000);
    assert_eq!(rtt.min(), 100_000);
    assert_eq!(rtt.smoothed(), 100_000);
    assert_eq!(rtt.variance(), 50_000);
}

/// **LES CONSTANTES DE §5.3, PRISES À LA LETTRE** : trois quarts et un quart
/// pour la variance, sept huitièmes et un huitième pour la moyenne.
#[test]
fn les_constantes_de_la_rfc_sont_appliquees() {
    let mut rtt = Rtt::new();
    rtt.sample(100_000, 0, 0);
    // Second échantillon, sans délai à retirer.
    rtt.sample(200_000, 0, 0);
    // écart = |100000 - 200000| = 100000
    // variance = (50000*3 + 100000)/4 = 62500
    // moyenne  = (100000*7 + 200000)/8 = 112500
    assert_eq!(rtt.variance(), 62_500);
    assert_eq!(rtt.smoothed(), 112_500);
    assert_eq!(rtt.min(), 100_000, "le minimum ne se lisse pas");
    assert_eq!(rtt.latest(), 200_000);
}

/// **LE DÉLAI DU PAIR SE RETIRE, PARCE QUE CE N'EST PAS DE LA LATENCE.**
#[test]
fn le_delai_annonce_se_retire() {
    let mut rtt = Rtt::new();
    rtt.sample(100_000, 0, 1_000_000);
    // 300 ms mesurées, dont 50 ms d'attente chez le pair : 250 ms de réseau.
    rtt.sample(300_000, 50_000, 1_000_000);
    // écart = |100000 - 250000| = 150000 ; variance = (50000*3+150000)/4 = 75000
    assert_eq!(rtt.variance(), 75_000);
    // moyenne = (100000*7 + 250000)/8 = 118750
    assert_eq!(rtt.smoothed(), 118_750);
}

/// **LE DÉLAI EST BORNÉ PAR CE QUE LE PAIR A PROMIS.** Un pair qui annoncerait
/// un délai énorme ferait croire à un réseau instantané — et l'on
/// retransmettrait tout, tout le temps.
#[test]
fn un_delai_au_dela_de_ce_qui_fut_promis_se_borne() {
    let mut menteur = Rtt::new();
    menteur.sample(100_000, 0, 25_000);
    // Il annonce 200 ms d'attente pour un maximum promis de 25 ms.
    menteur.sample(300_000, 200_000, 25_000);

    let mut honnete = Rtt::new();
    honnete.sample(100_000, 0, 25_000);
    honnete.sample(300_000, 25_000, 25_000);

    assert_eq!(
        menteur, honnete,
        "le mensonge n'a rien changé : le délai est borné"
    );
}

/// **ON NE RETIRE PAS LE DÉLAI SI CELA DESCEND SOUS LE MINIMUM OBSERVÉ** (§5.3).
/// La correction dirait sinon que le réseau va plus vite que tout ce qu'on a
/// jamais mesuré.
#[test]
fn une_correction_sous_le_minimum_ne_s_applique_pas() {
    let mut rtt = Rtt::new();
    rtt.sample(100_000, 0, 1_000_000);
    // 110 ms mesurées, 50 ms de délai annoncé : 60 ms, sous le minimum de 100.
    rtt.sample(110_000, 50_000, 1_000_000);
    // La correction est écartée : l'échantillon vaut 110 000 tel quel.
    // écart = |100000 - 110000| = 10000 ; variance = (50000*3+10000)/4 = 40000
    assert_eq!(rtt.variance(), 40_000);
    // moyenne = (100000*7 + 110000)/8 = 101250
    assert_eq!(rtt.smoothed(), 101_250);
    assert_eq!(rtt.min(), 100_000);
}

/// **L'ORDRE DE §5.3 COMPTE** : le minimum se met à jour sur l'échantillon BRUT,
/// avant toute correction. L'inverse ferait juger une correction avec un minimum
/// qu'elle vient elle-même d'abaisser.
#[test]
fn le_minimum_se_met_a_jour_avant_la_correction() {
    let mut rtt = Rtt::new();
    rtt.sample(100_000, 0, 1_000_000);
    // Un échantillon plus court que le minimum : il devient le minimum, et la
    // correction se juge alors contre LUI.
    rtt.sample(40_000, 30_000, 1_000_000);
    assert_eq!(rtt.min(), 40_000, "le brut a fixé le minimum");
    // 40 000 >= 40 000 + 30 000 est faux : la correction est écartée.
    // écart = |100000 - 40000| = 60000 ; variance = (50000*3+60000)/4 = 52500
    assert_eq!(rtt.variance(), 52_500);
}

/// **LE DÉLAI DOUBLE À CHAQUE ESSAI** (§6.2.1) : sans ce repli, la panne d'un
/// serveur deviendrait une inondation du réseau.
#[test]
fn le_delai_double_a_chaque_essai() {
    let mut rtt = Rtt::new();
    rtt.sample(100_000, 0, 0);
    // pto = smoothed + max(4*variance, granularité) + délai maximal
    //     = 100000 + max(200000, 1000) + 25000 = 325000
    let base = rtt.pto(25_000, 0);
    assert_eq!(base, 325_000);
    assert_eq!(rtt.pto(25_000, 1), 650_000);
    assert_eq!(rtt.pto(25_000, 2), 1_300_000);
    assert_eq!(rtt.pto(25_000, 3), 2_600_000);
}

/// **LA GRANULARITÉ EST UN PLANCHER** : en deçà, le système ne sait pas mesurer,
/// et une temporisation plus courte se déclencherait sur le bruit de
/// l'ordonnanceur.
#[test]
fn la_granularite_est_un_plancher() {
    let mut rtt = Rtt::new();
    // Un aller-retour de deux microsecondes : quatre fois la variance vaut
    // quatre microsecondes, sous la granularité.
    rtt.sample(2, 0, 0);
    assert_eq!(rtt.variance(), 1);
    assert_eq!(rtt.pto(0, 0), 2_u64.saturating_add(GRANULARITY_US));
}

/// **LE REPLI SATURE PLUTÔT QUE DE DÉBORDER.** Un décalage rendrait un délai NUL
/// au moment précis où l'on voulait attendre.
#[test]
fn un_repli_immense_sature() {
    let rtt = Rtt::new();
    for essais in [64_u32, 1_000, u32::MAX] {
        assert_eq!(rtt.pto(0, essais), u64::MAX, "{essais}");
    }
    // Et il croît sans jamais retomber.
    let mut precedent = 0_u64;
    for essais in 0..40_u32 {
        let delai = rtt.pto(0, essais);
        assert!(delai >= precedent, "le délai a reculé à l'essai {essais}");
        precedent = delai;
    }
}

/// **LE DÉLAI D'ACQUITTEMENT SE MULTIPLIE, ET LE PRODUIT PEUT DÉBORDER.** Un
/// décalage jetterait les bits qui sortent sans rien dire — c'est le défaut
/// qu'on avait écrit dans HPACK, et qu'un test avait trouvé.
#[test]
fn le_delai_d_acquittement_se_decode_ou_se_refuse() {
    assert_eq!(decode_ack_delay(1_000, 3).expect("lisible"), 8_000);
    assert_eq!(decode_ack_delay(0, 20).expect("lisible"), 0);
    assert_eq!(
        decode_ack_delay(1, ACK_DELAY_EXPONENT_MAX).expect("lisible"),
        1 << 20
    );

    // §18.2 : au-delà de vingt, l'exposant n'est pas licite.
    for exposant in [ACK_DELAY_EXPONENT_MAX.saturating_add(1), 64, u32::MAX] {
        let issue = decode_ack_delay(1, exposant).expect_err("hors borne");
        assert_eq!(issue.reason(), Reason::BadFrameField, "{exposant}");
    }
    // Et un produit qui déborde se refuse plutôt que de se tronquer.
    let issue = decode_ack_delay(u64::MAX, 1).expect_err("il déborde");
    assert_eq!(issue.reason(), Reason::BadFrameField);
}
