// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que les bornes d'usage de §6.6 doivent compter.

use super::Usage;
use crate::error::Reason;
use crate::suite::Suite;

/// **LES BORNES SONT CELLES DE §6.6**, et l'annexe B les démontre.
#[test]
fn les_bornes_sont_celles_de_la_rfc() {
    assert_eq!(Suite::Aes128Gcm.confidentiality_limit(), 1 << 23);
    assert_eq!(Suite::Aes256Gcm.confidentiality_limit(), 1 << 23);
    assert_eq!(Suite::ChaCha20Poly1305.confidentiality_limit(), 1 << 62);
    assert_eq!(Suite::Aes128Gcm.integrity_limit(), 1 << 52);
    assert_eq!(Suite::Aes256Gcm.integrity_limit(), 1 << 52);
    assert_eq!(Suite::ChaCha20Poly1305.integrity_limit(), 1 << 36);

    for suite in [Suite::Aes128Gcm, Suite::Aes256Gcm, Suite::ChaCha20Poly1305] {
        let usage = Usage::new(suite);
        assert_eq!(usage.confidentiality_limit(), suite.confidentiality_limit());
        assert_eq!(usage.integrity_limit(), suite.integrity_limit());
    }
}

/// **ON PEUT DESCENDRE, ET JAMAIS MONTER.** Les bornes de §6.6 ne sont pas des
/// préférences : l'annexe B les démontre, et en demander de plus hautes serait
/// demander à dépasser ce que l'analyse permet.
#[test]
fn les_bornes_se_baissent_et_ne_se_haussent_pas() {
    let suite = Suite::Aes128Gcm;
    let basses = Usage::with_limits(suite, 100, 200);
    assert_eq!(basses.confidentiality_limit(), 100);
    assert_eq!(basses.integrity_limit(), 200);

    let hautes = Usage::with_limits(suite, u64::MAX, u64::MAX);
    assert_eq!(
        hautes.confidentiality_limit(),
        suite.confidentiality_limit()
    );
    assert_eq!(hautes.integrity_limit(), suite.integrity_limit());

    // La borne exacte de la suite passe telle quelle.
    let pile = Usage::with_limits(
        suite,
        suite.confidentiality_limit(),
        suite.integrity_limit(),
    );
    assert_eq!(pile.confidentiality_limit(), suite.confidentiality_limit());
    assert_eq!(pile.integrity_limit(), suite.integrity_limit());
}

/// **DEUX COMPTES, ET ILS NE COMPTENT PAS LA MÊME CHOSE.**
#[test]
fn les_deux_comptes_sont_separes() {
    let mut usage = Usage::new(Suite::Aes128Gcm);
    assert_eq!(usage.sealed(), 0);
    assert_eq!(usage.rejected(), 0);

    usage.on_sealed().expect("sous la borne");
    usage.on_rejected().expect("sous la borne");
    assert_eq!(usage.sealed(), 1);
    assert_eq!(usage.rejected(), 1);
}

/// **SEUL LE COMPTE DES CHIFFRÉS REPART À LA MISE À JOUR** : les essais d'un
/// adversaire ne s'oublient pas parce qu'on a changé de clé.
#[test]
fn la_mise_a_jour_ne_remet_a_zero_que_les_chiffres() {
    let mut usage = Usage::new(Suite::Aes128Gcm);
    for _ in 0..5_u8 {
        usage.on_sealed().expect("sous la borne");
        usage.on_rejected().expect("sous la borne");
    }
    usage.on_key_update();
    assert_eq!(usage.sealed(), 0, "les chiffrés repartent");
    assert_eq!(usage.rejected(), 5, "les refusés se souviennent");
}

/// **ON PRÉVIENT À LA MOITIÉ, ET NON À LA BORNE** : attendre celle-ci
/// laisserait la connexion sans clé utilisable au moment d'en changer.
#[test]
fn on_previent_a_la_moitie() {
    let mut usage = Usage::with_limits(Suite::Aes128Gcm, 100, 100);
    assert!(!usage.should_update());
    for _ in 0..49_u8 {
        usage.on_sealed().expect("sous la borne");
    }
    assert!(!usage.should_update(), "un de trop tôt");
    usage.on_sealed().expect("sous la borne");
    assert!(usage.should_update(), "la moitié est atteinte");
    usage.on_key_update();
    assert!(!usage.should_update());
}

/// **AU-DELÀ DE LA BORNE DE CONFIDENTIALITÉ, ON REFUSE DE CHIFFRER.**
#[test]
fn au_dela_de_la_borne_de_confidentialite_on_refuse() {
    let mut usage = Usage::with_limits(Suite::Aes128Gcm, 3, 1_000);
    for _ in 0..3_u8 {
        usage.on_sealed().expect("sous la borne");
    }
    let issue = usage.on_sealed().expect_err("un de trop");
    assert_eq!(issue.reason(), Reason::AeadLimitReached);
    assert_eq!(
        issue.code(),
        ams_proto_quic::TransportError::AeadLimitReached
    );
    // Et le compte ne recule pas : la connexion reste condamnée.
    assert!(usage.on_sealed().is_err());
}

/// **AU-DELÀ DE LA BORNE D'INTÉGRITÉ, ON FERME.** §6.6 est catégorique : « close
/// the connection […] and not process any more packets ».
#[test]
fn au_dela_de_la_borne_d_integrite_on_ferme() {
    let mut usage = Usage::with_limits(Suite::ChaCha20Poly1305, 1_000, 2);
    usage.on_rejected().expect("sous la borne");
    usage.on_rejected().expect("sous la borne");
    let issue = usage.on_rejected().expect_err("un de trop");
    assert_eq!(issue.reason(), Reason::AeadLimitReached);

    // **UNE MISE À JOUR DE CLÉ NE FAIT PAS OUBLIER LES ESSAIS.**
    usage.on_key_update();
    assert!(usage.on_rejected().is_err(), "les essais se souviennent");
}
