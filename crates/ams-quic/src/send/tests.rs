// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que l'émission d'un flux a le droit de faire.

use ams_proto_quic::TransportError;

use super::{Send, SendState};
use crate::error::Reason;
use crate::plages::HOLES_MAX;

/// Un flux neuf n'a rien émis.
#[test]
fn un_flux_neuf_n_a_rien_emis() {
    let flux = Send::new(100);
    assert_eq!(flux.state(), SendState::Ready);
    assert_eq!(flux.offset(), 0);
    assert_eq!(flux.limit(), 100);
    assert_eq!(flux.credit(), 100);
    assert_eq!(flux.final_size(), None);
    assert_eq!(flux.stop_sending(), None);
    assert_eq!(flux.first_unacked(), 0);
    assert!(!flux.en_attente());
    assert!(!flux.blocked());
    assert!(flux.state().ouvert());
    assert!(!flux.state().fini());
}

/// **LES DEUX CRÉDITS SE CUMULENT SANS SE REMPLACER** (§4.1) : c'est le plus
/// petit des deux qui décide.
#[test]
fn c_est_le_plus_petit_des_deux_credits_qui_decide() {
    let mut flux = Send::new(100);
    assert_eq!(flux.allowed(1_000), 100, "le flux borne");
    assert_eq!(flux.allowed(30), 30, "la connexion borne");

    flux.on_sent(40, false).expect("sous la limite");
    assert_eq!(flux.credit(), 60);
    assert_eq!(flux.allowed(1_000), 60);

    // **UN FLUX FERMÉ N'ÉMET PLUS RIEN, QUEL QUE SOIT LE CRÉDIT.**
    flux.on_sent(0, true).expect("le `FIN` passe");
    assert_eq!(flux.allowed(1_000), 0);
}

/// Ce qui part avance le décalage, et l'on sait où écrire la trame suivante.
#[test]
fn ce_qui_part_avance_le_decalage() {
    let mut flux = Send::new(100);
    assert_eq!(flux.on_sent(10, false), Ok(0));
    assert_eq!(flux.state(), SendState::Send);
    assert_eq!(flux.on_sent(5, false), Ok(10));
    assert_eq!(flux.offset(), 15);
    assert!(flux.en_attente(), "rien n'est encore accusé");
}

/// **ÉMETTRE AU-DELÀ DE CE QUI NOUS EST OUVERT EST NOTRE FAUTE**, et la rendre
/// la fait voir en essai plutôt qu'en production.
#[test]
fn emettre_au_dela_de_ce_qui_est_ouvert_se_refuse() {
    let mut flux = Send::new(10);
    let issue = flux.on_sent(11, false).expect_err("au-delà");
    assert_eq!(issue.reason(), Reason::SendOverflow);
    assert_eq!(issue.code(), Some(TransportError::InternalError));
    assert_eq!(flux.offset(), 0, "rien n'est parti");
    // La limite elle-même passe.
    assert_eq!(flux.on_sent(10, false), Ok(0));
    assert_eq!(flux.credit(), 0);
}

/// **UN `STREAM_DATA_BLOCKED` NE SE DIT QUE SI L'ON EST VRAIMENT BLOQUÉ**
/// (§19.13) : le dire autrement serait du bruit.
#[test]
fn on_ne_se_dit_bloque_que_si_on_l_est() {
    let mut flux = Send::new(10);
    assert!(!flux.blocked());
    flux.on_sent(10, false).expect("sous la limite");
    assert!(flux.blocked(), "le robinet est fermé");

    // Le pair rouvre.
    flux.set_limit(20);
    assert!(!flux.blocked());
    assert_eq!(flux.credit(), 10);

    // Et un flux terminé n'est pas bloqué : il n'a plus rien à envoyer.
    flux.on_sent(10, true).expect("le `FIN` passe");
    assert!(!flux.blocked());
}

/// **UNE LIMITE PLUS BASSE N'EST PAS UNE FAUTE, ET N'A PAS D'EFFET** (§4.1).
#[test]
fn une_limite_plus_basse_n_a_pas_d_effet() {
    let mut flux = Send::new(100);
    flux.set_limit(50);
    assert_eq!(flux.limit(), 100);
    flux.set_limit(150);
    assert_eq!(flux.limit(), 150);
}

/// **UN FLUX N'EST FINI QUE QUAND TOUT EST ACQUITTÉ**, `FIN` compris (§3.1).
#[test]
fn un_flux_n_est_fini_que_quand_tout_est_acquitte() {
    let mut flux = Send::new(100);
    flux.on_sent(10, false).expect("sous la limite");
    flux.on_sent(10, true).expect("le `FIN` passe");
    assert_eq!(flux.state(), SendState::DataSent);
    assert_eq!(flux.final_size(), Some(20));
    assert!(!flux.state().ouvert());

    // Le second morceau est accusé le premier : il reste un trou.
    flux.on_acked(10, 10).expect("de la place");
    assert_eq!(flux.state(), SendState::DataSent, "il manque le début");
    assert_eq!(flux.first_unacked(), 0);
    assert!(flux.en_attente());

    flux.on_acked(0, 10).expect("de la place");
    assert_eq!(flux.state(), SendState::DataRecvd);
    assert_eq!(flux.first_unacked(), 20);
    assert!(!flux.en_attente());
    assert!(flux.state().fini());
}

/// Un flux vide se termine dès que son `FIN` est accusé.
#[test]
fn un_flux_vide_se_termine() {
    let mut flux = Send::new(100);
    flux.on_sent(0, true).expect("le `FIN` passe");
    assert_eq!(
        flux.state(),
        SendState::DataRecvd,
        "il n'y avait rien à accuser"
    );
}

/// **ON N'ÉMET PLUS RIEN APRÈS LE `FIN`** : deux tailles finales se
/// contrediraient, et §4.5 le refuse à la réception.
#[test]
fn on_n_emet_plus_rien_apres_le_fin() {
    let mut flux = Send::new(100);
    flux.on_sent(10, true).expect("le `FIN` passe");
    let issue = flux.on_sent(1, false).expect_err("le flux est clos");
    assert_eq!(issue.reason(), Reason::SendClosed);
    assert_eq!(flux.offset(), 10);
}

/// **LA TAILLE FINALE D'UNE ANNULATION EST CE QU'ON A DÉJÀ ÉMIS** (§4.5).
#[test]
fn une_annulation_declare_ce_qu_on_a_emis() {
    let mut flux = Send::new(100);
    flux.on_sent(30, false).expect("sous la limite");
    assert_eq!(flux.reset(), Ok(30));
    assert_eq!(flux.state(), SendState::ResetSent);
    assert_eq!(flux.final_size(), Some(30));

    // Plus un octet ne part.
    assert_eq!(
        flux.on_sent(1, false).expect_err("annulé").reason(),
        Reason::SendClosed
    );
    // Et les acquittements de données ne comptent plus.
    flux.on_acked(0, 30).expect("de la place");
    assert_eq!(flux.state(), SendState::ResetSent);

    // Une retransmission du `RESET_STREAM` redit la même taille.
    assert_eq!(flux.reset(), Ok(30));
    flux.on_reset_acked();
    assert_eq!(flux.state(), SendState::ResetRecvd);
    assert!(flux.state().fini());
    assert_eq!(flux.reset(), Ok(30), "et encore la même");
    // Un second accusé ne fait rien.
    flux.on_reset_acked();
    assert_eq!(flux.state(), SendState::ResetRecvd);
}

/// **UN FLUX ENTIÈREMENT LIVRÉ NE S'ANNULE PLUS** : le dire au pair le ferait
/// douter de ce qu'il a déjà remis à son application.
#[test]
fn un_flux_livre_ne_s_annule_plus() {
    let mut flux = Send::new(100);
    flux.on_sent(10, true).expect("le `FIN` passe");
    flux.on_acked(0, 10).expect("de la place");
    assert_eq!(flux.state(), SendState::DataRecvd);
    assert_eq!(
        flux.reset().expect_err("trop tard").reason(),
        Reason::SendClosed
    );
}

/// **UN `STOP_SENDING` N'EST PAS UNE FERMETURE, C'EST UNE DEMANDE** (§3.5) : il
/// peut croiser sur le fil le `FIN` qui la rendait sans objet.
#[test]
fn un_stop_sending_est_une_demande() {
    let mut flux = Send::new(100);
    flux.on_sent(10, false).expect("sous la limite");
    flux.on_stop_sending(0x0102);
    assert_eq!(flux.stop_sending(), Some(0x0102));
    // Le flux reste ouvert : c'est à l'appelant de décider.
    assert!(flux.state().ouvert());
    assert_eq!(flux.reset(), Ok(10), "et il décide d'annuler");

    // Sur un flux déjà clos, la demande est sans objet.
    let mut autre = Send::new(100);
    autre.on_sent(0, true).expect("le `FIN` passe");
    autre.on_stop_sending(7);
    assert_eq!(autre.stop_sending(), None);
}

/// **OUBLIER UN ACQUITTEMENT FERAIT RENVOYER SANS FIN CE QUE LE PAIR A DÉJÀ** :
/// quand la place manque, on le dit.
#[test]
fn la_place_qui_manque_pour_les_acquittements_se_dit() {
    let mut flux = Send::new(10_000);
    flux.on_sent(1_000, false).expect("sous la limite");
    for rang in 0..HOLES_MAX {
        let decalage = u64::try_from(rang).expect("court").saturating_mul(2);
        assert_eq!(flux.on_acked(decalage, 1), Ok(()), "morceau {rang}");
    }
    let trop = u64::try_from(HOLES_MAX).expect("court").saturating_mul(2);
    let issue = flux.on_acked(trop, 1).expect_err("un morceau de trop");
    assert_eq!(issue.reason(), Reason::TooManyHoles);
}
