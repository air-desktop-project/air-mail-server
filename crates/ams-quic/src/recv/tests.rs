// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que la réception d'un flux a le droit de faire.

use ams_proto_quic::TransportError;

use super::{Recv, RecvState};
use crate::error::Reason;
use crate::plages::HOLES_MAX;

/// Une fenêtre de la taille de la limite annoncée.
const FENETRE: usize = 64;

/// Un flux neuf, et sa fenêtre.
fn neuf() -> (Recv, [u8; FENETRE]) {
    (Recv::new(FENETRE as u64), [0_u8; FENETRE])
}

/// Lit tout ce qui est prêt, et le rend.
fn lire(flux: &mut Recv, fenetre: &mut [u8]) -> std::vec::Vec<u8> {
    let mut vers = [0_u8; FENETRE];
    let pris = flux.read(fenetre, &mut vers);
    vers.get(..pris).unwrap_or_default().to_vec()
}

/// Un flux neuf n'a rien reçu.
#[test]
fn un_flux_neuf_n_a_rien_recu() {
    let (flux, _) = neuf();
    assert_eq!(flux.state(), RecvState::Recv);
    assert_eq!(flux.largest(), 0);
    assert_eq!(flux.read_offset(), 0);
    assert_eq!(flux.readable(), 0);
    assert_eq!(flux.final_size(), None);
    assert_eq!(flux.limit(), FENETRE as u64);
    assert!(flux.state().accepte());
    assert!(!flux.state().fini());
}

/// **UN FLUX ARRIVE DANS LE DÉSORDRE, ET SE LIT DANS L'ORDRE.** C'est tout le
/// travail de ce module.
#[test]
fn le_desordre_se_lit_dans_l_ordre() {
    let (mut flux, mut fenetre) = neuf();
    // Les octets 5..10 arrivent avant les 0..5.
    flux.on_stream(5, b"monde", false, &mut fenetre)
        .expect("licite");
    assert_eq!(flux.readable(), 0, "il manque le début");
    assert_eq!(lire(&mut flux, &mut fenetre), b"");
    assert_eq!(flux.largest(), 10);

    flux.on_stream(0, b"salut", false, &mut fenetre)
        .expect("licite");
    assert_eq!(flux.readable(), 10, "le trou est comblé");
    assert_eq!(lire(&mut flux, &mut fenetre), b"salutmonde");
    assert_eq!(flux.read_offset(), 10);
    assert_eq!(flux.readable(), 0);
}

/// **CE QUE LE CONTRÔLE DE CONNEXION COMPTE, C'EST LE PLUS GRAND DÉCALAGE**
/// (§4.1), et non le nombre d'octets reçus : compter les octets ferait payer
/// deux fois une retransmission.
#[test]
fn c_est_le_plus_grand_decalage_qui_compte() {
    let (mut flux, mut fenetre) = neuf();
    let monte = flux
        .on_stream(0, b"salut", false, &mut fenetre)
        .expect("licite");
    assert_eq!(monte, 5);

    // Les mêmes octets, à nouveau : rien de neuf pour le contrôle de flux.
    let monte = flux
        .on_stream(0, b"salut", false, &mut fenetre)
        .expect("licite");
    assert_eq!(monte, 0, "une retransmission ne coûte rien de plus");

    // Un morceau qui déborde : seul le surplus compte.
    let monte = flux
        .on_stream(3, b"utmonde", false, &mut fenetre)
        .expect("licite");
    assert_eq!(monte, 5, "de cinq à dix");
    assert_eq!(flux.largest(), 10);
}

/// **AU-DELÀ DE CE QU'ON A ANNONCÉ, C'EST UNE FAUTE** (§4.1) — et le pair ne
/// peut pas l'ignorer, puisque c'est nous qui avons annoncé.
#[test]
fn au_dela_de_la_limite_on_refuse() {
    let (mut flux, mut fenetre) = neuf();
    let trop = std::vec![0x41_u8; FENETRE + 1];
    let issue = flux
        .on_stream(0, &trop, false, &mut fenetre)
        .expect_err("au-delà");
    assert_eq!(issue.reason(), Reason::FlowControl);
    assert_eq!(issue.code(), Some(TransportError::FlowControlError));
    assert!(!issue.se_jette());

    // La limite elle-même passe.
    let pile = std::vec![0x41_u8; FENETRE];
    assert!(flux.on_stream(0, &pile, false, &mut fenetre).is_ok());
}

/// **UNE LIMITE PLUS BASSE N'EST PAS UNE FAUTE, ET N'A PAS D'EFFET** (§4.1). La
/// refuser fermerait des connexions pour un `MAX_STREAM_DATA` arrivé dans le
/// désordre.
#[test]
fn une_limite_plus_basse_n_a_pas_d_effet() {
    let (mut flux, _) = neuf();
    flux.set_limit(FENETRE as u64 - 10);
    assert_eq!(flux.limit(), FENETRE as u64, "elle n'a pas baissé");
    flux.set_limit(FENETRE as u64 + 100);
    assert_eq!(flux.limit(), FENETRE as u64 + 100);
}

/// **LE `FIN` DIT LA TAILLE FINALE**, et l'état la suit (§3.2).
#[test]
fn le_fin_fait_avancer_l_etat() {
    let (mut flux, mut fenetre) = neuf();
    // Le `FIN` arrive AVANT ce qui le précède : la taille est connue, mais il
    // manque des octets.
    flux.on_stream(5, b"monde", true, &mut fenetre)
        .expect("licite");
    assert_eq!(flux.state(), RecvState::SizeKnown);
    assert_eq!(flux.final_size(), Some(10));

    flux.on_stream(0, b"salut", false, &mut fenetre)
        .expect("licite");
    assert_eq!(flux.state(), RecvState::DataRecvd, "tout est là");

    assert_eq!(lire(&mut flux, &mut fenetre), b"salutmonde");
    assert_eq!(flux.state(), RecvState::DataRead);
    assert!(flux.state().fini());
    assert!(!flux.state().accepte());
}

/// Un flux vide se termine aussi.
#[test]
fn un_flux_vide_se_termine() {
    let (mut flux, mut fenetre) = neuf();
    flux.on_stream(0, b"", true, &mut fenetre).expect("licite");
    assert_eq!(flux.final_size(), Some(0));
    assert_eq!(
        flux.state(),
        RecvState::DataRead,
        "il n'y avait rien à lire"
    );
}

/// **UNE TAILLE FINALE NE CHANGE PAS** (§4.5). C'est la même contradiction
/// qu'une double longueur en HTTP/1.1 : deux façons de savoir où un flux
/// s'arrête, et rien pour les départager.
#[test]
fn une_taille_finale_ne_change_pas() {
    let (mut flux, mut fenetre) = neuf();
    flux.on_stream(0, b"salut", true, &mut fenetre)
        .expect("licite");

    // Un second `FIN` à une autre taille.
    let issue = flux
        .on_stream(0, b"salutmonde", true, &mut fenetre)
        .expect_err("elle change");
    assert_eq!(issue.reason(), Reason::FinalSize);
    assert_eq!(issue.code(), Some(TransportError::FinalSizeError));

    // Des octets AU-DELÀ de la taille finale.
    let issue = flux
        .on_stream(5, b"monde", false, &mut fenetre)
        .expect_err("au-delà");
    assert_eq!(issue.reason(), Reason::FinalSize);

    // Un `RESET_STREAM` qui dit autre chose — sous la limite, sans quoi ce
    // serait le contrôle de flux qui parlerait le premier.
    let issue = flux.on_reset(9).expect_err("elle change");
    assert_eq!(issue.reason(), Reason::FinalSize);

    // Le même `FIN`, en revanche, est une retransmission ordinaire.
    assert!(flux.on_stream(0, b"salut", true, &mut fenetre).is_ok());
    assert!(
        flux.on_reset(5).is_ok(),
        "la même taille, par une autre trame"
    );
}

/// **UN FLUX ANNULÉ COMPTE SA TAILLE FINALE DANS LE CONTRÔLE DE CONNEXION**
/// (§4.5), même si l'on n'a jamais reçu ces octets.
#[test]
fn un_flux_annule_compte_sa_taille_finale() {
    let (mut flux, mut fenetre) = neuf();
    flux.on_stream(0, b"sal", false, &mut fenetre)
        .expect("licite");
    assert_eq!(flux.largest(), 3);

    let monte = flux.on_reset(20).expect("licite");
    assert_eq!(monte, 17, "de trois à vingt");
    assert_eq!(flux.state(), RecvState::ResetRecvd);
    assert_eq!(flux.final_size(), Some(20));

    // **`Reset Read` EST UN ÉTAT SÉPARÉ** (§3.2) : l'application décide quand
    // elle prend acte.
    assert!(!flux.state().fini());
    flux.read_reset();
    assert_eq!(flux.state(), RecvState::ResetRead);
    assert!(flux.state().fini());

    // Et un second `RESET_STREAM` ne fait rien.
    assert_eq!(flux.on_reset(20).expect("licite"), 0);
}

/// **UNE FENÊTRE TROP COURTE PERDRAIT DES OCTETS EN SILENCE.** L'appelant doit
/// fournir une fenêtre aussi grande que la limite annoncée ; ne pas le vérifier
/// ferait de cette règle une intention, et le manquement ne se saurait qu'en
/// production, sous la forme d'un flux qui se fige.
#[test]
fn une_fenetre_trop_courte_se_refuse() {
    let mut flux = Recv::new(FENETRE as u64);
    let mut trop_courte = [0_u8; FENETRE - 1];
    // Ce qui tient encore passe.
    flux.on_stream(0, b"salut", false, &mut trop_courte)
        .expect("cela tient");
    // Ce qui déborde d'un octet se dit.
    let pile = std::vec![0x41_u8; FENETRE];
    let issue = flux
        .on_stream(0, &pile, false, &mut trop_courte)
        .expect_err("un octet de trop");
    assert_eq!(issue.reason(), Reason::WindowTooSmall);
    // **ET LE REFUS NE LAISSE PAS DE TRACE.**
    assert_eq!(flux.largest(), 5);
}

/// **UNE ANNULATION NE SE DÉFAIT PAS EN LISANT** : des octets peuvent être
/// arrivés avant le `RESET_STREAM`, et les lire ne doit pas ramener le flux dans
/// un état où il se terminerait normalement.
#[test]
fn lire_ne_defait_pas_une_annulation() {
    let (mut flux, mut fenetre) = neuf();
    flux.on_stream(0, b"salut", false, &mut fenetre)
        .expect("licite");
    flux.on_reset(5).expect("licite");
    assert_eq!(flux.state(), RecvState::ResetRecvd);
    // Ce qui était arrivé est toujours là, et se lit.
    assert_eq!(lire(&mut flux, &mut fenetre), b"salut");
    assert_eq!(
        flux.state(),
        RecvState::ResetRecvd,
        "le flux reste annulé, et non terminé"
    );
    flux.read_reset();
    assert_eq!(flux.state(), RecvState::ResetRead);
}

/// **PRENDRE ACTE D'UNE ANNULATION QUI N'A PAS EU LIEU NE FAIT RIEN** :
/// l'appelant tient un seul jeu de flux, et n'a pas à savoir lequel a été annulé
/// avant de le lui demander.
#[test]
fn prendre_acte_d_une_annulation_absente_ne_fait_rien() {
    let (mut flux, mut fenetre) = neuf();
    flux.read_reset();
    assert_eq!(flux.state(), RecvState::Recv);
    flux.on_stream(0, b"salut", true, &mut fenetre)
        .expect("licite");
    flux.read_reset();
    assert_eq!(flux.state(), RecvState::DataRecvd);
}

/// **UN FLUX ANNULÉ N'ACCEPTE PLUS RIEN, ET LE DIRE N'EST PAS UNE FAUTE** : la
/// trame a pu croiser notre `STOP_SENDING` sur le fil.
#[test]
fn un_flux_annule_n_accepte_plus_rien() {
    let (mut flux, mut fenetre) = neuf();
    flux.on_reset(10).expect("licite");
    let monte = flux
        .on_stream(0, b"salut", false, &mut fenetre)
        .expect("ce n'est pas une faute");
    assert_eq!(monte, 0);
    assert_eq!(flux.state(), RecvState::ResetRecvd);
}

/// **AU-DELÀ DE LA LIMITE, UN `RESET_STREAM` SE REFUSE AUSSI** : sa taille
/// finale consomme le même crédit que les octets.
#[test]
fn un_reset_hors_limite_se_refuse() {
    let (mut flux, _) = neuf();
    let issue = flux.on_reset(FENETRE as u64 + 1).expect_err("au-delà");
    assert_eq!(issue.reason(), Reason::FlowControl);
}

/// **ON NE PEUT PAS RETIRER UN ACQUITTEMENT** : au-delà de ce qu'on retient de
/// désordre, on le dit et l'on ferme, plutôt que de perdre des octets en
/// silence.
#[test]
fn au_dela_du_desordre_qu_on_retient_on_ferme() {
    let mut flux = Recv::new(4_096);
    let mut fenetre = [0_u8; 4_096];
    // Un octet sur deux : autant de trous que d'octets.
    for rang in 0..HOLES_MAX {
        let decalage = u64::try_from(rang).expect("court").saturating_mul(2);
        assert!(
            flux.on_stream(decalage, b"x", false, &mut fenetre).is_ok(),
            "trou {rang}"
        );
    }
    let trop = u64::try_from(HOLES_MAX).expect("court").saturating_mul(2);
    let avant = flux.largest();
    let issue = flux
        .on_stream(trop, b"x", false, &mut fenetre)
        .expect_err("un trou de trop");
    assert_eq!(issue.reason(), Reason::TooManyHoles);
    // **ET LE REFUS NE LAISSE PAS DE TRACE** : un plus grand décalage qui aurait
    // monté laisserait le contrôle de connexion désaccordé du flux.
    assert_eq!(flux.largest(), avant);
    // **C'EST NOTRE BORNE, PAS LA SIENNE** : on ne la lui reproche pas comme une
    // faute de contrôle de flux.
    assert_eq!(issue.code(), Some(TransportError::InternalError));
}

/// Combler les trous les fait disparaître, et l'on peut recommencer.
#[test]
fn combler_les_trous_libere_la_place() {
    let mut flux = Recv::new(4_096);
    let mut fenetre = [0_u8; 4_096];
    for rang in 0..HOLES_MAX {
        let decalage = u64::try_from(rang).expect("court").saturating_mul(2);
        flux.on_stream(decalage, b"x", false, &mut fenetre)
            .expect("licite");
    }
    // On comble tout : les plages se réunissent en une seule.
    for rang in 0..HOLES_MAX {
        let decalage = u64::try_from(rang)
            .expect("court")
            .saturating_mul(2)
            .saturating_add(1);
        flux.on_stream(decalage, b"y", false, &mut fenetre)
            .expect("licite");
    }
    let tout = flux.readable();
    assert_eq!(tout, u64::try_from(HOLES_MAX).expect("court") * 2);
    // Et il y a de nouveau de la place pour du désordre.
    let loin = 1_000_u64;
    assert!(flux.on_stream(loin, b"z", false, &mut fenetre).is_ok());
}

/// **LA FENÊTRE GLISSE** : ce qu'on lit s'en va, et le reste remonte.
#[test]
fn la_fenetre_glisse_a_la_lecture() {
    let (mut flux, mut fenetre) = neuf();
    flux.on_stream(0, b"salut", false, &mut fenetre)
        .expect("licite");
    // On ne prend que trois octets.
    let mut vers = [0_u8; 3];
    let pris = flux.read(&mut fenetre, &mut vers);
    assert_eq!(pris, 3);
    assert_eq!(&vers, b"sal");
    assert_eq!(flux.read_offset(), 3);
    assert_eq!(flux.readable(), 2, "il reste `ut`");
    assert_eq!(lire(&mut flux, &mut fenetre), b"ut");

    // Et la suite du flux se range à la bonne place.
    flux.on_stream(5, b"monde", false, &mut fenetre)
        .expect("licite");
    assert_eq!(lire(&mut flux, &mut fenetre), b"monde");
}

/// Des octets déjà lus qui reviennent ne réécrivent rien.
#[test]
fn ce_qui_est_deja_lu_ne_se_reecrit_pas() {
    let (mut flux, mut fenetre) = neuf();
    flux.on_stream(0, b"salut", false, &mut fenetre)
        .expect("licite");
    assert_eq!(lire(&mut flux, &mut fenetre), b"salut");

    // La même trame revient, puis la suite.
    flux.on_stream(0, b"salut", false, &mut fenetre)
        .expect("licite");
    assert_eq!(flux.readable(), 0, "rien de neuf");
    flux.on_stream(0, b"salutmonde", false, &mut fenetre)
        .expect("licite");
    assert_eq!(lire(&mut flux, &mut fenetre), b"monde");
}

/// Une lecture dans un tampon plus petit que ce qui est prêt en prend ce qu'elle
/// peut.
#[test]
fn une_lecture_partielle_prend_ce_qu_elle_peut() {
    let (mut flux, mut fenetre) = neuf();
    flux.on_stream(0, b"salutmonde", true, &mut fenetre)
        .expect("licite");
    assert_eq!(flux.state(), RecvState::DataRecvd);
    let mut vers = [0_u8; 4];
    assert_eq!(flux.read(&mut fenetre, &mut vers), 4);
    assert_eq!(&vers, b"salu");
    assert_eq!(flux.state(), RecvState::DataRecvd, "il en reste");
    assert_eq!(lire(&mut flux, &mut fenetre), b"tmonde");
    assert_eq!(flux.state(), RecvState::DataRead);
}
