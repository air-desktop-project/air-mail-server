// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que le contrôle de connexion et la concurrence ont le droit de faire.

use ams_proto_quic::{Directional, Initiator, StreamId, TransportError};

use super::{Concurrence, Concurrences, Flow};
use crate::error::Reason;

/// Un compteur neuf n'a rien consommé.
#[test]
fn un_compteur_neuf_n_a_rien_consomme() {
    let flux = Flow::receiving(1_000);
    assert_eq!(flux.limit(), 1_000);
    assert_eq!(flux.used(), 0);
    assert_eq!(flux.available(), 1_000);
    assert!(!flux.blocked());
}

/// **LA MÊME ARITHMÉTIQUE, DEUX FAUTES DIFFÉRENTES** : dépasser ce qu'on a
/// annoncé est la faute du pair, dépasser ce qu'il a annoncé est la nôtre.
#[test]
fn le_meme_depassement_a_deux_fautes() {
    let mut recu = Flow::receiving(10);
    let issue = recu.consume(11).expect_err("au-delà");
    assert_eq!(issue.reason(), Reason::FlowControl);
    assert_eq!(issue.code(), Some(TransportError::FlowControlError));

    let mut emis = Flow::sending(10);
    let issue = emis.consume(11).expect_err("au-delà");
    assert_eq!(issue.reason(), Reason::SendOverflow);
    assert_eq!(issue.code(), Some(TransportError::InternalError));

    // **ET RIEN N'EST CONSOMMÉ QUAND ON REFUSE.**
    assert_eq!(recu.used(), 0);
    assert_eq!(emis.used(), 0);
}

/// Ce qui passe se cumule, et la limite elle-même passe.
#[test]
fn ce_qui_passe_se_cumule() {
    let mut flux = Flow::receiving(10);
    flux.consume(4).expect("sous la limite");
    flux.consume(6).expect("pile la limite");
    assert_eq!(flux.used(), 10);
    assert_eq!(flux.available(), 0);
    assert!(flux.blocked());
    assert!(flux.consume(1).is_err());
    // Une progression nulle passe toujours : une retransmission n'apporte rien.
    assert!(flux.consume(0).is_ok());
}

/// **UNE LIMITE PLUS BASSE N'EST PAS UNE FAUTE, ET N'A PAS D'EFFET** (§4.1).
#[test]
fn une_limite_plus_basse_n_a_pas_d_effet() {
    let mut flux = Flow::receiving(100);
    flux.set_limit(50);
    assert_eq!(flux.limit(), 100);
    flux.set_limit(150);
    assert_eq!(flux.limit(), 150);
}

/// **ON N'ÉCRIT PAS UN `MAX_DATA` QUI NE DIT RIEN DE NEUF.**
#[test]
fn on_n_annonce_que_ce_qui_ajoute() {
    let mut flux = Flow::receiving(100);
    assert_eq!(flux.grant(50), None, "il en reste assez");
    flux.consume(80).expect("sous la limite");
    assert_eq!(flux.grant(20), None, "il en reste pile assez");
    assert_eq!(
        flux.grant(50),
        Some(130),
        "quatre-vingts consommés, plus cinquante"
    );
}

/// Un compte de flux neuf n'en a ouvert aucun.
#[test]
fn un_compte_neuf_n_a_rien_ouvert() {
    let compte = Concurrence::new(3);
    assert_eq!(compte.limit(), 3);
    assert_eq!(compte.next(), 0);
    assert_eq!(compte.available(), 3);
    assert!(!compte.blocked());
}

/// **SEULS LES RANGS STRICTEMENT INFÉRIEURS AU PLAFOND SONT PERMIS** (§4.6).
#[test]
fn le_plafond_borne_les_rangs() {
    let mut compte = Concurrence::new(3);
    compte.open_remote(0).expect("permis");
    compte.open_remote(2).expect("permis");
    let issue = compte.open_remote(3).expect_err("au-delà");
    assert_eq!(issue.reason(), Reason::StreamLimit);
    assert_eq!(issue.code(), Some(TransportError::StreamLimitError));
}

/// **OUVRIR LE RANG N OUVRE AUSSI TOUS CEUX D'AVANT** (§2.1) : les flux ne
/// s'ouvrent pas dans l'ordre, et compter autrement laisserait des rangs jamais
/// consommés.
#[test]
fn ouvrir_un_rang_ouvre_ceux_d_avant() {
    let mut compte = Concurrence::new(10);
    compte.open_remote(4).expect("permis");
    assert_eq!(compte.next(), 5, "les rangs zéro à quatre sont pris");
    assert_eq!(compte.available(), 5);

    // Un rang déjà couvert ne consomme rien de plus : une trame peut arriver
    // deux fois, et les flux s'ouvrent dans le désordre.
    compte.open_remote(1).expect("permis");
    assert_eq!(compte.next(), 5);
    compte.open_remote(4).expect("permis");
    assert_eq!(compte.next(), 5);
}

/// **UN FLUX FERMÉ NE REND PAS SON RANG** (§4.6) : c'est un `MAX_STREAMS` qui
/// rend du crédit, et lui seul.
#[test]
fn seul_un_max_streams_rend_du_credit() {
    let mut compte = Concurrence::new(2);
    compte.open_remote(0).expect("permis");
    compte.open_remote(1).expect("permis");
    assert!(compte.blocked());

    // **UN `MAX_STREAMS` QUI N'AUGMENTE PAS SE JETTE** (§4.6).
    compte.set_limit(1);
    assert_eq!(compte.limit(), 2);
    compte.set_limit(4);
    assert_eq!(compte.limit(), 4);
    assert_eq!(compte.available(), 2);
    compte.open_remote(2).expect("permis");
}

/// De notre côté, le rang se prend, et le plafond nous arrête.
#[test]
fn on_prend_les_rangs_dans_l_ordre() {
    let mut compte = Concurrence::new(2);
    assert_eq!(compte.open_local(), Ok(0));
    assert_eq!(compte.open_local(), Ok(1));
    // **C'EST NOTRE FAUTE** : il faut attendre un `MAX_STREAMS`.
    let issue = compte.open_local().expect_err("au-delà");
    assert_eq!(issue.reason(), Reason::StreamLimit);
    compte.set_limit(3);
    assert_eq!(compte.open_local(), Ok(2));
}

/// **LES QUATRE COMPTES SONT INDÉPENDANTS** : les confondre laisserait un pair
/// épuiser un crédit accordé pour autre chose.
#[test]
fn les_quatre_comptes_sont_independants() {
    // Nous sommes le serveur : le client ouvre les flux pairs.
    let mut comptes = Concurrences::new(Initiator::Server, (2, 1), (5, 6));
    assert_eq!(comptes.incoming(Directional::Bidirectional).limit(), 2);
    assert_eq!(comptes.incoming(Directional::Unidirectional).limit(), 1);
    assert_eq!(comptes.outgoing(Directional::Bidirectional).limit(), 5);
    assert_eq!(comptes.outgoing(Directional::Unidirectional).limit(), 6);

    let bidi = StreamId::from_index(0, Initiator::Client, Directional::Bidirectional)
        .expect("dans l'espace");
    comptes.seen(bidi).expect("permis");
    assert_eq!(comptes.incoming(Directional::Bidirectional).next(), 1);
    assert_eq!(
        comptes.incoming(Directional::Unidirectional).next(),
        0,
        "l'autre compte n'a pas bougé"
    );

    // Le troisième bidirectionnel du client dépasse ce qu'on a annoncé.
    let trop = StreamId::from_index(2, Initiator::Client, Directional::Bidirectional)
        .expect("dans l'espace");
    assert_eq!(
        comptes.seen(trop).expect_err("au-delà").reason(),
        Reason::StreamLimit
    );

    // Et l'on prend nos propres rangs sur nos propres comptes.
    assert_eq!(
        comptes
            .outgoing_mut(Directional::Unidirectional)
            .open_local(),
        Ok(0)
    );
    assert_eq!(
        comptes
            .outgoing_mut(Directional::Bidirectional)
            .open_local(),
        Ok(0),
        "et l'autre sens a son propre rang"
    );
    comptes
        .incoming_mut(Directional::Unidirectional)
        .set_limit(9);
    assert_eq!(comptes.incoming(Directional::Unidirectional).limit(), 9);
}

/// **UN FLUX QU'ON A OUVERT NE S'OUVRE PAS PAR SA TRAME** : le pair ne peut qu'y
/// répondre, et seulement s'il est bidirectionnel.
#[test]
fn le_pair_ne_reouvre_pas_nos_flux() {
    let mut comptes = Concurrences::new(Initiator::Server, (2, 2), (2, 2));
    // Notre flux bidirectionnel : le pair a le droit d'y répondre.
    let notre_bidi = StreamId::from_index(0, Initiator::Server, Directional::Bidirectional)
        .expect("dans l'espace");
    comptes.seen(notre_bidi).expect("il peut répondre");
    assert_eq!(
        comptes.incoming(Directional::Bidirectional).next(),
        0,
        "cela n'ouvre rien de son côté"
    );

    // **UN FLUX UNIDIRECTIONNEL NE VA QUE DANS UN SENS**, et c'est le nôtre.
    let notre_uni = StreamId::from_index(0, Initiator::Server, Directional::Unidirectional)
        .expect("dans l'espace");
    let issue = comptes.seen(notre_uni).expect_err("à contresens");
    assert_eq!(issue.reason(), Reason::WrongStreamDirection);
    assert_eq!(issue.code(), Some(TransportError::StreamStateError));
}
