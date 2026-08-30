// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un flux a le droit de faire.

use super::{MAX_CONCURRENT_STREAMS, StreamState, Streams};
use crate::error::{Cause, ErrorCode};
use crate::flow::INITIAL_WINDOW_SIZE;

/// Une connexion neuve.
fn neuve() -> Streams {
    Streams::new(INITIAL_WINDOW_SIZE)
}

/// Un flux s'ouvre, reçoit, se termine et se ferme.
#[test]
fn un_flux_parcourt_ses_etats() {
    let mut flux = neuve();
    assert!(flux.is_empty());
    assert_eq!(flux.last_received(), 0);
    // Oisif : il n'a jamais existé.
    assert_eq!(flux.state(1), None);

    flux.open(1).expect("un impair qui progresse");
    assert_eq!(flux.state(1), Some(StreamState::Open));
    assert_eq!(flux.len(), 1);
    assert_eq!(flux.last_received(), 1);

    flux.consume(1, 1_000).expect("il y a la place");
    assert_eq!(
        flux.window(1).map(|f| f.available()),
        Some(i64::from(INITIAL_WINDOW_SIZE) - 1_000)
    );

    flux.end_remote(1);
    assert_eq!(flux.state(1), Some(StreamState::HalfClosedRemote));

    flux.close(1);
    assert!(flux.is_empty());
    // **FERMÉ, ET NON OISIF** : il est en deçà du plus grand numéro reçu.
    assert_eq!(flux.state(1), Some(StreamState::Closed));
    assert_eq!(flux.state(3), None, "celui-là n'a jamais existé");
}

/// **LES FLUX D'UN CLIENT SONT IMPAIRS, ET LE ZÉRO EST LA CONNEXION** (§5.1.1).
/// Un numéro pair désignerait un flux que seul un serveur ouvre — pour une
/// poussée qu'on ne fait pas.
#[test]
fn un_numero_qui_n_en_est_pas_un_se_refuse() {
    let mut flux = neuve();
    for id in [0_u32, 2, 4, 100, 0x7fff_fffe] {
        let issue = flux.open(id).expect_err("refusé");
        assert_eq!(issue.cause(), Cause::BadStreamId, "{id}");
        assert_eq!(issue.code(), ErrorCode::ProtocolError, "{id}");
        assert!(issue.is_fatal(), "{id}");
    }
    assert!(flux.is_empty());
}

/// **STRICTEMENT SUPÉRIEUR** (§5.1.1) : un numéro réemployé désignerait deux
/// requêtes au même moment, et la réponse de l'une pourrait partir vers l'autre.
#[test]
fn un_numero_qui_ne_progresse_pas_se_refuse() {
    let mut flux = neuve();
    flux.open(5).expect("le premier");
    for id in [1_u32, 3, 5] {
        let issue = flux.open(id).expect_err("refusé");
        assert_eq!(issue.cause(), Cause::BadStreamId, "{id}");
    }
    // Et il progresse encore après une fermeture.
    flux.close(5);
    let issue = flux.open(5).expect_err("réemployé");
    assert_eq!(issue.cause(), Cause::BadStreamId);
    flux.open(7).expect("celui-là progresse");
}

/// **`REFUSED_STREAM` EST UNE PROMESSE** (§8.7) : le client peut réémettre sans
/// risque, parce qu'on n'a rien commencé.
#[test]
fn au_dela_de_ce_qu_on_traite_on_refuse_sans_commencer() {
    let mut flux = neuve();
    for tour in 0..MAX_CONCURRENT_STREAMS {
        let id = tour.saturating_mul(2).saturating_add(1);
        flux.open(id).unwrap_or_else(|_| panic!("{id}"));
    }
    assert_eq!(flux.len(), MAX_CONCURRENT_STREAMS);

    let issue = flux
        .open(MAX_CONCURRENT_STREAMS.saturating_mul(2).saturating_add(1))
        .expect_err("refusé");
    assert_eq!(issue.cause(), Cause::TooManyStreams);
    assert_eq!(issue.code(), ErrorCode::RefusedStream);
    assert!(!issue.is_fatal(), "un flux refusé ne tue pas la connexion");

    // Une place libérée en rend une.
    flux.close(1);
    assert!(
        flux.open(MAX_CONCURRENT_STREAMS.saturating_mul(2).saturating_add(1))
            .is_ok()
    );
}

/// **UN FLUX DONT LE PAIR A FINI NE REÇOIT PLUS** : le tolérer laisserait un
/// pair envoyer deux corps pour une requête.
#[test]
fn ce_qui_arrive_apres_la_fin_se_refuse() {
    let mut flux = neuve();
    flux.open(1).expect("ouvert");
    flux.end_remote(1);

    let issue = flux.consume(1, 1).expect_err("des données après la fin");
    assert_eq!(issue.cause(), Cause::WrongStreamState);
    assert_eq!(issue.code(), ErrorCode::StreamClosed);
    assert!(!issue.is_fatal());

    // **RÉPÉTER LA FIN NE FAIT RIEN, ET NE REND RIEN.** La faute qu'on
    // pourrait rendre ici est déjà rendue par `consume`, qui précède
    // nécessairement tout `END_STREAM` de `DATA`.
    flux.end_remote(1);
    assert_eq!(flux.state(1), Some(StreamState::HalfClosedRemote));

    // Sur un flux fermé, la fin ne ressuscite rien : la table ne le porte plus.
    flux.close(1);
    flux.end_remote(1);
    assert_eq!(flux.state(1), Some(StreamState::Closed));
    assert_eq!(
        flux.consume(9, 1).expect_err("oisif").cause(),
        Cause::WrongStreamState
    );
    // Remplir la fenêtre d'un flux qui n'est plus là ne fait rien : la table ne
    // le porte plus, et lui promettre une fenêtre serait mentir.
    flux.refill(9, 100);
    assert_eq!(flux.window(9), None);
}

/// **UN `RST_STREAM` SUR UN FLUX DÉJÀ FERMÉ N'EST PAS UNE FAUTE** : il a pu
/// croiser notre réponse sur le fil.
#[test]
fn fermer_deux_fois_n_est_pas_une_faute() {
    let mut flux = neuve();
    flux.open(1).expect("ouvert");
    flux.close(1);
    flux.close(1);
    flux.close(99);
    assert!(flux.is_empty());
}

/// La fenêtre d'un flux se consomme et se recrédite.
#[test]
fn la_fenetre_d_un_flux_se_gere() {
    let mut flux = neuve();
    flux.open(1).expect("ouvert");
    assert_eq!(flux.window(3), None, "un flux qui n'existe pas n'en a pas");

    let issue = flux
        .consume(1, INITIAL_WINDOW_SIZE.saturating_add(1))
        .expect_err("refusé");
    assert_eq!(issue.cause(), Cause::WindowExceeded);

    flux.consume(1, INITIAL_WINDOW_SIZE).expect("jusqu'au bout");
    assert_eq!(flux.window(1).map(|f| f.available()), Some(0));

    // **ON REMPLIT, ON NE CRÉDITE PAS** : personne d'autre que nous n'ouvre
    // cette fenêtre-là, et nous savons donc toujours à quelle valeur la ramener.
    flux.refill(1, 100);
    assert_eq!(flux.window(1).map(|f| f.available()), Some(100));
}

/// **TOUTES LES FENÊTRES OUVERTES BOUGENT, DE LA MÊME DIFFÉRENCE** (§6.9.2), et
/// certaines deviennent négatives. Ne l'appliquer qu'aux flux à venir ferait
/// diverger notre compte de celui du pair.
#[test]
fn un_changement_de_fenetre_initiale_bouge_tout_le_monde() {
    let mut flux = neuve();
    flux.open(1).expect("ouvert");
    flux.open(3).expect("ouvert");
    flux.consume(1, 60_000).expect("il y a la place");

    // Le pair ramène la fenêtre initiale à mille.
    flux.set_initial_window(1_000).expect("l'ajustement passe");
    assert_eq!(
        flux.window(1).map(|f| f.available()),
        Some(5_535 - 64_535),
        "négative, et c'est correct"
    );
    assert_eq!(flux.window(3).map(|f| f.available()), Some(1_000));

    // Et un flux ouvert APRÈS part de la nouvelle taille.
    flux.open(5).expect("ouvert");
    assert_eq!(flux.window(5).map(|f| f.available()), Some(1_000));

    // Un ajustement qui ferait déborder est une faute. Il faut pour cela une
    // fenêtre déjà créditée : l'ajustement seul ramène chacune à la nouvelle
    // taille, et ne peut donc pas la dépasser.
    flux.refill(3, INITIAL_WINDOW_SIZE.saturating_add(1));
    let issue = flux.set_initial_window(0x7fff_ffff).expect_err("refusé");
    assert_eq!(issue.cause(), Cause::WindowOverflow);
}

/// **ON VÉRIFIE TOUT AVANT D'APPLIQUER QUOI QUE CE SOIT.** Ajuster au fil de la
/// boucle et s'arrêter en chemin laisserait la moitié des fenêtres déplacées et
/// l'autre non — un état que ni nous ni le pair ne saurions décrire.
///
/// Défaut trouvé par le fuzz, avec sa jumelle : une taille au-delà de 2^31-1
/// était acceptée, et fabriquait des fenêtres hors borne.
#[test]
fn un_ajustement_qui_echoue_ne_deplace_rien() {
    let mut flux = neuve();
    flux.open(1).expect("ouvert");
    flux.open(3).expect("ouvert");
    flux.refill(3, INITIAL_WINDOW_SIZE.saturating_add(1_000));
    let avant = (
        flux.window(1).map(|f| f.available()),
        flux.window(3).map(|f| f.available()),
    );

    // Celui-ci ferait déborder le second flux, mais pas le premier.
    let issue = flux.set_initial_window(0x7fff_ff00).expect_err("refusé");
    assert_eq!(issue.cause(), Cause::WindowOverflow);
    assert_eq!(
        (
            flux.window(1).map(|f| f.available()),
            flux.window(3).map(|f| f.available())
        ),
        avant,
        "aucune fenêtre n'a bougé"
    );
    // Et la taille initiale non plus : un flux ouvert ensuite part de l'ancienne.
    flux.open(5).expect("ouvert");
    assert_eq!(
        flux.window(5).map(|f| f.available()),
        Some(i64::from(INITIAL_WINDOW_SIZE))
    );
}

/// **UNE TAILLE AU-DELÀ DE 2^31-1 SE REFUSE ICI AUSSI** (§6.5.2), et pas
/// seulement à la lecture des `SETTINGS` : cette méthode est publique, et un
/// appelant qui l'oublierait fabriquerait des fenêtres hors borne.
#[test]
fn une_taille_initiale_hors_borne_se_refuse() {
    let mut flux = neuve();
    for taille in [0x8000_0000_u32, u32::MAX] {
        let issue = flux.set_initial_window(taille).expect_err("refusé");
        assert_eq!(issue.cause(), Cause::WindowOverflow, "{taille}");
        assert_eq!(issue.code(), ErrorCode::FlowControlError, "{taille}");
    }
    // La borne exacte passe, et un flux ouvert ensuite y part.
    flux.set_initial_window(0x7fff_ffff)
        .expect("la borne exacte");
    flux.open(1).expect("ouvert");
    assert_eq!(flux.window(1).map(|f| f.available()), Some(0x7fff_ffff));
}

/// L'ensemble se montre, et sans montrer les fenêtres de chacun.
#[test]
fn l_ensemble_se_montre() {
    let flux = neuve();
    assert!(std::format!("{flux:?}").contains("Streams"));
    assert!(std::format!("{:?}", StreamState::Open).contains("Open"));
}

/// **DEUX FENÊTRES PAR FLUX, ET ELLES NE SE MÉLANGENT PAS** (§5.2.1) : celle de
/// réception se consomme quand le pair envoie, celle d'émission quand nous
/// envoyons. N'en tenir qu'une reviendrait à croire son propre compte pour celui
/// du pair.
#[test]
fn la_fenetre_d_emission_est_une_autre_fenetre() {
    let mut flux = neuve();
    flux.open(1).expect("ouvert");
    assert_eq!(
        flux.send_window(3),
        None,
        "un flux qui n'existe pas n'en a pas"
    );
    assert_eq!(
        flux.send_window(1).map(|f| f.available()),
        Some(i64::from(INITIAL_WINDOW_SIZE))
    );

    assert_eq!(flux.take_send(1, 1_000), 1_000, "il y a la place");
    assert_eq!(
        flux.send_window(1).map(|f| f.available()),
        Some(i64::from(INITIAL_WINDOW_SIZE) - 1_000)
    );
    // La fenêtre de RÉCEPTION, elle, n'a pas bougé.
    assert_eq!(
        flux.window(1).map(|f| f.available()),
        Some(i64::from(INITIAL_WINDOW_SIZE))
    );

    // **ON PREND AU PLUS CE QUI EST OUVERT.** Demander davantage ne rend pas de
    // faute : à l'émission, c'est nous qui choisissons, et la fenêtre borne.
    assert_eq!(
        flux.take_send(1, INITIAL_WINDOW_SIZE),
        INITIAL_WINDOW_SIZE.saturating_sub(1_000)
    );
    assert_eq!(flux.send_window(1).map(|f| f.available()), Some(0));
    assert_eq!(flux.take_send(1, 10), 0, "une fenêtre fermée ne donne rien");
    assert_eq!(flux.take_send(9, 10), 0, "un flux oisif non plus");

    let issue = flux.credit_send(9, 1).expect_err("oisif");
    assert_eq!(issue.cause(), Cause::WrongStreamState);

    // Un crédit qui ferait dépasser 2^31-1 est une faute de contrôle de flux.
    flux.credit_send(1, 0x7fff_0000).expect("du crédit");
    let issue = flux.credit_send(1, 0x7fff_0000).expect_err("cela déborde");
    assert_eq!(issue.cause(), Cause::WindowOverflow);
}

/// **LE RÉGLAGE DU PAIR BOUGE LES FENÊTRES D'ÉMISSION, PAS LES NÔTRES** (§6.9.2).
/// Le confondre avec le nôtre ferait bouger les fenêtres du mauvais côté, et les
/// deux comptes divergeraient sans qu'un seul cadre soit fautif.
#[test]
fn le_reglage_du_pair_ne_bouge_que_l_emission() {
    let mut flux = neuve();
    flux.open(1).expect("ouvert");
    flux.set_peer_initial_window(1_000).expect("mille");
    assert_eq!(flux.send_window(1).map(|f| f.available()), Some(1_000));
    assert_eq!(
        flux.window(1).map(|f| f.available()),
        Some(i64::from(INITIAL_WINDOW_SIZE)),
        "la réception n'a pas bougé"
    );

    // Un flux ouvert APRÈS part de la nouvelle taille.
    flux.open(3).expect("ouvert");
    assert_eq!(flux.send_window(3).map(|f| f.available()), Some(1_000));

    // Au-delà de 2^31-1, §6.5.2 refuse. La lecture des `SETTINGS` le refuse
    // déjà — et on le refuse ICI aussi, parce que cette méthode est publique.
    let issue = flux
        .set_peer_initial_window(0x8000_0000)
        .expect_err("hors borne");
    assert_eq!(issue.cause(), Cause::WindowOverflow);
    assert_eq!(issue.code(), ErrorCode::FlowControlError);

    // Et un ajustement qui ferait déborder une fenêtre déjà créditée.
    flux.credit_send(1, 1).expect("du crédit");
    let issue = flux
        .set_peer_initial_window(0x7fff_ffff)
        .expect_err("cela déborde");
    assert_eq!(issue.cause(), Cause::WindowOverflow);
}

/// **LES DEUX MOITIÉS D'UNE FERMETURE.** Chacune laisse l'autre côté parler ;
/// c'est la seconde qui rend la place, et l'ordre n'y change rien.
#[test]
fn les_deux_moities_d_une_fermeture() {
    // Nous d'abord, le pair ensuite.
    let mut flux = neuve();
    flux.open(1).expect("ouvert");
    flux.end_local(1);
    assert_eq!(flux.state(1), Some(StreamState::HalfClosedLocal));
    // Le pair peut encore envoyer : c'est tout l'intérêt de cet état.
    flux.consume(1, 100).expect("il envoie encore");
    flux.end_remote(1);
    assert_eq!(flux.state(1), Some(StreamState::Closed));
    assert!(flux.is_empty(), "le flux a rendu sa place");

    // Le pair d'abord, nous ensuite.
    let mut flux = neuve();
    flux.open(1).expect("ouvert");
    flux.end_remote(1);
    assert_eq!(flux.state(1), Some(StreamState::HalfClosedRemote));
    flux.end_local(1);
    assert_eq!(flux.state(1), Some(StreamState::Closed));
    assert!(flux.is_empty());

    // Répéter ne fait rien, et sur un flux qui n'est plus là non plus.
    flux.end_local(1);
    flux.end_local(99);
    let mut flux = neuve();
    flux.open(1).expect("ouvert");
    flux.end_local(1);
    flux.end_local(1);
    assert_eq!(flux.state(1), Some(StreamState::HalfClosedLocal));
}
