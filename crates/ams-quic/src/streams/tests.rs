// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que §2.1, §4.1, §4.5 et §4.6 imposent à la collection de flux.
//!
//! # CE QUI SE VÉRIFIE ICI, ET QUI NE SE VÉRIFIE NULLE PART AILLEURS
//!
//! Les machines par flux sont éprouvées chacune de son côté. Ce module est le
//! seul qui décide **à quel flux une trame s'adresse**, **avec quelle limite il
//! s'ouvre**, et **quand sa place se libère**. Les essais portent donc là, et
//! non sur ce que `Send` ou `Recv` savent déjà faire.

use ams_proto_quic::{Directional, Initiator, StreamId, TransportParameters};

use super::{FLUX_PAR_FAMILLE_MAX, Streams};
use crate::error::Reason;

/// Les paramètres d'un pair ordinaire, avec des limites qui se distinguent
/// les unes des autres — sans quoi une confusion des trois ne se verrait pas.
fn parametres(donnees: u64) -> TransportParameters {
    TransportParameters {
        initial_max_data: donnees,
        initial_max_stream_data_bidi_local: 1_000,
        initial_max_stream_data_bidi_remote: 2_000,
        initial_max_stream_data_uni: 3_000,
        initial_max_streams_bidi: 4,
        initial_max_streams_uni: 4,
        ..TransportParameters::default()
    }
}

/// Un serveur, et ce que les deux côtés ont annoncé.
fn serveur() -> Streams {
    Streams::new(Initiator::Server, &parametres(10_000), &parametres(10_000))
}

/// Le flux de ce numéro.
fn flux(numero: u64) -> StreamId {
    StreamId::new(numero).expect("un numéro qui tient")
}

/// **LES DEUX NOMS DE §18.2 S'INVERSENT D'UN CÔTÉ À L'AUTRE.**
///
/// `initial_max_stream_data_bidi_local` d'un paramètre REÇU parle des flux que
/// le PAIR a ouverts ; le même nom, dans un paramètre qu'on ENVOIE, parle de
/// ceux qu'on ouvre soi-même. Prendre le même nom des deux côtés donnerait la
/// mauvaise limite exactement pour les flux qu'on ouvre — ceux dont on se sert
/// le plus.
///
/// Les trois limites de l'essai valent 1 000, 2 000 et 3 000 : une confusion se
/// voit donc au chiffre.
#[test]
fn les_deux_noms_de_dix_huit_deux_s_inversent() {
    let mut flux_ = serveur();
    // Un bidirectionnel que le CLIENT ouvre : le numéro 0.
    let sien = flux(0);
    flux_.accueillir(sien).expect("il a le droit");
    // Ce qu'on lui a ouvert en réception : `bidi_remote`, car c'est LUI qui l'a
    // ouvert.
    let mut fenetre = [0_u8; 2_000];
    assert!(
        flux_
            .on_stream(sien, 1_999, &[7], false, &mut fenetre)
            .is_ok(),
        "2 000 octets nous ont été annoncés pour ses flux à lui"
    );
    // Et ce qu'il nous a ouvert en émission : `bidi_local`, car de SON point de
    // vue ce flux est local.
    assert_eq!(flux_.credit(sien), 1_000);

    // Un bidirectionnel qu'on ouvre nous-mêmes : l'inverse, terme à terme.
    let notre = flux_
        .open(Directional::Bidirectional)
        .expect("il reste de la place");
    assert_eq!(
        flux_.credit(notre),
        2_000,
        "de son point de vue ce flux est distant, donc `bidi_remote`"
    );
}

/// **UN FLUX UNIDIRECTIONNEL NE VA QUE DANS UN SENS** (§2.1).
#[test]
fn un_unidirectionnel_ne_va_que_dans_un_sens() {
    let mut flux_ = serveur();
    // Le numéro 2 : unidirectionnel, ouvert par le client.
    let sien = flux(2);
    let mut fenetre = [0_u8; 3_000];
    assert!(
        flux_
            .on_stream(sien, 0, b"bonjour", false, &mut fenetre)
            .is_ok()
    );
    assert_eq!(
        flux_.credit(sien),
        0,
        "on n'écrit pas sur un unidirectionnel entrant"
    );
    assert_eq!(
        flux_.on_sent(sien, 1, false).map_err(|e| e.reason()),
        Err(Reason::SendClosed)
    );

    // Et le nôtre : le contraire, exactement.
    let notre = flux_
        .open(Directional::Unidirectional)
        .expect("de la place");
    assert_eq!(flux_.credit(notre), 3_000, "`uni`, annoncé par le pair");
    let mut vers = [0_u8; 8];
    assert_eq!(
        flux_.read(notre, &mut fenetre, &mut vers),
        0,
        "et rien n'y arrive jamais"
    );
}

/// **LE PAIR NE PEUT PAS ÉCRIRE SUR UN UNIDIRECTIONNEL QUI EST LE NÔTRE**
/// (§19.8).
#[test]
fn le_pair_ne_peut_pas_ecrire_sur_notre_unidirectionnel() {
    let mut flux_ = serveur();
    let notre = flux_
        .open(Directional::Unidirectional)
        .expect("de la place");
    let mut fenetre = [0_u8; 3_000];
    assert_eq!(
        flux_
            .on_stream(notre, 0, b"x", false, &mut fenetre)
            .map_err(|e| e.reason()),
        Err(Reason::WrongStreamDirection)
    );
}

/// **LE CRÉDIT DE CONNEXION SE VÉRIFIE AVANT DE RANGER** (§4.1).
///
/// Si l'on rangeait d'abord, le plus grand décalage du flux monterait avant
/// qu'on découvre que la connexion n'en avait pas le crédit — et l'état qu'on
/// rapporterait en fermant n'aurait plus rien à voir avec celui d'avant la
/// trame.
#[test]
fn le_credit_de_connexion_se_verifie_avant_de_ranger() {
    // Cent octets pour toute la connexion, deux mille par flux : c'est la
    // connexion qui borne, et c'est ce qu'on veut voir.
    let mut flux_ = Streams::new(Initiator::Server, &parametres(100), &parametres(10_000));
    let sien = flux(0);
    let mut fenetre = [0_u8; 2_000];
    assert!(
        flux_
            .on_stream(sien, 0, &[0; 100], false, &mut fenetre)
            .is_ok()
    );
    assert_eq!(flux_.incoming().used(), 100);

    let refus = flux_.on_stream(sien, 100, &[0; 1], false, &mut fenetre);
    assert_eq!(refus.map_err(|e| e.reason()), Err(Reason::FlowControl));
    assert_eq!(
        flux_.incoming().used(),
        100,
        "RIEN N'A BOUGÉ : ni le compte de la connexion…"
    );
    // …ni celui du flux, ce que dit la reprise à l'identique une fois le
    // crédit relevé.
    flux_.on_max_data(200);
    assert_eq!(
        flux_.incoming().used(),
        100,
        "un `MAX_DATA` ne consomme rien"
    );
}

/// **UNE RETRANSMISSION NE PAIE PAS DEUX FOIS** (§4.1).
///
/// Le contrôle de connexion compte la somme des plus grands décalages, et non
/// les octets reçus. Compter les octets ferait payer une seconde fois ce que le
/// pair a simplement redit.
#[test]
fn une_retransmission_ne_paie_pas_deux_fois() {
    let mut flux_ = serveur();
    let sien = flux(0);
    let mut fenetre = [0_u8; 2_000];
    flux_
        .on_stream(sien, 0, &[1, 2, 3], false, &mut fenetre)
        .expect("neuf");
    assert_eq!(flux_.incoming().used(), 3);
    flux_
        .on_stream(sien, 0, &[1, 2, 3], false, &mut fenetre)
        .expect("redit");
    assert_eq!(flux_.incoming().used(), 3, "le même décalage ne coûte rien");
}

/// **UN FLUX ANNULÉ REND SON CRÉDIT COMPTÉ, MÊME SANS SES OCTETS** (§4.5).
///
/// Sans cela, un pair qui annule tous ses flux récupérerait du crédit qu'il n'a
/// jamais rendu.
#[test]
fn un_flux_annule_compte_sa_taille_finale() {
    let mut flux_ = serveur();
    let sien = flux(0);
    flux_.on_reset_stream(sien, 500).expect("§19.4");
    assert_eq!(
        flux_.incoming().used(),
        500,
        "la taille finale compte, bien qu'aucun octet ne soit arrivé"
    );
}

/// **UNE PLACE LIBRE N'EST PAS UNE PROMESSE** (§4.6).
///
/// Tant que le `MAX_STREAMS` n'est pas parti, le pair ne sait rien du crédit
/// qu'une place rendue vient d'ouvrir. Relever le plafond en oubliant le flux
/// accepterait des flux qu'il n'a pas le droit d'ouvrir.
#[test]
fn une_place_libre_n_est_pas_une_promesse() {
    let mut flux_ = serveur();
    let sien = flux(0);
    let rang = flux_.accueillir(sien).expect("il a le droit");
    // Le flux se termine des deux côtés : `FIN` reçu et lu, `FIN` émis et
    // acquitté.
    let mut fenetre = [0_u8; 2_000];
    flux_
        .on_stream(sien, 0, b"a", true, &mut fenetre)
        .expect("son `FIN`");
    let mut vers = [0_u8; 4];
    flux_.read(sien, &mut fenetre, &mut vers);
    flux_.on_sent(sien, 0, true).expect("notre `FIN`");
    flux_.on_acked(sien, 0, 0).expect("il l'accuse");
    assert!(flux_.fini(rang), "les deux côtés sont finis");

    let avant = flux_.max_streams(Directional::Bidirectional);
    assert_eq!(flux_.oublier(rang), Some(sien));
    assert_eq!(
        flux_.max_streams(Directional::Bidirectional),
        avant,
        "OUBLIER NE PROMET RIEN : le plafond n'a pas bougé"
    );
    // C'est `grant_streams` qui propose, et `set_max_streams` qui entérine.
    let propose = flux_
        .grant_streams(Directional::Bidirectional)
        .expect("une place s'est libérée");
    assert_eq!(propose, FLUX_PAR_FAMILLE_MAX.saturating_add(1));
    flux_.set_max_streams(Directional::Bidirectional, propose);
    assert_eq!(flux_.max_streams(Directional::Bidirectional), propose);
}

/// **UN FLUX VIVANT NE REND PAS SA PLACE.**
///
/// Tant qu'une moitié bouge, un `MAX_STREAM_DATA` ou un `ACK` peut arriver pour
/// elle — et la place réattribuée ferait suivre le mauvais flux.
#[test]
fn un_flux_vivant_ne_rend_pas_sa_place() {
    let mut flux_ = serveur();
    let sien = flux(0);
    let rang = flux_.accueillir(sien).expect("il a le droit");
    let mut fenetre = [0_u8; 2_000];
    flux_
        .on_stream(sien, 0, b"a", true, &mut fenetre)
        .expect("son `FIN`");
    assert!(!flux_.fini(rang), "notre côté n'a rien conclu");
    assert_eq!(flux_.oublier(rang), None);
    assert_eq!(flux_.slot(sien), Some(rang), "il est toujours là");
}

/// **UNE FAMILLE NE PEUT PAS PRENDRE LES PLACES DES AUTRES** (§4.6).
///
/// Un seul réservoir laisserait le pair remplir la table avec une famille et
/// rendre les trois autres inutilisables — sans dépasser aucune limite qu'on lui
/// a annoncée.
#[test]
fn une_famille_ne_prend_pas_les_places_des_autres() {
    // Un plafond au maximum de ce qu'on tient, des deux côtés.
    let mut large = parametres(1_000_000);
    large.initial_max_streams_bidi = 100;
    large.initial_max_streams_uni = 100;
    let mut flux_ = Streams::new(Initiator::Server, &large, &large);

    // Le pair remplit sa famille bidirectionnelle jusqu'au plafond.
    for rang in 0..FLUX_PAR_FAMILLE_MAX {
        let numero = rang.saturating_mul(4);
        flux_.accueillir(flux(numero)).expect("sous le plafond");
    }
    assert_eq!(
        flux_
            .accueillir(flux(FLUX_PAR_FAMILLE_MAX.saturating_mul(4)))
            .map_err(|e| e.reason()),
        Err(Reason::StreamLimit),
        "au-delà, c'est §4.6"
    );

    // **ET LES TROIS AUTRES FAMILLES SONT INTACTES.**
    flux_
        .accueillir(flux(2))
        .expect("un unidirectionnel entrant");
    flux_
        .open(Directional::Bidirectional)
        .expect("un bidirectionnel à nous");
    flux_
        .open(Directional::Unidirectional)
        .expect("un unidirectionnel à nous");
}

/// **CE QU'ON ANNONCE EST CE QU'ON TIENT** (§4.6).
///
/// Annoncer plus que la table ne tient ferait refuser un flux qu'on avait promis
/// d'accepter — et le pair aurait raison de s'en étonner.
#[test]
fn on_n_annonce_que_ce_qu_on_tient() {
    let mut genereux = parametres(1_000_000);
    genereux.initial_max_streams_bidi = 1_000;
    genereux.initial_max_streams_uni = 1_000;
    let mut flux_ = Streams::new(Initiator::Server, &genereux, &genereux);
    assert_eq!(
        flux_.max_streams(Directional::Bidirectional),
        FLUX_PAR_FAMILLE_MAX
    );
    assert_eq!(
        flux_.max_streams(Directional::Unidirectional),
        FLUX_PAR_FAMILLE_MAX
    );

    // Et un pair généreux ne nous fait pas ouvrir plus que notre table.
    flux_.on_max_streams(Directional::Bidirectional, 1_000);
    for _ in 0..FLUX_PAR_FAMILLE_MAX {
        flux_
            .open(Directional::Bidirectional)
            .expect("sous notre propre borne");
    }
    assert_eq!(
        flux_
            .open(Directional::Bidirectional)
            .map_err(|e| e.reason()),
        Err(Reason::StreamLimit),
        "la table est la nôtre, et c'est elle qui borne"
    );
}

/// **LE CRÉDIT D'ÉMISSION EST LE PLUS BAS DES DEUX** (§4.1).
#[test]
fn le_credit_d_emission_est_le_plus_bas_des_deux() {
    // Vingt octets pour la connexion, mille pour le flux.
    let mut flux_ = Streams::new(Initiator::Server, &parametres(10_000), &parametres(20));
    let sien = flux(0);
    flux_.accueillir(sien).expect("il a le droit");
    assert_eq!(flux_.credit(sien), 20, "c'est la connexion qui borne");

    assert_eq!(flux_.on_sent(sien, 20, false).expect("dans le crédit"), 0);
    assert_eq!(flux_.credit(sien), 0);
    assert_eq!(
        flux_.on_sent(sien, 1, false).map_err(|e| e.reason()),
        Err(Reason::SendOverflow)
    );
    assert_eq!(flux_.outgoing().used(), 20, "UN REFUS N'A RIEN DÉPENSÉ");
}

/// **UN REFUS N'ENTAME PAS LE CRÉDIT DE CONNEXION**, même quand c'est le flux
/// qui refuse.
#[test]
fn un_flux_qui_refuse_ne_depense_rien() {
    let mut flux_ = serveur();
    let notre = flux_
        .open(Directional::Unidirectional)
        .expect("de la place");
    flux_.on_sent(notre, 10, true).expect("notre `FIN`");
    let depense = flux_.outgoing().used();
    // §3.1 : après un `FIN`, le flux n'accepte plus rien.
    assert_eq!(
        flux_.on_sent(notre, 1, false).map_err(|e| e.reason()),
        Err(Reason::SendClosed)
    );
    assert_eq!(flux_.outgoing().used(), depense);
}

/// **UN `STOP_SENDING` N'EST PAS UNE FERMETURE** (§3.5).
#[test]
fn un_stop_sending_n_est_pas_une_fermeture() {
    let mut flux_ = serveur();
    let sien = flux(0);
    flux_.accueillir(sien).expect("il a le droit");
    flux_.on_stop_sending(sien, 0x10).expect("§19.5");
    // Le flux émet toujours : c'est à l'appelant de décider d'annuler.
    assert_eq!(flux_.on_sent(sien, 1, false).expect("il émet encore"), 0);
    assert_eq!(flux_.reset(sien).expect("on décide d'annuler"), 1);
}

/// **UN `MAX_STREAM_DATA` NE VAUT QUE LÀ OÙ NOUS ÉCRIVONS** (§19.10).
#[test]
fn un_max_stream_data_ne_vaut_que_la_ou_nous_ecrivons() {
    let mut flux_ = serveur();
    let sien = flux(0);
    flux_
        .on_max_stream_data(sien, 9_000)
        .expect("bidirectionnel");
    assert_eq!(flux_.credit(sien), 9_000);

    // Le numéro 2 est un unidirectionnel du pair : nous n'y écrivons pas.
    assert_eq!(
        flux_
            .on_max_stream_data(flux(2), 9_000)
            .map_err(|e| e.reason()),
        Err(Reason::WrongStreamDirection)
    );
}

/// **CE QU'ON N'A JAMAIS OUVERT NE SE LIT PAS, ET NE FERME PAS LA CONNEXION.**
#[test]
fn ce_qu_on_n_a_jamais_ouvert_ne_se_lit_pas() {
    let mut flux_ = serveur();
    let inconnu = flux(400);
    let mut fenetre = [0_u8; 16];
    let mut vers = [0_u8; 16];
    assert_eq!(flux_.read(inconnu, &mut fenetre, &mut vers), 0);
    assert_eq!(flux_.credit(inconnu), 0);
    assert_eq!(flux_.slot(inconnu), None);
    assert_eq!(
        flux_.on_acked(inconnu, 0, 1).map_err(|e| e.reason()),
        Err(Reason::SendClosed)
    );
    assert_eq!(
        flux_.reset(inconnu).map_err(|e| e.reason()),
        Err(Reason::SendClosed)
    );
    assert_eq!(
        flux_.on_sent(inconnu, 1, false).map_err(|e| e.reason()),
        Err(Reason::SendClosed)
    );
    assert_eq!(
        flux_.outgoing().used(),
        0,
        "et ce refus-là non plus n'a rien dépensé"
    );
}

/// **LE CRÉDIT DE CONNEXION À ANNONCER** (§19.9).
#[test]
fn le_credit_de_connexion_a_annoncer() {
    let mut flux_ = serveur();
    assert_eq!(flux_.grant_data(100), None, "dix mille suffisent déjà");
    let sien = flux(0);
    let mut fenetre = [0_u8; 2_000];
    flux_
        .on_stream(sien, 0, &[0; 2_000], false, &mut fenetre)
        .expect("neuf");
    assert_eq!(flux_.grant_data(9_000), Some(11_000));
    // **ET LE PLAFOND SE PROPOSE MÊME SANS RIEN AVOIR RENDU** : le pair nous
    // avait annoncé quatre flux, la table en tient huit, et cette place-là est
    // disponible depuis le premier instant.
    assert_eq!(
        flux_.grant_streams(Directional::Bidirectional),
        Some(FLUX_PAR_FAMILLE_MAX)
    );
}

/// **L'APPLICATION LIT DANS L'ORDRE, ET LE RESTE ATTEND** (§2.2).
#[test]
fn l_application_lit_dans_l_ordre() {
    let mut flux_ = serveur();
    let sien = flux(0);
    let mut fenetre = [0_u8; 2_000];
    // Le second morceau arrive d'abord : rien n'est lisible.
    flux_
        .on_stream(sien, 3, b"def", false, &mut fenetre)
        .expect("le désordre");
    let mut vers = [0_u8; 8];
    assert_eq!(flux_.read(sien, &mut fenetre, &mut vers), 0);
    // Le trou se bouche, et tout vient d'un coup.
    flux_
        .on_stream(sien, 0, b"abc", false, &mut fenetre)
        .expect("le début");
    assert_eq!(flux_.read(sien, &mut fenetre, &mut vers), 6);
    assert_eq!(&vers[..6], b"abcdef");
}

/// **UN UNIDIRECTIONNEL REND SA PLACE SUR SA SEULE MOITIÉ.**
///
/// Il n'en a qu'une : attendre que les deux soient finies l'y garderait pour
/// toujours, et la table se remplirait de flux morts.
#[test]
fn un_unidirectionnel_rend_sa_place_sur_sa_seule_moitie() {
    let mut flux_ = serveur();

    // Le sien : reçu jusqu'au `FIN`, puis lu.
    let sien = flux(2);
    let rang = flux_.accueillir(sien).expect("il a le droit");
    let mut fenetre = [0_u8; 3_000];
    flux_
        .on_stream(sien, 0, b"a", true, &mut fenetre)
        .expect("son `FIN`");
    let mut vers = [0_u8; 4];
    flux_.read(sien, &mut fenetre, &mut vers);
    assert!(flux_.fini(rang), "il n'a pas d'autre moitié à attendre");
    assert_eq!(flux_.oublier(rang), Some(sien));

    // Le nôtre : émis jusqu'au `FIN`, puis acquitté.
    let notre = flux_
        .open(Directional::Unidirectional)
        .expect("de la place");
    let rang = flux_.slot(notre).expect("il vient d'être ouvert");
    flux_.on_sent(notre, 4, true).expect("notre `FIN`");
    flux_.on_acked(notre, 0, 4).expect("il l'accuse");
    assert!(flux_.fini(rang));
    assert_eq!(flux_.oublier(rang), Some(notre));
    assert_eq!(
        flux_.grant_streams(Directional::Unidirectional),
        Some(FLUX_PAR_FAMILLE_MAX.saturating_add(1)),
        "la place rendue s'annonce"
    );
}

/// **UN `RESET_STREAM` AU-DELÀ DU CRÉDIT DE CONNEXION EST UNE FAUTE** (§4.5).
///
/// La taille finale compte comme des octets reçus. Un pair qui annoncerait une
/// taille énorme sur un flux annulé obtiendrait autrement du crédit qu'on ne lui
/// a jamais ouvert.
#[test]
fn un_reset_stream_au_dela_du_credit_est_une_faute() {
    let mut flux_ = Streams::new(Initiator::Server, &parametres(100), &parametres(10_000));
    assert_eq!(
        flux_.on_reset_stream(flux(0), 101).map_err(|e| e.reason()),
        Err(Reason::FlowControl)
    );
    assert_eq!(flux_.incoming().used(), 0, "RIEN N'A BOUGÉ");
}

/// **UN `MAX_STREAMS` PLUS BAS QUE CE QU'ON TIENT PASSE TEL QUEL** (§19.11).
///
/// Le ramener à la table n'a de sens que pour ce qui la dépasse ; en dessous,
/// c'est le pair qui décide, et une limite plus basse n'a de toute façon pas
/// d'effet (§4.6).
#[test]
fn un_max_streams_plus_bas_que_la_table_passe_tel_quel() {
    // Un pair avare : il ne nous en ouvre qu'un seul au départ.
    let mut avare = parametres(10_000);
    avare.initial_max_streams_uni = 1;
    let mut flux_ = Streams::new(Initiator::Server, &parametres(10_000), &avare);
    flux_
        .open(Directional::Unidirectional)
        .expect("le seul qu'il ouvre");
    assert_eq!(
        flux_
            .open(Directional::Unidirectional)
            .map_err(|e| e.reason()),
        Err(Reason::StreamLimit)
    );
    // Il en ouvre un second : deux, c'est moins que les huit qu'on tient, donc
    // le plafond passe tel quel.
    flux_.on_max_streams(Directional::Unidirectional, 2);
    flux_.open(Directional::Unidirectional).expect("deux");
    assert_eq!(
        flux_
            .open(Directional::Unidirectional)
            .map_err(|e| e.reason()),
        Err(Reason::StreamLimit),
        "il n'en a ouvert que deux"
    );
}

/// **CE QU'ON A DÉJÀ ANNONCÉ NE SE RÉANNONCE PAS** (§19.11).
///
/// Un `MAX_STREAMS` qui ne dit rien de neuf coûte un paquet au pair, et ne lui
/// apprend rien.
#[test]
fn ce_qu_on_a_deja_annonce_ne_se_reannonce_pas() {
    let mut flux_ = serveur();
    let propose = flux_
        .grant_streams(Directional::Unidirectional)
        .expect("la table tient plus que ce qu'on a annoncé");
    flux_.set_max_streams(Directional::Unidirectional, propose);
    assert_eq!(
        flux_.grant_streams(Directional::Unidirectional),
        None,
        "c'est déjà dit"
    );
}

/// **ON N'ANNULE QUE CE SUR QUOI ON ÉCRIT** (§19.4, §19.5).
///
/// Un flux unidirectionnel du pair n'a pas de moitié d'émission : l'annuler ou
/// en accuser un morceau n'aurait aucun sens, et le silence laisserait croire
/// que c'est fait.
#[test]
fn on_n_annule_que_ce_sur_quoi_on_ecrit() {
    let mut flux_ = serveur();
    let sien = flux(2);
    flux_.accueillir(sien).expect("un unidirectionnel du pair");
    assert_eq!(
        flux_.reset(sien).map_err(|e| e.reason()),
        Err(Reason::SendClosed)
    );
    assert_eq!(
        flux_.on_acked(sien, 0, 1).map_err(|e| e.reason()),
        Err(Reason::SendClosed)
    );
}

/// **LE PAIR N'ANNULE QUE CE SUR QUOI IL ÉCRIT** (§19.4).
///
/// Un `RESET_STREAM` sur un unidirectionnel qui est le nôtre veut dire qu'il a
/// mal compris à qui appartient le flux — donc que la suite ne sera pas ce qu'on
/// croit.
#[test]
fn le_pair_n_annule_que_ce_sur_quoi_il_ecrit() {
    let mut flux_ = serveur();
    let notre = flux_
        .open(Directional::Unidirectional)
        .expect("de la place");
    assert_eq!(
        flux_.on_reset_stream(notre, 0).map_err(|e| e.reason()),
        Err(Reason::WrongStreamDirection)
    );
}

/// **LE PAIR N'ARRÊTE QUE CE QU'ON PEUT LUI ENVOYER** (§19.5).
///
/// Un `STOP_SENDING` sur son propre unidirectionnel demanderait d'arrêter ce que
/// nous n'écrivons pas.
#[test]
fn le_pair_n_arrete_que_ce_qu_on_peut_lui_envoyer() {
    let mut flux_ = serveur();
    assert_eq!(
        flux_.on_stop_sending(flux(2), 0).map_err(|e| e.reason()),
        Err(Reason::WrongStreamDirection)
    );
}

/// **AU-DELÀ DU PLAFOND, TOUTE TRAME EST UNE FAUTE** (§4.6).
///
/// §19 ne fait pas de différence entre les trames qui parlent d'un flux : c'est
/// le FLUX qui n'existe pas, et le pair le sait aussi bien que nous. En laisser
/// passer une seule reviendrait à ouvrir le flux qu'on refusait d'ouvrir.
#[test]
fn au_dela_du_plafond_toute_trame_est_une_faute() {
    // Le plafond annoncé est quatre : le rang quatre porte le numéro seize.
    let au_dela = flux(16);
    let mut fenetre = [0_u8; 2_000];
    let faute = |resultat: Result<(), crate::error::Error>| {
        assert_eq!(resultat.map_err(|e| e.reason()), Err(Reason::StreamLimit));
    };
    faute(serveur().on_stream(au_dela, 0, b"x", false, &mut fenetre));
    faute(serveur().on_reset_stream(au_dela, 0));
    faute(serveur().on_stop_sending(au_dela, 0));
    faute(serveur().on_max_stream_data(au_dela, 100));
}

/// **LE CRÉDIT D'UN FLUX BORNE AUSSI, ET SÉPARÉMENT DE CELUI DE LA CONNEXION**
/// (§4.1).
///
/// Deux mille octets ont été annoncés pour ce flux, dix mille pour la connexion.
/// C'est donc le flux qui refuse, alors que la connexion aurait laissé passer.
#[test]
fn le_credit_d_un_flux_borne_aussi() {
    let mut flux_ = serveur();
    let sien = flux(0);
    let mut fenetre = [0_u8; 2_000];
    assert_eq!(
        flux_
            .on_stream(sien, 2_000, b"x", false, &mut fenetre)
            .map_err(|e| e.reason()),
        Err(Reason::FlowControl)
    );
    assert!(
        flux_.incoming().available() > 0,
        "la connexion, elle, avait de quoi"
    );
}

/// **UNE TAILLE FINALE NE CHANGE PAS** (§4.5).
///
/// Un `RESET_STREAM` qui contredit le `FIN` déjà reçu veut dire que l'un des
/// deux mentait — et l'application aurait déjà pu livrer ce qu'elle a lu.
#[test]
fn une_taille_finale_ne_change_pas() {
    let mut flux_ = serveur();
    let sien = flux(0);
    let mut fenetre = [0_u8; 2_000];
    flux_
        .on_stream(sien, 0, b"abcde", true, &mut fenetre)
        .expect("son `FIN`, à cinq");
    assert_eq!(
        flux_.on_reset_stream(sien, 9).map_err(|e| e.reason()),
        Err(Reason::FinalSize),
        "neuf contredit cinq"
    );
}

/// **LA TABLE SE PARCOURT PAR SES RANGS.**
///
/// C'est la seule façon de savoir à quel flux appartiennent les tampons d'un
/// rang, et donc de les relâcher quand il se libère.
#[test]
fn la_table_se_parcourt_par_ses_rangs() {
    let mut flux_ = serveur();
    let sien = flux(0);
    let rang = flux_.accueillir(sien).expect("il a le droit");
    assert_eq!(flux_.occupant(rang), Some(sien));
    // Une part vide, et un rang hors de la table : ni l'un ni l'autre ne porte
    // quoi que ce soit.
    assert_eq!(flux_.occupant(rang.saturating_add(1)), None);
    assert_eq!(flux_.occupant(crate::FLUX_MAX), None);
    assert!(!flux_.fini(crate::FLUX_MAX), "et rien n'y est fini");
}

/// **UN FLUX À NOUS QU'ON N'A PAS OUVERT N'EXISTE PAS** (§19.8).
///
/// §2.1 donne à chaque côté ses propres numéros, et celui qui ouvre est le seul
/// à choisir quand. Un pair qui parle d'un numéro à nous que nous n'avons pas
/// pris ne prend pas de l'avance : il désigne quelque chose dont nous n'avons
/// aucune idée.
///
/// # C'EST LE FUZZ QUI L'A TROUVÉ, ET PAR SA CONSÉQUENCE
///
/// L'ouvrir à sa place en faisait un second flux du même numéro le jour où
/// `open` prenait ce rang — donc deux contrôles de flux pour un seul flux, qui
/// divergeaient en silence. La faute se voyait au rang qui bougeait sous un flux
/// vivant, et non à l'endroit où elle était commise.
#[test]
fn un_flux_a_nous_qu_on_n_a_pas_ouvert_n_existe_pas() {
    // Nous sommes le serveur : le numéro 1 est un bidirectionnel à nous.
    let notre = flux(1);
    let mut fenetre = [0_u8; 2_000];
    assert_eq!(
        serveur()
            .on_stream(notre, 0, b"x", false, &mut fenetre)
            .map_err(|e| e.reason()),
        Err(Reason::StreamNotCreated)
    );
    assert_eq!(
        serveur().on_reset_stream(notre, 0).map_err(|e| e.reason()),
        Err(Reason::StreamNotCreated)
    );

    // **ET UNE FOIS OUVERT, IL EXISTE** — c'est nous qui en décidons le moment.
    let mut flux_ = serveur();
    let ouvert = flux_.open(Directional::Bidirectional).expect("de la place");
    assert_eq!(ouvert, notre);
    assert!(flux_.on_stream(notre, 0, b"x", false, &mut fenetre).is_ok());
}
