// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que §6 et l'annexe A de RFC 9002 imposent au suivi des paquets émis.
//!
//! # LES `ACK` SONT ÉCRITS À LA MAIN, D'APRÈS §19.3
//!
//! Les fabriquer avec notre propre encodeur ne prouverait rien : si le pliage
//! des intervalles était faux DES DEUX CÔTÉS, l'aller-retour passerait quand
//! même. Ici, chaque `gap` et chaque `length` sont posés d'après le texte.

use ams_proto_quic::{Ack, AckRange, GRANULARITY_US, Rtt, varints};

use super::{SENT_MAX, Sent};
use crate::error::Reason;

/// Le délai maximal d'acquittement qu'on annonce, en microsecondes.
const DELAI_MAX: u64 = 25_000;

/// Écrit les intervalles d'un `ACK`, tels que §19.3 les veut.
fn intervalles(suite: &[AckRange], out: &mut [u8]) -> usize {
    let mut rang = 0_usize;
    for intervalle in suite {
        for valeur in [intervalle.gap, intervalle.length] {
            let ecrits = varints::encode(valeur, out.get_mut(rang..).expect("de la place"))
                .expect("écrivable");
            rang = rang.saturating_add(ecrits);
        }
    }
    rang
}

/// Un `ACK` qui acquitte `largest` et les `first_range` numéros du dessous.
fn ack(largest: u64, first_range: u64) -> Ack<'static> {
    Ack {
        largest,
        delay: 0,
        first_range,
        range_count: 0,
        encoded_ranges: &[],
        ecn: None,
    }
}

/// Un trajet mesuré, pour que les seuils temporels aient un sens.
fn trajet(aller_retour: u64) -> Rtt {
    let mut rtt = Rtt::new();
    rtt.sample(aller_retour, 0, DELAI_MAX);
    rtt
}

/// **UN PAQUET ÉMIS COMPTE EN VOL, ET UN `ACK` L'EN RETIRE** (§A.5, §A.7).
#[test]
fn ce_qui_part_compte_en_vol_et_un_ack_l_en_retire() {
    let mut espace = Sent::new();
    assert_eq!(espace.in_flight(), 0);
    assert!(!espace.has_eliciting());

    espace
        .on_sent(0, 1_000, 1_200, true, true)
        .expect("il y a de la place");
    espace
        .on_sent(1, 2_000, 1_200, true, true)
        .expect("il y a de la place");
    assert_eq!(espace.in_flight(), 2_400);
    assert!(espace.has_eliciting());

    // Un `ACK` qui acquitte 0 et 1.
    let acquis = espace.on_ack(&ack(1, 1), false).expect("lisible");
    assert_eq!(acquis.count, 2);
    assert_eq!(acquis.bytes, 2_400);
    assert!(acquis.eliciting);
    assert_eq!(
        acquis.largest,
        Some((1, 2_000)),
        "l'échantillon de trajet se prend sur le plus grand"
    );
    assert_eq!(espace.in_flight(), 0);
    assert!(!espace.has_eliciting());
}

/// **UN PAQUET QUI NE PORTE QUE DES `ACK` N'EST PAS EN VOL** (§2).
///
/// Les compter ferait rétrécir la fenêtre de congestion à chaque acquittement
/// qu'on envoie — c'est-à-dire punir le fait de bien se comporter.
#[test]
fn un_paquet_d_acquittement_seul_n_est_pas_en_vol() {
    let mut espace = Sent::new();
    espace.on_sent(0, 1_000, 60, false, false).expect("place");
    assert_eq!(espace.in_flight(), 0);
    assert!(
        !espace.has_eliciting(),
        "un ACK seul ne sollicite pas d'acquittement"
    );
    // Il n'arme pas non plus le sondage : il n'y a rien à attendre.
    assert_eq!(espace.pto_deadline(&trajet(50_000), DELAI_MAX, 0), None);

    let acquis = espace.on_ack(&ack(0, 0), false).expect("lisible");
    assert_eq!(acquis.count, 1);
    assert_eq!(acquis.bytes, 0, "il ne comptait pas en vol");
    assert!(!acquis.eliciting);
}

/// **RIEN N'EST PERDU TANT QUE RIEN N'EST ACQUITTÉ** (§A.10).
///
/// Sans point de comparaison, « parti avant un paquet acquitté » n'a pas de
/// sens. Un émetteur qui déclarerait perdu sur le seul écoulement du temps
/// retransmettrait tout au premier hoquet du réseau.
#[test]
fn rien_n_est_perdu_tant_que_rien_n_est_acquitte() {
    let mut espace = Sent::new();
    for numero in 0..10_u64 {
        espace
            .on_sent(numero, 1_000, 1_200, true, true)
            .expect("place");
    }
    // Très longtemps après, et pourtant : rien.
    let perdus = espace.detect_lost(&trajet(50_000), 10_000_000);
    assert!(perdus.is_empty());
    assert_eq!(perdus.bytes(), 0);
    assert_eq!(espace.in_flight(), 12_000);
    assert_eq!(espace.loss_time(), None);
}

/// **LE SEUIL DE RANG** (§6.1.1) : trois paquets derrière un acquitté.
#[test]
fn le_seuil_de_rang_declare_perdu() {
    let mut espace = Sent::new();
    for numero in 0..5_u64 {
        espace
            .on_sent(numero, 1_000, 1_200, true, true)
            .expect("place");
    }
    // Le paquet 3 est acquitté ; 0 est donc trois rangs derrière lui.
    espace.on_ack(&ack(3, 0), false).expect("lisible");
    let perdus = espace.detect_lost(&trajet(50_000), 1_100);

    assert_eq!(perdus.numbers(), [0], "seul 0 atteint le seuil de trois");
    assert_eq!(perdus.bytes(), 1_200);
    // 1 et 2 ne sont pas encore perdus, mais on sait QUAND ils le seront.
    assert!(perdus.numbers().len() < 3);
    assert!(
        espace.loss_time().is_some(),
        "un délai doit être armé pour ceux qui attendent"
    );
    // 4 est parti après le plus grand acquitté : rien ne dit qu'il aurait dû
    // arriver.
    assert_eq!(espace.in_flight(), 1_200 * 3, "1, 2 et 4 restent");
}

/// **LE SEUIL TEMPOREL** (§6.1.2) : `9/8 × max(latest, smoothed)`.
#[test]
fn le_seuil_temporel_declare_perdu() {
    let mut espace = Sent::new();
    espace.on_sent(0, 1_000, 1_200, true, true).expect("place");
    espace.on_sent(1, 1_000, 1_200, true, true).expect("place");
    espace
        .on_sent(2, 900_000, 1_200, true, true)
        .expect("place");
    espace.on_ack(&ack(2, 0), false).expect("lisible");

    let rtt = trajet(80_000);
    // Le seuil vaut 9/8 de 80 000, soit 90 000 microsecondes.
    let seuil = rtt
        .latest()
        .max(rtt.smoothed())
        .saturating_mul(9)
        .checked_div(8)
        .expect("huit");
    assert_eq!(seuil, 90_000);

    // Juste avant le seuil : rien n'est perdu par le temps, et 0 et 1 sont à
    // deux et un rangs derrière — sous le seuil de trois.
    let perdus = espace.detect_lost(&rtt, 1_000 + seuil);
    assert_eq!(perdus.numbers(), [0, 1], "la borne est inclusive (§A.10)");

    // Et le délai armé est exactement la date d'envoi plus le seuil.
    let mut autre = Sent::new();
    autre.on_sent(0, 1_000, 1_200, true, true).expect("place");
    autre.on_sent(1, 5_000, 1_200, true, true).expect("place");
    autre.on_ack(&ack(1, 0), false).expect("lisible");
    autre.detect_lost(&rtt, 2_000);
    assert_eq!(autre.loss_time(), Some(1_000 + seuil));
}

/// **LE SEUIL NE DESCEND PAS SOUS LA GRANULARITÉ DE L'HORLOGE** (§6.1.2).
///
/// « this time threshold MUST be set to at least the local timer granularity ».
/// Un seuil plus fin que ce qu'on sait mesurer déclarerait perdu ce qui vient
/// d'arriver.
#[test]
fn le_seuil_ne_descend_pas_sous_la_granularite() {
    let mut espace = Sent::new();
    espace.on_sent(0, 5_000, 1_200, true, true).expect("place");
    espace.on_sent(1, 5_000, 1_200, true, true).expect("place");
    espace.on_ack(&ack(1, 0), false).expect("lisible");
    // **UN TRAJET MESURÉ À ZÉRO**, ce qui arrive sur une boucle locale : sans
    // plancher, le seuil vaudrait zéro et 0 serait perdu sur-le-champ.
    //
    // `Rtt::new()` ne conviendrait pas : un trajet non mesuré vaut
    // `INITIAL_RTT_US` (§6.2.2), et non zéro — c'est une estimation de départ,
    // pas une absence.
    let rtt = trajet(0);
    assert_eq!(rtt.latest(), 0);
    assert_eq!(rtt.smoothed(), 0);
    espace.detect_lost(&rtt, 5_100);
    assert_eq!(
        espace.loss_time(),
        Some(5_000 + GRANULARITY_US),
        "le plancher est la granularité"
    );
}

/// **UN PAQUET ÉMIS PRÈS DE L'ORIGINE DE L'HORLOGE N'EST PAS PERDU D'AVANCE.**
///
/// §A.10 pose `lost_send_time = now - loss_delay`. Quand l'horloge n'a pas
/// encore atteint le délai, cette date est avant l'origine : rien n'a pu être
/// émis si tôt. **Une soustraction saturante donnerait zéro**, et tout paquet
/// émis à l'instant zéro serait déclaré perdu dès le premier acquittement.
///
/// Ce n'est pas une bizarrerie d'essai : une horloge monotone commence près de
/// zéro, et ce sont les tout premiers paquets d'une connexion — ceux de la
/// poignée de main — qui auraient été retransmis pour rien.
#[test]
fn un_paquet_emis_a_l_origine_n_est_pas_perdu_d_avance() {
    let mut espace = Sent::new();
    espace.on_sent(0, 0, 1_200, true, true).expect("place");
    espace.on_sent(1, 0, 1_200, true, true).expect("place");
    espace.on_ack(&ack(1, 0), false).expect("lisible");

    let rtt = trajet(50_000);
    let perdus = espace.detect_lost(&rtt, 0);
    assert!(
        perdus.is_empty(),
        "rien ne peut avoir été émis avant l'origine"
    );
    assert_eq!(espace.in_flight(), 1_200, "le paquet 0 est toujours là");
    // Et l'on sait quand il le sera : sa date, plus le seuil.
    let seuil = rtt
        .latest()
        .max(rtt.smoothed())
        .saturating_mul(9)
        .checked_div(8)
        .expect("huit");
    assert_eq!(espace.loss_time(), Some(seuil));
}

/// **UN `ACK` QUI N'ACQUITTE RIEN DE NEUF NE MESURE RIEN** (§5.1).
///
/// Un `ACK` réémis acquitte à nouveau ce qu'il avait déjà acquitté (§13.2.3 de
/// RFC 9000) : prendre un échantillon dessus mesurerait le temps écoulé depuis
/// un envoi bien plus ancien, et gonflerait le trajet estimé.
#[test]
fn un_ack_deja_vu_ne_mesure_rien() {
    let mut espace = Sent::new();
    espace.on_sent(0, 1_000, 1_200, true, true).expect("place");
    let premier = espace.on_ack(&ack(0, 0), false).expect("lisible");
    assert_eq!(premier.largest, Some((0, 1_000)));

    // Le même `ACK`, réémis : plus rien de neuf.
    let second = espace.on_ack(&ack(0, 0), true).expect("lisible");
    assert_eq!(second.count, 0);
    assert_eq!(second.bytes, 0);
    assert_eq!(second.largest, None, "rien de neuf ne se mesure");
}

/// **LES INTERVALLES SE DÉPLIENT SELON §19.3.1**, et les deux qu'on retranche
/// ne sont pas un détail.
///
/// Un intervalle est séparé du précédent par au moins un numéro NON acquitté,
/// sans quoi les deux n'en feraient qu'un. Le `gap` compte donc les manquants
/// moins un.
#[test]
fn les_intervalles_se_deplient_selon_la_rfc() {
    let mut espace = Sent::new();
    for numero in 0..12_u64 {
        espace
            .on_sent(numero, 1_000, 100, true, true)
            .expect("place");
    }
    // On acquitte 10..=11, puis un trou en 9, puis 6..=8, puis un trou en 5,
    // puis 0..=4.
    //
    // §19.3.1 : le premier intervalle est `largest - first_range` = 10.
    // Le suivant : `haut = 10 - gap - 2`. Pour un haut de 8, `gap` vaut 0.
    // Puis `smallest = haut - length` = 8 - 2 = 6.
    // Le troisième : `haut = 6 - gap - 2`. Pour un haut de 4, `gap` vaut 0.
    // Puis `smallest = 4 - 4` = 0.
    let mut octets = [0_u8; 64];
    let poses = intervalles(
        &[
            AckRange { gap: 0, length: 2 },
            AckRange { gap: 0, length: 4 },
        ],
        &mut octets,
    );
    let trame = Ack {
        largest: 11,
        delay: 0,
        first_range: 1,
        range_count: 2,
        encoded_ranges: octets.get(..poses).expect("posés"),
        ecn: None,
    };

    let acquis = espace.on_ack(&trame, false).expect("lisible");
    assert_eq!(acquis.count, 10, "dix acquittés : 0..=4, 6..=8, 10..=11");
    assert_eq!(acquis.bytes, 1_000);
    assert_eq!(espace.in_flight(), 200, "5 et 9 restent");

    // Et ceux qui restent sont bien 5 et 9. **SEUL 5 EST PERDU** : le seuil de
    // rang veut trois paquets d'écart, et 9 n'est qu'à deux de 11. C'est le
    // seuil temporel qui finira par le condamner, pas celui-ci.
    let perdus = espace.detect_lost(&trajet(50_000), 1_100);
    assert_eq!(perdus.numbers(), [5]);
    assert!(espace.loss_time().is_some(), "9 attend son délai");
}

/// Un `ACK` mal formé se refuse plutôt que d'acquitter à moitié.
///
/// Acquitter à moitié ferait déclarer perdus des paquets qui ne le sont pas —
/// et une retransmission inutile coûte à la fois de la bande passante et une
/// fenêtre de congestion.
#[test]
fn un_ack_mal_forme_se_refuse() {
    let mut espace = Sent::new();
    espace.on_sent(0, 1_000, 100, true, true).expect("place");

    // §19.3.1 : un premier intervalle qui descend sous zéro.
    let issue = espace
        .on_ack(&ack(3, 10), false)
        .expect_err("l'intervalle descend sous zéro");
    assert_eq!(issue.reason(), Reason::TooManyHoles);

    // Un intervalle suivant qui descend sous zéro.
    let mut octets = [0_u8; 64];
    let poses = intervalles(
        &[AckRange {
            gap: 200,
            length: 0,
        }],
        &mut octets,
    );
    let trame = Ack {
        largest: 5,
        delay: 0,
        first_range: 0,
        range_count: 1,
        encoded_ranges: octets.get(..poses).expect("posés"),
        ecn: None,
    };
    assert_eq!(
        espace
            .on_ack(&trame, false)
            .expect_err("le second descend sous zéro")
            .reason(),
        Reason::TooManyHoles
    );

    // Et rien n'a été acquitté au passage.
    assert_eq!(espace.in_flight(), 100);
}

/// **PLUS D'INTERVALLES QU'ON N'EN TIENT SE REFUSE.**
#[test]
fn plus_d_intervalles_qu_on_n_en_tient_se_refuse() {
    let mut espace = Sent::new();
    espace.on_sent(0, 1_000, 100, true, true).expect("place");

    let combien = ams_proto_quic::RANGES_MAX;
    let suite = std::vec![AckRange { gap: 0, length: 0 }; combien];
    let mut octets = std::vec![0_u8; combien * 16];
    let poses = intervalles(&suite, &mut octets);
    let trame = Ack {
        largest: u64::try_from(combien).expect("tient") * 2 + 4,
        delay: 0,
        first_range: 0,
        range_count: u64::try_from(combien).expect("tient"),
        encoded_ranges: octets.get(..poses).expect("posés"),
        ecn: None,
    };
    assert_eq!(
        espace
            .on_ack(&trame, false)
            .expect_err("un de plus que ce qu'on tient")
            .reason(),
        Reason::TooManyHoles
    );
}

/// **LA TABLE A UNE BORNE, ET LA DÉPASSER SE DIT** — c'est notre borne, pas une
/// faute du pair.
#[test]
fn la_table_a_une_borne() {
    let mut espace = Sent::new();
    for numero in 0..SENT_MAX {
        espace
            .on_sent(u64::try_from(numero).expect("tient"), 1_000, 10, true, true)
            .expect("dans la borne");
    }
    let issue = espace
        .on_sent(
            u64::try_from(SENT_MAX).expect("tient"),
            1_000,
            10,
            true,
            true,
        )
        .expect_err("un de trop");
    assert_eq!(issue.reason(), Reason::TooManyHoles);
    assert_eq!(
        issue.code(),
        Some(ams_proto_quic::TransportError::InternalError),
        "c'est notre borne : un pair honnête ne l'atteint pas"
    );

    // Un acquittement libère la place.
    espace.on_ack(&ack(0, 0), false).expect("lisible");
    espace
        .on_sent(
            u64::try_from(SENT_MAX).expect("tient"),
            1_000,
            10,
            true,
            true,
        )
        .expect("la place est revenue");
}

/// **LE SONDAGE DOUBLE À CHAQUE ESSAI** (§6.2.1), et c'est le seul frein d'un
/// émetteur qui n'entend plus rien.
#[test]
fn le_sondage_double_a_chaque_essai() {
    let mut espace = Sent::new();
    assert_eq!(
        espace.pto_deadline(&trajet(50_000), DELAI_MAX, 0),
        None,
        "rien à sonder tant que rien n'est parti"
    );
    espace.on_sent(0, 1_000, 1_200, true, true).expect("place");

    let rtt = trajet(50_000);
    let premier = espace
        .pto_deadline(&rtt, DELAI_MAX, 0)
        .expect("il y a de quoi sonder");
    let second = espace
        .pto_deadline(&rtt, DELAI_MAX, 1)
        .expect("il y a de quoi sonder");
    let troisieme = espace
        .pto_deadline(&rtt, DELAI_MAX, 2)
        .expect("il y a de quoi sonder");
    // Chaque essai double le délai compté depuis l'envoi.
    assert_eq!(second - 1_000, (premier - 1_000) * 2);
    assert_eq!(troisieme - 1_000, (premier - 1_000) * 4);
}

/// **UN ESPACE ABANDONNÉ REND TOUT** (§A.11).
///
/// §4.9 de RFC 9001 jette les clés `Initial` puis `Handshake`. Les paquets qui
/// restaient ne seront jamais acquittés, et les attendre figerait le sondage.
#[test]
fn un_espace_abandonne_rend_tout() {
    let mut espace = Sent::new();
    espace.on_sent(0, 1_000, 1_200, true, true).expect("place");
    espace.on_sent(1, 1_000, 800, true, true).expect("place");
    assert_eq!(espace.in_flight(), 2_000);

    assert_eq!(espace.discard(), 2_000, "les octets en vol reviennent");
    assert_eq!(espace.in_flight(), 0);
    assert!(!espace.has_eliciting());
    assert_eq!(espace.loss_time(), None);
    assert_eq!(espace.pto_deadline(&trajet(50_000), DELAI_MAX, 0), None);
    // Et il repart comme neuf.
    assert!(espace.detect_lost(&trajet(50_000), 10_000_000).is_empty());
}

/// **LA FENÊTRE DE CONGESTION PERSISTANTE NE COMPTE QUE LES SOLLICITANTS EN
/// VOL** (§7.6).
///
/// Un paquet qu'on n'attendait pas d'acquitter ne prouve rien sur le chemin :
/// son absence peut n'être qu'un `ACK` qui s'est croisé. On le place donc en
/// TÊTE, là où son exclusion se voit : s'il comptait, la fenêtre partirait de
/// sa date à lui.
#[test]
fn la_fenetre_persistante_ne_compte_que_les_sollicitants() {
    let mut espace = Sent::new();
    // Le premier ne sollicite rien et ne compte pas en vol.
    espace.on_sent(0, 0, 60, false, false).expect("place");
    espace.on_sent(1, 1_000, 1_200, true, true).expect("place");
    espace
        .on_sent(2, 1_001_000, 1_200, true, true)
        .expect("place");
    espace
        .on_sent(3, 1_002_000, 1_200, true, true)
        .expect("place");
    espace
        .on_sent(4, 1_003_000, 1_200, true, true)
        .expect("place");
    espace.on_ack(&ack(4, 0), false).expect("lisible");

    // Un trajet très court : le seuil temporel condamne tout ce qui précède.
    let perdus = espace.detect_lost(&trajet(1_000), 1_003_500);
    assert_eq!(perdus.numbers(), [0, 1, 2, 3]);
    // La fenêtre va de 1 000 à 1 002 000 : le paquet 0, qui ne sollicitait rien
    // et ne comptait pas en vol, n'y entre pas — sinon elle partirait de zéro.
    assert_eq!(perdus.persistent_window(), Some(1_001_000));
    // Et les octets rendus sont ceux des trois qui comptaient en vol.
    assert_eq!(perdus.bytes(), 3_600);

    // Un seul perdu sollicitant ne fait pas de fenêtre.
    let mut seul = Sent::new();
    seul.on_sent(0, 1_000, 1_200, true, true).expect("place");
    seul.on_sent(1, 1_000, 1_200, true, true).expect("place");
    seul.on_sent(2, 1_000, 1_200, true, true).expect("place");
    seul.on_sent(3, 1_000, 1_200, true, true).expect("place");
    seul.on_ack(&ack(3, 2), false).expect("lisible");
    let perdus = seul.detect_lost(&trajet(1_000_000), 1_100);
    assert_eq!(perdus.numbers(), [0], "seul 0 est trois rangs derrière 3");
    assert_eq!(
        perdus.persistent_window(),
        None,
        "un seul paquet ne fait pas une durée"
    );
}

/// Un espace neuf est celui que `Default` rend.
#[test]
fn l_espace_par_defaut_est_celui_qui_commence() {
    let defaut = Sent::default();
    assert_eq!(defaut.in_flight(), 0);
    assert_eq!(defaut.loss_time(), None);
    assert!(!defaut.has_eliciting());
}

/// **UN `ACK` NE FAIT PAS RECULER LE PLUS GRAND ACQUITTÉ** (§A.7).
///
/// Les `ACK` se croisent sur le réseau ; un ancien qui arriverait après un
/// récent ferait, sinon, oublier ce qu'on savait déjà — et des paquets déjà
/// jugés perdus redeviendraient en attente.
#[test]
fn un_ack_ne_fait_pas_reculer_le_plus_grand() {
    let mut espace = Sent::new();
    for numero in 0..8_u64 {
        espace
            .on_sent(numero, 1_000, 100, true, true)
            .expect("place");
    }
    espace.on_ack(&ack(7, 0), false).expect("lisible");
    // Un `ACK` plus ancien arrive après.
    espace.on_ack(&ack(1, 0), true).expect("lisible");

    // Le seuil de rang se compte toujours depuis 7 : 0, 2, 3 et 4 sont perdus.
    let perdus = espace.detect_lost(&trajet(50_000), 1_100);
    assert_eq!(perdus.numbers(), [0, 2, 3, 4]);
}

/// **DES PERTES SANS AUCUN SOLLICITANT NE FONT PAS DE FENÊTRE** (§7.6).
///
/// « two ack-eliciting packets » : perdre des paquets qui ne demandaient rien
/// ne prouve pas que le chemin est coupé. Déclarer une congestion persistante
/// là-dessus ramènerait la fenêtre à son minimum pour rien.
#[test]
fn des_pertes_sans_sollicitant_ne_font_pas_de_fenetre() {
    let mut espace = Sent::new();
    // Quatre paquets qui ne sollicitent rien, et un qui le fait pour être
    // acquitté.
    for numero in 0..4_u64 {
        espace
            .on_sent(numero, 1_000, 60, false, false)
            .expect("place");
    }
    espace.on_sent(4, 1_000, 1_200, true, true).expect("place");
    espace.on_ack(&ack(4, 0), false).expect("lisible");

    let perdus = espace.detect_lost(&trajet(1_000), 1_100);
    assert_eq!(
        perdus.numbers(),
        [0, 1],
        "0 et 1 sont trois rangs derrière 4"
    );
    assert_eq!(perdus.bytes(), 0, "aucun ne comptait en vol");
    assert_eq!(
        perdus.persistent_window(),
        None,
        "aucun sollicitant : rien à conclure sur le chemin"
    );
}

/// **UN INTERVALLE PLUS LONG QUE SON SOMMET SE REFUSE** (§19.3.1).
///
/// C'est l'autre façon dont un `ACK` descend sous zéro : non par son écart au
/// précédent, mais par sa propre longueur.
#[test]
fn un_intervalle_plus_long_que_son_sommet_se_refuse() {
    let mut espace = Sent::new();
    espace.on_sent(0, 1_000, 100, true, true).expect("place");

    let mut octets = [0_u8; 64];
    // Le sommet du second intervalle vaut `5 - 0 - 2` = 3, et sa longueur en
    // demande vingt : il descendrait sous zéro.
    let poses = intervalles(&[AckRange { gap: 0, length: 20 }], &mut octets);
    let trame = Ack {
        largest: 5,
        delay: 0,
        first_range: 0,
        range_count: 1,
        encoded_ranges: octets.get(..poses).expect("posés"),
        ecn: None,
    };
    assert_eq!(
        espace
            .on_ack(&trame, false)
            .expect_err("la longueur descend sous zéro")
            .reason(),
        Reason::TooManyHoles
    );
    assert_eq!(espace.in_flight(), 100, "rien n'a été acquitté au passage");
}

/// **DES INTERVALLES ILLISIBLES SE REFUSENT.**
///
/// Un `ACK` annonce combien d'intervalles il porte, puis les écrit en entiers
/// de longueur variable (§19.3). Si les octets manquent, le compte annoncé ment
/// — et acquitter ce qu'on a pu lire ferait déclarer perdus des paquets qui ne
/// le sont pas.
#[test]
fn des_intervalles_illisibles_se_refusent() {
    let mut espace = Sent::new();
    espace.on_sent(0, 1_000, 100, true, true).expect("place");

    // §16 : les deux bits de tête à `01` annoncent un entier de deux octets.
    // On n'en donne qu'un.
    let trame = Ack {
        largest: 5,
        delay: 0,
        first_range: 0,
        range_count: 1,
        encoded_ranges: &[0x40],
        ecn: None,
    };
    assert_eq!(
        espace
            .on_ack(&trame, false)
            .expect_err("les octets manquent")
            .reason(),
        Reason::TooManyHoles
    );
    assert_eq!(espace.in_flight(), 100, "rien n'a été acquitté au passage");
}

/// **UN NUMÉRO NE SE RÉEMPLOIE PAS** (§12.3 de RFC 9000).
///
/// « A QUIC endpoint MUST NOT reuse a packet number within the same packet
/// number space. » Une seconde entrée pour un même numéro ferait compter deux
/// fois les mêmes octets à l'acquittement, et la comptabilité des octets en vol
/// dériverait — ce qui se voit dans un débit qui s'écroule, jamais dans un
/// journal.
///
/// C'est un essai automatisé qui l'a montré : le module l'acceptait.
#[test]
fn un_numero_ne_se_reemploie_pas() {
    let mut espace = Sent::new();
    espace.on_sent(7, 1_000, 1_200, true, true).expect("place");
    let issue = espace
        .on_sent(7, 2_000, 800, true, true)
        .expect_err("§12.3 l'interdit");
    assert_eq!(issue.reason(), Reason::PacketNumberReused);
    assert_eq!(
        issue.code(),
        Some(ams_proto_quic::TransportError::InternalError),
        "c'est notre faute : le pair n'y est pour rien"
    );
    assert_eq!(espace.in_flight(), 1_200, "le refus n'a rien ajouté");

    // Une fois acquitté, le numéro n'est plus retenu — mais §12.3 le proscrit
    // toujours ; ce module ne se souvient que de ce qui est EN VOL, et c'est
    // la limite de ce qu'il peut promettre.
    espace.on_ack(&ack(7, 0), false).expect("lisible");
    espace
        .on_sent(7, 3_000, 800, true, true)
        .expect("ce module ne se souvient plus de lui");
}
