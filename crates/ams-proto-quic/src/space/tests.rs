// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un espace de numéros de paquet retient, et ce qu'il acquitte.

use super::{ELICITING_BEFORE_ACK, RANGES_MAX, Received, Space};
use crate::error::Reason;
use crate::frame::Frame;
use crate::packet_number::PACKET_NUMBER_MAX;

/// Relit l'`ACK` qu'un espace vient d'écrire.
fn relire(recu: &Received, instant: u64) -> (u64, u64, std::vec::Vec<(u64, u64)>) {
    let mut place = [0_u8; 1024];
    let ecrits = recu
        .write_ack(instant, 0, &mut place)
        .expect("écrivable")
        .expect("il y a de quoi acquitter");
    let (trame, lus) = Frame::parse(place.get(..ecrits).expect("écrit")).expect("relisible");
    assert_eq!(lus, ecrits, "on relit exactement ce qu'on a écrit");
    let Frame::Ack(ack) = trame else {
        panic!("ce devait être un ACK");
    };
    let intervalles: std::vec::Vec<(u64, u64)> = ack
        .ranges()
        .map(|issue| {
            let intervalle = issue.expect("lisible");
            (intervalle.gap, intervalle.length)
        })
        .collect();
    assert_eq!(
        u64::try_from(intervalles.len()).expect("court"),
        ack.range_count,
        "le compte annoncé ne correspond pas"
    );
    (ack.largest, ack.first_range, intervalles)
}

/// Rend les numéros que cet `ACK` acquitte, du plus grand au plus petit.
///
/// **C'EST LA RECONSTRUCTION DE §19.3.1**, et elle vaut d'être écrite : l'écart
/// compte les numéros MANQUANTS moins un, et c'est ce « moins un » qu'on oublie
/// en le réécrivant de mémoire. Le test qui s'en sert prouve donc aussi qu'on
/// l'écrit comme on le lit.
fn couverts(recu: &Received) -> std::vec::Vec<u64> {
    let (plus_grand, premier, intervalles) = relire(recu, 0);
    let mut tous = std::vec::Vec::new();
    let haut = plus_grand;
    let mut bas = plus_grand.saturating_sub(premier);
    for numero in (bas..=haut).rev() {
        tous.push(numero);
    }
    // Les intervalles suivants, du plus récent au plus ancien.
    for (ecart, longueur) in intervalles {
        let haut = bas
            .checked_sub(ecart.saturating_add(2))
            .expect("un intervalle sous zéro");
        bas = haut.saturating_sub(longueur);
        for numero in (bas..=haut).rev() {
            tous.push(numero);
        }
    }
    tous
}

/// **TROIS ESPACES, ET ILS NE SE MÉLANGENT JAMAIS** (§12.3). Ce n'est pas une
/// commodité : les trois emploient des clés différentes, et le numéro entre dans
/// le nonce.
#[test]
fn les_trois_espaces_se_distinguent() {
    assert_ne!(Space::Initial, Space::Handshake);
    assert_ne!(Space::Handshake, Space::Application);
    assert_ne!(Space::Initial, Space::Application);
}

/// Un espace neuf n'a rien à dire.
#[test]
fn un_espace_neuf_n_a_rien_a_dire() {
    let recu = Received::new();
    assert!(recu.is_empty());
    assert_eq!(recu.len(), 0);
    assert_eq!(recu.largest(), None);
    assert!(!recu.has_pending());
    assert!(!recu.owes_ack());
    assert!(!recu.should_ack_now());
    assert_eq!(recu.ack_deadline(25_000), None);
    assert_eq!(recu, Received::default());
    // Et il n'écrit pas d'`ACK` vide.
    assert_eq!(recu.write_ack(0, 3, &mut [0_u8; 64]).expect("licite"), None);
}

/// Des paquets qui se suivent font un seul intervalle.
#[test]
fn les_paquets_qui_se_suivent_font_un_intervalle() {
    let mut recu = Received::new();
    for numero in 0..5_u64 {
        recu.on_received(numero, true, numero.saturating_mul(1_000))
            .expect("licite");
    }
    assert_eq!(recu.len(), 1, "un seul intervalle");
    assert_eq!(recu.largest(), Some(4));
    assert_eq!(recu.largest_at(), 4_000);

    let (plus_grand, premier, intervalles) = relire(&recu, 4_000);
    assert_eq!(plus_grand, 4);
    assert_eq!(premier, 4, "de quatre à zéro");
    assert!(intervalles.is_empty());
}

/// **UN DOUBLON NE SE TRAITE PAS DEUX FOIS** : le réseau duplique, et compter
/// deux fois les mêmes données fermerait la connexion pour une faute que
/// personne n'a commise.
#[test]
fn un_doublon_se_reconnait() {
    let mut recu = Received::new();
    recu.on_received(3, true, 100).expect("licite");
    assert!(recu.contains(3));
    assert!(!recu.contains(2));
    assert!(!recu.contains(4));

    recu.on_ack_sent();
    // Le même, à nouveau : rien ne change.
    recu.on_received(3, true, 200).expect("licite");
    assert!(!recu.has_pending(), "un doublon n'a rien de neuf à dire");
    assert!(!recu.owes_ack());
    assert_eq!(recu.largest_at(), 100, "l'instant n'a pas bougé");
}

/// **UN TROU FAIT DEUX INTERVALLES**, et le combler les réunit.
#[test]
fn un_trou_fait_deux_intervalles_puis_se_comble() {
    let mut recu = Received::new();
    recu.on_received(0, true, 0).expect("licite");
    recu.on_received(2, true, 100).expect("licite");
    assert_eq!(recu.len(), 2);

    let (plus_grand, premier, intervalles) = relire(&recu, 100);
    assert_eq!(plus_grand, 2);
    assert_eq!(premier, 0, "le deux tout seul");
    assert_eq!(intervalles.len(), 1);
    // §19.3.1 : l'écart compte les numéros MANQUANTS moins un. Un seul manque
    // — le un — donc l'écart vaut zéro.
    assert_eq!(
        intervalles[0],
        (0, 0),
        "un écart de zéro, un intervalle de zéro"
    );

    // Le comblement réunit les deux.
    recu.on_received(1, true, 200).expect("licite");
    assert_eq!(recu.len(), 1, "les deux intervalles se sont réunis");
    let (plus_grand, premier, intervalles) = relire(&recu, 200);
    assert_eq!(plus_grand, 2);
    assert_eq!(premier, 2, "de deux à zéro");
    assert!(intervalles.is_empty());
}

/// **ON NE RÉPOND PAS À UN ACQUITTEMENT PAR UN ACQUITTEMENT** (§13.2.1). Sans
/// cette règle, deux pairs qui n'ont plus rien à se dire s'acquitteraient
/// mutuellement sans fin.
#[test]
fn un_paquet_qui_ne_sollicite_rien_ne_fait_rien_envoyer() {
    let mut recu = Received::new();
    // Un paquet qui ne porte que des `ACK` : il ne sollicite rien.
    recu.on_received(0, false, 0).expect("licite");
    assert!(recu.has_pending(), "il y a bien quelque chose de neuf");
    assert!(!recu.owes_ack(), "mais rien qui oblige à répondre");
    assert!(!recu.should_ack_now());
    assert_eq!(recu.ack_deadline(25_000), None);

    // **MÊME AVEC UN TROU DEVANT** : §13.2.1 est explicite.
    recu.on_received(5, false, 100).expect("licite");
    assert!(!recu.should_ack_now(), "un trou ne suffit pas");
    assert!(!recu.owes_ack());

    // Un seul paquet sollicitant change tout.
    recu.on_received(6, true, 200).expect("licite");
    assert!(recu.owes_ack());
    assert_eq!(recu.ack_deadline(25_000), Some(200 + 25_000));
}

/// **UN PAQUET SOLLICITANT QUI ARRIVE DANS LE DÉSORDRE S'ACQUITTE SANS
/// ATTENDRE** (§13.2.1) : c'est ce qui évite au pair de croire à une perte.
#[test]
fn le_desordre_fait_acquitter_sans_attendre() {
    // Un numéro plus petit que le plus grand vu.
    let mut recu = Received::new();
    recu.on_received(5, true, 0).expect("licite");
    assert!(!recu.should_ack_now(), "un seul paquet dans l'ordre");
    recu.on_ack_sent();
    recu.on_received(3, true, 100).expect("licite");
    assert!(recu.should_ack_now(), "il arrive après un plus grand");

    // Un numéro qui laisse un trou derrière lui.
    let mut recu = Received::new();
    recu.on_received(0, true, 0).expect("licite");
    recu.on_ack_sent();
    recu.on_received(4, true, 100).expect("licite");
    assert!(recu.should_ack_now(), "il laisse un trou");

    // Le suivant immédiat, lui, n'a rien d'urgent.
    let mut recu = Received::new();
    recu.on_received(0, true, 0).expect("licite");
    recu.on_ack_sent();
    recu.on_received(1, true, 100).expect("licite");
    assert!(!recu.should_ack_now(), "il suit celui d'avant");
}

/// **UN ACQUITTEMENT TOUS LES DEUX PAQUETS SOLLICITANTS** (§13.2.2).
#[test]
fn deux_paquets_sollicitants_font_acquitter() {
    let mut recu = Received::new();
    recu.on_received(0, true, 0).expect("licite");
    assert!(!recu.should_ack_now());
    recu.on_received(1, true, 100).expect("licite");
    assert!(recu.should_ack_now());
    assert_eq!(ELICITING_BEFORE_ACK, 2);

    // Et l'envoi remet le compte à zéro.
    recu.on_ack_sent();
    assert!(!recu.should_ack_now());
    assert!(!recu.owes_ack());
    assert!(!recu.has_pending());
}

/// **LES INTERVALLES RESTENT APRÈS L'ENVOI** (§13.2.3) : un `ACK` acquitte à
/// nouveau ce qu'il a déjà acquitté, au cas où le précédent se serait perdu.
#[test]
fn les_intervalles_restent_apres_l_envoi() {
    let mut recu = Received::new();
    recu.on_received(0, true, 0).expect("licite");
    recu.on_received(2, true, 100).expect("licite");
    recu.on_ack_sent();
    assert_eq!(recu.len(), 2, "on n'oublie pas ce qu'on a acquitté");
    let (plus_grand, _, intervalles) = relire(&recu, 100);
    assert_eq!(plus_grand, 2);
    assert_eq!(intervalles.len(), 1);
}

/// **ON OUBLIE LE PLUS ANCIEN, JAMAIS LE PLUS RÉCENT** (§13.2.3). Un pair qui
/// enverrait des paquets aux numéros très espacés obligerait sinon à retenir
/// autant d'intervalles qu'il en choisit.
#[test]
fn on_oublie_le_plus_ancien() {
    let mut recu = Received::new();
    // Un paquet sur deux : autant d'intervalles que de paquets.
    for rang in 0..(RANGES_MAX as u64 + 10) {
        let numero = rang.saturating_mul(2);
        recu.on_received(numero, true, rang).expect("licite");
    }
    assert_eq!(recu.len(), RANGES_MAX, "la table ne déborde pas");
    // Le plus récent est là ; le plus ancien, non.
    let dernier = (RANGES_MAX as u64 + 9).saturating_mul(2);
    assert!(recu.contains(dernier), "le plus récent a été gardé");
    assert!(!recu.contains(0), "le plus ancien est tombé");
}

/// **LE DÉLAI S'ÉCRIT EN UNITÉS DE 2^EXPOSANT MICROSECONDES** (§19.3), et c'est
/// l'exposant qu'on a annoncé qui décide.
#[test]
fn le_delai_s_ecrit_dans_l_unite_annoncee() {
    let mut recu = Received::new();
    recu.on_received(0, true, 1_000).expect("licite");
    let mut place = [0_u8; 64];

    // Exposant zéro : le délai s'écrit en microsecondes.
    let ecrits = recu
        .write_ack(1_064, 0, &mut place)
        .expect("écrivable")
        .expect("il y a de quoi");
    let (trame, _) = Frame::parse(place.get(..ecrits).expect("écrit")).expect("relisible");
    let Frame::Ack(ack) = trame else {
        panic!("un ACK");
    };
    assert_eq!(ack.delay, 64);

    // Exposant trois : le délai se divise par huit.
    let ecrits = recu
        .write_ack(1_064, 3, &mut place)
        .expect("écrivable")
        .expect("il y a de quoi");
    let (trame, _) = Frame::parse(place.get(..ecrits).expect("écrit")).expect("relisible");
    let Frame::Ack(ack) = trame else {
        panic!("un ACK");
    };
    assert_eq!(ack.delay, 8);
}

/// **ON N'ANNONCE PAS D'ECN**, parce qu'on ne le lit pas : annoncer des comptes
/// qu'on ne tient pas ferait croire au pair que le réseau va bien.
#[test]
fn on_n_annonce_pas_d_ecn() {
    let mut recu = Received::new();
    recu.on_received(0, true, 0).expect("licite");
    let mut place = [0_u8; 64];
    let ecrits = recu
        .write_ack(0, 3, &mut place)
        .expect("écrivable")
        .expect("il y a de quoi");
    let (trame, _) = Frame::parse(place.get(..ecrits).expect("écrit")).expect("relisible");
    let Frame::Ack(ack) = trame else {
        panic!("un ACK");
    };
    assert!(ack.ecn.is_none());
    assert_eq!(place.first(), Some(&0x02), "le type sans ECN");
}

/// Un numéro hors de l'espace, et un tampon qui ne suffit pas.
#[test]
fn les_bornes_se_disent() {
    let mut recu = Received::new();
    let issue = recu
        .on_received(PACKET_NUMBER_MAX.saturating_add(1), true, 0)
        .expect_err("hors de l'espace");
    assert_eq!(issue.reason(), Reason::PacketNumberTooLarge);

    recu.on_received(0, true, 0).expect("licite");
    recu.on_received(4, true, 0).expect("licite");
    let complet = recu
        .write_ack(0, 3, &mut [0_u8; 64])
        .expect("écrivable")
        .expect("il y a de quoi");
    for taille in 0..complet {
        let mut court = [0_u8; 64];
        let issue = recu
            .write_ack(0, 3, court.get_mut(..taille).expect("assez court"))
            .expect_err("la place manque");
        assert_eq!(issue.reason(), Reason::BufferTooSmall, "{taille}");
    }
}

/// **LE NUMÉRO LE PLUS GRAND POSSIBLE S'ACQUITTE AUSSI.**
#[test]
fn le_plus_grand_numero_s_acquitte() {
    let mut recu = Received::new();
    recu.on_received(PACKET_NUMBER_MAX, true, 0)
        .expect("licite");
    assert_eq!(recu.largest(), Some(PACKET_NUMBER_MAX));
    let (plus_grand, premier, _) = relire(&recu, 0);
    assert_eq!(plus_grand, PACKET_NUMBER_MAX);
    assert_eq!(premier, 0);
}

/// **L'`ACK` ÉCRIT COUVRE EXACTEMENT CE QU'ON A REÇU, ET RIEN D'AUTRE.**
///
/// C'est la propriété qui compte : acquitter un paquet qu'on n'a pas reçu ferait
/// croire à l'émetteur qu'il est arrivé, et il ne le retransmettrait jamais.
#[test]
fn l_acquittement_couvre_exactement_ce_qu_on_a_recu() {
    // Des paquets qui se suivent.
    let mut recu = Received::new();
    for numero in [10_u64, 11, 12] {
        recu.on_received(numero, true, 0).expect("licite");
    }
    assert_eq!(couverts(&recu), std::vec![12, 11, 10]);

    // Des trous de tailles différentes : c'est là que l'écart de §19.3.1 se
    // vérifie, avec son « moins un ».
    let mut recu = Received::new();
    for numero in [0_u64, 1, 3, 7, 8, 9, 20] {
        recu.on_received(numero, true, 0).expect("licite");
    }
    assert_eq!(
        couverts(&recu),
        std::vec![20, 9, 8, 7, 3, 1, 0],
        "l'ACK ne couvre pas exactement ce qu'on a reçu"
    );

    // Et ce que l'ACK couvre est exactement ce que `contains` dit.
    for numero in 0..25_u64 {
        assert_eq!(
            couverts(&recu).contains(&numero),
            recu.contains(numero),
            "le paquet {numero}"
        );
    }
}

/// **LE DÉFAUT QUE LE FUZZ A TROUVÉ** : l'`ACK` acquittait un paquet jamais
/// reçu — le pire de cette famille, puisque l'émetteur croit alors son paquet
/// arrivé et ne le retransmet jamais.
///
/// La cause était dans l'ordre des deux côtés d'un `zip` : `Zip::next` interroge
/// le premier itérateur puis le second, et jette l'élément du premier si le
/// second est épuisé. La destination était en premier, et chaque écriture
/// brûlait donc deux places de la table pour n'en remplir qu'une.
///
/// **Il faut cinq numéros dans un ordre précis pour que cela se voie.** Aucun
/// test écrit à la main ne serait tombé dessus.
#[test]
fn le_defaut_trouve_par_le_fuzz() {
    let mut recu = Received::new();
    for numero in [1_u64, 6336, 256, 0, 13, 167] {
        recu.on_received(numero, true, numero).expect("licite");
    }
    // La table n'a pas de trou : les intervalles occupent les premières places.
    let pleins = recu.len();
    for (rang, place) in recu.intervalles.iter().enumerate() {
        assert_eq!(
            place.is_some(),
            rang < pleins,
            "un trou au rang {rang} pour {pleins} intervalles"
        );
    }
    // Et l'`ACK` couvre exactement ce qu'on a reçu.
    for numero in 0..300_u64 {
        assert_eq!(
            couverts(&recu).contains(&numero),
            recu.contains(numero),
            "le paquet {numero}"
        );
    }
}

/// **LA TABLE NE PREND JAMAIS DE TROU**, quel que soit l'ordre d'arrivée. C'est
/// l'invariant que le défaut du `zip` violait, et il se vérifie mieux
/// directement que par ses conséquences.
#[test]
fn la_table_ne_prend_jamais_de_trou() {
    // Quelques ordres d'arrivée qui font travailler l'insertion et la réunion.
    let suites: [&[u64]; 5] = [
        &[1, 6336, 256, 0, 13, 167],
        &[5, 4, 3, 2, 1, 0],
        &[0, 2, 4, 6, 1, 3, 5],
        &[100, 50, 75, 51, 76, 99, 74],
        &[10, 20, 30, 40, 11, 21, 31, 41, 12, 22],
    ];
    for suite in suites {
        let mut recu = Received::new();
        for numero in suite {
            recu.on_received(*numero, true, *numero).expect("licite");
            let pleins = recu.len();
            for (rang, place) in recu.intervalles.iter().enumerate() {
                assert!(
                    place.is_some() == (rang < pleins),
                    "un trou au rang {rang} après {numero} dans {suite:?}"
                );
            }
            // Et les intervalles restent triés, du plus récent au plus ancien.
            let hauts: std::vec::Vec<u64> =
                recu.intervalles.iter().flatten().map(|i| i.haut).collect();
            for paire in hauts.windows(2) {
                assert!(
                    paire[0] > paire[1],
                    "la table n'est plus triée après {numero} dans {suite:?} : {hauts:?}"
                );
            }
        }
        // Ce que l'`ACK` couvre est exactement ce qu'on a reçu.
        let plus_grand = recu.largest().unwrap_or(0);
        for numero in 0..=plus_grand.saturating_add(2) {
            assert_eq!(
                couverts(&recu).contains(&numero),
                recu.contains(numero),
                "le paquet {numero} dans {suite:?}"
            );
        }
    }
}
