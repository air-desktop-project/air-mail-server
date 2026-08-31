// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : le suivi des paquets émis et la détection de perte** (§6 et
//! annexe A de RFC 9002).
//!
//! # Pourquoi celle-ci
//!
//! **Les `ACK` viennent du pair**, et un pair authentifié peut quand même être
//! malveillant, ou simplement bogué. Ce module lui fait confiance sur un point
//! précis : ce qu'il dit avoir reçu. Deux façons de s'en servir contre nous :
//!
//! - **acquitter ce qu'on n'a jamais envoyé**, pour fausser la mesure du trajet
//!   ou vider les octets en vol — ce qui ouvrirait la fenêtre de congestion ;
//! - **acquitter très haut**, pour faire déclarer perdu tout ce qui précède et
//!   nous faire retransmettre inutilement.
//!
//! Aucune de ces deux-là ne se voit dans un journal : elles se voient dans un
//! débit qui s'écroule, ou dans une bande passante gaspillée.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient l'`ACK`, les dates et les tailles.
//! 2. **LES OCTETS EN VOL NE MENTENT PAS.** À tout instant, ils valent la somme
//!    des paquets encore retenus qui comptaient en vol — jamais plus.
//! 3. **RIEN N'EST PERDU TANT QUE RIEN N'EST ACQUITTÉ** (§A.10).
//! 4. **UN PAQUET PERDU L'EST POUR UNE RAISON DE §6.1** : soit trois rangs
//!    derrière un acquitté, soit parti depuis plus que le seuil temporel.
//! 5. **RIEN N'EST ACQUITTÉ NI PERDU DEUX FOIS**, et rien ne sort qui n'ait été
//!    émis.
//! 6. **UN REFUS N'ACQUITTE RIEN**, même partiellement.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_proto_quic::{Ack, AckRange, GRANULARITY_US, RANGES_MAX, Rtt, varints};
use ams_quic::{Reason, SENT_MAX, Sent};

/// Le délai maximal d'acquittement qu'on annonce.
const DELAI_MAX: u64 = 25_000;

/// Un paquet qu'on prétend avoir émis.
#[derive(Arbitrary, Debug)]
struct Envoi {
    numero: u64,
    parti_a: u64,
    octets: u16,
    sollicite: bool,
    en_vol: bool,
}

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree {
    /// Ce qu'on émet, dans l'ordre.
    envois: std::vec::Vec<Envoi>,
    /// Le plus grand que l'`ACK` prétend avoir reçu.
    largest: u64,
    /// Combien de numéros d'affilée sous lui.
    first_range: u64,
    /// Les intervalles suivants.
    suite: std::vec::Vec<(u64, u64)>,
    /// Le trajet mesuré, et l'instant où l'on cherche les pertes.
    aller_retour: u64,
    maintenant: u64,
    /// Le nombre de sondages déjà tentés.
    essais: u8,
}

/// Écrit les intervalles d'un `ACK`, tels que §19.3 les veut.
fn intervalles(suite: &[AckRange], out: &mut [u8]) -> usize {
    let mut rang = 0_usize;
    for intervalle in suite {
        for valeur in [intervalle.gap, intervalle.length] {
            let Ok(ecrits) = varints::encode(valeur, out.get_mut(rang..).unwrap_or_default())
            else {
                return rang;
            };
            rang = rang.saturating_add(ecrits);
        }
    }
    rang
}

fuzz_target!(|entree: Entree| {
    let mut espace = Sent::new();
    // **LE MODÈLE** : ce qu'on a émis et pas encore retiré, tenu à part.
    let mut modele: std::collections::BTreeMap<u64, (u64, u64, bool, bool)> = Default::default();

    for envoi in entree.envois.iter().take(SENT_MAX + 4) {
        let octets = u64::from(envoi.octets);
        match espace.on_sent(
            envoi.numero,
            envoi.parti_a,
            octets,
            envoi.sollicite,
            envoi.en_vol,
        ) {
            Ok(()) => {
                assert!(
                    modele
                        .insert(
                            envoi.numero,
                            (envoi.parti_a, octets, envoi.sollicite, envoi.en_vol)
                        )
                        .is_none(),
                    "§12.3 : un numéro accepté deux fois"
                );
            }
            // **UN MÊME NUMÉRO SE REFUSE** (§12.3), et c'est cet essai qui l'a
            // fait ajouter : le module l'acceptait, et la comptabilité des
            // octets en vol dérivait en silence.
            Err(issue) => {
                assert!(matches!(
                    issue.reason(),
                    Reason::TooManyHoles | Reason::PacketNumberReused
                ));
                if issue.reason() == Reason::PacketNumberReused {
                    assert!(
                        modele.contains_key(&envoi.numero),
                        "un numéro refusé comme réemployé n'avait jamais été émis"
                    );
                    continue;
                }
                break;
            }
        }
    }

    let mut rtt = Rtt::new();
    rtt.sample(entree.aller_retour, 0, DELAI_MAX);

    // PROPRIÉTÉ 3 : rien n'est perdu tant que rien n'est acquitté.
    let avant_tout = espace.detect_lost(&rtt, entree.maintenant);
    assert!(
        avant_tout.is_empty(),
        "aucun ACK n'est arrivé, et pourtant des paquets sont déclarés perdus"
    );
    assert_eq!(espace.loss_time(), None);

    // Le sondage ne s'arme que s'il y a de quoi sonder.
    let attendu = espace.has_eliciting();
    assert_eq!(
        espace
            .pto_deadline(&rtt, DELAI_MAX, u32::from(entree.essais))
            .is_some(),
        attendu,
        "on ne sonde que ce qui attend un acquittement"
    );

    // L'`ACK` soumis.
    let suite: std::vec::Vec<AckRange> = entree
        .suite
        .iter()
        .take(RANGES_MAX + 2)
        .map(|(gap, length)| AckRange {
            gap: *gap,
            length: *length,
        })
        .collect();
    let mut octets = std::vec![0_u8; (RANGES_MAX + 4) * 16];
    let poses = intervalles(&suite, &mut octets);
    let trame = Ack {
        largest: entree.largest,
        delay: 0,
        first_range: entree.first_range,
        range_count: u64::try_from(suite.len()).unwrap_or(0),
        encoded_ranges: octets.get(..poses).unwrap_or_default(),
        ecn: None,
    };

    let en_vol_avant = espace.in_flight();
    match espace.on_ack(&trame, false) {
        Ok(acquis) => {
            // PROPRIÉTÉ 5 : ce qui est acquitté avait été émis.
            assert!(
                acquis.count <= modele.len(),
                "plus de paquets acquittés qu'on n'en a émis"
            );
            assert!(
                acquis.bytes <= en_vol_avant,
                "plus d'octets acquittés qu'il n'y en avait en vol"
            );
            if let Some((numero, parti_a)) = acquis.largest {
                assert_eq!(numero, entree.largest, "l'échantillon vient du plus grand");
                assert_eq!(
                    modele.get(&numero).map(|vu| vu.0),
                    Some(parti_a),
                    "la date d'envoi n'est pas celle qu'on avait notée"
                );
            }
            assert_eq!(
                espace.in_flight(),
                en_vol_avant.saturating_sub(acquis.bytes),
                "les octets en vol ne suivent pas ce qui a été acquitté"
            );
        }
        Err(issue) => {
            // PROPRIÉTÉ 6 : un refus n'acquitte rien.
            assert_eq!(issue.reason(), Reason::TooManyHoles);
            assert_eq!(
                espace.in_flight(),
                en_vol_avant,
                "un ACK refusé ne doit rien avoir acquitté"
            );
            return;
        }
    }

    // PROPRIÉTÉ 4 : ce qui est perdu l'est pour une raison de §6.1.
    let seuil = rtt
        .latest()
        .max(rtt.smoothed())
        .saturating_mul(9)
        .checked_div(8)
        .unwrap_or(0)
        .max(GRANULARITY_US);
    let en_vol_avant = espace.in_flight();
    let perdus = espace.detect_lost(&rtt, entree.maintenant);

    let mut octets_perdus = 0_u64;
    for numero in perdus.numbers() {
        let (parti_a, octets, _, en_vol) = *modele
            .get(numero)
            .expect("un paquet perdu doit avoir été émis");
        assert!(
            *numero <= entree.largest,
            "{numero} est parti après le plus grand acquitté : rien ne le condamne"
        );
        let trop_loin = entree.largest >= numero.saturating_add(3);
        let trop_vieux = entree
            .maintenant
            .checked_sub(seuil)
            .is_some_and(|borne| parti_a <= borne);
        assert!(
            trop_loin || trop_vieux,
            "{numero} est déclaré perdu sans raison de §6.1"
        );
        if en_vol {
            octets_perdus = octets_perdus.saturating_add(octets);
        }
    }
    assert_eq!(
        perdus.bytes(),
        octets_perdus,
        "les octets perdus ne suivent pas"
    );
    assert_eq!(
        espace.in_flight(),
        en_vol_avant.saturating_sub(perdus.bytes()),
        "les octets en vol ne suivent pas ce qui a été perdu"
    );

    // PROPRIÉTÉ 5 : rien n'est perdu deux fois.
    let encore = espace.detect_lost(&rtt, entree.maintenant);
    for numero in encore.numbers() {
        assert!(
            !perdus.numbers().contains(numero),
            "{numero} est déclaré perdu une seconde fois"
        );
    }

    // PROPRIÉTÉ 2 : et un abandon rend exactement ce qui restait.
    let restant = espace.in_flight();
    assert_eq!(espace.discard(), restant);
    assert_eq!(espace.in_flight(), 0);
    assert!(!espace.has_eliciting());
    assert_eq!(espace.loss_time(), None);
});
