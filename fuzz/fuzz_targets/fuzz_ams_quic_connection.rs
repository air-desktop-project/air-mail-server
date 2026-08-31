// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : la machine d'état d'une connexion** (RFC 9000 §8.1, §10 ;
//! RFC 9001 §4.1, §4.9).
//!
//! # Pourquoi celle-ci
//!
//! Deux des invariants d'ici sont des propriétés de sécurité, et non de
//! correction. La borne d'amplification de §8.1 est ce qui empêche notre serveur
//! d'être l'arme de quelqu'un d'autre : une seule séquence d'événements qui la
//! ferait sauter suffirait. Et un état de fermeture qui répondrait à chaque
//! paquet rendrait la même amplification au moment précis où l'on n'a plus rien
//! à dire.
//!
//! Ce sont des propriétés d'ORDRE : elles ne tiennent pas dans un appel, mais
//! dans une suite d'appels quelconque. Un test les vérifie sur les séquences
//! qu'on a imaginées ; le fuzz les vérifie sur celles qu'on n'a pas imaginées.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quelle que soit la suite d'événements — y compris des
//!    instants qui reculent, qu'aucune horloge ne devrait produire mais qu'une
//!    horloge monotone mal choisie produirait quand même.
//! 2. **LE CRÉDIT D'ÉMISSION NE DÉPASSE JAMAIS TROIS FOIS CE QU'ON A REÇU**,
//!    tant que l'adresse n'est pas validée (§8.1).
//! 3. **UNE ADRESSE VALIDÉE NE SE DÉVALIDE PAS** : le crédit ne redevient pas
//!    borné après l'avoir été levé, sans quoi une poignée de main aboutie
//!    pourrait se retrouver à court de souffle.
//! 4. **UNE CLÉ JETÉE NE REVIENT PAS** (§4.9 de RFC 9001) : la retrouver
//!    rendrait utilisable une protection plus faible après qu'une plus forte est
//!    disponible.
//! 5. **UN ÉTAT NE REMONTE JAMAIS LA PENTE** : vivante, puis s'éteignant, puis
//!    éteinte — et jamais l'inverse.
//! 6. **EN `Draining`, ON NE RÉPOND JAMAIS** (§10.2.2), et en `Closing` on
//!    répond de moins en moins souvent : le nombre de réponses reste
//!    logarithmique dans le nombre de paquets reçus.
//! 7. **UNE ÉCHÉANCE DE FERMETURE NE SE REPOUSSE PAS** (§10.2.2) : un pair ne
//!    peut pas prolonger notre état en fermant après nous.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_proto_quic::Space;
use ams_quic::{AMPLIFICATION_FACTOR, Connection, State};
use ams_quic_crypto::Role;

/// Un événement qu'on peut faire subir à la machine.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum Evenement {
    /// Un datagramme arrive.
    Datagramme(u16),
    /// Un paquet est lu et traité.
    Traite(u8, u32),
    /// Un paquet part.
    Emis(u8, u16, bool, u32),
    /// La poignée de main est confirmée.
    Confirmee,
    /// On ferme.
    Ferme(u32),
    /// Le pair ferme.
    PairFerme(u32),
    /// L'heure sonne.
    Echeance(u32),
    /// Un paquet arrive pendant qu'on ferme.
    Tardif,
}

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree {
    /// Sommes-nous le serveur ?
    serveur: bool,
    /// Les délais d'inactivité annoncés.
    annonce: u32,
    recu: u32,
    /// Le délai de retransmission courant.
    pto: u32,
    /// Ce qui arrive.
    evenements: [Evenement; 40],
}

/// L'espace que désigne un octet.
const fn espace(brut: u8) -> Space {
    match brut % 3 {
        0 => Space::Initial,
        1 => Space::Handshake,
        _ => Space::Application,
    }
}

/// Le rang d'un état sur la pente : plus il est grand, plus on est loin.
const fn pente(etat: State) -> u8 {
    match etat {
        State::Handshaking => 0,
        State::Confirmed => 1,
        State::Closing | State::Draining => 2,
        State::Closed => 3,
    }
}

fuzz_target!(|entree: Entree| {
    let role = match entree.serveur {
        true => Role::Server,
        false => Role::Client,
    };
    let pto = u64::from(entree.pto);
    let mut connexion = Connection::new(role, u64::from(entree.annonce), u64::from(entree.recu), 0);

    let mut recu_total = 0_u64;
    let mut valide = connexion.address_validated();
    let mut clefs = [
        connexion.has_keys(Space::Initial),
        connexion.has_keys(Space::Handshake),
    ];
    let mut rang = pente(connexion.state());
    let mut echeance_de_fermeture = None;
    let mut tardifs = 0_u32;
    let mut reponses = 0_u32;

    for evenement in entree.evenements {
        match evenement {
            Evenement::Datagramme(octets) => {
                recu_total = recu_total.saturating_add(u64::from(octets));
                connexion.on_datagram_received(u64::from(octets));
            }
            Evenement::Traite(quel, quand) => {
                connexion.on_packet_processed(espace(quel), u64::from(quand));
            }
            Evenement::Emis(quel, octets, eliciting, quand) => {
                connexion.on_packet_sent(
                    espace(quel),
                    u64::from(octets),
                    eliciting,
                    u64::from(quand),
                );
            }
            Evenement::Confirmee => connexion.on_handshake_confirmed(),
            Evenement::Ferme(quand) => connexion.close(pto, u64::from(quand)),
            Evenement::PairFerme(quand) => {
                connexion.on_connection_close(pto, u64::from(quand));
            }
            Evenement::Echeance(quand) => {
                connexion.on_timeout(pto, u64::from(quand));
            }
            Evenement::Tardif => {
                tardifs = tardifs.saturating_add(1);
                if connexion.should_answer() {
                    reponses = reponses.saturating_add(1);
                    // PROPRIÉTÉ 6 : on ne répond jamais en drainage.
                    assert_eq!(
                        connexion.state(),
                        State::Closing,
                        "on a répondu hors de `Closing`"
                    );
                }
            }
        }

        // PROPRIÉTÉ 2 : le crédit reste sous trois fois ce qu'on a reçu.
        if !connexion.address_validated() {
            assert!(
                connexion.send_budget() <= recu_total.saturating_mul(AMPLIFICATION_FACTOR),
                "le crédit dépasse la borne d'amplification"
            );
        }

        // PROPRIÉTÉ 3 : une adresse validée ne se dévalide pas.
        assert!(
            connexion.address_validated() || !valide,
            "l'adresse s'est dévalidée"
        );
        valide = connexion.address_validated();

        // PROPRIÉTÉ 4 : une clé jetée ne revient pas.
        for (rang_de_clef, espace) in [Space::Initial, Space::Handshake].into_iter().enumerate() {
            let a_present = connexion.has_keys(espace);
            let avant = clefs.get_mut(rang_de_clef).expect("deux clés");
            assert!(!a_present || *avant, "une clé {espace:?} est revenue");
            *avant = a_present;
        }

        // PROPRIÉTÉ 5 : l'état ne remonte pas la pente.
        let a_present = pente(connexion.state());
        assert!(
            a_present >= rang,
            "l'état est remonté de {rang} à {a_present}"
        );
        rang = a_present;

        // PROPRIÉTÉ 7 : une échéance de fermeture ne se repousse pas.
        if connexion.state().s_eteint() {
            let echeance = connexion
                .deadline(pto)
                .expect("une fermeture a une échéance");
            if let Some(avant) = echeance_de_fermeture {
                assert!(echeance <= avant, "l'échéance a été repoussée");
            }
            echeance_de_fermeture = Some(echeance);
        }

        // Une connexion éteinte n'a plus d'échéance, et ne répond plus.
        if matches!(connexion.state(), State::Closed) {
            assert_eq!(connexion.deadline(pto), None);
            assert!(!connexion.should_answer());
        }
    }

    // PROPRIÉTÉ 6 : le nombre de réponses reste logarithmique.
    let plafond = u32::BITS.saturating_add(1);
    assert!(
        reponses <= plafond,
        "{reponses} réponses pour {tardifs} paquets : la limitation ne tient pas"
    );
});
