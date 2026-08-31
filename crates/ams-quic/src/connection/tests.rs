// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une connexion a le droit de faire.

use ams_proto_quic::Space;
use ams_quic_crypto::Role;

use super::{AMPLIFICATION_FACTOR, CLOSING_PTOS, Connection, IDLE_PTOS, State};

/// Un délai de retransmission commode, en microsecondes.
const PTO: u64 = 100_000;

/// Une connexion neuve est en poignée de main.
#[test]
fn une_connexion_neuve_est_en_poignee_de_main() {
    let connexion = Connection::new(Role::Server, 30_000_000, 30_000_000, 0);
    assert_eq!(connexion.state(), State::Handshaking);
    assert_eq!(connexion.role(), Role::Server);
    assert!(connexion.state().vivante());
    assert!(!connexion.state().s_eteint());
    // Toutes les clés sont là.
    for espace in [Space::Initial, Space::Handshake, Space::Application] {
        assert!(connexion.has_keys(espace), "{espace:?}");
    }
}

/// **LE DÉLAI EFFECTIF EST LE PLUS PETIT DES DEUX NON NULS** (§10.1) : un pair
/// qui n'annonce rien accepte de rester indéfiniment, et n'annule pas le délai
/// de celui qui en voulait un.
#[test]
fn le_delai_effectif_est_le_plus_petit_des_deux_non_nuls() {
    let cas = [
        (30_000_000_u64, 10_000_000_u64, 10_000_000_u64),
        (10_000_000, 30_000_000, 10_000_000),
        (0, 30_000_000, 30_000_000),
        (30_000_000, 0, 30_000_000),
        (0, 0, 0),
    ];
    for (annonce, recu, attendu) in cas {
        let connexion = Connection::new(Role::Server, annonce, recu, 0);
        assert_eq!(
            connexion.idle_timeout(),
            attendu,
            "{annonce} et {recu} donnent {attendu}"
        );
    }
}

/// **UN CLIENT N'A PAS D'ADRESSE À VALIDER** : c'est lui qui a écrit le premier.
#[test]
fn un_client_n_a_pas_d_adresse_a_valider() {
    let client = Connection::new(Role::Client, 0, 0, 0);
    assert!(client.address_validated());
    assert_eq!(client.send_budget(), u64::MAX);
    assert!(!client.amplification_limited());

    let serveur = Connection::new(Role::Server, 0, 0, 0);
    assert!(!serveur.address_validated());
    assert_eq!(serveur.send_budget(), 0);
    assert!(serveur.amplification_limited());
}

/// **TANT QUE L'ADRESSE N'EST PAS VALIDÉE, ON N'ÉMET PAS PLUS DE TROIS FOIS CE
/// QU'ON A REÇU** (§8.1). C'est ce qui empêche notre serveur d'être l'arme de
/// quelqu'un d'autre.
#[test]
fn la_borne_d_amplification_tient() {
    let mut connexion = Connection::new(Role::Server, 0, 0, 0);
    // Un `Initial` rembourré de mille deux cents octets, comme §8.1 l'exige du
    // client.
    connexion.on_datagram_received(1_200);
    assert_eq!(connexion.send_budget(), 1_200 * AMPLIFICATION_FACTOR);

    connexion.on_packet_sent(Space::Initial, 1_200, true, 0);
    assert_eq!(connexion.send_budget(), 2_400);
    connexion.on_packet_sent(Space::Initial, 2_400, true, 0);
    assert_eq!(connexion.send_budget(), 0);
    assert!(connexion.amplification_limited());

    // Le client répond, et le robinet se rouvre d'autant.
    connexion.on_datagram_received(1_200);
    assert_eq!(connexion.send_budget(), 3_600);
}

/// **ON NE DESCEND PAS SOUS ZÉRO** : un appelant qui dépasse la borne n'obtient
/// pas un crédit immense par débordement. Ce qu'il a émis en trop reste compté,
/// et c'est ce qui compte : le crédit ne se rétablit qu'en recevant vraiment.
#[test]
fn le_credit_ne_deborde_pas() {
    let mut connexion = Connection::new(Role::Server, 0, 0, 0);
    connexion.on_datagram_received(100);
    connexion.on_packet_sent(Space::Initial, 5_000, true, 0);
    assert_eq!(connexion.send_budget(), 0);
    // Cent octets de plus ne rendent pas trois cents : les cinq mille sont
    // toujours là.
    connexion.on_datagram_received(100);
    assert_eq!(connexion.send_budget(), 0);
}

/// **ON COMPTE TOUT CE QUI ARRIVE** (§8.1), y compris les paquets qu'on a
/// jetés : ne compter que ce qu'on sait lire donnerait moins de crédit à un pair
/// honnête dont un paquet s'est perdu qu'à celui qui n'envoie que du bruit.
#[test]
fn le_credit_compte_meme_ce_qu_on_jette() {
    let mut connexion = Connection::new(Role::Server, 0, 0, 0);
    // Rien n'est traité : seul le datagramme est compté.
    connexion.on_datagram_received(500);
    assert_eq!(connexion.send_budget(), 1_500);
}

/// **UN `Handshake` VALIDE L'ADRESSE, ET C'EST GRATUIT** (§8.1) : ses clés ne se
/// dérivent qu'après avoir lu les trames `CRYPTO` de l'`Initial`, ce qu'un
/// attaquant qui usurpe une adresse ne peut pas faire.
#[test]
fn un_handshake_valide_l_adresse() {
    let mut connexion = Connection::new(Role::Server, 0, 0, 0);
    connexion.on_datagram_received(1_200);
    connexion.on_packet_processed(Space::Initial, 0);
    assert!(
        !connexion.address_validated(),
        "un `Initial` ne valide rien"
    );

    connexion.on_packet_processed(Space::Handshake, 0);
    assert!(connexion.address_validated());
    assert_eq!(
        connexion.send_budget(),
        u64::MAX,
        "la borne ne s'applique plus"
    );
    assert!(!connexion.amplification_limited());
}

/// **LES CLÉS `Initial` PARTENT DÈS QUE LE `Handshake` SERT** (§4.9.1 de
/// RFC 9001), et pas au même moment des deux côtés : le client les jette quand
/// il ÉMET son premier `Handshake`, le serveur quand il en TRAITE un.
#[test]
fn les_clefs_initiales_partent_des_que_le_handshake_sert() {
    let mut serveur = Connection::new(Role::Server, 0, 0, 0);
    serveur.on_packet_sent(Space::Handshake, 100, true, 0);
    assert!(
        serveur.has_keys(Space::Initial),
        "un serveur qui ÉMET ne jette rien"
    );
    serveur.on_packet_processed(Space::Handshake, 0);
    assert!(!serveur.has_keys(Space::Initial));

    let mut client = Connection::new(Role::Client, 0, 0, 0);
    client.on_packet_processed(Space::Handshake, 0);
    assert!(
        client.has_keys(Space::Initial),
        "un client qui TRAITE ne jette rien"
    );
    client.on_packet_sent(Space::Handshake, 100, true, 0);
    assert!(!client.has_keys(Space::Initial));
    // Et les autres espaces sont intacts.
    assert!(client.has_keys(Space::Handshake));
    assert!(client.has_keys(Space::Application));
}

/// **LA CONFIRMATION EMPORTE LES CLÉS `Handshake`** (§4.9.2 de RFC 9001) : les
/// garder laisserait une protection plus faible utilisable après qu'une plus
/// forte est disponible.
#[test]
fn la_confirmation_emporte_les_clefs_de_poignee_de_main() {
    let mut connexion = Connection::new(Role::Server, 0, 0, 0);
    connexion.on_handshake_confirmed();
    assert_eq!(connexion.state(), State::Confirmed);
    assert!(!connexion.has_keys(Space::Initial));
    assert!(!connexion.has_keys(Space::Handshake));
    assert!(connexion.has_keys(Space::Application));
    assert!(connexion.address_validated());

    // Une seconde confirmation ne fait rien.
    connexion.on_handshake_confirmed();
    assert_eq!(connexion.state(), State::Confirmed);
}

/// Une connexion en fermeture ne revient pas à la vie.
#[test]
fn une_connexion_qui_ferme_ne_revient_pas() {
    let mut connexion = Connection::new(Role::Server, 0, 0, 0);
    connexion.close(PTO, 1_000);
    connexion.on_handshake_confirmed();
    assert_eq!(connexion.state(), State::Closing);
}

/// **ON RESTE LÀ TROIS DÉLAIS** (§10.2) : disparaître tout de suite ferait
/// répondre par un `Stateless Reset` au prochain paquet en retard.
#[test]
fn la_fermeture_dure_trois_delais() {
    let mut connexion = Connection::new(Role::Server, 0, 0, 0);
    connexion.close(PTO, 1_000);
    assert_eq!(connexion.state(), State::Closing);
    assert!(connexion.state().s_eteint());
    assert!(!connexion.state().vivante());

    let echeance = 1_000 + PTO * CLOSING_PTOS;
    assert_eq!(connexion.deadline(PTO), Some(echeance));
    assert!(!connexion.on_timeout(PTO, echeance - 1), "pas encore");
    assert_eq!(connexion.state(), State::Closing);
    assert!(connexion.on_timeout(PTO, echeance));
    assert_eq!(connexion.state(), State::Closed);
    assert_eq!(connexion.deadline(PTO), None);
    // Et une échéance de plus ne rend plus rien.
    assert!(!connexion.on_timeout(PTO, echeance + 1_000_000));

    // Fermer une connexion déjà éteinte ne fait rien.
    connexion.close(PTO, 0);
    assert_eq!(connexion.state(), State::Closed);
}

/// **VENANT DE `Closing`, L'ÉCHÉANCE NE BOUGE PAS** (§10.2.2) : la repousser
/// laisserait un pair prolonger notre état en fermant après nous.
#[test]
fn le_drainage_garde_l_echeance_de_la_fermeture() {
    let mut connexion = Connection::new(Role::Server, 0, 0, 0);
    connexion.close(PTO, 1_000);
    let echeance = connexion.deadline(PTO);
    // Le pair ferme bien plus tard.
    connexion.on_connection_close(PTO, 2_000_000);
    assert_eq!(connexion.state(), State::Draining);
    assert_eq!(
        connexion.deadline(PTO),
        echeance,
        "l'échéance a été repoussée"
    );

    // Et un second `CONNECTION_CLOSE` ne fait rien.
    connexion.on_connection_close(PTO, 9_000_000);
    assert_eq!(connexion.deadline(PTO), echeance);
}

/// Le pair ferme le premier : on draine à partir de maintenant.
#[test]
fn le_pair_qui_ferme_nous_fait_drainer() {
    let mut connexion = Connection::new(Role::Server, 0, 0, 0);
    connexion.on_connection_close(PTO, 1_000);
    assert_eq!(connexion.state(), State::Draining);
    assert_eq!(connexion.deadline(PTO), Some(1_000 + PTO * CLOSING_PTOS));

    // **ET EN `Draining`, ON NE RÉPOND JAMAIS** (§10.2.2) : sans cette règle,
    // deux pairs qui se répondent échangeraient des `CONNECTION_CLOSE` jusqu'à
    // ce que l'un des deux abandonne.
    assert!(!connexion.should_answer());
}

/// **ON RÉPOND DE MOINS EN MOINS SOUVENT** (§10.2.1) : sans cela, on
/// amplifierait au moment précis où l'on n'a plus rien à dire.
#[test]
fn on_repond_de_moins_en_moins_souvent() {
    let mut connexion = Connection::new(Role::Server, 0, 0, 0);
    connexion.close(PTO, 0);
    // Les rangs auxquels on répond : un, deux, quatre, huit, seize.
    let attendus = [1_u64, 2, 4, 8, 16];
    let mut repondus = std::vec::Vec::new();
    for rang in 1..=20_u64 {
        if connexion.should_answer() {
            repondus.push(rang);
        }
    }
    assert_eq!(repondus, attendus);

    // Une connexion vivante ne répond pas non plus : elle n'a rien à redire.
    let mut vivante = Connection::new(Role::Server, 0, 0, 0);
    assert!(!vivante.should_answer());
}

/// **L'INACTIVITÉ FERME EN SILENCE** (§10.1), et son délai repart à chaque
/// paquet traité.
#[test]
fn l_inactivite_ferme_en_silence() {
    let delai = 30_000_000_u64;
    let mut connexion = Connection::new(Role::Server, delai, delai, 1_000);
    assert_eq!(connexion.deadline(PTO), Some(1_000 + delai));

    // Un paquet traité relance le compte.
    connexion.on_packet_processed(Space::Initial, 5_000_000);
    assert_eq!(connexion.deadline(PTO), Some(5_000_000 + delai));
    assert!(!connexion.on_timeout(PTO, 5_000_000 + delai - 1));
    assert!(connexion.on_timeout(PTO, 5_000_000 + delai));
    assert_eq!(connexion.state(), State::Closed);
}

/// **SANS DÉLAI NÉGOCIÉ, RIEN N'ÉCHOIT** : les deux pairs ont accepté de rester.
#[test]
fn sans_delai_negocie_rien_n_echoit() {
    let mut connexion = Connection::new(Role::Server, 0, 0, 0);
    assert_eq!(connexion.deadline(PTO), None);
    assert!(!connexion.on_timeout(PTO, u64::MAX));
    assert_eq!(connexion.state(), State::Handshaking);
}

/// **LE PLANCHER DE TROIS DÉLAIS DE RETRANSMISSION** (§10.1) : sans lui, un pair
/// pourrait annoncer une milliseconde et faire expirer toute connexion avant la
/// première retransmission.
#[test]
fn le_plancher_de_trois_delais_tient() {
    let minuscule = 1_000_u64;
    let connexion = Connection::new(Role::Server, minuscule, minuscule, 0);
    assert_eq!(connexion.idle_timeout(), minuscule);
    assert_eq!(
        connexion.deadline(PTO),
        Some(PTO * IDLE_PTOS),
        "le plancher l'emporte"
    );
    // Et un délai plus grand que le plancher l'emporte, lui.
    let grand = 30_000_000_u64;
    let autre = Connection::new(Role::Server, grand, grand, 0);
    assert_eq!(autre.deadline(PTO), Some(grand));
}

/// **LE DÉLAI NE REPART À L'ÉMISSION QUE POUR LE PREMIER PAQUET SUSCITANT UN
/// ACQUITTEMENT** (§10.1) : le remettre à chaque envoi laisserait un pair muet
/// nous retenir indéfiniment, à condition qu'on parle.
#[test]
fn l_emission_ne_relance_le_delai_qu_une_fois() {
    let delai = 30_000_000_u64;
    let mut connexion = Connection::new(Role::Server, delai, delai, 0);
    connexion.on_packet_processed(Space::Application, 1_000);
    assert_eq!(connexion.deadline(PTO), Some(1_000 + delai));

    // Le premier paquet qui suscite un acquittement relance.
    connexion.on_packet_sent(Space::Application, 100, true, 2_000);
    assert_eq!(connexion.deadline(PTO), Some(2_000 + delai));
    // Les suivants, non.
    connexion.on_packet_sent(Space::Application, 100, true, 9_000);
    assert_eq!(connexion.deadline(PTO), Some(2_000 + delai));

    // Un paquet qui n'en suscite pas ne relance jamais.
    connexion.on_packet_processed(Space::Application, 10_000);
    connexion.on_packet_sent(Space::Application, 100, false, 20_000);
    assert_eq!(connexion.deadline(PTO), Some(10_000 + delai));
}
