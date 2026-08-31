// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : les en-têtes de paquet de §17**, longs et courts.
//!
//! # Pourquoi celle-ci
//!
//! L'en-tête est ce qu'on lit AVANT d'avoir la moindre clé. Tout ce qui s'y
//! trompe se trompe sur des octets qu'un inconnu a choisis, et qui peuvent venir
//! de n'importe où — le port est ouvert au monde entier. C'est la seule partie
//! de QUIC qu'on traite sans savoir à qui l'on parle.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **CE QU'ON REND EST DANS CE QU'ON A REÇU** : le jeton, les versions et le
//!    reste sont des sous-tranches du paquet, et l'endroit où commence le numéro
//!    ne dépasse jamais sa fin.
//! 3. **UN IDENTIFIANT RENDU TIENT DANS SES VINGT OCTETS**, toujours. C'est la
//!    seule borne qui empêche un pair de choisir combien on retient de lui.
//! 4. **UN `Retry` GARDE SES SEIZE OCTETS D'AUTHENTIFICATION**, et son jeton ne
//!    les recouvre pas.
//! 5. **LA FORME SE LIT D'UN SEUL BIT**, et les deux lectures ne se contredisent
//!    jamais : ce qui se lit comme un en-tête long n'est pas un en-tête court.
//! 6. **LA LONGUEUR D'UN IDENTIFIANT COURT VIENT DE NOUS**, et une longueur
//!    au-delà de vingt se refuse même quand c'est nous qui la demandons.
//! 7. **UNE TRAME LUE A CONSOMMÉ CE QU'ELLE DIT AVOIR CONSOMMÉ**, jamais plus
//!    que ce qu'on lui a donné, et jamais zéro. Une trame ne porte pas sa
//!    longueur : un décodeur qui n'avance pas boucle sans fin, et un décodeur
//!    qui avance trop lit le paquet suivant comme le sien.
//! 8. **CE QU'UNE TRAME REND EST DANS CE QU'ON A DONNÉ** : chaque tranche est
//!    une sous-tranche du tampon, et aucune longueur n'excède sa source.
//! 9. **DES PARAMÈTRES DE TRANSPORT ACCEPTÉS SONT DES PARAMÈTRES UTILISABLES** :
//!    chaque borne de §18.2 tient, et ce qu'un CLIENT n'a pas le droit
//!    d'annoncer n'est jamais retenu de lui.
//! 10. **UNE TRAME LUE SE RÉÉCRIT ET SE RELIT IDENTIQUE.** C'est la propriété
//!     qui couvre les combinaisons auxquelles personne n'a pensé — un décodeur
//!     sans encodeur ne se vérifie que sur des exemples. Les OCTETS, eux,
//!     peuvent différer : le pair a pu écrire un entier plus long que
//!     nécessaire, et §16 le permet.
//! 11. **UN `ACK` ACQUITTE EXACTEMENT CE QU'ON A REÇU**, et rien d'autre.
//!     Acquitter un paquet qu'on n'a pas reçu ferait croire à l'émetteur qu'il
//!     est arrivé, et il ne le retransmettrait jamais. C'est le seul défaut de
//!     cette famille qui ne se voit pas : la connexion continue, en perdant des
//!     données.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_proto_quic::{
    CONNECTION_ID_MAX, Frame, Long, LongKind, MAX_ACK_DELAY_LIMIT_MS, MAX_STREAMS_LIMIT,
    MIN_ACTIVE_CONNECTION_ID_LIMIT, MIN_UDP_PAYLOAD_SIZE, RETRY_TAG_OCTETS, Received, Sender,
    ShortHeader, TransportParameters, VERSION_NEGOTIATION, is_long, parse_long,
};

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// Un paquet, tel qu'il arriverait du réseau.
    paquet: &'a [u8],
    /// La longueur d'identifiant qu'on croit avoir émise.
    longueur: u8,
}

fuzz_target!(|entree: Entree| {
    let paquet = entree.paquet;

    // PROPRIÉTÉ 5 : la forme se lit d'un seul bit, et les deux lectures ne se
    // contredisent pas.
    let longue = is_long(paquet);
    if let Ok(lu) = parse_long(paquet) {
        assert!(longue, "un en-tête long qui ne se dit pas long");
        match lu {
            Long::Numbered(entete) => {
                // PROPRIÉTÉ 2 : le numéro commence DANS le paquet.
                assert!(
                    entete.number_offset() <= paquet.len(),
                    "le numéro commence hors du paquet"
                );
                // PROPRIÉTÉ 3 : les identifiants tiennent dans leurs bornes.
                assert!(entete.destination().len() <= CONNECTION_ID_MAX);
                assert!(entete.source().len() <= CONNECTION_ID_MAX);
                // Le jeton est une sous-tranche, et seul un `Initial` en a un.
                assert!(entete.token().len() <= paquet.len());
                if entete.kind() != LongKind::Initial {
                    assert!(entete.token().is_empty(), "un jeton hors d'un Initial");
                }
                assert_ne!(
                    entete.kind(),
                    LongKind::Retry,
                    "un Retry n'est pas numéroté"
                );
                assert_ne!(entete.version(), VERSION_NEGOTIATION);
            }
            Long::Retry(retry) => {
                // PROPRIÉTÉ 4 : le jeton ne recouvre pas le tag.
                assert!(
                    retry.token.len().saturating_add(RETRY_TAG_OCTETS) <= paquet.len(),
                    "le jeton et le tag ne tiennent pas dans le paquet"
                );
                assert!(retry.destination.len() <= CONNECTION_ID_MAX);
                assert!(retry.source.len() <= CONNECTION_ID_MAX);
            }
            Long::Negotiation(negociation) => {
                assert!(negociation.versions.len() <= paquet.len());
                assert!(negociation.destination.len() <= CONNECTION_ID_MAX);
                assert!(negociation.source.len() <= CONNECTION_ID_MAX);
            }
        }
    }

    // PROPRIÉTÉ 6 : la longueur vient de nous, et elle a quand même sa borne.
    let longueur = usize::from(entree.longueur);
    match ShortHeader::parse(paquet, longueur) {
        Ok(entete) => {
            assert!(!longue, "un en-tête court qui se dit long");
            assert!(
                longueur <= CONNECTION_ID_MAX,
                "une longueur hors borne a passé"
            );
            assert_eq!(entete.destination().len(), longueur);
            assert!(
                entete.number_offset() <= paquet.len(),
                "le numéro commence hors du paquet"
            );
            // L'identifiant rendu est bien celui qui était là.
            assert_eq!(
                entete.destination().as_bytes(),
                paquet.get(1..entete.number_offset()).unwrap_or_default()
            );
        }
        Err(_) => {}
    }

    // PROPRIÉTÉS 7 et 8 : les trames se lisent l'une après l'autre, et chacune
    // avance d'au moins un octet.
    let mut reste = paquet;
    let mut tours = 0_u32;
    while let Ok((trame, lus)) = Frame::parse(reste) {
        tours = tours.saturating_add(1);
        assert!(tours < 100_000, "le décodeur de trames n'avance pas");
        assert!(lus >= 1, "une trame rendue sans consommer d'octet");
        assert!(
            lus <= reste.len(),
            "une trame a consommé {lus} octets pour {}",
            reste.len()
        );
        verifier(&trame, reste);
        // PROPRIÉTÉ 10 : ce qu'on a lu se réécrit et se relit identique.
        let mut reecrit = [0_u8; 4096];
        if let Ok(poses) = trame.write(&mut reecrit) {
            let (relue, encore) = Frame::parse(reecrit.get(..poses).unwrap_or_default())
                .expect("ce qu'on écrit se relit");
            assert_eq!(relue, trame, "un aller-retour a changé la trame");
            assert_eq!(encore, poses, "on relit exactement ce qu'on a écrit");
        }
        reste = reste.get(lus..).unwrap_or_default();
        if reste.is_empty() {
            break;
        }
    }

    // PROPRIÉTÉ 11 : un `ACK` acquitte exactement ce qu'on a reçu.
    {
        let mut recu = Received::new();
        let mut vus = std::collections::BTreeSet::new();
        // Les octets du paquet, pris deux par deux, font des numéros.
        for paire in paquet.chunks_exact(2).take(64) {
            let numero = u64::from(u16::from_be_bytes([paire[0], paire[1]]));
            let sollicite = numero % 3 != 0;
            recu.on_received(numero, sollicite, numero)
                .expect("sous la borne");
            vus.insert(numero);
        }
        if let Some(plus_grand) = recu.largest() {
            assert_eq!(
                Some(plus_grand),
                vus.iter().next_back().copied(),
                "le plus grand reçu n'est pas le plus grand vu"
            );
            let mut sortie = [0_u8; 1024];
            let ecrits = recu
                .write_ack(0, 0, &mut sortie)
                .expect("écrivable")
                .expect("il y a de quoi acquitter");
            let (trame, lus) =
                Frame::parse(sortie.get(..ecrits).unwrap_or_default()).expect("relisible");
            assert_eq!(lus, ecrits);
            let Frame::Ack(ack) = trame else {
                panic!("ce devait être un ACK");
            };
            // **TOUT CE QUE L'ACK COUVRE A ÉTÉ REÇU.** L'inverse n'est pas vrai :
            // §13.2.3 permet d'oublier les plus anciens.
            let mut haut = ack.largest;
            let mut bas = ack.largest.saturating_sub(ack.first_range);
            for numero in bas..=haut {
                assert!(vus.contains(&numero), "l'ACK couvre {numero}, jamais reçu");
                assert!(recu.contains(numero));
            }
            for issue in ack.ranges() {
                let intervalle = issue.expect("lisible");
                haut = bas
                    .checked_sub(intervalle.gap.saturating_add(2))
                    .expect("un intervalle sous zéro");
                bas = haut.saturating_sub(intervalle.length);
                for numero in bas..=haut {
                    assert!(vus.contains(&numero), "l'ACK couvre {numero}, jamais reçu");
                }
            }
        }
    }

    // PROPRIÉTÉ 9 : les mêmes octets lus comme des paramètres de transport.
    for de in [Sender::Client, Sender::Server] {
        let Ok(lus) = TransportParameters::read(paquet, de) else {
            continue;
        };
        assert!(lus.max_udp_payload_size >= MIN_UDP_PAYLOAD_SIZE);
        assert!(lus.initial_max_streams_bidi <= MAX_STREAMS_LIMIT);
        assert!(lus.initial_max_streams_uni <= MAX_STREAMS_LIMIT);
        assert!(lus.ack_delay_exponent <= 20);
        assert!(lus.max_ack_delay_ms < MAX_ACK_DELAY_LIMIT_MS);
        assert!(lus.active_connection_id_limit >= MIN_ACTIVE_CONNECTION_ID_LIMIT);
        for id in [
            lus.initial_source_connection_id,
            lus.original_destination_connection_id,
            lus.retry_source_connection_id,
        ] {
            assert!(id.is_none_or(|id| id.len() <= CONNECTION_ID_MAX));
        }
        // **CE QU'UN CLIENT N'A PAS LE DROIT D'ANNONCER N'EST JAMAIS RETENU DE
        // LUI** : le laisser réécrirait ce qui prouve que la poignée de main
        // n'a pas été détournée.
        if matches!(de, Sender::Client) {
            assert!(lus.original_destination_connection_id.is_none());
            assert!(lus.retry_source_connection_id.is_none());
        }

        // **ET CE QU'ON RÉÉCRIT SE RELIT À L'IDENTIQUE.**
        //
        // Les paramètres voyagent dans une extension TLS : un pair qui les
        // relirait autrement qu'on ne les a écrits prendrait nos limites pour
        // d'autres — sans que rien ne le dise, jusqu'à ce qu'un flux se fige.
        // La propriété va dans les deux sens, et c'est ce qui la rend forte :
        // ce qu'un pair a pu écrire, nous devons savoir le réécrire.
        let mut reecrits = std::vec![0_u8; paquet.len().saturating_mul(2).saturating_add(256)];
        let ecrits = lus
            .write(de, &mut reecrits)
            .expect("ce qui a été lu doit pouvoir être réécrit");
        let relus = TransportParameters::read(reecrits.get(..ecrits).unwrap_or_default(), de)
            .expect("ce qu'on écrit doit se relire");
        assert_eq!(relus, lus, "l'aller-retour a changé les paramètres");
    }
});

/// Ce qu'une trame rend est dans ce qu'on lui a donné.
fn verifier(trame: &Frame<'_>, source: &[u8]) {
    match trame {
        Frame::Padding { count } => assert!(*count <= source.len()),
        Frame::Crypto { data, .. } | Frame::Stream { data, .. } => {
            assert!(
                data.len() <= source.len(),
                "une tranche plus longue que sa source"
            );
        }
        Frame::NewToken { token } => assert!(token.len() <= source.len()),
        Frame::ConnectionClose { reason, .. } => assert!(reason.len() <= source.len()),
        Frame::Ack(ack) => {
            assert!(ack.encoded_ranges.len() <= source.len());
            // Le parcours s'arrête : il ne rend jamais plus d'intervalles qu'il
            // n'en a annoncé.
            let vus = ack.ranges().count();
            assert!(u64::try_from(vus).unwrap_or(u64::MAX) <= ack.range_count);
        }
        Frame::MaxStreams { maximum, .. } => assert!(*maximum <= MAX_STREAMS_LIMIT),
        Frame::StreamsBlocked { limit, .. } => assert!(*limit <= MAX_STREAMS_LIMIT),
        Frame::NewConnectionId {
            sequence,
            retire_prior_to,
            id,
            ..
        } => {
            assert!(retire_prior_to <= sequence, "un retrait au-delà du rang");
            assert!(!id.is_empty(), "§19.15 veut au moins un octet");
            assert!(id.len() <= CONNECTION_ID_MAX);
        }
        Frame::Ping
        | Frame::ResetStream { .. }
        | Frame::StopSending { .. }
        | Frame::MaxData { .. }
        | Frame::MaxStreamData { .. }
        | Frame::DataBlocked { .. }
        | Frame::StreamDataBlocked { .. }
        | Frame::RetireConnectionId { .. }
        | Frame::PathChallenge { .. }
        | Frame::PathResponse { .. }
        | Frame::HandshakeDone => {}
    }
}
