// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : le tri des datagrammes arrivés** (§5.2 de RFC 9000).
//!
//! # Pourquoi celle-ci
//!
//! **C'est le tout premier code que touche un octet venu du réseau**, et il le
//! touche avant que quoi que ce soit soit authentifié. Le port est ouvert au
//! monde entier ; ce module voit des connexions en cours, des clients neufs,
//! des balayages de port, des paquets forgés avec une adresse source usurpée, et
//! des octets qui ne sont pas du QUIC du tout.
//!
//! Les autres cibles éprouvent du code qu'on n'atteint qu'après avoir déchiffré.
//! Celle-ci éprouve ce qui décide **si** l'on déchiffre.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **UN DATAGRAMME TROP PETIT N'OUVRE JAMAIS DE CONNEXION.** C'est la garde
//!    d'amplification au plus tôt (§14.1) : sans elle, un attaquant obtient
//!    trois fois un tout petit datagramme, autant de fois qu'il veut.
//! 3. **ON NE RÉPOND JAMAIS À UN PETIT DATAGRAMME.** Ni `New` ni `Negotiate`
//!    en deçà de 1200 octets — les deux font émettre, et émettre plus qu'on n'a
//!    reçu fait de ce port un amplificateur.
//! 4. **CE QUI EST À QUELQU'UN LUI VA, ET RIEN D'AUTRE.** `Route::Connection(n)`
//!    ne sort que si l'appelant a dit `Some(n)`, et avec le même `n`.
//! 5. **LA DÉCISION NE DÉPEND QUE DE CE QUI EST LU.** Deux lectures des mêmes
//!    octets donnent la même `Incoming`, et la même route.
//! 6. **UN SERVEUR NE SE LAISSE JAMAIS DIRE QU'IL A REÇU UN `Retry` OU UNE
//!    NÉGOCIATION.** Ces deux-là se jettent, quoi que dise la carte.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_proto_quic::{LongKind, VERSION_1};
use ams_quic::{Discard, INITIAL_DATAGRAM_OCTETS_MIN, Incoming, PacketKind, Route};

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// Le datagramme, tel qu'il sort de la carte réseau.
    datagramme: &'a [u8],
    /// Ce que la carte de l'appelant répond, s'il connaît cet identifiant.
    connu: Option<usize>,
    /// La longueur d'identifiant employée pour lire — la nôtre, ou une autre.
    ///
    /// **ELLE NE DEVRAIT JAMAIS VARIER EN PRODUCTION** (§17.3 : elle n'est pas
    /// sur le fil), mais rien dans le type ne l'impose, et ce qui n'est pas
    /// imposé se soumet.
    longueur: u8,
}

fuzz_target!(|entree: Entree| {
    // Une longueur d'identifiant plus grande que ce que §17.2 permet n'existe
    // pas ; le reste se soumet.
    let longueur = usize::from(entree.longueur % 21);

    let Ok(arrivee) = Incoming::read(entree.datagramme, longueur) else {
        // Un refus de lecture n'a qu'une forme, et c'est délibéré : distinguer
        // un bit fixe absent d'une troncature apprendrait, à qui balaie le
        // port, ce que nous savons lire.
        assert_eq!(
            Incoming::read(entree.datagramme, longueur),
            Err(Discard::NotAPacket)
        );
        return;
    };

    // PROPRIÉTÉ 5 : la lecture est une fonction de ses octets.
    let encore = Incoming::read(entree.datagramme, longueur).expect("lisible deux fois");
    assert_eq!(arrivee, encore, "deux lectures des mêmes octets diffèrent");

    // Ce qu'on a lu décrit bien le datagramme qu'on a donné.
    assert_eq!(arrivee.datagram_len(), entree.datagramme.len());
    assert_eq!(
        arrivee.big_enough_for_initial(),
        entree.datagramme.len() >= INITIAL_DATAGRAM_OCTETS_MIN
    );
    assert!(
        arrivee.destination().len() <= 20,
        "§17.2 borne un identifiant à vingt octets"
    );

    let route = arrivee.route(entree.connu);
    assert_eq!(
        route,
        arrivee.route(entree.connu),
        "la route n'est pas stable"
    );

    // PROPRIÉTÉ 2 et 3 : rien ne part en réponse à un petit datagramme.
    if !arrivee.big_enough_for_initial() {
        assert_ne!(
            route,
            Route::New,
            "un datagramme trop petit ne doit pas ouvrir de connexion (§14.1)"
        );
        assert_ne!(
            route,
            Route::Negotiate,
            "on ne répond pas à un petit datagramme (§5.2.2)"
        );
    }

    match route {
        // PROPRIÉTÉ 4 : ce rang-là vient de l'appelant, et de nulle part ailleurs.
        Route::Connection(rang) => {
            assert_eq!(
                entree.connu,
                Some(rang),
                "une connexion est sortie sans que la carte l'ait dite"
            );
            // Et seuls des paquets d'une version qu'on sert y parviennent.
            assert_eq!(arrivee.version(), VERSION_1);
            assert!(matches!(
                arrivee.kind(),
                Some(PacketKind::Short | PacketKind::Long(_))
            ));
            assert_ne!(arrivee.kind(), Some(PacketKind::Long(LongKind::Retry)));
        }
        // Une connexion neuve n'est jamais annoncée par autre chose qu'un
        // `Initial` de notre version, assez grand.
        Route::New => {
            assert_eq!(entree.connu, None);
            assert_eq!(arrivee.version(), VERSION_1);
            assert_eq!(arrivee.kind(), Some(PacketKind::Long(LongKind::Initial)));
            assert!(arrivee.big_enough_for_initial());
        }
        // On ne négocie que ce qu'on ne sert pas.
        Route::Negotiate => {
            assert_ne!(arrivee.version(), VERSION_1);
            assert_ne!(arrivee.version(), 0, "§6.1 : on ne répond pas à zéro");
            assert!(arrivee.kind().is_some());
            assert!(arrivee.big_enough_for_initial());
        }
        Route::Drop(pourquoi) => {
            // PROPRIÉTÉ 6, et le vocabulaire est fini.
            match pourquoi {
                Discard::VersionNegotiation => {
                    assert_eq!(arrivee.version(), 0);
                    assert_eq!(arrivee.kind(), None, "§17.2.1 : elle n'a pas de type");
                }
                Discard::Retry => {
                    assert_eq!(arrivee.kind(), Some(PacketKind::Long(LongKind::Retry)));
                }
                Discard::InitialTooSmall => {
                    assert!(!arrivee.big_enough_for_initial());
                    assert_eq!(arrivee.kind(), Some(PacketKind::Long(LongKind::Initial)));
                    assert_eq!(entree.connu, None);
                }
                Discard::UnknownVersionTooSmall => {
                    assert_ne!(arrivee.version(), VERSION_1);
                    assert!(!arrivee.big_enough_for_initial());
                }
                Discard::HandshakeWithoutConnection => {
                    assert_eq!(arrivee.kind(), Some(PacketKind::Long(LongKind::Handshake)));
                    assert_eq!(entree.connu, None);
                }
                Discard::EarlyDataWithoutConnection => {
                    assert_eq!(arrivee.kind(), Some(PacketKind::Long(LongKind::ZeroRtt)));
                    assert_eq!(entree.connu, None);
                }
                Discard::UnknownConnection => {
                    assert_eq!(arrivee.kind(), Some(PacketKind::Short));
                    assert_eq!(entree.connu, None);
                }
                // Un refus de LECTURE ne peut pas sortir d'un routage : la
                // lecture a déjà réussi.
                Discard::NotAPacket => {
                    panic!("NotAPacket ne se décide pas au routage")
                }
            }
        }
    }

    // **ET UN `Retry` OU UNE NÉGOCIATION SE JETTENT QUOI QUE DISE LA CARTE.**
    // C'est ce qui les distingue de tout le reste : leur seule présence est
    // déjà une faute côté serveur, et une carte complaisante ne les rattrape
    // pas.
    for pretendu in [None, Some(0_usize), Some(usize::MAX)] {
        match arrivee.kind() {
            None => assert_eq!(
                arrivee.route(pretendu),
                Route::Drop(Discard::VersionNegotiation)
            ),
            Some(PacketKind::Long(LongKind::Retry)) => {
                assert_eq!(arrivee.route(pretendu), Route::Drop(Discard::Retry));
            }
            Some(_) => {}
        }
    }
});
