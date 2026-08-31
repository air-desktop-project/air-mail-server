// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : les flux `CRYPTO` et les règles de §4 de RFC 9001.**
//!
//! # Pourquoi celle-ci
//!
//! Ces octets-là arrivent AVANT que quoi que ce soit soit authentifié. Un
//! paquet `Initial` se déchiffre avec des clés que tout le monde peut dériver
//! (§5.2) : n'importe qui sachant envoyer un datagramme peut donc nourrir ce
//! module, avec les décalages qu'il veut, dans l'ordre qu'il veut.
//!
//! Et ce qu'on range là finit dans la transcription de la poignée de main. Un
//! octet perdu, dupliqué ou mis à la mauvaise place ne se voit pas : il fait
//! simplement échouer la vérification du `Finished`, très loin de sa cause.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets, les décalages et les
//!    niveaux.
//! 2. **CE QUI SORT EST CE QUI EST ENTRÉ, À LA BONNE PLACE.** Un modèle tient
//!    en parallèle ce que chaque décalage devrait porter ; ce que le module rend
//!    doit lui correspondre, octet pour octet.
//! 3. **RIEN NE RECULE.** Le décalage de lecture d'un niveau ne décroît jamais,
//!    et ce qui est prêt ne dépasse jamais la fenêtre.
//! 4. **UN REFUS VIENT D'UN VOCABULAIRE FINI** — les quatre raisons que §4.1.3,
//!    §8.3 et §7.5 nomment, et rien d'autre.
//! 5. **LES TROIS FLUX SONT ÉTANCHES.** Ce qui entre à un niveau ne ressort pas
//!    à un autre.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_quic::{CRYPTO_OCTETS_MAX, Handshake, Level, Reason};

/// Une trame `CRYPTO` soumise.
#[derive(Arbitrary, Debug)]
struct Trame<'a> {
    /// À quel niveau elle arrive.
    niveau: u8,
    /// Son décalage.
    decalage: u64,
    /// Ce qu'elle porte.
    octets: &'a [u8],
    /// Faut-il, après, remettre à TLS ce qui est prêt ?
    prendre: bool,
    /// Et installer un niveau supérieur ?
    installer: Option<u8>,
}

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    trames: std::vec::Vec<Trame<'a>>,
}

/// Le niveau que ce rang désigne.
fn niveau_de(rang: u8) -> Level {
    match rang % 4 {
        0 => Level::Initial,
        1 => Level::ZeroRtt,
        2 => Level::Handshake,
        _ => Level::OneRtt,
    }
}

/// Le rang du flux d'un niveau — `0-RTT` n'en a pas.
fn flux_de(niveau: Level) -> Option<usize> {
    match niveau {
        Level::Initial => Some(0),
        Level::ZeroRtt => None,
        Level::Handshake => Some(1),
        Level::OneRtt => Some(2),
    }
}

fuzz_target!(|entree: Entree| {
    let mut poignee = Handshake::new();
    let mut fenetres = [
        std::vec![0_u8; CRYPTO_OCTETS_MAX],
        std::vec![0_u8; CRYPTO_OCTETS_MAX],
        std::vec![0_u8; CRYPTO_OCTETS_MAX],
    ];
    // **LE MODÈLE** : pour chaque flux, ce que chaque décalage absolu devrait
    // porter, et combien d'octets TLS a déjà pris. C'est lui qui juge, et il
    // n'a rien de commun avec l'implémentation.
    let mut modele: [std::collections::BTreeMap<u64, u8>; 3] = Default::default();
    let mut consommes: [u64; 3] = [0; 3];

    for trame in &entree.trames {
        let niveau = niveau_de(trame.niveau);
        let rang = flux_de(niveau);
        let fenetre = match rang {
            Some(rang) => &mut fenetres[rang],
            // `0-RTT` n'a pas de flux ; on lui donne quand même une fenêtre,
            // pour que le refus vienne de la règle et non d'un manque de place.
            None => &mut fenetres[0],
        };
        let lu_avant = poignee.read_offset(niveau);

        match poignee.on_crypto(niveau, trame.decalage, trame.octets, fenetre) {
            Ok(()) => {
                // Le modèle enregistre ce qui a été accepté — sauf ce qui est
                // déjà parti chez TLS, que le module a le droit d'ignorer.
                let rang = rang.expect("un niveau sans flux ne peut pas accepter");
                for (pas, octet) in trame.octets.iter().enumerate() {
                    let ou = trame
                        .decalage
                        .saturating_add(u64::try_from(pas).unwrap_or(u64::MAX));
                    if ou >= consommes[rang] {
                        modele[rang].insert(ou, *octet);
                    }
                }
            }
            Err(issue) => {
                // PROPRIÉTÉ 4 : un vocabulaire fini.
                assert!(
                    matches!(
                        issue.reason(),
                        Reason::CryptoInZeroRtt
                            | Reason::CryptoAfterLevel
                            | Reason::CryptoNotConsumed
                            | Reason::CryptoBufferExceeded
                            | Reason::TooManyHoles
                    ),
                    "un refus hors du vocabulaire : {:?}",
                    issue.reason()
                );
                // Un refus ne déplace pas la lecture.
                assert_eq!(poignee.read_offset(niveau), lu_avant);
            }
        }

        // PROPRIÉTÉ 3 : rien ne recule, et rien ne dépasse la fenêtre.
        assert!(poignee.read_offset(niveau) >= lu_avant);
        assert!(
            poignee.readable(niveau) <= u64::try_from(CRYPTO_OCTETS_MAX).unwrap_or(u64::MAX),
            "plus de prêt que la fenêtre ne peut en porter"
        );

        if trame.prendre {
            let mut vers = std::vec![0_u8; CRYPTO_OCTETS_MAX];
            let fenetre = match rang {
                Some(rang) => &mut fenetres[rang],
                None => &mut fenetres[0],
            };
            let pris = poignee.take(niveau, fenetre, &mut vers);
            match rang {
                // PROPRIÉTÉ 2 : ce qui sort est ce qui est entré, à la place où
                // il est entré.
                Some(rang) => {
                    for (pas, octet) in vers.iter().take(pris).enumerate() {
                        let ou =
                            consommes[rang].saturating_add(u64::try_from(pas).unwrap_or(u64::MAX));
                        assert_eq!(
                            modele[rang].get(&ou),
                            Some(octet),
                            "l'octet au décalage {ou} du flux {rang} n'est pas celui qu'on avait \
                             mis"
                        );
                    }
                    consommes[rang] =
                        consommes[rang].saturating_add(u64::try_from(pris).unwrap_or(u64::MAX));
                    assert_eq!(poignee.read_offset(niveau), consommes[rang]);
                }
                // **RIEN NE SORT D'UN NIVEAU QUI N'A PAS DE FLUX.**
                None => assert_eq!(pris, 0, "0-RTT ne porte pas de CRYPTO"),
            }
        }

        if let Some(rang) = trame.installer {
            let vise = niveau_de(rang);
            let lecture = poignee.read_level();
            match poignee.install_read(vise) {
                Ok(()) => assert!(
                    poignee.read_level() >= lecture,
                    "un niveau de lecture ne redescend pas"
                ),
                Err(issue) => {
                    assert_eq!(issue.reason(), Reason::CryptoNotConsumed);
                    assert_eq!(poignee.read_level(), lecture, "un refus ne déplace rien");
                }
            }
            poignee.install_write(vise);
            assert!(poignee.write_level() >= vise || poignee.write_level() > vise);
        }
    }

    // PROPRIÉTÉ 5 : les trois flux sont étanches. Ce qui reste à prendre à un
    // niveau ne peut pas venir d'un autre : on vide tout, et chaque octet doit
    // se retrouver dans le modèle de SON flux.
    for niveau in [Level::Initial, Level::Handshake, Level::OneRtt] {
        let rang = flux_de(niveau).expect("ces trois-là ont un flux");
        let mut vers = std::vec![0_u8; CRYPTO_OCTETS_MAX];
        let pris = poignee.take(niveau, &mut fenetres[rang], &mut vers);
        for (pas, octet) in vers.iter().take(pris).enumerate() {
            let ou = consommes[rang].saturating_add(u64::try_from(pas).unwrap_or(u64::MAX));
            assert_eq!(
                modele[rang].get(&ou),
                Some(octet),
                "flux {rang}, décalage {ou}"
            );
        }
    }
});
