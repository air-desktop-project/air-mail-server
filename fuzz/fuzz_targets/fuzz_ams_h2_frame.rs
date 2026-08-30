// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : le cadrage HTTP/2**, le préambule, le remplissage et les réglages.
//!
//! # Pourquoi celle-ci
//!
//! Le cadrage est ce qui décide où un message s'arrête. Un décodeur qui se
//! trompe d'un octet ne rend pas une réponse fausse : il fait lire la suite du
//! flux comme un cadre, et donc n'importe quoi comme une requête. C'est la place
//! qu'occupait la contrebande en HTTP/1.1, et la seule chose qui la ferme ici est
//! que ces neuf octets soient lus de la même façon par tout le monde.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **UN CADRE RENDU ENTIER TIENT DANS CE QU'ON A LU** : son total ne dépasse
//!    jamais le tampon, et vaut au moins les neuf octets d'en-tête. Rendre
//!    davantage ferait consommer à l'appelant des octets qu'il n'a pas.
//! 3. **CE QU'ON A LU SE RÉÉCRIT ET SE RELIT PAREIL.** Le bit réservé mis à part
//!    — §4.1 veut qu'on l'ignore, et on l'écrit à zéro —, l'aller-retour est
//!    l'identité. Sans cela, un cadre qu'on relaie ne serait plus celui qu'on a
//!    reçu.
//! 4. **UN CADRE ACCEPTÉ RESPECTE LA BORNE**, et un cadre de taille fixe a sa
//!    taille.
//! 5. **LE REMPLISSAGE ÔTÉ NE RALLONGE JAMAIS LA CHARGE**, et ce qui reste est
//!    bien une sous-tranche de ce qui est arrivé.
//! 6. **DES RÉGLAGES ACCEPTÉS SONT DES RÉGLAGES UTILISABLES** : la taille de
//!    cadre reste dans la plage de §6.5.2, et la fenêtre sous 2^31.
//! 7. **LE PRÉAMBULE NE S'ACCEPTE QUE COMPLET ET EXACT.**
//! 8. **UNE FENÊTRE RESTE DANS SES BORNES**, jusqu'à 2^31-1 par le haut. Elle
//!    peut en revanche devenir NÉGATIVE, et c'est légal (§6.9.2) : une fenêtre
//!    non signée passerait par zéro et laisserait entrer ce qu'elle devait
//!    refuser.
//! 9. **LES FLUX NE SE RÉEMPLOIENT PAS ET NE DÉBORDENT PAS.** Un numéro accepté
//!    progresse strictement, et la table n'excède jamais ce qu'on a annoncé
//!    traiter de front.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_proto_h2::{
    FRAME_HEADER_OCTETS, FrameHeader, FrameKind, FrameReader, INITIAL_WINDOW_SIZE,
    MAX_CONCURRENT_STREAMS, Need, PREFACE, Padded, Preface, Settings, SettingsReader, StreamState,
    Streams, WINDOW_MAX, Window, read_preface,
};

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// Un flux de cadres, tel qu'il arriverait du réseau.
    flux: &'a [u8],
    /// La taille de cadre en vigueur, ramenée dans la plage de §6.5.2.
    max_frame_size: u32,
    /// Une charge à dépouiller de son remplissage.
    remplie: &'a [u8],
    /// Le début d'une connexion.
    preambule: &'a [u8],
    /// Des gestes de contrôle de flux : un crédit, une consommation, un
    /// ajustement de fenêtre initiale.
    gestes: Vec<(u8, u32)>,
}

fuzz_target!(|entree: Entree<'_>| {
    // §6.5.2 borne le réglage lui-même ; le fuzz ne gagne rien à explorer des
    // valeurs que la lecture des `SETTINGS` refuse déjà.
    let max = entree.max_frame_size.clamp(16_384, 16_777_215);

    // ── Le découpage, cadre après cadre ─────────────────────────────────────
    let mut reste = entree.flux;
    let mut tours = 0_u32;
    while let Ok(Need::Complete(entete)) = FrameReader::poll(reste, max) {
        // PROPRIÉTÉ 7 : la boucle avance. Un cadre entier fait au moins neuf
        // octets, donc `reste` rétrécit — mais on le vérifie plutôt que de le
        // croire.
        tours = tours.saturating_add(1);
        assert!(tours < 100_000, "le découpage n'avance pas");

        // PROPRIÉTÉ 2.
        assert!(entete.total() >= FRAME_HEADER_OCTETS, "un cadre trop court");
        assert!(entete.total() <= reste.len(), "un cadre déborde du tampon");

        // PROPRIÉTÉ 4.
        assert!(entete.length() <= max, "un cadre accepté dépasse la borne");
        assert!(
            entete.check(max).is_ok(),
            "un cadre rendu ne se revérifie pas"
        );

        // PROPRIÉTÉ 3.
        let reecrit = entete.write();
        assert_eq!(
            FrameHeader::parse(&reecrit),
            entete,
            "un en-tête réécrit ne se relit pas pareil"
        );
        assert_eq!(reecrit[5] & 0x80, 0, "le bit réservé s'écrit à zéro");

        // PROPRIÉTÉ 5, sur la charge du cadre.
        let charge = reste
            .get(FRAME_HEADER_OCTETS..entete.total())
            .unwrap_or_default();
        if let Ok(nu) = Padded::strip(charge, entete.flags().padded()) {
            assert!(nu.data().len() <= charge.len(), "le remplissage a rallongé");
        }

        // PROPRIÉTÉ 6, quand c'est un `SETTINGS` qui n'acquitte rien.
        if entete.kind() == FrameKind::Settings && !entete.flags().ack() {
            let mut reglages = Settings::DEFAULT;
            if SettingsReader::apply_all(charge, &mut reglages).is_ok() {
                assert!(
                    (16_384..=16_777_215).contains(&reglages.max_frame_size),
                    "une taille de cadre acceptée est hors plage"
                );
                assert!(
                    reglages.initial_window_size <= 0x7fff_ffff,
                    "une fenêtre acceptée dépasse 2^31-1"
                );
            }
        }

        reste = reste.get(entete.total()..).unwrap_or_default();
    }

    // ── Le remplissage, sur une charge quelconque ───────────────────────────
    for pose in [false, true] {
        if let Ok(nu) = Padded::strip(entree.remplie, pose) {
            assert!(
                nu.data().len() <= entree.remplie.len(),
                "le remplissage a rallongé la charge"
            );
        }
    }

    // ── Les fenêtres et les flux ────────────────────────────────────────────
    let mut fenetre = Window::default();
    let mut flux = Streams::new(INITIAL_WINDOW_SIZE);
    let mut dernier = 0_u32;
    for (quoi, valeur) in &entree.gestes {
        match quoi % 5 {
            0 => {
                let _ = fenetre.consume(*valeur);
            }
            1 => {
                let _ = fenetre.increase(*valeur);
            }
            2 => {
                let _ = fenetre.adjust(i64::from(*valeur));
            }
            3 => {
                // PROPRIÉTÉ 9 : un numéro accepté progresse STRICTEMENT.
                if flux.open(*valeur).is_ok() {
                    assert!(
                        *valeur > dernier,
                        "un numéro accepté ne progresse pas : {valeur} après {dernier}"
                    );
                    assert!(!valeur.is_multiple_of(2), "un numéro pair a été accepté");
                    dernier = *valeur;
                    assert_eq!(flux.last_received(), *valeur);
                }
            }
            _ => {
                let _ = flux.set_initial_window(*valeur);
            }
        }
        // PROPRIÉTÉ 8 : la fenêtre de connexion reste sous la borne haute.
        assert!(
            fenetre.available() <= WINDOW_MAX,
            "une fenêtre a dépassé deux gibioctets"
        );
        // PROPRIÉTÉ 9 : la table ne déborde pas de ce qu'on a annoncé.
        assert!(
            flux.len() <= MAX_CONCURRENT_STREAMS,
            "plus de flux que ce qu'on traite"
        );
        for chacune in (1..=dernier).step_by(2).take(8) {
            if let Some(sienne) = flux.window(chacune) {
                assert!(
                    sienne.available() <= WINDOW_MAX,
                    "fenêtre de flux hors borne"
                );
                assert_eq!(
                    flux.state(chacune),
                    Some(StreamState::Open),
                    "un flux vivant n'est pas ouvert"
                );
            }
        }
    }

    // ── Le préambule ────────────────────────────────────────────────────────
    match read_preface(entree.preambule) {
        Ok(Preface::Complete) => assert!(
            entree.preambule.starts_with(PREFACE),
            "un préambule accepté n'est pas celui de §3.4"
        ),
        Ok(Preface::More) => assert!(
            entree.preambule.len() < PREFACE.len(),
            "un préambule complet a été pris pour un morceau"
        ),
        Err(_) => {}
    }
});
