// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : les flux QUIC**, leur réassemblage et leur contrôle de flux
//! (RFC 9000 §3, §4.1, §4.5, §4.6).
//!
//! # Pourquoi celle-ci
//!
//! Un flux arrive dans le désordre et se lit dans l'ordre : entre les deux, il
//! faut retenir ce qui est en avance, réunir ce qui se touche, et savoir ce qui
//! manque encore. C'est de l'arithmétique sur des décalages de soixante-deux
//! bits, avec des intervalles qui se recouvrent — exactement le genre de calcul
//! où une erreur ne se voit pas : le flux se fige, ou pire, il livre à
//! l'application des octets qui n'étaient pas les siens.
//!
//! Et le contrôle de flux est ce qui empêche un pair de nous faire retenir ce
//! qu'on ne peut pas retenir. Une seule voie qui laisserait passer un octet de
//! trop rendrait la mémoire du serveur commandée par le pair.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les morceaux et leur ordre.
//! 2. **CE QUI EST LIVRÉ EST CE QUI A ÉTÉ ENVOYÉ, DANS L'ORDRE.** C'est la seule
//!    promesse qu'un flux fait, et tout le reste n'est que du moyen. On rejoue
//!    donc le flux et l'on compare octet par octet.
//! 3. **ON NE LIVRE JAMAIS AU-DELÀ DE CE QUI EST ARRIVÉ** : le décalage de
//!    lecture ne dépasse jamais le plus grand décalage reçu.
//! 4. **RIEN NE PASSE AU-DELÀ DE LA LIMITE ANNONCÉE** (§4.1) : ni les octets, ni
//!    la taille finale d'une annulation.
//! 5. **LE PLUS GRAND DÉCALAGE NE RECULE JAMAIS**, et la progression rendue est
//!    exactement ce dont il a monté — c'est ce que le contrôle de connexion
//!    consomme, et le compter faux le ferait diverger sans qu'aucune faute ne se
//!    voie.
//! 6. **UNE TAILLE FINALE NE CHANGE PAS** (§4.5).
//! 7. **CE QU'ON ÉMET RESTE SOUS LES DEUX CRÉDITS**, et un flux entièrement
//!    acquitté est fini.
//! 8. **LE PLAFOND DE FLUX BORNE LES RANGS** (§4.6), dans les deux sens.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_quic::{Concurrence, Flow, Recv, RecvState, Send, SendState};

/// La fenêtre de réassemblage, qui fait la taille de la limite annoncée.
const FENETRE: usize = 512;

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree {
    /// Les morceaux d'un flux : (décalage, longueur, dernier).
    morceaux: [(u16, u8, bool); 24],
    /// Quand l'application lit, et combien.
    lectures: [u8; 24],
    /// Une annulation, et à quelle taille.
    annulation: Option<u16>,
    /// Ce qu'on émet : (longueur, dernier).
    emissions: [(u16, bool); 12],
    /// Ce que le pair acquitte : (décalage, longueur).
    acquittements: [(u16, u8); 12],
    /// Les crédits d'émission : flux, puis connexion.
    credit_de_flux: u16,
    credit_de_connexion: u16,
    /// Un plafond de flux, et des rangs à ouvrir.
    plafond: u8,
    rangs: [u8; 8],
}

fuzz_target!(|entree: Entree| {
    let limite = u64::try_from(FENETRE).expect("court");
    let mut flux = Recv::new(limite);
    let mut fenetre = [0_u8; FENETRE];
    // **CE QUE LE PAIR A ENVOYÉ**, rejoué en clair pour comparer à la fin.
    let mut verite = [0_u8; FENETRE];
    let mut ecrit = [false; FENETRE];
    let mut sorti = std::vec::Vec::new();
    // Le contrôle de connexion, qui compte les progressions.
    let mut connexion = Flow::receiving(u64::MAX);
    let mut progression_totale = 0_u64;
    let mut plus_grand = 0_u64;
    let mut taille_finale = None;

    for ((decalage, longueur, dernier), combien) in entree.morceaux.into_iter().zip(entree.lectures)
    {
        let decalage = u64::from(decalage) % (limite + 1);
        let longueur = usize::from(longueur);
        // Les octets portent leur propre décalage : un octet livré à la mauvaise
        // place se voit immédiatement.
        let mut morceau = [0_u8; 256];
        for (rang, octet) in morceau.iter_mut().enumerate().take(longueur) {
            let absolu = decalage.saturating_add(u64::try_from(rang).expect("court"));
            *octet = u8::try_from(absolu % 251).expect("sous 251");
        }
        let morceau = morceau.get(..longueur).expect("dans le tampon");
        let avant = flux.largest();

        match flux.on_stream(decalage, morceau, dernier, &mut fenetre) {
            Ok(monte) => {
                // PROPRIÉTÉ 5 : la progression est exactement ce dont le plus
                // grand décalage a monté.
                assert_eq!(
                    flux.largest(),
                    avant.saturating_add(monte),
                    "la progression rendue ne correspond pas"
                );
                assert!(flux.largest() >= avant, "le plus grand décalage a reculé");
                // PROPRIÉTÉ 4 : rien au-delà de ce qu'on a annoncé.
                assert!(flux.largest() <= limite, "au-delà de la limite annoncée");
                connexion
                    .consume(monte)
                    .expect("le compte de connexion suit");
                progression_totale = progression_totale.saturating_add(monte);

                // On note ce que le pair a vraiment envoyé, sauf après une
                // annulation, où plus rien n'est rangé.
                if !matches!(flux.state(), RecvState::ResetRecvd | RecvState::ResetRead) {
                    for (rang, octet) in morceau.iter().enumerate() {
                        let absolu = decalage.saturating_add(u64::try_from(rang).expect("court"));
                        let place = usize::try_from(absolu).expect("sous la fenêtre");
                        if let (Some(ou), Some(vu)) = (verite.get_mut(place), ecrit.get_mut(place))
                        {
                            *ou = *octet;
                            *vu = true;
                        }
                    }
                    plus_grand = plus_grand
                        .max(decalage.saturating_add(u64::try_from(longueur).expect("court")));
                    if dernier {
                        let bout = decalage.saturating_add(u64::try_from(longueur).expect("court"));
                        // PROPRIÉTÉ 6 : une taille finale acceptée est toujours
                        // la même.
                        assert!(
                            taille_finale.is_none_or(|connue| connue == bout),
                            "deux tailles finales ont été acceptées"
                        );
                        taille_finale = Some(bout);
                    }
                }
            }
            Err(_) => {
                // Une faute ferme la connexion : on ne continue pas à jouer.
                assert!(flux.largest() == avant, "un refus a laissé une trace");
            }
        }

        // PROPRIÉTÉ 2 : on lit, et ce qui sort est ce qui était entré.
        let mut vers = [0_u8; FENETRE];
        let voulu = usize::from(combien).min(vers.len());
        let debut = flux.read_offset();
        let pris = flux.read(&mut fenetre, vers.get_mut(..voulu).expect("dans le tampon"));
        for (rang, octet) in vers.iter().enumerate().take(pris) {
            let absolu = debut.saturating_add(u64::try_from(rang).expect("court"));
            let place = usize::try_from(absolu).expect("sous la fenêtre");
            assert_eq!(
                ecrit.get(place),
                Some(&true),
                "on a livré un octet jamais reçu, au décalage {absolu}"
            );
            assert_eq!(
                verite.get(place),
                Some(octet),
                "on a livré autre chose que ce qui était arrivé, au décalage {absolu}"
            );
            sorti.push(*octet);
        }
        // PROPRIÉTÉ 3 : on ne livre jamais au-delà de ce qui est arrivé.
        assert!(
            flux.read_offset() <= flux.largest(),
            "on a lu {} pour {} reçus",
            flux.read_offset(),
            flux.largest()
        );
    }

    // PROPRIÉTÉ 4 : la taille finale d'une annulation compte comme des octets.
    if let Some(taille) = entree.annulation {
        let taille = u64::from(taille);
        let avant = flux.largest();
        match flux.on_reset(taille) {
            Ok(monte) => {
                assert!(taille <= limite, "une annulation au-delà de la limite");
                assert_eq!(flux.largest(), avant.saturating_add(monte));
                assert_eq!(flux.final_size(), Some(taille));
                connexion
                    .consume(monte)
                    .expect("le compte de connexion suit");
                flux.read_reset();
                assert_eq!(flux.state(), RecvState::ResetRead);
            }
            Err(_) => assert_eq!(flux.largest(), avant, "un refus a laissé une trace"),
        }
    }

    // PROPRIÉTÉ 7 : ce qu'on émet reste sous les deux crédits.
    let mut sortant = Send::new(u64::from(entree.credit_de_flux));
    let mut sortante = Flow::sending(u64::from(entree.credit_de_connexion));
    for (longueur, dernier) in entree.emissions {
        let permis = sortant.allowed(sortante.available());
        let longueur = u64::from(longueur).min(permis);
        let avant = sortant.offset();
        if sortant.on_sent(longueur, dernier).is_ok() {
            assert_eq!(sortant.offset(), avant.saturating_add(longueur));
            assert!(
                sortant.offset() <= sortant.limit(),
                "au-delà du crédit du flux"
            );
            sortante
                .consume(longueur)
                .expect("le crédit de connexion suit");
            assert!(
                sortante.used() <= sortante.limit(),
                "au-delà du crédit de connexion"
            );
        }
    }
    for (decalage, longueur) in entree.acquittements {
        // Un pair n'acquitte que ce qu'on lui a envoyé.
        let decalage = u64::from(decalage).min(sortant.offset());
        let longueur = u64::from(longueur).min(sortant.offset().saturating_sub(decalage));
        if sortant.on_acked(decalage, longueur).is_err() {
            break;
        }
        assert!(
            sortant.first_unacked() <= sortant.offset(),
            "on a accusé plus qu'on n'a émis"
        );
    }
    // Tout accuser d'un coup termine le flux, s'il avait un `FIN`.
    if let Some(finale) = sortant.final_size() {
        if sortant.on_acked(0, finale).is_ok() && matches!(sortant.state(), SendState::DataSent) {
            panic!("tout est accusé et le flux n'est pas fini");
        }
    }

    // PROPRIÉTÉ 8 : le plafond borne les rangs, dans les deux sens.
    let plafond = u64::from(entree.plafond);
    let mut entrants = Concurrence::new(plafond);
    let mut sortants = Concurrence::new(plafond);
    for rang in entree.rangs {
        let rang = u64::from(rang);
        assert_eq!(
            entrants.open_remote(rang).is_ok(),
            rang < plafond,
            "le plafond n'a pas borné le rang {rang}"
        );
        assert!(entrants.next() <= plafond, "un rang au-delà du plafond");
        match sortants.open_local() {
            Ok(pris) => assert!(pris < plafond, "on a pris un rang au-delà du plafond"),
            Err(_) => assert!(sortants.blocked(), "un refus sans être bloqué"),
        }
    }
});
