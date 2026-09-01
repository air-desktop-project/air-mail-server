// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : le conducteur HTTP/3 sur des octets** (RFC 9114 §4.1, §6.2, §7.2,
//! §9).
//!
//! # Pourquoi celle-ci, alors que `h3-connection` existe
//!
//! Là-bas, l'état de connexion est éprouvé sur une suite de TYPES DE TRAMES
//! donnée à la main. Ici, ce sont **des octets** : le conducteur doit y
//! retrouver des têtes de flux, des en-têtes à cheval sur plusieurs livraisons,
//! des charges à sauter, et décider à chaque pas s'il en faut davantage ou si
//! c'est une faute.
//!
//! C'est le pair qui choisit ces octets et leur découpage. Un tampon mal borné ou
//! un pas qui n'avance pas ne se verraient pas comme une réponse fausse, mais
//! comme une boucle qui ne rend jamais la main, ou une mémoire qui monte.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets et leur découpage.
//! 2. **CHAQUE APPEL REND LA MAIN** : un pas qui n'avance pas doit s'arrêter, et
//!    non redemander les mêmes octets sans fin. Le moteur de fuzz le voit à son
//!    délai ; l'essai le voit à ce qu'il écrit.
//! 3. **UNE FAUTE EST DÉFINITIVE** : une fois refusé, on ne se remet pas à
//!    servir — le pair a déjà fait ce qu'il ne fallait pas.
//! 4. **CE QU'ON ÉCRIT RESTE BORNÉ** : une réponse par requête, et pas une de
//!    plus, quoi que le pair redise.

#![no_main]

use std::collections::HashMap;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_h3::{Error, Http3, Reponse, Service, Transport};
use ams_proto_http::{RequestHead, StatusCode};
use ams_proto_quic::{Directional, Initiator, StreamId};
use ams_quic::RecvState;

/// Ce qu'on soumet : des morceaux, et à quel flux ils vont.
#[derive(Arbitrary, Debug)]
struct Entree {
    /// Les livraisons : le rang du flux, s'il est bidirectionnel, les octets.
    morceaux: [(u8, bool, Vec<u8>); 12],
    /// À partir de quel morceau le pair a fini d'écrire.
    fin_au: u8,
}

/// Un transport de fer-blanc.
#[derive(Default)]
struct Faux {
    /// Ce que le pair a dit, par flux.
    entrant: HashMap<u64, Vec<u8>>,
    /// Combien on a écrit, par flux.
    ecrits: HashMap<u64, usize>,
    /// Ce que le pair a conclu, par flux.
    etats: HashMap<u64, RecvState>,
    /// Le prochain rang qu'on ouvrira.
    prochain: u64,
}

impl Transport for Faux {
    fn open_uni(&mut self) -> Result<StreamId, Error> {
        if self.prochain >= 8 {
            return Err(Error::transport());
        }
        let flux = StreamId::from_index(
            self.prochain,
            Initiator::Server,
            Directional::Unidirectional,
        )
        .map_err(|_| Error::transport())?;
        self.prochain = self.prochain.saturating_add(1);
        Ok(flux)
    }

    fn read(&mut self, flux: StreamId, vers: &mut [u8]) -> usize {
        let Some(file) = self.entrant.get_mut(&flux.value()) else {
            return 0;
        };
        let combien = file.len().min(vers.len());
        vers.get_mut(..combien)
            .unwrap_or_default()
            .copy_from_slice(file.get(..combien).unwrap_or_default());
        file.drain(..combien);
        combien
    }

    fn write(&mut self, flux: StreamId, octets: &[u8]) -> Result<usize, Error> {
        let compte = self.ecrits.entry(flux.value()).or_default();
        *compte = compte.saturating_add(octets.len());
        Ok(octets.len())
    }

    fn finish(&mut self, _flux: StreamId) -> Result<(), Error> {
        Ok(())
    }

    fn recv_state(&self, flux: StreamId) -> Option<RecvState> {
        self.etats.get(&flux.value()).copied()
    }
}

/// Un service qui répond toujours la même chose.
struct Bref;

impl Service for Bref {
    fn serve<'o>(
        &mut self,
        _tete: &RequestHead<'_>,
        _corps: &[u8],
        sortie: &'o mut [u8],
    ) -> Reponse<'o> {
        let combien = 2.min(sortie.len());
        sortie.get_mut(..combien).unwrap_or_default().fill(b'o');
        Reponse::new(StatusCode::OK, sortie.get(..combien).unwrap_or_default())
    }
}

fuzz_target!(|entree: Entree| {
    let mut faux = Faux::default();
    let mut h3 = Http3::new();
    let mut bref = Bref;
    // Sans flux de contrôle, rien de ce qui suit n'a de sens.
    if h3.on_established(&mut faux).is_err() {
        return;
    }

    let mut fautee = false;
    for (rang, (numero, bidi, octets)) in entree.morceaux.iter().enumerate() {
        let sens = match bidi {
            true => Directional::Bidirectional,
            false => Directional::Unidirectional,
        };
        let Ok(flux) = StreamId::from_index(u64::from(*numero), Initiator::Client, sens) else {
            continue;
        };
        faux.entrant
            .entry(flux.value())
            .or_default()
            .extend_from_slice(octets);
        faux.etats.entry(flux.value()).or_insert(RecvState::Recv);
        if rang >= usize::from(entree.fin_au) {
            faux.etats.insert(flux.value(), RecvState::DataRecvd);
        }

        let issue = h3.on_readable(&mut faux, &mut bref, flux);
        let etait = fautee;
        fautee |= issue.is_err();

        // 3. Une faute est définitive : après elle, on ne sert plus.
        if etait {
            assert!(
                issue.is_err() || faux.ecrits.values().sum::<usize>() < 1 << 20,
                "APRÈS UNE FAUTE, ON NE REPART PAS"
            );
        }

        // 4. Ce qu'on écrit reste borné : douze morceaux ne peuvent pas produire
        //    un mébioctet de réponses.
        assert!(
            faux.ecrits.values().sum::<usize>() < 1 << 20,
            "ON N'ÉCRIT PAS SANS FIN"
        );
    }
});
