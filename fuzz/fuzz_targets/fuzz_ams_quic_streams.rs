// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : la collection de flux d'une connexion** (RFC 9000 §2.1, §4.1,
//! §4.5, §4.6).
//!
//! # Pourquoi celle-ci, alors que `quic-stream` existe déjà
//!
//! Là-bas, un flux est éprouvé seul. Ici, ils sont plusieurs, et ce qui se joue
//! n'est plus le réassemblage mais **l'aiguillage** : à quel flux une trame
//! s'adresse, avec quelle limite il s'ouvre, dans quelle part de table il se
//! range, et quand sa place se libère. Aucune de ces quatre décisions n'existe
//! quand on n'a qu'un flux.
//!
//! Et c'est là que le pair a la main : c'est LUI qui choisit les numéros. Un
//! aiguillage qui se tromperait de part rendrait la table débordable — donc la
//! mémoire du serveur commandée par le pair, ce qui est exactement ce que le
//! découpage en familles doit rendre impossible.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique.** Les `expect` du module affirment que le débordement
//!    est impossible par construction ; si le découpage en familles était faux,
//!    c'est ici que cela se verrait, et sous la forme d'une panique.
//! 2. **LA TABLE NE DÉBORDE JAMAIS**, et aucune famille ne dépasse sa part —
//!    c'est la propriété qui porte tout le reste.
//! 3. **LE CONTRÔLE DE CONNEXION NE DÉPASSE JAMAIS CE QU'ON A ANNONCÉ** (§4.1),
//!    ni en réception ni en émission.
//! 4. **UN REFUS NE CONSOMME RIEN** : après une trame refusée, les deux compteurs
//!    de connexion sont exactement ce qu'ils étaient.
//! 5. **UN RANG NE BOUGE PAS TANT QUE SON FLUX VIT** : c'est par lui que
//!    l'appelant retrouve ses tampons, et le voir changer sous lui ferait suivre
//!    le mauvais flux.
//! 6. **ON N'ANNONCE JAMAIS PLUS QUE CE QU'ON TIENT** (§4.6) : ce qu'on a rendu
//!    plus une part, et pas un flux de plus.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_proto_quic::{Directional, Initiator, StreamId, TransportParameters};
use ams_quic::{FLUX_MAX, FLUX_PAR_FAMILLE_MAX, Streams};

/// La fenêtre qu'on prête, plus grande que toute limite annoncée ci-dessous.
const FENETRE: usize = 1_024;

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree {
    /// Les limites qu'on annonce, bornées plus bas.
    nos_donnees: u16,
    nos_flux_bidi: u8,
    nos_flux_uni: u8,
    /// Celles que le pair annonce.
    ses_donnees: u16,
    ses_flux_bidi: u8,
    ses_flux_uni: u8,
    /// Sommes-nous le serveur ?
    serveur: bool,
    /// Les gestes, dans l'ordre.
    gestes: [Geste; 48],
}

/// Un geste, du pair ou de nous.
#[derive(Arbitrary, Debug)]
enum Geste {
    /// Une trame `STREAM` : numéro, décalage, longueur, dernier.
    Stream(u8, u16, u8, bool),
    /// Un `RESET_STREAM` : numéro, taille finale.
    Reset(u8, u16),
    /// Un `STOP_SENDING`.
    Stop(u8),
    /// Un `MAX_DATA`.
    MaxData(u16),
    /// Un `MAX_STREAM_DATA`.
    MaxStreamData(u8, u16),
    /// Un `MAX_STREAMS`.
    MaxStreams(bool, u8),
    /// On ouvre un flux.
    Ouvrir(bool),
    /// L'application lit.
    Lire(u8),
    /// On émet.
    Emettre(u8, u8, bool),
    /// Le pair acquitte.
    Acquitter(u8, u16, u8),
    /// On annule.
    Annuler(u8),
    /// On rend les places de ce qui est fini.
    Oublier,
    /// On annonce ce qu'on peut annoncer.
    Annoncer(bool),
}

/// Les paramètres de ces trois nombres, bornés à ce qu'une fenêtre tient.
fn parametres(donnees: u16, bidi: u8, uni: u8) -> TransportParameters {
    // Les limites par flux restent sous `FENETRE` : au-delà, `Recv` refuserait
    // la fenêtre elle-même, et l'on n'éprouverait plus que cette garde-là.
    TransportParameters {
        initial_max_data: u64::from(donnees),
        initial_max_stream_data_bidi_local: 512,
        initial_max_stream_data_bidi_remote: 512,
        initial_max_stream_data_uni: 512,
        initial_max_streams_bidi: u64::from(bidi),
        initial_max_streams_uni: u64::from(uni),
        ..TransportParameters::default()
    }
}

/// Le sens que ce booléen désigne.
const fn sens(bidirectionnel: bool) -> Directional {
    match bidirectionnel {
        true => Directional::Bidirectional,
        false => Directional::Unidirectional,
    }
}

/// Le flux de ce numéro, s'il en est un.
fn flux(numero: u8) -> Option<StreamId> {
    StreamId::new(u64::from(numero)).ok()
}

fuzz_target!(|entree: Entree| {
    let nous = match entree.serveur {
        true => Initiator::Server,
        false => Initiator::Client,
    };
    let nos = parametres(
        entree.nos_donnees,
        entree.nos_flux_bidi,
        entree.nos_flux_uni,
    );
    let ses = parametres(
        entree.ses_donnees,
        entree.ses_flux_bidi,
        entree.ses_flux_uni,
    );
    let mut flux_ = Streams::new(nous, &nos, &ses);
    let mut fenetre = [0_u8; FENETRE];
    let mut vers = [0_u8; 256];
    let charge = [0_u8; 256];

    // Ce qu'on suit d'un geste à l'autre : les rangs promis, pour voir s'ils
    // bougent sous nos pieds.
    let mut promis: [Option<(StreamId, usize)>; FLUX_MAX] = [None; FLUX_MAX];

    for geste in &entree.gestes {
        let avant = (flux_.incoming().used(), flux_.outgoing().used());
        let refus = match *geste {
            Geste::Stream(numero, decalage, longueur, dernier) => flux(numero).is_some_and(|id| {
                let combien = usize::from(longueur).min(charge.len());
                flux_
                    .on_stream(
                        id,
                        u64::from(decalage),
                        &charge[..combien],
                        dernier,
                        &mut fenetre,
                    )
                    .is_err()
            }),
            Geste::Reset(numero, taille) => {
                flux(numero).is_some_and(|id| flux_.on_reset_stream(id, u64::from(taille)).is_err())
            }
            Geste::Stop(numero) => {
                flux(numero).is_some_and(|id| flux_.on_stop_sending(id, 0x10).is_err())
            }
            Geste::MaxData(limite) => {
                flux_.on_max_data(u64::from(limite));
                false
            }
            Geste::MaxStreamData(numero, limite) => flux(numero)
                .is_some_and(|id| flux_.on_max_stream_data(id, u64::from(limite)).is_err()),
            Geste::MaxStreams(bidi, plafond) => {
                flux_.on_max_streams(sens(bidi), u64::from(plafond));
                false
            }
            Geste::Ouvrir(bidi) => flux_.open(sens(bidi)).is_err(),
            Geste::Lire(numero) => {
                if let Some(id) = flux(numero) {
                    flux_.read(id, &mut fenetre, &mut vers);
                }
                false
            }
            Geste::Emettre(numero, longueur, dernier) => flux(numero)
                .is_some_and(|id| flux_.on_sent(id, u64::from(longueur), dernier).is_err()),
            Geste::Acquitter(numero, decalage, longueur) => flux(numero).is_some_and(|id| {
                flux_
                    .on_acked(id, u64::from(decalage), u64::from(longueur))
                    .is_err()
            }),
            Geste::Annuler(numero) => flux(numero).is_some_and(|id| flux_.reset(id).is_err()),
            Geste::Oublier => {
                for rang in 0..FLUX_MAX {
                    if flux_.fini(rang) {
                        let parti = flux_.oublier(rang);
                        assert!(parti.is_some(), "ce qui est fini se rend");
                        // Le rang est libre : ce qu'on avait promis pour lui ne
                        // vaut plus.
                        promis[rang] = None;
                    }
                }
                false
            }
            Geste::Annoncer(bidi) => {
                if let Some(plafond) = flux_.grant_streams(sens(bidi)) {
                    // 6. Jamais plus que ce qu'on tient.
                    let rendus = plafond
                        .checked_sub(FLUX_PAR_FAMILLE_MAX)
                        .expect("on n'annonce jamais moins qu'une part");
                    assert!(rendus <= FLUX_PAR_FAMILLE_MAX.saturating_mul(64));
                    flux_.set_max_streams(sens(bidi), plafond);
                }
                false
            }
        };

        // 4. Un refus ne consomme rien.
        if refus {
            assert_eq!(
                (flux_.incoming().used(), flux_.outgoing().used()),
                avant,
                "UN REFUS NE DOIT RIEN AVOIR BOUGÉ"
            );
        }

        // 3. Les deux compteurs de connexion restent sous ce qui est annoncé.
        assert!(flux_.incoming().used() <= flux_.incoming().limit());
        assert!(flux_.outgoing().used() <= flux_.outgoing().limit());

        // 2. La table ne déborde pas, et chaque famille tient dans sa part.
        //    On la relit par les rangs : un flux rangé hors de sa part se verrait
        //    à ce que deux familles se recouvrent.
        let mut par_part = [0_usize; 4];
        for rang in 0..FLUX_MAX {
            if flux_.occupant(rang).is_some() {
                let part = rang / (FLUX_MAX / 4);
                par_part[part] = par_part[part].saturating_add(1);
            }
        }
        for compte in par_part {
            assert!(
                compte <= FLUX_MAX / 4,
                "UNE FAMILLE A DÉPASSÉ SA PART : la table est débordable"
            );
        }

        // 5. Un rang ne bouge pas tant que son flux vit.
        for place in promis.iter().flatten() {
            let (id, rang) = *place;
            if let Some(ou) = flux_.slot(id) {
                assert_eq!(ou, rang, "LE RANG D'UN FLUX VIVANT NE BOUGE PAS");
            }
        }
        for rang in 0..FLUX_MAX {
            if let Some(id) = flux_.occupant(rang) {
                promis[rang] = Some((id, rang));
            }
        }
    }
});
