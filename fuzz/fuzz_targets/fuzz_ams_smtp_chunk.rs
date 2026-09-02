// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : les morceaux comptés de `BDAT`** (RFC 3030 §2).
//!
//! # CE QUI EST HOSTILE ICI, ET QUI NE SAUTE PAS AUX YEUX
//!
//! `BDAT` n'a pas de délimiteur : c'est le pair qui ANNONCE combien d'octets
//! suivent, et tout tient à ce que le récepteur n'en lise ni un de plus ni un de
//! moins. Un de plus, et le début de la commande suivante est avalé comme du
//! message ; un de moins, et la queue du message est servie comme des commandes
//! — c'est-à-dire un `MAIL FROM` que le pair aura écrit lui-même.
//!
//! La taille vient de lui, le contenu vient de lui, et le découpage des lectures
//! vient du réseau.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les tailles, les octets et le
//!    découpage.
//! 2. **LE DÉCOUPAGE DES LECTURES NE CHANGE RIEN** : lire d'un seul tenant ou
//!    par tranches d'un octet rend le même verdict et les mêmes octets. C'est la
//!    propriété qui vise la contrebande, ici comme en phase `DATA`.
//! 3. **ON NE CONSOMME JAMAIS PLUS QUE CE QUI EST ANNONCÉ.** La somme des octets
//!    consommés ne dépasse pas la somme des tailles annoncées, quoi qu'on
//!    présente en entrée.
//! 4. **AUCUN `CR` NI `LF` ISOLÉ N'A SURVÉCU** dans ce qui est accepté — ce
//!    qu'on dépose repart un jour chez un voisin qui coupe sur `<CRLF>.<CRLF>`.
//! 5. **LA BORNE DU MESSAGE TIENT**, tous morceaux confondus : c'est elle qui
//!    empêche un pair d'écrire un gibioctet en annonçant mille morceaux d'un
//!    mébioctet.
//!
//! Harnais **pur** : aucune entrée-sortie (C1).

#![no_main]

use ams_proto_smtp::{ChunkEvent, ChunkReceiver, DataFault, Limits};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Entree {
    /// Les morceaux annoncés : une taille, et le marqueur `LAST`.
    morceaux: Vec<(u16, bool)>,
    /// Ce que le pair envoie.
    flux: Vec<u8>,
    /// Comment le réseau découpe les lectures. Vide : d'un seul tenant.
    tranches: Vec<u8>,
    /// Ce qu'un message a le droit de peser.
    max_message: u16,
}

/// Ce qu'une lecture entière a produit.
#[derive(Debug, PartialEq, Eq)]
struct Lecture {
    /// Les octets rendus, dans l'ordre.
    rendu: Vec<u8>,
    /// La faute qui a arrêté la lecture, s'il y en a une.
    faute: Option<DataFault>,
    /// Le message a-t-il été conclu ?
    complet: bool,
    /// Ce que le récepteur compte avoir reçu.
    compte: u64,
}

fuzz_target!(|entree: Entree| {
    let max_message = u64::from(entree.max_message);
    let calendrier: Vec<usize> = entree
        .tranches
        .iter()
        .map(|taille| usize::from(*taille))
        .collect();

    let entiere = lire(&entree, &[usize::MAX], max_message);
    let hachee = lire(&entree, &calendrier, max_message);

    // 2. LE DÉCOUPAGE DES LECTURES NE CHANGE RIEN.
    assert_eq!(
        entiere, hachee,
        "le découpage change le résultat : {:?}",
        entree.flux
    );

    // 3. ON NE CONSOMME JAMAIS PLUS QUE CE QUI EST ANNONCÉ.
    let annonce: u64 = entree
        .morceaux
        .iter()
        .map(|(taille, _)| u64::from(*taille))
        .fold(0_u64, u64::saturating_add);
    assert!(
        entiere.compte <= annonce,
        "plus d'octets rendus que d'octets annoncés"
    );

    // 5. LA BORNE DU MESSAGE TIENT.
    assert!(
        entiere.compte <= max_message,
        "le message dépasse la borne : {} > {max_message}",
        entiere.compte
    );

    if entiere.faute.is_some() {
        return;
    }

    // 4. AUCUN `CR` NI `LF` ISOLÉ N'A SURVÉCU.
    let mut precedent = None;
    for (rang, octet) in entiere.rendu.iter().enumerate() {
        if *octet == b'\n' {
            assert_eq!(precedent, Some(b'\r'), "LF isolé à l'offset {rang}");
        }
        if precedent == Some(b'\r') {
            assert_eq!(*octet, b'\n', "CR isolé à l'offset {rang}");
        }
        precedent = Some(*octet);
    }
    // Et un message conclu ne se termine pas sur un `CR` pendant.
    if entiere.complet {
        assert_ne!(precedent, Some(b'\r'), "le message finit sur un CR isolé");
    }
});

/// Déroule tous les morceaux, en lisant selon le calendrier donné.
fn lire(entree: &Entree, calendrier: &[usize], max_message: u64) -> Lecture {
    let mut receveur = ChunkReceiver::new(&Limits::DEFAULT, max_message);
    let mut rendu = Vec::new();
    let mut reste: &[u8] = &entree.flux;
    let mut tranche = 0_usize;
    let mut complet = false;

    for (taille, last) in &entree.morceaux {
        if let Err(faute) = receveur.begin(u64::from(*taille), *last) {
            return Lecture {
                rendu,
                faute: Some(faute),
                complet,
                compte: receveur.content_octets(),
            };
        }
        loop {
            // Le calendrier dit combien d'octets le réseau livre d'un coup ; le
            // récepteur, lui, ne consomme jamais au-delà du morceau.
            let combien = prochaine(calendrier, &mut tranche).min(reste.len());
            let vu = reste.get(..combien).unwrap_or_default();
            match receveur.next(vu) {
                Ok((evenement, consomme)) => {
                    reste = reste.get(consomme..).unwrap_or_default();
                    match evenement {
                        ChunkEvent::Content(octets) => rendu.extend_from_slice(octets),
                        ChunkEvent::ChunkComplete => break,
                        ChunkEvent::Complete => {
                            complet = true;
                            return Lecture {
                                rendu,
                                faute: None,
                                complet,
                                compte: receveur.content_octets(),
                            };
                        }
                        // Plus rien à donner : le morceau ne se finira pas.
                        ChunkEvent::NeedMore => {
                            return Lecture {
                                rendu,
                                faute: None,
                                complet,
                                compte: receveur.content_octets(),
                            };
                        }
                    }
                }
                Err(faute) => {
                    return Lecture {
                        rendu,
                        faute: Some(faute),
                        complet,
                        compte: receveur.content_octets(),
                    };
                }
            }
        }
    }
    Lecture {
        rendu,
        faute: None,
        complet,
        compte: receveur.content_octets(),
    }
}

/// La taille de la prochaine lecture, en tournant sur le calendrier.
///
/// Une tranche de zéro ne ferait pas avancer la boucle : elle vaut un octet.
fn prochaine(calendrier: &[usize], rang: &mut usize) -> usize {
    if calendrier.is_empty() {
        return usize::MAX;
    }
    let taille = calendrier
        .get(*rang % calendrier.len())
        .copied()
        .unwrap_or(1);
    *rang = rang.wrapping_add(1);
    taille.max(1)
}
