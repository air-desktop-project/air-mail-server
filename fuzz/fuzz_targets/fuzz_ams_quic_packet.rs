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

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_proto_quic::{
    CONNECTION_ID_MAX, Long, LongKind, RETRY_TAG_OCTETS, ShortHeader, VERSION_NEGOTIATION, is_long,
    parse_long,
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
});
