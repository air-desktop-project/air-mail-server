// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : la réponse d'un résolveur DNS.**
//!
//! Ces octets-là arrivent par UDP, d'une adresse qu'on n'a pas authentifiée,
//! avec une charge que **n'importe qui sur le chemin peut fabriquer**. C'est la
//! surface la plus exposée du serveur après SMTP lui-même : elle s'atteint sans
//! ouvrir de connexion, en devinant un port et un identifiant.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, et surtout **rien ne boucle** : un nom peut pointer
//!    vers un autre nom, et un message hostile peut fabriquer un cycle. La
//!    parade est structurelle — chaque pointeur vise strictement plus bas — et
//!    c'est elle que le temps d'exécution éprouve ici.
//! 2. **Un message accepté se parcourt entièrement** : la validation est d'un
//!    seul tenant, donc l'itérateur des réponses rend ce que l'en-tête annonce,
//!    ni plus ni moins.
//! 3. **Un nom lu tient dans 255 octets.** Un nom plus long ne désigne rien
//!    d'interrogeable, et le tronquer désignerait AUTRE CHOSE.
//! 4. **Deux lectures rendent la même chose** : rien ne dépend de l'ordre dans
//!    lequel on interroge un enregistrement.
//! 5. **Une question qu'on encode est structurellement lisible**, et n'est
//!    jamais prise pour une réponse.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_dns::{Kind, Message, QUERY_MAX, encode_query};

#[derive(Debug, Arbitrary)]
struct Entree<'a> {
    /// La réponse, telle qu'un résolveur — ou n'importe qui — l'envoie.
    reponse: &'a [u8],
    /// Un nom à encoder, librement absurde.
    nom: &'a [u8],
    /// Le type demandé.
    genre: u8,
    /// L'identifiant de la question.
    id: u16,
}

fuzz_target!(|entree: Entree| {
    // ── 1, 2, 3, 4 : la réponse ─────────────────────────────────────────────
    if let Ok(message) = Message::parse(entree.reponse) {
        let _ = message.id();
        let _ = message.truncated();
        let _ = message.status();

        let mut combien = 0_usize;
        for enregistrement in message.answers() {
            combien += 1;
            // LA BORNE DE PARCOURS. L'en-tête compte les réponses sur seize
            // bits : au-delà, l'itérateur rendrait plus que ce qui peut être
            // annoncé, ce qui voudrait dire qu'il ne s'arrête pas.
            assert!(combien <= usize::from(u16::MAX), "l'itérateur ne s'arrête pas");

            let premier = enregistrement.owner();
            let second = enregistrement.owner();
            assert_eq!(
                premier.is_ok(),
                second.is_ok(),
                "deux lectures d'un même nom divergent"
            );
            if let Ok(nom) = premier {
                assert!(nom.as_bytes().len() <= 255, "un nom plus long qu'un nom");
                if let Ok(encore) = second {
                    assert_eq!(nom.as_bytes(), encore.as_bytes());
                }
            }

            if let Ok(cible) = enregistrement.target() {
                assert!(cible.as_bytes().len() <= 255);
            }
            if let Ok((_, echange)) = enregistrement.exchange() {
                assert!(echange.as_bytes().len() <= 255);
            }
            // Une adresse n'est rendue que si la longueur est EXACTE.
            match enregistrement.address() {
                Some(core::net::IpAddr::V4(_)) => assert_eq!(enregistrement.rdata().len(), 4),
                Some(core::net::IpAddr::V6(_)) => assert_eq!(enregistrement.rdata().len(), 16),
                None => {}
            }
            // Les chaînes d'un `TXT` ne dépassent jamais leurs données.
            let total: usize = enregistrement
                .strings()
                .map(|chaine| chaine.len() + 1)
                .sum();
            assert!(
                total <= enregistrement.rdata().len(),
                "les chaînes débordent des données"
            );
            let _ = enregistrement.class();
            let _ = enregistrement.is_opt();
        }
        // Un second parcours rend le même nombre : l'itérateur ne consomme rien
        // du message.
        assert_eq!(combien, message.answers().count());
    }

    // ── 5 : la question ─────────────────────────────────────────────────────
    let genre = match entree.genre % 6 {
        0 => Kind::A,
        1 => Kind::Cname,
        2 => Kind::Ptr,
        3 => Kind::Mx,
        4 => Kind::Txt,
        _ => Kind::Aaaa,
    };
    let mut tampon = [0_u8; QUERY_MAX];
    if let Ok(question) = encode_query(&mut tampon, entree.id, entree.nom, genre) {
        assert!(question.len() <= QUERY_MAX);
        // Elle n'est PAS une réponse, et le décodeur le dit plutôt que de la
        // lire. Sans ce refus, un pair injecterait ses questions dans le flot
        // des réponses attendues.
        assert!(
            Message::parse(question).is_err(),
            "une question a été prise pour une réponse"
        );
    }
});
