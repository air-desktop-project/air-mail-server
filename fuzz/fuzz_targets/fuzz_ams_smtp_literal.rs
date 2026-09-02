// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : le littéral d'adresse d'un `EHLO`** — et il est éprouvé CONTRE la
//! bibliothèque standard.
//!
//! # CE QUI EST HOSTILE ICI
//!
//! Un littéral est ce qu'un pair écrit quand il n'a pas de nom, avant toute
//! authentification, et il finit recopié dans l'en-tête `Received:` que nous
//! composons. Une chaîne qu'on aurait laissée passer sans la comprendre y serait
//! écrite telle quelle — et **le prochain lecteur, lui, la comprendra** :
//! journal, filtre, liste d'accès. Deux lecteurs qui tirent deux adresses
//! différentes des mêmes octets, c'est le défaut que le zéro de tête d'IPv4
//! exploite depuis vingt ans.
//!
//! # LA PROPRIÉTÉ QUI PORTE LES AUTRES : UN DIFFÉRENTIEL
//!
//! Notre validation et celle de `core::net` sont **deux moitiés qui ne partagent
//! aucun code**. Elles doivent pourtant accepter et refuser exactement les mêmes
//! octets : c'est la seule façon de savoir qu'on ne lit pas une adresse
//! autrement que le reste du monde.
//!
//! Une seule divergence est admise, et elle est nommée : `core::net` refuse un
//! groupe de plus de quatre chiffres hexadécimaux là où il accepte les zéros de
//! tête, ce que nous faisons aussi — il n'y a donc rien à excepter aujourd'hui.
//! Si un écart apparaissait, cette cible le dirait, et c'est tout son objet.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets.
//! 2. **NOTRE VERDICT EST CELUI DE `core::net`**, pour IPv4 comme pour IPv6.
//! 3. **CE QU'ON ACCEPTE NE PORTE QUE LE VOCABULAIRE D'UNE ADRESSE** : des
//!    chiffres hexadécimaux, des deux-points et des points. Un `%` de zone
//!    (RFC 6874) ou un espace ne veulent rien dire hors de la machine qui les
//!    écrit, et n'ont donc pas leur place dans ce qu'on recopie.
//!
//! Harnais **pur** : aucune entrée-sortie (C1).

#![no_main]

use ams_proto_smtp::check_address_literal;
use core::net::{Ipv4Addr, Ipv6Addr};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|dedans: &[u8]| {
    // Le littéral tel qu'un `EHLO` le porte : entre crochets.
    let mut litteral = Vec::with_capacity(dedans.len().saturating_add(2));
    litteral.push(b'[');
    litteral.extend_from_slice(dedans);
    litteral.push(b']');

    let notre = check_address_literal(&litteral).is_ok();

    // 3. CE QU'ON ACCEPTE NE PORTE QUE LE VOCABULAIRE D'UNE ADRESSE.
    if notre {
        let corps = sans_prefixe(dedans);
        assert!(
            corps
                .iter()
                .all(|octet| octet.is_ascii_hexdigit() || *octet == b':' || *octet == b'.'),
            "un littéral accepté porte autre chose qu'une adresse : {:?}",
            String::from_utf8_lossy(dedans)
        );
    }

    // La bibliothèque standard ne lit que de l'UTF-8 ; ce qui n'en est pas ne
    // peut pas être une adresse, et nous devons l'avoir refusé.
    let Ok(texte) = core::str::from_utf8(dedans) else {
        assert!(
            !notre,
            "des octets qui ne sont pas du texte ont été acceptés"
        );
        return;
    };

    // 2. NOTRE VERDICT EST CELUI DE `core::net`.
    let standard = match texte
        .strip_prefix("IPv6:")
        .or_else(|| texte.strip_prefix("ipv6:"))
        .or_else(|| texte.strip_prefix("IPV6:"))
    {
        Some(adresse) => adresse.parse::<Ipv6Addr>().is_ok(),
        // Sans le préfixe, seule une IPv4 est licite. Un préfixe écrit dans une
        // autre casse est notre affaire, pas celle de `core::net` : on ne
        // compare alors que ce qui est comparable.
        None if commence_par_ipv6(texte) => return,
        None => texte.parse::<Ipv4Addr>().is_ok(),
    };

    assert_eq!(
        notre, standard,
        "désaccord avec `core::net` sur {:?}",
        texte
    );
});

/// Le corps du littéral, préfixe `IPv6:` retiré.
fn sans_prefixe(dedans: &[u8]) -> &[u8] {
    if dedans.len() >= 5
        && dedans
            .get(..5)
            .is_some_and(|d| d.eq_ignore_ascii_case(b"IPv6:"))
    {
        return dedans.get(5..).unwrap_or_default();
    }
    dedans
}

/// Le texte commence-t-il par le préfixe `IPv6:`, quelle qu'en soit la casse ?
fn commence_par_ipv6(texte: &str) -> bool {
    texte.len() >= 5
        && texte
            .get(..5)
            .is_some_and(|d| d.eq_ignore_ascii_case("IPv6:"))
}
