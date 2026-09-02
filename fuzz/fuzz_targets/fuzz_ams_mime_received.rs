// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : l'en-tête `Received:`** (RFC 5321 §4.4) — la trace que ce serveur
//! pose EN TÊTE de chaque message qu'il accepte.
//!
//! # L'ENTRÉE HOSTILE EST LE NOM DU `HELO`
//!
//! C'est ce que le pair a bien voulu dire de lui-même, avant toute
//! authentification, et cela finit recopié en tête du message — là où un lecteur
//! croira que c'est nous qui parlons. Un `CRLF` glissé dedans écrirait un
//! en-tête entier sous notre nom, au-dessus de tous les autres.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets et l'instant.
//! 2. **RIEN N'EST ÉCRIT AU-DELÀ DU TAMPON** : ce qui borde ne bouge pas.
//! 3. **IL N'Y A QU'UN CHAMP** : une seule ligne ne commence pas par un blanc,
//!    et c'est la première. Toute autre serait un en-tête que le pair aurait
//!    écrit à travers nous.
//! 4. **TOUT CE QUI SORT EST ÉMETTABLE** : de l'ASCII imprimable, des
//!    tabulations, et des fins de ligne COMPLÈTES.
//! 5. **AUCUNE LIGNE NE DÉPASSE 998 OCTETS** (§2.1.1 de RFC 5322). Au-delà, les
//!    analyseurs en aval coupent où ils veulent, et ce qu'ils lisent n'est plus
//!    ce qu'on a écrit.
//! 6. **AUCUN DESTINATAIRE N'Y EST NOMMÉ** : ce serveur n'écrit jamais de clause
//!    `for`, et l'en-tête voyage avec le message.
//!
//! Harnais **pur** : aucune entrée-sortie (C1).

#![no_main]

use ams_mime::{RECEIVED_MAX, Received, Transport, write_received};
use arbitrary::Arbitrary;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use libfuzzer_sys::fuzz_target;

/// Ce qui borde le tampon, pour voir si l'on écrit au-delà.
const GARDE: u8 = 0xa5;

#[derive(Debug, Arbitrary)]
struct Entree {
    helo: Vec<u8>,
    receiver: Vec<u8>,
    /// Une adresse, v4 ou v6 selon le premier octet.
    six: bool,
    adresse: [u8; 16],
    transport: u8,
    date: u64,
    /// La place qu'on donne, bornée par ce que le produit réserve.
    place: u16,
}

fuzz_target!(|entree: Entree| {
    let client = if entree.six {
        IpAddr::V6(Ipv6Addr::from(entree.adresse))
    } else {
        let [a, b, c, d, ..] = entree.adresse;
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    };
    let champ = Received {
        helo: &entree.helo,
        client,
        receiver: &entree.receiver,
        with: match entree.transport % 4 {
            0 => Transport::Smtp,
            1 => Transport::Esmtp,
            2 => Transport::Esmtps,
            _ => Transport::EsmtpsA,
        },
        date: entree.date,
    };

    let place = usize::from(entree.place) % (RECEIVED_MAX + 1);
    let mut tampon = vec![GARDE; place.saturating_add(64)];
    let issue = {
        let dedans = &mut tampon[..place];
        write_received(dedans, &champ).map(<[u8]>::len)
    };

    // 2. RIEN N'EST ÉCRIT AU-DELÀ.
    assert!(
        tampon[place..].iter().all(|octet| *octet == GARDE),
        "écrit au-delà de la place donnée"
    );

    let Ok(combien) = issue else {
        return;
    };
    let ecrit = &tampon[..combien];

    // 4. TOUT CE QUI SORT EST ÉMETTABLE.
    assert!(
        emettable(ecrit),
        "un octet qu'on ne peut pas mettre sur le fil"
    );
    assert!(
        ecrit.starts_with(b"Received: from "),
        "le champ n'est pas celui qu'on annonce"
    );
    assert!(ecrit.ends_with(b"\r\n"), "le champ ne se termine pas");

    // 3. IL N'Y A QU'UN CHAMP, et 5. AUCUNE LIGNE NE DÉPASSE 998 OCTETS.
    for (rang, ligne) in ecrit.split(|octet| *octet == b'\n').enumerate() {
        let ligne = ligne.strip_suffix(b"\r").unwrap_or(ligne);
        if ligne.is_empty() {
            continue;
        }
        assert!(
            rang == 0 || matches!(ligne.first(), Some(b' ' | b'\t')),
            "une seconde ligne d'en-tête est apparue"
        );
        assert!(ligne.len() <= 998, "ligne de plus de 998 octets");
    }

    // 6. AUCUN DESTINATAIRE N'Y EST NOMMÉ.
    assert!(
        !contient(ecrit, b" for "),
        "une clause `for` est apparue : elle nommerait un destinataire"
    );
});

/// `botte` porte-t-elle `aiguille` ?
fn contient(botte: &[u8], aiguille: &[u8]) -> bool {
    botte
        .windows(aiguille.len())
        .any(|fenetre| fenetre == aiguille)
}

/// Ces octets peuvent-ils passer sur le fil tels quels ?
///
/// De l'ASCII imprimable, des tabulations, et des fins de ligne COMPLÈTES.
fn emettable(octets: &[u8]) -> bool {
    let mut attend_lf = false;
    for octet in octets {
        if attend_lf {
            if *octet != b'\n' {
                return false;
            }
            attend_lf = false;
            continue;
        }
        match *octet {
            b'\r' => attend_lf = true,
            b'\n' => return false,
            b'\t' => {}
            autre if autre.is_ascii_graphic() || autre == b' ' => {}
            _ => return false,
        }
    }
    !attend_lf
}
