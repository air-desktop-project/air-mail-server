// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : l'en-tête `Received-SPF` (RFC 7208 §9.1).**
//!
//! Cet en-tête porte deux valeurs que **le pair choisit** — son expéditeur
//! d'enveloppe et son `HELO` — et il est écrit DANS LE MESSAGE QU'ON REMET. Un
//! `CR LF` recopié tel quel, et le pair écrit les en-têtes qu'il veut : un
//! `Authentication-Results` fabriqué, un `To:` de plus, un faux
//! `Received-SPF: pass` sous le nôtre.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quelle que soit la taille du tampon.
//! 2. **AUCUN SAUT DE LIGNE QUI NE SOIT UN REPLI.** Tout `CR` est suivi d'un
//!    `LF` ; tout `LF` est précédé d'un `CR` et suivi d'une espace — sauf celui
//!    qui termine l'en-tête. C'est la propriété qui ferme l'injection.
//! 3. **Aucune ligne ne dépasse 998 octets** (RFC 5322 §2.1.1). Un en-tête plus
//!    long qu'une ligne se fait couper en aval, là où personne ne décide.
//! 4. **Un en-tête composé commence par le nom du champ et l'un des sept mots**
//!    de la RFC 7208 §2.6, et finit par un `CRLF`.
//! 5. **Une valeur non imprimable fait TOUJOURS refuser.** Pas d'échappement de
//!    secours, pas de remplacement : on n'écrit pas un en-tête dont on ne sait
//!    pas ce qu'il dit.

#![no_main]

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_spf::{Error, Identity, RECEIVED_SPF_MAX, ReceivedSpf, Verdict, write_received_spf};

#[derive(Debug, Arbitrary)]
struct Entree<'a> {
    /// L'expéditeur et le `HELO`, **tels que le pair les a dits**.
    sender: &'a [u8],
    helo: &'a [u8],
    /// Le nom du serveur, qui vient d'un fichier de configuration.
    receiver: &'a [u8],
    /// Le verdict.
    verdict: u8,
    /// L'identité vérifiée.
    sur_le_helo: bool,
    /// L'adresse du pair.
    en_v6: bool,
    v4: [u8; 4],
    v6: [u8; 16],
    /// La taille du tampon offert — ZÉRO COMPRIS.
    tampon: u16,
}

const MOTS: [&str; 7] = [
    "none",
    "neutral",
    "pass",
    "fail",
    "softfail",
    "temperror",
    "permerror",
];

fuzz_target!(|entree: Entree| {
    let verdict = match entree.verdict % 7 {
        0 => Verdict::None,
        1 => Verdict::Neutral,
        2 => Verdict::Pass,
        3 => Verdict::Fail,
        4 => Verdict::SoftFail,
        5 => Verdict::TempError,
        _ => Verdict::PermError,
    };
    let champ = ReceivedSpf {
        result: verdict,
        client: if entree.en_v6 {
            IpAddr::V6(Ipv6Addr::from(entree.v6))
        } else {
            IpAddr::V4(Ipv4Addr::from(entree.v4))
        },
        sender: entree.sender,
        helo: entree.helo,
        receiver: entree.receiver,
        identity: if entree.sur_le_helo {
            Identity::Helo
        } else {
            Identity::MailFrom
        },
    };

    // Le tampon est borné par ce que la crate annonce : au-delà, on n'éprouve
    // plus l'en-tête, on éprouve l'allocateur du harnais.
    let taille = usize::from(entree.tampon) % (RECEIVED_SPF_MAX + 1);
    let mut tampon = vec![0_u8; taille];

    // ── 5. L'IMPRIMABLE, ET RIEN D'AUTRE ────────────────────────────────────
    let propre = |valeur: &[u8]| {
        valeur
            .iter()
            .all(|octet| octet.is_ascii_graphic() || *octet == b' ')
    };
    let tout_propre = propre(entree.sender) && propre(entree.helo) && propre(entree.receiver);

    let ecrit = match write_received_spf(&mut tampon, &champ) {
        Ok(ecrit) => ecrit,
        Err(cause) => {
            if !tout_propre {
                assert_eq!(
                    cause,
                    Error::NotPrintable,
                    "une valeur non imprimable a été refusée pour une autre raison"
                );
            }
            return;
        }
    };
    assert!(
        tout_propre,
        "un en-tête a été composé avec une valeur non imprimable"
    );

    // ── 4. LA FORME ─────────────────────────────────────────────────────────
    assert!(
        ecrit.starts_with(b"Received-SPF: "),
        "l'en-tête ne porte pas son nom"
    );
    assert!(
        ecrit.ends_with(b"\r\n"),
        "l'en-tête ne finit pas par un CRLF"
    );
    let texte = String::from_utf8_lossy(ecrit);
    let mot = MOTS[usize::from(entree.verdict % 7)];
    assert!(
        texte[14..].starts_with(mot),
        "le verdict n'est pas celui qu'on a demandé"
    );

    // ── 2. AUCUN SAUT DE LIGNE QUI NE SOIT UN REPLI ─────────────────────────
    //
    // On lit les octets deux par deux : un `CR` doit être suivi d'un `LF`, et
    // un `LF` doit être précédé d'un `CR`. Puis, pour chaque `CRLF` qui n'est
    // pas le dernier, l'octet suivant doit être une espace — c'est ce qui fait
    // d'un saut de ligne un repli plutôt qu'un nouvel en-tête.
    let fin = ecrit.len().saturating_sub(2);
    for (rang, octet) in ecrit.iter().enumerate() {
        match *octet {
            b'\r' => assert_eq!(
                ecrit.get(rang + 1),
                Some(&b'\n'),
                "un CR isolé à l'octet {rang}"
            ),
            b'\n' => {
                assert_eq!(
                    rang.checked_sub(1).and_then(|avant| ecrit.get(avant)),
                    Some(&b'\r'),
                    "un LF isolé à l'octet {rang}"
                );
                if rang + 1 < ecrit.len() {
                    assert_eq!(
                        ecrit.get(rang + 1),
                        Some(&b' '),
                        "un saut de ligne qui n'est pas un repli à l'octet {rang}"
                    );
                }
                assert!(
                    rang < fin || rang + 1 == ecrit.len(),
                    "un repli après la fin"
                );
            }
            _ => {}
        }
    }

    // ── 3. LA BORNE D'UNE LIGNE ─────────────────────────────────────────────
    for ligne in ecrit.split(|octet| *octet == b'\n') {
        assert!(
            ligne.len() <= 999,
            "une ligne de {} octets (CR compris)",
            ligne.len()
        );
    }
});
