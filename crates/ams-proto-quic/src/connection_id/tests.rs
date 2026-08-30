// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un identifiant de connexion a le droit d'être.

use super::{CONNECTION_ID_MAX, ConnectionId};
use crate::error::{Reason, TransportError};

/// **ZÉRO À VINGT OCTETS** (§17.2), et le vide n'est pas un cas dégénéré : un
/// pair qui n'a rien à router économise vingt octets par paquet.
#[test]
fn de_zero_a_vingt_octets() {
    let vide = ConnectionId::EMPTY;
    assert!(vide.is_empty());
    assert_eq!(vide.len(), 0);
    assert_eq!(vide.as_bytes(), b"");
    assert_eq!(ConnectionId::new(&[]).expect("le vide est licite"), vide);

    for taille in 1..=CONNECTION_ID_MAX {
        let octets = [0xab_u8; CONNECTION_ID_MAX];
        let lus = octets.get(..taille).expect("assez court");
        let identifiant = ConnectionId::new(lus).expect("licite");
        assert_eq!(identifiant.len(), taille);
        assert_eq!(identifiant.as_bytes(), lus);
        assert!(!identifiant.is_empty());
    }
}

/// **LA LONGUEUR VIENT DU FIL, ET UN OCTET PEUT EN ANNONCER DEUX CENT
/// CINQUANTE-CINQ.** Sans la borne, un pair choisirait combien on retient de
/// lui.
#[test]
fn au_dela_de_vingt_octets_on_refuse() {
    for taille in [CONNECTION_ID_MAX.saturating_add(1), 64, 255] {
        let octets = [0_u8; 256];
        let issue =
            ConnectionId::new(octets.get(..taille).expect("assez court")).expect_err("hors borne");
        assert_eq!(issue.reason(), Reason::ConnectionIdTooLong, "{taille}");
        // §17.2 dit de JETER le paquet : une connexion qu'on ferme sur un
        // paquet égaré est une connexion qu'un tiers peut fermer.
        assert_eq!(issue.code(), TransportError::ProtocolViolation);
    }
}

/// Deux identifiants d'octets différents ne sont pas le même, et deux
/// identifiants de longueurs différentes non plus — même si l'un commence comme
/// l'autre.
#[test]
fn deux_identifiants_se_distinguent() {
    let court = ConnectionId::new(&[1, 2, 3]).expect("licite");
    let long = ConnectionId::new(&[1, 2, 3, 4]).expect("licite");
    let autre = ConnectionId::new(&[1, 2, 4]).expect("licite");
    assert_ne!(court, long, "un préfixe n'est pas l'identifiant");
    assert_ne!(court, autre);
    assert_eq!(court, ConnectionId::new(&[1, 2, 3]).expect("licite"));
}
