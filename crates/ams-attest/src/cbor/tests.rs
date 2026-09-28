// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::Cbor;
use crate::Refusal;

#[test]
fn les_formes_admises_se_lisent() {
    // Une table d'un texte vers un tableau d'octets, d'un entier et d'une table.
    let objet = [
        0xA1, 0x61, b'k', 0x83, 0x42, 1, 2, 0x18, 200, 0xA1, 0x61, b'a', 0x19, 0x01, 0x00,
    ];
    let mut lu = Cbor::new(&objet);
    assert_eq!(lu.table(), Ok(1));
    assert_eq!(lu.texte(), Ok(&b"k"[..]));
    let mut copie = lu.clone();
    assert_eq!(copie.sauter(0), Ok(()));
    assert!(copie.fini());
    assert_eq!(lu.tableau(), Ok(3));
    assert_eq!(lu.octets(), Ok(&[1_u8, 2][..]));
    // Les longueurs de quatre et huit octets.
    let long = [0x5A, 0, 0, 0, 1, 7, 0x1B, 0, 0, 0, 0, 0, 0, 0, 9];
    let mut lu = Cbor::new(&long);
    assert_eq!(lu.octets(), Ok(&[7_u8][..]));
    assert_eq!(lu.sauter(0), Ok(()));
    assert!(lu.fini());
    assert!(!std::format!("{lu:?}").is_empty());
}

#[test]
fn ce_que_ce_lecteur_ne_lit_pas_se_refuse() {
    for faux in [
        &[][..],
        // Longueur indéfinie, arguments réservés, argument tronqué.
        &[0x5F],
        &[0x5C],
        &[0x19, 0x01],
        // Une chaîne plus courte que sa longueur.
        &[0x43, 1],
        // Un nombre à virgule, une étiquette, une valeur simple.
        &[0xF9, 0, 0],
        &[0xC0, 0x01],
        &[0xF5],
    ] {
        let mut lu = Cbor::new(faux);
        assert_eq!(lu.octets(), Err(Refusal::Malformed), "{faux:02x?}");
        let mut lu = Cbor::new(faux);
        assert_eq!(lu.sauter(0), Err(Refusal::Malformed), "{faux:02x?}");
    }
    // Rien à lire là où l'on attend une table ; un texte tronqué à sauter.
    assert_eq!(Cbor::new(&[]).table(), Err(Refusal::Malformed));
    assert_eq!(Cbor::new(&[0x63, b'a']).sauter(0), Err(Refusal::Malformed));
    // Un entier se saute, mais n'est pas une chaîne d'octets.
    assert_eq!(Cbor::new(&[0x01]).octets(), Err(Refusal::Malformed));
    assert_eq!(Cbor::new(&[0x61, b'a']).table(), Err(Refusal::Malformed));
    assert_eq!(Cbor::new(&[0x40]).texte(), Err(Refusal::Malformed));
    // Neuf niveaux d'imbrication : au-delà de la borne.
    let profond = [0x81; 10];
    assert_eq!(Cbor::new(&profond).sauter(0), Err(Refusal::Malformed));
    // Une chaîne d'une longueur qui ne tient pas dans un `usize` de 32 bits
    // ne se lit pas plus qu'une chaîne trop courte.
    let enorme = [0x5B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    assert_eq!(Cbor::new(&enorme).octets(), Err(Refusal::Malformed));
}
