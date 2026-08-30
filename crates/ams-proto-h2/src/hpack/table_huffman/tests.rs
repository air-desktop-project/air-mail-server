// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que la table de Huffman garantit.

use super::{CODE, CODE_EOS, CODE_MIN_BITS, EOS, LONGUEUR, code_d_octet, symbole_de};

/// La plus longue longueur de code : celle d'`EOS`.
const CODE_MAX_BITS: u32 = CODE_EOS.1;

/// Le code d'un symbole quelconque, `EOS` compris.
///
/// La production n'a besoin que des octets — `code_d_octet` — et du code d'`EOS`
/// pour le remplissage. Les épreuves, elles, parcourent les deux cent
/// cinquante-sept, et lisent donc les tables directement.
fn code_de(symbole: u16) -> Option<(u32, u32)> {
    let rang = usize::from(symbole);
    let code = CODE.get(rang)?;
    let longueur = LONGUEUR.get(rang)?;
    Some((*code, u32::from(*longueur)))
}

/// **LE CODE EST PRÉFIXE**, et on le prouve plutôt que de le croire : aucun code
/// n'est le début d'un autre. Sans cette propriété, un décodeur ne saurait pas
/// où un symbole s'arrête.
#[test]
fn le_code_est_prefixe() {
    let mut vus = std::collections::HashSet::new();
    for symbole in 0..=EOS {
        let (code, bits) = code_de(symbole).expect("tout symbole a un code");
        assert!((CODE_MIN_BITS..=CODE_MAX_BITS).contains(&bits), "{symbole}");
        assert!(
            u64::from(code) < (1_u64 << bits),
            "{symbole} déborde sa longueur"
        );
        // Aucun préfixe de ce code n'est un code entier.
        for longueur in CODE_MIN_BITS..bits {
            let prefixe = code >> (bits.saturating_sub(longueur));
            assert!(
                !vus.contains(&(prefixe, longueur)),
                "le code de {symbole} commence par un autre code"
            );
        }
        assert!(vus.insert((code, bits)), "deux symboles, un seul code");
    }
    assert_eq!(vus.len(), 257);
}

/// **CHAQUE CODE SE RETROUVE**, et rien d'autre ne se retrouve à sa place.
#[test]
fn chaque_code_se_retrouve() {
    for symbole in 0..=EOS {
        let (code, bits) = code_de(symbole).expect("tout symbole a un code");
        assert_eq!(symbole_de(code, bits), Some(symbole), "{symbole}");
    }
}

/// **AUCUN CHEMIN DE TRENTE BITS NE RESTE SANS SYMBOLE**, et c'est ce qui
/// permet au décodeur de n'avoir aucune garde de longueur : la table est
/// COMPLÈTE à cette profondeur. Si elle cessait de l'être, ce test le dirait
/// avant que le décodeur ne se mette à accumuler sans fin.
#[test]
fn aucun_chemin_de_trente_bits_ne_reste_sans_symbole() {
    // Les nœuds internes à vingt-neuf bits : les préfixes qui ne sont pas
    // encore un symbole.
    let mut internes = std::collections::HashSet::new();
    for symbole in 0..=EOS {
        let (code, bits) = code_de(symbole).expect("tout symbole a un code");
        for longueur in 1..bits {
            internes.insert((code >> bits.saturating_sub(longueur), longueur));
        }
    }
    let mut profonds = 0_u32;
    for (prefixe, longueur) in &internes {
        if *longueur != CODE_EOS.1.saturating_sub(1) {
            continue;
        }
        for bit in 0..2_u32 {
            let code = (prefixe << 1) | bit;
            assert!(
                symbole_de(code, CODE_EOS.1).is_some(),
                "le chemin {code:#x} de trente bits n'aboutit à rien"
            );
            profonds = profonds.saturating_add(1);
        }
    }
    assert_eq!(profonds, 4, "quatre feuilles à trente bits, `EOS` compris");
    // Et il n'y a aucun nœud interne À trente bits : rien ne descend plus bas.
    assert!(
        !internes.iter().any(|(_, longueur)| *longueur >= CODE_EOS.1),
        "un chemin descend sous trente bits"
    );
}

/// Le code d'un octet se lit sans détour, et coïncide avec la table.
#[test]
fn le_code_d_un_octet_se_lit_sans_detour() {
    for octet in 0..=255_u8 {
        assert_eq!(
            code_d_octet(octet),
            code_de(u16::from(octet)).expect("un octet a un code"),
            "{octet}"
        );
    }
}

/// Quelques valeurs, confrontées au texte de l'annexe B.
#[test]
fn les_valeurs_sont_celles_de_l_annexe() {
    assert_eq!(code_de(0), Some((0x1ff8, 13)));
    assert_eq!(code_de(b' '.into()), Some((0x14, 6)));
    assert_eq!(code_de(b'0'.into()), Some((0x0, 5)));
    assert_eq!(code_de(b'a'.into()), Some((0x3, 5)));
    assert_eq!(code_de(b'z'.into()), Some((0x7b, 7)));
    assert_eq!(code_de(EOS), Some((0x3fff_ffff, 30)));
}

/// Au-delà d'`EOS`, il n'y a pas de symbole.
#[test]
fn au_dela_d_eos_il_n_y_a_rien() {
    for symbole in [257_u16, 300, u16::MAX] {
        assert_eq!(code_de(symbole), None, "{symbole}");
    }
}

/// Une longueur ou un code qui ne désignent rien ne désignent rien.
#[test]
fn ce_qui_ne_designe_rien_ne_designe_rien() {
    // Une longueur sous le minimum.
    for bits in 0..CODE_MIN_BITS {
        assert_eq!(symbole_de(0, bits), None, "{bits} bits");
    }
    // Une longueur au-delà du maximum.
    assert_eq!(symbole_de(0, CODE_MAX_BITS.saturating_add(1)), None);
    assert_eq!(symbole_de(0, u32::MAX), None);
    // Un code sous le premier de sa longueur.
    assert_eq!(
        symbole_de(0, 6),
        None,
        "le premier code de six bits est 0x14"
    );
    // Un code au-delà du dernier de sa longueur.
    assert_eq!(symbole_de(0xffff_ffff, 30), None);
    // Une longueur qu'aucun symbole n'emploie — il n'y a rien sur neuf bits.
    assert_eq!(symbole_de(0x1fc, 9), None);
}
