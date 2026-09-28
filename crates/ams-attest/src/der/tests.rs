// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::{CONTEXTE, Lecteur, OCTETS, SEQUENCE, petit_entier};
use crate::Refusal;

fn un(octets: &[u8]) -> Result<super::Tlv<'_>, Refusal> {
    Lecteur::new(octets).lire()
}

#[test]
fn un_element_se_lit_avec_ses_octets_entiers() {
    let lu = un(&[0x04, 0x02, 0xAB, 0xCD]).expect("lisible");
    assert!(lu.est(OCTETS) && !lu.construit);
    assert_eq!(lu.contenu, &[0xAB, 0xCD]);
    assert_eq!(lu.brut, &[0x04, 0x02, 0xAB, 0xCD]);
    // Une longueur longue, minimale.
    let mut long = std::vec![0x04, 0x81, 0x80];
    long.extend_from_slice(&[7_u8; 0x80]);
    assert_eq!(un(&long).expect("lisible").contenu.len(), 0x80);
    // Une étiquette haute : [709], construite, de contexte.
    let haute = un(&[0xBF, 0x85, 0x45, 0x00]).expect("lisible");
    assert_eq!(
        (haute.classe, haute.construit, haute.numero),
        (CONTEXTE, true, 709)
    );
}

/// **CE QUE DER INTERDIT EST REFUSÉ**, même quand un lecteur laxiste le lirait.
#[test]
fn ce_que_der_interdit_est_refuse() {
    for faux in [
        &[][..],
        // Une étiquette haute : un zéro de tête, une valeur qui tenait en
        // forme basse, cinq octets, ou pas de fin.
        &[0x1F, 0x80, 0x01, 0x00],
        &[0x1F, 0x1E, 0x00],
        &[0x1F, 0x81, 0x81, 0x81, 0x81, 0x01, 0x00],
        &[0x1F, 0x81],
        // Pas de longueur ; la longueur indéfinie ; quatre octets de longueur.
        &[0x04],
        &[0x04, 0x80],
        &[0x04, 0x84, 0x01, 0x00, 0x00, 0x00],
        // Des octets de longueur absents, un zéro de tête, une forme longue
        // pour ce qui tenait en courte.
        &[0x04, 0x82, 0x01],
        &[0x04, 0x81, 0x00],
        &[0x04, 0x81, 0x7F],
        // Un contenu plus court que sa longueur.
        &[0x04, 0x05, 0x01],
    ] {
        assert_eq!(un(faux), Err(Refusal::Malformed), "{faux:02x?}");
    }
}

#[test]
fn attendre_et_optionnel_disent_ce_qu_ils_trouvent() {
    let octets = [0xA0, 0x00, 0x30, 0x00];
    let mut lecteur = Lecteur::new(&octets);
    // [1] n'est pas là : rien, et le lecteur n'avance pas.
    assert_eq!(lecteur.optionnel(1), Ok(None));
    assert!(lecteur.optionnel(0).expect("lisible").is_some());
    // Une SEQUENCE n'est pas une chaîne d'octets.
    assert_eq!(lecteur.clone().attendre(OCTETS), Err(Refusal::Malformed));
    assert!(lecteur.attendre(SEQUENCE).is_ok());
    assert!(lecteur.fini());
    // Au bout : rien de facultatif.
    assert_eq!(lecteur.optionnel(3), Ok(None));
    // Un élément illisible ne se déguise pas en absence.
    assert_eq!(
        Lecteur::new(&[0x04, 0x05]).optionnel(0),
        Err(Refusal::Malformed)
    );
}

#[test]
fn un_petit_entier_est_positif_minimal_et_tient_sur_32_bits() {
    assert_eq!(petit_entier(&[0x05]), Ok(5));
    assert_eq!(petit_entier(&[0x00]), Ok(0));
    assert_eq!(petit_entier(&[0x00, 0x80]), Ok(128));
    assert_eq!(petit_entier(&[0x7F, 0xFF, 0xFF, 0xFF]), Ok(0x7FFF_FFFF));
    for faux in [
        &[][..],
        &[0x00, 0x01],
        &[0x80],
        &[0x01, 0x02, 0x03, 0x04, 0x05],
    ] {
        assert_eq!(petit_entier(faux), Err(Refusal::Malformed), "{faux:02x?}");
    }
    assert!(!std::format!("{:?}", Lecteur::new(&[])).is_empty());
}
