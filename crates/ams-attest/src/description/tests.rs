// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::{Demarrage, Niveau, RacineDeConfiance, application, lire};
use crate::Refusal;
use crate::tests::fabrique::{contexte, ensemble, entier, enumere, octets, seq, tlv};
use std::vec::Vec;

fn booleen(vrai: bool) -> Vec<u8> {
    tlv(&[0x01], &[if vrai { 0xFF } else { 0x00 }])
}

fn racine(verrouille: &[u8], etat: u8, suite: &[&[u8]]) -> Vec<u8> {
    let cle = octets(&[0; 32]);
    let etat = enumere(etat);
    let mut champs: Vec<&[u8]> = std::vec![&cle, verrouille, &etat];
    champs.extend_from_slice(suite);
    contexte(704, &seq(&champs))
}

/// Une `KeyDescription` : ces deux listes, sous ces niveaux.
fn description(niveau: u8, logiciel: &[&[u8]], materiel: &[&[u8]], suite: &[&[u8]]) -> Vec<u8> {
    let mut champs: Vec<Vec<u8>> = std::vec![
        entier(100),
        enumere(niveau),
        entier(100),
        enumere(niveau),
        octets(b"defi"),
        octets(b""),
        seq(logiciel),
        seq(materiel),
    ];
    champs.extend(suite.iter().map(|part| part.to_vec()));
    let refs: Vec<&[u8]> = champs.iter().map(Vec::as_slice).collect();
    seq(&refs)
}

#[test]
fn une_description_se_lit() {
    let origine = contexte(702, &entier(0));
    let racine_ = racine(&booleen(true), 0, &[&octets(&[1; 32])]);
    let correctifs = contexte(706, &entier(99));
    let appli = contexte(709, &octets(b"appli"));
    let lue_brute = description(2, &[&appli], &[&origine, &racine_, &correctifs], &[]);
    let lue = lire(&lue_brute).expect("lisible");
    assert_eq!(lue.niveau, Niveau::StrongBox);
    assert_eq!(lue.version, 100);
    assert_eq!(lue.defi, b"defi");
    assert!(lue.generee);
    assert_eq!(
        lue.racine,
        Some(RacineDeConfiance {
            verrouille: true,
            demarrage: Demarrage::Verifie,
        })
    );
    assert_eq!(lue.correctifs, Some(99));
    assert_eq!(lue.application, Some(&b"appli"[..]));
    // Dans la liste MATÉRIELLE, l'identité de l'application se lit aussi.
    let materielle = description(1, &[], &[&appli], &[]);
    assert_eq!(
        lire(&materielle).expect("lisible").application,
        Some(&b"appli"[..])
    );
}

/// **CHAQUE ÉTAT DU DÉMARRAGE SE LIT**, avec ou sans le condensat de la
/// version 3.
#[test]
fn chaque_etat_du_demarrage_se_lit() {
    for (etat, attendu) in [
        (0, Demarrage::Verifie),
        (1, Demarrage::AutoSigne),
        (2, Demarrage::NonVerifie),
        (3, Demarrage::Echoue),
    ] {
        let brute = description(1, &[], &[&racine(&booleen(false), etat, &[])], &[]);
        let lue = lire(&brute).expect("lisible");
        assert_eq!(
            lue.racine,
            Some(RacineDeConfiance {
                verrouille: false,
                demarrage: attendu,
            })
        );
    }
}

#[test]
fn ce_qui_n_a_pas_la_forme_d_une_description_est_refuse() {
    let appli = contexte(709, &octets(b"a"));
    let origine = contexte(702, &entier(0));
    let mut apres = description(1, &[], &[], &[]);
    apres.push(0);
    for faux in [
        apres,
        // Un champ de trop après les deux listes ; un niveau inconnu.
        description(1, &[], &[], &[&entier(0)]),
        description(3, &[], &[], &[]),
        // L'identité de l'application dans les DEUX listes.
        description(1, &[&appli], &[&appli], &[]),
        // Un élément qui n'est pas de contexte, une étiquette répétée, dans le
        // désordre, ou primitive.
        description(1, &[], &[&entier(0)], &[]),
        description(1, &[], &[&origine, &origine], &[]),
        description(1, &[], &[&appli, &origine], &[]),
        description(1, &[], &[&tlv(&[0x80], &[0])], &[]),
        // Une valeur suivie d'une autre.
        description(
            1,
            &[],
            &[&contexte(702, &[entier(0), entier(0)].concat())],
            &[],
        ),
        // Une racine de confiance suivie d'autre chose ; un booléen qui n'en est
        // pas un ; un état inconnu ; un champ après le condensat.
        description(
            1,
            &[],
            &[&contexte(704, &[seq(&[]), seq(&[])].concat())],
            &[],
        ),
        description(1, &[], &[&racine(&tlv(&[0x01], &[0x01]), 0, &[])], &[]),
        description(1, &[], &[&racine(&booleen(true), 4, &[])], &[]),
        description(
            1,
            &[],
            &[&racine(&booleen(true), 0, &[&octets(b""), &octets(b"")])],
            &[],
        ),
    ] {
        assert_eq!(lire(&faux), Err(Refusal::Malformed), "{faux:02x?}");
    }
}

/// Les paquets et les empreintes qu'une identité d'application nomme.
type Vus = (Vec<Vec<u8>>, Vec<Vec<u8>>);

/// Lit une identité d'application, et rend ce qu'on en a vu.
fn voir(encode: &[u8]) -> Result<Vus, Refusal> {
    let mut paquets = Vec::new();
    let mut empreintes = Vec::new();
    application(
        encode,
        &mut |nom| paquets.push(nom.to_vec()),
        &mut |empreinte| empreintes.push(empreinte.to_vec()),
    )?;
    Ok((paquets, empreintes))
}

#[test]
fn une_identite_d_application_se_lit_et_se_refuse() {
    let paquet = seq(&[&octets(b"org.airdesktop.mail"), &entier(7)]);
    let bonne = seq(&[&ensemble(&[&paquet]), &ensemble(&[&octets(&[9; 32])])]);
    assert_eq!(
        voir(&bonne),
        Ok((
            std::vec![b"org.airdesktop.mail".to_vec()],
            std::vec![std::vec![9; 32]]
        ))
    );
    let mut apres = bonne.clone();
    apres.push(0);
    let trois = seq(&[&ensemble(&[]), &ensemble(&[]), &ensemble(&[])]);
    let paquet_long = seq(&[&octets(b"p"), &entier(1), &entier(2)]);
    let paquet_de_trop = seq(&[&ensemble(&[&paquet_long]), &ensemble(&[])]);
    for fausse in [apres, trois, paquet_de_trop] {
        assert_eq!(voir(&fausse), Err(Refusal::Malformed), "{fausse:02x?}");
    }
}

/// Une description complète : chaque champ que la lecture emploie.
fn complete() -> Vec<u8> {
    let appli = contexte(709, &octets(b"appli"));
    let origine = contexte(702, &entier(0));
    let racine_ = racine(&booleen(true), 0, &[&octets(&[1; 32])]);
    let correctifs = contexte(706, &entier(99));
    description(1, &[&appli], &[&origine, &racine_, &correctifs], &[])
}

/// **AUCUN OCTET ALTÉRÉ NE FAIT PANIQUER** : la lecture rend une description,
/// ou un refus — jamais autre chose. Et chaque champ passe ainsi par son
/// chemin d'erreur.
#[test]
fn aucune_alteration_d_une_description_ne_fait_paniquer() {
    let bonne = complete();
    assert!(lire(&bonne).is_ok());
    let mut refusees = 0_usize;
    for rang in 0..bonne.len() {
        for valeur in [0x00_u8, 0xFF, 0x04, 0x30, bonne[rang] ^ 0x01] {
            let mut alteree = bonne.clone();
            alteree[rang] = valeur;
            if lire(&alteree).is_err() {
                refusees += 1;
            }
        }
    }
    assert!(
        refusees > bonne.len(),
        "presque toutes doivent être refusées"
    );
    // L'identité de l'application dans la liste matérielle, mais qui n'est pas
    // une chaîne d'octets.
    let fausse = description(1, &[], &[&contexte(709, &entier(0))], &[]);
    assert_eq!(lire(&fausse), Err(Refusal::Malformed));
}

#[test]
fn aucune_alteration_d_une_identite_d_application_ne_fait_paniquer() {
    let paquet = seq(&[&octets(b"org.airdesktop.mail"), &entier(7)]);
    let bonne = seq(&[&ensemble(&[&paquet]), &ensemble(&[&octets(&[9; 4])])]);
    assert!(voir(&bonne).is_ok());
    for rang in 0..bonne.len() {
        for valeur in [0x00_u8, 0xFF, 0x04, 0x30, bonne[rang] ^ 0x01] {
            let mut alteree = bonne.clone();
            alteree[rang] = valeur;
            let _ = voir(&alteree);
        }
    }
}
