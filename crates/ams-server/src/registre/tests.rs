// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

use ams_config::registre::{Abandon, Enregistrement, verifier};

use super::Registre;

/// 2026-09-29, 10:00 UTC.
const LUNDI: u64 = 1_790_676_000_000;
/// Le lendemain, 00:00:01 UTC.
const MARDI: u64 = 1_790_726_401_000;

fn atelier(nom: &str) -> PathBuf {
    let chemin = std::env::temp_dir().join(format!("ams-registre-{nom}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&chemin);
    chemin
}

fn abandon(numero: u32) -> Enregistrement {
    Enregistrement::Abandon(Abandon {
        session: [numero.to_le_bytes()[0]; 16],
        numero,
        quand: 1,
        raison: String::from("essai"),
    })
}

fn lire(chemin: &std::path::Path) -> Vec<u8> {
    std::fs::read(chemin).expect("lisible")
}

/// **UN JOUR, PUIS LE LENDEMAIN** : le premier fichier se scelle au premier
/// enregistrement du second, passe en lecture seule, et le second cite son
/// condensat.
#[test]
fn deux_jours_font_deux_fichiers_chaines() {
    let repertoire = atelier("deux-jours");
    let registre = Registre::ouvrir_a(repertoire.clone(), LUNDI).expect("ouvert");
    assert!(!format!("{registre:?}").is_empty());
    let mode = std::fs::metadata(&repertoire)
        .expect("existe")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700);
    registre.ecrire_a(&abandon(1), LUNDI).expect("écrit");
    registre.ecrire_a(&abandon(2), LUNDI).expect("écrit");
    // Le même jour, `tenir` ne scelle rien.
    registre.tenir_a(LUNDI).expect("tenu");
    let lundi = repertoire.join("2026-09-29.amsr");
    let ouvert = verifier(&lire(&lundi)).expect("vérifiable");
    assert!(ouvert.sceau.is_none());
    assert_eq!(ouvert.enregistrements, 3);
    assert_eq!(ouvert.entete.precedent, None);

    registre.ecrire_a(&abandon(3), MARDI).expect("écrit");
    let scelle = verifier(&lire(&lundi)).expect("vérifiable");
    assert_eq!(scelle.sceau.map(|sceau| sceau.enregistrements), Some(3));
    let mode = std::fs::metadata(&lundi)
        .expect("existe")
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o777,
        0o400,
        "un fichier scellé est en lecture seule"
    );
    let mardi = verifier(&lire(&repertoire.join("2026-09-30.amsr"))).expect("vérifiable");
    assert_eq!(mardi.entete.precedent, Some(scelle.condensat));
    assert_eq!(mardi.entete.jour, "2026-09-30");
    let _ = std::fs::remove_dir_all(&repertoire);
}

/// **UN JOUR SANS COURRIER SE SCELLE QUAND MÊME** : c'est `tenir` qui passe
/// minuit, et le fichier suivant — ouvert plus tard — cite le scellé.
#[test]
fn tenir_scelle_a_minuit() {
    let repertoire = atelier("minuit");
    let registre = Registre::ouvrir_a(repertoire.clone(), LUNDI).expect("ouvert");
    registre.tenir_a(LUNDI).expect("rien à tenir");
    registre.ecrire_a(&abandon(1), LUNDI).expect("écrit");
    registre.tenir_a(MARDI).expect("scellé");
    let scelle = verifier(&lire(&repertoire.join("2026-09-29.amsr"))).expect("vérifiable");
    assert!(scelle.sceau.is_some());
    registre.ecrire_a(&abandon(2), MARDI).expect("écrit");
    let mardi = verifier(&lire(&repertoire.join("2026-09-30.amsr"))).expect("vérifiable");
    assert_eq!(mardi.entete.precedent, Some(scelle.condensat));
    let _ = std::fs::remove_dir_all(&repertoire);
}

/// **UN ARRÊT BRUTAL NE CASSE PAS LA CHAÎNE** : la trame coupée se retire, le
/// même jour l'écriture reprend à la suite, et le sceau dit combien d'octets
/// ont été retirés.
#[test]
fn une_trame_coupee_se_retire_a_la_reprise() {
    let repertoire = atelier("coupee");
    {
        let registre = Registre::ouvrir_a(repertoire.clone(), LUNDI).expect("ouvert");
        registre.ecrire_a(&abandon(1), LUNDI).expect("écrit");
    }
    let lundi = repertoire.join("2026-09-29.amsr");
    let mut octets = lire(&lundi);
    let entier = octets.len();
    octets.extend_from_slice(&[40, 0, 0, 0, 1, 2, 3]);
    std::fs::write(&lundi, &octets).expect("coupé");

    let registre = Registre::ouvrir_a(repertoire.clone(), LUNDI).expect("rouvert");
    assert_eq!(lire(&lundi).len(), entier, "la trame coupée est retirée");
    registre
        .ecrire_a(&abandon(2), LUNDI)
        .expect("écrit à la suite");
    assert_eq!(
        verifier(&lire(&lundi)).expect("vérifiable").enregistrements,
        3
    );
    registre.tenir_a(MARDI).expect("scellé");
    let scelle = verifier(&lire(&lundi)).expect("vérifiable");
    assert_eq!(scelle.sceau.map(|sceau| sceau.tronques), Some(7));
    let _ = std::fs::remove_dir_all(&repertoire);
}

/// **UN JOUR PASSÉ RESTÉ OUVERT SE SCELLE AU REDÉMARRAGE**, et un fichier
/// déjà scellé donne le chaînon du suivant.
#[test]
fn le_redemarrage_scelle_un_jour_passe() {
    let repertoire = atelier("redemarrage");
    {
        let registre = Registre::ouvrir_a(repertoire.clone(), LUNDI).expect("ouvert");
        registre.ecrire_a(&abandon(1), LUNDI).expect("écrit");
    }
    let registre = Registre::ouvrir_a(repertoire.clone(), MARDI).expect("rouvert");
    let scelle = verifier(&lire(&repertoire.join("2026-09-29.amsr"))).expect("vérifiable");
    assert!(scelle.sceau.is_some());
    drop(registre);
    // Rouvert encore : le dernier fichier est scellé, il donne le chaînon.
    let registre = Registre::ouvrir_a(repertoire.clone(), MARDI).expect("rouvert");
    registre.ecrire_a(&abandon(2), MARDI).expect("écrit");
    let mardi = verifier(&lire(&repertoire.join("2026-09-30.amsr"))).expect("vérifiable");
    assert_eq!(mardi.entete.precedent, Some(scelle.condensat));
    let _ = std::fs::remove_dir_all(&repertoire);
}

/// **UNE CHAÎNE QU'ON NE SAIT PAS PROLONGER ARRÊTE LE DÉMARRAGE.**
#[test]
fn un_dernier_fichier_illisible_refuse_l_ouverture() {
    let repertoire = atelier("illisible");
    std::fs::create_dir_all(&repertoire).expect("créé");
    std::fs::write(repertoire.join("2026-09-29.amsr"), b"pas un registre").expect("écrit");
    std::fs::write(repertoire.join("notes.txt"), b"ignore").expect("écrit");
    let faute = Registre::ouvrir_a(repertoire.clone(), LUNDI).expect_err("refusé");
    assert_eq!(faute.kind(), std::io::ErrorKind::InvalidData);
    let _ = std::fs::remove_dir_all(&repertoire);
}

/// **UN DISQUE QUI REFUSE L'ÉCRITURE SE DIT** — c'est ce qui fera répondre
/// `451` au pair.
#[test]
fn une_ecriture_impossible_se_rend() {
    let repertoire = atelier("refus");
    let registre = Registre::ouvrir_a(repertoire.clone(), LUNDI).expect("ouvert");
    // Le fichier du jour existe déjà, écrit par un autre : `create_new` le
    // refuse plutôt que d'écrire à la suite d'un fichier qu'on n'a pas ouvert.
    std::fs::write(repertoire.join("2026-09-29.amsr"), b"").expect("posé");
    assert!(registre.ecrire_a(&abandon(1), LUNDI).is_err());
    let _ = std::fs::remove_dir_all(&repertoire);
}
