// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::{Juge, Refus, clefs_publiques};
use ams_config::{AndroidAttestation, Attested};

macro_rules! vecteur {
    ($nom:literal) => {
        include_bytes!(concat!("../../../ams-attest/src/vecteurs/synthese/", $nom))
    };
}

/// Le texte dont le SHA-256 est le défi des vecteurs : `fabriquer.py` le
/// tire de la même phrase.
const INVITATION: &str = "invitation d'essai";
/// 2026-09-28.
const MAINTENANT: i64 = 1_790_553_600;

fn appareil() -> [u8; 65] {
    <[u8; 65]>::try_from(&vecteur!("appareil.sec1")[..]).expect("soixante-cinq octets")
}

fn empreinte() -> [u8; 32] {
    <[u8; 32]>::try_from(&vecteur!("empreinte.bin")[..]).expect("trente-deux octets")
}

/// La racine d'essai, écrite comme un fichier PEM de clefs publiques.
fn pem_de_la_racine() -> std::vec::Vec<u8> {
    let der = vecteur!("racine.spki");
    let mut url = [0_u8; 512];
    let n = ams_push::encode_base64url(der, &mut url).expect("encodable");
    // Le PEM emploie l'alphabet standard, avec son remplissage.
    let standard: std::string::String = url[..n]
        .iter()
        .map(|octet| match octet {
            b'-' => '+',
            b'_' => '/',
            autre => char::from(*autre),
        })
        .collect();
    let rembourre = std::format!(
        "{standard}{}",
        "=".repeat(4_usize.saturating_sub(standard.len() % 4) % 4)
    );
    std::format!(
        "un commentaire\n-----BEGIN PUBLIC KEY-----\n{}\n{}\n-----END PUBLIC KEY-----\n",
        &rembourre[..64],
        &rembourre[64..]
    )
    .into_bytes()
}

fn juge(mode: AndroidAttestation) -> Juge {
    Juge::new(
        mode,
        "org.airdesktop.mail",
        &[empreinte()],
        Some(&pem_de_la_racine()),
    )
    .expect("un réglage cohérent")
}

fn encode(chaine: &[u8]) -> std::string::String {
    let mut url = std::vec![0_u8; chaine.len().saturating_mul(2)];
    let n = ams_push::encode_base64url(chaine, &mut url).expect("encodable");
    std::string::String::from_utf8(url[..n].to_vec()).expect("ascii")
}

#[test]
fn une_attestation_en_regle_dit_ou_vit_la_clef() {
    for mode in [AndroidAttestation::Verify, AndroidAttestation::Require] {
        let juge = juge(mode);
        assert_eq!(juge.mode(), mode);
        assert_eq!(
            juge.racines(),
            3,
            "Google, deux clefs, et la racine d'essai"
        );
        assert_eq!(
            juge.juger(
                &appareil(),
                INVITATION,
                Some(&encode(vecteur!("tee.der"))),
                MAINTENANT
            ),
            Ok(Some(Attested::Tee))
        );
        assert_eq!(
            juge.juger(
                &appareil(),
                INVITATION,
                Some(&encode(vecteur!("strongbox.der"))),
                MAINTENANT
            ),
            Ok(Some(Attested::StrongBox))
        );
    }
}

/// **CE QUE L'ABSENCE VEUT DIRE DÉPEND DU MODE** : rien à lire, laisser passer,
/// ou refuser.
#[test]
fn l_absence_se_juge_selon_le_mode() {
    let tee = encode(vecteur!("tee.der"));
    let eteint = Juge::eteint();
    assert_eq!(eteint.mode(), AndroidAttestation::Off);
    assert_eq!(
        eteint.juger(&appareil(), INVITATION, Some("§§"), MAINTENANT),
        Ok(None)
    );
    assert_eq!(
        juge(AndroidAttestation::Off).juger(&appareil(), INVITATION, Some(&tee), MAINTENANT),
        Ok(None),
        "éteinte, même une attestation en règle n'est pas lue"
    );
    assert_eq!(
        juge(AndroidAttestation::Verify).juger(&appareil(), INVITATION, None, MAINTENANT),
        Ok(None)
    );
    assert_eq!(
        juge(AndroidAttestation::Require).juger(&appareil(), INVITATION, None, MAINTENANT),
        Err(Refus::Absente)
    );
}

#[test]
fn une_attestation_illisible_ou_refusee_se_refuse() {
    let juge = juge(AndroidAttestation::Verify);
    assert_eq!(
        juge.juger(
            &appareil(),
            INVITATION,
            Some("pas du base64url !"),
            MAINTENANT
        ),
        Err(Refus::Illisible)
    );
    let enorme = "A".repeat(40_000);
    assert_eq!(
        juge.juger(&appareil(), INVITATION, Some(&enorme), MAINTENANT),
        Err(Refus::Illisible)
    );
    // **L'INVITATION EST LE DÉFI** : une autre invitation, et l'attestation ne
    // vaut plus.
    assert_eq!(
        juge.juger(
            &appareil(),
            "une autre invitation",
            Some(&encode(vecteur!("tee.der"))),
            MAINTENANT
        ),
        Err(Refus::Refusee(ams_attest::Refusal::OtherChallenge))
    );
    assert_eq!(
        juge.juger(
            &appareil(),
            INVITATION,
            Some(&encode(vecteur!("deverrouille.der"))),
            MAINTENANT
        ),
        Err(Refus::Refusee(ams_attest::Refusal::UnverifiedBoot))
    );
    // Sans la racine d'essai, la même chaîne ne remonte à rien.
    let google_seul = Juge::new(
        AndroidAttestation::Verify,
        "org.airdesktop.mail",
        &[empreinte()],
        None,
    )
    .expect("cohérent");
    assert_eq!(google_seul.racines(), 2);
    assert_eq!(
        google_seul.juger(
            &appareil(),
            INVITATION,
            Some(&encode(vecteur!("tee.der"))),
            MAINTENANT
        ),
        Err(Refus::Refusee(ams_attest::Refusal::UnknownRoot))
    );
    for refus in [
        Refus::Absente,
        Refus::Illisible,
        Refus::Refusee(ams_attest::Refusal::OtherSigner),
    ] {
        assert!(!refus.dire().is_empty());
    }
}

#[test]
fn un_reglage_incoherent_ne_fait_pas_de_juge() {
    assert!(Juge::new(AndroidAttestation::Verify, "", &[empreinte()], None).is_err());
    assert!(Juge::new(AndroidAttestation::Require, "org.a.b", &[], None).is_err());
    assert!(Juge::new(AndroidAttestation::Off, "", &[], None).is_ok());
    let vide = Juge::new(
        AndroidAttestation::Verify,
        "org.a.b",
        &[empreinte()],
        Some(b"-----BEGIN PUBLIC KEY-----\n!!!\n-----END PUBLIC KEY-----\n"),
    );
    assert!(
        vide.is_err(),
        "un fichier sans clef lisible refuse le démarrage"
    );
}

#[test]
fn les_clefs_d_un_fichier_pem_se_lisent() {
    let pem = pem_de_la_racine();
    assert_eq!(clefs_publiques(&pem), [vecteur!("racine.spki").to_vec()]);
    let deux = [&pem[..], &pem[..]].concat();
    assert_eq!(clefs_publiques(&deux).len(), 2);
    // Un bloc sans fin s'arrête là.
    let sans_fin = [&pem[..], b"-----BEGIN PUBLIC KEY-----\nAAAA"].concat();
    assert_eq!(clefs_publiques(&sans_fin).len(), 1);
    assert!(clefs_publiques(b"rien").is_empty());
    assert!(!std::format!("{:?}", Juge::eteint()).is_empty());
}
