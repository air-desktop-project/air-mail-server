// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! App Attest, éprouvé contre l'objet d'attestation d'exemple qu'Apple publie
//! — repris dans `nl-wallet` (`apple_app_attest`) : défi
//! `test_server_challenge`, application `0352187391.com.apple.example_app_attest`,
//! production, et un certificat de clef valide du 17 au 20 avril 2024.

use super::{APPLE_ROOTS, AppleEnvironment, ApplePolicy, verify_app_attest};
use crate::Refusal;
use sha2::Digest as _;

const EXEMPLE: &[u8] = include_bytes!("../vecteurs/apple/exemple-apple.cbor");
const DEFI: &[u8] = b"test_server_challenge";
const APPLICATION: &[u8] = b"0352187391.com.apple.example_app_attest";
/// 2024-04-18 à midi UTC.
const LE_18_AVRIL_2024: i64 = 1_713_441_600;

fn politique(app_id: &'static [u8], environment: AppleEnvironment) -> ApplePolicy<'static> {
    ApplePolicy {
        roots: &APPLE_ROOTS,
        app_id,
        environment,
    }
}

#[test]
fn l_exemple_d_apple_est_accepte() {
    let lue = verify_app_attest(
        EXEMPLE,
        DEFI,
        &politique(APPLICATION, AppleEnvironment::Production),
        LE_18_AVRIL_2024,
    )
    .expect("l'exemple d'Apple doit passer");
    // Le nom du certificat de la clef est son identifiant.
    assert_eq!(
        lue.key_id
            .iter()
            .map(|o| std::format!("{o:02x}"))
            .collect::<std::string::String>(),
        "6d2ac4845f1323322f5923f0bd9d22dbe50e06b7b80121fce2b2b5e66e9e98d6"
    );
}

#[test]
fn chaque_ecart_de_l_exemple_se_refuse_pour_sa_raison() {
    type Cas = (&'static [u8], &'static [u8], AppleEnvironment, i64, Refusal);
    let cas: [Cas; 5] = [
        (
            b"autre_defi",
            APPLICATION,
            AppleEnvironment::Production,
            LE_18_AVRIL_2024,
            Refusal::OtherChallenge,
        ),
        (
            DEFI,
            b"0352187391.com.exemple.autre",
            AppleEnvironment::Production,
            LE_18_AVRIL_2024,
            Refusal::OtherApplication,
        ),
        (
            DEFI,
            APPLICATION,
            AppleEnvironment::Development,
            LE_18_AVRIL_2024,
            Refusal::OtherEnvironment,
        ),
        // Le certificat de la clef ne vit que trois jours.
        (
            DEFI,
            APPLICATION,
            AppleEnvironment::Production,
            LE_18_AVRIL_2024 + 3 * 86_400,
            Refusal::Expired,
        ),
        (
            DEFI,
            APPLICATION,
            AppleEnvironment::Production,
            1_700_000_000,
            Refusal::Expired,
        ),
    ];
    for (defi, app, env, instant, attendu) in cas {
        assert_eq!(
            verify_app_attest(EXEMPLE, defi, &politique(app, env), instant),
            Err(attendu),
            "{}",
            attendu.describe()
        );
    }
    // Sans la racine d'Apple, rien ne remonte.
    let sans = ApplePolicy {
        roots: &[],
        ..politique(APPLICATION, AppleEnvironment::Production)
    };
    assert_eq!(
        verify_app_attest(EXEMPLE, DEFI, &sans, LE_18_AVRIL_2024),
        Err(Refusal::UnknownRoot)
    );
}

/// **LA RACINE EST CELLE QU'APPLE PUBLIE** — « Apple App Attestation Root CA ».
#[test]
fn la_racine_d_apple_est_celle_qu_apple_publie() {
    let empreinte: std::string::String = sha2::Sha256::digest(APPLE_ROOTS[0])
        .iter()
        .map(|o| std::format!("{o:02x}"))
        .collect();
    assert_eq!(
        empreinte,
        "1ae751fd29896d0f1f13fe226c063f445d40d8938acc6245c251ecc0679330bd"
    );
}

macro_rules! synthese {
    ($nom:literal) => {
        include_bytes!(concat!("../vecteurs/apple/synthese/", $nom))
    };
}

/// La politique des objets synthétiques : leur racine d'essai, leur
/// application.
fn juger(objet: &[u8], environment: AppleEnvironment) -> Result<super::AppAttestation, Refusal> {
    let racines = [&synthese!("racine.spki")[..]];
    let politique = ApplePolicy {
        roots: &racines,
        app_id: b"TEAM123456.org.airdesktop.mail",
        environment,
    };
    // 2026-09-28.
    verify_app_attest(objet, synthese!("client.bin"), &politique, 1_790_553_600)
}

#[test]
fn un_objet_synthetique_en_regle_passe_et_chaque_ecart_se_refuse() {
    assert!(juger(synthese!("bon.cbor"), AppleEnvironment::Production).is_ok());
    assert!(
        juger(
            synthese!("developpement.cbor"),
            AppleEnvironment::Development
        )
        .is_ok()
    );
    let cas: [(&[u8], Refusal); 16] = [
        (synthese!("auth-courte-6.cbor"), Refusal::Malformed),
        (synthese!("developpement.cbor"), Refusal::OtherEnvironment),
        (synthese!("compteur.cbor"), Refusal::Malformed),
        (synthese!("autre-identifiant.cbor"), Refusal::OtherKey),
        (synthese!("sans-extension.cbor"), Refusal::NoAttestation),
        (synthese!("extension-illisible.cbor"), Refusal::Malformed),
        (synthese!("autre-format.cbor"), Refusal::Malformed),
        (synthese!("feuille-p384.cbor"), Refusal::OtherKey),
        (synthese!("mal-signee.cbor"), Refusal::BadSignature),
        (synthese!("un-certificat.cbor"), Refusal::ChainLength),
        (synthese!("auth-courte-0.cbor"), Refusal::Malformed),
        (synthese!("auth-courte-1.cbor"), Refusal::Malformed),
        (synthese!("auth-courte-2.cbor"), Refusal::Malformed),
        (synthese!("auth-courte-3.cbor"), Refusal::Malformed),
        (synthese!("auth-courte-4.cbor"), Refusal::Malformed),
        (synthese!("auth-courte-5.cbor"), Refusal::Malformed),
    ];
    for (objet, attendu) in cas {
        assert_eq!(
            juger(objet, AppleEnvironment::Production),
            Err(attendu),
            "{}",
            attendu.describe()
        );
    }
}

/// **CE QUI N'A PAS LA FORME D'UN OBJET D'ATTESTATION SE REFUSE** — y compris
/// un objet entier suivi d'un octet, ou auquel il manque une partie.
#[test]
fn ce_qui_n_a_pas_la_forme_d_un_objet_se_refuse() {
    let bon: &[u8] = synthese!("bon.cbor");
    let mut apres = bon.to_vec();
    apres.push(0);
    // Une table vide, et une table où manquent `authData` ou `x5c`.
    for faux in [
        &apres[..],
        &[0xA0][..],
        &[0xA1, 0x63, b'f', b'm', b't', 0x6F][..],
        b"\xa2\x63fmt\x6fapple-appattest\x67attStmt\xa0",
        // Pas une table ; un `attStmt` qui n'en est pas une ; un `x5c` qui
        // n'est pas un tableau ; un champ inconnu illisible, dehors et dedans.
        &[0x80][..],
        b"\xa1\x67attStmt\x01",
        b"\xa1\x67attStmt\xa1\x63x5c\x01",
        b"\xa1\x67attStmt\xa1\x67receipt\x5f",
        b"\xa1\x63zut\x5f",
    ] {
        assert!(
            juger(faux, AppleEnvironment::Production).is_err(),
            "{faux:02x?}"
        );
    }
    // Chaque octet altéré : jamais de panique, et jamais d'acceptation hors
    // du reçu, que rien ne couvre.
    for rang in 0..bon.len() {
        let mut altere = bon.to_vec();
        altere[rang] ^= 0x01;
        let _ = juger(&altere, AppleEnvironment::Production);
    }
}

/// **LE NONCE A SA FORME, ET AUCUNE AUTRE** : `SEQUENCE { [1] OCTET STRING }`.
#[test]
fn le_nonce_a_sa_forme() {
    use super::nonce_de;
    assert_eq!(
        nonce_de(&[0x30, 0x05, 0xA1, 0x03, 0x04, 0x01, 0x07]),
        Ok(&[7_u8][..])
    );
    for faux in [
        &[0x04, 0x00][..],
        &[0x30, 0x02, 0xA2, 0x00],
        &[0x30, 0x02, 0x04, 0x05],
        &[0x30, 0x04, 0xA1, 0x02, 0x02, 0x00],
        &[0x30, 0x05, 0xA1, 0x03, 0x04, 0x01, 0x07, 0x00],
        &[0x30, 0x07, 0xA1, 0x03, 0x04, 0x01, 0x07, 0x05, 0x00],
        &[0x30, 0x07, 0xA1, 0x05, 0x04, 0x01, 0x07, 0x05, 0x00],
    ] {
        assert_eq!(nonce_de(faux), Err(Refusal::Malformed), "{faux:02x?}");
    }
    // Une racine qui n'est pas une clef lisible ne signe rien.
    assert!(crate::x509::cle_de_spki(b"pas une clef").is_err());
    assert!(crate::x509::cle_de_spki(&[0x30, 0x00, 0x00]).is_err());
    assert_eq!(
        Refusal::OtherEnvironment.describe(),
        "autre environnement App Attest"
    );
}
