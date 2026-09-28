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

/// Un juge sous la racine d'essai, avec une liste de révocation vide.
fn juge(mode: AndroidAttestation) -> Juge {
    let juge = Juge::new(
        mode,
        "org.airdesktop.mail",
        &[empreinte()],
        Some(&pem_de_la_racine()),
    )
    .expect("un réglage cohérent");
    assert_eq!(juge.liste().poser(std::vec::Vec::new()), 0);
    juge
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
    let _ = google_seul.liste().poser(std::vec::Vec::new());
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
        Refus::SansListe,
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

/// Le numéro de série du certificat de rang `rang` d'une chaîne — lu à la main :
/// `Certificate ::= SEQUENCE { TBSCertificate ::= SEQUENCE { [0] version,
/// serialNumber INTEGER, … } … }`.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "des positions dans une chaîne d'essai de quelques kilo-octets"
)]
fn serie(chaine: &[u8], rang: usize) -> u128 {
    fn tlv(octets: &[u8]) -> (usize, usize) {
        match octets[1] {
            n if n < 0x80 => (2, usize::from(n)),
            0x81 => (3, usize::from(octets[2])),
            _ => (4, usize::from(u16::from_be_bytes([octets[2], octets[3]]))),
        }
    }
    let mut debut = 0;
    for _ in 0..rang {
        let (entete, longueur) = tlv(&chaine[debut..]);
        debut += entete + longueur;
    }
    let certificat = &chaine[debut..];
    let tbs = &certificat[tlv(certificat).0..];
    let dans = &tbs[tlv(tbs).0..];
    let version = tlv(dans);
    let entier = &dans[version.0 + version.1..];
    let (entete, longueur) = tlv(entier);
    entier[entete..entete + longueur]
        .iter()
        .fold(0_u128, |acc, octet| (acc << 8) | u128::from(*octet))
}

/// **SANS LISTE, RIEN NE PASSE ; AVEC ELLE, UNE CLEF RÉVOQUÉE NON PLUS** (0.2.40).
#[test]
fn la_liste_de_revocation_decide() {
    let chaine = encode(vecteur!("tee.der"));
    let sans = Juge::new(
        AndroidAttestation::Verify,
        "org.airdesktop.mail",
        &[empreinte()],
        Some(&pem_de_la_racine()),
    )
    .expect("cohérent");
    assert!(sans.liste().courante().is_none());
    assert_eq!(
        sans.juger(&appareil(), INVITATION, Some(&chaine), MAINTENANT),
        Err(Refus::SansListe)
    );
    // Sans attestation, en `verify`, la liste ne compte pas.
    assert_eq!(
        sans.juger(&appareil(), INVITATION, None, MAINTENANT),
        Ok(None)
    );

    let intermediaire = serie(vecteur!("tee.der"), 1);
    assert_eq!(
        sans.liste().poser(std::vec![intermediaire, 7, 7, 3]),
        3,
        "triée, sans doublon"
    );
    assert_eq!(
        sans.juger(&appareil(), INVITATION, Some(&chaine), MAINTENANT),
        Err(Refus::Refusee(ams_attest::Refusal::Revoked))
    );
    // Une liste neuve la remplace entière.
    assert_eq!(sans.liste().poser(std::vec![7]), 1);
    assert_eq!(
        sans.juger(&appareil(), INVITATION, Some(&chaine), MAINTENANT),
        Ok(Some(Attested::Tee))
    );
    assert!(!std::format!("{:?}", sans.liste()).is_empty());
}

/// **LA VRAIE LISTE DE GOOGLE SE LIT**, et une liste mal formée se refuse.
#[test]
fn une_liste_se_lit_ou_se_refuse() {
    let lue = super::lire_la_liste(include_bytes!(
        "../../../ams-attest/src/vecteurs/google/status-2026-09-28.json"
    ))
    .expect("lisible");
    assert_eq!(lue.len(), 1757);
    assert_eq!(
        super::lire_la_liste(b"{\"entries\":["),
        Err(ams_attest::Refusal::Malformed)
    );
}
