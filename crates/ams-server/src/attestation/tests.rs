// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::{Juge, Refus, clefs_publiques};
use ams_config::{AttestationMode, Attested};

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
/// Le même instant, comme la liste le date.
const MAINTENANT_U64: u64 = 1_790_553_600;

fn appareil() -> [u8; 65] {
    <[u8; 65]>::try_from(&vecteur!("appareil.sec1")[..]).expect("soixante-cinq octets")
}

fn empreinte() -> [u8; 32] {
    <[u8; 32]>::try_from(&vecteur!("empreinte.bin")[..]).expect("trente-deux octets")
}

macro_rules! vecteur_apple {
    ($nom:literal) => {
        include_bytes!(concat!(
            "../../../ams-attest/src/vecteurs/apple/synthese/",
            $nom
        ))
    };
}

/// La racine d'essai, écrite comme un fichier PEM de clefs publiques.
fn pem_de_la_racine() -> std::vec::Vec<u8> {
    pem_de(vecteur!("racine.spki"))
}

/// Une clef publique `SubjectPublicKeyInfo`, écrite en PEM.
fn pem_de(der: &[u8]) -> std::vec::Vec<u8> {
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
fn juge(mode: AttestationMode) -> Juge {
    let juge = Juge::new(
        mode,
        "org.airdesktop.mail",
        &[empreinte()],
        Some(&pem_de_la_racine()),
        7,
    )
    .expect("un réglage cohérent");
    assert_eq!(juge.liste().poser(std::vec::Vec::new(), MAINTENANT_U64), 0);
    juge
}

fn encode(chaine: &[u8]) -> std::string::String {
    let mut url = std::vec![0_u8; chaine.len().saturating_mul(2)];
    let n = ams_push::encode_base64url(chaine, &mut url).expect("encodable");
    std::string::String::from_utf8(url[..n].to_vec()).expect("ascii")
}

#[test]
fn une_attestation_en_regle_dit_ou_vit_la_clef() {
    for mode in [AttestationMode::Verify, AttestationMode::Require] {
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
    assert_eq!(eteint.mode(), AttestationMode::Off);
    assert_eq!(
        eteint.juger(&appareil(), INVITATION, Some("§§"), MAINTENANT),
        Ok(None)
    );
    assert_eq!(
        juge(AttestationMode::Off).juger(&appareil(), INVITATION, Some(&tee), MAINTENANT),
        Ok(None),
        "éteinte, même une attestation en règle n'est pas lue"
    );
    assert_eq!(
        juge(AttestationMode::Verify).juger(&appareil(), INVITATION, None, MAINTENANT),
        Ok(None)
    );
    assert_eq!(
        juge(AttestationMode::Require).juger(&appareil(), INVITATION, None, MAINTENANT),
        Err(Refus::Absente)
    );
}

#[test]
fn une_attestation_illisible_ou_refusee_se_refuse() {
    let juge = juge(AttestationMode::Verify);
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
        AttestationMode::Verify,
        "org.airdesktop.mail",
        &[empreinte()],
        None,
        7,
    )
    .expect("cohérent");
    assert_eq!(google_seul.racines(), 2);
    let _ = google_seul
        .liste()
        .poser(std::vec::Vec::new(), MAINTENANT_U64);
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
    assert!(Juge::new(AttestationMode::Verify, "", &[empreinte()], None, 7).is_err());
    assert!(Juge::new(AttestationMode::Require, "org.a.b", &[], None, 7).is_err());
    assert!(Juge::new(AttestationMode::Off, "", &[], None, 7).is_ok());
    let vide = Juge::new(
        AttestationMode::Verify,
        "org.a.b",
        &[empreinte()],
        Some(b"-----BEGIN PUBLIC KEY-----\n!!!\n-----END PUBLIC KEY-----\n"),
        7,
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
        AttestationMode::Verify,
        "org.airdesktop.mail",
        &[empreinte()],
        Some(&pem_de_la_racine()),
        7,
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
        sans.liste()
            .poser(std::vec![intermediaire, 7, 7, 3], MAINTENANT_U64),
        3,
        "triée, sans doublon"
    );
    assert_eq!(
        sans.juger(&appareil(), INVITATION, Some(&chaine), MAINTENANT),
        Err(Refus::Refusee(ams_attest::Refusal::Revoked))
    );
    // Une liste neuve la remplace entière.
    assert_eq!(sans.liste().poser(std::vec![7], MAINTENANT_U64), 1);
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

/// **UNE LISTE TROP VIEILLE NE SE CROIT PLUS** (0.2.42) : sept jours, et une
/// seconde de plus refuse — comme sans liste.
#[test]
fn une_liste_trop_vieille_ne_se_croit_plus() {
    let juge = juge(AttestationMode::Verify);
    let chaine = encode(vecteur!("tee.der"));
    let sept_jours: u64 = 604_800;
    let _ = juge.liste().poser(
        std::vec::Vec::new(),
        MAINTENANT_U64.saturating_sub(sept_jours),
    );
    assert_eq!(
        juge.juger(&appareil(), INVITATION, Some(&chaine), MAINTENANT),
        Ok(Some(Attested::Tee)),
        "sept jours tout juste passent encore"
    );
    let _ = juge.liste().poser(
        std::vec::Vec::new(),
        MAINTENANT_U64.saturating_sub(sept_jours.saturating_add(1)),
    );
    assert_eq!(
        juge.juger(&appareil(), INVITATION, Some(&chaine), MAINTENANT),
        Err(Refus::ListePerimee)
    );
    // Une date à venir — une horloge déréglée — ne vieillit pas la liste.
    let _ = juge
        .liste()
        .poser(std::vec::Vec::new(), MAINTENANT_U64.saturating_add(3_600));
    assert!(
        juge.juger(&appareil(), INVITATION, Some(&chaine), MAINTENANT)
            .is_ok()
    );
    assert!(!Refus::ListePerimee.dire().is_empty());
    let courante = juge.liste().courante().expect("posée");
    assert_eq!(courante.date, MAINTENANT_U64.saturating_add(3_600));
}

/// Un juge d'App Attest sous les racines d'essai des DEUX plateformes, Android
/// dans ce mode.
fn juge_apple(android: AttestationMode, apple: AttestationMode, developpement: bool) -> Juge {
    let pem = [pem_de_la_racine(), pem_de(vecteur_apple!("racine.spki"))].concat();
    let juge = Juge::new(
        android,
        "org.airdesktop.mail",
        &[empreinte()],
        Some(&pem),
        7,
    )
    .expect("un réglage cohérent")
    .avec_apple(apple, "TEAM123456.org.airdesktop.mail", developpement)
    .expect("un réglage cohérent");
    assert_eq!(juge.liste().poser(std::vec::Vec::new(), MAINTENANT_U64), 0);
    juge
}

/// **LE `clientDataHash` LIE L'INVITATION ET LA CLEF D'APPAREIL** (0.2.43) :
/// celui que les vecteurs ont attesté est celui que le serveur recalcule.
#[test]
fn les_donnees_client_lient_l_invitation_et_la_clef() {
    assert_eq!(
        super::donnees_client(INVITATION, &appareil()).as_slice(),
        vecteur_apple!("client.bin").as_slice()
    );
}

#[test]
fn une_attestation_app_attest_en_regle_enrole() {
    for apple in [AttestationMode::Verify, AttestationMode::Require] {
        let juge = juge_apple(AttestationMode::Off, apple, false);
        assert_eq!(juge.mode_apple(), apple);
        assert_eq!(
            juge.racines_apple(),
            3,
            "Apple, et les deux racines d'essai"
        );
        assert_eq!(
            juge.juger(
                &appareil(),
                INVITATION,
                Some(&encode(vecteur_apple!("bon.cbor"))),
                MAINTENANT
            ),
            Ok(Some(Attested::AppAttest))
        );
    }
    // L'environnement de développement, et lui seul, quand il est demandé.
    let developpement = encode(vecteur_apple!("developpement.cbor"));
    assert_eq!(
        juge_apple(AttestationMode::Off, AttestationMode::Verify, true).juger(
            &appareil(),
            INVITATION,
            Some(&developpement),
            MAINTENANT
        ),
        Ok(Some(Attested::AppAttest))
    );
    assert_eq!(
        juge_apple(AttestationMode::Off, AttestationMode::Verify, false).juger(
            &appareil(),
            INVITATION,
            Some(&developpement),
            MAINTENANT
        ),
        Err(Refus::Refusee(ams_attest::Refusal::OtherEnvironment))
    );
}

/// **L'ATTESTATION NE VAUT QUE POUR SON INVITATION ET SA CLEF D'APPAREIL.**
#[test]
fn une_attestation_app_attest_d_ailleurs_se_refuse() {
    let juge = juge_apple(AttestationMode::Off, AttestationMode::Require, false);
    let bon = encode(vecteur_apple!("bon.cbor"));
    assert_eq!(
        juge.juger(&appareil(), "une autre invitation", Some(&bon), MAINTENANT),
        Err(Refus::Refusee(ams_attest::Refusal::OtherChallenge))
    );
    let mut autre_clef = appareil();
    autre_clef[64] ^= 1;
    assert_eq!(
        juge.juger(&autre_clef, INVITATION, Some(&bon), MAINTENANT),
        Err(Refus::Refusee(ams_attest::Refusal::OtherChallenge))
    );
    // Sans la racine d'essai, l'objet ne remonte à rien.
    let apple_seul = Juge::new(AttestationMode::Off, "", &[], None, 7)
        .expect("cohérent")
        .avec_apple(
            AttestationMode::Verify,
            "TEAM123456.org.airdesktop.mail",
            false,
        )
        .expect("cohérent");
    assert_eq!(apple_seul.racines_apple(), 1);
    assert_eq!(
        apple_seul.juger(&appareil(), INVITATION, Some(&bon), MAINTENANT),
        Err(Refus::Refusee(ams_attest::Refusal::UnknownRoot))
    );
    assert!(
        Juge::eteint()
            .avec_apple(AttestationMode::Verify, "", false)
            .is_err(),
        "juger sans identifiant laisserait passer n'importe quelle application"
    );
}

/// **LA PLATEFORME SE RECONNAÎT AU PREMIER OCTET**, et celle que le serveur ne
/// juge pas ne prouve rien — ce qui ne compte que si l'un des modes exige une
/// attestation.
#[test]
fn une_plateforme_non_jugee_ne_prouve_rien() {
    let bon = encode(vecteur_apple!("bon.cbor"));
    let tee = encode(vecteur!("tee.der"));
    assert_eq!(
        juge_apple(AttestationMode::Require, AttestationMode::Off, false).juger(
            &appareil(),
            INVITATION,
            Some(&bon),
            MAINTENANT
        ),
        Err(Refus::NonJugee)
    );
    assert_eq!(
        juge_apple(AttestationMode::Verify, AttestationMode::Off, false).juger(
            &appareil(),
            INVITATION,
            Some(&bon),
            MAINTENANT
        ),
        Ok(None)
    );
    assert_eq!(
        juge_apple(AttestationMode::Off, AttestationMode::Require, false).juger(
            &appareil(),
            INVITATION,
            Some(&tee),
            MAINTENANT
        ),
        Err(Refus::NonJugee)
    );
    assert_eq!(
        juge_apple(AttestationMode::Off, AttestationMode::Verify, false).juger(
            &appareil(),
            INVITATION,
            Some(&tee),
            MAINTENANT
        ),
        Ok(None)
    );
    // Les deux jugées : chacune va à son vérificateur.
    let deux = juge_apple(AttestationMode::Verify, AttestationMode::Verify, false);
    assert_eq!(
        deux.juger(&appareil(), INVITATION, Some(&tee), MAINTENANT),
        Ok(Some(Attested::Tee))
    );
    assert_eq!(
        deux.juger(&appareil(), INVITATION, Some(&bon), MAINTENANT),
        Ok(Some(Attested::AppAttest))
    );
    // Ni DER ni table CBOR : rien ne se lit.
    for illisible in [&b""[..], &[0x01, 0x02], &[0x80]] {
        assert_eq!(
            deux.juger(
                &appareil(),
                INVITATION,
                Some(&encode(illisible)),
                MAINTENANT
            ),
            Err(Refus::Illisible)
        );
    }
    // L'absence, sous App Attest seule : `require` refuse, `verify` laisse
    // passer.
    assert_eq!(
        juge_apple(AttestationMode::Off, AttestationMode::Require, false).juger(
            &appareil(),
            INVITATION,
            None,
            MAINTENANT
        ),
        Err(Refus::Absente)
    );
    assert_eq!(
        juge_apple(AttestationMode::Off, AttestationMode::Verify, false).juger(
            &appareil(),
            INVITATION,
            None,
            MAINTENANT
        ),
        Ok(None)
    );
    assert!(!Refus::NonJugee.dire().is_empty());
}
