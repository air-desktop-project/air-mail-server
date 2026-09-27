//! Ce qu'un abonnement admet, et ce qu'il refuse.

use alloc::string::String;
use alloc::vec::Vec;

use super::{Push, PushChannel, PushFault, endpoint_is_acceptable};

/// Une clef publique P-256 valable : le point générateur, non compressé.
fn clef() -> Vec<u8> {
    let mut octets = alloc::vec![0x04];
    octets.extend_from_slice(&[
        0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40,
        0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98,
        0xC2, 0x96,
    ]);
    octets.extend_from_slice(&[
        0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E,
        0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF,
        0x51, 0xF5,
    ]);
    octets
}

fn essai(canal: PushChannel, jeton: &str, cle: Vec<u8>, auth: Vec<u8>) -> Result<Push, PushFault> {
    Push::new(canal, String::from(jeton), cle, auth, 1_790_000_000)
}

#[test]
fn les_noms_des_canaux_font_l_aller_retour() {
    for canal in [PushChannel::Apns, PushChannel::Fcm, PushChannel::WebPush] {
        assert_eq!(PushChannel::from_name(canal.name()), Some(canal));
    }
    assert_eq!(PushChannel::from_name("sms"), None);
}

#[test]
fn un_jeton_apns_est_de_l_hexadecimal() {
    let bon = "a1".repeat(32);
    let lu = essai(PushChannel::Apns, &bon, Vec::new(), Vec::new()).expect("recevable");
    assert_eq!(
        (lu.channel(), lu.token(), lu.since()),
        (PushChannel::Apns, bon.as_str(), 1_790_000_000)
    );
    assert!(lu.key().is_empty() && lu.auth().is_empty());
    for mauvais in ["a1".repeat(31), "zz".repeat(32), "a".repeat(201)] {
        assert_eq!(
            essai(PushChannel::Apns, &mauvais, Vec::new(), Vec::new()),
            Err(PushFault::BadToken)
        );
    }
    // Une clef pour un canal qui n'en prend pas.
    assert_eq!(
        essai(PushChannel::Apns, &bon, clef(), Vec::new()),
        Err(PushFault::Unexpected)
    );
    assert_eq!(
        essai(PushChannel::Fcm, "abc", Vec::new(), alloc::vec![0; 16]),
        Err(PushFault::Unexpected)
    );
}

#[test]
fn un_jeton_fcm_a_ses_caracteres() {
    assert!(
        essai(
            PushChannel::Fcm,
            "dQw4w9WgXcQ:APA91b_x-y",
            Vec::new(),
            Vec::new()
        )
        .is_ok()
    );
    for mauvais in [String::new(), String::from("a b"), "x".repeat(4097)] {
        assert_eq!(
            essai(PushChannel::Fcm, &mauvais, Vec::new(), Vec::new()),
            Err(PushFault::BadToken)
        );
    }
}

#[test]
fn un_abonnement_web_push_porte_sa_clef_et_son_secret() {
    let url = "https://updates.push.services.mozilla.com/wpush/v2/gAAAA";
    let lu = essai(PushChannel::WebPush, url, clef(), alloc::vec![7; 16]).expect("recevable");
    assert_eq!((lu.key().len(), lu.auth().len()), (65, 16));
    // Une clef qui n'est pas un point, ou pas de la bonne longueur.
    let mut hors_courbe = clef();
    hors_courbe[64] ^= 1;
    for mauvaise in [hors_courbe, alloc::vec![4; 64]] {
        assert_eq!(
            essai(PushChannel::WebPush, url, mauvaise, alloc::vec![7; 16]),
            Err(PushFault::BadKey)
        );
    }
    assert_eq!(
        essai(PushChannel::WebPush, url, clef(), alloc::vec![7; 15]),
        Err(PushFault::BadAuth)
    );
    assert_eq!(
        essai(
            PushChannel::WebPush,
            "http://x.test/a",
            clef(),
            alloc::vec![7; 16]
        ),
        Err(PushFault::BadEndpoint)
    );
}

/// **LE SERVEUR NE POSTERA PAS VERS L'INTÉRIEUR** : seule une URL `https`,
/// port 443, vers un nom public passe.
#[test]
fn une_url_web_push_ne_designe_qu_un_nom_public() {
    for bonne in [
        "https://fcm.googleapis.com/fcm/send/abc",
        "https://web.push.apple.com:443/QGu",
        "https://Push.Example.COM/x?y=z",
    ] {
        assert!(endpoint_is_acceptable(bonne), "{bonne}");
    }
    let longue = alloc::format!("https://a.test/{}", "x".repeat(2048));
    for mauvaise in [
        "http://push.example.com/x",
        "https://10.0.0.1/x",
        "https://127.0.0.1:443/x",
        "https://[::1]/x",
        "https://localhost/x",
        "https://imprimante.local/x",
        "https://nas.home.arpa/x",
        "https://srv.internal/x",
        "https://box.lan/x",
        "https://x.localhost/x",
        "https://push.example.com:8443/x",
        "https://user@push.example.com/x",
        "https://push.example.com",
        "https://push.example.com/a b",
        "https://sanspoint/x",
        "https://-mauvais.example.com/x",
        "https://mauvais-.example.com/x",
        "https://a..b.com/x",
        "https://push.example.com:/x",
        longue.as_str(),
    ] {
        assert!(!endpoint_is_acceptable(mauvaise), "{mauvaise}");
    }
}
