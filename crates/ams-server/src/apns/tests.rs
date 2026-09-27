//! Ce que l'envoyeur APNs compose, et ce qu'il comprend d'Apple.

use super::{Apns, Envoi, Identite, composer, verdict};

fn identite(developpement: bool) -> Identite {
    Identite {
        cle: [9; 32],
        identifiant: String::from("ABC123DEFG"),
        equipe: String::from("DEF123GHIJ"),
        sujet: String::from("ch.narro.mail"),
        developpement,
    }
}

fn abonnement() -> ams_config::Push {
    ams_config::Push::new(
        ams_config::PushChannel::Apns,
        "ab".repeat(32),
        Vec::new(),
        Vec::new(),
        1,
    )
    .expect("recevable")
}

/// Une notification silencieuse, vers le bon environnement, qui ne dit que la
/// boîte.
#[test]
fn une_notification_silencieuse_se_compose() {
    let requete = composer(&identite(false), &abonnement(), "support", 1_790_000_000);
    assert_eq!(
        requete.url,
        std::format!("https://api.push.apple.com/3/device/{}", "ab".repeat(32))
    );
    assert_eq!(
        requete.corps,
        r#"{"aps":{"content-available":1},"account":"support"}"#
    );
    assert_eq!(requete.expiration, "1790003600");
    let requete = composer(&identite(true), &abonnement(), "support", 1);
    assert!(
        requete
            .url
            .starts_with("https://api.sandbox.push.apple.com/3/device/")
    );
}

/// Ce qu'Apple répond, et ce que l'abonnement en devient.
#[test]
fn la_reponse_d_apple_se_lit() {
    for (statut, corps, envoi) in [
        (200, &b""[..], Envoi::Transmis),
        (410, br#"{"reason":"Unregistered"}"#, Envoi::Perime),
        (400, br#"{"reason":"BadDeviceToken"}"#, Envoi::Perime),
        (
            400,
            br#"{"reason":"DeviceTokenNotForTopic"}"#,
            Envoi::Perime,
        ),
        (400, br#"{"reason":"PayloadTooLarge"}"#, Envoi::Echec),
        (403, br#"{"reason":"ExpiredProviderToken"}"#, Envoi::Echec),
        (429, br#"{"reason":"TooManyRequests"}"#, Envoi::Echec),
        (503, b"", Envoi::Echec),
    ] {
        assert_eq!(verdict(statut, corps), envoi, "{statut}");
    }
}

/// **LE JETON DE FOURNISSEUR SE GARDE TRENTE MINUTES**, puis se renouvelle ;
/// oublié, il se renouvelle au prochain envoi.
#[tokio::test(flavor = "multi_thread")]
async fn le_jeton_de_fournisseur_se_garde() {
    let resolveur = ams_loop_tokio::Resolver::new(
        std::vec!["127.0.0.1:9".parse().expect("une adresse")],
        std::time::Duration::from_millis(10),
    )
    .expect("un résolveur");
    let transport = ams_loop_tokio::PushTransport::new(
        resolveur,
        std::sync::Arc::new(rustls::RootCertStore::empty()),
        std::time::Duration::from_millis(10),
    );
    let apns = Apns::new(transport, identite(false));
    let premier = apns.jeton(1_000).expect("un jeton");
    assert!(premier.starts_with(b"bearer "));
    assert_eq!(apns.jeton(1_000 + 29 * 60), Some(premier.clone()));
    let second = apns.jeton(1_000 + 30 * 60).expect("un jeton");
    assert_ne!(second, premier);
    apns.oublier_le_jeton();
    assert_ne!(apns.jeton(1_000 + 30 * 60 + 1), Some(second));
    // Une clef qui ne signe pas ne donne pas de jeton.
    let mut fautive = identite(false);
    fautive.cle = [0; 32];
    let resolveur = ams_loop_tokio::Resolver::new(
        std::vec!["127.0.0.1:9".parse().expect("une adresse")],
        std::time::Duration::from_millis(10),
    )
    .expect("un résolveur");
    let transport = ams_loop_tokio::PushTransport::new(
        resolveur,
        std::sync::Arc::new(rustls::RootCertStore::empty()),
        std::time::Duration::from_millis(10),
    );
    assert_eq!(Apns::new(transport, fautive).jeton(1), None);
}

/// La raison d'un refus se lit, et rien d'autre ne passe au journal.
#[test]
fn la_raison_d_apple_se_lit() {
    assert_eq!(
        super::raison(br#"{"reason":"BadDeviceToken"}"#),
        "BadDeviceToken"
    );
    assert_eq!(super::raison(br#"{"reason":"<script>"}"#), "");
    assert_eq!(super::raison(br#"{"reason":""}"#), "");
    assert_eq!(super::raison(b""), "");
}
