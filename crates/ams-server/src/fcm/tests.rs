//! Ce que l'envoyeur FCM lit, signe, compose et comprend de Google.

use super::{
    CompteDeService, Envoi, assertion, lire_compte_de_service, lire_le_jeton, message, verdict,
};

/// Un compte de service d'ESSAI, au format que la console Firebase livre, avec
/// une clef RSA fabriquée par `openssl genpkey` pour lui. Elle ne sert nulle
/// part ailleurs.
const COMPTE: &str = include_str!("compte-essai.json");

fn compte() -> CompteDeService {
    lire_compte_de_service(COMPTE.as_bytes()).expect("un compte de service")
}

#[test]
fn un_compte_de_service_se_lit() {
    let lu = compte();
    assert_eq!(lu.projet, "narro-essai");
    assert_eq!(lu.email, "reveil@narro-essai.iam.gserviceaccount.com");
    assert_eq!(lu.adresse_du_jeton, "https://oauth2.googleapis.com/token");
}

/// Ce qui n'est pas un compte de service utilisable se refuse, et le dit —
/// sans jamais montrer la clef.
#[test]
fn un_compte_de_service_douteux_se_refuse() {
    let remplacer = |de: &str, par: &str| COMPTE.replacen(de, par, 1);
    let long = "x".repeat(20_000);
    for (fichier, attendu) in [
        (String::from("pas du json"), "illisible"),
        (long, "démesuré"),
        (
            remplacer("\"service_account\"", "\"authorized_user\""),
            "type",
        ),
        (remplacer("\"client_email\"", "\"autre\""), "client_email"),
        (
            remplacer("\"narro-essai\"", "\"narro/essai\""),
            "project_id",
        ),
        (
            remplacer("\"https://oauth2.googleapis.com/token\"", "\"http://x\""),
            "token_uri",
        ),
        (
            remplacer("\"private_key\"", "\"autre_clef\""),
            "private_key",
        ),
        (remplacer("BEGIN PRIVATE KEY", "BEGIN RIEN"), "private_key"),
        (
            remplacer(
                "\"type\": \"service_account\"",
                "\"type\": \"service\\u0020account\"",
            ),
            "type",
        ),
    ] {
        let Err(dit) = lire_compte_de_service(fichier.as_bytes()) else {
            panic!("accepté : {attendu}");
        };
        assert!(dit.contains(attendu), "{dit} — attendu « {attendu} »");
        assert!(!dit.contains("MII"), "la clef ne se montre jamais : {dit}");
    }
    // Une clef Ed25519 n'est pas une clef RSA.
    let ed25519 = r#"{"type":"service_account","project_id":"p","client_email":"e","token_uri":"https://t","private_key":"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END PRIVATE KEY-----\n"}"#;
    let Err(dit) = lire_compte_de_service(ed25519.as_bytes()) else {
        panic!("une clef Ed25519 acceptée");
    };
    assert!(dit.contains("RSA"), "{dit}");
}

/// **L'ASSERTION EST UN JWT RS256** : l'en-tête, les revendications que Google
/// attend, et la signature RSASSA-PKCS1-v1_5 — la même que la clef rend sans
/// aveuglement, puisque ce schéma est déterministe.
#[test]
fn l_assertion_se_signe() {
    let lu = compte();
    let jwt = assertion(&lu, 1_790_000_000).expect("une assertion");
    let morceaux: Vec<&str> = jwt.split('.').collect();
    assert_eq!(morceaux.len(), 3);
    let lire = |texte: &str| {
        let mut place = std::vec![0_u8; 1024];
        let lu = ams_api::decode_base64url(texte.as_bytes(), &mut place).expect("base64url");
        lu.to_vec()
    };
    assert_eq!(lire(morceaux[0]), br#"{"alg":"RS256","typ":"JWT"}"#);
    let revendications = String::from_utf8(lire(morceaux[1])).expect("UTF-8");
    assert_eq!(
        revendications,
        concat!(
            r#"{"iss":"reveil@narro-essai.iam.gserviceaccount.com","#,
            r#""scope":"https://www.googleapis.com/auth/firebase.messaging","#,
            r#""aud":"https://oauth2.googleapis.com/token","iat":1790000000,"exp":1790003600}"#
        )
    );
    let signe = std::format!("{}.{}", morceaux[0], morceaux[1]);
    let attendue = lu
        .cle
        .sign(&ams_sasl::sha256(signe.as_bytes()))
        .expect("signable");
    assert_eq!(lire(morceaux[2]), attendue);
}

/// Le jeton d'accès que Google rend, et ce qui n'en est pas un.
#[test]
fn le_jeton_d_acces_se_lit() {
    assert_eq!(
        lire_le_jeton(br#"{"access_token":"ya29.a0Af","expires_in":3599,"token_type":"Bearer"}"#),
        Some((String::from("ya29.a0Af"), 3599))
    );
    assert_eq!(
        lire_le_jeton(br#"{"access_token":"ya29"}"#),
        Some((String::from("ya29"), 3600))
    );
    for faux in [
        &br#"{"expires_in":3599}"#[..],
        br#"{"access_token":""}"#,
        br#"{"access_token":"a b"}"#,
        b"pas du json",
    ] {
        assert_eq!(lire_le_jeton(faux), None, "{faux:?}");
    }
}

/// Un message de DONNÉES : rien ne s'affiche, la boîte seule part.
#[test]
fn un_message_de_donnees_se_compose() {
    let push = ams_config::Push::new(
        ams_config::PushChannel::Fcm,
        String::from("dQw4:APA91b"),
        std::vec::Vec::new(),
        std::vec::Vec::new(),
        1,
    )
    .expect("recevable");
    assert_eq!(
        message(&push, "support"),
        r#"{"message":{"token":"dQw4:APA91b","data":{"account":"support"},"android":{"priority":"normal"}}}"#
    );
}

#[test]
fn la_reponse_de_google_se_lit() {
    for (statut, corps, envoi) in [
        (200, &b"{}"[..], Envoi::Transmis),
        (
            404,
            br#"{"error":{"details":[{"errorCode":"UNREGISTERED"}]}}"#,
            Envoi::Perime,
        ),
        (404, br#"{"error":{"status":"NOT_FOUND"}}"#, Envoi::Echec),
        (401, b"", Envoi::Echec),
        (429, b"", Envoi::Echec),
        (503, b"", Envoi::Echec),
    ] {
        assert_eq!(verdict(statut, corps), envoi, "{statut}");
    }
}

/// Le jeton gardé vaut jusqu'à une minute de sa fin.
#[tokio::test(flavor = "multi_thread")]
async fn le_jeton_garde_expire_avant_sa_fin() {
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
    let fcm = super::Fcm::new(transport, compte());
    assert_eq!(fcm.jeton_garde(1_000), None);
    *fcm.jeton.lock().expect("verrou") = Some((5_000, String::from("jeton")));
    assert_eq!(fcm.jeton_garde(4_939), Some(String::from("jeton")));
    assert_eq!(fcm.jeton_garde(4_940), None);
    // Sans réseau joignable, pas de jeton neuf : un échec, et pas une panique.
    assert_eq!(fcm.jeton_d_acces(4_940).await, None);
}
