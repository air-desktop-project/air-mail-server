// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! L'écoute HTTP/2, éprouvée de bout en bout : TLS, ALPN, cadres, réponses.
//!
//! # CE QUE CET ESSAI VÉRIFIE VRAIMENT, ET CE QU'IL NE PEUT PAS
//!
//! Le client est écrit ici, à la main, et il **n'emploie pas notre encodeur
//! HPACK** : les en-têtes de requête partent en représentations littérales sans
//! indexation, que §6.2.2 de RFC 7541 impose à tout décodeur d'accepter. C'est
//! donc bien notre décodeur qui est mis à l'épreuve, par des octets qu'il n'a pas
//! produits.
//!
//! **L'autoréférence qui demeure est du côté des réponses** : pour lire un code
//! d'état, il faudrait décoder du HPACK, et le seul décodeur à portée est le
//! nôtre. Cet essai contourne le problème plutôt que de le masquer — il vérifie
//! les CORPS, qui ne sont pas comprimés, et nos documents d'erreur portent leur
//! code d'état à l'intérieur.
//!
//! Ce qui reste hors de portée d'ici : qu'un vrai client tiers nous lise. Cela
//! demande un vrai client tiers, comme `starttls.rs` emploie un vrai OpenSSL.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use ams_api::{Area, Rights, Scope};
use ams_loop_tokio::http::{Api, Served};
use ams_proto_http::{Method, StatusCode};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// Le préambule de §3.4 de RFC 9113.
const PREAMBULE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Ce que l'API d'essai sait servir.
struct ApiEssai;

impl Api for ApiEssai {
    fn serve<'o>(
        &self,
        resource: ams_api::Resource<'_>,
        _method: Method,
        account: &str,
        _body: &[u8],
        _range: Option<&[u8]>,
        sortie: &'o mut [u8],
    ) -> Served<'o> {
        let mut json = ams_api::Json::new(sortie);
        let ecrit = (|| {
            json.begin_object()?;
            json.field_str("compte", account)?;
            json.field_str(
                "ressource",
                match resource {
                    ams_api::Resource::Health => "health",
                    ams_api::Resource::Mailboxes => "mailboxes",
                    _ => "autre",
                },
            )?;
            json.end_object()?;
            json.finish()
        })();
        Served {
            status: StatusCode::OK,
            media: ams_api::JSON_MEDIA_TYPE,
            body: ecrit.unwrap_or_default(),
            ..Served::default()
        }
    }

    fn authenticate(&self, login: &str, password: &[u8]) -> Option<Scope> {
        (login == "marc" && password == b"secret")
            .then(|| Scope::one(Area::Mail, Rights::Read).with(Area::Observe, Rights::Read))
    }

    fn nonce(&self) -> u64 {
        7
    }
}

/// Fabrique un certificat auto-signé, en PEM.
fn certificat_pem(repertoire: &Path) -> Option<(Vec<u8>, Vec<u8>)> {
    let cle = repertoire.join("cle.pem");
    let cert = repertoire.join("cert.pem");
    let genere = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "ec"])
        .args(["-pkeyopt", "ec_paramgen_curve:P-256"])
        .args(["-nodes", "-days", "1", "-subj", "/CN=localhost"])
        .arg("-keyout")
        .arg(&cle)
        .arg("-out")
        .arg(&cert)
        .output()
        .ok()?;
    genere
        .status
        .success()
        .then(|| Some((std::fs::read(&cert).ok()?, std::fs::read(&cle).ok()?)))
        .flatten()
}

/// Écrit un champ en représentation littérale **sans indexation**.
///
/// §6.2.2 de RFC 7541 : le premier octet vaut `0000xxxx`, l'index du nom est nul
/// — donc le nom suit en clair —, puis le nom et la valeur, chacun précédé de sa
/// longueur sur sept bits sans compression Huffman.
///
/// **C'est la forme la plus simple que la RFC définit**, et tout décodeur doit
/// l'accepter. L'employer ici plutôt que notre encodeur est ce qui donne son sens
/// à l'essai : les octets ne viennent pas de nous.
fn champ(nom: &[u8], valeur: &[u8], out: &mut Vec<u8>) {
    out.push(0x00);
    out.push(u8::try_from(nom.len()).expect("un nom court"));
    out.extend_from_slice(nom);
    out.push(u8::try_from(valeur.len()).expect("une valeur courte"));
    out.extend_from_slice(valeur);
}

/// L'en-tête d'un cadre : longueur, type, drapeaux, flux.
fn entete(longueur: usize, sorte: u8, drapeaux: u8, flux: u32) -> Vec<u8> {
    let n = u32::try_from(longueur).expect("un cadre court");
    let mut tete = Vec::with_capacity(9);
    tete.extend_from_slice(&n.to_be_bytes()[1..4]);
    tete.push(sorte);
    tete.push(drapeaux);
    tete.extend_from_slice(&flux.to_be_bytes());
    tete
}

/// Les octets d'une requête : `HEADERS`, et `DATA` s'il y a un corps.
fn requete(flux: u32, methode: &[u8], chemin: &[u8], jeton: Option<&str>, corps: &[u8]) -> Vec<u8> {
    let mut bloc = Vec::new();
    champ(b":method", methode, &mut bloc);
    champ(b":scheme", b"https", &mut bloc);
    champ(b":authority", b"localhost", &mut bloc);
    champ(b":path", chemin, &mut bloc);
    if let Some(porte) = jeton {
        let mut valeur = String::from("Bearer ");
        valeur.push_str(porte);
        champ(b"authorization", valeur.as_bytes(), &mut bloc);
    }
    if !corps.is_empty() {
        champ(b"content-type", b"application/json", &mut bloc);
    }

    // `END_HEADERS` vaut 0x04 ; `END_STREAM` vaut 0x01.
    let drapeaux = match corps.is_empty() {
        true => 0x05,
        false => 0x04,
    };
    let mut octets = entete(bloc.len(), 0x01, drapeaux, flux);
    octets.extend_from_slice(&bloc);
    if !corps.is_empty() {
        octets.extend_from_slice(&entete(corps.len(), 0x00, 0x01, flux));
        octets.extend_from_slice(corps);
    }
    octets
}

/// Lit des cadres jusqu'à en avoir un `DATA`, et rend sa charge.
///
/// Rend `None` si la connexion se ferme d'abord.
async fn attendre_un_corps<S>(flux: &mut S) -> Option<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut tampon = Vec::new();
    let mut morceau = [0_u8; 4096];
    loop {
        // On analyse ce qu'on a avant d'en redemander.
        let mut rang = 0_usize;
        while let Some(tete) = tampon.get(rang..rang.saturating_add(9)) {
            let longueur = usize::from(tete[0])
                .saturating_mul(65_536)
                .saturating_add(usize::from(tete[1]).saturating_mul(256))
                .saturating_add(usize::from(tete[2]));
            let sorte = tete[3];
            let charge = rang.saturating_add(9);
            let fin = charge.saturating_add(longueur);
            if tampon.len() < fin {
                break;
            }
            if sorte == 0x00 {
                return tampon.get(charge..fin).map(<[u8]>::to_vec);
            }
            rang = fin;
        }
        let lus = flux.read(&mut morceau).await.ok()?;
        if lus == 0 {
            return None;
        }
        tampon.extend_from_slice(morceau.get(..lus)?);
    }
}

/// Un client TLS qui annonce `h2`.
fn client_tls(annonce: &[&[u8]]) -> Arc<rustls::ClientConfig> {
    /// Ce vérificateur accepte tout : l'essai éprouve NOTRE côté, et le
    /// certificat est auto-signé, fabriqué il y a une seconde.
    #[derive(Debug)]
    struct ToutAccepter;

    impl rustls::client::danger::ServerCertVerifier for ToutAccepter {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Err(rustls::Error::General("TLS 1.2 n'est pas servi".into()))
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            ams_tls::provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(ams_tls::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ToutAccepter))
        .with_no_client_auth();
    config.alpn_protocols = annonce.iter().map(|dit| dit.to_vec()).collect();
    Arc::new(config)
}

/// Monte une écoute, et rend son adresse plus de quoi l'arrêter.
async fn ecoute(
    cert: &[u8],
    cle: &[u8],
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    ecoute_avec(cert, cle, ams_guard::Thresholds::default()).await
}

/// La même, avec des seuils choisis : c'est ce qui permet d'éprouver le videur
/// sans envoyer des dizaines de connexions.
async fn ecoute_avec(
    cert: &[u8],
    cle: &[u8],
    seuils: ams_guard::Thresholds,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let tls = Arc::new(
        ams_loop_tokio::http::http_server_config(cert, cle).expect("configuration assemblée"),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("un port libre");
    let adresse = listener.local_addr().expect("une adresse");
    let (arret, attente) = tokio::sync::oneshot::channel();
    let session = ams_session::http::Http::new(
        ams_api::Key::new(b"une clef de trente-deux octets!!").expect("trente-deux octets"),
        3_600 * 1_000_000,
    )
    .expect("une durée licite");
    let guard = Arc::new(ams_loop_tokio::SharedGuard::new(64, seuils));
    let tache = tokio::spawn(async move {
        let _ = ams_loop_tokio::http::serve_http(
            listener,
            ams_proto_http::Limits::DEFAULT,
            Arc::new(ApiEssai),
            guard,
            session,
            tls,
            ams_loop_tokio::ServeOptions::default(),
            async {
                let _ = attente.await;
            },
        )
        .await;
    });
    (adresse, arret, tache)
}

/// **UNE REQUÊTE TRAVERSE TOUT** : TLS, ALPN, préambule, cadres, session,
/// autorisation, rendu.
#[tokio::test]
async fn une_requete_traverse_toute_la_chaine() {
    let repertoire = std::env::temp_dir().join(format!("ams-http-{}", std::process::id()));
    std::fs::create_dir_all(&repertoire).expect("répertoire temporaire");
    let Some((cert, cle)) = certificat_pem(&repertoire) else {
        let _ = std::fs::remove_dir_all(&repertoire);
        eprintln!("SAUTÉ : `openssl` n'a pas su fabriquer de certificat.");
        return;
    };
    let (adresse, arret, tache) = ecoute(&cert, &cle).await;

    let connecteur = tokio_rustls::TlsConnector::from(client_tls(&[b"h2"]));
    let brut = tokio::net::TcpStream::connect(adresse)
        .await
        .expect("connexion");
    let nom = rustls::pki_types::ServerName::try_from("localhost").expect("un nom");
    let mut flux = connecteur
        .connect(nom, brut)
        .await
        .expect("poignée de main");

    // Le préambule, puis nos réglages (vides), puis la requête.
    let mut sortie = Vec::from(PREAMBULE);
    sortie.extend_from_slice(&entete(0, 0x04, 0x00, 0));
    sortie.extend_from_slice(&requete(
        1,
        b"POST",
        b"/v1/tokens",
        None,
        br#"{"login":"marc","password":"secret"}"#,
    ));
    flux.write_all(&sortie).await.expect("écriture");

    let corps = attendre_un_corps(&mut flux).await.expect("une réponse");
    let texte = String::from_utf8(corps).expect("de l'UTF-8");
    assert!(
        texte.starts_with(r#"{"token":""#),
        "l'échange d'identifiants doit rendre un jeton : {texte}"
    );

    // Le jeton rendu ouvre bien ce qu'on lui a donné.
    let debut = texte.find(':').expect("un premier champ").saturating_add(2);
    let fin = texte
        .get(debut..)
        .and_then(|reste| reste.find('"'))
        .expect("une fin de chaîne")
        .saturating_add(debut);
    let jeton = texte[debut..fin].to_string();

    let suite = requete(3, b"GET", b"/v1/health", Some(&jeton), &[]);
    flux.write_all(&suite).await.expect("écriture");
    let corps = attendre_un_corps(&mut flux).await.expect("une réponse");
    let texte = String::from_utf8(corps).expect("de l'UTF-8");
    assert_eq!(
        texte, r#"{"compte":"marc","ressource":"health"}"#,
        "la ressource doit être servie pour le compte du jeton"
    );

    let _ = arret.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&repertoire);
}

/// **SANS JETON, RIEN** — et le document d'erreur porte son propre code d'état,
/// ce qui permet de le vérifier sans décoder de HPACK.
#[tokio::test]
async fn sans_jeton_la_ressource_ne_se_sert_pas() {
    let repertoire = std::env::temp_dir().join(format!("ams-http-nu-{}", std::process::id()));
    std::fs::create_dir_all(&repertoire).expect("répertoire temporaire");
    let Some((cert, cle)) = certificat_pem(&repertoire) else {
        let _ = std::fs::remove_dir_all(&repertoire);
        eprintln!("SAUTÉ : `openssl` n'a pas su fabriquer de certificat.");
        return;
    };
    let (adresse, arret, tache) = ecoute(&cert, &cle).await;

    let connecteur = tokio_rustls::TlsConnector::from(client_tls(&[b"h2"]));
    let brut = tokio::net::TcpStream::connect(adresse)
        .await
        .expect("connexion");
    let nom = rustls::pki_types::ServerName::try_from("localhost").expect("un nom");
    let mut flux = connecteur
        .connect(nom, brut)
        .await
        .expect("poignée de main");

    let mut sortie = Vec::from(PREAMBULE);
    sortie.extend_from_slice(&entete(0, 0x04, 0x00, 0));
    sortie.extend_from_slice(&requete(1, b"GET", b"/v1/mailboxes", None, &[]));
    flux.write_all(&sortie).await.expect("écriture");

    let corps = attendre_un_corps(&mut flux).await.expect("une réponse");
    let texte = String::from_utf8(corps).expect("de l'UTF-8");
    assert!(texte.contains(r#""status":401"#), "{texte}");
    assert!(texte.contains("/problems/unauthorized"), "{texte}");
    assert!(!texte.contains("mailboxes"), "la réponse redit la requête");

    let _ = arret.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&repertoire);
}

/// **UN CLIENT QUI N'OFFRE PAS `h2` N'EST PAS SERVI**, et le refus tombe pendant
/// la poignée de main — pas après.
#[tokio::test]
async fn un_client_sans_h2_ne_passe_pas_la_poignee_de_main() {
    let repertoire = std::env::temp_dir().join(format!("ams-http-alpn-{}", std::process::id()));
    std::fs::create_dir_all(&repertoire).expect("répertoire temporaire");
    let Some((cert, cle)) = certificat_pem(&repertoire) else {
        let _ = std::fs::remove_dir_all(&repertoire);
        eprintln!("SAUTÉ : `openssl` n'a pas su fabriquer de certificat.");
        return;
    };
    let (adresse, arret, tache) = ecoute(&cert, &cle).await;

    let connecteur = tokio_rustls::TlsConnector::from(client_tls(&[b"http/1.1"]));
    let brut = tokio::net::TcpStream::connect(adresse)
        .await
        .expect("connexion");
    let nom = rustls::pki_types::ServerName::try_from("localhost").expect("un nom");
    let issue = connecteur.connect(nom, brut).await;
    assert!(
        issue.is_err(),
        "un client qui n'offre que `http/1.1` doit voir sa poignée de main échouer"
    );

    let _ = arret.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&repertoire);
}

/// **UN PRÉAMBULE QUI N'EN EST PAS UN COMPTE POUR LE VIDEUR** (C8).
///
/// C'était la seule faute du pair que cette écoute ne comptait pas — l'ALPN, les
/// cadres malformés, les identifiants refusés et un en-tête illisible l'étaient
/// tous — et c'est la PREMIÈRE qu'un hostile peut commettre. Une source pouvait
/// donc ouvrir des connexions et envoyer n'importe quoi sans jamais franchir le
/// seuil, alors que chacune coûte une poignée de main TLS.
#[tokio::test]
async fn un_preambule_invalide_compte_pour_le_videur() {
    let repertoire = std::env::temp_dir().join(format!("ams-http-videur-{}", std::process::id()));
    std::fs::create_dir_all(&repertoire).expect("répertoire temporaire");
    let Some((cert, cle)) = certificat_pem(&repertoire) else {
        let _ = std::fs::remove_dir_all(&repertoire);
        eprintln!("SAUTÉ : `openssl` n'a pas su fabriquer de certificat.");
        return;
    };
    // Un seuil bas : trois préambules fautifs suffisent, et le quatrième trouve
    // porte close.
    let seuils = ams_guard::Thresholds {
        invalid_frames_per_minute: 3,
        ..ams_guard::Thresholds::default()
    };
    let (adresse, arret, tache) = ecoute_avec(&cert, &cle, seuils).await;

    let connecteur = tokio_rustls::TlsConnector::from(client_tls(&[b"h2"]));
    let nom = rustls::pki_types::ServerName::try_from("localhost").expect("un nom");
    let mut refuses = 0_usize;
    for _ in 0..8 {
        let Ok(brut) = tokio::net::TcpStream::connect(adresse).await else {
            refuses += 1;
            continue;
        };
        let Ok(mut chiffre) = connecteur.connect(nom.clone(), brut).await else {
            refuses += 1;
            continue;
        };
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        if chiffre
            .write_all(b"CE N'EST PAS UN PREAMBULE\r\n\r\n")
            .await
            .is_err()
        {
            refuses += 1;
            continue;
        }
        let mut poubelle = [0_u8; 64];
        if chiffre.read(&mut poubelle).await.unwrap_or(0) == 0 {
            // Le serveur a coupé : c'est ce qu'on attend d'un préambule fautif.
        }
    }

    assert!(
        refuses > 0,
        "au-delà du seuil, la source doit être refusée : aucune ne l'a été"
    );

    let _ = arret.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&repertoire);
}

/// **UN JETON N'APPREND RIEN DES RESSOURCES QU'IL N'OUVRE PAS.**
///
/// # Ce que ce contrôle garde, et ce qu'il a coûté de ne pas l'avoir
///
/// `Reason::status` répond exprès la MÊME chose à « cela n'existe pas » et à
/// « vous n'avez pas le droit de savoir » : « la différence entre les deux
/// serait l'information elle-même ». Onze lignes plus bas dans le même `match`,
/// `MethodNotAllowed` rendait un `405` — et le routage le rendait AVANT toute
/// vérification de jeton.
///
/// Un porteur de jeton de courrier lisait donc la surface d'administration
/// qu'il n'ouvre pas : `PATCH /v1/bans` rendait `405` avec un `Allow`, quand
/// `PATCH /v1/inconnu` rendait `404`. L'arbre entier s'énumérait verbe par
/// verbe.
///
/// **ET LE `405` LÉGITIME EST GARDÉ** : sur une ressource que ce jeton PEUT
/// lire, §15.5.6 veut qu'un mauvais verbe se distingue d'un mauvais chemin,
/// sinon le client réessaie les deux.
#[tokio::test]
async fn un_jeton_n_apprend_rien_des_ressources_hors_de_sa_portee() {
    let repertoire = std::env::temp_dir().join(format!("ams-http-portee-{}", std::process::id()));
    std::fs::create_dir_all(&repertoire).expect("répertoire temporaire");
    let Some((cert, cle)) = certificat_pem(&repertoire) else {
        let _ = std::fs::remove_dir_all(&repertoire);
        eprintln!("SAUTÉ : `openssl` n'a pas su fabriquer de certificat.");
        return;
    };
    let (adresse, arret, tache) = ecoute(&cert, &cle).await;

    let connecteur = tokio_rustls::TlsConnector::from(client_tls(&[b"h2"]));
    let brut = tokio::net::TcpStream::connect(adresse)
        .await
        .expect("connexion");
    let nom = rustls::pki_types::ServerName::try_from("localhost").expect("un nom");
    let mut flux = connecteur
        .connect(nom, brut)
        .await
        .expect("poignée de main");

    let mut sortie = Vec::from(PREAMBULE);
    sortie.extend_from_slice(&entete(0, 0x04, 0x00, 0));
    sortie.extend_from_slice(&requete(
        1,
        b"POST",
        b"/v1/tokens",
        None,
        br#"{"login":"marc","password":"secret"}"#,
    ));
    flux.write_all(&sortie).await.expect("écriture");
    let corps = attendre_un_corps(&mut flux).await.expect("une réponse");
    let texte = String::from_utf8(corps).expect("de l'UTF-8");
    let debut = texte.find(':').expect("un premier champ").saturating_add(2);
    let fin = texte
        .get(debut..)
        .and_then(|reste| reste.find('"'))
        .expect("une fin de chaîne")
        .saturating_add(debut);
    // Ce jeton n'ouvre que le courrier et la supervision — jamais
    // l'administration. Voir l'authentificateur d'essai en tête de ce fichier.
    let jeton = texte[debut..fin].to_string();

    let dire = |rang: u32, methode: &[u8], chemin: &[u8]| {
        requete(rang, methode, chemin, Some(&jeton), &[])
    };

    // ── UNE RESSOURCE D'ADMINISTRATION, ET UN CHEMIN QUI N'EXISTE PAS ───────
    flux.write_all(&dire(3, b"PATCH", b"/v1/bans"))
        .await
        .expect("écriture");
    let hors_portee = attendre_un_corps(&mut flux).await.expect("une réponse");
    flux.write_all(&dire(5, b"PATCH", b"/v1/inconnu"))
        .await
        .expect("écriture");
    let inexistant = attendre_un_corps(&mut flux).await.expect("une réponse");

    assert_eq!(
        String::from_utf8_lossy(&hors_portee),
        String::from_utf8_lossy(&inexistant),
        "une ressource hors portée doit répondre EXACTEMENT comme un chemin qui \
         n'existe pas — sinon la différence est l'information"
    );
    assert!(
        String::from_utf8_lossy(&hors_portee).contains(r#""status":404"#),
        "{}",
        String::from_utf8_lossy(&hors_portee)
    );

    // ── ET LE `405` LÉGITIME, SUR CE QUE CE JETON PEUT LIRE ─────────────────
    flux.write_all(&dire(7, b"DELETE", b"/v1/health"))
        .await
        .expect("écriture");
    let mauvais_verbe = attendre_un_corps(&mut flux).await.expect("une réponse");
    let texte = String::from_utf8_lossy(&mauvais_verbe);
    assert!(
        texte.contains(r#""status":405"#),
        "un lecteur légitime doit apprendre que le verbe ne va pas : {texte}"
    );

    let _ = arret.send(());
    let _ = tache.await;
    let _ = std::fs::remove_dir_all(&repertoire);
}
