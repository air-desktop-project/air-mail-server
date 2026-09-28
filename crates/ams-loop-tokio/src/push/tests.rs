//! Le transport des réveils : quelles adresses il contacte, et un échange
//! entier contre un faux service de push, en TLS 1.3 et HTTP/2.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::{Demande, PushFault, RESPONSE_BODY_MAX, config_h2, decouper, echanger, is_public};

/// **LE SERVEUR NE CONTACTE QUE DES ADRESSES PUBLIQUES** pour le compte d'un
/// abonné.
#[test]
fn seules_les_adresses_publiques_passent() {
    for publique in ["142.250.74.10", "2a00:1450:4007:80e::200a", "17.57.144.10"] {
        assert!(
            is_public(publique.parse().expect("une adresse")),
            "{publique}"
        );
    }
    for interdite in [
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "0.1.2.3",
        "100.64.0.1",
        "100.127.255.254",
        "192.0.0.8",
        "192.0.2.1",
        "198.18.0.1",
        "198.19.255.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::1",
        "::",
        "fc00::1",
        "fd12:3456::1",
        "fe80::1",
        "ff02::1",
        "2001:db8::1",
        "64:ff9b::a00:1",
        "::ffff:10.0.0.1",
        "::ffff:127.0.0.1",
    ] {
        assert!(
            !is_public(interdite.parse().expect("une adresse")),
            "{interdite}"
        );
    }
    // Les voisines des plages interdites, elles, passent.
    for voisine in [
        "100.63.255.255",
        "100.128.0.1",
        "192.0.1.1",
        "198.20.0.1",
        "::ffff:8.8.8.8",
    ] {
        assert!(
            is_public(voisine.parse().expect("une adresse")),
            "{voisine}"
        );
    }
}

#[test]
fn une_url_se_decoupe() {
    assert_eq!(
        decouper("https://push.example.com/a/b?c"),
        Some(("push.example.com", "/a/b?c"))
    );
    assert_eq!(
        decouper("https://push.example.com:443/x"),
        Some(("push.example.com", "/x"))
    );
    for mauvaise in [
        "http://a.b/x",
        "https://a.b",
        "https://a.b:8443/x",
        "https:///x",
    ] {
        assert_eq!(decouper(mauvaise), None, "{mauvaise}");
    }
}

/// Un certificat auto-signé pour `push.test`, qui sert aussi d'ancre.
fn certificat(repertoire: &std::path::Path) -> Option<(Vec<u8>, Vec<u8>)> {
    let cle = repertoire.join("cle.pem");
    let cert = repertoire.join("cert.pem");
    let fait = std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
        ])
        .args(["-nodes", "-days", "1", "-subj", "/CN=push.test"])
        .args(["-addext", "subjectAltName=DNS:push.test"])
        .args(["-addext", "basicConstraints=critical,CA:FALSE"])
        .arg("-keyout")
        .arg(&cle)
        .arg("-out")
        .arg(&cert)
        .output()
        .ok()?;
    fait.status
        .success()
        .then(|| Some((std::fs::read(&cert).ok()?, std::fs::read(&cle).ok()?)))
        .flatten()
}

/// Ce que le faux service a vu.
#[derive(Debug, Default)]
struct Vu {
    methode: String,
    chemin: String,
    ttl: String,
    agent: String,
    corps: Vec<u8>,
}

/// Un faux service de push : une connexion, une requête, cette réponse.
async fn faux_service(
    ecoute: tokio::net::TcpListener,
    tls: Arc<rustls::ServerConfig>,
    statut: u16,
    reponse: &'static [u8],
) -> Vu {
    use ams_proto_h2::{Event, FrameReader, Handshake, Need, Settings};
    let (tcp, _) = ecoute.accept().await.expect("une connexion");
    let mut flux = tokio_rustls::TlsAcceptor::from(tls)
        .accept(tcp)
        .await
        .expect("TLS");
    let mut recu = Vec::new();
    let mut sortie = vec![0_u8; 64 * 1024];
    let mut bloc = vec![0_u8; 16 * 1024];
    let mut place = vec![0_u8; 16 * 1024];
    let mut morceau = [0_u8; 4096];
    let mut vu = Vu::default();
    let mut connexion = None;
    loop {
        let lus = flux.read(&mut morceau).await.expect("lisible");
        assert!(lus > 0, "le client a fermé trop tôt");
        recu.extend_from_slice(&morceau[..lus]);
        if connexion.is_none() {
            let (ouverte, ecrits) = Handshake::new(Settings::DEFAULT.pour_un_serveur())
                .open(&recu, &mut sortie)
                .expect("un préambule");
            let Some(ouverte) = ouverte else { continue };
            flux.write_all(&sortie[..ecrits]).await.expect("écrit");
            recu.drain(..ams_proto_h2::PREFACE.len());
            connexion = Some(ouverte);
        }
        let conn = connexion.as_mut().expect("ouverte");
        while let Ok(Need::Complete(entete)) = FrameReader::poll(&recu, 16_384) {
            let charge = recu[9..entete.total()].to_vec();
            let (evenement, ecrits) = conn
                .receive(entete, &charge, &mut bloc, &mut sortie)
                .expect("recevable");
            flux.write_all(&sortie[..ecrits]).await.expect("écrit");
            let fini = match evenement {
                Event::Head {
                    octets, end_stream, ..
                } => {
                    let tete = conn
                        .read_head(
                            &bloc[..octets],
                            &mut place,
                            &ams_proto_http::Limits::DEFAULT,
                        )
                        .expect("une requête");
                    vu.methode = std::format!("{:?}", tete.method());
                    vu.chemin = String::from_utf8_lossy(tete.path()).into_owned();
                    vu.ttl = String::from_utf8_lossy(tete.field(b"ttl").unwrap_or_default())
                        .into_owned();
                    vu.agent =
                        String::from_utf8_lossy(tete.field(b"user-agent").unwrap_or_default())
                            .into_owned();
                    end_stream
                }
                Event::Data {
                    payload,
                    end_stream,
                    ..
                } => {
                    vu.corps.extend_from_slice(payload);
                    end_stream
                }
                _ => false,
            };
            recu.drain(..entete.total());
            if fini {
                let code = ams_proto_http::StatusCode::new(statut).expect("un statut");
                let n = conn
                    .write_head(1, code, &[], reponse.is_empty(), &mut sortie)
                    .expect("tête");
                flux.write_all(&sortie[..n]).await.expect("écrit");
                // UN CORPS PLUS LONG QU'UN CADRE part en plusieurs : le pair
                // en accepte autant que ses fenêtres le permettent.
                let mut reste = reponse;
                while !reste.is_empty() {
                    let (n, pris) = conn.write_data(1, reste, true, &mut sortie).expect("corps");
                    assert!(pris > 0, "la fenêtre du client s'est fermée");
                    flux.write_all(&sortie[..n]).await.expect("écrit");
                    reste = &reste[pris..];
                }
                flux.flush().await.expect("vidé");
                return vu;
            }
        }
    }
}

/// Deux cent mille octets : plus de trois fois la fenêtre par défaut de §6.9.2.
static GROS: [u8; 200_000] = [b'x'; 200_000];

/// **UN `GET` RAMÈNE UN CORPS DE PLUSIEURS FENÊTRES** (0.2.40) — c'est ce que
/// la liste de révocation de Google demande, et ce que la fenêtre de 65 535
/// octets arrêtait. Et un corps plus long que ce que l'appelant accepte est
/// une faute, pas une troncature.
#[tokio::test(flavor = "multi_thread")]
async fn un_get_ramene_un_corps_de_plusieurs_fenetres() {
    let _exclusif = crate::SOCKETS_EXCLUSIFS.lock().await;
    let repertoire = std::env::temp_dir().join(std::format!("ams-get-{}", std::process::id()));
    std::fs::create_dir_all(&repertoire).expect("répertoire");
    let Some((cert, cle)) = certificat(&repertoire) else {
        eprintln!("SAUTÉ : `openssl` n'a pas su fabriquer de certificat.");
        return;
    };
    let ancres = Arc::new(ams_tls::anchors(&cert).expect("une ancre"));
    let client = Arc::new(config_h2(ancres));
    for (corps_max, attendu) in [(256 * 1024, true), (100_000, false)] {
        let mut serveur = ams_tls::server_config(&cert, &cle).expect("matériel");
        serveur.alpn_protocols = ams_tls::alpn();
        let ecoute = tokio::net::TcpListener::bind("[::1]:0")
            .await
            .expect("liée");
        let adresse = ecoute.local_addr().expect("adresse");
        let service = tokio::spawn(faux_service(ecoute, Arc::new(serveur), 200, &GROS));
        let reponse = echanger(
            &client,
            Duration::from_secs(5),
            adresse,
            Demande {
                methode: b"GET",
                hote: "push.test",
                chemin: "/attestation/status",
                fields: &[],
                body: &[],
                corps_max,
            },
        )
        .await;
        match attendu {
            true => {
                let reponse = reponse.expect("une réponse");
                assert_eq!(reponse.status, 200);
                assert_eq!(reponse.body.len(), GROS.len());
                let vu = service.await.expect("le service a fini");
                assert_eq!(vu.methode, "Get");
                assert!(vu.corps.is_empty());
            }
            false => {
                assert_eq!(reponse, Err(PushFault::Protocol));
                service.abort();
            }
        }
    }
    let _ = std::fs::remove_dir_all(&repertoire);
}

/// **UN ÉCHANGE ENTIER** : TLS 1.3 vérifié contre l'ancre et pour le nom,
/// HTTP/2 par ALPN, la requête et son corps arrivent, la réponse revient.
#[tokio::test(flavor = "multi_thread")]
async fn un_reveil_part_et_sa_reponse_revient() {
    // Voir `SOCKETS_EXCLUSIFS` : le test d'arrêt du serveur ne doit pas voir
    // son port repris par nos écoutes.
    let _exclusif = crate::SOCKETS_EXCLUSIFS.lock().await;
    let repertoire = std::env::temp_dir().join(std::format!("ams-push-{}", std::process::id()));
    std::fs::create_dir_all(&repertoire).expect("répertoire");
    let Some((cert, cle)) = certificat(&repertoire) else {
        eprintln!("SAUTÉ : `openssl` n'a pas su fabriquer de certificat.");
        return;
    };
    let mut serveur = ams_tls::server_config(&cert, &cle).expect("matériel");
    serveur.alpn_protocols = ams_tls::alpn();
    // SUR `[::1]`, ET NON SUR `127.0.0.1` : les tests de ce binaire tournent
    // ensemble, et un port de `127.0.0.1` tout juste libéré par l'un est celui
    // qu'un autre croit fermé. La boucle IPv6 est un autre espace de ports.
    let ecoute = tokio::net::TcpListener::bind("[::1]:0")
        .await
        .expect("liée");
    let adresse = ecoute.local_addr().expect("adresse");
    let service = tokio::spawn(faux_service(
        ecoute,
        Arc::new(serveur),
        201,
        "re\u{e7}u".as_bytes(),
    ));

    let ancres = Arc::new(ams_tls::anchors(&cert).expect("une ancre"));
    let client = Arc::new(config_h2(ancres));
    let reponse = echanger(
        &client,
        Duration::from_secs(5),
        adresse,
        Demande {
            methode: b"POST",
            hote: "push.test",
            chemin: "/wpush/abc",
            fields: &[(b"ttl", b"60")],
            body: b"le message chiffr\xc3\xa9",
            corps_max: RESPONSE_BODY_MAX,
        },
    )
    .await
    .expect("une réponse");
    assert_eq!(reponse.status, 201);
    assert_eq!(reponse.body, "reçu".as_bytes());
    let vu = service.await.expect("le service a fini");
    assert_eq!(vu.methode, "Post");
    assert_eq!(vu.chemin, "/wpush/abc");
    assert_eq!(vu.ttl, "60");
    // **LE SERVEUR S'ANNONCE**, sans version : un service peut refuser une
    // requête anonyme.
    assert_eq!(vu.agent, "air-mail-server");
    assert_eq!(vu.corps, "le message chiffré".as_bytes());

    // **UN AUTRE NOM QUE CELUI DU CERTIFICAT NE PASSE PAS** : la vérification
    // est réelle.
    let ecoute = tokio::net::TcpListener::bind("[::1]:0")
        .await
        .expect("liée");
    let adresse = ecoute.local_addr().expect("adresse");
    let mut serveur = ams_tls::server_config(&cert, &cle).expect("matériel");
    serveur.alpn_protocols = ams_tls::alpn();
    let accepte = tokio::spawn(async move {
        let (tcp, _) = ecoute.accept().await.expect("une connexion");
        let _ = tokio_rustls::TlsAcceptor::from(Arc::new(serveur))
            .accept(tcp)
            .await;
    });
    let faute = echanger(
        &client,
        Duration::from_secs(5),
        adresse,
        Demande {
            methode: b"POST",
            hote: "autre.test",
            chemin: "/x",
            fields: &[],
            body: b"",
            corps_max: RESPONSE_BODY_MAX,
        },
    )
    .await
    .expect_err("un nom qui ne correspond pas");
    assert_eq!(faute, PushFault::Unreachable);
    let _ = accepte.await;

    // **SANS HTTP/2, PAS D'ÉCHANGE.**
    let ecoute = tokio::net::TcpListener::bind("[::1]:0")
        .await
        .expect("liée");
    let adresse = ecoute.local_addr().expect("adresse");
    let serveur = Arc::new(ams_tls::server_config(&cert, &cle).expect("matériel"));
    let accepte = tokio::spawn(async move {
        let (tcp, _) = ecoute.accept().await.expect("une connexion");
        let _ = tokio_rustls::TlsAcceptor::from(serveur).accept(tcp).await;
    });
    let faute = echanger(
        &client,
        Duration::from_secs(5),
        adresse,
        Demande {
            methode: b"POST",
            hote: "push.test",
            chemin: "/x",
            fields: &[],
            body: b"",
            corps_max: RESPONSE_BODY_MAX,
        },
    )
    .await
    .expect_err("pas d'ALPN h2");
    assert_eq!(faute, PushFault::NotHttp2);
    let _ = accepte.await;

    // Personne n'écoute.
    let personne = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);
    let faute = echanger(
        &client,
        Duration::from_secs(5),
        personne,
        Demande {
            methode: b"POST",
            hote: "push.test",
            chemin: "/x",
            fields: &[],
            body: b"",
            corps_max: RESPONSE_BODY_MAX,
        },
    )
    .await
    .expect_err("fermé");
    assert_eq!(faute, PushFault::Unreachable);
    let _ = Ipv6Addr::LOCALHOST;
    let _ = std::fs::remove_dir_all(&repertoire);
}
