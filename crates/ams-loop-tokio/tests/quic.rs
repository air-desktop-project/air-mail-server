// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! L'écoute QUIC, éprouvée **sur une vraie socket UDP**.
//!
//! # CE QUE CES ESSAIS AJOUTENT À CEUX D'`ams-quic-tls`
//!
//! Là-bas, le conducteur est éprouvé sans socket : les datagrammes passent de
//! main en main dans le même processus. Ici, ils traversent la pile réseau du
//! système — avec sa fragmentation, ses tampons, et son ordre qui n'est garanti
//! par rien.
//!
//! **C'est ce qui éprouve le module d'écoute lui-même** : la carte des
//! identifiants, le choix du délai d'attente, l'émission vers la bonne adresse,
//! et l'oubli de ce qui s'est éteint. Aucune de ces quatre choses n'existe dans
//! les essais du conducteur.
//!
//! Le client vit dans `ams-quic-client` : il sert aussi aux essais du serveur,
//! et le dupliquer en ferait diverger les copies.

use std::sync::Arc;

use ams_proto_quic::Frame;
use ams_quic_client::{
    Client, SANS_OPENSSL, atelier, attendre_la_reponse, config_client, envoyer_une_requete,
    materiel,
};
use tokio::net::UdpSocket;

/// Combien de connexions ces essais laissent vivre en même temps.
///
/// **LA BORNE VIENT DE L'APPELANT, ET NON D'UNE CONSTANTE DU MODULE** : elle
/// était gravée à 1 024 pendant que les quatre autres écoutes prenaient
/// `--max-connections` de la configuration. Ces essais-ci n'éprouvent pas la
/// saturation — sauf le dernier, qui pose sa propre valeur.
const PLACES: usize = 64;

/// L'inactivité annoncée par ces essais, en microsecondes.
///
/// **ELLE VIENT DE L'APPELANT, ET NON D'UNE CONSTANTE DE LA CONNEXION** : elle
/// était gravée à trente secondes tout en se documentant « un réglage », si bien
/// qu'aucun exploitant ne pouvait l'abaisser. Ces essais reprennent le défaut.
const INACTIVITE: u64 = 30_000_000;

/// Un videur qui ne bannit personne.
///
/// **IL EST OBLIGATOIRE, ET C'EST VOULU** : une écoute QUIC sans garde ne
/// s'exprime plus depuis qu'un pair banni doit être refusé AVANT la poignée de
/// main. Le rendre facultatif aurait laissé exactement l'oubli qu'on vient de
/// corriger — HTTP/3 servait un banni que les quatre autres portes refusaient.
///
/// Ces essais-ci n'éprouvent pas le bannissement : ils éprouvent le transport,
/// et un videur permissif les laisse dire ce qu'ils disaient déjà.
fn videur_permissif() -> ams_loop_tokio::SharedGuard {
    ams_loop_tokio::SharedGuard::new(64, ams_guard::Thresholds::DEFAULT)
}

/// **UNE POIGNÉE DE MAIN QUIC SUR UNE VRAIE SOCKET UDP.**
///
/// C'est le premier essai où les datagrammes traversent la pile réseau du
/// système. Il éprouve ce que le conducteur ne peut pas éprouver seul : la carte
/// des identifiants, le choix du délai, l'émission vers la bonne adresse.
#[tokio::test(flavor = "current_thread")]
async fn une_poignee_de_main_sur_une_vraie_socket() {
    let atelier = atelier("poignee");
    let (autorite, cert, cle) = materiel(atelier.chemin()).expect(SANS_OPENSSL);

    let mut config = ams_tls::quic_server_config(&cert, &cle).expect("la paire est bonne");
    config.alpn_protocols = ams_tls::alpn_h3();
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("une socket");
    let adresse = socket.local_addr().expect("une adresse");

    let (fin, arret) = tokio::sync::oneshot::channel::<()>();
    let ecoute = tokio::spawn(async move {
        ams_loop_tokio::serve_quic(
            socket,
            Arc::new(config),
            &videur_permissif(),
            PLACES,
            INACTIVITE,
            &mut ams_loop_tokio::SansApplication,
            async {
                let _ = arret.await;
            },
        )
        .await
    });

    let mut client = Client::new(config_client(&autorite), adresse).await;
    for _ in 0..16 {
        if !client.parler().await && !client.tls().is_handshaking() {
            break;
        }
        if !client.ecouter().await && !client.tls().is_handshaking() {
            break;
        }
    }

    assert!(
        !client.tls().is_handshaking(),
        "la poignée de main doit aboutir sur une vraie socket"
    );
    assert_eq!(client.tls().alpn_protocol(), Some(&b"h3"[..]));
    assert!(
        client.tls().quic_transport_parameters().is_some(),
        "§8.2 : le serveur annonce les siens"
    );
    // **L'IDENTIFIANT A CHANGÉ** : le serveur nous a donné le sien, et nos
    // paquets l'ont atteint — c'est la carte de l'écoute qui l'a fait.
    assert_ne!(
        client.distant(),
        ams_quic_client::identifiant(&ams_quic_client::ORIGINE),
        "le serveur doit avoir imposé son identifiant"
    );

    let _ = fin.send(());
    let stats = ecoute
        .await
        .expect("la tâche d'écoute")
        .expect("l'écoute rend ses comptes");
    assert_eq!(stats.accepted, 1, "une connexion, et une seule");
    assert_eq!(stats.refused, 0);
}

/// **DU BRUIT SUR LE PORT N'OUVRE RIEN, ET NE FAIT RIEN TOMBER.**
///
/// Le port est ouvert au monde entier : n'importe qui peut y écrire. Un
/// datagramme qui n'est pas du QUIC, un `Initial` trop court (§14.1), un
/// en-tête inconnu — **aucun ne doit ouvrir de connexion ni arrêter l'écoute**.
#[tokio::test(flavor = "current_thread")]
async fn du_bruit_sur_le_port_n_ouvre_rien() {
    let atelier = atelier("bruit");
    let (_autorite, cert, cle) = materiel(atelier.chemin()).expect(SANS_OPENSSL);

    let mut config = ams_tls::quic_server_config(&cert, &cle).expect("la paire est bonne");
    config.alpn_protocols = ams_tls::alpn_h3();
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("une socket");
    let adresse = socket.local_addr().expect("une adresse");

    let (fin, arret) = tokio::sync::oneshot::channel::<()>();
    let ecoute = tokio::spawn(async move {
        ams_loop_tokio::serve_quic(
            socket,
            Arc::new(config),
            &videur_permissif(),
            PLACES,
            INACTIVITE,
            &mut ams_loop_tokio::SansApplication,
            async {
                let _ = arret.await;
            },
        )
        .await
    });

    let bavard = UdpSocket::bind("127.0.0.1:0").await.expect("une socket");
    for bruit in [
        vec![0x5a_u8; 1_200],
        vec![0_u8; 64],
        b"GET / HTTP/1.1\r\n\r\n".to_vec(),
        // Un `Initial` bien formé mais trop court : §14.1 le condamne.
        {
            let mut court = vec![0xc3_u8, 0x00, 0x00, 0x00, 0x01, 8];
            court.extend_from_slice(&ams_quic_client::ORIGINE);
            court.extend_from_slice(&[0, 0, 0x44, 0x00]);
            court.resize(200, 0);
            court
        },
    ] {
        bavard
            .send_to(&bruit, adresse)
            .await
            .expect("le bruit part");
    }
    // De quoi laisser l'écoute les traiter.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let _ = fin.send(());
    let stats = ecoute
        .await
        .expect("la tâche d'écoute")
        .expect("l'écoute rend ses comptes");
    assert_eq!(stats.accepted, 0, "aucun bruit n'ouvre de connexion");
    assert!(stats.discarded >= 4, "et tous sont comptés : {stats:?}");
}

/// **UN FLUX TRAVERSE LA VRAIE SOCKET.**
///
/// La poignée de main aboutissait déjà ; celui-ci va plus loin : le client ouvre
/// un flux bidirectionnel, y écrit, et le termine — le tout sur la pile réseau
/// du système.
///
/// # CE QUE CET ESSAI PROUVE, ET CE QU'IL NE PROUVE PAS
///
/// Il prouve que §12.4, §4.1 et §4.6 sont servis de bout en bout : la trame
/// arrive au bon niveau, le crédit est compté, le flux est ouvert et rangé dans
/// sa part de table. **Il ne prouve pas qu'une application reçoit ces octets** —
/// l'écoute n'a pas encore de couture applicative, et c'est le conducteur HTTP/3
/// qui l'apportera. Une connexion qui reste ouverte est donc tout ce qu'on peut
/// observer d'ici, et c'est déjà ce qui tomberait si l'un des trois manquait.
#[tokio::test(flavor = "current_thread")]
async fn un_flux_traverse_la_vraie_socket() {
    let atelier = atelier("flux");
    let (autorite, cert, cle) = materiel(atelier.chemin()).expect(SANS_OPENSSL);

    let mut config = ams_tls::quic_server_config(&cert, &cle).expect("la paire est bonne");
    config.alpn_protocols = ams_tls::alpn_h3();
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("une socket");
    let adresse = socket.local_addr().expect("une adresse");

    let (fin, arret) = tokio::sync::oneshot::channel::<()>();
    let ecoute = tokio::spawn(async move {
        ams_loop_tokio::serve_quic(
            socket,
            Arc::new(config),
            &videur_permissif(),
            PLACES,
            INACTIVITE,
            &mut ams_loop_tokio::SansApplication,
            async {
                let _ = arret.await;
            },
        )
        .await
    });

    let mut client = Client::new(config_client(&autorite), adresse).await;
    for _ in 0..16 {
        if !client.parler().await && !client.tls().is_handshaking() {
            break;
        }
        if !client.ecouter().await && !client.tls().is_handshaking() {
            break;
        }
    }
    assert!(!client.tls().is_handshaking(), "la poignée de main aboutit");

    // Le flux zéro : le premier bidirectionnel du client (§2.1).
    let mut trames = [0_u8; 64];
    let ecrits = (Frame::Stream {
        stream: 0,
        offset: 0,
        data: b"une requete",
        fin: true,
    })
    .write(&mut trames)
    .expect("écrivable");
    client.dire(trames.get(..ecrits).expect("écrits"));

    for _ in 0..6 {
        client.parler().await;
        client.ecouter().await;
    }

    assert_eq!(
        client.ferme(),
        None,
        "LE FLUX A ÉTÉ ACCEPTÉ : une faute de §12.4, §4.1 ou §4.6 aurait fermé"
    );

    let _ = fin.send(());
    let stats = ecoute
        .await
        .expect("la tâche d'écoute")
        .expect("l'écoute rend ses comptes");
    assert_eq!(stats.accepted, 1);
    assert_eq!(stats.closed, 0, "et la connexion vit toujours");
}

/// **ET UNE FAUTE DE FLUX FERME, SUR LA MÊME SOCKET.**
///
/// # C'EST LE CONTRÔLE NÉGATIF DE L'ESSAI PRÉCÉDENT
///
/// Sans lui, « la connexion est restée ouverte » ne prouverait rien : une écoute
/// qui jetterait toutes les trames de flux en silence passerait aussi bien. Ici
/// le client dépasse le plafond de §4.6, et le serveur doit le lui dire.
#[tokio::test(flavor = "current_thread")]
async fn une_faute_de_flux_ferme_sur_la_vraie_socket() {
    let atelier = atelier("faute-de-flux");
    let (autorite, cert, cle) = materiel(atelier.chemin()).expect(SANS_OPENSSL);

    let mut config = ams_tls::quic_server_config(&cert, &cle).expect("la paire est bonne");
    config.alpn_protocols = ams_tls::alpn_h3();
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("une socket");
    let adresse = socket.local_addr().expect("une adresse");

    let (fin, arret) = tokio::sync::oneshot::channel::<()>();
    let ecoute = tokio::spawn(async move {
        ams_loop_tokio::serve_quic(
            socket,
            Arc::new(config),
            &videur_permissif(),
            PLACES,
            INACTIVITE,
            &mut ams_loop_tokio::SansApplication,
            async {
                let _ = arret.await;
            },
        )
        .await
    });

    let mut client = Client::new(config_client(&autorite), adresse).await;
    for _ in 0..16 {
        if !client.parler().await && !client.tls().is_handshaking() {
            break;
        }
        if !client.ecouter().await && !client.tls().is_handshaking() {
            break;
        }
    }
    assert!(!client.tls().is_handshaking(), "la poignée de main aboutit");

    // Le rang cent, très au-delà des huit flux qu'on lui a annoncés.
    let mut trames = [0_u8; 64];
    let ecrits = (Frame::Stream {
        stream: 400,
        offset: 0,
        data: b"trop",
        fin: false,
    })
    .write(&mut trames)
    .expect("écrivable");
    client.dire(trames.get(..ecrits).expect("écrits"));

    for tour in 0..6 {
        let dit = client.parler().await;
        let entendu = client.ecouter().await;
        std::eprintln!(
            "DEBUG tour={tour} dit={dit} entendu={entendu} ferme={:?}",
            client.ferme()
        );
    }

    assert_eq!(
        client.ferme(),
        Some(ams_proto_quic::TransportError::StreamLimitError.value()),
        "§4.6 : le serveur le dit, et ne se contente pas de jeter"
    );

    let _ = fin.send(());
    let stats = ecoute
        .await
        .expect("la tâche d'écoute")
        .expect("l'écoute rend ses comptes");
    assert_eq!(stats.accepted, 1);
    // **ELLE A EU LE TEMPS DE FINIR D'ATTENDRE.** §10.2 : après avoir dit sa
    // fermeture, une connexion reste en état de fermeture trois PTO durant, pour
    // pouvoir redire son `CONNECTION_CLOSE` au pair qui n'aurait pas entendu.
    // `closed` ne compte que ce qui a fini d'attendre — et l'extinction de §5.2
    // continue de tourner jusqu'à ce que plus personne n'attende.
    //
    // Cet essai valait zéro tant que le signal d'arrêt rendait la main sur-le-
    // champ : il mesurait alors la brusquerie du retour, et non §10.2.
    assert_eq!(stats.closed, 1);
}

/// Une application qui renvoie ce qu'on lui dit, et termine.
///
/// **C'EST LE PLUS PETIT USAGE DE LA COUTURE QUI PROUVE QUELQUE CHOSE** : elle
/// lit, elle écrit, elle conclut. Un conducteur HTTP/3 fera davantage, mais rien
/// d'autre en nature.
#[derive(Default)]
struct Echo {
    /// Ce que chaque flux a dit jusqu'ici.
    recu: std::collections::HashMap<u64, Vec<u8>>,
    /// Combien de flux ont été servis.
    servis: usize,
    /// Les sources qui ont parlé.
    sources: Vec<ams_guard::Source>,
}

impl ams_loop_tokio::Application for Echo {
    fn on_readable(
        &mut self,
        connexion: &mut ams_quic_tls::Connection,
        flux: ams_proto_quic::StreamId,
        pair: ams_guard::Source,
    ) {
        // **L'APPLICATION SAIT QUI PARLE** : c'est ce qui permet une politique
        // par source, et l'écho s'en sert pour le prouver.
        if !self.sources.contains(&pair) {
            self.sources.push(pair);
        }
        let mut vers = [0_u8; 256];
        let lus = connexion.read(flux, &mut vers);
        if lus > 0 {
            self.recu
                .entry(flux.value())
                .or_default()
                .extend_from_slice(vers.get(..lus).expect("lus"));
        }
        // **ON NE RÉPOND QU'À UNE REQUÊTE COMPLÈTE** : §3.2 distingue « tout est
        // là » de « il en manque », et répondre trop tôt servirait une requête
        // tronquée.
        if !matches!(
            connexion.recv_state(flux),
            Some(ams_quic::RecvState::DataRecvd | ams_quic::RecvState::DataRead)
        ) {
            return;
        }
        let Some(dit) = self.recu.remove(&flux.value()) else {
            return;
        };
        let mut reponse = b"vous avez dit: ".to_vec();
        reponse.extend_from_slice(&dit);
        if connexion.write(flux, &reponse).is_ok() {
            let _ = connexion.finish(flux);
            self.servis = self.servis.saturating_add(1);
        }
    }
}

/// **DES OCTETS D'APPLICATION FONT L'ALLER-RETOUR SUR LA VRAIE SOCKET.**
///
/// C'est ce que toute la pile QUIC sert à rendre possible : le client ouvre un
/// flux, y écrit une requête, et reçoit la réponse d'une application qui n'a
/// jamais touché à une socket.
#[tokio::test(flavor = "current_thread")]
async fn des_octets_d_application_font_l_aller_retour() {
    let atelier = atelier("echo");
    let (autorite, cert, cle) = materiel(atelier.chemin()).expect(SANS_OPENSSL);

    let mut config = ams_tls::quic_server_config(&cert, &cle).expect("la paire est bonne");
    config.alpn_protocols = ams_tls::alpn_h3();
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("une socket");
    let adresse = socket.local_addr().expect("une adresse");

    let (fin, arret) = tokio::sync::oneshot::channel::<()>();
    let ecoute = tokio::spawn(async move {
        let mut echo = Echo::default();
        let videur = videur_permissif();
        let stats = ams_loop_tokio::serve_quic(
            socket,
            Arc::new(config),
            &videur,
            PLACES,
            INACTIVITE,
            &mut echo,
            async {
                let _ = arret.await;
            },
        )
        .await;
        (stats, echo.servis, echo.sources)
    });

    let mut client = Client::new(config_client(&autorite), adresse).await;
    for _ in 0..16 {
        if !client.parler().await && !client.tls().is_handshaking() {
            break;
        }
        if !client.ecouter().await && !client.tls().is_handshaking() {
            break;
        }
    }
    assert!(!client.tls().is_handshaking(), "la poignée de main aboutit");

    let mut trames = [0_u8; 64];
    let ecrits = (Frame::Stream {
        stream: 0,
        offset: 0,
        data: b"bonjour",
        fin: true,
    })
    .write(&mut trames)
    .expect("écrivable");
    client.dire(trames.get(..ecrits).expect("écrits"));

    for _ in 0..8 {
        client.parler().await;
        client.ecouter().await;
        if client.fin_recue(0) {
            break;
        }
    }

    assert_eq!(client.ferme(), None, "rien n'a fermé");
    assert_eq!(
        client.recu(0),
        b"vous avez dit: bonjour",
        "LA RÉPONSE DE L'APPLICATION EST ARRIVÉE"
    );
    assert!(client.fin_recue(0), "§19.8 : et le flux est terminé");

    let _ = fin.send(());
    let (stats, servis, sources) = ecoute.await.expect("la tâche d'écoute");
    assert_eq!(servis, 1, "un flux servi, et un seul");
    assert_eq!(
        sources.len(),
        1,
        "et l'application a su de quelle source il venait"
    );
    assert!(
        sources.contains(&ams_guard::Source::V4([127, 0, 0, 1])),
        "celle du bouclage : {sources:?}"
    );
    assert_eq!(stats.expect("l'écoute rend ses comptes").accepted, 1);
}

/// Une API d'essai, la même que celle d'HTTP/2 — c'est le but.
struct ApiEssai;

impl ams_loop_tokio::http::Api for ApiEssai {
    fn serve<'o>(
        &self,
        resource: ams_api::Resource<'_>,
        _method: ams_proto_http::Method,
        _account: &str,
        _body: &[u8],
        _range: Option<&[u8]>,
        sortie: &'o mut [u8],
    ) -> ams_loop_tokio::http::Served<'o> {
        let quoi: &[u8] = match resource {
            ams_api::Resource::Health => b"{\"etat\":\"bien\"}",
            _ => b"{\"etat\":\"autre\"}",
        };
        let combien = quoi.len().min(sortie.len());
        sortie
            .get_mut(..combien)
            .expect("la borne vient d'être prise")
            .copy_from_slice(quoi.get(..combien).expect("de même"));
        ams_loop_tokio::http::Served {
            status: ams_proto_http::StatusCode::OK,
            media: ams_api::JSON_MEDIA_TYPE,
            body: sortie.get(..combien).unwrap_or_default(),
            ..ams_loop_tokio::http::Served::default()
        }
    }

    fn authenticate(&self, login: &str, password: &[u8]) -> Option<ams_api::Scope> {
        (login == "marc" && password == b"secret").then(|| {
            ams_api::Scope::one(ams_api::Area::Mail, ams_api::Rights::Read)
                .with(ams_api::Area::Observe, ams_api::Rights::Read)
        })
    }

    fn nonce(&self) -> u64 {
        7
    }
}

/// **UNE REQUÊTE HTTP/3 TRAVERSE TOUTE LA CHAÎNE**, sur une vraie socket UDP.
///
/// QUIC, TLS, ALPN `h3`, flux de contrôle, réglages, QPACK, session, API, et la
/// réponse qui revient comprimée. C'est ce que chaque tranche depuis la
/// grammaire sert à rendre possible.
#[tokio::test(flavor = "current_thread")]
async fn une_requete_h3_traverse_toute_la_chaine() {
    let atelier = atelier("h3");
    let (autorite, cert, cle) = materiel(atelier.chemin()).expect(SANS_OPENSSL);

    let mut config = ams_tls::quic_server_config(&cert, &cle).expect("la paire est bonne");
    config.alpn_protocols = ams_tls::alpn_h3();
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("une socket");
    let adresse = socket.local_addr().expect("une adresse");

    let (fin, arret) = tokio::sync::oneshot::channel::<()>();
    let ecoute = tokio::spawn(async move {
        let session = ams_session::http::Http::new(
            ams_api::Key::new(b"une clef de trente-deux octets!!").expect("trente-deux octets"),
            3_600 * 1_000_000,
        )
        .expect("une durée licite");
        let guard = ams_loop_tokio::SharedGuard::new(64, ams_guard::Thresholds::default());
        let api = ApiEssai;
        let mut application = ams_loop_tokio::h3::Http3Application::new(&session, &api, &guard);
        let videur = videur_permissif();
        let stats = ams_loop_tokio::serve_quic(
            socket,
            Arc::new(config),
            &videur,
            PLACES,
            INACTIVITE,
            &mut application,
            async {
                let _ = arret.await;
            },
        )
        .await;
        (stats, application.comptes())
    });

    let mut client = Client::new(config_client(&autorite), adresse).await;
    for _ in 0..16 {
        if !client.parler().await && !client.tls().is_handshaking() {
            break;
        }
        if !client.ecouter().await && !client.tls().is_handshaking() {
            break;
        }
    }
    assert!(!client.tls().is_handshaking(), "la poignée de main aboutit");

    // **PREMIÈRE REQUÊTE : le jeton**, comme l'essai HTTP/2 le fait.
    let jeton = {
        let corps = br#"{"login":"marc","password":"secret"}"#;
        envoyer_une_requete(&mut client, 0, 20, b"/v1/tokens", None, corps).await;
        let recu = attendre_la_reponse(&mut client, 0).await;
        let texte = std::string::String::from_utf8_lossy(&recu).to_string();
        assert!(
            texte.contains(r#"{"token":""#),
            "l'échange d'identifiants doit rendre un jeton : {texte}"
        );
        let debut = texte.find(':').expect("un premier champ").saturating_add(2);
        let fin = texte
            .get(debut..)
            .and_then(|reste| reste.find('"'))
            .expect("une fin de chaîne")
            .saturating_add(debut);
        texte[debut..fin].to_string()
    };

    // **SECONDE REQUÊTE : la ressource**, sur SON flux, avec le jeton qu'on vient
    // d'obtenir. Rien n'est à oublier entre les deux : le client range désormais
    // ce qu'il reçoit par flux, et celui-ci n'a encore rien porté.
    envoyer_une_requete(&mut client, 4, 17, b"/v1/health", Some(&jeton), &[]).await;
    let recu = attendre_la_reponse(&mut client, 4).await;
    let texte = std::string::String::from_utf8_lossy(&recu).to_string();

    assert_eq!(client.ferme(), None, "rien n'a fermé");
    assert!(
        texte.contains("\"etat\""),
        "LA RÉPONSE DE L'API EST ARRIVÉE : {texte}"
    );

    let _ = fin.send(());
    let (stats, (servies, refusees)) = ecoute.await.expect("la tâche d'écoute");
    assert_eq!(stats.expect("l'écoute rend ses comptes").accepted, 1);
    assert_eq!(servies, 2, "deux requêtes servies");
    assert_eq!(refusees, 0, "et pas un refus");
}

/// **L'EXTINCTION SE DIT AVANT DE SE FAIRE** (§5.2 de RFC 9114).
///
/// Le signal d'arrêt ne lâche plus les connexions sans un mot : le serveur dit
/// d'abord « n'ouvre plus rien », laisse passer le délai de grâce, puis dit
/// jusqu'où il est allé et ferme en `H3_NO_ERROR`.
///
/// **CE QUE CET ESSAI PROUVE ET QUE LES ESSAIS D'`ams-h3` NE PEUVENT PAS** :
/// là-bas, le conducteur écrit dans un transport de fer-blanc. Ici les deux
/// `GOAWAY` traversent QUIC, TLS et une vraie socket, et c'est le client qui les
/// lit sur le flux de contrôle du serveur.
#[tokio::test(flavor = "current_thread")]
async fn l_extinction_se_dit_au_client_avant_de_fermer() {
    let atelier = atelier("h3-extinction");
    let (autorite, cert, cle) = materiel(atelier.chemin()).expect(SANS_OPENSSL);

    let mut config = ams_tls::quic_server_config(&cert, &cle).expect("la paire est bonne");
    config.alpn_protocols = ams_tls::alpn_h3();
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("une socket");
    let adresse = socket.local_addr().expect("une adresse");

    let (fin, arret) = tokio::sync::oneshot::channel::<()>();
    let ecoute = tokio::spawn(async move {
        let session = ams_session::http::Http::new(
            ams_api::Key::new(b"une clef de trente-deux octets!!").expect("trente-deux octets"),
            3_600 * 1_000_000,
        )
        .expect("une durée licite");
        let guard = ams_loop_tokio::SharedGuard::new(64, ams_guard::Thresholds::default());
        let api = ApiEssai;
        let mut application = ams_loop_tokio::h3::Http3Application::new(&session, &api, &guard);
        let videur = videur_permissif();
        ams_loop_tokio::serve_quic(
            socket,
            Arc::new(config),
            &videur,
            PLACES,
            INACTIVITE,
            &mut application,
            async {
                let _ = arret.await;
            },
        )
        .await
    });

    let mut client = Client::new(config_client(&autorite), adresse).await;
    for _ in 0..16 {
        if !client.parler().await && !client.tls().is_handshaking() {
            break;
        }
        if !client.ecouter().await && !client.tls().is_handshaking() {
            break;
        }
    }
    assert!(!client.tls().is_handshaking(), "la poignée de main aboutit");

    // Une requête servie : c'est elle qui donnera son rang au second `GOAWAY`.
    envoyer_une_requete(&mut client, 0, 20, b"/v1/tokens", None, br#"{}"#).await;
    let _ = attendre_la_reponse(&mut client, 0).await;

    // **LE SIGNAL D'ARRÊT.** Ce qui suit doit arriver AVANT que la connexion ne
    // se ferme, et c'est tout l'objet de §5.2.
    let _ = fin.send(());
    // **ON POMPE JUSQU'À LA FERMETURE**, et non un nombre de tours : le second
    // temps n'arrive qu'après le délai de grâce, et compter des tours ferait
    // dépendre l'essai de la vitesse de la machine.
    let debut = std::time::Instant::now();
    while debut.elapsed() < std::time::Duration::from_secs(20) {
        client.parler().await;
        client.ecouter().await;
        if client.ferme().is_some() {
            break;
        }
    }

    // §6.2 : le flux de contrôle du serveur est son premier unidirectionnel.
    let controle = 3_u64;
    let dit = client.recu(controle);
    // §6.2 : le premier entier d'un flux unidirectionnel dit ce qu'il est, une
    // fois, en tête. Les trames ne commencent qu'après lui.
    let (genre, tete) = ams_proto_quic::varints::decode(dit).expect("un type de flux");
    assert_eq!(
        genre,
        ams_proto_h3::StreamKind::Control.value(),
        "c'est bien le flux de contrôle du serveur"
    );
    let mut suite = dit.get(tete..).unwrap_or_default();
    let mut goaways = std::vec::Vec::new();
    while let Ok(entete) = ams_proto_h3::FrameHeader::parse(suite) {
        let total = usize::try_from(entete.total()).expect("tient");
        if suite.len() < total {
            break;
        }
        if matches!(entete.kind(), ams_proto_h3::FrameKind::GoAway) {
            let charge = suite.get(entete.header_len()..total).unwrap_or_default();
            let (identifiant, _) =
                ams_proto_quic::varints::decode(charge).expect("un identifiant de §16");
            goaways.push(identifiant);
        }
        suite = suite.get(total..).unwrap_or_default();
    }

    assert_eq!(
        goaways.len(),
        2,
        "§5.2 : deux temps, et non un — reçu {goaways:?}"
    );
    assert_eq!(
        goaways.first().copied(),
        Some(ams_proto_h3::GOAWAY_MAX),
        "d'abord « n'ouvre plus rien »"
    );
    assert_eq!(
        goaways.get(1).copied(),
        Some(4),
        "puis le rang qui suit la requête servie sur le flux 0"
    );
    assert_eq!(
        client.ferme(),
        Some(ams_proto_h3::H3Error::NoError.value()),
        "§5.2 : et l'on ferme en `H3_NO_ERROR` — rien n'a mal tourné"
    );

    let stats = ecoute.await.expect("la tâche d'écoute");
    assert!(stats.is_ok(), "l'écoute rend ses comptes");
}

/// **UN PAIR BANNI N'OBTIENT PAS DE POIGNÉE DE MAIN.**
///
/// # Le défaut que cet essai ferme
///
/// SMTP, POP3, IMAP et HTTP/2 consultaient tous le videur avant de servir.
/// HTTP/3 ne le consultait JAMAIS : il comptait les écarts — `observe` était
/// bien appelé — sans jamais opposer le bannissement. Un pair banni sur les
/// quatre premières portes était servi sur la cinquième.
///
/// La couche QUIC porte pourtant la `Source` du pair EXPRESSÉMENT pour cela, et
/// sa documentation le dit : « sans elle, aucune politique par source n'est
/// possible […] et HTTP/3 servirait sans la protection contre les essais
/// répétés que HTTP/2 a déjà ».
///
/// # Pourquoi le refus est ICI, et non dans l'application HTTP/3
///
/// En HTTP/2, le refus précède la poignée de main TLS : « chiffrer pour une
/// source bannie coûte un échange de clés, ce qu'un attaquant obtiendrait
/// gratuitement ». En QUIC, cette poignée de main est DANS le transport —
/// refuser à `on_established` serait refuser après l'avoir payée.
#[tokio::test(flavor = "current_thread")]
async fn un_pair_banni_n_obtient_pas_de_poignee_de_main() {
    let atelier = atelier("banni");
    let (autorite, cert, cle) = materiel(atelier.chemin()).expect(SANS_OPENSSL);

    let mut config = ams_tls::quic_server_config(&cert, &cle).expect("la paire est bonne");
    config.alpn_protocols = ams_tls::alpn_h3();
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("une socket");
    let adresse = socket.local_addr().expect("une adresse");

    // ON BANNIT L'ADRESSE D'OÙ LE CLIENT PARLERA, en dépassant le seuil de
    // trames invalides. C'est le chemin ordinaire : le videur ne se force pas,
    // il se mérite.
    let videur = videur_permissif();
    let source = ams_guard::Source::V4([127, 0, 0, 1]);
    let seuil = ams_guard::Thresholds::DEFAULT.invalid_frames_per_minute;
    for _ in 0..=seuil {
        videur.observe(source, ams_guard::Event::InvalidFrame);
    }
    assert!(
        matches!(videur.verdict(source), ams_guard::Verdict::Banned { .. }),
        "l'essai doit partir d'une source réellement bannie"
    );

    let (fin, arret) = tokio::sync::oneshot::channel::<()>();
    let ecoute = tokio::spawn(async move {
        ams_loop_tokio::serve_quic(
            socket,
            Arc::new(config),
            &videur,
            PLACES,
            INACTIVITE,
            &mut ams_loop_tokio::SansApplication,
            async {
                let _ = arret.await;
            },
        )
        .await
    });

    let mut client = Client::new(config_client(&autorite), adresse).await;
    for _ in 0..16 {
        if !client.parler().await && !client.tls().is_handshaking() {
            break;
        }
        if !client.ecouter().await && !client.tls().is_handshaking() {
            break;
        }
    }

    assert!(
        client.tls().is_handshaking(),
        "un banni ne doit RIEN obtenir : sa poignée de main reste en suspens"
    );

    let _ = fin.send(());
    let stats = ecoute
        .await
        .expect("la tâche d'écoute")
        .expect("l'écoute rend ses comptes");
    assert_eq!(
        stats.accepted, 0,
        "aucune connexion ne s'ouvre pour un banni"
    );
    assert!(stats.banned >= 1, "et le refus est compté : {stats:?}");
    // **LE COMPTE DU VIDEUR NE SE CONFOND PAS AVEC CELUI DE LA SATURATION.**
    // Les additionner ferait lire un service plein là où le garde travaille.
    assert_eq!(stats.refused, 0, "il restait de la place : {stats:?}");
}

/// **LA BORNE DE CONNEXIONS EST CELLE QU'ON A DEMANDÉE.**
///
/// # Le défaut que cet essai ferme
///
/// Elle était gravée à 1 024 dans l'écoute QUIC, pendant que SMTP, POP3, IMAP et
/// HTTP/2 prenaient tous `max_connections` de la configuration — et que
/// `--max-connections` se documente comme disant « combien de sessions le
/// serveur mène EN MÊME TEMPS, toutes sources confondues ».
///
/// Un serveur réglé à seize connexions en tenait donc mille vingt-quatre sur
/// cette porte-là : la borne de mémoire que l'exploitant croyait avoir posée
/// valait soixante-quatre fois ce qu'il avait demandé.
///
/// # Une seule place, et deux clients
///
/// C'est le plus petit dispositif qui distingue « la borne s'applique » de « la
/// borne est ignorée ». Avec la constante d'avant, les DEUX seraient entrés.
#[tokio::test(flavor = "current_thread")]
async fn la_borne_de_connexions_est_celle_qu_on_a_demandee() {
    let atelier = atelier("borne");
    let (autorite, cert, cle) = materiel(atelier.chemin()).expect(SANS_OPENSSL);

    let mut config = ams_tls::quic_server_config(&cert, &cle).expect("la paire est bonne");
    config.alpn_protocols = ams_tls::alpn_h3();
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("une socket");
    let adresse = socket.local_addr().expect("une adresse");

    let (fin, arret) = tokio::sync::oneshot::channel::<()>();
    let ecoute = tokio::spawn(async move {
        ams_loop_tokio::serve_quic(
            socket,
            Arc::new(config),
            &videur_permissif(),
            // UNE SEULE PLACE.
            1,
            INACTIVITE,
            &mut ams_loop_tokio::SansApplication,
            async {
                let _ = arret.await;
            },
        )
        .await
    });

    // LE PREMIER ENTRE.
    let mut premier = Client::new(config_client(&autorite), adresse).await;
    for _ in 0..16 {
        if !premier.parler().await && !premier.tls().is_handshaking() {
            break;
        }
        if !premier.ecouter().await && !premier.tls().is_handshaking() {
            break;
        }
    }
    assert!(
        !premier.tls().is_handshaking(),
        "la place libre doit servir au premier"
    );

    // LE SECOND TROUVE PORTE CLOSE. §5.2.2 permet de jeter son `Initial` : lui
    // répondre coûterait autant que de le servir.
    let mut second = Client::new(config_client(&autorite), adresse).await;
    for _ in 0..16 {
        if !second.parler().await && !second.tls().is_handshaking() {
            break;
        }
        if !second.ecouter().await && !second.tls().is_handshaking() {
            break;
        }
    }
    assert!(
        second.tls().is_handshaking(),
        "le second n'avait plus de place : sa poignée de main reste en suspens"
    );

    let _ = fin.send(());
    let stats = ecoute
        .await
        .expect("la tâche d'écoute")
        .expect("l'écoute rend ses comptes");
    assert_eq!(stats.accepted, 1, "une seule place, une seule connexion");
    assert!(stats.refused >= 1, "et le refus est compté : {stats:?}");
    // **CE N'EST PAS LE VIDEUR QUI A PARLÉ**, et les deux comptes le disent
    // séparément : ici le service était plein, personne n'était banni.
    assert_eq!(stats.banned, 0, "{stats:?}");
}
