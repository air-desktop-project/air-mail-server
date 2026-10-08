// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le client de production, contre **notre propre écoute**.
//!
//! # POURQUOI LE SERVEUR D'EN FACE EST LE VRAI
//!
//! Un faux pair dirait ce que nous croyons qu'un serveur HTTP/3 dit. Celui-ci
//! refuse un ALPN qui n'est pas le sien, une section qui ne fait pas une
//! requête, un flux hors de son ordre — et c'est le seul montage qui prouve que
//! les deux moitiés de la pile se parlent vraiment.
//!
//! Ce qui reste hors de portée d'ici, et il faut le dire : **aucune route de ce
//! serveur ne rend une réponse qui ne se termine jamais.** L'essai du flux tenu
//! prouve donc qu'on n'ATTEND pas la fin — ce qui est la propriété de cette
//! crate — mais non qu'un flot sans fin se lit indéfiniment, qui est celle du
//! pair.

use std::sync::Arc;

use ams_quic_client::{SANS_OPENSSL, atelier, config_client, materiel};
use tokio::net::UdpSocket;

/// Combien de connexions l'écoute de ces essais laisse vivre.
const PLACES: usize = 16;

/// Le délai d'inactivité de l'écoute, en microsecondes.
const INACTIVITE: u64 = 30_000_000;

/// L'étiquette d'export de ces essais.
///
/// **ELLE N'A DE SENS QUE POUR EUX.** Une vraie liaison de canal appartient au
/// protocole qui l'emploie — c'est `asl_cle::ETIQUETTE_LIAISON` pour
/// `air-service-locator` —, et cette crate-ci n'en connaît aucune.
const ETIQUETTE: &[u8] = b"ams-quic-dial/essai";

// ── L'écoute : la vraie, avec la vraie API ──────────────────────────────────

/// Une API d'essai, la même doublure que celle des bancs QUIC d'`ams-loop-tokio`.
struct ApiEssai;

impl ams_loop_tokio::http::Api for ApiEssai {
    fn serve<'o>(
        &self,
        resource: ams_api::Resource<'_>,
        _method: ams_proto_http::Method,
        _account: &str,
        _appel: ams_loop_tokio::http::Appel<'_>,
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

    /// **CE BANC N'ENRÔLE PAS**, et un refus net vaut mieux qu'une réussite
    /// feinte que personne ne regarde.
    fn enrol<'o>(
        &self,
        _account: &str,
        _public_key: &str,
        _name: &str,
        _invitation: &str,
        _attestation: Option<&str>,
        _source: ams_guard::Source,
        _sortie: &'o mut [u8],
    ) -> ams_loop_tokio::http::Served<'o> {
        ams_loop_tokio::http::Served {
            status: ams_proto_http::StatusCode::NOT_IMPLEMENTED,
            ..ams_loop_tokio::http::Served::default()
        }
    }

    fn verify_device(
        &self,
        _account: &str,
        _device: &str,
        _issued_at_ms: u64,
        _challenge: &str,
        _signature: &str,
    ) -> Option<ams_api::Scope> {
        None
    }

    fn authenticate(&self, login: &str, password: &[u8]) -> Option<ams_api::Scope> {
        (login == "marc" && password == b"secret").then(|| {
            ams_api::Scope::one(ams_api::Area::Mail, ams_api::Rights::Read)
                .with(ams_api::Area::Observe, ams_api::Rights::Read)
        })
    }

    fn refused(
        &self,
        _account: &str,
        _door: ams_loop_tokio::http::Door,
        _source: ams_guard::Source,
    ) {
    }

    fn nonce(&self) -> u64 {
        7
    }

    fn open_session(
        &self,
        _login: &str,
        _nonce: u64,
        _expiry: u64,
        _maintenant: u64,
        _device: Option<&str>,
        _source: ams_guard::Source,
    ) {
    }

    fn admit(
        &self,
        _login: &str,
        _nonce: u64,
        _maintenant: u64,
    ) -> ams_loop_tokio::http::Admission {
        ams_loop_tokio::http::Admission::Open
    }

    fn close_session(&self, _login: &str, _nonce: u64) -> bool {
        true
    }
}

/// Ce qu'une écoute lancée rend à l'essai : où la joindre, et comment l'arrêter.
struct Banc {
    adresse: std::net::SocketAddr,
    autorite: Vec<u8>,
    fin: tokio::sync::oneshot::Sender<()>,
    tache: tokio::task::JoinHandle<(u64, u64)>,
}

/// Lève une écoute QUIC qui sert l'API, sur le bouclage, sur un port libre.
async fn lever(cas: &str) -> Option<(Banc, ams_quic_client::Atelier)> {
    let atelier = atelier(cas);
    let (autorite, cert, cle) = materiel(atelier.chemin())?;

    let mut config = ams_tls::quic_server_config(&cert, &cle).expect("la paire est bonne");
    config.alpn_protocols = ams_tls::alpn_h3();
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("une socket");
    let adresse = socket.local_addr().expect("une adresse");

    let (fin, arret) = tokio::sync::oneshot::channel::<()>();
    let tache = tokio::spawn(async move {
        let session = ams_session::http::Http::new(
            ams_api::Key::new(b"une clef de trente-deux octets!!").expect("trente-deux octets"),
            3_600 * 1_000_000,
        )
        .expect("une durée licite");
        let garde = ams_loop_tokio::SharedGuard::new(64, ams_guard::Thresholds::DEFAULT);
        let api = ApiEssai;
        let mut application = ams_loop_tokio::h3::Http3Application::new(&session, &api, &garde);
        let _ = ams_loop_tokio::serve_quic(
            socket,
            Arc::new(config),
            &garde,
            PLACES,
            INACTIVITE,
            &mut application,
            async {
                let _ = arret.await;
            },
        )
        .await;
        application.comptes()
    });

    Some((
        Banc {
            adresse,
            autorite,
            fin,
            tache,
        },
        atelier,
    ))
}

impl Banc {
    /// Arrête l'écoute et rend ce qu'elle a compté : servies, refusées.
    async fn arreter(self) -> (u64, u64) {
        let _ = self.fin.send(());
        self.tache.await.expect("la tâche d'écoute")
    }
}

/// L'aléa de ces essais : constant, parce qu'un essai qui change de tirage à
/// chaque exécution ne se rejoue pas. **Ce n'est JAMAIS acceptable en
/// production** — §5.2 de RFC 9001 dérive les clés `Initial` de cet
/// identifiant-là.
fn alea_d_essai() -> [u8; 16] {
    [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x21, 0x43, 0x65, 0x87, 0xa9, 0xcb, 0xed,
        0x0f,
    ]
}

/// Joint ce banc avec le client de production.
async fn joindre(banc: &Banc) -> Result<ams_quic_dial::Appel, ams_quic_dial::Faute> {
    ams_quic_dial::Appel::ouvrir(
        banc.adresse,
        rustls::pki_types::ServerName::try_from("localhost").expect("un nom"),
        "localhost",
        config_client(&banc.autorite),
        &alea_d_essai,
    )
    .await
}

/// Obtient un jeton d'administration, par la même porte que les autres bancs.
async fn jeton(appel: &mut ams_quic_dial::Appel) -> String {
    let reponse = appel
        .requete(
            "POST",
            "/v1/tokens",
            &[(b"content-type", ams_api::JSON_MEDIA_TYPE.as_bytes())],
            br#"{"login":"marc","password":"secret"}"#,
        )
        .await
        .expect("l'échange d'identifiants aboutit");
    let texte = String::from_utf8_lossy(&reponse.corps).to_string();
    assert!(
        texte.contains(r#"{"token":""#),
        "un jeton devait revenir : {texte}"
    );
    let debut = texte.find(':').expect("un premier champ").saturating_add(2);
    let fin = texte
        .get(debut..)
        .and_then(|reste| reste.find('"'))
        .expect("une fin de chaîne")
        .saturating_add(debut);
    texte
        .get(debut..fin)
        .expect("les deux bornes viennent du texte")
        .to_owned()
}

// ── Les essais ──────────────────────────────────────────────────────────────

/// **UNE REQUÊTE DU CLIENT DE PRODUCTION TRAVERSE TOUTE LA CHAÎNE.**
///
/// Socket, QUIC, TLS 1.3, ALPN `h3`, les trois flux critiques, les réglages,
/// QPACK, la session, l'API — et la réponse qui revient. Jusqu'ici, seul le
/// harnais d'essai savait faire ce trajet ; le code livré ne le savait pas.
#[tokio::test(flavor = "current_thread")]
async fn une_requete_du_client_de_production_traverse_toute_la_chaine() {
    let Some((banc, _atelier)) = lever("dial-chaine").await else {
        panic!("{SANS_OPENSSL}");
    };

    let mut appel = joindre(&banc).await.expect("la connexion s'ouvre");

    assert_eq!(
        appel.alpn(),
        Some(b"h3".as_slice()),
        "l'ALPN retenu doit être celui de l'écoute"
    );

    let jeton = jeton(&mut appel).await;

    let reponse = appel
        .requete(
            "GET",
            "/v1/health",
            &[(b"authorization", format!("Bearer {jeton}").as_bytes())],
            &[],
        )
        .await
        .expect("la ressource répond");

    assert_eq!(reponse.statut, ams_proto_http::StatusCode::OK);
    assert!(
        String::from_utf8_lossy(&reponse.corps).contains("\"etat\""),
        "la réponse de l'API est arrivée : {:?}",
        String::from_utf8_lossy(&reponse.corps)
    );

    appel.fermer().await.expect("la fermeture s'annonce");

    let (servies, refusees) = banc.arreter().await;
    assert_eq!(servies, 2, "deux requêtes servies");
    assert_eq!(refusees, 0, "et pas un refus");
}

/// **LA LIAISON DE CANAL S'EXPORTE, ET ELLE EST PROPRE À LA CONNEXION.**
///
/// C'est ce qui permet de signer en liant la signature au canal (RFC 8446
/// §7.5), et c'est ce dont `air-service-locator` dépend pour prouver la clé
/// d'une machine. Deux connexions ne doivent pas rendre la même valeur — sinon
/// une signature prise sur l'une vaudrait sur l'autre, ce qui est exactement ce
/// que la liaison existe pour empêcher.
#[tokio::test(flavor = "current_thread")]
async fn la_liaison_de_canal_differe_d_une_connexion_a_l_autre() {
    let Some((banc, _atelier)) = lever("dial-liaison").await else {
        panic!("{SANS_OPENSSL}");
    };

    let mut premier = joindre(&banc).await.expect("la première s'ouvre");
    let une = premier.exporter(ETIQUETTE, None).expect("elle s'exporte");

    let mut second = joindre(&banc).await.expect("la seconde s'ouvre");
    let autre = second.exporter(ETIQUETTE, None).expect("elle s'exporte");

    assert_eq!(une.len(), 32, "trente-deux octets, comme RFC 8446 §7.5");
    assert_ne!(une, [0_u8; 32], "et non le tampon de passage");
    assert_ne!(
        une, autre,
        "DEUX CONNEXIONS NE DOIVENT PAS RENDRE LA MÊME LIAISON : une signature \
         prise sur l'une vaudrait sur l'autre"
    );

    // **UN CONTEXTE CHANGE LA VALEUR**, sur la même connexion : c'est la
    // seconde moitié de §7.5, et c'est ce qui permet à deux usages de dériver
    // sans se confondre.
    let avec = premier
        .exporter(ETIQUETTE, Some(b"autre usage"))
        .expect("elle s'exporte");
    assert_ne!(une, avec, "le contexte doit entrer dans la dérivation");

    premier.fermer().await.expect("la fermeture s'annonce");
    second.fermer().await.expect("la fermeture s'annonce");
    let _ = banc.arreter().await;
}

/// **UN FLUX TENU NE FAIT PAS ATTENDRE SON OUVERTURE.**
///
/// `tenir` rend le numéro du flux sans attendre la réponse : c'est ce qui rend
/// lisible une réponse qui ne se termine jamais, et `requete` l'attendrait pour
/// toujours. Ce que cet essai prouve est qu'on n'attend pas — la route servie
/// ici, elle, se termine, et son corps s'accumule donc jusqu'au bout.
#[tokio::test(flavor = "current_thread")]
async fn un_flux_tenu_ne_fait_pas_attendre_son_ouverture() {
    let Some((banc, _atelier)) = lever("dial-tenu").await else {
        panic!("{SANS_OPENSSL}");
    };

    let mut appel = joindre(&banc).await.expect("la connexion s'ouvre");
    let jeton = jeton(&mut appel).await;

    let flux = appel
        .tenir(
            "GET",
            "/v1/health",
            &[(b"authorization", format!("Bearer {jeton}").as_bytes())],
        )
        .await
        .expect("le flux s'ouvre");

    // **RIEN N'EST ENCORE ARRIVÉ**, et c'est tout le propos : la main est
    // rendue avant la réponse.
    assert!(
        !appel.fini(flux),
        "`tenir` a attendu la fin, ce qu'elle ne doit jamais faire"
    );

    let mut recueilli = Vec::new();
    for _ in 0..40_u32 {
        appel.entretenir(100).await.expect("l'entretien tourne");
        if let Some(morceau) = appel.recueillir(flux) {
            recueilli.extend_from_slice(&morceau);
        }
        if appel.fini(flux) {
            break;
        }
    }

    assert!(appel.fini(flux), "le flux doit finir par arriver en entier");
    assert_eq!(appel.statut(flux), Some(ams_proto_http::StatusCode::OK));
    assert!(
        String::from_utf8_lossy(&recueilli).contains("\"etat\""),
        "le corps s'est accumulé par `recueillir` : {:?}",
        String::from_utf8_lossy(&recueilli)
    );

    // **ELLE PREND, ELLE NE COPIE PAS** : ce qui a été recueilli ne revient pas.
    //
    // Et elle rend `Some` d'une tranche VIDE, non `None` : le flux est toujours
    // connu. Confondre les deux ferait prendre un flux tenu pour un flux
    // disparu — c'est l'hypothèse que la première écriture de cet essai
    // portait, et c'est elle qui est tombée.
    assert_eq!(
        appel.recueillir(flux).as_deref(),
        Some([].as_slice()),
        "`recueillir` vide ce qu'elle rend, et le flux reste connu"
    );
    assert!(
        appel
            .recueillir(ams_proto_quic::StreamId::new(4_000).expect("un numéro licite"))
            .is_none(),
        "`None` est réservé à un flux INCONNU"
    );

    appel.fermer().await.expect("la fermeture s'annonce");
    let _ = banc.arreter().await;
}

/// **UN ALPN QUE L'ÉCOUTE N'OFFRE PAS NE MONTE PAS DE CONNEXION.**
///
/// C'est voulu, et c'est une protection : une connexion montée sur un protocole
/// qu'aucun des deux ne sait parler se découvrirait à la première requête, là
/// où elle doit se découvrir à la poignée de main.
#[tokio::test(flavor = "current_thread")]
async fn un_alpn_que_l_ecoute_n_offre_pas_fait_echouer_la_poignee() {
    let Some((banc, _atelier)) = lever("dial-alpn").await else {
        panic!("{SANS_OPENSSL}");
    };

    let config = {
        let mut racines = rustls::RootCertStore::empty();
        for der in
            <rustls::pki_types::CertificateDer as rustls::pki_types::pem::PemObject>::pem_slice_iter(
                &banc.autorite,
            )
        {
            racines
                .add(der.expect("certificat lisible"))
                .expect("racine");
        }
        let mut config =
            rustls::ClientConfig::builder_with_provider(Arc::new(ams_tls::provider_quic()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("TLS 1.3")
                .with_root_certificates(racines)
                .with_no_client_auth();
        config.alpn_protocols = vec![b"ce-protocole-n-existe-pas".to_vec()];
        Arc::new(config)
    };

    let refus = ams_quic_dial::Appel::ouvrir(
        banc.adresse,
        rustls::pki_types::ServerName::try_from("localhost").expect("un nom"),
        "localhost",
        config,
        &alea_d_essai,
    )
    .await;

    assert!(
        refus.is_err(),
        "un ALPN inconnu de l'écoute ne doit pas monter de connexion"
    );

    let _ = banc.arreter().await;
}

/// **FERMER DEUX FOIS NE DIT RIEN DE PLUS, ET N'EST PAS UNE FAUTE.**
///
/// Un appelant qui ferme puis qui est repris par un chemin d'erreur fermerait
/// deux fois ; refuser la seconde l'obligerait à retenir ce qu'il a déjà fait,
/// pour un geste qui est idempotent par nature.
#[tokio::test(flavor = "current_thread")]
async fn fermer_deux_fois_ne_dit_rien_de_plus() {
    let Some((banc, _atelier)) = lever("dial-fermeture").await else {
        panic!("{SANS_OPENSSL}");
    };

    let mut appel = joindre(&banc).await.expect("la connexion s'ouvre");
    assert!(appel.vivante(), "elle vient de s'ouvrir");

    appel.fermer().await.expect("la première fermeture");
    assert!(!appel.vivante(), "et elle ne l'est plus");
    appel.fermer().await.expect("la seconde ne dit rien");

    // **ET PLUS RIEN NE S'Y FAIT**, plutôt qu'une requête qui attendrait son
    // délai avant de rendre la main.
    assert!(
        matches!(
            appel.requete("GET", "/v1/health", &[], &[]).await,
            Err(ams_quic_dial::Faute::Fermee)
        ),
        "une requête sur une connexion fermée doit le dire tout de suite"
    );

    let _ = banc.arreter().await;
}
