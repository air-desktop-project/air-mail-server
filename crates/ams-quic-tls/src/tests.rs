// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Une VRAIE poignée de main QUIC, menée jusqu'au bout.
//!
//! # POURQUOI UN CLIENT `rustls` EN FACE, ET NON UN FAUX
//!
//! Un faux client dirait ce que nous croyons qu'un client dit. Celui-ci ne sait
//! rien de nos hypothèses : il refuse un `ServerHello` arrivé au mauvais niveau,
//! il refuse une transcription incomplète, et il refuse un ALPN qui ne recouvre
//! pas le sien. **C'est exactement l'ensemble des fautes que ce pont peut
//! commettre**, et aucune ne se verrait dans un aller-retour avec soi-même.
//!
//! # ET IL FAUT UN VRAI CERTIFICAT
//!
//! Pour la même raison que `ams-tls/tests/materiel.rs` : `rustls` ne monte pas
//! de configuration serveur sans paire valide, et rien dans ce dépôt ne sait en
//! fabriquer une. Le test **échoue** au lieu de se sauter quand `openssl`
//! manque — un test sauté ferait tomber le gate des 100 % (C2) quelques secondes
//! plus tard, sans dire pourquoi.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use ams_quic::Level;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::quic::{ClientConnection, KeyChange, Version};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use super::{Error, Reason, Server, generic_close_code};

const SANS_OPENSSL: &str = "ce test EXIGE `openssl` : sans lui, la poignée de main réelle n'est \
                            pas couverte, et le gate des 100 % (C2) échouerait quelques secondes \
                            plus tard sans en dire la raison";

/// Les paramètres de transport, tels qu'ils voyagent (§8.2).
///
/// Leur contenu ne concerne pas ce module : il les transporte sans les lire.
const NOS_PARAMETRES: &[u8] = b"\x01\x04\x80\x00\x75\x30";
const SES_PARAMETRES: &[u8] = b"\x04\x04\x80\x0c\x00\x00";

/// Un répertoire par test — `cargo test` les lance en parallèle.
struct Atelier(PathBuf);

impl Drop for Atelier {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn atelier(nom: &str) -> Atelier {
    let chemin =
        std::env::temp_dir().join(std::format!("ams-quic-tls-{nom}-{}", std::process::id()));
    std::fs::create_dir_all(&chemin).expect("répertoire temporaire");
    Atelier(chemin)
}

/// Fabrique une autorité, puis une paire serveur qu'elle signe.
///
/// # POURQUOI PAS UN SIMPLE AUTO-SIGNÉ
///
/// C'est ce que faisait la première version, et le client `rustls` l'a refusé :
/// `CaUsedAsEndEntity`. Un certificat produit par `openssl req -x509` porte
/// `CA:TRUE` ; **une autorité n'est pas un serveur**, et webpki refuse de la
/// traiter comme tel — à raison, puisqu'une autorité peut signer n'importe quel
/// nom.
///
/// Le refus vient donc du matériel d'essai, pas du pont. Mais il fallait
/// l'apprendre pour de bon : une chaîne bricolée aurait fait échouer la poignée
/// de main pour une raison qui n'a rien à voir avec ce qu'on éprouve ici.
///
/// Rend (le certificat de l'autorité, le certificat serveur, la clé serveur).
fn materiel(repertoire: &Path) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let ca_cert = repertoire.join("ca.pem");
    let ca_cle = repertoire.join("ca.key");
    let srv_cle = repertoire.join("srv.key");
    let srv_csr = repertoire.join("srv.csr");
    let srv_cert = repertoire.join("srv.pem");
    let extensions = repertoire.join("srv.ext");

    reussit(
        Command::new("openssl")
            .args(["req", "-x509", "-newkey", "ec"])
            .args(["-pkeyopt", "ec_paramgen_curve:P-256"])
            .args(["-nodes", "-days", "1", "-subj", "/CN=ams-essai-autorite"])
            .arg("-keyout")
            .arg(&ca_cle)
            .arg("-out")
            .arg(&ca_cert),
    )?;
    reussit(
        Command::new("openssl")
            .args(["req", "-new", "-newkey", "ec"])
            .args(["-pkeyopt", "ec_paramgen_curve:P-256"])
            .args(["-nodes", "-subj", "/CN=localhost"])
            .arg("-keyout")
            .arg(&srv_cle)
            .arg("-out")
            .arg(&srv_csr),
    )?;
    // `CA:FALSE` est ce qui distingue un serveur d'une autorité, et
    // `subjectAltName` est le seul nom que webpki regarde depuis longtemps.
    std::fs::write(
        &extensions,
        "subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\n\
         extendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\n",
    )
    .ok()?;
    reussit(
        Command::new("openssl")
            .args(["x509", "-req", "-days", "1"])
            .arg("-in")
            .arg(&srv_csr)
            .arg("-CA")
            .arg(&ca_cert)
            .arg("-CAkey")
            .arg(&ca_cle)
            .arg("-CAcreateserial")
            .arg("-extfile")
            .arg(&extensions)
            .arg("-out")
            .arg(&srv_cert),
    )?;

    Some((
        std::fs::read(&ca_cert).ok()?,
        std::fs::read(&srv_cert).ok()?,
        std::fs::read(&srv_cle).ok()?,
    ))
}

/// Cette commande a-t-elle abouti ?
fn reussit(commande: &mut Command) -> Option<()> {
    commande.output().ok()?.status.success().then_some(())
}

/// La configuration serveur, avec l'ALPN qu'on annonce.
fn config_serveur(cert: &[u8], cle: &[u8], alpn: Vec<Vec<u8>>) -> Arc<ServerConfig> {
    // **`quic_server_config`, ET NON `server_config`** : le fournisseur ordinaire
    // ne sait pas chiffrer un paquet QUIC, et c'est précisément ce que
    // `Reason::NoQuicSuite` reproche quand on l'oublie.
    let mut config = ams_tls::quic_server_config(cert, cle).expect("la paire est bonne");
    config.alpn_protocols = alpn;
    Arc::new(config)
}

/// La configuration client, qui fait confiance à ce certificat-là.
fn config_client(cert: &[u8], alpn: Vec<Vec<u8>>) -> Arc<ClientConfig> {
    let mut racines = RootCertStore::empty();
    for der in CertificateDer::pem_slice_iter(cert) {
        racines
            .add(der.expect("certificat lisible"))
            .expect("racine ajoutable");
    }
    let mut config = ClientConfig::builder_with_provider(Arc::new(ams_tls::provider_quic()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_root_certificates(racines)
        .with_no_client_auth();
    config.alpn_protocols = alpn;
    Arc::new(config)
}

/// Le niveau `rustls` que ce changement de clés installe.
fn niveau_du_changement(change: &KeyChange) -> Level {
    match change {
        KeyChange::Handshake { .. } => Level::Handshake,
        KeyChange::OneRtt { .. } => Level::OneRtt,
    }
}

/// Un client d'essai : le pendant de [`super::Server`], écrit à la main pour
/// que le test ne se serve pas de ce qu'il éprouve.
///
/// # SON NIVEAU D'ÉMISSION PERSISTE, ET C'EST TOUT LE POINT
///
/// La première version le remettait à `Initial` à chaque tour, et le `Finished`
/// du client partait donc au niveau `Initial` — que le serveur refusait, à
/// raison, comme « du neuf à un niveau déjà dépassé ». **La faute était dans le
/// test, pas dans le pont**, et il a fallu instrumenter pour le voir : les deux
/// symptômes sont identiques.
struct Client {
    tls: ClientConnection,
    /// Le niveau où il écrit — il ne redescend jamais.
    niveau: Level,
    /// Les décalages atteints dans chaque flux `CRYPTO`.
    decalages: [u64; 4],
}

impl Client {
    fn new(config: Arc<ClientConfig>) -> Self {
        Self {
            tls: ClientConnection::new(
                config,
                Version::V1,
                ServerName::try_from("localhost").expect("un nom"),
                SES_PARAMETRES.to_vec(),
            )
            .expect("le client se construit"),
            niveau: Level::Initial,
            decalages: [0; 4],
        }
    }

    /// Redemande des octets à TLS et les remet au serveur.
    ///
    /// §4.1.3, littéralement : « Each time that TLS is provided with new data,
    /// new handshake bytes are requested from TLS. »
    fn parler(&mut self, serveur: &mut Server) -> Result<(), Error> {
        loop {
            let mut octets = Vec::new();
            let change = self.tls.write_hs(&mut octets);
            if octets.is_empty() && change.is_none() {
                return Ok(());
            }
            if !octets.is_empty() {
                let rang = self.niveau as usize;
                serveur.on_crypto(self.niveau, self.decalages[rang], &octets)?;
                self.decalages[rang] = self.decalages[rang]
                    .checked_add(u64::try_from(octets.len()).expect("tient"))
                    .expect("pas de débordement");
            }
            if let Some(change) = change.as_ref() {
                self.niveau = niveau_du_changement(change);
            }
        }
    }

    /// Écoute ce que le serveur dit.
    fn ecouter(&mut self, octets: &[u8]) {
        if !octets.is_empty() {
            self.tls
                .read_hs(octets)
                .expect("le client accepte ce que le serveur dit");
        }
    }
}

/// Mène la poignée de main jusqu'à ce que plus rien n'avance.
fn conduire(serveur: &mut Server, client: &mut Client) -> Result<(), Error> {
    client.parler(serveur)?;
    for _ in 0..8 {
        let mut a_dit = false;
        while let Some(envoi) = serveur.next_flight()? {
            a_dit = true;
            client.ecouter(envoi.bytes());
            // Après chaque donnée remise, on redemande — §4.1.3.
            client.parler(serveur)?;
        }
        if !a_dit {
            return Ok(());
        }
    }
    panic!("la poignée de main tourne en rond");
}

/// **UNE POIGNÉE DE MAIN COMPLÈTE, ET C'EST LE CLIENT QUI JUGE.**
///
/// Si le pont envoyait le `ServerHello` au mauvais niveau, remettait les octets
/// dans le désordre, ou en perdait un seul, ce client-là le refuserait.
#[test]
fn une_poignee_de_main_va_jusqu_au_bout() {
    let atelier = atelier("poignee-complete");
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);

    let mut serveur = Server::new(
        config_serveur(&cert, &cle, std::vec![b"h3".to_vec()]),
        NOS_PARAMETRES.to_vec(),
    )
    .expect("le fournisseur sait chiffrer QUIC");
    assert!(!serveur.is_complete());
    assert_eq!(serveur.read_level(), Level::Initial);
    assert_eq!(serveur.write_level(), Level::Initial);

    let mut client = Client::new(config_client(&autorite, std::vec![b"h3".to_vec()]));
    conduire(&mut serveur, &mut client).expect("la poignée de main aboutit");

    assert!(serveur.is_complete(), "la poignée de main doit aboutir");
    assert!(
        !client.tls.is_handshaking(),
        "le client aussi doit avoir fini"
    );

    // §4.9 : les données neuves partent au plus haut niveau disponible.
    assert_eq!(serveur.write_level(), Level::OneRtt);
    // §4.1.2 et §4.6.1 : une fois la poignée confirmée, ce qui reste à lire —
    // les tickets de session — voyage en `1-RTT`.
    assert_eq!(serveur.read_level(), Level::OneRtt);

    // §3.1 de RFC 9114 : le protocole applicatif se choisit par ALPN.
    assert_eq!(serveur.alpn(), Some(&b"h3"[..]));
    serveur.check_alpn().expect("h3 a bien été négocié");
    assert_eq!(client.tls.alpn_protocol(), Some(&b"h3"[..]));

    // §8.2 : les paramètres du pair sont AUTHENTIFIÉS par la poignée de main.
    assert_eq!(serveur.peer_parameters(), Some(SES_PARAMETRES));
    assert_eq!(client.tls.quic_transport_parameters(), Some(NOS_PARAMETRES));

    // Et rien de secret ne s'imprime.
    let dit = std::format!("{serveur:?}");
    assert!(dit.contains("complete: true"), "{dit}");
}

/// **UN CLIENT QUI NE PARLE PAS `h3` N'EST PAS SERVI** (§3.1 de RFC 9114).
///
/// `rustls` refuse de lui-même, et l'alerte qu'il produit devient le code de
/// fermeture — c'est le chemin de §4.8 pris pour de bon.
#[test]
fn un_client_sans_h3_n_est_pas_servi() {
    let atelier = atelier("alpn-refuse");
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);

    let mut serveur = Server::new(
        config_serveur(&cert, &cle, std::vec![b"h3".to_vec()]),
        NOS_PARAMETRES.to_vec(),
    )
    .expect("constructible");
    // Tant que rien n'est négocié, la ceinture refuse.
    assert_eq!(
        serveur
            .check_alpn()
            .expect_err("rien n'est négocié")
            .reason(),
        Reason::WrongAlpn
    );
    assert_eq!(
        Error::new(Reason::WrongAlpn).close_code(),
        0x0178,
        "§4.8 : 0x0100 + no_application_protocol (120)"
    );

    let mut client = Client::new(config_client(&autorite, std::vec![b"h2".to_vec()]));
    client
        .parler(&mut serveur)
        .expect("le ClientHello se range comme un autre");

    let issue = serveur
        .next_flight()
        .expect_err("un client qui ne parle pas h3 n'est pas servi");
    // §6.2 de RFC 8446 : `no_application_protocol` vaut 120.
    assert_eq!(issue.reason(), Reason::Tls(120));
    assert_eq!(issue.close_code(), 0x0178);
    assert!(!serveur.is_complete());
}

/// **LE FOURNISSEUR ORDINAIRE NE SAIT PAS CHIFFRER QUIC**, et le pont le dit.
///
/// C'est exactement ce qui bloquait HTTP/3 avant que `provider_quic()` existe :
/// `rustls` répondait « at least one ciphersuite must support QUIC », dans un
/// `Error::General` sans variante dédiée.
#[test]
fn un_fournisseur_sans_quic_se_refuse_a_la_construction() {
    let atelier = atelier("sans-quic");
    let (_autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);

    // Celle-ci monte sur le fournisseur ORDINAIRE — c'est la faute qu'on éprouve.
    let mut config = ams_tls::server_config(&cert, &cle).expect("la paire est bonne");
    config.alpn_protocols = std::vec![b"h3".to_vec()];

    let issue = Server::new(Arc::new(config), NOS_PARAMETRES.to_vec())
        .expect_err("le fournisseur ordinaire ne sait pas chiffrer QUIC");
    assert_eq!(issue.reason(), Reason::NoQuicSuite);
    // §20.1 : `INTERNAL_ERROR`. Le pair n'y est pour rien.
    assert_eq!(issue.close_code(), 0x01);
    assert!(
        std::format!("{issue}").contains("provider_quic"),
        "le message doit dire quoi faire : {issue}"
    );
}

/// **UNE TRAME `CRYPTO` EN `0-RTT` CONDAMNE** (§8.3), et le pont la refuse
/// avant même de la remettre à TLS.
#[test]
fn un_crypto_en_zero_rtt_condamne() {
    let atelier = atelier("zero-rtt");
    let (_autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let mut serveur = Server::new(
        config_serveur(&cert, &cle, std::vec![b"h3".to_vec()]),
        NOS_PARAMETRES.to_vec(),
    )
    .expect("constructible");

    let issue = serveur
        .on_crypto(Level::ZeroRtt, 0, b"n'importe quoi")
        .expect_err("§8.3 le nomme");
    assert_eq!(
        issue.reason(),
        Reason::Quic(ams_quic::Reason::CryptoInZeroRtt)
    );
    // §20.1 : `PROTOCOL_VIOLATION`.
    assert_eq!(issue.close_code(), 0x0a);
}

/// Plus d'octets `CRYPTO` hors d'ordre qu'on n'en retient (§7.5 de RFC 9000).
#[test]
fn plus_de_crypto_qu_on_n_en_retient() {
    let atelier = atelier("crypto-deborde");
    let (_autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let mut serveur = Server::new(
        config_serveur(&cert, &cle, std::vec![b"h3".to_vec()]),
        NOS_PARAMETRES.to_vec(),
    )
    .expect("constructible");

    let issue = serveur
        .on_crypto(Level::Initial, 1_000_000, b"loin")
        .expect_err("hors fenêtre");
    assert_eq!(
        issue.reason(),
        Reason::Quic(ams_quic::Reason::CryptoBufferExceeded)
    );
    // §20.1 : `CRYPTO_BUFFER_EXCEEDED`.
    assert_eq!(issue.close_code(), 0x0d);
}

/// **DES OCTETS INTELLIGIBLES MAIS FAUX FONT PRODUIRE UNE ALERTE**, et l'alerte
/// devient un code de fermeture (§4.8).
#[test]
fn ce_que_tls_refuse_devient_un_code_de_fermeture() {
    let atelier = atelier("tls-refuse");
    let (_autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let mut serveur = Server::new(
        config_serveur(&cert, &cle, std::vec![b"h3".to_vec()]),
        NOS_PARAMETRES.to_vec(),
    )
    .expect("constructible");

    // Un message de poignée de main de type inconnu, avec une longueur juste :
    // TLS le lit, ne sait qu'en faire, et refuse.
    serveur
        .on_crypto(Level::Initial, 0, &[0xff, 0x00, 0x00, 0x04, 1, 2, 3, 4])
        .expect("rangeable : la grammaire de CRYPTO ne juge pas le contenu");
    let issue = serveur
        .next_flight()
        .expect_err("TLS ne sait pas quoi faire de cela");
    // Quelle que soit l'alerte, le code est dans la plage réservée à
    // `CRYPTO_ERROR` — c'est cela que §4.8 garantit.
    assert!(
        (0x0100..=0x01ff).contains(&issue.close_code()),
        "{} n'est pas dans la plage CRYPTO_ERROR",
        issue.close_code()
    );
    assert!(matches!(
        issue.reason(),
        Reason::Tls(_) | Reason::TlsSansAlerte
    ));
}

/// Le code générique de §4.8, quand `rustls` refuse sans alerte.
#[test]
fn le_code_generique_est_handshake_failure() {
    // §4.8 le nomme lui-même : « handshake_failure (0x0128 in QUIC) ».
    assert_eq!(generic_close_code(), 0x0128);
    assert_eq!(
        Error::new(Reason::TlsSansAlerte).close_code(),
        generic_close_code()
    );
}

/// **RIEN NE SORT D'UN NIVEAU QUI NE PORTE PAS DE `CRYPTO`.**
///
/// TLS ne lit jamais en `0-RTT` ; si le niveau de lecture y était, nourrir
/// devrait ne rien faire plutôt que d'aller chercher une fenêtre qui n'existe
/// pas.
#[test]
fn nourrir_ne_va_pas_chercher_de_fenetre_pour_zero_rtt() {
    let atelier = atelier("zero-rtt-nourrir");
    let (_autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let mut serveur = Server::new(
        config_serveur(&cert, &cle, std::vec![b"h3".to_vec()]),
        NOS_PARAMETRES.to_vec(),
    )
    .expect("constructible");

    // Un serveur qui n'a rien reçu n'a rien à dire.
    assert!(
        serveur.next_flight().expect("rien à refuser").is_none(),
        "TLS ne parle pas le premier, côté serveur"
    );
    assert_eq!(serveur.read_level(), Level::Initial);
}

/// **LE `ServerHello` PART EN `Initial`, ET LE RESTE EN `Handshake`.**
///
/// C'est LA décision de ce pont, et celle qu'un `write_hs` mal lu ferait rater :
/// le changement de clés rendu par un appel ne vaut que pour les octets
/// SUIVANTS. Le client refuserait un `ServerHello` arrivé en `Handshake`, mais
/// il le refuserait pour une raison illisible ; ici, on le constate directement.
#[test]
fn le_serveur_hello_part_en_initial() {
    let atelier = atelier("niveaux-des-vols");
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let mut serveur = Server::new(
        config_serveur(&cert, &cle, std::vec![b"h3".to_vec()]),
        NOS_PARAMETRES.to_vec(),
    )
    .expect("constructible");
    let mut client = Client::new(config_client(&autorite, std::vec![b"h3".to_vec()]));
    client
        .parler(&mut serveur)
        .expect("le ClientHello se range");

    let mut vus = Vec::new();
    while let Some(mut envoi) = serveur.next_flight().expect("le serveur avance") {
        vus.push((envoi.level(), envoi.bytes().len(), envoi.change().is_some()));
        // Les clés se reprennent une fois, et une seule : elles vont à la
        // protection de paquet, qui en devient seule propriétaire.
        let reprise = envoi.take_change().is_some();
        assert_eq!(reprise, vus.last().expect("on vient d'en pousser un").2);
        assert!(
            envoi.take_change().is_none(),
            "les clés ne se reprennent pas deux fois"
        );
        // Et rien de secret ne s'imprime.
        let dit = std::format!("{envoi:?}");
        assert!(dit.contains("Flight"), "{dit}");
        assert!(!dit.contains("Keys"), "des clés dans un Debug : {dit}");
        client.ecouter(envoi.bytes());
    }

    // Deux vols : le `ServerHello` en clair, puis tout le reste chiffré.
    assert_eq!(vus.len(), 2, "{vus:?}");
    assert_eq!(vus[0].0, Level::Initial, "le ServerHello part en Initial");
    assert!(vus[0].1 > 0);
    assert!(vus[0].2, "et il installe les clés de Handshake");
    assert_eq!(
        vus[1].0,
        Level::Handshake,
        "le certificat et le Finished partent en Handshake"
    );
    assert!(vus[1].1 > 0);
    assert!(vus[1].2, "et ils installent celles de 1-RTT");
}

/// **UNE CONFIGURATION QUE `rustls` REFUSE POUR UNE AUTRE RAISON.**
///
/// §4.6.1 de RFC 9001 : sur QUIC, `max_early_data_size` ne peut valoir que zéro
/// ou 2^32-1. Une autre valeur fait refuser la connexion — et ce refus-là n'a
/// rien à voir avec les suites, donc il ne doit pas s'appeler `NoQuicSuite`.
#[test]
fn une_autre_faute_de_configuration_ne_s_appelle_pas_no_quic_suite() {
    let atelier = atelier("early-data");
    let (_autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let mut config = ams_tls::quic_server_config(&cert, &cle).expect("la paire est bonne");
    config.alpn_protocols = std::vec![b"h3".to_vec()];
    config.max_early_data_size = 5;

    let issue = Server::new(Arc::new(config), NOS_PARAMETRES.to_vec())
        .expect_err("§4.6.1 ne permet que zéro ou 2^32-1");
    assert_eq!(issue.reason(), Reason::TlsSansAlerte);
    assert_eq!(issue.close_code(), generic_close_code());
}

/// **DES OCTETS `Initial` NON LUS QUAND LES CLÉS DE `Handshake` ARRIVENT.**
///
/// §4.1.3 : « When TLS provides keys for a higher encryption level, if there is
/// data from a previous encryption level that TLS has not consumed, this MUST be
/// treated as a connection error of type PROTOCOL_VIOLATION. »
///
/// **CE N'EST PAS UNE POINTILLERIE** : ces octets-là sont entrés dans la
/// transcription du pair et pas dans la nôtre. Les ignorer ferait diverger ce
/// que les deux côtés ont haché — précisément ce que la poignée de main est
/// censée rendre impossible. C'est aussi la forme d'une attaque : bourrer le
/// niveau `Initial`, qui n'est authentifié par personne.
#[test]
fn des_octets_initial_non_lus_condamnent_a_l_installation() {
    let atelier = atelier("initial-non-lus");
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let mut serveur = Server::new(
        config_serveur(&cert, &cle, std::vec![b"h3".to_vec()]),
        NOS_PARAMETRES.to_vec(),
    )
    .expect("constructible");
    let mut client = Client::new(config_client(&autorite, std::vec![b"h3".to_vec()]));
    client
        .parler(&mut serveur)
        .expect("le ClientHello se range");

    // Un octet de plus, derrière un trou : il ne sera jamais contigu, donc
    // jamais consommé — et il est pourtant bien arrivé.
    serveur
        .on_crypto(Level::Initial, 3_000, b"!")
        .expect("un décalage en avance se range : c'est le désordre du réseau");

    let issue = serveur
        .next_flight()
        .expect_err("§4.1.3 refuse d'installer par-dessus des octets non lus");
    assert_eq!(
        issue.reason(),
        Reason::Quic(ams_quic::Reason::CryptoNotConsumed)
    );
    assert_eq!(issue.close_code(), 0x0a, "PROTOCOL_VIOLATION");
}

/// La même règle, un niveau plus haut : des octets `Handshake` non lus au moment
/// où la poignée se confirme.
#[test]
fn des_octets_handshake_non_lus_condamnent_a_la_confirmation() {
    let atelier = atelier("handshake-non-lus");
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let mut serveur = Server::new(
        config_serveur(&cert, &cle, std::vec![b"h3".to_vec()]),
        NOS_PARAMETRES.to_vec(),
    )
    .expect("constructible");
    let mut client = Client::new(config_client(&autorite, std::vec![b"h3".to_vec()]));

    // Un octet en avance dans le flux `Handshake`, AVANT que ce niveau ne serve.
    // Rien ne l'interdit à ce moment-là : `Handshake` n'est pas encore dépassé.
    serveur
        .on_crypto(Level::Handshake, 2_000, b"!")
        .expect("un décalage en avance se range");

    client
        .parler(&mut serveur)
        .expect("le ClientHello se range");
    let issue = loop {
        match serveur.next_flight() {
            Ok(Some(envoi)) => {
                client.ecouter(envoi.bytes());
                client.parler(&mut serveur).expect("le client répond");
            }
            Ok(None) => panic!("la poignée n'aurait pas dû aboutir"),
            Err(issue) => break issue,
        }
    };
    assert_eq!(
        issue.reason(),
        Reason::Quic(ams_quic::Reason::CryptoNotConsumed)
    );
    assert_eq!(issue.close_code(), 0x0a, "PROTOCOL_VIOLATION");
    assert!(
        !serveur.is_complete() || serveur.read_level() == Level::Handshake,
        "la lecture n'est pas passée en 1-RTT"
    );
}
