// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Une poignée de main QUIC **sur une vraie socket UDP**.
//!
//! # CE QUE CET ESSAI AJOUTE À CEUX D'`ams-quic-tls`
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
//! # ET IL FAUT UN VRAI CERTIFICAT
//!
//! Pour la même raison qu'ailleurs : `rustls` ne monte pas de configuration
//! serveur sans paire valide, et rien dans ce dépôt ne sait en fabriquer une.

use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use ams_proto_quic::{ConnectionId, Frame, Sender, Space, TransportParameters};
use ams_quic::{Incoming, Level, Plan, open_packet, seal_packet};
use ams_quic_crypto::{Keys, Role, Secret};
use ams_quic_tls::Clefs;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::quic::{ClientConnection, KeyChange, Version};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::UdpSocket;

const SANS_OPENSSL: &str = "ce test EXIGE `openssl` : sans lui, l'écoute QUIC n'est pas éprouvée \
                            sur une vraie socket, et rien ne dirait que le démultiplexage \
                            fonctionne";

/// L'identifiant que le client choisit pour son premier paquet.
const ORIGINE: [u8; 8] = [0x21, 0x43, 0x65, 0x87, 0xa9, 0xcb, 0xed, 0x0f];

/// Et celui du client.
const CLIENT: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

/// Les paramètres de transport que le client annonce.
/// Les paramètres que le client annonce (§18.2).
///
/// **LES SIX LIMITES, ET NON LA SEULE `initial_max_data`** : sans les crédits par
/// flux et les plafonds de §4.6, tout vaudrait zéro et un essai de flux passerait
/// en ne prouvant rien.
fn ses_parametres() -> Vec<u8> {
    let mut siens = TransportParameters::DEFAULT;
    siens.initial_max_data = 100_000;
    siens.initial_max_stream_data_bidi_local = 50_000;
    siens.initial_max_stream_data_bidi_remote = 50_000;
    siens.initial_max_stream_data_uni = 50_000;
    siens.initial_max_streams_bidi = 8;
    siens.initial_max_streams_uni = 8;
    let mut octets = vec![0_u8; 256];
    let ecrits = siens
        .write(Sender::Client, &mut octets)
        .expect("nos propres paramètres tiennent");
    octets.truncate(ecrits);
    octets
}

/// Un répertoire par test.
struct Atelier(std::path::PathBuf);

impl Drop for Atelier {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn atelier(nom: &str) -> Atelier {
    let chemin = std::env::temp_dir().join(format!("ams-quic-ecoute-{nom}-{}", std::process::id()));
    std::fs::create_dir_all(&chemin).expect("répertoire temporaire");
    Atelier(chemin)
}

/// Cette commande a-t-elle abouti ?
fn reussit(commande: &mut Command) -> Option<()> {
    commande.output().ok()?.status.success().then_some(())
}

/// Fabrique une autorité, puis une paire serveur qu'elle signe.
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

/// Un identifiant de connexion à partir de ces octets.
fn identifiant(octets: &[u8]) -> ConnectionId {
    ConnectionId::new(octets).expect("vingt octets au plus")
}

/// La configuration client, qui fait confiance à cette autorité.
fn config_client(autorite: &[u8]) -> Arc<ClientConfig> {
    let mut racines = RootCertStore::empty();
    for der in CertificateDer::pem_slice_iter(autorite) {
        racines
            .add(der.expect("certificat lisible"))
            .expect("racine ajoutable");
    }
    let mut config = ClientConfig::builder_with_provider(Arc::new(ams_tls::provider_quic()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_root_certificates(racines)
        .with_no_client_auth();
    config.alpn_protocols = ams_tls::alpn_h3();
    Arc::new(config)
}

/// Un client d'essai, qui parle sur une vraie socket.
struct Client {
    tls: ClientConnection,
    socket: UdpSocket,
    serveur: SocketAddr,
    chiffrement: [Option<Clefs>; 3],
    dechiffrement: [Option<Clefs>; 3],
    initiales_emission: Keys,
    initiales_reception: Keys,
    /// L'identifiant que le SERVEUR nous a donné — inconnu jusqu'à sa première
    /// réponse.
    ///
    /// **C'EST LUI QUI ÉPROUVE LE DÉMULTIPLEXAGE** : si l'écoute rangeait mal sa
    /// carte, nos paquets suivants n'atteindraient plus personne.
    distant: ConnectionId,
    niveau: Level,
    prochain: [u64; 3],
    decalage: [u64; 3],
    plus_grand: [Option<u64>; 3],
    a_acquitter: [Vec<u64>; 3],
    reassemblage: ams_quic::Handshake,
    fenetres: [Vec<u8>; 3],
    en_attente: Vec<(Level, Vec<u8>)>,
    /// Des trames applicatives à poser au prochain datagramme.
    a_dire: Vec<u8>,
    /// Le serveur a-t-il fermé, et avec quel code ?
    ferme: Option<u64>,
    /// Ce qu'un flux nous a apporté, replacé à son décalage.
    recu: Vec<u8>,
    /// Le pair a-t-il terminé ce flux ?
    fin_recue: bool,
    /// Ce datagramme-ci porte-t-il un `Initial` ?
    a_pose_un_initial: bool,
}

impl Client {
    async fn new(config: Arc<ClientConfig>, serveur: SocketAddr) -> Self {
        let clefs = |role| {
            Secret::initial(&ORIGINE, role)
                .expect("dérivable")
                .keys()
                .expect("dérivables")
        };
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("une socket");
        Self {
            tls: ClientConnection::new(
                config,
                Version::V1,
                ServerName::try_from("localhost").expect("un nom"),
                ses_parametres(),
            )
            .expect("le client se construit"),
            socket,
            serveur,
            chiffrement: [None, None, None],
            dechiffrement: [None, None, None],
            initiales_emission: clefs(Role::Client),
            initiales_reception: clefs(Role::Server),
            distant: identifiant(&ORIGINE),
            niveau: Level::Initial,
            prochain: [0; 3],
            decalage: [0; 3],
            plus_grand: [None; 3],
            a_acquitter: Default::default(),
            reassemblage: ams_quic::Handshake::new(),
            fenetres: [
                vec![0_u8; ams_quic::CRYPTO_OCTETS_MAX],
                vec![0_u8; ams_quic::CRYPTO_OCTETS_MAX],
                vec![0_u8; ams_quic::CRYPTO_OCTETS_MAX],
            ],
            en_attente: Vec::new(),
            a_dire: Vec::new(),
            ferme: None,
            recu: Vec::new(),
            fin_recue: false,
            a_pose_un_initial: false,
        }
    }

    const fn rang(espace: Space) -> usize {
        match espace {
            Space::Initial => 0,
            Space::Handshake => 1,
            Space::Application => 2,
        }
    }

    /// Redemande à TLS ce qu'il a à dire, et installe les clés qu'il donne.
    fn avancer(&mut self) {
        loop {
            let mut octets = Vec::new();
            let change = self.tls.write_hs(&mut octets);
            if octets.is_empty() && change.is_none() {
                return;
            }
            if !octets.is_empty() {
                self.en_attente.push((self.niveau, octets));
            }
            if let Some(change) = change {
                self.niveau = self.installer(change);
            }
        }
    }

    fn installer(&mut self, change: KeyChange) -> Level {
        let (niveau, clefs) = match change {
            KeyChange::Handshake { keys } => (Level::Handshake, keys),
            KeyChange::OneRtt { keys, .. } => (Level::OneRtt, keys),
        };
        let rang = Self::rang(niveau.space());
        self.chiffrement[rang] = Some(Clefs::new(clefs.local.packet, clefs.local.header));
        self.dechiffrement[rang] = Some(Clefs::new(clefs.remote.packet, clefs.remote.header));
        niveau
    }

    /// L'acquittement de cet espace, s'il y a quelque chose à acquitter.
    fn acquittement(&mut self, espace: Space) -> Option<Vec<u8>> {
        let rang = Self::rang(espace);
        if self.a_acquitter[rang].is_empty() {
            return None;
        }
        let plus_grand = self.a_acquitter[rang].iter().copied().max().unwrap_or(0);
        let plus_petit = self.a_acquitter[rang].iter().copied().min().unwrap_or(0);
        let mut trames = [0_u8; 64];
        let ack = Frame::Ack(ams_proto_quic::Ack {
            largest: plus_grand,
            delay: 0,
            first_range: plus_grand.saturating_sub(plus_petit),
            range_count: 0,
            encoded_ranges: &[],
            ecn: None,
        });
        let ecrits = ack.write(&mut trames).expect("écrivable");
        self.a_acquitter[rang].clear();
        Some(trames[..ecrits].to_vec())
    }

    /// Compose un datagramme et l'envoie pour de bon.
    ///
    /// # UN SEUL PAQUET `1-RTT`, ET IL EST LE DERNIER
    ///
    /// §17.3 : un en-tête court n'a pas de champ de longueur, et sa charge va
    /// jusqu'au BOUT du datagramme. Tout ce qu'on poserait derrière lui entrerait
    /// dans son chiffré, et il ne s'authentifierait plus — il serait jeté sans un
    /// mot, ce qu'un essai confondrait avec un serveur muet.
    ///
    /// L'acquittement applicatif et ce que l'essai veut dire vont donc dans le
    /// MÊME paquet, posé en dernier.
    async fn parler(&mut self) -> bool {
        self.a_pose_un_initial = false;
        let mut datagramme = Vec::new();

        // Les deux espaces à en-tête long : ils portent leur longueur, et se
        // coalescent sans se gêner (§12.2).
        for espace in [Space::Initial, Space::Handshake] {
            if let Some(ack) = self.acquittement(espace) {
                self.poser(&mut datagramme, espace, &ack);
            }
        }
        self.avancer();
        for (niveau, octets) in std::mem::take(&mut self.en_attente) {
            let espace = niveau.space();
            let rang = Self::rang(espace);
            let mut trames = vec![0_u8; octets.len().saturating_add(32)];
            let trame = Frame::Crypto {
                offset: self.decalage[rang],
                data: &octets,
            };
            let ecrits = trame.write(&mut trames).expect("écrivable");
            self.decalage[rang] = self.decalage[rang]
                .checked_add(u64::try_from(octets.len()).expect("tient"))
                .expect("pas de débordement");
            match espace {
                Space::Application => self.a_dire.extend_from_slice(&trames[..ecrits]),
                _ => self.poser(&mut datagramme, espace, &trames[..ecrits]),
            }
        }

        // Puis l'espace applicatif, tout entier dans un seul paquet.
        let mut applicatif = self.acquittement(Space::Application).unwrap_or_default();
        applicatif.extend_from_slice(&std::mem::take(&mut self.a_dire));
        if !applicatif.is_empty() {
            self.poser(&mut datagramme, Space::Application, &applicatif);
        }

        if datagramme.is_empty() {
            return false;
        }

        // §14.1 : un datagramme portant un `Initial` fait 1200 octets au moins.
        //
        // # ET SEULEMENT CELUI-LÀ
        //
        // Bourrer derrière un en-tête court ferait entrer les zéros dans son
        // chiffré, pour la raison dite plus haut.
        if self.a_pose_un_initial && datagramme.len() < 1_200 {
            datagramme.resize(1_200, 0);
        }
        self.socket
            .send_to(&datagramme, self.serveur)
            .await
            .expect("le datagramme part");
        true
    }

    /// Scelle un paquet de cet espace et l'ajoute au datagramme.
    fn poser(&mut self, datagramme: &mut Vec<u8>, espace: Space, trames: &[u8]) {
        self.a_pose_un_initial |= matches!(espace, Space::Initial);
        let rang = Self::rang(espace);
        let plan = match espace {
            Space::Initial => Plan::Initial {
                destination: self.distant,
                source: identifiant(&CLIENT),
                token: &[],
            },
            Space::Handshake => Plan::Handshake {
                destination: self.distant,
                source: identifiant(&CLIENT),
            },
            Space::Application => Plan::OneRtt {
                destination: self.distant,
                key_phase: false,
            },
        };
        let clefs: &dyn ams_quic::Protection = match rang {
            0 => &self.initiales_emission,
            _ => match self.chiffrement[rang].as_ref() {
                Some(clefs) => clefs,
                None => return,
            },
        };
        // §5.4.2 : de quoi échantillonner.
        let mut charge = trames.to_vec();
        while charge.len() < 3 {
            charge.push(0);
        }
        let mut place = vec![0_u8; 1_600];
        let ecrit = seal_packet(&mut place, clefs, &plan, self.prochain[rang], None, &charge)
            .expect("le client scelle ce qu'il compose");
        self.prochain[rang] = self.prochain[rang].saturating_add(1);
        datagramme.extend_from_slice(&place[..ecrit]);
    }

    /// Attend un datagramme du serveur et le traite.
    async fn ecouter(&mut self) -> bool {
        let mut octets = vec![0_u8; 65_535];
        let lu = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            self.socket.recv_from(&mut octets),
        )
        .await;
        let Ok(Ok((combien, _))) = lu else {
            return false;
        };
        octets.truncate(combien);

        let mut rang = 0_usize;
        while rang < octets.len() {
            let reste = &mut octets[rang..];
            let Ok(arrivee) = Incoming::read(reste, CLIENT.len()) else {
                return true;
            };
            let Some(niveau) = arrivee.kind().and_then(Level::of) else {
                return true;
            };
            // **LE SERVEUR NOUS A DONNÉ UN IDENTIFIANT** : c'est celui-là qu'on
            // lui adresse désormais, et c'est ce qui fait vivre sa carte.
            if !arrivee.source().is_empty() {
                self.distant = arrivee.source();
            }
            let quel = Self::rang(niveau.space());
            let clefs: &dyn ams_quic::Protection = match quel {
                0 => &self.initiales_reception,
                _ => match self.dechiffrement[quel].as_ref() {
                    Some(clefs) => clefs,
                    None => return true,
                },
            };
            let Ok(ouvert) = open_packet(reste, clefs, self.plus_grand[quel], CLIENT.len()) else {
                return true;
            };
            let total = ouvert.total;
            self.plus_grand[quel] =
                Some(self.plus_grand[quel].map_or(ouvert.number, |vu| vu.max(ouvert.number)));
            let charge = reste
                [ouvert.payload_at..ouvert.payload_at.saturating_add(ouvert.payload_len)]
                .to_vec();
            let mut suite = charge.as_slice();
            let mut sollicite = false;
            while !suite.is_empty() {
                let Ok((trame, lus)) = Frame::parse(suite) else {
                    break;
                };
                suite = &suite[lus..];
                sollicite |= !matches!(trame, Frame::Ack(_) | Frame::Padding { .. });
                if let Frame::ConnectionClose { code, .. } = trame {
                    self.ferme = Some(code);
                }
                if let Frame::Stream {
                    offset, data, fin, ..
                } = trame
                {
                    let debut = usize::try_from(offset).unwrap_or(usize::MAX);
                    let bout = debut.saturating_add(data.len());
                    if self.recu.len() < bout {
                        self.recu.resize(bout, 0);
                    }
                    self.recu
                        .get_mut(debut..bout)
                        .expect("la place vient d'être faite")
                        .copy_from_slice(data);
                    self.fin_recue |= fin;
                }
                if let Frame::Crypto { offset, data } = trame {
                    self.reassemblage
                        .on_crypto(niveau, offset, data, &mut self.fenetres[quel])
                        .expect("le client range ce que le serveur dit");
                }
            }
            let mut vers = vec![0_u8; ams_quic::CRYPTO_OCTETS_MAX];
            loop {
                let pris = self
                    .reassemblage
                    .take(niveau, &mut self.fenetres[quel], &mut vers);
                if pris == 0 {
                    break;
                }
                self.tls
                    .read_hs(&vers[..pris])
                    .expect("le client accepte ce que le serveur dit");
            }
            self.avancer();
            if sollicite {
                self.a_acquitter[quel].push(ouvert.number);
            }
            rang = rang.saturating_add(total);
        }
        true
    }
}

/// **UNE POIGNÉE DE MAIN QUIC SUR UNE VRAIE SOCKET UDP.**
///
/// C'est le premier essai où les datagrammes traversent la pile réseau du
/// système. Il éprouve ce que le conducteur ne peut pas éprouver seul : la carte
/// des identifiants, le choix du délai, l'émission vers la bonne adresse.
#[tokio::test(flavor = "current_thread")]
async fn une_poignee_de_main_sur_une_vraie_socket() {
    let atelier = atelier("poignee");
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);

    let mut config = ams_tls::quic_server_config(&cert, &cle).expect("la paire est bonne");
    config.alpn_protocols = ams_tls::alpn_h3();
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("une socket");
    let adresse = socket.local_addr().expect("une adresse");

    let (fin, arret) = tokio::sync::oneshot::channel::<()>();
    let ecoute = tokio::spawn(async move {
        ams_loop_tokio::serve_quic(
            socket,
            Arc::new(config),
            &mut ams_loop_tokio::SansApplication,
            async {
                let _ = arret.await;
            },
        )
        .await
    });

    let mut client = Client::new(config_client(&autorite), adresse).await;
    for _ in 0..16 {
        if !client.parler().await && !client.tls.is_handshaking() {
            break;
        }
        if !client.ecouter().await && !client.tls.is_handshaking() {
            break;
        }
    }

    assert!(
        !client.tls.is_handshaking(),
        "la poignée de main doit aboutir sur une vraie socket"
    );
    assert_eq!(client.tls.alpn_protocol(), Some(&b"h3"[..]));
    assert!(
        client.tls.quic_transport_parameters().is_some(),
        "§8.2 : le serveur annonce les siens"
    );
    // **L'IDENTIFIANT A CHANGÉ** : le serveur nous a donné le sien, et nos
    // paquets l'ont atteint — c'est la carte de l'écoute qui l'a fait.
    assert_ne!(
        client.distant,
        identifiant(&ORIGINE),
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
    let (_autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);

    let mut config = ams_tls::quic_server_config(&cert, &cle).expect("la paire est bonne");
    config.alpn_protocols = ams_tls::alpn_h3();
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("une socket");
    let adresse = socket.local_addr().expect("une adresse");

    let (fin, arret) = tokio::sync::oneshot::channel::<()>();
    let ecoute = tokio::spawn(async move {
        ams_loop_tokio::serve_quic(
            socket,
            Arc::new(config),
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
            court.extend_from_slice(&ORIGINE);
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
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);

    let mut config = ams_tls::quic_server_config(&cert, &cle).expect("la paire est bonne");
    config.alpn_protocols = ams_tls::alpn_h3();
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("une socket");
    let adresse = socket.local_addr().expect("une adresse");

    let (fin, arret) = tokio::sync::oneshot::channel::<()>();
    let ecoute = tokio::spawn(async move {
        ams_loop_tokio::serve_quic(
            socket,
            Arc::new(config),
            &mut ams_loop_tokio::SansApplication,
            async {
                let _ = arret.await;
            },
        )
        .await
    });

    let mut client = Client::new(config_client(&autorite), adresse).await;
    for _ in 0..16 {
        if !client.parler().await && !client.tls.is_handshaking() {
            break;
        }
        if !client.ecouter().await && !client.tls.is_handshaking() {
            break;
        }
    }
    assert!(!client.tls.is_handshaking(), "la poignée de main aboutit");

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
    client
        .a_dire
        .extend_from_slice(trames.get(..ecrits).expect("écrits"));

    for _ in 0..6 {
        client.parler().await;
        client.ecouter().await;
    }

    assert_eq!(
        client.ferme, None,
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
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);

    let mut config = ams_tls::quic_server_config(&cert, &cle).expect("la paire est bonne");
    config.alpn_protocols = ams_tls::alpn_h3();
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("une socket");
    let adresse = socket.local_addr().expect("une adresse");

    let (fin, arret) = tokio::sync::oneshot::channel::<()>();
    let ecoute = tokio::spawn(async move {
        ams_loop_tokio::serve_quic(
            socket,
            Arc::new(config),
            &mut ams_loop_tokio::SansApplication,
            async {
                let _ = arret.await;
            },
        )
        .await
    });

    let mut client = Client::new(config_client(&autorite), adresse).await;
    for _ in 0..16 {
        if !client.parler().await && !client.tls.is_handshaking() {
            break;
        }
        if !client.ecouter().await && !client.tls.is_handshaking() {
            break;
        }
    }
    assert!(!client.tls.is_handshaking(), "la poignée de main aboutit");

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
    client
        .a_dire
        .extend_from_slice(trames.get(..ecrits).expect("écrits"));

    for tour in 0..6 {
        let dit = client.parler().await;
        let entendu = client.ecouter().await;
        std::eprintln!(
            "DEBUG tour={tour} dit={dit} entendu={entendu} ferme={:?}",
            client.ferme
        );
    }

    assert_eq!(
        client.ferme,
        Some(ams_proto_quic::TransportError::StreamLimitError.value()),
        "§4.6 : le serveur le dit, et ne se contente pas de jeter"
    );

    let _ = fin.send(());
    let stats = ecoute
        .await
        .expect("la tâche d'écoute")
        .expect("l'écoute rend ses comptes");
    assert_eq!(stats.accepted, 1);
    // **ELLE N'EST PAS ENCORE ÉTEINTE, ET C'EST §10.2** : après avoir dit sa
    // fermeture, une connexion reste en état de fermeture trois PTO durant, pour
    // pouvoir redire son `CONNECTION_CLOSE` au pair qui n'aurait pas entendu.
    // `closed` ne compte que ce qui a fini d'attendre.
    assert_eq!(stats.closed, 0);
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
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);

    let mut config = ams_tls::quic_server_config(&cert, &cle).expect("la paire est bonne");
    config.alpn_protocols = ams_tls::alpn_h3();
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("une socket");
    let adresse = socket.local_addr().expect("une adresse");

    let (fin, arret) = tokio::sync::oneshot::channel::<()>();
    let ecoute = tokio::spawn(async move {
        let mut echo = Echo::default();
        let stats = ams_loop_tokio::serve_quic(socket, Arc::new(config), &mut echo, async {
            let _ = arret.await;
        })
        .await;
        (stats, echo.servis, echo.sources)
    });

    let mut client = Client::new(config_client(&autorite), adresse).await;
    for _ in 0..16 {
        if !client.parler().await && !client.tls.is_handshaking() {
            break;
        }
        if !client.ecouter().await && !client.tls.is_handshaking() {
            break;
        }
    }
    assert!(!client.tls.is_handshaking(), "la poignée de main aboutit");

    let mut trames = [0_u8; 64];
    let ecrits = (Frame::Stream {
        stream: 0,
        offset: 0,
        data: b"bonjour",
        fin: true,
    })
    .write(&mut trames)
    .expect("écrivable");
    client
        .a_dire
        .extend_from_slice(trames.get(..ecrits).expect("écrits"));

    for _ in 0..8 {
        client.parler().await;
        client.ecouter().await;
        if client.fin_recue {
            break;
        }
    }

    assert_eq!(client.ferme, None, "rien n'a fermé");
    assert_eq!(
        client.recu, b"vous avez dit: bonjour",
        "LA RÉPONSE DE L'APPLICATION EST ARRIVÉE"
    );
    assert!(client.fin_recue, "§19.8 : et le flux est terminé");

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

/// Écrit un entier à préfixe (§5.1 de RFC 7541, repris par QPACK).
///
/// **C'EST LE MÊME CODAGE QUE HPACK**, et c'est voulu : §4.1.1 de RFC 9204 le
/// reprend tel quel pour n'avoir pas deux façons d'écrire un nombre.
fn poser_entier(valeur: usize, bits: u32, motif: u8, out: &mut Vec<u8>) {
    let plafond = usize::from(u8::MAX >> 8_u32.saturating_sub(bits));
    if valeur < plafond {
        out.push(motif | u8::try_from(valeur).expect("sous le plafond"));
        return;
    }
    out.push(motif | u8::try_from(plafond).expect("un octet"));
    let mut reste = valeur.saturating_sub(plafond);
    while reste >= 128 {
        out.push(
            u8::try_from(reste % 128)
                .expect("sept bits")
                .saturating_add(128),
        );
        reste /= 128;
    }
    out.push(u8::try_from(reste).expect("sept bits"));
}

/// Pose un champ dont le nom ET la valeur sont littéraux (§4.5.6 de RFC 9204).
fn poser_champ(nom: &[u8], valeur: &[u8], out: &mut Vec<u8>) {
    // `001NH` puis la longueur du nom sur trois bits.
    poser_entier(nom.len(), 3, 0x20, out);
    out.extend_from_slice(nom);
    // `H` puis la longueur de la valeur sur sept bits.
    poser_entier(valeur.len(), 7, 0x00, out);
    out.extend_from_slice(valeur);
}

/// Compose une section de champs de requête avec la table statique de QPACK.
///
/// **À LA MAIN** : bâtir la requête avec notre propre encodeur ne prouverait
/// rien du fil — si l'ordre des champs était faux des deux côtés, l'essai
/// passerait quand même.
fn une_section(methode: u8, chemin: &[u8], jeton: Option<&str>, avec_corps: bool) -> Vec<u8> {
    let mut section = std::vec![0x00_u8, 0x00];
    // §4.5.2 de RFC 9204 : `1Tiiiiii`, T=1 pour la table statique.
    // Annexe A de RFC 9204 : 17 vaut `:method: GET`, 20 `:method: POST`, et 23
    // `:scheme: https`. **PAS 22** : celui-là vaut `:scheme: http`, que ce
    // serveur refuse (C4).
    for index in [methode, 23] {
        section.push(0xc0 | index);
    }
    // §4.5.4 : `01NTiiii` — nom indexé, valeur littérale.
    for (index, valeur) in [(0_u8, &b"exemple.test"[..]), (1, chemin)] {
        section.push(0x50 | index);
        section.push(u8::try_from(valeur.len()).expect("court"));
        section.extend_from_slice(valeur);
    }
    if avec_corps {
        // §8.3 de RFC 9110 : sans lui, la session ne sait pas ce qu'elle lit, et
        // refuse plutôt que de deviner.
        poser_champ(b"content-type", b"application/json", &mut section);
    }
    if let Some(jeton) = jeton {
        let mut valeur = std::string::String::from("Bearer ");
        valeur.push_str(jeton);
        poser_champ(b"authorization", valeur.as_bytes(), &mut section);
    }
    section
}

/// Envoie une requête complète sur ce flux : ses en-têtes, puis son corps.
async fn envoyer_une_requete(
    client: &mut Client,
    flux: u64,
    methode: u8,
    chemin: &[u8],
    jeton: Option<&str>,
    corps: &[u8],
) {
    let section = une_section(methode, chemin, jeton, !corps.is_empty());
    let mut entete = [0_u8; 16];
    let mut charge = Vec::new();
    let pose = ams_proto_h3::write_header(
        ams_proto_h3::FrameKind::Headers,
        u64::try_from(section.len()).expect("tient"),
        &mut entete,
    )
    .expect("écrivable");
    charge.extend_from_slice(&entete[..pose]);
    charge.extend_from_slice(&section);
    if !corps.is_empty() {
        let pose = ams_proto_h3::write_header(
            ams_proto_h3::FrameKind::Data,
            u64::try_from(corps.len()).expect("tient"),
            &mut entete,
        )
        .expect("écrivable");
        charge.extend_from_slice(&entete[..pose]);
        charge.extend_from_slice(corps);
    }

    let mut trames = std::vec![0_u8; charge.len().saturating_add(64)];
    let ecrits = (Frame::Stream {
        stream: flux,
        offset: 0,
        data: &charge,
        fin: true,
    })
    .write(&mut trames)
    .expect("écrivable");
    client
        .a_dire
        .extend_from_slice(trames.get(..ecrits).expect("écrits"));
    client.parler().await;
}

/// Attend la réponse, et rend le corps de sa trame `DATA`.
async fn attendre_la_reponse(client: &mut Client) -> Vec<u8> {
    for _ in 0..10 {
        client.ecouter().await;
        if client.fin_recue {
            break;
        }
        client.parler().await;
    }
    // §4.1 : les en-têtes d'abord, le corps ensuite.
    let Ok(entete) = ams_proto_h3::FrameHeader::parse(&client.recu) else {
        return Vec::new();
    };
    let apres = usize::try_from(entete.total()).expect("tient");
    let Some(reste) = client.recu.get(apres..) else {
        return Vec::new();
    };
    let Ok(corps) = ams_proto_h3::FrameHeader::parse(reste) else {
        return Vec::new();
    };
    reste.get(corps.header_len()..).unwrap_or_default().to_vec()
}

/// **UNE REQUÊTE HTTP/3 TRAVERSE TOUTE LA CHAÎNE**, sur une vraie socket UDP.
///
/// QUIC, TLS, ALPN `h3`, flux de contrôle, réglages, QPACK, session, API, et la
/// réponse qui revient comprimée. C'est ce que chaque tranche depuis la
/// grammaire sert à rendre possible.
#[tokio::test(flavor = "current_thread")]
async fn une_requete_h3_traverse_toute_la_chaine() {
    let atelier = atelier("h3");
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);

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
        let stats = ams_loop_tokio::serve_quic(socket, Arc::new(config), &mut application, async {
            let _ = arret.await;
        })
        .await;
        (stats, application.comptes())
    });

    let mut client = Client::new(config_client(&autorite), adresse).await;
    for _ in 0..16 {
        if !client.parler().await && !client.tls.is_handshaking() {
            break;
        }
        if !client.ecouter().await && !client.tls.is_handshaking() {
            break;
        }
    }
    assert!(!client.tls.is_handshaking(), "la poignée de main aboutit");

    // **PREMIÈRE REQUÊTE : le jeton**, comme l'essai HTTP/2 le fait.
    let jeton = {
        let corps = br#"{"login":"marc","password":"secret"}"#;
        envoyer_une_requete(&mut client, 0, 20, b"/v1/tokens", None, corps).await;
        let recu = attendre_la_reponse(&mut client).await;
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

    // **SECONDE REQUÊTE : la ressource**, avec le jeton qu'on vient d'obtenir.
    client.recu.clear();
    client.fin_recue = false;
    envoyer_une_requete(&mut client, 4, 17, b"/v1/health", Some(&jeton), &[]).await;
    let recu = attendre_la_reponse(&mut client).await;
    let texte = std::string::String::from_utf8_lossy(&recu).to_string();

    assert_eq!(client.ferme, None, "rien n'a fermé");
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
