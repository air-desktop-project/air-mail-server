// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Un client QUIC et HTTP/3 **pour les essais**, et pour eux seuls.
//!
//! # POURQUOI UN CRATE, ET NON UNE COPIE PAR FICHIER D'ESSAI
//!
//! Ce client est la seule chose qui puisse dire si notre serveur parle vraiment
//! QUIC : il compose ses paquets à la main, d'après §17 de RFC 9000 et §4.5 de
//! RFC 9204, **et non par notre propre encodeur**. Un essai qui bâtirait ses
//! requêtes avec notre écriture ne prouverait rien du fil : si l'ordre des champs
//! était faux DES DEUX CÔTÉS, il passerait quand même.
//!
//! Le dupliquer par fichier d'essai en ferait diverger les copies — et la copie
//! qui divergerait serait celle qu'on ne regarde plus.
//!
//! # IL N'ENTRE JAMAIS DANS LE SERVEUR
//!
//! `publish = false`, et aucune crate de production n'en dépend : il ne vit que
//! dans les `[dev-dependencies]`. Il n'est donc pas dans le périmètre de
//! couverture (C2) — ce n'est pas du code qu'on sert, c'est du code qui éprouve.

use std::collections::{HashMap, HashSet};
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

/// Ce qu'un essai dit quand `openssl` manque.
///
/// **IL ÉCHOUE PLUTÔT QUE DE SE TAIRE** : sans certificat, la poignée de main ne
/// monte pas, et un essai qui se sauterait en silence laisserait croire que le
/// serveur est éprouvé alors qu'il ne l'est pas.
pub const SANS_OPENSSL: &str = "ce test EXIGE `openssl` : sans lui, l'écoute QUIC n'est pas éprouvée \
                            sur une vraie socket, et rien ne dirait que le démultiplexage \
                            fonctionne";

/// L'identifiant que le client choisit pour son premier paquet.
pub const ORIGINE: [u8; 8] = [0x21, 0x43, 0x65, 0x87, 0xa9, 0xcb, 0xed, 0x0f];

/// Et celui du client.
/// L'identifiant que le client se donne, et que le serveur devra employer
/// pour lui répondre (§7.2).
pub const CLIENT: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

/// Les paramètres de transport que le client annonce.
/// Les paramètres que le client annonce (§18.2).
///
/// **LES SIX LIMITES, ET NON LA SEULE `initial_max_data`** : sans les crédits par
/// flux et les plafonds de §4.6, tout vaudrait zéro et un essai de flux passerait
/// en ne prouvant rien.
pub fn ses_parametres() -> Vec<u8> {
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
pub struct Atelier(std::path::PathBuf);

impl Atelier {
    /// Le répertoire de travail de cet essai.
    #[must_use]
    pub fn chemin(&self) -> &Path {
        &self.0
    }
}

impl Drop for Atelier {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Un répertoire de travail par essai — `cargo test` les lance en parallèle.
pub fn atelier(nom: &str) -> Atelier {
    let chemin = std::env::temp_dir().join(format!("ams-quic-ecoute-{nom}-{}", std::process::id()));
    std::fs::create_dir_all(&chemin).expect("répertoire temporaire");
    Atelier(chemin)
}

/// Cette commande a-t-elle abouti ?
fn reussit(commande: &mut Command) -> Option<()> {
    commande.output().ok()?.status.success().then_some(())
}

/// Fabrique une autorité, puis une paire serveur qu'elle signe.
pub fn materiel(repertoire: &Path) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
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
pub fn identifiant(octets: &[u8]) -> ConnectionId {
    ConnectionId::new(octets).expect("vingt octets au plus")
}

/// La configuration client, qui fait confiance à cette autorité.
pub fn config_client(autorite: &[u8]) -> Arc<ClientConfig> {
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
pub struct Client {
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
    /// Ce que chaque flux nous a apporté, replacé à son décalage.
    ///
    /// **PAR FLUX, ET NON EN UN SEUL TAMPON.** La première version fusionnait
    /// tout : les décalages de deux flux distincts commencent tous deux à zéro,
    /// et le dernier écrit effaçait le premier. Le serveur n'ouvrait alors qu'un
    /// flux unidirectionnel, et la réponse arrivait après lui, plus longue que
    /// lui — l'essai passait donc, mais par accident d'ordonnancement, et non
    /// parce qu'il lisait ce qu'il croyait lire.
    recu: HashMap<u64, Vec<u8>>,
    /// Les flux que le pair a terminés.
    fins_recues: HashSet<u64>,
    /// Ce datagramme-ci porte-t-il un `Initial` ?
    a_pose_un_initial: bool,
}

/// Ce que les essais lisent d'un client.
///
/// **DES ACCESSEURS, ET NON DES CHAMPS PUBLICS** : ce crate est une interface
/// d'essai, employée par deux crates qui n'ont pas les mêmes besoins. Ouvrir ses
/// champs laisserait l'un d'eux s'appuyer sur une forme interne, et ce serait
/// alors le client qu'on ne pourrait plus changer.
impl Client {
    /// La moitié TLS, pour savoir où en est la poignée de main.
    #[must_use]
    pub const fn tls(&self) -> &ClientConnection {
        &self.tls
    }

    /// Pose ces trames applicatives, qui partiront au prochain datagramme.
    pub fn dire(&mut self, octets: &[u8]) {
        self.a_dire.extend_from_slice(octets);
    }

    /// Ce que CE flux nous a apporté, replacé à son décalage.
    #[must_use]
    pub fn recu(&self, flux: u64) -> &[u8] {
        self.recu.get(&flux).map_or(&[][..], Vec::as_slice)
    }

    /// Le pair a-t-il terminé CE flux ?
    #[must_use]
    pub fn fin_recue(&self, flux: u64) -> bool {
        self.fins_recues.contains(&flux)
    }

    /// Le serveur a-t-il fermé, et avec quel code ?
    #[must_use]
    pub const fn ferme(&self) -> Option<u64> {
        self.ferme
    }

    /// L'identifiant que le serveur nous a donné.
    ///
    /// **IL CHANGE APRÈS LA PREMIÈRE RÉPONSE** : c'est ce qui prouve que la carte
    /// de l'écoute range ce qu'elle distribue.
    #[must_use]
    pub const fn distant(&self) -> ConnectionId {
        self.distant
    }

    /// Un client neuf, sur une socket éphémère, qui parlera à ce serveur.
    pub async fn new(config: Arc<ClientConfig>, serveur: SocketAddr) -> Self {
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
            recu: HashMap::new(),
            fins_recues: HashSet::new(),
            a_pose_un_initial: false,
        }
    }

    /// Le rang d'un espace de numérotation dans nos tableaux.
    pub const fn rang(espace: Space) -> usize {
        match espace {
            Space::Initial => 0,
            Space::Handshake => 1,
            Space::Application => 2,
        }
    }

    /// Redemande à TLS ce qu'il a à dire, et installe les clés qu'il donne.
    pub fn avancer(&mut self) {
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

    /// Range les clés qu'un changement apporte, et rend le niveau d'émission.
    pub fn installer(&mut self, change: KeyChange) -> Level {
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
    pub async fn parler(&mut self) -> bool {
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
    pub fn poser(&mut self, datagramme: &mut Vec<u8>, espace: Space, trames: &[u8]) {
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
    pub async fn ecouter(&mut self) -> bool {
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
                    stream,
                    offset,
                    data,
                    fin,
                } = trame
                {
                    let debut = usize::try_from(offset).unwrap_or(usize::MAX);
                    let bout = debut.saturating_add(data.len());
                    let bac = self.recu.entry(stream).or_default();
                    if bac.len() < bout {
                        bac.resize(bout, 0);
                    }
                    bac.get_mut(debut..bout)
                        .expect("la place vient d'être faite")
                        .copy_from_slice(data);
                    if fin {
                        self.fins_recues.insert(stream);
                    }
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

/// Écrit un entier à préfixe (§5.1 de RFC 7541, repris par QPACK).
///
/// **C'EST LE MÊME CODAGE QUE HPACK**, et c'est voulu : §4.1.1 de RFC 9204 le
/// reprend tel quel pour n'avoir pas deux façons d'écrire un nombre.
pub fn poser_entier(valeur: usize, bits: u32, motif: u8, out: &mut Vec<u8>) {
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
pub fn poser_champ(nom: &[u8], valeur: &[u8], out: &mut Vec<u8>) {
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
pub fn une_section(methode: u8, chemin: &[u8], jeton: Option<&str>, avec_corps: bool) -> Vec<u8> {
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
pub async fn envoyer_une_requete(
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

/// Attend la réponse SUR CE FLUX, et rend le corps de sa trame `DATA`.
///
/// **LE NUMÉRO DE FLUX N'EST PAS UN ORNEMENT** : le serveur écrit aussi sur ses
/// trois flux unidirectionnels — le contrôle et les deux flux QPACK de §4.2 de
/// RFC 9204 —, et leurs octets ne sont pas une réponse.
pub async fn attendre_la_reponse(client: &mut Client, flux: u64) -> Vec<u8> {
    for _ in 0..10 {
        client.ecouter().await;
        if client.fin_recue(flux) {
            break;
        }
        client.parler().await;
    }
    let recu = client.recu(flux).to_vec();
    // §4.1 : les en-têtes d'abord, le corps ensuite.
    let Ok(entete) = ams_proto_h3::FrameHeader::parse(&recu) else {
        return Vec::new();
    };
    let apres = usize::try_from(entete.total()).expect("tient");
    let Some(reste) = recu.get(apres..) else {
        return Vec::new();
    };
    let Ok(corps) = ams_proto_h3::FrameHeader::parse(reste) else {
        return Vec::new();
    };
    reste.get(corps.header_len()..).unwrap_or_default().to_vec()
}
