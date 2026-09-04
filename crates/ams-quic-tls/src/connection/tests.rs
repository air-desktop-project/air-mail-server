// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Une poignée de main QUIC complète, en vrais paquets.
//!
//! # LE CLIENT EST FAIT DE NOS PIÈCES, ET C'EST ASSUMÉ
//!
//! Sa moitié TLS est un vrai `rustls::quic::ClientConnection` — celle-là ne
//! partage rien avec nous, et c'est elle qui refuse un `ServerHello` mal placé,
//! une transcription incomplète ou un ALPN qui ne recouvre pas le sien.
//!
//! Sa moitié QUIC, en revanche, emploie `seal_packet` et `open_packet`, c'est-à-
//! dire notre code. **Cet essai ne prouve donc pas l'interopérabilité** : il
//! prouve que le conducteur assemble correctement des pièces déjà éprouvées
//! séparément — l'ordre des niveaux, le budget d'amplification, les
//! acquittements, le bourrage de §14.1. L'interopérabilité demandera un client
//! tiers, et c'est écrit dans le registre des contraintes.

use std::sync::Arc;

use ams_proto_quic::{
    ConnectionId, Directional, Frame, LongKind, Sender, Space, StreamId, TransportError,
    TransportParameters, varints,
};
use ams_quic::{Incoming, Level, PacketKind, Plan, open_packet, seal_packet};
use ams_quic_crypto::{Keys, Role, Secret};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::quic::{ClientConnection, KeyChange, Version};
use rustls::{ClientConfig, RootCertStore};

use super::{ACQUITTEMENT_MAX_MS, Connection, INACTIVITE_US};
use crate::{Clefs, Reason};

const SANS_OPENSSL: &str = "ce test EXIGE `openssl` : sans lui, la poignée de main réelle n'est \
                            pas couverte, et le gate des 100 % (C2) échouerait quelques secondes \
                            plus tard sans en dire la raison";

/// L'identifiant que le client choisit pour son premier paquet.
const ORIGINE: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

/// Celui que le serveur veut qu'on emploie ensuite.
const LOCAL: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

/// Et celui du client.
const CLIENT: [u8; 4] = [0xaa, 0xbb, 0xcc, 0xdd];

/// Les paramètres de transport que le client annonce : `initial_max_data` à
/// 786 432 (§18.2), et rien d'autre.
const SES_PARAMETRES: &[u8] = b"\x04\x04\x80\x0c\x00\x00";

/// Les paramètres d'un client qui ouvre vraiment des flux (§18.2).
///
/// **`SES_PARAMETRES` N'EN OUVRE AUCUN** : il ne porte qu'un `initial_max_data`,
/// ce qui suffisait tant que la poignée de main était toute la portée. Un flux
/// demande les six limites, et sans elles le crédit vaudrait zéro partout —
/// l'essai passerait en ne prouvant rien.
fn ses_parametres_avec_flux() -> Vec<u8> {
    let mut siens = TransportParameters::DEFAULT;
    siens.initial_max_data = 100_000;
    siens.initial_max_stream_data_bidi_local = 50_000;
    siens.initial_max_stream_data_bidi_remote = 50_000;
    siens.initial_max_stream_data_uni = 50_000;
    siens.initial_max_streams_bidi = 8;
    siens.initial_max_streams_uni = 8;
    let mut octets = std::vec![0_u8; 256];
    let ecrits = siens
        .write(Sender::Client, &mut octets)
        .expect("nos propres paramètres tiennent");
    octets.truncate(ecrits);
    octets
}

/// Un identifiant de connexion à partir de ces octets.
fn identifiant(octets: &[u8]) -> ConnectionId {
    ConnectionId::new(octets).expect("vingt octets au plus")
}

/// Un répertoire par test — `cargo test` les lance en parallèle.
struct Atelier(std::path::PathBuf);

impl Drop for Atelier {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn atelier(nom: &str) -> Atelier {
    let chemin =
        std::env::temp_dir().join(std::format!("ams-quic-conn-{nom}-{}", std::process::id()));
    std::fs::create_dir_all(&chemin).expect("répertoire temporaire");
    Atelier(chemin)
}

/// Fabrique une autorité, puis une paire serveur qu'elle signe.
fn materiel(repertoire: &std::path::Path) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    crate::tests::materiel(repertoire)
}

/// La configuration serveur, capable de QUIC et n'annonçant que `h3`.
fn config_serveur(cert: &[u8], cle: &[u8]) -> Arc<rustls::ServerConfig> {
    let mut config = ams_tls::quic_server_config(cert, cle).expect("la paire est bonne");
    config.alpn_protocols = ams_tls::alpn_h3();
    Arc::new(config)
}

/// La configuration client, qui fait confiance à cette autorité.
fn config_client(autorite: &[u8], alpn: Vec<Vec<u8>>) -> Arc<ClientConfig> {
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
    config.alpn_protocols = alpn;
    Arc::new(config)
}

/// Un client d'essai : la moitié TLS vient de `rustls`, la moitié QUIC de nous.
struct Client {
    tls: ClientConnection,
    /// Les clés, par espace et par sens.
    chiffrement: [Option<Clefs>; 3],
    dechiffrement: [Option<Clefs>; 3],
    initiales_emission: Keys,
    initiales_reception: Keys,
    /// Le niveau où TLS écrit — **il PERSISTE**, et c'est ce qui fait partir le
    /// `Finished` au bon niveau.
    niveau: Level,
    /// Le prochain numéro de paquet, et le décalage `CRYPTO`, par espace.
    prochain: [u64; 3],
    decalage: [u64; 3],
    /// Le plus grand numéro reçu, par espace.
    plus_grand: [Option<u64>; 3],
    /// Ce qu'il faut acquitter, par espace.
    a_acquitter: [Vec<u64>; 3],
    /// Le réassemblage du flux `CRYPTO`, et ses trois fenêtres.
    ///
    /// **SANS LUI, UN VOL COUPÉ EN DEUX SERAIT PERDU** : les octets d'un
    /// `CRYPTO` portent un décalage, et les remettre à TLS dans l'ordre où ils
    /// arrivent ferait échouer la vérification du `Finished` — très loin de la
    /// cause.
    reassemblage: ams_quic::Handshake,
    fenetres: [Vec<u8>; 3],
    /// Ce que TLS veut dire et qui n'est pas encore parti.
    en_attente: Vec<(Level, Vec<u8>)>,
    /// Les octets qu'un flux nous a apportés.
    recu: Vec<u8>,
    /// Les annulations qu'on a reçues : le flux, le code, la taille finale.
    ///
    /// **ON LES EMPILE, ON NE LES DÉDUPLIQUE PAS** : une annulation retransmise
    /// doit se voir, sans quoi l'essai de perte ne prouverait rien.
    annulations_recues: Vec<(u64, u64, u64)>,
    /// Sur quel flux, et avec un `FIN` ou non.
    flux_recu: Option<u64>,
    fin_recue: bool,
    /// Ce datagramme-ci porte-t-il un `Initial` ?
    a_pose_un_initial: bool,
    /// Les crédits que le serveur a annoncés.
    plafond_recu: Option<u64>,
    credit_recu: Option<u64>,
}

impl Client {
    fn new(config: Arc<ClientConfig>, params: &[u8]) -> Self {
        let clefs = |role| {
            Secret::initial(&ORIGINE, role)
                .expect("dérivable")
                .keys()
                .expect("dérivables")
        };
        Self {
            tls: ClientConnection::new(
                config,
                Version::V1,
                ServerName::try_from("localhost").expect("un nom"),
                params.to_vec(),
            )
            .expect("le client se construit"),
            chiffrement: [None, None, None],
            dechiffrement: [None, None, None],
            initiales_emission: clefs(Role::Client),
            initiales_reception: clefs(Role::Server),
            niveau: Level::Initial,
            prochain: [0; 3],
            decalage: [0; 3],
            plus_grand: [None; 3],
            a_acquitter: Default::default(),
            reassemblage: ams_quic::Handshake::new(),
            fenetres: [
                std::vec![0_u8; ams_quic::CRYPTO_OCTETS_MAX],
                std::vec![0_u8; ams_quic::CRYPTO_OCTETS_MAX],
                std::vec![0_u8; ams_quic::CRYPTO_OCTETS_MAX],
            ],
            en_attente: Vec::new(),
            a_pose_un_initial: false,
            recu: Vec::new(),
            annulations_recues: Vec::new(),
            flux_recu: None,
            fin_recue: false,
            plafond_recu: None,
            credit_recu: None,
        }
    }

    /// Redemande à TLS ce qu'il a à dire, et installe les clés qu'il donne.
    ///
    /// §4.1.3 : « Each time that TLS is provided with new data, new handshake
    /// bytes are requested from TLS. » **C'est cet appel-là qui installe les
    /// clés**, et c'est pourquoi il doit suivre CHAQUE paquet remis — sans quoi
    /// le paquet suivant du même datagramme serait indéchiffrable.
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

    /// Le rang d'un espace.
    const fn rang(espace: Space) -> usize {
        match espace {
            Space::Initial => 0,
            Space::Handshake => 1,
            Space::Application => 2,
        }
    }

    /// Compose un datagramme : ce que TLS veut dire, et ce qu'il doit acquitter.
    fn parler(&mut self) -> Vec<u8> {
        self.a_pose_un_initial = false;
        let mut datagramme = Vec::new();
        // D'abord les acquittements que l'on doit, espace par espace.
        for espace in [Space::Initial, Space::Handshake, Space::Application] {
            let rang = Self::rang(espace);
            if self.a_acquitter[rang].is_empty() {
                continue;
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
            self.poser(
                &mut datagramme,
                espace,
                trames.get(..ecrits).expect("écrits"),
            );
        }

        // Puis ce que TLS a à dire, et qui attend depuis la dernière écoute.
        //
        // **ON NE TIRE PAS SUR `write_hs` ICI** : c'est `avancer` qui le fait,
        // après chaque paquet remis (§4.1.3), parce que c'est lui qui installe
        // les clés du niveau suivant. Tirer une seconde fois ne rendrait rien —
        // et la première version le faisait, ce qui perdait le `Finished`.
        self.avancer();
        for (niveau, octets) in core::mem::take(&mut self.en_attente) {
            let espace = niveau.space();
            let rang = Self::rang(espace);
            let mut trames = std::vec![0_u8; octets.len().saturating_add(32)];
            let trame = Frame::Crypto {
                offset: self.decalage[rang],
                data: &octets,
            };
            let ecrits = trame.write(&mut trames).expect("écrivable");
            self.decalage[rang] = self.decalage[rang]
                .checked_add(u64::try_from(octets.len()).expect("tient"))
                .expect("pas de débordement");
            self.poser(
                &mut datagramme,
                espace,
                trames.get(..ecrits).expect("écrits"),
            );
        }
        // §14.1 : un datagramme portant un `Initial` fait 1200 octets au moins.
        //
        // # ET SEULEMENT CELUI-LÀ
        //
        // **UN EN-TÊTE COURT N'A PAS DE CHAMP DE LONGUEUR** (§17.3) : sa charge
        // va jusqu'au bout du datagramme. Bourrer derrière lui ferait entrer les
        // zéros dans le chiffré, et le paquet ne s'authentifierait plus — il
        // serait jeté sans un mot, ce qui est exactement ce qu'un essai ne doit
        // pas confondre avec un serveur muet.
        if self.a_pose_un_initial && !datagramme.is_empty() && datagramme.len() < 1_200 {
            datagramme.resize(1_200, 0);
        }
        datagramme
    }

    /// Scelle un paquet de cet espace et l'ajoute au datagramme.
    fn poser(&mut self, datagramme: &mut Vec<u8>, espace: Space, trames: &[u8]) {
        self.a_pose_un_initial |= matches!(espace, Space::Initial);
        let rang = Self::rang(espace);
        let plan = match espace {
            Space::Initial => Plan::Initial {
                destination: identifiant(&ORIGINE),
                source: identifiant(&CLIENT),
                token: &[],
            },
            Space::Handshake => Plan::Handshake {
                destination: identifiant(&LOCAL),
                source: identifiant(&CLIENT),
            },
            Space::Application => Plan::OneRtt {
                destination: identifiant(&LOCAL),
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
        // §5.4.2 de RFC 9001 : de quoi échantillonner. Une trame seule — un
        // `PING`, par exemple — n'y suffit pas, et un `PADDING` complète.
        let mut charge = trames.to_vec();
        while charge.len() < 3 {
            charge.push(0);
        }
        let mut place = std::vec![0_u8; 1_600];
        let ecrit = seal_packet(&mut place, clefs, &plan, self.prochain[rang], None, &charge)
            .expect("le client scelle ce qu'il compose");
        self.prochain[rang] = self.prochain[rang].saturating_add(1);
        datagramme.extend_from_slice(place.get(..ecrit).expect("écrit"));
    }

    /// Lit un datagramme venu du serveur.
    fn ecouter(&mut self, datagramme: &[u8]) {
        let mut octets = datagramme.to_vec();
        let mut rang = 0_usize;
        while rang < octets.len() {
            let reste = octets.get_mut(rang..).expect("dans le datagramme");
            let Ok(arrivee) = Incoming::read(reste, CLIENT.len()) else {
                return;
            };
            let Some(niveau) = arrivee.kind().and_then(Level::of) else {
                return;
            };
            let espace = niveau.space();
            let quel = Self::rang(espace);
            let clefs: &dyn ams_quic::Protection = match quel {
                0 => &self.initiales_reception,
                _ => match self.dechiffrement[quel].as_ref() {
                    Some(clefs) => clefs,
                    None => return,
                },
            };
            let Ok(ouvert) = open_packet(reste, clefs, self.plus_grand[quel], CLIENT.len()) else {
                return;
            };
            let total = ouvert.total;
            self.plus_grand[quel] =
                Some(self.plus_grand[quel].map_or(ouvert.number, |vu| vu.max(ouvert.number)));
            let charge = reste
                .get(ouvert.payload_at..ouvert.payload_at.saturating_add(ouvert.payload_len))
                .unwrap_or_default()
                .to_vec();
            let mut suite = charge.as_slice();
            let mut sollicite = false;
            while !suite.is_empty() {
                let Ok((trame, lus)) = Frame::parse(suite) else {
                    break;
                };
                suite = suite.get(lus..).unwrap_or_default();
                sollicite |= !matches!(trame, Frame::Ack(_) | Frame::Padding { .. });
                match trame {
                    Frame::ResetStream {
                        stream,
                        code,
                        final_size,
                    } => self.annulations_recues.push((stream, code, final_size)),
                    Frame::Stream {
                        stream,
                        offset,
                        data,
                        fin,
                    } => {
                        // **LES OCTETS SE REPLACENT À LEUR DÉCALAGE**, et ne
                        // s'empilent pas : une retransmission redit ce qui est
                        // déjà là, et les empiler ferait passer un essai de
                        // perte qui ne prouverait rien.
                        let debut = usize::try_from(offset).unwrap_or(usize::MAX);
                        let fin_de = debut.saturating_add(data.len());
                        if self.recu.len() < fin_de {
                            self.recu.resize(fin_de, 0);
                        }
                        self.recu
                            .get_mut(debut..fin_de)
                            .expect("la place vient d'être faite")
                            .copy_from_slice(data);
                        self.flux_recu = Some(stream);
                        self.fin_recue |= fin;
                    }
                    Frame::MaxStreams { maximum, .. } => self.plafond_recu = Some(maximum),
                    Frame::MaxData { maximum } => self.credit_recu = Some(maximum),
                    _ => {}
                }
                if let Frame::Crypto { offset, data } = trame {
                    // **LE DÉCALAGE COMPTE** : un vol coupé en deux arrive en
                    // deux morceaux, et les remettre à TLS dans l'ordre
                    // d'arrivée ferait échouer la vérification du `Finished`.
                    self.reassemblage
                        .on_crypto(niveau, offset, data, &mut self.fenetres[quel])
                        .expect("le client range ce que le serveur dit");
                }
            }
            // Ce qui est devenu contigu part chez TLS, et l'on redemande —
            // §4.1.3, et c'est ce qui installe les clés du niveau suivant.
            let mut vers = std::vec![0_u8; ams_quic::CRYPTO_OCTETS_MAX];
            loop {
                let pris = self
                    .reassemblage
                    .take(niveau, &mut self.fenetres[quel], &mut vers);
                if pris == 0 {
                    break;
                }
                self.tls
                    .read_hs(vers.get(..pris).expect("pris"))
                    .expect("le client accepte ce que le serveur dit");
            }
            self.avancer();
            if sollicite {
                self.a_acquitter[quel].push(ouvert.number);
            }
            rang = rang.saturating_add(total);
        }
    }

    /// Range les clés qu'un changement apporte, et rend le niveau d'émission.
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
}

/// Ce que le client envoie en premier, lu comme le démultiplexeur le lirait.
fn premier(datagramme: &[u8]) -> Incoming {
    Incoming::read(datagramme, ORIGINE.len()).expect("lisible")
}

/// Mène la poignée de main jusqu'au bout, et rend le nombre de tours.
///
/// # ON REDEMANDE À TLS APRÈS CHAQUE LIVRAISON, ET C'EST §4.1.3
///
/// « Each time that TLS is provided with new data, new handshake bytes are
/// requested from TLS. » Ce n'est pas une politesse : **c'est cet appel-là qui
/// installe les clés du niveau suivant**. Sans lui, le client reçoit le vol
/// `Handshake` du serveur alors qu'il n'a pas encore les clés pour l'ouvrir, et
/// la poignée de main tourne en rond.
///
/// La première version de cet essai l'omettait. Le symptôme — « le serveur ne
/// répond plus » — désignait le serveur, et la faute était dans le client.
fn conduire(serveur: &mut Connection, client: &mut Client, horloge: &mut u64) -> usize {
    for tour in 1..=12 {
        let mut du_client = client.parler();
        if !du_client.is_empty() {
            serveur
                .on_datagram(&mut du_client, *horloge)
                .expect("le serveur accepte");
        }
        *horloge = horloge.saturating_add(1_000);

        let mut a_dit = false;
        loop {
            let mut place = std::vec![0_u8; 1_500];
            let ecrit = serveur
                .poll_transmit(&mut place, *horloge)
                .expect("le serveur avance");
            if ecrit == 0 {
                break;
            }
            a_dit = true;
            client.ecouter(place.get(..ecrit).expect("écrit"));
            // §4.1.3 : après chaque donnée remise, on redemande.
            let mut suite = client.parler();
            if !suite.is_empty() {
                serveur
                    .on_datagram(&mut suite, *horloge)
                    .expect("le serveur accepte");
            }
        }
        *horloge = horloge.saturating_add(1_000);
        if serveur.is_established() && !client.tls.is_handshaking() && !a_dit {
            return tour;
        }
    }
    panic!("la poignée de main tourne en rond");
}

/// **UNE POIGNÉE DE MAIN QUIC COMPLÈTE, EN VRAIS PAQUETS.**
///
/// C'est le premier essai où tout est assemblé : le tri, la protection de
/// paquet, les trames, la poignée de main TLS, les acquittements et la garde
/// d'amplification. Si l'un des six se trompait, le client `rustls` refuserait.
#[test]
fn une_poignee_de_main_va_jusqu_au_bout() {
    let atelier = atelier("poignee");
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let mut horloge = 1_000_000_u64;

    let mut client = Client::new(config_client(&autorite, ams_tls::alpn_h3()), SES_PARAMETRES);
    let premier_datagramme = client.parler();
    let arrivee = premier(&premier_datagramme);
    assert_eq!(arrivee.kind(), Some(PacketKind::Long(LongKind::Initial)));
    assert!(
        arrivee.big_enough_for_initial(),
        "§14.1 : le client bourre son premier datagramme"
    );

    let mut serveur = Connection::accept(
        config_serveur(&cert, &cle),
        &arrivee,
        identifiant(&LOCAL),
        identifiant(&CLIENT),
        INACTIVITE_US,
        horloge,
    )
    .expect("le fournisseur sait chiffrer QUIC");
    assert!(!serveur.is_established());
    assert!(!serveur.is_closed());
    assert_eq!(serveur.local_id(), identifiant(&LOCAL));

    // Le premier datagramme est déjà composé : on le donne tel quel, puis la
    // conduite prend le relais.
    serveur
        .on_datagram(&mut premier_datagramme.clone(), horloge)
        .expect("le serveur accepte le ClientHello");
    conduire(&mut serveur, &mut client, &mut horloge);

    assert!(serveur.is_established(), "la poignée de main doit aboutir");
    assert!(!client.tls.is_handshaking(), "le client aussi doit finir");
    assert_eq!(serveur.alpn(), Some(&b"h3"[..]));
    assert_eq!(client.tls.alpn_protocol(), Some(&b"h3"[..]));

    // §8.2 : les paramètres du pair sont authentifiés par la poignée de main.
    let siens = serveur.peer_parameters().expect("le client en a annoncé");
    assert_eq!(siens.initial_max_data, 786_432);

    // Et les nôtres portent ce que §7.3 impose.
    let nos_octets = client
        .tls
        .quic_transport_parameters()
        .expect("le serveur en a annoncé");
    let notres = TransportParameters::read(nos_octets, Sender::Server).expect("relisibles");
    assert_eq!(
        notres.original_destination_connection_id,
        Some(identifiant(&ORIGINE)),
        "§7.3 : le serveur prouve qu'il a vu le premier paquet"
    );
    assert_eq!(
        notres.initial_source_connection_id,
        Some(identifiant(&LOCAL))
    );
    assert_eq!(notres.max_idle_timeout_ms, INACTIVITE_US / 1_000);
    assert_eq!(notres.max_ack_delay_ms, ACQUITTEMENT_MAX_MS);

    // Rien de secret ne s'imprime.
    let dit = std::format!("{serveur:?}");
    assert!(dit.contains("established: true"), "{dit}");
}

/// **LA GARDE D'AMPLIFICATION TIENT** (§8.1).
///
/// Tant que l'adresse du client n'est pas validée, le serveur n'émet jamais plus
/// de trois fois ce qu'il a reçu. **C'est ce qui empêche ce port de servir
/// d'arme** : un attaquant qui usurpe une adresse obtiendrait sinon un
/// amplificateur.
#[test]
fn la_garde_d_amplification_tient() {
    let atelier = atelier("amplification");
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let horloge = 1_000_000_u64;

    let mut client = Client::new(config_client(&autorite, ams_tls::alpn_h3()), SES_PARAMETRES);
    let mut premier_datagramme = client.parler();
    let recu = premier_datagramme.len();
    let arrivee = premier(&premier_datagramme);
    let mut serveur = Connection::accept(
        config_serveur(&cert, &cle),
        &arrivee,
        identifiant(&LOCAL),
        identifiant(&CLIENT),
        INACTIVITE_US,
        horloge,
    )
    .expect("constructible");
    serveur
        .on_datagram(&mut premier_datagramme, horloge)
        .expect("accepté");

    // On tire tout ce que le serveur veut dire, sans jamais lui répondre.
    let mut emis = 0_usize;
    for _ in 0..64 {
        let mut place = std::vec![0_u8; 1_500];
        let ecrit = serveur.poll_transmit(&mut place, horloge).expect("avance");
        if ecrit == 0 {
            break;
        }
        emis = emis.saturating_add(ecrit);
    }
    assert!(emis > 0, "le serveur doit répondre au moins une fois");
    assert!(
        emis <= recu.saturating_mul(3),
        "§8.1 : {emis} octets émis pour {recu} reçus — plus de trois fois"
    );
}

/// **DU BRUIT NE CONDAMNE PAS, ET IL COMPTE QUAND MÊME** (§8.1, §5.2).
///
/// Deux règles se rencontrent ici.
///
/// §5.2 : « Endpoints MUST discard packets that cannot be authenticated. » Un
/// datagramme qu'on n'ouvre pas se jette — **fermer sur lui offrirait la
/// connexion à qui sait envoyer un datagramme**, puisque n'importe qui peut en
/// forger un.
///
/// §8.1 : « servers MUST count all of the payload bytes received in datagrams
/// that are uniquely attributed to a single connection. This includes […]
/// datagrams that contain packets that are all discarded. » Ne pas les compter
/// figerait une connexion dont quelques paquets se perdent en chemin.
///
/// # CE QUE CET ESSAI PEUT MONTRER, ET CE QU'IL NE PEUT PAS
///
/// Le comptage lui-même n'est pas observable ici : avec un certificat sur
/// courbe elliptique, les vols du serveur tiennent largement dans trois fois ce
/// qu'il a reçu, et le budget ne le contraint jamais. Ce qui EST observable,
/// c'est que le bruit ne condamne pas et que la connexion aboutit quand même —
/// ce qu'un `on_datagram` qui refuserait, ou qui perdrait son état, empêcherait.
/// La borne elle-même est éprouvée par `la_garde_d_amplification_tient`.
#[test]
fn du_bruit_ne_condamne_pas() {
    let atelier = atelier("bruit");
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let mut horloge = 1_000_000_u64;

    let mut client = Client::new(config_client(&autorite, ams_tls::alpn_h3()), SES_PARAMETRES);
    let mut premier_datagramme = client.parler();
    let arrivee = premier(&premier_datagramme);
    let mut serveur = Connection::accept(
        config_serveur(&cert, &cle),
        &arrivee,
        identifiant(&LOCAL),
        identifiant(&CLIENT),
        INACTIVITE_US,
        horloge,
    )
    .expect("constructible");
    serveur
        .on_datagram(&mut premier_datagramme, horloge)
        .expect("accepté");

    // Trois sortes de bruit, chacune sur un chemin de refus différent.
    for (quoi, mut bruit) in [
        (
            "des octets qui ne sont pas du QUIC",
            std::vec![0x5a_u8; 1_200],
        ),
        ("un en-tête long tronqué", std::vec![0xc3_u8, 0x00, 0x00]),
        ("des zéros", std::vec![0_u8; 1_200]),
    ] {
        serveur
            .on_datagram(&mut bruit, horloge)
            .expect("du bruit ne condamne pas");
        assert!(!serveur.is_closed(), "{quoi} ne doit pas condamner");
    }

    // Et la poignée de main aboutit malgré tout.
    conduire(&mut serveur, &mut client, &mut horloge);
    assert!(serveur.is_established());
    assert_eq!(serveur.alpn(), Some(&b"h3"[..]));
}

/// **UNE FERMETURE SE DIT** (§10.2), et la connexion s'éteint.
#[test]
fn une_fermeture_se_dit() {
    let atelier = atelier("fermeture");
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let mut horloge = 1_000_000_u64;

    let mut client = Client::new(config_client(&autorite, ams_tls::alpn_h3()), SES_PARAMETRES);
    let mut premier_datagramme = client.parler();
    let arrivee = premier(&premier_datagramme);
    let mut serveur = Connection::accept(
        config_serveur(&cert, &cle),
        &arrivee,
        identifiant(&LOCAL),
        identifiant(&CLIENT),
        INACTIVITE_US,
        horloge,
    )
    .expect("constructible");
    serveur
        .on_datagram(&mut premier_datagramme, horloge)
        .expect("accepté");

    serveur.close(TransportError::NoError, horloge);
    let mut place = std::vec![0_u8; 1_500];
    let ecrit = serveur.poll_transmit(&mut place, horloge).expect("avance");
    assert!(ecrit > 0, "une fermeture doit partir");

    // Et le délai finit par l'éteindre.
    horloge = horloge.saturating_add(60_000_000);
    assert!(serveur.on_timeout(horloge), "elle doit s'éteindre");
    assert!(serveur.is_closed());
    assert_eq!(
        serveur.poll_transmit(&mut place, horloge).expect("avance"),
        0,
        "une connexion éteinte ne dit plus rien"
    );
}

/// **UN CLIENT QUI NE PARLE PAS `h3` N'EST PAS SERVI** (§3.1 de RFC 9114).
#[test]
fn un_client_sans_h3_n_est_pas_servi() {
    let atelier = atelier("alpn");
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let horloge = 1_000_000_u64;

    let mut client = Client::new(
        config_client(&autorite, std::vec![b"h2".to_vec()]),
        SES_PARAMETRES,
    );
    let mut premier_datagramme = client.parler();
    let arrivee = premier(&premier_datagramme);
    let mut serveur = Connection::accept(
        config_serveur(&cert, &cle),
        &arrivee,
        identifiant(&LOCAL),
        identifiant(&CLIENT),
        INACTIVITE_US,
        horloge,
    )
    .expect("constructible");
    // **LE REFUS A LIEU DÈS LE DATAGRAMME**, et non à l'émission qui suit :
    // `on_datagram` fait avancer la poignée de main depuis qu'un `Finished`
    // coalescé avec la première requête doit pouvoir bâtir les flux avant le
    // paquet suivant. La boucle traite les deux fautes de la même façon —
    // `close_with(issue.close_code())` —, si bien que le pair reçoit le même
    // `CONNECTION_CLOSE`, un aller-retour plus tôt.
    let issue = serveur
        .on_datagram(&mut premier_datagramme, horloge)
        .expect_err("un client qui ne parle pas h3 n'est pas servi");
    // §6.2 de RFC 8446 : `no_application_protocol` vaut 120 ; §4.8 de RFC 9001
    // en fait 0x0178.
    assert_eq!(issue.reason(), Reason::Tls(120));
    assert_eq!(issue.close_code(), 0x0178);
}

/// **LE DÉLAI D'INACTIVITÉ FINIT PAR ÉTEINDRE** (§10.1), et l'on sait quand.
#[test]
fn le_delai_d_inactivite_eteint() {
    let atelier = atelier("inactivite");
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let horloge = 1_000_000_u64;

    let mut client = Client::new(config_client(&autorite, ams_tls::alpn_h3()), SES_PARAMETRES);
    let mut premier_datagramme = client.parler();
    let arrivee = premier(&premier_datagramme);
    let mut serveur = Connection::accept(
        config_serveur(&cert, &cle),
        &arrivee,
        identifiant(&LOCAL),
        identifiant(&CLIENT),
        INACTIVITE_US,
        horloge,
    )
    .expect("constructible");
    serveur
        .on_datagram(&mut premier_datagramme, horloge)
        .expect("accepté");

    let quand = serveur.deadline(horloge).expect("il y a un délai");
    assert!(quand > horloge, "un délai est dans l'avenir");
    assert!(
        quand <= horloge.saturating_add(INACTIVITE_US),
        "et pas au-delà de l'inactivité annoncée"
    );

    // Bien après, elle s'éteint.
    let tard = horloge.saturating_add(INACTIVITE_US).saturating_add(1);
    assert!(serveur.on_timeout(tard));
    assert!(serveur.is_closed());
}

/// **UN `0-RTT` NE SE SERT PAS** (§8.3 de RFC 9001, et C6).
///
/// Le conducteur s'arrête devant lui plutôt que de l'ouvrir : nous n'offrons pas
/// les données précoces, et un paquet qu'on ne peut pas déchiffrer ne doit pas
/// faire condamner la connexion.
#[test]
fn un_zero_rtt_ne_se_sert_pas() {
    let atelier = atelier("zero-rtt");
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let horloge = 1_000_000_u64;

    let mut client = Client::new(config_client(&autorite, ams_tls::alpn_h3()), SES_PARAMETRES);
    let premier_datagramme = client.parler();
    let arrivee = premier(&premier_datagramme);
    let mut serveur = Connection::accept(
        config_serveur(&cert, &cle),
        &arrivee,
        identifiant(&LOCAL),
        identifiant(&CLIENT),
        INACTIVITE_US,
        horloge,
    )
    .expect("constructible");

    // Un paquet `0-RTT` fabriqué à la main, avec les clés `Initial` — il ne
    // s'ouvrira pas, et c'est bien le but.
    let mut octets = std::vec::Vec::new();
    octets.push(0xd3_u8); // forme longue, bit fixe, type 0x10, deux octets de numéro
    octets.extend_from_slice(&1_u32.to_be_bytes());
    octets.push(u8::try_from(LOCAL.len()).expect("huit"));
    octets.extend_from_slice(&LOCAL);
    octets.push(0);
    let mut longueur = [0_u8; 8];
    let ecrits = varints::encode(64, &mut longueur).expect("écrivable");
    octets.extend_from_slice(longueur.get(..ecrits).expect("écrits"));
    octets.resize(1_200, 0);

    serveur
        .on_datagram(&mut octets, horloge)
        .expect("un 0-RTT se jette, il ne condamne pas");
    assert!(!serveur.is_closed());
}

/// Monte un serveur et un client, et leur fait faire la poignée de main.
fn etabli(nom: &str) -> (Atelier, Connection, Client, u64) {
    let atelier = atelier(nom);
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let mut horloge = 1_000_000_u64;
    let mut client = Client::new(
        config_client(&autorite, ams_tls::alpn_h3()),
        &ses_parametres_avec_flux(),
    );
    let mut premier_datagramme = client.parler();
    let arrivee = premier(&premier_datagramme);
    let mut serveur = Connection::accept(
        config_serveur(&cert, &cle),
        &arrivee,
        identifiant(&LOCAL),
        identifiant(&CLIENT),
        INACTIVITE_US,
        horloge,
    )
    .expect("constructible");
    serveur
        .on_datagram(&mut premier_datagramme, horloge)
        .expect("accepté");
    conduire(&mut serveur, &mut client, &mut horloge);
    assert!(serveur.is_established());
    (atelier, serveur, client, horloge)
}

/// Fabrique un paquet `1-RTT` portant ces trames, tel que le client l'enverrait.
fn un_paquet_du_client(client: &mut Client, trames: &[u8]) -> Vec<u8> {
    let mut datagramme = Vec::new();
    client.poser(&mut datagramme, Space::Application, trames);
    datagramme
}

/// **UN `Retry` N'A PAS DE NIVEAU, ET S'ARRÊTE LÀ** (§17.2.5).
///
/// C'est un serveur qui l'émet ; en recevoir un ne veut rien dire, et
/// prétendre l'ouvrir demanderait des clés qu'aucun niveau ne porte.
#[test]
fn un_retry_recu_s_arrete_la() {
    let (_atelier, mut serveur, _client, horloge) = etabli("retry");
    let mut octets = std::vec::Vec::new();
    // §17.2.5 : forme longue, bit fixe, type 0x30, puis les identifiants et
    // seize octets de tag.
    octets.push(0xf0_u8);
    octets.extend_from_slice(&1_u32.to_be_bytes());
    octets.push(u8::try_from(LOCAL.len()).expect("huit"));
    octets.extend_from_slice(&LOCAL);
    octets.push(0);
    octets.extend_from_slice(&[0xaa; 16]);
    serveur
        .on_datagram(&mut octets, horloge)
        .expect("un Retry se jette, il ne condamne pas");
    assert!(!serveur.is_closed());
}

/// **UNE TRAME ILLISIBLE ARRÊTE LE PAQUET, ET NE CONDAMNE PAS.**
///
/// §12.4 condamnerait. On se contente de jeter le reste du paquet, qui n'a plus
/// de frontière connue : **le pair réémettra**, et fermer sur une trame qu'on a
/// mal lue coûterait une connexion pour un octet.
#[test]
fn une_trame_illisible_arrete_le_paquet() {
    let (_atelier, mut serveur, mut client, horloge) = etabli("trame-illisible");
    // §19 ne définit pas le type 0x3f, et `Frame::parse` le refuse.
    let mut datagramme = un_paquet_du_client(&mut client, &[0x01, 0x3f, 0x01, 0x02]);
    serveur
        .on_datagram(&mut datagramme, horloge)
        .expect("une trame illisible ne condamne pas");
    assert!(!serveur.is_closed());
}

/// **LES TRAMES QU'ON NE SERT PAS ENCORE SONT IGNORÉES**, et non refusées.
///
/// Ce sont des trames que §19 définit et que §12.4 admet à ce niveau ; on les
/// servira quand le chemin et les jetons viendront. Les refuser fermerait des
/// connexions qu'on servira demain.
#[test]
fn les_trames_qu_on_ne_sert_pas_encore_sont_ignorees() {
    let (_atelier, mut serveur, mut client, horloge) = etabli("trames-ignorees");
    let mut trames = [0_u8; 64];
    let mut pose = 0_usize;
    for trame in [
        Frame::Ping,
        Frame::MaxData { maximum: 1_000_000 },
        // Celles-ci, §12.4 les admet en `1-RTT` et nous ne les servons pas
        // encore : le chemin et les jetons viendront plus tard.
        Frame::NewToken { token: b"jeton" },
        Frame::DataBlocked { limit: 10 },
        Frame::PathChallenge { data: [0; 8] },
    ] {
        let place = trames.get_mut(pose..).expect("de la place");
        pose = pose.saturating_add(trame.write(place).expect("écrivable"));
    }
    let mut datagramme = un_paquet_du_client(&mut client, trames.get(..pose).expect("posées"));
    serveur
        .on_datagram(&mut datagramme, horloge)
        .expect("elles s'ignorent");
    assert!(!serveur.is_closed());
    // Et le `PING` a bien sollicité : le serveur doit un acquittement.
    let mut place = std::vec![0_u8; 1_500];
    assert!(
        serveur.poll_transmit(&mut place, horloge).expect("avance") > 0,
        "un PING sollicite un acquittement (§19.2)"
    );
}

/// **LE PAIR PEUT FERMER** (§10.2.2), et l'on entre alors en `Draining`.
///
/// « An endpoint in the draining state MUST NOT send any packets. » Sans cette
/// règle, deux pairs qui se répondent échangeraient des `CONNECTION_CLOSE`
/// jusqu'à ce que l'un des deux abandonne.
#[test]
fn le_pair_peut_fermer() {
    let (_atelier, mut serveur, mut client, horloge) = etabli("pair-ferme");
    let mut trames = [0_u8; 32];
    let close = Frame::ConnectionClose {
        code: 0,
        frame_type: Some(0),
        reason: &[],
    };
    let ecrits = close.write(&mut trames).expect("écrivable");
    let mut datagramme = un_paquet_du_client(&mut client, trames.get(..ecrits).expect("écrites"));
    serveur
        .on_datagram(&mut datagramme, horloge)
        .expect("une fermeture se lit");

    let mut place = std::vec![0_u8; 1_500];
    assert_eq!(
        serveur.poll_transmit(&mut place, horloge).expect("avance"),
        0,
        "§10.2.2 : en Draining, on n'émet plus rien"
    );
}

/// **UNE FERMETURE SE REDIT SUR ARRIVÉE, DE MOINS EN MOINS SOUVENT** (§10.2.1).
///
/// Un pair qui continue d'émettre — parce qu'il n'a pas reçu notre fermeture, ou
/// parce qu'il le fait exprès — obtiendrait sinon une réponse par paquet, et
/// l'on amplifierait au moment précis où l'on n'a plus rien à dire.
#[test]
fn une_fermeture_se_redit_de_moins_en_moins() {
    let (_atelier, mut serveur, mut client, horloge) = etabli("redite");
    serveur.close(TransportError::NoError, horloge);
    let mut place = std::vec![0_u8; 1_500];
    assert!(
        serveur.poll_transmit(&mut place, horloge).expect("avance") > 0,
        "la première part tout de suite"
    );
    assert_eq!(
        serveur.poll_transmit(&mut place, horloge).expect("avance"),
        0,
        "et pas deux fois de suite"
    );

    // Un paquet arrive : on la redit.
    let mut trames = [0_u8; 8];
    let ecrits = Frame::Ping.write(&mut trames).expect("écrivable");
    let mut datagramme = un_paquet_du_client(&mut client, trames.get(..ecrits).expect("écrite"));
    serveur
        .on_datagram(&mut datagramme.clone(), horloge)
        .expect("accepté");
    assert!(
        serveur.poll_transmit(&mut place, horloge).expect("avance") > 0,
        "§10.2.1 : on répond au premier paquet reçu"
    );
    // **AU PREMIER, AU DEUXIÈME, AU QUATRIÈME** : l'écart double, et le coût
    // total reste logarithmique. Le troisième est donc sauté.
    serveur
        .on_datagram(&mut datagramme.clone(), horloge)
        .expect("accepté");
    assert!(
        serveur.poll_transmit(&mut place, horloge).expect("avance") > 0,
        "on répond encore au deuxième"
    );
    serveur
        .on_datagram(&mut datagramme, horloge)
        .expect("accepté");
    assert_eq!(
        serveur.poll_transmit(&mut place, horloge).expect("avance"),
        0,
        "et l'on saute le troisième : l'écart a doublé"
    );
}

/// **UN PAQUET PERDU REPART, ET LE SONDAGE LE PROVOQUE** (§6.2 de RFC 9002).
///
/// On établit la connexion, puis on laisse le temps passer sans rien acquitter :
/// le sondage échoit, le serveur réémet, et ce qu'il réémet SOLLICITE — sans
/// quoi il ne provoquerait pas l'acquittement qui le rendrait utile (§6.2.4).
#[test]
fn un_sondage_finit_par_partir() {
    let (_atelier, mut serveur, mut client, mut horloge) = etabli("sondage");
    // On fait dire quelque chose au serveur, sans jamais l'acquitter.
    let mut trames = [0_u8; 8];
    let ecrits = Frame::Ping.write(&mut trames).expect("écrivable");
    let mut datagramme = un_paquet_du_client(&mut client, trames.get(..ecrits).expect("écrite"));
    serveur
        .on_datagram(&mut datagramme, horloge)
        .expect("accepté");
    let mut place = std::vec![0_u8; 1_500];
    while serveur.poll_transmit(&mut place, horloge).expect("avance") > 0 {}

    // Le délai dit quand se réveiller, et il est dans l'avenir.
    let quand = serveur.deadline(horloge).expect("il y a un délai");
    assert!(quand > horloge);

    // Bien après, le sondage échoit — et il fait repartir quelque chose.
    horloge = quand.saturating_add(1);
    assert!(!serveur.on_timeout(horloge), "elle ne s'éteint pas encore");
    let ecrit = serveur.poll_transmit(&mut place, horloge).expect("avance");
    assert!(ecrit > 0, "un sondage doit partir");
    // Et il est lisible par le client.
    client.ecouter(place.get(..ecrit).expect("écrit"));
}

/// **LE BUDGET D'AMPLIFICATION FINIT PAR TOUT TAIRE** (§8.1).
///
/// Quand il est épuisé, `poll_transmit` ne rend plus rien — et c'est ce silence
/// qui empêche ce port de servir d'arme. §8.1 décrit l'interblocage qui en
/// découle, et le remet au client : c'est à lui de parler pour rouvrir le
/// budget.
#[test]
fn le_budget_epuise_fait_taire() {
    let atelier = atelier("budget-epuise");
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let horloge = 1_000_000_u64;
    let mut client = Client::new(config_client(&autorite, ams_tls::alpn_h3()), SES_PARAMETRES);
    let mut premier_datagramme = client.parler();
    let arrivee = premier(&premier_datagramme);
    let mut serveur = Connection::accept(
        config_serveur(&cert, &cle),
        &arrivee,
        identifiant(&LOCAL),
        identifiant(&CLIENT),
        INACTIVITE_US,
        horloge,
    )
    .expect("constructible");
    serveur
        .on_datagram(&mut premier_datagramme, horloge)
        .expect("accepté");

    // On tire tout, sans jamais répondre. Le budget vaut trois fois ce qui est
    // arrivé, et il finit donc par se fermer.
    let mut place = std::vec![0_u8; 1_500];
    let mut tours = 0_usize;
    while serveur.poll_transmit(&mut place, horloge).expect("avance") > 0 {
        tours = tours.saturating_add(1);
        assert!(tours < 64, "le budget devrait avoir fermé la bouche");
    }
    assert_eq!(
        serveur.poll_transmit(&mut place, horloge).expect("avance"),
        0
    );
}

/// **UN `Initial` QUI ARRIVE APRÈS QUE SES CLÉS SONT JETÉES S'ARRÊTE LÀ**
/// (§4.9.1 de RFC 9001).
///
/// « a server MUST discard Initial keys when it first successfully processes a
/// Handshake packet. » Les garder laisserait ouverte une porte que personne n'a
/// plus de raison d'emprunter — et cette porte-là n'est authentifiée par
/// personne.
#[test]
fn un_initial_tardif_s_arrete_la() {
    let (_atelier, mut serveur, mut client, horloge) = etabli("initial-tardif");
    // Un paquet `Initial`, fabriqué avec les clés que tout le monde connaît.
    let mut trames = [0_u8; 8];
    let ecrits = Frame::Ping.write(&mut trames).expect("écrivable");
    let mut datagramme = Vec::new();
    client.poser(
        &mut datagramme,
        Space::Initial,
        trames.get(..ecrits).expect("écrite"),
    );
    datagramme.resize(1_200, 0);
    serveur
        .on_datagram(&mut datagramme, horloge)
        .expect("il se jette, il ne condamne pas");
    assert!(!serveur.is_closed());
}

/// **UNE FERMETURE AVANT TOUTE CLÉ PART EN `Initial`** (§10.2.3).
///
/// « endpoints MUST send a CONNECTION_CLOSE frame in an Initial or Handshake
/// packet if the handshake has not completed. » Sans cela, le pair ne pourrait
/// pas la lire, et attendrait son délai d'inactivité sans savoir pourquoi.
#[test]
fn une_fermeture_sans_clefs_part_en_initial() {
    let atelier = atelier("fermeture-initial");
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let horloge = 1_000_000_u64;
    let mut client = Client::new(config_client(&autorite, ams_tls::alpn_h3()), SES_PARAMETRES);
    let premier_datagramme = client.parler();
    let arrivee = premier(&premier_datagramme);
    let mut serveur = Connection::accept(
        config_serveur(&cert, &cle),
        &arrivee,
        identifiant(&LOCAL),
        identifiant(&CLIENT),
        INACTIVITE_US,
        horloge,
    )
    .expect("constructible");

    // **UN DATAGRAMME SANS `CRYPTO`** : il ouvre le budget d'amplification
    // (§8.1) sans faire avancer la poignée de main, donc aucune clé n'existe
    // encore. C'est le seul état où la fermeture doit partir en `Initial`.
    //
    // Sans lui, rien ne partirait — et ce serait juste : §8.1 interdit à un
    // serveur d'émettre avant d'avoir reçu.
    let mut trames = [0_u8; 8];
    let ecrits = Frame::Ping.write(&mut trames).expect("écrivable");
    let mut sans_crypto = Vec::new();
    client.poser(
        &mut sans_crypto,
        Space::Initial,
        trames.get(..ecrits).expect("écrite"),
    );
    sans_crypto.resize(1_200, 0);
    serveur
        .on_datagram(&mut sans_crypto, horloge)
        .expect("accepté");

    serveur.close(TransportError::ConnectionRefused, horloge);
    let mut place = std::vec![0_u8; 1_500];
    let ecrit = serveur.poll_transmit(&mut place, horloge).expect("avance");
    assert!(ecrit > 0, "elle doit partir quand même");

    let arrivee =
        Incoming::read(place.get(..ecrit).expect("écrit"), CLIENT.len()).expect("lisible");
    assert_eq!(
        arrivee.kind(),
        Some(PacketKind::Long(LongKind::Initial)),
        "§10.2.3 : le pair doit pouvoir la lire"
    );
}

/// **UN TAMPON TROP PETIT NE FAIT RIEN ÉMETTRE**, plutôt qu'un paquet tronqué.
///
/// §5.4.2 impose un plancher de charge ; en deçà, il n'y a pas de paquet
/// possible, et en fabriquer un que le pair **MUST** jeter serait pire que de se
/// taire.
#[test]
fn un_tampon_trop_petit_ne_fait_rien_emettre() {
    let (_atelier, mut serveur, mut client, horloge) = etabli("tampon-petit");
    // On lui donne de quoi vouloir parler.
    let mut trames = [0_u8; 8];
    let ecrits = Frame::Ping.write(&mut trames).expect("écrivable");
    let mut datagramme = un_paquet_du_client(&mut client, trames.get(..ecrits).expect("écrite"));
    serveur
        .on_datagram(&mut datagramme, horloge)
        .expect("accepté");

    for taille in [1_usize, 8, 24] {
        let mut minuscule = std::vec![0_u8; taille];
        assert_eq!(
            serveur
                .poll_transmit(&mut minuscule, horloge)
                .expect("avance"),
            0,
            "{taille} octets ne portent pas un paquet"
        );
    }
    // Et avec de la place, il parle.
    let mut place = std::vec![0_u8; 1_500];
    assert!(serveur.poll_transmit(&mut place, horloge).expect("avance") > 0);
}

/// **LA POIGNÉE DE MAIN SURVIT À UN DATAGRAMME PERDU** (§6 de RFC 9002).
///
/// # LA PERTE SE FABRIQUE EN JETANT UN DATAGRAMME EN CHEMIN
///
/// §A.10 ne condamne que ce qui est parti AVANT un paquet acquitté : « if
/// unacked.packet_number > largest_acked_packet, continue ». Cesser
/// d'acquitter ne suffit donc pas — il faut un TROU, c'est-à-dire un paquet
/// perdu suivi d'un paquet reçu. C'est exactement ce qu'un réseau fait.
///
/// **C'est l'essai qui compte le plus de cette tranche** : sans détection de
/// perte ni retransmission, une poignée de main ne survivrait pas au premier
/// datagramme égaré, et QUIC n'a pas de retransmission automatique.
#[test]
fn la_poignee_de_main_survit_a_un_datagramme_perdu() {
    let atelier = atelier("perte");
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let mut horloge = 1_000_000_u64;
    let mut client = Client::new(config_client(&autorite, ams_tls::alpn_h3()), SES_PARAMETRES);
    let mut premier_datagramme = client.parler();
    let arrivee = premier(&premier_datagramme);
    let mut serveur = Connection::accept(
        config_serveur(&cert, &cle),
        &arrivee,
        identifiant(&LOCAL),
        identifiant(&CLIENT),
        INACTIVITE_US,
        horloge,
    )
    .expect("constructible");
    serveur
        .on_datagram(&mut premier_datagramme, horloge)
        .expect("accepté");

    let mut place = std::vec![0_u8; 1_500];
    let mut vus = 0_usize;
    let mut perdu = false;
    for _ in 0..16 {
        let mut du_client = client.parler();
        if !du_client.is_empty() {
            serveur
                .on_datagram(&mut du_client, horloge)
                .expect("accepté");
        }
        loop {
            let ecrit = serveur.poll_transmit(&mut place, horloge).expect("avance");
            if ecrit == 0 {
                break;
            }
            vus = vus.saturating_add(1);
            // **LE DEUXIÈME DATAGRAMME DU SERVEUR N'ARRIVE JAMAIS.** Le premier
            // porte le `ServerHello`, sans lequel rien ne peut avancer ; le
            // second porte une partie du certificat, et c'est celui-là qu'on
            // égare.
            if vus == 2 {
                perdu = true;
                continue;
            }
            client.ecouter(place.get(..ecrit).expect("écrit"));
            let mut suite = client.parler();
            if !suite.is_empty() {
                serveur.on_datagram(&mut suite, horloge).expect("accepté");
            }
        }
        // Le temps passe : c'est lui qui fait constater la perte (§6.1.2), et
        // qui fait échoir le sondage (§6.2).
        horloge = horloge.saturating_add(200_000);
        serveur.on_timeout(horloge);
        if serveur.is_established() && !client.tls.is_handshaking() {
            break;
        }
    }

    assert!(perdu, "un datagramme devait se perdre");
    assert!(
        serveur.is_established(),
        "la poignée de main doit aboutir malgré la perte"
    );
    assert!(!client.tls.is_handshaking());
    assert_eq!(serveur.alpn(), Some(&b"h3"[..]));
}

/// **UN `ACK` MAL FORMÉ CONDAMNE** (§19.3.1).
///
/// Un intervalle qui descend sous zéro n'est pas un acquittement : le lire à
/// moitié ferait déclarer perdus des paquets qui ne le sont pas, et une
/// retransmission inutile coûte à la fois de la bande passante et une fenêtre de
/// congestion. **Celui-là vient d'un pair AUTHENTIFIÉ**, donc on ferme.
#[test]
fn un_acquittement_mal_forme_condamne() {
    let (_atelier, mut serveur, mut client, horloge) = etabli("ack-mal-forme");
    let mut trames = [0_u8; 32];
    // §19.3.1 : le premier intervalle descend de `first_range` sous `largest`.
    let ack = Frame::Ack(ams_proto_quic::Ack {
        largest: 1,
        delay: 0,
        first_range: 1_000,
        range_count: 0,
        encoded_ranges: &[],
        ecn: None,
    });
    let ecrits = ack.write(&mut trames).expect("écrivable");
    let mut datagramme = un_paquet_du_client(&mut client, trames.get(..ecrits).expect("écrite"));
    let issue = serveur
        .on_datagram(&mut datagramme, horloge)
        .expect_err("§19.3.1 le condamne");
    assert_eq!(issue.reason(), Reason::Quic(ams_quic::Reason::TooManyHoles));
}

/// **UN `ACK` DÉJÀ VU N'ACQUITTE RIEN DE NEUF, ET NE MESURE RIEN** (§5.1 de
/// RFC 9002).
///
/// §13.2.3 de RFC 9000 fait réacquitter ce qui l'a déjà été, au cas où le
/// précédent se serait perdu. Prendre un échantillon de trajet sur celui-là
/// mesurerait le temps écoulé depuis un envoi bien plus ancien, et **gonflerait
/// le trajet estimé** — donc tous les délais qui en dépendent.
#[test]
fn un_acquittement_deja_vu_ne_mesure_rien() {
    let (_atelier, mut serveur, mut client, horloge) = etabli("ack-deja-vu");
    let mut trames = [0_u8; 32];
    let ack = Frame::Ack(ams_proto_quic::Ack {
        largest: 0,
        delay: 0,
        first_range: 0,
        range_count: 0,
        encoded_ranges: &[],
        ecn: None,
    });
    let ecrits = ack.write(&mut trames).expect("écrivable");
    let datagramme = un_paquet_du_client(&mut client, trames.get(..ecrits).expect("écrite"));

    // Deux fois le même : la seconde n'acquitte plus rien de neuf.
    for _ in 0..2 {
        serveur
            .on_datagram(&mut datagramme.clone(), horloge)
            .expect("un ACK réémis se lit comme un autre");
    }
    assert!(!serveur.is_closed());
}

/// **CE QUI N'EST PAS PERDU RESTE EN ATTENTE** (§A.10 de RFC 9002).
///
/// « if unacked.packet_number > largest_acked_packet: continue » — un paquet
/// parti APRÈS celui qu'on acquitte n'est pas en retard, il est en route.
/// Et sous le seuil de trois rangs, un paquet plus ancien attend encore son
/// délai. **Les jeter tous parce que l'un manque ferait retransmettre ce qui
/// arrive** : de la bande passante gaspillée, et une fenêtre de congestion qui
/// se referme pour rien.
#[test]
fn ce_qui_n_est_pas_perdu_reste_en_attente() {
    let (_atelier, mut serveur, mut client, horloge) = etabli("attente");
    let mut trames = [0_u8; 8];
    let ecrits = Frame::Ping.write(&mut trames).expect("écrivable");
    let mut place = std::vec![0_u8; 1_500];

    // Six échanges : le serveur émet six paquets d'acquittement, qu'on ne lui
    // acquitte pas.
    for _ in 0..6 {
        let mut datagramme =
            un_paquet_du_client(&mut client, trames.get(..ecrits).expect("écrite"));
        serveur
            .on_datagram(&mut datagramme, horloge)
            .expect("accepté");
        while serveur.poll_transmit(&mut place, horloge).expect("avance") > 0 {}
    }

    // Puis un acquittement qui ne désigne que le quatrième : le premier est
    // trois rangs derrière — perdu —, les deuxième et troisième ne le sont pas
    // encore, et les deux derniers ne sont même pas jugeables.
    let mut trames = [0_u8; 32];
    let ack = Frame::Ack(ams_proto_quic::Ack {
        largest: 3,
        delay: 0,
        first_range: 0,
        range_count: 0,
        encoded_ranges: &[],
        ecn: None,
    });
    let ecrits = ack.write(&mut trames).expect("écrivable");
    let mut datagramme = un_paquet_du_client(&mut client, trames.get(..ecrits).expect("écrite"));
    serveur
        .on_datagram(&mut datagramme, horloge)
        .expect("un acquittement partiel se lit");
    assert!(!serveur.is_closed());
}

/// **`Sortie` EST UNE PETITE MACHINE, ET ELLE S'ÉPROUVE SEULE.**
///
/// Elle décide ce qui repart après une perte. Ses trois règles ne se voient pas
/// dans une poignée de main qui réussit — il faut les regarder de près.
#[test]
fn le_flux_crypto_a_emettre_suit_ses_trois_regles() {
    let mut sortie = super::Sortie::default();
    sortie.octets.extend_from_slice(b"abcdefghij");
    assert_eq!(sortie.en_attente(), (0, &b"abcdefghij"[..]));

    // Ce qui part avance le curseur, et n'attend plus.
    sortie.on_sent(4);
    assert_eq!(sortie.en_attente(), (4, &b"efghij"[..]));

    // **SEUL LE PRÉFIXE CONTIGU AVANCE.** Un acquittement qui arrive dans le
    // désordre ne crédite rien : sauter le trou ferait croire confirmé ce qui
    // ne l'est pas, et une perte ultérieure ne serait jamais rattrapée.
    sortie.on_acked(6, 2);
    assert_eq!(sortie.acquitte, 0, "le trou de 0 à 6 n'est pas comblé");
    sortie.on_acked(0, 4);
    assert_eq!(sortie.acquitte, 4, "et là, le préfixe avance");

    // Ce qui se perd fait reculer le curseur : tout ce qui suit repartira.
    sortie.on_sent(6);
    assert_eq!(sortie.en_attente(), (10, &b""[..]));
    sortie.on_lost(4);
    assert_eq!(sortie.en_attente(), (4, &b"efghij"[..]));
    // **ET L'ON NE RECULE JAMAIS AU-DELÀ** : une perte plus récente que le
    // curseur ne le fait pas avancer.
    sortie.on_lost(8);
    assert_eq!(sortie.en_attente(), (4, &b"efghij"[..]));
}

/// **UN FOURNISSEUR SANS QUIC SE REFUSE DÈS L'ACCUEIL.**
///
/// C'est la faute qu'un développeur rencontrera en premier, et elle doit se dire
/// au montage — pas à la première connexion.
#[test]
fn un_fournisseur_sans_quic_ne_donne_pas_de_connexion() {
    let atelier = atelier("accueil-sans-quic");
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let horloge = 1_000_000_u64;
    let mut client = Client::new(config_client(&autorite, ams_tls::alpn_h3()), SES_PARAMETRES);
    let premier_datagramme = client.parler();
    let arrivee = premier(&premier_datagramme);

    let mut config = ams_tls::server_config(&cert, &cle).expect("la paire est bonne");
    config.alpn_protocols = ams_tls::alpn_h3();
    let issue = Connection::accept(
        Arc::new(config),
        &arrivee,
        identifiant(&LOCAL),
        identifiant(&CLIENT),
        INACTIVITE_US,
        horloge,
    )
    .expect_err("le fournisseur ordinaire ne sait pas chiffrer QUIC");
    assert_eq!(issue.reason(), Reason::NoQuicSuite);
}

/// **UN RÉVEIL QUI N'EST PAS UN SONDAGE NE COMPTE PAS** (§6.2.1 de RFC 9002).
///
/// Le compte de sondages DOUBLE le délai suivant. L'incrémenter à chaque réveil
/// — y compris ceux qui ne viennent que d'un acquittement dû — ferait grandir ce
/// délai sans raison, et une connexion qui perd un paquet mettrait des secondes
/// à s'en apercevoir.
#[test]
fn un_reveil_qui_n_est_pas_un_sondage_ne_compte_pas() {
    let (_atelier, mut serveur, _client, horloge) = etabli("reveil");
    // Juste après l'établissement, rien n'a échu.
    assert!(!serveur.on_timeout(horloge));
    assert!(!serveur.is_closed());
    let mut place = std::vec![0_u8; 1_500];
    assert_eq!(
        serveur.poll_transmit(&mut place, horloge).expect("avance"),
        0,
        "un réveil sans échéance ne fait rien partir"
    );
}

/// **DES PARAMÈTRES DE TRANSPORT ILLISIBLES CONDAMNENT** (§7.4 de RFC 9000).
///
/// « An endpoint MUST treat receipt of transport parameters that it cannot
/// process as a connection error of type TRANSPORT_PARAMETER_ERROR. » Les
/// ignorer laisserait la connexion tourner sur des limites qu'on aurait
/// inventées — et le pair, lui, tiendrait les siennes.
#[test]
fn des_parametres_illisibles_condamnent() {
    let atelier = atelier("parametres");
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let mut horloge = 1_000_000_u64;
    // §18 veut des triplets ; ces octets-là n'en font pas un.
    let mut client = Client::new(
        config_client(&autorite, ams_tls::alpn_h3()),
        b"\xff\xff\xff",
    );
    let mut premier_datagramme = client.parler();
    let arrivee = premier(&premier_datagramme);
    let mut serveur = Connection::accept(
        config_serveur(&cert, &cle),
        &arrivee,
        identifiant(&LOCAL),
        identifiant(&CLIENT),
        INACTIVITE_US,
        horloge,
    )
    .expect("constructible");
    serveur
        .on_datagram(&mut premier_datagramme, horloge)
        .expect("accepté");

    // La faute peut venir de l'une ou de l'autre : voir
    // `une_poignee_sans_alpn_n_est_pas_servie`. Ce qui compte est la RAISON.
    let mut place = std::vec![0_u8; 1_500];
    let issue = loop {
        let donner = |serveur: &mut Connection, client: &mut Client| {
            let mut suite = client.parler();
            match suite.is_empty() {
                true => Ok(false),
                false => serveur.on_datagram(&mut suite, horloge).map(|()| true),
            }
        };
        match serveur.poll_transmit(&mut place, horloge) {
            Ok(0) => {
                match donner(&mut serveur, &mut client) {
                    Ok(true) => {}
                    Ok(false) => panic!("le serveur aurait dû refuser"),
                    Err(issue) => break issue,
                }
                horloge = horloge.saturating_add(1_000);
            }
            Ok(ecrit) => {
                client.ecouter(place.get(..ecrit).expect("écrit"));
                if let Err(issue) = donner(&mut serveur, &mut client) {
                    break issue;
                }
            }
            Err(issue) => break issue,
        }
    };
    assert_eq!(issue.reason(), Reason::BadParameters);
    // §20.1 : `TRANSPORT_PARAMETER_ERROR` vaut 0x08.
    assert_eq!(issue.close_code(), 0x08);
}

/// **CE QUI NE TIENT PAS NE PART PAS**, et le paquet part quand même.
///
/// La place d'un paquet est bornée par le budget d'amplification (§8.1), par la
/// fenêtre de congestion (§7 de RFC 9002) et par le datagramme lui-même. Quand
/// elle devient étroite, chaque trame qu'on voudrait poser peut ne plus entrer —
/// et **la sauter vaut mieux que d'écrire un paquet tronqué**, que le pair
/// jetterait sans rien en tirer.
///
/// On éprouve les quatre états où quelque chose attend d'être dit : un
/// acquittement dû, une fermeture, la confirmation de §19.20, et un sondage.
#[test]
fn ce_qui_ne_tient_pas_ne_part_pas() {
    let mut trames = [0_u8; 8];
    let ecrits = Frame::Ping.write(&mut trames).expect("écrivable");

    for (quoi, fermer) in [("en cours", false), ("en fermeture", true)] {
        let (_atelier, mut serveur, mut client, mut horloge) =
            etabli(&std::format!("etroit-{}", fermer));
        // De quoi devoir un acquittement, et de quoi sonder.
        let mut datagramme =
            un_paquet_du_client(&mut client, trames.get(..ecrits).expect("écrite"));
        serveur
            .on_datagram(&mut datagramme, horloge)
            .expect("accepté");
        if fermer {
            serveur.close(TransportError::NoError, horloge);
        }
        horloge = horloge.saturating_add(10_000_000);
        serveur.on_timeout(horloge);

        // Des tampons de plus en plus larges : certains ne portent rien, et
        // aucun ne doit paniquer ni écrire de travers.
        for taille in [20_usize, 26, 28, 30, 32, 36, 44, 60] {
            let mut place = std::vec![0_u8; taille];
            let ecrit = serveur
                .poll_transmit(&mut place, horloge)
                .unwrap_or_else(|_| panic!("{quoi}, {taille} octets"));
            assert!(ecrit <= taille, "{quoi}, {taille} octets : {ecrit} écrits");
        }
        assert!(!serveur.is_closed() || fermer);
    }
}

/// **UN `CRYPTO` À UN NIVEAU DÉJÀ DÉPASSÉ CONDAMNE** (§4.1.3 de RFC 9001).
///
/// « If the packet is from a previously installed encryption level, it MUST NOT
/// contain data that extends past the end of previously received data in that
/// flow. » Ces octets-là entreraient dans une transcription que le pair croit
/// close : **ce que les deux côtés ont haché différerait**, et c'est ce que la
/// poignée de main est censée rendre impossible.
#[test]
fn un_crypto_a_un_niveau_depasse_condamne() {
    let (_atelier, mut serveur, mut client, horloge) = etabli("crypto-tardif");
    let mut trames = [0_u8; 64];
    let trame = Frame::Crypto {
        offset: 4_000,
        data: b"du neuf, bien apres",
    };
    let ecrits = trame.write(&mut trames).expect("écrivable");
    let mut datagramme = Vec::new();
    client.poser(
        &mut datagramme,
        Space::Handshake,
        trames.get(..ecrits).expect("écrite"),
    );
    let issue = serveur
        .on_datagram(&mut datagramme, horloge)
        .expect_err("§4.1.3 le condamne");
    assert_eq!(
        issue.reason(),
        Reason::Quic(ams_quic::Reason::CryptoAfterLevel)
    );
    // §20.1 : `PROTOCOL_VIOLATION`.
    assert_eq!(issue.close_code(), 0x0a);
}

/// **UNE POIGNÉE DE MAIN SANS ALPN N'EST PAS SERVIE** (§3.1 de RFC 9114).
///
/// `rustls` ne fait respecter l'ALPN que si la configuration en annonce un. Une
/// configuration qui n'en annonce aucun laisse donc passer une poignée de main
/// où rien n'a été négocié — et **on servirait alors un protocole qu'on n'a pas
/// annoncé**. C'est la ceinture de `check_alpn`, et voici ce qu'elle retient.
#[test]
fn une_poignee_sans_alpn_n_est_pas_servie() {
    let atelier = atelier("sans-alpn");
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let mut horloge = 1_000_000_u64;
    // **NI L'UN NI L'AUTRE N'ANNONCE D'ALPN** : `rustls` n'a alors rien à faire
    // respecter, et la poignée de main aboutit sans que rien soit négocié.
    //
    // Un client qui, lui, en annonce un se fait refuser par `rustls` avec
    // `no_application_protocol` — c'est ce qu'éprouve
    // `un_client_sans_h3_n_est_pas_servi`. La ceinture de `check_alpn` ne sert
    // que dans ce cas-ci, où l'amont n'a plus rien à dire.
    let config = Arc::new(ams_tls::quic_server_config(&cert, &cle).expect("la paire est bonne"));
    let mut client = Client::new(config_client(&autorite, Vec::new()), SES_PARAMETRES);
    let mut premier_datagramme = client.parler();
    let arrivee = premier(&premier_datagramme);
    let mut serveur = Connection::accept(
        config,
        &arrivee,
        identifiant(&LOCAL),
        identifiant(&CLIENT),
        INACTIVITE_US,
        horloge,
    )
    .expect("constructible");
    serveur
        .on_datagram(&mut premier_datagramme, horloge)
        .expect("accepté");

    // **LA FAUTE PEUT VENIR DE L'UNE OU DE L'AUTRE** : depuis que `on_datagram`
    // fait avancer la poignée de main — pour qu'un `Finished` coalescé bâtisse
    // les flux avant le paquet qui suit —, c'est lui qui la voit le premier.
    // La boucle de service les traite de la même façon, et cet essai aussi : ce
    // qui compte est la RAISON, non l'appel qui la rend.
    let mut place = std::vec![0_u8; 1_500];
    let issue = loop {
        let donner = |serveur: &mut Connection, client: &mut Client| {
            let mut suite = client.parler();
            match suite.is_empty() {
                true => Ok(false),
                false => serveur.on_datagram(&mut suite, horloge).map(|()| true),
            }
        };
        match serveur.poll_transmit(&mut place, horloge) {
            Ok(0) => {
                match donner(&mut serveur, &mut client) {
                    Ok(true) => {}
                    Ok(false) => panic!("le serveur aurait dû refuser"),
                    Err(issue) => break issue,
                }
                horloge = horloge.saturating_add(1_000);
            }
            Ok(ecrit) => {
                client.ecouter(place.get(..ecrit).expect("écrit"));
                if let Err(issue) = donner(&mut serveur, &mut client) {
                    break issue;
                }
            }
            Err(issue) => break issue,
        }
    };
    assert_eq!(issue.reason(), Reason::WrongAlpn);
    // §4.8 : 0x0100 + `no_application_protocol` (120).
    assert_eq!(issue.close_code(), 0x0178);
}

/// **UNE FERMETURE QUI NE TIENT PAS ATTEND LE PROCHAIN PAQUET** (§10.2).
///
/// Quand la place manque après l'acquittement, la fermeture ne part pas — et
/// **elle reste due** : `a_dire` n'est levé que si elle est réellement écrite.
/// L'oublier ferait disparaître la fermeture, et le pair attendrait son délai
/// d'inactivité sans savoir pourquoi.
///
/// # L'ARITHMÉTIQUE DE CET ESSAI
///
/// L'en-tête court fait cinq octets ici — un de forme, quatre d'identifiant —,
/// le numéro un, le tag seize : la charge disponible vaut la taille moins
/// vingt-deux. Un acquittement en occupe cinq ou six, une fermeture quatre.
/// **Entre les deux, il y a un intervalle où l'un passe et l'autre pas**, et
/// c'est celui-là qu'on vise.
#[test]
fn une_fermeture_qui_ne_tient_pas_attend() {
    let (_atelier, mut serveur, mut client, horloge) = etabli("fermeture-etroite");
    let mut trames = [0_u8; 8];
    let ecrits = Frame::Ping.write(&mut trames).expect("écrivable");
    serveur.close(TransportError::NoError, horloge);

    let mut parti = false;
    for taille in [28_usize, 29, 30, 31, 32] {
        // **ON RÉARME AVANT CHAQUE ESSAI, AVEC DES PAQUETS NEUFS.** Réémettre le
        // même numéro ne réarmerait rien : un doublon n'est pas une arrivée, et
        // n'appelle donc pas d'acquittement. §10.2.1 fait par ailleurs répondre
        // au premier paquet reçu, au deuxième, au quatrième — huit arrivées
        // garantissent qu'au moins l'une redit la fermeture.
        for _ in 0..8 {
            let mut neuf = un_paquet_du_client(&mut client, trames.get(..ecrits).expect("écrite"));
            serveur.on_datagram(&mut neuf, horloge).expect("accepté");
        }
        let mut etroit = std::vec![0_u8; taille];
        let ecrit = serveur.poll_transmit(&mut etroit, horloge).expect("avance");
        parti |= ecrit > 0;
        assert!(ecrit <= taille, "{taille} octets : {ecrit} écrits");
    }
    assert!(parti, "l'acquittement, lui, part");

    // Et avec de la place, la fermeture part enfin.
    let mut large = std::vec![0_u8; 1_500];
    for _ in 0..16 {
        let mut neuf = un_paquet_du_client(&mut client, trames.get(..ecrits).expect("écrite"));
        serveur.on_datagram(&mut neuf, horloge).expect("accepté");
    }
    assert!(
        serveur.poll_transmit(&mut large, horloge).expect("avance") > 0,
        "la fermeture est toujours due"
    );
}

/// **UN `CRYPTO` QUI NE TIENT PAS ATTEND SON TOUR** (§12.2).
///
/// La trame porte un type, un décalage et une longueur avant ses octets. Quand
/// il ne reste pas de quoi les écrire, on n'écrit rien plutôt qu'une trame vide :
/// **une trame `CRYPTO` sans octets ne dit rien et coûte un paquet.**
#[test]
fn un_crypto_qui_ne_tient_pas_attend_son_tour() {
    let atelier = atelier("crypto-etroit");
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let mut horloge = 1_000_000_u64;
    let mut client = Client::new(config_client(&autorite, ams_tls::alpn_h3()), SES_PARAMETRES);
    let mut premier_datagramme = client.parler();
    let arrivee = premier(&premier_datagramme);
    let mut serveur = Connection::accept(
        config_serveur(&cert, &cle),
        &arrivee,
        identifiant(&LOCAL),
        identifiant(&CLIENT),
        INACTIVITE_US,
        horloge,
    )
    .expect("constructible");
    serveur
        .on_datagram(&mut premier_datagramme, horloge)
        .expect("accepté");

    // Des tampons juste trop courts pour porter un morceau de `ServerHello`
    // après l'acquittement.
    for taille in [50_usize, 56, 62, 68, 74] {
        let mut etroit = std::vec![0_u8; taille];
        let ecrit = serveur
            .poll_transmit(&mut etroit, horloge)
            .expect("le serveur avance");
        assert!(ecrit <= taille, "{taille} octets : {ecrit} écrits");
        horloge = horloge.saturating_add(100);
    }

    // Et avec un datagramme entier, la poignée de main repart.
    conduire(&mut serveur, &mut client, &mut horloge);
    assert!(serveur.is_established());
}

/// **LE PLUS PROCHE DE DEUX INSTANTS**, quand l'un des deux manque.
///
/// `deadline` combine quatre délais par espace, et la plupart sont absents la
/// plupart du temps. **Un `None` ne doit pas effacer un `Some`** : ce serait un
/// réveil qu'on n'aurait jamais, et une connexion qui ne se rendrait jamais
/// compte d'une perte.
#[test]
fn le_plus_proche_de_deux_instants() {
    assert_eq!(super::plus_tot(None, None), None);
    assert_eq!(super::plus_tot(Some(7), None), Some(7));
    assert_eq!(super::plus_tot(None, Some(9)), Some(9));
    assert_eq!(super::plus_tot(Some(7), Some(9)), Some(7));
    assert_eq!(super::plus_tot(Some(9), Some(7)), Some(7));
}

/// **DES OCTETS D'APPLICATION TRAVERSENT UN FLUX, DANS LES DEUX SENS.**
///
/// C'est ce que tout le reste sert à rendre possible. Le client ouvre un flux
/// bidirectionnel, y écrit ; le serveur lit, répond et termine ; le client
/// reçoit la réponse et le `FIN`.
#[test]
fn des_octets_d_application_traversent_un_flux() {
    let (_atelier, mut serveur, mut client, mut horloge) = etabli("flux");
    let flux = ams_proto_quic::StreamId::new(0).expect("le premier bidirectionnel du client");

    // Le client écrit sur le flux zéro.
    let mut trames = [0_u8; 64];
    let ecrits = (Frame::Stream {
        stream: 0,
        offset: 0,
        data: b"bonjour",
        fin: false,
    })
    .write(&mut trames)
    .expect("écrivable");
    let mut datagramme = un_paquet_du_client(&mut client, trames.get(..ecrits).expect("écrits"));
    serveur
        .on_datagram(&mut datagramme, horloge)
        .expect("le serveur accepte un flux");

    // **UN SECOND MORCEAU, SUR LE MÊME FLUX** : la fenêtre est déjà réservée, et
    // ne doit pas l'être une seconde fois — sans quoi ce qui est arrivé
    // disparaîtrait.
    let ecrits = (Frame::Stream {
        stream: 0,
        offset: 7,
        data: b" toi",
        fin: false,
    })
    .write(&mut trames)
    .expect("écrivable");
    let mut suite = un_paquet_du_client(&mut client, trames.get(..ecrits).expect("écrits"));
    serveur
        .on_datagram(&mut suite, horloge)
        .expect("le serveur accepte la suite");

    // Le serveur lit ce qui est arrivé.
    let mut vers = [0_u8; 32];
    let lus = serveur.read(flux, &mut vers);
    assert_eq!(vers.get(..lus), Some(&b"bonjour toi"[..]));

    // Il répond, et termine.
    assert_eq!(serveur.write(flux, b"salut").expect("il peut écrire"), 5);
    serveur.finish(flux).expect("et terminer");

    // Le paquet part, et le client le reçoit.
    for _ in 0..4 {
        let mut place = std::vec![0_u8; 1_500];
        let ecrit = serveur
            .poll_transmit(&mut place, horloge)
            .expect("le serveur avance");
        if ecrit == 0 {
            break;
        }
        client.ecouter(place.get(..ecrit).expect("écrit"));
        horloge = horloge.saturating_add(1_000);
    }

    assert_eq!(client.recu, b"salut", "LA RÉPONSE EST ARRIVÉE");
    assert_eq!(client.flux_recu, Some(0), "sur le flux qu'il avait ouvert");
    assert!(client.fin_recue, "§19.8 : et le flux est terminé");
}

/// **AVANT LA POIGNÉE DE MAIN, IL N'Y A PAS DE FLUX** (§7.4).
///
/// §4.1 et §4.6 se règlent sur des paramètres qu'on n'a le droit de croire
/// qu'authentifiés. Les inventer plus tôt réglerait la connexion sur des limites
/// que le pair n'a jamais annoncées.
#[test]
fn avant_la_poignee_de_main_il_n_y_a_pas_de_flux() {
    let atelier = atelier("sans-flux");
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let mut client = Client::new(
        config_client(&autorite, ams_tls::alpn_h3()),
        &ses_parametres_avec_flux(),
    );
    let premier_datagramme = client.parler();
    let arrivee = premier(&premier_datagramme);
    let mut serveur = Connection::accept(
        config_serveur(&cert, &cle),
        &arrivee,
        identifiant(&LOCAL),
        identifiant(&CLIENT),
        INACTIVITE_US,
        1_000_000,
    )
    .expect("constructible");

    assert!(serveur.streams().is_none());
    let flux = ams_proto_quic::StreamId::new(0).expect("un numéro");
    assert!(
        serveur
            .open_stream(ams_proto_quic::Directional::Unidirectional)
            .is_err()
    );
    assert!(serveur.write(flux, b"x").is_err());
    assert!(serveur.finish(flux).is_err());
    assert_eq!(serveur.read(flux, &mut [0_u8; 4]), 0);
    // §3.2 : et il n'y a aucune annulation dont prendre acte.
    serveur.read_reset(flux);
}

/// **LE SERVEUR ANNONCE CE QU'IL TIENT** (§19.9, §19.11).
///
/// Le client de cet essai n'ouvre que huit flux par famille et cent mille
/// octets ; le serveur en tient davantage, et le dire est ce qui permet au
/// client de s'en servir.
#[test]
fn le_serveur_annonce_ce_qu_il_tient() {
    let (_atelier, mut serveur, mut client, mut horloge) = etabli("credits");
    // Le client écrit, et le serveur lit : **c'est la lecture qui rouvre la
    // fenêtre** (§4.1), et non l'arrivée des octets.
    //
    // Un unidirectionnel, terminé d'un coup : il n'a qu'une moitié, et une fois
    // lu il est fini — donc sa place se rend, et c'est cela qui donne au serveur
    // un plafond neuf à annoncer.
    let mut trames = [0_u8; 64];
    let ecrits = (Frame::Stream {
        stream: 2,
        offset: 0,
        data: b"bonjour",
        fin: true,
    })
    .write(&mut trames)
    .expect("écrivable");
    let mut datagramme = un_paquet_du_client(&mut client, trames.get(..ecrits).expect("écrits"));
    serveur
        .on_datagram(&mut datagramme, horloge)
        .expect("le serveur accepte un flux");
    let flux = ams_proto_quic::StreamId::new(2).expect("un numéro");
    assert_eq!(serveur.read(flux, &mut [0_u8; 32]), 7);
    for _ in 0..4 {
        let mut place = std::vec![0_u8; 1_500];
        let ecrit = serveur
            .poll_transmit(&mut place, horloge)
            .expect("le serveur avance");
        if ecrit == 0 {
            break;
        }
        client.ecouter(place.get(..ecrit).expect("écrit"));
        horloge = horloge.saturating_add(1_000);
    }
    assert_eq!(
        client.credit_recu,
        Some(crate::connection::CONNEXION_OCTETS.saturating_add(7)),
        "§19.9 : sept octets lus, sept octets rouverts"
    );
    assert_eq!(
        client.plafond_recu,
        Some(ams_quic::FLUX_PAR_FAMILLE_MAX.saturating_add(1)),
        "§19.11 : une place rendue, un flux de plus annoncé"
    );
}

/// **LE SERVEUR SERT TOUTES LES TRAMES QUI PARLENT D'UN FLUX** (§19.4, §19.5,
/// §19.9 à §19.11).
///
/// Elles n'arrivent qu'en `1-RTT`, et les ignorer laisserait la connexion
/// tourner sur des crédits périmés — le pair croirait avoir ouvert ce qu'on
/// n'aurait pas entendu.
#[test]
fn le_serveur_sert_toutes_les_trames_de_flux() {
    let (_atelier, mut serveur, mut client, horloge) = etabli("trames-de-flux");

    // Le pair nous ouvre en grand, puis annule et arrête un flux.
    let mut trames = std::vec![0_u8; 256];
    let mut pose = 0_usize;
    for trame in [
        Frame::MaxData { maximum: 500_000 },
        Frame::MaxStreams {
            directional: ams_proto_quic::Directional::Unidirectional,
            maximum: 6,
        },
        Frame::Stream {
            stream: 0,
            offset: 0,
            data: b"salut",
            fin: false,
        },
        Frame::MaxStreamData {
            stream: 0,
            maximum: 400_000,
        },
        Frame::StopSending {
            stream: 0,
            code: 0x10,
        },
        // **UN UNIDIRECTIONNEL DU CLIENT** : un `RESET_STREAM` en termine la
        // seule moitié, là où un bidirectionnel garderait la nôtre ouverte.
        Frame::ResetStream {
            stream: 6,
            code: 0x10,
            final_size: 3,
        },
    ] {
        let place = trames.get_mut(pose..).expect("de la place");
        pose = pose.saturating_add(trame.write(place).expect("écrivable"));
    }
    let mut datagramme = un_paquet_du_client(&mut client, trames.get(..pose).expect("posées"));
    serveur
        .on_datagram(&mut datagramme, horloge)
        .expect("le serveur sert tout cela");

    let flux = serveur.streams().expect("établie");
    let zero = ams_proto_quic::StreamId::new(0).expect("un numéro");
    assert_eq!(
        flux.credit(zero),
        400_000,
        "§19.10 : le crédit du flux a monté"
    );
    assert_eq!(
        flux.outgoing().limit(),
        500_000,
        "§19.9 : et celui de la connexion"
    );

    // §19.4 : le flux annulé a pris son crédit de connexion, sans un octet reçu.
    assert_eq!(flux.incoming().used(), 8, "cinq octets, plus trois annulés");

    // §3.2 : on prend acte de l'annulation, et la place se rend.
    let annule = ams_proto_quic::StreamId::new(6).expect("un numéro");
    serveur.read_reset(annule);
    let mut place = std::vec![0_u8; 1_500];
    let _ = serveur.poll_transmit(&mut place, horloge);
    assert!(
        serveur.streams().expect("établie").slot(annule).is_none(),
        "la place du flux annulé est rendue"
    );
}

/// **LE SERVEUR OUVRE SES PROPRES FLUX** (§2.1).
///
/// C'est ce dont HTTP/3 a besoin pour son flux de contrôle et ceux de QPACK :
/// trois unidirectionnels que le serveur ouvre de lui-même, sans que le client
/// ait rien demandé.
#[test]
fn le_serveur_ouvre_ses_propres_flux() {
    let (_atelier, mut serveur, mut client, mut horloge) = etabli("ouvrir");
    let sien = serveur
        .open_stream(ams_proto_quic::Directional::Unidirectional)
        .expect("le client lui en a ouvert huit");
    assert_eq!(
        sien.value(),
        3,
        "§2.1 : le premier unidirectionnel du serveur"
    );

    assert_eq!(serveur.write(sien, b"controle").expect("il écrit"), 8);
    serveur.finish(sien).expect("et termine");
    for _ in 0..4 {
        let mut place = std::vec![0_u8; 1_500];
        let ecrit = serveur
            .poll_transmit(&mut place, horloge)
            .expect("le serveur avance");
        if ecrit == 0 {
            break;
        }
        client.ecouter(place.get(..ecrit).expect("écrit"));
        horloge = horloge.saturating_add(1_000);
    }
    assert_eq!(client.recu, b"controle");
    assert_eq!(client.flux_recu, Some(3));
    assert!(client.fin_recue);
}

/// **CE QU'ON N'A PAS OUVERT NE S'ÉCRIT PAS, ET NE SE LIT PAS.**
#[test]
fn ce_qu_on_n_a_pas_ouvert_ne_s_ecrit_pas() {
    let (_atelier, mut serveur, _client, _horloge) = etabli("inconnu");
    let inconnu = ams_proto_quic::StreamId::new(400).expect("un numéro");
    assert_eq!(serveur.read(inconnu, &mut [0_u8; 8]), 0);
    assert!(serveur.write(inconnu, b"x").is_err());
    assert!(serveur.finish(inconnu).is_err());
    // Et le dire à un flux qui n'existe pas ne fait rien.
    serveur.read_reset(inconnu);
}

/// **L'ATTENTE D'ÉMISSION EST BORNÉE** (C3).
///
/// L'application écrit, et ces octets attendent qu'un paquet les emporte. Sans
/// borne, une application pressée remplirait la mémoire du serveur plus vite que
/// le réseau ne la vide — et ce serait notre faute, non celle du pair.
#[test]
fn l_attente_d_emission_est_bornee() {
    let (_atelier, mut serveur, _client, _horloge) = etabli("borne");
    let sien = serveur
        .open_stream(ams_proto_quic::Directional::Unidirectional)
        .expect("de la place");
    let beaucoup = std::vec![0x61_u8; crate::connection::SORTIE_OCTETS_MAX];
    assert_eq!(
        serveur.write(sien, &beaucoup).expect("il prend tout"),
        crate::connection::SORTIE_OCTETS_MAX
    );
    assert_eq!(
        serveur
            .write(sien, b"un octet de trop")
            .expect("il en prend zéro"),
        0,
        "ET IL LE DIT, plutôt que de faire croire que c'est parti"
    );
}

/// **UNE TRAME HORS DE SON NIVEAU FERME LA CONNEXION** (§12.4).
///
/// « An endpoint MUST treat receipt of a frame in a packet type that is not
/// permitted as a connection error of type PROTOCOL_VIOLATION. »
///
/// # CE N'EST PAS UNE FORMALITÉ
///
/// Sans ce contrôle, une trame de flux dans un paquet de poignée de main
/// atteindrait une collection qui n'existe pas encore. Et l'ignorer en silence
/// ne vaudrait pas mieux : le pair croirait avoir dit quelque chose.
#[test]
fn une_trame_hors_de_son_niveau_ferme_la_connexion() {
    let atelier = atelier("hors-niveau");
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let horloge = 1_000_000_u64;
    let mut client = Client::new(
        config_client(&autorite, ams_tls::alpn_h3()),
        &ses_parametres_avec_flux(),
    );
    let premier_datagramme = client.parler();
    let arrivee = premier(&premier_datagramme);
    let mut serveur = Connection::accept(
        config_serveur(&cert, &cle),
        &arrivee,
        identifiant(&LOCAL),
        identifiant(&CLIENT),
        INACTIVITE_US,
        horloge,
    )
    .expect("constructible");

    // Une trame `STREAM` dans un paquet `Initial` : §12.4 ne l'admet pas.
    let mut trames = [0_u8; 64];
    let ecrits = (Frame::Stream {
        stream: 0,
        offset: 0,
        data: b"trop tot",
        fin: false,
    })
    .write(&mut trames)
    .expect("écrivable");
    let mut datagramme = Vec::new();
    client.poser(
        &mut datagramme,
        Space::Initial,
        trames.get(..ecrits).expect("écrits"),
    );
    datagramme.resize(1_200.max(datagramme.len()), 0);

    let faute = serveur
        .on_datagram(&mut datagramme, horloge)
        .expect_err("§12.4 la refuse");
    assert_eq!(
        faute.close_code(),
        TransportError::ProtocolViolation.value()
    );
}

/// **UN SERVEUR NE REÇOIT PAS DE `HANDSHAKE_DONE`** (§19.20).
///
/// « A server MUST treat receipt of a HANDSHAKE_DONE frame as a connection error
/// of type PROTOCOL_VIOLATION. » C'est lui qui l'émet : en recevoir un veut dire
/// que le pair se croit serveur, et rien de ce qui suivrait n'aurait le sens
/// qu'on lui prêterait.
#[test]
fn un_serveur_ne_recoit_pas_de_handshake_done() {
    let (_atelier, mut serveur, mut client, horloge) = etabli("handshake-done");
    let mut trames = [0_u8; 8];
    let ecrits = Frame::HandshakeDone.write(&mut trames).expect("écrivable");
    let mut datagramme = un_paquet_du_client(&mut client, trames.get(..ecrits).expect("écrits"));
    let faute = serveur
        .on_datagram(&mut datagramme, horloge)
        .expect_err("§19.20 la refuse");
    assert_eq!(
        faute.close_code(),
        TransportError::ProtocolViolation.value()
    );
}

/// **UN FLUX ACQUITTÉ SE TERMINE, ET REND SA PLACE** (§3.1).
///
/// C'est l'acquittement du `FIN` qui fait passer le côté émission à
/// `Data Recvd`. Sans lui, un flux resterait vivant pour toujours et sa place ne
/// reviendrait jamais à la table.
#[test]
fn un_flux_acquitte_se_termine_et_rend_sa_place() {
    let (_atelier, mut serveur, mut client, mut horloge) = etabli("acquitte");
    let sien = serveur
        .open_stream(ams_proto_quic::Directional::Unidirectional)
        .expect("de la place");
    serveur.write(sien, b"bonjour").expect("il écrit");
    serveur.finish(sien).expect("et termine");

    // Le paquet part, le client l'entend, puis l'acquitte.
    for _ in 0..6 {
        let mut place = std::vec![0_u8; 1_500];
        let ecrit = serveur
            .poll_transmit(&mut place, horloge)
            .expect("le serveur avance");
        if ecrit == 0 {
            break;
        }
        client.ecouter(place.get(..ecrit).expect("écrit"));
        horloge = horloge.saturating_add(1_000);
        let mut du_client = client.parler();
        if !du_client.is_empty() {
            serveur
                .on_datagram(&mut du_client, horloge)
                .expect("son acquittement");
        }
    }
    assert_eq!(client.recu, b"bonjour");
    assert!(
        client.fin_recue,
        "§19.8 : le `FIN` chevauchait les derniers octets"
    );
    assert!(
        serveur.streams().expect("établie").slot(sien).is_none(),
        "TOUT EST ACQUITTÉ : la place est revenue à la table"
    );
}

/// **CE QUI S'EST PERDU REPART** (§13.3).
///
/// Le premier paquet n'arrive jamais. C'est la détection de perte de §6.1.1 qui
/// recule le curseur d'émission, et les paquets suivants redisent ce qui
/// manquait. Sans cela, le flux se figerait sur un trou que personne ne
/// comblerait — et rien ne le dirait.
///
/// # IL FAUT PLUSIEURS PAQUETS, ET C'EST TOUT LE MONTAGE
///
/// §6.1.1 déclare perdu ce qu'un acquittement distance de trois paquets. Avec un
/// seul paquet en vol, rien ne le distance jamais : l'essai passerait sans avoir
/// rien éprouvé. On écrit donc de quoi en remplir plusieurs.
#[test]
fn ce_qui_s_est_perdu_repart() {
    let (_atelier, mut serveur, mut client, mut horloge) = etabli("perte-de-flux");
    let sien = serveur
        .open_stream(ams_proto_quic::Directional::Unidirectional)
        .expect("de la place");
    let dire = std::vec![0x7a_u8; 5_000];
    let mut ecrits = 0_usize;
    while ecrits < dire.len() {
        let pris = serveur
            .write(sien, dire.get(ecrits..).expect("le reste"))
            .expect("il écrit");
        if pris == 0 {
            break;
        }
        ecrits = ecrits.saturating_add(pris);
    }
    assert_eq!(ecrits, dire.len());
    serveur.finish(sien).expect("et termine");

    let mut jete = false;
    for _ in 0..40 {
        let mut place = std::vec![0_u8; 1_500];
        let ecrit = serveur
            .poll_transmit(&mut place, horloge)
            .expect("le serveur avance");
        if ecrit > 0 {
            // **LE PREMIER SE PERD, ET LUI SEUL.**
            match jete {
                false => jete = true,
                true => client.ecouter(place.get(..ecrit).expect("écrit")),
            }
        }
        horloge = horloge.saturating_add(20_000);
        let mut du_client = client.parler();
        if !du_client.is_empty() {
            serveur
                .on_datagram(&mut du_client, horloge)
                .expect("ses acquittements");
        }
    }
    assert!(jete, "un paquet a bien été perdu");
    assert_eq!(
        client.recu, dire,
        "LES OCTETS PERDUS SONT REPARTIS, et le flux ne s'est pas figé"
    );
    assert!(client.fin_recue, "§19.8 : le `FIN` aussi");
}

/// **ON NE TERMINE UN FLUX QU'UNE FOIS** (§3.1).
///
/// Un second `FIN` sur un flux déjà terminé n'a rien à dire, et l'écrire ferait
/// se contredire la taille finale (§4.5).
#[test]
fn on_ne_termine_un_flux_qu_une_fois() {
    let (_atelier, mut serveur, _client, horloge) = etabli("deux-fins");
    let sien = serveur
        .open_stream(ams_proto_quic::Directional::Unidirectional)
        .expect("de la place");
    // **DES OCTETS, ET NON UN `FIN` SEUL** : un flux qui ne dit rien passe
    // aussitôt à `Data Recvd` — il n'y a rien à acquitter —, et sa place
    // reviendrait à la table avant qu'on ait pu redire quoi que ce soit.
    serveur.write(sien, b"quelque chose").expect("il écrit");
    serveur.finish(sien).expect("une fois");
    let mut place = std::vec![0_u8; 1_500];
    let _ = serveur.poll_transmit(&mut place, horloge);

    // **LE FLUX EST EN `Data Sent`, ET IL LE DIT.** Se taire laisserait
    // l'application croire qu'un second `FIN` partira — et §4.5 ferait alors se
    // contredire la taille finale.
    assert!(
        serveur.finish(sien).is_err(),
        "§3.1 : on ne termine un flux qu'une fois"
    );
    assert!(
        serveur.write(sien, b"encore").is_err(),
        "et l'on n'y écrit plus rien"
    );
    let mut encore = std::vec![0_u8; 1_500];
    let _ = serveur.poll_transmit(&mut encore, horloge);
    assert!(!serveur.is_closed(), "et cela ne condamne pas la connexion");
    assert!(
        serveur.streams().expect("établie").slot(sien).is_some(),
        "le flux attend toujours son acquittement"
    );
}

/// **UNE TRAME DE FLUX FAUTIVE FERME LA CONNEXION**, chacune avec son code.
///
/// §12.4 fait des fautes de flux des erreurs de connexion, et non des paquets à
/// jeter : le pair a déjà agi sur ce qu'il croyait vrai, et continuer le
/// laisserait s'enfoncer.
#[test]
fn une_trame_de_flux_fautive_ferme_la_connexion() {
    // §4.1 : au-delà de ce qu'on a annoncé pour ce flux.
    let cas: [(Frame<'_>, TransportError); 4] = [
        (
            Frame::Stream {
                stream: 0,
                offset: crate::connection::FLUX_OCTETS,
                data: b"x",
                fin: false,
            },
            TransportError::FlowControlError,
        ),
        // §4.6 : au-delà du plafond de flux qu'on a annoncé.
        (
            Frame::Stream {
                stream: 400,
                offset: 0,
                data: b"x",
                fin: false,
            },
            TransportError::StreamLimitError,
        ),
        // §19.5 : arrêter ce que nous n'écrivons pas.
        (
            Frame::StopSending {
                stream: 2,
                code: 0x10,
            },
            TransportError::StreamStateError,
        ),
        // §19.10 : ouvrir du crédit là où nous n'écrivons pas.
        (
            Frame::MaxStreamData {
                stream: 2,
                maximum: 10,
            },
            TransportError::StreamStateError,
        ),
    ];

    for (numero, (trame, attendu)) in cas.into_iter().enumerate() {
        let (_atelier, mut serveur, mut client, horloge) =
            etabli(&std::format!("fautive-{numero}"));
        let mut trames = std::vec![0_u8; 64];
        let ecrits = trame.write(&mut trames).expect("écrivable");
        let mut datagramme =
            un_paquet_du_client(&mut client, trames.get(..ecrits).expect("écrits"));
        let faute = serveur
            .on_datagram(&mut datagramme, horloge)
            .expect_err("cette trame est une faute");
        assert_eq!(faute.close_code(), attendu.value(), "cas {numero}");
    }
}

/// **UN `RESET_STREAM` QUI SE CONTREDIT FERME LA CONNEXION** (§4.5).
///
/// « Once a final size for a stream is known, it cannot change. » Une taille
/// finale qui change veut dire que l'un des deux messages mentait — et
/// l'application a peut-être déjà livré ce qu'elle a lu.
#[test]
fn un_reset_stream_qui_se_contredit_ferme_la_connexion() {
    let (_atelier, mut serveur, mut client, horloge) = etabli("finale-contredite");
    let mut trames = std::vec![0_u8; 64];
    let mut pose = 0_usize;
    for trame in [
        Frame::Stream {
            stream: 2,
            offset: 0,
            data: b"abcde",
            fin: true,
        },
        Frame::ResetStream {
            stream: 2,
            code: 0x10,
            final_size: 9,
        },
    ] {
        let place = trames.get_mut(pose..).expect("de la place");
        pose = pose.saturating_add(trame.write(place).expect("écrivable"));
    }
    let mut datagramme = un_paquet_du_client(&mut client, trames.get(..pose).expect("posées"));
    let faute = serveur
        .on_datagram(&mut datagramme, horloge)
        .expect_err("§4.5 la refuse");
    assert_eq!(faute.close_code(), TransportError::FinalSizeError.value());
}

/// **UN PAQUET QUI NE S'AUTHENTIFIE PAS SE JETTE** (§5.3 de RFC 9001).
///
/// « An endpoint MUST discard packets that cannot be authenticated. » Ce n'est
/// pas une indulgence : c'est ce qui empêche un tiers de fermer une connexion
/// qui ne lui appartient pas — il lui suffirait sinon d'envoyer n'importe quoi à
/// la bonne adresse.
#[test]
fn un_paquet_qui_ne_s_authentifie_pas_se_jette() {
    let (_atelier, mut serveur, mut client, horloge) = etabli("faux-paquet");
    let mut datagramme = un_paquet_du_client(&mut client, &[0x01]);
    // Le dernier octet est dans l'étiquette d'authentification.
    let dernier = datagramme.len().saturating_sub(1);
    datagramme[dernier] ^= 0xff;
    serveur
        .on_datagram(&mut datagramme, horloge)
        .expect("il se jette, il ne condamne pas");
    assert!(!serveur.is_closed(), "et surtout, il ne ferme rien");
}

/// **L'APPLICATION VOIT CE QUI EST PRÊT, ET CE QUE LE PAIR A CONCLU.**
///
/// Ce sont les trois choses dont une couture applicative a besoin : quels flux
/// vivent, combien d'octets sont prêts sur chacun, et si le pair a terminé ou
/// annulé. Sans la troisième, une application servirait une requête tronquée dès
/// qu'un datagramme arriverait en deux morceaux.
#[test]
fn l_application_voit_ce_qui_est_pret() {
    let (_atelier, mut serveur, mut client, horloge) = etabli("visible");
    let zero = ams_proto_quic::StreamId::new(0).expect("un numéro");

    // Avant toute trame, rien ne vit et rien n'est prêt.
    assert_eq!(serveur.streams_alive().count(), 0);
    assert_eq!(serveur.readable(zero), 0);
    assert_eq!(serveur.recv_state(zero), None);

    // Un morceau en avance : il est arrivé, il n'est pas prêt (§2.2).
    let mut trames = std::vec![0_u8; 64];
    let ecrits = (Frame::Stream {
        stream: 0,
        offset: 3,
        data: b"def",
        fin: true,
    })
    .write(&mut trames)
    .expect("écrivable");
    let mut datagramme = un_paquet_du_client(&mut client, trames.get(..ecrits).expect("écrits"));
    serveur
        .on_datagram(&mut datagramme, horloge)
        .expect("le désordre s'accepte");
    assert_eq!(serveur.streams_alive().collect::<Vec<_>>(), std::vec![zero]);
    assert_eq!(serveur.readable(zero), 0, "le trou n'est pas comblé");
    assert_eq!(
        serveur.recv_state(zero),
        Some(ams_quic::RecvState::SizeKnown),
        "§3.2 : le `FIN` est là, les octets non"
    );

    // Le début arrive : tout devient prêt d'un coup.
    let ecrits = (Frame::Stream {
        stream: 0,
        offset: 0,
        data: b"abc",
        fin: false,
    })
    .write(&mut trames)
    .expect("écrivable");
    let mut suite = un_paquet_du_client(&mut client, trames.get(..ecrits).expect("écrits"));
    serveur
        .on_datagram(&mut suite, horloge)
        .expect("le début s'accepte");
    assert_eq!(serveur.readable(zero), 6);
    assert_eq!(
        serveur.recv_state(zero),
        Some(ams_quic::RecvState::DataRecvd),
        "**C'EST LÀ QU'UNE REQUÊTE EST COMPLÈTE**, et pas avant"
    );

    let mut vers = [0_u8; 16];
    assert_eq!(serveur.read(zero, &mut vers), 6);
    assert_eq!(vers.get(..6), Some(&b"abcdef"[..]));
    assert_eq!(serveur.readable(zero), 0);
    assert_eq!(
        serveur.recv_state(zero),
        Some(ams_quic::RecvState::DataRead)
    );
}

/// Un serveur qui a accepté, mais dont la poignée de main n'a pas abouti.
fn accepte(nom: &str) -> (Atelier, Connection, u64) {
    let atelier = atelier(nom);
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let horloge = 1_000_000_u64;
    let mut client = Client::new(
        config_client(&autorite, ams_tls::alpn_h3()),
        &ses_parametres_avec_flux(),
    );
    let premier_datagramme = client.parler();
    let arrivee = premier(&premier_datagramme);
    let serveur = Connection::accept(
        config_serveur(&cert, &cle),
        &arrivee,
        identifiant(&LOCAL),
        identifiant(&CLIENT),
        INACTIVITE_US,
        horloge,
    )
    .expect("constructible");
    (atelier, serveur, horloge)
}

/// **AVANT LA POIGNÉE DE MAIN, IL N'Y A PAS DE FLUX À ANNULER** (§7.4).
///
/// Les limites du pair ne sont pas authentifiées tant qu'elle n'a pas abouti :
/// il n'y a donc aucune table de flux, et rien à annuler dedans.
#[test]
fn une_annulation_avant_la_poignee_de_main_se_refuse() {
    let (_atelier, mut serveur, _horloge) = accepte("annulation-trop-tot");
    let issue = serveur
        .reset(StreamId::new(3).expect("un numéro qui tient"), 0x0100)
        .expect_err("il n'y a pas encore de flux");
    assert_eq!(issue.reason(), Reason::PasEncoreDeFlux);
}

/// **UN FLUX QU'ON N'A PAS N'A RIEN À ANNULER** (§3.1).
#[test]
fn une_annulation_d_un_flux_inconnu_se_refuse() {
    let (_atelier, mut serveur, _client, _horloge) = etabli("annulation-inconnue");
    serveur
        .reset(StreamId::new(3).expect("un numéro qui tient"), 0x0100)
        .expect_err("ce flux n'existe pas");
}

/// **UNE ANNULATION PART AU PAIR, ET CE QUI RESTAIT À DIRE NE PART PAS** (§3.3).
///
/// `RESET_STREAM` et `FIN` s'excluent : après l'annulation, plus un octet ne
/// quitte ce flux. Les garder pour un paquet qui ne viendra jamais retiendrait de
/// la mémoire pour rien — et le pair, lui, attendrait des octets qu'on ne lui
/// doit plus.
#[test]
fn une_annulation_part_et_ce_qui_restait_a_dire_ne_part_pas() {
    let (_atelier, mut serveur, mut client, mut horloge) = etabli("annulation-part");
    let flux = serveur
        .open_stream(Directional::Unidirectional)
        .expect("le crédit du client le permet");
    serveur.write(flux, b"ce qu'on ne dira pas").expect("écrit");
    serveur.reset(flux, 0x010b).expect("on l'annule");

    conduire(&mut serveur, &mut client, &mut horloge);
    assert_eq!(
        client.annulations_recues,
        std::vec![(flux.value(), 0x010b, 0)],
        "§19.4 : le flux, le code, et une taille finale de zéro — rien n'était parti"
    );
    assert!(
        client.recu.is_empty(),
        "§3.3 : et pas un octet du flux annulé"
    );
}

/// **UNE ANNULATION ACQUITTÉE REND SA PLACE** (§3.1).
///
/// C'est l'acquittement, et lui seul, qui fait passer le flux à `Reset Recvd`.
/// Sans cela il resterait à retransmettre pour toujours, et sa place — une sur
/// trente-deux — ne reviendrait jamais à la table.
#[test]
fn une_annulation_acquittee_rend_sa_place() {
    let (_atelier, mut serveur, mut client, mut horloge) = etabli("annulation-acquittee");
    let flux = serveur
        .open_stream(Directional::Unidirectional)
        .expect("le crédit du client le permet");
    serveur.reset(flux, 0x010b).expect("on l'annule");
    conduire(&mut serveur, &mut client, &mut horloge);

    assert!(
        serveur.annulations.iter().all(Option::is_none),
        "acquittée, elle n'est plus en attente"
    );
    assert!(
        !serveur.streams_alive().any(|vivant| vivant == flux),
        "et le flux a rendu sa place"
    );
}

/// **UNE ANNULATION PERDUE SE REDIT, À L'IDENTIQUE** (§13.3 de RFC 9000).
///
/// Contrairement aux octets d'un flux, qu'on retransmet en reculant un curseur,
/// celle-ci porte une taille finale qui ne changera plus. **Ne pas la redire
/// laisserait le pair tenir pour ouvert un flux que nous croirions clos**, et il
/// attendrait des octets jusqu'à son délai d'inactivité.
///
/// # POURQUOI L'ESSAI DOIT FAIRE ACQUITTER UN PAQUET PLUS RÉCENT
///
/// §6.1 de RFC 9002 ne déclare rien perdu dans l'absolu : un paquet est perdu
/// *par rapport au plus grand acquitté*. Sans acquittement plus récent, il n'y a
/// pas de perte à détecter — seulement un sondage qui finira par en provoquer un.
#[test]
fn une_annulation_perdue_se_redit() {
    let (_atelier, mut serveur, mut client, horloge) = etabli("annulation-perdue");
    let flux = serveur
        .open_stream(Directional::Unidirectional)
        .expect("le crédit du client le permet");
    serveur.reset(flux, 0x010b).expect("on l'annule");

    let mut place = std::vec![0_u8; 1_500];
    let mut vider = |serveur: &mut Connection, paquets: &mut Vec<Vec<u8>>| {
        while let Ok(ecrit) = serveur.poll_transmit(&mut place, horloge) {
            if ecrit == 0 {
                break;
            }
            paquets.push(
                place
                    .get(..ecrit)
                    .expect("ce qui vient d'être écrit")
                    .to_vec(),
            );
        }
    };

    // Le paquet qui porte l'annulation part, et n'arrive jamais.
    let mut paquets = Vec::new();
    vider(&mut serveur, &mut paquets);
    assert!(!paquets.is_empty(), "l'annulation est partie");
    assert!(
        client.annulations_recues.is_empty(),
        "et le client ne l'a pas eue"
    );

    // Trois paquets plus loin, le pair n'acquitte que le dernier : §6.1.1 déclare
    // alors perdu tout ce qui le précède de trois rangs.
    let autre = serveur
        .open_stream(Directional::Unidirectional)
        .expect("il reste du crédit");
    for _ in 0..3 {
        serveur.write(autre, b"x").expect("écrit");
        vider(&mut serveur, &mut paquets);
    }
    let dernier = paquets.last().expect("il y en a").clone();
    client.ecouter(&dernier);
    let mut acquittement = client.parler();
    serveur
        .on_datagram(&mut acquittement, horloge)
        .expect("un ACK sain");

    // Et l'annulation repart, identique à elle-même.
    let mut apres = Vec::new();
    vider(&mut serveur, &mut apres);
    for paquet in &apres {
        client.ecouter(paquet);
    }
    assert_eq!(
        client.annulations_recues,
        std::vec![(flux.value(), 0x010b, 0)],
        "§13.3 : la même, à l'identique"
    );
}

/// **UNE ANNULATION QUI NE TIENT PAS DANS LE PAQUET ATTEND LE SUIVANT.**
///
/// Elle reste marquée comme non émise, donc rien n'est perdu — c'est le seul
/// comportement qui ne demande ni de tronquer une trame, ni de la jeter.
#[test]
fn une_annulation_sans_place_attend_le_paquet_suivant() {
    let (_atelier, mut serveur, _client, _horloge) = etabli("annulation-sans-place");
    let flux = serveur
        .open_stream(Directional::Unidirectional)
        .expect("le crédit du client le permet");
    serveur.reset(flux, 0x010b).expect("on l'annule");

    let mut trames = [0_u8; 64];
    // Deux octets ne suffisent pas à un numéro de flux, un code et une taille.
    assert!(
        serveur.poser_une_annulation(&mut trames, 0, 2).is_none(),
        "pas de place, pas de trame"
    );
    assert!(
        serveur.poser_une_annulation(&mut trames, 0, 64).is_some(),
        "et elle repart dès qu'il y a la place"
    );
    // **UNE FOIS ÉMISE, ELLE NE SE REDIT PAS** tant qu'elle n'est ni acquittée
    // ni perdue : la redire à chaque paquet coûterait sans rien apprendre.
    assert!(
        serveur.poser_une_annulation(&mut trames, 0, 64).is_none(),
        "elle attend son sort"
    );
}

/// **LA PREMIÈRE ANNULATION EST CELLE QUI COMPTE.**
///
/// La redire remettrait la trame en attente d'émission alors qu'elle est
/// peut-être déjà partie, et le pair recevrait deux fois la même chose sans rien
/// apprendre.
#[test]
fn une_annulation_redite_ne_repart_pas() {
    let (_atelier, mut serveur, mut client, mut horloge) = etabli("annulation-redite");
    let flux = serveur
        .open_stream(Directional::Unidirectional)
        .expect("le crédit du client le permet");
    serveur.reset(flux, 0x010b).expect("on l'annule");
    serveur
        .reset(flux, 0x0102)
        .expect("§3.1 : redire une annulation n'est pas une faute");

    conduire(&mut serveur, &mut client, &mut horloge);
    assert_eq!(
        client.annulations_recues,
        std::vec![(flux.value(), 0x010b, 0)],
        "une seule, et c'est le code du premier refus"
    );
}

/// Le serveur a dit tout son vol, le client en a tiré ses clés `1-RTT` — et son
/// `Finished` n'est PAS encore arrivé.
///
/// C'est la fenêtre exacte du défaut : les clés de lecture `1-RTT` sont
/// installées, donc un paquet applicatif se déchiffre, mais les paramètres du
/// pair ne sont pas authentifiés et la collection de flux n'existe pas.
fn avant_le_finished(nom: &str) -> (Atelier, Connection, Client, u64) {
    let atelier = atelier(nom);
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let horloge = 1_000_000_u64;
    let mut client = Client::new(
        config_client(&autorite, ams_tls::alpn_h3()),
        &ses_parametres_avec_flux(),
    );
    let mut bonjour = client.parler();
    let arrivee = premier(&bonjour);
    let mut serveur = Connection::accept(
        config_serveur(&cert, &cle),
        &arrivee,
        identifiant(&LOCAL),
        identifiant(&CLIENT),
        INACTIVITE_US,
        horloge,
    )
    .expect("constructible");
    serveur.on_datagram(&mut bonjour, horloge).expect("accepté");
    // Le vol du serveur part au client, qui en tire ses clés `1-RTT`. **On ne
    // lui redonne pas son `Finished`** : c'est ce silence qui fait la fenêtre.
    loop {
        let mut place = std::vec![0_u8; 1_500];
        let ecrit = serveur.poll_transmit(&mut place, horloge).expect("avance");
        if ecrit == 0 {
            break;
        }
        client.ecouter(place.get(..ecrit).expect("écrit"));
    }
    (atelier, serveur, client, horloge)
}

/// Une trame `STREAM` de cinq octets sur le flux zéro, et un `PING`.
fn une_requete(trames: &mut [u8]) -> usize {
    let mut pose = 0_usize;
    for trame in [
        Frame::Stream {
            stream: 0,
            offset: 0,
            data: b"salut",
            fin: false,
        },
        // **LE `PING` EST LE TÉMOIN** : §19.2 en fait une trame qui SOLLICITE un
        // acquittement. Si le paquet est traité, le serveur en doit un ; s'il est
        // jeté, il ne doit rien. C'est ce qui rend le silence observable.
        Frame::Ping,
    ] {
        let place = trames.get_mut(pose..).expect("de la place");
        pose = pose.saturating_add(trame.write(place).expect("écrivable"));
    }
    pose
}

/// **LE DÉFAUT LUI-MÊME** : une requête qui suit le `Finished` sans que le
/// serveur ait émis entre les deux.
///
/// Les flux ne se bâtissaient que dans `poll_transmit`. Un pair qui coalesce son
/// `Finished` et sa première requête — c'est-à-dire TOUT client réel, `curl`
/// compris — atteignait donc `sur_un_flux` avec une collection absente, et
/// faisait PANIQUER le fil de travail. Un pair non authentifié éteignait ainsi
/// l'écoute HTTP/3 au premier échange.
#[test]
fn une_requete_qui_suit_le_finished_est_servie() {
    let (_atelier, mut serveur, mut client, horloge) = avant_le_finished("apres-finished");
    let mut trames = [0_u8; 64];
    let ecrits = une_requete(&mut trames);

    // Le `Finished`, puis la requête — et RIEN entre les deux.
    let mut fini = client.parler();
    assert!(!fini.is_empty(), "le client doit son `Finished`");
    serveur.on_datagram(&mut fini, horloge).expect("le `Finished` se lit");
    let mut requete = un_paquet_du_client(&mut client, trames.get(..ecrits).expect("écrites"));
    serveur.on_datagram(&mut requete, horloge).expect("servie");

    assert!(!serveur.is_closed(), "rien n'a fermé la connexion");
    let flux = StreamId::new(0).expect("un numéro de flux");
    assert_eq!(
        serveur.readable(flux),
        5,
        "la requête est lisible : les flux existaient quand elle est arrivée"
    );
}

/// **ET CELUI QUI DEVANCE VRAIMENT LA POIGNÉE SE JETTE, SANS S'ACQUITTER.**
///
/// Le réseau réordonne : un paquet `1-RTT` peut précéder le `Finished`. §5.7 de
/// RFC 9001 interdit alors de le TRAITER — les paramètres du pair ne sont pas
/// authentifiés —, et l'acquitter reviendrait à dire « reçu » de ce qu'on jette.
/// Le pair le réémettra.
#[test]
fn un_paquet_1_rtt_qui_devance_le_finished_se_jette() {
    let (_atelier, mut serveur, mut client, horloge) = avant_le_finished("avant-finished");
    let mut trames = [0_u8; 64];
    let ecrits = une_requete(&mut trames);

    let mut requete = un_paquet_du_client(&mut client, trames.get(..ecrits).expect("écrites"));
    serveur
        .on_datagram(&mut requete, horloge)
        .expect("jeté, et non fatal");

    assert!(!serveur.is_closed(), "le jeter ne condamne pas le pair");
    let mut place = std::vec![0_u8; 1_500];
    assert_eq!(
        serveur.poll_transmit(&mut place, horloge).expect("avance"),
        0,
        "le `PING` n'a pas été acquitté : le paquet n'a pas été traité"
    );
}

/// **UN PAQUET D'UN ESPACE DONT ON N'A PAS LES CLÉS SE JETTE, SANS UN MOT.**
///
/// §5.7 de RFC 9001 permet de RETENIR de tels paquets. Retenir est de la mémoire
/// offerte à qui en demande, et le pair réémettra : on s'arrête là.
///
/// Le paquet est ici de forme courte — donc de l'espace applicatif —, présenté à
/// une connexion qui vient d'accepter le premier datagramme et n'a que ses clés
/// `Initial`. Rien ne se déchiffre, rien ne se ferme, rien ne s'acquitte.
#[test]
fn un_paquet_sans_clefs_pour_son_espace_se_jette() {
    let atelier = atelier("sans-clefs");
    let (autorite, cert, cle) = materiel(&atelier.0).expect(SANS_OPENSSL);
    let horloge = 1_000_000_u64;
    let mut client = Client::new(
        config_client(&autorite, ams_tls::alpn_h3()),
        &ses_parametres_avec_flux(),
    );
    let bonjour = client.parler();
    let arrivee = premier(&bonjour);
    // **ON N'AVANCE PAS LA POIGNÉE** : le serveur n'a que ses clés `Initial`.
    let mut serveur = Connection::accept(
        config_serveur(&cert, &cle),
        &arrivee,
        identifiant(&LOCAL),
        identifiant(&CLIENT),
        INACTIVITE_US,
        horloge,
    )
    .expect("constructible");

    // §17.3 : forme courte, bit fixe posé, puis l'identifiant qu'on s'est donné.
    let mut court = std::vec::Vec::new();
    court.push(0x40_u8);
    court.extend_from_slice(&LOCAL);
    court.extend_from_slice(&[0_u8; 32]);
    serveur
        .on_datagram(&mut court, horloge)
        .expect("jeté, et non fatal");

    assert!(!serveur.is_closed(), "le jeter ne condamne pas le pair");
    let mut place = std::vec![0_u8; 1_500];
    assert_eq!(
        serveur.poll_transmit(&mut place, horloge).expect("avance"),
        0,
        "rien à dire : le paquet n'a même pas été ouvert"
    );
}
