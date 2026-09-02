// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **L'en-tête `Authentication-Results` (RFC 8601), et la quarantaine.**
//!
//! # Pourquoi ces deux-là dans le même fichier
//!
//! Ils répondent à la même question : « qu'est-ce que ce serveur a FAIT de ce
//! message ? ». L'en-tête le dit à qui lira le message — c'est la seule façon,
//! en POP3, de voir un verdict DMARC. La quarantaine le dit en le rangeant
//! ailleurs. Et les deux ne se savent qu'une fois le corps entier lu, parce que
//! DKIM signe le corps et que DMARC dépend de DKIM.

mod commun;

use ams_guard::Thresholds;
use ams_loop_tokio::{
    Delivery, DeliveryFailure, DmarcChecker, Resolver, Service, SharedGuard, Timeouts,
    serve_connection,
};
use ams_mime::AUTHRES_RESERVE;
use ams_proto_smtp::Limits;
use ams_session::Config;
use commun::{NotreDomaine, PAIR, resolveur_par_nom};
use core::time::Duration;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// Un extrait de la liste des suffixes publics.
const SUFFIXES: &[u8] = b"com\nnet\n";

/// Une remise qui ne garde que ce que la boucle lui a dit.
#[derive(Default)]
struct Temoin {
    /// Combien d'octets la boucle a demandé de réserver.
    reserve: usize,
    /// L'en-tête composé, tel qu'il serait écrit en tête du message.
    trace: Vec<u8>,
    /// La boucle a-t-elle demandé de mettre ce message de côté ?
    ecarte: bool,
    /// Ce dépôt-ci sait-il mettre de côté ?
    sait_ecarter: bool,
    /// Le message, tel qu'il a été diffusé.
    corps: Vec<u8>,
}

impl Delivery for Temoin {
    fn reserve_trace(&mut self, combien: usize) {
        self.reserve = combien;
    }
    fn trace(&mut self, entete: &[u8]) {
        self.trace = entete.to_vec();
    }
    fn quarantine(&mut self) -> bool {
        self.ecarte = true;
        self.sait_ecarter
    }
    fn add_recipient(&mut self, _address: &[u8]) -> Result<(), DeliveryFailure> {
        Ok(())
    }
    fn append(&mut self, chunk: &[u8]) -> Result<(), DeliveryFailure> {
        self.corps.extend_from_slice(chunk);
        Ok(())
    }
    fn finish(&mut self) -> Result<(), DeliveryFailure> {
        Ok(())
    }
    fn abort(&mut self) {}
}

fn checker(resolveur: SocketAddr) -> DmarcChecker {
    DmarcChecker::new(
        Resolver::new(std::vec![resolveur], Duration::from_secs(2)).expect("résolveur"),
        Arc::new(SUFFIXES.to_vec()),
        // **`observe`, ET NON `enforce`** : ces essais montrent que la
        // quarantaine ne dépend pas de ce réglage-là.
        false,
    )
}

/// Joue une transaction complète, et rend ce que la remise a vu.
async fn transaction(
    dmarc: Option<DmarcChecker>,
    sait_ecarter: bool,
) -> (Temoin, std::string::String) {
    let ecouteur = TcpListener::bind("127.0.0.1:0").await.expect("écoute");
    let adresse = ecouteur.local_addr().expect("adresse");

    let serveur = tokio::spawn(async move {
        let (mut flux, _) = ecouteur.accept().await.expect("connexion");
        let garde = SharedGuard::new(4, Thresholds::DEFAULT);
        let service = Service {
            config: Config::new(b"mail.example.com", 100, 10_485_760, Limits::DEFAULT)
                .expect("configurable"),
            guard: &garde,
            timeouts: Timeouts::default(),
            tls: None,
            spf: None,
            dkim: None,
            dmarc,
            reports: None,
        };
        let mut temoin = Temoin {
            sait_ecarter,
            ..Temoin::default()
        };
        serve_connection(&mut flux, &service, NotreDomaine, &mut temoin, PAIR)
            .await
            .expect("servie");
        temoin
    });

    let flux = TcpStream::connect(adresse).await.expect("connexion");
    let mut lecteur = BufReader::new(flux);
    let mut ligne = std::string::String::new();
    lecteur.read_line(&mut ligne).await.expect("bannière");
    for commande in [
        "EHLO client.example.net",
        "MAIL FROM:<personne@ailleurs.test>",
        "RCPT TO:<marie@example.com>",
        "DATA",
    ] {
        let ecrit = std::format!("{commande}\r\n");
        lecteur
            .get_mut()
            .write_all(ecrit.as_bytes())
            .await
            .expect("écriture");
        loop {
            ligne.clear();
            lecteur.read_line(&mut ligne).await.expect("réponse");
            if ligne.as_bytes().get(3) != Some(&b'-') {
                break;
            }
        }
    }
    lecteur
        .get_mut()
        .write_all(b"From: Joe SixPack <joe@example.com>\r\nSubject: bonjour\r\n\r\nsalut\r\n.\r\n")
        .await
        .expect("corps");
    ligne.clear();
    lecteur.read_line(&mut ligne).await.expect("fin");
    drop(lecteur);
    (serveur.await.expect("tâche"), ligne)
}

// ── L'EN-TÊTE ───────────────────────────────────────────────────────────────

/// **L'EN-TÊTE OCCUPE EXACTEMENT LA PLACE RÉSERVÉE.**
///
/// Un octet de trop écraserait le premier en-tête du pair ; un de moins
/// laisserait un trou au milieu du message.
#[tokio::test]
async fn l_en_tete_occupe_exactement_la_place_reservee() {
    let table: &[(&str, &str)] = &[("_dmarc.example.com", "v=DMARC1; p=none")];
    let resolveur = resolveur_par_nom(table).await;
    let (temoin, reponse) = transaction(Some(checker(resolveur)), false).await;

    assert!(reponse.starts_with("250"), "{reponse}");
    assert_eq!(temoin.reserve, AUTHRES_RESERVE);
    assert_eq!(temoin.trace.len(), AUTHRES_RESERVE);
    // Il commence par le champ, se replie sur des espaces, et finit par une
    // fin de ligne : c'est UN champ RFC 5322 valable, du premier octet au
    // dernier.
    let trace = std::string::String::from_utf8(temoin.trace).expect("ASCII");
    assert!(
        trace.starts_with(
            "Authentication-Results: mail.example.com;\r\n\tdmarc=fail header.from=example.com\r\n "
        ),
        "{trace:?}"
    );
    assert!(trace.ends_with("\r\n"), "{trace:?}");
    assert!(
        trace[..trace.len() - 2]
            .rsplit("\r\n ")
            .next()
            .is_some_and(|fin| fin.bytes().all(|octet| octet == b' ')),
        "le remplissage n'est pas fait d'espaces : {trace:?}"
    );
    // ET LE MESSAGE DU PAIR N'EST PAS TOUCHÉ — il suit la trace `Received:`,
    // que la boucle pose avant lui (RFC 5321 §4.4).
    assert!(
        temoin
            .corps
            .starts_with(b"Received: from client.example.net ")
    );
    assert!(
        temoin
            .corps
            .ends_with(b"From: Joe SixPack <joe@example.com>\r\nSubject: bonjour\r\n\r\nsalut\r\n")
    );
}

/// **QUAND RIEN N'A ÉTÉ VÉRIFIÉ, ON ÉCRIT `none` (§2.2).**
///
/// Un en-tête absent laisserait croire qu'un autre, fabriqué par le pair, vient
/// de nous.
#[tokio::test]
async fn sans_rien_a_verifier_l_en_tete_dit_none() {
    let (temoin, reponse) = transaction(None, false).await;

    assert!(reponse.starts_with("250"), "{reponse}");
    let trace = std::string::String::from_utf8(temoin.trace).expect("ASCII");
    assert!(
        trace.starts_with("Authentication-Results: mail.example.com; none\r\n "),
        "{trace:?}"
    );
    assert!(!temoin.ecarte, "rien n'est mis de côté sans DMARC");
}

// ── LA QUARANTAINE ──────────────────────────────────────────────────────────

/// **UN `p=quarantine` EST REMIS, ET MIS DE CÔTÉ.**
///
/// Il n'est pas refusé : la quarantaine déplace, elle ne jette pas. Et elle ne
/// dépend pas de `--dmarc enforce` — le vérificateur de ces essais est en
/// observation.
#[tokio::test]
async fn un_message_en_quarantaine_est_remis_et_ecarte() {
    let table: &[(&str, &str)] = &[("_dmarc.example.com", "v=DMARC1; p=quarantine")];
    let resolveur = resolveur_par_nom(table).await;
    let (temoin, reponse) = transaction(Some(checker(resolveur)), true).await;

    assert!(reponse.starts_with("250"), "{reponse}");
    assert!(temoin.ecarte, "la boucle a demandé de le mettre de côté");
    assert!(
        temoin
            .corps
            .starts_with(b"Received: from client.example.net ")
    );
}

/// **UN MESSAGE ALIGNÉ N'EST PAS MIS DE CÔTÉ**, même sous `p=quarantine`.
#[tokio::test]
async fn un_message_aligne_n_est_pas_ecarte() {
    let table: &[(&str, &str)] = &[("_dmarc.ailleurs.test", "v=DMARC1; p=quarantine")];
    let resolveur = resolveur_par_nom(table).await;
    let (temoin, reponse) = transaction(Some(checker(resolveur)), true).await;

    assert!(reponse.starts_with("250"), "{reponse}");
    assert!(
        !temoin.ecarte,
        "`example.com` ne publie rien : il n'y a pas de politique à opposer"
    );
}
