// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **La boucle IMAP**, de la bannière au `LOGOUT`.
//!
//! # Ce qui ne s'éprouve QUE là
//!
//! Le découpage des commandes et les états de la session ont leurs propres
//! tests, dans le périmètre couvert à 100 %. Ce qui se vérifie ici est la
//! jonction : qu'une commande à littéral traverse une vraie socket, que la
//! demande de continuation parte au bon moment, et qu'une syntaxe fautive ferme
//! la connexion au lieu de laisser le client choisir ce qu'on lira ensuite.

mod commun;

use ams_guard::Thresholds;
use ams_loop_tokio::SharedGuard;
use ams_loop_tokio::imap::{ImapService, serve_imap_connection};
use ams_proto_imap::Limits;
use commun::{COMPTE, NotreDomaine, PAIR, SECRET, materiel};
use core::time::Duration;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// Monte un service IMAP et rend l'adresse où le joindre.
async fn service(
    chiffrement: Option<Arc<rustls::ServerConfig>>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let ecouteur = TcpListener::bind("127.0.0.1:0").await.expect("écoute");
    let adresse = ecouteur.local_addr().expect("adresse");
    let tache = tokio::spawn(async move {
        let (mut flux, _) = ecouteur.accept().await.expect("connexion");
        let garde = SharedGuard::new(4, Thresholds::DEFAULT);
        let service = ImapService {
            limits: Limits::DEFAULT,
            guard: &garde,
            timeouts: ams_loop_tokio::Timeouts::default(),
            tls: chiffrement,
        };
        let _ = serve_imap_connection(&mut flux, &service, NotreDomaine, PAIR).await;
    });
    (adresse, tache)
}

/// Lit une ligne de réponse.
async fn ligne(lecteur: &mut BufReader<TcpStream>) -> std::string::String {
    let mut texte = std::string::String::new();
    lecteur.read_line(&mut texte).await.expect("réponse");
    texte
}

/// Écrit une commande.
async fn ecrire(lecteur: &mut BufReader<TcpStream>, octets: &[u8]) {
    lecteur.get_mut().write_all(octets).await.expect("écriture");
}

// ── LE CHEMIN ORDINAIRE ─────────────────────────────────────────────────────

#[tokio::test]
async fn la_banniere_annonce_puis_la_session_repond() {
    let (adresse, _) = service(None).await;
    let flux = TcpStream::connect(adresse).await.expect("connexion");
    let mut lecteur = BufReader::new(flux);

    let banniere = ligne(&mut lecteur).await;
    assert!(
        banniere.starts_with("* OK [CAPABILITY IMAP4rev2 LITERAL- LOGINDISABLED]"),
        "{banniere}"
    );

    ecrire(&mut lecteur, b"a001 CAPABILITY\r\n").await;
    let annonce = ligne(&mut lecteur).await;
    assert!(annonce.starts_with("* CAPABILITY IMAP4rev2"), "{annonce}");
    let conclusion = ligne(&mut lecteur).await;
    assert_eq!(conclusion, "a001 OK CAPABILITY completed\r\n");

    ecrire(&mut lecteur, b"a002 LOGOUT\r\n").await;
    assert!(ligne(&mut lecteur).await.starts_with("* BYE"));
    assert_eq!(ligne(&mut lecteur).await, "a002 OK LOGOUT completed\r\n");
    // La connexion se ferme d'elle-même.
    assert_eq!(ligne(&mut lecteur).await, "");
}

/// **Un mot de passe ne traverse pas une connexion en clair.**
#[tokio::test]
async fn en_clair_le_login_est_refuse_sur_le_fil() {
    let (adresse, _) = service(None).await;
    let flux = TcpStream::connect(adresse).await.expect("connexion");
    let mut lecteur = BufReader::new(flux);
    ligne(&mut lecteur).await;

    ecrire(&mut lecteur, b"a001 LOGIN jean ouvre-toi\r\n").await;
    let refus = ligne(&mut lecteur).await;
    assert!(refus.starts_with("a001 NO [PRIVACYREQUIRED]"), "{refus}");
}

// ── LES LITTÉRAUX, DE BOUT EN BOUT ──────────────────────────────────────────

/// **La demande de continuation part au bon moment** : le client attend, et
/// n'enverra rien avant de l'avoir vue.
#[tokio::test]
async fn un_litteral_synchronisant_traverse_la_socket() {
    let Some(materiel) = materiel("imap-litteral") else {
        return;
    };
    let (adresse, _) = service(Some(Arc::clone(&materiel.tls))).await;
    let mut lecteur = BufReader::new(TcpStream::connect(adresse).await.expect("connexion"));
    ligne(&mut lecteur).await;

    ecrire(&mut lecteur, b"a001 STARTTLS\r\n").await;
    assert!(ligne(&mut lecteur).await.starts_with("a001 OK Begin TLS"));

    let flux = lecteur.into_inner();
    let connecteur = tokio_rustls::TlsConnector::from(Arc::new(ams_tls::relay_config()));
    let chiffre = connecteur
        .connect("localhost".try_into().expect("nom"), flux)
        .await
        .expect("poignée de main");
    let mut lecteur = BufReader::new(chiffre);

    // Le nom du compte arrive en littéral, en deux temps.
    let debut = std::format!("a002 LOGIN {{{}}}\r\n", COMPTE.len());
    lecteur
        .get_mut()
        .write_all(debut.as_bytes())
        .await
        .expect("écriture");
    let mut invite = std::string::String::new();
    lecteur.read_line(&mut invite).await.expect("continuation");
    assert_eq!(invite, "+ ready for literal\r\n");

    let mut suite = std::vec::Vec::from(COMPTE);
    suite.push(b' ');
    suite.extend_from_slice(SECRET);
    suite.extend_from_slice(b"\r\n");
    lecteur.get_mut().write_all(&suite).await.expect("écriture");
    let mut reponse = std::string::String::new();
    lecteur.read_line(&mut reponse).await.expect("réponse");
    assert!(reponse.starts_with("a002 OK Authenticated"), "{reponse}");
}

/// **`{4294967295}` est une ligne de treize octets qui demande quatre
/// gibioctets.** Le pilote la refuse et raccroche : on ne sait plus où la
/// commande se termine.
#[tokio::test]
async fn un_litteral_demesure_ferme_la_connexion() {
    let (adresse, _) = service(None).await;
    let mut lecteur = BufReader::new(TcpStream::connect(adresse).await.expect("connexion"));
    ligne(&mut lecteur).await;

    ecrire(&mut lecteur, b"a001 APPEND boite {4294967295}\r\n").await;
    let adieu = ligne(&mut lecteur).await;
    assert_eq!(
        adieu,
        "* BAD Command could not be parsed; closing connection\r\n"
    );
    assert_eq!(ligne(&mut lecteur).await, "", "la connexion doit se fermer");
}

/// Une commande à littéral NON synchronisant part d'un seul tenant, et le
/// pilote ne doit pas la couper au premier `CRLF`.
#[tokio::test]
async fn un_litteral_non_synchronisant_ne_coupe_pas_la_commande() {
    let (adresse, _) = service(None).await;
    let mut lecteur = BufReader::new(TcpStream::connect(adresse).await.expect("connexion"));
    ligne(&mut lecteur).await;

    // Le littéral contient lui-même un `CRLF` : une lecture naïve lirait
    // « toto MOTDEPASSE » comme une commande.
    ecrire(&mut lecteur, b"a001 LOGIN {6+}\r\nto\r\nto secret\r\n").await;
    let reponse = ligne(&mut lecteur).await;
    // En clair, c'est le refus de `LOGIN` qui répond — ce qui prouve que la
    // commande a été lue en entier, et une seule fois.
    assert!(
        reponse.starts_with("a001 NO [PRIVACYREQUIRED]"),
        "{reponse}"
    );

    ecrire(&mut lecteur, b"a002 NOOP\r\n").await;
    assert_eq!(ligne(&mut lecteur).await, "a002 OK NOOP completed\r\n");
}

// ── CE QU'ON N'A PAS SU LIRE ────────────────────────────────────────────────

#[tokio::test]
async fn une_ligne_demesuree_ferme_la_connexion() {
    let (adresse, _) = service(None).await;
    let mut lecteur = BufReader::new(TcpStream::connect(adresse).await.expect("connexion"));
    ligne(&mut lecteur).await;

    let mut trop = std::vec::Vec::from(&b"a001 "[..]);
    trop.resize(Limits::DEFAULT.max_line_octets + 16, b'x');
    trop.extend_from_slice(b"\r\n");
    ecrire(&mut lecteur, &trop).await;
    let adieu = ligne(&mut lecteur).await;
    assert!(
        adieu.starts_with("* BAD Command could not be parsed"),
        "{adieu}"
    );
}

#[tokio::test]
async fn un_tag_illisible_repond_sans_tag_et_la_session_continue() {
    let (adresse, _) = service(None).await;
    let mut lecteur = BufReader::new(TcpStream::connect(adresse).await.expect("connexion"));
    ligne(&mut lecteur).await;

    ecrire(&mut lecteur, b"a*1 NOOP\r\n").await;
    assert_eq!(ligne(&mut lecteur).await, "* BAD Malformed tag\r\n");
    // La commande était lisible — c'est son tag qui ne l'était pas — donc la
    // connexion reste ouverte.
    ecrire(&mut lecteur, b"a002 NOOP\r\n").await;
    assert_eq!(ligne(&mut lecteur).await, "a002 OK NOOP completed\r\n");
}

// ── SASL ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn authenticate_plain_traverse_la_socket() {
    let Some(materiel) = materiel("imap-sasl") else {
        return;
    };
    let (adresse, _) = service(Some(Arc::clone(&materiel.tls))).await;
    let mut lecteur = BufReader::new(TcpStream::connect(adresse).await.expect("connexion"));
    ligne(&mut lecteur).await;
    ecrire(&mut lecteur, b"a001 STARTTLS\r\n").await;
    ligne(&mut lecteur).await;

    let connecteur = tokio_rustls::TlsConnector::from(Arc::new(ams_tls::relay_config()));
    let chiffre = connecteur
        .connect("localhost".try_into().expect("nom"), lecteur.into_inner())
        .await
        .expect("poignée de main");
    let mut lecteur = BufReader::new(chiffre);

    lecteur
        .get_mut()
        .write_all(b"a002 AUTHENTICATE PLAIN\r\n")
        .await
        .expect("écriture");
    let mut defi = std::string::String::new();
    lecteur.read_line(&mut defi).await.expect("défi");
    assert_eq!(defi, "+ \r\n");

    // base64 de "\0jean\0ouvre-toi"
    lecteur
        .get_mut()
        .write_all(b"AGplYW4Ab3V2cmUtdG9p\r\n")
        .await
        .expect("écriture");
    let mut reponse = std::string::String::new();
    lecteur.read_line(&mut reponse).await.expect("réponse");
    assert!(reponse.starts_with("a002 OK Authenticated"), "{reponse}");
}

// ── LE GARDE ────────────────────────────────────────────────────────────────

/// **On ne parle pas à un banni** : rien ne lui est dit, la connexion se ferme.
#[tokio::test]
async fn un_pair_banni_n_obtient_pas_de_banniere() {
    let ecouteur = TcpListener::bind("127.0.0.1:0").await.expect("écoute");
    let adresse = ecouteur.local_addr().expect("adresse");
    let tache = tokio::spawn(async move {
        let (mut flux, _) = ecouteur.accept().await.expect("connexion");
        let garde = SharedGuard::new(4, Thresholds::DEFAULT);
        // On le bannit avant même qu'il ne parle.
        for _ in 0..1000 {
            garde.observe(PAIR, ams_guard::Event::InvalidFrame);
        }
        let service = ImapService {
            limits: Limits::DEFAULT,
            guard: &garde,
            timeouts: ams_loop_tokio::Timeouts::default(),
            tls: None,
        };
        serve_imap_connection(&mut flux, &service, NotreDomaine, PAIR).await
    });

    let mut lecteur = BufReader::new(TcpStream::connect(adresse).await.expect("connexion"));
    assert_eq!(ligne(&mut lecteur).await, "", "un banni n'entend rien");
    let resume = tache.await.expect("tâche").expect("servie");
    assert!(resume.banned);
    assert_eq!(resume.commands, 0);
}

/// Un délai dépassé ferme la connexion : un pair muet n'occupe pas une place.
#[tokio::test]
async fn un_pair_muet_est_abandonne() {
    let ecouteur = TcpListener::bind("127.0.0.1:0").await.expect("écoute");
    let adresse = ecouteur.local_addr().expect("adresse");
    let tache = tokio::spawn(async move {
        let (mut flux, _) = ecouteur.accept().await.expect("connexion");
        let garde = SharedGuard::new(4, Thresholds::DEFAULT);
        let service = ImapService {
            limits: Limits::DEFAULT,
            guard: &garde,
            timeouts: ams_loop_tokio::Timeouts {
                command: Duration::from_millis(50),
                ..ams_loop_tokio::Timeouts::default()
            },
            tls: None,
        };
        serve_imap_connection(&mut flux, &service, NotreDomaine, PAIR).await
    });

    let mut lecteur = BufReader::new(TcpStream::connect(adresse).await.expect("connexion"));
    ligne(&mut lecteur).await;
    // On ne dit rien, et on attend.
    let issue = tache.await.expect("tâche");
    assert!(issue.is_err(), "le pair muet devait être abandonné");
}
