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
use ams_proto_imap::{Flags, PartWhat, StoreMode};
use ams_session::imap::{Mailbox, Mailboxes, MessageInfo};
use commun::{COMPTE, NotreDomaine, PAIR, SECRET, materiel};
use core::time::Duration;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// Deux messages d'épreuve, en mémoire.
const MESSAGES: [&[u8]; 2] = [
    b"From: a@x.test\r\nSubject: un\r\n\r\nPremier corps.\r\n",
    b"From: b@x.test\r\nSubject: deux\r\n\r\nSecond corps.\r\n",
];

/// Une boîte en mémoire : c'est le protocole qu'on éprouve ici, pas Maildir.
struct Boite;

impl Boite {
    /// Compose un choix de champs sur l'en-tête d'un message.
    fn choisir(
        &self,
        sequence: u32,
        path: &[u32],
        names: &[u8],
        except: bool,
        out: &mut [u8],
    ) -> Option<usize> {
        let corps = MESSAGES.get(usize::try_from(sequence).unwrap_or(0).saturating_sub(1))?;
        // Seul l'en-tête du message : les messages d'épreuve n'encapsulent rien.
        if !path.is_empty() {
            return None;
        }
        ams_mime::write_header_fields(corps, names, except, out, &ams_mime::Limits::DEFAULT).ok()
    }
}

impl Mailbox for Boite {
    fn exists(&self) -> u32 {
        2
    }
    fn uid_validity(&self) -> u32 {
        7
    }
    fn uid_next(&self) -> u32 {
        3
    }
    fn info(&self, sequence: u32) -> Option<MessageInfo> {
        let corps = MESSAGES.get(usize::try_from(sequence).ok()?.checked_sub(1)?)?;
        Some(MessageInfo {
            uid: sequence,
            size: corps.len() as u64,
            flags: Flags::NONE,
            internal_date: 1_787_987_311,
        })
    }
    fn header_octets(&self, sequence: u32) -> u64 {
        let Some(corps) = MESSAGES.get(usize::try_from(sequence).unwrap_or(0).saturating_sub(1))
        else {
            return 0;
        };
        corps
            .windows(4)
            .position(|fenetre| fenetre == b"\r\n\r\n")
            .map_or(0, |rang| (rang as u64).saturating_add(4))
    }
    fn permanent_flags(&self) -> Flags {
        Flags::SEEN.with(Flags::FLAGGED)
    }
    fn envelope(&self, sequence: u32, offset: u64, out: &mut [u8]) -> usize {
        let Some(corps) = MESSAGES.get(usize::try_from(sequence).unwrap_or(0).saturating_sub(1))
        else {
            return 0;
        };
        let fin = corps
            .windows(4)
            .position(|fenetre| fenetre == b"\r\n\r\n")
            .map_or(corps.len(), |rang| rang.saturating_add(4));
        let mut compose = std::vec![0_u8; 4096];
        let Ok(ecrits) = ams_mime::write_envelope(
            corps.get(..fin).unwrap_or_default(),
            &mut compose,
            &ams_mime::Limits::DEFAULT,
        ) else {
            return 0;
        };
        let reste = compose
            .get(usize::try_from(offset).unwrap_or(usize::MAX)..ecrits)
            .unwrap_or_default();
        let voulu = reste.len().min(out.len());
        for (place, octet) in out.iter_mut().zip(reste.get(..voulu).unwrap_or_default()) {
            *place = *octet;
        }
        voulu
    }

    fn part_span(&self, sequence: u32, path: &[u32], what: PartWhat) -> Option<(u64, u64)> {
        let corps = MESSAGES.get(usize::try_from(sequence).unwrap_or(0).saturating_sub(1))?;
        let mut balayeur = ams_mime::BodyScanner::new(&ams_mime::Limits::DEFAULT);
        balayeur.push(corps);
        balayeur.finish();
        balayeur.span(
            path,
            match what {
                PartWhat::Content => ams_mime::BodySpan::Content,
                PartWhat::Mime => ams_mime::BodySpan::Mime,
                PartWhat::Header => ams_mime::BodySpan::Header,
                PartWhat::Text => ams_mime::BodySpan::Text,
                // Un choix n'est pas un intervalle : il passe par
                // `header_fields`.
                PartWhat::HeaderFields { .. } => return None,
            },
        )
    }

    fn header_fields_len(
        &self,
        sequence: u32,
        path: &[u32],
        names: &[u8],
        except: bool,
    ) -> Option<u64> {
        let mut sortie = std::vec![0_u8; 4096];
        let ecrits = self.choisir(sequence, path, names, except, &mut sortie)?;
        Some(u64::try_from(ecrits).unwrap_or(u64::MAX))
    }

    fn header_fields(
        &self,
        sequence: u32,
        path: &[u32],
        names: &[u8],
        except: bool,
        offset: u64,
        out: &mut [u8],
    ) -> usize {
        let mut sortie = std::vec![0_u8; 4096];
        let Some(ecrits) = self.choisir(sequence, path, names, except, &mut sortie) else {
            return 0;
        };
        let reste = sortie
            .get(usize::try_from(offset).unwrap_or(usize::MAX)..ecrits)
            .unwrap_or_default();
        let voulu = reste.len().min(out.len());
        for (place, octet) in out.iter_mut().zip(reste.get(..voulu).unwrap_or_default()) {
            *place = *octet;
        }
        voulu
    }

    fn body_structure(&self, sequence: u32, offset: u64, out: &mut [u8]) -> usize {
        let Some(corps) = MESSAGES.get(usize::try_from(sequence).unwrap_or(0).saturating_sub(1))
        else {
            return 0;
        };
        let mut compose = std::vec![0_u8; 4096];
        let Ok(ecrits) =
            ams_mime::write_body_structure(corps, &mut compose, &ams_mime::Limits::DEFAULT)
        else {
            return 0;
        };
        let reste = compose
            .get(usize::try_from(offset).unwrap_or(usize::MAX)..ecrits)
            .unwrap_or_default();
        let voulu = reste.len().min(out.len());
        for (place, octet) in out.iter_mut().zip(reste.get(..voulu).unwrap_or_default()) {
            *place = *octet;
        }
        voulu
    }

    fn read(&self, sequence: u32, offset: u64, out: &mut [u8]) -> usize {
        let Some(corps) = MESSAGES.get(usize::try_from(sequence).unwrap_or(0).saturating_sub(1))
        else {
            return 0;
        };
        let Ok(depart) = usize::try_from(offset) else {
            return 0;
        };
        let reste = corps.get(depart..).unwrap_or_default();
        let combien = reste.len().min(out.len());
        out.get_mut(..combien)
            .unwrap_or_default()
            .copy_from_slice(reste.get(..combien).unwrap_or_default());
        combien
    }
    fn copy_to(&mut self, sequence: u32, mailbox: &[u8]) -> Option<u32> {
        // La boîte d'épreuve ne grandit pas : elle rend un UID plausible, ce qui
        // suffit à éprouver ce qui passe sur le fil.
        (mailbox == b"INBOX" && (1..=2).contains(&sequence)).then_some(sequence.saturating_add(2))
    }

    fn undo_copies(&mut self, _mailbox: &[u8], _premier: u32, _dernier: u32) {
        // Rien à défaire : la boîte d'épreuve n'a rien retenu.
    }

    fn remove(&mut self, _sequence: u32) -> bool {
        // La boîte d'épreuve ne rétrécit pas ; voir `expunge`.
        false
    }

    fn expunge(&mut self, _sequence: u32) -> bool {
        // La boîte d'épreuve ne rétrécit pas : rien ne s'y efface, et c'est le
        // passage sur le fil qu'on éprouve ici. `false` dit « toujours là », ce
        // qui fait passer la session au message suivant sans rien annoncer.
        false
    }

    fn store_flags(&mut self, sequence: u32, _mode: StoreMode, _flags: Flags) -> Option<Flags> {
        // La boîte d'épreuve ne retient rien : ce qu'on éprouve ici est le
        // passage sur le fil, pas la persistance.
        (1..=2).contains(&sequence).then_some(Flags::SEEN)
    }
}

/// Un dépôt d'épreuve : il compte, et ne garde rien.
#[derive(Default)]
struct Depot {
    recus: usize,
}

impl ams_session::imap::Deposit for Depot {
    fn write(&mut self, chunk: &[u8]) -> bool {
        self.recus = self.recus.saturating_add(chunk.len());
        true
    }

    fn commit(self, _flags: Flags, _date: Option<u64>) -> Option<u32> {
        // L'UID rendu dit combien d'octets sont passés : de quoi vérifier sur le
        // fil que le message est arrivé entier.
        u32::try_from(self.recus).ok()
    }

    fn abort(self) {}
}

struct Boites;

impl Mailboxes for Boites {
    type Open = Boite;
    fn name<'n>(
        &self,
        _user: &[u8],
        index: usize,
        out: &'n mut [u8],
    ) -> Option<ams_session::imap::Listing<'n>> {
        let (nom, selectable): (&[u8], bool) = match index {
            0 => (b"INBOX", true),
            1 => (b"Brouillons", true),
            // Une boîte effacée qui avait des filles : elle garde son nom.
            2 => (b"Videe", false),
            _ => return None,
        };
        let longueur = nom.len().min(out.len());
        for (place, octet) in out.iter_mut().zip(nom) {
            *place = *octet;
        }
        Some(ams_session::imap::Listing {
            name: out.get(..longueur)?,
            selectable,
        })
    }

    fn rename(&self, _user: &[u8], from: &[u8], to: &[u8]) -> ams_session::imap::Renaming {
        match (from, to) {
            (b"Brouillons", b"Anciens") => ams_session::imap::Renaming::Faite,
            (b"Brouillons", _) => ams_session::imap::Renaming::DejaLa,
            _ => ams_session::imap::Renaming::Absente,
        }
    }

    fn delete(&self, _user: &[u8], name: &[u8]) -> ams_session::imap::Deletion {
        if name == b"Brouillons" {
            ams_session::imap::Deletion::Faite
        } else {
            ams_session::imap::Deletion::Absente
        }
    }

    fn create(&self, _user: &[u8], name: &[u8]) -> ams_session::imap::Creation {
        // La boîte d'épreuve ne crée rien : elle dit ce qui existe, et refuse
        // le reste. C'est le passage sur le fil qu'on éprouve ici.
        if name == b"Brouillons" {
            ams_session::imap::Creation::DejaLa
        } else {
            ams_session::imap::Creation::Faite
        }
    }
    type Deposit = Depot;

    fn append(&self, _user: &[u8], name: &[u8]) -> Option<Depot> {
        (name == b"INBOX").then(Depot::default)
    }

    fn open(&self, _user: &[u8], name: &[u8]) -> Option<Boite> {
        (name == b"INBOX").then_some(Boite)
    }
}

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
            max_append_octets: 1_000_000,
        };
        let _ = serve_imap_connection(&mut flux, &service, NotreDomaine, &Boites, PAIR).await;
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
            max_append_octets: 1_000_000,
        };
        serve_imap_connection(&mut flux, &service, NotreDomaine, &Boites, PAIR).await
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
            max_append_octets: 1_000_000,
        };
        serve_imap_connection(&mut flux, &service, NotreDomaine, &Boites, PAIR).await
    });

    let mut lecteur = BufReader::new(TcpStream::connect(adresse).await.expect("connexion"));
    ligne(&mut lecteur).await;
    // On ne dit rien, et on attend.
    let issue = tache.await.expect("tâche");
    assert!(issue.is_err(), "le pair muet devait être abandonné");
}

// ── LES BOÎTES, DE BOUT EN BOUT ─────────────────────────────────────────────

/// Ouvre une session chiffrée et authentifiée, et rend le flux.
async fn authentifiee(
    materiel: &commun::Materiel,
) -> BufReader<tokio_rustls::client::TlsStream<TcpStream>> {
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
        .write_all(b"a002 LOGIN jean ouvre-toi\r\n")
        .await
        .expect("écriture");
    let mut reponse = std::string::String::new();
    lecteur.read_line(&mut reponse).await.expect("réponse");
    assert!(reponse.contains("OK Authenticated"), "{reponse}");
    lecteur
}

/// Lit des lignes jusqu'à en trouver une qui commence par `tag`.
async fn jusqu_a(
    lecteur: &mut BufReader<tokio_rustls::client::TlsStream<TcpStream>>,
    tag: &str,
) -> std::string::String {
    let mut tout = std::string::String::new();
    loop {
        let mut une = std::string::String::new();
        lecteur.read_line(&mut une).await.expect("réponse");
        let fini = une.starts_with(tag) || une.is_empty();
        tout.push_str(&une);
        if fini {
            return tout;
        }
    }
}

#[tokio::test]
async fn une_boite_s_ouvre_et_se_lit_sur_le_fil() {
    let Some(materiel) = materiel("imap-boite") else {
        return;
    };
    let mut lecteur = authentifiee(&materiel).await;

    lecteur
        .get_mut()
        .write_all(b"a003 LIST \"\" *\r\n")
        .await
        .expect("écriture");
    let liste = jusqu_a(&mut lecteur, "a003 ").await;
    assert!(liste.contains("* LIST () \"/\" \"INBOX\"\r\n"), "{liste}");

    lecteur
        .get_mut()
        .write_all(b"a004 SELECT INBOX\r\n")
        .await
        .expect("écriture");
    let selection = jusqu_a(&mut lecteur, "a004 ").await;
    assert!(selection.contains("* 2 EXISTS\r\n"), "{selection}");
    assert!(selection.contains("[UIDVALIDITY 7]"), "{selection}");
    assert!(selection.contains("a004 OK [READ-WRITE]"), "{selection}");

    // **Le corps traverse la socket tel quel**, précédé de sa longueur.
    lecteur
        .get_mut()
        .write_all(b"a005 FETCH 1 (UID BODY.PEEK[])\r\n")
        .await
        .expect("écriture");
    let mut attendu = std::string::String::from("* 1 FETCH (UID 1 BODY[] {");
    attendu.push_str(&std::format!("{}", MESSAGES[0].len()));
    attendu.push_str("}\r\n");
    attendu.push_str(&std::string::String::from_utf8_lossy(MESSAGES[0]));
    attendu.push_str(")\r\n");
    let fetch = jusqu_a(&mut lecteur, "a005 ").await;
    assert!(
        fetch.starts_with(&attendu),
        "attendu :\n{attendu}\nreçu :\n{fetch}"
    );
    assert!(fetch.ends_with("a005 OK FETCH completed\r\n"), "{fetch}");
}

/// **Une section rend exactement ce qu'elle annonce**, et l'en-tête d'un message
/// n'est pas son corps.
#[tokio::test]
async fn les_sections_rendent_ce_qu_elles_annoncent() {
    let Some(materiel) = materiel("imap-sections") else {
        return;
    };
    let mut lecteur = authentifiee(&materiel).await;
    lecteur
        .get_mut()
        .write_all(b"a003 SELECT INBOX\r\n")
        .await
        .expect("écriture");
    jusqu_a(&mut lecteur, "a003 ").await;

    lecteur
        .get_mut()
        .write_all(b"a004 FETCH 1 BODY.PEEK[HEADER]\r\n")
        .await
        .expect("écriture");
    let entete = jusqu_a(&mut lecteur, "a004 ").await;
    assert!(
        entete.contains("From: a@x.test\r\nSubject: un\r\n\r\n)"),
        "{entete}"
    );
    assert!(!entete.contains("Premier corps"), "{entete}");

    lecteur
        .get_mut()
        .write_all(b"a005 FETCH 1 BODY.PEEK[TEXT]<2.5>\r\n")
        .await
        .expect("écriture");
    let tranche = jusqu_a(&mut lecteur, "a005 ").await;
    // « Premier corps. » à partir du deuxième octet, sur cinq : « emier ».
    assert!(tranche.contains("BODY[TEXT]<2> {5}\r\nemier)"), "{tranche}");
}

/// Un `UID FETCH` désigne par UID, et rend le rang.
#[tokio::test]
async fn uid_fetch_traverse_la_socket() {
    let Some(materiel) = materiel("imap-uid") else {
        return;
    };
    let mut lecteur = authentifiee(&materiel).await;
    lecteur
        .get_mut()
        .write_all(b"a003 SELECT INBOX\r\n")
        .await
        .expect("écriture");
    jusqu_a(&mut lecteur, "a003 ").await;
    lecteur
        .get_mut()
        .write_all(b"a004 UID FETCH 2 (UID RFC822.SIZE)\r\n")
        .await
        .expect("écriture");
    let fetch = jusqu_a(&mut lecteur, "a004 ").await;
    assert!(
        fetch.contains(&std::format!(
            "* 2 FETCH (UID 2 RFC822.SIZE {})\r\n",
            MESSAGES[1].len()
        )),
        "{fetch}"
    );
}

/// **Un `STORE` traverse la socket, et sa conclusion vient APRÈS ses réponses.**
#[tokio::test]
async fn un_store_traverse_la_socket() {
    let Some(materiel) = materiel("imap-store") else {
        return;
    };
    let mut lecteur = authentifiee(&materiel).await;
    lecteur
        .get_mut()
        .write_all(b"a003 SELECT INBOX\r\n")
        .await
        .expect("écriture");
    let selection = jusqu_a(&mut lecteur, "a003 ").await;
    // La boîte sait écrire deux drapeaux, et le dit.
    assert!(
        selection.contains("* OK [PERMANENTFLAGS (\\Seen \\Flagged)] Flags permitted\r\n"),
        "{selection}"
    );
    assert!(selection.contains("a003 OK [READ-WRITE]"), "{selection}");

    lecteur
        .get_mut()
        .write_all(b"a004 STORE 1:2 +FLAGS (\\Seen)\r\n")
        .await
        .expect("écriture");
    let store = jusqu_a(&mut lecteur, "a004 ").await;
    assert_eq!(
        store,
        "* 1 FETCH (FLAGS (\\Seen))\r\n* 2 FETCH (FLAGS (\\Seen))\r\n\
         a004 OK STORE completed\r\n",
        "{store}"
    );

    // `.SILENT` ne rend que la conclusion.
    lecteur
        .get_mut()
        .write_all(b"a005 STORE 1 +FLAGS.SILENT (\\Seen)\r\n")
        .await
        .expect("écriture");
    let silencieux = jusqu_a(&mut lecteur, "a005 ").await;
    assert_eq!(silencieux, "a005 OK STORE completed\r\n");

    // Un drapeau que la boîte ne fait pas survivre est refusé, pas ignoré.
    lecteur
        .get_mut()
        .write_all(b"a006 STORE 1 +FLAGS (\\Draft)\r\n")
        .await
        .expect("écriture");
    let refus = jusqu_a(&mut lecteur, "a006 ").await;
    assert!(refus.starts_with("a006 NO [CANNOT]"), "{refus}");
}

/// **`EXPUNGE` traverse la socket**, et un magasin qui refuse d'effacer n'y fait
/// rien annoncer.
#[tokio::test]
async fn un_expunge_traverse_la_socket() {
    let Some(materiel) = materiel("imap-expunge") else {
        return;
    };
    let mut lecteur = authentifiee(&materiel).await;
    lecteur
        .get_mut()
        .write_all(b"a003 SELECT INBOX\r\n")
        .await
        .expect("écriture");
    jusqu_a(&mut lecteur, "a003 ").await;

    // La boîte d'épreuve ne sait pas écrire `\Deleted` : `EXPUNGE` est donc
    // refusé, et le dire vaut mieux que de laisser croire à un effacement.
    lecteur
        .get_mut()
        .write_all(b"a004 EXPUNGE\r\n")
        .await
        .expect("écriture");
    let refus = jusqu_a(&mut lecteur, "a004 ").await;
    assert!(refus.starts_with("a004 NO [CANNOT]"), "{refus}");

    // `UNSELECT` referme sans rien effacer, et se nomme.
    lecteur
        .get_mut()
        .write_all(b"a005 UNSELECT\r\n")
        .await
        .expect("écriture");
    let referme = jusqu_a(&mut lecteur, "a005 ").await;
    assert_eq!(referme, "a005 OK UNSELECT completed\r\n");
}

/// **`SEARCH` traverse la socket**, et rend un `ESEARCH` en une ligne.
#[tokio::test]
async fn une_recherche_traverse_la_socket() {
    let Some(materiel) = materiel("imap-search") else {
        return;
    };
    let mut lecteur = authentifiee(&materiel).await;
    lecteur
        .get_mut()
        .write_all(b"a003 SELECT INBOX\r\n")
        .await
        .expect("écriture");
    jusqu_a(&mut lecteur, "a003 ").await;

    lecteur
        .get_mut()
        .write_all(b"a004 SEARCH ALL\r\n")
        .await
        .expect("écriture");
    let tout = jusqu_a(&mut lecteur, "a004 ").await;
    assert_eq!(
        tout,
        "* ESEARCH (TAG \"a004\") ALL 1:2\r\na004 OK SEARCH completed\r\n"
    );

    lecteur
        .get_mut()
        .write_all(b"a005 UID SEARCH LARGER 40\r\n")
        .await
        .expect("écriture");
    let grands = jusqu_a(&mut lecteur, "a005 ").await;
    assert_eq!(
        grands,
        "* ESEARCH (TAG \"a005\") UID ALL 1:2\r\na005 OK UID SEARCH completed\r\n"
    );

    // Un critère qu'on ne sert pas est refusé, pas rendu faux.
    lecteur
        .get_mut()
        .write_all(b"a006 SEARCH SUBJECT facture\r\n")
        .await
        .expect("écriture");
    let refus = jusqu_a(&mut lecteur, "a006 ").await;
    assert!(refus.starts_with("a006 NO [CANNOT]"), "{refus}");
}

/// **`COPY` traverse la socket**, et sa conclusion porte le `COPYUID`.
#[tokio::test]
async fn une_copie_traverse_la_socket() {
    let Some(materiel) = materiel("imap-copy") else {
        return;
    };
    let mut lecteur = authentifiee(&materiel).await;
    lecteur
        .get_mut()
        .write_all(b"a003 SELECT INBOX\r\n")
        .await
        .expect("écriture");
    jusqu_a(&mut lecteur, "a003 ").await;

    lecteur
        .get_mut()
        .write_all(b"a004 COPY 1:2 INBOX\r\n")
        .await
        .expect("écriture");
    let copie = jusqu_a(&mut lecteur, "a004 ").await;
    assert_eq!(copie, "a004 OK [COPYUID 7 1:2 3:4] COPY completed\r\n");

    // Une destination inconnue se dit `[TRYCREATE]`, jamais autrement.
    lecteur
        .get_mut()
        .write_all(b"a005 COPY 1 Archives\r\n")
        .await
        .expect("écriture");
    let refus = jusqu_a(&mut lecteur, "a005 ").await;
    assert!(refus.starts_with("a005 NO [TRYCREATE]"), "{refus}");
}

/// **`MOVE` traverse la socket, et dans l'ordre de §6.4.8** : le `COPYUID` non
/// sollicité d'abord, les `EXPUNGE` ensuite, la conclusion enfin.
#[tokio::test]
async fn un_deplacement_traverse_la_socket_dans_le_bon_ordre() {
    let Some(materiel) = materiel("imap-move") else {
        return;
    };
    let mut lecteur = authentifiee(&materiel).await;
    lecteur
        .get_mut()
        .write_all(b"a003 SELECT INBOX\r\n")
        .await
        .expect("écriture");
    jusqu_a(&mut lecteur, "a003 ").await;

    // La boîte d'épreuve ne rétrécit pas : le `COPYUID` passe, et aucun
    // `EXPUNGE` ne suit — ce qui est exactement ce que le magasin a fait.
    lecteur
        .get_mut()
        .write_all(b"a004 MOVE 1 INBOX\r\n")
        .await
        .expect("écriture");
    let deplace = jusqu_a(&mut lecteur, "a004 ").await;
    assert_eq!(
        deplace,
        "* OK [COPYUID 7 1 3] Moved\r\na004 OK MOVE completed\r\n"
    );

    lecteur
        .get_mut()
        .write_all(b"a005 MOVE 1 Archives\r\n")
        .await
        .expect("écriture");
    let refus = jusqu_a(&mut lecteur, "a005 ").await;
    assert!(refus.starts_with("a005 NO [TRYCREATE]"), "{refus}");
}

/// **`APPEND` écoule son message sans le retenir.** Le dépôt d'épreuve rend le
/// nombre d'octets reçus comme UID : la conclusion dit donc, sur le fil, que le
/// message est arrivé entier.
#[tokio::test]
async fn un_append_ecoule_son_message() {
    let Some(materiel) = materiel("imap-append") else {
        return;
    };
    let mut lecteur = authentifiee(&materiel).await;
    let message = "From: a@x.test\r\nSubject: déposé\r\n\r\nUn corps.\r\n";
    lecteur
        .get_mut()
        .write_all(std::format!("a003 APPEND INBOX {{{}}}\r\n", message.len()).as_bytes())
        .await
        .expect("écriture");
    // Le littéral est synchronisant : le serveur invite avant tout octet.
    let mut invite = std::string::String::new();
    lecteur.read_line(&mut invite).await.expect("invite");
    assert!(invite.starts_with("+ "), "{invite}");
    lecteur
        .get_mut()
        .write_all(message.as_bytes())
        .await
        .expect("écriture");
    let conclusion = jusqu_a(&mut lecteur, "a003 ").await;
    assert_eq!(
        conclusion,
        std::format!(
            "a003 OK [APPENDUID 7 {}] APPEND completed\r\n",
            message.len()
        )
    );

    // Et la session continue : le flux n'a pas été désynchronisé.
    lecteur
        .get_mut()
        .write_all(b"a004 SELECT INBOX\r\n")
        .await
        .expect("écriture");
    let apres = jusqu_a(&mut lecteur, "a004 ").await;
    assert!(apres.contains("a004 OK ["), "{apres}");
}

/// **Une boîte inconnue se dit `[TRYCREATE]`, sans qu'un octet ait été lu.**
/// C'est tout l'intérêt du littéral synchronisant : le client attend.
#[tokio::test]
async fn un_append_vers_une_boite_inconnue_se_refuse_avant_le_message() {
    let Some(materiel) = materiel("imap-append-inconnue") else {
        return;
    };
    let mut lecteur = authentifiee(&materiel).await;
    lecteur
        .get_mut()
        .write_all(b"a003 APPEND Archives {100}\r\n")
        .await
        .expect("écriture");
    let refus = jusqu_a(&mut lecteur, "a003 ").await;
    assert!(refus.starts_with("a003 NO [TRYCREATE]"), "{refus}");

    // Aucun octet de message n'a été envoyé, et la session suit toujours.
    lecteur
        .get_mut()
        .write_all(b"a004 SELECT INBOX\r\n")
        .await
        .expect("écriture");
    let apres = jusqu_a(&mut lecteur, "a004 ").await;
    assert!(apres.contains("a004 OK"), "{apres}");
}

/// **Un message plus gros que ce qu'on accepte ferme la connexion**, plutôt que
/// de laisser ses octets se lire comme des commandes.
#[tokio::test]
async fn un_append_demesure_ferme_la_connexion() {
    let Some(materiel) = materiel("imap-append-gros") else {
        return;
    };
    let mut lecteur = authentifiee(&materiel).await;
    lecteur
        .get_mut()
        .write_all(b"a003 APPEND INBOX {99999999}\r\n")
        .await
        .expect("écriture");
    let adieu = jusqu_a(&mut lecteur, "a003 ").await;
    assert!(adieu.contains("BYE") || adieu.contains("BAD"), "{adieu}");
}

/// **`DELETE` traverse la socket**, et une boîte effacée qui avait des filles
/// garde son nom, marqué `\Noselect`.
#[tokio::test]
async fn un_effacement_traverse_la_socket() {
    let Some(materiel) = materiel("imap-delete") else {
        return;
    };
    let mut lecteur = authentifiee(&materiel).await;
    lecteur
        .get_mut()
        .write_all(b"a003 LIST \"\" *\r\n")
        .await
        .expect("écriture");
    let liste = jusqu_a(&mut lecteur, "a003 ").await;
    assert!(
        liste.contains("* LIST (\\Noselect) \"/\" \"Videe\"\r\n"),
        "{liste}"
    );

    lecteur
        .get_mut()
        .write_all(b"a004 DELETE Brouillons\r\n")
        .await
        .expect("écriture");
    let efface = jusqu_a(&mut lecteur, "a004 ").await;
    assert_eq!(efface, "a004 OK DELETE completed\r\n");

    lecteur
        .get_mut()
        .write_all(b"a005 DELETE INBOX\r\n")
        .await
        .expect("écriture");
    let refus = jusqu_a(&mut lecteur, "a005 ").await;
    assert!(refus.starts_with("a005 NO [CANNOT]"), "{refus}");
}

/// **`RENAME` traverse la socket**, et ses deux refus se distinguent.
#[tokio::test]
async fn un_renommage_traverse_la_socket() {
    let Some(materiel) = materiel("imap-rename") else {
        return;
    };
    let mut lecteur = authentifiee(&materiel).await;
    lecteur
        .get_mut()
        .write_all(b"a003 RENAME Brouillons Anciens\r\n")
        .await
        .expect("écriture");
    let renomme = jusqu_a(&mut lecteur, "a003 ").await;
    assert_eq!(renomme, "a003 OK RENAME completed\r\n");

    lecteur
        .get_mut()
        .write_all(b"a004 RENAME Inconnue Autre\r\n")
        .await
        .expect("écriture");
    let absente = jusqu_a(&mut lecteur, "a004 ").await;
    assert!(absente.starts_with("a004 NO [NONEXISTENT]"), "{absente}");

    lecteur
        .get_mut()
        .write_all(b"a005 RENAME Brouillons INBOX\r\n")
        .await
        .expect("écriture");
    let prise = jusqu_a(&mut lecteur, "a005 ").await;
    assert!(prise.starts_with("a005 NO [ALREADYEXISTS]"), "{prise}");
}

/// **L'enveloppe traverse la socket**, composée du vrai en-tête du message.
#[tokio::test]
async fn une_enveloppe_traverse_la_socket() {
    let Some(materiel) = materiel("imap-envelope") else {
        return;
    };
    let mut lecteur = authentifiee(&materiel).await;
    lecteur
        .get_mut()
        .write_all(b"a003 SELECT INBOX\r\n")
        .await
        .expect("écriture");
    jusqu_a(&mut lecteur, "a003 ").await;

    lecteur
        .get_mut()
        .write_all(b"a004 FETCH 1 (ENVELOPE UID)\r\n")
        .await
        .expect("écriture");
    let enveloppe = jusqu_a(&mut lecteur, "a004 ").await;
    assert_eq!(
        enveloppe,
        "* 1 FETCH (ENVELOPE (NIL \"un\" ((NIL NIL \"a\" \"x.test\")) \
         ((NIL NIL \"a\" \"x.test\")) ((NIL NIL \"a\" \"x.test\")) NIL NIL NIL NIL NIL) \
         UID 1)\r\na004 OK FETCH completed\r\n",
        "{enveloppe}"
    );
}

/// **La structure traverse la socket**, composée par `ams-mime` et écoulée par
/// la boucle comme n'importe quelle réponse.
#[tokio::test]
async fn une_structure_traverse_la_socket() {
    let Some(materiel) = materiel("imap-structure") else {
        return;
    };
    let mut lecteur = authentifiee(&materiel).await;
    lecteur
        .get_mut()
        .write_all(b"a003 SELECT INBOX\r\n")
        .await
        .expect("écriture");
    jusqu_a(&mut lecteur, "a003 ").await;

    lecteur
        .get_mut()
        .write_all(b"a004 FETCH 1 (BODYSTRUCTURE UID)\r\n")
        .await
        .expect("écriture");
    let structure = jusqu_a(&mut lecteur, "a004 ").await;
    assert_eq!(
        structure,
        "* 1 FETCH (BODYSTRUCTURE (\"TEXT\" \"PLAIN\" (\"CHARSET\" \"us-ascii\") \
         NIL NIL \"7BIT\" 16 1 NIL NIL NIL NIL) UID 1)\r\na004 OK FETCH completed\r\n",
        "{structure}"
    );
}

/// **Une partie désignée traverse la socket**, et une partie absente vaut `NIL`.
#[tokio::test]
async fn une_partie_designee_traverse_la_socket() {
    let Some(materiel) = materiel("imap-partie") else {
        return;
    };
    let mut lecteur = authentifiee(&materiel).await;
    lecteur
        .get_mut()
        .write_all(b"a003 SELECT INBOX\r\n")
        .await
        .expect("écriture");
    jusqu_a(&mut lecteur, "a003 ").await;

    lecteur
        .get_mut()
        .write_all(b"a004 FETCH 1 BODY.PEEK[1]\r\n")
        .await
        .expect("écriture");
    let partie = jusqu_a(&mut lecteur, "a004 ").await;
    assert_eq!(
        partie, "* 1 FETCH (BODY[1] {16}\r\nPremier corps.\r\n)\r\na004 OK FETCH completed\r\n",
        "{partie}"
    );

    // Les lignes d'en-tête MIME de la même partie.
    lecteur
        .get_mut()
        .write_all(b"a005 FETCH 1 BODY.PEEK[1.MIME]\r\n")
        .await
        .expect("écriture");
    let mime = jusqu_a(&mut lecteur, "a005 ").await;
    assert!(mime.contains("BODY[1.MIME] {31}"), "{mime}");
    assert!(mime.contains("Subject: un"), "{mime}");

    // Et une partie qui n'existe pas : `NIL`, pas une erreur.
    lecteur
        .get_mut()
        .write_all(b"a006 FETCH 1 (BODY.PEEK[4] UID)\r\n")
        .await
        .expect("écriture");
    let absente = jusqu_a(&mut lecteur, "a006 ").await;
    assert_eq!(
        absente, "* 1 FETCH (BODY[4] NIL UID 1)\r\na006 OK FETCH completed\r\n",
        "{absente}"
    );
}

/// **Un choix de champs traverse la socket**, et la réponse échoit les noms.
#[tokio::test]
async fn un_choix_de_champs_traverse_la_socket() {
    let Some(materiel) = materiel("imap-choix") else {
        return;
    };
    let mut lecteur = authentifiee(&materiel).await;
    lecteur
        .get_mut()
        .write_all(b"a003 SELECT INBOX\r\n")
        .await
        .expect("écriture");
    jusqu_a(&mut lecteur, "a003 ").await;

    lecteur
        .get_mut()
        .write_all(b"a004 FETCH 1 BODY.PEEK[HEADER.FIELDS (Subject)]\r\n")
        .await
        .expect("écriture");
    let choix = jusqu_a(&mut lecteur, "a004 ").await;
    assert_eq!(
        choix,
        "* 1 FETCH (BODY[HEADER.FIELDS (Subject)] {15}\r\nSubject: un\r\n\r\n)\r\n\
         a004 OK FETCH completed\r\n",
        "{choix}"
    );

    // Et son inverse rend tout le reste.
    lecteur
        .get_mut()
        .write_all(b"a005 FETCH 1 BODY.PEEK[HEADER.FIELDS.NOT (Subject)]\r\n")
        .await
        .expect("écriture");
    let sauf = jusqu_a(&mut lecteur, "a005 ").await;
    assert!(sauf.contains("From: a@x.test"), "{sauf}");
    assert!(!sauf.contains("Subject: un"), "{sauf}");
}
