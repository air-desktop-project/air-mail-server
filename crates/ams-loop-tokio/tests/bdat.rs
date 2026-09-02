// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **`BDAT` et `CHUNKING` (RFC 3030), câblés dans la boucle SMTP.**
//!
//! # Ce que ces essais prouvent, et que les unitaires ne peuvent pas
//!
//! Que la boucle lit EXACTEMENT les octets annoncés, et pas un de plus : la
//! commande qui suit un morceau doit être lue comme une commande. C'est la
//! propriété qui remplace, pour `BDAT`, la recherche de `<CRLF>.<CRLF>` — et
//! c'est celle qu'un essai unitaire de la session ne peut pas voir, puisqu'il
//! ne tient pas la socket.

mod commun;

use ams_guard::Thresholds;
use ams_loop_tokio::{Delivery, DeliveryFailure, Service, SharedGuard, Timeouts, serve_connection};
use ams_proto_smtp::Limits;
use ams_session::Config;
use commun::{NotreDomaine, PAIR};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// Une remise qui retient ce qu'on lui a donné.
#[derive(Default)]
struct Temoin {
    corps: Arc<std::sync::Mutex<std::vec::Vec<u8>>>,
    messages: Arc<std::sync::Mutex<usize>>,
}

impl Delivery for Temoin {
    fn add_recipient(&mut self, _address: &[u8]) -> Result<(), DeliveryFailure> {
        Ok(())
    }
    fn append(&mut self, chunk: &[u8]) -> Result<(), DeliveryFailure> {
        if let Ok(mut corps) = self.corps.lock() {
            corps.extend_from_slice(chunk);
        }
        Ok(())
    }
    fn finish(&mut self) -> Result<(), DeliveryFailure> {
        if let Ok(mut combien) = self.messages.lock() {
            *combien = combien.saturating_add(1);
        }
        Ok(())
    }
    fn abort(&mut self) {}
}

/// Joue une session complète, et rend les réponses et ce qui a été remis.
async fn session(envoi: &[u8]) -> (std::string::String, std::vec::Vec<u8>, usize) {
    let corps = Arc::new(std::sync::Mutex::new(std::vec::Vec::new()));
    let messages = Arc::new(std::sync::Mutex::new(0_usize));
    let ecouteur = TcpListener::bind("127.0.0.1:0").await.expect("écoute");
    let adresse = ecouteur.local_addr().expect("adresse");

    let (pour_le_corps, pour_les_messages) = (Arc::clone(&corps), Arc::clone(&messages));
    let serveur = tokio::spawn(async move {
        let (mut flux, _) = ecouteur.accept().await.expect("connexion");
        let garde = SharedGuard::new(4, Thresholds::DEFAULT);
        let service = Service {
            config: Config::new(b"mail.example.com", 100, 1_048_576, Limits::DEFAULT)
                .expect("configurable"),
            guard: &garde,
            timeouts: Timeouts::default(),
            tls: None,
            spf: None,
            dkim: None,
            dmarc: None,
            reports: None,
        };
        let mut temoin = Temoin {
            corps: pour_le_corps,
            messages: pour_les_messages,
        };
        serve_connection(&mut flux, &service, NotreDomaine, &mut temoin, PAIR).await
    });

    let flux = TcpStream::connect(adresse).await.expect("connexion");
    let mut lecteur = BufReader::new(flux);
    let mut ligne = std::string::String::new();
    lecteur.read_line(&mut ligne).await.expect("bannière");
    lecteur.get_mut().write_all(envoi).await.expect("envoi");
    lecteur.get_mut().shutdown().await.ok();

    let mut dit = std::string::String::new();
    while lecteur.read_line(&mut ligne).await.unwrap_or(0) > 0 {
        dit.push_str(&ligne);
        ligne.clear();
    }
    let _ = serveur.await.expect("tâche");
    let remis = corps.lock().map(|vu| vu.clone()).unwrap_or_default();
    let combien = messages.lock().map(|vu| *vu).unwrap_or_default();
    (dit, remis, combien)
}

/// Le début d'une transaction acceptée.
const OUVERTURE: &[u8] = b"EHLO client.example.net\r\n\
                           MAIL FROM:<joe@example.net>\r\n\
                           RCPT TO:<marie@example.com>\r\n";

// ── L'ANNONCE ───────────────────────────────────────────────────────────────

/// **ON ANNONCE CE QU'ON TIENT.** Un service servi sans être annoncé est un
/// service que personne n'emploie.
#[tokio::test]
async fn l_ehlo_annonce_chunking() {
    let (dit, _, _) = session(b"EHLO client.example.net\r\nQUIT\r\n").await;
    assert!(dit.contains("CHUNKING"), "{dit}");
}

// ── UN MESSAGE QUI ARRIVE PAR MORCEAUX ──────────────────────────────────────

/// **CE QUI EST COMPTÉ ARRIVE ENTIER, ET DANS L'ORDRE.**
#[tokio::test]
async fn un_message_en_deux_morceaux_arrive_entier() {
    let mut envoi = std::vec::Vec::from(OUVERTURE);
    envoi.extend_from_slice(b"BDAT 23\r\nFrom: joe\r\nSubject: x\r\n");
    envoi.extend_from_slice(b"BDAT 11 LAST\r\n\r\nbonjour\r\n");
    envoi.extend_from_slice(b"QUIT\r\n");
    let (dit, remis, combien) = session(&envoi).await;

    assert!(
        dit.contains("250 2.0.0 Chunk ok"),
        "le premier morceau : {dit}"
    );
    assert!(
        dit.contains("250 2.0.0 Message accepted"),
        "le dernier : {dit}"
    );
    assert_eq!(combien, 1);
    assert!(
        remis.ends_with(b"From: joe\r\nSubject: x\r\n\r\nbonjour\r\n"),
        "{}",
        std::string::String::from_utf8_lossy(&remis)
    );
}

/// **`BDAT 0 LAST` TERMINE UN MESSAGE DÉJÀ ARRIVÉ** — c'est l'idiome de §2.
#[tokio::test]
async fn un_dernier_morceau_vide_conclut() {
    let mut envoi = std::vec::Vec::from(OUVERTURE);
    envoi.extend_from_slice(b"BDAT 13\r\nFrom: joe\r\n\r\n");
    envoi.extend_from_slice(b"BDAT 0 LAST\r\n");
    envoi.extend_from_slice(b"QUIT\r\n");
    let (dit, remis, combien) = session(&envoi).await;

    assert!(dit.contains("250 2.0.0 Message accepted"), "{dit}");
    assert_eq!(combien, 1);
    assert!(remis.ends_with(b"From: joe\r\n\r\n"));
}

/// **CE QUI SUIT LE MORCEAU EST UNE COMMANDE**, et non des données.
///
/// C'est la propriété qui remplace, pour `BDAT`, la recherche d'un délimiteur :
/// lire un octet de trop ferait passer le début d'une commande pour du message,
/// et lire un de moins ferait passer la queue du message pour des commandes.
#[tokio::test]
async fn la_commande_qui_suit_un_morceau_est_lue_comme_une_commande() {
    let mut envoi = std::vec::Vec::from(OUVERTURE);
    // Le morceau contient LITTÉRALEMENT une ligne de commande. Si la boucle
    // cherchait un délimiteur au lieu de compter, elle la servirait.
    envoi.extend_from_slice(b"BDAT 23\r\nRSET\r\nMAIL FROM:<x@y>\r\n");
    envoi.extend_from_slice(b"BDAT 0 LAST\r\nQUIT\r\n");
    let (dit, remis, combien) = session(&envoi).await;

    assert_eq!(combien, 1, "le message a été remis : {dit}");
    assert!(
        remis.ends_with(b"RSET\r\nMAIL FROM:<x@y>\r\n"),
        "les octets du morceau ont été servis comme des commandes : {}",
        std::string::String::from_utf8_lossy(&remis)
    );
    assert!(
        !dit.contains("250 2.0.0 Reset ok"),
        "un RSET a été servi : {dit}"
    );
}

// ── ET CE QUI EST REFUSÉ ────────────────────────────────────────────────────

/// **UN `LF` NU EST REFUSÉ, COMME EN PHASE `DATA`.** Ce qu'on dépose repart un
/// jour chez un voisin qui coupe sur `<CRLF>.<CRLF>`.
#[tokio::test]
async fn un_lf_nu_dans_un_morceau_est_refuse() {
    let mut envoi = std::vec::Vec::from(OUVERTURE);
    envoi.extend_from_slice(b"BDAT 12 LAST\r\nFrom: joe\n\r\n");
    envoi.extend_from_slice(b"QUIT\r\n");
    let (dit, _, combien) = session(&envoi).await;

    assert!(dit.contains("554"), "{dit}");
    assert!(dit.contains("Bare CR or LF"), "{dit}");
    assert_eq!(combien, 0, "rien n'a été remis");
}

/// **`BDAT` ET `DATA` SE DISPUTENT LE MÊME MESSAGE** : le second est une faute
/// de séquence, et non de syntaxe.
#[tokio::test]
async fn un_data_apres_un_bdat_est_refuse_par_503() {
    let mut envoi = std::vec::Vec::from(OUVERTURE);
    envoi.extend_from_slice(b"BDAT 5\r\nsalut");
    envoi.extend_from_slice(b"DATA\r\n");
    envoi.extend_from_slice(b"QUIT\r\n");
    let (dit, _, combien) = session(&envoi).await;

    assert!(dit.contains("503"), "{dit}");
    assert!(dit.contains("BDAT already started"), "{dit}");
    assert_eq!(combien, 0);
}

/// **SANS DESTINATAIRE, RIEN N'EST LU.** Un morceau accepté sans `RCPT` ferait
/// lire des octets pour personne.
#[tokio::test]
async fn un_bdat_sans_rcpt_est_refuse() {
    let envoi = b"EHLO client.example.net\r\nMAIL FROM:<joe@example.net>\r\nBDAT 5\r\nQUIT\r\n";
    let (dit, _, combien) = session(envoi).await;

    assert!(dit.contains("503"), "{dit}");
    assert_eq!(combien, 0);
}

/// **UNE TAILLE QUI DÉPASSE LA BORNE EST REFUSÉE AVANT D'ÊTRE LUE** : elle est
/// annoncée, et lire un mébioctet qu'on jettera ne sert personne.
#[tokio::test]
async fn un_morceau_plus_grand_que_le_message_permis_est_refuse() {
    let mut envoi = std::vec::Vec::from(OUVERTURE);
    envoi.extend_from_slice(b"BDAT 99999999 LAST\r\n");
    envoi.extend_from_slice(b"QUIT\r\n");
    let (dit, _, combien) = session(&envoi).await;

    assert!(dit.contains("552"), "{dit}");
    assert_eq!(combien, 0);
}

/// **UN ARGUMENT MAL FORMÉ N'EST PAS UNE TAILLE DE ZÉRO.**
#[tokio::test]
async fn un_bdat_mal_forme_est_une_erreur_de_syntaxe() {
    let mut envoi = std::vec::Vec::from(OUVERTURE);
    envoi.extend_from_slice(b"BDAT abc\r\nQUIT\r\n");
    let (dit, _, combien) = session(&envoi).await;

    assert!(dit.contains("500") || dit.contains("501"), "{dit}");
    assert_eq!(combien, 0);
}
