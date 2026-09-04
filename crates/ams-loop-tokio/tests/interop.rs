// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Ce qu'un VRAI serveur de courrier envoie, rejoué octet pour octet.**
//!
//! # Pourquoi cet essai existe
//!
//! Deux défauts graves de ce serveur n'ont été trouvés qu'en installant Postfix
//! et en lui parlant. Aucune barrière ne pouvait les voir : ils ne vivaient pas
//! dans une fonction, mais dans des combinaisons qu'aucun essai n'avait formées,
//! et qu'un pair réel forme sans y penser.
//!
//! Le plus coûteux : `ORCPT=` (§4.2 de RFC 3461) sur un destinataire SUIVI d'un
//! autre faisait refuser la transaction entière. Postfix envoie `ORCPT` dès
//! qu'on annonce `DSN` — c'est-à-dire toujours —, si bien que TOUT message d'un
//! MTA conforme à deux destinataires ou plus était perdu.
//!
//! # Ce que cet essai rejoue
//!
//! La conversation capturée d'un Postfix 3.x remettant un message à deux
//! destinataires : `EHLO`, puis `MAIL`, deux `RCPT` et `DATA` **pipelinés** en
//! un seul envoi, avec `SIZE=` sur l'enveloppe et `ORCPT=` sur chaque
//! destinataire. Il ne demande pas que Postfix soit installé : ce sont ses
//! octets, figés.
//!
//! **On vérifie les ADRESSES QUE LA REMISE REÇOIT**, et non seulement le code de
//! retour : c'est là que le défaut se voyait — la seconde arrivait avec l'`ORCPT`
//! de la première collé devant.

mod commun;

use ams_guard::Thresholds;
use ams_loop_tokio::{Delivery, DeliveryFailure, Service, SharedGuard, Timeouts, serve_connection};
use ams_proto_smtp::Limits;
use ams_session::{Capabilities, Config};
use commun::{NotreDomaine, PAIR};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// Une remise qui retient les adresses telles qu'elle les reçoit.
#[derive(Default)]
struct Temoin {
    destinataires: Arc<std::sync::Mutex<std::vec::Vec<std::vec::Vec<u8>>>>,
}

impl Delivery for Temoin {
    fn add_recipient(&mut self, address: &[u8]) -> Result<(), DeliveryFailure> {
        if let Ok(mut vus) = self.destinataires.lock() {
            vus.push(address.to_vec());
        }
        Ok(())
    }
    fn append(&mut self, _chunk: &[u8]) -> Result<(), DeliveryFailure> {
        Ok(())
    }
    fn finish(&mut self) -> Result<(), DeliveryFailure> {
        Ok(())
    }
    fn abort(&mut self) {}
}

/// Joue ces octets, et rend les réponses et les adresses que la remise a vues.
async fn session(envoi: &[u8]) -> (std::string::String, std::vec::Vec<std::vec::Vec<u8>>) {
    let destinataires = Arc::new(std::sync::Mutex::new(std::vec::Vec::new()));
    let ecouteur = TcpListener::bind("127.0.0.1:0").await.expect("écoute");
    let adresse = ecouteur.local_addr().expect("adresse");

    let pour_le_temoin = Arc::clone(&destinataires);
    let serveur = tokio::spawn(async move {
        let (mut flux, _) = ecouteur.accept().await.expect("connexion");
        let garde = SharedGuard::new(4, Thresholds::DEFAULT);
        let service = Service {
            // **`DSN` EST ANNONCÉ**, comme sur le vrai serveur : c'est ce qui
            // fait qu'un pair conforme envoie `ORCPT=`, et donc ce qui rend cet
            // essai fidèle.
            config: Config::new(b"mail.example.com", 100, 1_048_576, Limits::DEFAULT)
                .expect("configurable")
                .with_capabilities(Capabilities {
                    starttls: false,
                    auth: false,
                    dsn: true,
                }),
            guard: &garde,
            timeouts: Timeouts::default(),
            tls: None,
            spf: None,
            dkim: None,
            dmarc: None,
            reports: None,
        };
        let mut temoin = Temoin {
            destinataires: pour_le_temoin,
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
    let _ = serveur.await;
    let vus = destinataires.lock().map(|v| v.clone()).unwrap_or_default();
    (dit, vus)
}

/// **LA CONVERSATION D'UN VRAI MTA, À DEUX DESTINATAIRES.**
///
/// Capturée d'un Postfix remettant chez nous. Tout ce qui suit l'`EHLO` part
/// d'un seul tenant : c'est le pipelining de RFC 2920, et Postfix l'emploie
/// toujours quand on l'annonce.
#[tokio::test]
async fn la_conversation_d_un_vrai_mta_est_servie() {
    let (dit, vus) = session(
        b"EHLO speedy.home\r\n\
          MAIL FROM:<tester@essai.local> SIZE=380\r\n\
          RCPT TO:<jean@example.com> ORCPT=rfc822;jean@example.com\r\n\
          RCPT TO:<marie@example.com> ORCPT=rfc822;marie@example.com\r\n\
          DATA\r\n\
          From: tester@essai.local\r\n\
          To: jean@example.com,marie@example.com\r\n\
          Subject: interop\r\n\
          \r\n\
          Deux.\r\n\
          .\r\n\
          QUIT\r\n",
    )
    .await;

    assert!(
        dit.contains("250 2.0.0 Message accepted"),
        "le message d'un vrai MTA est accepté : {dit}"
    );

    // **C'EST ICI QUE LE DÉFAUT SE VOYAIT.** La seconde adresse arrivait avec
    // l'`ORCPT` de la première collé devant, ne routait plus vers personne, et
    // la transaction entière finissait refusée par `554`.
    assert_eq!(
        vus,
        std::vec![
            std::vec::Vec::from(&b"jean@example.com"[..]),
            std::vec::Vec::from(&b"marie@example.com"[..]),
        ],
        "la remise reçoit les deux adresses, et rien d'autre"
    );
}

/// **ET L'`ORCPT` NE DOIT PAS DÉTEINDRE SUR CE QUI SUIT**, quel que soit le rang
/// où il se trouve. Trois destinataires, l'`ORCPT` sur le premier et le dernier.
#[tokio::test]
async fn un_orcpt_ne_deteint_sur_aucun_voisin() {
    let (dit, vus) = session(
        b"EHLO speedy.home\r\n\
          MAIL FROM:<tester@essai.local>\r\n\
          RCPT TO:<jean@example.com> ORCPT=rfc822;origine@ailleurs.test\r\n\
          RCPT TO:<marie@example.com>\r\n\
          RCPT TO:<paul@example.com> ORCPT=rfc822;autre@ailleurs.test\r\n\
          DATA\r\n\
          From: tester@essai.local\r\n\
          Subject: trois\r\n\
          \r\n\
          Trois.\r\n\
          .\r\n\
          QUIT\r\n",
    )
    .await;

    assert!(dit.contains("250 2.0.0 Message accepted"), "{dit}");
    assert_eq!(
        vus,
        std::vec![
            std::vec::Vec::from(&b"jean@example.com"[..]),
            std::vec::Vec::from(&b"marie@example.com"[..]),
            std::vec::Vec::from(&b"paul@example.com"[..]),
        ],
        "les trois adresses arrivent entières"
    );
}
