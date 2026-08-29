// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **SPF, câblé dans la boucle SMTP** (C9).
//!
//! # Ce que ces épreuves ajoutent aux autres
//!
//! L'évaluation est couverte à 100 % chez elle, et la résolution est éprouvée
//! sur un vrai résolveur dans `ams-loop-tokio`. Ce qui ne l'est nulle part
//! ailleurs, c'est la **jonction** : que la session rende la main sans répondre,
//! que la boucle résolve, et que la réponse au `MAIL FROM:` soit celle du
//! verdict — un `550` qui refuse, un `451` qui ajourne, un `250` qui laisse
//! passer.
//!
//! C'est aussi le seul endroit où l'on voit que **la transaction est bien
//! abandonnée** après un refus : un `RCPT TO:` qui suivrait un `MAIL FROM:`
//! refusé ne doit pas être accepté.

mod commun;

use ams_guard::Thresholds;
use ams_loop_tokio::{Delivery, DeliveryFailure};
use ams_loop_tokio::{SenderChecker, Service, SharedGuard, Timeouts, serve_connection};
use ams_proto_smtp::Limits;
use ams_session::{Config, SenderPolicy};
use commun::{Neant, NotreDomaine, PAIR, nulle_part, resolveur_txt};
use core::time::Duration;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, TcpStream};

fn config(politique: SenderPolicy) -> Config<'static> {
    Config::new(b"mail.example.com", 100, 10_485_760, Limits::DEFAULT)
        .expect("configurable")
        .with_sender_policy(politique)
}

/// Joue un dialogue en clair contre la boucle, et rend les réponses lues.
async fn dialogue(
    politique: SenderPolicy,
    resolveur: Option<SocketAddr>,
    delai: Duration,
    lignes: &[&str],
) -> Vec<String> {
    let ecouteur = TcpListener::bind("127.0.0.1:0").await.expect("écoute");
    let adresse = ecouteur.local_addr().expect("adresse");
    let spf = resolveur
        .map(|serveur| SenderChecker::new(std::vec![serveur], delai).expect("vérificateur"));

    let serveur = tokio::spawn(async move {
        let (mut flux, _) = ecouteur.accept().await.expect("connexion");
        let garde = SharedGuard::new(4, Thresholds::DEFAULT);
        let service = Service {
            config: config(politique),
            guard: &garde,
            timeouts: Timeouts::default(),
            tls: None,
            spf,
            dkim: None,
            dmarc: None,
            reports: None,
        };
        serve_connection(&mut flux, &service, NotreDomaine, &mut Neant, PAIR).await
    });

    let flux = TcpStream::connect(adresse).await.expect("connexion");
    let mut lecteur = BufReader::new(flux);
    let mut lues = Vec::new();
    let mut ligne = String::new();
    // La bannière.
    lecteur.read_line(&mut ligne).await.expect("bannière");
    lues.push(core::mem::take(&mut ligne));

    for commande in lignes {
        let ecrit = std::format!("{commande}\r\n");
        lecteur
            .get_mut()
            .write_all(ecrit.as_bytes())
            .await
            .expect("écriture");
        loop {
            ligne.clear();
            let lus = lecteur.read_line(&mut ligne).await.expect("réponse");
            if lus == 0 {
                break;
            }
            let derniere = ligne.as_bytes().get(3) != Some(&b'-');
            lues.push(core::mem::take(&mut ligne));
            if derniere {
                break;
            }
        }
    }
    // ON FERME AVANT D'ATTENDRE. La boucle sert tant que le pair parle : sans
    // cette fermeture, le test attendrait le délai de commande — c'est-à-dire
    // qu'il attendrait cinq minutes pour prouver qu'il a fini.
    drop(lecteur);
    let _ = serveur.await;
    lues
}

/// La réponse au `MAIL FROM:`, quel que soit le nombre de lignes d'`EHLO`.
fn reponse_au_mail(lues: &[String]) -> &str {
    lues.iter()
        .rev()
        .find(|ligne| !ligne.starts_with("250-"))
        .map_or("", |ligne| ligne.as_str())
}

#[tokio::test]
async fn un_expediteur_refuse_par_sa_propre_politique_est_refuse() {
    // Le domaine dit lui-même que cette adresse n'a pas le droit d'émettre pour
    // lui. C'est le SEUL verdict qui refuse.
    let resolveur = resolveur_txt("v=spf1 ip4:203.0.113.0/24 -all").await;
    let lues = dialogue(
        SenderPolicy::Enforce,
        Some(resolveur),
        Duration::from_secs(2),
        &["EHLO client.example.net", "MAIL FROM:<jean@example.com>"],
    )
    .await;
    let reponse = reponse_au_mail(&lues);
    assert!(reponse.starts_with("550 5.7.23"), "{reponse}");
}

#[tokio::test]
async fn un_refus_abandonne_la_transaction() {
    // Sans cela, un pair refusé au `MAIL FROM:` enchaînerait ses destinataires
    // comme si de rien n'était.
    let resolveur = resolveur_txt("v=spf1 -all").await;
    let lues = dialogue(
        SenderPolicy::Enforce,
        Some(resolveur),
        Duration::from_secs(2),
        &[
            "EHLO client.example.net",
            "MAIL FROM:<jean@example.com>",
            "RCPT TO:<marie@example.com>",
        ],
    )
    .await;
    let derniere = lues.last().map_or("", |ligne| ligne.as_str());
    assert!(derniere.starts_with("503"), "{derniere}");
}

#[tokio::test]
async fn un_expediteur_autorise_passe() {
    let resolveur = resolveur_txt("v=spf1 ip4:127.0.0.0/8 -all").await;
    let lues = dialogue(
        SenderPolicy::Enforce,
        Some(resolveur),
        Duration::from_secs(2),
        &["EHLO client.example.net", "MAIL FROM:<jean@example.com>"],
    )
    .await;
    let reponse = reponse_au_mail(&lues);
    assert!(reponse.starts_with("250"), "{reponse}");
}

#[tokio::test]
async fn en_observation_rien_n_est_oppose() {
    // C'est l'état où l'on découvre ce qu'une politique refuserait AVANT de la
    // laisser refuser.
    let resolveur = resolveur_txt("v=spf1 -all").await;
    let lues = dialogue(
        SenderPolicy::Observe,
        Some(resolveur),
        Duration::from_secs(2),
        &["EHLO client.example.net", "MAIL FROM:<jean@example.com>"],
    )
    .await;
    let reponse = reponse_au_mail(&lues);
    assert!(reponse.starts_with("250"), "{reponse}");
}

#[tokio::test]
async fn une_resolution_qui_n_aboutit_pas_ajourne() {
    // 451, JAMAIS 550 : un message ajourné revient, un message refusé est
    // perdu. Le résolveur n'écoute pas, et le délai est court.
    let lues = dialogue(
        SenderPolicy::Enforce,
        Some(nulle_part()),
        Duration::from_millis(200),
        &["EHLO client.example.net", "MAIL FROM:<jean@example.com>"],
    )
    .await;
    let reponse = reponse_au_mail(&lues);
    assert!(reponse.starts_with("451 4.4.3"), "{reponse}");
}

#[tokio::test]
async fn sans_politique_d_expediteur_aucune_question_n_est_posee() {
    // Le résolveur est injoignable et le délai serait long : si une question
    // partait, ce test durerait. Il ne dure pas.
    let lues = dialogue(
        SenderPolicy::Ignore,
        None,
        Duration::from_secs(30),
        &["EHLO client.example.net", "MAIL FROM:<jean@example.com>"],
    )
    .await;
    let reponse = reponse_au_mail(&lues);
    assert!(reponse.starts_with("250"), "{reponse}");
}

#[tokio::test]
async fn verifier_sans_verificateur_est_refuse_avant_la_banniere() {
    // La session réclamerait une vérification que personne ne conduit. On le dit
    // AVANT d'ouvrir la bouche, comme pour `STARTTLS` sans matériel TLS.
    let ecouteur = TcpListener::bind("127.0.0.1:0").await.expect("écoute");
    let adresse = ecouteur.local_addr().expect("adresse");
    let serveur = tokio::spawn(async move {
        let (mut flux, _) = ecouteur.accept().await.expect("connexion");
        let garde = SharedGuard::new(4, Thresholds::DEFAULT);
        let service = Service {
            config: config(SenderPolicy::Enforce),
            guard: &garde,
            timeouts: Timeouts::default(),
            tls: None,
            spf: None,
            dkim: None,
            dmarc: None,
            reports: None,
        };
        serve_connection(&mut flux, &service, NotreDomaine, &mut Neant, PAIR).await
    });
    let flux = TcpStream::connect(adresse).await.expect("connexion");
    let issue = serveur.await.expect("tâche");
    drop(flux);
    assert!(
        matches!(issue, Err(ams_loop_tokio::Error::CapabilityNotSupported)),
        "{issue:?}"
    );
}

// ── L'EN-TÊTE `Received-SPF` (RFC 7208 §9.1) ────────────────────────────────

/// Une remise qui garde ce qu'on lui donne.
#[derive(Clone, Default)]
struct Cahier(Arc<Mutex<Vec<u8>>>);

impl Delivery for Cahier {
    fn add_recipient(&mut self, _address: &[u8]) -> Result<(), DeliveryFailure> {
        Ok(())
    }
    fn append(&mut self, chunk: &[u8]) -> Result<(), DeliveryFailure> {
        self.0.lock().expect("verrou").extend_from_slice(chunk);
        Ok(())
    }
    fn finish(&mut self) -> Result<(), DeliveryFailure> {
        Ok(())
    }
    fn abort(&mut self) {
        self.0.lock().expect("verrou").clear();
    }
}

/// Joue une transaction complète, et rend le message tel qu'il a été REMIS.
async fn message_remis(
    politique: SenderPolicy,
    resolveur: Option<SocketAddr>,
    corps: &str,
) -> String {
    let ecouteur = TcpListener::bind("127.0.0.1:0").await.expect("écoute");
    let adresse = ecouteur.local_addr().expect("adresse");
    let spf = resolveur
        .map(|serveur| SenderChecker::new(std::vec![serveur], Duration::from_secs(2)).expect("v"));
    let cahier = Cahier::default();
    let copie = cahier.clone();

    let serveur = tokio::spawn(async move {
        let (mut flux, _) = ecouteur.accept().await.expect("connexion");
        let garde = SharedGuard::new(4, Thresholds::DEFAULT);
        let service = Service {
            config: config(politique),
            guard: &garde,
            timeouts: Timeouts::default(),
            tls: None,
            spf,
            dkim: None,
            dmarc: None,
            reports: None,
        };
        let mut remise = copie;
        serve_connection(&mut flux, &service, NotreDomaine, &mut remise, PAIR).await
    });

    let flux = TcpStream::connect(adresse).await.expect("connexion");
    let mut lecteur = BufReader::new(flux);
    let mut ligne = String::new();
    lecteur.read_line(&mut ligne).await.expect("bannière");
    for commande in [
        "EHLO client.example.net",
        "MAIL FROM:<jean@example.com>",
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
        .write_all(corps.as_bytes())
        .await
        .expect("corps");
    ligne.clear();
    lecteur.read_line(&mut ligne).await.expect("fin de données");
    assert!(
        ligne.starts_with("250"),
        "le message a été refusé : {ligne}"
    );
    drop(lecteur);
    let _ = serveur.await;
    let remis = cahier.0.lock().expect("verrou").clone();
    String::from_utf8(remis).expect("message ASCII")
}

#[tokio::test]
async fn le_message_remis_porte_l_en_tete_received_spf() {
    // UN VERDICT QU'ON N'ÉCRIT PAS NE SERT À RIEN : sans cet en-tête, ni le
    // lecteur, ni un filtre en aval, ni DMARC ne peuvent savoir ce qu'on a
    // vérifié.
    let resolveur = resolveur_txt("v=spf1 ip4:127.0.0.0/8 -all").await;
    let remis = message_remis(
        SenderPolicy::Enforce,
        Some(resolveur),
        "Subject: bonjour\r\n\r\nDeux lignes.\r\n.\r\n",
    )
    .await;

    // EN TÊTE, ET AVANT LES EN-TÊTES DU PAIR. Un en-tête de trace posé après se
    // retrouverait dans le corps, où personne ne le lit.
    let plat = remis.replace("\r\n ", " ");
    assert!(plat.starts_with("Received-SPF: pass "), "{plat}");
    assert!(plat.contains("client-ip=127.0.0.1"), "{plat}");
    assert!(
        plat.contains("envelope-from=\"jean@example.com\""),
        "{plat}"
    );
    assert!(plat.contains("identity=mailfrom"), "{plat}");
    // Et le message du pair est intact, derrière.
    assert!(
        remis.contains("Subject: bonjour\r\n\r\nDeux lignes.\r\n"),
        "{remis}"
    );
}

#[tokio::test]
async fn un_softfail_est_remis_avec_sa_trace() {
    // En observation, rien n'est opposé — mais TOUT est écrit. C'est l'état où
    // l'on découvre ce qu'une politique refuserait, et il ne sert à rien si le
    // message ne porte pas ce qu'on a conclu.
    let resolveur = resolveur_txt("v=spf1 ~all").await;
    let remis = message_remis(
        SenderPolicy::Observe,
        Some(resolveur),
        "Subject: bonjour\r\n\r\n.\r\n",
    )
    .await;
    let plat = remis.replace("\r\n ", " ");
    assert!(plat.starts_with("Received-SPF: softfail "), "{plat}");
}

#[tokio::test]
async fn sans_verification_aucune_trace_n_est_ecrite() {
    // Un en-tête qui dirait `none` sans qu'aucune résolution ait eu lieu
    // mentirait sur ce qu'on a fait.
    let remis = message_remis(SenderPolicy::Ignore, None, "Subject: bonjour\r\n\r\n.\r\n").await;
    assert!(!remis.contains("Received-SPF"), "{remis}");
    assert!(remis.starts_with("Subject: bonjour"), "{remis}");
}
