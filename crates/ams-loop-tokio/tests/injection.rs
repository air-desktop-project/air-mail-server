// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **L'INJECTION DE COMMANDES PAR `STARTTLS`**, et ce qui la ferme.
//!
//! # Le défaut, en une phrase
//!
//! Un pair envoie `STARTTLS\r\n` ET la commande suivante **dans le même
//! segment**. Le serveur répond `220`, conduit la poignée de main — et trouve
//! encore dans son tampon de lecture des octets arrivés EN CLAIR. S'il les
//! traite, il exécute sous chiffrement une commande que n'importe qui a pu
//! écrire sur le fil : c'est la faille d'injection de RFC 3207 §4.2, celle qui a
//! frappé plusieurs MTA en 2011 puis de nouveau en 2021.
//!
//! Le pipelining la rend banale plutôt qu'exotique : un client qui groupe ses
//! commandes envoie exactement cette forme-là.
//!
//! # ON REFUSE, PLUTÔT QUE DE JETER
//!
//! RFC 3207 §4.2 demande d'OUBLIER ce qui précède. Ce serveur va plus loin : il
//! refuse la connexion entière par un `421` (ou son équivalent), et compte une
//! trame invalide au garde.
//!
//! Jeter en silence suffirait à fermer la faille, mais laisserait une attaque
//! en cours passer pour un client bavard — et le garde n'en saurait rien. Un
//! client qui groupe ses commandes par-dessus la montée en chiffrement est
//! d'ailleurs fautif dans les trois protocoles : RFC 2920 §3.1, RFC 2595 §4 et
//! RFC 9051 §6.2.1 l'interdisent chacun.
//!
//! **LES TROIS BOUCLES DISENT LA MÊME CHOSE.** SMTP refusait déjà ; POP3 servait
//! la commande injectée, et IMAP la jetait en silence. Une règle de sûreté
//! écrite trois fois différemment est une règle qui finira par ne plus être la
//! même.

mod commun;

use ams_guard::Thresholds;
use ams_loop_tokio::pop3::{Mailboxes, Pop3Service, serve_pop3_connection};
use ams_loop_tokio::{Outcome, Service, SharedGuard, Timeouts, serve_connection};
use ams_session::pop3::Mailbox;
use commun::{Neant, NotreDomaine, PAIR, config, materiel};
use core::time::Duration;
use std::sync::Arc;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

/// Un magasin qui n'ouvre aucune boîte : ces essais ne relèvent rien.
struct SansBoite;

impl Mailboxes for SansBoite {
    type Open = AucuneBoite;

    fn open(&self, _user: &[u8]) -> Option<Self::Open> {
        None
    }
    fn commit(&self, _mailbox: Self::Open) -> usize {
        0
    }
    fn read(
        &self,
        _mailbox: &Self::Open,
        _message: ams_proto_pop3::MessageNumber,
        _offset: u64,
        _buffer: &mut [u8],
    ) -> std::io::Result<usize> {
        Ok(0)
    }
}

/// Elle n'existe que pour satisfaire le trait : rien ne l'ouvre.
struct AucuneBoite;

impl Mailbox for AucuneBoite {
    fn highest(&self) -> u32 {
        0
    }
    fn size(&self, _message: ams_proto_pop3::MessageNumber) -> Option<u64> {
        None
    }
    fn uid(&self, _message: ams_proto_pop3::MessageNumber) -> Option<u32> {
        None
    }
    fn mark_deleted(&mut self, _message: ams_proto_pop3::MessageNumber) -> bool {
        false
    }
    fn reset_deletions(&mut self) {}
}

/// Lit ce qui vient, ou rend une chaîne vide si rien ne vient à temps.
async fn ce_qui_vient<S>(flux: &mut S) -> String
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut tampon = [0_u8; 512];
    match tokio::time::timeout(Duration::from_millis(400), flux.read(&mut tampon)).await {
        Ok(Ok(lus)) => String::from_utf8_lossy(tampon.get(..lus).unwrap_or_default()).into_owned(),
        Ok(Err(_)) | Err(_) => String::new(),
    }
}

/// **CE QUI EST ARRIVÉ EN CLAIR NE S'EXÉCUTE PAS SOUS CHIFFREMENT** (SMTP).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_ne_sert_pas_ce_qui_a_ete_dit_avant_la_poignee_de_main() {
    let Some(materiel) = materiel("injection-smtp") else {
        return;
    };
    let ecouteur = TcpListener::bind("127.0.0.1:0").await.expect("écoute");
    let adresse = ecouteur.local_addr().expect("adresse");
    let tls = Arc::clone(&materiel.tls);

    let serveur = tokio::spawn(async move {
        let (mut flux, _) = ecouteur.accept().await.expect("connexion");
        let garde = SharedGuard::new(4, Thresholds::DEFAULT);
        let service = Service {
            config: config(true, false),
            guard: &garde,
            timeouts: Timeouts::default(),
            tls: Some(tls),
            spf: None,
            dkim: None,
            dmarc: None,
            reports: None,
        };
        serve_connection(&mut flux, &service, NotreDomaine, &mut Neant, PAIR).await
    });

    let mut flux = TcpStream::connect(adresse).await.expect("connexion");
    let _banniere = ce_qui_vient(&mut flux).await;
    // **TOUT DANS LE MÊME SEGMENT** : c'est exactement ce qu'un client qui
    // groupe ses commandes envoie, et c'est l'injection.
    flux.write_all(b"EHLO client.example\r\nSTARTTLS\r\nRSET\r\nNOOP\r\n")
        .await
        .expect("écriture");
    flux.flush().await.expect("vidage");
    // On lit le `250-…` de l'`EHLO`, puis ce que le serveur fait du `STARTTLS`.
    let mut clair = String::new();
    while !clair.contains("421 ") {
        let morceau = ce_qui_vient(&mut flux).await;
        if morceau.is_empty() {
            break;
        }
        clair.push_str(&morceau);
    }
    // **PAS DE `220`, ET PAS DE POIGNÉE DE MAIN** : la connexion est refusée.
    assert!(
        clair.contains("421 "),
        "l'injection n'a pas été refusée : {clair}"
    );
    assert!(
        !clair.contains("220 Ready to start TLS"),
        "le serveur a promis le chiffrement à un pair qui injectait : {clair}"
    );
    assert!(
        !clair.contains("250 Reset ok"),
        "le RSET injecté a été servi : {clair}"
    );
    drop(flux);

    let resume = serveur.await.expect("tâche").expect("servie");
    assert_eq!(resume.outcome, Outcome::Injected, "l'issue ne le dit pas");
}

/// **UN LOT DE COMMANDES ARRIVÉ EN UN SEUL SEGMENT EST SERVI EN ENTIER**
/// (RFC 2920), et dans l'ordre.
///
/// C'est ce que `PIPELINING` annonce, et l'annoncer sans le tenir serait pire
/// que de se taire : un client qui groupe attend autant de réponses que de
/// commandes, et une de moins le laisse pendu jusqu'au délai.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn un_lot_de_commandes_est_servi_en_entier_et_dans_l_ordre() {
    let ecouteur = TcpListener::bind("127.0.0.1:0").await.expect("écoute");
    let adresse = ecouteur.local_addr().expect("adresse");

    let serveur = tokio::spawn(async move {
        let (mut flux, _) = ecouteur.accept().await.expect("connexion");
        let garde = SharedGuard::new(4, Thresholds::DEFAULT);
        let service = Service {
            config: config(false, false),
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

    let mut flux = TcpStream::connect(adresse).await.expect("connexion");
    let banniere = ce_qui_vient(&mut flux).await;
    assert!(banniere.starts_with("220"), "bannière : {banniere:?}");
    // **UNE SEULE ÉCRITURE**, message compris : la transaction entière.
    flux.write_all(
        b"EHLO client.example\r\nMAIL FROM:<joe@example.net>\r\nRCPT TO:<marie@example.com>\r\nDATA\r\nFrom: joe\r\n\r\nbonjour\r\n.\r\nQUIT\r\n",
    )
    .await
    .expect("écriture");
    flux.flush().await.expect("vidage");

    // Le pair a tout dit : il ferme son côté, et lit jusqu'au bout.
    flux.shutdown().await.ok();
    let mut dit = String::new();
    let mut tampon = [0_u8; 1024];
    while let Ok(lus) = flux.read(&mut tampon).await {
        if lus == 0 {
            break;
        }
        dit.push_str(&String::from_utf8_lossy(
            tampon.get(..lus).unwrap_or_default(),
        ));
    }
    let resume = serveur.await.expect("tâche");
    // L'annonce, puis UNE réponse par commande, dans l'ordre.
    assert!(
        dit.contains("PIPELINING"),
        "réponses vues : {dit:?} ; le serveur a rendu {resume:?}"
    );
    for attendu in [
        "250 Sender ok",
        "250 Recipient ok",
        "354 ",
        "250 Message accepted",
        "221 Bye",
    ] {
        assert!(dit.contains(attendu), "« {attendu} » manque : {dit}");
    }
    // **ET DANS L'ORDRE** : le `354` précède l'acceptation, qui précède l'adieu.
    let rang = |quoi: &str| dit.find(quoi).unwrap_or(usize::MAX);
    assert!(rang("354 ") < rang("250 Message accepted"), "{dit}");
    assert!(rang("250 Message accepted") < rang("221 Bye"), "{dit}");

    let resume = resume.unwrap_or_else(|cause| panic!("le serveur a rendu {cause:?}"));
    assert_eq!(resume.messages, 1, "le message groupé n'est pas arrivé");
}

/// **UN MESSAGE QUI TOURNE EN BOUCLE FINIT PAR S'ARRÊTER** (RFC 5321 §6.3).
///
/// Deux serveurs mal réglés qui se renvoient un message le multiplient à chaque
/// tour, et chaque saut est licite. La seule méthode qui marche sans mémoire
/// partagée est de compter les traces — celles-là mêmes que §4.4 oblige à
/// poser — et de refuser au-delà d'un seuil large.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn un_message_qui_porte_trop_de_traces_est_refuse() {
    let ecouteur = TcpListener::bind("127.0.0.1:0").await.expect("écoute");
    let adresse = ecouteur.local_addr().expect("adresse");

    let serveur = tokio::spawn(async move {
        let (mut flux, _) = ecouteur.accept().await.expect("connexion");
        let garde = SharedGuard::new(4, Thresholds::DEFAULT);
        let service = Service {
            config: config(false, false),
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

    let mut flux = TcpStream::connect(adresse).await.expect("connexion");
    let _banniere = ce_qui_vient(&mut flux).await;
    let mut envoi = std::vec::Vec::from(
        &b"EHLO client.example\r\nMAIL FROM:<joe@example.net>\r\nRCPT TO:<marie@example.com>\r\nDATA\r\n"[..],
    );
    // Trente et une traces : une de plus que ce que §6.3 tolère ici. La nôtre
    // n'est pas encore posée — elle le serait à la remise, qui n'aura pas lieu.
    for rang in 0..31 {
        envoi.extend_from_slice(format!("Received: par le saut {rang}\r\n").as_bytes());
    }
    envoi.extend_from_slice(b"From: joe\r\n\r\nbonjour\r\n.\r\nQUIT\r\n");
    flux.write_all(&envoi).await.expect("écriture");
    flux.flush().await.expect("vidage");
    flux.shutdown().await.ok();

    let mut dit = String::new();
    let mut tampon = [0_u8; 1024];
    while let Ok(lus) = flux.read(&mut tampon).await {
        if lus == 0 {
            break;
        }
        dit.push_str(&String::from_utf8_lossy(
            tampon.get(..lus).unwrap_or_default(),
        ));
    }
    let resume = serveur.await.expect("tâche").expect("servie");

    assert!(dit.contains("554"), "la boucle n'a pas été arrêtée : {dit}");
    assert!(dit.contains("Too many hops"), "{dit}");
    assert_eq!(resume.messages, 0, "un message en boucle a été remis");
}

/// **TRENTE TRACES PASSENT ENCORE** : le seuil est large, et un message qui a
/// beaucoup voyagé n'est pas un message qui tourne.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn un_message_qui_a_beaucoup_voyage_passe_encore() {
    let ecouteur = TcpListener::bind("127.0.0.1:0").await.expect("écoute");
    let adresse = ecouteur.local_addr().expect("adresse");

    let serveur = tokio::spawn(async move {
        let (mut flux, _) = ecouteur.accept().await.expect("connexion");
        let garde = SharedGuard::new(4, Thresholds::DEFAULT);
        let service = Service {
            config: config(false, false),
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

    let mut flux = TcpStream::connect(adresse).await.expect("connexion");
    let _banniere = ce_qui_vient(&mut flux).await;
    let mut envoi = std::vec::Vec::from(
        &b"EHLO client.example\r\nMAIL FROM:<joe@example.net>\r\nRCPT TO:<marie@example.com>\r\nDATA\r\n"[..],
    );
    for rang in 0..30 {
        envoi.extend_from_slice(format!("Received: par le saut {rang}\r\n").as_bytes());
    }
    envoi.extend_from_slice(b"From: joe\r\n\r\nbonjour\r\n.\r\nQUIT\r\n");
    flux.write_all(&envoi).await.expect("écriture");
    flux.flush().await.expect("vidage");
    flux.shutdown().await.ok();

    let mut dit = String::new();
    let mut tampon = [0_u8; 1024];
    while let Ok(lus) = flux.read(&mut tampon).await {
        if lus == 0 {
            break;
        }
        dit.push_str(&String::from_utf8_lossy(
            tampon.get(..lus).unwrap_or_default(),
        ));
    }
    let resume = serveur.await.expect("tâche").expect("servie");

    assert!(dit.contains("250 Message accepted"), "{dit}");
    assert_eq!(resume.messages, 1);
}

/// **LA MÊME PROPRIÉTÉ, POUR POP3** (`STLS`, RFC 2595 §4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pop3_ne_sert_pas_ce_qui_a_ete_dit_avant_la_poignee_de_main() {
    let Some(materiel) = materiel("injection-pop3") else {
        return;
    };
    let ecouteur = TcpListener::bind("127.0.0.1:0").await.expect("écoute");
    let adresse = ecouteur.local_addr().expect("adresse");
    let tls = Arc::clone(&materiel.tls);

    let serveur = tokio::spawn(async move {
        let (mut flux, _) = ecouteur.accept().await.expect("connexion");
        let garde = SharedGuard::new(4, Thresholds::DEFAULT);
        let service = Pop3Service {
            limits: ams_proto_pop3::Limits::DEFAULT,
            guard: &garde,
            timeouts: Timeouts::default(),
            tls: Some(tls),
        };
        serve_pop3_connection(&mut flux, &service, NotreDomaine, &SansBoite, PAIR).await
    });

    let mut flux = TcpStream::connect(adresse).await.expect("connexion");
    let _banniere = ce_qui_vient(&mut flux).await;
    flux.write_all(b"STLS\r\nNOOP\r\n").await.expect("écriture");
    flux.flush().await.expect("vidage");
    let clair = ce_qui_vient(&mut flux).await;
    assert!(
        clair.starts_with("-ERR"),
        "l'injection n'a pas été refusée : {clair}"
    );
    drop(flux);

    let resume = serveur.await.expect("tâche").expect("servie");
    assert!(resume.injected, "l'issue ne dit pas l'injection");
    assert!(!resume.tls, "le chiffrement n'aurait pas dû être monté");
}
