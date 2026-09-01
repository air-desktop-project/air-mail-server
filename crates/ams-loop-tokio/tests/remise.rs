// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **La remise SORTANTE**, éprouvée contre notre propre serveur.
//!
//! # Deux moitiés du même protocole, mises face à face
//!
//! Le client et le serveur de ce dépôt ne partagent aucun code : l'un lit des
//! commandes et écrit des réponses, l'autre fait l'inverse. Les faire dialoguer
//! est donc un vrai test d'interopérabilité — et pas un aller-retour où une
//! erreur symétrique passerait inaperçue.
//!
//! Ce qui s'y vérifie et ne se vérifie nulle part ailleurs : que le
//! point-farcissage à l'émission et sa défaite à la réception se répondent, et
//! qu'un message contenant une ligne au seul point arrive **intact**.

mod commun;

use std::sync::{Arc, Mutex};

use ams_guard::Thresholds;
use ams_loop_tokio::{
    Delivery, DeliveryFailure, Outgoing, Relay, RelayOutcome, Resolver, Service, SharedGuard,
    Timeouts, serve_connection,
};
use ams_proto_smtp::Limits;
use ams_session::{Capabilities, Config};
use commun::{NotreDomaine, PAIR, materiel};
use core::time::Duration;
use tokio::net::TcpListener;

/// Une remise qui garde ce qu'elle reçoit.
#[derive(Clone, Default)]
struct Cahier(Arc<Mutex<std::vec::Vec<u8>>>);

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

/// Un remetteur branché sur un résolveur qui ne sert à rien : ces tests
/// s'adressent à une adresse connue, et n'ont donc rien à résoudre.
fn remetteur(exige_tls: bool) -> Relay {
    Relay::new(
        Resolver::new(
            std::vec!["127.0.0.1:1".parse().expect("adresse")],
            Duration::from_secs(1),
        )
        .expect("résolveur"),
        Arc::new(ams_tls::relay_config()),
        std::string::String::from("mail.nous.test"),
        exige_tls,
        Duration::from_secs(5),
    )
}

/// Monte notre propre serveur, et rend son adresse et le cahier qu'il remplit.
async fn serveur(chiffrement: Option<Arc<rustls::ServerConfig>>) -> (std::net::SocketAddr, Cahier) {
    let ecouteur = TcpListener::bind("127.0.0.1:0").await.expect("écoute");
    let adresse = ecouteur.local_addr().expect("adresse");
    let cahier = Cahier::default();
    let sien = cahier.clone();
    tokio::spawn(async move {
        let (mut flux, _) = ecouteur.accept().await.expect("connexion");
        let garde = SharedGuard::new(4, Thresholds::DEFAULT);
        let mut remise = sien;
        let service = Service {
            config: Config::new(b"mail.eux.test", 100, 10_485_760, Limits::DEFAULT)
                .expect("configurable")
                .with_capabilities(Capabilities {
                    starttls: chiffrement.is_some(),
                    auth: false,
                }),
            guard: &garde,
            timeouts: Timeouts::default(),
            tls: chiffrement,
            spf: None,
            dkim: None,
            dmarc: None,
            reports: None,
        };
        let _ = serve_connection(&mut flux, &service, NotreDomaine, &mut remise, PAIR).await;
    });
    (adresse, cahier)
}

/// Le message d'épreuve. **Il porte une ligne au seul point** : sans le
/// point-farcissage, il se terminerait tout seul au milieu.
const CORPS: &[u8] = b"From: nous@nous.test\r\n\
                       To: marie@example.com\r\n\
                       Subject: essai\r\n\
                       \r\n\
                       Bonjour.\r\n\
                       .\r\n\
                       Et la suite, qui ne doit pas devenir une commande.\r\n";

fn message<'a>(destinataires: &'a [std::string::String]) -> Outgoing<'a> {
    Outgoing {
        sender: "",
        recipients: destinataires,
        body: CORPS,
    }
}

// ── LES DEUX MOITIÉS SE RÉPONDENT ───────────────────────────────────────────

#[tokio::test]
async fn un_message_traverse_notre_propre_serveur_intact() {
    let (adresse, cahier) = serveur(None).await;
    let destinataires = std::vec![std::string::String::from("marie@example.com")];
    let issue = remetteur(false)
        .with_port(adresse.port())
        .send_to("mail.eux.test", adresse, &message(&destinataires))
        .await;
    assert_eq!(
        issue,
        RelayOutcome::Delivered {
            accepted: 1,
            refused: 0,
            encrypted: false,
            // `send_to` n'a pas de `TLSA` : ces essais s'adressent à une
            // adresse connue, sans passer par le DNS.
            authenticated: false,
        }
    );

    let recu = cahier.0.lock().expect("verrou").clone();
    let texte = std::string::String::from_utf8(recu).expect("de l'ASCII");
    // **Le farcissage et sa défaite se répondent** : la ligne au seul point est
    // arrivée telle qu'elle est partie, et ce qui la suit n'est pas devenu une
    // commande.
    assert!(
        texte.contains("Bonjour.\r\n.\r\nEt la suite"),
        "le message a été abîmé :\n{texte}"
    );
    assert!(texte.starts_with("From: nous@nous.test\r\n"), "{texte}");
}

#[tokio::test]
async fn un_destinataire_que_le_pair_refuse_fait_renoncer() {
    let (adresse, cahier) = serveur(None).await;
    // `NotreDomaine` n'accepte que `example.com` : celui-ci est refusé.
    let destinataires = std::vec![std::string::String::from("jean@ailleurs.test")];
    let issue = remetteur(false)
        .with_port(adresse.port())
        .send_to("mail.eux.test", adresse, &message(&destinataires))
        .await;
    assert!(
        matches!(issue, RelayOutcome::Rejected(code) if (500..600).contains(&code)),
        "{issue:?}"
    );
    assert!(cahier.0.lock().expect("verrou").is_empty());
}

#[tokio::test]
async fn un_destinataire_sur_deux_suffit_a_remettre() {
    let (adresse, _) = serveur(None).await;
    let destinataires = std::vec![
        std::string::String::from("jean@ailleurs.test"),
        std::string::String::from("marie@example.com"),
    ];
    let issue = remetteur(false)
        .with_port(adresse.port())
        .send_to("mail.eux.test", adresse, &message(&destinataires))
        .await;
    assert_eq!(
        issue,
        RelayOutcome::Delivered {
            accepted: 1,
            refused: 1,
            encrypted: false,
            // `send_to` n'a pas de `TLSA` : ces essais s'adressent à une
            // adresse connue, sans passer par le DNS.
            authenticated: false,
        }
    );
}

// ── LE CHIFFREMENT ──────────────────────────────────────────────────────────

#[tokio::test]
async fn la_remise_chiffree_traverse_aussi() {
    let Some(materiel) = materiel("remise-chiffree") else {
        return;
    };
    let (adresse, cahier) = serveur(Some(Arc::clone(&materiel.tls))).await;
    let destinataires = std::vec![std::string::String::from("marie@example.com")];
    let issue = remetteur(true)
        .with_port(adresse.port())
        .send_to("mail.eux.test", adresse, &message(&destinataires))
        .await;
    assert_eq!(
        issue,
        RelayOutcome::Delivered {
            accepted: 1,
            refused: 0,
            encrypted: true,
            // `send_to` n'a pas de `TLSA` : ces essais s'adressent à une
            // adresse connue, sans passer par le DNS.
            authenticated: false,
        },
        "la remise devait aboutir SOUS CHIFFREMENT"
    );
    let recu = cahier.0.lock().expect("verrou").clone();
    assert!(std::string::String::from_utf8_lossy(&recu).contains("Bonjour.\r\n.\r\nEt la suite"));
}

/// **On n'écrit pas en clair quand on a dit qu'on ne le ferait pas.** Le pair
/// n'a rien fait de mal : c'est nous qui refusons.
#[tokio::test]
async fn sans_starttls_l_exigence_fait_renoncer() {
    let (adresse, cahier) = serveur(None).await;
    let destinataires = std::vec![std::string::String::from("marie@example.com")];
    let issue = remetteur(true)
        .with_port(adresse.port())
        .send_to("mail.eux.test", adresse, &message(&destinataires))
        .await;
    assert_eq!(issue, RelayOutcome::NoEncryption);
    assert!(cahier.0.lock().expect("verrou").is_empty());
}

// ── CE QUI NE PART PAS ──────────────────────────────────────────────────────

/// Un `LF` isolé est une faute **de notre côté**, et l'émettre serait pire que
/// de la voir.
#[tokio::test]
async fn un_corps_mal_termine_ne_part_pas() {
    let destinataires = std::vec![std::string::String::from("marie@example.com")];
    let issue = remetteur(false)
        .send_to(
            "mail.eux.test",
            "127.0.0.1:1".parse().expect("adresse"),
            &Outgoing {
                sender: "",
                recipients: &destinataires,
                body: b"Sujet: essai\nsans CR\n",
            },
        )
        .await;
    assert_eq!(issue, RelayOutcome::Unsendable);
}

/// L'adresse d'un rapport DMARC est publiée par le domaine qu'on rapporte.
#[tokio::test]
async fn une_adresse_qui_porte_une_commande_ne_part_pas() {
    let destinataires = std::vec![std::string::String::from(
        "victime@x.test>\r\nRCPT TO:<autre@y.test"
    )];
    let issue = remetteur(false)
        .send_to(
            "mail.eux.test",
            "127.0.0.1:1".parse().expect("adresse"),
            &message(&destinataires),
        )
        .await;
    assert_eq!(issue, RelayOutcome::Unsendable);
}

#[tokio::test]
async fn un_serveur_injoignable_est_une_panne_pas_un_refus() {
    // Le port 1 sur la boucle locale : personne n'écoute, et l'on n'y a pas
    // droit. Une panne de réseau n'est pas un refus, et la traiter comme tel
    // perdrait du courrier.
    let destinataires = std::vec![std::string::String::from("marie@example.com")];
    let issue = remetteur(false)
        .send_to(
            "mail.eux.test",
            "127.0.0.1:1".parse().expect("adresse"),
            &message(&destinataires),
        )
        .await;
    assert_eq!(issue, RelayOutcome::Unreachable);
}

// ── TROUVER LE SERVEUR D'UN DOMAINE ─────────────────────────────────────────

use commun::{Enregistrement, resolveur_courrier};

/// Un remetteur qui résout pour de vrai, sur le DNS d'épreuve.
fn remetteur_resolvant(dns: std::net::SocketAddr, port: u16) -> Relay {
    Relay::new(
        Resolver::new(std::vec![dns], Duration::from_secs(2)).expect("résolveur"),
        Arc::new(ams_tls::relay_config()),
        std::string::String::from("mail.nous.test"),
        false,
        Duration::from_secs(5),
    )
    .with_port(port)
}

#[tokio::test]
async fn le_mx_dit_ou_frapper() {
    const TABLE: &[(&str, Enregistrement)] = &[
        ("eux.test", Enregistrement::Mx(10, "mx.eux.test")),
        ("mx.eux.test", Enregistrement::A([127, 0, 0, 1])),
    ];
    let dns = resolveur_courrier(TABLE).await;
    let (adresse, cahier) = serveur(None).await;
    let destinataires = std::vec![std::string::String::from("marie@example.com")];
    let issue = remetteur_resolvant(dns, adresse.port())
        .send("eux.test", &message(&destinataires))
        .await;
    assert_eq!(
        issue,
        RelayOutcome::Delivered {
            accepted: 1,
            refused: 0,
            encrypted: false,
            // `send_to` n'a pas de `TLSA` : ces essais s'adressent à une
            // adresse connue, sans passer par le DNS.
            authenticated: false,
        }
    );
    assert!(!cahier.0.lock().expect("verrou").is_empty());
}

/// RFC 5321 §5.1 : sans `MX`, c'est le nom lui-même qui reçoit.
#[tokio::test]
async fn sans_mx_c_est_le_domaine_lui_meme_qui_recoit() {
    const TABLE: &[(&str, Enregistrement)] = &[("eux.test", Enregistrement::A([127, 0, 0, 1]))];
    let dns = resolveur_courrier(TABLE).await;
    let (adresse, _) = serveur(None).await;
    let destinataires = std::vec![std::string::String::from("marie@example.com")];
    let issue = remetteur_resolvant(dns, adresse.port())
        .send("eux.test", &message(&destinataires))
        .await;
    assert!(matches!(issue, RelayOutcome::Delivered { .. }), "{issue:?}");
}

/// **Le `MX` nul est un refus publié à l'avance** (RFC 7505). Le confondre avec
/// une panne ferait réessayer des jours durant ce qu'un domaine a fermé.
#[tokio::test]
async fn un_mx_nul_est_un_refus_definitif() {
    const TABLE: &[(&str, Enregistrement)] = &[("eux.test", Enregistrement::Mx(0, ""))];
    let dns = resolveur_courrier(TABLE).await;
    let destinataires = std::vec![std::string::String::from("marie@example.com")];
    let issue = remetteur_resolvant(dns, 25)
        .send("eux.test", &message(&destinataires))
        .await;
    assert_eq!(issue, RelayOutcome::NullMx);
}

/// **Le plus préféré d'abord**, et l'on ne passe au suivant que si le premier
/// n'a pas répondu du tout.
#[tokio::test]
async fn les_mx_s_essaient_par_preference() {
    const TABLE: &[(&str, Enregistrement)] = &[
        ("eux.test", Enregistrement::Mx(50, "secours.eux.test")),
        ("eux.test", Enregistrement::Mx(10, "premier.eux.test")),
        // Le premier ne mène nulle part : aucune adresse.
        ("secours.eux.test", Enregistrement::A([127, 0, 0, 1])),
    ];
    let dns = resolveur_courrier(TABLE).await;
    let (adresse, cahier) = serveur(None).await;
    let destinataires = std::vec![std::string::String::from("marie@example.com")];
    let issue = remetteur_resolvant(dns, adresse.port())
        .send("eux.test", &message(&destinataires))
        .await;
    assert!(matches!(issue, RelayOutcome::Delivered { .. }), "{issue:?}");
    assert!(!cahier.0.lock().expect("verrou").is_empty());
}

#[tokio::test]
async fn un_domaine_qu_on_ne_sait_pas_joindre_est_une_panne() {
    const TABLE: &[(&str, Enregistrement)] = &[];
    let dns = resolveur_courrier(TABLE).await;
    let destinataires = std::vec![std::string::String::from("marie@example.com")];
    let issue = remetteur_resolvant(dns, 25)
        .send("nulle-part.test", &message(&destinataires))
        .await;
    assert_eq!(issue, RelayOutcome::Unreachable);
}

// ── DU JOURNAL DMARC JUSQU'AU SERVEUR D'EN FACE ─────────────────────────────

/// **La chaîne entière**, du message observé au rapport remis : DMARC compte,
/// le journal compose, le MIME emballe, le client remet, et notre propre serveur
/// reçoit. C'est le seul test qui la parcourt d'un bout à l'autre.
#[tokio::test]
async fn un_rapport_observe_finit_dans_la_boite_d_en_face() {
    use ams_dmarc::report::aggregate::{DkimAuthResult, SpfAuthResult, SpfScope};
    use ams_dmarc::{Alignment, Policy, Verdict};
    use ams_loop_tokio::{Observation, PolitiqueLue, ReportSpool, SignatureVue, SpfVu};
    use std::net::{IpAddr, Ipv4Addr};

    // Le domaine rapporté demande ses rapports CHEZ LUI : aucune vérification
    // externe n'est due (§7.1), et `example.com` est justement ce que notre
    // serveur d'épreuve accepte.
    const TABLE: &[(&str, Enregistrement)] = &[("example.com", Enregistrement::A([127, 0, 0, 1]))];
    let dns = resolveur_courrier(TABLE).await;
    let (adresse, cahier) = serveur(None).await;

    let dossier =
        std::env::temp_dir().join(std::format!("ams-remise-rapport-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dossier);
    let spool = ReportSpool::new(
        std::string::String::from("mail.nous.test"),
        std::string::String::from("dmarc@nous.test"),
        dossier.clone(),
        Resolver::new(std::vec![dns], Duration::from_secs(2)).expect("résolveur"),
    )
    .with_relay(remetteur_resolvant(dns, adresse.port()));

    spool.observer(Observation {
        domain: std::string::String::from("example.com"),
        published: PolitiqueLue {
            dkim_alignment: Alignment::Relaxed,
            spf_alignment: Alignment::Relaxed,
            policy: Policy::None,
            subdomain_policy: None,
            percent: 100,
        },
        destinations: std::string::String::from("mailto:dmarc@example.com"),
        source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        disposition: Policy::None,
        dkim: Verdict::Fail,
        spf: Verdict::Pass,
        envelope_from: Some(std::string::String::from("example.com")),
        signatures: std::vec![SignatureVue {
            domain: std::string::String::from("example.com"),
            selector: std::string::String::from("sel"),
            result: DkimAuthResult::Fail,
        }],
        spf_auth: SpfVu {
            domain: std::string::String::from("example.com"),
            scope: SpfScope::MailFrom,
            result: SpfAuthResult::Pass,
        },
    });

    let compose = spool.vider().await;
    assert_eq!(compose.reports, 1);
    assert_eq!(compose.destinations, 1);

    let remis = spool.envoyer().await;
    assert_eq!(remis.sent, 1, "le rapport devait partir : {remis:?}");
    assert_eq!(remis.deferred, 0);

    // **Ce qui est remis est retiré.** Le dossier est vide.
    let restants: std::vec::Vec<_> = std::fs::read_dir(&dossier)
        .expect("dossier lisible")
        .filter_map(Result::ok)
        .collect();
    assert!(
        restants.is_empty(),
        "{} fichier(s) restant(s)",
        restants.len()
    );

    let recu = cahier.0.lock().expect("verrou").clone();
    let texte = std::string::String::from_utf8_lossy(&recu).into_owned();
    for morceau in [
        "From: <dmarc@nous.test>\r\n",
        "To: <dmarc@example.com>\r\n",
        "Subject: Report Domain: example.com Submitter: mail.nous.test Report-ID:",
        "MIME-Version: 1.0\r\n",
        "Auto-Submitted: auto-generated\r\n",
        "Content-Type: multipart/mixed; boundary=\"----ams-",
        "Content-Type: application/gzip\r\n",
        "Content-Transfer-Encoding: base64\r\n",
        "filename=\"mail.nous.test!example.com!",
        "This is a DMARC aggregate report (RFC 7489).",
    ] {
        assert!(
            texte.contains(morceau),
            "{morceau:?} manque dans :\n{texte}"
        );
    }
    let _ = std::fs::remove_dir_all(&dossier);
}

/// **Un rapport que personne ne peut recevoir aujourd'hui reste pour demain** :
/// c'est tout l'intérêt de l'avoir écrit sur un disque.
#[tokio::test]
async fn un_serveur_injoignable_laisse_le_rapport_en_place() {
    use ams_dmarc::report::aggregate::{SpfAuthResult, SpfScope};
    use ams_dmarc::{Alignment, Policy, Verdict};
    use ams_loop_tokio::{Observation, PolitiqueLue, ReportSpool, SpfVu};
    use std::net::{IpAddr, Ipv4Addr};

    const TABLE: &[(&str, Enregistrement)] = &[("example.com", Enregistrement::A([127, 0, 0, 1]))];
    let dns = resolveur_courrier(TABLE).await;
    let dossier =
        std::env::temp_dir().join(std::format!("ams-remise-differee-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dossier);
    let spool = ReportSpool::new(
        std::string::String::from("mail.nous.test"),
        std::string::String::from("dmarc@nous.test"),
        dossier.clone(),
        Resolver::new(std::vec![dns], Duration::from_secs(2)).expect("résolveur"),
    )
    // Le port 1 sur la boucle locale : personne n'écoute.
    .with_relay(remetteur_resolvant(dns, 1));

    spool.observer(Observation {
        domain: std::string::String::from("example.com"),
        published: PolitiqueLue {
            dkim_alignment: Alignment::Relaxed,
            spf_alignment: Alignment::Relaxed,
            policy: Policy::None,
            subdomain_policy: None,
            percent: 100,
        },
        destinations: std::string::String::from("mailto:dmarc@example.com"),
        source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        disposition: Policy::None,
        dkim: Verdict::Fail,
        spf: Verdict::Fail,
        envelope_from: None,
        signatures: std::vec![],
        spf_auth: SpfVu {
            domain: std::string::String::from("example.com"),
            scope: SpfScope::Helo,
            result: SpfAuthResult::None,
        },
    });
    spool.vider().await;
    let remis = spool.envoyer().await;
    assert_eq!(remis.sent, 0);
    assert_eq!(remis.deferred, 1);

    let restants = std::fs::read_dir(&dossier)
        .expect("dossier lisible")
        .filter_map(Result::ok)
        .count();
    assert_eq!(restants, 2, "le rapport et ses destinations restent");
    let _ = std::fs::remove_dir_all(&dossier);
}

/// Sans remetteur, on dépose et rien de plus — et c'est le défaut.
#[tokio::test]
async fn sans_remetteur_rien_ne_part() {
    use ams_loop_tokio::ReportSpool;

    let dossier = std::env::temp_dir().join(std::format!(
        "ams-remise-sans-relais-{}",
        std::process::id()
    ));
    let spool = ReportSpool::new(
        std::string::String::from("mail.nous.test"),
        std::string::String::from("dmarc@nous.test"),
        dossier,
        Resolver::new(
            std::vec!["127.0.0.1:1".parse().expect("adresse")],
            Duration::from_secs(1),
        )
        .expect("résolveur"),
    );
    assert_eq!(spool.envoyer().await, Default::default());
}

// ── LE RAPPORT D'ÉCHEC : CE QU'IL DIT, ET CE QU'IL TAIT ─────────────────────

/// Le bloc d'en-tête d'un message rapporté, avec de tout dedans.
const ENTETES_RAPPORTES: &[u8] = b"Received: from mechant.test (mechant.test [192.0.2.1])\r\n\
                                   \tby mail.nous.test with ESMTP id 42\r\n\
                                   From: Service <securite@example.com>\r\n\
                                   To: Marie Dupont <marie@nous.test>\r\n\
                                   Subject: Votre compte\r\n\
                                   Date: Sat, 29 Aug 2026 07:08:31 +0000\r\n\
                                   X-Interne: dossier 12345\r\n\
                                   \r\n";

fn observation_d_echec() -> ams_loop_tokio::FailureObservation {
    use std::net::{IpAddr, Ipv4Addr};

    ams_loop_tokio::FailureObservation {
        domain: std::string::String::from("example.com"),
        destinations: std::string::String::from("mailto:echecs@example.com"),
        source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        arrival: 1_787_987_311,
        envelope_from: Some(std::string::String::from("expediteur@ailleurs.test")),
        dkim_domain: Some(std::string::String::from("signataire.test")),
        dkim_selector: Some(std::string::String::from("sel")),
        spf_domain: Some(std::string::String::from("ailleurs.test")),
        rejected: true,
        aligned_dkim: false,
        aligned_spf: false,
        headers: ENTETES_RAPPORTES.to_vec(),
    }
}

/// Ouvre un journal branché sur le serveur d'épreuve.
async fn journal_d_echec(
    nom: &str,
    port: u16,
    dns: std::net::SocketAddr,
    actif: bool,
) -> (ams_loop_tokio::ReportSpool, std::path::PathBuf) {
    use ams_loop_tokio::ReportSpool;

    let dossier = std::env::temp_dir().join(std::format!("ams-echec-{nom}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dossier);
    let spool = ReportSpool::new(
        std::string::String::from("mail.nous.test"),
        std::string::String::from("dmarc@nous.test"),
        dossier.clone(),
        Resolver::new(std::vec![dns], Duration::from_secs(2)).expect("résolveur"),
    )
    .with_relay(remetteur_resolvant(dns, port));
    let spool = if actif {
        spool.with_failure_reports()
    } else {
        spool
    };
    (spool, dossier)
}

/// **Ce qui sort d'ici est une liste blanche.** Le destinataire du message, les
/// en-têtes de routage et le corps ne sortent jamais.
#[tokio::test]
async fn un_rapport_d_echec_ne_livre_ni_le_corps_ni_le_destinataire() {
    const TABLE: &[(&str, Enregistrement)] = &[("example.com", Enregistrement::A([127, 0, 0, 1]))];
    let dns = resolveur_courrier(TABLE).await;
    let (adresse, cahier) = serveur(None).await;
    let (spool, dossier) = journal_d_echec("livre", adresse.port(), dns, true).await;

    spool.echec(&observation_d_echec()).await;
    let remis = spool.envoyer().await;
    assert_eq!(
        remis.sent, 1,
        "le rapport d'échec devait partir : {remis:?}"
    );

    let recu = cahier.0.lock().expect("verrou").clone();
    let texte = std::string::String::from_utf8_lossy(&recu).into_owned();
    for garde in [
        "Content-Type: multipart/report; report-type=feedback-report;",
        "Content-Type: message/feedback-report\r\n",
        "Content-Type: text/rfc822-headers\r\n",
        "Feedback-Type: auth-failure\r\n",
        "Reported-Domain: example.com\r\n",
        "Source-IP: 192.0.2.1\r\n",
        "Delivery-Result: reject\r\n",
        "Identity-Alignment: none\r\n",
        "DKIM-Domain: signataire.test\r\n",
        "SPF-DNS: ailleurs.test\r\n",
        // Ce qui reste du message : son auteur prétendu, et son sujet.
        "From: Service <securite@example.com>\r\n",
        "Subject: Votre compte\r\n",
    ] {
        assert!(texte.contains(garde), "{garde:?} manque dans :\n{texte}");
    }
    for interdit in [
        "marie@nous.test",
        "Marie Dupont",
        "Received: from mechant.test",
        "X-Interne",
        "12345",
        "Original-Rcpt-To",
    ] {
        assert!(!texte.contains(interdit), "{interdit:?} a fuité :\n{texte}");
    }
    let _ = std::fs::remove_dir_all(&dossier);
}

/// **Sans qu'on l'ait demandé, aucun rapport d'échec n'est composé.**
#[tokio::test]
async fn sans_la_demande_aucun_rapport_d_echec_n_est_compose() {
    const TABLE: &[(&str, Enregistrement)] = &[("example.com", Enregistrement::A([127, 0, 0, 1]))];
    let dns = resolveur_courrier(TABLE).await;
    let (spool, dossier) = journal_d_echec("muet", 1, dns, false).await;
    spool.echec(&observation_d_echec()).await;
    assert!(
        !dossier.exists(),
        "un dossier a été créé pour un rapport qu'on n'a pas demandé"
    );
}

/// **Sans ce plafond, une usurpation en masse devient un déluge** : un rapport
/// par message ferait écrire cent mille fois à un domaine qui n'a rien demandé
/// de tel.
#[tokio::test]
async fn un_meme_domaine_ne_vaut_qu_un_nombre_borne_de_rapports() {
    const TABLE: &[(&str, Enregistrement)] = &[("example.com", Enregistrement::A([127, 0, 0, 1]))];
    let dns = resolveur_courrier(TABLE).await;
    let (spool, dossier) = journal_d_echec("plafond", 1, dns, true).await;

    for _ in 0..120 {
        spool.echec(&observation_d_echec()).await;
    }
    let composes = std::fs::read_dir(&dossier)
        .expect("dossier lisible")
        .filter_map(Result::ok)
        .filter(|entree| {
            entree
                .file_name()
                .to_str()
                .is_some_and(|nom| nom.ends_with(".eml"))
        })
        .count();
    assert_eq!(composes, 100, "le plafond n'a pas tenu");
    let _ = std::fs::remove_dir_all(&dossier);
}

/// Une destination externe qui n'a pas consenti n'obtient rien — ici comme pour
/// les rapports agrégés, et pour la même raison.
#[tokio::test]
async fn un_rapport_d_echec_ne_part_pas_vers_qui_n_a_pas_consenti() {
    const TABLE: &[(&str, Enregistrement)] = &[];
    let dns = resolveur_courrier(TABLE).await;
    let (spool, dossier) = journal_d_echec("consentement", 1, dns, true).await;
    spool
        .echec(&ams_loop_tokio::FailureObservation {
            destinations: std::string::String::from("mailto:victime@banque.test"),
            ..observation_d_echec()
        })
        .await;
    assert!(!dossier.exists(), "un rapport est parti sans consentement");
}
