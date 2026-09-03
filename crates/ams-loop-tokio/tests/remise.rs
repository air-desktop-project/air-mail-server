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

/// Une file d'attente dans un dossier neuf.
///
/// **LES RAPPORTS PASSENT PAR LA FILE COMME LE RESTE.** Ces essais éprouvent
/// donc le chemin ENTIER — composer, déposer, reprendre, remettre — et non plus
/// une remise directe qui n'existe plus.
fn file_d_essai(nom: &str) -> std::sync::Arc<ams_loop_tokio::Spool> {
    let dossier = std::env::temp_dir().join(std::format!(
        "ams-file-rapports-{nom}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dossier);
    std::fs::create_dir_all(&dossier).expect("dossier");
    std::sync::Arc::new(ams_loop_tokio::Spool::new(
        dossier,
        ams_queue::Backoff::DEFAULT,
        std::string::String::from("mail.nous.test"),
        std::string::String::from("postmaster@mail.nous.test"),
    ))
}

/// Un rendu d'avis qui accepte tout : ces essais n'éprouvent pas la
/// non-remise, qui a ses propres essais dans `file.rs`.
struct SansAvis;

impl ams_loop_tokio::Bounced for SansAvis {
    fn deliver(&self, _recipient: &str, _message: &[u8]) -> bool {
        true
    }
}

/// L'heure, en secondes depuis l'époque.
fn maintenant() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |depuis| depuis.as_secs())
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

/// Ce qu'un serveur a retenu d'une demande de RFC 3461 : l'identifiant
/// d'enveloppe, puis le silence, le succès, le retard, et l'adresse d'origine.
type DemandeVue = (std::vec::Vec<u8>, bool, bool, bool, std::vec::Vec<u8>);

/// Une remise qui retient ce que le déposant a demandé du sort de son message.
#[derive(Clone, Default)]
struct CahierDsn(Arc<Mutex<DemandeVue>>);

impl Delivery for CahierDsn {
    fn add_recipient(&mut self, _address: &[u8]) -> Result<(), DeliveryFailure> {
        Ok(())
    }
    fn envelope_id(&mut self, id: &[u8]) {
        self.0.lock().expect("verrou").0 = id.to_vec();
    }
    fn recipient_report(&mut self, never: bool, on_success: bool, on_delay: bool, original: &[u8]) {
        let mut vu = self.0.lock().expect("verrou");
        vu.1 = never;
        vu.2 = on_success;
        vu.3 = on_delay;
        vu.4 = original.to_vec();
    }
    fn append(&mut self, _chunk: &[u8]) -> Result<(), DeliveryFailure> {
        Ok(())
    }
    fn finish(&mut self) -> Result<(), DeliveryFailure> {
        Ok(())
    }
    fn abort(&mut self) {}
}

/// Monte un serveur qui ANNONCE `DSN`, et rend ce qu'il a retenu de la demande.
async fn serveur_dsn() -> (std::net::SocketAddr, CahierDsn) {
    let ecouteur = TcpListener::bind("127.0.0.1:0").await.expect("écoute");
    let adresse = ecouteur.local_addr().expect("adresse");
    let cahier = CahierDsn::default();
    let sien = cahier.clone();
    tokio::spawn(async move {
        let (mut flux, _) = ecouteur.accept().await.expect("connexion");
        let garde = SharedGuard::new(4, Thresholds::DEFAULT);
        let mut remise = sien;
        let service = Service {
            config: Config::new(b"mail.eux.test", 100, 10_485_760, Limits::DEFAULT)
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
        let _ = serve_connection(&mut flux, &service, NotreDomaine, &mut remise, PAIR).await;
    });
    (adresse, cahier)
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
                    dsn: false,
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
        dsn: None,
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
            // Rien n'a été demandé : il n'y avait rien à passer.
            dsn_forwarded: false,
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
    // **LE SERVEUR D'EN FACE POSE LES DEUX EN-TÊTES DE §4.4**, dans l'ordre où
    // ce paragraphe les place : le `Return-Path:` de la remise finale, puis la
    // trace. Le message arrive intact derrière eux.
    //
    // **ET `<>` EST ICI LE CAS QUI COMPTE** : cet envoi part d'un chemin nul,
    // et c'est cette ligne qui apprend au destinataire que le message est un
    // rapport — donc qu'un répondeur automatique doit s'en abstenir (§2 de
    // RFC 3834). Sans elle, rien ne le distinguait d'un message ordinaire.
    assert!(
        texte.starts_with("Return-Path: <>\r\nReceived: from mail.nous.test ([127.0.0.1])\r\n"),
        "{texte}"
    );
    assert!(texte.contains("\r\nFrom: nous@nous.test\r\n"), "{texte}");
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
    let RelayOutcome::Rejected(refus) = &issue else {
        panic!("le refus devait être définitif : {issue:?}");
    };
    assert!((500..600).contains(&refus.code), "{issue:?}");
    // **CE QUE LE PAIR A DIT REMONTE**, et ce n'est pas une phrase de notre cru :
    // c'est notre propre serveur qui refuse ici, et son texte est reconnaissable.
    assert!(
        refus.diagnostic.contains("Relay access denied"),
        "le texte du pair s'est perdu : {refus:?}"
    );
    // Il annonce `ENHANCEDSTATUSCODES`, donc son état étendu est lu plutôt que
    // deviné — et `5.7.1` n'est PAS ce que le code seul aurait fait écrire.
    assert_eq!(
        refus.status.map(|dit| dit.class()),
        Some(5),
        "l'état du pair s'est perdu : {refus:?}"
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
            // Rien n'a été demandé : il n'y avait rien à passer.
            dsn_forwarded: false,
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
            // Rien n'a été demandé : il n'y avait rien à passer.
            dsn_forwarded: false,
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
                dsn: None,
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
            // Rien n'a été demandé : il n'y avait rien à passer.
            dsn_forwarded: false,
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
    let file = file_d_essai("rapport");
    let spool = ReportSpool::new(
        std::string::String::from("mail.nous.test"),
        std::string::String::from("dmarc@nous.test"),
        dossier.clone(),
        Resolver::new(std::vec![dns], Duration::from_secs(2)).expect("résolveur"),
    )
    .with_queue(std::sync::Arc::clone(&file));

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

    // **LE RAPPORT PASSE PAR LA FILE, COMME LE RESTE.** `envoyer` DÉPOSE ; c'est
    // le parcours de la file qui remet, avec la même attente et la même
    // péremption que n'importe quel message.
    let remis = spool.envoyer().await;
    assert_eq!(remis.sent, 1, "le rapport devait être déposé : {remis:?}");
    assert_eq!(remis.deferred, 0);

    // **Ce qui est déposé est retiré du dossier des rapports.**
    let restants: std::vec::Vec<_> = std::fs::read_dir(&dossier)
        .expect("dossier lisible")
        .filter_map(Result::ok)
        .collect();
    assert!(
        restants.is_empty(),
        "{} fichier(s) restant(s)",
        restants.len()
    );

    let parcours = file
        .parcourir(
            &remetteur_resolvant(dns, adresse.port()),
            &SansAvis,
            maintenant(),
        )
        .await;
    assert_eq!(
        parcours.sent, 1,
        "la file devait le remettre : {parcours:?}"
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
    let file = file_d_essai("differee");
    let spool = ReportSpool::new(
        std::string::String::from("mail.nous.test"),
        std::string::String::from("dmarc@nous.test"),
        dossier.clone(),
        Resolver::new(std::vec![dns], Duration::from_secs(2)).expect("résolveur"),
    )
    .with_queue(std::sync::Arc::clone(&file));

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
    // Le dépôt en file réussit toujours : c'est une écriture sur un disque.
    let remis = spool.envoyer().await;
    assert_eq!(remis.sent, 1, "{remis:?}");

    // **C'EST LA FILE QUI DIFFÈRE, MAINTENANT.** Le port 1 sur la boucle
    // locale : personne n'écoute, et l'entrée reste pour la reprise suivante —
    // avec l'attente qui double, ce que l'ancienne remise ad hoc ne faisait pas.
    let parcours = file
        .parcourir(&remetteur_resolvant(dns, 1), &SansAvis, maintenant())
        .await;
    assert_eq!(parcours.sent, 0);
    assert_eq!(parcours.deferred, 1, "{parcours:?}");

    let restants = std::fs::read_dir(file.dossier())
        .expect("dossier lisible")
        .filter_map(Result::ok)
        .count();
    assert_eq!(restants, 2, "le message et son enveloppe restent en file");
    let _ = std::fs::remove_dir_all(&dossier);
    let _ = std::fs::remove_dir_all(file.dossier());
}

/// Sans file, on dépose dans le dossier des rapports et rien de plus — et
/// c'est le défaut : `--tlsrpt-send` et `--dmarc-send` sont deux crans.
#[tokio::test]
async fn sans_file_rien_ne_part() {
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
) -> (
    ams_loop_tokio::ReportSpool,
    std::path::PathBuf,
    std::sync::Arc<ams_loop_tokio::Spool>,
    Relay,
) {
    use ams_loop_tokio::ReportSpool;

    let dossier = std::env::temp_dir().join(std::format!("ams-echec-{nom}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dossier);
    let file = file_d_essai(nom);
    let spool = ReportSpool::new(
        std::string::String::from("mail.nous.test"),
        std::string::String::from("dmarc@nous.test"),
        dossier.clone(),
        Resolver::new(std::vec![dns], Duration::from_secs(2)).expect("résolveur"),
    )
    .with_queue(std::sync::Arc::clone(&file));
    let spool = if actif {
        spool.with_failure_reports()
    } else {
        spool
    };
    (spool, dossier, file, remetteur_resolvant(dns, port))
}

/// **Ce qui sort d'ici est une liste blanche.** Le destinataire du message, les
/// en-têtes de routage et le corps ne sortent jamais.
#[tokio::test]
async fn un_rapport_d_echec_ne_livre_ni_le_corps_ni_le_destinataire() {
    const TABLE: &[(&str, Enregistrement)] = &[("example.com", Enregistrement::A([127, 0, 0, 1]))];
    let dns = resolveur_courrier(TABLE).await;
    let (adresse, cahier) = serveur(None).await;
    let (spool, dossier, file, remetteur) =
        journal_d_echec("livre", adresse.port(), dns, true).await;

    spool.echec(&observation_d_echec()).await;
    let remis = spool.envoyer().await;
    assert_eq!(
        remis.sent, 1,
        "le rapport d'échec devait être déposé : {remis:?}"
    );
    // **PUIS LA FILE LE REMET**, comme n'importe quel message.
    let parcours = file.parcourir(&remetteur, &SansAvis, maintenant()).await;
    assert_eq!(
        parcours.sent, 1,
        "la file devait le remettre : {parcours:?}"
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
    let (spool, dossier, _file, _remetteur) = journal_d_echec("muet", 1, dns, false).await;
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
    let (spool, dossier, _file, _remetteur) = journal_d_echec("plafond", 1, dns, true).await;

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
    let (spool, dossier, _file, _remetteur) = journal_d_echec("consentement", 1, dns, true).await;
    spool
        .echec(&ams_loop_tokio::FailureObservation {
            destinations: std::string::String::from("mailto:victime@banque.test"),
            ..observation_d_echec()
        })
        .await;
    assert!(!dossier.exists(), "un rapport est parti sans consentement");
}

// ── CE QUE LE DÉPOSANT A DEMANDÉ, D'UNE MOITIÉ À L'AUTRE (RFC 3461) ─────────

/// **L'ENCODAGE ET LE DÉCODAGE SE RÉPONDENT, ET RIEN D'AUTRE NE LE PROUVE.**
///
/// L'écrivain et le lecteur du xtext (§4) ne partagent aucun code : l'un
/// échappe, l'autre défait. Les faire dialoguer sur `marie+liste@x.test` —
/// l'adressage par étiquette, qui est partout — est le seul essai où une erreur
/// d'un côté ne peut pas être rattrapée par l'erreur inverse de l'autre.
///
/// Écrite en clair, cette adresse serait relue comme l'échappée `+li`, qui n'est
/// pas de l'hexadécimal : le `RCPT` serait refusé, et le message perdu.
#[tokio::test]
async fn la_demande_du_deposant_traverse_intacte() {
    let (adresse, vu) = serveur_dsn().await;
    let destinataires = std::vec![std::string::String::from("marie@example.com")];
    let rapports = [ams_loop_tokio::ClientReport {
        never: false,
        on_success: true,
        original: b"marie+liste@x.test",
    }];
    let issue = remetteur(false)
        .with_port(adresse.port())
        .send_to(
            "mail.eux.test",
            adresse,
            &Outgoing {
                sender: "",
                recipients: &destinataires,
                body: CORPS,
                dsn: Some(ams_loop_tokio::ClientDsn {
                    // Un `+` dans l'identifiant AUSSI : c'est le caractère que
                    // §4 réserve, et le seul dont l'oubli se voit.
                    envelope_id: b"envoi+42",
                    reports: &rapports,
                }),
            },
        )
        .await;
    assert_eq!(
        issue,
        RelayOutcome::Delivered {
            accepted: 1,
            refused: 0,
            encrypted: false,
            authenticated: false,
            // **LE SAUT SUIVANT A PRIS LA DEMANDE**, donc c'est LUI qui rendra
            // compte, et la file se tait (§5.2.1).
            dsn_forwarded: true,
        }
    );
    let (identifiant, jamais, succes, retard, origine) = vu.0.lock().expect("verrou").clone();
    assert_eq!(identifiant, b"envoi+42", "l'identifiant a changé en route");
    assert_eq!(
        origine, b"marie+liste@x.test",
        "l'adresse a changé en route"
    );
    assert!(succes, "le rapport de succès demandé s'est perdu");
    assert!(!jamais);
    assert!(!retard, "un retard qu'on n'avait pas demandé");
}

/// **UN PAIR QUI N'ANNONCE PAS `DSN` NOUS LAISSE RENDRE COMPTE.**
///
/// C'est la moitié qui compte pour la file : sans ce faux, elle se tairait
/// toujours, et un rapport de succès demandé ne partirait jamais.
#[tokio::test]
async fn un_pair_qui_ignore_le_dsn_le_dit() {
    let (adresse, _cahier) = serveur(None).await;
    let destinataires = std::vec![std::string::String::from("marie@example.com")];
    let rapports = [ams_loop_tokio::ClientReport {
        never: false,
        on_success: true,
        original: b"",
    }];
    let issue = remetteur(false)
        .with_port(adresse.port())
        .send_to(
            "mail.eux.test",
            adresse,
            &Outgoing {
                sender: "",
                recipients: &destinataires,
                body: CORPS,
                dsn: Some(ams_loop_tokio::ClientDsn {
                    envelope_id: b"envoi-42",
                    reports: &rapports,
                }),
            },
        )
        .await;
    assert_eq!(
        issue,
        RelayOutcome::Delivered {
            accepted: 1,
            refused: 0,
            encrypted: false,
            authenticated: false,
            dsn_forwarded: false,
        }
    );
}
