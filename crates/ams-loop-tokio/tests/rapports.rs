// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Les rapports agrégés DMARC** (RFC 7489 §7.2), du journal au fichier déposé.
//!
//! # Ce que ces tests éprouvent
//!
//! Qu'un rapport dit ce qui s'est passé — et qu'il ne dit rien de plus. Qu'il
//! est nommé, compressé et déposé comme la RFC le demande. Et surtout : **qu'une
//! destination qui n'a pas consenti n'y figure pas**, parce que sans ce contrôle
//! DMARC serait un amplificateur, et non une protection.

mod commun;

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;

use ams_dmarc::report::aggregate::{DkimAuthResult, SpfAuthResult, SpfScope};
use ams_dmarc::{Alignment, Policy, Verdict};
use ams_loop_tokio::{Observation, PolitiqueLue, ReportSpool, Resolver, SignatureVue, SpfVu};
use commun::resolveur_par_nom;
use core::time::Duration;

/// Un dossier de dépôt qui n'appartient qu'à ce test.
fn dossier(nom: &str) -> PathBuf {
    let chemin = std::env::temp_dir().join(std::format!(
        "ams-rapports-{nom}-{}-{}",
        std::process::id(),
        nom.len()
    ));
    let _ = std::fs::remove_dir_all(&chemin);
    chemin
}

/// La politique la plus ordinaire.
fn politique() -> PolitiqueLue {
    PolitiqueLue {
        dkim_alignment: Alignment::Relaxed,
        spf_alignment: Alignment::Relaxed,
        policy: Policy::None,
        subdomain_policy: None,
        percent: 100,
    }
}

/// Une observation, paramétrée par ce qui la distingue d'une autre.
fn observation(source: [u8; 4], destinations: &str) -> Observation {
    Observation {
        domain: std::string::String::from("example.com"),
        published: politique(),
        destinations: std::string::String::from(destinations),
        source: IpAddr::V4(Ipv4Addr::from(source)),
        disposition: Policy::None,
        dkim: Verdict::Fail,
        spf: Verdict::Pass,
        envelope_from: Some(std::string::String::from("example.com")),
        signatures: std::vec![SignatureVue {
            domain: std::string::String::from("example.com"),
            selector: std::string::String::from("selecteur"),
            result: DkimAuthResult::Fail,
        }],
        spf_auth: SpfVu {
            domain: std::string::String::from("example.com"),
            scope: SpfScope::MailFrom,
            result: SpfAuthResult::Pass,
        },
    }
}

/// Ouvre un journal branché sur un DNS d'épreuve.
async fn journal(
    nom: &str,
    table: &'static [(&'static str, &'static str)],
) -> (Arc<ReportSpool>, PathBuf) {
    let adresse = resolveur_par_nom(table).await;
    let dossier = dossier(nom);
    let spool = ReportSpool::new(
        std::string::String::from("mail.receveur.test"),
        std::string::String::from("dmarc@receveur.test"),
        dossier.clone(),
        Resolver::new(std::vec![adresse], Duration::from_secs(2)).expect("résolveur"),
    );
    (Arc::new(spool), dossier)
}

/// Décompresse le rapport déposé, et rend son XML.
fn lire_le_rapport(dossier: &PathBuf) -> (std::string::String, std::string::String) {
    use std::io::Read as _;

    let mut rapport = None;
    let mut destinations = std::string::String::new();
    for entree in std::fs::read_dir(dossier).expect("dossier lisible") {
        let chemin = entree.expect("entrée").path();
        let nom = chemin
            .file_name()
            .and_then(|brut| brut.to_str())
            .unwrap_or_default()
            .to_string();
        if nom.ends_with(".destinations") {
            destinations = std::fs::read_to_string(&chemin).expect("destinations lisibles");
        } else {
            let octets = std::fs::read(&chemin).expect("rapport lisible");
            let mut clair = std::string::String::new();
            flate2::read::GzDecoder::new(&octets[..])
                .read_to_string(&mut clair)
                .expect("le rapport est bien du gzip");
            rapport = Some((nom, clair));
        }
    }
    let (nom, xml) = rapport.expect("un rapport a été déposé");
    (std::format!("{nom}\n{xml}"), destinations)
}

// ── LE RAPPORT DIT CE QUI S'EST PASSÉ ───────────────────────────────────────

#[tokio::test]
async fn un_rapport_est_compose_nomme_compresse_et_depose() {
    let (spool, dossier) = journal("depose", &[]).await;
    assert!(!spool.en_attente());
    spool.observer(observation([192, 0, 2, 1], ""));
    assert!(spool.en_attente());

    let compte = spool.vider().await;
    assert_eq!(compte.reports, 1);
    assert_eq!(compte.rows, 1);
    assert!(!spool.en_attente(), "la période s'est refermée");

    let (tout, _) = lire_le_rapport(&dossier);
    // Le NOM suit §7.2.1.1, et l'extension ne ment pas sur le contenu.
    assert!(
        tout.starts_with("mail.receveur.test!example.com!"),
        "{tout}"
    );
    assert!(
        tout.lines()
            .next()
            .is_some_and(|nom| nom.ends_with(".xml.gz")),
        "{tout}"
    );
    for morceau in [
        "<feedback>",
        "<org_name>mail.receveur.test</org_name>",
        "<email>dmarc@receveur.test</email>",
        "<domain>example.com</domain>",
        "<source_ip>192.0.2.1</source_ip>",
        "<count>1</count>",
        "<disposition>none</disposition>",
        "<selector>selecteur</selector>",
        "<header_from>example.com</header_from>",
    ] {
        assert!(tout.contains(morceau), "{morceau} manque dans :\n{tout}");
    }
    let _ = std::fs::remove_dir_all(&dossier);
}

/// **Deux messages qui se ressemblent ne font qu'une ligne**, et c'est ce qui
/// garantit qu'un rapport ne dit jamais rien d'un message en particulier.
#[tokio::test]
async fn ce_qui_se_ressemble_se_compte_ensemble() {
    let (spool, dossier) = journal("compte", &[]).await;
    for _ in 0..3 {
        spool.observer(observation([192, 0, 2, 1], ""));
    }
    spool.observer(observation([198, 51, 100, 7], ""));

    let compte = spool.vider().await;
    assert_eq!(compte.reports, 1, "un seul domaine, un seul rapport");
    assert_eq!(compte.rows, 2, "deux sources, deux lignes");

    let (tout, _) = lire_le_rapport(&dossier);
    assert_eq!(tout.matches("<record>").count(), 2);
    assert!(tout.contains("<count>3</count>"));
    assert!(tout.contains("<count>1</count>"));
    let _ = std::fs::remove_dir_all(&dossier);
}

#[tokio::test]
async fn un_journal_vide_ne_depose_rien() {
    let (spool, dossier) = journal("vide", &[]).await;
    let compte = spool.vider().await;
    assert_eq!(compte, Default::default());
    assert!(!dossier.exists(), "on ne crée pas un dossier pour rien");
}

// ── SANS CONSENTEMENT, PAS DE DESTINATION ───────────────────────────────────

/// La destination est **dans le domaine qui la demande** : rien à vérifier.
#[tokio::test]
async fn une_destination_chez_soi_est_retenue_sans_rien_demander() {
    let (spool, dossier) = journal("chez-soi", &[]).await;
    spool.observer(observation([192, 0, 2, 1], "mailto:dmarc@example.com"));
    let compte = spool.vider().await;
    assert_eq!(compte.destinations, 1);
    assert_eq!(compte.refused, 0);

    let (_, destinations) = lire_le_rapport(&dossier);
    assert_eq!(destinations, "dmarc@example.com\n");
    let _ = std::fs::remove_dir_all(&dossier);
}

/// **C'est ce contrôle qui empêche DMARC d'être une arme.** Sans lui, il
/// suffirait de publier `rua=mailto:victime@banque.test` sous un domaine qu'on
/// détient pour faire bombarder cette adresse par tous les receveurs du monde.
#[tokio::test]
async fn une_destination_externe_sans_consentement_est_ecartee() {
    let (spool, dossier) = journal("sans-consentement", &[]).await;
    spool.observer(observation([192, 0, 2, 1], "mailto:victime@banque.test"));
    let compte = spool.vider().await;
    assert_eq!(compte.destinations, 0, "personne n'a consenti");
    assert_eq!(compte.refused, 1);

    let (_, destinations) = lire_le_rapport(&dossier);
    assert!(
        destinations.is_empty(),
        "aucun fichier de destinations ne devrait exister : {destinations}"
    );
    let _ = std::fs::remove_dir_all(&dossier);
}

/// Le consentement se publie **sous le domaine de la destination**, à un nom que
/// celui qui la désigne ne peut pas écrire.
#[tokio::test]
async fn une_destination_externe_qui_consent_est_retenue() {
    const TABLE: &[(&str, &str)] = &[("example.com._report._dmarc.rapports.test", "v=DMARC1")];
    let (spool, dossier) = journal("consentement", TABLE).await;
    spool.observer(observation([192, 0, 2, 1], "mailto:collecte@rapports.test"));
    let compte = spool.vider().await;
    assert_eq!(compte.destinations, 1);
    assert_eq!(compte.refused, 0);

    let (_, destinations) = lire_le_rapport(&dossier);
    assert_eq!(destinations, "collecte@rapports.test\n");
    let _ = std::fs::remove_dir_all(&dossier);
}

/// Le consentement d'un domaine ne vaut **que pour celui qui l'a demandé**.
#[tokio::test]
async fn le_consentement_ne_vaut_que_pour_le_domaine_nomme() {
    const TABLE: &[(&str, &str)] = &[("autre.example._report._dmarc.rapports.test", "v=DMARC1")];
    let (spool, dossier) = journal("consentement-autrui", TABLE).await;
    spool.observer(observation([192, 0, 2, 1], "mailto:collecte@rapports.test"));
    let compte = spool.vider().await;
    assert_eq!(
        compte.refused, 1,
        "le consentement d'`autre.example` n'autorise pas `example.com`"
    );
    let _ = std::fs::remove_dir_all(&dossier);
}

/// Une taille maximale et une destination qu'on ne sait pas servir se lisent
/// sans faire tomber les autres.
#[tokio::test]
async fn une_liste_melangee_ne_retient_que_ce_qui_se_sert() {
    let (spool, dossier) = journal("melange", &[]).await;
    spool.observer(observation(
        [192, 0, 2, 1],
        "https://example.com/dmarc, mailto:dmarc@example.com!10m , pas-une-uri",
    ));
    let compte = spool.vider().await;
    assert_eq!(compte.destinations, 1, "seul le `mailto:` se sert");
    assert_eq!(compte.refused, 1, "`pas-une-uri` n'en est pas une");

    let (_, destinations) = lire_le_rapport(&dossier);
    assert_eq!(destinations, "dmarc@example.com\n");
    let _ = std::fs::remove_dir_all(&dossier);
}

// ── DE BOUT EN BOUT : UN MESSAGE REFUSÉ SE RAPPORTE COMME REFUSÉ ────────────

/// **On rapporte ce qu'on a FAIT, jamais ce qui était demandé.**
///
/// Un message que `p=reject` condamne et que ce serveur a refusé se rapporte
/// `reject` ; le même message, en observation, se rapporte `none` — parce qu'il
/// a été remis. Écrire `reject` dans ce second cas ferait croire à un domaine
/// qu'il est protégé là où il ne l'est pas, et c'est le seul mensonge qu'un
/// rapport ne peut pas se permettre.
async fn bout_en_bout(applique: bool, nom: &str) -> (std::string::String, std::string::String) {
    use ams_guard::Thresholds;
    use ams_loop_tokio::{DmarcChecker, Service, SharedGuard, Timeouts, serve_connection};
    use ams_proto_smtp::Limits;
    use ams_session::Config;
    use commun::{Neant, NotreDomaine, PAIR};
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    const TABLE: &[(&str, &str)] = &[(
        "_dmarc.example.com",
        "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
    )];
    let adresse_dns = resolveur_par_nom(TABLE).await;
    let dossier = dossier(nom);
    let spool = Arc::new(ReportSpool::new(
        std::string::String::from("mail.receveur.test"),
        std::string::String::from("dmarc@receveur.test"),
        dossier.clone(),
        Resolver::new(std::vec![adresse_dns], Duration::from_secs(2)).expect("résolveur"),
    ));
    let verificateur = DmarcChecker::new(
        Resolver::new(std::vec![adresse_dns], Duration::from_secs(2)).expect("résolveur"),
        Arc::new(b"com\nnet\n".to_vec()),
        applique,
    );

    let ecouteur = TcpListener::bind("127.0.0.1:0").await.expect("écoute");
    let adresse = ecouteur.local_addr().expect("adresse");
    let pour_le_service = Arc::clone(&spool);
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
            dmarc: Some(verificateur),
            reports: Some(pour_le_service),
        };
        serve_connection(&mut flux, &service, NotreDomaine, &mut Neant, PAIR).await
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
    let corps = "From: Joe SixPack <joe@example.com>\r\n\
                 Subject: je ne suis pas Joe\r\n\r\n\
                 Bonjour.\r\n.\r\n";
    lecteur
        .get_mut()
        .write_all(corps.as_bytes())
        .await
        .expect("corps");
    ligne.clear();
    lecteur.read_line(&mut ligne).await.expect("fin");
    drop(lecteur);
    serveur.await.expect("tâche").expect("servie");

    let compte = spool.vider().await;
    assert_eq!(compte.reports, 1, "un message vu, un rapport déposé");
    let (tout, destinations) = lire_le_rapport(&dossier);
    let _ = std::fs::remove_dir_all(&dossier);
    (std::format!("{ligne}{tout}"), destinations)
}

#[tokio::test]
async fn un_message_refuse_se_rapporte_refuse() {
    let (tout, destinations) = bout_en_bout(true, "bout-refus").await;
    assert!(tout.starts_with("550 5.7.1"), "{tout}");
    assert!(tout.contains("<disposition>reject</disposition>"), "{tout}");
    assert!(tout.contains("<dkim>fail</dkim>"), "{tout}");
    assert!(tout.contains("<spf>fail</spf>"), "{tout}");
    // Le `p=` rapporté est celui qu'on a LU dans la zone.
    assert!(tout.contains("<p>reject</p>"), "{tout}");
    // La destination est dans le domaine qui la demande : rien à vérifier.
    assert_eq!(destinations, "dmarc@example.com\n");
}

#[tokio::test]
async fn en_observation_le_meme_message_se_rapporte_remis() {
    let (tout, _) = bout_en_bout(false, "bout-observe").await;
    assert!(tout.starts_with("250"), "{tout}");
    assert!(
        tout.contains("<disposition>none</disposition>"),
        "un message remis se rapporte remis :\n{tout}"
    );
    assert!(tout.contains("<p>reject</p>"), "{tout}");
}
