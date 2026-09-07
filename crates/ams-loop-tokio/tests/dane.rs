// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **DANE, de la question DNS jusqu'à la poignée de main** (RFC 7672).
//!
//! # Ce que ces épreuves ferment
//!
//! `ams-dane` — l'analyse d'un `TLSA`, le choix d'un ensemble, l'extraction du
//! `SubjectPublicKeyInfo` — est couvert à 100 %, et `ams-tls` éprouve le
//! vérificateur qui s'en sert. Ce qui DÉCIDE d'engager DANE ne l'était par rien :
//! `Relay::dane_pour` interroge le `_25._tcp.<hôte>`, exige que la réponse ET le
//! `MX` soient authentiques, et n'engage que si l'ensemble le permet.
//!
//! Aucun essai n'y touchait, et le résolveur d'épreuve ne savait pas même
//! répondre un `TLSA` ni poser le bit `AD`. Il le sait depuis le 2026-09-07.
//!
//! # Le condensat est calculé HORS de ce dépôt
//!
//! Le `TLSA` publié ici porte un condensat du `SubjectPublicKeyInfo` du
//! certificat, calculé par `openssl` :
//!
//! ```text
//! openssl x509 -inform DER -pubkey -noout | openssl pkey -pubin -outform DER \
//!     | openssl dgst -sha256 -binary
//! ```
//!
//! Le fabriquer avec notre propre extraction de `SPKI` ferait une épreuve
//! circulaire : elle passerait aussi bien si cette extraction était fausse, du
//! moment qu'elle l'est deux fois.

mod commun;

use ams_guard::Thresholds;
use ams_loop_tokio::{
    Delivery, DeliveryFailure, Outgoing, Relay, RelayOutcome, Resolver, Service, SharedGuard,
    Timeouts, serve_connection,
};
use ams_proto_smtp::Limits;
use ams_session::{Capabilities, Config};
use commun::{Enregistrement, Materiel, NotreDomaine, PAIR, materiel, resolveur_courrier_signe};
use core::time::Duration;
use std::process::Command;
use std::sync::{Arc, Mutex};
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

const CORPS: &[u8] = b"From: nous@nous.test\r\n\
                       To: marie@example.com\r\n\
                       Subject: essai DANE\r\n\
                       \r\n\
                       Bonjour.\r\n";

fn message(destinataires: &[std::string::String]) -> Outgoing<'_> {
    Outgoing {
        sender: "nous@nous.test",
        recipients: destinataires,
        body: CORPS,
        dsn: None,
    }
}

/// Le `TLSA` `3 1 1` du certificat de `materiel`, calculé par `openssl`.
///
/// Rend `None` si `openssl` refuse : l'épreuve se saute alors, en le disant.
fn tlsa_du_certificat(materiel: &Materiel) -> Option<std::vec::Vec<u8>> {
    let cert = materiel.repertoire.join("cert.der");
    let extrait = Command::new("openssl")
        .args(["x509", "-inform", "DER", "-pubkey", "-noout"])
        .arg("-in")
        .arg(&cert)
        .output()
        .ok()?;
    if !extrait.status.success() {
        return None;
    }
    let spki = materiel.repertoire.join("spki.der");
    let pem = materiel.repertoire.join("spki.pem");
    std::fs::write(&pem, &extrait.stdout).ok()?;
    let converti = Command::new("openssl")
        .args(["pkey", "-pubin", "-outform", "DER"])
        .arg("-in")
        .arg(&pem)
        .arg("-out")
        .arg(&spki)
        .output()
        .ok()?;
    if !converti.status.success() {
        return None;
    }
    let condense = Command::new("openssl")
        .args(["dgst", "-sha256", "-binary"])
        .arg(&spki)
        .output()
        .ok()?;
    if !condense.status.success() || condense.stdout.len() != 32 {
        return None;
    }
    // usage 3 (DANE-EE), sélecteur 1 (SPKI), correspondance 1 (SHA-256).
    let mut rdata = std::vec![3_u8, 1, 1];
    rdata.extend_from_slice(&condense.stdout);
    Some(rdata)
}

/// Un `TLSA` de même forme, mais dont le condensat ne désigne RIEN.
fn tlsa_qui_ne_correspond_a_rien() -> std::vec::Vec<u8> {
    let mut rdata = std::vec![3_u8, 1, 1];
    rdata.extend_from_slice(&[0xAA; 32]);
    rdata
}

/// Monte un serveur qui annonce `STARTTLS`, et rend ce qu'il a reçu.
async fn serveur(chiffrement: Arc<rustls::ServerConfig>) -> (std::net::SocketAddr, Cahier) {
    let ecouteur = TcpListener::bind("127.0.0.1:0").await.expect("écoute");
    let adresse = ecouteur.local_addr().expect("adresse");
    let cahier = Cahier::default();
    let sien = cahier.clone();
    tokio::spawn(async move {
        while let Ok((mut flux, _)) = ecouteur.accept().await {
            let garde = SharedGuard::new(4, Thresholds::DEFAULT);
            let mut remise = sien.clone();
            let service = Service {
                config: Config::new(b"mx.eux.test", 100, 10_485_760, Limits::DEFAULT)
                    .expect("configurable")
                    .with_capabilities(Capabilities {
                        starttls: true,
                        auth: false,
                        dsn: false,
                    }),
                guard: &garde,
                timeouts: Timeouts::default(),
                tls: Some(Arc::clone(&chiffrement)),
                spf: None,
                dkim: None,
                dmarc: None,
                reports: None,
            };
            let _ = serve_connection(&mut flux, &service, NotreDomaine, &mut remise, PAIR).await;
        }
    });
    (adresse, cahier)
}

/// La zone d'épreuve : un `MX`, son adresse, et le `TLSA` demandé.
fn zone(tlsa: Option<std::vec::Vec<u8>>) -> std::vec::Vec<(std::string::String, Enregistrement)> {
    let mut table = std::vec![
        (
            std::string::String::from("eux.test"),
            Enregistrement::Mx(10, "mx.eux.test"),
        ),
        (
            std::string::String::from("mx.eux.test"),
            Enregistrement::A([127, 0, 0, 1]),
        ),
    ];
    if let Some(rdata) = tlsa {
        table.push((
            std::string::String::from("_25._tcp.mx.eux.test"),
            Enregistrement::Tlsa(rdata),
        ));
    }
    // **LE DOMAINE DEMANDE DES RAPPORTS.** §3 de RFC 8460 : sans `_smtp._tls`,
    // rien n'est déposé, et le journal ne dirait rien de ce qui a gouverné la
    // remise. C'est ce qui a fait échouer la première écriture de ces épreuves.
    table.push((
        std::string::String::from("_smtp._tls.eux.test"),
        Enregistrement::Txt("v=TLSRPTv1; rua=mailto:tls@eux.test"),
    ));
    table
}

/// Un journal TLSRPT dans un dossier neuf.
///
/// **C'EST LUI QUI REND L'ENGAGEMENT VISIBLE.** Sans ce journal, l'épreuve
/// positive serait faible : une remise qui RÉUSSIT réussirait tout autant si
/// DANE ne s'était pas engagé et que le chiffrement était redevenu
/// opportuniste. Le rapport, lui, écrit `"policy-type": "tlsa"` — et il ne
/// l'écrit que si `dane.is_some()`.
fn journal(
    nom: &str,
    dns: std::net::SocketAddr,
) -> (Arc<ams_loop_tokio::TlsReports>, std::path::PathBuf) {
    let dossier = std::env::temp_dir().join(std::format!(
        "ams-dane-rapports-{nom}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dossier);
    std::fs::create_dir_all(&dossier).expect("dossier de rapports");
    let rapports = ams_loop_tokio::TlsReports::new(
        std::string::String::from("nous"),
        std::string::String::from("tlsrpt@nous.test"),
        std::string::String::from("127.0.0.1"),
        dossier.clone(),
        // LE MÊME résolveur que la remise : c'est lui qui porte le
        // `_smtp._tls` du domaine.
        Resolver::new(std::vec![dns], Duration::from_secs(2)).expect("résolveur"),
        Duration::from_secs(2),
    );
    (Arc::new(rapports), dossier)
}

/// Le genre de politique que le journal a retenu, une fois vidé sur le disque.
async fn genre_rapporte(
    rapports: &Arc<ams_loop_tokio::TlsReports>,
    dossier: &std::path::Path,
) -> std::string::String {
    rapports.vider().await;
    // **LE RAPPORT EST GZIPPÉ** (§3 de RFC 8460), et son voisin en clair ne
    // porte que les destinations. Lire le dossier sans décomprimer rendait
    // « mailto:tls@eux.test » — ce qui n'est pas faux, mais ne dit rien du genre
    // de politique. C'est ce qui a fait échouer la deuxième écriture de ces
    // épreuves.
    let mut tout = std::string::String::new();
    for entree in std::fs::read_dir(dossier)
        .expect("dossier lisible")
        .flatten()
    {
        let Ok(octets) = std::fs::read(entree.path()) else {
            continue;
        };
        let mut decomprime = std::vec::Vec::new();
        let mut lecteur = flate2::read::GzDecoder::new(&octets[..]);
        if std::io::Read::read_to_end(&mut lecteur, &mut decomprime).is_ok()
            && let Ok(texte) = std::string::String::from_utf8(decomprime)
        {
            tout.push_str(&texte);
        }
    }
    tout
}

fn remetteur(dns: std::net::SocketAddr, port: u16) -> Relay {
    Relay::new(
        Resolver::new(std::vec![dns], Duration::from_secs(2)).expect("résolveur"),
        Arc::new(ams_tls::relay_config()),
        std::string::String::from("mail.nous.test"),
        // **`exige_tls` RESTE FAUX**, et c'est le point : ce qui rend le
        // chiffrement obligatoire dans ces épreuves est le `TLSA`, pas un
        // réglage. §2.2 de RFC 7672 ne laisse pas le choix.
        false,
        Duration::from_secs(5),
    )
    .with_port(port)
}

/// **UN `TLSA` QUI CORRESPOND LAISSE PASSER LE COURRIER.**
#[tokio::test]
async fn un_tlsa_qui_correspond_remet_le_courrier() {
    let Some(atelier) = materiel("dane-juste") else {
        return;
    };
    let Some(tlsa) = tlsa_du_certificat(&atelier) else {
        eprintln!("SAUTÉ : `openssl` n'a pas su condenser le SPKI.");
        return;
    };
    let (adresse, recu) = serveur(Arc::clone(&atelier.tls)).await;
    let dns = resolveur_courrier_signe(zone(Some(tlsa)), true).await;
    let (rapports, dossier) = journal("juste", dns);
    let remetteur = remetteur(dns, adresse.port()).with_tls_reports(Arc::clone(&rapports));

    let destinataires = std::vec![std::string::String::from("marie@example.com")];
    let issue = remetteur.send("eux.test", &message(&destinataires)).await;

    assert!(
        matches!(issue, RelayOutcome::Delivered { .. }),
        "la remise a échoué : {issue:?}"
    );
    let vu = recu.0.lock().expect("verrou").clone();
    assert!(
        vu.windows(11).any(|f| f == b"essai DANE\r"),
        "le message n'est pas arrivé"
    );

    // **ET DANE S'EST BIEN ENGAGÉ.** Une remise réussie ne le dirait pas : elle
    // réussirait tout autant en opportuniste. Le rapport, lui, ne porte `tlsa`
    // que si un `TLSA` a gouverné la poignée de main.
    let rapporte = genre_rapporte(&rapports, &dossier).await;
    assert!(
        rapporte.contains("\"tlsa\""),
        "le rapport ne dit pas que DANE a gouverné : {rapporte:.400}"
    );
    let _ = std::fs::remove_dir_all(&dossier);
}

/// **UN `TLSA` QUI NE CORRESPOND PAS FAIT RENONCER, ET NE RETOMBE PAS EN CLAIR.**
///
/// C'est tout l'objet de DANE. Un remetteur qui, faute de correspondance,
/// réessaierait sans chiffrement offrirait à l'attaquant exactement ce qu'il
/// cherche : il lui suffirait de casser la poignée de main.
#[tokio::test]
async fn un_tlsa_qui_ne_correspond_pas_fait_renoncer() {
    let Some(atelier) = materiel("dane-faux") else {
        return;
    };
    let (adresse, recu) = serveur(Arc::clone(&atelier.tls)).await;
    let dns = resolveur_courrier_signe(zone(Some(tlsa_qui_ne_correspond_a_rien())), true).await;
    let remetteur = remetteur(dns, adresse.port());

    let destinataires = std::vec![std::string::String::from("marie@example.com")];
    let issue = remetteur.send("eux.test", &message(&destinataires)).await;

    assert!(
        !matches!(issue, RelayOutcome::Delivered { .. }),
        "le courrier est parti malgré un `TLSA` qui ne correspond pas : {issue:?}"
    );
    assert!(
        recu.0.lock().expect("verrou").is_empty(),
        "le serveur a reçu quelque chose"
    );
}

/// **SANS BIT `AD`, DANE NE S'ENGAGE PAS** (§2.1 de RFC 7672).
///
/// Le `TLSA` est le bon ; c'est la RÉPONSE qui n'est pas authentique. Un
/// attaquant capable de forger du DNS pourrait sans cela publier un `TLSA` à
/// lui — ou le retirer.
///
/// Ici, le retrait ne coûte rien : le `TLSA` correspond, la remise passe. Ce que
/// l'épreuve montre est que la remise passe **sans DANE**, et c'est l'épreuve
/// suivante qui le rend visible.
#[tokio::test]
async fn sans_bit_ad_dane_ne_s_engage_pas() {
    let Some(atelier) = materiel("dane-non-signe") else {
        return;
    };
    let (adresse, _) = serveur(Arc::clone(&atelier.tls)).await;
    // Le `TLSA` NE CORRESPOND PAS, et pourtant la remise doit passer : puisque
    // la réponse n'est pas authentique, DANE n'est pas engagé, et le
    // chiffrement redevient opportuniste.
    let dns = resolveur_courrier_signe(zone(Some(tlsa_qui_ne_correspond_a_rien())), false).await;
    let remetteur = remetteur(dns, adresse.port());

    let destinataires = std::vec![std::string::String::from("marie@example.com")];
    let issue = remetteur.send("eux.test", &message(&destinataires)).await;

    assert!(
        matches!(issue, RelayOutcome::Delivered { .. }),
        "sans bit `AD`, DANE ne devait pas s'engager : {issue:?}"
    );
}

/// **UN `MX` AUTHENTIQUE NE SUFFIT PAS : LE `TLSA` DOIT L'ÊTRE AUSSI** (§2.1).
///
/// # Le trou que cette épreuve ferme, et comment il s'est vu
///
/// Les quatre premières épreuves montaient une zone ENTIÈREMENT signée ou
/// ENTIÈREMENT non signée. Aucune ne distinguait donc les DEUX contrôles de
/// `dane_pour` : celui du `MX` et celui du `TLSA`. Retirer le second du produit
/// ne faisait tomber AUCUNE d'elles — ce qu'a montré la confrontation, et non la
/// relecture.
///
/// C'est pourtant l'attaque que ce contrôle arrête : un pair capable de forger
/// la réponse `TLSA` seule publierait un condensat à lui, ou la retirerait.
///
/// Ici le `TLSA` ne correspond PAS et sa réponse n'est pas authentique : la
/// remise doit passer quand même, parce que DANE ne s'engage pas. Si le
/// contrôle disparaissait, elle échouerait — le condensat ne correspond à rien.
#[tokio::test]
async fn un_tlsa_non_authentique_n_engage_pas_dane() {
    let Some(atelier) = materiel("dane-tlsa-non-signe") else {
        return;
    };
    let (adresse, _) = serveur(Arc::clone(&atelier.tls)).await;
    let mut table = zone(None);
    table.push((
        std::string::String::from("_25._tcp.mx.eux.test"),
        Enregistrement::TlsaNonSigne(tlsa_qui_ne_correspond_a_rien()),
    ));
    // Le reste de la zone EST authentique : le `MX` passe le premier contrôle.
    let dns = resolveur_courrier_signe(table, true).await;
    let remetteur = remetteur(dns, adresse.port());

    let destinataires = std::vec![std::string::String::from("marie@example.com")];
    let issue = remetteur.send("eux.test", &message(&destinataires)).await;

    assert!(
        matches!(issue, RelayOutcome::Delivered { .. }),
        "le `TLSA` n'était pas authentique : DANE ne devait pas s'engager, \
         et la remise devait passer — {issue:?}"
    );
}

/// **SANS `TLSA` DU TOUT, LA REMISE EST CE QU'ELLE ÉTAIT.**
///
/// C'est la moitié du courrier, et elle ne doit rien coûter de plus.
#[tokio::test]
async fn sans_tlsa_la_remise_reste_opportuniste() {
    let Some(atelier) = materiel("dane-absent") else {
        return;
    };
    let (adresse, recu) = serveur(Arc::clone(&atelier.tls)).await;
    let dns = resolveur_courrier_signe(zone(None), true).await;
    let (rapports, dossier) = journal("absent", dns);
    let remetteur = remetteur(dns, adresse.port()).with_tls_reports(Arc::clone(&rapports));

    let destinataires = std::vec![std::string::String::from("marie@example.com")];
    let issue = remetteur.send("eux.test", &message(&destinataires)).await;

    assert!(
        matches!(issue, RelayOutcome::Delivered { .. }),
        "sans `TLSA`, la remise aurait dû passer : {issue:?}"
    );
    assert!(!recu.0.lock().expect("verrou").is_empty());

    // **ET LE RAPPORT DIT QU'AUCUNE POLITIQUE N'A GOUVERNÉ.** C'est le pendant
    // de l'épreuve positive : les deux lisent le même champ, et il diffère.
    let rapporte = genre_rapporte(&rapports, &dossier).await;
    assert!(
        rapporte.contains("no-policy-found"),
        "le rapport devrait dire qu'il n'y avait pas de politique : {rapporte:.400}"
    );
    assert!(!rapporte.contains("\"tlsa\""), "{rapporte:.400}");
    let _ = std::fs::remove_dir_all(&dossier);
}
