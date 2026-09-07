// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Le relais de sortie** : tout ce qui part passe par lui (RFC 4954).
//!
//! # Ce que ces épreuves gardent
//!
//! Beaucoup de machines n'émettent pas en direct — parce que leur adresse n'a
//! pas d'histoire, ou parce que la délivrabilité se loue. Elles confient alors
//! leur courrier à un service qui l'expédie sous SA réputation, et
//! s'authentifient auprès de lui. C'est le `relayhost` de Postfix.
//!
//! Trois choses ne doivent JAMAIS arriver, et chacune a son épreuve :
//!
//! - que le mot de passe sorte en clair ;
//! - qu'on remette à un relais dont on n'a pas vérifié le certificat ;
//! - qu'un refus d'authentification RENDE les messages à leurs expéditeurs,
//!   qui n'y sont pour rien.

mod commun;

use ams_loop_tokio::{Outgoing, Relay, RelayOutcome, Relayhost, Resolver};
use commun::{Enregistrement, resolveur_courrier_signe};
use core::time::Duration;
use std::process::Command;
use std::sync::Arc;

const CORPS: &[u8] = b"From: jean@nous.test\r\n\
                       To: marie@ailleurs.test\r\n\
                       Subject: par le relais\r\n\
                       \r\n\
                       Bonjour.\r\n";

/// Le certificat du relais, et de quoi le VÉRIFIER.
struct Materiel {
    repertoire: std::path::PathBuf,
    tls: Arc<rustls::ClientConfig>,
}

impl Drop for Materiel {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.repertoire);
    }
}

/// Fabrique une AUTORITÉ, un certificat qu'elle signe au nom du relais, et le
/// magasin qui croit cette autorité.
///
/// **Une autorité, et pas un certificat auto-signé.** Un auto-signé sans
/// `basicConstraints CA:TRUE` n'est pas une ancre de confiance recevable, et la
/// poignée de main échoue pour une raison qui n'a rien à voir avec ce qu'on
/// éprouve. C'est le même montage que les épreuves MTA-STS.
fn materiel(cas: &str, nom: &str) -> Option<Materiel> {
    let repertoire = std::env::temp_dir().join(std::format!(
        "ams-relayhost-{cas}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&repertoire);
    std::fs::create_dir_all(&repertoire).ok()?;
    let ca_cle = repertoire.join("ca.key");
    let ca_cert = repertoire.join("ca.pem");
    let ca_der = repertoire.join("ca.der");
    let cle = repertoire.join("k.pem");
    let demande = repertoire.join("d.csr");
    let cert = repertoire.join("c.pem");
    let extensions = repertoire.join("ext.cnf");
    std::fs::write(&extensions, std::format!("subjectAltName=DNS:{nom}\n")).ok()?;

    let ok = |commande: &mut Command| commande.output().ok().is_some_and(|s| s.status.success());

    if !ok(Command::new("openssl")
        .args(["req", "-x509", "-newkey", "ec"])
        .args(["-pkeyopt", "ec_paramgen_curve:P-256"])
        .args(["-nodes", "-days", "1", "-subj", "/CN=autorite-d-epreuve"])
        .arg("-keyout")
        .arg(&ca_cle)
        .arg("-out")
        .arg(&ca_cert))
    {
        return None;
    }
    if !ok(Command::new("openssl")
        .args(["x509", "-outform", "DER"])
        .arg("-in")
        .arg(&ca_cert)
        .arg("-out")
        .arg(&ca_der))
    {
        return None;
    }
    if !ok(Command::new("openssl")
        .args(["req", "-newkey", "ec"])
        .args(["-pkeyopt", "ec_paramgen_curve:P-256"])
        .args(["-nodes", "-subj", &std::format!("/CN={nom}")])
        .arg("-keyout")
        .arg(&cle)
        .arg("-out")
        .arg(&demande))
    {
        return None;
    }
    if !ok(Command::new("openssl")
        .args(["x509", "-req", "-days", "1"])
        .arg("-in")
        .arg(&demande)
        .arg("-CA")
        .arg(&ca_cert)
        .arg("-CAkey")
        .arg(&ca_cle)
        .arg("-extfile")
        .arg(&extensions)
        .arg("-out")
        .arg(&cert))
    {
        return None;
    }

    let mut magasin = rustls::RootCertStore::empty();
    magasin
        .add(rustls::pki_types::CertificateDer::from(
            std::fs::read(&ca_der).ok()?,
        ))
        .ok()?;
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(ams_tls::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .ok()?
        .with_root_certificates(magasin)
        .with_no_client_auth();
    Some(Materiel {
        repertoire,
        tls: Arc::new(tls),
    })
}

/// Monte le faux relais, et rend son port.
///
/// `mode` vaut `ok`, `refuse` — il rejette les identifiants — ou `sans-auth` :
/// il n'annonce pas `AUTH`.
fn relais(atelier: &Materiel, mode: &str) -> Option<(u16, std::process::Child)> {
    let script = atelier.repertoire.join("relais.py");
    std::fs::write(&script, include_str!("relais.py")).ok()?;
    // Le port est choisi par le noyau, et le script l'imprime.
    let mut enfant = Command::new("python3")
        .arg(&script)
        .arg("0")
        .arg(atelier.repertoire.join("c.pem"))
        .arg(atelier.repertoire.join("k.pem"))
        .arg(mode)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    let sortie = enfant.stdout.as_mut()?;
    let mut lue = std::string::String::new();
    {
        use std::io::Read as _;
        let mut octet = [0_u8; 1];
        while sortie.read(&mut octet).ok()? == 1 {
            if octet[0] == b'\n' {
                break;
            }
            lue.push(char::from(octet[0]));
        }
    }
    let port = lue.rsplit(':').next()?.trim().parse().ok()?;
    Some((port, enfant))
}

fn remetteur(dns: std::net::SocketAddr) -> Relay {
    Relay::new(
        Resolver::new(std::vec![dns], Duration::from_secs(2)).expect("résolveur"),
        Arc::new(ams_tls::relay_config()),
        std::string::String::from("mail.nous.test"),
        false,
        Duration::from_secs(5),
    )
}

fn zone() -> std::vec::Vec<(std::string::String, Enregistrement)> {
    std::vec![(
        std::string::String::from("relais.essai.test"),
        Enregistrement::A([127, 0, 0, 1]),
    )]
}

fn message(destinataires: &[std::string::String]) -> Outgoing<'_> {
    Outgoing {
        sender: "jean@nous.test",
        recipients: destinataires,
        body: CORPS,
        dsn: None,
    }
}

fn hote(atelier: &Materiel, port: u16, mot: &str) -> Arc<Relayhost> {
    Arc::new(Relayhost {
        host: std::string::String::from("relais.essai.test"),
        port,
        implicit_tls: true,
        user: std::string::String::from("jean"),
        password: std::string::String::from(mot),
        tls: Arc::clone(&atelier.tls),
    })
}

/// **LE COURRIER PART PAR LE RELAIS, APRÈS S'ÊTRE AUTHENTIFIÉ.**
#[tokio::test]
async fn le_relais_recoit_le_courrier_apres_authentification() {
    let Some(atelier) = materiel("juste", "relais.essai.test") else {
        eprintln!("SAUTÉ : `openssl` n'a pas su fabriquer de certificat.");
        return;
    };
    let Some((port, mut enfant)) = relais(&atelier, "ok") else {
        eprintln!("SAUTÉ : le relais d'épreuve n'a pas démarré.");
        return;
    };
    let dns = resolveur_courrier_signe(zone(), false).await;
    let remetteur = remetteur(dns).with_relayhost(hote(&atelier, port, "secret"));

    let destinataires = std::vec![std::string::String::from("marie@ailleurs.test")];
    let issue = remetteur
        .send("ailleurs.test", &message(&destinataires))
        .await;
    let _ = enfant.kill();

    assert!(
        matches!(
            issue,
            RelayOutcome::Delivered {
                accepted: 1,
                encrypted: true,
                ..
            }
        ),
        "le relais n'a pas pris le message : {issue:?}"
    );
}

/// **UN MOT DE PASSE REFUSÉ AJOURNE, ET NE REND RIEN.**
///
/// Le message n'y est pour rien : c'est notre configuration. Le rendre à son
/// expéditeur ferait payer à un utilisateur une faute qu'il ne peut pas
/// corriger — et une fois rendu, il ne revient pas.
#[tokio::test]
async fn un_mot_de_passe_refuse_ajourne_le_message() {
    let Some(atelier) = materiel("refus", "relais.essai.test") else {
        return;
    };
    let Some((port, mut enfant)) = relais(&atelier, "refuse") else {
        return;
    };
    let dns = resolveur_courrier_signe(zone(), false).await;
    let remetteur = remetteur(dns).with_relayhost(hote(&atelier, port, "secret"));

    let destinataires = std::vec![std::string::String::from("marie@ailleurs.test")];
    let issue = remetteur
        .send("ailleurs.test", &message(&destinataires))
        .await;
    let _ = enfant.kill();

    assert_eq!(
        issue,
        RelayOutcome::RelayAuth,
        "un refus d'authentification doit AJOURNER"
    );
}

/// **UN RELAIS QUI N'OFFRE PAS `AUTH` NE REÇOIT RIEN.**
///
/// On ne se rabat pas sur une remise anonyme : ce serait lui confier du courrier
/// sous une identité que personne n'a vérifiée.
#[tokio::test]
async fn un_relais_sans_auth_ne_recoit_rien() {
    let Some(atelier) = materiel("sans-auth", "relais.essai.test") else {
        return;
    };
    let Some((port, mut enfant)) = relais(&atelier, "sans-auth") else {
        return;
    };
    let dns = resolveur_courrier_signe(zone(), false).await;
    let remetteur = remetteur(dns).with_relayhost(hote(&atelier, port, "secret"));

    let destinataires = std::vec![std::string::String::from("marie@ailleurs.test")];
    let issue = remetteur
        .send("ailleurs.test", &message(&destinataires))
        .await;
    let _ = enfant.kill();

    assert_eq!(issue, RelayOutcome::RelayAuth);
}

/// **UN CERTIFICAT QU'ON NE CROIT PAS ARRÊTE TOUT**, avant le mot de passe.
///
/// C'est l'épreuve qui compte le plus. Postfix expédie par défaut sous
/// `smtp_tls_security_level = encrypt`, qui chiffre SANS vérifier — défendable
/// entre MTA, et pas ici : on présente un secret, et un pair qu'on n'a pas
/// identifié peut être n'importe qui.
#[tokio::test]
async fn un_relais_non_verifie_ne_recoit_pas_le_mot_de_passe() {
    let Some(atelier) = materiel("vrai", "relais.essai.test") else {
        return;
    };
    let Some(usurpateur) = materiel("faux", "relais.essai.test") else {
        return;
    };
    // Le relais sert le certificat de l'USURPATEUR ; on ne croit que le vrai.
    let Some((port, mut enfant)) = relais(&usurpateur, "ok") else {
        return;
    };
    let dns = resolveur_courrier_signe(zone(), false).await;
    let remetteur = remetteur(dns).with_relayhost(hote(&atelier, port, "secret"));

    let destinataires = std::vec![std::string::String::from("marie@ailleurs.test")];
    let issue = remetteur
        .send("ailleurs.test", &message(&destinataires))
        .await;
    let _ = enfant.kill();

    assert_eq!(
        issue,
        RelayOutcome::NoEncryption,
        "un certificat non vérifié a reçu notre mot de passe"
    );
}
