// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que les tests d'intégration de cette crate se partagent.
//!
//! Monter un service chiffré demande un certificat, une politique et une remise.
//! Les recopier dans chaque fichier ferait diverger trois copies d'un même
//! montage — et la première qui divergerait serait celle qu'on ne relit plus.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use ams_guard::Source;
use ams_loop_tokio::{Delivery, DeliveryFailure};
use ams_proto_smtp::{Limits, Path as SmtpPath};
use ams_session::{Capabilities, Config, Policy, RecipientVerdict};
use rustls::ServerConfig;

// ── De quoi monter un service ───────────────────────────────────────────────

/// Le seul compte que la politique de test connaisse.
pub const COMPTE: &[u8] = b"jean";
/// Son mot de passe.
pub const SECRET: &[u8] = b"ouvre-toi";

/// N'accepte que ce que ce serveur héberge, et ne connaît qu'un compte.
pub struct NotreDomaine;

impl ams_session::Authenticator for NotreDomaine {
    /// Une comparaison de TEST, et elle n'est pas à temps constant.
    ///
    /// Une vraie politique doit l'être — voir la documentation du trait. Ici, le
    /// seul secret est dans ce fichier, et le mesurer ne rapporterait rien.
    fn authenticate(&self, credentials: &ams_sasl::Credentials<'_>) -> bool {
        credentials.authentication_identity == COMPTE && credentials.password == SECRET
    }
}

impl Policy for NotreDomaine {
    fn accepts_recipient(&self, forward_path: &SmtpPath<'_>) -> RecipientVerdict {
        match forward_path {
            SmtpPath::Mailbox(boite) if boite.domain().as_bytes() == b"example.com" => {
                RecipientVerdict::Accept
            }
            _ => RecipientVerdict::RelayDenied,
        }
    }
}

/// Une remise qui ne garde rien : ces tests parlent du chiffrement.
pub struct Neant;

impl Delivery for Neant {
    fn add_recipient(&mut self, _address: &[u8]) -> Result<(), DeliveryFailure> {
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

pub const PAIR: Source = Source::V4([127, 0, 0, 1]);

pub fn config(starttls: bool, auth: bool) -> Config<'static> {
    Config::new(b"mail.example.com", 100, 10_485_760, Limits::DEFAULT)
        .expect("configurable")
        .with_capabilities(Capabilities { starttls, auth })
}

// ── Le certificat, fabriqué à la volée ──────────────────────────────────────

/// Fabrique un certificat auto-signé, en DER pour n'avoir rien à analyser.
///
/// Rien n'est versionné : une clé privée dans un dépôt, même de test, reste une
/// clé privée dans un dépôt.
pub fn certificat(repertoire: &Path) -> Option<(PathBuf, PathBuf)> {
    let cle_pem = repertoire.join("cle.pem");
    let cert = repertoire.join("cert.der");
    let cle = repertoire.join("cle.der");

    let genere = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "ec"])
        .args(["-pkeyopt", "ec_paramgen_curve:P-256"])
        .args(["-nodes", "-days", "1", "-subj", "/CN=localhost"])
        .arg("-keyout")
        .arg(&cle_pem)
        .args(["-outform", "DER"])
        .arg("-out")
        .arg(&cert)
        .output()
        .ok()?;
    if !genere.status.success() {
        return None;
    }
    let convertie = Command::new("openssl")
        .args(["pkcs8", "-topk8", "-nocrypt"])
        .arg("-in")
        .arg(&cle_pem)
        .args(["-outform", "DER"])
        .arg("-out")
        .arg(&cle)
        .output()
        .ok()?;
    convertie.status.success().then_some((cert, cle))
}

/// Le répertoire de travail d'un test, et sa configuration TLS.
pub struct Materiel {
    pub repertoire: PathBuf,
    pub tls: Arc<ServerConfig>,
}

impl Drop for Materiel {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.repertoire);
    }
}

/// Monte de quoi chiffrer, ou explique pourquoi le test se saute.
pub fn materiel(nom: &str) -> Option<Materiel> {
    let repertoire =
        std::env::temp_dir().join(format!("ams-starttls-{nom}-{}", std::process::id()));
    std::fs::create_dir_all(&repertoire).expect("répertoire temporaire");
    let Some((chemin_cert, chemin_cle)) = certificat(&repertoire) else {
        let _ = std::fs::remove_dir_all(&repertoire);
        eprintln!("SAUTÉ : `openssl` n'a pas su fabriquer de certificat pour {nom}.");
        return None;
    };

    let cert = rustls::pki_types::CertificateDer::from(
        std::fs::read(&chemin_cert).expect("certificat lisible"),
    );
    let cle = rustls::pki_types::PrivateKeyDer::try_from(
        std::fs::read(&chemin_cle).expect("clé lisible"),
    )
    .expect("clé PKCS#8");

    // NOTRE fournisseur, celui de `ams-tls` : TLS 1.3 seul, groupe hybride en
    // tête. La boucle n'en construit aucun — elle reçoit celui-ci tout fait.
    let tls = ServerConfig::builder_with_provider(Arc::new(ams_tls::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(vec![cert], cle)
        .expect("certificat accepté");

    Some(Materiel {
        repertoire,
        tls: Arc::new(tls),
    })
}
