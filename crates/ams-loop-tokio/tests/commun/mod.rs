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

// ── Un résolveur DNS de test ────────────────────────────────────────────────

/// Monte un résolveur qui répond **le même `TXT`** à toute question `TXT`, et
/// « ce nom n'existe pas » au reste.
///
/// Une politique SPF ou une clé DKIM : c'est le même enregistrement pour qui
/// répond. Et c'est tout ce qu'il faut pour éprouver un CÂBLAGE — ce que le
/// résolveur sait faire de plus (`MX`, `PTR`, reprise en TCP, réponse usurpée)
/// est éprouvé chez lui, sur un montage qui en dit bien davantage.
pub async fn resolveur_txt(texte: &'static str) -> std::net::SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("socket UDP");
    let adresse = socket.local_addr().expect("adresse");
    tokio::spawn(async move {
        let mut recu = vec![0_u8; 2048];
        loop {
            let Ok((lus, pair)) = socket.recv_from(&mut recu).await else {
                return;
            };
            let question = recu.get(..lus).unwrap_or_default().to_vec();
            let Some((genre, fin)) = genre_et_fin(&question) else {
                continue;
            };
            let mut reponse = Vec::new();
            reponse.extend_from_slice(question.get(..2).unwrap_or_default());
            // Réponse, récursion disponible ; `NXDOMAIN` si ce n'est pas un TXT.
            let txt = genre == 16;
            let drapeaux: u16 = if txt { 0x8180 } else { 0x8183 };
            reponse.extend_from_slice(&drapeaux.to_be_bytes());
            reponse.extend_from_slice(&1_u16.to_be_bytes());
            reponse.extend_from_slice(&u16::from(txt).to_be_bytes());
            reponse.extend_from_slice(&0_u16.to_be_bytes());
            reponse.extend_from_slice(&0_u16.to_be_bytes());
            reponse.extend_from_slice(question.get(12..fin).unwrap_or_default());
            if txt {
                let mut donnees = Vec::new();
                for morceau in texte.as_bytes().chunks(255) {
                    donnees.push(u8::try_from(morceau.len()).expect("morceau court"));
                    donnees.extend_from_slice(morceau);
                }
                reponse.extend_from_slice(&[0xC0, 0x0C]);
                reponse.extend_from_slice(&16_u16.to_be_bytes());
                reponse.extend_from_slice(&1_u16.to_be_bytes());
                reponse.extend_from_slice(&60_u32.to_be_bytes());
                reponse.extend_from_slice(
                    &u16::try_from(donnees.len())
                        .expect("politique courte")
                        .to_be_bytes(),
                );
                reponse.extend_from_slice(&donnees);
            }
            let _ = socket.send_to(&reponse, pair).await;
        }
    });
    adresse
}

/// Le type demandé, et où finit la question.
fn genre_et_fin(message: &[u8]) -> Option<(u16, usize)> {
    let mut position = 12_usize;
    loop {
        let &longueur = message.get(position)?;
        position = position.saturating_add(1);
        if longueur == 0 {
            break;
        }
        position = position.saturating_add(usize::from(longueur));
    }
    let genre = u16::from_be_bytes([
        *message.get(position)?,
        *message.get(position.saturating_add(1))?,
    ]);
    Some((genre, position.saturating_add(4)))
}

/// Une socket qui n'écoute pas : de quoi éprouver un résolveur injoignable.
pub fn nulle_part() -> std::net::SocketAddr {
    // Le port 1 en bouclage : rien n'y écoute, et rien n'y écoutera — un port
    // privilégié qu'aucun service de test ne peut ouvrir (C10).
    "127.0.0.1:1".parse().expect("adresse")
}

/// Monte un résolveur qui répond **selon le nom demandé**.
///
/// La table associe un nom exact à un `TXT` ; tout le reste reçoit « ce nom
/// n'existe pas ». C'est ce qu'il faut dès qu'un montage pose plus d'une
/// question — DMARC en pose deux, et pas au même nom.
pub async fn resolveur_par_nom(
    table: &'static [(&'static str, &'static str)],
) -> std::net::SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("socket UDP");
    let adresse = socket.local_addr().expect("adresse");
    tokio::spawn(async move {
        let mut recu = vec![0_u8; 2048];
        loop {
            let Ok((lus, pair)) = socket.recv_from(&mut recu).await else {
                return;
            };
            let question = recu.get(..lus).unwrap_or_default().to_vec();
            let Some((nom, genre, fin)) = nom_genre_et_fin(&question) else {
                continue;
            };
            let texte = (genre == 16)
                .then(|| {
                    table
                        .iter()
                        .find(|(connu, _)| connu.eq_ignore_ascii_case(&nom))
                        .map(|(_, texte)| *texte)
                })
                .flatten();

            let mut reponse = Vec::new();
            reponse.extend_from_slice(question.get(..2).unwrap_or_default());
            let drapeaux: u16 = if texte.is_some() { 0x8180 } else { 0x8183 };
            reponse.extend_from_slice(&drapeaux.to_be_bytes());
            reponse.extend_from_slice(&1_u16.to_be_bytes());
            reponse.extend_from_slice(&u16::from(texte.is_some()).to_be_bytes());
            reponse.extend_from_slice(&0_u16.to_be_bytes());
            reponse.extend_from_slice(&0_u16.to_be_bytes());
            reponse.extend_from_slice(question.get(12..fin).unwrap_or_default());
            if let Some(texte) = texte {
                let mut donnees = Vec::new();
                for morceau in texte.as_bytes().chunks(255) {
                    donnees.push(u8::try_from(morceau.len()).expect("morceau court"));
                    donnees.extend_from_slice(morceau);
                }
                reponse.extend_from_slice(&[0xC0, 0x0C]);
                reponse.extend_from_slice(&16_u16.to_be_bytes());
                reponse.extend_from_slice(&1_u16.to_be_bytes());
                reponse.extend_from_slice(&60_u32.to_be_bytes());
                reponse
                    .extend_from_slice(&u16::try_from(donnees.len()).expect("court").to_be_bytes());
                reponse.extend_from_slice(&donnees);
            }
            let _ = socket.send_to(&reponse, pair).await;
        }
    });
    adresse
}

/// Le nom demandé, son type, et où finit la question.
fn nom_genre_et_fin(message: &[u8]) -> Option<(String, u16, usize)> {
    let mut position = 12_usize;
    let mut nom = String::new();
    loop {
        let &longueur = message.get(position)?;
        position = position.saturating_add(1);
        if longueur == 0 {
            break;
        }
        let fin = position.saturating_add(usize::from(longueur));
        let etiquette = message.get(position..fin)?;
        if !nom.is_empty() {
            nom.push('.');
        }
        nom.push_str(&String::from_utf8_lossy(etiquette));
        position = fin;
    }
    let genre = u16::from_be_bytes([
        *message.get(position)?,
        *message.get(position.saturating_add(1))?,
    ]);
    Some((nom, genre, position.saturating_add(4)))
}
