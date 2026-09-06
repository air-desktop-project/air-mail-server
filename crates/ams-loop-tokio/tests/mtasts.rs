// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **La récupération d'une politique MTA-STS** (RFC 8461).
//!
//! # Ce que ces épreuves ferment
//!
//! `ams-mtasts` — l'analyse d'une politique, la lecture d'un `id`, le nom de son
//! fichier de cache — est couvert à 100 %. Ce qui va la CHERCHER ne l'était par
//! rien : ni le `TXT` interrogé, ni la connexion en `https`, ni la vérification
//! du certificat dont TOUTE la confiance dépend, ni le cache qui évite d'y
//! retourner à chaque message.
//!
//! La raison en était simple et matérielle : §3.3 de RFC 8461 fixe le port à
//! 443, et un essai ne peut pas l'ouvrir sans privilège. `Sts::with_port` existe
//! désormais pour cela — comme `Relay::with_port` avant lui, et avec la même
//! mention « réservé aux tests ».
//!
//! # Pourquoi cette absence-là coûtait plus cher qu'une autre
//!
//! Une politique MTA-STS en `enforce` est ce qui EMPÊCHE un attaquant en
//! position de coupure de faire retomber une remise en clair. Le seul point où
//! elle devient digne de foi est la vérification du certificat de
//! `mta-sts.<domaine>` : si ce contrôle cédait, la politique ne serait plus
//! qu'un texte que n'importe qui aurait écrit — et un attaquant écrirait
//! `mode: none`.

mod commun;

use ams_loop_tokio::{Resolver, Sts};
use commun::{Enregistrement, resolveur_courrier};
use core::time::Duration;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

/// La politique servie par l'hôte d'épreuve.
const POLITIQUE: &str = "version: STSv1\nmode: enforce\nmx: mx.essai.test\nmax_age: 86400\n";

/// La zone : le `TXT` de version, et l'adresse de l'hôte qui sert la politique.
const ZONE: &[(&str, Enregistrement)] = &[
    ("_mta-sts.essai.test", Enregistrement::Txt("v=STSv1; id=42")),
    ("mta-sts.essai.test", Enregistrement::A([127, 0, 0, 1])),
];

/// La même zone, avec un identifiant DIFFÉRENT : la politique a changé.
const ZONE_NEUVE: &[(&str, Enregistrement)] = &[
    ("_mta-sts.essai.test", Enregistrement::Txt("v=STSv1; id=99")),
    ("mta-sts.essai.test", Enregistrement::A([127, 0, 0, 1])),
];

/// Une zone SANS `TXT`, mais dont l'hôte de politique existe.
const ZONE_SANS_TXT: &[(&str, Enregistrement)] =
    &[("mta-sts.essai.test", Enregistrement::A([127, 0, 0, 1]))];

/// Une zone où RIEN n'existe : ni `TXT`, ni hôte de politique. C'est le cas de
/// la quasi-totalité du courrier.
const ZONE_VIDE: &[(&str, Enregistrement)] =
    &[("ailleurs.test", Enregistrement::A([127, 0, 0, 1]))];

/// Une autorité et un certificat AU NOM DE `mta-sts.essai.test`.
///
/// Rien n'est versionné : une clé privée dans un dépôt, même de test, reste une
/// clé privée dans un dépôt.
struct Autorite {
    repertoire: PathBuf,
    /// L'autorité, en DER — ce qu'un client doit croire pour accepter l'hôte.
    ca_der: Vec<u8>,
    /// De quoi servir en TLS sous le nom `mta-sts.essai.test`.
    serveur: Arc<rustls::ServerConfig>,
}

impl Drop for Autorite {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.repertoire);
    }
}

/// Fabrique une autorité, et un certificat qu'elle signe pour `nom`.
///
/// Rend `None` si `openssl` n'est pas là ou refuse : le test se saute alors, en
/// le disant. Un essai qui échouerait faute d'outil accuserait le produit.
fn autorite(cas: &str, nom: &str) -> Option<Autorite> {
    let repertoire = std::env::temp_dir().join(std::format!(
        "ams-mtasts-{cas}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&repertoire);
    std::fs::create_dir_all(&repertoire).ok()?;

    let ca_cle = repertoire.join("ca.key");
    let ca_cert = repertoire.join("ca.pem");
    let ca_der = repertoire.join("ca.der");
    let cle = repertoire.join("hote.key");
    let demande = repertoire.join("hote.csr");
    let cert = repertoire.join("hote.pem");
    let cert_der = repertoire.join("hote.der");
    let cle_der = repertoire.join("hote.p8");
    let extensions = repertoire.join("ext.cnf");
    std::fs::write(&extensions, std::format!("subjectAltName=DNS:{nom}\n")).ok()?;

    let ok = |commande: &mut Command| commande.output().ok().is_some_and(|s| s.status.success());

    // L'autorité, auto-signée.
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
    // La même, en DER, telle qu'un magasin de confiance la veut.
    if !ok(Command::new("openssl")
        .args(["x509", "-outform", "DER"])
        .arg("-in")
        .arg(&ca_cert)
        .arg("-out")
        .arg(&ca_der))
    {
        return None;
    }
    // La clé de l'hôte, et sa demande.
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
    // Signée par l'autorité, avec le nom en `subjectAltName` — sans lui, aucun
    // vérificateur moderne ne regarde le `CN`.
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
    if !ok(Command::new("openssl")
        .args(["x509", "-outform", "DER"])
        .arg("-in")
        .arg(&cert)
        .arg("-out")
        .arg(&cert_der))
    {
        return None;
    }
    if !ok(Command::new("openssl")
        .args(["pkcs8", "-topk8", "-nocrypt"])
        .arg("-in")
        .arg(&cle)
        .args(["-outform", "DER"])
        .arg("-out")
        .arg(&cle_der))
    {
        return None;
    }

    let chaine = rustls::pki_types::CertificateDer::from(std::fs::read(&cert_der).ok()?);
    let privee = rustls::pki_types::PrivateKeyDer::try_from(std::fs::read(&cle_der).ok()?).ok()?;
    let serveur = rustls::ServerConfig::builder_with_provider(Arc::new(ams_tls::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .ok()?
        .with_no_client_auth()
        .with_single_cert(std::vec![chaine], privee)
        .ok()?;

    Some(Autorite {
        ca_der: std::fs::read(&ca_der).ok()?,
        repertoire,
        serveur: Arc::new(serveur),
    })
}

/// Un client qui ne croit QUE l'autorité donnée.
fn client_qui_croit(ca_der: &[u8]) -> Arc<rustls::ClientConfig> {
    let mut magasin = rustls::RootCertStore::empty();
    magasin
        .add(rustls::pki_types::CertificateDer::from(ca_der.to_vec()))
        .expect("autorité acceptée");
    Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(ams_tls::provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .with_root_certificates(magasin)
            .with_no_client_auth(),
    )
}

/// Sert `reponse` une fois, en TLS, et rend son adresse.
///
/// Le corps est donné tel quel : c'est ce qui permet d'éprouver un `404` ou un
/// découpage aussi bien qu'une politique.
async fn hote(serveur: Arc<rustls::ServerConfig>, reponse: String) -> std::net::SocketAddr {
    let ecoute = TcpListener::bind("127.0.0.1:0").await.expect("écoute");
    let adresse = ecoute.local_addr().expect("adresse");
    tokio::spawn(async move {
        let accepteur = tokio_rustls::TlsAcceptor::from(serveur);
        while let Ok((flux, _)) = ecoute.accept().await {
            let reponse = reponse.clone();
            let accepteur = accepteur.clone();
            tokio::spawn(async move {
                let Ok(mut chiffre) = accepteur.accept(flux).await else {
                    return;
                };
                let mut recu = [0_u8; 2048];
                let _ = chiffre.read(&mut recu).await;
                let _ = chiffre.write_all(reponse.as_bytes()).await;
                let _ = chiffre.flush().await;
                let _ = chiffre.shutdown().await;
            });
        }
    });
    adresse
}

/// Une réponse `200` qui porte `texte`.
fn deux_cents(texte: &str) -> String {
    std::format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{texte}",
        texte.len()
    )
}

/// Monte le tout, et rend un `Sts` prêt à interroger.
async fn monter(ca_der: &[u8], resolveur: std::net::SocketAddr, port: u16, cache: PathBuf) -> Sts {
    std::fs::create_dir_all(&cache).expect("cache");
    Sts::new(
        Resolver::new(std::vec![resolveur], Duration::from_secs(2)).expect("résolveur"),
        client_qui_croit(ca_der),
        cache,
        Duration::from_secs(2),
    )
    .with_port(port)
}

/// **UNE POLITIQUE SE RÉCUPÈRE, ET SE GARDE.**
#[tokio::test]
async fn une_politique_se_recupere_puis_se_relit_du_cache() {
    let Some(ca) = autorite("juste", "mta-sts.essai.test") else {
        eprintln!("SAUTÉ : `openssl` n'a pas su fabriquer d'autorité.");
        return;
    };
    let adresse = hote(Arc::clone(&ca.serveur), deux_cents(POLITIQUE)).await;
    let dns = resolveur_courrier(ZONE).await;
    let cache = ca.repertoire.join("cache");
    let sts = monter(&ca.ca_der, dns, adresse.port(), cache.clone()).await;

    assert_eq!(
        sts.policy_for("essai.test", 1_000).await.as_deref(),
        Some(POLITIQUE),
        "la politique n'a pas été récupérée"
    );
    // ELLE EST SUR LE DISQUE : c'est ce qui évite d'y retourner à chaque message.
    let gardees = std::fs::read_dir(&cache).expect("cache lisible").count();
    assert_eq!(gardees, 1, "la politique n'a pas été gardée");

    // **ET L'HÔTE N'EST PLUS NÉCESSAIRE.** On monte un `Sts` neuf sur le même
    // cache, en pointant le port vers rien : si la réponse vient encore, c'est
    // qu'elle vient du disque.
    let orphelin = monter(&ca.ca_der, dns, 1, cache).await;
    assert_eq!(
        orphelin.policy_for("essai.test", 2_000).await.as_deref(),
        Some(POLITIQUE),
        "le cache n'a pas servi"
    );
}

/// **UN `id` QUI CHANGE FAIT RETOURNER LA CHERCHER** (§5).
#[tokio::test]
async fn un_identifiant_neuf_fait_recharger_la_politique() {
    let Some(ca) = autorite("neuf", "mta-sts.essai.test") else {
        return;
    };
    let cache = ca.repertoire.join("cache");
    let premiere = hote(Arc::clone(&ca.serveur), deux_cents(POLITIQUE)).await;
    let sts = monter(
        &ca.ca_der,
        resolveur_courrier(ZONE).await,
        premiere.port(),
        cache.clone(),
    )
    .await;
    assert_eq!(
        sts.policy_for("essai.test", 1_000).await.as_deref(),
        Some(POLITIQUE)
    );

    // Une politique DIFFÉRENTE, sous un identifiant DIFFÉRENT.
    let autre = "version: STSv1\nmode: testing\nmx: mx.essai.test\nmax_age: 86400\n";
    let seconde = hote(Arc::clone(&ca.serveur), deux_cents(autre)).await;
    let apres = monter(
        &ca.ca_der,
        resolveur_courrier(ZONE_NEUVE).await,
        seconde.port(),
        cache,
    )
    .await;
    assert_eq!(
        apres.policy_for("essai.test", 2_000).await.as_deref(),
        Some(autre),
        "l'identifiant a changé, la politique aurait dû être rechargée"
    );
}

/// **UN CERTIFICAT QU'ON NE CROIT PAS NE DONNE AUCUNE POLITIQUE.**
///
/// C'est le contrôle dont tout dépend : sans lui, la politique ne serait qu'un
/// texte que n'importe qui aurait écrit, et un attaquant écrirait `mode: none`.
#[tokio::test]
async fn une_autorite_inconnue_ne_donne_aucune_politique() {
    let Some(ca) = autorite("vraie", "mta-sts.essai.test") else {
        return;
    };
    let Some(usurpateur) = autorite("fausse", "mta-sts.essai.test") else {
        return;
    };
    // L'hôte sert le certificat de l'USURPATEUR ; le client ne croit que la
    // vraie autorité.
    let adresse = hote(Arc::clone(&usurpateur.serveur), deux_cents(POLITIQUE)).await;
    let sts = monter(
        &ca.ca_der,
        resolveur_courrier(ZONE).await,
        adresse.port(),
        ca.repertoire.join("cache"),
    )
    .await;
    assert_eq!(
        sts.policy_for("essai.test", 1_000).await,
        None,
        "une politique servie sous un certificat non vérifié a été retenue"
    );
}

/// **UN CERTIFICAT AU MAUVAIS NOM NON PLUS.**
///
/// L'autorité est la bonne ; le nom ne l'est pas. Sans ce contrôle, il
/// suffirait d'un certificat valable pour un autre domaine.
#[tokio::test]
async fn un_certificat_au_mauvais_nom_ne_donne_aucune_politique() {
    let Some(ca) = autorite("mauvais-nom", "mta-sts.ailleurs.test") else {
        return;
    };
    let adresse = hote(Arc::clone(&ca.serveur), deux_cents(POLITIQUE)).await;
    let sts = monter(
        &ca.ca_der,
        resolveur_courrier(ZONE).await,
        adresse.port(),
        ca.repertoire.join("cache"),
    )
    .await;
    assert_eq!(
        sts.policy_for("essai.test", 1_000).await,
        None,
        "un certificat au nom d'un autre domaine a été accepté"
    );
}

/// **RIEN D'AUTRE QU'UN `200` NE PORTE UNE POLITIQUE** (§3.3).
///
/// Une redirection n'est pas suivie : un `301` vers un autre hôte ferait
/// chercher la politique là où l'attaquant l'aura mise.
#[tokio::test]
async fn ni_redirection_ni_erreur_ne_portent_de_politique() {
    for reponse in [
        "HTTP/1.1 301 Moved Permanently\r\nLocation: https://ailleurs.test/p\r\n\
         Content-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    ] {
        let Some(ca) = autorite("refus", "mta-sts.essai.test") else {
            return;
        };
        let adresse = hote(Arc::clone(&ca.serveur), reponse.to_owned()).await;
        let sts = monter(
            &ca.ca_der,
            resolveur_courrier(ZONE).await,
            adresse.port(),
            ca.repertoire.join("cache"),
        )
        .await;
        assert_eq!(
            sts.policy_for("essai.test", 1_000).await,
            None,
            "cette réponse a porté une politique : {reponse:.40}"
        );
    }
}

/// **SANS `TXT`, ON CHERCHE TOUT DE MÊME — ET C'EST PERMIS.**
///
/// # L'essai que j'avais écrit d'abord, et pourquoi il avait tort
///
/// Il affirmait l'inverse : « sans déclaration DNS, aucune politique ». Le
/// raisonnement paraissait solide — §3.1 fait du `TXT` la DÉCLARATION qu'un
/// domaine implémente MTA-STS, et aller chercher quand même coûterait une
/// connexion par domaine et par message.
///
/// §5.1 dit autre chose, et il a fallu le lire pour s'en apercevoir :
///
/// > Check for a cached policy whose time-since-fetch has not exceeded its
/// > "max_age".  If none exists, attempt to fetch a new policy (perhaps
/// > asynchronously, so as not to block message delivery).  Optionally, Sending
/// > MTAs may unconditionally check for a new policy at this step.
///
/// La récupération n'est pas conditionnée au `TXT`, et §6 le confirme à
/// l'envers en ne rendant rapportables que « HTTPS policy fetch failures WHEN A
/// VALID TXT RECORD IS PRESENT » — ce qui n'aurait aucun sens si l'absence de
/// `TXT` interdisait de chercher.
///
/// # Et le coût redouté n'est pas celui que je croyais
///
/// L'essai suivant le montre : quand `mta-sts.<domaine>` n'existe pas — le cas
/// de la quasi-totalité du courrier — la récupération s'arrête à la résolution
/// du nom. Une question DNS, pas une connexion `https`.
#[tokio::test]
async fn sans_txt_la_politique_est_tout_de_meme_cherchee() {
    let Some(ca) = autorite("sans-txt", "mta-sts.essai.test") else {
        return;
    };
    let adresse = hote(Arc::clone(&ca.serveur), deux_cents(POLITIQUE)).await;
    let sts = monter(
        &ca.ca_der,
        resolveur_courrier(ZONE_SANS_TXT).await,
        adresse.port(),
        ca.repertoire.join("cache"),
    )
    .await;
    assert_eq!(
        sts.policy_for("essai.test", 1_000).await.as_deref(),
        Some(POLITIQUE),
        "§5.1 permet de chercher sans `TXT`, et c'est ce que fait ce serveur"
    );
}

/// **SANS HÔTE DE POLITIQUE, LA RECHERCHE S'ARRÊTE AU DNS.**
///
/// C'est ce qui borne le coût du choix précédent : un domaine qui n'implémente
/// pas MTA-STS n'a pas de `mta-sts.<domaine>`, et la récupération ne va pas plus
/// loin qu'une question `A`. Pas de TCP, pas de poignée de main TLS.
#[tokio::test]
async fn sans_hote_de_politique_rien_ne_se_connecte() {
    let Some(ca) = autorite("vide", "mta-sts.essai.test") else {
        return;
    };
    // Le port pointe vers RIEN. Si la récupération allait jusqu'à se connecter,
    // elle attendrait le délai ; elle rend `None` tout de suite.
    let sts = monter(
        &ca.ca_der,
        resolveur_courrier(ZONE_VIDE).await,
        1,
        ca.repertoire.join("cache"),
    )
    .await;
    let debut = std::time::Instant::now();
    assert_eq!(sts.policy_for("essai.test", 1_000).await, None);
    // Le délai monté est de deux secondes ; on est très loin en dessous.
    assert!(
        debut.elapsed() < Duration::from_millis(500),
        "la recherche a duré {:?} — elle a dû tenter une connexion",
        debut.elapsed()
    );
}
