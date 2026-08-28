//! Interopérabilité de `X25519MLKEM768` avec une implémentation de référence.
//!
//! # Pourquoi ce test existe, et pourquoi les tests unitaires ne suffisent pas
//!
//! L'aller-retour de `kx.rs` fait dialoguer notre implémentation avec elle-même.
//! **Si l'ordre des octets était inversé DES DEUX CÔTÉS, il passerait quand
//! même.** C'est le piège que le brouillon annonce lui-même : le nom
//! `X25519MLKEM768` ne suit pas la convention, et l'ordre des parts est inversé
//! « pour raisons historiques ».
//!
//! Seul un pair qui ne partage pas notre code peut trancher. Celui-ci est
//! OpenSSL, qui connaît `X25519MLKEM768` depuis sa version 3.5.
//!
//! # Ce test N'EST PAS un gate de CI, et c'est dit
//!
//! Il exige OpenSSL ≥ 3.5. Les images d'intégration continue courantes portent
//! encore la 3.0, où le groupe n'existe pas. Le test se **saute bruyamment**
//! plutôt que d'échouer — mais un test sauté ne prouve rien, et c'est pourquoi le
//! résultat de son exécution manuelle est consigné, avec sa date, dans le
//! registre des contraintes.

use std::io::Write as _;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

/// Ce que le serveur envoie une fois la poignée de main terminée.
const MARQUEUR: &[u8] = b"air-mail-server: poignee de main terminee\n";

/// OpenSSL connaît-il le groupe ?
fn openssl_connait_le_groupe() -> bool {
    Command::new("openssl")
        .args(["list", "-tls-groups"])
        .output()
        .is_ok_and(|sortie| String::from_utf8_lossy(&sortie.stdout).contains("X25519MLKEM768"))
}

/// Fabrique un certificat auto-signé, en DER pour n'avoir rien à analyser.
fn certificat(repertoire: &Path) -> Option<(PathBuf, PathBuf)> {
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

#[test]
fn openssl_negocie_x25519mlkem768_avec_notre_fournisseur() {
    if !openssl_connait_le_groupe() {
        eprintln!(
            "SAUTÉ : cet OpenSSL ne connaît pas `X25519MLKEM768` (il faut ≥ 3.5).\n\
             Un test sauté ne prouve rien : voir `docs/contraintes.md`, C14, pour la\n\
             date et le résultat de la dernière exécution réelle."
        );
        return;
    }

    let repertoire = std::env::temp_dir().join(format!("ams-tls-interop-{}", std::process::id()));
    std::fs::create_dir_all(&repertoire).expect("répertoire temporaire");
    let Some((chemin_cert, chemin_cle)) = certificat(&repertoire) else {
        let _ = std::fs::remove_dir_all(&repertoire);
        panic!("openssl n'a pas su fabriquer de certificat");
    };

    let cert = rustls::pki_types::CertificateDer::from(
        std::fs::read(&chemin_cert).expect("certificat lisible"),
    );
    let cle = rustls::pki_types::PrivateKeyDer::try_from(
        std::fs::read(&chemin_cle).expect("clé lisible"),
    )
    .expect("clé PKCS#8");

    // NOTRE fournisseur : pur Rust, TLS 1.3 seul, `X25519MLKEM768` en tête.
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(ams_tls::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(vec![cert], cle)
        .expect("certificat accepté");

    let ecouteur = TcpListener::bind("127.0.0.1:0").expect("écoute");
    let adresse = ecouteur.local_addr().expect("adresse");

    let serveur = std::thread::spawn(move || {
        let (mut flux, _) = ecouteur.accept().expect("connexion");
        let mut connexion = rustls::ServerConnection::new(Arc::new(config)).expect("connexion TLS");
        connexion.complete_io(&mut flux).expect("poignée de main");
        // Le groupe RÉELLEMENT négocié, vu de notre côté.
        let groupe = connexion.negotiated_key_exchange_group().map(|g| g.name());
        connexion.writer().write_all(MARQUEUR).expect("écriture");
        connexion.complete_io(&mut flux).expect("vidage");
        connexion.send_close_notify();
        let _ = connexion.complete_io(&mut flux);
        groupe
    });

    let client = Command::new("openssl")
        .args(["s_client", "-connect"])
        .arg(format!("127.0.0.1:{}", adresse.port()))
        .args(["-groups", "X25519MLKEM768"])
        .args(["-tls1_3", "-brief"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("openssl s_client");

    let groupe = serveur.join().expect("fil serveur");
    let _ = std::fs::remove_dir_all(&repertoire);

    let dit = format!(
        "{}{}",
        String::from_utf8_lossy(&client.stdout),
        String::from_utf8_lossy(&client.stderr)
    );

    // ── CE QUE CHAQUE ASSERTION PROUVE ──────────────────────────────────────
    //
    // 1. LA POIGNÉE DE MAIN A ABOUTI. C'est l'assertion décisive, et il faut
    //    savoir pourquoi : le message `Finished` de TLS 1.3 porte un MAC calculé
    //    sur toute la transcription avec une clé dérivée du secret partagé. Il
    //    ne peut se vérifier que si les DEUX côtés ont dérivé LE MÊME secret à
    //    partir des MÊMES octets.
    //
    //    Un ordre d'octets faux de notre côté seul — la part inversée, ou les
    //    deux moitiés du secret échangées — ferait échouer cette vérification.
    //    C'est exactement ce que l'aller-retour contre soi-même ne peut pas
    //    attraper.
    assert!(
        dit.contains("CONNECTION ESTABLISHED"),
        "la poignée de main n'a pas abouti.\n{dit}"
    );
    assert!(
        dit.contains("Protocol version: TLSv1.3"),
        "la connexion n'est pas en TLS 1.3.\n{dit}"
    );

    // 2. ET C'EST BIEN LE GROUPE HYBRIDE, des deux points de vue — le nôtre, et
    //    celui d'un pair qui ne partage pas notre code.
    assert!(
        dit.contains("Negotiated TLS1.3 group: X25519MLKEM768"),
        "OpenSSL n'a pas négocié X25519MLKEM768.\n{dit}"
    );
    assert_eq!(
        groupe,
        Some(rustls::NamedGroup::X25519MLKEM768),
        "notre côté n'a pas négocié le groupe hybride"
    );

    // Le marqueur, lui, n'est PAS attendu : `s_client -brief` referme la
    // connexion dès la poignée de main terminée, sans lire les données
    // applicatives. L'écrire éprouve tout de même que l'écriture chiffrée ne
    // panique pas.
}
