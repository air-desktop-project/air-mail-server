// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que la configuration TLS d'HTTP/2 annonce, sur du vrai matériel.
//!
//! # POURQUOI CET ESSAI VIT ICI, ET NON DANS `ams-tls`
//!
//! Assembler une configuration demande un certificat, et un certificat dans un
//! dépôt reste un certificat dans un dépôt — même de test. Les essais
//! d'intégration en fabriquent un à la volée avec `openssl`.
//!
//! **Et le seuil de couverture ne mesure que les crates du périmètre sans
//! entrée-sortie** : un essai posé ici n'y compte pas. Y faire dépendre une
//! ligne du périmètre reviendrait à faire dépendre le seuil de la présence
//! d'`openssl` sur la machine — une fragilité qu'on ne veut pas dans un gate.
//!
//! La découpe suit donc ce que chaque morceau peut prouver seul : ce qu'on
//! annonce se vérifie sans rien, l'assemblage demande de quoi assembler.

use std::path::Path;
use std::process::Command;

/// Fabrique un certificat auto-signé, en PEM.
///
/// Rien n'est versionné : une clé privée dans un dépôt, même de test, reste une
/// clé privée dans un dépôt.
fn certificat_pem(repertoire: &Path) -> Option<(Vec<u8>, Vec<u8>)> {
    let cle = repertoire.join("cle.pem");
    let cert = repertoire.join("cert.pem");
    let genere = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "ec"])
        .args(["-pkeyopt", "ec_paramgen_curve:P-256"])
        .args(["-nodes", "-days", "1", "-subj", "/CN=localhost"])
        .arg("-keyout")
        .arg(&cle)
        .arg("-out")
        .arg(&cert)
        .output()
        .ok()?;
    if !genere.status.success() {
        return None;
    }
    Some((std::fs::read(&cert).ok()?, std::fs::read(&cle).ok()?))
}

/// **LA CONFIGURATION HTTP ANNONCE `h2`, ET LA CONFIGURATION ORDINAIRE
/// N'ANNONCE RIEN.**
///
/// Les deux moitiés comptent. Sans la première, un client ne peut pas négocier
/// HTTP/2 — §3.4 de RFC 9113 l'exige. Sans la seconde, une écoute SMTP ou IMAP
/// annoncerait un protocole applicatif qu'elle ne sert pas.
#[test]
fn la_configuration_http_annonce_h2_et_l_autre_rien() {
    let repertoire = std::env::temp_dir().join(format!("ams-alpn-{}", std::process::id()));
    std::fs::create_dir_all(&repertoire).expect("répertoire temporaire");
    let Some((cert, cle)) = certificat_pem(&repertoire) else {
        let _ = std::fs::remove_dir_all(&repertoire);
        eprintln!("SAUTÉ : `openssl` n'a pas su fabriquer de certificat.");
        return;
    };

    let http =
        ams_loop_tokio::http::http_server_config(&cert, &cle).expect("configuration assemblée");
    assert_eq!(
        http.alpn_protocols,
        vec![b"h2".to_vec()],
        "la configuration HTTP doit annoncer `h2`, et rien d'autre"
    );

    let ordinaire = ams_tls::server_config(&cert, &cle).expect("configuration assemblée");
    assert!(
        ordinaire.alpn_protocols.is_empty(),
        "une écoute qui ne sert pas HTTP n'annonce aucun protocole applicatif"
    );

    let _ = std::fs::remove_dir_all(&repertoire);
}
