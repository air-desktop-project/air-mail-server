// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! L'échange SASL, conduit de bout en bout **dans le tuyau chiffré**.
//!
//! # Pourquoi ces tests-là ne peuvent pas se jouer en mémoire
//!
//! `AUTH` n'existe que sous TLS : la session le refuse autrement, sans réglage
//! possible. Éprouver l'échange demande donc un vrai chiffrement, et un vrai
//! client — ici `openssl s_client -starttls smtp`, qui envoie ce qu'on lui donne
//! sur l'entrée standard **après** la poignée de main.
//!
//! # Ce qu'ils éprouvent de la BOUCLE
//!
//! La session est couverte à 100 % chez elle. Ce qui n'y est pas éprouvé, c'est
//! la seule chose que la boucle sait de SASL : qu'après un défi, la ligne
//! suivante va à `feed_auth` plutôt qu'à `handle`, **et sans son `CRLF`**. Un
//! `CRLF` laissé au bout ferait échouer le base64, et l'échange refuserait des
//! identifiants justes — un défaut qui ne se voit qu'ici.

mod commun;

use std::io::Write as _;
use std::process::{Command, Stdio};
use std::sync::Arc;

use ams_guard::Thresholds;
use ams_loop_tokio::{Service, SharedGuard, Timeouts, serve_connection};
use commun::{Neant, NotreDomaine, PAIR, config, materiel};
use tokio::net::TcpListener;

/// `\0jean\0ouvre-toi` en base64 : les identifiants qui ouvrent.
const JUSTE: &str = "AGplYW4Ab3V2cmUtdG9p";
/// `\0jean\0autre` : le compte existe, le mot de passe non.
const FAUX: &str = "AGplYW4AYXV0cmU=";

/// Monte un service chiffré qui authentifie, y joue `dialogue`, et rend ce que
/// le client a lu **dans le tuyau chiffré**.
async fn conversation_chiffree(nom: &str, dialogue: &'static str) -> Option<String> {
    let materiel = materiel(nom)?;
    let ecouteur = TcpListener::bind("127.0.0.1:0").await.expect("écoute");
    let adresse = ecouteur.local_addr().expect("adresse");
    let tls = Arc::clone(&materiel.tls);

    let serveur = tokio::spawn(async move {
        let (mut flux, _) = ecouteur.accept().await.expect("connexion");
        let garde = SharedGuard::new(4, Thresholds::DEFAULT);
        let service = Service {
            config: config(true, true),
            guard: &garde,
            timeouts: Timeouts::default(),
            tls: Some(tls),
            spf: None,
        };
        serve_connection(&mut flux, &service, NotreDomaine, &mut Neant, PAIR).await
    });

    let client = tokio::task::spawn_blocking(move || {
        let mut processus = Command::new("openssl")
            .args(["s_client", "-connect"])
            .arg(format!("127.0.0.1:{}", adresse.port()))
            .args(["-starttls", "smtp", "-ign_eof"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .ok()?;
        processus
            .stdin
            .as_mut()?
            .write_all(dialogue.as_bytes())
            .ok()?;
        processus.wait_with_output().ok()
    })
    .await
    .expect("tâche openssl")
    .expect("`openssl s_client` doit être lançable : ces tests l'exigent");

    let resume = serveur
        .await
        .expect("tâche serveur")
        .expect("connexion servie");
    // Le résumé porte l'état de la session, et c'est notre point de vue à nous
    // sur le même échange.
    let vu_du_serveur = if resume.authenticated { "[OK]" } else { "[KO]" };
    // ON NE GARDE QUE LES RÉPONSES SMTP, et ce n'est pas de la cosmétique.
    // `openssl s_client` écrit sur sa SORTIE STANDARD, avant le dialogue, la
    // chaîne de certificats en base64 et le vidage hexadécimal de la session —
    // plusieurs milliers de caractères tirés au hasard à chaque exécution.
    // Chercher « 334 » là-dedans, c'est chercher trois chiffres dans du bruit :
    // la CI l'a trouvé un jour dans un certificat, et le test a échoué en
    // annonçant un défi que personne n'avait envoyé.
    let sortie = String::from_utf8_lossy(&client.stdout);
    let dialogue: Vec<&str> = sortie
        .lines()
        .filter(|ligne| est_une_reponse(ligne))
        .collect();
    Some(format!("{vu_du_serveur}\n{}", dialogue.join("\n")))
}

/// Cette ligne est-elle une réponse SMTP ?
///
/// Trois chiffres, puis une espace ou un tiret (RFC 5321 §4.2). Le vidage
/// d'`openssl` ne peut pas s'y glisser : ses lignes de base64 n'ont pas
/// d'espace, et celles du vidage hexadécimal commencent par des espaces.
fn est_une_reponse(ligne: &str) -> bool {
    let octets = ligne.as_bytes();
    let Some([a, b, c, quatrieme]) = octets.first_chunk::<4>() else {
        return false;
    };
    a.is_ascii_digit()
        && b.is_ascii_digit()
        && c.is_ascii_digit()
        && (*quatrieme == b' ' || *quatrieme == b'-')
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn une_reponse_initiale_ouvre_la_session_en_un_seul_aller() {
    let Some(dit) = conversation_chiffree(
        "sasl-initiale",
        concat!(
            "EHLO client.example\r\n",
            "AUTH PLAIN AGplYW4Ab3V2cmUtdG9p\r\n",
            "QUIT\r\n"
        ),
    )
    .await
    else {
        panic!("`openssl` est nécessaire à ce test");
    };

    // L'extension est annoncée — et elle ne l'est QUE sous chiffrement.
    assert!(dit.contains("250 AUTH PLAIN"), "{dit}");
    assert!(dit.contains("235 Authentication successful"), "{dit}");
    // Et AUCUN défi n'a été envoyé : la RFC 4954 §4 l'interdit quand une réponse
    // initiale est fournie. Un `334` de trop désynchroniserait la conversation.
    assert!(!dit.contains("334"), "un défi a été envoyé en trop.\n{dit}");
    assert!(dit.starts_with("[OK]"), "{dit}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sans_reponse_initiale_le_defi_puis_la_reponse_ouvrent_la_session() {
    // C'EST LE TEST DE LA BOUCLE : c'est le seul chemin où la ligne suivante va
    // à `feed_auth` au lieu de `handle`, et où le `CRLF` doit être retiré.
    let Some(dit) = conversation_chiffree(
        "sasl-defi",
        concat!(
            "EHLO client.example\r\n",
            "AUTH PLAIN\r\n",
            "AGplYW4Ab3V2cmUtdG9p\r\n",
            "QUIT\r\n"
        ),
    )
    .await
    else {
        panic!("`openssl` est nécessaire à ce test");
    };

    assert!(dit.contains("334"), "aucun défi n'a été posé.\n{dit}");
    assert!(dit.contains("235 Authentication successful"), "{dit}");
    assert!(dit.starts_with("[OK]"), "{dit}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn un_mot_de_passe_faux_est_refuse_et_la_session_continue() {
    let Some(dit) = conversation_chiffree(
        "sasl-faux",
        concat!(
            "EHLO client.example\r\n",
            "AUTH PLAIN AGplYW4AYXV0cmU=\r\n",
            "NOOP\r\n",
            "QUIT\r\n"
        ),
    )
    .await
    else {
        panic!("`openssl` est nécessaire à ce test");
    };

    assert!(
        dit.contains("535 Authentication credentials invalid"),
        "{dit}"
    );
    // La connexion ne se ferme PAS : c'est au garde (C8) d'en décider, et non à
    // la grammaire. Fermer au premier échec ferait de chaque faute de frappe un
    // incident.
    assert!(
        dit.contains("250 OK"),
        "le `NOOP` n'a pas été servi.\n{dit}"
    );
    assert!(dit.starts_with("[KO]"), "{dit}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn le_pair_peut_annuler_l_echange() {
    let Some(dit) = conversation_chiffree(
        "sasl-annule",
        concat!(
            "EHLO client.example\r\n",
            "AUTH PLAIN\r\n",
            "*\r\n",
            "NOOP\r\n",
            "QUIT\r\n"
        ),
    )
    .await
    else {
        panic!("`openssl` est nécessaire à ce test");
    };

    assert!(dit.contains("501 Authentication aborted"), "{dit}");
    assert!(dit.contains("250 OK"), "la session n'a pas repris.\n{dit}");
    assert!(dit.starts_with("[KO]"), "{dit}");
}

#[test]
fn les_identifiants_de_test_sont_bien_ceux_qu_on_croit() {
    // Un base64 recopié à la main est un base64 faux : on le vérifie avec le
    // décodeur du produit plutôt qu'à l'œil.
    let mut clair = [0_u8; 64];
    let ecrits = ams_sasl::decode_base64(JUSTE.as_bytes(), &mut clair).expect("base64");
    let lu = ams_sasl::parse_plain(&clair[..ecrits]).expect("PLAIN");
    assert_eq!(lu.authentication_identity, commun::COMPTE);
    assert_eq!(lu.password, commun::SECRET);

    let ecrits = ams_sasl::decode_base64(FAUX.as_bytes(), &mut clair).expect("base64");
    let lu = ams_sasl::parse_plain(&clair[..ecrits]).expect("PLAIN");
    assert_eq!(lu.authentication_identity, commun::COMPTE);
    assert_ne!(lu.password, commun::SECRET);
}
