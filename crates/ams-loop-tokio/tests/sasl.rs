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
            dkim: None,
            dmarc: None,
            reports: None,
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
    assert!(dit.contains("235 2.7.0 Authentication successful"), "{dit}");
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
    assert!(dit.contains("235 2.7.0 Authentication successful"), "{dit}");
    assert!(dit.starts_with("[OK]"), "{dit}");
}

/// **UN MESSAGE EN `LF` NU PASSE QUAND LE PAIR S'EST AUTHENTIFIÉ — ET PAS
/// AUTREMENT.**
///
/// VU EN PRODUCTION LE 2026-09-23 : une passerelle Milesight écrivait ses
/// alertes en `LF` nu, ce que Postfix tolérait depuis des années. Ce serveur
/// l'acceptait jusqu'au `DATA` puis refusait le message par `554` — l'appareil
/// n'affichait qu'un « Erreur » muet.
///
/// **IL FALLAIT LA BOUCLE POUR QUE CELA SE VOIE** : la session seule ne dit
/// rien de ce qu'un vrai client envoie sur le fil.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn le_lf_nu_passe_pour_un_pair_authentifie() {
    let Some(dit) = conversation_chiffree(
        "sasl-lf-authentifie",
        concat!(
            "EHLO client.example\r\n",
            "AUTH PLAIN AGplYW4Ab3V2cmUtdG9p\r\n",
            "MAIL FROM:<jean@example.com>\r\n",
            "RCPT TO:<jean@example.com>\r\n",
            "DATA\r\n",
            "From: jean@example.com\nSubject: alerte\n\ncorps\n.\n",
            "QUIT\r\n",
        ),
    )
    .await
    else {
        return;
    };
    assert!(
        dit.contains("235 2.7.0"),
        "l'authentification a échoué : {dit}"
    );
    assert!(
        dit.contains("250 2.0.0 Message accepted"),
        "un pair authentifié doit pouvoir déposer en `LF` nu : {dit}"
    );
    assert!(
        !dit.contains("Bare CR or LF"),
        "message refusé alors que le pair était authentifié : {dit}"
    );
}

/// **ET SANS AUTHENTIFICATION, LA RÈGLE ENTIÈRE** — c'est le courrier entrant
/// que la contrebande SMTP vise, et c'est là que deux serveurs peuvent se
/// contredire.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn le_lf_nu_reste_refuse_sans_authentification() {
    let Some(dit) = conversation_chiffree(
        "sasl-lf-anonyme",
        concat!(
            "EHLO client.example\r\n",
            "MAIL FROM:<jean@example.com>\r\n",
            "RCPT TO:<jean@example.com>\r\n",
            "DATA\r\n",
            // **LE CORPS PORTE DU `LF` NU, MAIS SE TERMINE PROPREMENT.** Sans
            // tolérance, `.\n` n'est PAS une fin de message — le serveur
            // attendrait indéfiniment, et ce banc expirerait au lieu de
            // mesurer le refus. C'est la règle qui veut cela, pas un défaut.
            "From: jean@example.com\nSubject: alerte\n\ncorps\r\n.\r\n",
            "QUIT\r\n",
        ),
    )
    .await
    else {
        return;
    };
    assert!(
        dit.contains("554 5.6.0 Bare CR or LF in message data"),
        "le courrier entrant doit garder la règle entière : {dit}"
    );
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
        dit.contains("535 5.7.1 Authentication credentials invalid"),
        "{dit}"
    );
    // La connexion ne se ferme PAS : c'est au garde (C8) d'en décider, et non à
    // la grammaire. Fermer au premier échec ferait de chaque faute de frappe un
    // incident.
    assert!(
        dit.contains("250 2.0.0 OK"),
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

    assert!(dit.contains("501 5.7.0 Authentication aborted"), "{dit}");
    assert!(
        dit.contains("250 2.0.0 OK"),
        "la session n'a pas repris.\n{dit}"
    );
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

// ── CE QUE L'EN-TÊTE DE TRACE DIT D'UNE SOUMISSION ──────────────────────────

/// Un témoin qui ne retient qu'une chose : l'en-tête `Authentication-Results`.
#[derive(Clone, Default)]
struct Trace(Arc<std::sync::Mutex<Vec<u8>>>);

impl ams_loop_tokio::Delivery for Trace {
    fn add_recipient(&mut self, _address: &[u8]) -> Result<(), ams_loop_tokio::DeliveryFailure> {
        Ok(())
    }
    fn append(&mut self, _chunk: &[u8]) -> Result<(), ams_loop_tokio::DeliveryFailure> {
        Ok(())
    }
    fn finish(&mut self) -> Result<(), ams_loop_tokio::DeliveryFailure> {
        Ok(())
    }
    fn abort(&mut self) {}
    fn trace(&mut self, entete: &[u8]) {
        if let Ok(mut place) = self.0.lock() {
            place.clear();
            place.extend_from_slice(entete);
        }
    }
}

/// Conduit un dialogue chiffré et rend l'en-tête de trace qui en est sorti.
async fn trace_chiffree(nom: &str, dialogue: &'static str) -> Option<String> {
    let materiel = materiel(nom)?;
    let ecouteur = TcpListener::bind("127.0.0.1:0").await.expect("écoute");
    let adresse = ecouteur.local_addr().expect("adresse");
    let tls = Arc::clone(&materiel.tls);
    let vu = Trace::default();
    let copie = vu.clone();

    let serveur = tokio::spawn(async move {
        let (mut flux, _) = ecouteur.accept().await.expect("connexion");
        let garde = SharedGuard::new(4, Thresholds::DEFAULT);
        let service = Service {
            config: config(true, true),
            guard: &garde,
            timeouts: Timeouts::default(),
            tls: Some(tls),
            spf: None,
            dkim: None,
            dmarc: None,
            reports: None,
        };
        let mut temoin = copie;
        let _ = serve_connection(&mut flux, &service, NotreDomaine, &mut temoin, PAIR).await;
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
    });

    let _ = client.await.ok()?;
    let _ = serveur.await;
    let place = vu.0.lock().ok()?;
    Some(String::from_utf8_lossy(&place).into_owned())
}

/// **UNE SOUMISSION AUTHENTIFIÉE NE PORTE QUE `auth=`** (RFC 8601 §2.7.4).
///
/// # CE QUE CET ESSAI EMPÊCHE DE REVENIR
///
/// Le serveur évaluait SPF, DKIM et DMARC sur une soumission qu'il venait
/// lui-même d'authentifier, et écrivait `dmarc=fail` sur le courrier de son
/// propre client — vu en production le 2026-09-23 sur la passerelle
/// `ofrou-sierre`, qui se présente en `HELO 127.0.0.1` et n'a donc rien
/// d'aligné en SPF. Un verdict d'usurpation contre quelqu'un qui vient de
/// prouver son identité.
///
/// **Sans le correctif, cet en-tête dirait `none`** — car rien n'aurait été
/// vérifié et le compte ne serait pas nommé.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn une_soumission_authentifiee_ne_porte_que_le_compte() {
    let Some(trace) = trace_chiffree(
        "sasl-authres-soumission",
        concat!(
            "EHLO client.example\r\n",
            "AUTH PLAIN AGplYW4Ab3V2cmUtdG9p\r\n",
            "MAIL FROM:<jean@example.com>\r\n",
            "RCPT TO:<jean@example.com>\r\n",
            "DATA\r\n",
            "From: jean@example.com\r\nSubject: alerte\r\n\r\ncorps\r\n.\r\n",
            "QUIT\r\n",
        ),
    )
    .await
    else {
        return;
    };
    assert!(
        trace.contains("auth=pass smtp.auth=jean"),
        "le compte doit être nommé : {trace}"
    );
    // **AUCUNE DES TROIS MÉTHODES D'ENTRANT**, puisqu'aucune n'a été conduite.
    for absent in ["dmarc=", "spf=", "dkim=", "none"] {
        assert!(
            !trace.contains(absent),
            "`{absent}` n'a rien à faire sur une soumission : {trace}"
        );
    }
}
