// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `STARTTLS` de bout en bout : la boucle, le fournisseur, et un vrai pair.
//!
//! # Pourquoi un test d'intégration, et pas des tests en mémoire
//!
//! Les conversations en mémoire de `connection.rs` prouvent que la boucle dit
//! les bonnes choses. Elles ne peuvent pas prouver qu'un **pair qui ne partage
//! pas notre code** monte en chiffrement : la poignée de main est précisément
//! l'endroit où deux implémentations se mettent d'accord, et se parler à
//! soi-même n'est pas se mettre d'accord.
//!
//! Le pair est ici `openssl s_client -starttls smtp`, qui conduit la séquence
//! RFC 3207 complète — bannière, `EHLO`, `STARTTLS`, poignée de main — puis
//! laisse parler l'entrée standard **dans le tuyau chiffré**. C'est ce qui
//! permet de vérifier la remise à zéro de la session de l'autre côté du
//! chiffrement.
//!
//! # Celui-là, lui, TOURNE en intégration continue
//!
//! Contrairement au test d'interopérabilité de `ams-tls`, il n'exige aucun
//! groupe post-quantique : un OpenSSL 3.0 négocie `X25519` et la conversation se
//! déroule pareil. Il se saute tout de même si `openssl` manque — bruyamment,
//! parce qu'un test sauté ne prouve rien.

use std::process::{Command, Stdio};
use std::sync::Arc;

use ams_guard::{Thresholds, Verdict};
use ams_loop_tokio::{Error, Outcome, Service, SharedGuard, Timeouts, serve_connection};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

mod commun;

use commun::{Neant, NotreDomaine, PAIR, config, materiel};

// ── Ce qui ne demande aucun certificat ──────────────────────────────────────

#[tokio::test]
async fn annoncer_starttls_sans_materiel_est_refuse_avant_la_banniere() {
    // Un serveur qui annonce `STARTTLS` puis ne sait pas chiffrer a menti à son
    // pair dès la bannière — et le pair, lui, aura peut-être décidé d'envoyer un
    // mot de passe sur la foi de cette annonce. Le refus est donc AVANT le
    // premier octet, pas au moment du `STARTTLS`.
    let (mut serveur, _client) = tokio::io::duplex(1024);
    let garde = SharedGuard::new(4, Thresholds::DEFAULT);
    let service = Service {
        config: config(true, false),
        guard: &garde,
        timeouts: Timeouts::default(),
        tls: None,
        spf: None,
    };
    let resultat = serve_connection(&mut serveur, &service, NotreDomaine, &mut Neant, PAIR).await;
    assert!(matches!(resultat, Err(Error::CapabilityNotSupported)));
}

// ── Ce qui demande un certificat ────────────────────────────────────────────

#[tokio::test]
async fn une_commande_derriere_starttls_n_est_jamais_executee() {
    // CVE-2011-0411, en miniature. Le pair dépose `MAIL FROM` derrière son
    // `STARTTLS`, en pariant que ces octets survivront à la poignée de main et
    // passeront alors pour dits sous chiffrement.
    let Some(materiel) = materiel("injection") else {
        return;
    };
    let garde = SharedGuard::new(4, Thresholds::DEFAULT);
    let service = Service {
        config: config(true, false),
        guard: &garde,
        timeouts: Timeouts::default(),
        tls: Some(Arc::clone(&materiel.tls)),
        spf: None,
    };

    let (mut serveur, mut client) = tokio::io::duplex(4096);
    let bavard = tokio::spawn(async move {
        // TOUT EN UNE SEULE ÉCRITURE : c'est ce qui fait l'attaque. Un client
        // conforme attendrait le `220` avant d'écrire la ligne suivante.
        let _ = client
            .write_all(
                b"EHLO client.example\r\nSTARTTLS\r\nMAIL FROM:<pirate@ailleurs.example>\r\n",
            )
            .await;
        let mut recu = Vec::new();
        let _ = client.read_to_end(&mut recu).await;
        recu
    });

    let resume = serve_connection(&mut serveur, &service, NotreDomaine, &mut Neant, PAIR)
        .await
        .expect("connexion servie");
    drop(serveur);
    let dit = String::from_utf8_lossy(&bavard.await.expect("tâche cliente")).into_owned();

    assert_eq!(resume.outcome, Outcome::Injected);
    // Rien n'a été chiffré : la poignée de main n'a pas eu lieu.
    assert!(!resume.tls);
    // Et le `220 Ready to start TLS` n'a JAMAIS été dit. C'est le point : le
    // pair n'obtient pas le tuyau dans lequel il comptait replacer ses octets.
    assert!(
        !dit.contains("220 Ready to start TLS"),
        "le serveur a proposé de chiffrer malgré l'injection.\n{dit}"
    );
    assert!(dit.contains("421 "), "le refus n'a pas été dit.\n{dit}");
    // Le garde l'a vu passer : aucun client honnête ne fait cela par accident.
    assert!(garde.tracked() >= 1);
}

#[tokio::test]
async fn une_poignee_de_main_ratee_compte_comme_une_trame_invalide() {
    let Some(materiel) = materiel("poignee-ratee") else {
        return;
    };
    // Une seule trame invalide tolérée : si le garde compte la poignée de main
    // ratée, la source est bannie juste après.
    let garde = SharedGuard::new(
        4,
        Thresholds {
            // ZÉRO toléré : la toute première trame invalide bannit. Avec `1`,
            // il en faudrait deux — et le test passerait pour la mauvaise raison
            // en disant « pas banni » alors que le compte a bien eu lieu.
            invalid_frames_per_minute: 0,
            ..Thresholds::DEFAULT
        },
    );
    let service = Service {
        config: config(true, false),
        guard: &garde,
        timeouts: Timeouts::default(),
        tls: Some(Arc::clone(&materiel.tls)),
        spf: None,
    };

    let (mut serveur, mut client) = tokio::io::duplex(4096);
    let maladroit = tokio::spawn(async move {
        let mut tampon = [0_u8; 512];
        // La bannière.
        let _ = client.read(&mut tampon).await;
        let _ = client.write_all(b"EHLO client.example\r\n").await;
        let _ = client.read(&mut tampon).await;
        let _ = client.write_all(b"STARTTLS\r\n").await;
        let _ = client.read(&mut tampon).await;
        // Et maintenant, tout sauf un `ClientHello`.
        let _ = client.write_all(b"ceci n'est pas du TLS\r\n").await;
        let _ = client.shutdown().await;
        let mut reste = Vec::new();
        let _ = client.read_to_end(&mut reste).await;
    });

    let resultat = serve_connection(&mut serveur, &service, NotreDomaine, &mut Neant, PAIR).await;
    drop(serveur);
    let _ = maladroit.await;

    assert!(
        matches!(resultat, Err(Error::Io(_))),
        "une poignée de main ratée doit remonter comme une erreur d'entrée-sortie"
    );
    assert!(
        matches!(garde.verdict(PAIR), Verdict::Banned { .. }),
        "le pair n'a pas été compté fautif"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openssl_monte_en_chiffrement_et_le_ehlo_suivant_change() {
    let Some(materiel) = materiel("bout-en-bout") else {
        return;
    };

    let ecouteur = TcpListener::bind("127.0.0.1:0").await.expect("écoute");
    let adresse = ecouteur.local_addr().expect("adresse");
    let tls = Arc::clone(&materiel.tls);

    let serveur = tokio::spawn(async move {
        let (mut flux, _) = ecouteur.accept().await.expect("connexion");
        let garde = SharedGuard::new(4, Thresholds::DEFAULT);
        let service = Service {
            config: config(true, false),
            guard: &garde,
            timeouts: Timeouts::default(),
            tls: Some(tls),
            spf: None,
        };
        serve_connection(&mut flux, &service, NotreDomaine, &mut Neant, PAIR).await
    });

    // `-starttls smtp` conduit la séquence de la RFC 3207 en entier ; ce qui
    // suit sur l'entrée standard part DANS LE TUYAU CHIFFRÉ.
    let client = tokio::task::spawn_blocking(move || {
        use std::io::Write as _;
        let mut processus = Command::new("openssl")
            .args(["s_client", "-connect"])
            .arg(format!("127.0.0.1:{}", adresse.port()))
            // PAS de `-brief` ici, contrairement au test d'interopérabilité de
            // `ams-tls` : `-brief` referme la connexion dès la poignée de main
            // terminée, et il n'y aurait alors aucun dialogue chiffré à
            // observer — c'est-à-dire rien de ce que ce test cherche.
            //
            // `-ign_eof` est ce qui rend le test possible : sans lui, `s_client`
            // referme la connexion dès que son entrée standard est épuisée,
            // c'est-à-dire AVANT que la réponse du serveur n'arrive. Avec, il
            // attend que ce soit le serveur qui raccroche — ce que celui-ci fait
            // après le `QUIT`.
            .args(["-starttls", "smtp", "-ign_eof"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .ok()?;
        let entree = processus.stdin.as_mut()?;
        // Trois lignes, toutes CHIFFRÉES :
        //
        // 1. un SECOND `EHLO` — ce que la RFC 3207 §4.2 impose au client, puisque
        //    le serveur a tout oublié ;
        // 2. un SECOND `STARTTLS` — dont la réponse, `503 TLS already active`,
        //    ne peut venir que d'une session qui SAIT être déjà chiffrée. C'est
        //    la preuve que l'état a traversé la poignée de main, et cette
        //    réponse-là est impossible à confondre avec quoi que ce soit du
        //    dialogue en clair ;
        // 3. `QUIT`.
        entree
            .write_all(b"EHLO client.example\r\nSTARTTLS\r\nQUIT\r\n")
            .ok()?;
        processus.wait_with_output().ok()
    })
    .await
    .expect("tâche openssl");

    let Some(client) = client else {
        eprintln!("SAUTÉ : `openssl s_client` n'est pas lançable ici.");
        serveur.abort();
        return;
    };
    let resume = serveur.await.expect("tâche serveur");

    // LES DEUX FLUX SONT TENUS SÉPARÉS, et c'est le cœur de ce test.
    //
    // `s_client` écrit sur sa SORTIE STANDARD ce qu'il lit dans le tuyau
    // chiffré, et sur son ERREUR STANDARD sa propre trace — y compris l'écho de
    // la négociation SMTP EN CLAIR qu'il mène lui-même avant la poignée de main.
    // Les concaténer effacerait la seule chose qui distingue ici le chiffré du
    // clair, et toutes les assertions qui suivent deviendraient des passoires.
    // (Écrit après s'être fait prendre : la première version cherchait bien la
    // réponse au second `EHLO`, mais dans un texte où figurait aussi le premier.)
    let chiffre = String::from_utf8_lossy(&client.stdout).into_owned();
    let trace = String::from_utf8_lossy(&client.stderr).into_owned();
    let dit = format!("--- chiffré ---\n{chiffre}\n--- trace ---\n{trace}");

    assert!(
        trace.contains("TLSv1.3") || chiffre.contains("TLSv1.3"),
        "la connexion n'est pas en TLS 1.3 — C4.\n{dit}"
    );

    let resume = resume.expect("connexion servie");
    assert!(
        resume.tls,
        "le résumé ne dit pas que la connexion a chiffré"
    );
    assert_eq!(resume.outcome, Outcome::Served);

    // ── CE QUE LE SECOND `EHLO` PROUVE ──────────────────────────────────────
    //
    // Il a été envoyé APRÈS la poignée de main, donc chiffré, et le serveur y a
    // répondu : la session a bien continué par-dessus le nouveau tuyau. Et sa
    // réponse n'annonce plus `STARTTLS`, parce qu'il n'y a plus rien à démarrer.
    // ── CE QUE PROUVE CHAQUE LIGNE DU CANAL CHIFFRÉ ─────────────────────────
    //
    // 1. La session SE SOUVIENT d'être chiffrée. Cette réponse-là ne peut pas
    //    venir du dialogue en clair : avant la poignée de main, `STARTTLS`
    //    obtenait `220`. L'état a donc bien traversé le changement de tuyau.
    assert!(
        chiffre.contains("503 TLS already active"),
        "la session ne se souvient pas d'être chiffrée.\n{dit}"
    );
    // 2. Le second `EHLO`, chiffré, a été servi en entier.
    assert!(
        chiffre.contains("250-mail.example.com") && chiffre.contains("250 SIZE"),
        "le second EHLO, chiffré, n'a pas reçu de réponse.\n{dit}"
    );
    // 3. Et il n'annonce PLUS `STARTTLS`, parce qu'il n'y a plus rien à démarrer.
    //    La trace, elle, en porte encore la trace — c'est la négociation en
    //    clair, et sa présence là-bas confirme que les deux flux disent bien
    //    deux choses différentes.
    assert!(
        !chiffre.contains("STARTTLS"),
        "le serveur annonce encore STARTTLS une fois chiffré.\n{dit}"
    );
    // 3bis. Que la négociation en clair ait bien eu lieu se prouve de NOTRE côté,
    //    et pas en fouillant la trace d'OpenSSL — dont le format varie d'une
    //    version à l'autre, et qui ferait échouer ce test pour une raison
    //    étrangère au code. Cinq commandes comptées, c'est la séquence entière :
    //    `EHLO` et `STARTTLS` en clair, puis `EHLO`, `STARTTLS` et `QUIT`
    //    chiffrés. Le compteur, lui aussi, a traversé la poignée de main.
    assert_eq!(
        resume.commands, 5,
        "la séquence complète n'a pas été comptée.\n{dit}"
    );
    // 4. Le `QUIT` chiffré a eu son congé.
    assert!(
        chiffre.contains("221 "),
        "le `QUIT` chiffré n'a pas reçu son `221`.\n{dit}"
    );
}
