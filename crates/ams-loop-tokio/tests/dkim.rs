// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **DKIM, câblé dans la boucle SMTP** (C9).
//!
//! # Ce que ces épreuves ajoutent aux autres
//!
//! La vérification est couverte à 100 % chez elle, contre des vecteurs
//! extérieurs. Ce qui ne l'est nulle part ailleurs, c'est la JONCTION : que le
//! bloc d'en-tête soit retenu pendant que le corps s'écoule, que la clé soit
//! allée se chercher au bon nom, et que le verdict arrive dans le résumé de la
//! connexion.
//!
//! Le message signé de ces épreuves l'a été par OpenSSL, sur un bloc d'en-têtes
//! canonicalisé par une implémentation Python écrite séparément. Si le câblage
//! donnait à condenser autre chose que ce qui a été signé, rien ne vérifierait.

mod commun;

use ams_guard::Thresholds;
use ams_loop_tokio::{
    DkimChecker, DkimStream, DkimVerdict, Resolver, Service, SharedGuard, Timeouts,
    serve_connection,
};
use ams_proto_smtp::Limits;
use ams_session::Config;
use commun::{Neant, NotreDomaine, PAIR, nulle_part, resolveur_txt};
use core::time::Duration;
use std::net::SocketAddr;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// L'enregistrement de clé publié sous `brisbane._domainkey.example.com`.
const CLE: &str = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx6X1Z8atmh0Hi6UhKel/kQjPVpzANayrU7CW+Ds8LPQfHgnHu2xys6Telb22NitOEcIL3BufK1wzm+6AXU42QbSxIXOlzwbiM1r6/1nzaLd0iGrrZyBIlAoAAE5jM/7Hh12Pgf5WFyV1fAfof1OcN5/jqs/PKIn12zer+nBX2XFRHUWeT9mBmCHe2LaP2mbEkeq3waiOvlGQ1N9IrHPYeuiPlB3yAxBn9+FXI1lEamF7u4lVBNc921dGMxDZvE9XPNL9qHRRU8RHwhEeQjO4yVaLGxNlmNOnIukKpdic/WyxcjiK951IEjVj2EOzPxd+N574bs57d9A8RmOa3uU9OQIDAQAB";

/// La signature du message d'épreuve.
const B: &str = "g5OKVTgIYQUyq9A2gE95pwI7a1A9SaKub+1WiXm/7aSYmgfJK6unxdE21/i4YhlC8pTrUukqkKf+YICy5WfITO4Nt+0x6lvfWcFLM1yHzL/3eDXjBd0na63VVIfv827zgdIXVNDYCtsL1Il2RPiJ2WmAAmP/lMvx4/yISRVN+z5B6RtQ7QzGLveNzfBf6I35Iz1OrWz6QQ4A7/BwKLUeKCWSjpnFK+wJeZ5is2dnz1cEaP9IERGu9jSeMwK3mjVVfmD9HHCeS5PUr5i1nLoidl/KXx52jnPcgDSldaYlINPssxdahtzJW+Treq03CUSCrAIIEmcXaISEhmfT538Piw==";

/// Le message signé, tel qu'il arrive après le `DATA`.
fn message() -> String {
    std::format!(
        "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=brisbane;\r\n \
         h=from:to:subject:date;\r\n bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n \
         b={B}\r\n\
         From: Joe SixPack <joe@football.example.com>\r\n\
         To: Suzie Q <suzie@shopping.example.net>\r\n\
         Subject: Is dinner ready?\r\n\
         Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n\
         \r\n\
         Hi.\r\n\r\nWe lost the game. Are you hungry yet?\r\n\r\nJoe.\r\n"
    )
}

/// Conduit un message dans le vérificateur, et rend ses verdicts.
async fn verdicts(message: &str, resolveur: SocketAddr, morceaux: usize) -> Vec<DkimVerdict> {
    let checker = DkimChecker::new(
        Resolver::new(std::vec![resolveur], Duration::from_secs(2)).expect("résolveur"),
    );
    let mut flux = DkimStream::new(true);
    for morceau in message.as_bytes().chunks(morceaux.max(1)) {
        flux.update(morceau);
    }
    flux.finish(&checker)
        .await
        .into_iter()
        .map(|resultat| resultat.verdict)
        .collect()
}

#[tokio::test]
async fn une_signature_juste_passe() {
    let resolveur = resolveur_txt(CLE).await;
    assert_eq!(
        verdicts(&message(), resolveur, 4096).await,
        [DkimVerdict::Pass]
    );
}

#[tokio::test]
async fn le_decoupage_du_message_ne_change_rien() {
    // LE PAIR CHOISIT LA TAILLE DE SES PAQUETS, et la ligne vide qui sépare
    // en-tête et corps peut être coupée en deux. Un octet à la fois est le
    // découpage qui casse les implémentations naïves.
    let resolveur = resolveur_txt(CLE).await;
    for taille in [1, 2, 3, 7, 64] {
        assert_eq!(
            verdicts(&message(), resolveur, taille).await,
            [DkimVerdict::Pass],
            "par morceaux de {taille}"
        );
    }
}

#[tokio::test]
async fn un_corps_modifie_fait_echouer_la_signature() {
    let resolveur = resolveur_txt(CLE).await;
    let altere = message().replace("Are you hungry yet?", "Are you hungry now?");
    assert_eq!(
        verdicts(&altere, resolveur, 4096).await,
        [DkimVerdict::Fail]
    );
}

#[tokio::test]
async fn un_en_tete_signe_modifie_fait_echouer_la_signature() {
    let resolveur = resolveur_txt(CLE).await;
    let altere = message().replace("Is dinner ready?", "Is dinner burnt?");
    assert_eq!(
        verdicts(&altere, resolveur, 4096).await,
        [DkimVerdict::Fail]
    );
}

#[tokio::test]
async fn un_en_tete_ajoute_en_haut_ne_casse_rien() {
    // Un relais qui ajoute un `Received:` en tête ne doit pas invalider une
    // signature : `h=` ne le nomme pas, et les champs se prennent depuis le bas.
    let resolveur = resolveur_txt(CLE).await;
    let ajoute = std::format!("Received: by un.relais.example\r\n{}", message());
    assert_eq!(
        verdicts(&ajoute, resolveur, 4096).await,
        [DkimVerdict::Pass]
    );
}

#[tokio::test]
async fn une_cle_revoquee_est_un_permerror() {
    // `p=` vide : le détenteur du domaine dit que cette clé ne doit plus rien
    // signer.
    let resolveur = resolveur_txt("v=DKIM1; k=rsa; p=").await;
    assert_eq!(
        verdicts(&message(), resolveur, 4096).await,
        [DkimVerdict::PermError]
    );
}

#[tokio::test]
async fn une_cle_absente_est_un_permerror() {
    // Le sélecteur ne publie rien : cette signature ne se vérifiera JAMAIS.
    // Ajourner ferait revenir un message qui échouera pareil.
    let resolveur = resolveur_txt("").await;
    assert_eq!(
        verdicts(&message(), resolveur, 4096).await,
        [DkimVerdict::PermError]
    );
}

#[tokio::test]
async fn un_resolveur_injoignable_est_un_temperror() {
    // Le pair peut réessayer : la clé existe peut-être, on n'a pas su demander.
    assert_eq!(
        verdicts(&message(), nulle_part(), 4096).await,
        [DkimVerdict::TempError]
    );
}

#[tokio::test]
async fn un_message_sans_signature_ne_rend_aucun_verdict() {
    // C'est le `none` de la RFC 8601, et c'est la moitié du courrier.
    let resolveur = resolveur_txt(CLE).await;
    let sans = "From: jean@example.com\r\n\r\nBonjour.\r\n";
    assert!(verdicts(sans, resolveur, 4096).await.is_empty());
}

#[tokio::test]
async fn une_signature_illisible_ne_coute_aucune_resolution() {
    // Elle n'occupe pas une des places : ni résolution, ni exponentiation.
    let resolveur = resolveur_txt(CLE).await;
    let mechante = "DKIM-Signature: v=42; oups\r\nFrom: jean@example.com\r\n\r\nBonjour.\r\n";
    assert!(verdicts(mechante, resolveur, 4096).await.is_empty());
}

// ── DANS LA BOUCLE ──────────────────────────────────────────────────────────

#[tokio::test]
async fn le_resume_de_la_connexion_porte_le_verdict() {
    // C'est là que le verdict va : le résumé, que le journal lira. Rien n'est
    // écrit dans le message — l'en-tête de résultat se pose EN TÊTE, or à ce
    // moment-là le corps n'a pas encore été lu.
    let resolveur = resolveur_txt(CLE).await;
    let checker = DkimChecker::new(
        Resolver::new(std::vec![resolveur], Duration::from_secs(2)).expect("résolveur"),
    );
    let ecouteur = TcpListener::bind("127.0.0.1:0").await.expect("écoute");
    let adresse = ecouteur.local_addr().expect("adresse");

    let serveur = tokio::spawn(async move {
        let (mut flux, _) = ecouteur.accept().await.expect("connexion");
        let garde = SharedGuard::new(4, Thresholds::DEFAULT);
        let service = Service {
            config: Config::new(b"mail.example.com", 100, 10_485_760, Limits::DEFAULT)
                .expect("configurable"),
            guard: &garde,
            timeouts: Timeouts::default(),
            tls: None,
            spf: None,
            dkim: Some(checker),
            dmarc: None,
        };
        serve_connection(&mut flux, &service, NotreDomaine, &mut Neant, PAIR).await
    });

    let flux = TcpStream::connect(adresse).await.expect("connexion");
    let mut lecteur = BufReader::new(flux);
    let mut ligne = String::new();
    lecteur.read_line(&mut ligne).await.expect("bannière");
    for commande in [
        "EHLO client.example.net",
        "MAIL FROM:<joe@football.example.com>",
        "RCPT TO:<marie@example.com>",
        "DATA",
    ] {
        let ecrit = std::format!("{commande}\r\n");
        lecteur
            .get_mut()
            .write_all(ecrit.as_bytes())
            .await
            .expect("écriture");
        loop {
            ligne.clear();
            lecteur.read_line(&mut ligne).await.expect("réponse");
            if ligne.as_bytes().get(3) != Some(&b'-') {
                break;
            }
        }
    }
    let corps = std::format!("{}.\r\n", message());
    lecteur
        .get_mut()
        .write_all(corps.as_bytes())
        .await
        .expect("corps");
    ligne.clear();
    lecteur.read_line(&mut ligne).await.expect("fin");
    assert!(ligne.starts_with("250"), "{ligne}");
    drop(lecteur);

    let resume = serveur.await.expect("tâche").expect("servie");
    assert_eq!(resume.dkim.pass, 1, "{:?}", resume.dkim);
    assert_eq!(resume.dkim.fail, 0);
    assert_eq!(resume.dkim.temp_error, 0);
    assert_eq!(resume.dkim.perm_error, 0);
    assert_eq!(resume.messages, 1);
}

// ── LES BORNES ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn un_bloc_d_en_tete_demesure_fait_renoncer_a_verifier() {
    // Il est RETENU en entier — il faut pouvoir relire les champs que `h=`
    // nomme. Au-delà de la borne, on ne vérifie plus rien plutôt que de laisser
    // un pair choisir combien de mémoire il occupe. Le message, lui, passe : la
    // session l'a accepté, et DKIM ne refuse personne.
    let resolveur = resolveur_txt(CLE).await;
    let bourrage = "X-Rembourrage: ".to_string() + &"a".repeat(300) + "\r\n";
    let enorme = bourrage.repeat(1000) + &message();
    assert!(enorme.len() > 256 * 1024);
    assert!(verdicts(&enorme, resolveur, 4096).await.is_empty());
}

#[tokio::test]
async fn le_nombre_de_signatures_verifiees_est_borne() {
    // Chacune coûte une résolution DNS et une exponentiation modulaire. Un
    // message qui en porterait cent ferait travailler la machine cent fois pour
    // un seul envoi : c'est une amplification, et elle se borne.
    let resolveur = resolveur_txt(CLE).await;
    let une = "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=x; h=from; \
               bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=; b=AAAA\r\n";
    let beaucoup = une.repeat(20) + "From: jean@example.com\r\n\r\nBonjour.\r\n";
    let rendus = verdicts(&beaucoup, resolveur, 4096).await;
    assert_eq!(rendus.len(), 5, "{rendus:?}");
}
