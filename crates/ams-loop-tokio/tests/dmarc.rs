// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **DMARC, câblé dans la boucle SMTP** (C9).
//!
//! # C'est le seul endroit où un message est refusé pour ce qu'il PRÉTEND être
//!
//! SPF refuse une enveloppe, le garde refuse un débit, la session refuse une
//! syntaxe. DMARC, lui, refuse un message dont le `From:` ne correspond à rien
//! de ce qui a été authentifié — et il ne le fait que si le domaine de ce
//! `From:` le demande.

mod commun;

use ams_guard::Thresholds;
use ams_loop_tokio::{
    Authenticated, DmarcChecker, DmarcVerdict, Resolver, Service, SharedGuard, Timeouts,
    serve_connection,
};
use ams_proto_smtp::Limits;
use ams_session::Config;
use commun::{Neant, NotreDomaine, PAIR, nulle_part, resolveur_par_nom};
use core::time::Duration;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// Un extrait de la liste des suffixes publics.
const SUFFIXES: &[u8] = b"com\nnet\nco.uk\n";

/// Le bloc d'en-tête d'un message ordinaire.
const ENTETES: &[u8] = b"From: Joe SixPack <joe@example.com>\r\n\
                         To: Marie <marie@example.net>\r\n\
                         Subject: Bonjour\r\n\r\n";

fn checker(resolveur: SocketAddr, applique: bool) -> DmarcChecker {
    DmarcChecker::new(
        Resolver::new(std::vec![resolveur], Duration::from_secs(2)).expect("résolveur"),
        Arc::new(SUFFIXES.to_vec()),
        applique,
    )
}

fn authentifie(spf: Option<&str>, dkim: &[&str]) -> Authenticated {
    Authenticated {
        spf: spf.map(std::string::ToString::to_string),
        dkim: dkim.iter().map(|nom| (*nom).to_string()).collect(),
    }
}

// ── UN SEUL MÉCANISME SUFFIT ────────────────────────────────────────────────

#[tokio::test]
async fn une_signature_alignee_suffit() {
    let table: &[(&str, &str)] = &[("_dmarc.example.com", "v=DMARC1; p=reject")];
    let resolveur = resolveur_par_nom(table).await;
    let resultat = checker(resolveur, true)
        .verdict(ENTETES, &authentifie(None, &["example.com"]))
        .await;
    assert_eq!(resultat.verdict, DmarcVerdict::Pass);
    assert!(!resultat.applies);
    assert_eq!(resultat.domain, "example.com");
}

#[tokio::test]
async fn une_enveloppe_alignee_suffit() {
    let table: &[(&str, &str)] = &[("_dmarc.example.com", "v=DMARC1; p=reject")];
    let resolveur = resolveur_par_nom(table).await;
    let resultat = checker(resolveur, true)
        .verdict(ENTETES, &authentifie(Some("envoi.example.com"), &[]))
        .await;
    assert_eq!(
        resultat.verdict,
        DmarcVerdict::Pass,
        "l'alignement est relâché"
    );
}

#[tokio::test]
async fn un_mecanisme_qui_reussit_sans_s_aligner_ne_vaut_rien() {
    // C'EST L'USURPATION QUE DMARC FERME : l'attaquant émet depuis un domaine
    // qu'il détient, le signe, et écrit ce qu'il veut dans le `From:`.
    let table: &[(&str, &str)] = &[("_dmarc.example.com", "v=DMARC1; p=reject")];
    let resolveur = resolveur_par_nom(table).await;
    let resultat = checker(resolveur, true)
        .verdict(
            ENTETES,
            &authentifie(Some("attaquant.net"), &["attaquant.net"]),
        )
        .await;
    assert_eq!(resultat.verdict, DmarcVerdict::Fail);
    assert!(resultat.applies, "un `p=reject` appliqué doit s'appliquer");
}

// ── LA POLITIQUE, ET CE QU'ON EN FAIT ───────────────────────────────────────

#[tokio::test]
async fn en_observation_rien_n_est_oppose() {
    // C'est l'état où l'on découvre ce qu'une politique refuserait — et il faut
    // y rester quelque temps : un domaine qui publie `p=reject` refuse aussi le
    // courrier de ses propres listes de diffusion.
    let table: &[(&str, &str)] = &[("_dmarc.example.com", "v=DMARC1; p=reject")];
    let resolveur = resolveur_par_nom(table).await;
    let resultat = checker(resolveur, false)
        .verdict(ENTETES, &authentifie(None, &[]))
        .await;
    assert_eq!(resultat.verdict, DmarcVerdict::Fail);
    assert!(!resultat.applies);
}

#[tokio::test]
async fn une_politique_qui_ne_demande_rien_ne_s_applique_pas() {
    // `p=none` EST une politique : le domaine demande des rapports, pas des
    // refus. Lui refuser du courrier reviendrait à décider à sa place.
    let table: &[(&str, &str)] = &[("_dmarc.example.com", "v=DMARC1; p=none")];
    let resolveur = resolveur_par_nom(table).await;
    let resultat = checker(resolveur, true)
        .verdict(ENTETES, &authentifie(None, &[]))
        .await;
    assert_eq!(resultat.verdict, DmarcVerdict::Fail);
    assert!(!resultat.applies);
}

#[tokio::test]
async fn un_tirage_a_zero_pour_cent_n_applique_jamais() {
    let table: &[(&str, &str)] = &[("_dmarc.example.com", "v=DMARC1; p=reject; pct=0")];
    let resolveur = resolveur_par_nom(table).await;
    let resultat = checker(resolveur, true)
        .verdict(ENTETES, &authentifie(None, &[]))
        .await;
    assert_eq!(resultat.verdict, DmarcVerdict::Fail);
    assert!(!resultat.applies);
}

#[tokio::test]
async fn la_politique_se_cherche_aussi_sous_le_domaine_organisationnel() {
    // §6.6.3, EN DEUX TEMPS : rien sous `envoi.example.com`, donc on recommence
    // sous `example.com` — et c'est alors `sp=` qui décide, puisque le message
    // vient d'un sous-domaine.
    let table: &[(&str, &str)] = &[("_dmarc.example.com", "v=DMARC1; p=none; sp=reject")];
    let resolveur = resolveur_par_nom(table).await;
    let entetes = b"From: joe@envoi.example.com\r\n\r\n";
    let resultat = checker(resolveur, true)
        .verdict(entetes, &authentifie(None, &[]))
        .await;
    assert_eq!(resultat.verdict, DmarcVerdict::Fail);
    assert!(
        resultat.applies,
        "c'est `sp=reject` qui s'applique, pas `p=none`"
    );
}

#[tokio::test]
async fn un_domaine_sans_politique_ne_dit_rien() {
    let resolveur = resolveur_par_nom(&[]).await;
    let resultat = checker(resolveur, true)
        .verdict(ENTETES, &authentifie(None, &[]))
        .await;
    assert_eq!(resultat.verdict, DmarcVerdict::NoPolicy);
    assert!(!resultat.applies);
}

#[tokio::test]
async fn un_txt_qui_parle_d_autre_chose_n_est_pas_une_politique() {
    let table: &[(&str, &str)] = &[("_dmarc.example.com", "google-site-verification=x")];
    let resolveur = resolveur_par_nom(table).await;
    let resultat = checker(resolveur, true)
        .verdict(ENTETES, &authentifie(None, &[]))
        .await;
    assert_eq!(resultat.verdict, DmarcVerdict::NoPolicy);
}

#[tokio::test]
async fn un_resolveur_injoignable_ajourne() {
    let resultat = checker(nulle_part(), true)
        .verdict(ENTETES, &authentifie(None, &[]))
        .await;
    assert_eq!(resultat.verdict, DmarcVerdict::TempError);
    assert!(!resultat.applies);
}

// ── CE QU'ON NE SAIT PAS LIRE ───────────────────────────────────────────────

#[tokio::test]
async fn un_from_illisible_ou_multiple_rend_le_message_inutilisable() {
    // §6.6.1 : avec deux auteurs, il y a deux politiques, et rien pour dire
    // laquelle s'applique.
    let table: &[(&str, &str)] = &[("_dmarc.example.com", "v=DMARC1; p=reject")];
    let resolveur = resolveur_par_nom(table).await;
    let verificateur = checker(resolveur, true);
    for entetes in [
        &b"From: joe@example.com, marie@example.net\r\n\r\n"[..],
        b"From: Joe SixPack\r\n\r\n",
        b"To: marie@example.net\r\n\r\n",
        // DEUX champs `From:` : la RFC 5322 §3.6 n'en admet qu'un.
        b"From: joe@example.com\r\nFrom: marie@example.net\r\n\r\n",
        b"",
    ] {
        let resultat = verificateur.verdict(entetes, &authentifie(None, &[])).await;
        assert_eq!(
            resultat.verdict,
            DmarcVerdict::Unusable,
            "{}",
            std::string::String::from_utf8_lossy(entetes)
        );
        assert!(!resultat.applies);
    }
}

// ── DANS LA BOUCLE ──────────────────────────────────────────────────────────

/// Joue une transaction complète, et rend la réponse au point final.
async fn message_refuse(applique: bool) -> (std::string::String, u32) {
    let table: &[(&str, &str)] = &[("_dmarc.example.com", "v=DMARC1; p=reject")];
    let resolveur = resolveur_par_nom(table).await;
    let verificateur = checker(resolveur, applique);
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
            dkim: None,
            dmarc: Some(verificateur),
            reports: None,
        };
        serve_connection(&mut flux, &service, NotreDomaine, &mut Neant, PAIR).await
    });

    let flux = TcpStream::connect(adresse).await.expect("connexion");
    let mut lecteur = BufReader::new(flux);
    let mut ligne = std::string::String::new();
    lecteur.read_line(&mut ligne).await.expect("bannière");
    for commande in [
        "EHLO client.example.net",
        "MAIL FROM:<personne@ailleurs.test>",
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
    let corps = "From: Joe SixPack <joe@example.com>\r\n\
                 Subject: je ne suis pas Joe\r\n\r\n\
                 Bonjour.\r\n.\r\n";
    lecteur
        .get_mut()
        .write_all(corps.as_bytes())
        .await
        .expect("corps");
    ligne.clear();
    lecteur.read_line(&mut ligne).await.expect("fin");
    drop(lecteur);
    let resume = serveur.await.expect("tâche").expect("servie");
    (ligne, resume.dmarc.applied)
}

#[tokio::test]
async fn un_message_usurpe_est_refuse_au_point_final() {
    // Rien n'a été authentifié, le `From:` dit `example.com`, et ce domaine
    // demande le rejet. C'EST LE SEUL ENDROIT DU SERVEUR où un message est
    // refusé pour ce qu'il prétend être.
    let (reponse, appliquees) = message_refuse(true).await;
    assert!(reponse.starts_with("550 5.7.1"), "{reponse}");
    assert_eq!(appliquees, 1);
}

#[tokio::test]
async fn en_observation_le_meme_message_passe() {
    let (reponse, appliquees) = message_refuse(false).await;
    assert!(reponse.starts_with("250"), "{reponse}");
    assert_eq!(appliquees, 0);
}
