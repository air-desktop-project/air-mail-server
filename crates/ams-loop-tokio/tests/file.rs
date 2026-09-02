// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **La file de réémission**, éprouvée sur un vrai dossier.
//!
//! # CE QUE CES ESSAIS ATTRAPENT, ET QUE RIEN D'AUTRE N'ATTRAPE
//!
//! `ams-queue` sait quand réessayer et quand renoncer, et il est couvert à
//! 100 %. Mais il ne touche à aucun fichier : ce qui reste à éprouver, c'est le
//! passage de sa décision au disque — le renommage qui porte l'état, l'enveloppe
//! qui suit le message, et le rapport de non-remise qui part quand on abandonne.
//!
//! Le résolveur pointe vers une adresse où rien n'écoute. Ce n'est pas un
//! contournement : c'est exactement la panne que la file existe pour absorber,
//! et elle rend `Unreachable`, donc un ajournement. Les deux chemins qui comptent
//! — celui qui réessaie et celui qui renonce — se jouent donc en entier.

use core::time::Duration;
use std::sync::{Arc, Mutex};

use ams_loop_tokio::{Bounced, Relay, Resolver, Spool};
use ams_queue::Backoff;

/// Un rapport tel qu'il a été remis : à qui, et quoi.
type Remis = (String, Vec<u8>);

/// Ce qu'on remet localement, retenu pour être lu.
#[derive(Clone, Default)]
struct Cahier(Arc<Mutex<Vec<Remis>>>);

impl Bounced for Cahier {
    fn deliver(&self, recipient: &str, message: &[u8]) -> bool {
        self.0
            .lock()
            .expect("verrou")
            .push((String::from(recipient), message.to_vec()));
        true
    }
}

impl Cahier {
    fn rapports(&self) -> Vec<(String, String)> {
        self.0
            .lock()
            .expect("verrou")
            .iter()
            .map(|(a, m)| (a.clone(), String::from_utf8_lossy(m).into_owned()))
            .collect()
    }
}

/// Un remetteur dont le résolveur ne mène nulle part : toute remise est une
/// panne, donc un ajournement.
fn remetteur() -> Relay {
    Relay::new(
        Resolver::new(
            vec!["127.0.0.1:1".parse().expect("adresse")],
            Duration::from_millis(50),
        )
        .expect("résolveur"),
        Arc::new(ams_tls::relay_config()),
        String::from("mail.nous.test"),
        false,
        Duration::from_millis(200),
    )
}

/// Un répertoire temporaire qui se nettoie tout seul.
///
/// La même façon de faire que les essais de `ams-store`, et pour la même
/// raison : cette crate écrit de VRAIS fichiers, et simuler le système de
/// fichiers reviendrait à mesurer la simulation.
struct Ephemere(std::path::PathBuf);

impl Ephemere {
    fn nouveau() -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static RANG: AtomicU32 = AtomicU32::new(0);
        let chemin = std::env::temp_dir().join(format!(
            "ams-file-{}-{}",
            std::process::id(),
            RANG.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&chemin);
        std::fs::create_dir_all(&chemin).expect("répertoire temporaire");
        Self(chemin)
    }

    fn chemin(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for Ephemere {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Une file dans un dossier neuf, avec la reprise qu'on lui donne.
fn file(reprise: Backoff) -> (Spool, Ephemere) {
    let dossier = Ephemere::nouveau();
    let spool = Spool::new(
        dossier.chemin().to_path_buf(),
        reprise,
        String::from("mail.nous.test"),
        String::from("postmaster@mail.nous.test"),
    );
    (spool, dossier)
}

/// Les noms du dossier, triés.
fn noms(dossier: &std::path::Path) -> Vec<String> {
    let mut vus: Vec<String> = std::fs::read_dir(dossier)
        .expect("lisible")
        .filter_map(|entree| entree.ok())
        .map(|entree| entree.file_name().to_string_lossy().into_owned())
        .collect();
    vus.sort();
    vus
}

const MESSAGE: &[u8] = b"From: jean@nous.test\r\nSubject: bonjour\r\n\r\nun corps\r\n";

/// **UN ÉCHEC RENOMME L'ENTRÉE, ET NE LA PERD PAS.**
///
/// Le nom porte tout l'état de la reprise : après un essai, il doit dire un
/// essai de plus et une reprise plus tard. L'enveloppe, elle, ne bouge pas —
/// c'est ce qui rend le renommage atomique à lui seul.
#[tokio::test(flavor = "multi_thread")]
async fn un_echec_repousse_l_entree_sans_la_perdre() {
    let reprise = Backoff {
        first: Duration::from_secs(100),
        ceiling: Duration::from_secs(1_000),
        expiry: Duration::from_secs(100_000),
    };
    let (spool, dossier) = file(reprise);
    spool
        .deposer(
            "jean@nous.test",
            &[String::from("marie@ailleurs.test")],
            &[],
            "",
            MESSAGE,
            1_000,
        )
        .expect("déposé");

    let avant = noms(dossier.chemin());
    assert_eq!(avant.len(), 2, "{avant:?}");
    let enveloppe = avant
        .iter()
        .find(|nom| nom.ends_with(".enveloppe"))
        .expect("une enveloppe")
        .clone();

    let cahier = Cahier::default();
    let compte = spool.parcourir(&remetteur(), &cahier, 1_000).await;
    assert_eq!(compte.deferred, 1, "{compte:?}");
    assert_eq!(compte.bounced, 0);
    assert!(cahier.rapports().is_empty(), "personne ne renonce encore");

    let apres = noms(dossier.chemin());
    assert_eq!(apres.len(), 2, "{apres:?}");
    // L'ENVELOPPE N'A PAS CHANGÉ DE NOM : son nom ne dépend que de
    // l'identifiant, et c'est ce qui évite d'avoir deux renommages à réussir
    // ensemble.
    assert!(apres.contains(&enveloppe), "{apres:?}");
    let entree = apres
        .iter()
        .find(|nom| nom.ends_with(".eml"))
        .expect("une entrée");
    let part = ams_queue::parse_name(entree).expect("un nom d'entrée");
    assert_eq!(part.attempts, 1, "un essai de plus");
    assert_eq!(part.deposited, 1_000, "le dépôt ne bouge pas");
    assert_eq!(part.due, 1_100, "la première attente");
}

/// **RIEN N'EST REPRIS AVANT L'HEURE.**
///
/// Sans cela, un passage suivrait l'autre sans attendre, et la file martèlerait
/// un pair en panne aussi vite que le disque tourne.
#[tokio::test(flavor = "multi_thread")]
async fn rien_n_est_repris_avant_l_heure() {
    let reprise = Backoff {
        first: Duration::from_secs(100),
        ceiling: Duration::from_secs(1_000),
        expiry: Duration::from_secs(100_000),
    };
    let (spool, _dossier) = file(reprise);
    spool
        .deposer(
            "jean@nous.test",
            &[String::from("marie@ailleurs.test")],
            &[],
            "",
            MESSAGE,
            1_000,
        )
        .expect("déposé");
    let cahier = Cahier::default();
    assert_eq!(
        spool.parcourir(&remetteur(), &cahier, 1_000).await.deferred,
        1
    );
    // Une seconde plus tard, l'entrée n'est pas due : on ne la touche pas.
    let compte = spool.parcourir(&remetteur(), &cahier, 1_001).await;
    assert_eq!(compte, ams_loop_tokio::QueueTally::default(), "{compte:?}");
}

/// **QUAND ON RENONCE, UN RAPPORT PART — ET IL RESTE ICI.**
///
/// Il est remis LOCALEMENT, à l'adresse du chemin de retour. Ce serveur ne
/// relaie que pour ses comptes, donc aucun rebond ne part vers un inconnu.
#[tokio::test(flavor = "multi_thread")]
async fn la_peremption_rend_le_message_a_son_expediteur() {
    let reprise = Backoff {
        first: Duration::from_secs(1),
        ceiling: Duration::from_secs(1),
        expiry: Duration::from_secs(10),
    };
    let (spool, dossier) = file(reprise);
    spool
        .deposer(
            "jean@nous.test",
            &[String::from("marie@ailleurs.test")],
            &[],
            "",
            MESSAGE,
            1_000,
        )
        .expect("déposé");

    let cahier = Cahier::default();
    // À l'échéance exacte : l'essai a lieu, il échoue, et il n'y a plus de temps.
    let compte = spool.parcourir(&remetteur(), &cahier, 1_010).await;
    assert_eq!(compte.bounced, 1, "{compte:?}");
    assert_eq!(compte.deferred, 0);

    // LES DEUX FICHIERS ONT DISPARU : rien ne réessaiera.
    assert!(
        noms(dossier.chemin()).is_empty(),
        "{:?}",
        noms(dossier.chemin())
    );

    let rapports = cahier.rapports();
    assert_eq!(rapports.len(), 1, "{rapports:?}");
    let (destinataire, rapport) = &rapports[0];
    assert_eq!(destinataire, "jean@nous.test", "le chemin de retour");
    // Ce que RFC 3464 exige, et ce que le client lira.
    assert!(rapport.starts_with("Return-Path: <>\r\n"), "{rapport}");
    assert!(rapport.contains("To: <jean@nous.test>\r\n"), "{rapport}");
    assert!(
        rapport.contains("Content-Type: multipart/report; report-type=delivery-status;"),
        "{rapport}"
    );
    assert!(
        rapport.contains("Final-Recipient: rfc822; marie@ailleurs.test\r\n"),
        "{rapport}"
    );
    assert!(rapport.contains("Action: failed\r\n"), "{rapport}");
    assert!(rapport.contains("Reporting-MTA: dns; mail.nous.test\r\n"));
    // LES EN-TÊTES DU MESSAGE PERDU, ET PAS SON CORPS.
    assert!(rapport.contains("Subject: bonjour\r\n"), "{rapport}");
    assert!(!rapport.contains("un corps"), "le corps ne revient pas");
}

/// **UN DOSSIER QU'ON PARTAGE NE SE REPREND PAS AU JUGÉ.**
///
/// Ce qui n'a pas la forme d'une entrée n'est ni lu, ni renommé, ni effacé.
#[tokio::test(flavor = "multi_thread")]
async fn ce_qui_n_est_pas_une_entree_n_est_pas_touche() {
    let (spool, dossier) = file(Backoff::DEFAULT);
    std::fs::write(dossier.chemin().join("README"), b"rien a voir").expect("écrit");
    std::fs::write(dossier.chemin().join("notes.txt"), b"non plus").expect("écrit");

    let cahier = Cahier::default();
    let compte = spool.parcourir(&remetteur(), &cahier, 2_000).await;
    assert_eq!(compte, ams_loop_tokio::QueueTally::default(), "{compte:?}");
    assert_eq!(noms(dossier.chemin()), ["README", "notes.txt"]);
}

/// **SANS ENVELOPPE, ON NE SAIT NI À QUI REMETTRE NI À QUI RENDRE COMPTE.**
///
/// Garder l'entrée ne servirait qu'à relire indéfiniment un fichier qui ne dira
/// jamais rien de plus.
#[tokio::test(flavor = "multi_thread")]
async fn une_entree_sans_enveloppe_est_retiree() {
    let (spool, dossier) = file(Backoff::DEFAULT);
    let orpheline = "000000001000!000000001000!0!abcdef.eml";
    std::fs::write(dossier.chemin().join(orpheline), MESSAGE).expect("écrit");

    let cahier = Cahier::default();
    let compte = spool.parcourir(&remetteur(), &cahier, 2_000).await;
    assert_eq!(compte.unreadable, 1, "{compte:?}");
    assert!(noms(dossier.chemin()).is_empty());
    // ET AUCUN RAPPORT : on ne saurait pas à qui l'adresser.
    assert!(cahier.rapports().is_empty());
}

/// **UNE ADRESSE QU'ON REFUSE D'ÉCRIRE EST UN REFUS DÉFINITIF.**
///
/// Un `LF` glissé dans une adresse ajouterait une ligne à l'enveloppe —
/// c'est-à-dire un destinataire — et aucune reprise ne le rendrait acceptable.
#[test]
fn une_adresse_qui_injecterait_une_ligne_est_refusee() {
    let (spool, dossier) = file(Backoff::DEFAULT);
    assert_eq!(
        spool.deposer(
            "jean@nous.test",
            &[String::from("marie@ailleurs.test\nvictime@banque.test")],
            &[],
            "",
            MESSAGE,
            1_000,
        ),
        Err(ams_loop_tokio::DeliveryFailure::Permanent)
    );
    // ET RIEN N'EST RESTÉ : ni message, ni enveloppe à moitié écrite.
    assert!(
        noms(dossier.chemin()).is_empty(),
        "{:?}",
        noms(dossier.chemin())
    );
}

/// **UN DÉPÔT SANS DESTINATAIRE NE VEUT RIEN DIRE.**
#[test]
fn un_depot_sans_destinataire_est_refuse() {
    let (spool, _dossier) = file(Backoff::DEFAULT);
    assert_eq!(
        spool.deposer("jean@nous.test", &[], &[], "", MESSAGE, 1_000),
        Err(ams_loop_tokio::DeliveryFailure::Permanent)
    );
}

/// **DEUX DÉPÔTS DE LA MÊME SECONDE NE SE MARCHENT PAS DESSUS.**
///
/// Sans identifiant distinct, le second écraserait le premier — et un message
/// disparaîtrait sans que rien ne le dise.
#[test]
fn deux_depots_de_la_meme_seconde_coexistent() {
    let (spool, dossier) = file(Backoff::DEFAULT);
    for adresse in ["a@ailleurs.test", "b@ailleurs.test"] {
        spool
            .deposer(
                "jean@nous.test",
                &[String::from(adresse)],
                &[],
                "",
                MESSAGE,
                1_000,
            )
            .expect("déposé");
    }
    let vus = noms(dossier.chemin());
    assert_eq!(vus.len(), 4, "deux messages et deux enveloppes : {vus:?}");
}
