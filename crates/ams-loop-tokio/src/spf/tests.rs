//! Ce que la résolution des questions SPF doit tenir.
//!
//! Les épreuves montent un **vrai résolveur** sur une socket locale : c'est le
//! seul moyen d'éprouver ce que ce module fait réellement — encoder, attendre,
//! reprendre en TCP, refuser une réponse qui ne répond pas.

use super::{SenderChecker, nom_inverse};
use ams_session::SenderIdentity;
use ams_spf::Verdict;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, UdpSocket};

/// Ce que le faux résolveur fait d'une question.
#[derive(Clone)]
enum Reaction {
    /// Des enregistrements, sous la forme (type, données).
    Rend(Vec<(u16, Vec<u8>)>),
    /// « Ce nom n'existe pas. »
    Nxdomain,
    /// En UDP, le drapeau de troncature et rien d'autre ; en TCP, la réponse.
    Tronquee(Vec<(u16, Vec<u8>)>),
    /// Une réponse dont l'identifiant est faux, PUIS la bonne.
    Usurpee(Vec<(u16, Vec<u8>)>),
    /// Rien du tout.
    Silence,
}

type Table = HashMap<(String, u16), Reaction>;

const A: u16 = 1;
const PTR: u16 = 12;
const MX: u16 = 15;
const TXT: u16 = 16;
const AAAA: u16 = 28;

/// Les octets d'un `TXT`, chaînes de 255 au plus.
fn txt(texte: &str) -> Vec<u8> {
    let mut octets = Vec::new();
    for morceau in texte.as_bytes().chunks(255) {
        octets.push(u8::try_from(morceau.len()).expect("morceau court"));
        octets.extend_from_slice(morceau);
    }
    octets
}

/// Les octets d'un nom sur le fil.
fn nom(texte: &str) -> Vec<u8> {
    let mut octets = Vec::new();
    for etiquette in texte.split('.').filter(|e| !e.is_empty()) {
        octets.push(u8::try_from(etiquette.len()).expect("étiquette courte"));
        octets.extend_from_slice(etiquette.as_bytes());
    }
    octets.push(0);
    octets
}

fn mx(preference: u16, cible: &str) -> Vec<u8> {
    let mut octets = Vec::from(preference.to_be_bytes());
    octets.extend_from_slice(&nom(cible));
    octets
}

/// Lit le nom et le type d'une question, sous sa forme pointée.
fn question_posee(message: &[u8]) -> Option<(String, u16, usize)> {
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

/// Compose une réponse à partir de la question reçue.
fn composer(
    question: &[u8],
    fin_question: usize,
    enregistrements: &[(u16, Vec<u8>)],
    rcode: u8,
    tronquee: bool,
    id: u16,
) -> Vec<u8> {
    let mut reponse = Vec::new();
    reponse.extend_from_slice(&id.to_be_bytes());
    let drapeaux = 0x8180_u16 | u16::from(rcode) | if tronquee { 0x0200 } else { 0 };
    reponse.extend_from_slice(&drapeaux.to_be_bytes());
    reponse.extend_from_slice(&1_u16.to_be_bytes());
    let combien = if tronquee { 0 } else { enregistrements.len() };
    reponse.extend_from_slice(&u16::try_from(combien).expect("peu").to_be_bytes());
    reponse.extend_from_slice(&0_u16.to_be_bytes());
    reponse.extend_from_slice(&0_u16.to_be_bytes());
    reponse.extend_from_slice(question.get(12..fin_question).unwrap_or_default());
    if !tronquee {
        for (genre, donnees) in enregistrements {
            // Le propriétaire : un pointeur vers la question, comme un vrai
            // serveur l'écrit.
            reponse.extend_from_slice(&[0xC0, 0x0C]);
            reponse.extend_from_slice(&genre.to_be_bytes());
            reponse.extend_from_slice(&1_u16.to_be_bytes());
            reponse.extend_from_slice(&60_u32.to_be_bytes());
            reponse.extend_from_slice(
                &u16::try_from(donnees.len())
                    .expect("données courtes")
                    .to_be_bytes(),
            );
            reponse.extend_from_slice(donnees);
        }
    }
    reponse
}

/// Monte un résolveur de test, et rend son adresse.
async fn resolveur(table: Table) -> SocketAddr {
    let udp = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .expect("socket UDP");
    let adresse = udp.local_addr().expect("adresse");
    let tcp = TcpListener::bind(adresse).await.expect("socket TCP");
    let table = Arc::new(table);

    let en_udp = Arc::clone(&table);
    tokio::spawn(async move {
        let mut recu = vec![0_u8; 2048];
        loop {
            let Ok((lus, pair)) = udp.recv_from(&mut recu).await else {
                return;
            };
            let question = recu.get(..lus).unwrap_or_default().to_vec();
            let Some((nom, genre, fin)) = question_posee(&question) else {
                continue;
            };
            let id = u16::from_be_bytes([question[0], question[1]]);
            let reaction = en_udp
                .get(&(nom, genre))
                .cloned()
                .unwrap_or(Reaction::Nxdomain);
            match reaction {
                Reaction::Rend(enregistrements) => {
                    let reponse = composer(&question, fin, &enregistrements, 0, false, id);
                    let _ = udp.send_to(&reponse, pair).await;
                }
                Reaction::Nxdomain => {
                    let reponse = composer(&question, fin, &[], 3, false, id);
                    let _ = udp.send_to(&reponse, pair).await;
                }
                Reaction::Tronquee(_) => {
                    let reponse = composer(&question, fin, &[], 0, true, id);
                    let _ = udp.send_to(&reponse, pair).await;
                }
                Reaction::Usurpee(enregistrements) => {
                    // D'ABORD une réponse dont l'identifiant est faux : c'est
                    // exactement ce qu'envoie qui veut répondre à notre place.
                    let usurpee = composer(
                        &question,
                        fin,
                        &[(A, std::vec![203, 0, 113, 66])],
                        0,
                        false,
                        id ^ 1,
                    );
                    let _ = udp.send_to(&usurpee, pair).await;
                    let vraie = composer(&question, fin, &enregistrements, 0, false, id);
                    let _ = udp.send_to(&vraie, pair).await;
                }
                Reaction::Silence => {}
            }
        }
    });

    tokio::spawn(async move {
        loop {
            let Ok((mut flux, _)) = tcp.accept().await else {
                return;
            };
            let table = Arc::clone(&table);
            tokio::spawn(async move {
                let mut entete = [0_u8; 2];
                if flux.read_exact(&mut entete).await.is_err() {
                    return;
                }
                let annoncee = usize::from(u16::from_be_bytes(entete));
                let mut question = vec![0_u8; annoncee];
                if flux.read_exact(&mut question).await.is_err() {
                    return;
                }
                let Some((nom, genre, fin)) = question_posee(&question) else {
                    return;
                };
                let id = u16::from_be_bytes([question[0], question[1]]);
                let enregistrements = match table.get(&(nom, genre)) {
                    Some(Reaction::Tronquee(records) | Reaction::Rend(records)) => records.clone(),
                    _ => Vec::new(),
                };
                let reponse = composer(&question, fin, &enregistrements, 0, false, id);
                let longueur = u16::try_from(reponse.len()).expect("réponse courte");
                let _ = flux.write_all(&longueur.to_be_bytes()).await;
                let _ = flux.write_all(&reponse).await;
                let _ = flux.flush().await;
            });
        }
    });

    adresse
}

fn identite<'a>(domaine: &'a str, expediteur: &'a str, helo: &'a str) -> SenderIdentity<'a> {
    SenderIdentity {
        domain: domaine.as_bytes(),
        sender: expediteur.as_bytes(),
        helo: helo.as_bytes(),
    }
}

async fn verdict_pour(table: Table, client: &str) -> Verdict {
    let adresse = resolveur(table).await;
    let verificateur =
        SenderChecker::new(std::vec![adresse], Duration::from_secs(2)).expect("vérificateur");
    verificateur
        .verdict(
            client.parse().expect("adresse"),
            &identite("example.com", "jean@example.com", "mx.example.com"),
        )
        .await
}

fn politique(texte: &str) -> Table {
    let mut table = Table::new();
    table.insert(
        ("example.com".to_string(), TXT),
        Reaction::Rend(std::vec![(TXT, txt(texte))]),
    );
    table
}

#[tokio::test]
async fn une_adresse_autorisee_passe() {
    let verdict = verdict_pour(politique("v=spf1 ip4:192.0.2.0/24 -all"), "192.0.2.7").await;
    assert_eq!(verdict, Verdict::Pass);
}

#[tokio::test]
async fn une_adresse_non_autorisee_echoue() {
    let verdict = verdict_pour(politique("v=spf1 ip4:192.0.2.0/24 -all"), "198.51.100.7").await;
    assert_eq!(verdict, Verdict::Fail);
}

#[tokio::test]
async fn un_domaine_sans_politique_ne_dit_rien() {
    // `none` N'EST PAS UN REFUS : la moitié d'internet n'a pas publié de SPF.
    let verdict = verdict_pour(Table::new(), "192.0.2.7").await;
    assert_eq!(verdict, Verdict::None);
}

#[tokio::test]
async fn le_mecanisme_a_resout_les_deux_familles() {
    let mut table = politique("v=spf1 a -all");
    table.insert(
        ("example.com".to_string(), A),
        Reaction::Rend(std::vec![(A, std::vec![192, 0, 2, 7])]),
    );
    table.insert(
        ("example.com".to_string(), AAAA),
        Reaction::Rend(std::vec![(
            AAAA,
            std::vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        )]),
    );
    let adresse = resolveur(table).await;
    let verificateur =
        SenderChecker::new(std::vec![adresse], Duration::from_secs(2)).expect("vérificateur");
    let identite = identite("example.com", "jean@example.com", "mx.example.com");
    // Le pair arrive en IPv6 : n'interroger que les `A` ne le trouverait jamais.
    assert_eq!(
        verificateur
            .verdict("2001:db8::1".parse().expect("adresse"), &identite)
            .await,
        Verdict::Pass
    );
    assert_eq!(
        verificateur
            .verdict("192.0.2.7".parse().expect("adresse"), &identite)
            .await,
        Verdict::Pass
    );
    assert_eq!(
        verificateur
            .verdict("192.0.2.8".parse().expect("adresse"), &identite)
            .await,
        Verdict::Fail
    );
}

#[tokio::test]
async fn le_mecanisme_mx_se_deplie_en_deux_tours() {
    // UNE question SPF, DEUX résolutions : c'est le découpage de la RFC, qui
    // compte un `mx` pour une seule des dix.
    let mut table = politique("v=spf1 mx -all");
    table.insert(
        ("example.com".to_string(), MX),
        Reaction::Rend(std::vec![(MX, mx(10, "relais.example.net"))]),
    );
    table.insert(
        ("relais.example.net".to_string(), A),
        Reaction::Rend(std::vec![(A, std::vec![198, 51, 100, 25])]),
    );
    let adresse = resolveur(table).await;
    let verificateur =
        SenderChecker::new(std::vec![adresse], Duration::from_secs(2)).expect("vérificateur");
    let identite = identite("example.com", "jean@example.com", "mx.example.com");
    assert_eq!(
        verificateur
            .verdict("198.51.100.25".parse().expect("adresse"), &identite)
            .await,
        Verdict::Pass
    );
}

#[tokio::test]
async fn un_include_suit_la_politique_d_un_tiers() {
    let mut table = politique("v=spf1 include:tiers.example.net ~all");
    table.insert(
        ("tiers.example.net".to_string(), TXT),
        Reaction::Rend(std::vec![(TXT, txt("v=spf1 ip4:203.0.113.0/24 -all"))]),
    );
    let adresse = resolveur(table).await;
    let verificateur =
        SenderChecker::new(std::vec![adresse], Duration::from_secs(2)).expect("vérificateur");
    let identite = identite("example.com", "jean@example.com", "mx.example.com");
    assert_eq!(
        verificateur
            .verdict("203.0.113.7".parse().expect("adresse"), &identite)
            .await,
        Verdict::Pass
    );
    // L'incluse dit `fail` : l'`include` NE CORRESPOND PAS, et c'est le `~all`
    // de l'appelante qui décide.
    assert_eq!(
        verificateur
            .verdict("192.0.2.7".parse().expect("adresse"), &identite)
            .await,
        Verdict::SoftFail
    );
}

#[tokio::test]
async fn le_mecanisme_ptr_exige_la_verification_en_avant() {
    // RFC 7208 §5.5 : un `PTR` est publié par qui détient le bloc d'adresses.
    // Sans revérifier en avant, il se ferait passer pour n'importe qui.
    let mut table = politique("v=spf1 ptr -all");
    table.insert(
        ("7.2.0.192.in-addr.arpa".to_string(), PTR),
        Reaction::Rend(std::vec![
            (PTR, nom("menteur.example.com")),
            (PTR, nom("vrai.example.com")),
        ]),
    );
    // Le premier nom ne résout PAS vers l'adresse du pair : il est écarté.
    table.insert(
        ("menteur.example.com".to_string(), A),
        Reaction::Rend(std::vec![(A, std::vec![203, 0, 113, 1])]),
    );
    table.insert(
        ("vrai.example.com".to_string(), A),
        Reaction::Rend(std::vec![(A, std::vec![192, 0, 2, 7])]),
    );
    assert_eq!(verdict_pour(table, "192.0.2.7").await, Verdict::Pass);
}

#[tokio::test]
async fn un_ptr_qui_ne_se_confirme_pas_ne_correspond_pas() {
    let mut table = politique("v=spf1 ptr -all");
    table.insert(
        ("7.2.0.192.in-addr.arpa".to_string(), PTR),
        Reaction::Rend(std::vec![(PTR, nom("menteur.example.com"))]),
    );
    table.insert(
        ("menteur.example.com".to_string(), A),
        Reaction::Rend(std::vec![(A, std::vec![203, 0, 113, 1])]),
    );
    assert_eq!(verdict_pour(table, "192.0.2.7").await, Verdict::Fail);
}

#[tokio::test]
async fn le_mecanisme_exists_developpe_ses_macros() {
    let mut table = politique("v=spf1 exists:%{ir}.liste.example.net -all");
    table.insert(
        ("7.2.0.192.liste.example.net".to_string(), A),
        Reaction::Rend(std::vec![(A, std::vec![127, 0, 0, 2])]),
    );
    assert_eq!(verdict_pour(table, "192.0.2.7").await, Verdict::Pass);
}

#[tokio::test]
async fn une_reponse_tronquee_se_reprend_en_tcp() {
    // RFC 1035 §4.2.1 : ce qui est arrivé NE S'UTILISE PAS. Une politique
    // coupée en deux se lirait comme une politique valide qui dit autre chose.
    let mut table = Table::new();
    table.insert(
        ("example.com".to_string(), TXT),
        Reaction::Tronquee(std::vec![(TXT, txt("v=spf1 ip4:192.0.2.0/24 -all"))]),
    );
    assert_eq!(verdict_pour(table, "192.0.2.7").await, Verdict::Pass);
}

#[tokio::test]
async fn une_reponse_dont_l_identifiant_est_faux_est_ignoree() {
    // Celui qui injecte n'a pas gagné en arrivant le premier : on continue
    // d'écouter jusqu'au délai. Sans ce refus, il suffirait de répondre vite
    // pour décider du verdict d'autrui.
    let mut table = Table::new();
    table.insert(
        ("example.com".to_string(), TXT),
        Reaction::Usurpee(std::vec![(TXT, txt("v=spf1 ip4:192.0.2.0/24 -all"))]),
    );
    assert_eq!(verdict_pour(table, "192.0.2.7").await, Verdict::Pass);
}

#[tokio::test]
async fn un_resolveur_muet_vaut_temperror() {
    // JAMAIS UN REFUS : dire `fail` ferait jeter un message qui serait passé
    // cinq minutes plus tard.
    let mut table = Table::new();
    table.insert(("example.com".to_string(), TXT), Reaction::Silence);
    let adresse = resolveur(table).await;
    let verificateur =
        SenderChecker::new(std::vec![adresse], Duration::from_millis(150)).expect("vérificateur");
    let verdict = verificateur
        .verdict(
            "192.0.2.7".parse().expect("adresse"),
            &identite("example.com", "jean@example.com", "mx.example.com"),
        )
        .await;
    assert_eq!(verdict, Verdict::TempError);
}

#[tokio::test]
async fn un_second_resolveur_prend_le_relais() {
    let mut muet = Table::new();
    muet.insert(("example.com".to_string(), TXT), Reaction::Silence);
    let sourd = resolveur(muet).await;
    let vivant = resolveur(politique("v=spf1 ip4:192.0.2.0/24 -all")).await;
    let verificateur = SenderChecker::new(std::vec![sourd, vivant], Duration::from_millis(300))
        .expect("vérificateur");
    let verdict = verificateur
        .verdict(
            "192.0.2.7".parse().expect("adresse"),
            &identite("example.com", "jean@example.com", "mx.example.com"),
        )
        .await;
    assert_eq!(verdict, Verdict::Pass);
}

#[tokio::test]
async fn sans_resolveur_le_verificateur_ne_se_construit_pas() {
    // Un vérificateur sans personne à qui demander répondrait `temperror` à
    // chaque message. Refuser de le construire le dit au démarrage.
    assert!(SenderChecker::new(Vec::new(), Duration::from_secs(1)).is_err());
}

#[tokio::test]
async fn une_politique_en_deux_morceaux_se_recolle_sans_separateur() {
    // RFC 7208 §3.3 : au-delà de 255 octets, un `TXT` arrive en plusieurs
    // chaînes. Les joindre par une espace ferait une politique différente.
    let longue = std::format!(
        "v=spf1{} ip4:192.0.2.0/24 -all",
        " ip4:198.51.100.0/24".repeat(13)
    );
    assert!(longue.len() > 255, "{} octets", longue.len());
    // Le mécanisme qui correspond est le DERNIER : si le recollage avait perdu
    // ou décalé un octet, on ne l'atteindrait pas.
    assert_eq!(
        verdict_pour(politique(&longue), "192.0.2.7").await,
        Verdict::Pass
    );
}

#[test]
fn le_nom_inverse_suit_les_deux_formes() {
    assert_eq!(
        nom_inverse("192.0.2.7".parse().expect("adresse")),
        "7.2.0.192.in-addr.arpa"
    );
    // RFC 3596 §2.5 : un quartet par étiquette, à l'envers.
    assert_eq!(
        nom_inverse("2001:db8::1".parse().expect("adresse")),
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
    );
}

#[tokio::test]
async fn le_verificateur_se_debogue_sans_dire_d_ou_vient_l_alea() {
    let verificateur = SenderChecker::new(
        std::vec!["127.0.0.1:53".parse().expect("adresse")],
        Duration::from_secs(1),
    )
    .expect("vérificateur");
    let rendu = std::format!("{verificateur:?}");
    assert!(rendu.contains("127.0.0.1:53"), "{rendu}");
    assert!(!rendu.contains("urandom"), "{rendu}");
}
