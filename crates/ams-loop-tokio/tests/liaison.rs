// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Les deux bouts du canal tirent-ils LES MÊMES octets de liaison ?
//!
//! # CE QUE CE BANC ÉPROUVE, ET QU'AUCUN AUTRE NE PEUT ÉPROUVER
//!
//! `SCRAM-SHA-256-PLUS` repose entièrement sur une égalité : le client mêle à
//! sa preuve trente-deux octets tirés de SA session TLS, et le serveur compare
//! avec ceux qu'il tire de la SIENNE. Si les deux dérivations diffèrent —
//! étiquette mal orthographiée, contexte absent au lieu de vide, longueur
//! fausse, appel avant la fin de la poignée de main —, **rien ne le dit** : le
//! serveur répond « identifiants invalides », et l'on cherche un mot de passe.
//!
//! Les essais de session, eux, prêtent les mêmes octets aux deux côtés : ils
//! prouvent que la RÈGLE est juste, jamais que la DÉRIVATION l'est. Il faut
//! pour cela une vraie poignée de main, un vrai client `rustls`, et les deux
//! exportateurs tirés séparément. C'est ce que fait ce fichier.
//!
//! # LA POLITIQUE N'Y VÉRIFIE AUCUNE PREUVE, ET C'EST VOULU
//!
//! La session vérifie la liaison AVANT d'appeler la politique. Une doublure qui
//! accepte toute preuve laisse donc la liaison seule décider du verdict : un
//! `235` ne peut venir que d'une égalité, et un `535` que d'un écart.

mod commun;

use std::sync::Arc;

use ams_guard::Thresholds;
use ams_loop_tokio::{Service, SharedGuard, Timeouts, serve_connection};
use ams_sasl::{LIAISON_CONTEXTE, LIAISON_ETIQUETTE, LIAISON_OCTETS};
use commun::{Neant, PAIR, QuiLieLeCanal, config, materiel};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

/// Ce que le client écrit dans son `c=` : l'en-tête GS2 puis la liaison.
const ENTETE: &[u8] = b"p=tls-exporter,,";

/// Monte le client TLS qui fait confiance à CE certificat-là.
fn client_tls(cert: &std::path::Path) -> Arc<rustls::ClientConfig> {
    let mut racines = rustls::RootCertStore::empty();
    racines
        .add(rustls::pki_types::CertificateDer::from(
            std::fs::read(cert).expect("certificat lisible"),
        ))
        .expect("racine acceptée");
    // **LE FOURNISSEUR DU PRODUIT, ET NON UN AUTRE** : c'est lui qui décide du
    // groupe d'échange et des suites, et un banc qui en prendrait un autre
    // mesurerait autre chose que ce qu'on livre.
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(ams_tls::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .with_root_certificates(racines)
        .with_no_client_auth();
    Arc::new(config)
}

/// Lit jusqu'à une ligne complète de réponse.
async fn lire(flux: &mut (impl tokio::io::AsyncRead + Unpin), tampon: &mut Vec<u8>) -> String {
    loop {
        let mut octet = [0_u8; 1];
        let lus = flux.read(&mut octet).await.expect("lecture");
        assert!(lus == 1, "le serveur a fermé");
        tampon.push(octet[0]);
        if tampon.ends_with(b"\r\n") {
            let ligne = String::from_utf8_lossy(tampon).into_owned();
            tampon.clear();
            // Une réponse à plusieurs lignes continue par un tiret.
            if ligne.as_bytes().get(3) != Some(&b'-') {
                return ligne;
            }
            tampon.clear();
        }
    }
}

/// Lit toute une réponse, ses lignes de continuation comprises.
async fn lire_tout(flux: &mut (impl tokio::io::AsyncRead + Unpin)) -> String {
    let mut tout = String::new();
    let mut tampon = Vec::new();
    loop {
        let mut octet = [0_u8; 1];
        let lus = flux.read(&mut octet).await.expect("lecture");
        assert!(lus == 1, "le serveur a fermé");
        tampon.push(octet[0]);
        if tampon.ends_with(b"\r\n") {
            let ligne = String::from_utf8_lossy(&tampon).into_owned();
            let derniere = ligne.as_bytes().get(3) != Some(&b'-');
            tout.push_str(&ligne);
            tampon.clear();
            if derniere {
                return tout;
            }
        }
    }
}

fn en_base64(clair: &[u8]) -> String {
    let mut place = [0_u8; 512];
    String::from_utf8_lossy(ams_mime::encode_base64_line(clair, &mut place).expect("base64"))
        .into_owned()
}

/// Joue l'échange `-PLUS` avec la liaison que l'appelant veut y mettre, et rend
/// la dernière réponse du serveur.
async fn echange(nom: &str, mentir: bool) -> Option<String> {
    let materiel = materiel(nom)?;
    let cert = materiel.repertoire.join("cert.der");
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
        serve_connection(&mut flux, &service, QuiLieLeCanal, &mut Neant, PAIR).await
    });

    let mut brut = TcpStream::connect(adresse).await.expect("connexion");
    let mut tampon = Vec::new();
    assert!(lire(&mut brut, &mut tampon).await.starts_with("220 "));
    brut.write_all(b"EHLO client.example\r\n")
        .await
        .expect("EHLO");
    let _ = lire_tout(&mut brut).await;
    brut.write_all(b"STARTTLS\r\n").await.expect("STARTTLS");
    assert!(lire(&mut brut, &mut tampon).await.starts_with("220 "));

    let connecteur = tokio_rustls::TlsConnector::from(client_tls(&cert));
    let nom_serveur = rustls::pki_types::ServerName::try_from("localhost").expect("nom");
    let mut chiffre = connecteur
        .connect(nom_serveur, brut)
        .await
        .expect("poignée de main");

    // ── LES OCTETS DU CLIENT, TIRÉS DE SA PROPRE CONNEXION ──────────────────
    let mut liaison = chiffre
        .get_ref()
        .1
        .export_keying_material(
            [0_u8; LIAISON_OCTETS],
            LIAISON_ETIQUETTE,
            Some(LIAISON_CONTEXTE),
        )
        .expect("exportateur");
    if mentir {
        // Un octet de plus, et la liaison ne correspond plus à ce canal-ci.
        liaison[0] = liaison[0].wrapping_add(1);
    }

    chiffre
        .write_all(b"EHLO client.example\r\n")
        .await
        .expect("EHLO");
    let annonce = lire_tout(&mut chiffre).await;
    assert!(
        annonce.contains("AUTH SCRAM-SHA-256-PLUS"),
        "`-PLUS` n'est pas annoncé sur un canal qui se lie : {annonce}"
    );

    // ── PREMIER TOUR ────────────────────────────────────────────────────────
    let mut premier = Vec::from(ENTETE);
    premier.extend_from_slice(b"n=jean,r=nonceduclient");
    let commande = format!("AUTH SCRAM-SHA-256-PLUS {}\r\n", en_base64(&premier));
    chiffre.write_all(commande.as_bytes()).await.expect("AUTH");
    let defi = lire_tout(&mut chiffre).await;
    assert!(defi.starts_with("334 "), "défi attendu : {defi}");

    // ── SECOND TOUR : le `c=` porte l'en-tête PUIS la liaison ───────────────
    let mut canal = Vec::from(ENTETE);
    canal.extend_from_slice(&liaison);
    let final_client = format!(
        "c={},r=nonceduclientnoncedeserveur,p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        en_base64(&canal)
    );
    chiffre
        .write_all(format!("{}\r\n", en_base64(final_client.as_bytes())).as_bytes())
        .await
        .expect("client-final");
    let verdict = lire_tout(&mut chiffre).await;

    let _ = chiffre.write_all(b"QUIT\r\n").await;
    let _ = serveur.await;
    Some(verdict)
}

#[tokio::test]
async fn les_deux_bouts_tirent_les_memes_octets_de_liaison() {
    let Some(verdict) = echange("liaison-juste", false).await else {
        return;
    };
    assert!(
        verdict.starts_with("235 "),
        "les deux exportateurs ne concordent pas : {verdict}"
    );
}

#[tokio::test]
async fn une_liaison_d_un_autre_canal_est_refusee() {
    // **C'EST LE CAS QUE `-PLUS` EXISTE POUR ATTRAPER** : un intermédiaire qui
    // relaie l'échange tient DEUX canaux, et ne peut pas produire les octets du
    // nôtre. Un seul octet de différence suffit à le dire.
    let Some(verdict) = echange("liaison-fausse", true).await else {
        return;
    };
    assert!(
        verdict.starts_with("535 "),
        "une liaison d'un autre canal a été acceptée : {verdict}"
    );
}
