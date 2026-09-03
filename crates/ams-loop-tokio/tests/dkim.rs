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

use ams_dkim::SigningKey;
use ams_guard::Thresholds;
use ams_loop_tokio::{
    DkimChecker, DkimSigner, DkimStream, DkimVerdict, Resolver, Service, SharedGuard, Timeouts,
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
            reports: None,
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

// ── Signer ce qu'on émet ────────────────────────────────────────────────────

/// Une clé Ed25519 (RFC 8463) JETABLE, écrite ici et nulle part ailleurs.
///
/// Ed25519 plutôt que RSA parce qu'elle tient en trois lignes : ce qu'on éprouve
/// ici est le CÂBLAGE, et la signature elle-même l'est chez elle, jusqu'à la
/// comparaison avec OpenSSL.
const CLE_PRIVEE: &str = "-----BEGIN PRIVATE KEY-----\n\
     MC4CAQAwBQYDK2VwBCIEIPycWR71gsJjQjlyixhg1EFwd/RmkyoHfIBubnK3v8rE\n\
     -----END PRIVATE KEY-----\n";

const RAPPORT: &[u8] = b"From: postmaster@exemple.test\r\n\
To: dmarc@ailleurs.test\r\n\
Subject: rapport\r\n\
Date: Mon, 31 Aug 2026 09:00:00 +0200\r\n\
Message-Id: <1@exemple.test>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/plain\r\n\
\r\n\
Le corps du rapport.\r\n";

fn signataire() -> DkimSigner {
    let cle = SigningKey::from_pem(CLE_PRIVEE.as_bytes()).expect("la clé d'épreuve se lit");
    DkimSigner::new(String::from("epreuve"), std::sync::Arc::new(cle))
}

/// **CE QU'ON ÉMET PORTE SA SIGNATURE**, et le reste du message ne bouge pas.
///
/// Ce que cette épreuve ajoute aux autres : la JONCTION. Que le champ se pose EN
/// TÊTE — §3.5 veut qu'il précède ce qu'il couvre —, qu'il nomme le domaine du
/// `From:` et le sélecteur configuré, et que rien de ce qui suit n'ait changé.
#[test]
fn ce_qu_on_emet_porte_sa_signature() {
    let signe = signataire().sign(
        std::vec::Vec::from(RAPPORT),
        "postmaster@exemple.test",
        1_788_000_000,
    );
    let texte = String::from_utf8_lossy(&signe).into_owned();

    assert!(texte.starts_with("DKIM-Signature: "), "{texte}");
    assert!(texte.contains("d=exemple.test"), "{texte}");
    assert!(texte.contains("s=epreuve"), "{texte}");
    assert!(texte.contains("a=ed25519-sha256"), "{texte}");
    assert!(texte.contains("t=1788000000"), "{texte}");
    // `from` DOIT être couvert : sans lui, la signature ne dirait rien de
    // l'auteur, et le signataire refuse d'écrire un champ pareil.
    assert!(texte.contains("h=from:"), "{texte}");
    // Et ce qui suit le champ est le message, à l'octet près.
    assert!(
        signe
            .windows(RAPPORT.len())
            .any(|fenetre| fenetre == RAPPORT),
        "le message a changé : {texte}"
    );
}

/// **UN MESSAGE QU'ON NE SAIT PAS SIGNER PART QUAND MÊME.** Un `From:` sans
/// arobase ne donne pas de domaine, donc pas de `d=` — et un rapport non signé
/// vaut mieux qu'un rapport qui n'arrive pas.
#[test]
fn un_message_qu_on_ne_sait_pas_signer_part_quand_meme() {
    const NU: &[u8] = b"From: personne\r\n\r\nCorps.\r\n";
    assert_eq!(
        signataire().sign(std::vec::Vec::from(NU), "personne", 0),
        std::vec::Vec::from(NU)
    );
}

/// **LA CLÉ N'APPARAÎT JAMAIS DANS UNE TRACE.** Une clé privée qui figure dans
/// un journal n'est plus une clé privée, et c'est le genre de fuite qu'on ne
/// remarque qu'après.
#[test]
fn la_trace_du_signataire_ne_porte_pas_la_cle() {
    let rendu = std::format!("{:?}", signataire());
    assert!(rendu.contains("epreuve"), "{rendu}");
    assert!(!rendu.contains("MC4CAQAw"), "{rendu}");
}

// ── L'ALLER-RETOUR : CE QU'ON SIGNE SE VÉRIFIE ─────────────────────────────
//
// # CE QUE CET ESSAI PROUVE, ET QUE RIEN D'AUTRE NE PROUVAIT
//
// Jusqu'ici, les essais de signature regardaient la FORME du champ produit —
// son domaine, son sélecteur, sa place en tête. Aucun ne calculait la
// cryptographie, faute d'avoir la clé publique correspondante : elle n'existait
// nulle part dans le dépôt.
//
// Deux tranches plus tôt, cela a coûté un essai. Il devait établir qu'on
// complète AVANT de signer ; il comparait des positions, et les positions sont
// les mêmes dans les deux ordres. Il a fallu le réécrire en disant franchement
// qu'il ne prouvait pas ce qu'on aurait voulu.
//
// Depuis que `SigningKey::public_record` rend ce qu'un exploitant doit publier,
// le vérificateur a de quoi travailler — et l'essai qui manquait devient
// possible. Il assemble EXACTEMENT ce qu'un pair assemblerait : la clé lue de
// l'enregistrement, le condensat du corps, celui des en-têtes signés, et la
// signature dépliée.

/// Vérifie la signature d'un message, comme un pair le ferait.
fn verifier(message: &[u8], enregistrement: &[u8]) -> Result<(), ams_dkim::Error> {
    let bornes = ams_mime::Limits::DEFAULT;
    let lu = ams_mime::Message::parse(message, &bornes).expect("lisible");
    let champ = lu
        .fields()
        .find(|champ| champ.name_is(b"dkim-signature"))
        .expect("signé");
    let signature = ams_dkim::Signature::parse(champ.raw_value())?;
    let record = ams_dkim::PublicKeyRecord::parse(enregistrement)?;

    // Le corps, tel que la canonicalisation le voit.
    let mut corps = ams_dkim::BodyHasher::new(signature.canonicalization.body, None);
    corps.update(lu.body());
    let (condensat_du_corps, _) = corps.finish();

    // La clé publique, dépliée puis décodée.
    let mut sans_blancs = std::vec![0_u8; record.key.len()];
    let deplie = record.key_base64(&mut sans_blancs)?;
    let mut cle = std::vec![0_u8; deplie.len()];
    let combien = ams_dkim::decoder_base64(deplie, &mut cle)?;
    cle.truncate(combien);

    // La signature elle-même, de même.
    let mut tampon = std::vec![0_u8; signature.signature.len()];
    let deplie = signature.signature_base64(&mut tampon)?;
    let mut scellee = std::vec![0_u8; deplie.len()];
    let combien = ams_dkim::decoder_base64(deplie, &mut scellee)?;
    scellee.truncate(combien);

    // Et les en-têtes signés, le champ de signature compris — son `b=` retiré.
    let mut condensat = ams_dkim::HeaderHasher::new(signature.canonicalization.header);
    ams_dkim::hash_signed_headers(&signature, &mut condensat, || {
        lu.fields().map(|champ| (champ.name(), champ.raw_value()))
    });
    condensat.signature_field(champ.name(), champ.raw_value())?;

    ams_dkim::verify(
        &signature,
        &record,
        &cle,
        &condensat_du_corps,
        &condensat.finish(),
        &scellee,
    )
}

/// Le message d'épreuve, signé.
fn signe() -> std::vec::Vec<u8> {
    signataire().sign(
        std::vec::Vec::from(RAPPORT),
        "postmaster@exemple.test",
        1_788_000_000,
    )
}

/// L'enregistrement que l'exploitant publierait pour la clé d'épreuve.
fn enregistrement() -> std::vec::Vec<u8> {
    SigningKey::from_pem(CLE_PRIVEE.as_bytes())
        .expect("la clé d'épreuve se lit")
        .public_record()
}

/// **CE QU'ON SIGNE SE VÉRIFIE**, avec l'enregistrement qu'on dit de publier.
///
/// C'est l'essai qui relie les deux moitiés : si l'enregistrement composé pour
/// l'exploitant ne correspondait pas à la clé qui signe, TOUTES nos signatures
/// échoueraient chez le destinataire — et rien, dans ce dépôt, ne l'aurait dit.
#[test]
fn ce_qu_on_signe_se_verifie_avec_ce_qu_on_publie() {
    assert_eq!(verifier(&signe(), &enregistrement()), Ok(()));
}

/// **UN CORPS MODIFIÉ EN ROUTE SE VOIT.**
///
/// Sans quoi l'essai précédent ne dirait rien : il faut que la vérification
/// puisse échouer.
#[test]
fn un_corps_modifie_casse_la_signature() {
    let mut abime = signe();
    let dernier = abime.len().saturating_sub(4);
    abime[dernier] = abime[dernier].wrapping_add(1);
    assert_eq!(
        verifier(&abime, &enregistrement()),
        Err(ams_dkim::Error::BodyHashMismatch)
    );
}

/// **UN SECOND `From:` AJOUTÉ CASSE LA SIGNATURE**, et c'est toute la raison du
/// sur-scellement (§5.4.2).
///
/// Un vérificateur prend l'instance la plus BASSE de chaque nom listé — celle
/// d'origine. Sans la seconde mention dans `h=`, un tiers qui préfixe un `From:`
/// laisserait la signature VALABLE, pendant que la plupart des clients affichent
/// le premier.
#[test]
fn un_second_from_ajoute_est_refuse() {
    let signe = signe();
    // Le champ de signature est PLIÉ : le couper au premier `CRLF` le casserait.
    // Le message d'origine commence là où le champ finit.
    let fin = signe.len().saturating_sub(RAPPORT.len());
    let mut force = std::vec::Vec::new();
    force.extend_from_slice(&signe[..fin]);
    force.extend_from_slice(b"From: attaquant@ailleurs.test\r\n");
    force.extend_from_slice(&signe[fin..]);

    assert_eq!(
        verifier(&force, &enregistrement()),
        Err(ams_dkim::Error::SignatureMismatch)
    );
}
