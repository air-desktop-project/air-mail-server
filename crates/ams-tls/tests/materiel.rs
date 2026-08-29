// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le chemin nominal de [`ams_tls::server_config`], avec du VRAI matériel.
//!
//! # Pourquoi ce test EXIGE `openssl`, et ne se saute pas
//!
//! `rustls` vérifie que la clé publique de la clé privée est bien celle du
//! certificat de tête. Le chemin nominal ne s'atteint donc qu'avec une paire
//! réelle, et rien dans ce dépôt ne sait en fabriquer une : `ml-kem` et
//! `x25519-dalek` ne signent pas de certificat.
//!
//! Restaient deux options. **Versionner une clé privée de test** — ce que font
//! beaucoup de projets — dépose dans le dépôt un motif que tous les scanners de
//! secrets cherchent, pour un fichier qui devra être renouvelé et dont personne
//! ne saura jamais s'il est vraiment sans valeur. **La fabriquer à l'exécution**
//! coûte une dépendance à `openssl` sur la machine qui teste.
//!
//! C'est la seconde qui est retenue, et le test **échoue** au lieu de se sauter
//! quand l'outil manque. Un test sauté ferait tomber le gate des 100 % (C2)
//! quelques secondes plus tard, sans dire pourquoi : mieux vaut le dire ici.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Fabrique une paire certificat/clé, en PEM.
fn paire(repertoire: &Path, sujet: &str) -> Option<(PathBuf, PathBuf)> {
    let cert = repertoire.join(format!("{sujet}-cert.pem"));
    let cle = repertoire.join(format!("{sujet}-cle.pem"));
    let genere = Command::new("openssl")
        .args(["req", "-x509", "-newkey", "ec"])
        .args(["-pkeyopt", "ec_paramgen_curve:P-256"])
        .args(["-nodes", "-days", "1"])
        .arg("-subj")
        .arg(format!("/CN={sujet}"))
        .arg("-keyout")
        .arg(&cle)
        .arg("-out")
        .arg(&cert)
        .output()
        .ok()?;
    genere.status.success().then_some((cert, cle))
}

struct Atelier(PathBuf);

impl Drop for Atelier {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Un répertoire PAR TEST, et pas un par processus : `cargo test` lance les
/// tests d'un même binaire EN PARALLÈLE, et un nom partagé fait effacer par l'un
/// le répertoire de l'autre. Invisible en les lançant un à un — et c'est sous
/// `cargo llvm-cov`, dont le rythme diffère, que la course a fini par se voir.
fn atelier(nom: &str) -> Atelier {
    let chemin = std::env::temp_dir().join(format!("ams-tls-{nom}-{}", std::process::id()));
    std::fs::create_dir_all(&chemin).expect("répertoire temporaire");
    Atelier(chemin)
}

const SANS_OPENSSL: &str = "ce test EXIGE `openssl` : sans lui, le chemin nominal de \
                            `server_config` n'est pas couvert, et le gate des 100 % (C2) \
                            échouerait quelques secondes plus tard sans en dire la raison";

#[test]
fn une_vraie_paire_donne_un_serveur_tls_13() {
    let atelier = atelier("paire-valide");
    let (cert, cle) = paire(&atelier.0, "localhost").expect(SANS_OPENSSL);

    let config = ams_tls::server_config(
        &std::fs::read(&cert).expect("certificat lisible"),
        &std::fs::read(&cle).expect("clé lisible"),
    )
    .expect("la paire devrait être acceptée");

    // C4, vérifié sur l'objet réellement construit et pas sur l'intention : la
    // configuration n'offre QUE des suites TLS 1.3.
    let suites = &config.crypto_provider().cipher_suites;
    assert!(!suites.is_empty());
    for suite in suites {
        let nom = suite.suite();
        assert_eq!(
            suite.version().version,
            rustls::ProtocolVersion::TLSv1_3,
            "une suite hors TLS 1.3 : {nom:?}"
        );
    }
    // Et C14 : le groupe hybride est en tête, donc préféré.
    assert_eq!(
        config.crypto_provider().kx_groups.first().map(|g| g.name()),
        Some(rustls::NamedGroup::X25519MLKEM768)
    );
}

/// **Ce test consigne une FAIBLESSE, pas une garantie.**
///
/// `rustls` documente que `with_single_cert` échoue quand la clé ne correspond
/// pas au certificat de tête. Avec `rustls-rustcrypto`, ce n'est pas le cas : la
/// clé de signature ne sait pas rendre sa clé publique, et la comparaison est
/// sautée en silence. Ce test le MESURE au lieu de le supposer.
///
/// Le cas est celui d'un renouvellement où l'un des deux fichiers a été remplacé
/// et pas l'autre. Le serveur démarre, et toutes ses poignées de main échouent —
/// un symptôme très loin de sa cause.
///
/// Le jour où l'amont saura comparer, ce test échouera. C'est voulu : il faudra
/// alors retirer la mise en garde du registre des contraintes, et la joie sera
/// entière.
#[test]
fn une_paire_depareillee_n_est_pas_detectee_par_ce_fournisseur() {
    let atelier = atelier("paire-depareillee");
    let (cert, _) = paire(&atelier.0, "premier").expect(SANS_OPENSSL);
    let (_, cle) = paire(&atelier.0, "second").expect(SANS_OPENSSL);

    let resultat = ams_tls::server_config(
        &std::fs::read(&cert).expect("certificat lisible"),
        &std::fs::read(&cle).expect("clé lisible"),
    );
    assert!(
        resultat.is_ok(),
        "l'amont sait désormais comparer clé et certificat : très bien, mais la \
         documentation de `MaterialError::Rejected` et le registre des contraintes \
         disent encore le contraire. À corriger."
    );
}

/// **Une vraie poignée de main, de bout en bout, en mémoire.**
///
/// Le chiffrement opportuniste (RFC 7435) n'authentifie pas le pair — c'est
/// écrit partout — mais il VÉRIFIE la signature de la poignée de main. Un test
/// qui ne ferait qu'appeler le vérificateur avec une fausse signature ne
/// prouverait que le refus ; c'est le chemin nominal qu'il faut voir aboutir,
/// et il n'aboutit qu'avec un vrai certificat en face.
///
/// Aucune socket : les deux connexions s'échangent leurs octets à la main. Le
/// test dit donc quelque chose de rustls et de notre fournisseur, et rien du
/// réseau.
#[test]
fn le_chiffrement_opportuniste_conduit_une_vraie_poignee_de_main() {
    use std::sync::Arc;

    let atelier = atelier("poignee-opportuniste");
    let (cert, cle) = paire(&atelier.0, "mx.eux.test").expect(SANS_OPENSSL);
    let serveur = ams_tls::server_config(
        &std::fs::read(&cert).expect("certificat lisible"),
        &std::fs::read(&cle).expect("clé lisible"),
    )
    .expect("la paire devrait être acceptée");

    let mut client = rustls::ClientConnection::new(
        Arc::new(ams_tls::relay_config()),
        "mx.eux.test".try_into().expect("nom de serveur"),
    )
    .expect("connexion cliente");
    let mut hote = rustls::ServerConnection::new(Arc::new(serveur)).expect("connexion serveur");

    // Vingt allers-retours majorent très largement une poignée de main TLS 1.3 ;
    // la boucle s'arrête d'elle-même dès que les deux ont fini.
    for _ in 0..20 {
        if !client.is_handshaking() && !hote.is_handshaking() {
            break;
        }
        let mut fil = Vec::new();
        client.write_tls(&mut fil).expect("le client écrit");
        if !fil.is_empty() {
            hote.read_tls(&mut fil.as_slice()).expect("le serveur lit");
            hote.process_new_packets().expect("le serveur traite");
        }
        let mut retour = Vec::new();
        hote.write_tls(&mut retour).expect("le serveur écrit");
        if !retour.is_empty() {
            client
                .read_tls(&mut retour.as_slice())
                .expect("le client lit");
            client.process_new_packets().expect("le client traite");
        }
    }

    assert!(
        !client.is_handshaking(),
        "la poignée de main n'a pas abouti"
    );
    assert!(!hote.is_handshaking());
    // C6, vérifié sur la connexion réellement établie.
    assert_eq!(
        client.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    // Et le groupe de C14, celui qu'aucun autre fournisseur pur Rust n'offre.
    assert!(
        client
            .negotiated_key_exchange_group()
            .is_some_and(|groupe| groupe.name() == rustls::NamedGroup::X25519MLKEM768),
        "l'échange hybride post-quantique n'a pas été négocié"
    );
}
