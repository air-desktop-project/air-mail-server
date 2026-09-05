//! Le serveur air-mail-server — binaire `air-mail-server` (C12).
//!
//! Il assemble les pièces : le codec SMTP, la machine à états de session, le
//! garde anti-flooding, la boucle d'entrées-sorties et la boîte Maildir. Il ne
//! contient lui-même **aucune logique de protocole** — seulement le fil.
//!
//! # Ce qu'il sert, et ce qu'il ne sert pas
//!
//! Il reçoit du courrier en clair, pour les domaines qu'on lui nomme, et le
//! dépose dans une boîte Maildir. Il refuse les sources qui abusent.
//!
//! **Ni TLS ni authentification** : ni `STARTTLS` ni `AUTH` ne sont annoncés,
//! parce que rien ne sait les conduire, et qu'annoncer ce qu'on ne sait pas faire
//! ferait envoyer un mot de passe à un serveur sans de quoi le protéger.
//!
//! **Une seule boîte pour tout le monde.** Répartir par destinataire demande un
//! modèle de comptes qui n'existe pas — et dériver un nom de répertoire d'une
//! partie locale est précisément là où vit la traversée de répertoire. On ne
//! l'improvise pas.
//!
//! **Pas de journal structuré** : quelques lignes sur la sortie d'erreur, et
//! c'est tout.
//!
//! # Il ne se règle QUE par un fichier
//!
//! C11 veut une configuration binaire ; ce binaire ne lit rien d'autre. Il n'a
//! pas d'options de réglage, et c'est délibéré : deux sources de configuration
//! seraient une de trop — c'est ainsi qu'un serveur finit par tourner autrement
//! que ce que son administrateur croit avoir demandé. Le fichier se produit avec
//! `air-mail-admin config write`.

mod api;
mod comptes;
mod delivery;
mod imap;
mod incidents;
mod policy;
mod pop3;

use std::collections::BTreeMap;
use std::process::ExitCode;
use std::sync::Arc;

use std::path::{Path, PathBuf};
use std::time::Duration;

use ams_auth::Account;
use ams_config::{Configuration, Enforcement, Tls};
use ams_dkim::SigningKey;
use ams_loop_tokio::imap::serve_imap;
use ams_loop_tokio::pop3::serve_pop3;
use ams_loop_tokio::{
    DkimChecker, DkimSigner, DmarcChecker, Relay, ReportSpool, SenderChecker, ServeOptions,
    SharedGuard, Timeouts, masque_trop_large, refuse_root, restreindre_le_masque, serve,
};
use ams_session::{Capabilities, Config, SenderPolicy};
use ams_store::Maildir;
use tokio::net::TcpListener;

use rustls::ServerConfig;

use crate::delivery::{Boites, MaildirDelivery};
use crate::imap::BoitesImap;
use crate::policy::BoitesConnues;
use crate::pop3::BoitesPop3;

/// Le texte de `--help`.
///
/// # IL NE DIT PLUS CE QUI MANQUE, ET C'EST DÉLIBÉRÉ
///
/// Il l'a dit — « TLS et l'authentification ne sont pas implémentés […] le
/// courrier reçu va dans UNE SEULE boîte » — et il a continué de le dire
/// longtemps après que les trois soient arrivés. Un `--help` est ce qu'on lit
/// AVANT d'essayer : il était donc le mieux placé pour décourager un usage que
/// le serveur rendait déjà.
///
/// Ce que ce serveur sert dépend de sa CONFIGURATION, et le démarrage l'annonce
/// ligne par ligne — ce qui est offert comme ce qui ne l'est pas, faute de
/// certificat ou de résolveur. Cette liste-là ne peut pas vieillir : elle est
/// relevée à l'exécution.
const AIDE: &str = "\
air-mail-server — serveur de courrier SMTP, POP3, IMAP et HTTP

USAGE
    air-mail-server --config <fichier>

Le fichier de configuration est BINAIRE, et se produit avec
`air-mail-admin config write`. Ce serveur n'a AUCUNE autre option de réglage :
deux sources de configuration seraient une de trop.

    --config <fichier>  la configuration
    --help              ce texte
    --version           la version

CE QU'IL SERT, IL LE DIT AU DÉMARRAGE
    Les protocoles ouverts, les domaines servis, le chiffrement, les comptes —
    et ce qui MANQUE : « EN CLAIR », « AUTH non annoncé », « aucun résolveur ».
    Cette liste-là est relevée à l'exécution ; celle qu'on écrirait ici
    vieillirait sans que personne ne s'en aperçoive.
";

/// L'ordonnanceur est MULTI-FILS, et ce n'est pas un défaut de configuration :
/// la remise Maildir appelle `block_in_place` pour ses `fsync`, qui panique sur
/// l'ordonnanceur mono-fil.
#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let mots: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let fichier = match mots.as_slice() {
        ["--help" | "-h"] => {
            println!("{AIDE}");
            return ExitCode::SUCCESS;
        }
        ["--version" | "-V"] => {
            println!("air-mail-server {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        ["--config", fichier] => PathBuf::from(fichier),
        autre => {
            eprintln!("air-mail-server : arguments inattendus : {autre:?}");
            eprintln!("Essayez `air-mail-server --help`.");
            return ExitCode::from(2);
        }
    };

    match servir(&fichier).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("air-mail-server : {message}");
            ExitCode::FAILURE
        }
    }
}

/// Combien de temps un jeton d'API vaut, en microsecondes.
///
/// Une heure. **UN JETON NE SE RÉVOQUE PAS TOUT SEUL** : il se vérifie sans
/// consulter quoi que ce soit, donc sa seule fin garantie est son expiration.
/// Plus il vit, plus longtemps un vol reste utile.
const DUREE_DE_JETON_US: u64 = 3_600 * 1_000_000;

/// Ce qu'il faut pour servir l'API.
type MontageApi = (
    TcpListener,
    ams_session::http::Http,
    Arc<ServerConfig>,
    Arc<crate::api::ApiMaildir>,
);

/// Monte l'API REST, ou explique pourquoi elle n'est pas servie.
///
/// # TROIS CONDITIONS, ET AUCUNE N'EST FACULTATIVE
///
/// Une adresse d'écoute, un certificat, et une clé de scellement.
///
/// **Le certificat n'est pas négociable, et c'est la différence avec les trois
/// autres écoutes.** SMTP, POP3 et IMAP servent en clair et refusent
/// l'authentification ; l'API, elle, porte des jetons porteurs, et un jeton qui
/// traverse un réseau en clair est un jeton volé. Ce port ne s'ouvre donc pas
/// sans chiffrement (C4).
///
/// Chaque refus se dit **au démarrage**, avec sa raison. Un port qu'on ouvrirait
/// pour répondre 500 à chaque requête serait pire qu'un port fermé.
#[expect(
    clippy::too_many_arguments,
    reason = "monter l'API demande la configuration, le chiffrement, les boîtes, \
              les comptes, la remise, les domaines, le videur et le compteur \
              d'incidents — chacun vient d'un endroit différent, et les grouper \
              en une structure d'appel ne ferait que déplacer la liste."
)]
fn monter_l_api(
    options: &Configuration,
    tls: Option<&Arc<ServerConfig>>,
    dkim: Option<ams_loop_tokio::DkimSigner>,
    boites: Arc<BoitesImap>,
    comptes: Arc<crate::comptes::Comptes>,
    remise: Arc<Boites>,
    domaines: Arc<Vec<String>>,
    garde: Arc<ams_loop_tokio::SharedGuard>,
    incidents: Arc<crate::incidents::Incidents>,
    file: Option<ams_loop_tokio::Spool>,
    message_max: usize,
    port_h3: Option<u16>,
) -> Result<Option<MontageApi>, String> {
    if options.listen_http.is_empty() {
        eprintln!("air-mail-server : API REST non servie — aucune adresse d'écoute configurée");
        return Ok(None);
    }
    let Some(tls) = tls else {
        eprintln!(
            "air-mail-server : API REST NON SERVIE — aucun certificat. Elle porte des jetons \
             porteurs, et un jeton qui traverse un réseau en clair est un jeton volé : ce port \
             ne s'ouvre pas sans chiffrement (C4)."
        );
        return Ok(None);
    };
    if options.token_key.is_empty() {
        eprintln!(
            "air-mail-server : API REST NON SERVIE — aucun secret de scellement. Sans clé, aucun \
             jeton ne peut être scellé ni vérifié."
        );
        return Ok(None);
    }

    let clef = ams_api::key_from_hex(&options.token_key).map_err(dire_la_clef)?;
    let session = ams_session::http::Http::new(clef, DUREE_DE_JETON_US).map_err(|_| {
        String::from("la durée de vie des jetons dépasse ce qu'un jeton peut vivre")
    })?;
    // **`Alt-Svc` EST LA SEULE CHOSE QUI RENDE LE PORT HTTP/3 TROUVABLE**
    // (RFC 7838, §3.1 de RFC 9114) : sans elle, ce serveur ouvre un port UDP
    // qu'aucun client conforme ne cherchera jamais. Elle n'est écrite que si ce
    // port est RÉELLEMENT lié — annoncer une alternative absente ferait perdre
    // une connexion à chaque client qui la croit.
    let session = match port_h3 {
        Some(port) => session.with_h3_port(port),
        None => session,
    };

    let adresse: std::net::SocketAddr = options.listen_http.parse().map_err(|_| {
        format!(
            "`{}` n'est pas une adresse d'écoute HTTP",
            options.listen_http
        )
    })?;
    let ecouteur = std::net::TcpListener::bind(adresse)
        .map_err(|erreur| format!("écoute HTTP sur {adresse} : {erreur}"))?;
    ecouteur
        .set_nonblocking(true)
        .map_err(|erreur| format!("écoute HTTP sur {adresse} : {erreur}"))?;
    let ecouteur = TcpListener::from_std(ecouteur)
        .map_err(|erreur| format!("écoute HTTP sur {adresse} : {erreur}"))?;

    // **LA CONFIGURATION TLS DE L'API N'EST PAS CELLE DES AUTRES ÉCOUTES** :
    // elle porte l'ALPN `h2`, et rien d'autre. La partager telle quelle ferait
    // annoncer `h2` sur le port SMTP, où il ne veut rien dire.
    let mut http_tls = (**tls).clone();
    http_tls.alpn_protocols = ams_tls::alpn();

    eprintln!(
        "air-mail-server : API REST sur {adresse} — HTTP/2 sur TLS, ALPN `h2` seul. \
         UN MOT DE PASSE N'OUVRE PAS L'ADMINISTRATION : il ouvre le courrier, la soumission \
         et la supervision du compte, et rien de plus."
    );
    Ok(Some((
        ecouteur,
        session,
        Arc::new(http_tls),
        Arc::new({
            let api =
                crate::api::ApiMaildir::new(boites, comptes, remise, domaines, garde, incidents);
            // LA MÊME RÈGLE QUE SMTP : sans file, une soumission qui nomme un
            // destinataire d'ailleurs est refusée. Deux portes, une seule règle.
            let api = match file {
                Some(file) => api.avec_file(file, message_max),
                None => api,
            };
            // **ET LA MÊME SIGNATURE.** Un message soumis par l'API n'est pas
            // moins émis par ce serveur qu'un message soumis en SMTP : deux
            // portes qui signeraient différemment donneraient à l'exploitant un
            // courrier authentifié une fois sur deux, sans qu'il sache laquelle.
            match dkim {
                Some(signataire) => api.avec_dkim(signataire),
                None => api,
            }
        }),
    )))
}

/// Ouvre la socket UDP de l'API en HTTP/3, si elle est configurée.
///
/// # LES MÊMES CONDITIONS QUE HTTP/2, ET POUR LES MÊMES RAISONS
///
/// Sans certificat ni secret de scellement, ce port ne s'ouvre pas : il porte les
/// mêmes jetons, et un jeton qui traverse un réseau en clair est un jeton volé
/// (C4). QUIC chiffre toujours (§5 de RFC 9001) — il n'y a donc même pas de mode
/// en clair à refuser, seulement une configuration incomplète.
///
/// **ET IL NE S'OUVRE PAS TOUT SEUL** : HTTP/3 se sert conventionnellement sur le
/// même numéro de port que HTTP/2, en UDP, mais l'ouvrir sans qu'on l'ait dit
/// serait ouvrir un port derrière un pare-feu que l'exploitant n'a pas ouvert. Une
/// surprise sur un port est un incident.
fn monter_l_api_h3(
    options: &Configuration,
) -> Result<Option<(std::net::UdpSocket, Arc<ServerConfig>)>, String> {
    if options.listen_h3.is_empty() {
        return Ok(None);
    }
    if !options.tls.est_configure() {
        eprintln!(
            "air-mail-server : API REST EN HTTP/3 NON SERVIE — aucun certificat. QUIC ne monte \
             pas sans lui (§4 de RFC 9001)."
        );
        return Ok(None);
    }
    if options.token_key.is_empty() {
        eprintln!(
            "air-mail-server : API REST EN HTTP/3 NON SERVIE — aucun secret de scellement, comme \
             pour HTTP/2."
        );
        return Ok(None);
    }

    let adresse: std::net::SocketAddr = options.listen_h3.parse().map_err(|_| {
        format!(
            "`{}` n'est pas une adresse d'écoute HTTP/3",
            options.listen_h3
        )
    })?;
    let socket = std::net::UdpSocket::bind(adresse)
        .map_err(|erreur| format!("écoute HTTP/3 sur {adresse} : {erreur}"))?;
    socket
        .set_nonblocking(true)
        .map_err(|erreur| format!("écoute HTTP/3 sur {adresse} : {erreur}"))?;

    // **ELLE SE BÂTIT DEPUIS LES CERTIFICATS, ET NE SE CLONE PAS.**
    //
    // Cloner celle d'HTTP/2 pour n'en changer que l'ALPN paraît suffisant, et ne
    // l'est pas : `ams_tls::server_config` monte le fournisseur ORDINAIRE, et
    // §5 de RFC 9001 demande un fournisseur qui sache dériver des clés de paquet.
    // Une configuration QUIC bâtie sur le fournisseur ordinaire **se construit,
    // démarre, et refuse toute poignée de main** — le port écoute, annonce `h3`,
    // et ne sert rien. `ams-tls` le dit dans sa propre documentation ; je l'ai
    // écrit quand même, et c'est l'essai contre le binaire qui l'a montré.
    let chaine = std::fs::read(&options.tls.certificate_chain_path).map_err(|erreur| {
        format!(
            "certificat `{}` : {erreur}",
            options.tls.certificate_chain_path
        )
    })?;
    let cle = std::fs::read(&options.tls.private_key_path)
        .map_err(|erreur| format!("clé privée `{}` : {erreur}", options.tls.private_key_path))?;
    let mut h3_tls = ams_tls::quic_server_config(&chaine, &cle)
        .map_err(|erreur| format!("matériel TLS pour HTTP/3 : {erreur}"))?;
    // §3.1 de RFC 9114 : l'ALPN `h3` est la condition de la connexion.
    h3_tls.alpn_protocols = ams_tls::alpn_h3();

    eprintln!(
        "air-mail-server : API REST sur {adresse}/udp — HTTP/3 sur QUIC, ALPN `h3` seul. \
         Les mêmes jetons, la même session, le même videur que HTTP/2."
    );
    Ok(Some((socket, Arc::new(h3_tls))))
}

/// Dit à l'exploitant ce qui cloche dans son secret de scellement.
///
/// **CELUI QUI LIT CECI A ÉCRIT LA CONFIGURATION**, et il a le droit de savoir ce
/// qu'il doit corriger. C'est l'exact contraire de ce qu'on dit à un client de
/// l'API, et pour la même raison : ce qui apprend à qui sonde ne doit pas se
/// dire, ce qui aide qui répare doit se dire.
fn dire_la_clef(quoi: ams_api::KeyProblem) -> String {
    String::from(match quoi {
        ams_api::KeyProblem::OddLength => {
            "le secret de scellement des jetons n'a pas un nombre pair de chiffres"
        }
        ams_api::KeyProblem::NotHex => {
            "le secret de scellement des jetons n'est pas de l'hexadécimal"
        }
        ams_api::KeyProblem::TooShort => {
            "le secret de scellement des jetons fait moins de trente-deux octets : une clé plus \
             courte que le sceau qu'elle produit donnerait moins de sécurité que la taille du \
             sceau ne le laisse croire"
        }
    })
}

/// Charge le magasin de comptes que la configuration nomme, s'il en nomme.
///
/// # Le fichier doit être illisible par tout le monde, comme une clé
///
/// Ce ne sont que des empreintes, et l'on n'en remonte pas aux mots de passe.
/// Mais un fichier de comptes lisible par tous est **un dictionnaire de noms à
/// essayer**, offert à qui a un compte sur la machine — et c'est aussi le
/// matériel d'une attaque hors ligne, menée à loisir, sans qu'aucun garde ne
/// compte les essais.
fn charger_comptes(chemin: &str) -> Result<Vec<Account>, String> {
    if chemin.is_empty() {
        return Ok(Vec::new());
    }
    refuser_fichier_lisible_par_tous(chemin, "magasin de comptes")?;
    let octets =
        std::fs::read(chemin).map_err(|erreur| format!("comptes `{chemin}` : {erreur}"))?;
    ams_config::decode_accounts(&octets).map_err(|erreur| format!("comptes `{chemin}` : {erreur}"))
}

/// Chaque adresse de compte relève-t-elle d'un domaine annoncé ?
///
/// # Ce que `--hosted` veut dire, maintenant
///
/// Il ne sert plus à ACCEPTER — c'est le magasin de comptes qui décide de cela,
/// adresse par adresse. Il reste la liste de ce que ce serveur déclare servir,
/// et elle est confrontée aux comptes **une fois, au démarrage**. Une adresse
/// dans un domaine qu'on n'annonce pas est presque toujours une faute de frappe,
/// et la découvrir ici coûte une seconde plutôt qu'un courrier qui n'arrive
/// jamais.
fn verifier_les_domaines(comptes: &[Account], heberges: &[String]) -> Result<(), String> {
    for compte in comptes {
        for adresse in &compte.addresses {
            let domaine = adresse.rsplit_once('@').map_or("", |(_, apres)| apres);
            if !heberges
                .iter()
                .any(|heberge| heberge.eq_ignore_ascii_case(domaine))
            {
                return Err(format!(
                    "compte `{}` : l'adresse `{adresse}` est dans un domaine qui n'est pas \
                     annoncé. Ajoutez `--hosted {domaine}` à la configuration, ou corrigez \
                     l'adresse.",
                    compte.login
                ));
            }
        }
    }
    Ok(())
}

/// Les écoutes SMTP de la configuration, et le mode TLS de chacune.
///
/// # Errors
///
/// Une adresse illisible, ou aucune écoute du tout.
fn lire_les_ecoutes(
    options: &Configuration,
) -> Result<std::vec::Vec<(std::net::SocketAddr, ams_loop_tokio::TlsMode)>, String> {
    let mut ecoutes = std::vec::Vec::new();
    if options.smtp_listeners.is_empty() {
        let adresse: std::net::SocketAddr = options
            .listen
            .parse()
            .map_err(|_| format!("`{}` n'est pas une adresse d'écoute", options.listen))?;
        ecoutes.push((adresse, ams_loop_tokio::TlsMode::StartTls));
        return Ok(ecoutes);
    }
    for ecoute in &options.smtp_listeners {
        let adresse: std::net::SocketAddr = ecoute
            .address
            .parse()
            .map_err(|_| format!("`{}` n'est pas une adresse d'écoute", ecoute.address))?;
        let mode = match ecoute.implicit_tls {
            true => ams_loop_tokio::TlsMode::Implicit,
            false => ams_loop_tokio::TlsMode::StartTls,
        };
        ecoutes.push((adresse, mode));
    }
    Ok(ecoutes)
}

/// Charge le matériel TLS que la configuration nomme, s'il en nomme.
///
/// # Le refus d'une clé lisible par tout le monde
///
/// Une clé privée que n'importe quel compte de la machine peut lire n'est plus
/// une clé privée : il suffit d'un compte de service compromis pour repartir
/// avec l'identité du serveur, et le vol ne laisse aucune trace. Le serveur
/// refuse donc de démarrer.
///
/// **Le partage par GROUPE reste permis**, et ce n'est pas un oubli : c'est
/// exactement ainsi que les certificats se partagent sur un système bien tenu
/// (le groupe `ssl-cert` de Debian, par exemple, avec des clés en `0640`).
/// Refuser cela punirait la bonne pratique au lieu de la mauvaise.
fn charger_tls(tls: &Tls) -> Result<Option<Arc<ServerConfig>>, String> {
    if !tls.est_configure() {
        return Ok(None);
    }

    let chaine = std::fs::read(&tls.certificate_chain_path)
        .map_err(|erreur| format!("certificat `{}` : {erreur}", tls.certificate_chain_path))?;
    let cle = std::fs::read(&tls.private_key_path)
        .map_err(|erreur| format!("clé privée `{}` : {erreur}", tls.private_key_path))?;
    refuser_fichier_lisible_par_tous(&tls.private_key_path, "clé privée")?;

    let config = ams_tls::server_config(&chaine, &cle)
        .map_err(|erreur| format!("matériel TLS : {erreur}"))?;
    Ok(Some(Arc::new(config)))
}

/// Charge la clé DKIM que la configuration nomme, s'il y en a une.
///
/// # LA MÊME EXIGENCE QUE POUR TLS, ET POUR LA MÊME RAISON
///
/// Une clé de signature lisible par tout le monde n'est plus une clé de
/// signature : qui la vole signe en notre nom, et rien ne le distingue de nous.
/// Le serveur refuse donc de démarrer, et le partage par groupe reste permis.
///
/// # ON LA LIT AU DÉMARRAGE, ET PAS À CHAQUE SIGNATURE
///
/// Un serveur qui découvrirait à la première émission que sa clé est illisible
/// aurait déjà annoncé qu'il signe. Ce qui ne peut pas marcher doit refuser de
/// démarrer.
fn charger_dkim(dkim: &ams_config::Dkim) -> Result<Option<Arc<SigningKey>>, String> {
    if !dkim.est_configure() {
        return Ok(None);
    }
    refuser_fichier_lisible_par_tous(&dkim.private_key_path, "clé DKIM")?;
    let pem = std::fs::read(&dkim.private_key_path)
        .map_err(|erreur| format!("clé DKIM `{}` : {erreur}", dkim.private_key_path))?;
    let cle = SigningKey::from_pem(&pem)
        .map_err(|erreur| format!("clé DKIM `{}` : {erreur}", dkim.private_key_path))?;
    Ok(Some(Arc::new(cle)))
}

/// Ce que l'exploitant doit publier, prêt à coller dans sa zone.
///
/// # POURQUOI LE COMPOSER, ET NE PAS LAISSER LE FAIRE
///
/// Cette ligne disait OÙ publier — `<sélecteur>._domainkey.<domaine>` — et pas
/// QUOI. Il fallait donc dériver la clé publique à la main : `openssl pkey
/// -pubout`, retirer l'en-tête PEM, recoller les lignes, préfixer les étiquettes.
/// Quatre étapes, quatre occasions de se tromper.
///
/// **Et une erreur y est PIRE que l'absence de signature** : un enregistrement
/// faux fait échouer TOUTES nos signatures, ce qui se lit dans les rapports
/// DMARC du domaine comme un échec d'authentification. Ce serveur détient la
/// seule information qui rend l'étape sûre.
///
/// # UNE LIGNE PAR DOMAINE, AVEC SON NOM ENTIER
///
/// Le serveur connaît la liste ; la faire recopier serait lui faire refaire un
/// travail qu'il a déjà fait, et c'est en recopiant qu'on se trompe.
fn a_publier(selecteur: &str, domaines: &[String], cle: &Arc<SigningKey>) -> String {
    if domaines.is_empty() {
        return String::from(" — aucun domaine hébergé, rien ne sera signé");
    }
    let record = cle.public_record();
    let valeur = String::from_utf8_lossy(&record);
    let mut dit = String::from(" — À PUBLIER :");
    for domaine in domaines {
        dit.push_str(&format!(
            "\n    {selecteur}._domainkey.{domaine}. IN TXT \"{valeur}\""
        ));
    }
    dit
}

/// Interroge la zone pour chaque domaine, et dit ce qu'on y a trouvé.
///
/// # LES CINQ ISSUES NE DEMANDENT PAS LA MÊME CHOSE
///
/// Une clé DIFFÉRENTE veut dire que tout ce qu'on émet échoue DÉJÀ : c'est la
/// seule qui appelle une correction immédiate. Une clé RÉVOQUÉE échoue tout
/// autant, mais n'appelle PAS la même correction : ce n'est pas une erreur de
/// publication, c'est une déclaration du détenteur du domaine, et lui parler
/// d'une « autre clé » l'enverrait chercher ce qui n'existe pas. Une clé ABSENTE
/// veut dire qu'elle n'est pas encore publiée, ou pas encore propagée — attendre
/// suffit peut-être. Un DNS INJOIGNABLE ne dit rien du tout, et le faire passer
/// pour un problème de zone enverrait chercher au mauvais endroit.
///
/// **CE QUI VA BIEN NE S'ÉCRIT PAS.** Un journal qui répète « conforme » à chaque
/// domaine et à chaque démarrage est un journal qu'on cesse de lire, et c'est
/// alors la ligne qui compte qu'on manque. Seul le compte est rendu.
async fn dire_la_publication(
    resolveur: &ams_loop_tokio::Resolver,
    selecteur: &str,
    domaines: &[String],
    cle: &Arc<SigningKey>,
) {
    use ams_loop_tokio::PublicationDkim;

    let mut conformes = 0_usize;
    for domaine in domaines {
        match ams_loop_tokio::publication_dkim(resolveur, selecteur, domaine, cle).await {
            PublicationDkim::Conforme => conformes = conformes.saturating_add(1),
            PublicationDkim::Differente => eprintln!(
                "air-mail-server : ATTENTION — `{selecteur}._domainkey.{domaine}` porte une \
                 AUTRE clé que celle qui signe. Tout ce qui part pour `{domaine}` échoue déjà \
                 en DKIM chez ses destinataires."
            ),
            PublicationDkim::Revoquee => eprintln!(
                "air-mail-server : ATTENTION — `{selecteur}._domainkey.{domaine}` publie une \
                 clé RÉVOQUÉE (`p=` vide, §3.6.1 de RFC 6376), et non une autre clé. Tout ce \
                 qui part pour `{domaine}` échoue déjà en DKIM. Ce sélecteur a été RETIRÉ : \
                 signer avec un autre, ou republier celui-ci si la révocation était une \
                 erreur."
            ),
            PublicationDkim::Absente => eprintln!(
                "air-mail-server : `{selecteur}._domainkey.{domaine}` est INTROUVABLE — pas \
                 encore publié, ou pas encore propagé. Ce qui part pour `{domaine}` échoue en \
                 DKIM tant qu'il l'est."
            ),
            PublicationDkim::Injoignable => eprintln!(
                "air-mail-server : `{selecteur}._domainkey.{domaine}` n'a pas pu être \
                 interrogé — on ne conclut RIEN de ce silence."
            ),
        }
    }
    if conformes > 0 {
        eprintln!(
            "air-mail-server : clé DKIM publiée et conforme pour {conformes} domaine(s) sur {}",
            domaines.len()
        );
    }
}

/// Refuse un fichier secret que le reste du monde peut lire.
fn refuser_fichier_lisible_par_tous(chemin: &str, quoi: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;

    let etat =
        std::fs::metadata(chemin).map_err(|erreur| format!("{quoi} `{chemin}` : {erreur}"))?;
    let mode = etat.permissions().mode();
    if mode & 0o004 != 0 {
        return Err(format!(
            "{quoi} `{chemin}` : lisible par TOUT LE MONDE (mode {:o}). \
             `chmod o-r` le répare. Le partage par groupe, lui, reste permis.",
            mode & 0o777
        ));
    }
    Ok(())
}

/// Dit ce qui, DÉJÀ SUR LE DISQUE, se laisse lire par les autres comptes.
///
/// # Pourquoi le masque ne suffit pas
///
/// Il gouverne ce qu'on CRÉE, et rien d'autre. Une installation antérieure à ce
/// resserrement garde ses `0755` et ses `0644` : le courrier déjà livré reste
/// lisible, et rien ne le dirait jamais. Le corriger à la place de l'exploitant
/// serait pire — changer les permissions de ses fichiers sans le lui demander —,
/// mais se taire reviendrait à laisser croire que le resserrement a tout réglé.
///
/// # Ce qu'on regarde, et pourquoi c'est suffisant
///
/// La RACINE du Maildir décide de tout ce qu'elle contient : sans le bit `x`
/// pour les autres, aucun chemin ne la traverse, quels que soient les modes en
/// dessous. Parcourir chaque boîte coûterait un temps proportionnel au courrier
/// stocké, pour une réponse que la racine donne déjà.
fn dire_ce_qui_reste_ouvert(chemins: &[(&str, &Path)]) {
    use std::os::unix::fs::PermissionsExt as _;

    for (quoi, chemin) in chemins {
        if chemin.as_os_str().is_empty() {
            continue;
        }
        let Ok(etat) = std::fs::metadata(chemin) else {
            continue;
        };
        let mode = etat.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            eprintln!(
                "air-mail-server : {quoi} `{}` est en {mode:04o} — les autres comptes de \
                 cette machine y ont accès. Le masque ne corrige que ce qui NAÎT APRÈS lui ; \
                 pour le reste : `chmod -R go= {}`",
                chemin.display(),
                chemin.display()
            );
        }
    }
}

/// Monte le serveur et le fait tourner jusqu'à l'arrêt.
async fn servir(fichier: &Path) -> Result<(), String> {
    // LE REFUS DU SUPERUTILISATEUR VIENT AVANT TOUT LE RESTE (C10) — avant
    // d'ouvrir un port, avant de créer un répertoire. Rien de ce qui suit ne doit
    // s'exécuter avec ces privilèges, pas même une seconde.
    refuse_root().map_err(|erreur| erreur.to_string())?;

    // **ET LE MASQUE AVANT LA PREMIÈRE CRÉATION**, pour la même raison : rien de
    // ce qui suit ne doit naître lisible par les autres comptes de la machine,
    // pas même une seconde. Le masque n'est PAS rétroactif ; c'est pourquoi les
    // permissions déjà en place sont examinées plus bas, une fois le Maildir
    // connu.
    let ancien_masque = restreindre_le_masque();
    if masque_trop_large(ancien_masque) {
        eprintln!(
            "air-mail-server : masque de création resserré de {ancien_masque:04o} à 0077 — ce \
             qui suit naît lisible par son seul propriétaire"
        );
    }

    let octets =
        std::fs::read(fichier).map_err(|erreur| format!("`{}` : {erreur}", fichier.display()))?;
    let options: Configuration = ams_config::decode(&octets)
        .map_err(|erreur| format!("`{}` : {erreur}", fichier.display()))?;
    // **LA LISTE, SI ELLE EXISTE ; SINON `listen` SEUL, EN `STARTTLS`.** C'est
    // ce qui rend le champ ajoutable sans rien casser : un fichier écrit avant
    // lui décode une liste vide, donc une seule écoute — exactement son
    // comportement d'alors.
    let ecoutes = lire_les_ecoutes(&options)?;
    let maildir = PathBuf::from(&options.maildir);

    // CE QUI EST DÉJÀ LÀ NE SE RESSERRE PAS TOUT SEUL. Les trois chemins que ce
    // serveur n'a pas forcément créés lui-même, et dont l'ouverture coûterait le
    // plus : le courrier, le secret de scellement, les empreintes.
    dire_ce_qui_reste_ouvert(&[
        ("le Maildir", &maildir),
        ("la configuration", fichier),
        ("le magasin des comptes", Path::new(&options.accounts)),
    ]);

    if options.hosted.is_empty() {
        eprintln!(
            "air-mail-server : aucun `--hosted` : ce serveur n'acceptera de courrier \
             pour personne."
        );
    }

    // Le domaine vit aussi longtemps que le processus. Le fuir est ici exact :
    // il est lu une fois, jamais remplacé, et libéré à la sortie du programme.
    let domaine: &'static [u8] = Box::leak(options.domain.clone().into_bytes().into_boxed_slice());
    let config = Config::new(
        domaine,
        usize::try_from(options.max_recipients).unwrap_or(usize::MAX),
        options.max_message_octets,
        options.limits,
    )
    .map_err(|erreur| format!("domaine `{}` : {erreur}", options.domain))?;

    // LE CHIFFREMENT SE DÉCIDE ICI, ET D'UN SEUL ENDROIT : le matériel existe,
    // donc `STARTTLS` est annoncé. Deux valeurs qui pourraient se contredire —
    // « annoncer » d'un côté, « savoir chiffrer » de l'autre — n'existent pas :
    // c'est la même.
    let chiffrement = charger_tls(&options.tls)?;
    // LA CLÉ DE SIGNATURE SE LIT AVANT D'OUVRIR QUOI QUE CE SOIT : ce qui ne
    // peut pas marcher doit refuser de démarrer, et non le découvrir à la
    // première émission.
    let signature = charger_dkim(&options.dkim)?;
    let charges = charger_comptes(&options.accounts)?;
    verifier_les_domaines(&charges, &options.hosted)?;
    // **UN SEUL MAGASIN POUR LES QUATRE SERVICES**, et il est modifiable :
    // ce qu'un administrateur change doit être vu par SMTP, IMAP, POP3 et l'API,
    // tout de suite, sans arrêter le service.
    let comptes = Arc::new(crate::comptes::Comptes::new(
        std::path::PathBuf::from(&options.accounts),
        charges,
    ));
    // `AUTH` n'est annoncé QUE si les deux conditions tiennent : quelqu'un à qui
    // répondre oui, et de quoi chiffrer. La session refuse `AUTH` hors TLS de
    // toute façon ; l'annoncer sans chiffrement ne ferait que mentir plus tôt.
    let authentifie = !comptes.vue().is_empty() && chiffrement.is_some();
    let config = if chiffrement.is_some() {
        config.with_capabilities(Capabilities {
            starttls: true,
            auth: authentifie,
            dsn: false,
        })
    } else {
        config
    };

    // ── SPF (C9) ────────────────────────────────────────────────────────────
    //
    // Comme le chiffrement : PAS DE DRAPEAU. La vérification a lieu si et
    // seulement si la configuration nomme au moins un résolveur.
    let mut resolveurs = Vec::new();
    for brute in &options.spf.resolvers {
        let adresse: std::net::SocketAddr = brute
            .parse()
            .map_err(|_| format!("résolveur `{brute}` : ce n'est pas une adresse `hôte:port`"))?;
        resolveurs.push(adresse);
    }
    let politique_expediteur = if resolveurs.is_empty() {
        SenderPolicy::Ignore
    } else if options.spf.enforcement == Enforcement::Enforce {
        SenderPolicy::Enforce
    } else {
        SenderPolicy::Observe
    };
    let verificateur = if resolveurs.is_empty() {
        None
    } else {
        let delai = Duration::from_millis(u64::from(options.spf.timeout_millis));
        Some(
            SenderChecker::new(resolveurs.clone(), delai)
                .map_err(|erreur| format!("SPF : {erreur}"))?,
        )
    };
    let config = config.with_sender_policy(politique_expediteur);
    // **UN COMPTEUR ÉTEINT QU'ON CROIT ALLUMÉ EST PIRE QU'UN COMPTEUR ABSENT.**
    // Ce seuil a été AJOUTÉ au schéma : une configuration écrite avant lui décode
    // zéro, et zéro l'éteint. L'exploitant doit l'apprendre au démarrage, et non
    // le jour où une récolte passe.
    if options.guard.refused_recipients_per_minute == 0 {
        eprintln!(
            "air-mail-server : RÉCOLTE D'ADRESSES NON COMPTÉE — cette configuration est \
             antérieure à ce seuil. Une rafale de destinataires refusés ne bannira personne. \
             `air-mail-admin config write` la réécrit avec la valeur par défaut."
        );
    }
    eprintln!(
        "air-mail-server : {}",
        match politique_expediteur {
            SenderPolicy::Ignore => String::from(
                "SPF non vérifié — aucun résolveur configuré (`air-mail-admin --resolver …`)"
            ),
            SenderPolicy::Observe => format!(
                "SPF vérifié et RETENU, sans rien opposer ; résolveurs : {}",
                options.spf.resolvers.join(", ")
            ),
            SenderPolicy::Enforce => format!(
                "SPF APPLIQUÉ — un `fail` est refusé (550), une panne ajournée (451) ; \
                 résolveurs : {}",
                options.spf.resolvers.join(", ")
            ),
        }
    );
    // ── DMARC (C9) ──────────────────────────────────────────────────────────
    //
    // Comme le reste : PAS DE DRAPEAU. DMARC est évalué si et seulement si une
    // liste de suffixes publics est nommée ET qu'un résolveur l'est aussi — il
    // faut aller chercher la politique du domaine de l'en-tête `From:`. Les DEUX
    // moitiés de cette règle tiennent désormais dans `est_configure` : les
    // écrire ici obligeait chaque appelant à s'en souvenir, et un l'oubliait.
    let alignement = if options.dmarc.est_configure(&options.spf) {
        let chemin = Path::new(&options.dmarc.public_suffix_list);
        let liste = std::fs::read(chemin).map_err(|erreur| {
            format!(
                "liste des suffixes publics `{}` : {erreur}",
                chemin.display()
            )
        })?;
        Some(std::sync::Arc::new(liste))
    } else {
        None
    };
    let dmarc_applique = options.dmarc.enforcement == Enforcement::Enforce;
    let verificateur_dmarc = match (verificateur.as_ref(), alignement) {
        (Some(checker), Some(liste)) => Some(DmarcChecker::new(
            checker.resolver().clone(),
            liste,
            dmarc_applique,
        )),
        _ => None,
    };
    eprintln!(
        "air-mail-server : {}",
        match (&verificateur_dmarc, dmarc_applique) {
            // ON INTERROGE LE CHAMP, ET NON LE PRÉDICAT : celui-ci répond
            // maintenant « non » dans ce cas précis, et le bras ne se
            // déclencherait jamais. Ce qu'on cherche ici est justement la MOITIÉ
            // de la règle qui est remplie, pour dire laquelle manque.
            (None, _) if !options.dmarc.public_suffix_list.is_empty() => String::from(
                "DMARC non évalué — une liste de suffixes est nommée, mais aucun résolveur"
            ),
            (None, _) => String::from(
                "DMARC non évalué — aucune liste de suffixes publics (`air-mail-admin \
                 --public-suffix-list …`)"
            ),
            (Some(_), false) => format!(
                "DMARC évalué et RETENU, sans rien opposer ; suffixes publics `{}`",
                options.dmarc.public_suffix_list
            ),
            (Some(_), true) => format!(
                "DMARC APPLIQUÉ — un `p=reject` est opposé (550) ; suffixes publics `{}`",
                options.dmarc.public_suffix_list
            ),
        }
    );
    // **VIDE, LA QUARANTAINE N'EXISTE PAS** : un `p=quarantine` est remis dans la
    // boîte de réception, et le rapport agrégé le dit. `met_en_quarantaine`
    // exige aussi que DMARC soit évalué — un dossier que rien ne remplirait
    // annoncerait une protection qui n'a pas lieu.
    let quarantaine = options
        .dmarc
        .met_en_quarantaine(&options.spf)
        .then(|| options.dmarc.quarantine_folder.clone());
    if verificateur_dmarc.is_some() {
        // **CE N'EST PAS LE MÊME RÉGLAGE QUE `--dmarc enforce`**, et le dire
        // séparément évite qu'on croie l'un compris dans l'autre : `enforce`
        // gouverne le REFUS d'un `p=reject`, la quarantaine REMET ailleurs.
        eprintln!(
            "air-mail-server : {}",
            match &quarantaine {
                Some(dossier) => format!(
                    "quarantaine DMARC dans le dossier `{dossier}` de chaque compte, créé à la \
                     première remise"
                ),
                None => String::from(
                    "quarantaine DMARC AUCUNE — un `p=quarantine` est remis dans la boîte de \
                     réception, et les rapports le disent (`air-mail-admin \
                     --dmarc-quarantine-folder …`)"
                ),
            }
        );
    }

    // ── MTA-STS (RFC 8461) ──────────────────────────────────────────────────
    //
    // **PAS DE DRAPEAU** : l'absence d'autorités EST l'absence de service, comme
    // la liste des suffixes publics pour DMARC. Et il faut LES DEUX — sans
    // cache, un redémarrage rouvrirait la fenêtre de déclassement que §5 ferme.
    let mtasts = if options.mtasts.est_configure() {
        let Some(checker) = verificateur.as_ref() else {
            return Err(String::from(
                "MTA-STS est configuré sans résolveur DNS : l'identifiant de politique se lit \
                 dans un `TXT`, et l'hôte qui la sert se résout \
                 (`air-mail-admin config write … --resolver 127.0.0.1:53`)",
            ));
        };
        let pem = std::fs::read(&options.mtasts.anchors)
            .map_err(|erreur| format!("`{}` : {erreur}", options.mtasts.anchors))?;
        let racines = ams_tls::anchors(&pem)
            .map_err(|erreur| format!("`{}` : {erreur}", options.mtasts.anchors))?;
        let combien = racines.len();
        let dossier = PathBuf::from(&options.mtasts.cache);
        // ON CRÉE LE DOSSIER, MAIS PAS SON PARENT — la même règle que la file :
        // poser un chemin entier écrirait quelque part où l'exploitant ne
        // l'attendait pas, sur une faute de frappe.
        if let Err(erreur) = std::fs::create_dir(&dossier)
            && erreur.kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(format!("`{}` : {erreur}", dossier.display()));
        }
        eprintln!(
            "air-mail-server : MTA-STS (RFC 8461) évalué — {combien} autorité(s) lue(s) dans \
             `{}`, cache `{}`. DANE L'EMPORTE quand un domaine publie les deux. L'hôte de \
             politique est joint en TLS 1.3 SEUL (C4) : un domaine dont il ne fait que TLS 1.2 \
             ne sera pas lu, et sa remise restera opportuniste.",
            options.mtasts.anchors, options.mtasts.cache
        );
        Some(std::sync::Arc::new(ams_loop_tokio::Sts::new(
            checker.resolver().clone(),
            std::sync::Arc::new(ams_tls::webpki_config(std::sync::Arc::new(racines))),
            dossier,
            Duration::from_secs(u64::from(options.timeouts.command_seconds)),
        )))
    } else {
        eprintln!(
            "air-mail-server : MTA-STS non évalué — aucune autorité nommée \
             (`air-mail-admin config write … --mta-sts-anchors /etc/ssl/certs/ca-certificates.crt \
             --mta-sts-cache /var/cache/ams/mtasts`)"
        );
        None
    };

    // ── LA FILE D'ATTENTE DU SERVEUR ────────────────────────────────────────
    //
    // **TOUT CE QUI SORT PASSE PAR ELLE**, et c'est le point de cette tranche :
    // il y avait trois politiques de reprise dans ce produit — celle-ci, et deux
    // écrites à la main pour les rapports DMARC et TLS, qui réessayaient à
    // chaque tour quotidien et s'effaçaient en silence au bout de sept jours.
    // Trois politiques, c'est trois vérités qui divergent, et deux d'entre elles
    // n'avaient jamais été éprouvées.
    //
    // Deux refus AU DÉMARRAGE plutôt que du courrier perdu en silence :
    //
    //   - sans dossier, on accepterait un message qu'on n'a nulle part où poser ;
    //   - sans résolveur, on ne saurait trouver AUCUN `MX`. Le message resterait
    //     en file jusqu'à sa péremption, puis reviendrait à son expéditeur —
    //     cinq jours pour apprendre que le serveur n'a jamais pu essayer.
    //
    // Refuser de démarrer se voit tout de suite ; l'autre se découvre une
    // semaine plus tard, chez celui qui attendait la réponse.
    let emet =
        options.relay.enabled || options.dmarc.envoie(&options.spf) || options.tlsrpt.envoie();
    let mut resolveur_de_file = None;
    let file = if emet {
        if options.queue.spool.is_empty() {
            return Err(String::from(
                "quelque chose doit sortir — relais, rapports DMARC ou rapports TLS — et aucun \
                 dossier de file n'est nommé : un message accepté qu'on n'a nulle part où poser \
                 est un message perdu (`air-mail-admin config write … --queue-spool \
                 /var/spool/ams/file`)",
            ));
        }
        let Some(checker) = verificateur.as_ref() else {
            return Err(String::from(
                "quelque chose doit sortir, et aucun résolveur DNS n'est nommé : aucun `MX` ne \
                 pourrait être trouvé, et tout message accepté reviendrait à son expéditeur \
                 après la péremption (`air-mail-admin config write … --resolver 127.0.0.1:53`)",
            ));
        };
        resolveur_de_file = Some(checker.resolver().clone());
        let dossier = PathBuf::from(&options.queue.spool);
        // ON CRÉE LE DOSSIER, MAIS ON NE CRÉE PAS SON PARENT. Poser un chemin
        // entier au démarrage écrirait quelque part où l'exploitant ne
        // l'attendait pas, sur une faute de frappe.
        if let Err(erreur) = std::fs::create_dir(&dossier)
            && erreur.kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(format!("`{}` : {erreur}", dossier.display()));
        }
        let reprise = options.queue.backoff();
        eprintln!(
            "air-mail-server : FILE D'ATTENTE `{}` — 1er essai à {} s, plafond {} s, abandon à \
             {} s. TOUT ce qui sort y passe : le courrier des comptes, les rapports DMARC et les \
             rapports TLS. Quand on renonce, un rapport de non-remise (RFC 3464) revient \
             LOCALEMENT dans la boîte de l'expéditeur.",
            options.queue.spool,
            reprise.first.as_secs(),
            reprise.ceiling.as_secs(),
            reprise.expiry.as_secs()
        );
        if options.relay.enabled && !authentifie {
            eprintln!(
                "air-mail-server : ATTENTION — émission ouverte SANS CHIFFREMENT : `AUTH` n'est \
                 pas annoncé, donc aucune session ne pourra s'authentifier, donc rien ne sortira \
                 pour les comptes."
            );
        }
        Some(std::sync::Arc::new(ams_loop_tokio::Spool::new(
            dossier,
            reprise,
            options.domain.clone(),
            format!("postmaster@{}", options.domain),
        )))
    } else {
        if !options.queue.spool.is_empty() {
            eprintln!(
                "air-mail-server : dossier de file nommé, mais RIEN NE SORT — ni relais, ni \
                 rapports remis. Rien n'y sera écrit."
            );
        }
        eprintln!(
            "air-mail-server : aucune émission — ce serveur REÇOIT, et ne remet rien à \
             l'extérieur. Un destinataire qui n'est pas d'ici est refusé (550), même authentifié."
        );
        None
    };

    // ── LES RAPPORTS TLS (RFC 8460) ─────────────────────────────────────────
    //
    // **PAS DE DRAPEAU POUR COMPOSER** : l'absence de dossier EST l'absence de
    // service, comme pour les rapports DMARC. Le drapeau, lui, ne gouverne que
    // la REMISE — deux crans, pour qu'un exploitant puisse lire ce qu'il
    // enverrait.
    let rapports_tls = if options.tlsrpt.compose() {
        let Some(checker) = verificateur.as_ref() else {
            return Err(String::from(
                "les rapports TLS sont configurés sans résolveur DNS : `_smtp._tls` se lit dans \
                 un `TXT`, et la vérification des destinations aussi \
                 (`air-mail-admin config write … --resolver 127.0.0.1:53`)",
            ));
        };
        let dossier = PathBuf::from(&options.tlsrpt.directory);
        if let Err(erreur) = std::fs::create_dir(&dossier)
            && erreur.kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(format!("`{}` : {erreur}", dossier.display()));
        }
        // **NOTRE ADRESSE D'ÉMISSION SE DÉDUIT DE L'ÉCOUTE**, faute de mieux :
        // une machine peut sortir par une autre interface que celle où elle
        // écoute, et ce champ est facultatif (§4.3). L'écrire faux serait pire
        // que de l'omettre — mais le nom de l'écoute est ce que l'exploitant a
        // choisi, donc ce qu'il reconnaîtra dans ses propres journaux.
        let notre_adresse = options
            .listen
            .rsplit_once(':')
            .map_or_else(|| options.listen.clone(), |(hote, _)| String::from(hote));
        let journal = ams_loop_tokio::TlsReports::new(
            options.domain.clone(),
            format!("postmaster@{}", options.domain),
            notre_adresse,
            dossier,
            checker.resolver().clone(),
            Duration::from_secs(u64::from(options.timeouts.command_seconds)),
        );
        let journal = match signature.clone() {
            Some(cle) => journal.with_dkim(DkimSigner::new(options.dkim.selector.clone(), cle)),
            None => journal,
        };
        // LA FILE N'EST LÀ QUE SI ON A DEMANDÉ LA REMISE.
        let journal = if options.tlsrpt.envoie() {
            let journal = match file.as_ref() {
                Some(attente) => journal.with_queue(std::sync::Arc::clone(attente)),
                // Sans file, `--tlsrpt-send` n'aurait pas passé le contrôle de
                // démarrage : ce bras est la ceinture de cette bretelle.
                None => journal,
            };
            // **LE TRANSPORT `https:` EMPRUNTE LES AUTORITÉS DE MTA-STS**, parce
            // qu'il n'y a aucune raison d'en avoir deux jeux. Sans elles, seul
            // `mailto:` fonctionne, et on le dit.
            match mtasts.as_ref() {
                Some(sts) => journal.with_https(std::sync::Arc::clone(sts.tls())),
                None => {
                    eprintln!(
                        "air-mail-server : rapports TLS — le transport `https:` est INDISPONIBLE, \
                         faute d'autorités (`--mta-sts-anchors`). Un domaine qui ne publie \
                         qu'un `rua=https:` ne recevra rien."
                    );
                    journal
                }
            }
        } else {
            journal
        };
        eprintln!(
            "air-mail-server : {}",
            if options.tlsrpt.envoie() {
                format!(
                    "rapports TLS (RFC 8460) composés dans `{}` PUIS REMIS aux destinations qui \
                     ont consenti (§3). On ne rapporte qu'aux domaines qui publient \
                     `_smtp._tls`.",
                    options.tlsrpt.directory
                )
            } else {
                format!(
                    "rapports TLS (RFC 8460) déposés dans `{}`. DÉPOSÉS, PAS REMIS : \
                     `air-mail-admin config write … --tlsrpt-send` les enverrait.",
                    options.tlsrpt.directory
                )
            }
        );
        Some(std::sync::Arc::new(journal))
    } else {
        eprintln!(
            "air-mail-server : rapports TLS non composés — aucun dossier nommé. Les domaines \
             qui publient `_smtp._tls` n'apprendront rien de ce serveur \
             (`air-mail-admin config write … --tlsrpt-dir /var/spool/ams/tlsrpt`)."
        );
        None
    };

    // ── LE JOURNAL DES RAPPORTS (RFC 7489 §7.2) ─────────────────────────────
    //
    // Il ne se compose que si DMARC est évalué : sans évaluation, il n'y aurait
    // rien à rapporter. Et il ne s'ouvre que si un dossier est nommé — composer
    // des rapports est un service qu'on rend à autrui, et il se demande.
    let journal_rapports = match (verificateur.as_ref(), options.dmarc.rapporte(&options.spf)) {
        (Some(checker), true) => {
            let spool = ReportSpool::new(
                if options.dmarc.report_org_name.is_empty() {
                    options.domain.clone()
                } else {
                    options.dmarc.report_org_name.clone()
                },
                if options.dmarc.report_email.is_empty() {
                    format!("postmaster@{}", options.domain)
                } else {
                    options.dmarc.report_email.clone()
                },
                PathBuf::from(&options.dmarc.report_directory),
                checker.resolver().clone(),
            );
            // LE REMETTEUR N'EST LÀ QUE SI ON L'A DEMANDÉ. Émettre du courrier
            // vers des tiers ne se décide pas à la place de celui qui exploite
            // la machine.
            let spool = if options.dmarc.rapporte_les_echecs(&options.spf) {
                spool.with_failure_reports()
            } else {
                spool
            };
            // LA SIGNATURE N'EST LÀ QUE SI UNE CLÉ L'EST : pas de drapeau, et
            // donc pas d'état où l'on croirait signer sans le faire.
            let spool = match signature.clone() {
                Some(cle) => spool.with_dkim(DkimSigner::new(options.dkim.selector.clone(), cle)),
                None => spool,
            };
            // **LA FILE, ET NON UN REMETTEUR À SOI.** Un rapport DMARC passe
            // par la même attente et la même péremption que le reste du
            // courrier, et il y a désormais UNE politique de reprise.
            let spool = match (options.dmarc.envoie(&options.spf), file.as_ref()) {
                (true, Some(attente)) => spool.with_queue(std::sync::Arc::clone(attente)),
                // Sans file, `--dmarc-send` n'aurait pas passé le contrôle de
                // démarrage : ce bras est la ceinture de cette bretelle.
                (true, None) | (false, _) => spool,
            };
            Some(std::sync::Arc::new(spool))
        }
        _ => None,
    };
    // ON DIT SI L'ON SIGNE, ET POUR QUOI. Un serveur qui n'annonce rien laisse
    // croire qu'il signe : c'est ce que l'on attend d'un serveur de courrier, et
    // le découvrir chez le destinataire coûte une réputation.
    //
    // **CETTE LIGNE A DIT « ce qui est ÉMIS est signé » ALORS QUE SEULS LES
    // RAPPORTS L'ÉTAIENT.** L'exploitant publiait la clé, croyait son courrier
    // signé, et ce sont ses utilisateurs qui payaient — c'est exactement la
    // faute que le commentaire ci-dessus décrit. Elle nomme donc désormais les
    // domaines pour lesquels la signature vaut : c'est vérifiable d'un coup
    // d'œil, là où « ce qui est émis » ne l'était pas.
    eprintln!(
        "air-mail-server : {}",
        match &signature {
            Some(cle) => format!(
                "ce qui est ÉMIS est signé (DKIM, RFC 6376) — sélecteur `{}`{}",
                options.dkim.selector,
                a_publier(&options.dkim.selector, &options.hosted, cle)
            ),
            None => String::from(
                "ce qui est ÉMIS n'est PAS signé — aucune clé DKIM nommée \
                 (`air-mail-admin config write … --dkim-selector … --dkim-key …`)"
            ),
        }
    );

    // ── LA ZONE PORTE-T-ELLE CE QU'ON VIENT DE DIRE D'Y METTRE ? ────────────
    //
    // Dire QUOI publier ne dit pas si c'est publié. Un copier-coller tronqué, un
    // enregistrement posé sur le mauvais nom, une propagation qui n'a pas eu
    // lieu : le symptôme est SILENCIEUX et DIFFÉRÉ — le courrier part signé,
    // échoue en DKIM chez tous les destinataires, et l'exploitant ne l'apprend
    // que par les rapports DMARC de son propre domaine, s'il les lit.
    //
    // **CELA NE FAIT JAMAIS ÉCHOUER LE DÉMARRAGE.** Un DNS pas encore joignable
    // au démarrage de la machine est ordinaire ; refuser de démarrer pour cela
    // transformerait une aide en panne.
    if let (Some(cle), Some(resolveur)) = (signature.as_ref(), resolveur_de_file.as_ref()) {
        dire_la_publication(resolveur, &options.dkim.selector, &options.hosted, cle).await;
    }

    // ── LE REMETTEUR DU PARCOURS DE FILE ────────────────────────────────────
    //
    // Il se construit ICI, après les rapports TLS, parce qu'il les consigne :
    // chaque essai qu'il fait — réussi comme manqué — nourrit le rapport qu'on
    // rendra au domaine d'en face.
    let remetteur_de_file = file.as_ref().map(|_| {
        let remetteur = Relay::new(
            resolveur_de_file
                .as_ref()
                .expect("la file exige un résolveur, et le démarrage l'a déjà refusé sans lui")
                .clone(),
            std::sync::Arc::new(ams_tls::relay_config()),
            options.domain.clone(),
            false,
            Duration::from_secs(u64::from(options.timeouts.command_seconds)),
        );
        // **UNE LIGNE À LIRE** pour chaque chose qu'on lui ajoute : ce sont des
        // décisions de remise, pas des réglages.
        let remetteur = match mtasts.clone() {
            Some(sts) => remetteur.with_mtasts(sts),
            None => remetteur,
        };
        match rapports_tls.clone() {
            Some(journal) => remetteur.with_tls_reports(journal),
            None => remetteur,
        }
    });

    let intervalle_rapports =
        Duration::from_secs(u64::from(if options.dmarc.report_interval_seconds == 0 {
            86_400
        } else {
            options.dmarc.report_interval_seconds
        }));
    eprintln!(
        "air-mail-server : {}",
        match &journal_rapports {
            // LE CHAMP, ET NON LE PRÉDICAT, pour la raison déjà donnée plus
            // haut : `rapporte` exige maintenant que DMARC soit évalué, si bien
            // que ce bras ne se déclencherait JAMAIS. Ce qu'on veut dire ici est
            // précisément qu'un dossier est nommé et que l'évaluation manque.
            None if !options.dmarc.report_directory.is_empty() => String::from(
                "rapports DMARC non composés — un dossier est nommé, mais DMARC n'est pas évalué"
            ),
            None => String::from(
                "rapports DMARC non composés — aucun dossier nommé \
                 (`air-mail-admin --dmarc-report-dir …`)"
            ),
            Some(_)
                if options.dmarc.envoie(&options.spf)
                    && options.dmarc.rapporte_les_echecs(&options.spf) =>
                format!(
                    "rapports DMARC composés dans `{}` toutes les {} s, agrégés ET D'ÉCHEC, puis \
                 remis aux destinations qui ont consenti (§7.1). Un rapport d'échec porte des \
                 en-têtes filtrés, jamais de corps ni de destinataire.",
                    options.dmarc.report_directory,
                    intervalle_rapports.as_secs()
                ),
            Some(_) if options.dmarc.envoie(&options.spf) => format!(
                "rapports DMARC composés dans `{}` toutes les {} s, PUIS REMIS aux destinations \
                 qui ont consenti (§7.1). Chiffrement opportuniste : il n'authentifie personne.",
                options.dmarc.report_directory,
                intervalle_rapports.as_secs()
            ),
            Some(_) => format!(
                "rapports DMARC déposés dans `{}` toutes les {} s. DÉPOSÉS, PAS REMIS : \
                 `air-mail-admin --dmarc-send` les enverrait.",
                options.dmarc.report_directory,
                intervalle_rapports.as_secs()
            ),
        }
    );

    if !resolveurs.is_empty() {
        // DKIM (C9) vérifie dès qu'il y a un résolveur, sans réglage de plus :
        // il ne décide d'aucun message — c'est DMARC qui décidera — donc il n'y
        // a rien à activer ni à opposer.
        eprintln!(
            "air-mail-server : DKIM vérifié sur les mêmes résolveurs — les verdicts vont au \
             journal, et n'opposent rien (c'est DMARC qui décidera)"
        );
        // On ne valide pas DNSSEC : un `pass` ne vaut que ce que vaut le chemin
        // jusqu'au résolveur. Le taire laisserait croire à une garantie qui
        // n'existe pas.
        eprintln!(
            "air-mail-server : SPF et DKIM font CONFIANCE à ces résolveurs — DNSSEC n'est pas \
             validé. Un résolveur local, ou joint par un lien maîtrisé, est ce que cela suppose."
        );
    }

    // UNE BOÎTE PAR COMPTE, sous `<maildir>/<login>/`. Le nom du compte est le
    // nom du répertoire, et `ams_auth::check_login` l'a déjà validé — deux fois
    // plutôt qu'une, ici et à l'écriture du magasin, parce que c'est une
    // frontière de sécurité et qu'un fichier peut arriver autrement que par
    // notre outil.
    //
    // Toutes sont ouvertes AU DÉMARRAGE, ce qui coûte un parcours de répertoire
    // par compte. Le faire à la demande étalerait ce coût sur les connexions et
    // rendrait la première remise de chaque boîte plus lente que les autres ;
    // surtout, un magasin illisible se découvrirait alors sous charge plutôt
    // qu'au démarrage.
    let mut boites: BTreeMap<String, Arc<Maildir>> = BTreeMap::new();
    let mut messages = 0_u32;
    for compte in comptes.vue().iter() {
        let racine = maildir.join(&compte.login);
        let boite = Maildir::open(&racine, domaine, ams_store::fresh_uid_validity())
            .map_err(|erreur| format!("boîte de `{}` : {erreur}", compte.login))?;
        let resume = boite
            .summary()
            .map_err(|erreur| format!("boîte de `{}` : {erreur}", compte.login))?;
        messages = messages.saturating_add(resume.numbered);
        boites.insert(compte.login.clone(), Arc::new(boite));
    }
    // La carte n'est PAS close : voir [`Boites::get`]. Un compte ajouté pendant
    // que le serveur tourne fait ouvrir la sienne à la première remise.
    let boites = Arc::new(Boites::new(
        boites,
        maildir.clone(),
        domaine.to_vec(),
        Arc::clone(&comptes),
    ));

    // **TOUTES LES ÉCOUTES SE LIENT AVANT QUE LA PREMIÈRE NE SERVE.** Lier au
    // fur et à mesure ferait démarrer un serveur qui accepte du courrier sur le
    // `25` et découvre ensuite que le `465` est pris — un serveur à moitié en
    // service, dont personne ne saurait dire s'il faut le laisser tourner.
    let mut ecouteurs = std::vec::Vec::new();
    for (adresse, mode) in &ecoutes {
        // UN PORT À TLS IMPLICITE SANS CERTIFICAT NE SERT PERSONNE, et ne peut
        // pas se rabattre en clair : le client attend déjà une poignée de main.
        // On refuse de démarrer plutôt que d'ouvrir un port muet.
        if *mode == ams_loop_tokio::TlsMode::Implicit && chiffrement.is_none() {
            return Err(format!(
                "`{adresse}` est demandée en TLS implicite, et aucun certificat n'est \
                 configuré. Ce port ne pourrait rien servir : le client attend une poignée \
                 de main avant le premier octet, et il n'y a pas de repli en clair."
            ));
        }
        let ecouteur = TcpListener::bind(adresse)
            .await
            .map_err(|erreur| format!("écoute sur {adresse} : {erreur}"))?;
        ecouteurs.push((ecouteur, *adresse, *mode));
    }

    eprintln!(
        "air-mail-server {} : {} écoute sur {}, {} boîte(s) sous `{}` ({} message(s))",
        env!("CARGO_PKG_VERSION"),
        options.domain,
        ecoutes
            .iter()
            .map(|(adresse, mode)| match mode {
                ams_loop_tokio::TlsMode::Implicit => format!("{adresse} (TLS implicite)"),
                ams_loop_tokio::TlsMode::StartTls => format!("{adresse}"),
            })
            .collect::<std::vec::Vec<_>>()
            .join(", "),
        comptes.vue().len(),
        options.maildir,
        messages
    );
    eprintln!(
        "air-mail-server : {}",
        match &options.tls.certificate_chain_path {
            chaine if chiffrement.is_some() => format!("STARTTLS offert, certificat `{chaine}`"),
            _ => String::from("EN CLAIR — aucun certificat configuré, STARTTLS n'est pas annoncé"),
        }
    );
    eprintln!(
        "air-mail-server : domaines servis : {}",
        if options.hosted.is_empty() {
            String::from("(aucun)")
        } else {
            options.hosted.join(", ")
        }
    );

    let garde = Arc::new(SharedGuard::new(
        usize::try_from(options.tracked_sources).unwrap_or(usize::MAX),
        options.guard,
    ));
    let comptes = Arc::new(comptes);
    let postmaster = format!("postmaster@{}", options.domain);
    // **LES DEUX CONDITIONS SE REJOIGNENT ICI**, et sur une ligne qu'on lit : le
    // drapeau de configuration d'un côté, l'authentification de la session de
    // l'autre. Sans `qui_relaie`, la politique refuse tout ce qui n'est pas d'ici,
    // quoi qu'un pair ait prouvé.
    // **LE NOM ANNONCÉ COMPTE PARMI LES DOMAINES DONT ON RÉPOND**, en plus de
    // ceux que `--hosted` déclare. Il n'y est pas d'office : `--hosted` nomme les
    // domaines dont on reçoit le courrier, `--domain` le nom sous lequel on se
    // présente. Mais §4.5.1 de RFC 5321 rend ce serveur responsable de
    // `postmaster@<son nom>` — et répondre « Relay access denied » à qui écrit à
    // NOTRE PROPRE postmaster serait absurde : il n'y a pas de relais à nier, on
    // est déjà arrivé.
    //
    // La conséquence vaut pour toute adresse de ce domaine-là, et elle est
    // juste : un inconnu chez nous est un inconnu (`5.1.1`), pas un relais nié.
    let mut responsables = options.hosted.clone();
    responsables.push(options.domain.clone());
    let politique = BoitesConnues::new(Arc::clone(&comptes), postmaster.clone(), &responsables);
    // **`DSN` NE S'ANNONCE QUE SI L'ON PEUT ÉMETTRE** (RFC 3461 §4.2). Un
    // serveur qui l'annonce DOIT rendre compte d'un succès quand on lui en
    // demande un, et rendre compte suppose la file. Sans elle, `NOTIFY=SUCCESS`
    // reçoit un `504` : le pair sait à quoi s'en tenir, au lieu d'attendre un
    // rapport qui ne viendrait jamais.
    let capacites = Capabilities {
        dsn: file.is_some(),
        ..config.capabilities()
    };
    let config = config.with_capabilities(capacites);
    let politique = Arc::new(if file.is_some() {
        politique.qui_relaie()
    } else {
        politique
    });
    eprintln!(
        "air-mail-server : {}",
        match (politique.a_des_comptes(), authentifie) {
            (_, true) => format!("AUTH PLAIN offert, magasin `{}`", options.accounts),
            // Le cas qui mentait avant : des comptes, mais pas de chiffrement.
            // Ils servent alors au ROUTAGE seulement, et `AUTH` n'est pas
            // annoncé — la session le refuse hors TLS, sans réglage possible.
            (true, false) => format!(
                "comptes chargés pour le routage, magasin `{}` — AUTH non annoncé, faute de \
                 chiffrement",
                options.accounts
            ),
            (false, false) => String::from(
                "aucun compte : ce serveur n'accepte de courrier pour PERSONNE, et n'annonce \
                 pas AUTH",
            ),
        }
    );
    // LE POSTMASTER EST UN COMPTE COMME UN AUTRE, et la RFC 5321 §4.5.1 exige
    // qu'il soit joignable. On ne le fabrique pas d'office — inventer une boîte
    // que personne n'a demandée serait pire — mais on le DIT, parce qu'un
    // serveur qui refuse `postmaster` est un serveur dont personne ne peut
    // signaler qu'il va mal.
    if ams_auth::route(&comptes.vue(), postmaster.as_bytes()).is_none() {
        eprintln!(
            "air-mail-server : ATTENTION — aucun compte ne reçoit `{postmaster}`. \
             La RFC 5321 §4.5.1 l'exige : `air-mail-admin account add … --address {postmaster}`."
        );
    }

    // CE QUI RATE À LA REMISE SE COMPTE ICI, et pour tout le processus : la
    // remise naît par connexion, donc un compteur qui vivrait dedans redirait sa
    // première ligne à chaque connexion et ne compterait jamais rien.
    let incidents = Arc::new(crate::incidents::Incidents::new());
    let pour_la_remise = Arc::clone(&boites);
    let comptes_pour_la_remise = Arc::clone(&comptes);
    let incidents_pour_la_remise = Arc::clone(&incidents);
    let incidents_pour_les_rapports = Arc::clone(&incidents);
    let incidents_pour_l_api = Arc::clone(&incidents);
    let file_pour_la_remise = file.as_ref().map(|attente| attente.as_ref().clone());
    let message_max = usize::try_from(options.max_message_octets).unwrap_or(usize::MAX);

    let options_de_service = ServeOptions {
        max_connections: usize::try_from(options.max_connections).unwrap_or(usize::MAX),
        timeouts: Timeouts {
            command: Duration::from_secs(u64::from(options.timeouts.command_seconds)),
            data: Duration::from_secs(u64::from(options.timeouts.data_seconds)),
            // Pas de champ dans le schéma : le délai de poignée de main reste
            // celui de la boucle, faute d'une raison de le régler.
            handshake: Timeouts::default().handshake,
        },
        // `None` quand la configuration ne nomme pas de certificat : la session
        // n'annonce alors pas `STARTTLS`, et le serveur sert en clair sans
        // mentir à personne.
        tls: chiffrement.clone(),
        // **POSÉ PAR ÉCOUTE**, juste avant de servir : ces options-ci sont le
        // patron commun, et chaque port y met son mode.
        tls_mode: ams_loop_tokio::TlsMode::StartTls,
        // DKIM VÉRIFIE DÈS QU'IL Y A UN RÉSOLVEUR, sans réglage de plus : il ne
        // décide d'aucun message — c'est DMARC qui décidera — donc il n'y a rien
        // à activer ni à opposer. Ce sont les mêmes serveurs que SPF, la même
        // confiance, et le démarrage l'a déjà dit.
        dkim: verificateur
            .as_ref()
            .map(|checker| DkimChecker::new(checker.resolver().clone())),
        // Le seul des trois qui peut REFUSER un message — et seulement quand le
        // domaine du `From:` le demande.
        dmarc: verificateur_dmarc,
        // Ce qui permettra aux domaines protégés de durcir leur politique sans
        // le faire à l'aveugle.
        reports: journal_rapports,
        report_interval: intervalle_rapports,
        // `None` quand aucun résolveur n'est nommé — et la session ne demande
        // alors aucune vérification. Les deux vont ensemble, et la boucle refuse
        // l'assemblage inverse avant même la bannière.
        spf: verificateur,
    };

    // ── LE SERVICE POP3, S'IL EST DEMANDÉ ───────────────────────────────────
    //
    // Les deux boucles tournent EN MÊME TEMPS, et le même signal les arrête. Un
    // seul `arret()` ne peut pas être attendu deux fois : on en fabrique un
    // second, et les deux écoutent le même `SIGTERM`.
    let pop3 = if options.listen_pop3.is_empty() {
        eprintln!("air-mail-server : POP3 non servi — aucune adresse d'écoute configurée");
        None
    } else {
        let adresse: std::net::SocketAddr = options.listen_pop3.parse().map_err(|_| {
            format!(
                "`{}` n'est pas une adresse d'écoute POP3",
                options.listen_pop3
            )
        })?;
        // SANS CERTIFICAT, CE PORT NE SERT PERSONNE : la session POP3 refuse
        // `USER`/`PASS` hors chiffrement, sans réglage possible (C6). On le dit
        // plutôt que de laisser le découvrir un client à la fois.
        if options_de_service.tls.is_none() {
            eprintln!(
                "air-mail-server : ATTENTION — POP3 écoute sur {adresse} SANS certificat. \
                 `USER`/`PASS` y seront refusés (C6), donc personne ne pourra relever son \
                 courrier."
            );
        }
        let ecouteur = TcpListener::bind(adresse)
            .await
            .map_err(|erreur| format!("écoute POP3 sur {adresse} : {erreur}"))?;
        eprintln!("air-mail-server : POP3 écoute sur {adresse}");
        Some(tokio::spawn(serve_pop3(
            ecouteur,
            ams_proto_pop3::Limits::DEFAULT,
            Arc::clone(&politique),
            Arc::new(BoitesPop3::new(Arc::clone(&boites))),
            Arc::clone(&garde),
            options_de_service.clone(),
            arret(),
        )))
    };

    // ── LE SERVICE IMAP, S'IL EST DEMANDÉ ───────────────────────────────────
    // **UN SEUL SERVICE DE BOÎTES POUR IMAP ET POUR L'API** : deux voies de
    // lecture finiraient par ne plus montrer la même chose, et personne ne
    // saurait laquelle croire.
    let boites_imap = Arc::new(BoitesImap::new(Arc::clone(&boites), domaine));

    let imap = if options.listen_imap.is_empty() {
        eprintln!("air-mail-server : IMAP non servi — aucune adresse d'écoute configurée");
        None
    } else {
        let adresse: std::net::SocketAddr = options.listen_imap.parse().map_err(|_| {
            format!(
                "`{}` n'est pas une adresse d'écoute IMAP",
                options.listen_imap
            )
        })?;
        // SANS CERTIFICAT, CE PORT NE SERT PERSONNE : la session IMAP refuse
        // `LOGIN` et `AUTHENTICATE` hors chiffrement, sans réglage possible (C6).
        if options_de_service.tls.is_none() {
            eprintln!(
                "air-mail-server : ATTENTION — IMAP écoute sur {adresse} SANS certificat. \
                 `LOGIN` et `AUTHENTICATE` y seront refusés (C6), donc personne ne pourra s'y \
                 connecter."
            );
        }
        let ecouteur = TcpListener::bind(adresse)
            .await
            .map_err(|erreur| format!("écoute IMAP sur {adresse} : {erreur}"))?;
        // ON DIT CE QU'ON SERT, ET COMMENT. Un port IMAP ouvert laisse croire à
        // beaucoup de choses ; celles-ci sont vraies, et bornées.
        //
        // **UNE AFFIRMATION PAR LIGNE.** Tout ceci tenait sur UNE ligne de mille
        // neuf cent soixante-dix-huit caractères — la suivante, dans le même
        // démarrage, en faisait deux cent quatorze. Un terminal la repliait en
        // pavé, `journalctl` la tronquait selon la vue, et ce que ce registre
        // reproche ailleurs à un journal répétitif — qu'on cesse de le lire —
        // lui arrivait par excès. Sept lignes qu'on peut lire valent mieux
        // qu'une qu'on saute.
        for dit in [
            std::format!("IMAP écoute sur {adresse} — IMAP4rev2 est servi EN ENTIER"),
            String::from(
                "  commandes  `SELECT`, `LIST`, `STATUS`, `FETCH`, `STORE`, `EXPUNGE`, \
                 `SEARCH`, `COPY`, `MOVE`, `APPEND`, `CREATE`, `DELETE`, `RENAME`, \
                 `NAMESPACE`, `ENABLE`, `IDLE`, `SUBSCRIBE` et `UNSUBSCRIBE`",
            ),
            String::from(
                "  `FETCH`    rend une `ENVELOPE`, une `BODYSTRUCTURE`, une PARTIE désignée \
                 — `BODY[1]`, `BODY[1.MIME]` — et un CHOIX de champs — \
                 `BODY[HEADER.FIELDS (FROM)]`. `BINARY[…]` rend ce que les octets VEULENT \
                 DIRE, transfert-décodé, et refuse par `NO [UNKNOWN-CTE]` ce qu'il ne sait \
                 pas défaire",
            ),
            String::from(
                "  `SEARCH`   cherche DANS LE TEXTE et non dans les octets : les mots encodés \
                 se défont, les corps se transfert-décodent — au plus un mébioctet par \
                 partie, en `us-ascii`, `utf-8` ou `iso-8859-1`. `SENTBEFORE`, `SENTON` et \
                 `SENTSINCE` lisent le champ `Date:` ; `BEFORE`, `ON` et `SINCE` la date \
                 d'arrivée",
            ),
            String::from(
                "  §E         les options absorbées dans le protocole de base le sont aussi : \
                 `STATUS` rend ce qu'on lui demande — `UNSEEN`, `DELETED`, `SIZE` —, \
                 `LIST … RETURN (STATUS (…))` en rend un par boîte, \
                 `SEARCH RETURN (MIN MAX ALL COUNT SAVE)` répond de quatre façons, et `$` \
                 désigne la dernière recherche — en UID, pour qu'un message effacé en sorte \
                 de lui-même",
            ),
            String::from(
                "  mots-clefs les cinq de §E.15 — `$MDNSent`, `$Forwarded`, `$Junk`, \
                 `$NonJunk`, `$Phishing` —, avec `KEYWORD` et `UNKEYWORD` ; Maildir les porte \
                 dans le nom du fichier. L'ENSEMBLE EST FERMÉ, et `PERMANENTFLAGS` n'annonce \
                 donc pas `\\*` : ce serait promettre qu'on accepte tout mot-clef nouveau",
            ),
            String::from(
                "  sur disque un nom de boîte devient un RÉPERTOIRE : seuls les noms qu'on \
                 sait transcrire sans risque sont acceptés, et jamais transformés. Un \
                 `EXPUNGE` efface POUR DE BON, un `CLOSE` aussi, et les abonnements \
                 s'écrivent dans la racine du compte sous `ams-abonnements`",
            ),
        ] {
            eprintln!("air-mail-server : {dit}");
        }
        let mut options_imap = options_de_service.clone();
        options_imap.tls_mode = match options.imap_implicit_tls {
            true => ams_loop_tokio::TlsMode::Implicit,
            false => ams_loop_tokio::TlsMode::StartTls,
        };
        // **LE MODE DE CETTE ÉCOUTE-CI**, et non celui du SMTP : le `993` est en
        // TLS implicite là où le `25` est en `STARTTLS`, et rien n'oblige les
        // deux à s'accorder.
        let mut options_imap = options_de_service.clone();
        options_imap.tls_mode = match options.imap_implicit_tls {
            true => ams_loop_tokio::TlsMode::Implicit,
            false => ams_loop_tokio::TlsMode::StartTls,
        };
        Some(tokio::spawn(serve_imap(
            ecouteur,
            // LA BORNE D'UN `APPEND` EST CELLE D'UN MESSAGE, et c'est la même
            // que celle de SMTP : un message qu'on refuserait de recevoir par un
            // chemin n'a pas de raison de passer par l'autre.
            ams_proto_imap::Limits {
                max_append_octets: options.max_message_octets,
                ..ams_proto_imap::Limits::DEFAULT
            },
            Arc::clone(&politique),
            Arc::clone(&boites_imap),
            Arc::clone(&garde),
            options_imap,
            arret(),
        )))
    };

    // **LE PORT UDP SE LIE AVANT QUE LA SESSION NE SE MONTE**, et l'ordre n'est
    // pas décoratif : ce que l'on annonce dans `Alt-Svc` est le port que le
    // noyau a RÉELLEMENT donné. `listenH3` peut dire `:0`, et annoncer ce qui est
    // écrit dans le fichier enverrait les clients là où personne n'écoute.
    let h3_lie = monter_l_api_h3(&options)?;
    let port_h3 = h3_lie
        .as_ref()
        .and_then(|(socket, _)| socket.local_addr().ok())
        .map(|adresse| adresse.port());

    // **LES DOMAINES POUR LESQUELS ON PEUT SIGNER** sont ceux dont on tient la
    // zone : c'est là, et là seulement, que la clé publique se publie sous
    // `<sélecteur>._domainkey.<domaine>`. Signer ailleurs produirait une
    // signature qui échoue partout, et un échec DKIM se voit dans les rapports
    // DMARC du domaine usurpé.
    let domaines_signables = Arc::new(options.hosted.clone());
    let signature_de_la_remise = signature
        .clone()
        .map(|cle| ams_loop_tokio::DkimSigner::new(options.dkim.selector.clone(), cle));
    // L'API reçoit déjà les domaines hébergés à son montage : c'est la même
    // liste, et la lui passer deux fois en donnerait deux à tenir d'accord.
    let signature_pour_l_api = signature_de_la_remise.clone();

    let montage = monter_l_api(
        &options,
        options_de_service.tls.as_ref(),
        signature_pour_l_api,
        Arc::clone(&boites_imap),
        Arc::clone(&comptes),
        Arc::clone(&boites),
        Arc::new(options.hosted.clone()),
        Arc::clone(&garde),
        incidents_pour_l_api,
        file.as_ref().map(|attente| attente.as_ref().clone()),
        message_max,
        port_h3,
    )?;
    // **LA MÊME SESSION ET LA MÊME API POUR LES DEUX VERSIONS** : un jeton scellé
    // par HTTP/2 doit ouvrir HTTP/3, et une ressource servie d'un côté doit être
    // la même de l'autre. Deux montages en donneraient deux, avec deux clés.
    let h3 = match (montage.as_ref(), h3_lie) {
        (Some((_, session, _, api)), Some((socket, tls))) => {
            let session = session.clone();
            let api = Arc::clone(api);
            let garde_h3 = Arc::clone(&garde);
            // **LA MÊME BORNE QUE LES QUATRE AUTRES ÉCOUTES.** Elle était gravée
            // à 1 024 dans l'écoute QUIC, si bien qu'un serveur réglé à seize
            // connexions en tenait mille vingt-quatre sur cette porte-là.
            let connexions_max = usize::try_from(options.max_connections).unwrap_or(usize::MAX);
            // **ZÉRO PREND LE DÉFAUT**, et la substitution vit dans `ams-config` :
            // la recopier ici ferait deux vérités pour une seule décision.
            let inactivite_us =
                u64::from(options.timeouts.quic_idle_secondes()).saturating_mul(1_000_000);
            let attente = arret();
            Some(tokio::spawn(async move {
                let socket = match tokio::net::UdpSocket::from_std(socket) {
                    Ok(socket) => socket,
                    Err(erreur) => {
                        eprintln!("air-mail-server : HTTP/3 : {erreur}");
                        return;
                    }
                };
                let mut application =
                    ams_loop_tokio::h3::Http3Application::new(&session, api.as_ref(), &garde_h3);
                match ams_loop_tokio::serve_quic(
                    socket,
                    tls,
                    &garde_h3,
                    connexions_max,
                    inactivite_us,
                    &mut application,
                    attente,
                )
                .await
                {
                    Ok(stats) => {
                        let (servies, refusees) = application.comptes();
                        // **CE QUE LE GARDE A REFUSÉ SE DIT À PART**, et seulement
                        // s'il y en a : un compte toujours nul est une ligne
                        // qu'on cesse de lire, et c'est alors celle qui compte
                        // qu'on manque.
                        let banni = if stats.banned == 0 {
                            String::new()
                        } else {
                            format!(", {} refusée(s) au videur", stats.banned)
                        };
                        eprintln!(
                            "air-mail-server : HTTP/3 ; {} connexion(s) acceptée(s), \
                             {servies} requête(s) servie(s), {refusees} refusée(s){banni}",
                            stats.accepted
                        );
                    }
                    Err(erreur) => eprintln!("air-mail-server : HTTP/3 : {erreur}"),
                }
            }))
        }
        // **HTTP/3 SANS HTTP/2 NE SE SERT PAS** : la session et l'API se montent
        // avec le port TCP, et les monter deux fois donnerait deux clés de
        // scellement — donc des jetons qui ne s'ouvriraient pas d'un côté à
        // l'autre.
        (None, Some(_)) => {
            eprintln!(
                "air-mail-server : API REST EN HTTP/3 NON SERVIE — `listenHttp` n'est pas \
                 configurée, et la session comme l'API se montent avec elle."
            );
            None
        }
        _ => None,
    };

    let http = montage.map(|(ecouteur, session, tls, api)| {
        tokio::spawn(ams_loop_tokio::http::serve_http(
            ecouteur,
            ams_proto_http::Limits::DEFAULT,
            api,
            Arc::clone(&garde),
            session,
            tls,
            options_de_service.clone(),
            arret(),
        ))
    });

    // ── LA TÂCHE DES RAPPORTS TLS ───────────────────────────────────────────
    //
    // §4 : une période de vingt-quatre heures. On réutilise l'intervalle des
    // rapports DMARC, qui vaut un jour par défaut et se règle par la même
    // option : deux réglages pour deux rapports quotidiens seraient deux fois la
    // même décision.
    let tache_tls = rapports_tls.as_ref().map(|journal| {
        let journal = std::sync::Arc::clone(journal);
        let envoie = options.tlsrpt.envoie();
        let intervalle = intervalle_rapports;
        let attente = arret();
        tokio::spawn(async move {
            let mut horloge = tokio::time::interval(intervalle);
            horloge.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // **LE PREMIER TOUR NE DÉPOSE RIEN**, et c'est voulu : `interval`
            // se déclenche tout de suite, et la période n'a pas encore
            // commencé. Il ne fait donc que remettre ce qu'une exécution
            // précédente aurait laissé.
            let mut premier = true;
            let mut depots = ams_loop_tokio::TlsSpoolTally::default();
            let mut remises = ams_loop_tokio::TlsSendTally::default();
            tokio::pin!(attente);
            loop {
                tokio::select! {
                    () = &mut attente => break,
                    _ = horloge.tick() => {
                        if !premier {
                            let compte = journal.vider().await;
                            depots.reports = depots.reports.saturating_add(compte.reports);
                            depots.unasked = depots.unasked.saturating_add(compte.unasked);
                            depots.errors = depots.errors.saturating_add(compte.errors);
                        }
                        premier = false;
                        if envoie {
                            let compte = journal.envoyer().await;
                            remises.sent = remises.sent.saturating_add(compte.sent);
                            remises.deferred = remises.deferred.saturating_add(compte.deferred);
                            remises.dropped = remises.dropped.saturating_add(compte.dropped);
                        }
                    }
                }
            }
            // **CE QUI RESTE AU JOURNAL SE DÉPOSE À L'ARRÊT.** Le perdre
            // reviendrait à ne rien rapporter d'une journée entière parce que le
            // serveur a redémarré à vingt-trois heures.
            let compte = journal.vider().await;
            depots.reports = depots.reports.saturating_add(compte.reports);
            depots.unasked = depots.unasked.saturating_add(compte.unasked);
            depots.errors = depots.errors.saturating_add(compte.errors);
            (depots, remises)
        })
    });

    // ── LA TÂCHE DE REPRISE ─────────────────────────────────────────────────
    //
    // Elle tourne à côté des boucles de service, et le même signal l'arrête. Son
    // premier tour a lieu TOUT DE SUITE : une file laissée par une exécution
    // précédente ne doit pas attendre un intervalle pour repartir.
    //
    // Le rythme est celui du plus court des deux — une minute, ou la première
    // attente. Chaque entrée porte son propre instant de reprise dans son nom :
    // un tour qui passe trop souvent ne fait que lire un répertoire.
    let reprise = file
        .as_ref()
        .zip(remetteur_de_file.as_ref())
        .map(|(spool, relay)| {
            let spool = std::sync::Arc::clone(spool);
            let relay = relay.clone();
            let rendre = RapportsLocaux {
                boites: Arc::clone(&boites),
                comptes: Arc::clone(&comptes),
                incidents: Arc::clone(&incidents_pour_les_rapports),
            };
            let battement = spool_battement(&options.queue);
            let attente = arret();
            tokio::spawn(async move {
                let mut horloge = tokio::time::interval(battement);
                horloge.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                let mut total = ams_loop_tokio::QueueTally::default();
                tokio::pin!(attente);
                loop {
                    tokio::select! {
                        () = &mut attente => break,
                        _ = horloge.tick() => {
                            let compte = spool.parcourir(&relay, &rendre, maintenant()).await;
                            total.sent = total.sent.saturating_add(compte.sent);
                            total.authenticated =
                                total.authenticated.saturating_add(compte.authenticated);
                            total.bounced = total.bounced.saturating_add(compte.bounced);
                            total.deferred = total.deferred.saturating_add(compte.deferred);
                            total.unreadable = total.unreadable.saturating_add(compte.unreadable);
                            total.reports_lost =
                                total.reports_lost.saturating_add(compte.reports_lost);
                        }
                    }
                }
                total
            })
        });

    // **UNE TÂCHE PAR ÉCOUTE**, chacune avec son mode TLS. Elles écoutent le même
    // signal d'arrêt et se referment ensemble ; leurs comptes se rassemblent, un
    // serveur ne rendant qu'un bilan.
    let mut taches = std::vec::Vec::new();
    for (ecouteur, adresse, mode) in ecouteurs {
        let politique = Arc::clone(&politique);
        let garde = Arc::clone(&garde);
        let mut options_de_cette_ecoute = options_de_service.clone();
        options_de_cette_ecoute.tls_mode = mode;
        // Les fabriques de remise partagent tout par `Arc` : une écoute de plus
        // ne recopie ni les boîtes, ni les comptes, ni la clé de signature.
        let pour_la_remise = Arc::clone(&pour_la_remise);
        let comptes_pour_la_remise = Arc::clone(&comptes_pour_la_remise);
        let incidents_pour_la_remise = Arc::clone(&incidents_pour_la_remise);
        let domaines_signables = Arc::clone(&domaines_signables);
        let quarantaine = quarantaine.clone();
        let signature_de_la_remise = signature_de_la_remise.clone();
        let file_pour_la_remise = file_pour_la_remise.clone();
        let attente = arret();
        taches.push(tokio::spawn(async move {
            let issue = serve(
                ecouteur,
                config,
                politique,
                garde,
                move || {
                    let remise = MaildirDelivery::new(
                        Arc::clone(&pour_la_remise),
                        Arc::clone(&comptes_pour_la_remise),
                        Arc::clone(&incidents_pour_la_remise),
                    );
                    let remise = match quarantaine.clone() {
                        Some(dossier) => remise.avec_quarantaine(dossier),
                        None => remise,
                    };
                    // **CE QUE NOS COMPTES ÉMETTENT EST SIGNÉ** (RFC 6376). Sans
                    // cela, le courrier de l'exploitant échoue en DMARC dès que
                    // SPF ne suffit plus — un transfert, une liste de diffusion —
                    // alors même que le serveur annonce au démarrage qu'il signe
                    // ce qu'il émet.
                    let remise = remise.avec_domaines(Arc::clone(&domaines_signables));
                    let remise = match signature_de_la_remise.clone() {
                        Some(signataire) => remise.avec_dkim(signataire),
                        None => remise,
                    };
                    match file_pour_la_remise.clone() {
                        Some(file) => remise.avec_file(file, message_max),
                        None => remise,
                    }
                },
                options_de_cette_ecoute,
                attente,
            )
            .await;
            (adresse, issue)
        }));
    }

    let mut stats = ams_loop_tokio::Stats::default();
    for tache in taches {
        match tache.await {
            Ok((adresse, Ok(compte))) => {
                let _ = adresse;
                stats = stats.plus(compte);
            }
            // **UNE ÉCOUTE QUI TOMBE SE NOMME.** « écoute : erreur » sans dire
            // laquelle enverrait chercher dans trois ports.
            Ok((adresse, Err(erreur))) => return Err(format!("écoute {adresse} : {erreur}")),
            Err(erreur) => return Err(format!("écoute : {erreur}")),
        }
    }

    if let Some(tache) = tache_tls {
        match tache.await {
            Ok((depots, remises)) => eprintln!(
                "air-mail-server : rapports TLS ; {} déposé(s), {} domaine(s) qui n'en \
                 demandaient pas, {} en erreur ; {} remis, {} ajourné(s), {} abandonné(s)",
                depots.reports,
                depots.unasked,
                depots.errors,
                remises.sent,
                remises.deferred,
                remises.dropped
            ),
            Err(erreur) => eprintln!("air-mail-server : rapports TLS : {erreur}"),
        }
    }

    if let Some(tache) = reprise {
        match tache.await {
            Ok(compte) => {
                eprintln!(
                    "air-mail-server : émission ; {} message(s) remis dont {} AUTHENTIFIÉ(S) \
                     PAR DANE, {} rendu(s) à leur expéditeur, {} ajourné(s), {} illisible(s)",
                    compte.sent,
                    compte.authenticated,
                    compte.bounced,
                    compte.deferred,
                    compte.unreadable
                );
                // **UNE PERTE SÈCHE NE SE MÊLE PAS AU RESTE.** Les autres
                // comptes disent ce qu'on a fait ; celui-ci dit ce qu'on n'a pas
                // su faire savoir, et quelqu'un croit avoir écrit. Le noyer dans
                // la même ligne le ferait lire comme une statistique de plus.
                //
                // ZÉRO NE S'ÉCRIT PAS : un journal qui répète « aucune perte »
                // est un journal qu'on cesse de lire.
                if compte.reports_lost > 0 {
                    eprintln!(
                        "air-mail-server : ATTENTION — {} rapport(s) n'ont PAS pu être remis à \
                         leur destinataire. Autant d'expéditeurs qui croient avoir écrit, et \
                         que personne ne détrompera : le message est déjà effacé.",
                        compte.reports_lost
                    );
                }
            }
            Err(erreur) => eprintln!("air-mail-server : émission : {erreur}"),
        }
    }

    if let Some(tache) = pop3 {
        // La boucle POP3 s'arrête sur le même signal ; on attend qu'elle ait
        // fini d'accepter avant de rendre la main, sans quoi le message d'arrêt
        // partirait pendant qu'elle sert encore.
        match tache.await {
            Ok(Ok(stats_pop3)) => {
                eprintln!(
                    "air-mail-server : POP3 ; {} connexion(s) acceptée(s), {} refusée(s) par le \
                     noyau",
                    stats_pop3.accepted, stats_pop3.failed
                );
                dire_les_injections("POP3", "STLS", stats_pop3.injections);
            }
            Ok(Err(erreur)) => eprintln!("air-mail-server : POP3 : {erreur}"),
            Err(erreur) => eprintln!("air-mail-server : POP3 : {erreur}"),
        }
    }
    if let Some(tache) = imap {
        match tache.await {
            Ok(Ok(stats_imap)) => {
                eprintln!(
                    "air-mail-server : IMAP ; {} connexion(s) acceptée(s), {} refusée(s) par le \
                     noyau",
                    stats_imap.accepted, stats_imap.failed
                );
                dire_les_injections("IMAP", "STARTTLS", stats_imap.injections);
            }
            Ok(Err(erreur)) => eprintln!("air-mail-server : IMAP : {erreur}"),
            Err(erreur) => eprintln!("air-mail-server : IMAP : {erreur}"),
        }
    }
    if let Some(tache) = http {
        match tache.await {
            Ok(Ok(stats_http)) => eprintln!(
                "air-mail-server : HTTP ; {} connexion(s) acceptée(s), {} refusée(s) par le noyau",
                stats_http.accepted, stats_http.failed
            ),
            Ok(Err(erreur)) => eprintln!("air-mail-server : HTTP : {erreur}"),
            Err(erreur) => eprintln!("air-mail-server : HTTP : {erreur}"),
        }
    }
    if let Some(tache) = h3 {
        // **LA MÊME ATTENTE QUE LES AUTRES** : l'écoute HTTP/3 s'arrête sur le
        // même signal, et lui laisser le temps de finir évite que le message
        // d'arrêt parte pendant qu'elle sert encore.
        if let Err(erreur) = tache.await {
            eprintln!("air-mail-server : HTTP/3 : {erreur}");
        }
    }

    eprintln!(
        "air-mail-server : arrêt ; {} connexion(s) acceptée(s), {} refusée(s) par le noyau",
        stats.accepted, stats.failed
    );
    // **LES TENTATIVES D'INJECTION SE DISENT TOUJOURS**, et non seulement quand
    // SPF ou DKIM sont réglés : elles ne dépendent d'aucune option, et un
    // exploitant qui en voit passer veut le savoir. Zéro ne s'écrit pas — un
    // journal qui répète « rien » chaque jour est un journal qu'on cesse de
    // lire.
    if stats.injections > 0 {
        eprintln!(
            "air-mail-server : SMTP ; {} pair(s) ont glissé une commande derrière leur \
             `STARTTLS` — connexion REFUSÉE (RFC 3207 §4.2)",
            stats.injections
        );
    }

    // **CE QUI A RATÉ À LA REMISE**, cause par cause. Chacune a déjà été dite au
    // moment où elle est survenue ; ce bilan-ci donne le TOTAL, que personne ne
    // pourrait reconstituer en relisant des lignes espacées de cinq minutes.
    //
    // ZÉRO NE S'ÉCRIT PAS, comme pour les autres compteurs : un journal qui
    // répète « rien n'a raté » est un journal qu'on cesse de lire.
    for (cause, combien) in incidents.bilan() {
        eprintln!("air-mail-server : ATTENTION — {combien} {}", cause.bilan());
    }

    // ON DIT CE QU'ON A CONCLU. Un verdict qu'on ne rend nulle part ne sert à
    // rien : en attendant `air-log`, ce compte-là est ce que le serveur peut
    // dire des signatures qu'il a vérifiées.
    if politique_expediteur != SenderPolicy::Ignore {
        let dkim = stats.dkim;
        eprintln!(
            "air-mail-server : DKIM ; {} signature(s) vraie(s), {} fausse(s), {} clé(s) \
             injoignable(s), {} irrecevable(s)",
            dkim.pass, dkim.fail, dkim.temp_error, dkim.perm_error
        );
        let dmarc = stats.dmarc;
        eprintln!(
            "air-mail-server : DMARC ; {} aligné(s), {} non aligné(s) dont {} REFUSÉ(S), \
             {} sans politique, {} injoignable(s), {} illisible(s)",
            dmarc.pass,
            dmarc.fail,
            dmarc.applied,
            dmarc.no_policy,
            dmarc.temp_error,
            dmarc.unusable
        );
        let remises = stats.sends;
        if remises.sent > 0
            || remises.rejected > 0
            || remises.deferred > 0
            || remises.expired > 0
            || remises.unsendable > 0
        {
            eprintln!(
                "air-mail-server : remise des rapports ; {} remis, {} refusé(s) définitivement, \
                 {} différé(s), {} périmé(s), {} incomposable(s)",
                remises.sent,
                remises.rejected,
                remises.deferred,
                remises.expired,
                remises.unsendable
            );
        }
        let rapports = stats.reports;
        if rapports.reports > 0 || rapports.errors > 0 || rapports.refused > 0 {
            eprintln!(
                "air-mail-server : rapports DMARC ; {} déposé(s) pour {} ligne(s), {} \
                 destination(s) retenue(s), {} ÉCARTÉE(S) faute de consentement (§7.1), {} \
                 en échec",
                rapports.reports,
                rapports.rows,
                rapports.destinations,
                rapports.refused,
                rapports.errors
            );
        }
    }
    Ok(())
}

/// Attend `SIGINT` ou `SIGTERM`.
///
/// Les deux, et pas seulement `Ctrl-C` : un service arrêté par un gestionnaire
/// reçoit `SIGTERM`, et l'ignorer le ferait tuer au bout du délai de grâce —
/// c'est-à-dire au milieu d'une remise.
/// Remet un rapport de non-remise DANS UNE BOÎTE D'ICI.
///
/// # AUCUN REBOND NE PART VERS UN INCONNU
///
/// Ce serveur ne relaie que pour ses propres comptes, si bien que le chemin de
/// retour d'une entrée de file est toujours l'une de ses adresses. Le rapport se
/// dépose donc localement, et jamais sur le réseau : c'est ce qui tient ce
/// serveur hors de la rétro-diffusion — émettre un rebond vers une adresse qu'un
/// tiers a écrite dans un `MAIL FROM:` usurpé ferait de nous l'instrument de son
/// envoi.
struct RapportsLocaux {
    boites: Arc<Boites>,
    comptes: Arc<crate::comptes::Comptes>,
    incidents: Arc<crate::incidents::Incidents>,
}

impl ams_loop_tokio::Bounced for RapportsLocaux {
    fn deliver(&self, recipient: &str, message: &[u8]) -> bool {
        use ams_loop_tokio::Delivery as _;

        // **LA MÊME REMISE QUE PARTOUT AILLEURS**, et sans file : un rapport ne
        // se met pas en file. Sans cela, un rapport qu'on n'arriverait pas à
        // déposer engendrerait un rapport, qui en engendrerait un autre.
        let mut remise = MaildirDelivery::new(
            Arc::clone(&self.boites),
            Arc::clone(&self.comptes),
            Arc::clone(&self.incidents),
        );
        remise.begin(None);
        if remise.add_recipient(recipient.as_bytes()).is_err() {
            return false;
        }
        if remise.append(message).is_err() || remise.finish().is_err() {
            remise.abort();
            return false;
        }
        true
    }
}

/// Dit combien de pairs ont tenté d'injecter derrière la montée en chiffrement.
///
/// **ZÉRO NE S'ÉCRIT PAS.** Un journal qui répète « rien » à chaque arrêt est un
/// journal qu'on cesse de lire, et c'est alors la ligne qui compte qu'on manque.
fn dire_les_injections(protocole: &str, commande: &str, combien: u64) {
    if combien == 0 {
        return;
    }
    eprintln!(
        "air-mail-server : {protocole} ; {combien} pair(s) ont glissé une commande derrière leur \
         `{commande}` — connexion REFUSÉE"
    );
}

/// L'heure, en secondes depuis l'époque.
fn maintenant() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |depuis| depuis.as_secs())
}

/// À quel rythme repasser sur la file.
///
/// **LE PLUS COURT DES DEUX — une minute, ou la première attente.** Passer plus
/// souvent ne ferait que relire un répertoire, puisque chaque entrée porte son
/// propre instant de reprise ; passer moins souvent retarderait la plus pressée.
fn spool_battement(attente: &ams_config::Queue) -> Duration {
    let minute = Duration::from_secs(60);
    attente
        .backoff()
        .first
        .min(minute)
        .max(Duration::from_secs(1))
}

async fn arret() {
    let interruption = tokio::signal::ctrl_c();
    let mut terminaison =
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(erreur) => {
                eprintln!("air-mail-server : `SIGTERM` non écouté : {erreur}");
                let _ = interruption.await;
                return;
            }
        };
    tokio::select! {
        resultat = interruption => {
            if let Err(erreur) = resultat {
                eprintln!("air-mail-server : `SIGINT` non écouté : {erreur}");
            }
        }
        _ = terminaison.recv() => {}
    }
}

#[cfg(test)]
mod tests {
    use super::{
        charger_comptes, charger_tls, refuser_fichier_lisible_par_tous, verifier_les_domaines,
    };
    use ams_auth::Account;
    use ams_config::Tls;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    /// Un répertoire de travail qui se nettoie tout seul.
    struct Atelier(PathBuf);

    impl Drop for Atelier {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn atelier(nom: &str) -> Atelier {
        let chemin = std::env::temp_dir().join(format!("ams-server-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&chemin);
        std::fs::create_dir_all(&chemin).expect("répertoire temporaire");
        Atelier(chemin)
    }

    /// Écrit un fichier avec un mode donné, et rend son chemin.
    fn fichier(atelier: &Atelier, nom: &str, mode: u32) -> String {
        let chemin = atelier.0.join(nom);
        std::fs::write(&chemin, b"peu importe").expect("écriture");
        std::fs::set_permissions(&chemin, std::fs::Permissions::from_mode(mode))
            .expect("permissions");
        chemin.display().to_string()
    }

    #[test]
    fn une_adresse_hors_des_domaines_annonces_empeche_le_demarrage() {
        // Presque toujours une faute de frappe, et la découvrir au démarrage
        // coûte une seconde plutôt qu'un courrier qui n'arrive jamais.
        let compte = Account {
            login: String::from("jean"),
            hash: String::from(ams_auth::DUMMY_HASH),
            addresses: vec![String::from("jean@ailleurs.example")],
        };
        let erreur = verifier_les_domaines(
            std::slice::from_ref(&compte),
            &[String::from("example.com")],
        )
        .expect_err("refusé");
        assert!(erreur.contains("ailleurs.example"), "{erreur}");
        assert!(erreur.contains("--hosted"), "{erreur}");

        // Et la casse ne fait pas échouer un domaine qui est bien annoncé.
        assert!(
            verifier_les_domaines(
                std::slice::from_ref(&compte),
                &[String::from("Ailleurs.EXAMPLE")]
            )
            .is_ok()
        );
        // Un compte sans adresse ne dépend d'aucun domaine.
        let muet = Account {
            addresses: Vec::new(),
            ..compte
        };
        assert!(verifier_les_domaines(&[muet], &[]).is_ok());
    }

    #[test]
    fn sans_chemin_le_serveur_n_a_aucun_compte() {
        // Chaîne vide : pas de magasin, donc personne à qui répondre oui, donc
        // `AUTH` non annoncé. L'absence se lit à un chemin vide, pas à un
        // drapeau qui pourrait le contredire.
        assert!(
            charger_comptes("")
                .expect("aucun magasin est normal")
                .is_empty()
        );
    }

    #[test]
    fn un_magasin_introuvable_le_dit_avec_son_chemin() {
        let erreur = charger_comptes("/nulle/part/comptes.bin").expect_err("introuvable");
        assert!(erreur.contains("/nulle/part/comptes.bin"), "{erreur}");
    }

    #[test]
    fn sans_chemins_le_serveur_ne_chiffre_pas() {
        assert!(
            charger_tls(&Tls::default())
                .expect("aucun matériel n'est une situation normale")
                .is_none()
        );
    }

    #[test]
    fn une_cle_lisible_par_tout_le_monde_empeche_le_demarrage() {
        // Il suffit d'un compte de service compromis pour repartir avec
        // l'identité du serveur, et le vol ne laisse aucune trace.
        let atelier = atelier("cle-ouverte");
        let chemin = fichier(&atelier, "cle.pem", 0o644);
        let erreur = refuser_fichier_lisible_par_tous(&chemin, "clé privée").expect_err("refusée");
        assert!(erreur.contains("TOUT LE MONDE"), "{erreur}");
        assert!(erreur.contains("chmod o-r"), "{erreur}");
    }

    #[test]
    fn le_partage_par_groupe_reste_permis() {
        // `0640` avec un groupe dédié est exactement la BONNE pratique — celle
        // du groupe `ssl-cert` de Debian. La refuser punirait ceux qui rangent
        // bien leurs clés.
        let atelier = atelier("cle-groupe");
        for mode in [0o600, 0o640, 0o660] {
            let chemin = fichier(&atelier, &format!("cle-{mode:o}.pem"), mode);
            assert!(
                refuser_fichier_lisible_par_tous(&chemin, "clé privée").is_ok(),
                "le mode {mode:o} devrait être accepté"
            );
        }
    }

    #[test]
    fn un_certificat_absent_le_dit_avec_son_chemin() {
        // Le message doit nommer LE FICHIER : « certificat introuvable » sans
        // chemin oblige à deviner lequel des deux.
        let erreur = charger_tls(&Tls {
            certificate_chain_path: String::from("/nulle/part/chaine.pem"),
            private_key_path: String::from("/nulle/part/cle.pem"),
        })
        .expect_err("introuvable");
        assert!(erreur.contains("/nulle/part/chaine.pem"), "{erreur}");
    }

    #[test]
    fn un_materiel_illisible_est_refuse_au_demarrage() {
        let atelier = atelier("materiel-bidon");
        let chaine = fichier(&atelier, "chaine.pem", 0o644);
        let cle = fichier(&atelier, "cle.pem", 0o600);
        let erreur = charger_tls(&Tls {
            certificate_chain_path: chaine,
            private_key_path: cle,
        })
        .expect_err("refusé");
        assert!(erreur.contains("matériel TLS"), "{erreur}");
    }
}
