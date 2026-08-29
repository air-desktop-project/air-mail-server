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

mod delivery;
mod policy;
mod pop3;

use std::collections::BTreeMap;
use std::process::ExitCode;
use std::sync::Arc;

use std::path::{Path, PathBuf};
use std::time::Duration;

use ams_auth::Account;
use ams_config::{Configuration, Enforcement, Tls};
use ams_loop_tokio::pop3::serve_pop3;
use ams_loop_tokio::{
    DkimChecker, DmarcChecker, SenderChecker, ServeOptions, SharedGuard, Timeouts, refuse_root,
    serve,
};
use ams_session::{Capabilities, Config, SenderPolicy};
use ams_store::Maildir;
use tokio::net::TcpListener;

use rustls::ServerConfig;

use crate::delivery::{Boites, MaildirDelivery};
use crate::policy::BoitesConnues;
use crate::pop3::BoitesPop3;

/// Le texte de `--help`.
const AIDE: &str = "\
air-mail-server — serveur de courrier SMTP

USAGE
    air-mail-server --config <fichier>

Le fichier de configuration est BINAIRE, et se produit avec
`air-mail-admin config write`. Ce serveur n'a AUCUNE autre option de réglage :
deux sources de configuration seraient une de trop.

    --config <fichier>  la configuration
    --help              ce texte
    --version           la version

CE QUI N'EST PAS ENCORE LÀ
    TLS et l'authentification ne sont pas implémentés, donc ni STARTTLS ni AUTH
    ne sont annoncés. Le courrier reçu va dans UNE SEULE boîte : répartir par
    destinataire demande un modèle de comptes qui n'existe pas.
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

/// Monte le serveur et le fait tourner jusqu'à l'arrêt.
async fn servir(fichier: &Path) -> Result<(), String> {
    // LE REFUS DU SUPERUTILISATEUR VIENT AVANT TOUT LE RESTE (C10) — avant
    // d'ouvrir un port, avant de créer un répertoire. Rien de ce qui suit ne doit
    // s'exécuter avec ces privilèges, pas même une seconde.
    refuse_root().map_err(|erreur| erreur.to_string())?;

    let octets =
        std::fs::read(fichier).map_err(|erreur| format!("`{}` : {erreur}", fichier.display()))?;
    let options: Configuration = ams_config::decode(&octets)
        .map_err(|erreur| format!("`{}` : {erreur}", fichier.display()))?;
    let ecoute: std::net::SocketAddr = options
        .listen
        .parse()
        .map_err(|_| format!("`{}` n'est pas une adresse d'écoute", options.listen))?;
    let maildir = PathBuf::from(&options.maildir);

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
    let comptes = charger_comptes(&options.accounts)?;
    verifier_les_domaines(&comptes, &options.hosted)?;
    // `AUTH` n'est annoncé QUE si les deux conditions tiennent : quelqu'un à qui
    // répondre oui, et de quoi chiffrer. La session refuse `AUTH` hors TLS de
    // toute façon ; l'annoncer sans chiffrement ne ferait que mentir plus tôt.
    let authentifie = !comptes.is_empty() && chiffrement.is_some();
    let config = if chiffrement.is_some() {
        config.with_capabilities(Capabilities {
            starttls: true,
            auth: authentifie,
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
    // faut aller chercher la politique du domaine de l'en-tête `From:`.
    let alignement = if options.dmarc.est_configure() && !resolveurs.is_empty() {
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
            (None, _) if options.dmarc.est_configure() => String::from(
                "DMARC non évalué — une liste de suffixes est nommée, mais aucun résolveur"
            ),
            (None, _) => String::from(
                "DMARC non évalué — aucune liste de suffixes publics                  (`air-mail-admin --public-suffix-list …`)"
            ),
            (Some(_), false) => format!(
                "DMARC évalué et RETENU, sans rien opposer ; suffixes publics `{}`",
                options.dmarc.public_suffix_list
            ),
            (Some(_), true) => format!(
                "DMARC APPLIQUÉ — un `p=reject` est opposé (550) ; suffixes publics `{}`. \
                 La quarantaine, elle, n'est pas encore un endroit : ces messages sont remis.",
                options.dmarc.public_suffix_list
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
    for compte in &comptes {
        let racine = maildir.join(&compte.login);
        let boite = Maildir::open(&racine, domaine, ams_store::fresh_uid_validity())
            .map_err(|erreur| format!("boîte de `{}` : {erreur}", compte.login))?;
        let resume = boite
            .summary()
            .map_err(|erreur| format!("boîte de `{}` : {erreur}", compte.login))?;
        messages = messages.saturating_add(resume.numbered);
        boites.insert(compte.login.clone(), Arc::new(boite));
    }
    let boites: Boites = Arc::new(boites);

    let ecouteur = TcpListener::bind(ecoute)
        .await
        .map_err(|erreur| format!("écoute sur {ecoute} : {erreur}"))?;

    eprintln!(
        "air-mail-server {} : {} écoute sur {}, {} boîte(s) sous `{}` ({} message(s))",
        env!("CARGO_PKG_VERSION"),
        options.domain,
        ecoute,
        boites.len(),
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
    let politique = Arc::new(BoitesConnues::new(Arc::clone(&comptes), postmaster.clone()));
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
    if ams_auth::route(&comptes, postmaster.as_bytes()).is_none() {
        eprintln!(
            "air-mail-server : ATTENTION — aucun compte ne reçoit `{postmaster}`. \
             La RFC 5321 §4.5.1 l'exige : `air-mail-admin account add … --address {postmaster}`."
        );
    }

    let pour_la_remise = Arc::clone(&boites);
    let comptes_pour_la_remise = Arc::clone(&comptes);

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
        tls: chiffrement,
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

    let stats = serve(
        ecouteur,
        config,
        politique,
        garde,
        move || {
            MaildirDelivery::new(
                Arc::clone(&pour_la_remise),
                Arc::clone(&comptes_pour_la_remise),
            )
        },
        options_de_service,
        arret(),
    )
    .await
    .map_err(|erreur| erreur.to_string())?;

    if let Some(tache) = pop3 {
        // La boucle POP3 s'arrête sur le même signal ; on attend qu'elle ait
        // fini d'accepter avant de rendre la main, sans quoi le message d'arrêt
        // partirait pendant qu'elle sert encore.
        match tache.await {
            Ok(Ok(stats_pop3)) => eprintln!(
                "air-mail-server : POP3 ; {} connexion(s) acceptée(s), {} refusée(s) par le noyau",
                stats_pop3.accepted, stats_pop3.failed
            ),
            Ok(Err(erreur)) => eprintln!("air-mail-server : POP3 : {erreur}"),
            Err(erreur) => eprintln!("air-mail-server : POP3 : {erreur}"),
        }
    }

    eprintln!(
        "air-mail-server : arrêt ; {} connexion(s) acceptée(s), {} refusée(s) par le noyau",
        stats.accepted, stats.failed
    );
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
    }
    Ok(())
}

/// Attend `SIGINT` ou `SIGTERM`.
///
/// Les deux, et pas seulement `Ctrl-C` : un service arrêté par un gestionnaire
/// reçoit `SIGTERM`, et l'ignorer le ferait tuer au bout du délai de grâce —
/// c'est-à-dire au milieu d'une remise.
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
