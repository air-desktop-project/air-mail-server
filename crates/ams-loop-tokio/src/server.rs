//! La boucle d'acceptation.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use ams_guard::Source;
use ams_session::{Config, Policy};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::{
    Delivery, DkimChecker, Error, SenderChecker, Service, SharedGuard, Timeouts, serve_connection,
};

/// Ce qui borne le service.
///
/// Ni `Copy` ni `Eq` depuis que [`ServeOptions::tls`] existe : une configuration
/// TLS est un `Arc` qu'on partage, pas une valeur qu'on recopie — et deux
/// configurations TLS ne se comparent pas.
#[derive(Debug, Clone)]
pub struct ServeOptions {
    /// Connexions servies **en même temps**.
    ///
    /// Au-delà, l'acceptation attend qu'une place se libère : le noyau garde les
    /// connexions en file, et le pair patiente au lieu d'être refusé. C'est de la
    /// contre-pression, pas un refus.
    ///
    /// **La limite de cette approche est réelle** : des pairs lents peuvent
    /// occuper toutes les places. Ce sont les délais ([`Timeouts`]) qui bornent
    /// la durée d'une place, et le garde qui borne le débit d'ouverture. Aucun
    /// des deux ne rend l'autre inutile.
    pub max_connections: usize,
    /// Les délais appliqués à chaque connexion.
    pub timeouts: Timeouts,
    /// De quoi chiffrer, si le service sait le faire.
    ///
    /// Voir [`Service::tls`] : c'est la même valeur, et les mêmes règles. Le
    /// service refuse de démarrer une connexion qui annoncerait `STARTTLS` sans
    /// elle.
    pub tls: Option<Arc<ServerConfig>>,
    /// De quoi vérifier l'expéditeur (C9), si le service sait le faire.
    ///
    /// Voir [`Service::spf`] : mêmes règles. Une politique d'expéditeur qui
    /// n'est pas `Ignore` sans ce champ fait échouer chaque connexion — au
    /// démarrage plutôt qu'au premier `MAIL FROM:`.
    pub spf: Option<SenderChecker>,
    /// De quoi vérifier les signatures DKIM (C9).
    ///
    /// Voir [`Service::dkim`] : son absence ne refuse rien.
    pub dkim: Option<DkimChecker>,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            max_connections: 256,
            timeouts: Timeouts::default(),
            tls: None,
            spf: None,
            dkim: None,
        }
    }
}

/// Ce que le service a fait.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Connexions acceptées.
    pub accepted: u64,
    /// Acceptations que le noyau a refusées.
    pub failed: u64,
    /// Ce que les signatures DKIM ont donné, toutes connexions confondues.
    ///
    /// # Pourquoi ici, et pas dans un journal
    ///
    /// Parce qu'il n'y en a pas encore. Un verdict qu'on ne rend nulle part ne
    /// sert à rien — c'est ce qu'on a écrit pour SPF, et cela vaut ici. En
    /// attendant `air-log`, ce compte-là est ce que le serveur peut dire, et il
    /// le dit à l'arrêt.
    pub dkim: DkimSums,
}

/// Le compte des verdicts DKIM, sur toute la durée du service.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DkimSums {
    /// Signatures vraies.
    pub pass: u64,
    /// Signatures fausses.
    pub fail: u64,
    /// Clés qu'on n'a pas pu résoudre.
    pub temp_error: u64,
    /// Signatures, clés ou algorithmes irrecevables.
    pub perm_error: u64,
}

/// Les mêmes comptes, partagés par les tâches de connexion.
///
/// Une tâche par connexion, et chacune rend son résumé à personne : c'est ce
/// compteur-là qui les rassemble. Des entiers atomiques suffisent — il n'y a
/// rien à lire en cours de route, seulement à ajouter.
#[derive(Debug, Default)]
struct CompteurDkim {
    pass: AtomicU64,
    fail: AtomicU64,
    temp_error: AtomicU64,
    perm_error: AtomicU64,
}

impl CompteurDkim {
    fn ajouter(&self, tally: crate::connection::DkimTally) {
        self.pass
            .fetch_add(u64::from(tally.pass), Ordering::Relaxed);
        self.fail
            .fetch_add(u64::from(tally.fail), Ordering::Relaxed);
        self.temp_error
            .fetch_add(u64::from(tally.temp_error), Ordering::Relaxed);
        self.perm_error
            .fetch_add(u64::from(tally.perm_error), Ordering::Relaxed);
    }

    fn sommes(&self) -> DkimSums {
        DkimSums {
            pass: self.pass.load(Ordering::Relaxed),
            fail: self.fail.load(Ordering::Relaxed),
            temp_error: self.temp_error.load(Ordering::Relaxed),
            perm_error: self.perm_error.load(Ordering::Relaxed),
        }
    }
}

/// Accepte des connexions et les sert, jusqu'à l'arrêt demandé.
///
/// # Elle refuse de démarrer en superutilisateur
///
/// [`crate::refuse_root`] est appelée ici, **avant la première acceptation**
/// (C10). Les ports privilégiés s'atteignent par une redirection de pare-feu ;
/// il n'y a aucun abandon de privilèges à écrire, donc aucun à se tromper.
///
/// # L'arrêt est net, mais pas brutal
///
/// Quand `shutdown` se résout, l'acceptation cesse **immédiatement** ; les
/// connexions en cours, elles, vont à leur terme. Une tâche par connexion, et le
/// nombre de tâches est borné par [`ServeOptions::max_connections`].
///
/// # Errors
///
/// [`Error::RunningAsRoot`], ou une erreur d'entrée-sortie sur l'écouteur.
pub async fn serve<P, D, F, S>(
    listener: TcpListener,
    config: Config<'static>,
    policy: Arc<P>,
    guard: Arc<SharedGuard>,
    make_delivery: F,
    options: ServeOptions,
    shutdown: S,
) -> Result<Stats, Error>
where
    P: Policy + Send + Sync + 'static,
    D: Delivery + Send + 'static,
    F: Fn() -> D + Send + Sync + 'static,
    S: Future<Output = ()>,
{
    crate::refuse_root()?;

    let places = Arc::new(Semaphore::new(options.max_connections));
    let fabrique = Arc::new(make_delivery);
    let comptes_dkim = Arc::new(CompteurDkim::default());
    let mut stats = Stats::default();
    let mut arret = core::pin::pin!(shutdown);

    loop {
        let acceptee = tokio::select! {
            // `biased` : l'arrêt est examiné EN PREMIER. Sans cela, un flot
            // continu de connexions pourrait le repousser indéfiniment, et un
            // serveur qu'on ne peut pas arrêter sous charge est un serveur qu'on
            // finit par tuer.
            biased;
            () = &mut arret => return Ok(avec_dkim(stats, &comptes_dkim)),
            acceptee = listener.accept() => acceptee,
        };

        let (flux, pair) = match acceptee {
            Ok(connexion) => connexion,
            Err(_) => {
                // Une acceptation qui échoue — descripteurs épuisés, connexion
                // déjà fermée — n'arrête pas le service. Renoncer ici offrirait
                // l'arrêt du serveur à qui sait ouvrir puis fermer assez vite.
                stats.failed = stats.failed.saturating_add(1);
                continue;
            }
        };
        stats.accepted = stats.accepted.saturating_add(1);

        let Ok(place) = Arc::clone(&places).acquire_owned().await else {
            // Le sémaphore n'est jamais fermé : ce chemin ne s'emprunte pas.
            return Ok(avec_dkim(stats, &comptes_dkim));
        };
        let comptes = Arc::clone(&comptes_dkim);
        let policy = Arc::clone(&policy);
        let guard = Arc::clone(&guard);
        let fabrique = Arc::clone(&fabrique);
        let timeouts = options.timeouts;
        // Un `Arc` de plus par connexion, et rien d'autre : la configuration TLS
        // est partagée, jamais recopiée. C'est ce qui rend le chiffrement
        // gratuit à l'acceptation.
        let tls = options.tls.clone();
        let spf = options.spf.clone();
        let dkim = options.dkim.clone();

        tokio::spawn(async move {
            let mut flux = flux;
            let mut remise = fabrique();
            let service = Service {
                config,
                guard: &guard,
                timeouts,
                tls,
                spf,
                dkim,
            };
            // L'ÉCHEC d'une connexion ne regarde qu'elle — le journal viendra
            // avec `air-log`. Ce qu'elle a CONCLU des signatures, en revanche,
            // se rassemble : un verdict qu'on ne rend nulle part ne sert à rien.
            if let Ok(resume) =
                serve_connection(&mut flux, &service, &*policy, &mut remise, source_de(pair)).await
            {
                comptes.ajouter(resume.dkim);
            }
            drop(place);
        });
    }
}

/// Verse les comptes DKIM dans le résumé du service.
fn avec_dkim(stats: Stats, comptes: &CompteurDkim) -> Stats {
    Stats {
        dkim: comptes.sommes(),
        ..stats
    }
}

/// L'adresse d'un pair, telle que le garde la compte.
#[must_use]
pub fn source_de(adresse: SocketAddr) -> Source {
    match adresse {
        SocketAddr::V4(v4) => Source::V4(v4.ip().octets()),
        SocketAddr::V6(v6) => Source::V6(v6.ip().octets()),
    }
}

#[cfg(test)]
mod tests {
    use super::{DkimSums, ServeOptions, Stats, serve, source_de};
    use crate::{Delivery, DeliveryFailure, Error, SharedGuard, Timeouts};
    use ams_guard::{Source, Thresholds};
    use ams_proto_smtp::{Limits, Path};
    use ams_session::{Config, Policy, RecipientVerdict};
    use core::time::Duration;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};

    struct ToutAccepter;

    impl ams_session::Authenticator for ToutAccepter {}

    impl Policy for ToutAccepter {
        fn accepts_recipient(&self, _forward_path: &Path<'_>) -> RecipientVerdict {
            RecipientVerdict::Accept
        }
    }

    /// Une remise qui jette tout : ce qui est éprouvé ici est la boucle.
    struct Neant;

    impl Delivery for Neant {
        fn add_recipient(&mut self, _address: &[u8]) -> Result<(), DeliveryFailure> {
            Ok(())
        }
        fn append(&mut self, _chunk: &[u8]) -> Result<(), DeliveryFailure> {
            Ok(())
        }
        fn finish(&mut self) -> Result<(), DeliveryFailure> {
            Ok(())
        }
        fn abort(&mut self) {}
    }

    fn config() -> Config<'static> {
        Config::new(b"mail.example.com", 100, 1_048_576, Limits::DEFAULT).expect("configurable")
    }

    /// Parle à un serveur, et rend ce qu'il a dit.
    ///
    /// Tolère un `RST` : quand le serveur ferme sans avoir lu ce que le client
    /// venait d'écrire, TCP jette la connexion plutôt que de la clore proprement.
    /// C'est un fait du protocole de transport, pas un défaut du serveur, et un
    /// client réel lit sa réponse avant d'en redemander.
    async fn cliente(adresse: SocketAddr, envoi: &[u8]) -> String {
        let mut flux = TcpStream::connect(adresse).await.expect("connexion");
        let _ = flux.write_all(envoi).await;
        let mut recu = Vec::new();
        let _ = flux.read_to_end(&mut recu).await;
        String::from_utf8_lossy(&recu).into_owned()
    }

    #[tokio::test]
    async fn un_serveur_ecoute_et_sert_de_vraies_connexions() {
        // Le port `0` laisse le noyau choisir : aucun port en dur, donc aucun
        // test qui échoue parce qu'un autre l'occupait.
        let ecouteur = TcpListener::bind("127.0.0.1:0").await.expect("écoute");
        let adresse = ecouteur.local_addr().expect("adresse");
        let (arret, attendre) = tokio::sync::oneshot::channel::<()>();

        let service = tokio::spawn(serve(
            ecouteur,
            config(),
            Arc::new(ToutAccepter),
            Arc::new(SharedGuard::new(64, Thresholds::DEFAULT)),
            || Neant,
            ServeOptions::default(),
            async {
                let _ = attendre.await;
            },
        ));

        let dit = cliente(
            adresse,
            b"EHLO client.example\r\n\
              MAIL FROM:<moi@ailleurs.example>\r\n\
              RCPT TO:<jean@example.com>\r\n\
              DATA\r\nbonjour\r\n.\r\nQUIT\r\n",
        )
        .await;
        assert!(dit.starts_with("220 mail.example.com ESMTP\r\n"));
        assert!(dit.contains("250 Message accepted\r\n"));
        assert!(dit.ends_with("221 Bye\r\n"));

        // Une seconde connexion : le service n'est pas à usage unique.
        let encore = cliente(adresse, b"QUIT\r\n").await;
        assert!(encore.ends_with("221 Bye\r\n"));

        let _ = arret.send(());
        let stats = service.await.expect("tâche").expect("service");
        assert!(stats.accepted >= 2, "{stats:?}");
    }

    #[tokio::test]
    async fn l_arret_cesse_l_acceptation_sans_couper_ce_qui_est_en_cours() {
        let ecouteur = TcpListener::bind("127.0.0.1:0").await.expect("écoute");
        let adresse = ecouteur.local_addr().expect("adresse");
        let (arret, attendre) = tokio::sync::oneshot::channel::<()>();
        let service = tokio::spawn(serve(
            ecouteur,
            config(),
            Arc::new(ToutAccepter),
            Arc::new(SharedGuard::new(64, Thresholds::DEFAULT)),
            || Neant,
            ServeOptions::default(),
            async {
                let _ = attendre.await;
            },
        ));

        assert!(cliente(adresse, b"QUIT\r\n").await.ends_with("221 Bye\r\n"));
        let _ = arret.send(());
        let stats = service.await.expect("tâche").expect("service");
        assert_eq!(stats.accepted, 1);

        // Plus personne n'écoute : la connexion suivante est refusée par le noyau.
        assert!(TcpStream::connect(adresse).await.is_err());
    }

    #[tokio::test]
    async fn le_garde_refuse_avant_meme_la_banniere() {
        let garde = Arc::new(SharedGuard::new(
            64,
            Thresholds {
                connections_per_minute: 1,
                ..Thresholds::DEFAULT
            },
        ));
        let ecouteur = TcpListener::bind("127.0.0.1:0").await.expect("écoute");
        let adresse = ecouteur.local_addr().expect("adresse");
        let (arret, attendre) = tokio::sync::oneshot::channel::<()>();
        let service = tokio::spawn(serve(
            ecouteur,
            config(),
            Arc::new(ToutAccepter),
            Arc::clone(&garde),
            || Neant,
            ServeOptions {
                timeouts: Timeouts {
                    command: Duration::from_millis(200),
                    data: Duration::from_millis(200),
                    handshake: Duration::from_millis(200),
                },
                ..ServeOptions::default()
            },
            async {
                let _ = attendre.await;
            },
        ));

        assert!(cliente(adresse, b"QUIT\r\n").await.contains("220 "));
        // La seconde connexion, depuis la même source, dépasse le seuil.
        let seconde = cliente(adresse, b"QUIT\r\n").await;
        assert_eq!(
            seconde,
            "421 Service not available, closing transmission channel\r\n"
        );

        let _ = arret.send(());
        let _ = service.await.expect("tâche");
    }

    #[test]
    fn une_adresse_de_pair_devient_une_source() {
        assert_eq!(
            source_de(SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 25))),
            Source::V4([192, 0, 2, 1])
        );
        let six = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        assert_eq!(
            source_de(SocketAddr::from((six, 25))),
            Source::V6(six.octets())
        );
    }

    #[test]
    fn les_reglages_par_defaut_bornent_quelque_chose() {
        let defaut = ServeOptions::default();
        assert_eq!(defaut.max_connections, 256);
        assert!(!format!("{defaut:?}").is_empty());
        assert_eq!(
            Stats::default(),
            Stats {
                accepted: 0,
                failed: 0,
                dkim: DkimSums::default(),
            }
        );
        assert!(!format!("{:?}", Stats::default()).is_empty());
    }

    #[tokio::test]
    async fn le_service_refuse_de_demarrer_en_superutilisateur() {
        // Le test ne peut vérifier que le cas où l'on n'est PAS root — ce qui est
        // précisément ce que le projet exige de son environnement (C10).
        let ecouteur = TcpListener::bind("127.0.0.1:0").await.expect("écoute");
        let service = serve(
            ecouteur,
            config(),
            Arc::new(ToutAccepter),
            Arc::new(SharedGuard::new(1, Thresholds::DEFAULT)),
            || Neant,
            ServeOptions::default(),
            async {},
        );
        match service.await {
            Ok(_) => {}
            Err(Error::RunningAsRoot) => panic!("les tests tournent en root, ce que C10 proscrit"),
            Err(autre) => panic!("erreur inattendue : {autre}"),
        }
    }
}
