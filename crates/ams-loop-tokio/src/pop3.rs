//! Le pilote d'une connexion POP3 : il lit, il écrit, il ne décide de rien.
//!
//! # Ce qu'il sait du protocole : trois choses, et pas une de plus
//!
//! 1. qu'une ligne finit par un `CRLF` — c'est du découpage, pas du protocole ;
//! 2. qu'une réponse s'écrit telle quelle ;
//! 3. que la session lui dit quoi faire ensuite.
//!
//! Ni le doublement du point, ni le vocabulaire, ni les états : tout cela vit
//! dans `ams-session` et `ams-proto-pop3`, c'est-à-dire dans le périmètre
//! couvert à 100 %, et n'aura pas à être réécrit pour Air.

use ams_guard::{Event as GuardEvent, Source, Verdict};
use ams_proto_pop3::Limits;
use ams_session::Authenticator;
use ams_session::pop3::{Action, Mailbox, Session};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};

use crate::connection::{lire, trouver_crlf};
use crate::{Error, SharedGuard};

/// Ce qu'un service POP3 apporte à chacune de ses connexions.
///
/// Même découpage que pour SMTP : ce qui ne varie pas d'une connexion à l'autre
/// est ici, ce qui varie reste en paramètres.
#[derive(Clone)]
pub struct Pop3Service<'a> {
    /// Les bornes du décodeur (C3).
    pub limits: Limits,
    /// Le garde anti-flooding (C8), partagé par toutes les connexions.
    pub guard: &'a SharedGuard,
    /// Les délais.
    pub timeouts: crate::Timeouts,
    /// De quoi chiffrer, si le service sait le faire.
    ///
    /// **Sans elle, `USER` et `PASS` sont refusés** : la session l'impose sans
    /// réglage possible (C6), et ce service ne servira donc personne. Un POP3
    /// sans TLS n'est pas un POP3 dégradé, c'est un POP3 inutile — et le dire
    /// ici évite de le découvrir en production.
    pub tls: Option<std::sync::Arc<rustls::ServerConfig>>,
}

/// Ce qu'il faut savoir ouvrir pour servir une session.
///
/// # Pourquoi un trait, et pas un chemin
///
/// La boucle ne sait pas où vivent les boîtes, ni comment un compte s'y
/// rattache : c'est le binaire qui le sait. Elle sait seulement qu'après un
/// `PASS` accepté, il faut ouvrir **la boîte de ce nom-là**, et qu'un refus est
/// une réponse comme une autre.
pub trait Mailboxes {
    /// La boîte ouverte, telle que la session la verra.
    type Open: Mailbox;

    /// Ouvre et **verrouille** la boîte d'un compte, ou rend `None`.
    ///
    /// `None` veut dire « pas maintenant » : boîte déjà tenue par une autre
    /// session, ou illisible. La session répondra `-ERR`, et le pair pourra
    /// réessayer.
    fn open(&self, user: &[u8]) -> Option<Self::Open>;

    /// Applique les effacements demandés, et rend le nombre d'échecs.
    ///
    /// Appelée **une seule fois**, au `QUIT` venu de TRANSACTION. C'est l'état
    /// UPDATE de la RFC 1939 §6.
    fn commit(&self, mailbox: Self::Open) -> usize;

    /// Lit un morceau du message `message`, à partir de `offset`.
    ///
    /// Rend le nombre d'octets écrits dans `buffer` ; zéro signale la fin.
    ///
    /// # Errors
    ///
    /// Toute erreur d'entrée-sortie ; la connexion est alors abandonnée.
    fn read(
        &self,
        mailbox: &Self::Open,
        message: ams_proto_pop3::MessageNumber,
        offset: u64,
        buffer: &mut [u8],
    ) -> std::io::Result<usize>;
}

/// Ce qu'une connexion POP3 a produit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Pop3Summary {
    /// Lignes de commande traitées.
    pub commands: u64,
    /// Messages remis au pair.
    pub retrieved: u64,
    /// Messages effacés à la fermeture.
    pub expunged: u64,
    /// La session a-t-elle été chiffrée ?
    pub tls: bool,
    /// Le pair était-il banni ? **Rien ne lui a alors été dit.**
    pub banned: bool,
    /// Le pair a-t-il tenté de glisser une commande derrière son `STLS` ?
    ///
    /// Voir la garde de `conduire` : c'est une injection, et la connexion est
    /// refusée sans que la commande soit servie.
    pub injected: bool,
}

/// Sert une connexion POP3 jusqu'à sa fin.
///
/// # Errors
///
/// [`Error::Timeout`], [`Error::Io`], ou [`Error::CapabilityNotSupported`] si le
/// service annonce `STLS` sans matériel TLS.
pub async fn serve_pop3_connection<S, A, B>(
    stream: &mut S,
    service: &Pop3Service<'_>,
    auth: A,
    boites: &B,
    source: Source,
) -> Result<Pop3Summary, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    A: Authenticator,
    B: Mailboxes,
{
    let mut resume = Pop3Summary::default();

    // ON NE PARLE PAS À UN BANNI. Interroger le garde ne compte pas comme un
    // événement : demander son avis ne doit pas nourrir ses compteurs.
    if matches!(service.guard.verdict(source), Verdict::Banned { .. }) {
        resume.banned = true;
        return Ok(resume);
    }

    let accepteur = service
        .tls
        .as_ref()
        .map(|configuration| tokio_rustls::TlsAcceptor::from(std::sync::Arc::clone(configuration)));
    let mut session: Session<A, B::Open> = Session::new(service.limits, accepteur.is_some(), auth);

    let mut etat = Etat::neuf(&service.limits);
    if matches!(
        service.guard.observe(source, GuardEvent::Connection),
        Verdict::Throttled | Verdict::Banned { .. }
    ) {
        let refus = session.unavailable(&mut etat.sortie)?;
        stream.write_all(refus).await?;
        stream.flush().await?;
        return Ok(resume);
    }

    let banniere = session.greeting(&mut etat.sortie)?;
    stream.write_all(banniere).await?;
    stream.flush().await?;

    match conduire(stream, &mut session, &mut etat, service, boites, source).await? {
        Etape::Terminee => {
            resume.merge(&etat);
            return Ok(resume);
        }
        Etape::Chiffrement => {}
    }

    // Inatteignable : la session n'offre `STLS` que si l'accepteur existe.
    // Comme ailleurs dans cette crate — étage 3, hors du 100 % de C2 — on rend
    // une erreur plutôt que de faire tomber un serveur.
    let Some(accepteur) = accepteur else {
        return Err(Error::CapabilityNotSupported);
    };
    let mut chiffre = match tokio::time::timeout(
        service.timeouts.handshake,
        accepteur.accept(&mut *stream),
    )
    .await
    {
        Ok(Ok(flux)) => flux,
        // Une poignée de main ratée après un `+OK` est une trame invalide au
        // sens de C8 : le pair a demandé le chiffrement, puis n'a pas su le
        // conduire.
        Ok(Err(cause)) => {
            service.guard.observe(source, GuardEvent::InvalidFrame);
            resume.merge(&etat);
            return Err(Error::Io(cause));
        }
        Err(_) => {
            service.guard.observe(source, GuardEvent::InvalidFrame);
            resume.merge(&etat);
            return Err(Error::Timeout);
        }
    };
    session.on_tls_established();
    etat.tls = true;

    let etape = conduire(
        &mut chiffre,
        &mut session,
        &mut etat,
        service,
        boites,
        source,
    )
    .await?;
    debug_assert_eq!(etape, Etape::Terminee, "un second STLS a été demandé");
    // `close_notify` avant de raccrocher : il dit au pair que la fin est VOULUE.
    let _ = chiffre.shutdown().await;
    resume.merge(&etat);
    Ok(resume)
}

/// Ce qui survit à la montée en chiffrement.
struct Etat {
    lecture: Vec<u8>,
    rempli: usize,
    sortie: Vec<u8>,
    corps: Vec<u8>,
    commands: u64,
    retrieved: u64,
    expunged: u64,
    tls: bool,
    injected: bool,
}

impl Etat {
    fn neuf(limits: &Limits) -> Self {
        // Le tampon de LECTURE est borné par la borne de commande, plus un
        // octet : quand il se remplit sans CRLF, la ligne dépasse forcément la
        // borne, et la session la refuse d'elle-même.
        Self {
            lecture: vec![0_u8; limits.max_command_octets.saturating_add(1)],
            rempli: 0,
            // Deux fois la borne de réponse : une ligne de liste y tient, et le
            // terminateur aussi.
            sortie: vec![0_u8; limits.max_reply_octets.saturating_mul(2)],
            // Le corps d'un message se transforme par morceaux. La sortie peut
            // DOUBLER — un point de tête en coûte deux — d'où le facteur deux.
            corps: vec![0_u8; 16_384],
            commands: 0,
            retrieved: 0,
            expunged: 0,
            tls: false,
            injected: false,
        }
    }
}

impl Pop3Summary {
    fn merge(&mut self, etat: &Etat) {
        self.commands = etat.commands;
        self.retrieved = etat.retrieved;
        self.expunged = etat.expunged;
        self.tls = etat.tls;
        self.injected = etat.injected;
    }
}

/// Pourquoi le pilote a rendu la main.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Etape {
    Terminee,
    Chiffrement,
}

/// Le pilote proprement dit.
async fn conduire<S, A, B>(
    stream: &mut S,
    session: &mut Session<A, B::Open>,
    etat: &mut Etat,
    service: &Pop3Service<'_>,
    boites: &B,
    source: Source,
) -> Result<Etape, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    A: Authenticator,
    B: Mailboxes,
{
    let capacite = etat.lecture.len();
    loop {
        let Some(fin_ligne) = trouver_crlf(&etat.lecture[..etat.rempli]) else {
            if etat.rempli == capacite {
                // La ligne dépasse la borne : la session la refuse et répond,
                // puis on ferme — un pair qui envoie plus de 512 octets sur une
                // ligne ne se rattrapera pas.
                let tour = session.handle(&etat.lecture[..etat.rempli], &mut etat.sortie)?;
                stream.write_all(tour.reply()).await?;
                stream.flush().await?;
                etat.commands = etat.commands.saturating_add(1);
                return Ok(Etape::Terminee);
            }
            let lus = lire(
                stream,
                &mut etat.lecture[etat.rempli..],
                service.timeouts.command,
            )
            .await?;
            if lus == 0 {
                // Le pair a raccroché sans `QUIT` : RIEN N'EST EFFACÉ. C'est la
                // RFC 1939 §6, et c'est ce qui protège le courrier d'une
                // coupure réseau.
                return Ok(Etape::Terminee);
            }
            etat.rempli = etat.rempli.saturating_add(lus);
            continue;
        };

        let tour = session.handle(&etat.lecture[..fin_ligne], &mut etat.sortie)?;
        let action = tour.action();
        let faute = tour.peer_fault();

        // ── L'INJECTION PAR `STLS` (RFC 2595 §4) ────────────────────────────
        //
        // Le pair a-t-il déjà envoyé autre chose derrière son `STLS` ? Alors il
        // n'aura pas son `+OK` : ces octets-là sont arrivés EN CLAIR, donc
        // peut-être de quelqu'un d'autre, et les servir après la poignée de main
        // reviendrait à exécuter sous chiffrement ce que le fil a dicté.
        //
        // **ON REFUSE PLUTÔT QUE DE JETER**, comme SMTP : jeter en silence
        // laisserait une attaque en cours passer pour un client bavard, et le
        // garde n'en saurait rien. Voir `connection::conduire`, la même garde
        // pour la même faille.
        if action == Action::StartTls && etat.rempli > fin_ligne {
            service.guard.observe(source, GuardEvent::InvalidFrame);
            let refus = session.unavailable(&mut etat.sortie)?;
            stream.write_all(refus).await?;
            stream.flush().await?;
            etat.injected = true;
            return Ok(Etape::Terminee);
        }

        stream.write_all(tour.reply()).await?;
        stream.flush().await?;
        etat.commands = etat.commands.saturating_add(1);

        etat.lecture.copy_within(fin_ligne..etat.rempli, 0);
        etat.rempli = etat.rempli.saturating_sub(fin_ligne);

        let evenement = if faute {
            GuardEvent::InvalidFrame
        } else {
            GuardEvent::Command
        };
        if matches!(
            service.guard.observe(source, evenement),
            Verdict::Throttled | Verdict::Banned { .. }
        ) {
            let refus = session.unavailable(&mut etat.sortie)?;
            stream.write_all(refus).await?;
            stream.flush().await?;
            return Ok(Etape::Terminee);
        }

        match action {
            Action::Continue => {}
            Action::StartTls => return Ok(Etape::Chiffrement),
            Action::Close => return Ok(Etape::Terminee),
            Action::CommitAndClose => {
                // L'ÉTAT UPDATE. C'est le seul endroit où quoi que ce soit
                // s'efface, et il n'est atteint que par un `QUIT` venu de
                // TRANSACTION.
                if let Some(boite) = session.take_mailbox() {
                    let echecs = boites.commit(boite);
                    etat.expunged = etat.expunged.saturating_add(1);
                    let _ = echecs;
                }
                return Ok(Etape::Terminee);
            }
            Action::OpenMailbox => {
                let boite = boites.open(session.user());
                let tour = session.on_mailbox_opened(boite, &mut etat.sortie)?;
                stream.write_all(tour.reply()).await?;
                stream.flush().await?;
            }
            Action::SendListing => {
                while let Some(ligne) = session.next_listing(&mut etat.sortie)? {
                    stream.write_all(ligne).await?;
                }
                stream.flush().await?;
            }
            Action::SendBody { message, .. } => {
                emettre_le_corps(stream, session, etat, boites, message).await?;
                etat.retrieved = etat.retrieved.saturating_add(1);
            }
        }
    }
}

/// Lit le message et le donne à la session, qui le rend doublé.
async fn emettre_le_corps<S, A, B>(
    stream: &mut S,
    session: &mut Session<A, B::Open>,
    etat: &mut Etat,
    boites: &B,
    message: ams_proto_pop3::MessageNumber,
) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    A: Authenticator,
    B: Mailboxes,
{
    let mut position = 0_u64;
    let moitie = etat.corps.len() / 2;
    loop {
        if session.body_complete() {
            // `TOP` a rendu son compte : inutile de lire la suite du fichier.
            break;
        }
        let lus = {
            let Some(boite) = session.mailbox() else {
                // Inatteignable : la session n'émet un corps qu'en TRANSACTION.
                break;
            };
            let (lecture, _) = etat.corps.split_at_mut(moitie);
            boites.read(boite, message, position, lecture)?
        };
        if lus == 0 {
            break;
        }
        position = position.saturating_add(lus as u64);

        // La transformation peut DOUBLER : on ne lui donne donc que la moitié
        // du tampon à lire, et l'autre moitié lui sert de sortie. Elle peut tout
        // de même s'arrêter en chemin, d'où la boucle.
        let mut consomme = 0_usize;
        while consomme < lus {
            let (lecture, sortie) = etat.corps.split_at_mut(moitie);
            let (pris, emis) = session.feed_body(&lecture[consomme..lus], sortie)?;
            stream.write_all(emis).await?;
            consomme = consomme.saturating_add(pris);
            if pris == 0 {
                // La sortie était pleine ET rien n'a été consommé : impossible,
                // la sortie fait la moitié du tampon et un octet en coûte deux
                // au plus. On sort tout de même plutôt que de tourner sans fin.
                break;
            }
        }
    }
    let fin = session.finish_body(&mut etat.sortie)?;
    stream.write_all(fin).await?;
    stream.flush().await?;
    Ok(())
}

/// Accepte des connexions POP3 et les sert, jusqu'à l'arrêt demandé.
///
/// # Elle ne refuse pas de démarrer en superutilisateur
///
/// Ce n'est pas un oubli : [`crate::refuse_root`] est appelée par la boucle SMTP,
/// et un serveur qui sert les deux l'appelle une fois. L'appeler ici aussi ne
/// changerait rien, sinon donner à croire qu'on peut lancer celle-ci seule sans y
/// penser.
///
/// # Errors
///
/// Une erreur d'entrée-sortie sur l'écouteur.
pub async fn serve_pop3<A, B, S>(
    listener: tokio::net::TcpListener,
    limits: Limits,
    auth: std::sync::Arc<A>,
    boites: std::sync::Arc<B>,
    guard: std::sync::Arc<SharedGuard>,
    options: crate::ServeOptions,
    shutdown: S,
) -> Result<crate::Stats, Error>
where
    A: Authenticator + Send + Sync + 'static,
    B: Mailboxes + Send + Sync + 'static,
    B::Open: Send,
    S: core::future::Future<Output = ()>,
{
    let places = std::sync::Arc::new(tokio::sync::Semaphore::new(options.max_connections));
    let mut stats = crate::Stats::default();
    // **UN COMPTEUR PARTAGÉ**, comme celui des verdicts DKIM : chaque connexion
    // vit dans sa tâche, et son résumé ne remonte à personne. Un entier atomique
    // suffit — il n'y a rien à lire en cours de route, seulement à ajouter.
    let injections = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut arret = core::pin::pin!(shutdown);

    loop {
        let acceptee = tokio::select! {
            // `biased` : l'arrêt est examiné EN PREMIER. Un serveur qu'on ne peut
            // pas arrêter sous charge est un serveur qu'on finit par tuer.
            biased;
            () = &mut arret => return Ok(stats),
            acceptee = listener.accept() => acceptee,
        };
        let (flux, pair) = match acceptee {
            Ok(connexion) => connexion,
            Err(_) => {
                // Une acceptation qui échoue n'arrête pas le service : renoncer
                // ici offrirait l'arrêt du serveur à qui sait ouvrir puis fermer
                // assez vite.
                stats.failed = stats.failed.saturating_add(1);
                continue;
            }
        };
        stats.accepted = stats.accepted.saturating_add(1);
        stats.injections = injections.load(std::sync::atomic::Ordering::Relaxed);

        let Ok(place) = std::sync::Arc::clone(&places).acquire_owned().await else {
            return Ok(stats);
        };
        let auth = std::sync::Arc::clone(&auth);
        let boites = std::sync::Arc::clone(&boites);
        let guard = std::sync::Arc::clone(&guard);
        let timeouts = options.timeouts;
        let tls = options.tls.clone();
        let injections = std::sync::Arc::clone(&injections);

        tokio::spawn(async move {
            let mut flux = flux;
            let service = Pop3Service {
                limits,
                guard: &guard,
                timeouts,
                tls,
            };
            // L'ÉCHEC d'une connexion ne regarde qu'elle — le journal viendra
            // avec `air-log`. Une TENTATIVE D'INJECTION, en revanche, se
            // rassemble : un compte que personne ne lit est un compte qui
            // n'existe pas, et celle-là mérite d'être vue.
            let issue = serve_pop3_connection(
                &mut flux,
                &service,
                &*auth,
                &*boites,
                crate::source_de(pair),
            )
            .await;
            if issue.is_ok_and(|resume| resume.injected) {
                injections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            drop(place);
        });
    }
}
