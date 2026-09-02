//! Le pilote d'une connexion IMAP : il lit, il écrit, il ne décide de rien.
//!
//! # Ce qu'il sait du protocole : trois choses, et pas une de plus
//!
//! 1. **qu'une commande ne se découpe pas au premier `CRLF`** — c'est
//!    `ams_proto_imap::CommandReader` qui le sait, et le pilote se contente de
//!    lui redonner un tampon qui grandit ;
//! 2. qu'une réponse s'écrit telle quelle ;
//! 3. que la session lui dit quoi faire ensuite.
//!
//! Ni le vocabulaire, ni les états, ni les capacités : tout cela vit dans
//! `ams-session` et `ams-proto-imap`, c'est-à-dire dans le périmètre couvert à
//! 100 %, et n'aura pas à être réécrit pour Air.
//!
//! # LE TAMPON GRANDIT, ET IL EST BORNÉ PAR LA GRAMMAIRE
//!
//! Un pilote SMTP ou POP3 lit dans un tampon de taille fixe : une ligne y tient
//! ou ne tient pas. Une commande IMAP, elle, porte des littéraux, et sa longueur
//! n'est connue qu'en la lisant. Le tampon grandit donc au fil de l'eau — et ce
//! qui l'empêche de croître sans fin n'est pas une taille choisie ici, mais les
//! bornes du découpage : un littéral trop gros, trop de littéraux, une ligne
//! trop longue sont refusés **avant** que le moindre octet ne soit lu.
//!
//! # Une commande indécodable ferme la connexion
//!
//! Quand la syntaxe est fautive, on ne sait plus où la commande se termine.
//! Reprendre la lecture laisserait le client choisir ce qu'on lira comme une
//! commande — exactement la faille que le découpage existe pour fermer. On le
//! dit, et l'on raccroche.

use ams_guard::{Event as GuardEvent, Source, Verdict};
use ams_proto_imap::{CommandReader, Limits, Need};
use ams_session::Authenticator;
use ams_session::imap::{Action, FetchChunk, Mailboxes, Session};
use core::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio::time::Instant;

use crate::connection::lire;
use crate::{Error, SharedGuard};

/// Ce qu'un service IMAP apporte à chacune de ses connexions.
#[derive(Clone)]
pub struct ImapService<'a> {
    /// Les bornes du décodeur (C3).
    pub limits: Limits,
    /// Le garde anti-flooding (C8), partagé par toutes les connexions.
    pub guard: &'a SharedGuard,
    /// Les délais.
    pub timeouts: crate::Timeouts,
    /// De quoi chiffrer, si le service sait le faire.
    ///
    /// **Sans elle, `LOGIN` et `AUTHENTICATE` sont refusés** : la session
    /// l'impose sans réglage possible, et ce service ne servira donc personne.
    /// Un IMAP sans TLS n'est pas un IMAP dégradé, c'est un IMAP inutile — et le
    /// dire ici évite de le découvrir en production.
    pub tls: Option<std::sync::Arc<rustls::ServerConfig>>,
    /// La taille maximale d'un message déposé par `APPEND`.
    ///
    /// **Ce n'est pas la borne d'un littéral ordinaire** : celle-là dit ce
    /// qu'une connexion RETIENT, celle-ci ce qu'un message pèse. Voir
    /// `Limits::max_append_octets`.
    pub max_append_octets: u64,
}

/// Ce qu'une connexion IMAP a fait.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImapSummary {
    /// Commandes traitées.
    pub commands: u64,
    /// La session a-t-elle été chiffrée ?
    pub tls: bool,
    /// Le pair s'est-il authentifié ?
    pub authenticated: bool,
    /// Le pair était-il banni ? **Rien ne lui a alors été dit.**
    pub banned: bool,
    /// Le pair a-t-il tenté de glisser une commande derrière son `STARTTLS` ?
    ///
    /// C'est une injection (§6.2.1), et la connexion est refusée sans que la
    /// commande soit servie.
    pub injected: bool,
}

/// Sert une connexion IMAP jusqu'à sa fin.
///
/// # Errors
///
/// [`Error::Timeout`], [`Error::Io`], ou [`Error::CapabilityNotSupported`] si le
/// service annonce `STARTTLS` sans matériel TLS.
pub async fn serve_imap_connection<S, A, B>(
    stream: &mut S,
    service: &ImapService<'_>,
    auth: A,
    boites: &B,
    source: Source,
) -> Result<ImapSummary, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    A: Authenticator,
    B: Mailboxes,
{
    let mut resume = ImapSummary::default();

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
    let mut session = Session::new(service.limits, accepteur.is_some(), auth, boites);
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

    match conduire(stream, &mut session, &mut etat, service, source).await? {
        Etape::Terminee => {
            resume.merge(&etat, &session);
            return Ok(resume);
        }
        Etape::Chiffrement => {}
    }

    // Inatteignable : la session n'offre `STARTTLS` que si l'accepteur existe.
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
        // Une poignée de main ratée après un `OK` est une trame invalide au sens
        // de C8 : le pair a demandé le chiffrement, puis n'a pas su le conduire.
        Ok(Err(cause)) => {
            service.guard.observe(source, GuardEvent::InvalidFrame);
            resume.merge(&etat, &session);
            return Err(Error::Io(cause));
        }
        Err(_) => {
            service.guard.observe(source, GuardEvent::InvalidFrame);
            resume.merge(&etat, &session);
            return Err(Error::Timeout);
        }
    };
    session.on_tls_established();
    etat.tls = true;
    // §6.2.1 : tout ce qui précède est oublié, LE TAMPON COMPRIS. Ce qui restait
    // à lire a été envoyé en clair, donc peut-être par quelqu'un d'autre ; le
    // traiter après la poignée de main reviendrait à lui faire confiance.
    etat.rempli = 0;
    etat.lecteur.reset();

    let etape = conduire(&mut chiffre, &mut session, &mut etat, service, source).await?;
    debug_assert_eq!(etape, Etape::Terminee, "un second STARTTLS a été demandé");
    // `close_notify` avant de raccrocher : il dit au pair que la fin est VOULUE.
    let _ = chiffre.shutdown().await;
    resume.merge(&etat, &session);
    Ok(resume)
}

/// Ce qui survit à la montée en chiffrement.
struct Etat {
    /// Le tampon d'accumulation, qui grandit avec les littéraux.
    tampon: Vec<u8>,
    rempli: usize,
    /// De quoi lire un morceau à la fois.
    morceau: Vec<u8>,
    sortie: Vec<u8>,
    lecteur: CommandReader,
    commands: u64,
    tls: bool,
    injected: bool,
}

impl Etat {
    fn neuf(limits: &Limits) -> Self {
        Self {
            // On commence petit : la plupart des commandes tiennent sur une
            // ligne, et une connexion qui n'en envoie que de courtes ne doit pas
            // payer la place d'un littéral qu'elle n'utilisera jamais.
            tampon: Vec::with_capacity(1024),
            rempli: 0,
            morceau: vec![0_u8; 4096],
            // Deux lignes de réponse : `CAPABILITY` et `LOGOUT` en écrivent
            // chacune deux, et rien n'en écrit davantage.
            sortie: vec![
                0_u8;
                limits
                    .max_response_octets
                    .saturating_mul(2)
                    .saturating_add(64)
            ],
            lecteur: CommandReader::new(),
            commands: 0,
            tls: false,
            injected: false,
        }
    }
}

impl ImapSummary {
    fn merge<A: Authenticator, M: Mailboxes>(&mut self, etat: &Etat, session: &Session<A, M>) {
        self.commands = etat.commands;
        self.tls = etat.tls;
        self.injected = etat.injected;
        self.authenticated = session.state() != ams_session::imap::State::NotAuthenticated;
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
    session: &mut Session<A, &B>,
    etat: &mut Etat,
    service: &ImapService<'_>,
    source: Source,
) -> Result<Etape, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    A: Authenticator,
    B: Mailboxes,
{
    loop {
        // ── `APPEND` NE PASSE PAS PAR LE DÉCOUPAGE ORDINAIRE ────────────────
        //
        // C'est la seule commande dont un argument est un MESSAGE. Le découpage
        // ordinaire accumule une commande entière avant de la rendre ; pour
        // celle-ci, il accumulerait le message — et donnerait au client le droit
        // de choisir combien de mémoire le serveur consomme. On la reconnaît
        // donc AVANT, sur sa première ligne, et l'on écoule le reste.
        //
        // Ce qui n'est pas de cette forme-là — un `APPEND` sans littéral, ou
        // dont le nom de boîte EST un littéral — retombe sur le chemin
        // ordinaire, qui le refusera en le disant.
        if etat.lecteur.is_fresh()
            && let Some(fin) = fin_de_ligne(etat.tampon.get(..etat.rempli).unwrap_or_default())
        {
            // La ligne est recopiée : `deposer` a besoin du tampon en écriture,
            // et l'annonce qu'on vient d'y lire ne survivrait pas à cet emprunt.
            let ligne = etat.tampon.get(..fin).unwrap_or_default().to_vec();
            match ams_proto_imap::Append::parse(&ligne, service.max_append_octets) {
                Ok(Some(append)) => {
                    if deposer(stream, session, etat, service, source, fin, &append).await? {
                        return Ok(Etape::Terminee);
                    }
                    continue;
                }
                Ok(None) => {}
                Err(_) => {
                    // L'annonce est illisible, ou le message trop gros. On le
                    // dit et l'on raccroche : le client attend une continuation
                    // qu'on ne donnera pas, et reprendre laisserait ses octets
                    // se lire comme des commandes.
                    service.guard.observe(source, GuardEvent::InvalidFrame);
                    let adieu = session.cannot_parse(&mut etat.sortie)?;
                    stream.write_all(adieu).await?;
                    stream.flush().await?;
                    return Ok(Etape::Terminee);
                }
            }
        }

        let vu = etat.tampon.get(..etat.rempli).unwrap_or_default();
        let besoin = match etat.lecteur.poll(vu, &service.limits) {
            Ok(besoin) => besoin,
            Err(_) => {
                // ON NE SAIT PLUS OÙ LA COMMANDE SE TERMINE. On le dit, et l'on
                // raccroche : reprendre laisserait le client choisir ce qu'on
                // lira comme une commande.
                service.guard.observe(source, GuardEvent::InvalidFrame);
                let adieu = session.cannot_parse(&mut etat.sortie)?;
                stream.write_all(adieu).await?;
                stream.flush().await?;
                return Ok(Etape::Terminee);
            }
        };

        let longueur = match besoin {
            Need::More => {
                let lus = lire(stream, &mut etat.morceau, service.timeouts.command).await?;
                if lus == 0 {
                    // Le pair a raccroché sans `LOGOUT`. Rien à faire de plus :
                    // aucune boîte n'est ouverte, donc rien n'est en attente.
                    return Ok(Etape::Terminee);
                }
                etat.tampon
                    .extend_from_slice(etat.morceau.get(..lus).unwrap_or_default());
                etat.rempli = etat.rempli.saturating_add(lus);
                continue;
            }
            Need::Continuation => {
                let invite = session.literal_continuation(&mut etat.sortie)?;
                stream.write_all(invite).await?;
                stream.flush().await?;
                continue;
            }
            Need::Complete(longueur) => longueur,
        };

        let commande = etat.tampon.get(..longueur).unwrap_or_default();
        let tour = session.handle(commande, &mut etat.sortie)?;
        let action = tour.action();
        let faute = tour.peer_fault();

        // ── L'INJECTION PAR `STARTTLS` (§6.2.1) ─────────────────────────────
        //
        // Le pair a-t-il déjà envoyé autre chose derrière son `STARTTLS` ? Ces
        // octets sont arrivés EN CLAIR, donc peut-être de quelqu'un d'autre.
        //
        // **ON REFUSE PLUTÔT QUE DE JETER.** Cette boucle les jetait en silence,
        // ce que §6.2.1 demande — mais jeter laisse une attaque en cours passer
        // pour un client bavard, et le garde n'en sait rien. SMTP refusait déjà ;
        // les trois protocoles disent maintenant la même chose, et une règle de
        // sûreté écrite trois fois différemment est une règle qui finira par ne
        // plus être la même.
        if action == Action::StartTls && etat.rempli > longueur {
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

        etat.tampon.drain(..longueur.min(etat.tampon.len()));
        etat.rempli = etat.rempli.saturating_sub(longueur);
        etat.lecteur.reset();

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
            Action::ReadAuthResponse => {
                if lire_la_reponse_sasl(stream, session, etat, service, source).await? {
                    return Ok(Etape::Terminee);
                }
            }
            Action::SendFetch => {
                ecouler_le_fetch(stream, session, etat).await?;
            }
            Action::Idle => {
                if attendre(stream, session, etat, service, source).await? {
                    return Ok(Etape::Terminee);
                }
            }
            // Un `APPEND` ne passe pas par ici : sa ligne est reconnue avant le
            // découpage, et son message écoulé là-bas.
            Action::ReadAppend => return Ok(Etape::Terminee),
        }
    }
}

/// Tous les combien l'on regarde si la boîte a changé.
///
/// # POURQUOI ON REGARDE, PLUTÔT QUE D'ÊTRE PRÉVENU
///
/// Se faire prévenir demanderait `inotify` : une dépendance de plus, et un
/// descripteur de surveillance par session ouverte. Regarder coûte deux `stat` —
/// le magasin ne relit le répertoire que si l'un des deux a bougé —, ce qui est
/// bien moins qu'un descripteur qu'on ne rend jamais.
///
/// Cinq secondes : un client voit son courrier arriver dans le temps qu'il met à
/// lever les yeux, et une boîte au repos coûte deux `stat` toutes les cinq
/// secondes.
const REGARD: Duration = Duration::from_secs(5);

/// Combien de temps un `IDLE` peut durer.
///
/// RFC 2177 : le client doit le relancer au moins toutes les vingt-neuf minutes,
/// et le serveur peut le tenir pour inactif au-delà de trente. **On raccroche en
/// le disant** : une connexion qu'on abandonne sans un mot laisse le client
/// croire qu'il idle encore.
const IDLE_MAX: Duration = Duration::from_secs(30 * 60);

/// Conduit un `IDLE` : on attend, et l'on pousse ce qui change.
///
/// Rend `true` si la connexion doit se fermer.
///
/// # DEUX ATTENTES À LA FOIS, ET C'EST TOUT L'OBJET DE LA COMMANDE
///
/// Le client peut parler — `DONE` — pendant que la boîte change. Attendre l'un
/// puis l'autre ferait manquer celui qui arrive en premier ; `select!` les attend
/// ensemble. La lecture y est ANNULABLE sans perte : tokio ne consomme rien
/// tant que le futur n'a pas abouti.
async fn attendre<S, A, B>(
    stream: &mut S,
    session: &mut Session<A, &B>,
    etat: &mut Etat,
    service: &ImapService<'_>,
    source: Source,
) -> Result<bool, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    A: Authenticator,
    B: Mailboxes,
{
    let debut = Instant::now();
    loop {
        // Le client a peut-être déjà parlé : sa ligne peut être arrivée collée
        // à l'`IDLE` lui-même.
        if let Some(longueur) = fin_de_ligne(etat.tampon.get(..etat.rempli).unwrap_or_default()) {
            let ligne = etat.tampon.get(..longueur).unwrap_or_default();
            let tour = session.end_idle(ligne, &mut etat.sortie)?;
            let faute = tour.peer_fault();
            stream.write_all(tour.reply()).await?;
            stream.flush().await?;
            etat.tampon.drain(..longueur.min(etat.tampon.len()));
            etat.rempli = etat.rempli.saturating_sub(longueur);
            etat.lecteur.reset();
            let evenement = match faute {
                true => GuardEvent::InvalidFrame,
                false => GuardEvent::Command,
            };
            if matches!(
                service.guard.observe(source, evenement),
                Verdict::Throttled | Verdict::Banned { .. }
            ) {
                let refus = session.unavailable(&mut etat.sortie)?;
                stream.write_all(refus).await?;
                stream.flush().await?;
                return Ok(true);
            }
            return Ok(false);
        }

        tokio::select! {
            lus = tokio::io::AsyncReadExt::read(stream, &mut etat.morceau) => {
                let lus = lus.map_err(Error::Io)?;
                if lus == 0 {
                    // Le pair a raccroché sans `DONE`. Rien à conclure.
                    return Ok(true);
                }
                if etat.rempli.saturating_add(lus) > service.limits.max_line_octets {
                    // MÊME BORNE QU'AILLEURS : `DONE` fait quatre octets, et ce
                    // qui déborde n'est pas un `DONE`.
                    let adieu = session.cannot_parse(&mut etat.sortie)?;
                    stream.write_all(adieu).await?;
                    stream.flush().await?;
                    return Ok(true);
                }
                etat.tampon
                    .extend_from_slice(etat.morceau.get(..lus).unwrap_or_default());
                etat.rempli = etat.rempli.saturating_add(lus);
            }
            () = tokio::time::sleep(REGARD) => {
                let ecrits = session.idle_poll(&mut etat.sortie)?;
                if ecrits > 0 {
                    stream
                        .write_all(etat.sortie.get(..ecrits).unwrap_or_default())
                        .await?;
                    stream.flush().await?;
                }
                if debut.elapsed() >= IDLE_MAX {
                    let adieu = session.idle_timed_out(&mut etat.sortie)?;
                    stream.write_all(adieu).await?;
                    stream.flush().await?;
                    return Ok(true);
                }
            }
        }
    }
}

/// Où finit la première ligne du tampon, `CRLF` compris.
fn fin_de_ligne(tampon: &[u8]) -> Option<usize> {
    tampon
        .windows(2)
        .position(|paire| paire == b"\r\n")
        .map(|rang| rang.saturating_add(2))
}

/// Conduit un `APPEND` : la ligne est lue, le message va suivre.
///
/// Rend `true` si la connexion doit se fermer.
async fn deposer<S, A, B>(
    stream: &mut S,
    session: &mut Session<A, &B>,
    etat: &mut Etat,
    service: &ImapService<'_>,
    source: Source,
    fin: usize,
    append: &ams_proto_imap::Append<'_>,
) -> Result<bool, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    A: Authenticator,
    B: Mailboxes,
{
    let ligne = etat.tampon.get(..fin).unwrap_or_default().to_vec();
    let tour = session.begin_append(&ligne, append, &mut etat.sortie)?;
    let accepte = tour.action() == Action::ReadAppend;
    stream.write_all(tour.reply()).await?;
    stream.flush().await?;
    etat.commands = etat.commands.saturating_add(1);
    etat.tampon.drain(..fin.min(etat.tampon.len()));
    etat.rempli = etat.rempli.saturating_sub(fin);

    if !accepte {
        // Refusé avant d'avoir rien lu : c'est TOUT L'INTÉRÊT du littéral
        // synchronisant, et le client n'enverra rien. S'il n'était pas
        // synchronisant, ses octets arrivent quand même — mais la session a
        // déjà répondu, et le chemin ordinaire les lira comme des commandes.
        // C'est le prix d'un `{n+}` refusé, et la RFC le prévoit ainsi.
        return Ok(false);
    }
    if append.synchronizing() {
        let invite = session.literal_continuation(&mut etat.sortie)?;
        stream.write_all(invite).await?;
        stream.flush().await?;
    }

    // ── LE MESSAGE S'ÉCOULE, ET NE SÉJOURNE NULLE PART ─────────────────────
    while session.append_remaining() > 0 {
        if etat.rempli == 0 {
            let lus = lire(stream, &mut etat.morceau, service.timeouts.command).await?;
            if lus == 0 {
                // Le pair a raccroché au milieu du message : rien ne se dépose.
                let _ = session.end_append(&mut etat.sortie);
                return Ok(true);
            }
            etat.tampon
                .extend_from_slice(etat.morceau.get(..lus).unwrap_or_default());
            etat.rempli = etat.rempli.saturating_add(lus);
        }
        let disponible = etat.tampon.get(..etat.rempli).unwrap_or_default();
        let pris = session.append_chunk(disponible);
        etat.tampon.drain(..pris.min(etat.tampon.len()));
        etat.rempli = etat.rempli.saturating_sub(pris);
    }

    let tour = session.end_append(&mut etat.sortie)?;
    let faute = tour.peer_fault();
    stream.write_all(tour.reply()).await?;
    stream.flush().await?;
    let evenement = if faute {
        GuardEvent::InvalidFrame
    } else {
        GuardEvent::Command
    };
    Ok(matches!(
        service.guard.observe(source, evenement),
        Verdict::Throttled | Verdict::Banned { .. }
    ))
}

/// Écoule les réponses d'un `FETCH`.
///
/// # ON A ANNONCÉ UNE LONGUEUR, ET ON LA TIENT
///
/// Un corps est précédé d'un littéral `{n}` : le client lit exactement `n`
/// octets, puis reprend sa lecture des réponses. En écrire moins le laisserait
/// attendre, en écrire plus lui ferait lire le reste comme du protocole. Si le
/// magasin ne rend pas ce qu'il avait annoncé — un fichier qui a rétréci sous
/// nos pieds — **on complète**. Un message tronqué se voit ; un flux
/// désynchronisé se traduit en n'importe quoi.
async fn ecouler_le_fetch<S, A, B>(
    stream: &mut S,
    session: &mut Session<A, &B>,
    etat: &mut Etat,
) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    A: Authenticator,
    B: Mailboxes,
{
    while let Some(morceau) = session.next_fetch(&mut etat.sortie)? {
        match morceau {
            FetchChunk::Bytes(octets) => stream.write_all(octets).await?,
            FetchChunk::Message {
                sequence,
                offset,
                length,
            } => {
                let mut reste = length;
                let mut position = offset;
                while reste > 0 {
                    let voulu = usize::try_from(reste)
                        .unwrap_or(usize::MAX)
                        .min(etat.morceau.len());
                    let place = etat.morceau.get_mut(..voulu).unwrap_or_default();
                    let lus = session.read_selected(sequence, position, place);
                    if lus == 0 {
                        // Le magasin n'a plus rien à donner. On complète ce
                        // qu'on avait annoncé plutôt que de laisser le client
                        // attendre — voir la note ci-dessus.
                        let mut manque = reste;
                        while manque > 0 {
                            let bloc = usize::try_from(manque)
                                .unwrap_or(usize::MAX)
                                .min(etat.morceau.len());
                            let place = etat.morceau.get_mut(..bloc).unwrap_or_default();
                            place.fill(b' ');
                            stream.write_all(place).await?;
                            manque = manque.saturating_sub(bloc as u64);
                        }
                        break;
                    }
                    let ecrits = etat.morceau.get(..lus).unwrap_or_default();
                    stream.write_all(ecrits).await?;
                    position = position.saturating_add(lus as u64);
                    reste = reste.saturating_sub(lus as u64);
                }
            }
        }
    }
    stream.flush().await?;
    Ok(())
}

/// Lit la ligne qui répond à un défi SASL, et la donne à la session.
///
/// Rend `true` s'il faut fermer.
async fn lire_la_reponse_sasl<S, A, M>(
    stream: &mut S,
    session: &mut Session<A, M>,
    etat: &mut Etat,
    service: &ImapService<'_>,
    source: Source,
) -> Result<bool, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    A: Authenticator,
    M: Mailboxes,
{
    // UNE RÉPONSE SASL EST UNE LIGNE, pas une commande : elle ne porte ni tag,
    // ni littéral, et se termine au premier `CRLF`. Lui appliquer le découpage
    // des commandes lui ferait chercher une syntaxe qu'elle n'a pas.
    loop {
        let vu = etat.tampon.get(..etat.rempli).unwrap_or_default();
        if let Some(rang) = vu.windows(2).position(|paire| paire == b"\r\n") {
            let ligne = etat.tampon.get(..rang).unwrap_or_default().to_vec();
            etat.tampon
                .drain(..rang.saturating_add(2).min(etat.tampon.len()));
            etat.rempli = etat.rempli.saturating_sub(rang.saturating_add(2));
            let tour = session.on_auth_response(&ligne, &mut etat.sortie)?;
            let faute = tour.peer_fault();
            stream.write_all(tour.reply()).await?;
            stream.flush().await?;
            let evenement = if faute {
                GuardEvent::InvalidFrame
            } else {
                GuardEvent::Command
            };
            return Ok(matches!(
                service.guard.observe(source, evenement),
                Verdict::Throttled | Verdict::Banned { .. }
            ));
        }
        if vu.len() > service.limits.max_line_octets {
            // Une réponse SASL plus longue qu'une ligne de commande n'en est
            // pas une : on ferme, comme pour une commande indécodable.
            let adieu = session.cannot_parse(&mut etat.sortie)?;
            stream.write_all(adieu).await?;
            stream.flush().await?;
            return Ok(true);
        }
        let lus = lire(stream, &mut etat.morceau, service.timeouts.command).await?;
        if lus == 0 {
            return Ok(true);
        }
        etat.tampon
            .extend_from_slice(etat.morceau.get(..lus).unwrap_or_default());
        etat.rempli = etat.rempli.saturating_add(lus);
    }
}

/// Sert des connexions IMAP jusqu'à l'arrêt.
///
/// # Errors
///
/// Une erreur d'entrée-sortie sur l'écouteur.
pub async fn serve_imap<A, B, S>(
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
    B::Deposit: Send,
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
            // `biased` : l'arrêt est examiné EN PREMIER. Un serveur qu'on ne
            // peut pas arrêter sous charge est un serveur qu'on finit par tuer.
            biased;
            () = &mut arret => return Ok(stats),
            acceptee = listener.accept() => acceptee,
        };
        let (flux, pair) = match acceptee {
            Ok(connexion) => connexion,
            Err(_) => {
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
            let service = ImapService {
                limits,
                guard: &guard,
                timeouts,
                tls,
                max_append_octets: limits.max_append_octets,
            };
            // L'ÉCHEC d'une connexion ne regarde qu'elle — le journal viendra
            // avec `air-log`. Une TENTATIVE D'INJECTION, en revanche, se
            // rassemble : un compte que personne ne lit est un compte qui
            // n'existe pas, et celle-là mérite d'être vue.
            let issue = serve_imap_connection(
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
