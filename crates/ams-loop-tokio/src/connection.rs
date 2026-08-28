//! Le pilote d'une connexion : il lit, il écrit, il n'décide de rien.

use core::time::Duration;
use std::sync::Arc;

use ams_guard::{Event as GuardEvent, Source, Verdict};
use ams_proto_smtp::DataEvent;
use ams_session::{Action, Config, DataOutcome, Policy, SmtpSession};
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use crate::{Delivery, DeliveryFailure, Error, SharedGuard};

/// Combien de lignes une réponse peut compter au plus.
///
/// L'`EHLO` est la plus longue : domaine, `SIZE`, `STARTTLS`, `AUTH`.
const REPLY_LINES_MAX: usize = 4;

/// Ce que la boucle retient d'une action, une fois la ligne oubliée.
///
/// [`Action`] emprunte la ligne de commande — le mécanisme d'un `AUTH` y pointe.
/// La boucle n'en a aucun usage, et le garder l'empêcherait de réutiliser son
/// tampon de lecture. On en extrait donc ce dont elle a besoin, et rien de plus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Suite {
    /// Lire la commande suivante.
    Continuer,
    /// Fermer la connexion.
    Fermer,
    /// Lire le message.
    LireLeMessage,
    /// Conduire la poignée de main TLS, puis tout recommencer par-dessus.
    Chiffrer,
    /// Une extension que cette boucle ne sait pas conduire.
    NonServie,
}

impl Suite {
    fn depuis(action: Action<'_>) -> Self {
        match action {
            Action::Continue => Suite::Continuer,
            Action::Close => Suite::Fermer,
            Action::ReceiveData => Suite::LireLeMessage,
            Action::StartTls => Suite::Chiffrer,
            Action::BeginAuth { .. } => Suite::NonServie,
        }
    }
}

/// Les délais au-delà desquels un pair silencieux est abandonné.
///
/// # Ils appartiennent à la boucle, pas à la session
///
/// Une machine à états qui n'attend jamais n'a pas d'horloge à consulter. Le temps
/// n'existe qu'ici, à l'endroit où l'on attend vraiment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// Attente d'une ligne de commande.
    ///
    /// La RFC 5321 §4.5.3.2 recommande cinq minutes entre deux commandes.
    pub command: Duration,
    /// Attente d'un morceau de message.
    pub data: Duration,
    /// Attente de la poignée de main TLS, une fois le `220` envoyé.
    ///
    /// **Il est plus court que les autres, et c'est délibéré.** Une poignée de
    /// main est un échange fixe entre deux programmes : rien ne s'y compose, rien
    /// n'y est tapé. Sans ce délai, un pair qui dirait `STARTTLS` puis se
    /// tairait garderait une place de connexion pour toujours — un déni de
    /// service à une ligne, et gratuit.
    pub handshake: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            command: Duration::from_secs(300),
            data: Duration::from_secs(600),
            handshake: Duration::from_secs(60),
        }
    }
}

/// Comment une connexion s'est terminée.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Outcome {
    /// Servie jusqu'à son terme.
    #[default]
    Served,
    /// Le pair était banni : **rien ne lui a été dit**.
    ///
    /// Pas même une bannière. Répondre confirmerait qu'il y a un serveur ici, et
    /// le texte du refus lui apprendrait qu'il est banni plutôt que hors service
    /// — deux renseignements qu'on n'a aucune raison de lui offrir.
    Banned,
    /// Le débit du pair dépassait le seuil : il a reçu un `421` et la fermeture.
    Throttled,
    /// Le pair avait déjà envoyé autre chose derrière son `STARTTLS`.
    ///
    /// Voir [`serve_connection`] : ces octets-là ne seront jamais exécutés.
    Injected,
}

/// Ce qu'une connexion a produit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    /// Lignes de commande traitées.
    pub commands: u64,
    /// Messages remis avec succès.
    pub messages: u64,
    /// La connexion a-t-elle été chiffrée ?
    pub tls: bool,
    /// Comment elle s'est terminée.
    pub outcome: Outcome,
}

/// Ce qu'un service apporte à CHACUNE de ses connexions.
///
/// # Pourquoi une structure plutôt que des paramètres
///
/// Ces quatre-là ne varient pas d'une connexion à l'autre : ce sont les réglages
/// du service. Ce qui varie — le flux, la politique, la remise, la source — reste
/// en paramètres. La coupure n'est pas cosmétique : elle dit lesquelles de ces
/// valeurs une seconde boucle (celle d'Air) devra elle aussi recevoir telles
/// quelles.
///
/// Pas de `Debug` : le garde n'en a pas, et lui en donner un imprimerait sur
/// demande la table des sources vues — un renseignement qui n'a rien à faire
/// dans une trace.
#[derive(Clone)]
pub struct Service<'a> {
    /// Ce que la session annonce et refuse.
    pub config: Config<'a>,
    /// Le garde anti-flooding (C8), partagé par toutes les connexions.
    pub guard: &'a SharedGuard,
    /// Les délais.
    pub timeouts: Timeouts,
    /// De quoi chiffrer, si le service sait le faire.
    ///
    /// **`Some` sans `capabilities().starttls` ne chiffre jamais rien** : la
    /// session n'annonce pas l'extension, donc aucun pair ne la demande. Ce n'est
    /// pas refusé — un port de soumission implicite pourrait un jour s'en servir
    /// autrement — mais c'est un service en clair, et il vaut mieux le lire ici
    /// que le découvrir sur le fil.
    ///
    /// L'inverse, lui, est refusé : annoncer `STARTTLS` sans matériel TLS ferait
    /// mentir la bannière, et [`serve_connection`] rend alors
    /// [`Error::CapabilityNotSupported`] avant d'ouvrir la bouche.
    ///
    /// La boucle ne construit **aucun** fournisseur cryptographique : celui-ci
    /// vient de `ams-tls`, et l'appelant l'apporte tout fait. C'est ce qui garde
    /// C4 et C14 à un seul endroit du dépôt.
    pub tls: Option<Arc<ServerConfig>>,
}

/// Ce qui survit à la montée en chiffrement.
///
/// Les tampons et le résumé traversent la poignée de main ; le flux, lui, change
/// de type. C'est toute la raison d'être de cette structure.
struct Etat {
    resume: Summary,
    lecture: Vec<u8>,
    rempli: usize,
    sortie: Vec<u8>,
}

impl Etat {
    fn neuf(config: &Config<'_>) -> Self {
        // Le tampon de LECTURE est borné par la borne de commande, plus un octet :
        // quand il se remplit sans CRLF, la ligne dépasse forcément la borne, et la
        // session répond « 500 Line too long » d'elle-même. La boucle n'a donc aucune
        // décision de protocole à prendre pour cela — et rien ne peut croître sans
        // fin en attendant un CRLF qui ne vient pas.
        let capacite = config.limits().max_command_octets.saturating_add(1);
        Self {
            resume: Summary::default(),
            lecture: vec![0_u8; capacite],
            rempli: 0,
            sortie: vec![
                0_u8;
                config
                    .limits()
                    .max_reply_octets
                    .saturating_mul(REPLY_LINES_MAX)
            ],
        }
    }
}

/// Pourquoi le pilote a rendu la main.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Etape {
    /// La connexion est finie ; il n'y a plus rien à faire.
    Terminee,
    /// Le pair a demandé le chiffrement, et le `220` est parti.
    Chiffrement,
}

/// Sert une connexion jusqu'à sa fin.
///
/// # Cette fonction ne connaît aucun protocole
///
/// Elle lit des octets, les donne à la session, écrit ce que la session rend, et
/// exécute l'action demandée. Le seul « choix » qu'elle fait est de fermer quand
/// la session le dit. Tout ce qui décide vit dans `ams-session` et
/// `ams-proto-smtp`.
///
/// C'est ce qui permet d'en écrire une seconde pour Air sans rien réécrire
/// d'autre — et c'est ce que C1 achète.
///
/// # `STARTTLS` : le même pilote, deux fois, sur deux flux différents
///
/// La montée en chiffrement ne change rien à la conversation — elle change le
/// tuyau. Le pilote est donc rejoué **tel quel** au-dessus du flux TLS, avec la
/// même session, les mêmes tampons et le même résumé. La session, elle, se remet
/// à zéro (RFC 3207 §4.2) : ce qu'un pair a dit en clair ne compte plus, et il
/// doit se renommer par un nouvel `EHLO`.
///
/// # Ce qu'un pair envoie derrière son `STARTTLS` n'est JAMAIS exécuté
///
/// Un client conforme attend le `220` avant de parler (RFC 3207 §4). Celui qui
/// écrit `STARTTLS\r\nMAIL FROM:...\r\n` d'un seul trait fait autre chose : il
/// dépose des commandes en clair dans un tampon, en pariant qu'elles y seront
/// encore après la poignée de main — et qu'elles passeront alors pour siennes,
/// dites sous chiffrement. C'est la faille de 2011 (CVE-2011-0411), et elle a
/// touché à peu près tout le monde.
///
/// Ici, le tampon **n'est pas vidé en silence** : le pair reçoit un `421` à la
/// place de son `220`, la connexion se ferme sans chiffrer, et le garde en est
/// averti — c'est une trame invalide au sens de C8, parce qu'aucun client
/// honnête ne fait cela par accident.
///
/// # Un pair qui parle encore quand on ferme peut perdre la dernière réponse
///
/// Quand la connexion se ferme alors que le pair vient d'écrire, TCP jette la
/// connexion (`RST`) au lieu de la clore proprement, et ce qui restait dans le
/// tampon de réception du pair est perdu — y compris le `421` qui explique le
/// refus. Vider ce qui reste avant de fermer l'éviterait, au prix d'une place de
/// connexion tenue plus longtemps par un pair hostile. Le choix n'est pas
/// tranché ; le comportement est celui-ci, et il est écrit plutôt que découvert.
///
/// # Errors
///
/// [`Error::CapabilityNotSupported`] si `service` annonce une extension que cette
/// boucle ne sait pas conduire, ou `STARTTLS` sans matériel TLS ;
/// [`Error::Timeout`], [`Error::Io`] ou [`Error::Session`].
pub async fn serve_connection<S, P, D>(
    stream: &mut S,
    service: &Service<'_>,
    policy: P,
    delivery: &mut D,
    source: Source,
) -> Result<Summary, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    P: Policy,
    D: Delivery,
{
    // ON REFUSE AVANT DE PARLER, pas au milieu de la conversation. Annoncer une
    // extension qu'on ne sait pas conduire reviendrait à mentir au pair dès la
    // bannière — et un serveur qui annonce `STARTTLS` puis ne chiffre pas est
    // pire qu'un serveur qui ne l'annonce pas.
    let capacites = service.config.capabilities();
    if capacites.auth {
        return Err(Error::CapabilityNotSupported);
    }
    let accepteur = match (capacites.starttls, service.tls.as_ref()) {
        (true, None) => return Err(Error::CapabilityNotSupported),
        (true, Some(configuration)) => Some(TlsAcceptor::from(Arc::clone(configuration))),
        (false, _) => None,
    };

    let mut session = SmtpSession::new(service.config, policy);
    let mut etat = Etat::neuf(&service.config);

    // ON NE PARLE PAS À UN BANNI. Interroger le garde ne compte pas comme un
    // événement : demander son avis ne doit pas nourrir ses compteurs.
    if matches!(service.guard.verdict(source), Verdict::Banned { .. }) {
        etat.resume.outcome = Outcome::Banned;
        return Ok(etat.resume);
    }

    if matches!(
        service.guard.observe(source, GuardEvent::Connection),
        Verdict::Throttled | Verdict::Banned { .. }
    ) {
        // Le débit dépasse le seuil : on le dit, et on ferme. Le `421` vient de
        // la SESSION — une réponse fabriquée ici serait la première fuite de
        // protocole hors des crates sans entrée-sortie.
        let refus = session.unavailable(&mut etat.sortie)?;
        stream.write_all(refus).await?;
        stream.flush().await?;
        etat.resume.outcome = Outcome::Throttled;
        return Ok(etat.resume);
    }

    let banniere = session.greeting(&mut etat.sortie)?;
    stream.write_all(banniere).await?;
    stream.flush().await?;

    if conduire(stream, &mut session, &mut etat, service, delivery, source).await?
        == Etape::Terminee
    {
        return Ok(etat.resume);
    }

    // Inatteignable : la session n'annonce `STARTTLS` que si les capacités le
    // disent, et ce cas-là exige le matériel TLS ci-dessus. Comme pour
    // `Suite::NonServie`, on rend une erreur plutôt que de faire tomber un
    // serveur sur un `unreachable!()`.
    let Some(accepteur) = accepteur else {
        return Err(Error::CapabilityNotSupported);
    };

    let mut chiffre =
        match timeout(service.timeouts.handshake, accepteur.accept(&mut *stream)).await {
            Ok(Ok(flux)) => flux,
            // Une poignée de main qui échoue APRÈS un `220` est une trame invalide au
            // sens de C8 : le pair a demandé le chiffrement, puis n'a pas su le
            // conduire. Un client mal configuré s'en remet ; un scanner, non.
            Ok(Err(cause)) => {
                service.guard.observe(source, GuardEvent::InvalidFrame);
                return Err(Error::Io(cause));
            }
            Err(_) => {
                service.guard.observe(source, GuardEvent::InvalidFrame);
                return Err(Error::Timeout);
            }
        };

    // RFC 3207 §4.2 : le serveur DOIT oublier tout ce que le pair a dit en clair.
    // C'est la session qui le fait, pas la boucle.
    session.on_tls_established();
    etat.resume.tls = true;

    let etape = conduire(
        &mut chiffre,
        &mut session,
        &mut etat,
        service,
        delivery,
        source,
    )
    .await?;
    // La session refuse un second `STARTTLS` (`503 TLS already active`) : ce
    // second passage ne peut plus demander de chiffrement. L'affirmation est
    // vérifiée en débogage plutôt que supposée en silence.
    debug_assert_eq!(etape, Etape::Terminee, "un second STARTTLS a été demandé");

    // `close_notify` avant de raccrocher : il dit au pair que la fin est VOULUE.
    // Sans lui, une coupure et une fin propre se ressemblent, et un pair prudent
    // doit traiter la première comme une troncature possible.
    let _ = chiffre.shutdown().await;
    Ok(etat.resume)
}

/// Le pilote proprement dit : il tourne jusqu'à la fin, ou jusqu'au chiffrement.
async fn conduire<S, P, D>(
    stream: &mut S,
    session: &mut SmtpSession<'_, P>,
    etat: &mut Etat,
    service: &Service<'_>,
    delivery: &mut D,
    source: Source,
) -> Result<Etape, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    P: Policy,
    D: Delivery,
{
    let capacite = etat.lecture.len();
    loop {
        let Some(fin_ligne) = trouver_crlf(&etat.lecture[..etat.rempli]) else {
            if etat.rempli == capacite {
                // La ligne dépasse la borne. On la donne telle quelle : la
                // session la refuse et répond, puis on ferme — un pair qui envoie
                // une commande de plus de 512 octets ne se rattrapera pas.
                let tour = session.handle(&etat.lecture[..etat.rempli], &mut etat.sortie)?;
                stream.write_all(tour.reply()).await?;
                stream.flush().await?;
                // Elle a reçu une réponse : elle compte comme les autres.
                etat.resume.commands = etat.resume.commands.saturating_add(1);
                return Ok(Etape::Terminee);
            }
            let lus = lire(
                stream,
                &mut etat.lecture[etat.rempli..],
                service.timeouts.command,
            )
            .await?;
            if lus == 0 {
                // Le pair a raccroché sans `QUIT`.
                return Ok(Etape::Terminee);
            }
            etat.rempli = etat.rempli.saturating_add(lus);
            continue;
        };

        let tour = session.handle(&etat.lecture[..fin_ligne], &mut etat.sortie)?;
        let suite = Suite::depuis(tour.action());
        // C'EST LA SESSION QUI DIT CE QUI EST UNE FAUTE, pas le code de réponse :
        // `502` sanctionne un verbe retiré — une faute — comme un `EXPN` qu'on
        // décline, qui n'en est pas une.
        let faute = tour.peer_fault();

        // Le pair a-t-il déjà envoyé autre chose derrière son `STARTTLS` ? Alors
        // il n'aura pas son `220` : voir `serve_connection`.
        if suite == Suite::Chiffrer && etat.rempli > fin_ligne {
            service.guard.observe(source, GuardEvent::InvalidFrame);
            let refus = session.unavailable(&mut etat.sortie)?;
            stream.write_all(refus).await?;
            stream.flush().await?;
            etat.resume.outcome = Outcome::Injected;
            return Ok(Etape::Terminee);
        }

        stream.write_all(tour.reply()).await?;
        stream.flush().await?;
        etat.resume.commands = etat.resume.commands.saturating_add(1);

        // On décale ce qui reste : plusieurs commandes peuvent tenir dans une
        // seule lecture, et les jeter obligerait le pair à les renvoyer.
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
            // Le pair a reçu sa réponse ; il apprend maintenant que le canal se
            // ferme. L'ordre compte : répondre d'abord, refuser ensuite.
            let refus = session.unavailable(&mut etat.sortie)?;
            stream.write_all(refus).await?;
            stream.flush().await?;
            etat.resume.outcome = Outcome::Throttled;
            return Ok(Etape::Terminee);
        }

        match suite {
            Suite::Continuer => {}
            Suite::Fermer => return Ok(Etape::Terminee),
            Suite::Chiffrer => return Ok(Etape::Chiffrement),
            Suite::LireLeMessage => {
                let remis = recevoir_message(
                    stream,
                    session,
                    delivery,
                    &mut etat.lecture,
                    &mut etat.rempli,
                    &mut etat.sortie,
                    service.timeouts.data,
                )
                .await?;
                if remis {
                    etat.resume.messages = etat.resume.messages.saturating_add(1);
                }
            }
            // Inatteignable : les capacités ont été refusées à l'entrée. Cette
            // crate est de l'étage 3, hors du 100 % de C2 — c'est le seul endroit
            // du dépôt où une garde inexerçable a sa place, et elle est ici parce
            // qu'un `unreachable!()` ferait tomber un serveur.
            Suite::NonServie => return Err(Error::CapabilityNotSupported),
        }
    }
}

/// Lit le message jusqu'à sa fin, et rend `true` s'il a été remis.
async fn recevoir_message<S, P, D>(
    stream: &mut S,
    session: &mut SmtpSession<'_, P>,
    delivery: &mut D,
    lecture: &mut [u8],
    rempli: &mut usize,
    sortie: &mut [u8],
    delai: Duration,
) -> Result<bool, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    P: Policy,
    D: Delivery,
{
    let mut echec: Option<DeliveryFailure> = None;
    let mut refuse = false;
    let mut fini = false;

    while !fini {
        if *rempli == 0 {
            let lus = lire(stream, lecture, delai).await?;
            if lus == 0 {
                // Le pair a raccroché en plein message : rien n'est remis.
                delivery.abort();
                return Ok(false);
            }
            *rempli = lus;
        }
        match session.feed_data(&lecture[..*rempli]) {
            Ok((evenement, consomme)) => {
                match evenement {
                    DataEvent::Content(morceau) => {
                        // ON CONTINUE DE LIRE APRÈS UN ÉCHEC DE REMISE. S'arrêter
                        // laisserait la connexion désynchronisée, et le reste du
                        // message serait lu comme des commandes.
                        // La chaîne `&&` COURT-CIRCUITE : après un échec,
                        // `append` n'est plus appelé du tout. Un tuple
                        // `(echec, delivery.append(..))` l'appellerait encore,
                        // et continuerait d'écrire dans une remise abandonnée.
                        if echec.is_none()
                            && let Err(cause) = delivery.append(morceau)
                        {
                            echec = Some(cause);
                        }
                    }
                    DataEvent::Complete => fini = true,
                    DataEvent::NeedMore => {}
                }
                lecture.copy_within(consomme..*rempli, 0);
                *rempli = rempli.saturating_sub(consomme);
            }
            Err(ams_session::Error::DataRefused) => {
                refuse = true;
                fini = true;
            }
            Err(autre) => return Err(Error::Session(autre)),
        }
    }

    let verdict = if refuse {
        // Le verdict ne sera pas consulté : la session répond la faute. On
        // nettoie tout de même ce qui a pu être écrit.
        delivery.abort();
        DataOutcome::RejectedPermanent
    } else {
        match echec.map_or_else(|| delivery.finish(), Err) {
            Ok(()) => DataOutcome::Accepted,
            Err(DeliveryFailure::Permanent) => {
                delivery.abort();
                DataOutcome::RejectedPermanent
            }
            Err(DeliveryFailure::Temporary) => {
                delivery.abort();
                DataOutcome::RejectedTemporary
            }
        }
    };

    let tour = session.on_data_settled(verdict, sortie)?;
    stream.write_all(tour.reply()).await?;
    stream.flush().await?;
    Ok(verdict == DataOutcome::Accepted)
}

/// Lit, en abandonnant un pair qui se tait trop longtemps.
async fn lire<S: AsyncRead + Unpin>(
    stream: &mut S,
    cible: &mut [u8],
    delai: Duration,
) -> Result<usize, Error> {
    match timeout(delai, stream.read(cible)).await {
        Ok(lus) => Ok(lus?),
        Err(_) => Err(Error::Timeout),
    }
}

/// L'indice **après** le premier CRLF, s'il y en a un.
fn trouver_crlf(tampon: &[u8]) -> Option<usize> {
    tampon
        .windows(2)
        .position(|paire| paire == b"\r\n")
        .map(|at| at.saturating_add(2))
}

#[cfg(test)]
mod tests {
    use super::{Outcome, Service, Summary, Timeouts, serve_connection};
    use crate::{Delivery, DeliveryFailure, Error, SharedGuard};
    use ams_guard::{Source, Thresholds};
    use ams_proto_smtp::{Limits, Path};
    use ams_session::{Capabilities, Config, Policy, RecipientVerdict};
    use core::time::Duration;
    use tokio::io::AsyncWriteExt as _;

    /// N'accepte que ce que ce serveur héberge.
    struct NotreDomaine;

    impl Policy for NotreDomaine {
        fn accepts_recipient(&self, forward_path: &Path<'_>) -> RecipientVerdict {
            match forward_path {
                Path::Mailbox(boite) if boite.domain().as_bytes() == b"example.com" => {
                    RecipientVerdict::Accept
                }
                _ => RecipientVerdict::RelayDenied,
            }
        }
    }

    /// Une remise en mémoire, qui peut être réglée pour échouer.
    #[derive(Default)]
    struct Boite {
        recu: Vec<u8>,
        acheve: bool,
        abandonne: bool,
        echec: Option<DeliveryFailure>,
    }

    impl Delivery for Boite {
        fn append(&mut self, chunk: &[u8]) -> Result<(), DeliveryFailure> {
            if let Some(cause) = self.echec {
                return Err(cause);
            }
            self.recu.extend_from_slice(chunk);
            Ok(())
        }

        fn finish(&mut self) -> Result<(), DeliveryFailure> {
            self.acheve = true;
            Ok(())
        }

        fn abort(&mut self) {
            self.abandonne = true;
            self.recu.clear();
        }
    }

    fn config() -> Config<'static> {
        Config::new(b"mail.example.com", 100, 10_485_760, Limits::DEFAULT).expect("configurable")
    }

    const PAIR: Source = Source::V4([192, 0, 2, 1]);

    /// Un garde qui ne freine ni ne bannit personne.
    fn garde_permissif() -> SharedGuard {
        SharedGuard::new(16, Thresholds::DEFAULT)
    }

    /// Joue une conversation entière en mémoire, et rend ce que le serveur a dit.
    async fn conversation(envoi: &[u8], boite: &mut Boite) -> (Result<Summary, Error>, String) {
        conversation_avec(config(), envoi, boite).await
    }

    async fn conversation_avec(
        config: Config<'_>,
        envoi: &[u8],
        boite: &mut Boite,
    ) -> (Result<Summary, Error>, String) {
        conversation_gardee(config, envoi, boite, &garde_permissif()).await
    }

    async fn conversation_gardee(
        config: Config<'_>,
        envoi: &[u8],
        boite: &mut Boite,
        garde: &SharedGuard,
    ) -> (Result<Summary, Error>, String) {
        // `duplex` donne deux bouts de tuyau en mémoire : la conversation se joue
        // ENTIÈREMENT sans ouvrir un port, donc sans dépendre du réseau de la
        // machine de test.
        let (mut serveur, mut client) = tokio::io::duplex(4096);
        let ecriture = tokio::spawn({
            let envoi = envoi.to_vec();
            async move {
                // Le serveur peut avoir raccroché avant d'avoir tout lu — c'est
                // le cas quand il refuse de servir. Un tuyau rompu n'est pas une
                // faute du test.
                let _ = client.write_all(&envoi).await;
                let _ = client.shutdown().await;
                let mut recu = Vec::new();
                tokio::io::AsyncReadExt::read_to_end(&mut client, &mut recu)
                    .await
                    .expect("lecture");
                recu
            }
        });
        let service = Service {
            config,
            guard: garde,
            timeouts: Timeouts::default(),
            tls: None,
        };
        let resultat = serve_connection(&mut serveur, &service, NotreDomaine, boite, PAIR).await;
        drop(serveur);
        let dit = ecriture.await.expect("tâche cliente");
        (resultat, String::from_utf8_lossy(&dit).into_owned())
    }

    // ── Le cas nominal ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn une_transaction_complete_remet_le_message() {
        let mut boite = Boite::default();
        let (resume, dit) = conversation(
            b"EHLO client.example\r\n\
              MAIL FROM:<moi@ailleurs.example>\r\n\
              RCPT TO:<jean@example.com>\r\n\
              DATA\r\n\
              From: moi\r\n\r\nbonjour\r\n.\r\n\
              QUIT\r\n",
            &mut boite,
        )
        .await;

        let resume = resume.expect("connexion servie");
        assert_eq!(resume.messages, 1);
        // `EHLO`, `MAIL`, `RCPT`, `DATA`, `QUIT` : les lignes du message n'en
        // sont pas.
        assert_eq!(resume.commands, 5);
        assert_eq!(boite.recu, b"From: moi\r\n\r\nbonjour\r\n");
        assert!(boite.acheve);
        assert!(!boite.abandonne);

        assert!(dit.starts_with("220 mail.example.com ESMTP\r\n"));
        assert!(dit.contains("250 Message accepted\r\n"));
        assert!(dit.ends_with("221 Bye\r\n"));
        // Rien n'est annoncé que cette boucle ne sache conduire.
        assert!(!dit.contains("STARTTLS"));
        assert!(!dit.contains("AUTH"));
    }

    #[tokio::test]
    async fn le_relais_est_refuse_pour_un_domaine_etranger() {
        let mut boite = Boite::default();
        let (resume, dit) = conversation(
            b"EHLO client.example\r\n\
              MAIL FROM:<moi@ailleurs.example>\r\n\
              RCPT TO:<qui@ailleurs.example>\r\n\
              QUIT\r\n",
            &mut boite,
        )
        .await;
        assert_eq!(resume.expect("servie").messages, 0);
        assert!(dit.contains("550 Relay access denied\r\n"));
    }

    #[tokio::test]
    async fn plusieurs_commandes_dans_une_seule_lecture_sont_toutes_traitees() {
        // Les jeter obligerait le pair à les renvoyer.
        let mut boite = Boite::default();
        let (resume, dit) = conversation(b"NOOP\r\nNOOP\r\nNOOP\r\nQUIT\r\n", &mut boite).await;
        assert_eq!(resume.expect("servie").commands, 4);
        assert_eq!(dit.matches("250 OK\r\n").count(), 3);
    }

    #[tokio::test]
    async fn un_pair_qui_raccroche_sans_quit_est_servi_quand_meme() {
        let mut boite = Boite::default();
        let (resume, _) = conversation(b"NOOP\r\n", &mut boite).await;
        assert_eq!(resume.expect("servie").commands, 1);
    }

    // ── Ce que la boucle refuse ─────────────────────────────────────────────

    #[tokio::test]
    async fn une_capacite_non_conduite_est_refusee_avant_la_banniere() {
        // MENTIR DÈS LA BANNIÈRE serait pire que ne rien servir : un client qui
        // aurait cru l'offre `STARTTLS` attendrait un chiffrement qui ne
        // viendrait pas.
        let menteuse = config().with_capabilities(Capabilities {
            starttls: true,
            auth: false,
        });
        let mut boite = Boite::default();
        let (resultat, dit) = conversation_avec(menteuse, b"QUIT\r\n", &mut boite).await;
        assert!(matches!(resultat, Err(Error::CapabilityNotSupported)));
        assert_eq!(dit, "", "le serveur n'a pas dit un mot");
    }

    #[tokio::test]
    async fn une_ligne_trop_longue_est_refusee_puis_la_connexion_ferme() {
        let mut boite = Boite::default();
        let mut ligne = Vec::from(b"NOOP ".as_slice());
        ligne.extend(std::iter::repeat_n(b'a', 1000));
        ligne.extend_from_slice(b"\r\nNOOP\r\n");
        let (resume, dit) = conversation(&ligne, &mut boite).await;
        assert_eq!(resume.expect("servie").commands, 1);
        assert!(dit.contains("500 Line too long\r\n"));
        // La seconde commande n'a jamais été traitée.
        assert!(!dit.contains("250 OK\r\n"));
    }

    #[tokio::test]
    async fn la_contrebande_est_refusee_et_le_verdict_n_est_pas_consulte() {
        // Le message porte un LF isolé suivi de ce qui ressemble à de nouvelles
        // commandes. Rien n'est remis, et la réponse est celle de la faute.
        let mut boite = Boite::default();
        let (resume, dit) = conversation(
            b"EHLO client.example\r\n\
              MAIL FROM:<moi@ailleurs.example>\r\n\
              RCPT TO:<jean@example.com>\r\n\
              DATA\r\n\
              corps\r\n\n.\r\nMAIL FROM:<usurpe@example.com>\r\n",
            &mut boite,
        )
        .await;
        assert_eq!(resume.expect("servie").messages, 0);
        assert!(dit.contains("554 Bare CR or LF in message data\r\n"));
        assert!(boite.abandonne);
        assert!(boite.recu.is_empty());
    }

    #[tokio::test]
    async fn un_echec_de_remise_ne_desynchronise_pas_la_connexion() {
        // ON CONTINUE DE LIRE APRÈS L'ÉCHEC : s'arrêter laisserait le reste du
        // message être lu comme des commandes.
        let mut boite = Boite {
            echec: Some(DeliveryFailure::Temporary),
            ..Boite::default()
        };
        let (resume, dit) = conversation(
            b"EHLO client.example\r\n\
              MAIL FROM:<moi@ailleurs.example>\r\n\
              RCPT TO:<jean@example.com>\r\n\
              DATA\r\n\
              corps\r\n.\r\n\
              NOOP\r\n\
              QUIT\r\n",
            &mut boite,
        )
        .await;
        let resume = resume.expect("servie");
        assert_eq!(resume.messages, 0);
        assert!(dit.contains("451 Message not accepted, try again later\r\n"));
        // La connexion a suivi : le `NOOP` d'après le message a bien été traité.
        assert!(dit.contains("250 OK\r\n"));
        assert!(dit.ends_with("221 Bye\r\n"));
        assert!(boite.abandonne);
    }

    #[tokio::test]
    async fn un_pair_qui_raccroche_en_plein_message_ne_remet_rien() {
        let mut boite = Boite::default();
        let (resume, _) = conversation(
            b"EHLO client.example\r\n\
              MAIL FROM:<moi@ailleurs.example>\r\n\
              RCPT TO:<jean@example.com>\r\n\
              DATA\r\n\
              debut sans fin\r\n",
            &mut boite,
        )
        .await;
        assert_eq!(resume.expect("servie").messages, 0);
        assert!(boite.abandonne);
        assert!(!boite.acheve);
    }

    #[tokio::test]
    async fn un_pair_muet_est_abandonne() {
        let (mut serveur, _client) = tokio::io::duplex(64);
        let mut boite = Boite::default();
        let garde = garde_permissif();
        let service = Service {
            config: config(),
            guard: &garde,
            timeouts: Timeouts {
                command: Duration::from_millis(20),
                data: Duration::from_millis(20),
                handshake: Duration::from_millis(20),
            },
            tls: None,
        };
        let resultat =
            serve_connection(&mut serveur, &service, NotreDomaine, &mut boite, PAIR).await;
        assert!(matches!(resultat, Err(Error::Timeout)));
    }

    // ── Le garde ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn on_ne_dit_pas_un_mot_a_un_banni() {
        // Répondre confirmerait qu'il y a un serveur ici, et le texte du refus
        // apprendrait au pair qu'il est banni plutôt que hors service.
        let garde = SharedGuard::new(
            8,
            Thresholds {
                invalid_frames_per_minute: 0,
                ..Thresholds::DEFAULT
            },
        );
        garde.observe(PAIR, ams_guard::Event::InvalidFrame);

        let mut boite = Boite::default();
        let (resume, dit) = conversation_gardee(config(), b"QUIT\r\n", &mut boite, &garde).await;
        assert_eq!(resume.expect("servie").outcome, Outcome::Banned);
        assert_eq!(dit, "", "le serveur n'a pas dit un mot");
    }

    #[tokio::test]
    async fn un_debit_de_connexion_excessif_recoit_un_421_et_la_fermeture() {
        let garde = SharedGuard::new(
            8,
            Thresholds {
                connections_per_minute: 1,
                ..Thresholds::DEFAULT
            },
        );
        let mut boite = Boite::default();
        // La première connexion passe.
        let (premiere, _) = conversation_gardee(config(), b"QUIT\r\n", &mut boite, &garde).await;
        assert_eq!(premiere.expect("servie").outcome, Outcome::Served);
        // La seconde est refusée avant même la bannière.
        let (seconde, dit) = conversation_gardee(config(), b"QUIT\r\n", &mut boite, &garde).await;
        assert_eq!(seconde.expect("servie").outcome, Outcome::Throttled);
        assert_eq!(
            dit,
            "421 Service not available, closing transmission channel\r\n"
        );
        assert!(!dit.contains("220 "), "aucune bannière n'a été envoyée");
    }

    #[tokio::test]
    async fn les_trames_invalides_finissent_par_bannir_en_cours_de_connexion() {
        let garde = SharedGuard::new(
            8,
            Thresholds {
                invalid_frames_per_minute: 2,
                ..Thresholds::DEFAULT
            },
        );
        let mut boite = Boite::default();
        let (resume, dit) = conversation_gardee(
            config(),
            b"XYZZY\r\nXYZZY\r\nXYZZY\r\nNOOP\r\n",
            &mut boite,
            &garde,
        )
        .await;
        let resume = resume.expect("servie");
        assert_eq!(resume.outcome, Outcome::Throttled);
        // Le pair a reçu ses trois réponses, PUIS la fermeture. L'ordre compte.
        assert_eq!(dit.matches("500 Command not recognised\r\n").count(), 3);
        assert!(dit.ends_with("421 Service not available, closing transmission channel\r\n"));
        // Le `NOOP` qui suivait n'a jamais été traité.
        assert!(!dit.contains("250 OK\r\n"));
    }

    #[tokio::test]
    async fn les_refus_legitimes_ne_bannissent_personne() {
        // UN EXPÉDITEUR QUI SE TROMPE D'ADRESSE N'EST PAS UN ATTAQUANT. Vingt
        // destinataires refusés, sous un seuil de deux trames invalides.
        let garde = SharedGuard::new(
            8,
            Thresholds {
                invalid_frames_per_minute: 2,
                ..Thresholds::DEFAULT
            },
        );
        let mut envoi =
            Vec::from(b"EHLO client.example\r\nMAIL FROM:<moi@ailleurs.example>\r\n".as_slice());
        for _ in 0..20 {
            envoi.extend_from_slice(b"RCPT TO:<qui@ailleurs.example>\r\n");
        }
        envoi.extend_from_slice(b"QUIT\r\n");

        let mut boite = Boite::default();
        let (resume, dit) = conversation_gardee(config(), &envoi, &mut boite, &garde).await;
        assert_eq!(resume.expect("servie").outcome, Outcome::Served);
        assert_eq!(dit.matches("550 Relay access denied\r\n").count(), 20);
        assert!(dit.ends_with("221 Bye\r\n"));
    }

    #[tokio::test]
    async fn le_garde_partage_survit_aux_connexions() {
        // C'est tout l'intérêt : ce qu'une connexion a appris sert à la suivante.
        let garde = SharedGuard::new(
            8,
            Thresholds {
                invalid_frames_per_minute: 1,
                ..Thresholds::DEFAULT
            },
        );
        let mut boite = Boite::default();
        let (premiere, _) =
            conversation_gardee(config(), b"XYZZY\r\nXYZZY\r\n", &mut boite, &garde).await;
        assert_eq!(premiere.expect("servie").outcome, Outcome::Throttled);
        assert_eq!(garde.tracked(), 1);

        let (seconde, dit) = conversation_gardee(config(), b"NOOP\r\n", &mut boite, &garde).await;
        assert_eq!(seconde.expect("servie").outcome, Outcome::Banned);
        assert_eq!(dit, "");
    }

    #[test]
    fn les_delais_par_defaut_suivent_la_rfc() {
        // RFC 5321 §4.5.3.2 : cinq minutes entre deux commandes.
        let defaut = Timeouts::default();
        assert_eq!(defaut.command, Duration::from_secs(300));
        assert!(defaut.data > defaut.command);
        // La poignée de main est plus courte que l'attente d'une commande, et
        // c'est le sens même du réglage : rien ne s'y compose, rien n'y est tapé.
        assert!(defaut.handshake < defaut.command);
        assert!(!format!("{defaut:?}").is_empty());
        assert_eq!(
            Summary::default(),
            Summary {
                commands: 0,
                messages: 0,
                tls: false,
                outcome: Outcome::Served,
            }
        );
    }
}
