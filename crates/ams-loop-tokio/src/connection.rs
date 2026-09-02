//! Le pilote d'une connexion : il lit, il écrit, il n'décide de rien.

use core::time::Duration;
use std::sync::Arc;

use ams_guard::{Event as GuardEvent, Source, Verdict};
use ams_mime::{AUTHRES_RESERVE, RECEIVED_MAX};
use ams_proto_smtp::{ChunkEvent, DataEvent};
use ams_session::{
    Action, Config, DataOutcome, Identity as SpfIdentity, Policy, RECEIVED_SPF_MAX, SenderPolicy,
    SmtpSession,
};
use ams_spf::Verdict as SpfVerdict;
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use crate::dkim::{DkimChecker, DkimStream, DkimVerdict};
use crate::dmarc::{Authenticated, DmarcChecker, DmarcResult, DmarcVerdict};
use crate::reports::{FailureObservation, Observation, ReportSpool, SignatureVue, SpfVu};
use crate::{Delivery, DeliveryFailure, Error, SenderChecker, SharedGuard};
use ams_dmarc::Policy as DmarcPolicy;
use ams_dmarc::Verdict as DmarcVerdict2;
use ams_dmarc::report::aggregate::{DkimAuthResult, SpfAuthResult, SpfScope};
use std::string::String;

/// Combien de lignes une réponse peut compter au plus.
///
/// L'`EHLO` est la plus longue : domaine, `SIZE`, `STARTTLS`, `AUTH`.
const REPLY_LINES_MAX: usize = 4;

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
    /// Le pair s'est-il authentifié ?
    pub authenticated: bool,
    /// Comment elle s'est terminée.
    pub outcome: Outcome,
    /// Ce que les signatures DKIM ont donné.
    pub dkim: DkimTally,
    /// Ce que DMARC a conclu.
    pub dmarc: DmarcTally,
}

/// Le compte des verdicts DMARC d'une connexion.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DmarcTally {
    /// Messages dont un mécanisme s'alignait.
    pub pass: u32,
    /// Messages dont aucun ne s'alignait.
    pub fail: u32,
    /// Domaines qui ne publient pas de politique.
    pub no_policy: u32,
    /// Politiques qu'on n'a pas pu résoudre.
    pub temp_error: u32,
    /// Messages dont le `From:` est illisible ou multiple.
    pub unusable: u32,
    /// Messages auxquels la politique a été **appliquée**.
    pub applied: u32,
}

/// Le compte des verdicts DKIM d'une connexion.
///
/// # Un compte, et pas la liste
///
/// Le résumé d'une connexion est `Copy` — il traverse la boucle sans allouer —
/// et une liste de domaines ne l'est pas. Ce qu'un journal veut à ce niveau,
/// c'est de savoir COMBIEN ; ce que DMARC voudra, ce sont les résultats
/// eux-mêmes, et il les prendra là où ils sont produits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DkimTally {
    /// Signatures vraies.
    pub pass: u32,
    /// Signatures fausses. **Ce n'est pas « messages faux »** : une liste de
    /// diffusion qui ajoute un pied de page casse une signature honnête.
    pub fail: u32,
    /// Clés qu'on n'a pas pu résoudre.
    pub temp_error: u32,
    /// Signatures, clés ou algorithmes irrecevables.
    pub perm_error: u32,
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
    /// De quoi vérifier l'expéditeur (C9), si le service sait le faire.
    ///
    /// **`None` avec une politique d'expéditeur qui n'est pas
    /// [`SenderPolicy::Ignore`] fait échouer l'ouverture** : la session
    /// demanderait une vérification que personne ne conduirait, et attendrait
    /// une réponse qui ne viendrait pas. Le dire au démarrage vaut mieux que de
    /// le découvrir sur le premier `MAIL FROM:`.
    pub spf: Option<SenderChecker>,
    /// De quoi vérifier les signatures DKIM (C9), si le service sait le faire.
    ///
    /// `None` ne refuse rien : DKIM ne décide d'aucun message, et un service qui
    /// ne le vérifie pas sert exactement comme avant. C'est la différence avec
    /// [`Service::spf`], dont la session ATTEND une réponse.
    pub dkim: Option<DkimChecker>,
    /// De quoi évaluer DMARC (C9), si le service sait le faire.
    ///
    /// **C'est le seul de ces trois-là qui peut REFUSER un message** — et
    /// seulement quand le domaine du `From:` le demande.
    pub dmarc: Option<DmarcChecker>,
    /// Où consigner ce qu'on rapportera aux domaines qui le demandent.
    ///
    /// `None` ne refuse rien et ne change aucun verdict : un serveur qui ne
    /// rapporte pas sert exactement comme avant. Il laisse simplement les
    /// domaines qu'il protège durcir leur politique à l'aveugle.
    pub reports: Option<Arc<ReportSpool>>,
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
    /// Le message qui arrive par morceaux, s'il y en a un.
    ///
    /// # POURQUOI IL VIT ICI ET NON DANS UNE VARIABLE LOCALE
    ///
    /// Un message de `DATA` tient dans un appel : on ouvre la remise, on lit
    /// jusqu'au point, on conclut. Un message de `BDAT` traverse PLUSIEURS
    /// commandes — un appel par morceau — et ce qui s'accumule entre eux (la
    /// remise ouverte, le condensat DKIM en cours, un échec déjà survenu) ne
    /// peut pas vivre sur la pile de l'un d'eux.
    message: Option<EnCours>,
}

/// Ce qu'un message accumule pendant qu'il arrive.
struct EnCours {
    /// La remise a-t-elle échoué, et comment ?
    ///
    /// **Un échec n'arrête pas la lecture** : les octets sont annoncés, et ne
    /// pas les consommer laisserait la queue du morceau se faire lire comme des
    /// commandes.
    echec: Option<DeliveryFailure>,
    /// La grammaire a-t-elle refusé le message ?
    refuse: bool,
    /// Le suivi DKIM, quand il y a quelque chose à vérifier.
    flux: Option<DkimStream>,
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
            message: None,
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
    // `AUTH` ne figure plus ici : la boucle sait le conduire, parce qu'elle n'a
    // rien à en connaître — c'est la session qui décode, lit et tranche. Seul
    // `STARTTLS` exige encore quelque chose d'elle : du matériel TLS.
    // Même règle pour SPF : une session qui réclamerait une vérification que
    // personne ne conduit attendrait une réponse qui ne vient pas.
    if service.config.sender_policy() != SenderPolicy::Ignore && service.spf.is_none() {
        return Err(Error::CapabilityNotSupported);
    }
    let capacites = service.config.capabilities();
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
    // La ligne SUIVANTE est-elle une réponse SASL plutôt qu'une commande ?
    // C'est tout ce que la boucle sait de l'authentification : ni base64, ni
    // format de `PLAIN`, ni annulation par `*`.
    let mut reponse_sasl_attendue = false;
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

        let tour = if reponse_sasl_attendue {
            reponse_sasl_attendue = false;
            // SANS le `CRLF` : c'est la couche qui encadre les lignes qui les
            // décadre, et elle vient justement de le trouver. `handle`, lui,
            // reçoit la ligne entière parce que la grammaire des commandes
            // VALIDE cet encadrement (le contrebandage SMTP se joue là).
            let fin_utile = fin_ligne.saturating_sub(2);
            session.feed_auth(&etat.lecture[..fin_utile], &mut etat.sortie)?
        } else {
            session.handle(&etat.lecture[..fin_ligne], &mut etat.sortie)?
        };
        let action = tour.action();
        // Le résumé porte l'état de la SESSION, pas une déduction de la boucle —
        // et il est relevé AVANT le `match`, dont plusieurs bras rendent la main.
        // Le relever après en aurait perdu la dernière valeur sur un `QUIT`.
        etat.resume.authenticated = session.is_authenticated();
        // C'EST LA SESSION QUI DIT CE QUI EST UNE FAUTE, pas le code de réponse :
        // `502` sanctionne un verbe retiré — une faute — comme un `EXPN` qu'on
        // décline, qui n'en est pas une.
        let faute = tour.peer_fault();
        let refus_de_destinataire = tour.refused_recipient();

        // Le pair a-t-il déjà envoyé autre chose derrière son `STARTTLS` ? Alors
        // il n'aura pas son `220` : voir `serve_connection`.
        if action == Action::StartTls && etat.rempli > fin_ligne {
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

        // **TROIS ÉVÉNEMENTS, ET LE PLUS GRAVE L'EMPORTE.** Un refus de
        // destinataire est aussi une commande ; le compter comme telle SEULEMENT
        // ferait qu'une récolte passerait sous le seuil des commandes, qui est
        // dix fois plus haut. Une faute reste au-dessus de tout : c'est le seul
        // des trois qui dise que le pair a mal parlé.
        let evenement = match (faute, refus_de_destinataire) {
            (true, _) => GuardEvent::InvalidFrame,
            (false, true) => GuardEvent::RefusedRecipient,
            (false, false) => GuardEvent::Command,
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

        match action {
            Action::Continue => {}
            Action::Close => return Ok(Etape::Terminee),
            // La session ne peut pas répondre seule au `MAIL FROM:` : SPF veut
            // le DNS. On résout, on lui rend le verdict, et C'EST ELLE qui
            // compose la réponse — le vocabulaire de sortie reste clos.
            Action::CheckSender => {
                let verdict = verifier_l_expediteur(service, session, source).await;
                let tour = session.sender_checked(verdict, &mut etat.sortie)?;
                stream.write_all(tour.reply()).await?;
                stream.flush().await?;
                if tour.action() == Action::Close {
                    return Ok(Etape::Terminee);
                }
            }
            Action::StartTls => return Ok(Etape::Chiffrement),
            // La session vient de poser son défi ; la ligne suivante y répond.
            Action::ReadAuthResponse => reponse_sasl_attendue = true,
            Action::ReceiveData => {
                let remis =
                    recevoir_message(stream, session, delivery, etat, service, source).await?;
                if remis {
                    etat.resume.messages = etat.resume.messages.saturating_add(1);
                }
            }
            Action::ReceiveChunk { size, last } => {
                let remis =
                    recevoir_morceau(stream, session, delivery, etat, service, source, size, last)
                        .await?;
                if remis {
                    etat.resume.messages = etat.resume.messages.saturating_add(1);
                }
            }
        }
    }
}

/// Ouvre la remise d'un message : les destinataires, la place réservée, la trace
/// SPF.
///
/// # ELLE N'A LIEU QU'UNE FOIS PAR MESSAGE, ET NON PAR MORCEAU
///
/// Un message de `BDAT` arrive en plusieurs commandes. Refaire ceci à chaque
/// morceau rouvrirait la remise — donc écrirait le message une fois par
/// morceau — et poserait autant d'en-têtes `Received-SPF` que de morceaux.
fn ouvrir_le_message<P, D>(
    session: &mut SmtpSession<'_, P>,
    delivery: &mut D,
    service: &Service<'_>,
    source: Source,
) -> EnCours
where
    P: Policy,
    D: Delivery,
{
    // LES DESTINATAIRES D'ABORD, et c'est la session qui les fournit. La boucle
    // ne voit pas les `RCPT` — elle ne connaît aucun protocole — et ne les garde
    // pas : une liste tenue ici survivrait au `RSET` qu'elle ne voit pas non
    // plus, et livrerait le message suivant aux destinataires du précédent.
    //
    // LE CHEMIN DE RETOUR D'ABORD, parce qu'il vaut pour la transaction entière
    // et non pour un destinataire : c'est à lui qu'un rapport de non-remise
    // reviendra, et une remise qui l'apprendrait après coup aurait déjà écrit
    // une entrée de file sans savoir à qui rendre compte.
    delivery.begin(session.return_path());
    // **LA PLACE DE L'EN-TÊTE `Authentication-Results` SE RÉSERVE ICI**, avant
    // le premier octet. DKIM ne se juge qu'une fois le corps entier lu, et DMARC
    // en dépend : le verdict arrivera bien après. Voir `Delivery::reserve_trace`,
    // qui dit pourquoi on réserve plutôt que de rassembler le message.
    delivery.reserve_trace(AUTHRES_RESERVE);
    let mut echec: Option<DeliveryFailure> = None;
    for adresse in session.recipients() {
        if let Err(cause) = delivery.add_recipient(adresse) {
            echec = Some(cause);
            break;
        }
    }
    // ── L'EN-TÊTE `Received:` (RFC 5321 §4.4) ───────────────────────────────
    //
    // **C'EST LE SEUL EN-TÊTE QUE LA NORME EXIGE D'AJOUTER**, et il vient AVANT
    // les deux autres : un lecteur qui remonte un chemin lit les traces de haut
    // en bas, la plus récente d'abord, et c'est celle-ci qui date le saut.
    //
    // La session le compose — la boucle ne fabrique aucun texte de protocole —
    // et n'apporte que ce qu'elle seule sait : l'adresse du pair, et l'heure.
    // Une session ne lit pas d'horloge (C1).
    let mut trace_recue = [0_u8; RECEIVED_MAX];
    if echec.is_none()
        && let Some(trace) =
            session.received(adresse_du_pair(source), maintenant(), &mut trace_recue)
        && let Err(cause) = delivery.append(trace)
    {
        echec = Some(cause);
    }

    // ── L'EN-TÊTE `Received-SPF` (RFC 7208 §9.1) ────────────────────────────
    //
    // AVANT le premier octet du message : un en-tête de trace se pose EN TÊTE,
    // et l'écrire après les en-têtes du pair le mettrait dans le corps, où
    // personne ne le lirait. La session le compose — la boucle ne fabrique
    // aucun texte de protocole — et n'apporte ici que ce qu'elle seule sait :
    // l'adresse du pair.
    //
    // Rien n'est écrit quand rien n'a été vérifié : un en-tête qui dirait
    // `none` sans qu'aucune résolution ait eu lieu mentirait sur ce qu'on a
    // fait.
    let mut entete = [0_u8; RECEIVED_SPF_MAX];
    if echec.is_none()
        && let Some(trace) = session.received_spf(adresse_du_pair(source), &mut entete)
        && let Err(cause) = delivery.append(trace)
    {
        echec = Some(cause);
    }
    // La vérification DKIM (C9) suit le message OCTET PAR OCTET : son condensat
    // porte sur le corps entier, et rassembler celui-ci laisserait le pair
    // choisir combien de mémoire on lui consacre. DMARC, lui, n'a besoin que du
    // bloc d'en-tête — mais il en a besoin même quand DKIM n'est pas vérifié.
    let suivre = service.dkim.is_some() || service.dmarc.is_some();
    EnCours {
        echec,
        refuse: false,
        flux: suivre.then(|| DkimStream::new(service.dkim.is_some())),
    }
}

/// Le nombre de secondes depuis l'époque.
///
/// Une horloge d'avant 1970 rendrait zéro : une date à l'époque se remarque, là
/// où une soustraction qui déborde ne se remarquerait pas.
fn maintenant() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |ecoule| ecoule.as_secs())
}

/// Le verdict SPF, dans les mots de RFC 8601.
fn resultat_spf(verdict: SpfVerdict) -> ams_mime::SpfResult {
    match verdict {
        SpfVerdict::None => ams_mime::SpfResult::None,
        SpfVerdict::Neutral => ams_mime::SpfResult::Neutral,
        SpfVerdict::Pass => ams_mime::SpfResult::Pass,
        SpfVerdict::Fail => ams_mime::SpfResult::Fail,
        SpfVerdict::SoftFail => ams_mime::SpfResult::SoftFail,
        SpfVerdict::TempError => ams_mime::SpfResult::TempError,
        SpfVerdict::PermError => ams_mime::SpfResult::PermError,
    }
}

/// Le verdict DMARC, dans les mots de RFC 8601.
///
/// **AUCUN FOURRE-TOUT** : chaque verdict a son mot. Un `_` qui rendrait `pass`
/// écrirait, le jour où un verdict s'ajoute, que le message est aligné alors
/// qu'on n'en sait rien — et c'est exactement le genre de mensonge que cet
/// en-tête ne peut pas se permettre, puisqu'il est écrit sous notre nom.
fn resultat_dmarc(verdict: DmarcVerdict) -> ams_mime::DmarcResult {
    match verdict {
        DmarcVerdict::Pass => ams_mime::DmarcResult::Pass,
        DmarcVerdict::Fail => ams_mime::DmarcResult::Fail,
        DmarcVerdict::TempError => ams_mime::DmarcResult::TempError,
        // Pas de politique lisible : il n'y a rien à dire de ce domaine.
        DmarcVerdict::NoPolicy => ams_mime::DmarcResult::None,
        // Une politique qu'on a lue sans pouvoir s'en servir est un défaut
        // PERMANENT de ce que le domaine publie, et non un aléa de réseau.
        DmarcVerdict::Unusable => ams_mime::DmarcResult::PermError,
    }
}

/// Ce qu'une signature DKIM devient dans un rapport (§7.2, `DKIMResultType`).
fn resultat_dkim(verdict: DkimVerdict) -> DkimAuthResult {
    match verdict {
        DkimVerdict::Pass => DkimAuthResult::Pass,
        DkimVerdict::Fail => DkimAuthResult::Fail,
        DkimVerdict::TempError => DkimAuthResult::TempError,
        DkimVerdict::PermError => DkimAuthResult::PermError,
    }
}

/// Ce que SPF devient dans un rapport (§7.2, `SPFResultType`).
///
/// **Sans verdict, on écrit `none`** : c'est le mot de la RFC 7208 §2.6 pour
/// « rien n'a été évalué », et c'est exactement la situation d'un serveur qui ne
/// vérifie pas l'expéditeur. Écrire autre chose ferait dire au rapport une
/// évaluation qui n'a pas eu lieu.
fn spf_vu<P: Policy>(session: &SmtpSession<'_, P>) -> SpfVu {
    let identite = session.sender_identity();
    SpfVu {
        domain: identite
            .map(|vue| String::from_utf8_lossy(vue.domain).into_owned())
            .unwrap_or_default(),
        scope: match identite.map(|vue| vue.scope) {
            Some(SpfIdentity::Helo) => SpfScope::Helo,
            _ => SpfScope::MailFrom,
        },
        result: match session.sender_verdict() {
            Some(SpfVerdict::Pass) => SpfAuthResult::Pass,
            Some(SpfVerdict::Fail) => SpfAuthResult::Fail,
            Some(SpfVerdict::SoftFail) => SpfAuthResult::SoftFail,
            Some(SpfVerdict::Neutral) => SpfAuthResult::Neutral,
            Some(SpfVerdict::TempError) => SpfAuthResult::TempError,
            Some(SpfVerdict::PermError) => SpfAuthResult::PermError,
            Some(SpfVerdict::None) | None => SpfAuthResult::None,
        },
    }
}

/// Verse un verdict DMARC dans le compte d'une connexion.
fn compter_dmarc(compte: DmarcTally, resultat: &DmarcResult) -> DmarcTally {
    let mut compte = compte;
    match resultat.verdict {
        DmarcVerdict::Pass => compte.pass = compte.pass.saturating_add(1),
        DmarcVerdict::Fail => compte.fail = compte.fail.saturating_add(1),
        DmarcVerdict::NoPolicy => compte.no_policy = compte.no_policy.saturating_add(1),
        DmarcVerdict::TempError => compte.temp_error = compte.temp_error.saturating_add(1),
        DmarcVerdict::Unusable => compte.unusable = compte.unusable.saturating_add(1),
    }
    if resultat.applies {
        compte.applied = compte.applied.saturating_add(1);
    }
    compte
}

/// Conduit la vérification de l'expéditeur, et rend son verdict.
async fn verifier_l_expediteur<P: Policy>(
    service: &Service<'_>,
    session: &SmtpSession<'_, P>,
    source: Source,
) -> SpfVerdict {
    match (service.spf.as_ref(), session.sender_identity()) {
        (Some(verificateur), Some(identite)) => {
            verificateur
                .verdict(adresse_du_pair(source), &identite)
                .await
        }
        // Refusé à l'ouverture — la session ne demande une vérification que si
        // quelqu'un a déclaré savoir la conduire. Si l'impossible arrivait, ON
        // AJOURNE : un message ajourné revient, un message accepté en silence
        // aurait franchi une vérification qui n'a pas eu lieu.
        _ => SpfVerdict::TempError,
    }
}

/// L'adresse exacte du pair.
///
/// **Pas celle que le garde compte** : il replie les sources sur un préfixe
/// (`/64` en IPv6), et SPF compare des adresses. Vérifier sur une adresse
/// repliée autoriserait tout un bloc pour ce qu'une seule machine a le droit
/// d'émettre.
fn adresse_du_pair(source: Source) -> std::net::IpAddr {
    match source {
        Source::V4(octets) => std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)),
        Source::V6(octets) => std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)),
    }
}

/// Lit le message jusqu'à sa fin, et rend `true` s'il a été remis.
async fn recevoir_message<S, P, D>(
    stream: &mut S,
    session: &mut SmtpSession<'_, P>,
    delivery: &mut D,
    etat: &mut Etat,
    service: &Service<'_>,
    source: Source,
) -> Result<bool, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    P: Policy,
    D: Delivery,
{
    // LES DESTINATAIRES D'ABORD, et c'est la session qui les fournit. La boucle
    // ne voit pas les `RCPT` — elle ne connaît aucun protocole — et ne les garde
    // pas : une liste tenue ici survivrait au `RSET` qu'elle ne voit pas non
    // plus, et livrerait le message suivant aux destinataires du précédent.
    //
    // LE CHEMIN DE RETOUR D'ABORD, parce qu'il vaut pour la transaction entière
    // et non pour un destinataire : c'est à lui qu'un rapport de non-remise
    // reviendra, et une remise qui l'apprendrait après coup aurait déjà écrit
    // une entrée de file sans savoir à qui rendre compte.
    let mut en_cours = ouvrir_le_message(session, delivery, service, source);
    let mut fini = false;

    while !fini {
        if etat.rempli == 0 {
            let lus = lire(stream, &mut etat.lecture, service.timeouts.data).await?;
            if lus == 0 {
                // Le pair a raccroché en plein message : rien n'est remis.
                delivery.abort();
                return Ok(false);
            }
            etat.rempli = lus;
        }
        match session.feed_data(&etat.lecture[..etat.rempli]) {
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
                        if let Some(lecture) = en_cours.flux.as_mut() {
                            lecture.update(morceau);
                        }
                        if en_cours.echec.is_none()
                            && let Err(cause) = delivery.append(morceau)
                        {
                            en_cours.echec = Some(cause);
                        }
                    }
                    DataEvent::Complete => fini = true,
                    DataEvent::NeedMore => {}
                }
                etat.lecture.copy_within(consomme..etat.rempli, 0);
                etat.rempli = etat.rempli.saturating_sub(consomme);
            }
            Err(ams_session::Error::DataRefused) => {
                en_cours.refuse = true;
                fini = true;
            }
            Err(autre) => return Err(Error::Session(autre)),
        }
    }

    conclure_le_message(stream, session, delivery, etat, service, source, en_cours).await
}

/// Lit **exactement** les octets qu'un `BDAT` a annoncés (RFC 3030 §2).
///
/// # ON LES LIT TOUS, MÊME QUAND ON N'EN VEUT PLUS
///
/// C'est la règle qui tient toute cette fonction. Les octets sont ANNONCÉS :
/// ils arriveront, quoi qu'on décide de leur contenu. En cesser la lecture
/// laisserait la queue du morceau dans la socket, et la commande suivante
/// commencerait au milieu du message — c'est-à-dire que le pair choisirait ce
/// que nous lisons comme des commandes. La contrebande, par l'autre porte.
///
/// Un refus se retient donc, et ne s'arrête pas.
///
/// # ET LA CONCLUSION N'A LIEU QU'AU DERNIER
///
/// Les morceaux précédents nourrissent le condensat DKIM et la remise, puis
/// rendent un `250`. Seul celui qui porte `LAST` fait juger le message.
#[expect(
    clippy::too_many_arguments,
    reason = "chaque argument est une pièce distincte du service ; les grouper \
              dans une structure n'ajouterait qu'un nom à retenir"
)]
async fn recevoir_morceau<S, P, D>(
    stream: &mut S,
    session: &mut SmtpSession<'_, P>,
    delivery: &mut D,
    etat: &mut Etat,
    service: &Service<'_>,
    source: Source,
    size: u64,
    last: bool,
) -> Result<bool, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    P: Policy,
    D: Delivery,
{
    // **LE PREMIER MORCEAU OUVRE LE MESSAGE, LES SUIVANTS LE CONTINUENT.** Le
    // rouvrir à chaque morceau écrirait le message une fois par morceau, et
    // poserait autant d'en-têtes `Received-SPF`.
    let mut en_cours = match etat.message.take() {
        Some(deja) => deja,
        None => ouvrir_le_message(session, delivery, service, source),
    };
    let mut reste = size;

    while reste > 0 {
        if etat.rempli == 0 {
            let lus = lire(stream, &mut etat.lecture, service.timeouts.data).await?;
            if lus == 0 {
                // Le pair a raccroché en plein morceau : rien n'est remis, et il
                // n'y a personne à qui répondre.
                delivery.abort();
                return Ok(false);
            }
            etat.rempli = lus;
        }
        // ON NE DONNE À LA SESSION QUE CE QUI APPARTIENT AU MORCEAU. Ce qui
        // suit est une COMMANDE, et le lui donner reviendrait à la lui faire
        // avaler comme des données.
        let dispo = usize::try_from(reste)
            .unwrap_or(usize::MAX)
            .min(etat.rempli);
        let (evenement, consomme) =
            session.feed_chunk(etat.lecture.get(..dispo).unwrap_or_default())?;
        if let ChunkEvent::Content(morceau) = evenement {
            if let Some(lecture) = en_cours.flux.as_mut() {
                lecture.update(morceau);
            }
            if en_cours.echec.is_none()
                && let Err(cause) = delivery.append(morceau)
            {
                en_cours.echec = Some(cause);
            }
        }
        reste = reste.saturating_sub(consomme as u64);
        etat.lecture.copy_within(consomme..etat.rempli, 0);
        etat.rempli = etat.rempli.saturating_sub(consomme);
    }
    // Le morceau est consommé jusqu'au dernier octet annoncé ; on le dit à la
    // session, qui saura si la grammaire l'a refusé.
    let (evenement, _) = session.feed_chunk(&[])?;
    if evenement != ChunkEvent::Complete && last {
        // Un dernier morceau qui ne conclut pas est un message refusé — un `CR`
        // pendant, par exemple. La session le sait déjà.
        en_cours.refuse = true;
    }

    if !last {
        etat.message = Some(en_cours);
        let tour = session.on_chunk_received(&mut etat.sortie)?;
        stream.write_all(tour.reply()).await?;
        stream.flush().await?;
        return Ok(false);
    }
    conclure_le_message(stream, session, delivery, etat, service, source, en_cours).await
}

/// Conclut un message : les vérifications, l'en-tête de trace, la remise, et la
/// réponse.
///
/// # ELLE N'A LIEU QU'UNE FOIS PAR MESSAGE, ET NON PAR MORCEAU
///
/// DKIM ne se juge qu'une fois le corps entier lu — son condensat porte
/// dessus — et DMARC en dépend. Un message de `BDAT` n'est donc jugé qu'au
/// morceau marqué `LAST`, et les précédents ne font que nourrir le condensat.
async fn conclure_le_message<S, P, D>(
    stream: &mut S,
    session: &mut SmtpSession<'_, P>,
    delivery: &mut D,
    etat: &mut Etat,
    service: &Service<'_>,
    source: Source,
    en_cours: EnCours,
) -> Result<bool, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    P: Policy,
    D: Delivery,
{
    let EnCours {
        echec,
        refuse,
        flux,
    } = en_cours;
    // ON NE VÉRIFIE PAS CE QU'ON REFUSE. Chaque signature coûte une résolution
    // DNS et une exponentiation modulaire ; les dépenser pour un message qu'on
    // jette offrirait à un pair de faire travailler la machine sans rien livrer.
    let mut usurpe = false;
    // Ce que l'en-tête `Authentication-Results` dira. Les trois se remplissent
    // au fil des vérifications, et rien n'est écrit qui n'ait été mesuré.
    let mut dkim_vus: Vec<(ams_mime::DkimResult, String, String)> = Vec::new();
    let mut dmarc_vu: Option<(ams_mime::DmarcResult, String)> = None;
    if !refuse
        && echec.is_none()
        && let Some(mut lecture) = flux
    {
        let mut authentifies = Authenticated::default();
        // CE QUE LES SIGNATURES ONT DONNÉ, TOUTES, et pas seulement les vraies :
        // un rapport qui ne nommerait que les signatures réussies cacherait au
        // domaine le prestataire dont la clé a expiré — c'est-à-dire exactement
        // ce qu'il cherche à apprendre.
        let mut vues: Vec<SignatureVue> = Vec::new();
        if let Some(verificateur) = service.dkim.as_ref() {
            for resultat in lecture.finish(verificateur).await {
                vues.push(SignatureVue {
                    domain: resultat.domain.clone(),
                    selector: resultat.selector.clone(),
                    result: resultat_dkim(resultat.verdict),
                });
                dkim_vus.push((
                    match resultat.verdict {
                        DkimVerdict::Pass => ams_mime::DkimResult::Pass,
                        DkimVerdict::Fail => ams_mime::DkimResult::Fail,
                        DkimVerdict::TempError => ams_mime::DkimResult::TempError,
                        DkimVerdict::PermError => ams_mime::DkimResult::PermError,
                    },
                    resultat.domain.clone(),
                    resultat.selector.clone(),
                ));
                let compte = &mut etat.resume.dkim;
                match resultat.verdict {
                    DkimVerdict::Pass => {
                        compte.pass = compte.pass.saturating_add(1);
                        // C'est ce domaine-là que DMARC comparera au `From:`.
                        authentifies.dkim.push(resultat.domain);
                    }
                    DkimVerdict::Fail => compte.fail = compte.fail.saturating_add(1),
                    DkimVerdict::TempError => {
                        compte.temp_error = compte.temp_error.saturating_add(1);
                    }
                    DkimVerdict::PermError => {
                        compte.perm_error = compte.perm_error.saturating_add(1);
                    }
                }
            }
        }
        if let Some(verificateur) = service.dmarc.as_ref() {
            // Le domaine que SPF a autorisé est celui de l'ENVELOPPE, et il ne
            // compte que si SPF a bien rendu `pass`.
            if session.sender_verdict() == Some(SpfVerdict::Pass)
                && let Some(identite) = session.sender_identity()
            {
                authentifies.spf = Some(String::from_utf8_lossy(identite.domain).into_owned());
            }
            let resultat = verificateur.verdict(lecture.headers(), &authentifies).await;
            etat.resume.dmarc = compter_dmarc(etat.resume.dmarc, &resultat);
            // C'EST ICI, ET SEULEMENT ICI, QU'UN MESSAGE EST REFUSÉ POUR CE
            // QU'IL PRÉTEND ÊTRE. La quarantaine, elle, REMET : elle déplace le
            // message, elle ne le jette pas.
            usurpe = resultat.applies && resultat.policy == DmarcPolicy::Reject;
            // **LA QUARANTAINE NE DÉPEND PAS DE `enforce`**, qui gouverne le
            // refus d'un `p=reject` — c'est-à-dire ce qui se perd si l'on se
            // trompe. Mettre de côté ne perd rien : le message est remis, dans
            // un dossier que son destinataire ouvre quand il veut.
            //
            // ET C'EST LA REMISE QUI DIT SI ELLE L'A FAIT : sans dossier
            // configuré, elle rend `false`, et le rapport dira `none`.
            let ecarte = resultat.designated
                && resultat.policy == DmarcPolicy::Quarantine
                && delivery.quarantine();
            // **CE QU'ON ÉCRIT EST CE QU'ON A TROUVÉ**, et non ce que la
            // politique demandait ni ce qu'on en a fait : `pass` quand le
            // message est aligné, `fail` sinon, et rien du tout quand le domaine
            // ne publie pas.
            //
            // C'est le VERDICT qu'on lit, et non `applies` : en observation,
            // rien ne s'applique, et écrire `dmarc=pass` sur un message qui
            // échoue en ferait un en-tête qui ment.
            dmarc_vu = resultat
                .report
                .as_ref()
                .map(|_| (resultat_dmarc(resultat.verdict), resultat.domain.clone()));
            // ── Ce qu'on en rapportera (RFC 7489 §7.2) ──────────────────────
            //
            // On rapporte CE QU'ON A FAIT, jamais ce qui était demandé : un
            // message que `p=quarantine` visait et que ce serveur a remis dans
            // la boîte de réception — faute de dossier configuré — se rapporte
            // `none`, parce que c'est la vérité. Écrire `quarantine` ferait
            // croire à un domaine qu'il est protégé là où il ne l'est pas, et
            // c'est le seul mensonge qu'un rapport ne peut pas se permettre.
            if let Some(spool) = service.reports.as_ref()
                && let Some(pour) = resultat.report.as_ref()
            {
                // ── LE RAPPORT D'ÉCHEC, S'IL EST DEMANDÉ ────────────────
                //
                // Il part AVANT le compte agrégé : il a besoin des signatures
                // et du bloc d'en-tête, que la ligne suivante consomme. Et il
                // ne part que si `fo=` le demande — le défaut du défaut étant
                // « seulement quand rien n'a réussi ».
                let vu_pour_le_compte = spf_vu(session);
                let signature_fautive = vues
                    .iter()
                    .find(|vue| vue.result == DkimAuthResult::Fail)
                    .or_else(|| vues.first());
                let spf_casse = matches!(
                    session.sender_verdict(),
                    Some(verdict) if verdict != SpfVerdict::Pass
                );
                if !pour.failure_destinations.is_empty()
                    && pour.failure_options.wants(
                        pour.dkim,
                        pour.spf,
                        signature_fautive.is_some_and(|vue| vue.result == DkimAuthResult::Fail),
                        spf_casse,
                    )
                {
                    let vu = &vu_pour_le_compte;
                    spool
                        .echec(&FailureObservation {
                            domain: resultat.domain.clone(),
                            destinations: pour.failure_destinations.clone(),
                            source: adresse_du_pair(source),
                            arrival: maintenant(),
                            envelope_from: session.sender_identity().map(|identite| {
                                String::from_utf8_lossy(identite.sender).into_owned()
                            }),
                            dkim_domain: signature_fautive.map(|vue| vue.domain.clone()),
                            dkim_selector: signature_fautive
                                .map(|vue| vue.selector.clone())
                                .filter(|selecteur| !selecteur.is_empty()),
                            spf_domain: (!vu.domain.is_empty()).then(|| vu.domain.clone()),
                            rejected: usurpe,
                            aligned_dkim: pour.dkim == DmarcVerdict2::Pass,
                            aligned_spf: pour.spf == DmarcVerdict2::Pass,
                            headers: lecture.headers().to_vec(),
                        })
                        .await;
                }
                spool.observer(Observation {
                    domain: resultat.domain.clone(),
                    published: pour.published,
                    destinations: pour.destinations.clone(),
                    source: adresse_du_pair(source),
                    disposition: if usurpe {
                        DmarcPolicy::Reject
                    } else if ecarte {
                        DmarcPolicy::Quarantine
                    } else {
                        DmarcPolicy::None
                    },
                    dkim: pour.dkim,
                    spf: pour.spf,
                    envelope_from: session
                        .sender_identity()
                        .map(|identite| String::from_utf8_lossy(identite.domain).into_owned()),
                    signatures: vues,
                    spf_auth: vu_pour_le_compte,
                });
            }
        }
    }

    // ── L'EN-TÊTE `Authentication-Results` (RFC 8601) ───────────────────────
    //
    // Il occupe EXACTEMENT la place réservée : un octet de trop écraserait le
    // premier en-tête du pair, un de moins laisserait un trou au milieu du
    // message. Quand rien n'a été vérifié, §2.2 prévoit le mot `none`, et c'est
    // celui-là qu'on écrit — un en-tête absent laisserait croire qu'un autre,
    // fabriqué par le pair, vient de nous.
    let signatures: Vec<ams_mime::DkimSeen<'_>> = dkim_vus
        .iter()
        .map(|(resultat, domaine, selecteur)| ams_mime::DkimSeen {
            result: *resultat,
            domain: domaine.as_bytes(),
            selector: selecteur.as_bytes(),
        })
        .collect();
    let identite = session.sender_identity();
    let spf_vu = session.sender_verdict().and_then(|verdict| {
        let vue = identite.as_ref()?;
        Some((
            resultat_spf(verdict),
            match vue.scope {
                SpfIdentity::Helo => ams_mime::SpfIdentity::Helo,
                SpfIdentity::MailFrom => ams_mime::SpfIdentity::MailFrom,
            },
            vue.domain,
        ))
    });
    let mut trace = [0_u8; AUTHRES_RESERVE];
    if ams_mime::write_authres_padded(
        &mut trace,
        &ams_mime::Authentication {
            serv_id: service.config.domain(),
            spf: spf_vu,
            dkim: &signatures,
            dmarc: dmarc_vu
                .as_ref()
                .map(|(resultat, domaine)| (*resultat, domaine.as_bytes())),
        },
    )
    .is_ok()
    {
        delivery.trace(&trace);
    }

    let verdict = if refuse || usurpe {
        // Refusé : soit la session a dit la faute, soit DMARC vient de dire que
        // ce message n'est pas de qui il prétend. On nettoie ce qui a été écrit
        // — un message refusé ne se remet pas à moitié.
        //
        // LES DEUX RAISONS NE SE DISENT PAS PAREIL : le pair dont le message est
        // mal formé doit corriger son message ; celui qu'une politique refuse
        // n'a rien à corriger chez lui.
        delivery.abort();
        if usurpe {
            DataOutcome::RejectedByPolicy
        } else {
            DataOutcome::RejectedPermanent
        }
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

    let tour = session.on_data_settled(verdict, &mut etat.sortie)?;
    stream.write_all(tour.reply()).await?;
    stream.flush().await?;
    Ok(verdict == DataOutcome::Accepted)
}

/// Lit, en abandonnant un pair qui se tait trop longtemps.
pub(crate) async fn lire<S: AsyncRead + Unpin>(
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
pub(crate) fn trouver_crlf(tampon: &[u8]) -> Option<usize> {
    tampon
        .windows(2)
        .position(|paire| paire == b"\r\n")
        .map(|at| at.saturating_add(2))
}

#[cfg(test)]
mod tests {
    use super::{Outcome, Service, Summary, Timeouts, serve_connection};
    use crate::connection::{DkimTally, DmarcTally};
    use crate::{Delivery, DeliveryFailure, Error, SharedGuard};
    use ams_guard::{Source, Thresholds};
    use ams_proto_smtp::{Limits, Path};
    use ams_session::{Capabilities, Config, Policy, RecipientVerdict};
    use core::time::Duration;
    use tokio::io::AsyncWriteExt as _;

    /// N'accepte que ce que ce serveur héberge.
    struct NotreDomaine;

    impl ams_session::Authenticator for NotreDomaine {}

    impl Policy for NotreDomaine {
        fn accepts_recipient(&self, forward_path: &Path<'_>, _submitter: bool) -> RecipientVerdict {
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
        destinataires: Vec<Vec<u8>>,
        echec_a_l_ouverture: Option<DeliveryFailure>,
        recu: Vec<u8>,
        acheve: bool,
        abandonne: bool,
        echec: Option<DeliveryFailure>,
    }

    impl Delivery for Boite {
        fn add_recipient(&mut self, address: &[u8]) -> Result<(), DeliveryFailure> {
            if let Some(cause) = self.echec_a_l_ouverture {
                return Err(cause);
            }
            self.destinataires.push(address.to_vec());
            Ok(())
        }

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
            spf: None,
            dkim: None,
            dmarc: None,
            reports: None,
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
        // **LA TRACE VIENT EN TÊTE, ET LE MESSAGE SUIT INTACT** (RFC 5321
        // §4.4). Un lecteur qui remonte un chemin lit la plus récente d'abord.
        let recu = std::string::String::from_utf8_lossy(&boite.recu).into_owned();
        assert!(
            recu.starts_with(
                "Received: from client.example ([192.0.2.1])\r\n\tby \
                 mail.example.com with ESMTP;\r\n\t"
            ),
            "{recu:?}"
        );
        assert!(
            recu.ends_with("\r\nFrom: moi\r\n\r\nbonjour\r\n"),
            "{recu:?}"
        );
        assert!(
            !recu.contains(" for "),
            "aucun destinataire nommé : {recu:?}"
        );
        assert!(boite.acheve);
        assert!(!boite.abandonne);

        assert!(dit.starts_with("220 mail.example.com ESMTP\r\n"));
        assert!(dit.contains("250 2.0.0 Message accepted\r\n"));
        assert!(dit.ends_with("221 2.0.0 Bye\r\n"));
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
        assert!(dit.contains("550 5.7.1 Relay access denied\r\n"));
    }

    #[tokio::test]
    async fn plusieurs_commandes_dans_une_seule_lecture_sont_toutes_traitees() {
        // Les jeter obligerait le pair à les renvoyer.
        let mut boite = Boite::default();
        let (resume, dit) = conversation(b"NOOP\r\nNOOP\r\nNOOP\r\nQUIT\r\n", &mut boite).await;
        assert_eq!(resume.expect("servie").commands, 4);
        assert_eq!(dit.matches("250 2.0.0 OK\r\n").count(), 3);
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
        assert!(dit.contains("500 5.5.2 Line too long\r\n"));
        // La seconde commande n'a jamais été traitée.
        assert!(!dit.contains("250 2.0.0 OK\r\n"));
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
        assert!(dit.contains("554 5.6.0 Bare CR or LF in message data\r\n"));
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
        assert!(dit.contains("451 4.3.2 Message not accepted, try again later\r\n"));
        // La connexion a suivi : le `NOOP` d'après le message a bien été traité.
        assert!(dit.contains("250 2.0.0 OK\r\n"));
        assert!(dit.ends_with("221 2.0.0 Bye\r\n"));
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
            spf: None,
            dkim: None,
            dmarc: None,
            reports: None,
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
            "421 4.3.2 Service not available, closing transmission channel\r\n"
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
        assert_eq!(
            dit.matches("500 5.5.1 Command not recognised\r\n").count(),
            3
        );
        assert!(dit.ends_with("421 4.3.2 Service not available, closing transmission channel\r\n"));
        // Le `NOOP` qui suivait n'a jamais été traité.
        assert!(!dit.contains("250 2.0.0 OK\r\n"));
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
        assert_eq!(dit.matches("550 5.7.1 Relay access denied\r\n").count(), 20);
        assert!(dit.ends_with("221 2.0.0 Bye\r\n"));
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
                authenticated: false,
                outcome: Outcome::Served,
                dkim: DkimTally::default(),
                dmarc: DmarcTally::default(),
            }
        );
    }
}
