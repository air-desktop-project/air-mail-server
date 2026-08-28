//! Le pilote d'une connexion : il lit, il écrit, il n'décide de rien.

use core::time::Duration;

use ams_proto_smtp::DataEvent;
use ams_session::{Action, Config, DataOutcome, Policy, SmtpSession};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::time::timeout;

use crate::{Delivery, DeliveryFailure, Error};

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
    /// Une extension que cette boucle ne sait pas conduire.
    NonServie,
}

impl Suite {
    fn depuis(action: Action<'_>) -> Self {
        match action {
            Action::Continue => Suite::Continuer,
            Action::Close => Suite::Fermer,
            Action::ReceiveData => Suite::LireLeMessage,
            Action::StartTls | Action::BeginAuth { .. } => Suite::NonServie,
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
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            command: Duration::from_secs(300),
            data: Duration::from_secs(600),
        }
    }
}

/// Ce qu'une connexion a produit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    /// Lignes de commande traitées.
    pub commands: u64,
    /// Messages remis avec succès.
    pub messages: u64,
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
/// # Errors
///
/// [`Error::CapabilityNotSupported`] si `config` annonce une extension que cette
/// boucle ne sait pas conduire, [`Error::Timeout`], [`Error::Io`] ou
/// [`Error::Session`].
pub async fn serve_connection<S, P, D>(
    stream: &mut S,
    config: Config<'_>,
    policy: P,
    delivery: &mut D,
    timeouts: &Timeouts,
) -> Result<Summary, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    P: Policy,
    D: Delivery,
{
    // ON REFUSE AVANT DE PARLER, pas au milieu de la conversation. Cette boucle
    // ne sait conduire ni TLS ni SASL ; servir une configuration qui les annonce
    // reviendrait à mentir au pair dès la bannière.
    let capacites = config.capabilities();
    if capacites.starttls || capacites.auth {
        return Err(Error::CapabilityNotSupported);
    }

    let mut session = SmtpSession::new(config, policy);
    let mut resume = Summary::default();

    // Le tampon de LECTURE est borné par la borne de commande, plus un octet :
    // quand il se remplit sans CRLF, la ligne dépasse forcément la borne, et la
    // session répond « 500 Line too long » d'elle-même. La boucle n'a donc aucune
    // décision de protocole à prendre pour cela — et rien ne peut croître sans
    // fin en attendant un CRLF qui ne vient pas.
    let capacite = config.limits().max_command_octets.saturating_add(1);
    let mut lecture = vec![0_u8; capacite];
    let mut rempli = 0_usize;
    let mut sortie = vec![
        0_u8;
        config
            .limits()
            .max_reply_octets
            .saturating_mul(REPLY_LINES_MAX)
    ];

    let banniere = session.greeting(&mut sortie)?;
    stream.write_all(banniere).await?;
    stream.flush().await?;

    loop {
        let Some(fin_ligne) = trouver_crlf(&lecture[..rempli]) else {
            if rempli == capacite {
                // La ligne dépasse la borne. On la donne telle quelle : la
                // session la refuse et répond, puis on ferme — un pair qui envoie
                // une commande de plus de 512 octets ne se rattrapera pas.
                let tour = session.handle(&lecture[..rempli], &mut sortie)?;
                stream.write_all(tour.reply()).await?;
                stream.flush().await?;
                // Elle a reçu une réponse : elle compte comme les autres.
                resume.commands = resume.commands.saturating_add(1);
                return Ok(resume);
            }
            let lus = lire(stream, &mut lecture[rempli..], timeouts.command).await?;
            if lus == 0 {
                // Le pair a raccroché sans `QUIT`.
                return Ok(resume);
            }
            rempli = rempli.saturating_add(lus);
            continue;
        };

        let tour = session.handle(&lecture[..fin_ligne], &mut sortie)?;
        stream.write_all(tour.reply()).await?;
        stream.flush().await?;
        resume.commands = resume.commands.saturating_add(1);
        let suite = Suite::depuis(tour.action());

        // On décale ce qui reste : plusieurs commandes peuvent tenir dans une
        // seule lecture, et les jeter obligerait le pair à les renvoyer.
        lecture.copy_within(fin_ligne..rempli, 0);
        rempli = rempli.saturating_sub(fin_ligne);

        match suite {
            Suite::Continuer => {}
            Suite::Fermer => return Ok(resume),
            Suite::LireLeMessage => {
                let remis = recevoir_message(
                    stream,
                    &mut session,
                    delivery,
                    &mut lecture,
                    &mut rempli,
                    &mut sortie,
                    timeouts.data,
                )
                .await?;
                if remis {
                    resume.messages = resume.messages.saturating_add(1);
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
    use super::{Summary, Timeouts, serve_connection};
    use crate::{Delivery, DeliveryFailure, Error};
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

    /// Joue une conversation entière en mémoire, et rend ce que le serveur a dit.
    async fn conversation(envoi: &[u8], boite: &mut Boite) -> (Result<Summary, Error>, String) {
        conversation_avec(config(), envoi, boite).await
    }

    async fn conversation_avec(
        config: Config<'_>,
        envoi: &[u8],
        boite: &mut Boite,
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
        let resultat = serve_connection(
            &mut serveur,
            config,
            NotreDomaine,
            boite,
            &Timeouts::default(),
        )
        .await;
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
        let resultat = serve_connection(
            &mut serveur,
            config(),
            NotreDomaine,
            &mut boite,
            &Timeouts {
                command: Duration::from_millis(20),
                data: Duration::from_millis(20),
            },
        )
        .await;
        assert!(matches!(resultat, Err(Error::Timeout)));
    }

    #[test]
    fn les_delais_par_defaut_suivent_la_rfc() {
        // RFC 5321 §4.5.3.2 : cinq minutes entre deux commandes.
        let defaut = Timeouts::default();
        assert_eq!(defaut.command, Duration::from_secs(300));
        assert!(defaut.data > defaut.command);
        assert!(!format!("{defaut:?}").is_empty());
        assert_eq!(
            Summary::default(),
            Summary {
                commands: 0,
                messages: 0
            }
        );
    }
}
