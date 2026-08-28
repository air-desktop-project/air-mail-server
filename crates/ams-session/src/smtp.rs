//! La machine à états d'une session SMTP, **sans entrée-sortie**.

use ams_proto_smtp::{
    Code, Command, DataEvent, DataFault, DataReceiver, Error as SmtpError, Path, encode,
};

use crate::digits::{MAX_DIGITS, decimal};
use crate::{Config, Error, Policy, RecipientVerdict};

/// La bannière : le domaine (255 au plus) suivi de `" ESMTP"`.
const BANNER_MAX: usize = 255 + 6;
/// La ligne `SIZE` : le mot-clé, une espace, et vingt chiffres au plus.
const SIZE_LINE_MAX: usize = 5 + MAX_DIGITS;
/// Le nombre maximal de lignes d'un `EHLO` : domaine, `SIZE`, `STARTTLS`, `AUTH`.
const EHLO_LINES_MAX: usize = 4;

/// Où en est la session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// La bannière est partie ; on attend `EHLO` ou `HELO`.
    Greeted,
    /// Le pair s'est nommé ; aucune transaction n'est ouverte.
    Identified,
    /// `MAIL FROM` accepté. `recipients` compte les `RCPT` acceptés.
    Transaction { recipients: usize },
    /// Un `AUTH` a été accepté : l'appelant conduit l'échange SASL.
    Auth,
    /// Un `DATA` a été accepté : l'appelant lit le message.
    Data,
    /// Les données ont été refusées par la grammaire. La cause décide de la
    /// réponse, et **le verdict de l'appelant ne sera pas consulté**.
    DataFailed(DataFault),
    /// `QUIT` a été traité.
    Closed,
}

/// Ce que l'appelant doit faire après avoir émis la réponse.
///
/// Pas `#[non_exhaustive]`, pour la même raison que
/// [`Command`](ams_proto_smtp::Command) : une action nouvelle doit casser la
/// compilation de la boucle qui la pilote, pas tomber dans un bras `_`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action<'l> {
    /// Rien de particulier : lire la commande suivante.
    Continue,
    /// Conduire la poignée de main TLS, puis appeler
    /// [`SmtpSession::on_tls_established`].
    StartTls,
    /// Conduire l'échange SASL, puis appeler [`SmtpSession::on_auth_settled`].
    BeginAuth {
        /// Le mécanisme demandé.
        mechanism: &'l [u8],
        /// La réponse initiale, si le pair en a fourni une.
        initial_response: Option<&'l [u8]>,
    },
    /// Lire le message jusqu'à `<CRLF>.<CRLF>`.
    ReceiveData,
    /// Fermer la connexion.
    Close,
}

/// Ce que l'appelant a fait du message reçu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataOutcome {
    /// Le message est pris en charge. Le pair n'a plus à s'en occuper.
    Accepted,
    /// Refusé **définitivement**.
    RejectedPermanent,
    /// Refusé **pour l'instant** : le pair doit réessayer.
    RejectedTemporary,
}

/// Une réponse à émettre, et ce qu'il faut faire ensuite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Turn<'b, 'l> {
    reply: &'b [u8],
    action: Action<'l>,
}

impl<'b, 'l> Turn<'b, 'l> {
    /// Les octets à émettre, tels quels.
    #[must_use]
    pub fn reply(&self) -> &'b [u8] {
        self.reply
    }

    /// Ce qu'il faut faire **après** les avoir émis.
    #[must_use]
    pub fn action(&self) -> Action<'l> {
        self.action
    }
}

/// Une session SMTP côté serveur.
///
/// # Elle ne fait aucune entrée-sortie
///
/// Elle reçoit une ligne, rend des octets à émettre et une action. Elle
/// n'attend jamais, ne lit rien, n'écrit nulle part. C'est ce qui la rend
/// pilotable pas à pas depuis un test, donc couvrable à 100 % (C2).
///
/// # Elle n'échappe JAMAIS ce que le pair a envoyé
///
/// Aucune réponse ne contient de donnée venue du client — pas d'adresse
/// reprise, pas de commande citée, pas de détail d'erreur d'analyse. C'est ce
/// qui rend l'injection de réponse inexprimable ici, plutôt que seulement
/// refusée par l'encodeur. Cela prive le pair d'un diagnostic précis, et c'est
/// un prix assumé : ce qu'il a envoyé, il le sait déjà.
pub struct SmtpSession<'a, P: Policy> {
    config: Config<'a>,
    policy: P,
    phase: Phase,
    tls: bool,
    authenticated: bool,
    data: DataReceiver,
    banner: [u8; BANNER_MAX],
    banner_len: usize,
    size_line: [u8; SIZE_LINE_MAX],
    size_len: usize,
}

impl<'a, P: Policy> SmtpSession<'a, P> {
    /// Ouvre une session.
    ///
    /// La bannière et la ligne `SIZE` sont composées **une fois**, ici : elles ne
    /// changent pas, et les recomposer à chaque `EHLO` serait du travail offert à
    /// qui envoie mille `EHLO`.
    #[must_use]
    pub fn new(config: Config<'a>, policy: P) -> Self {
        let domaine = config.domain();
        let mut banner = [0_u8; BANNER_MAX];
        // `Config::new` a borné le domaine à 255 octets : la bannière tient.
        let fin_domaine = domaine.len();
        banner[..fin_domaine].copy_from_slice(domaine);
        let fin_banniere = fin_domaine.saturating_add(6);
        banner[fin_domaine..fin_banniere].copy_from_slice(b" ESMTP");

        let mut size_line = [0_u8; SIZE_LINE_MAX];
        size_line[..5].copy_from_slice(b"SIZE ");
        let mut chiffres = [0_u8; MAX_DIGITS];
        let debut = decimal(config.max_message_octets(), &mut chiffres);
        let ecrits = MAX_DIGITS.saturating_sub(debut);
        let fin_size = ecrits.saturating_add(5);
        size_line[5..fin_size].copy_from_slice(&chiffres[debut..]);

        Self {
            config,
            policy,
            phase: Phase::Greeted,
            data: DataReceiver::new(config.limits(), config.max_message_octets()),
            tls: false,
            authenticated: false,
            banner,
            banner_len: fin_banniere,
            size_line,
            size_len: fin_size,
        }
    }

    /// La bannière d'accueil, à émettre **avant** toute commande.
    ///
    /// # Errors
    ///
    /// [`Error::Reply`] si `out` est trop petit.
    pub fn greeting<'b>(&self, out: &'b mut [u8]) -> Result<&'b [u8], Error> {
        let banniere = self.banner.get(..self.banner_len).unwrap_or_default();
        encode(out, Code::SERVICE_READY, &[banniere], self.config.limits()).map_err(Error::Reply)
    }

    /// La poignée de main TLS a abouti.
    ///
    /// **Toute la session est remise à zéro**, et ce n'est pas une précaution :
    /// la RFC 3207 §4.2 l'exige. Ce qu'un pair a dit en clair a pu être dit par
    /// quelqu'un d'autre ; le conserver après le chiffrement reviendrait à
    /// authentifier de la parole non protégée. Le pair doit renvoyer `EHLO`.
    pub fn on_tls_established(&mut self) {
        self.tls = true;
        self.authenticated = false;
        self.phase = Phase::Greeted;
    }

    /// L'échange SASL s'est conclu : rend la réponse à émettre.
    ///
    /// La session revient à l'état identifié dans les deux cas. **Un échec
    /// d'authentification ne ferme pas la connexion** : c'est à la politique de
    /// bannissement (C8) d'en décider, pas à la grammaire — et fermer sur le
    /// premier échec transformerait chaque faute de frappe en incident.
    ///
    /// # Errors
    ///
    /// [`Error::NotInCommandPhase`] si aucun `AUTH` n'est en cours.
    pub fn on_auth_settled<'b, 'l>(
        &mut self,
        succeeded: bool,
        out: &'b mut [u8],
    ) -> Result<Turn<'b, 'l>, Error> {
        if self.phase != Phase::Auth {
            return Err(Error::NotInCommandPhase);
        }
        self.authenticated = succeeded;
        self.phase = Phase::Identified;
        if succeeded {
            self.simple(Code::AUTH_SUCCEEDED, b"Authentication successful", out)
        } else {
            // Le refus ne dit PAS ce qui a manqué. « Utilisateur inconnu » et
            // « mot de passe faux » sont deux réponses différentes, et cette
            // différence est un annuaire pour qui la mesure.
            self.simple(
                Code::AUTH_FAILED,
                b"Authentication credentials invalid",
                out,
            )
        }
    }

    /// Le message a été lu : rend la réponse à émettre.
    ///
    /// C'est ici que la transaction se termine. La session revient à l'état
    /// identifié : le pair peut enchaîner un autre `MAIL` sans se renommer.
    ///
    /// # Errors
    ///
    /// [`Error::NotInCommandPhase`] si aucun `DATA` n'est en cours.
    pub fn on_data_settled<'b, 'l>(
        &mut self,
        outcome: DataOutcome,
        out: &'b mut [u8],
    ) -> Result<Turn<'b, 'l>, Error> {
        let refus = match self.phase {
            Phase::Data => None,
            Phase::DataFailed(cause) => Some(cause),
            _ => return Err(Error::NotInCommandPhase),
        };
        self.phase = Phase::Identified;
        // UN MESSAGE REFUSÉ PAR LA GRAMMAIRE NE PEUT PAS ÊTRE ACCEPTÉ PAR
        // L'APPELANT : le verdict n'est pas consulté. Sans cela, une boucle
        // distraite pourrait remettre un message que le décodeur a rejeté.
        if let Some(cause) = refus {
            return match cause {
                DataFault::BareLineEnding => self.simple(
                    Code::TRANSACTION_FAILED,
                    b"Bare CR or LF in message data",
                    out,
                ),
                DataFault::LineTooLong { .. } => {
                    self.simple(Code::SYNTAX_ERROR, b"Line too long", out)
                }
                DataFault::MessageTooLarge { .. } => self.simple(
                    Code::MESSAGE_TOO_LARGE,
                    b"Message exceeds maximum size",
                    out,
                ),
            };
        }
        match outcome {
            DataOutcome::Accepted => self.simple(Code::OK, b"Message accepted", out),
            DataOutcome::RejectedPermanent => {
                self.simple(Code::TRANSACTION_FAILED, b"Message rejected", out)
            }
            DataOutcome::RejectedTemporary => self.simple(
                Code::LOCAL_ERROR,
                b"Message not accepted, try again later",
                out,
            ),
        }
    }

    /// Fournit des octets de la phase de données.
    ///
    /// Rend l'événement et le nombre d'octets **consommés** — qui n'est pas celui
    /// des octets rendus : un point échappé est consommé sans être rendu.
    ///
    /// # Errors
    ///
    /// [`Error::NotInDataPhase`] hors de la phase de données, et
    /// [`Error::DataRefused`] quand le pair a envoyé ce que la grammaire refuse.
    /// Dans ce dernier cas, **cesser de lire** et appeler
    /// [`Self::on_data_settled`].
    pub fn feed_data<'i>(&mut self, input: &'i [u8]) -> Result<(DataEvent<'i>, usize), Error> {
        if self.phase != Phase::Data {
            return Err(Error::NotInDataPhase);
        }
        match self.data.next(input) {
            Ok(progres) => Ok(progres),
            Err(cause) => {
                self.phase = Phase::DataFailed(cause);
                Err(Error::DataRefused)
            }
        }
    }

    /// Le nombre d'octets de message reçus pour la transaction en cours.
    #[must_use]
    pub fn received_octets(&self) -> u64 {
        self.data.content_octets()
    }

    /// La session est-elle chiffrée ?
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.tls
    }

    /// Le pair est-il authentifié ?
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    /// Traite une ligne de commande, **CRLF compris**.
    ///
    /// # Errors
    ///
    /// [`Error::SessionClosed`], [`Error::NotInCommandPhase`] ou
    /// [`Error::Reply`]. Un pair qui envoie n'importe quoi obtient une
    /// **réponse**, jamais une erreur.
    pub fn handle<'b, 'l>(
        &mut self,
        line: &'l [u8],
        out: &'b mut [u8],
    ) -> Result<Turn<'b, 'l>, Error> {
        match self.phase {
            Phase::Closed => return Err(Error::SessionClosed),
            Phase::Auth | Phase::Data | Phase::DataFailed(_) => {
                return Err(Error::NotInCommandPhase);
            }
            Phase::Greeted | Phase::Identified | Phase::Transaction { .. } => {}
        }

        let commande = match Command::parse(line, self.config.limits()) {
            Ok(commande) => commande,
            Err(cause) => return self.on_parse_error(&cause, out),
        };

        match commande {
            Command::Ehlo(_) => self.on_ehlo(out),
            Command::Helo(_) => self.on_helo(out),
            Command::Mail { .. } => self.on_mail(out),
            Command::Rcpt { forward_path, .. } => self.on_rcpt(&forward_path, out),
            Command::Data => self.on_data(out),
            Command::Rset => {
                self.reset_transaction();
                self.simple(Code::OK, b"Reset ok", out)
            }
            Command::Noop => self.simple(Code::OK, b"OK", out),
            Command::Quit => {
                self.phase = Phase::Closed;
                self.finish(Code::CLOSING, b"Bye", Action::Close, out)
            }
            Command::StartTls => self.on_starttls(out),
            Command::Auth {
                mechanism,
                initial_response,
            } => self.on_auth(mechanism, initial_response, out),
            Command::Vrfy => self.simple(
                Code::CANNOT_VRFY,
                b"Cannot verify; message will be attempted",
                out,
            ),
            // `EXPN` developpe une liste, c'est-a-dire en publie les membres.
            // La RFC 5321 §7.3 autorise a ne pas l'implementer, et c'est ce
            // qu'on fait.
            Command::Expn => self.simple(Code::NOT_IMPLEMENTED, b"EXPN not available", out),
            Command::Help => self.simple(Code::HELP_MESSAGE, b"See RFC 5321", out),
        }
    }

    /// Traduit une erreur d'analyse en code de reponse.
    ///
    /// **Le detail n'est jamais renvoye au pair.** Il sait ce qu'il a envoye ;
    /// le lui reciter n'ajoute rien, et exposerait le vocabulaire interne de
    /// l'analyseur a qui cherche a le cartographier.
    fn on_parse_error<'b, 'l>(
        &mut self,
        cause: &SmtpError,
        out: &'b mut [u8],
    ) -> Result<Turn<'b, 'l>, Error> {
        match cause {
            SmtpError::LineTooLong { .. } => self.simple(Code::SYNTAX_ERROR, b"Line too long", out),
            SmtpError::MalformedLineEnding => {
                self.simple(Code::SYNTAX_ERROR, b"Line must end with CRLF", out)
            }
            SmtpError::UnknownVerb => {
                self.simple(Code::SYNTAX_ERROR, b"Command not recognised", out)
            }
            SmtpError::ObsoleteVerb => {
                self.simple(Code::NOT_IMPLEMENTED, b"Command not implemented", out)
            }
            // Tout le reste porte sur les ARGUMENTS, et `501` est exactement ce
            // que la RFC 5321 §4.2.2 prevoit pour cela.
            _ => self.simple(
                Code::ARGUMENT_ERROR,
                b"Syntax error in parameters or arguments",
                out,
            ),
        }
    }

    /// `EHLO` — annonce les extensions **effectivement servies**.
    fn on_ehlo<'b, 'l>(&mut self, out: &'b mut [u8]) -> Result<Turn<'b, 'l>, Error> {
        // RFC 5321 §4.1.4 : `EHLO` annule la transaction en cours.
        self.phase = Phase::Identified;

        let mut lignes: [&[u8]; EHLO_LINES_MAX] = [b""; EHLO_LINES_MAX];
        let mut posees = 0_usize;
        lignes[posees] = self.config.domain();
        posees = posees.saturating_add(1);
        lignes[posees] = self.size_line.get(..self.size_len).unwrap_or_default();
        posees = posees.saturating_add(1);
        // On n'annonce QUE ce que l'appelant a declare savoir conduire, et
        // `AUTH` seulement sous chiffrement (C6) : annoncer un mecanisme qu'on
        // refusera ensuite ferait envoyer un mot de passe en clair a un client
        // qui aurait cru l'offre.
        if self.config.capabilities().starttls && !self.tls {
            lignes[posees] = b"STARTTLS";
            posees = posees.saturating_add(1);
        }
        if self.config.capabilities().auth && self.tls {
            lignes[posees] = b"AUTH PLAIN";
            posees = posees.saturating_add(1);
        }

        let reply = encode(
            out,
            Code::OK,
            lignes.get(..posees).unwrap_or_default(),
            self.config.limits(),
        )
        .map_err(Error::Reply)?;
        Ok(Turn {
            reply,
            action: Action::Continue,
        })
    }

    /// `HELO` — accepte, mais n'annonce rien.
    ///
    /// Une session `HELO` n'a donc ni `STARTTLS` ni `AUTH` : elle ne peut que
    /// remettre du courrier en clair et sans s'authentifier. C6 n'interdit pas
    /// `HELO` ; ce qu'une telle session a le droit de faire releve de la
    /// politique de relais, pas de cette couche.
    fn on_helo<'b, 'l>(&mut self, out: &'b mut [u8]) -> Result<Turn<'b, 'l>, Error> {
        self.phase = Phase::Identified;
        let domaine = self.config.domain();
        let reply =
            encode(out, Code::OK, &[domaine], self.config.limits()).map_err(Error::Reply)?;
        Ok(Turn {
            reply,
            action: Action::Continue,
        })
    }

    /// `MAIL FROM:` — ouvre une transaction.
    fn on_mail<'b, 'l>(&mut self, out: &'b mut [u8]) -> Result<Turn<'b, 'l>, Error> {
        match self.phase {
            Phase::Greeted => self.simple(Code::BAD_SEQUENCE, b"Send EHLO first", out),
            Phase::Transaction { .. } => {
                self.simple(Code::BAD_SEQUENCE, b"Nested MAIL command", out)
            }
            _ => {
                self.phase = Phase::Transaction { recipients: 0 };
                self.simple(Code::OK, b"Sender ok", out)
            }
        }
    }

    /// `RCPT TO:` — la seule commande dont la session ne decide pas elle-meme.
    fn on_rcpt<'b, 'l>(
        &mut self,
        forward_path: &Path<'_>,
        out: &'b mut [u8],
    ) -> Result<Turn<'b, 'l>, Error> {
        let Phase::Transaction { recipients } = self.phase else {
            return self.simple(Code::BAD_SEQUENCE, b"Need MAIL before RCPT", out);
        };
        if recipients >= self.config.max_recipients() {
            return self.simple(Code::TOO_MANY_RECIPIENTS, b"Too many recipients", out);
        }
        match self.policy.accepts_recipient(forward_path) {
            RecipientVerdict::Accept => {
                self.phase = Phase::Transaction {
                    recipients: recipients.saturating_add(1),
                };
                self.simple(Code::OK, b"Recipient ok", out)
            }
            RecipientVerdict::RejectPermanent => {
                self.simple(Code::MAILBOX_UNAVAILABLE, b"Mailbox unavailable", out)
            }
            RecipientVerdict::RejectTemporary => {
                self.simple(Code::MAILBOX_BUSY, b"Mailbox busy, try again later", out)
            }
            RecipientVerdict::RelayDenied => {
                self.simple(Code::MAILBOX_UNAVAILABLE, b"Relay access denied", out)
            }
        }
    }

    /// `DATA` — exige au moins un destinataire accepte.
    fn on_data<'b, 'l>(&mut self, out: &'b mut [u8]) -> Result<Turn<'b, 'l>, Error> {
        match self.phase {
            Phase::Transaction { recipients } if recipients > 0 => {
                self.phase = Phase::Data;
                // Un récepteur NEUF par message : celui du message précédent
                // porte ses compteurs, et les réutiliser ferait refuser le
                // second message pour la taille du premier.
                self.data =
                    DataReceiver::new(self.config.limits(), self.config.max_message_octets());
                self.finish(
                    Code::START_MAIL_INPUT,
                    b"Start mail input; end with <CRLF>.<CRLF>",
                    Action::ReceiveData,
                    out,
                )
            }
            _ => self.simple(Code::BAD_SEQUENCE, b"Need RCPT before DATA", out),
        }
    }

    /// `STARTTLS` (RFC 3207 §4).
    fn on_starttls<'b, 'l>(&mut self, out: &'b mut [u8]) -> Result<Turn<'b, 'l>, Error> {
        if !self.config.capabilities().starttls {
            return self.simple(Code::NOT_IMPLEMENTED, b"Command not implemented", out);
        }
        if self.tls {
            return self.simple(Code::BAD_SEQUENCE, b"TLS already active", out);
        }
        if self.phase == Phase::Greeted {
            return self.simple(Code::BAD_SEQUENCE, b"Send EHLO first", out);
        }
        self.finish(
            Code::SERVICE_READY,
            b"Ready to start TLS",
            Action::StartTls,
            out,
        )
    }

    /// `AUTH` (RFC 4954) — **le refus emblematique de C6**.
    fn on_auth<'b, 'l>(
        &mut self,
        mechanism: &'l [u8],
        initial_response: Option<&'l [u8]>,
        out: &'b mut [u8],
    ) -> Result<Turn<'b, 'l>, Error> {
        if !self.config.capabilities().auth {
            return self.simple(Code::NOT_IMPLEMENTED, b"Command not implemented", out);
        }
        if !self.tls {
            // Ce refus n'est PAS reglable. Un mot de passe envoye en clair est
            // lu par qui regarde passer les paquets, et l'avoir accepte une fois
            // suffit a le compromettre pour toujours.
            return self.simple(
                Code::ENCRYPTION_REQUIRED,
                b"Encryption required for authentication",
                out,
            );
        }
        if self.authenticated {
            return self.simple(Code::BAD_SEQUENCE, b"Already authenticated", out);
        }
        if self.phase == Phase::Greeted {
            return self.simple(Code::BAD_SEQUENCE, b"Send EHLO first", out);
        }
        self.phase = Phase::Auth;
        self.finish(
            Code::AUTH_CHALLENGE,
            b"Proceed",
            Action::BeginAuth {
                mechanism,
                initial_response,
            },
            out,
        )
    }

    /// Annule la transaction en cours, sans toucher a l'identification.
    fn reset_transaction(&mut self) {
        if let Phase::Transaction { .. } = self.phase {
            self.phase = Phase::Identified;
        }
    }

    /// Une reponse d'une ligne, sans action.
    fn simple<'b, 'l>(
        &self,
        code: Code,
        texte: &[u8],
        out: &'b mut [u8],
    ) -> Result<Turn<'b, 'l>, Error> {
        self.finish(code, texte, Action::Continue, out)
    }

    /// Une reponse d'une ligne, avec une action.
    fn finish<'b, 'l>(
        &self,
        code: Code,
        texte: &[u8],
        action: Action<'l>,
        out: &'b mut [u8],
    ) -> Result<Turn<'b, 'l>, Error> {
        let reply = encode(out, code, &[texte], self.config.limits()).map_err(Error::Reply)?;
        Ok(Turn { reply, action })
    }
}

#[cfg(test)]
mod tests {
    use super::{Action, DataOutcome, SmtpSession};
    use crate::{Capabilities, Config, Error, Policy, RecipientVerdict};
    use ams_proto_smtp::{DataEvent, Error as SmtpError, Limits, Path};

    /// L'erreur qu'un tampon de `disponible` octets provoque quand il en faut
    /// `needed`.
    ///
    /// On assère la valeur EXACTE plutôt qu'un `matches!` : ce dernier engendre
    /// un bras `_ => false` que rien n'emprunte, et le 100 % de C2 le compterait
    /// à jamais découvert — exactement comme un `panic!` de destructuration.
    fn tampon_trop_petit(needed: usize) -> Error {
        Error::Reply(SmtpError::BufferTooSmall { needed })
    }

    /// Une politique qui rend toujours le même verdict.
    struct Verdict(RecipientVerdict);

    impl Policy for Verdict {
        fn accepts_recipient(&self, _forward_path: &Path<'_>) -> RecipientVerdict {
            self.0
        }
    }

    fn config() -> Config<'static> {
        Config::new(b"mail.example.com", 2, 10_485_760, Limits::DEFAULT)
            .expect("configurable")
            .with_capabilities(Capabilities {
                starttls: true,
                auth: true,
            })
    }

    fn session(verdict: RecipientVerdict) -> SmtpSession<'static, Verdict> {
        SmtpSession::new(config(), Verdict(verdict))
    }

    fn acceptante() -> SmtpSession<'static, Verdict> {
        session(RecipientVerdict::Accept)
    }

    /// Joue une ligne et rend la réponse sous forme de chaîne.
    fn jouer(session: &mut SmtpSession<'_, Verdict>, ligne: &[u8]) -> std::string::String {
        let mut tampon = [0_u8; 512];
        let tour = session.handle(ligne, &mut tampon).expect("réponse");
        std::string::String::from_utf8(tour.reply().to_vec()).expect("réponse ASCII")
    }

    /// Amène une session jusqu'à l'état identifié.
    fn identifier(session: &mut SmtpSession<'_, Verdict>) {
        assert!(jouer(session, b"EHLO client.example\r\n").starts_with("250"));
    }

    // ── L'ouverture ─────────────────────────────────────────────────────────

    #[test]
    fn la_banniere_nomme_le_serveur() {
        let session = acceptante();
        let mut tampon = [0_u8; 128];
        let banniere = session.greeting(&mut tampon).expect("bannière");
        assert_eq!(banniere, b"220 mail.example.com ESMTP\r\n");
    }

    #[test]
    fn un_tampon_trop_petit_est_une_faute_de_l_appelant_pas_du_pair() {
        let session = acceptante();
        let mut tampon = [0_u8; 4];
        // « mail.example.com ESMTP » fait 22 octets, plus l'enveloppe de six.
        assert_eq!(session.greeting(&mut tampon), Err(tampon_trop_petit(28)));
    }

    // ── EHLO, et ce qu'il annonce ───────────────────────────────────────────

    #[test]
    fn ehlo_annonce_starttls_mais_pas_auth_avant_chiffrement() {
        // ANNONCER `AUTH` EN CLAIR FERAIT ENVOYER UN MOT DE PASSE EN CLAIR à un
        // client qui aurait cru l'offre.
        let mut session = acceptante();
        let reponse = jouer(&mut session, b"EHLO client.example\r\n");
        assert_eq!(
            reponse,
            "250-mail.example.com\r\n250-SIZE 10485760\r\n250 STARTTLS\r\n"
        );
        assert!(!reponse.contains("AUTH"));
    }

    #[test]
    fn ehlo_annonce_auth_mais_plus_starttls_apres_chiffrement() {
        let mut session = acceptante();
        session.on_tls_established();
        let reponse = jouer(&mut session, b"EHLO client.example\r\n");
        assert_eq!(
            reponse,
            "250-mail.example.com\r\n250-SIZE 10485760\r\n250 AUTH PLAIN\r\n"
        );
        assert!(!reponse.contains("STARTTLS"));
    }

    #[test]
    fn helo_est_accepte_mais_n_annonce_rien() {
        // Une session `HELO` ne peut donc ni chiffrer ni s'authentifier.
        let mut session = acceptante();
        assert_eq!(
            jouer(&mut session, b"HELO client.example\r\n"),
            "250 mail.example.com\r\n"
        );
    }

    #[test]
    fn ehlo_annule_la_transaction_en_cours() {
        // RFC 5321 §4.1.4.
        let mut session = acceptante();
        identifier(&mut session);
        assert!(jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n").starts_with("250"));
        identifier(&mut session);
        // La transaction n'existe plus : `RCPT` redevient hors séquence.
        assert!(jouer(&mut session, b"RCPT TO:<c@d.co>\r\n").starts_with("503"));
    }

    // ── Le séquencement ─────────────────────────────────────────────────────

    #[test]
    fn le_sequencement_est_impose() {
        let mut session = acceptante();
        assert!(jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n").starts_with("503"));
        identifier(&mut session);
        assert!(jouer(&mut session, b"RCPT TO:<c@d.co>\r\n").starts_with("503"));
        assert!(jouer(&mut session, b"DATA\r\n").starts_with("503"));
        assert!(jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n").starts_with("250"));
        assert!(jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n").starts_with("503"));
        assert!(jouer(&mut session, b"DATA\r\n").starts_with("503"));
        assert!(jouer(&mut session, b"RCPT TO:<c@d.co>\r\n").starts_with("250"));
        assert!(jouer(&mut session, b"DATA\r\n").starts_with("354"));
    }

    #[test]
    fn data_rend_la_main_a_l_appelant() {
        let mut session = acceptante();
        identifier(&mut session);
        jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n");
        jouer(&mut session, b"RCPT TO:<c@d.co>\r\n");
        let mut tampon = [0_u8; 128];
        let tour = session.handle(b"DATA\r\n", &mut tampon).expect("réponse");
        assert_eq!(tour.action(), Action::ReceiveData);
        // Et la session n'accepte plus de commande : c'est le message qu'elle
        // attend, pas un verbe.
        assert_eq!(
            session.handle(b"NOOP\r\n", &mut tampon),
            Err(Error::NotInCommandPhase)
        );

        // Le verdict de l'appelant referme la transaction.
        let tour = session
            .on_data_settled(DataOutcome::Accepted, &mut tampon)
            .expect("verdict");
        assert_eq!(tour.reply(), b"250 Message accepted\r\n");
        // On reste identifié : un autre message peut suivre sans nouvel `EHLO`.
        assert!(jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n").starts_with("250"));
    }

    /// Amène une session jusqu'à la phase de données.
    fn jusqu_aux_donnees(session: &mut SmtpSession<'_, Verdict>) {
        identifier(session);
        jouer(session, b"MAIL FROM:<a@b.co>\r\n");
        jouer(session, b"RCPT TO:<c@d.co>\r\n");
        assert!(jouer(session, b"DATA\r\n").starts_with("354"));
    }

    /// Donne un message entier à la session, et rend ce qu'elle en a extrait.
    fn remettre(
        session: &mut SmtpSession<'_, Verdict>,
        flux: &[u8],
    ) -> Result<std::vec::Vec<u8>, Error> {
        let mut recu = std::vec::Vec::new();
        let mut debut = 0_usize;
        while debut < flux.len() {
            let (evenement, consomme) = session.feed_data(&flux[debut..])?;
            match evenement {
                DataEvent::Complete => return Ok(recu),
                DataEvent::Content(morceau) => recu.extend_from_slice(morceau),
                DataEvent::NeedMore => {}
            }
            // L'invariante de progrès du récepteur, éprouvée ici aussi.
            assert!(consomme > 0, "le récepteur n'a ni consommé ni conclu");
            debut = debut.saturating_add(consomme);
        }
        // Le flux s'est arrêté sans `<CRLF>.<CRLF>` : le pair a raccroché.
        Ok(recu)
    }

    // ── La phase de données ─────────────────────────────────────────────────

    #[test]
    fn un_message_traverse_la_session_intact() {
        let mut session = acceptante();
        jusqu_aux_donnees(&mut session);
        assert_eq!(
            remettre(&mut session, b"From: moi\r\n\r\nbonjour\r\n.\r\n").expect("recevable"),
            b"From: moi\r\n\r\nbonjour\r\n"
        );
        assert_eq!(session.received_octets(), 22);

        let mut tampon = [0_u8; 128];
        let tour = session
            .on_data_settled(DataOutcome::Accepted, &mut tampon)
            .expect("verdict");
        assert_eq!(tour.reply(), b"250 Message accepted\r\n");
    }

    #[test]
    fn le_point_echappe_traverse_la_session_comme_le_codec() {
        // RFC 5321 §4.5.2 : la session ne fait que relayer le récepteur, et le
        // point échappé se consomme sans rien rendre — c'est le seul cas où un
        // appel ne produit aucun octet tout en progressant.
        let mut session = acceptante();
        jusqu_aux_donnees(&mut session);
        assert_eq!(
            remettre(&mut session, b"..cache\r\n.\r\n").expect("recevable"),
            b".cache\r\n"
        );
        // Le point échappé compte sur le fil, pas dans le message.
        assert_eq!(session.received_octets(), 8);
    }

    #[test]
    fn un_pair_qui_raccroche_laisse_un_message_inachevé() {
        // La transaction ne se conclut pas d'elle-même : c'est à la boucle de
        // constater la déconnexion, et de ne rien remettre.
        let mut session = acceptante();
        jusqu_aux_donnees(&mut session);
        assert_eq!(
            remettre(&mut session, b"debut sans fin\r\n").expect("recevable"),
            b"debut sans fin\r\n"
        );
        // La session attend toujours la suite du message.
        let mut tampon = [0_u8; 128];
        assert_eq!(
            session.handle(b"NOOP\r\n", &mut tampon),
            Err(Error::NotInCommandPhase)
        );
    }

    #[test]
    fn des_donnees_hors_phase_sont_refusees() {
        let mut session = acceptante();
        assert_eq!(
            session.feed_data(b"peu importe"),
            Err(Error::NotInDataPhase)
        );
    }

    #[test]
    fn un_message_refuse_par_la_grammaire_ne_peut_pas_etre_accepte() {
        // LA PROPRIÉTÉ QUI COMPTE : une boucle distraite ne peut pas remettre un
        // message que le décodeur a rejeté. Le verdict n'est même pas consulté.
        for (contrebande, attendu) in [
            (
                b"corps\r\n\n.\r\nMAIL FROM:<usurpe@x.co>\r\n".as_slice(),
                "554 Bare CR or LF in message data\r\n",
            ),
            (b"a\r.\r\n", "554 Bare CR or LF in message data\r\n"),
        ] {
            let mut session = acceptante();
            jusqu_aux_donnees(&mut session);
            assert_eq!(
                remettre(&mut session, contrebande),
                Err(Error::DataRefused),
                "{contrebande:?}"
            );
            let mut tampon = [0_u8; 128];
            // L'appelant demande l'acceptation ; elle n'est PAS accordée.
            let tour = session
                .on_data_settled(DataOutcome::Accepted, &mut tampon)
                .expect("verdict");
            assert_eq!(
                std::string::String::from_utf8(tour.reply().to_vec()).expect("ASCII"),
                attendu
            );
        }
    }

    #[test]
    fn chaque_faute_de_donnees_a_sa_reponse() {
        let etroite = Config::new(
            b"mail.example.com",
            2,
            8,
            Limits {
                max_text_line_octets: 6,
                ..Limits::DEFAULT
            },
        )
        .expect("configurable");

        for (flux, attendu) in [
            (b"abcdef\r\n.\r\n".as_slice(), "500 Line too long\r\n"),
            (
                b"abcd\r\nabcd\r\n.\r\n",
                "552 Message exceeds maximum size\r\n",
            ),
        ] {
            let mut session = SmtpSession::new(etroite, Verdict(RecipientVerdict::Accept));
            jusqu_aux_donnees(&mut session);
            assert_eq!(
                remettre(&mut session, flux),
                Err(Error::DataRefused),
                "{flux:?}"
            );
            let mut tampon = [0_u8; 128];
            let tour = session
                .on_data_settled(DataOutcome::Accepted, &mut tampon)
                .expect("verdict");
            assert_eq!(
                std::string::String::from_utf8(tour.reply().to_vec()).expect("ASCII"),
                attendu
            );
        }
    }

    #[test]
    fn le_compteur_repart_a_zero_pour_le_message_suivant() {
        // Réutiliser le récepteur ferait refuser le second message pour la
        // taille du premier.
        let mut session = acceptante();
        jusqu_aux_donnees(&mut session);
        remettre(&mut session, b"premier\r\n.\r\n").expect("recevable");
        let mut tampon = [0_u8; 128];
        session
            .on_data_settled(DataOutcome::Accepted, &mut tampon)
            .expect("verdict");

        jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n");
        jouer(&mut session, b"RCPT TO:<c@d.co>\r\n");
        jouer(&mut session, b"DATA\r\n");
        assert_eq!(session.received_octets(), 0);
        assert_eq!(
            remettre(&mut session, b"second\r\n.\r\n").expect("recevable"),
            b"second\r\n"
        );
    }

    #[test]
    fn aucune_commande_n_est_traitee_apres_un_refus_de_donnees() {
        let mut session = acceptante();
        jusqu_aux_donnees(&mut session);
        assert_eq!(remettre(&mut session, b"a\n.\r\n"), Err(Error::DataRefused));
        let mut tampon = [0_u8; 128];
        assert_eq!(
            session.handle(b"NOOP\r\n", &mut tampon),
            Err(Error::NotInCommandPhase)
        );
    }

    #[test]
    fn chaque_verdict_de_message_a_sa_reponse() {
        for (verdict, attendu) in [
            (DataOutcome::Accepted, "250 Message accepted\r\n"),
            (DataOutcome::RejectedPermanent, "554 Message rejected\r\n"),
            (
                DataOutcome::RejectedTemporary,
                "451 Message not accepted, try again later\r\n",
            ),
        ] {
            let mut session = acceptante();
            identifier(&mut session);
            jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n");
            jouer(&mut session, b"RCPT TO:<c@d.co>\r\n");
            jouer(&mut session, b"DATA\r\n");
            let mut tampon = [0_u8; 128];
            let tour = session
                .on_data_settled(verdict, &mut tampon)
                .expect("verdict");
            assert_eq!(
                std::string::String::from_utf8(tour.reply().to_vec()).expect("ASCII"),
                attendu
            );
        }
    }

    #[test]
    fn un_verdict_rendu_hors_de_sa_phase_est_refuse() {
        // L'appelant ne peut pas conclure ce qui n'a pas commencé.
        let mut session = acceptante();
        let mut tampon = [0_u8; 128];
        assert_eq!(
            session.on_data_settled(DataOutcome::Accepted, &mut tampon),
            Err(Error::NotInCommandPhase)
        );
        assert_eq!(
            session.on_auth_settled(true, &mut tampon),
            Err(Error::NotInCommandPhase)
        );
    }

    #[test]
    fn rset_annule_la_transaction_sans_desidentifier() {
        let mut session = acceptante();
        identifier(&mut session);
        jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n");
        assert!(jouer(&mut session, b"RSET\r\n").starts_with("250"));
        // Hors transaction, `RSET` reste licite et ne défait rien.
        assert!(jouer(&mut session, b"RSET\r\n").starts_with("250"));
        // On est toujours identifié : `MAIL` repasse.
        assert!(jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n").starts_with("250"));
    }

    #[test]
    fn quit_ferme_et_la_session_ne_repond_plus() {
        let mut session = acceptante();
        let mut tampon = [0_u8; 128];
        let tour = session.handle(b"QUIT\r\n", &mut tampon).expect("réponse");
        assert_eq!(tour.reply(), b"221 Bye\r\n");
        assert_eq!(tour.action(), Action::Close);
        assert_eq!(
            session.handle(b"NOOP\r\n", &mut tampon),
            Err(Error::SessionClosed)
        );
    }

    // ── Les destinataires ───────────────────────────────────────────────────

    #[test]
    fn chaque_verdict_a_sa_reponse() {
        for (verdict, attendu) in [
            (RecipientVerdict::Accept, "250"),
            (RecipientVerdict::RejectPermanent, "550"),
            (RecipientVerdict::RejectTemporary, "450"),
            (RecipientVerdict::RelayDenied, "550"),
        ] {
            let mut session = session(verdict);
            identifier(&mut session);
            jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n");
            let reponse = jouer(&mut session, b"RCPT TO:<c@d.co>\r\n");
            assert!(
                reponse.starts_with(attendu),
                "{verdict:?} : « {reponse} » n'est pas un {attendu}"
            );
        }
    }

    #[test]
    fn le_relais_refuse_se_distingue_de_la_boite_absente() {
        // Même code, textes différents : un expéditeur légitime qui se trompe de
        // serveur doit pouvoir le comprendre sans lire les journaux d'en face.
        let mut absente = session(RecipientVerdict::RejectPermanent);
        identifier(&mut absente);
        jouer(&mut absente, b"MAIL FROM:<a@b.co>\r\n");
        let sans_boite = jouer(&mut absente, b"RCPT TO:<c@d.co>\r\n");

        let mut relais = session(RecipientVerdict::RelayDenied);
        identifier(&mut relais);
        jouer(&mut relais, b"MAIL FROM:<a@b.co>\r\n");
        let sans_relais = jouer(&mut relais, b"RCPT TO:<c@d.co>\r\n");

        assert_ne!(sans_boite, sans_relais);
    }

    #[test]
    fn le_nombre_de_destinataires_est_borne() {
        let mut session = acceptante();
        identifier(&mut session);
        jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n");
        assert!(jouer(&mut session, b"RCPT TO:<un@d.co>\r\n").starts_with("250"));
        assert!(jouer(&mut session, b"RCPT TO:<deux@d.co>\r\n").starts_with("250"));
        // La configuration en autorise deux.
        assert!(jouer(&mut session, b"RCPT TO:<trois@d.co>\r\n").starts_with("452"));
    }

    // ── TLS ─────────────────────────────────────────────────────────────────

    #[test]
    fn starttls_exige_ehlo_et_ne_se_repete_pas() {
        let mut session = acceptante();
        assert!(jouer(&mut session, b"STARTTLS\r\n").starts_with("503"));
        identifier(&mut session);
        let mut tampon = [0_u8; 128];
        let tour = session
            .handle(b"STARTTLS\r\n", &mut tampon)
            .expect("réponse");
        assert_eq!(tour.reply(), b"220 Ready to start TLS\r\n");
        assert_eq!(tour.action(), Action::StartTls);

        session.on_tls_established();
        identifier(&mut session);
        assert!(jouer(&mut session, b"STARTTLS\r\n").starts_with("503"));
    }

    #[test]
    fn la_poignee_de_main_remet_toute_la_session_a_zero() {
        // RFC 3207 §4.2. Ce qu'un pair a dit EN CLAIR a pu être dit par quelqu'un
        // d'autre : le conserver après chiffrement authentifierait de la parole
        // non protégée.
        let mut session = acceptante();
        identifier(&mut session);
        jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n");
        assert!(!session.is_encrypted());

        session.on_tls_established();
        assert!(session.is_encrypted());
        assert!(!session.is_authenticated());
        // Ni l'identification ni la transaction n'ont survécu.
        assert!(jouer(&mut session, b"MAIL FROM:<a@b.co>\r\n").starts_with("503"));
    }

    // ── AUTH : le refus emblématique ────────────────────────────────────────

    #[test]
    fn auth_est_refuse_hors_chiffrement_et_ce_n_est_pas_reglable() {
        let mut session = acceptante();
        identifier(&mut session);
        assert_eq!(
            jouer(&mut session, b"AUTH PLAIN\r\n"),
            "538 Encryption required for authentication\r\n"
        );
    }

    #[test]
    fn auth_sous_chiffrement_delegue_l_echange() {
        let mut session = acceptante();
        session.on_tls_established();
        identifier(&mut session);
        let mut tampon = [0_u8; 128];
        let tour = session
            .handle(b"AUTH PLAIN dGVzdA==\r\n", &mut tampon)
            .expect("réponse");
        assert_eq!(
            tour.action(),
            Action::BeginAuth {
                mechanism: b"PLAIN",
                initial_response: Some(b"dGVzdA=="),
            }
        );
        // La session attend le verdict : elle ne traite plus de commande.
        assert_eq!(
            session.handle(b"NOOP\r\n", &mut tampon),
            Err(Error::NotInCommandPhase)
        );

        let tour = session.on_auth_settled(true, &mut tampon).expect("verdict");
        assert_eq!(tour.reply(), b"235 Authentication successful\r\n");
        assert!(session.is_authenticated());
        assert!(jouer(&mut session, b"AUTH PLAIN\r\n").starts_with("503"));
    }

    #[test]
    fn un_echec_d_authentification_ne_ferme_pas_la_connexion() {
        // C'est à la politique de bannissement (C8) d'en décider, pas à la
        // grammaire.
        let mut session = acceptante();
        session.on_tls_established();
        identifier(&mut session);
        let mut tampon = [0_u8; 128];
        session
            .handle(b"AUTH PLAIN\r\n", &mut tampon)
            .expect("réponse");
        let tour = session
            .on_auth_settled(false, &mut tampon)
            .expect("verdict");
        // Le refus ne dit PAS ce qui a manqué : la différence entre « utilisateur
        // inconnu » et « mot de passe faux » est un annuaire pour qui la mesure.
        assert_eq!(tour.reply(), b"535 Authentication credentials invalid\r\n");
        assert!(!session.is_authenticated());
        assert!(jouer(&mut session, b"NOOP\r\n").starts_with("250"));
    }

    #[test]
    fn auth_juste_apres_la_poignee_de_main_exige_un_nouvel_ehlo() {
        let mut session = acceptante();
        session.on_tls_established();
        assert_eq!(
            jouer(&mut session, b"AUTH PLAIN\r\n"),
            "503 Send EHLO first\r\n"
        );
    }

    // ── Les commandes sans effet, et les refus ──────────────────────────────

    #[test]
    fn noop_vrfy_expn_et_help_repondent_sans_rien_reveler() {
        let mut session = acceptante();
        assert_eq!(jouer(&mut session, b"NOOP\r\n"), "250 OK\r\n");
        // `VRFY` ne dit pas si la boîte existe (RFC 5321 §7.3).
        assert_eq!(
            jouer(&mut session, b"VRFY jean\r\n"),
            "252 Cannot verify; message will be attempted\r\n"
        );
        // `EXPN` publierait les membres d'une liste.
        assert_eq!(
            jouer(&mut session, b"EXPN liste\r\n"),
            "502 EXPN not available\r\n"
        );
        assert_eq!(jouer(&mut session, b"HELP\r\n"), "214 See RFC 5321\r\n");
    }

    #[test]
    fn chaque_famille_d_erreur_d_analyse_a_son_code() {
        let mut session = acceptante();
        let bornes = [
            (b"XYZZY\r\n".as_slice(), "500 Command not recognised\r\n"),
            (b"TURN\r\n", "502 Command not implemented\r\n"),
            (b"QUIT", "500 Line must end with CRLF\r\n"),
            (
                b"MAIL FROM:<pas-une-boite>\r\n",
                "501 Syntax error in parameters or arguments\r\n",
            ),
        ];
        for (ligne, attendu) in bornes {
            assert_eq!(jouer(&mut session, ligne), attendu, "sur {ligne:?}");
        }

        // La ligne trop longue a sa borne propre.
        let mut longue = std::vec::Vec::from(b"NOOP ".as_slice());
        longue.extend(std::iter::repeat_n(b'a', 600));
        longue.extend_from_slice(b"\r\n");
        assert_eq!(jouer(&mut session, &longue), "500 Line too long\r\n");
    }

    #[test]
    fn aucune_reponse_ne_reprend_ce_que_le_pair_a_envoye() {
        // L'INJECTION DE RÉPONSE DEVIENT INEXPRIMABLE, et pas seulement refusée
        // par l'encodeur : la session ne compose ses réponses qu'avec des textes
        // constants et son propre domaine.
        let mut session = acceptante();
        let sonde = b"MAIL FROM:<zzmarqueurzz@example.invalid>\r\n";
        let reponse = jouer(&mut session, sonde);
        assert!(!reponse.contains("zzmarqueurzz"), "{reponse}");
    }

    // ── Les types ───────────────────────────────────────────────────────────

    #[test]
    fn ce_qui_n_est_pas_declare_n_est_ni_annonce_ni_servi() {
        // UN SERVEUR N'OFFRE QUE CE QUE QUELQU'UN SAIT CONDUIRE. Annoncer
        // `STARTTLS` sans savoir chiffrer ferait attendre un chiffrement qui ne
        // viendrait pas ; annoncer `AUTH` ferait envoyer un mot de passe.
        let nue = Config::new(b"mail.example.com", 2, 1024, Limits::DEFAULT).expect("configurable");
        let mut session = SmtpSession::new(nue, Verdict(RecipientVerdict::Accept));

        let annonce = jouer(&mut session, b"EHLO client.example\r\n");
        assert_eq!(annonce, "250-mail.example.com\r\n250 SIZE 1024\r\n");
        assert!(!annonce.contains("STARTTLS"));
        assert!(!annonce.contains("AUTH"));

        // Et les commandes correspondantes sont refusées comme non servies.
        assert_eq!(
            jouer(&mut session, b"STARTTLS\r\n"),
            "502 Command not implemented\r\n"
        );
        assert_eq!(
            jouer(&mut session, b"AUTH PLAIN\r\n"),
            "502 Command not implemented\r\n"
        );
    }

    #[test]
    fn les_types_publics_se_copient_et_se_deboguent() {
        let mut session = acceptante();
        let mut tampon = [0_u8; 128];
        let tour = session.handle(b"NOOP\r\n", &mut tampon).expect("réponse");
        let copie = tour;
        assert_eq!(copie, tour);
        assert!(!std::format!("{tour:?}").is_empty());
        assert!(!std::format!("{:?}", tour.action()).is_empty());
        assert_ne!(Action::Continue, Action::Close);
        assert!(!std::format!("{:?}", RecipientVerdict::Accept).is_empty());
        assert_ne!(RecipientVerdict::Accept, RecipientVerdict::RelayDenied);
        assert!(!std::format!("{:?}", DataOutcome::Accepted).is_empty());
        assert_ne!(DataOutcome::Accepted, DataOutcome::RejectedPermanent);
    }

    #[test]
    fn une_reponse_qui_ne_tient_pas_dans_le_tampon_est_une_erreur() {
        let mut session = acceptante();
        let mut minuscule = [0_u8; 4];
        assert_eq!(
            session.handle(b"NOOP\r\n", &mut minuscule),
            Err(tampon_trop_petit(8))
        );
        // Y compris pour l'`EHLO`, qui est multiligne : 22 + 19 + 14.
        assert_eq!(
            session.handle(b"EHLO client.example\r\n", &mut minuscule),
            Err(tampon_trop_petit(55))
        );
        // Et pour `HELO`, qui ne l'est pas.
        assert_eq!(
            session.handle(b"HELO client.example\r\n", &mut minuscule),
            Err(tampon_trop_petit(22))
        );
    }
}
