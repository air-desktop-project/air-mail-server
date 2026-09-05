//! La session POP3 (RFC 1939), **sans entrée-sortie** (C1).
//!
//! # Les trois états, et ce que chacun interdit
//!
//! - **AUTHORIZATION** : le pair se nomme. `STLS`, `CAPA`, `USER`, `PASS`,
//!   `QUIT`, et rien d'autre.
//! - **TRANSACTION** : la boîte est ouverte et **verrouillée** (RFC 1939 §3).
//!   `STAT`, `LIST`, `UIDL`, `RETR`, `TOP`, `DELE`, `RSET`, `NOOP`, `QUIT`.
//! - **UPDATE** : atteint par `QUIT` depuis TRANSACTION. C'est **là seulement**
//!   que les effacements sont appliqués — un `QUIT` depuis AUTHORIZATION, ou une
//!   connexion coupée, n'efface rien. La RFC est explicite, et l'inverse
//!   perdrait du courrier sur une coupure réseau.
//!
//! # Ce que la session ne fait pas, et ne peut pas faire
//!
//! Elle ne lit aucun fichier. Ce qu'elle sait de la boîte lui vient d'un
//! [`Mailbox`] que l'appelant lui remet **une fois la session ouverte** : un
//! instantané pris au verrouillage, comme la RFC le demande. Les octets d'un
//! message, eux, ne passent jamais par elle en entier : l'appelant les lui donne
//! par morceaux, et elle les rend **doublés** ([`Session::feed_body`]).
//!
//! # `USER`/`PASS` hors chiffrement : refusé, et ce n'est pas un réglage
//!
//! Le mot de passe traverse le fil tel quel. C6 l'exclut, et il n'y a pas de
//! champ pour en décider autrement — exactement comme `AUTH` en SMTP.

use ams_proto_pop3::{Command, Error as Pop3Error, Limits, MessageNumber, Status, encode};
use ams_sasl::Credentials;

use core::fmt;

use crate::Authenticator;
use crate::digits::{MAX_DIGITS, decimal};

/// Ce qu'une session POP3 refuse à son appelant.
///
/// # Pourquoi POP3 a son propre vocabulaire d'erreurs
///
/// Celui de SMTP parle de phase de données et de destinataires refusés : rien de
/// tout cela n'existe ici, et une énumération commune obligerait chaque appelant
/// à traiter des cas que son protocole ne produit jamais.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// L'encodage de la réponse a échoué — en pratique, un tampon trop petit.
    Reply(Pop3Error),
    /// Une commande a été soumise alors que la session n'en attend pas.
    NotInCommandPhase,
    /// Une commande a été soumise après `QUIT`.
    SessionClosed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Reply(cause) => write!(f, "réponse inencodable : {cause}"),
            Error::NotInCommandPhase => {
                f.write_str("la session n'attend pas de commande à cet instant")
            }
            Error::SessionClosed => f.write_str("la session est close depuis `QUIT`"),
        }
    }
}

impl core::error::Error for Error {}

/// Le nom d'utilisateur le plus long que la session retienne.
///
/// Soixante-quatre octets, comme `ams_auth` : un nom plus long ne peut
/// correspondre à aucun compte, et le retenir ne servirait qu'à occuper de la
/// place par connexion.
pub const USER_MAX_OCTETS: usize = 64;

/// Ce que l'appelant doit faire après avoir émis la réponse.
///
/// Pas `#[non_exhaustive]`, pour la même raison qu'en SMTP : une action nouvelle
/// doit casser la compilation de la boucle qui la pilote, pas tomber dans un
/// bras `_`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Rien de particulier : lire la commande suivante.
    Continue,
    /// Conduire la poignée de main TLS, puis appeler
    /// [`Session::on_tls_established`].
    StartTls,
    /// Ouvrir et **verrouiller** la boîte de [`Session::user`], puis appeler
    /// [`Session::on_mailbox_opened`].
    OpenMailbox,
    /// Émettre les lignes de [`Session::next_listing`] jusqu'à `None`.
    SendListing,
    /// Émettre un message par [`Session::feed_body`], puis
    /// [`Session::finish_body`].
    SendBody {
        /// Le message demandé.
        message: MessageNumber,
        /// Combien de lignes de corps au plus — `None` pour tout le message.
        lines: Option<u32>,
    },
    /// Fermer **sans rien effacer**.
    Close,
    /// Appliquer les effacements, puis fermer.
    ///
    /// C'est l'état UPDATE de la RFC 1939 §6, et il n'est atteint que par un
    /// `QUIT` venu de TRANSACTION.
    CommitAndClose,
}

/// Une réponse à émettre, et ce qu'il faut faire ensuite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Turn<'b> {
    reply: &'b [u8],
    action: Action,
    peer_fault: bool,
}

impl<'b> Turn<'b> {
    /// Les octets à émettre, tels quels.
    #[must_use]
    pub const fn reply(&self) -> &'b [u8] {
        self.reply
    }

    /// Ce qu'il faut faire **après** les avoir émis.
    #[must_use]
    pub const fn action(&self) -> Action {
        self.action
    }

    /// Cette réponse sanctionne-t-elle une faute du pair ?
    ///
    /// Comme en SMTP, c'est la session qui le dit : POP3 n'a que `-ERR`, et un
    /// code de retour ne distingue pas un verbe inconnu d'un mot de passe faux.
    /// Seul l'endroit qui compose la réponse sait laquelle des deux c'est.
    #[must_use]
    pub const fn peer_fault(&self) -> bool {
        self.peer_fault
    }
}

/// Ce que la session sait d'une boîte, sans la lire.
///
/// # C'est un INSTANTANÉ, et la RFC l'exige
///
/// RFC 1939 §3 : la boîte est verrouillée à l'ouverture de la session, et le
/// nombre de messages ne change plus jusqu'au `QUIT`. Les numéros sont donc
/// stables — `1` désigne le même message du début à la fin.
///
/// # Toutes les réponses sont IMMÉDIATES
///
/// Pas de lecture de fichier : tailles et identifiants viennent de ce que
/// l'appelant a relevé au verrouillage. Une méthode qui attendrait ferait
/// attendre la session, et une session qui attend est une session qu'un pair
/// peut faire attendre.
pub trait Mailbox {
    /// Le plus grand numéro de message, effacés compris.
    ///
    /// Les numéros vont de `1` à celui-ci, et **ne sont jamais renumérotés** :
    /// un message effacé laisse son numéro inoccupé jusqu'au `QUIT`.
    fn highest(&self) -> u32;

    /// La taille d'un message, ou `None` s'il n'existe pas ou est marqué effacé.
    fn size(&self, message: MessageNumber) -> Option<u64>;

    /// L'identifiant durable d'un message (RFC 1939 §7), ou `None`.
    ///
    /// Un entier plutôt qu'une chaîne : l'UID d'une boîte Maildir en est un, et
    /// le formater ici évite à l'appelant de fournir un tampon dont la session
    /// devrait se méfier.
    fn uid(&self, message: MessageNumber) -> Option<u32>;

    /// Marque un message pour effacement. Rend `false` s'il n'existe pas ou est
    /// déjà marqué.
    fn mark_deleted(&mut self, message: MessageNumber) -> bool;

    /// Oublie toutes les marques (`RSET`, RFC 1939 §6).
    fn reset_deletions(&mut self);
}

/// L'état de la session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Le pair se nomme.
    Authorization,
    /// `PASS` a été accepté ; l'appelant doit ouvrir la boîte.
    OpeningMailbox,
    /// La boîte est ouverte.
    Transaction,
    /// Une réponse multiligne est en cours d'émission.
    Listing,
    /// Un message est en cours d'émission.
    Body,
    /// `QUIT` a été traité.
    Closed,
}

/// Ce qu'une réponse multiligne reste à dire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Listing {
    /// Les capacités (RFC 2449), à partir de ce rang.
    Capabilities(usize),
    /// `LIST` sans argument, à partir de ce numéro.
    Scan(u32),
    /// `UIDL` sans argument, à partir de ce numéro.
    Uidl(u32),
    /// Il ne reste que le terminateur.
    Terminator,
    /// Le terminateur est parti ; l'appel suivant rend `None`.
    ///
    /// **Cet état existe parce que l'appelant ne peut pas savoir.** Il boucle sur
    /// `next_listing` jusqu'à `None` — c'est le contrat — et sans cet état, la
    /// session lui répondait `NotInCommandPhase` après le terminateur. Le pilote
    /// prenait ce refus pour une panne et abandonnait la connexion : le premier
    /// `RETR` qui suivait un `LIST` n'a jamais eu lieu. Trouvé par le test de
    /// bout en bout, pas par les tests de la session — dont le harnais
    /// s'arrêtait, lui, sur le terminateur.
    Done,
}

/// La session POP3.
pub struct Session<A: Authenticator, M: Mailbox> {
    limits: Limits,
    stls_offered: bool,
    auth: A,
    phase: Phase,
    tls: bool,
    /// Le nom donné par `USER`, en attente de son `PASS`.
    user: [u8; USER_MAX_OCTETS],
    user_len: usize,
    user_given: bool,
    mailbox: Option<M>,
    listing: Listing,
    body: BodySender,
}

impl<A: Authenticator, M: Mailbox> Session<A, M> {
    /// Ouvre une session.
    ///
    /// `stls_offered` dit si l'appelant sait chiffrer. **Annoncer `STLS` sans
    /// savoir le conduire ferait envoyer un mot de passe à un serveur qui ne
    /// protégera rien** : la session ne l'annonce donc que sur déclaration.
    ///
    /// # Pas de nom de serveur, contrairement à SMTP
    ///
    /// La RFC 5321 §4.2 EXIGE que la bannière SMTP porte le nom du serveur ; la
    /// RFC 1939 §4 n'en demande rien. Ne pas le dire, c'est une chose de moins
    /// apprise par un inconnu qui n'a encore rien prouvé — et un champ de moins
    /// à tenir à jour.
    #[must_use]
    pub fn new(limits: Limits, stls_offered: bool, auth: A) -> Self {
        Self {
            limits,
            stls_offered,
            auth,
            phase: Phase::Authorization,
            tls: false,
            user: [0; USER_MAX_OCTETS],
            user_len: 0,
            user_given: false,
            mailbox: None,
            listing: Listing::Terminator,
            body: BodySender::inerte(),
        }
    }

    /// La bannière d'accueil, à émettre **avant** toute commande.
    ///
    /// # Errors
    ///
    /// [`Error::Reply`] si `out` est trop petit.
    pub fn greeting<'b>(&self, out: &'b mut [u8]) -> Result<&'b [u8], Error> {
        // Pas d'horodatage APOP dans la bannière : il ne sert qu'à `APOP`, que
        // C6 exclut, et l'y mettre inviterait un client à l'essayer.
        self.ligne(Status::Ok, b"POP3 server ready", out)
    }

    /// La réponse à émettre avant de fermer une connexion qu'on ne peut pas
    /// servir : garde anti-flooding, arrêt du service, saturation.
    ///
    /// # Errors
    ///
    /// [`Error::Reply`] si `out` est trop petit.
    pub fn unavailable<'b>(&self, out: &'b mut [u8]) -> Result<&'b [u8], Error> {
        self.ligne(Status::Err, b"Service not available", out)
    }

    /// Le nom donné par `USER`, une fois `PASS` accepté.
    #[must_use]
    pub fn user(&self) -> &[u8] {
        self.user.get(..self.user_len).unwrap_or_default()
    }

    /// La session est-elle chiffrée ?
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.tls
    }

    /// La boîte est-elle ouverte ?
    #[must_use]
    pub const fn is_open(&self) -> bool {
        self.mailbox.is_some()
    }

    /// La boîte ouverte, pour y lire un message.
    ///
    /// La session ne lit aucun fichier : c'est l'appelant qui le fait, et il lui
    /// faut donc l'objet qu'il a lui-même remis.
    #[must_use]
    pub const fn mailbox(&self) -> Option<&M> {
        self.mailbox.as_ref()
    }

    /// Reprend la boîte, pour appliquer les effacements.
    ///
    /// # Elle ne revient pas
    ///
    /// C'est l'état UPDATE : la session est close, il n'y a plus rien à servir,
    /// et laisser la boîte en place inviterait à s'en servir après coup. La
    /// reprendre **ferme aussi le verrou** dès que l'appelant la relâche.
    pub fn take_mailbox(&mut self) -> Option<M> {
        self.mailbox.take()
    }

    /// La poignée de main TLS a abouti.
    ///
    /// **Tout ce que le pair a dit en clair est oublié** (RFC 2595 §4) : le nom
    /// donné par un `USER` d'avant le chiffrement a pu être dit par quelqu'un
    /// d'autre.
    pub fn on_tls_established(&mut self) {
        self.tls = true;
        self.user_given = false;
        self.user_len = 0;
        self.phase = Phase::Authorization;
    }

    /// L'appelant a ouvert — ou n'a pas pu ouvrir — la boîte.
    ///
    /// # Errors
    ///
    /// [`Error::NotInCommandPhase`] si aucune ouverture n'était demandée.
    pub fn on_mailbox_opened<'b>(
        &mut self,
        mailbox: Option<M>,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        if self.phase != Phase::OpeningMailbox {
            return Err(Error::NotInCommandPhase);
        }
        match mailbox {
            Some(boite) => {
                self.mailbox = Some(boite);
                self.phase = Phase::Transaction;
                self.repondre(Status::Ok, b"Mailbox open", Action::Continue, false, out)
            }
            None => {
                // La boîte est verrouillée par une autre session, ou illisible.
                // Le pair revient à AUTHORIZATION : il pourra réessayer, et
                // c'est ce que la RFC 1939 §4 prévoit.
                self.phase = Phase::Authorization;
                self.user_given = false;
                self.user_len = 0;
                self.repondre(
                    Status::Err,
                    b"Mailbox unavailable",
                    Action::Continue,
                    false,
                    out,
                )
            }
        }
    }

    /// Traite une ligne de commande, **CRLF compris**.
    ///
    /// # Errors
    ///
    /// [`Error::SessionClosed`] après `QUIT`, [`Error::NotInCommandPhase`]
    /// pendant une émission, ou [`Error::Reply`].
    pub fn handle<'b>(&mut self, line: &[u8], out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        match self.phase {
            Phase::Closed => return Err(Error::SessionClosed),
            Phase::OpeningMailbox | Phase::Listing | Phase::Body => {
                return Err(Error::NotInCommandPhase);
            }
            Phase::Authorization | Phase::Transaction => {}
        }

        let commande = match Command::parse(line, &self.limits) {
            Ok(commande) => commande,
            Err(cause) => return self.on_parse_error(cause, out),
        };

        // LA BOÎTE SORT DE LA SESSION LE TEMPS DE LA COMMANDE, et c'est ce qui
        // rend l'état structurel : une commande de TRANSACTION reçoit la boîte
        // en argument, donc elle ne PEUT PAS être appelée sans. Une phase et un
        // `Option` disaient deux fois la même chose, et rien n'empêchait qu'ils
        // se contredisent — il fallait alors écrire des gardes qu'aucun test ne
        // pouvait emprunter.
        let Some(mut boite) = self.mailbox.take() else {
            return self.commande_hors_boite(commande, out);
        };
        let resultat = self.commande_de_transaction(commande, &mut boite, out);
        self.mailbox = Some(boite);
        resultat
    }

    /// Les commandes recevables **sans boîte ouverte**.
    fn commande_hors_boite<'b>(
        &mut self,
        commande: Command<'_>,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        match commande {
            Command::User(nom) => self.on_user(nom, out),
            Command::Pass(secret) => self.on_pass(secret, out),
            Command::Stls => self.on_stls(out),
            Command::Noop => self.repondre(Status::Ok, b"", Action::Continue, false, out),
            Command::Capa => self.on_capa(out),
            Command::Quit => {
                // Un `QUIT` d'ici N'EFFACE RIEN : l'état UPDATE n'est atteint
                // que depuis TRANSACTION (RFC 1939 §6), et l'inverse perdrait du
                // courrier sur une coupure réseau.
                self.phase = Phase::Closed;
                self.repondre(Status::Ok, b"Bye", Action::Close, false, out)
            }
            _ => self.mauvais_etat(out),
        }
    }

    /// Les commandes qui exigent une boîte.
    fn commande_de_transaction<'b>(
        &mut self,
        commande: Command<'_>,
        boite: &mut M,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        match commande {
            Command::Stat => self.on_stat(boite, out),
            Command::List(numero) => self.on_scan(numero, boite, out),
            Command::Uidl(numero) => self.on_uidl(numero, boite, out),
            Command::Retr(numero) => self.on_body(numero, None, boite, out),
            Command::Top { message, lines } => self.on_body(message, Some(lines), boite, out),
            Command::Dele(numero) => self.on_dele(numero, boite, out),
            Command::Rset => {
                boite.reset_deletions();
                self.repondre(Status::Ok, b"Deletions reset", Action::Continue, false, out)
            }
            Command::Noop => self.repondre(Status::Ok, b"", Action::Continue, false, out),
            Command::Capa => self.on_capa(out),
            Command::Quit => {
                self.phase = Phase::Closed;
                self.repondre(Status::Ok, b"Bye", Action::CommitAndClose, false, out)
            }
            // `USER`, `PASS`, `STLS` : la session est déjà ouverte.
            _ => self.mauvais_etat(out),
        }
    }

    /// La RFC 1939 n'a qu'un `-ERR` pour dire « pas dans cet état », et le texte
    /// ne distingue pas « pas encore » de « plus maintenant » : un pair
    /// apprendrait sinon, **sans mot de passe**, dans quel état il se trouve.
    fn mauvais_etat<'b>(&mut self, out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        self.refus(b"Command not valid in this state", out)
    }

    /// La ligne suivante d'une réponse multiligne, ou `None` quand tout est dit.
    ///
    /// # Errors
    ///
    /// [`Error::NotInCommandPhase`] si aucune émission n'est en cours, ou
    /// [`Error::Reply`] si `out` est trop petit.
    pub fn next_listing<'b>(&mut self, out: &'b mut [u8]) -> Result<Option<&'b [u8]>, Error> {
        if self.phase != Phase::Listing {
            return Err(Error::NotInCommandPhase);
        }
        match self.listing {
            Listing::Done => {
                self.phase = Phase::Transaction;
                Ok(None)
            }
            Listing::Terminator => {
                self.listing = Listing::Done;
                // LE TERMINATEUR VIENT D'ICI, et pas de la boucle : c'est du
                // protocole, et la boucle n'en compose aucun.
                let ecrit = out
                    .get_mut(..3)
                    .ok_or(Error::Reply(Pop3Error::BufferTooSmall { needed: 3 }))?;
                ecrit.copy_from_slice(b".\r\n");
                Ok(Some(ecrit))
            }
            Listing::Capabilities(rang) => {
                let capacites = self.capacites();
                // ON SAUTE LES ABSENTES. Une capacité qui n'est pas offerte vaut
                // la chaîne vide, et l'émettre telle quelle donnerait une LIGNE
                // VIDE au milieu de la liste — que la RFC 2449 ne prévoit pas, et
                // que certains clients lisent comme la fin de la réponse.
                let suivante = capacites
                    .iter()
                    .enumerate()
                    .skip(rang)
                    .find(|(_, ligne)| !ligne.is_empty());
                match suivante {
                    Some((trouve, ligne)) => {
                        self.listing = Listing::Capabilities(trouve.saturating_add(1));
                        Ok(Some(ligne_brute(out, ligne)?))
                    }
                    None => {
                        self.listing = Listing::Terminator;
                        self.next_listing(out)
                    }
                }
            }
            Listing::Scan(numero) | Listing::Uidl(numero) => {
                let uidl = matches!(self.listing, Listing::Uidl(_));
                self.ligne_de_liste(numero, uidl, out)
            }
        }
    }

    /// Rend les octets d'un message **doublés**, et dit combien ont été lus.
    ///
    /// # Le doublement est ici, et à un seul endroit
    ///
    /// Une ligne qui commence par `.` en reçoit un second (RFC 1939 §3), sans
    /// quoi elle serait prise pour le terminateur et le message finirait au
    /// milieu. L'appelant n'a donc **rien** à savoir du format : il lit son
    /// fichier, il donne les octets, il émet ce qui revient.
    ///
    /// Rend `(lus, à émettre)`. Il faut rappeler tant que `lus` est inférieur à
    /// la longueur du morceau : la sortie est bornée par `out`, et un point
    /// doublé occupe deux places pour une.
    ///
    /// # Errors
    ///
    /// [`Error::NotInCommandPhase`] si aucun message n'est en cours.
    pub fn feed_body<'b>(
        &mut self,
        chunk: &[u8],
        out: &'b mut [u8],
    ) -> Result<(usize, &'b [u8]), Error> {
        if self.phase != Phase::Body {
            return Err(Error::NotInCommandPhase);
        }
        Ok(self.body.transformer(chunk, out))
    }

    /// Le message est fini : rend la fin de ligne éventuelle et le terminateur.
    ///
    /// # Errors
    ///
    /// [`Error::NotInCommandPhase`] si aucun message n'est en cours, ou
    /// [`Error::Reply`] si `out` est trop petit.
    pub fn finish_body<'b>(&mut self, out: &'b mut [u8]) -> Result<&'b [u8], Error> {
        if self.phase != Phase::Body {
            return Err(Error::NotInCommandPhase);
        }
        self.phase = Phase::Transaction;
        // Un message qui ne finit pas par un `CRLF` en reçoit un : sans lui, le
        // terminateur se collerait à la dernière ligne, et le client lirait un
        // message tronqué suivi d'un point qui n'en est pas un.
        let fin: &[u8] = if self.body.debut_de_ligne {
            b".\r\n"
        } else {
            b"\r\n.\r\n"
        };
        let ecrit = out
            .get_mut(..fin.len())
            .ok_or(Error::Reply(Pop3Error::BufferTooSmall {
                needed: fin.len(),
            }))?;
        ecrit.copy_from_slice(fin);
        Ok(ecrit)
    }

    /// Le message demandé est-il entièrement émis ?
    ///
    /// Vrai quand `TOP` a rendu toutes les lignes demandées : l'appelant peut
    /// alors cesser de lire le fichier.
    #[must_use]
    pub const fn body_complete(&self) -> bool {
        self.body.fini
    }

    // ── Les commandes ───────────────────────────────────────────────────────

    fn on_user<'b>(&mut self, nom: &[u8], out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        if !self.tls {
            // C6, ET CE N'EST PAS UN RÉGLAGE. Un mot de passe envoyé en clair
            // est lu par qui regarde passer les paquets, et l'avoir accepté une
            // fois suffit à le compromettre pour toujours.
            return self.refus(b"Encryption required", out);
        }
        let Some(cible) = self.user.get_mut(..nom.len()) else {
            // Plus long que tout compte possible : le retenir n'ouvrirait rien.
            return self.refus(b"Invalid user", out);
        };
        cible.copy_from_slice(nom);
        self.user_len = nom.len();
        self.user_given = true;
        self.repondre(Status::Ok, b"Send PASS", Action::Continue, false, out)
    }

    fn on_pass<'b>(&mut self, secret: &[u8], out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        if !self.tls {
            return self.refus(b"Encryption required", out);
        }
        if !self.user_given {
            return self.refus(b"Send USER first", out);
        }
        let identifiants = Credentials {
            authorization_identity: b"",
            authentication_identity: self.user.get(..self.user_len).unwrap_or_default(),
            password: secret,
        };
        if self.auth.authenticate(&identifiants) {
            self.phase = Phase::OpeningMailbox;
            // **RIEN N'EST RÉPONDU ICI**, et c'est tout le correctif : le sort
            // du `PASS` n'est pas encore connu. La boîte peut être verrouillée
            // par une autre session, et §4 veut alors un `-ERR` — que
            // `on_mailbox_opened` écrira. Répondre `+OK` d'avance en ferait DEUX
            // pour une commande, et RFC 1939 §3 n'en prévoit qu'une.
            return Ok(self.differer(Action::OpenMailbox));
        }
        // LE REFUS NE DIT PAS CE QUI A MANQUÉ, et le nom est oublié : le pair
        // recommence par `USER`. « Compte inconnu » et « mot de passe faux »
        // sont deux réponses différentes, et cette différence est un annuaire
        // pour qui la mesure.
        self.user_given = false;
        self.user_len = 0;
        self.refus(b"Authentication failed", out)
    }

    fn on_stls<'b>(&mut self, out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        if !self.stls_offered {
            return self.refus(b"Command not supported", out);
        }
        if self.tls {
            return self.refus(b"Already using TLS", out);
        }
        self.repondre(Status::Ok, b"Begin TLS", Action::StartTls, false, out)
    }

    fn on_capa<'b>(&mut self, out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        self.phase = Phase::Listing;
        self.listing = Listing::Capabilities(0);
        self.repondre(
            Status::Ok,
            b"Capability list follows",
            Action::SendListing,
            false,
            out,
        )
    }

    fn on_stat<'b>(&mut self, boite: &M, out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        let (combien, octets) = compter(boite);
        let mut texte = [0_u8; MAX_DIGITS * 2 + 1];
        let ecrits = deux_nombres(&mut texte, u64::from(combien), octets);
        let texte = texte.get(..ecrits).unwrap_or_default();
        // `compose` emprunte `texte`, qui vit sur la pile de cette fonction :
        // la réponse est donc écrite AVANT d'en sortir.
        let reply = encode(out, Status::Ok, texte, &self.limits).map_err(Error::Reply)?;
        Ok(Turn {
            reply,
            action: Action::Continue,
            peer_fault: false,
        })
    }

    fn on_scan<'b>(
        &mut self,
        numero: Option<MessageNumber>,
        boite: &M,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        match numero {
            Some(message) => self.ligne_unique(message, false, boite, out),
            None => {
                self.phase = Phase::Listing;
                self.listing = Listing::Scan(1);
                self.repondre(
                    Status::Ok,
                    b"Scan listing follows",
                    Action::SendListing,
                    false,
                    out,
                )
            }
        }
    }

    fn on_uidl<'b>(
        &mut self,
        numero: Option<MessageNumber>,
        boite: &M,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        match numero {
            Some(message) => self.ligne_unique(message, true, boite, out),
            None => {
                self.phase = Phase::Listing;
                self.listing = Listing::Uidl(1);
                self.repondre(
                    Status::Ok,
                    b"Unique-id listing follows",
                    Action::SendListing,
                    false,
                    out,
                )
            }
        }
    }

    fn on_dele<'b>(
        &mut self,
        numero: MessageNumber,
        boite: &mut M,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        if boite.mark_deleted(numero) {
            self.repondre(Status::Ok, b"Message deleted", Action::Continue, false, out)
        } else {
            self.refus(b"No such message", out)
        }
    }

    fn on_body<'b>(
        &mut self,
        message: MessageNumber,
        lines: Option<u32>,
        boite: &M,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        if boite.size(message).is_none() {
            return self.refus(b"No such message", out);
        }
        self.phase = Phase::Body;
        self.body = BodySender::nouveau(lines);
        self.repondre(
            Status::Ok,
            b"Message follows",
            Action::SendBody { message, lines },
            false,
            out,
        )
    }

    fn on_parse_error<'b>(
        &mut self,
        cause: Pop3Error,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        // Le TEXTE ne distingue pas les causes — un pair n'a rien à apprendre de
        // la façon dont sa ligne a déplu — mais la FAUTE, elle, est signalée au
        // garde (C8) : une ligne irrecevable n'est pas une commande refusée.
        let _ = cause;
        self.refus(b"Invalid command", out)
    }

    // ── Les briques ─────────────────────────────────────────────────────────

    /// Les capacités annoncées (RFC 2449), dans l'ordre.
    fn capacites(&self) -> [&'static [u8]; 4] {
        // `STLS` disparaît une fois chiffré, et `USER` n'apparaît QUE sous
        // chiffrement : annoncer `USER` en clair inviterait à envoyer un mot de
        // passe que l'on refusera, et la RFC 2449 §5 veut que les capacités
        // décrivent ce qui est RÉELLEMENT disponible.
        [
            b"TOP",
            b"UIDL",
            if self.tls { b"USER" } else { b"" },
            if self.stls_offered && !self.tls {
                b"STLS"
            } else {
                b""
            },
        ]
    }

    /// `LIST n` ou `UIDL n`.
    fn ligne_unique<'b>(
        &mut self,
        message: MessageNumber,
        uidl: bool,
        boite: &M,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        let Some(valeur) = valeur(boite, message, uidl) else {
            return self.refus(b"No such message", out);
        };
        let mut texte = [0_u8; MAX_DIGITS * 2 + 1];
        let ecrits = deux_nombres(&mut texte, u64::from(message.value()), valeur);
        let texte = texte.get(..ecrits).unwrap_or_default();
        let reply = encode(out, Status::Ok, texte, &self.limits).map_err(Error::Reply)?;
        Ok(Turn {
            reply,
            action: Action::Continue,
            peer_fault: false,
        })
    }

    /// Une ligne de `LIST` ou `UIDL` sans argument, en sautant les effacés.
    /// # Une boîte absente donne une liste vide, sans qu'on ait à le vérifier
    ///
    /// `map_or` et `and_then` disent « rien à lister » sans ouvrir de branche à
    /// nous : l'état où cette fonction serait appelée sans boîte n'existe pas,
    /// et une garde qu'aucun test ne peut emprunter n'est pas une garde.
    fn ligne_de_liste<'b>(
        &mut self,
        depuis: u32,
        uidl: bool,
        out: &'b mut [u8],
    ) -> Result<Option<&'b [u8]>, Error> {
        let plus_grand = self.mailbox.as_ref().map_or(0, Mailbox::highest);
        let mut rang = depuis;
        while rang <= plus_grand {
            let suivant = rang.saturating_add(1);
            if let Some(numero) = MessageNumber::new(rang)
                && let Some(valeur) = self
                    .mailbox
                    .as_ref()
                    .and_then(|boite| valeur(boite, numero, uidl))
            {
                self.listing = if uidl {
                    Listing::Uidl(suivant)
                } else {
                    Listing::Scan(suivant)
                };
                let mut texte = [0_u8; MAX_DIGITS * 2 + 1];
                let ecrits = deux_nombres(&mut texte, u64::from(rang), valeur);
                return ligne_brute(out, texte.get(..ecrits).unwrap_or_default()).map(Some);
            }
            rang = suivant;
        }
        self.listing = Listing::Terminator;
        self.next_listing(out)
    }

    /// Une réponse d'une ligne, avec son action.
    fn repondre<'b>(
        &self,
        status: Status,
        texte: &[u8],
        action: Action,
        peer_fault: bool,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        let reply = encode(out, status, texte, &self.limits).map_err(Error::Reply)?;
        Ok(Turn {
            reply,
            action,
            peer_fault,
        })
    }

    /// N'émet RIEN, et confie la réponse à l'étape que l'action déclenche.
    ///
    /// # UNE COMMANDE, UNE RÉPONSE (RFC 1939 §3)
    ///
    /// Les autres actions répondent d'abord et poursuivent ensuite : un `RETR`
    /// dit `+OK Message follows` PUIS émet le corps, et les deux ne font qu'une
    /// réponse multiligne. `OpenMailbox` n'est pas de cette sorte — ce qui suit
    /// n'est pas la suite d'une réponse, c'EST la réponse, et elle peut être un
    /// refus. Émettre une ligne avant elle en ferait deux.
    ///
    /// **Ce que cela coûtait** : tout client conforme lit UNE réponse par
    /// commande. Le `+OK` de trop le laissait décalé d'un cran pour le reste de
    /// la session — `poplib` lisait la réponse du `PASS` en guise de `STAT` et
    /// s'arrêtait sur « non-numeric values ». Autrement dit : POP3 ne servait
    /// aucun client qui respecte la RFC.
    const fn differer<'b>(&self, action: Action) -> Turn<'b> {
        Turn {
            reply: &[],
            action,
            peer_fault: false,
        }
    }

    /// Un refus, qui compte comme une faute du pair (C8).
    fn refus<'b>(&self, texte: &[u8], out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        self.repondre(Status::Err, texte, Action::Continue, true, out)
    }

    /// Une ligne simple, sans action.
    fn ligne<'b>(
        &self,
        status: Status,
        texte: &[u8],
        out: &'b mut [u8],
    ) -> Result<&'b [u8], Error> {
        encode(out, status, texte, &self.limits).map_err(Error::Reply)
    }
}

/// Combien de messages, et combien d'octets — **effacés exclus** (RFC 1939 §5).
fn compter<M: Mailbox>(boite: &M) -> (u32, u64) {
    let mut combien = 0_u32;
    let mut octets = 0_u64;
    // `filter_map(MessageNumber::new)` plutôt qu'un `if let` : le zéro ne peut
    // pas sortir d'une plage qui commence à un, et la branche qui le refuserait
    // ici serait inatteignable. Elle vit dans `MessageNumber::new`, où elle est
    // éprouvée.
    for numero in (1..=boite.highest()).filter_map(MessageNumber::new) {
        if let Some(taille) = boite.size(numero) {
            combien = combien.saturating_add(1);
            octets = octets.saturating_add(taille);
        }
    }
    (combien, octets)
}

/// La taille d'un message, ou son identifiant durable.
fn valeur<M: Mailbox>(boite: &M, message: MessageNumber, uidl: bool) -> Option<u64> {
    if uidl {
        boite.uid(message).map(u64::from)
    } else {
        boite.size(message)
    }
}

/// Écrit une ligne de corps telle quelle, avec son `CRLF`.
///
/// Les lignes que la session compose — capacités, `LIST`, `UIDL` — ne
/// commencent jamais par un point : il n'y a donc rien à doubler ici, et le
/// doublement vit à un seul endroit, celui qui voit les octets d'un message.
fn ligne_brute<'b>(out: &'b mut [u8], texte: &[u8]) -> Result<&'b [u8], Error> {
    let needed = texte.len().saturating_add(2);
    if out.len() < needed {
        return Err(Error::Reply(Pop3Error::BufferTooSmall { needed }));
    }
    let (cible, _) = out.split_at_mut(needed);
    let (corps, fin) = cible.split_at_mut(texte.len());
    corps.copy_from_slice(texte);
    fin.copy_from_slice(b"\r\n");
    Ok(cible)
}

/// Écrit `a b` en décimal, et rend le nombre d'octets écrits.
///
/// Le tampon est toujours assez grand — l'appelant lui donne
/// `MAX_DIGITS * 2 + 1` — et `split_at_mut` le dit mieux qu'un `get_mut` dont le
/// bras d'échec serait inatteignable.
fn deux_nombres(out: &mut [u8], a: u64, b: u64) -> usize {
    let mut reste: &mut [u8] = out;
    let mut ecrits = 0_usize;
    for (rang, valeur) in [a, b].into_iter().enumerate() {
        if rang > 0 {
            let (espace, apres) = reste.split_at_mut(1);
            espace[0] = b' ';
            reste = apres;
            ecrits = ecrits.saturating_add(1);
        }
        let mut chiffres = [0_u8; MAX_DIGITS];
        let debut = decimal(valeur, &mut chiffres);
        let combien = MAX_DIGITS.saturating_sub(debut);
        let (cible, apres) = reste.split_at_mut(combien);
        cible.copy_from_slice(&chiffres[debut..]);
        reste = apres;
        ecrits = ecrits.saturating_add(combien);
    }
    ecrits
}

/// L'émetteur du corps d'un message : il double les points, et compte les
/// lignes de `TOP`.
#[derive(Debug, Clone, Copy)]
struct BodySender {
    /// Le prochain octet commence-t-il une ligne ?
    debut_de_ligne: bool,
    /// Combien d'octets ont été vus sur la ligne en cours.
    ///
    /// **C'est ce compteur, et non `debut_de_ligne`, qui reconnaît la ligne
    /// vide** : quand le `CR` d'un `CRLF` isolé est traité, `debut_de_ligne` est
    /// déjà retombé à faux, et la séparation en-tête/corps passait inaperçue.
    /// `TOP 1 0` rendait alors le message entier.
    octets_de_la_ligne: usize,
    /// `TOP` : combien de lignes de corps restent à rendre.
    lignes_restantes: Option<u32>,
    /// A-t-on dépassé l'en-tête ? (la première ligne vide)
    dans_le_corps: bool,
    /// Le dernier octet rendu était-il un `CR` ?
    cr_vu: bool,
    /// Tout ce qui devait être rendu l'a été.
    fini: bool,
}

impl BodySender {
    const fn inerte() -> Self {
        Self {
            debut_de_ligne: true,
            octets_de_la_ligne: 0,
            lignes_restantes: None,
            dans_le_corps: false,
            cr_vu: false,
            fini: true,
        }
    }

    const fn nouveau(lignes: Option<u32>) -> Self {
        Self {
            debut_de_ligne: true,
            octets_de_la_ligne: 0,
            lignes_restantes: lignes,
            dans_le_corps: false,
            cr_vu: false,
            fini: false,
        }
    }

    /// Transforme ce qui tient, et rend `(lus, à émettre)`.
    fn transformer<'b>(&mut self, chunk: &[u8], out: &'b mut [u8]) -> (usize, &'b [u8]) {
        let mut lus = 0_usize;
        let mut ecrits = 0_usize;
        for &octet in chunk {
            if self.fini {
                // `TOP` a rendu son compte : on CONSOMME sans rien émettre, pour
                // que l'appelant puisse cesser de lire quand il le voudra plutôt
                // que de devoir vérifier à chaque morceau.
                lus = lus.saturating_add(1);
                continue;
            }
            // Deux places au plus par octet : un point de tête en coûte deux.
            let point = self.debut_de_ligne && octet == b'.';
            let besoin = if point { 2 } else { 1 };
            if ecrits.saturating_add(besoin) > out.len() {
                break;
            }
            // `split_at_mut` plutôt qu'un `get_mut` : la place vient d'être
            // vérifiée, et le bras d'échec d'un `get_mut` serait inatteignable.
            let (_, libre) = out.split_at_mut(ecrits);
            let (cible, _) = libre.split_at_mut(besoin);
            if point {
                cible[0] = b'.';
                cible[1] = octet;
            } else {
                cible[0] = octet;
            }
            ecrits = ecrits.saturating_add(besoin);
            lus = lus.saturating_add(1);

            // La fin d'une ligne est un `LF` précédé d'un `CR` : c'est la même
            // règle qu'en SMTP, et un `LF` nu ne termine rien.
            let fin_de_ligne = octet == b'\n' && self.cr_vu;
            self.cr_vu = octet == b'\r';
            self.octets_de_la_ligne = self.octets_de_la_ligne.saturating_add(1);
            if fin_de_ligne {
                // Une ligne VIDE ne porte que son `CRLF`, soit deux octets.
                let vide = self.octets_de_la_ligne == 2;
                self.octets_de_la_ligne = 0;
                if self.dans_le_corps {
                    self.lignes_restantes = self.lignes_restantes.map(|reste| {
                        let apres = reste.saturating_sub(1);
                        if apres == 0 {
                            self.fini = true;
                        }
                        apres
                    });
                } else if vide {
                    // La séparation en-tête/corps (RFC 5322 §2.1).
                    self.dans_le_corps = true;
                    if self.lignes_restantes == Some(0) {
                        self.fini = true;
                    }
                }
            }
            self.debut_de_ligne = fin_de_ligne;
        }
        let (emis, _) = out.split_at_mut(ecrits);
        (lus, emis)
    }
}

#[cfg(test)]
mod tests;
