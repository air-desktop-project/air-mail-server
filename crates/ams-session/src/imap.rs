//! La session IMAP (RFC 9051 §3), **sans entrée-sortie**.
//!
//! # Quatre états, et c'est l'état qui décide de tout
//!
//! IMAP est le seul des trois protocoles de ce dépôt dont le vocabulaire dépend
//! entièrement d'où l'on en est (§3) :
//!
//! - **non authentifié** — on peut se présenter, chiffrer, s'authentifier ;
//! - **authentifié** — on peut parler de boîtes ;
//! - **sélectionné** — on peut parler des messages de l'une d'elles ;
//! - **déconnecté** — on ne peut plus rien.
//!
//! `SELECT` avant authentification est une commande parfaitement FORMÉE : c'est
//! l'état qui la refuse, pas la grammaire. Mélanger les deux ferait un analyseur
//! qui doit connaître l'état, et un état qui doit connaître la grammaire.
//!
//! # UN MOT DE PASSE NE TRAVERSE PAS UNE CONNEXION EN CLAIR
//!
//! `LOGIN` envoie l'identifiant et le mot de passe en clair, et `AUTHENTICATE
//! PLAIN` fait la même chose en base64 — ce qui n'est pas un chiffrement. La
//! RFC 9051 §6.2.3 impose d'annoncer `LOGINDISABLED` tant que la connexion n'est
//! pas protégée ; cette session va au bout de la même idée et **refuse les
//! deux**, avec le code `[PRIVACYREQUIRED]` que la RFC prévoit exactement pour
//! cela.
//!
//! Annoncer sans refuser laisserait un client mal écrit envoyer le mot de passe
//! quand même — et l'annonce n'aurait servi qu'à se donner bonne conscience.
//!
//! # `STARTTLS` EFFACE TOUT CE QUI PRÉCÈDE
//!
//! RFC 9051 §6.2.1 : après la poignée de main, le client doit oublier ce que le
//! serveur avait annoncé, et le serveur ce qu'il avait entendu. Ce n'est pas une
//! politesse : ce qui a été dit en clair a pu être dit par quelqu'un d'autre.
//! [`Session::on_tls_established`] repart donc de l'état non authentifié.
//!
//! # Ce qui n'est pas ici
//!
//! **Les boîtes.** `SELECT`, `LIST`, `FETCH` et les autres sont reconnus, leur
//! état est vérifié, et la session répond qu'elle ne les sert pas encore. Les
//! servir demande un magasin qui porte des UID stables et des marques
//! persistantes — ce que Maildir ne fait pas seul, et ce à quoi `ams-index`
//! existe. C'est la tranche suivante, pas un oubli.

use ams_proto_imap::{
    Args, Command, Error as ImapError, Limits, Line, Status, Tag, encode_continuation,
    encode_tagged, encode_untagged, encode_untagged_parts,
};
use ams_sasl::{decode_base64, parse_plain};
use core::fmt;

use crate::policy::Authenticator;

/// Ce qui peut mal se passer dans une session IMAP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// L'encodage de la réponse a échoué — en pratique, un tampon trop petit.
    Reply(ImapError),
    /// Une commande est arrivée alors que la session attend autre chose.
    NotInCommandPhase,
    /// Une commande est arrivée après `LOGOUT`.
    SessionClosed,
    /// Une réponse SASL est arrivée alors qu'aucun défi n'est en attente.
    NotInAuthExchange,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Reply(cause) => write!(f, "réponse inencodable : {cause}"),
            Error::NotInCommandPhase => {
                f.write_str("la session n'attend pas de commande à cet instant")
            }
            Error::SessionClosed => f.write_str("la session est close depuis `LOGOUT`"),
            Error::NotInAuthExchange => {
                f.write_str("une réponse SASL est arrivée hors d'un échange d'authentification")
            }
        }
    }
}

impl core::error::Error for Error {}

/// L'état d'une session (RFC 9051 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Rien n'est établi : se présenter, chiffrer, s'authentifier.
    NotAuthenticated,
    /// Authentifié : on peut parler de boîtes.
    Authenticated,
    /// Une boîte est ouverte : on peut parler de ses messages.
    Selected,
    /// Fini.
    Logout,
}

/// Ce que l'appelant doit faire après avoir émis la réponse.
///
/// Pas `#[non_exhaustive]`, pour la même raison qu'en SMTP et en POP3 : une
/// action nouvelle doit casser la compilation de la boucle qui la pilote, pas
/// tomber dans un bras `_`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Rien de particulier : lire la commande suivante.
    Continue,
    /// Conduire la poignée de main TLS, puis appeler
    /// [`Session::on_tls_established`].
    StartTls,
    /// Lire une ligne de plus, et la passer à [`Session::on_auth_response`].
    ReadAuthResponse,
    /// Fermer la connexion.
    Close,
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
    /// C'est la session qui le dit, comme ailleurs : `NO` sanctionne aussi bien
    /// un mot de passe faux qu'une boîte absente, et seul l'endroit qui compose
    /// la réponse sait laquelle des deux c'est.
    #[must_use]
    pub const fn peer_fault(&self) -> bool {
        self.peer_fault
    }
}

/// Le tag le plus long que la session retienne.
///
/// Elle le recopie dans sa réponse : le retenir demande de la place, et cette
/// place est bornée ici plutôt que par la configuration. Un tag plus long est
/// refusé à la lecture.
pub const TAG_MAX_OCTETS: usize = 32;

/// Le nom d'utilisateur le plus long que la session retienne.
///
/// Soixante-quatre octets, comme `ams_auth` : un nom plus long ne peut
/// correspondre à aucun compte.
pub const USER_MAX_OCTETS: usize = 64;

/// Ce qu'une réponse SASL peut faire au plus, une fois décodée.
///
/// `PLAIN` porte trois champs séparés par des octets nuls ; mille vingt-quatre
/// octets majorent largement tout ce qui peut correspondre à un compte.
const SASL_DECODED_MAX: usize = 1024;

/// Une session IMAP.
#[derive(Debug, Clone)]
pub struct Session<A: Authenticator> {
    limits: Limits,
    /// Ce serveur sait-il monter en chiffrement ?
    starttls_offered: bool,
    /// L'est-il déjà ?
    chiffre: bool,
    etat: State,
    policy: A,
    /// Le tag de la commande dont on attend la suite.
    tag: [u8; TAG_MAX_OCTETS],
    tag_len: usize,
    /// Attend-on une réponse SASL ?
    attend_sasl: bool,
    /// L'utilisateur authentifié.
    utilisateur: [u8; USER_MAX_OCTETS],
    utilisateur_len: usize,
}

impl<A: Authenticator> Session<A> {
    /// Ouvre une session.
    ///
    /// `starttls_offered` dit si l'appelant sait conduire une poignée de main.
    /// **Annoncer `STARTTLS` sans savoir le faire ferait mentir la bannière**,
    /// et la session ne l'annonce donc que si on le lui dit.
    #[must_use]
    pub fn new(limits: Limits, starttls_offered: bool, policy: A) -> Self {
        Self {
            // Le tag est retenu dans un tableau de taille fixe : la borne de la
            // session prime sur celle de la configuration, sans quoi un tag
            // accepté ne tiendrait pas dans ce qui doit le recopier.
            limits: Limits {
                max_tag_octets: limits.max_tag_octets.min(TAG_MAX_OCTETS),
                ..limits
            },
            starttls_offered,
            chiffre: false,
            etat: State::NotAuthenticated,
            policy,
            tag: [0; TAG_MAX_OCTETS],
            tag_len: 0,
            attend_sasl: false,
            utilisateur: [0; USER_MAX_OCTETS],
            utilisateur_len: 0,
        }
    }

    /// L'état courant.
    #[must_use]
    pub fn state(&self) -> State {
        self.etat
    }

    /// La connexion est-elle chiffrée ?
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.chiffre
    }

    /// L'utilisateur authentifié, ou une tranche vide.
    #[must_use]
    pub fn user(&self) -> &[u8] {
        self.utilisateur.get(..self.utilisateur_len).unwrap_or(&[])
    }

    /// La bannière, `CAPABILITY` compris (RFC 9051 §7.1.1).
    ///
    /// # Errors
    ///
    /// [`Error::Reply`] si `out` ne suffit pas.
    pub fn greeting<'b>(&self, out: &'b mut [u8]) -> Result<&'b [u8], Error> {
        let morceaux = self.capacites(b"OK [CAPABILITY ", b"] IMAP4rev2 service ready");
        encode_untagged_parts(out, &morceaux, &self.limits).map_err(Error::Reply)
    }

    /// La demande de continuation qui précède un littéral synchronisant.
    ///
    /// C'est le découpage qui dit quand — voir
    /// [`ams_proto_imap::Need::Continuation`] — et c'est la session qui écrit,
    /// parce qu'aucun texte de protocole ne se compose ailleurs qu'ici.
    ///
    /// # Errors
    ///
    /// [`Error::Reply`] si `out` ne suffit pas.
    pub fn literal_continuation<'b>(&self, out: &'b mut [u8]) -> Result<&'b [u8], Error> {
        encode_continuation(out, b"ready for literal", &self.limits).map_err(Error::Reply)
    }

    /// Ce qu'on dit à un pair qu'on ne servira pas maintenant.
    ///
    /// Le garde (C8) l'a écarté : on le lui dit, et l'on ferme. `BYE` est la
    /// seule réponse qu'un serveur puisse émettre sans qu'une commande l'ait
    /// demandée (§7.1.5), et c'est exactement le cas ici.
    ///
    /// # Errors
    ///
    /// [`Error::Reply`] si `out` ne suffit pas.
    pub fn unavailable<'b>(&self, out: &'b mut [u8]) -> Result<&'b [u8], Error> {
        encode_untagged(
            out,
            b"BYE [UNAVAILABLE] Service temporarily unavailable",
            &self.limits,
        )
        .map_err(Error::Reply)
    }

    /// Ce qu'on dit avant de raccrocher sur une commande indécodable.
    ///
    /// # POURQUOI ON FERME PLUTÔT QUE DE REPRENDRE
    ///
    /// Une commande IMAP se termine là où sa syntaxe le dit — un `CRLF` hors
    /// littéral. Quand cette syntaxe est fautive, **on ne sait plus où elle se
    /// termine** : reprendre la lecture reviendrait à laisser le client choisir
    /// ce qu'on lira comme une commande, ce qui est exactement la faille que le
    /// découpage existe pour fermer.
    ///
    /// # Errors
    ///
    /// [`Error::Reply`] si `out` ne suffit pas.
    pub fn cannot_parse<'b>(&self, out: &'b mut [u8]) -> Result<&'b [u8], Error> {
        encode_untagged(
            out,
            b"BAD Command could not be parsed; closing connection",
            &self.limits,
        )
        .map_err(Error::Reply)
    }

    /// Reprend après la poignée de main.
    ///
    /// **Tout ce qui précède est oublié** (RFC 9051 §6.2.1) : ce qui a été dit
    /// en clair a pu être dit par quelqu'un d'autre.
    pub fn on_tls_established(&mut self) {
        self.chiffre = true;
        self.etat = State::NotAuthenticated;
        self.attend_sasl = false;
        self.tag_len = 0;
        self.utilisateur_len = 0;
    }

    /// Traite une commande **entière**, telle que
    /// [`ams_proto_imap::CommandReader`] l'a délimitée.
    ///
    /// # Errors
    ///
    /// [`Error::SessionClosed`] après `LOGOUT`, [`Error::NotInCommandPhase`]
    /// pendant un échange SASL, [`Error::Reply`] si `out` ne suffit pas.
    pub fn handle<'b>(&mut self, commande: &[u8], out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        if self.etat == State::Logout {
            return Err(Error::SessionClosed);
        }
        if self.attend_sasl {
            return Err(Error::NotInCommandPhase);
        }
        let lue = match Line::parse(commande, &self.limits) {
            Ok(lue) => lue,
            Err(cause) => return self.faute_de_lecture(commande, cause, out),
        };
        self.retenir_le_tag(lue.tag);
        match lue.command {
            // ── Valables dans tous les états (§6.1) ─────────────────────────
            Command::Capability => self.capability(out),
            Command::Noop => self.termine(Status::Ok, b"NOOP completed", Action::Continue, out),
            Command::Logout => self.logout(out),
            // ── Non authentifié seulement (§6.2) ────────────────────────────
            Command::StartTls => self.starttls(out),
            Command::Login => self.login(lue.arguments, out),
            Command::Authenticate => self.authenticate(lue.arguments, out),
            // ── Authentifié, ou sélectionné (§6.3) ──────────────────────────
            Command::Enable
            | Command::Select
            | Command::Examine
            | Command::Create
            | Command::Delete
            | Command::Rename
            | Command::Subscribe
            | Command::Unsubscribe
            | Command::List
            | Command::Namespace
            | Command::Status
            | Command::Append
            | Command::Idle => self.si_authentifie(out),
            // ── Sélectionné seulement (§6.4) ────────────────────────────────
            Command::Close
            | Command::Unselect
            | Command::Expunge
            | Command::Search
            | Command::Fetch
            | Command::Store
            | Command::Copy
            | Command::Move
            | Command::Uid => self.si_selectionne(out),
            // ── Retirés par IMAP4rev2 (§A) ──────────────────────────────────
            Command::Lsub | Command::Check => self.termine(
                Status::Bad,
                b"Command removed in IMAP4rev2",
                Action::Continue,
                out,
            ),
        }
    }

    /// Traite la réponse à un défi SASL.
    ///
    /// # Errors
    ///
    /// [`Error::NotInAuthExchange`] si aucun défi n'est en attente,
    /// [`Error::Reply`] si `out` ne suffit pas.
    pub fn on_auth_response<'b>(
        &mut self,
        reponse: &[u8],
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        if !self.attend_sasl {
            return Err(Error::NotInAuthExchange);
        }
        self.attend_sasl = false;
        // `*` annule l'échange (§6.2.2). Ce n'est pas une faute du pair : c'est
        // un client qui se ravise, et le lui reprocher gonflerait un compteur
        // qui doit rester celui des vraies fautes.
        if reponse.trim_ascii() == b"*" {
            return self.termine(
                Status::Bad,
                b"Authentication cancelled",
                Action::Continue,
                out,
            );
        }
        self.regler_authentification(reponse.trim_ascii(), out)
    }

    // ── Les commandes ───────────────────────────────────────────────────────

    /// `CAPABILITY` : une réponse non sollicitée, puis la conclusion.
    fn capability<'b>(&mut self, out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        let morceaux = self.capacites(b"CAPABILITY ", b"");
        let annonce = encode_untagged_parts(out, &morceaux, &self.limits)
            .map_err(Error::Reply)?
            .len();
        let suite = out.get_mut(annonce..).unwrap_or_default();
        let conclusion = encode_tagged(
            suite,
            self.tag_lu(),
            Status::Ok,
            b"CAPABILITY completed",
            &self.limits,
        )
        .map_err(Error::Reply)?
        .len();
        Ok(Turn {
            reply: out
                .get(..annonce.saturating_add(conclusion))
                .unwrap_or_default(),
            action: Action::Continue,
            peer_fault: false,
        })
    }

    /// `LOGOUT` : un adieu non sollicité, puis la conclusion (§6.1.3).
    fn logout<'b>(&mut self, out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        let adieu = encode_untagged(out, b"BYE IMAP4rev2 server logging out", &self.limits)
            .map_err(Error::Reply)?
            .len();
        let suite = out.get_mut(adieu..).unwrap_or_default();
        let conclusion = encode_tagged(
            suite,
            self.tag_lu(),
            Status::Ok,
            b"LOGOUT completed",
            &self.limits,
        )
        .map_err(Error::Reply)?
        .len();
        self.etat = State::Logout;
        Ok(Turn {
            reply: out
                .get(..adieu.saturating_add(conclusion))
                .unwrap_or_default(),
            action: Action::Close,
            peer_fault: false,
        })
    }

    /// `STARTTLS` (§6.2.1).
    fn starttls<'b>(&mut self, out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        if self.chiffre {
            return self.faute(b"TLS is already active", out);
        }
        if !self.starttls_offered {
            // On ne l'annonce pas ; le demander quand même n'est pas une faute
            // de syntaxe, c'est une demande qu'on ne peut pas satisfaire.
            return self.termine(
                Status::No,
                b"STARTTLS is not available",
                Action::Continue,
                out,
            );
        }
        // ON NE VÉRIFIE PAS L'ÉTAT ICI, et ce n'est pas un oubli : on ne peut
        // pas être authentifié sans être chiffré — `LOGIN` et `AUTHENTICATE`
        // l'exigent tous deux — donc toute session qui a dépassé l'état non
        // authentifié est déjà repartie par le refus ci-dessus. Une comparaison
        // de plus serait une garde qu'aucune entrée ne peut faire céder.
        self.termine(
            Status::Ok,
            b"Begin TLS negotiation now",
            Action::StartTls,
            out,
        )
    }

    /// `LOGIN` (§6.2.3).
    fn login<'b>(&mut self, arguments: &[u8], out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        if self.etat != State::NotAuthenticated {
            return self.faute(b"LOGIN is not allowed in this state", out);
        }
        if !self.chiffre {
            // §6.2.3 : le refus, et le code que la RFC prévoit pour lui.
            return self.termine(
                Status::No,
                b"[PRIVACYREQUIRED] Encryption required before LOGIN",
                Action::Continue,
                out,
            );
        }
        let mut lus = Args::new(arguments);
        let (Some(Ok(nom)), Some(Ok(secret)), None) = (lus.next(), lus.next(), lus.next()) else {
            return self.faute(b"LOGIN expects a user name and a password", out);
        };
        let mut place_nom = [0_u8; USER_MAX_OCTETS];
        let mut place_secret = [0_u8; SASL_DECODED_MAX];
        let (Ok(nom), Ok(secret)) = (nom.value(&mut place_nom), secret.value(&mut place_secret))
        else {
            // Trop long pour tenir : cela ne correspond à aucun compte.
            return self.refuser_l_authentification(out);
        };
        let credentials = ams_sasl::Credentials {
            authorization_identity: &[],
            authentication_identity: nom,
            password: secret,
        };
        let succes = self.policy.authenticate(&credentials);
        self.conclure_l_authentification(succes, nom, out)
    }

    /// `AUTHENTICATE` (§6.2.2), avec la réponse initiale de la RFC 4959.
    fn authenticate<'b>(&mut self, arguments: &[u8], out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        if self.etat != State::NotAuthenticated {
            return self.faute(b"AUTHENTICATE is not allowed in this state", out);
        }
        let mut lus = Args::new(arguments);
        let Some(Ok(mecanisme)) = lus.next() else {
            return self.faute(b"AUTHENTICATE expects a mechanism", out);
        };
        if !mecanisme.equals_ignore_case(b"PLAIN") {
            // Le seul mécanisme servi. Le dire ainsi vaut mieux qu'un `BAD` :
            // le client sait alors qu'il doit en essayer un autre.
            return self.termine(
                Status::No,
                b"Unsupported authentication mechanism",
                Action::Continue,
                out,
            );
        }
        if !self.chiffre {
            // `PLAIN` en base64 n'est pas un chiffrement. Annoncer sans refuser
            // laisserait un client mal écrit envoyer le mot de passe quand même.
            return self.termine(
                Status::No,
                b"[PRIVACYREQUIRED] Encryption required before AUTHENTICATE",
                Action::Continue,
                out,
            );
        }
        match (lus.next(), lus.next()) {
            // RFC 4959 : la réponse initiale évite un aller-retour.
            (Some(Ok(initiale)), None) => {
                let mut place = [0_u8; SASL_DECODED_MAX];
                let Ok(base64) = initiale.value(&mut place) else {
                    return self.refuser_l_authentification(out);
                };
                let mut copie = [0_u8; SASL_DECODED_MAX];
                let longueur = base64.len().min(copie.len());
                copie
                    .get_mut(..longueur)
                    .unwrap_or_default()
                    .copy_from_slice(base64.get(..longueur).unwrap_or_default());
                self.regler_authentification(copie.get(..longueur).unwrap_or_default(), out)
            }
            (None, _) => {
                self.attend_sasl = true;
                let ecrit = encode_continuation(out, b"", &self.limits)
                    .map_err(Error::Reply)?
                    .len();
                Ok(Turn {
                    reply: out.get(..ecrit).unwrap_or_default(),
                    action: Action::ReadAuthResponse,
                    peer_fault: false,
                })
            }
            _ => self.faute(b"AUTHENTICATE takes at most one initial response", out),
        }
    }

    /// Décode, lit, interroge la politique, et répond.
    fn regler_authentification<'b>(
        &mut self,
        base64: &[u8],
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        let mut clair = [0_u8; SASL_DECODED_MAX];
        let (succes, nom) = match decode_base64(base64, &mut clair) {
            Ok(ecrits) => {
                let lus = clair.get(..ecrits).unwrap_or_default();
                match parse_plain(lus) {
                    Ok(identifiants) => (
                        self.policy.authenticate(&identifiants),
                        identifiants.authentication_identity,
                    ),
                    Err(_) => (false, &[][..]),
                }
            }
            Err(_) => (false, &[][..]),
        };
        if succes {
            let mut place = [0_u8; USER_MAX_OCTETS];
            let longueur = nom.len().min(place.len());
            place
                .get_mut(..longueur)
                .unwrap_or_default()
                .copy_from_slice(nom.get(..longueur).unwrap_or_default());
            return self.conclure_l_authentification(
                true,
                place.get(..longueur).unwrap_or_default(),
                out,
            );
        }
        self.refuser_l_authentification(out)
    }

    /// Retient l'utilisateur et passe à l'état suivant, ou refuse.
    fn conclure_l_authentification<'b>(
        &mut self,
        succes: bool,
        nom: &[u8],
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        if !succes {
            return self.refuser_l_authentification(out);
        }
        let longueur = nom.len().min(self.utilisateur.len());
        self.utilisateur
            .get_mut(..longueur)
            .unwrap_or_default()
            .copy_from_slice(nom.get(..longueur).unwrap_or_default());
        self.utilisateur_len = longueur;
        self.etat = State::Authenticated;
        self.termine(Status::Ok, b"Authenticated", Action::Continue, out)
    }

    /// Le refus, qui ne dit pas ce qui a manqué.
    ///
    /// « Utilisateur inconnu » et « mot de passe faux » sont deux réponses
    /// différentes, et cette différence est un annuaire pour qui la mesure. Il
    /// est en revanche compté comme une FAUTE (C8) : un mot de passe essayé au
    /// hasard est exactement ce qu'un garde doit voir passer.
    fn refuser_l_authentification<'b>(&mut self, out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        let ecrit = encode_tagged(
            out,
            self.tag_lu(),
            Status::No,
            b"[AUTHENTICATIONFAILED] Authentication credentials invalid",
            &self.limits,
        )
        .map_err(Error::Reply)?
        .len();
        Ok(Turn {
            reply: out.get(..ecrit).unwrap_or_default(),
            action: Action::Continue,
            peer_fault: true,
        })
    }

    // ── Les états ───────────────────────────────────────────────────────────

    /// Une commande qui demande d'être authentifié.
    fn si_authentifie<'b>(&mut self, out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        if self.etat == State::NotAuthenticated {
            return self.faute(b"Command is not allowed before authentication", out);
        }
        self.pas_encore(out)
    }

    /// Une commande qui demande une boîte ouverte.
    ///
    /// # AUCUNE BOÎTE NE PEUT ÊTRE OUVERTE AUJOURD'HUI
    ///
    /// `SELECT` n'est pas servi : l'état sélectionné n'est donc jamais atteint,
    /// et une comparaison d'état serait ici une garde qu'aucune entrée ne peut
    /// faire céder — c'est-à-dire une affirmation non vérifiée. Le refus est
    /// donc écrit tel quel, et il dit dès maintenant au client la seule chose
    /// vraie : il n'y a pas de boîte ouverte. La comparaison reviendra avec
    /// `SELECT`, et un test l'accompagnera.
    fn si_selectionne<'b>(&mut self, out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        self.faute(b"Command is not allowed unless a mailbox is selected", out)
    }

    /// Ce que la session sait faire, et ne fait pas encore.
    ///
    /// **`NO`, et non `BAD`** : la commande est correcte et permise ; c'est ce
    /// serveur qui ne la sert pas. Un `BAD` dirait au client qu'il l'a mal
    /// écrite, et il chercherait la faute là où elle n'est pas.
    fn pas_encore<'b>(&mut self, out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        self.termine(
            Status::No,
            b"[UNAVAILABLE] Mailbox commands are not served yet",
            Action::Continue,
            out,
        )
    }

    // ── L'écriture des réponses ─────────────────────────────────────────────

    /// La liste des capacités, EN MORCEAUX, entre un préfixe et un suffixe.
    ///
    /// # Aucun tampon intermédiaire, et donc aucune garde à écrire
    ///
    /// Recoller ces bouts dans un tableau demanderait de le borner — et cette
    /// borne, qu'aucun état ne peut faire céder, serait une garde qu'aucun test
    /// ne pourrait atteindre. Les morceaux passent donc tels quels à l'encodeur,
    /// et la seule borne qui puisse échouer est celle du tampon de sortie.
    ///
    /// `LITERAL-` annonce les littéraux non synchronisants bornés à quatre
    /// kibioctets : c'est exactement ce que le découpage applique, et l'annoncer
    /// autrement serait promettre ce qu'on ne fait pas.
    fn capacites(&self, prefixe: &'static [u8], suffixe: &'static [u8]) -> [&'static [u8]; 5] {
        // §6.2.3 : tant que la connexion n'est pas protégée, on l'annonce.
        let (troisieme, quatrieme): (&[u8], &[u8]) = match (self.chiffre, self.starttls_offered) {
            (true, _) => (b" AUTH=PLAIN", b""),
            (false, true) => (b" STARTTLS", b" LOGINDISABLED"),
            (false, false) => (b" LOGINDISABLED", b""),
        };
        [
            prefixe,
            b"IMAP4rev2 LITERAL-",
            troisieme,
            quatrieme,
            suffixe,
        ]
    }

    /// Conclut la commande en cours.
    fn termine<'b>(
        &mut self,
        status: Status,
        texte: &[u8],
        action: Action,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        let ecrit = encode_tagged(out, self.tag_lu(), status, texte, &self.limits)
            .map_err(Error::Reply)?
            .len();
        Ok(Turn {
            reply: out.get(..ecrit).unwrap_or_default(),
            action,
            peer_fault: status == Status::Bad,
        })
    }

    /// Un `BAD` : le client a mal écrit sa commande, ou l'a écrite au mauvais
    /// moment.
    fn faute<'b>(&mut self, texte: &[u8], out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        self.termine(Status::Bad, texte, Action::Continue, out)
    }

    /// Ce qu'on répond à une commande qu'on n'a pas su lire.
    ///
    /// # QUAND LE TAG EST ILLISIBLE, LA RÉPONSE EST NON SOLLICITÉE
    ///
    /// RFC 9051 §7 : une réponse conclut la commande que son tag désigne. Si le
    /// tag lui-même est irrecevable, il n'y a rien à désigner — et le recopier
    /// pour le dire serait précisément l'injection que sa validation ferme. On
    /// répond alors par `*`, la seule forme qui n'affirme rien.
    fn faute_de_lecture<'b>(
        &mut self,
        commande: &[u8],
        cause: ImapError,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        let corps = commande.strip_suffix(b"\r\n").unwrap_or(commande);
        let mot = corps
            .iter()
            .position(|octet| *octet == b' ')
            .map_or(corps, |rang| corps.get(..rang).unwrap_or_default());
        let texte: &[u8] = match cause {
            ImapError::UnknownCommand => b"Unknown command",
            ImapError::MissingCommand => b"Missing command",
            _ => b"Malformed command",
        };
        let Ok(tag) = Tag::parse(mot, &self.limits) else {
            let ecrit = encode_untagged(out, b"BAD Malformed tag", &self.limits)
                .map_err(Error::Reply)?
                .len();
            return Ok(Turn {
                reply: out.get(..ecrit).unwrap_or_default(),
                action: Action::Continue,
                peer_fault: true,
            });
        };
        self.retenir_le_tag(tag);
        self.faute(texte, out)
    }

    /// Retient le tag de la commande en cours.
    fn retenir_le_tag(&mut self, tag: Tag<'_>) {
        let octets = tag.as_bytes();
        let longueur = octets.len().min(self.tag.len());
        self.tag
            .get_mut(..longueur)
            .unwrap_or_default()
            .copy_from_slice(octets.get(..longueur).unwrap_or_default());
        self.tag_len = longueur;
    }

    /// Le tag retenu, tel que l'encodeur l'attend.
    ///
    /// Il a été validé à la lecture : le relire ne peut pas échouer, et
    /// `unwrap_or` porte cette impossibilité dans la bibliothèque standard
    /// plutôt que d'ouvrir ici une branche qu'aucune entrée n'atteint.
    fn tag_lu(&self) -> Tag<'_> {
        let octets = self.tag.get(..self.tag_len).unwrap_or_default();
        Tag::parse(octets, &self.limits).unwrap_or(Tag::PLACEHOLDER)
    }
}

#[cfg(test)]
mod tests;
