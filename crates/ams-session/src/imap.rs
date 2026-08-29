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
//! # LES BOÎTES SONT SERVIES, ET LE MAGASIN RESTE AILLEURS
//!
//! `SELECT`, `EXAMINE`, `CLOSE`, `UNSELECT`, `LIST`, `STATUS` et `FETCH` sont
//! servis. La session ne sait pas où vivent les messages : elle demande, par
//! [`Mailboxes`] et [`Mailbox`], ce qu'elle ne peut pas savoir — combien il y
//! en a, ce que chacun pèse, où finit son en-tête — et compose le reste.
//!
//! **Elle ne lit jamais un message.** Un `FETCH` qui rend un corps ne rend pas
//! des octets : il rend un INTERVALLE dans un message, que l'appelant écoulera.
//! C'est ce qui permet de servir un message de cent mébioctets sans en tenir un
//! seul en mémoire, et c'est aussi C1 — lire un fichier est une entrée-sortie.
//!
//! # Ce qui n'est pas ici
//!
//! `STORE`, `SEARCH`, `COPY`, `MOVE`, `APPEND`, `CREATE`, `DELETE`, `RENAME` :
//! tout ce qui ÉCRIT. Lire d'abord, écrire ensuite — et écrire demande de
//! décider ce qu'un effacement veut dire dans un Maildir partagé.
//!
//! `ENVELOPE` et `BODYSTRUCTURE` non plus : ce sont des analyses du message, que
//! `ams-mime` saura faire et qui n'ont rien à voir avec une session.

use ams_proto_imap::{
    Args, Command, Error as ImapError, Fetch, FetchItem, Flags, Limits, Line, Section, SequenceSet,
    Status, Tag, encode_continuation, encode_tagged, encode_untagged, encode_untagged_parts,
    write_internal_date,
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
    /// Émettre les réponses d'un `FETCH` : appeler [`Session::next_fetch`]
    /// jusqu'à `None`, et écouler ce qu'elle désigne.
    SendFetch,
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

/// Ce que la session sait d'un message sans le lire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageInfo {
    /// L'identifiant durable (RFC 9051 §2.3.1.1).
    pub uid: u32,
    /// La taille du message entier, en octets.
    pub size: u64,
    /// Les marques.
    pub flags: Flags,
    /// Quand le message est arrivé ICI, en secondes depuis l'époque.
    pub internal_date: u64,
}

/// Une boîte ouverte.
pub trait Mailbox {
    /// Combien de messages elle porte.
    fn exists(&self) -> u32;
    /// Son `UIDVALIDITY` (RFC 9051 §2.3.1.1).
    ///
    /// **S'il change, tous les UID que le client a retenus ne valent plus.**
    /// C'est la seule chose qui autorise à réattribuer un UID.
    fn uid_validity(&self) -> u32;
    /// L'UID que portera le prochain message déposé.
    fn uid_next(&self) -> u32;
    /// Ce qu'on sait du message de rang `sequence`, à partir de un.
    ///
    /// **Ce doit être bon marché** : la session l'appelle pour chaque message
    /// qu'un ensemble pourrait désigner, y compris ceux qu'il ne désigne pas.
    fn info(&self, sequence: u32) -> Option<MessageInfo>;

    /// Où finit le bloc d'en-tête d'un message, ligne vide comprise.
    ///
    /// # Pourquoi ce n'est PAS dans [`MessageInfo`]
    ///
    /// Le trouver demande de lire le message ; le mettre dans `info` ferait
    /// ouvrir un fichier pour chaque message qu'un ensemble pourrait désigner.
    /// La session ne le demande que pour un `BODY[HEADER]` ou un `BODY[TEXT]`,
    /// c'est-à-dire une fois par message réellement rendu.
    fn header_octets(&self, sequence: u32) -> u64;

    /// Lit au plus `out.len()` octets du message de rang `sequence`, à partir
    /// de `offset`. Rend combien ont été lus ; zéro signifie « plus rien ».
    ///
    /// # C'EST LA BOÎTE OUVERTE QUI LIT, PAS LE MAGASIN
    ///
    /// La demander au magasin obligerait celui-ci à retrouver le message à
    /// chaque morceau — c'est-à-dire à relire le répertoire de la boîte pour
    /// chaque tranche de quelques kibioctets. Un `FETCH 1:* BODY[]` sur une
    /// boîte de dix mille messages y deviendrait quadratique, et c'est le
    /// client qui l'écrit. La boîte ouverte, elle, tient déjà son instantané.
    fn read(&self, sequence: u32, offset: u64, out: &mut [u8]) -> usize;

    /// Cette boîte accepte-t-elle qu'on la modifie ?
    ///
    /// # LA SESSION NE PEUT PAS LE DEVINER, ET NE DOIT PAS LE SUPPOSER
    ///
    /// `SELECT` annonce `[READ-WRITE]`, ce qui promet au client qu'il pourra
    /// marquer, effacer, déposer. Un magasin qui ne sait rien écrire rendrait
    /// cette promesse fausse, et le client ne l'apprendrait qu'en essayant.
    /// C'est donc le magasin qui répond, et `SELECT` se range à ce qu'il dit :
    /// une boîte qui ne se modifie pas est annoncée `[READ-ONLY]`, comme après
    /// un `EXAMINE`.
    fn writable(&self) -> bool;

    /// Marque un message comme lu.
    ///
    /// Appelé quand un `BODY[…]` **sans `PEEK`** le rend (§6.4.5).
    fn mark_seen(&mut self, sequence: u32);
}

/// Ce qu'il faut savoir énumérer et ouvrir pour servir une session.
///
/// # Pourquoi un trait, et pas un chemin
///
/// La session ne sait pas où vivent les boîtes, ni comment un compte s'y
/// rattache : c'est le binaire qui le sait. Elle sait seulement qu'après une
/// authentification, il faut pouvoir les nommer et en ouvrir une.
pub trait Mailboxes {
    /// Ce qu'ouvrir rend.
    type Open: Mailbox;

    /// Le nom de la boîte de rang `index`, ou `None` au-delà de la dernière.
    ///
    /// Un accès par rang plutôt qu'une liste : la session n'alloue pas, et une
    /// tranche de tranches ferait porter à l'appelant une durée de vie dont il
    /// n'a que faire.
    fn name(&self, user: &[u8], index: usize) -> Option<&[u8]>;

    /// Ouvre une boîte, ou dit qu'elle n'existe pas.
    fn open(&self, user: &[u8], name: &[u8]) -> Option<Self::Open>;
}

/// Un magasin PARTAGÉ en est un aussi.
///
/// La session prend son magasin par valeur ; une boucle qui sert mille
/// connexions n'en a qu'un. Cette implémentation-là est ce qui réconcilie les
/// deux, sans que personne n'ait à recopier une table de boîtes par connexion.
impl<T: Mailboxes> Mailboxes for &T {
    type Open = T::Open;

    fn name(&self, user: &[u8], index: usize) -> Option<&[u8]> {
        (**self).name(user, index)
    }

    fn open(&self, user: &[u8], name: &[u8]) -> Option<Self::Open> {
        (**self).open(user, name)
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

/// La longueur d'un ensemble de numéros que la session retient.
///
/// Elle le recopie pour le parcourir après avoir rendu la main : `1:*` fait
/// trois octets, et mille intervalles en font quelques milliers. Au-delà, ce
/// n'est plus la demande d'un client qui lit son courrier.
pub const SEQUENCE_TEXT_MAX: usize = 1024;

/// La longueur d'un nom de boîte que la session retient.
pub const MAILBOX_NAME_MAX: usize = 255;

/// Ce qu'une réponse SASL peut faire au plus, une fois décodée.
///
/// `PLAIN` porte trois champs séparés par des octets nuls ; mille vingt-quatre
/// octets majorent largement tout ce qui peut correspondre à un compte.
const SASL_DECODED_MAX: usize = 1024;

/// Un morceau de réponse `FETCH` à écouler.
///
/// # Pourquoi la session ne rend pas des octets
///
/// Un message peut peser cent mébioctets. Les faire passer par un tampon de
/// session obligerait à en tenir un par connexion, et à choisir sa taille — donc
/// à refuser des messages plus gros que ce qu'on a décidé. La session rend donc
/// un INTERVALLE, et c'est l'appelant qui l'écoule : c'est lui qui a le fichier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchChunk<'b> {
    /// Écrire ces octets tels quels.
    Bytes(&'b [u8]),
    /// Écrire `length` octets du message de rang `sequence`, à partir de
    /// `offset`. **Ni plus, ni moins** : la longueur a été annoncée au client.
    Message {
        /// Le rang du message dans la boîte, à partir de un.
        sequence: u32,
        /// Le décalage, en octets, depuis le début du message.
        offset: u64,
        /// Combien d'octets écrire.
        length: u64,
    },
}

/// Ce qu'un `FETCH` reste à émettre.
#[derive(Debug, Clone, Copy)]
struct Emission {
    texte: [u8; SEQUENCE_TEXT_MAX],
    texte_len: usize,
    items: [FetchItem; ams_proto_imap::FETCH_ITEMS_MAX],
    items_len: usize,
    /// L'ensemble porte-t-il des UID, ou des numéros de séquence ?
    par_uid: bool,
    /// Ce que vaut l'étoile.
    star: u32,
    /// Le prochain rang à examiner.
    courant: u32,
    /// Combien la boîte en porte.
    exists: u32,
    /// Où en est l'émission du message courant.
    etape: Etape,
}

/// Ce que l'émission d'un `FETCH` reste à faire.
///
/// **L'intervalle voyage dans l'étape**, et non à côté d'elle : une étape
/// « écouler le corps » sans corps à écouler serait un état qu'aucune entrée ne
/// produit, et qu'il faudrait pourtant traiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Etape {
    /// Choisir le message suivant, et composer sa réponse.
    Choisir,
    /// Écouler `length` octets du message `sequence`, à partir de `offset`.
    Corps {
        sequence: u32,
        offset: u64,
        length: u64,
    },
    /// Refermer la parenthèse du message courant.
    Fermer,
    /// Écrire la conclusion étiquetée, et finir.
    ///
    /// # LA CONCLUSION EST LE DERNIER MORCEAU, ET C'EST VOULU
    ///
    /// RFC 9051 §7 : les réponses non sollicitées d'une commande PRÉCÈDENT sa
    /// conclusion. La rendre par `handle`, comme toutes les autres, obligerait
    /// l'appelant à la retenir et à l'écrire après les morceaux — un ordre
    /// qu'aucun type ne lui rappellerait, et qu'il inverserait un jour. Elle est
    /// donc un morceau comme les autres, et l'ordre se lit dans le code.
    Conclure,
}

/// Une session IMAP.
#[derive(Debug, Clone)]
pub struct Session<A: Authenticator, M: Mailboxes> {
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
    /// Où vivent les boîtes.
    boites: M,
    /// La boîte ouverte, s'il y en a une.
    ouverte: Option<M::Open>,
    /// Son nom, tel que le client l'a écrit.
    nom_ouvert: [u8; MAILBOX_NAME_MAX],
    nom_ouvert_len: usize,
    /// A-t-elle été ouverte en lecture seule (`EXAMINE`) ?
    lecture_seule: bool,
    /// Le `FETCH` en cours d'émission.
    emission: Option<Emission>,
}

impl Emission {
    /// Le prochain rang qui appartient à l'ensemble, et son information.
    ///
    /// # Le coût est le produit de deux bornes, et les deux existent
    ///
    /// On parcourt les rangs, et pour chacun on demande à l'ensemble s'il le
    /// désigne. C'est `exists` fois le nombre d'intervalles — l'un borné par la
    /// boîte, l'autre par `max_sequence_items`. Aucun des deux ne vient du
    /// réseau sans borne, et c'est ce qui rend ce parcours acceptable.
    fn suivant<B: Mailbox>(&mut self, boite: &B, limits: &Limits) -> Option<(u32, MessageInfo)> {
        let texte = self.texte.get(..self.texte_len).unwrap_or_default();
        // LE TEXTE A DÉJÀ ÉTÉ VALIDÉ : `fetch` ne retient que ce qui se lit.
        // `unwrap_or` porte cette impossibilité dans la bibliothèque standard —
        // un ensemble vide ne désigne rien, ce qui est aussi la bonne réponse
        // pour un texte qu'on ne saurait plus lire.
        let ensemble = SequenceSet::parse(texte, limits).unwrap_or(SequenceSet::EMPTY);
        while self.courant <= self.exists {
            let rang = self.courant;
            self.courant = self.courant.saturating_add(1);
            let Some(info) = boite.info(rang) else {
                continue;
            };
            let clef = if self.par_uid { info.uid } else { rang };
            if ensemble.contains(clef, self.star) {
                return Some((rang, info));
            }
        }
        None
    }
}

impl<A: Authenticator, M: Mailboxes> Session<A, M> {
    /// Ouvre une session.
    ///
    /// `starttls_offered` dit si l'appelant sait conduire une poignée de main.
    /// **Annoncer `STARTTLS` sans savoir le faire ferait mentir la bannière**,
    /// et la session ne l'annonce donc que si on le lui dit.
    #[must_use]
    pub fn new(limits: Limits, starttls_offered: bool, policy: A, boites: M) -> Self {
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
            boites,
            ouverte: None,
            nom_ouvert: [0; MAILBOX_NAME_MAX],
            nom_ouvert_len: 0,
            lecture_seule: false,
            emission: None,
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

    /// Le nom de la boîte ouverte, ou une tranche vide.
    #[must_use]
    pub fn selected(&self) -> &[u8] {
        self.nom_ouvert.get(..self.nom_ouvert_len).unwrap_or(&[])
    }

    /// Lit dans la boîte ouverte, pour le compte de l'appelant.
    ///
    /// C'est le seul passage par lequel des octets de message traversent la
    /// session — et **ils la traversent sans y séjourner** : ils vont dans le
    /// tampon de l'appelant, jamais dans un état de la session.
    ///
    /// Rend zéro si aucune boîte n'est ouverte.
    pub fn read_selected(&self, sequence: u32, offset: u64, out: &mut [u8]) -> usize {
        match &self.ouverte {
            Some(boite) => boite.read(sequence, offset, out),
            None => 0,
        }
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
        self.ouverte = None;
        self.nom_ouvert_len = 0;
        self.emission = None;
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
            Command::Select => self.select(lue.arguments, false, out),
            Command::Examine => self.select(lue.arguments, true, out),
            Command::List => self.list(lue.arguments, out),
            Command::Status => self.status(lue.arguments, out),
            Command::Enable
            | Command::Create
            | Command::Delete
            | Command::Rename
            | Command::Subscribe
            | Command::Unsubscribe
            | Command::Namespace
            | Command::Append
            | Command::Idle => self.si_authentifie(out),
            // ── Sélectionné seulement (§6.4) ────────────────────────────────
            Command::Close | Command::Unselect => self.close(out),
            Command::Fetch => self.fetch(lue.arguments, false, out),
            Command::Uid => self.uid(lue.arguments, out),
            Command::Expunge | Command::Search | Command::Store | Command::Copy | Command::Move => {
                self.si_selectionne(out)
            }
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
    /// La comparaison d'état est revenue avec `SELECT` : tant qu'aucune boîte ne
    /// pouvait s'ouvrir, elle était une garde qu'aucune entrée ne pouvait faire
    /// céder, et elle n'était pas écrite. Elle l'est de nouveau, et un test
    /// l'emprunte dans les deux sens.
    fn si_selectionne<'b>(&mut self, out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        if self.etat != State::Selected {
            return self.faute(b"Command is not allowed unless a mailbox is selected", out);
        }
        self.pas_encore(out)
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

// ── LES COMMANDES DE BOÎTE ──────────────────────────────────────────────────

impl<A: Authenticator, M: Mailboxes> Session<A, M> {
    /// `SELECT` et `EXAMINE` (§6.3.2 et §6.3.3).
    ///
    /// # Sept réponses, et chacune dit quelque chose que le client ne sait pas
    ///
    /// La RFC 9051 §6.3.2 en exige plusieurs, et les omettre ne fait pas gagner
    /// une ligne : un client qui ne reçoit pas `UIDVALIDITY` ne peut pas savoir
    /// si les UID qu'il a retenus valent encore, et resynchronise tout.
    fn select<'b>(
        &mut self,
        arguments: &[u8],
        examine: bool,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        if self.etat == State::NotAuthenticated {
            return self.faute(b"Command is not allowed before authentication", out);
        }
        let mut nom = [0_u8; MAILBOX_NAME_MAX];
        let Some(nom) = self.un_nom(arguments, &mut nom) else {
            return self.faute(b"SELECT expects a mailbox name", out);
        };
        // §6.3.2 : un `SELECT` qui échoue FERME la boîte précédente. Le client
        // se retrouve authentifié sans sélection, et il doit le savoir.
        self.ouverte = None;
        self.emission = None;
        self.nom_ouvert_len = 0;
        self.etat = State::Authenticated;
        let Some(boite) = self.boites.open(self.user(), nom) else {
            return self.termine(
                Status::No,
                b"[NONEXISTENT] Mailbox does not exist",
                Action::Continue,
                out,
            );
        };

        // Une boîte qu'on ne peut pas modifier est en lecture seule, que le
        // client ait dit `SELECT` ou `EXAMINE`.
        let lecture_seule = examine || !boite.writable();
        let mut plume = Plume::neuve(out);
        plume.nombre_non_sollicite(boite.exists(), b"EXISTS")?;
        plume.crochet(b"UIDVALIDITY", boite.uid_validity())?;
        plume.crochet(b"UIDNEXT", boite.uid_next())?;
        plume.pousser(b"* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n")?;
        // PERMANENTFLAGS dit ce qui SURVIT à la session. En lecture seule, rien
        // ne survit — et le dire évite qu'un client croie avoir marqué un
        // message.
        plume.pousser(if lecture_seule {
            b"* OK [PERMANENTFLAGS ()] Read-only mailbox\r\n"
        } else {
            b"* OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)] Flags permitted\r\n"
        })?;
        plume.pousser(b"* LIST () \"/\" ")?;
        plume.pousser(nom)?;
        plume.pousser(b"\r\n")?;
        let ecrits = plume.ecrits();

        // Le nom tient : `un_nom` a écrit dans un tampon de cette taille-là.
        // On recopie par appariement, ce qui retire la question de la place.
        let longueur = nom.len().min(self.nom_ouvert.len());
        for (place, octet) in self.nom_ouvert.iter_mut().zip(nom) {
            *place = *octet;
        }
        self.nom_ouvert_len = longueur;
        self.ouverte = Some(boite);
        self.lecture_seule = lecture_seule;
        self.etat = State::Selected;
        let suite = out.get_mut(ecrits..).unwrap_or_default();
        let conclusion = encode_tagged(
            suite,
            self.tag_lu(),
            Status::Ok,
            match (lecture_seule, examine) {
                (true, true) => b"[READ-ONLY] EXAMINE completed".as_slice(),
                (true, false) => b"[READ-ONLY] SELECT completed".as_slice(),
                (false, _) => b"[READ-WRITE] SELECT completed".as_slice(),
            },
            &self.limits,
        )
        .map_err(Error::Reply)?
        .len();
        Ok(Turn {
            reply: out
                .get(..ecrits.saturating_add(conclusion))
                .unwrap_or_default(),
            action: Action::Continue,
            peer_fault: false,
        })
    }

    /// `CLOSE` et `UNSELECT` (§6.4.2 et §6.4.3).
    ///
    /// # Les deux ferment, et un seul purge
    ///
    /// `CLOSE` efface les messages marqués `\Deleted` ; `UNSELECT` non
    /// (§6.4.3). Ce serveur n'efface rien — `STORE` n'est pas servi, donc rien
    /// n'est jamais marqué — et les deux se comportent donc pareil. **Le jour où
    /// `STORE` arrivera, cette égalité devra cesser**, et c'est écrit ici pour
    /// qu'on ne l'oublie pas.
    fn close<'b>(&mut self, out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        if self.etat != State::Selected {
            return self.faute(b"Command is not allowed unless a mailbox is selected", out);
        }
        self.ouverte = None;
        self.emission = None;
        self.nom_ouvert_len = 0;
        self.etat = State::Authenticated;
        self.termine(Status::Ok, b"Mailbox closed", Action::Continue, out)
    }

    /// `LIST` (§6.3.9), dans sa forme la plus simple.
    fn list<'b>(&mut self, arguments: &[u8], out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        if self.etat == State::NotAuthenticated {
            return self.faute(b"Command is not allowed before authentication", out);
        }
        let mut lus = Args::new(arguments);
        let mut reference = [0_u8; MAILBOX_NAME_MAX];
        let mut motif = [0_u8; MAILBOX_NAME_MAX];
        let (Some(Ok(premier)), Some(Ok(second)), None) = (lus.next(), lus.next(), lus.next())
        else {
            return self.faute(b"LIST expects a reference and a pattern", out);
        };
        let (Ok(_), Ok(motif)) = (premier.value(&mut reference), second.value(&mut motif)) else {
            return self.faute(b"LIST arguments are too long", out);
        };
        // La référence est ignorée : ce serveur n'a qu'un espace de noms, et
        // prétendre en gérer plusieurs demanderait `NAMESPACE`, qui n'est pas
        // servi. Un client qui envoie autre chose que `""` obtient la même
        // liste, ce qui est ce qu'il attend d'un serveur à un seul espace.
        let mut plume = Plume::neuve(out);
        let mut index = 0_usize;
        while let Some(nom) = self.boites.name(self.user(), index) {
            index = index.saturating_add(1);
            if correspond(motif, nom) {
                plume.pousser(b"* LIST () \"/\" ")?;
                plume.pousser(nom)?;
                plume.pousser(b"\r\n")?;
            }
        }
        let ecrits = plume.ecrits();
        let suite = out.get_mut(ecrits..).unwrap_or_default();
        let conclusion = encode_tagged(
            suite,
            self.tag_lu(),
            Status::Ok,
            b"LIST completed",
            &self.limits,
        )
        .map_err(Error::Reply)?
        .len();
        Ok(Turn {
            reply: out
                .get(..ecrits.saturating_add(conclusion))
                .unwrap_or_default(),
            action: Action::Continue,
            peer_fault: false,
        })
    }

    /// `STATUS` (§6.3.11) : ce qu'une boîte contient, sans l'ouvrir.
    fn status<'b>(&mut self, arguments: &[u8], out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        if self.etat == State::NotAuthenticated {
            return self.faute(b"Command is not allowed before authentication", out);
        }
        let mut nom = [0_u8; MAILBOX_NAME_MAX];
        let Some(nom) = self.un_nom(arguments, &mut nom) else {
            return self.faute(b"STATUS expects a mailbox name and items", out);
        };
        // ON N'INTERROGE PAS DEUX FOIS CE QU'ON TIENT DÉJÀ. RFC 9051 §6.3.11
        // déconseille `STATUS` sur la boîte sélectionnée, mais ne l'interdit
        // pas, et un client le fait. La rouvrir pour l'interroger, c'est
        // demander au magasin de retrouver ce que la session a sous la main —
        // et, pour un magasin qui verrouille, c'est se heurter à son propre
        // verrou et répondre « elle n'existe pas » d'une boîte qu'on a ouverte.
        let (exists, uid_next, uid_validity) = match &self.ouverte {
            Some(ouverte) if nom == self.selected() => {
                (ouverte.exists(), ouverte.uid_next(), ouverte.uid_validity())
            }
            _ => {
                let Some(boite) = self.boites.open(self.user(), nom) else {
                    return self.termine(
                        Status::No,
                        b"[NONEXISTENT] Mailbox does not exist",
                        Action::Continue,
                        out,
                    );
                };
                (boite.exists(), boite.uid_next(), boite.uid_validity())
            }
        };
        // ON REND LES TROIS QU'ON SAIT, sans regarder ce qui a été demandé : un
        // client qui en demande un les lit tous sans dommage, et prétendre
        // filtrer demanderait d'analyser une liste dont aucun élément ne change
        // ce qu'on sait de la boîte.
        let mut plume = Plume::neuve(out);
        plume.pousser(b"* STATUS ")?;
        plume.pousser(nom)?;
        plume.pousser(b" (MESSAGES ")?;
        plume.nombre(u64::from(exists))?;
        plume.pousser(b" UIDNEXT ")?;
        plume.nombre(u64::from(uid_next))?;
        plume.pousser(b" UIDVALIDITY ")?;
        plume.nombre(u64::from(uid_validity))?;
        plume.pousser(b")\r\n")?;
        let ecrits = plume.ecrits();
        let suite = out.get_mut(ecrits..).unwrap_or_default();
        let conclusion = encode_tagged(
            suite,
            self.tag_lu(),
            Status::Ok,
            b"STATUS completed",
            &self.limits,
        )
        .map_err(Error::Reply)?
        .len();
        Ok(Turn {
            reply: out
                .get(..ecrits.saturating_add(conclusion))
                .unwrap_or_default(),
            action: Action::Continue,
            peer_fault: false,
        })
    }

    /// `UID FETCH` (§6.4.9) — et rien d'autre pour l'instant.
    fn uid<'b>(&mut self, arguments: &[u8], out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        if self.etat != State::Selected {
            return self.faute(b"Command is not allowed unless a mailbox is selected", out);
        }
        let arguments = arguments.trim_ascii_start();
        let rang = arguments
            .iter()
            .position(|octet| *octet == b' ')
            .unwrap_or(arguments.len());
        let verbe = arguments.get(..rang).unwrap_or_default();
        let reste = arguments.get(rang.saturating_add(1)..).unwrap_or_default();
        if verbe.eq_ignore_ascii_case(b"FETCH") {
            return self.fetch(reste, true, out);
        }
        self.termine(
            Status::No,
            b"[CANNOT] Only UID FETCH is served yet",
            Action::Continue,
            out,
        )
    }

    /// `FETCH` (§6.4.5).
    fn fetch<'b>(
        &mut self,
        arguments: &[u8],
        par_uid: bool,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        // LA PRÉSENCE DE LA BOÎTE EST L'ÉTAT. Vérifier les deux ferait une
        // seconde garde qu'aucune entrée ne peut faire céder : rien ne pose
        // l'état sélectionné sans boîte, ni l'inverse.
        if self.ouverte.is_none() {
            return self.faute(b"Command is not allowed unless a mailbox is selected", out);
        }
        let demande = match Fetch::parse(arguments, &self.limits) {
            Ok(demande) => demande,
            Err(ImapError::UnsupportedFetchItem) => {
                // RECONNU, ET REFUSÉ : le client sait qu'il doit demander
                // autrement, au lieu de chercher la faute dans ce qu'il a écrit.
                return self.termine(
                    Status::No,
                    b"[CANNOT] This FETCH item is not served yet",
                    Action::Continue,
                    out,
                );
            }
            Err(_) => return self.faute(b"FETCH arguments are malformed", out),
        };
        // UN SEUL CORPS PAR COMMANDE. En rendre deux demanderait d'entrelacer
        // deux intervalles de fichier dans une même réponse ; c'est faisable, ce
        // n'est pas fait, et un client qui en demande deux l'apprend plutôt que
        // d'en recevoir un.
        let corps = demande
            .items()
            .iter()
            .filter(|item| matches!(item, FetchItem::Body { .. }))
            .count();
        if corps > 1 {
            return self.termine(
                Status::No,
                b"[CANNOT] Only one body item per FETCH is served",
                Action::Continue,
                out,
            );
        }
        let texte = demande.set_text();
        if texte.len() > SEQUENCE_TEXT_MAX {
            return self.termine(
                Status::No,
                b"[CANNOT] Sequence set is too long",
                Action::Continue,
                out,
            );
        }
        // `ouverte` a été vérifiée en tête ; `unwrap_or` porte cette
        // impossibilité dans la bibliothèque standard.
        let (exists, dernier_uid) = self.ouverte.as_ref().map_or((0, 0), |boite| {
            let exists = boite.exists();
            (exists, boite.info(exists).map_or(0, |info| info.uid))
        });
        // L'ÉTOILE NE VEUT PAS DIRE LA MÊME CHOSE DANS LES DEUX MODES : le plus
        // grand numéro de séquence, ou le plus grand UID. Les confondre ferait
        // désigner autre chose que ce que le client a demandé.
        let star = if par_uid { dernier_uid } else { exists };

        let mut emission = Emission {
            texte: [0; SEQUENCE_TEXT_MAX],
            texte_len: texte.len(),
            items: [FetchItem::Uid; ams_proto_imap::FETCH_ITEMS_MAX],
            items_len: demande.items().len(),
            par_uid,
            star,
            courant: 1,
            exists,
            etape: Etape::Choisir,
        };
        // La longueur a été vérifiée juste au-dessus ; `zip` s'arrête de
        // lui-même, et il n'y a donc pas de garde à écrire.
        for (place, octet) in emission.texte.iter_mut().zip(texte) {
            *place = *octet;
        }
        for (place, item) in emission.items.iter_mut().zip(demande.items()) {
            *place = *item;
        }
        self.emission = Some(emission);
        // RIEN N'EST ÉCRIT ICI : la conclusion sera le dernier morceau, après
        // les réponses non sollicitées, comme §7 le demande.
        Ok(Turn {
            reply: out.get(..0).unwrap_or_default(),
            action: Action::SendFetch,
            peer_fault: false,
        })
    }

    /// Le morceau suivant d'un `FETCH` en cours.
    ///
    /// **L'appelant écrit ce qu'il obtient, dans l'ordre où il l'obtient**, et
    /// la conclusion étiquetée est le dernier morceau : il n'y a donc pas
    /// d'ordre à se rappeler, ni d'inversion possible.
    ///
    /// # Errors
    ///
    /// [`Error::Reply`] si `out` ne suffit pas.
    pub fn next_fetch<'b>(&mut self, out: &'b mut [u8]) -> Result<Option<FetchChunk<'b>>, Error> {
        // UNE ÉMISSION SUPPOSE UNE BOÎTE : `CLOSE` efface les deux ensemble, et
        // rien ne pose l'une sans l'autre. Les prendre du même geste évite une
        // seconde garde qu'aucune entrée ne pourrait emprunter.
        let (Some(mut emission), Some(boite)) = (self.emission, self.ouverte.as_mut()) else {
            self.emission = None;
            return Ok(None);
        };
        match emission.etape {
            Etape::Corps {
                sequence,
                offset,
                length,
            } => {
                emission.etape = Etape::Fermer;
                self.emission = Some(emission);
                return Ok(Some(FetchChunk::Message {
                    sequence,
                    offset,
                    length,
                }));
            }
            Etape::Fermer => {
                emission.etape = Etape::Choisir;
                self.emission = Some(emission);
                let mut plume = Plume::neuve(out);
                plume.pousser(b")\r\n")?;
                let ecrits = plume.ecrits();
                return Ok(Some(FetchChunk::Bytes(
                    out.get(..ecrits).unwrap_or_default(),
                )));
            }
            Etape::Conclure => {
                self.emission = None;
                let ecrit = encode_tagged(
                    out,
                    self.tag_lu(),
                    Status::Ok,
                    if emission.par_uid {
                        b"UID FETCH completed"
                    } else {
                        b"FETCH completed"
                    },
                    &self.limits,
                )
                .map_err(Error::Reply)?
                .len();
                return Ok(Some(FetchChunk::Bytes(
                    out.get(..ecrit).unwrap_or_default(),
                )));
            }
            Etape::Choisir => {}
        }

        let Some((rang, info)) = emission.suivant(boite, &self.limits) else {
            emission.etape = Etape::Conclure;
            self.emission = Some(emission);
            return self.next_fetch(out);
        };
        // §6.4.5 : un corps rendu SANS `PEEK` marque le message comme lu. On le
        // marque AVANT de composer, pour que les `FLAGS` de la même réponse
        // disent la vérité plutôt que l'état d'avant.
        let items = emission.items.get(..emission.items_len).unwrap_or_default();
        if items
            .iter()
            .any(|item| matches!(item, FetchItem::Body { peek: false, .. }))
        {
            boite.mark_seen(rang);
        }
        let info = boite.info(rang).unwrap_or(info);

        let mut plume = Plume::neuve(out);
        plume.pousser(b"* ")?;
        plume.nombre(u64::from(rang))?;
        plume.pousser(b" FETCH (")?;
        let mut premier = true;
        let mut corps = None;
        for item in items {
            if !premier {
                plume.pousser(b" ")?;
            }
            premier = false;
            match item {
                FetchItem::Uid => {
                    plume.pousser(b"UID ")?;
                    plume.nombre(u64::from(info.uid))?;
                }
                FetchItem::Flags => {
                    plume.pousser(b"FLAGS (")?;
                    plume.drapeaux(info.flags)?;
                    plume.pousser(b")")?;
                }
                FetchItem::InternalDate => {
                    plume.pousser(b"INTERNALDATE ")?;
                    plume.date(info.internal_date)?;
                }
                FetchItem::Rfc822Size => {
                    plume.pousser(b"RFC822.SIZE ")?;
                    plume.nombre(info.size)?;
                }
                FetchItem::Body {
                    section,
                    partial,
                    peek: _,
                } => {
                    // On ne demande où finit l'en-tête QUE si la section le
                    // réclame : le trouver demande de lire le message.
                    let entete = match section {
                        Section::Full => 0,
                        Section::Header | Section::Text => boite.header_octets(rang),
                    };
                    let (debut, fin) = decouper(*section, &info, entete);
                    let (offset, longueur) = tailler(debut, fin, *partial);
                    plume.pousser(b"BODY[")?;
                    plume.pousser(match section {
                        Section::Full => b"",
                        Section::Header => b"HEADER",
                        Section::Text => b"TEXT",
                    })?;
                    plume.pousser(b"]")?;
                    if let Some(partie) = partial {
                        plume.pousser(b"<")?;
                        plume.nombre(u64::from(partie.offset))?;
                        plume.pousser(b">")?;
                    }
                    plume.pousser(b" {")?;
                    plume.nombre(longueur)?;
                    plume.pousser(b"}\r\n")?;
                    corps = Some((rang, offset, longueur));
                }
            }
        }
        emission.etape = match corps {
            Some((sequence, offset, length)) => Etape::Corps {
                sequence,
                offset,
                length,
            },
            None => {
                plume.pousser(b")\r\n")?;
                Etape::Choisir
            }
        };
        let ecrits = plume.ecrits();
        self.emission = Some(emission);
        Ok(Some(FetchChunk::Bytes(
            out.get(..ecrits).unwrap_or_default(),
        )))
    }

    /// Lit le premier argument comme un nom de boîte.
    fn un_nom<'n>(&self, arguments: &[u8], place: &'n mut [u8]) -> Option<&'n [u8]> {
        let mut lus = Args::new(arguments);
        let premier = lus.next()?.ok()?;
        let ecrit = premier.value(place).ok()?;
        // LE NOM VA DANS UNE RÉPONSE, et il vient du client. On n'y laisse que
        // de l'ASCII imprimable sans espace : le recopier tel quel ferait écrire
        // au client une réponse de notre part.
        if ecrit.is_empty() || !ecrit.iter().all(u8::is_ascii_graphic) {
            return None;
        }
        let longueur = ecrit.len();
        place.get(..longueur)
    }
}

/// Où commence et où finit la section demandée.
fn decouper(section: Section, info: &MessageInfo, header_octets: u64) -> (u64, u64) {
    match section {
        Section::Full => (0, info.size),
        Section::Header => (0, header_octets.min(info.size)),
        Section::Text => (header_octets.min(info.size), info.size),
    }
}

/// Applique la demande partielle, sans jamais sortir du message.
///
/// # C'EST ICI QUE LE DÉBORDEMENT S'ARRÊTE
///
/// Le décalage et la longueur viennent du réseau ; la taille du message vient du
/// magasin. Les additionner sans précaution donnerait un intervalle qui déborde
/// du fichier, et c'est ce que l'appelant lirait. Tout est donc saturé, puis
/// ramené dans l'intervalle réel.
fn tailler(debut: u64, fin: u64, partial: Option<ams_proto_imap::Partial>) -> (u64, u64) {
    let fin = fin.max(debut);
    let Some(partie) = partial else {
        return (debut, fin.saturating_sub(debut));
    };
    let depart = debut.saturating_add(u64::from(partie.offset)).min(fin);
    let longueur = u64::from(partie.length).min(fin.saturating_sub(depart));
    (depart, longueur)
}

/// Ce nom correspond-il au motif ?
///
/// # Deux jokers, et ils ne disent pas la même chose
///
/// `*` traverse la hiérarchie ; `%` s'arrête au séparateur (§6.3.9). Les
/// confondre ferait rendre à `%` les boîtes d'un sous-dossier qu'il ne désigne
/// pas.
fn correspond(motif: &[u8], nom: &[u8]) -> bool {
    match motif.split_first() {
        None => nom.is_empty(),
        Some((b'*', suite)) => {
            // L'étoile absorbe n'importe quoi, séparateur compris.
            (0..=nom.len()).any(|rang| correspond(suite, nom.get(rang..).unwrap_or_default()))
        }
        Some((b'%', suite)) => (0..=nom.len())
            .take_while(|rang| {
                nom.get(..*rang)
                    .unwrap_or_default()
                    .iter()
                    .all(|octet| *octet != b'/')
            })
            .any(|rang| correspond(suite, nom.get(rang..).unwrap_or_default())),
        Some((attendu, suite)) => match nom.split_first() {
            Some((octet, reste)) if octet == attendu => correspond(suite, reste),
            _ => false,
        },
    }
}

/// De quoi écrire des réponses dans le tampon de l'appelant.
struct Plume<'a> {
    out: &'a mut [u8],
    ecrits: usize,
}

impl<'a> Plume<'a> {
    fn neuve(out: &'a mut [u8]) -> Self {
        Self { out, ecrits: 0 }
    }

    fn ecrits(&self) -> usize {
        self.ecrits
    }

    fn pousser(&mut self, morceau: &[u8]) -> Result<(), Error> {
        let fin = self.ecrits.saturating_add(morceau.len());
        let place = self
            .out
            .get_mut(self.ecrits..fin)
            .ok_or(Error::Reply(ImapError::BufferTooSmall { needed: fin }))?;
        place.copy_from_slice(morceau);
        self.ecrits = fin;
        Ok(())
    }

    /// Écrit un entier décimal.
    fn nombre(&mut self, valeur: u64) -> Result<(), Error> {
        // Vingt chiffres majorent tout `u64`, et la boucle les parcourt tous :
        // s'arrêter plus tôt demanderait une borne, donc une garde qu'aucun
        // appel ne peut faire céder.
        let mut chiffres = [b'0'; 20];
        let mut reste = valeur;
        let mut significatifs = 1_usize;
        for (rang, place) in chiffres.iter_mut().rev().enumerate() {
            *place = b'0'.wrapping_add(u8::try_from(reste % 10).unwrap_or_default());
            reste /= 10;
            if reste != 0 {
                significatifs = rang.saturating_add(2);
            }
        }
        let debut = chiffres.len().saturating_sub(significatifs);
        self.pousser(chiffres.get(debut..).unwrap_or_default())
    }

    /// `* <n> <MOT>`.
    fn nombre_non_sollicite(&mut self, valeur: u32, mot: &[u8]) -> Result<(), Error> {
        self.pousser(b"* ")?;
        self.nombre(u64::from(valeur))?;
        self.pousser(b" ")?;
        self.pousser(mot)?;
        self.pousser(b"\r\n")
    }

    /// `* OK [<MOT> <n>] <MOT>`.
    fn crochet(&mut self, mot: &[u8], valeur: u32) -> Result<(), Error> {
        self.pousser(b"* OK [")?;
        self.pousser(mot)?;
        self.pousser(b" ")?;
        self.nombre(u64::from(valeur))?;
        self.pousser(b"] ")?;
        self.pousser(mot)?;
        self.pousser(b"\r\n")
    }

    /// Les deux suivantes écrivent DIRECTEMENT dans la sortie.
    ///
    /// Passer par un tampon intermédiaire dimensionné pour elles ajouterait une
    /// garde qu'aucune entrée ne pourrait faire céder ; ici, la seule borne qui
    /// puisse échouer est celle du tampon de l'appelant.
    fn drapeaux(&mut self, flags: Flags) -> Result<(), Error> {
        let place = self.out.get_mut(self.ecrits..).unwrap_or_default();
        let ecrit = flags.write(place).map_err(Error::Reply)?.len();
        self.ecrits = self.ecrits.saturating_add(ecrit);
        Ok(())
    }

    fn date(&mut self, secondes: u64) -> Result<(), Error> {
        let place = self.out.get_mut(self.ecrits..).unwrap_or_default();
        let ecrit = write_internal_date(secondes, place)
            .map_err(Error::Reply)?
            .len();
        self.ecrits = self.ecrits.saturating_add(ecrit);
        Ok(())
    }
}
