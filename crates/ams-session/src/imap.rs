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
//! `SELECT`, `EXAMINE`, `CLOSE`, `UNSELECT`, `LIST`, `STATUS`, `FETCH`, `STORE`,
//! `EXPUNGE`, `SEARCH`, `COPY` et `MOVE` sont servis. La session ne sait pas où vivent les messages : elle demande, par
//! [`Mailboxes`] et [`Mailbox`], ce qu'elle ne peut pas savoir — combien il y
//! en a, ce que chacun pèse, où finit son en-tête — et compose le reste.
//!
//! **Elle ne lit jamais un message.** Un `FETCH` qui rend un corps ne rend pas
//! des octets : il rend un INTERVALLE dans un message, que l'appelant écoulera.
//! C'est ce qui permet de servir un message de cent mébioctets sans en tenir un
//! seul en mémoire, et c'est aussi C1 — lire un fichier est une entrée-sortie.
//!
//! # UNE SEULE VÉRITÉ SUR CE QUI S'ÉCRIT
//!
//! [`Mailbox::permanent_flags`] énumère les drapeaux que la boîte sait faire
//! survivre, et trois réponses en découlent : `PERMANENTFLAGS` les cite,
//! `SELECT` annonce `[READ-ONLY]` quand il n'y en a aucun, et `STORE` refuse ce
//! qui n'y figure pas. Une seconde méthode « est-elle modifiable ? » aurait fini
//! par ne plus dire la même chose que la première.
//!
//! # Ce qui n'est pas ici
//!
//! `APPEND`, `CREATE`, `DELETE`, `RENAME` — et les critères de
//! `SEARCH` qui demandent de LIRE le message (`BODY`, `TEXT`, `SUBJECT`,
//! `FROM`, `HEADER`…), qui sont refusés plutôt que rendus faux.
//!
//! `ENVELOPE` et `BODYSTRUCTURE` non plus : ce sont des analyses du message, que
//! `ams-mime` saura faire et qui n'ont rien à voir avec une session.

use ams_proto_imap::{
    Args, Candidate, Command, Error as ImapError, Fetch, FetchItem, Flags, Limits, Line, Search,
    Section, SequenceSet, Status, Store, StoreMode, Tag, encode_continuation, encode_tagged,
    encode_untagged, encode_untagged_parts, write_internal_date,
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
    /// Un `APPEND` est accepté : écouler le littéral vers la session.
    ///
    /// L'appelant écrit la demande de continuation si le littéral est
    /// synchronisant, puis passe les octets à [`Session::append_chunk`] — autant
    /// de fois qu'il le faut — et conclut par [`Session::end_append`].
    ///
    /// **Le message ne passe pas par la session** : elle le fait suivre au
    /// magasin sans en retenir un octet.
    ReadAppend,
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

    /// Les drapeaux que cette boîte sait faire SURVIVRE à la session.
    ///
    /// # UNE SEULE VÉRITÉ SUR CE QUI S'ÉCRIT
    ///
    /// Trois réponses en dépendent, et les faire dériver d'un même mot les
    /// empêche de se contredire : `PERMANENTFLAGS` les énumère, `SELECT`
    /// annonce `[READ-ONLY]` quand il n'y en a aucun, et `STORE` refuse ce qui
    /// n'y est pas. Deux méthodes — « est-elle modifiable ? » et « que
    /// sait-elle écrire ? » — auraient fini par ne plus dire la même chose.
    ///
    /// **Ce n'est pas la liste de ce qu'un message peut porter** : un message
    /// peut arriver marqué par un autre outil. C'est la liste de ce que ce
    /// serveur sait écrire, ce qui est une promesse plus étroite.
    fn permanent_flags(&self) -> Flags;

    /// Copie le message de rang `sequence` dans la boîte nommée, et rend l'UID
    /// qu'il y porte.
    ///
    /// Rend `None` si la copie n'a pas eu lieu — le message a disparu, le disque
    /// a refusé. **Ce n'est pas une erreur de commande** (§6.4.7) : ce qui a été
    /// copié l'est, et le client l'apprend par le `COPYUID` qui ne le nomme pas.
    ///
    /// # LES UID RENDUS SONT STRICTEMENT CROISSANTS
    ///
    /// C'est ce qui permet à `COPYUID` de nommer la destination par UNE plage —
    /// `10:14` — sans rien accumuler. Un magasin qui les rendrait dans le
    /// désordre ferait écrire une plage qui ne désigne pas ce qu'elle nomme.
    /// Maildir le garantit : l'UID vient d'un compteur qui n'avance jamais à
    /// reculons.
    fn copy_to(&mut self, sequence: u32, mailbox: &[u8]) -> Option<u32>;

    /// Retire de la boîte nommée les copies dont l'UID est compris entre
    /// `premier` et `dernier` — **et seulement celles-là**.
    ///
    /// # §6.4.7 : UN `COPY` N'EST PAS PARTIELLEMENT RÉUSSI
    ///
    /// « If the server can't copy all the messages, it should restore the
    /// destination mailbox to its state before the COPY and return a tagged
    /// error. » Un client qui reçoit `NO` doit pouvoir recommencer sans se
    /// demander lesquels de ses messages sont déjà passés.
    ///
    /// Les UID à retirer forment TOUJOURS une plage, puisque
    /// [`copy_to`](Mailbox::copy_to) les rend en croissant : il n'y a donc rien
    /// à retenir pour défaire, et pas de mémoire que le client puisse choisir.
    fn undo_copies(&mut self, mailbox: &[u8], premier: u32, dernier: u32);

    /// Retire le message de rang `sequence`, SANS RIEN VÉRIFIER, et renumérote.
    ///
    /// # POURQUOI CE N'EST PAS [`expunge`](Mailbox::expunge)
    ///
    /// `EXPUNGE` efface sur la foi d'une marque `\Deleted` posée il y a
    /// peut-être des heures, et le magasin doit donc la relire avant d'effacer :
    /// c'est la garde qui empêche de perdre du courrier sur une croyance
    /// périmée. `MOVE`, lui, n'a aucune marque à relire — il retire un message
    /// qu'il vient de copier, à l'instant, et sur ordre exprès du client. Faire
    /// passer l'un pour l'autre ferait ou bien un `MOVE` qui ne déplace rien, ou
    /// bien un `EXPUNGE` qui efface ce qu'on ne lui a pas demandé.
    fn remove(&mut self, sequence: u32) -> bool;

    /// Efface DÉFINITIVEMENT le message de rang `sequence`, et renumérote : ce
    /// qui suivait descend d'un rang.
    ///
    /// Rend `true` si le message n'est plus là — qu'on vienne de l'effacer ou
    /// qu'il eût déjà disparu. Rend `false` s'il est TOUJOURS LÀ, auquel cas la
    /// session passe au suivant sans rien annoncer : annoncer un effacement qui
    /// n'a pas eu lieu ferait perdre au client le fil des numéros de séquence.
    ///
    /// # LE MAGASIN A LE DERNIER MOT SUR CE QU'IL EFFACE
    ///
    /// La session demande d'effacer ce que SON INSTANTANÉ dit marqué `\Deleted`.
    /// Entre l'instantané et l'appel, une autre session a pu retirer la marque —
    /// et effacer sur une croyance périmée, c'est perdre du courrier que
    /// personne n'a demandé de perdre. Un magasin qui peut le vérifier doit le
    /// vérifier, et rendre `false` s'il ne trouve plus la marque.
    fn expunge(&mut self, sequence: u32) -> bool;

    /// Écrit les drapeaux du message de rang `sequence`, et rend les nouveaux.
    ///
    /// Rend `None` si le message a disparu — ce qu'une boîte lue sans verrou ne
    /// peut pas exclure, et ce dont §6.4.6 dit précisément qu'il ne faut pas
    /// faire une erreur : le client apprend l'absence en ne recevant rien pour
    /// ce message.
    ///
    /// **N'écrit jamais hors de [`permanent_flags`](Mailbox::permanent_flags)** :
    /// la session ne lui soumet que ce qui y figure.
    fn store_flags(&mut self, sequence: u32, mode: StoreMode, flags: Flags) -> Option<Flags>;
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

    /// Le nom de la boîte de rang `index`, écrit dans `out`, ou `None` au-delà
    /// de la dernière.
    ///
    /// Un accès par rang plutôt qu'une liste : la session n'alloue pas, et une
    /// tranche de tranches ferait porter à l'appelant une durée de vie dont il
    /// n'a que faire. **Le nom est ÉCRIT** plutôt que prêté, parce qu'un magasin
    /// qui découvre ses boîtes sur un disque ne peut pas prêter ce qu'il vient
    /// de lire.
    fn name<'n>(&self, user: &[u8], index: usize, out: &'n mut [u8]) -> Option<Listing<'n>>;

    /// Crée une boîte (§6.3.4).
    ///
    /// # LE NOM VIENT DU CLIENT ET DEVIENT UN CHEMIN
    ///
    /// C'est la frontière la plus délicate du serveur. La session a déjà écarté
    /// ce que la grammaire refuse — voir `mailbox_name_is_safe` — mais **le
    /// magasin ne doit pas s'y fier** : il vérifie à son tour, parce que c'est
    /// lui qui touche le système de fichiers, et qu'une vérification faite
    /// ailleurs est une vérification qu'on ne voit pas en lisant l'endroit qui
    /// en dépend.
    fn create(&self, user: &[u8], name: &[u8]) -> Creation;

    /// Efface une boîte (§6.3.5).
    ///
    /// **Une boîte qui a des filles ne disparaît pas** : §6.3.5 veut que son
    /// courrier s'en aille et que son NOM demeure, marqué `\Noselect`, faute de
    /// quoi la hiérarchie se romprait et les filles deviendraient
    /// inatteignables.
    fn delete(&self, user: &[u8], name: &[u8]) -> Deletion;

    /// Renomme une boîte (§6.3.6).
    ///
    /// **Les filles suivent** : renommer `Archives` en `Vieux` renomme aussi
    /// `Archives/2026` en `Vieux/2026`. Les laisser derrière ferait des boîtes
    /// dont le chemin ne mène plus nulle part.
    ///
    /// **Renommer `INBOX` la vide, sans la faire disparaître** : ses messages
    /// s'en vont vers le nouveau nom, et elle reste — c'est le seul endroit où
    /// le courrier arrive.
    fn rename(&self, user: &[u8], from: &[u8], to: &[u8]) -> Renaming;

    /// Ouvre une boîte, ou dit qu'elle n'existe pas.
    fn open(&self, user: &[u8], name: &[u8]) -> Option<Self::Open>;

    /// Ce qu'un dépôt en cours est.
    type Deposit: Deposit;

    /// Ouvre un dépôt dans la boîte nommée, ou dit qu'elle n'existe pas.
    ///
    /// **Rien n'est visible tant que le dépôt n'est pas validé** : c'est ce qui
    /// permet d'abandonner un message à moitié reçu sans que personne ne l'ait
    /// vu.
    fn append(&self, user: &[u8], name: &[u8]) -> Option<Self::Deposit>;
}

/// Une boîte, telle que `LIST` la rend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Listing<'n> {
    /// Son nom.
    pub name: &'n [u8],
    /// Peut-on l'ouvrir ?
    ///
    /// **Une boîte effacée qui avait des filles garde son nom sans son
    /// courrier** (§6.3.5) : elle paraît dans la liste, marquée `\Noselect`, et
    /// `SELECT` la refuse. Sans elle, ses filles n'auraient plus de chemin.
    pub selectable: bool,
}

/// Ce qu'un effacement de boîte a donné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deletion {
    /// La boîte est effacée.
    Faite,
    /// Elle avait des filles : son courrier est parti, son nom demeure.
    Videe,
    /// Elle n'existe pas (§6.3.5 : `[NONEXISTENT]`).
    Absente,
    /// Le magasin n'a pas pu.
    Refusee,
}

/// Ce qu'un renommage de boîte a donné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Renaming {
    /// La boîte est renommée.
    Faite,
    /// L'ancienne n'existe pas (§6.3.6 : `[NONEXISTENT]`).
    Absente,
    /// La nouvelle existe déjà (§6.3.6 : `[ALREADYEXISTS]`).
    DejaLa,
    /// Le magasin n'a pas pu, et n'a rien changé.
    Refusee,
}

/// Ce qu'une création de boîte a donné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Creation {
    /// La boîte est créée.
    Faite,
    /// Elle existait déjà (§6.3.4 : `[ALREADYEXISTS]`).
    DejaLa,
    /// Le magasin n'en a pas voulu.
    Refusee,
}

/// Un message en cours de dépôt.
///
/// # POURQUOI CE N'EST PAS UNE TRANCHE D'OCTETS
///
/// `APPEND` est la seule commande dont un argument est un MESSAGE. Le retenir en
/// mémoire pour le remettre ensuite donnerait au client le droit de choisir
/// combien de mémoire le serveur consomme — dix mébioctets par connexion, pour
/// un serveur qui n'a rien à en faire. Le message s'écoule donc au fil de l'eau,
/// exactement comme le `DATA` de SMTP.
pub trait Deposit {
    /// Ajoute des octets au message. Rend `false` si le dépôt est perdu.
    fn write(&mut self, chunk: &[u8]) -> bool;

    /// Valide le dépôt, et rend l'UID que le message porte.
    ///
    /// `date` à `None` : la date d'arrivée est celle du dépôt.
    fn commit(self, flags: Flags, date: Option<u64>) -> Option<u32>;

    /// Abandonne le dépôt : rien n'en subsiste.
    fn abort(self);
}

/// Un magasin PARTAGÉ en est un aussi.
///
/// La session prend son magasin par valeur ; une boucle qui sert mille
/// connexions n'en a qu'un. Cette implémentation-là est ce qui réconcilie les
/// deux, sans que personne n'ait à recopier une table de boîtes par connexion.
impl<T: Mailboxes> Mailboxes for &T {
    type Open = T::Open;
    type Deposit = T::Deposit;

    fn name<'n>(&self, user: &[u8], index: usize, out: &'n mut [u8]) -> Option<Listing<'n>> {
        (**self).name(user, index, out)
    }

    fn create(&self, user: &[u8], name: &[u8]) -> Creation {
        (**self).create(user, name)
    }

    fn delete(&self, user: &[u8], name: &[u8]) -> Deletion {
        (**self).delete(user, name)
    }

    fn rename(&self, user: &[u8], from: &[u8], to: &[u8]) -> Renaming {
        (**self).rename(user, from, to)
    }

    fn open(&self, user: &[u8], name: &[u8]) -> Option<Self::Open> {
        (**self).open(user, name)
    }

    fn append(&self, user: &[u8], name: &[u8]) -> Option<Self::Deposit> {
        (**self).append(user, name)
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
///
/// **C'est celle de la grammaire, et pas une seconde** : ce que la session
/// retient et ce que le protocole admet doivent coïncider, faute de quoi un nom
/// accepté serait tronqué — donc un autre nom.
pub const MAILBOX_NAME_MAX: usize = ams_proto_imap::MAILBOX_NAME_MAX;

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
    /// La COMMANDE portait-elle sur des UID ? Cela ne décide que du nom qu'on
    /// donne à la conclusion.
    par_uid: bool,
    /// L'ensemble RETENU porte-t-il des UID, ou des numéros de séquence ?
    ///
    /// # LES DEUX NE COÏNCIDENT PAS TOUJOURS
    ///
    /// Un `MOVE` retire des messages en marchant, et retirer RENUMÉROTE. Un
    /// ensemble de rangs cesse donc de désigner ce qu'il désignait dès le
    /// premier retrait — alors qu'un ensemble d'UID, lui, ne bouge pas. Un
    /// `MOVE` traduit donc son ensemble en UID avant de retirer, quelle que soit
    /// la forme sous laquelle le client l'a écrit.
    cles_uid: bool,
    /// Le retrait exige-t-il la marque `\Deleted` ? `EXPUNGE` oui, `MOVE` non.
    exige_la_marque: bool,
    /// Ce que vaut l'étoile pour l'ensemble de la commande.
    star: u32,
    /// Ce que vaut l'étoile dans un `UID <ensemble>` d'une recherche.
    ///
    /// Une expression peut porter les deux — `UID 5:* 2:*` — et l'étoile n'y
    /// désigne pas la même chose : le plus grand UID d'un côté, le plus grand
    /// rang de l'autre.
    star_uid: u32,
    /// Le prochain rang à examiner.
    courant: u32,
    /// Combien la boîte en porte.
    exists: u32,
    /// Ce qu'il faut ÉCRIRE dans chaque message choisi, s'il faut écrire.
    ///
    /// # POURQUOI `STORE` EMPRUNTE LA MACHINE DE `FETCH`
    ///
    /// §6.4.6 : un `STORE` non silencieux rend une réponse `FETCH` par message
    /// modifié. Ce sont donc les mêmes réponses, dans le même ordre, sur le même
    /// ensemble — et les écrire deux fois aurait fait deux codes qui divergent.
    ecriture: Option<(StoreMode, Flags)>,
    /// Le client a-t-il demandé qu'on ne lui rende rien (`.SILENT`) ?
    silencieux: bool,
    /// Ce que la conclusion doit nommer.
    genre: Genre,
    /// La plage de résultats en cours de constitution : `(début, fin)`.
    ///
    /// # ON COMPRIME EN AVANÇANT, SANS RIEN RETENIR
    ///
    /// §7.3.4 : `ESEARCH` rend un ENSEMBLE de numéros, pas une liste — `2,4:7`
    /// et non `2,4,5,6,7`. Comprimer demande de savoir si le résultat suivant
    /// prolonge le précédent, ce qui tient dans deux entiers : la plage ouverte.
    /// Retenir tous les résultats pour les comprimer à la fin demanderait une
    /// mémoire que le client choisirait.
    plage: Option<(u32, u32)>,
    /// Une plage CLOSE, qui attend qu'il y ait la place de l'écrire.
    ///
    /// Sans elle, un tampon qui déborde au milieu d'une plage perdrait le
    /// résultat qu'on venait de lire — et un résultat de recherche perdu ne se
    /// voit pas : le client croit simplement que le message ne correspondait
    /// pas.
    a_ecrire: Option<(u32, u32)>,
    /// A-t-on déjà écrit l'en-tête `* ESEARCH (TAG "…")` ?
    entame: bool,
    /// A-t-on déjà écrit au moins un résultat ?
    trouve: bool,
    /// Combien de messages ont déjà été effacés par cette commande.
    ///
    /// # CE N'EST PAS UNE STATISTIQUE, C'EST LA BORNE DE LA BOUCLE
    ///
    /// L'effacement n'avance pas le rang courant : ce qui suivait descend à sa
    /// place, et il faut l'examiner à son tour. Le tour ne se termine donc que
    /// parce que la boîte rétrécit — ce que la session ne peut pas vérifier.
    /// Une boîte qui dirait « effacé » sans rétrécir ferait une boucle sans fin,
    /// et un appelant qui écrit ce qu'elle rend remplirait la mémoire de la
    /// machine. **C'est arrivé ici, sur un itérateur qui ne consommait pas son
    /// entrée** : 6 Gio, et le noyau qui tue le processus. On ne compte donc pas
    /// sur la boîte : on n'efface jamais plus de messages qu'elle n'en portait.
    effaces: u32,
    /// Où en est l'émission du message courant.
    etape: Etape,
}

/// Ce qu'un dépôt fait des octets qu'il reçoit.
///
/// # ON LIT MÊME CE QU'ON REFUSE
///
/// Un littéral NON synchronisant part sans que le serveur ait rien dit : ses
/// octets arrivent que la commande soit acceptée ou non, et ne pas les lire
/// ferait lire un message comme des commandes. On les lit donc, et on les
/// jette — c'est la seule façon de rester en phase avec le client.
///
/// Un littéral synchronisant, lui, se refuse AVANT : le client attend une
/// invitation qu'on ne donnera pas, et §6.3.12 veut précisément qu'on réponde
/// `NO` à sa place. C'est tout l'intérêt de la forme.
enum Dedans<D> {
    /// Le dépôt est ouvert : les octets y vont.
    Ouvert(D),
    /// Les octets se jettent, et voici pourquoi.
    Jete(Refus),
}

/// Pourquoi un `APPEND` sera refusé, une fois ses octets lus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refus {
    /// La session n'est pas authentifiée.
    Authentification,
    /// La boîte n'existe pas.
    Inconnue,
}

/// Un `APPEND` en cours de réception.
struct Depot<D> {
    /// Le dépôt lui-même, ou la raison pour laquelle on jette les octets.
    dedans: Dedans<D>,
    /// Combien d'octets restent à recevoir.
    reste: u64,
    /// Les drapeaux à poser au dépôt validé.
    flags: Flags,
    /// La date d'arrivée demandée.
    date: Option<u64>,
    /// Le magasin a-t-il lâché en route ?
    perdu: bool,
    /// La boîte visée, pour l'`UIDVALIDITY` de la conclusion.
    nom: [u8; MAILBOX_NAME_MAX],
    nom_len: usize,
}

/// La commande qui a ouvert l'émission, pour la nommer dans sa conclusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Genre {
    Fetch,
    Store,
    Expunge,
    Search,
    Move,
}

impl Genre {
    /// Le texte de la conclusion.
    fn conclusion(self, par_uid: bool) -> &'static [u8] {
        match (self, par_uid) {
            (Genre::Fetch, false) => b"FETCH completed",
            (Genre::Fetch, true) => b"UID FETCH completed",
            (Genre::Store, false) => b"STORE completed",
            (Genre::Store, true) => b"UID STORE completed",
            (Genre::Expunge, false) => b"EXPUNGE completed",
            (Genre::Expunge, true) => b"UID EXPUNGE completed",
            (Genre::Search, false) => b"SEARCH completed",
            (Genre::Search, true) => b"UID SEARCH completed",
            (Genre::Move, false) => b"MOVE completed",
            (Genre::Move, true) => b"UID MOVE completed",
        }
    }
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
///
/// # NI `Clone`, NI `Debug`, ET C'EST VOULU
///
/// Une session peut tenir un DÉPÔT en cours — un fichier ouvert dans lequel un
/// message s'écoule. Le recopier ferait deux sessions qui écrivent dans le même
/// message ; l'afficher ferait passer un morceau de courrier dans un journal.
/// Ce que la session porte se lit par ses accesseurs, et rien d'autre.
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
    /// Le dépôt d'un `APPEND` en cours, s'il y en a un.
    depot: Option<Depot<M::Deposit>>,
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
    /// Le prochain résultat d'une recherche, ou `None` quand la boîte est
    /// parcourue.
    ///
    /// Rend la CLEF — l'UID pour un `UID SEARCH`, le rang sinon — parce que
    /// c'est elle que la réponse porte (§6.4.4).
    fn trouvaille<B: Mailbox>(&mut self, boite: &B, limits: &Limits) -> Option<u32> {
        let texte = self.texte.get(..self.texte_len).unwrap_or_default();
        // LE TEXTE A DÉJÀ ÉTÉ VALIDÉ par `search` : on ne retient que ce qui se
        // lit. Une expression qu'on ne saurait plus lire ne désigne rien, ce qui
        // est aussi la bonne réponse.
        let recherche = Search::parse(texte, limits).unwrap_or(Search::NONE);
        while self.courant <= self.exists {
            let rang = self.courant;
            self.courant = self.courant.saturating_add(1);
            let Some(info) = boite.info(rang) else {
                continue;
            };
            let candidat = Candidate {
                sequence: rang,
                uid: info.uid,
                size: info.size,
                flags: info.flags,
                internal_date: info.internal_date,
            };
            // L'ÉTOILE D'UN ENSEMBLE IMBRIQUÉ NE VEUT PAS DIRE LA MÊME CHOSE
            // SELON LE CÔTÉ : `UID 5:*` parle d'UID, `5:*` de rangs, et les deux
            // peuvent se rencontrer dans la même expression.
            if recherche.matches(&candidat, self.exists, self.star_uid) {
                return Some(if self.par_uid { info.uid } else { rang });
            }
        }
        None
    }

    /// Le prochain message à effacer, s'il en reste un.
    ///
    /// **Le rang courant n'avance pas** : ce qui suivait le message effacé
    /// descend à sa place, et il faut l'examiner à son tour. C'est l'appelant
    /// qui avance, quand l'effacement n'a pas eu lieu.
    ///
    /// `exists` est relu à chaque tour — la boîte rétrécit sous nos pieds, et
    /// c'est précisément ce qu'on veut.
    fn a_effacer<B: Mailbox>(&mut self, boite: &B, limits: &Limits) -> Option<u32> {
        let texte = self.texte.get(..self.texte_len).unwrap_or_default();
        let ensemble = SequenceSet::parse(texte, limits).unwrap_or(SequenceSet::EMPTY);
        // ON N'EFFACE JAMAIS PLUS QUE CE QUE LA BOÎTE PORTAIT. Voir `effaces`.
        while self.courant <= boite.exists() && self.effaces < self.exists {
            let rang = self.courant;
            let Some(info) = boite.info(rang) else {
                self.courant = self.courant.saturating_add(1);
                continue;
            };
            let clef = if self.cles_uid { info.uid } else { rang };
            let marque = !self.exige_la_marque || info.flags.contains(Flags::DELETED);
            if marque && ensemble.contains(clef, self.star) {
                return Some(rang);
            }
            self.courant = self.courant.saturating_add(1);
        }
        None
    }

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
            let clef = if self.cles_uid { info.uid } else { rang };
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
            depot: None,
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
            Command::Create => self.create(lue.arguments, out),
            Command::Delete => self.delete(lue.arguments, out),
            Command::Rename => self.rename(lue.arguments, out),
            Command::Enable
            | Command::Subscribe
            | Command::Unsubscribe
            | Command::Namespace
            | Command::Idle => self.si_authentifie(out),
            // UN `APPEND` QUI ARRIVE ICI N'EST PAS CELUI QU'ON SAIT ÉCOULER.
            // Le chemin ordinaire ne voit que les commandes COMPLÈTES : un
            // `APPEND` normal n'y passe jamais, puisque son message s'écoule.
            // Ce qui y passe, c'est un `APPEND` sans littéral, ou dont le nom de
            // boîte EST un littéral — une forme légale que ce serveur ne sert
            // pas, et le dire vaut mieux que de la laisser deviner.
            Command::Append => {
                self.faute(b"APPEND expects a mailbox name and a message literal", out)
            }
            // ── Sélectionné seulement (§6.4) ────────────────────────────────
            Command::Close => self.close(true, out),
            Command::Unselect => self.close(false, out),
            Command::Expunge => self.expunge(lue.arguments, false, out),
            Command::Search => self.search(lue.arguments, false, out),
            Command::Copy => self.copy(lue.arguments, false, out),
            Command::Move => self.deplacer(lue.arguments, false, out),
            Command::Fetch => self.fetch(lue.arguments, false, out),
            Command::Store => self.store(lue.arguments, false, out),
            Command::Uid => self.uid(lue.arguments, out),
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

        // UNE BOÎTE OÙ RIEN NE SURVIT EST EN LECTURE SEULE, que le client ait
        // dit `SELECT` ou `EXAMINE`. C'est la même vérité qui sert aux trois
        // réponses, plutôt que trois qui finiraient par se contredire.
        let permanents = if examine {
            Flags::NONE
        } else {
            boite.permanent_flags()
        };
        let lecture_seule = permanents == Flags::NONE;
        let mut plume = Plume::neuve(out);
        plume.nombre_non_sollicite(boite.exists(), b"EXISTS")?;
        plume.crochet(b"UIDVALIDITY", boite.uid_validity())?;
        plume.crochet(b"UIDNEXT", boite.uid_next())?;
        // `FLAGS` dit ce qu'un message PEUT PORTER — un autre outil a pu en
        // poser. `PERMANENTFLAGS` dit ce que CE serveur sait écrire, et les deux
        // ne coïncident pas forcément.
        plume.pousser(b"* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n")?;
        plume.pousser(b"* OK [PERMANENTFLAGS (")?;
        plume.drapeaux(permanents)?;
        plume.pousser(if lecture_seule {
            b")] Read-only mailbox\r\n"
        } else {
            b")] Flags permitted\r\n"
        })?;
        plume.nom_de_boite(b"* LIST () \"/\" ", nom, b"\r\n")?;
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
    /// La boîte ouverte accepte-t-elle qu'on efface ?
    ///
    /// Deux conditions, et les deux comptent : la boîte doit savoir écrire
    /// `\Deleted` — sans quoi rien n'a pu être marqué par nous — et la session
    /// ne doit pas avoir été ouverte en lecture seule (§6.4.2).
    fn peut_effacer(&self) -> bool {
        !self.lecture_seule
            && self
                .ouverte
                .as_ref()
                .is_some_and(|boite| boite.permanent_flags().contains(Flags::DELETED))
    }

    /// `CLOSE` (§6.4.2) et `UNSELECT` (§6.4.4).
    ///
    /// # DEUX COMMANDES QUI SE RESSEMBLENT ET QUI NE SONT PAS LA MÊME
    ///
    /// `CLOSE` EFFACE les messages marqués `\Deleted` avant de refermer, et sans
    /// rien annoncer — le client s'en va, il n'y a personne à qui renuméroter.
    /// `UNSELECT` referme et n'efface rien : il existe précisément pour cela.
    /// Les confondre ferait effacer du courrier à qui demandait le contraire.
    fn close<'b>(&mut self, expurge: bool, out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        // LA PRÉSENCE DE LA BOÎTE EST L'ÉTAT. La prendre ICI plutôt que de
        // vérifier l'état puis de la reprendre plus bas évite une seconde garde
        // qu'aucune entrée ne pourrait emprunter — et une garde inatteignable
        // n'est pas une garde, c'est une affirmation non vérifiée.
        let lecture_seule = self.lecture_seule;
        let Some(boite) = self.ouverte.as_mut() else {
            return self.faute(b"Command is not allowed unless a mailbox is selected", out);
        };
        if expurge && !lecture_seule && boite.permanent_flags().contains(Flags::DELETED) {
            // ON N'EFFACE JAMAIS PLUS QUE CE QUE LA BOÎTE PORTAIT ; voir
            // `Emission::effaces`. Ici la borne est explicite, faute d'émission
            // où la loger.
            let plafond = boite.exists();
            let mut rang = 1_u32;
            let mut effaces = 0_u32;
            while rang <= boite.exists() && effaces < plafond {
                let marque = boite
                    .info(rang)
                    .is_some_and(|info| info.flags.contains(Flags::DELETED));
                if marque && boite.expunge(rang) {
                    effaces = effaces.saturating_add(1);
                    continue;
                }
                rang = rang.saturating_add(1);
            }
        }
        self.ouverte = None;
        self.emission = None;
        self.nom_ouvert_len = 0;
        self.etat = State::Authenticated;
        self.termine(
            Status::Ok,
            if expurge {
                b"CLOSE completed".as_slice()
            } else {
                b"UNSELECT completed".as_slice()
            },
            Action::Continue,
            out,
        )
    }

    /// `COPY` et `UID COPY` (§6.4.7).
    ///
    /// # `COPYUID` EST UN SERVICE, PAS UNE PROMESSE QU'ON TIENT À MOITIÉ
    ///
    /// §6.4.7 : le serveur DEVRAIT rendre `[COPYUID <validité> <source>
    /// <destination>]`, qui dit au client où ses messages ont atterri. Les deux
    /// ensembles peuvent être longs ; celui de destination tient toujours en une
    /// plage — les UID sont attribués en croissant — mais celui de source est ce
    /// que le client a désigné, à trous compris. On l'accumule dans un tampon
    /// borné, et **s'il déborde, on omet `COPYUID` entièrement**. Un `COPYUID`
    /// tronqué désignerait d'autres messages que ceux qu'on a copiés, ce qui est
    /// pire que de ne rien dire.
    fn copy<'b>(
        &mut self,
        arguments: &[u8],
        par_uid: bool,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        // LA PRÉSENCE DE LA BOÎTE EST L'ÉTAT ; voir `fetch`.
        if self.ouverte.is_none() {
            return self.faute(b"Command is not allowed unless a mailbox is selected", out);
        }
        let arguments = arguments.trim_ascii();
        let rang = arguments
            .iter()
            .position(|octet| *octet == b' ')
            .unwrap_or(arguments.len());
        let texte = arguments.get(..rang).unwrap_or_default();
        let reste = arguments.get(rang.saturating_add(1)..).unwrap_or_default();
        let mut nom = [0_u8; MAILBOX_NAME_MAX];
        let (Ok(ensemble), Some(nom)) = (
            SequenceSet::parse(texte, &self.limits),
            self.un_nom(reste, &mut nom),
        ) else {
            return self.faute(b"COPY expects a sequence set and a mailbox name", out);
        };

        // §6.4.7 : UNE DESTINATION QUI N'EXISTE PAS SE DIT `[TRYCREATE]`, et pas
        // autrement. C'est le code qui apprend au client qu'un `CREATE` suivi du
        // même `COPY` marcherait — le lui refuser sèchement le laisserait
        // deviner.
        let Some(destination) = self.boites.open(self.user(), nom) else {
            return self.termine(
                Status::No,
                b"[TRYCREATE] Destination mailbox does not exist",
                Action::Continue,
                out,
            );
        };
        let uid_validity = destination.uid_validity();
        drop(destination);

        let (exists, dernier_uid) = self.ouverte.as_ref().map_or((0, 0), |boite| {
            let exists = boite.exists();
            (exists, boite.info(exists).map_or(0, |info| info.uid))
        });
        let star = if par_uid { dernier_uid } else { exists };

        let Ok(Copies {
            source,
            premier_copie,
            dernier_copie,
            copies,
        }) = self.copier(&ensemble, nom, par_uid, exists, star, false)
        else {
            return self.termine(
                Status::No,
                b"Copy failed; no messages were copied",
                Action::Continue,
                out,
            );
        };

        if copies == 0 {
            // §6.4.7 : rien de copié, rien à dire de plus.
            return self.termine(
                Status::Ok,
                if par_uid {
                    b"UID COPY completed".as_slice()
                } else {
                    b"COPY completed".as_slice()
                },
                Action::Continue,
                out,
            );
        }

        let mut texte_reponse = [0_u8; COPYUID_MAX];
        let ecrits = copyuid(
            &mut texte_reponse,
            uid_validity,
            &source,
            premier_copie,
            dernier_copie,
            par_uid,
        );
        self.termine(
            Status::Ok,
            texte_reponse.get(..ecrits).unwrap_or_default(),
            Action::Continue,
            out,
        )
    }

    /// Copie tout ce que l'ensemble désigne, et défait tout si l'une échoue.
    ///
    /// Rend `None` quand une copie a échoué : ce qui avait été copié est alors
    /// déjà défait, et l'appelant n'a plus qu'à le dire.
    fn copier(
        &mut self,
        ensemble: &SequenceSet<'_>,
        nom: &[u8],
        par_uid: bool,
        exists: u32,
        star: u32,
        exiger_les_noms: bool,
    ) -> Result<Copies, Echec> {
        // ON COPIE DANS UN NOMBRE DE MESSAGES ARRÊTÉ D'AVANCE. Copier dans la
        // boîte ouverte l'agrandit ; relire `exists` à chaque tour ferait de
        // `COPY 1:* INBOX` une boucle que le client n'aurait qu'à demander.
        let mut faites = Copies {
            source: Plage::neuve(),
            premier_copie: 0,
            dernier_copie: 0,
            copies: 0,
        };
        let mut echec = None;
        for rang in 1..=exists {
            let Some(info) = self.ouverte.as_ref().and_then(|boite| boite.info(rang)) else {
                continue;
            };
            let clef = if par_uid { info.uid } else { rang };
            if !ensemble.contains(clef, star) {
                continue;
            }
            let Some(nouveau) = self
                .ouverte
                .as_mut()
                .and_then(|boite| boite.copy_to(rang, nom))
            else {
                echec = Some(Echec::Copie);
                break;
            };
            faites.source.pousser(info.uid);
            if faites.copies == 0 {
                faites.premier_copie = nouveau;
            }
            faites.dernier_copie = nouveau;
            faites.copies = faites.copies.saturating_add(1);
        }
        faites.source.fermer();
        // UN `MOVE` DOIT POUVOIR NOMMER CE QU'IL RETIRERA. S'il ne le peut pas,
        // il vaut mieux ne rien déplacer que retirer au hasard.
        if echec.is_none() && exiger_les_noms && faites.source.a_deborde() && faites.copies != 0 {
            echec = Some(Echec::TropMorcele);
        }
        if let Some(raison) = echec {
            // §6.4.7 : ON DÉFAIT CE QU'ON A FAIT. Une copie à moitié réussie
            // laisserait le client se demander lesquels de ses messages sont
            // déjà passés — et recommencer en ferait des doublons.
            if let Some(boite) = self.ouverte.as_mut().filter(|_| faites.copies != 0) {
                boite.undo_copies(nom, faites.premier_copie, faites.dernier_copie);
            }
            return Err(raison);
        }
        Ok(faites)
    }

    /// Lit `<ensemble> SP <boîte>`, et vérifie que la boîte existe.
    ///
    /// Rend l'ensemble, le nom recopié dans `place`, et l'`UIDVALIDITY` de la
    /// destination. `Err` porte la réponse à faire.
    fn destination<'n>(
        &self,
        arguments: &[u8],
        place: &'n mut [u8; MAILBOX_NAME_MAX],
    ) -> Result<(&'n [u8], u32), &'static [u8]> {
        let arguments = arguments.trim_ascii();
        let rang = arguments
            .iter()
            .position(|octet| *octet == b' ')
            .unwrap_or(arguments.len());
        let texte = arguments.get(..rang).unwrap_or_default();
        let reste = arguments.get(rang.saturating_add(1)..).unwrap_or_default();
        if SequenceSet::parse(texte, &self.limits).is_err() {
            return Err(b"");
        }
        let longueur = match self.un_nom(reste, place) {
            Some(nom) => nom.len(),
            None => return Err(b""),
        };
        let nom = place.get(..longueur).unwrap_or_default();
        // §6.4.7 : UNE DESTINATION QUI N'EXISTE PAS SE DIT `[TRYCREATE]`, et pas
        // autrement. C'est le code qui apprend au client qu'un `CREATE` suivi de
        // la même commande marcherait — le lui refuser sèchement le laisserait
        // deviner.
        let Some(boite) = self.boites.open(self.user(), nom) else {
            return Err(b"[TRYCREATE] Destination mailbox does not exist");
        };
        Ok((nom, boite.uid_validity()))
    }

    /// Ouvre un `APPEND` (§6.3.12) : la ligne est lue, le message va suivre.
    ///
    /// # POURQUOI CE N'EST PAS `handle`
    ///
    /// `handle` reçoit une commande COMPLÈTE. Celle-ci ne l'est jamais : son
    /// dernier argument est un message, et l'attendre en entier avant de
    /// commencer donnerait au client le droit de choisir combien de mémoire le
    /// serveur consomme. L'appelant passe donc la LIGNE, et écoule le reste.
    ///
    /// Rend `Action::ReadAppend` dans tous les cas où le littéral doit être lu —
    /// **y compris quand la commande est déjà refusée** : un littéral non
    /// synchronisant est en route quoi qu'on réponde, et ne pas le lire ferait
    /// lire un message comme des commandes. La réponse, elle, attend la fin.
    ///
    /// # Errors
    ///
    /// [`Error::Reply`] si `out` ne suffit pas.
    pub fn begin_append<'b>(
        &mut self,
        ligne: &[u8],
        append: &ams_proto_imap::Append<'_>,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        // LE TAG VIENT DE LA LIGNE, et il sera recopié dans la conclusion : on
        // le relit par la grammaire plutôt que de le découper à la main, pour
        // que ce qu'on recopie soit ce qu'elle a validé.
        let tag = Line::parse(ligne, &self.limits)
            .map(|lue| lue.tag)
            .unwrap_or(Tag::PLACEHOLDER);
        self.retenir_le_tag(tag);

        // §6.3.12 : LA BOÎTE DOIT EXISTER, et son absence se dit `[TRYCREATE]`.
        let dedans = if self.etat == State::NotAuthenticated {
            Dedans::Jete(Refus::Authentification)
        } else {
            match self.boites.append(self.user(), append.mailbox()) {
                Some(depot) => Dedans::Ouvert(depot),
                None => Dedans::Jete(Refus::Inconnue),
            }
        };
        // ON REFUSE AVANT D'INVITER. Un littéral synchronisant attend une
        // invitation ; la donner puis refuser ferait attendre le serveur pour
        // des octets que le client n'enverra jamais — un délai d'attente entier,
        // par commande refusée.
        if let Dedans::Jete(raison) = &dedans
            && append.synchronizing()
        {
            let (statut, texte) = Self::dire_le_refus(*raison);
            return self.termine(statut, texte, Action::Continue, out);
        }
        let mut nom = [0_u8; MAILBOX_NAME_MAX];
        let nom_len = append.mailbox().len().min(nom.len());
        for (place, octet) in nom.iter_mut().zip(append.mailbox()) {
            *place = *octet;
        }
        self.depot = Some(Depot {
            dedans,
            reste: append.octets(),
            flags: append.flags(),
            date: append.date(),
            perdu: false,
            nom,
            nom_len,
        });
        Ok(Turn {
            reply: out.get(..0).unwrap_or_default(),
            action: Action::ReadAppend,
            peer_fault: false,
        })
    }

    /// Ce qu'un refus de dépôt vaut comme réponse.
    fn dire_le_refus(raison: Refus) -> (Status, &'static [u8]) {
        match raison {
            Refus::Authentification => (
                Status::Bad,
                b"Command is not allowed before authentication".as_slice(),
            ),
            Refus::Inconnue => (
                Status::No,
                b"[TRYCREATE] Destination mailbox does not exist".as_slice(),
            ),
        }
    }

    /// Combien d'octets de message restent à recevoir.
    #[must_use]
    pub fn append_remaining(&self) -> u64 {
        self.depot.as_ref().map_or(0, |depot| depot.reste)
    }

    /// Écoule un morceau du message vers le magasin.
    ///
    /// Rend combien d'octets ont été CONSOMMÉS : l'appelant garde le reste, qui
    /// est ce qui suit le littéral.
    pub fn append_chunk(&mut self, morceau: &[u8]) -> usize {
        let Some(depot) = self.depot.as_mut() else {
            return 0;
        };
        let pris = usize::try_from(depot.reste)
            .unwrap_or(usize::MAX)
            .min(morceau.len());
        let morceau = morceau.get(..pris).unwrap_or_default();
        depot.reste = depot.reste.saturating_sub(pris as u64);
        // ON ÉCRIT TANT QU'ON PEUT, ET L'ON LIT JUSQU'AU BOUT. Un dépôt perdu
        // n'autorise pas à cesser de lire : les octets restants sont un message,
        // pas des commandes.
        if let Dedans::Ouvert(dedans) = &mut depot.dedans
            && !dedans.write(morceau)
        {
            depot.perdu = true;
        }
        pris
    }

    /// Conclut un `APPEND` : le message est reçu.
    ///
    /// # `APPENDUID` DIT OÙ LE MESSAGE EST ALLÉ
    ///
    /// §6.3.12 : `OK [APPENDUID <validité> <uid>]`. C'est ce qui permet au
    /// client de retrouver ce qu'il vient de déposer sans relire la boîte.
    ///
    /// # Errors
    ///
    /// [`Error::Reply`] si `out` ne suffit pas.
    pub fn end_append<'b>(&mut self, out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        let Some(depot) = self.depot.take() else {
            return self.termine(Status::Bad, b"No APPEND in progress", Action::Continue, out);
        };
        // Quatre issues, et une seule dépose : on jetait déjà, le magasin a
        // lâché, le message est arrivé tronqué — le pair a raccroché au milieu —
        // ou tout s'est bien passé. VALIDER UN MESSAGE TRONQUÉ serait déposer du
        // courrier que personne n'a envoyé.
        let uid = match depot.dedans {
            Dedans::Jete(raison) => {
                let (statut, texte) = Self::dire_le_refus(raison);
                return self.termine(statut, texte, Action::Continue, out);
            }
            Dedans::Ouvert(dedans) if depot.perdu || depot.reste != 0 => {
                dedans.abort();
                None
            }
            Dedans::Ouvert(dedans) => dedans.commit(depot.flags, depot.date),
        };
        let Some(uid) = uid else {
            return self.termine(
                Status::No,
                b"Append failed; the message was not stored",
                Action::Continue,
                out,
            );
        };
        let validite = self
            .boites
            .open(
                self.user(),
                depot.nom.get(..depot.nom_len).unwrap_or_default(),
            )
            .map_or(0, |boite| boite.uid_validity());
        let mut texte = [0_u8; 64];
        let mut ecrits = recopier(&mut texte, 0, b"[APPENDUID ");
        ecrits = ecrits.saturating_add(nombre_en_octets(
            texte.get_mut(ecrits..).unwrap_or_default(),
            validite,
        ));
        ecrits = recopier(&mut texte, ecrits, b" ");
        ecrits = ecrits.saturating_add(nombre_en_octets(
            texte.get_mut(ecrits..).unwrap_or_default(),
            uid,
        ));
        ecrits = recopier(&mut texte, ecrits, b"] APPEND completed");
        self.termine(
            Status::Ok,
            texte.get(..ecrits).unwrap_or_default(),
            Action::Continue,
            out,
        )
    }

    /// `MOVE` et `UID MOVE` (§6.4.8).
    ///
    /// # L'ORDRE DES RÉPONSES EST CELUI QUE §6.4.8 IMPOSE
    ///
    /// D'abord `* OK [COPYUID …]`, **non sollicité**, qui dit où les messages
    /// sont allés ; puis les `* n EXPUNGE` qui disent qu'ils ne sont plus là ;
    /// enfin la conclusion. Le premier voyage donc comme réponse du tour, et les
    /// autres comme morceaux d'émission : c'est exactement l'ordre où l'appelant
    /// les écrit.
    fn deplacer<'b>(
        &mut self,
        arguments: &[u8],
        par_uid: bool,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        if self.ouverte.is_none() {
            return self.faute(b"Command is not allowed unless a mailbox is selected", out);
        }
        let mut place = [0_u8; MAILBOX_NAME_MAX];
        let (nom, uid_validity) = match self.destination(arguments, &mut place) {
            Ok(trouvee) => trouvee,
            Err(b"") => {
                return self.faute(b"MOVE expects a sequence set and a mailbox name", out);
            }
            Err(refus) => return self.termine(Status::No, refus, Action::Continue, out),
        };
        let texte = arguments.trim_ascii();
        let fin = texte
            .iter()
            .position(|octet| *octet == b' ')
            .unwrap_or(texte.len());
        let ensemble = SequenceSet::parse(texte.get(..fin).unwrap_or_default(), &self.limits)
            .unwrap_or(SequenceSet::EMPTY);

        let (exists, dernier_uid) = self.ouverte.as_ref().map_or((0, 0), |boite| {
            let exists = boite.exists();
            (exists, boite.info(exists).map_or(0, |info| info.uid))
        });
        let star = if par_uid { dernier_uid } else { exists };

        let faites = match self.copier(&ensemble, nom, par_uid, exists, star, true) {
            Ok(faites) => faites,
            Err(Echec::Copie) => {
                return self.termine(
                    Status::No,
                    b"Move failed; no messages were moved",
                    Action::Continue,
                    out,
                );
            }
            Err(Echec::TropMorcele) => {
                return self.termine(
                    Status::No,
                    b"[CANNOT] Move set is too fragmented",
                    Action::Continue,
                    out,
                );
            }
        };
        if faites.copies == 0 {
            return self.termine(
                Status::Ok,
                if par_uid {
                    b"UID MOVE completed".as_slice()
                } else {
                    b"MOVE completed".as_slice()
                },
                Action::Continue,
                out,
            );
        }

        // ON RETIRE PAR UID, MÊME QUAND LE CLIENT A DÉSIGNÉ DES RANGS. Retirer
        // renumérote : un ensemble de rangs cesserait de désigner ce qu'il
        // désignait dès le premier retrait, et l'on retirerait des messages que
        // personne n'a nommés.
        // `copier` a refusé de rendre des copies dont il ne saurait pas nommer
        // les sources : le texte est donc là.
        let ecrit = faites.source.texte().unwrap_or_default();
        let mut uids = [0_u8; SEQUENCE_TEXT_MAX];
        for (place, octet) in uids.iter_mut().zip(ecrit) {
            *place = *octet;
        }
        let uids_len = ecrit.len().min(uids.len());

        let mut emission = Emission {
            texte: uids,
            texte_len: uids_len,
            items: [FetchItem::Flags; ams_proto_imap::FETCH_ITEMS_MAX],
            items_len: 0,
            par_uid,
            cles_uid: true,
            exige_la_marque: false,
            star: dernier_uid,
            star_uid: dernier_uid,
            courant: 1,
            exists,
            ecriture: None,
            silencieux: false,
            genre: Genre::Move,
            plage: None,
            a_ecrire: None,
            entame: false,
            trouve: false,
            effaces: 0,
            etape: Etape::Choisir,
        };
        emission.texte_len = uids_len;
        self.emission = Some(emission);

        // La réponse du tour EST le `* OK [COPYUID …]` : il précède les
        // `EXPUNGE`, comme §6.4.8 le demande.
        let mut texte_reponse = [0_u8; COPYUID_MAX];
        let ecrits = copyuid_non_sollicite(
            &mut texte_reponse,
            uid_validity,
            uids.get(..uids_len).unwrap_or_default(),
            faites.premier_copie,
            faites.dernier_copie,
        );
        // SI LA LIGNE NE TIENT PAS, ON L'OMET — et le déplacement a lieu quand
        // même. `COPYUID` est un `SHOULD` (§6.4.8) ; échouer ici laisserait les
        // copies faites et les retraits à faire, ce qui est bien pire que de ne
        // pas dire où les messages sont allés.
        let ligne = encode_untagged(
            out,
            texte_reponse.get(..ecrits).unwrap_or_default(),
            &self.limits,
        )
        .map_or(0, <[u8]>::len);
        Ok(Turn {
            reply: out.get(..ligne).unwrap_or_default(),
            action: Action::SendFetch,
            peer_fault: false,
        })
    }

    /// `SEARCH` et `UID SEARCH` (§6.4.4).
    ///
    /// # IMAP4rev2 A REMPLACÉ `* SEARCH` PAR `* ESEARCH`
    ///
    /// La réponse `* SEARCH 2 4 5 6 7` de rev1 a disparu (§7.3.4) : rev2 rend
    /// `* ESEARCH (TAG "a001") ALL 2,4:7`, où les résultats sont un ENSEMBLE et
    /// non une liste. Ce serveur n'annonce que `IMAP4rev2`, et rendre l'ancienne
    /// forme à un client qui a lu l'annonce serait le tromper.
    fn search<'b>(
        &mut self,
        arguments: &[u8],
        par_uid: bool,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        // LA PRÉSENCE DE LA BOÎTE EST L'ÉTAT ; voir `fetch`.
        let Some(boite) = self.ouverte.as_ref() else {
            return self.faute(b"Command is not allowed unless a mailbox is selected", out);
        };
        let exists = boite.exists();
        let dernier_uid = boite.info(exists).map_or(0, |info| info.uid);

        // §6.4.4 : le jeu de caractères est optionnel, et rev2 impose UTF-8. On
        // accepte ce qu'on sait lire, et l'on refuse le reste par le code que la
        // RFC prévoit — plutôt que de chercher dans un encodage qu'on ignore.
        let mut critere = arguments.trim_ascii();
        if let Some(reste) = tete_sans_casse(critere, b"CHARSET") {
            let reste = reste.trim_ascii_start();
            let fin = reste
                .iter()
                .position(|octet| *octet == b' ')
                .unwrap_or(reste.len());
            let nom = reste.get(..fin).unwrap_or_default();
            let nom = nom.strip_prefix(b"\"").unwrap_or(nom);
            let nom = nom.strip_suffix(b"\"").unwrap_or(nom);
            if !nom.eq_ignore_ascii_case(b"UTF-8") && !nom.eq_ignore_ascii_case(b"US-ASCII") {
                return self.termine(
                    Status::No,
                    b"[BADCHARSET (UTF-8 US-ASCII)] Unsupported charset",
                    Action::Continue,
                    out,
                );
            }
            critere = reste.get(fin..).unwrap_or_default().trim_ascii();
        }

        if critere.len() > SEQUENCE_TEXT_MAX {
            return self.termine(
                Status::No,
                b"[CANNOT] Search criteria are too long",
                Action::Continue,
                out,
            );
        }
        match Search::parse(critere, &self.limits) {
            Ok(_) => {}
            Err(ImapError::SearchTooComplex { .. } | ImapError::SearchTooDeep { .. }) => {
                // CE N'EST PAS UNE FAUTE DE SYNTAXE, c'est une borne. Le client
                // saura qu'il doit demander plus simplement, au lieu de chercher
                // l'erreur dans ce qu'il a écrit.
                return self.termine(
                    Status::No,
                    b"[CANNOT] Search expression is too complex",
                    Action::Continue,
                    out,
                );
            }
            Err(ImapError::UnsupportedSearchKey) => {
                // RECONNU, ET REFUSÉ : un `SEARCH SUBJECT "facture"` à qui l'on
                // répondrait « aucun résultat » serait un mensonge exact.
                return self.termine(
                    Status::No,
                    b"[CANNOT] This search key is not served yet",
                    Action::Continue,
                    out,
                );
            }
            Err(_) => return self.faute(b"SEARCH arguments are malformed", out),
        }

        let mut emission = Emission {
            texte: [0; SEQUENCE_TEXT_MAX],
            texte_len: critere.len(),
            items: [FetchItem::Flags; ams_proto_imap::FETCH_ITEMS_MAX],
            items_len: 0,
            par_uid,
            cles_uid: par_uid,
            exige_la_marque: true,
            star: exists,
            star_uid: dernier_uid,
            courant: 1,
            exists,
            ecriture: None,
            silencieux: false,
            genre: Genre::Search,
            plage: None,
            a_ecrire: None,
            entame: false,
            trouve: false,
            effaces: 0,
            etape: Etape::Choisir,
        };
        for (place, octet) in emission.texte.iter_mut().zip(critere) {
            *place = *octet;
        }
        self.emission = Some(emission);
        Ok(Turn {
            reply: out.get(..0).unwrap_or_default(),
            action: Action::SendFetch,
            peer_fault: false,
        })
    }

    /// `EXPUNGE` et `UID EXPUNGE` (§6.4.3 et §6.4.9).
    fn expunge<'b>(
        &mut self,
        arguments: &[u8],
        par_uid: bool,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        // LA PRÉSENCE DE LA BOÎTE EST L'ÉTAT ; voir `fetch`.
        let Some(boite) = self.ouverte.as_ref() else {
            return self.faute(b"Command is not allowed unless a mailbox is selected", out);
        };
        let exists = boite.exists();
        let dernier_uid = boite.info(exists).map_or(0, |info| info.uid);
        if !self.peut_effacer() {
            return self.termine(
                Status::No,
                b"[CANNOT] Mailbox is read-only",
                Action::Continue,
                out,
            );
        }
        // UN `EXPUNGE` NU EFFACE TOUT CE QUI EST MARQUÉ ; un `UID EXPUNGE` s'en
        // tient à l'ensemble qu'on lui donne (§6.4.9). Le premier se dit `1:*`,
        // ce qui évite un second chemin dans le parcours.
        let arguments = arguments.trim_ascii();
        let texte: &[u8] = if par_uid {
            if arguments.is_empty() {
                return self.faute(b"UID EXPUNGE expects a sequence set", out);
            }
            arguments
        } else {
            if !arguments.is_empty() {
                return self.faute(b"EXPUNGE takes no arguments", out);
            }
            b"1:*"
        };
        if texte.len() > SEQUENCE_TEXT_MAX {
            return self.termine(
                Status::No,
                b"[CANNOT] Sequence set is too long",
                Action::Continue,
                out,
            );
        }
        if SequenceSet::parse(texte, &self.limits).is_err() {
            return self.faute(b"EXPUNGE arguments are malformed", out);
        }
        let mut emission = Emission {
            texte: [0; SEQUENCE_TEXT_MAX],
            texte_len: texte.len(),
            items: [FetchItem::Flags; ams_proto_imap::FETCH_ITEMS_MAX],
            items_len: 0,
            par_uid,
            cles_uid: par_uid,
            exige_la_marque: true,
            star: if par_uid { dernier_uid } else { exists },
            star_uid: dernier_uid,
            courant: 1,
            exists,
            ecriture: None,
            silencieux: false,
            genre: Genre::Expunge,
            plage: None,
            a_ecrire: None,
            entame: false,
            trouve: false,
            effaces: 0,
            etape: Etape::Choisir,
        };
        for (place, octet) in emission.texte.iter_mut().zip(texte) {
            *place = *octet;
        }
        self.emission = Some(emission);
        Ok(Turn {
            reply: out.get(..0).unwrap_or_default(),
            action: Action::SendFetch,
            peer_fault: false,
        })
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
        let mut place = [0_u8; MAILBOX_NAME_MAX];
        while let Some(boite) = self.boites.name(self.user(), index, &mut place) {
            index = index.saturating_add(1);
            if correspond(motif, boite.name) {
                // §6.3.5 : une boîte effacée qui avait des filles garde son nom
                // sans son courrier, et le dit.
                let attributs: &[u8] = if boite.selectable {
                    b"* LIST () \"/\" "
                } else {
                    b"* LIST (\\Noselect) \"/\" "
                };
                plume.nom_de_boite(attributs, boite.name, b"\r\n")?;
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

    /// `STORE` et `UID STORE` (§6.4.6).
    ///
    /// # Ce qui se décide ici, et ce qui se décide dans le magasin
    ///
    /// Ici : la commande est-elle recevable, les drapeaux demandés sont-ils de
    /// ceux que cette boîte sait faire survivre, et l'ensemble tient-il. Là-bas :
    /// comment deux sessions qui écrivent en même temps se départagent — une
    /// question de système de fichiers, pas de protocole.
    fn store<'b>(
        &mut self,
        arguments: &[u8],
        par_uid: bool,
        out: &'b mut [u8],
    ) -> Result<Turn<'b>, Error> {
        // LA PRÉSENCE DE LA BOÎTE EST L'ÉTAT ; voir `fetch`.
        let Some(boite) = self.ouverte.as_ref() else {
            return self.faute(b"Command is not allowed unless a mailbox is selected", out);
        };
        let permanents = boite.permanent_flags();
        let (exists, dernier_uid) = {
            let exists = boite.exists();
            (exists, boite.info(exists).map_or(0, |info| info.uid))
        };
        let demande = match Store::parse(arguments, &self.limits) {
            Ok(demande) => demande,
            Err(ImapError::UnknownFlag) => {
                // RECONNU, ET REFUSÉ : le client sait que son étiquette n'est
                // pas posée, au lieu de la croire posée pour toujours.
                return self.termine(
                    Status::No,
                    b"[CANNOT] This flag cannot be stored",
                    Action::Continue,
                    out,
                );
            }
            Err(_) => return self.faute(b"STORE arguments are malformed", out),
        };
        // ON NE PROMET QUE CE QUI SURVIT. Un drapeau hors de `PERMANENTFLAGS`
        // serait écrit puis perdu, et le client ne l'apprendrait jamais.
        if !permanents.contains(demande.flags()) {
            return self.termine(
                Status::No,
                b"[CANNOT] This flag does not persist in this mailbox",
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
        let mut emission = Emission {
            texte: [0; SEQUENCE_TEXT_MAX],
            texte_len: texte.len(),
            // §6.4.6 : la réponse d'un `STORE` dit les drapeaux, et rien
            // d'autre. Même si le `STORE` était par UID — le client sait déjà de
            // quel UID il parle, et le numéro de séquence lui suffit à recoller.
            items: [FetchItem::Flags; ams_proto_imap::FETCH_ITEMS_MAX],
            items_len: 1,
            par_uid,
            cles_uid: par_uid,
            exige_la_marque: true,
            star: if par_uid { dernier_uid } else { exists },
            star_uid: dernier_uid,
            courant: 1,
            exists,
            ecriture: Some((demande.mode(), demande.flags())),
            silencieux: demande.silent(),
            genre: Genre::Store,
            plage: None,
            a_ecrire: None,
            entame: false,
            trouve: false,
            effaces: 0,
            etape: Etape::Choisir,
        };
        for (place, octet) in emission.texte.iter_mut().zip(texte) {
            *place = *octet;
        }
        self.emission = Some(emission);
        Ok(Turn {
            reply: out.get(..0).unwrap_or_default(),
            action: Action::SendFetch,
            peer_fault: false,
        })
    }

    /// `CREATE` (§6.3.4).
    ///
    /// # LE PREMIER ENDROIT OÙ UN NOM DE CLIENT DEVIENT UN CHEMIN
    ///
    /// Jusqu'ici, `INBOX` se comparait à une constante et rien de ce que le
    /// client écrivait ne devenait un morceau de chemin. Cette commande-là fait
    /// exactement cela, et c'est pourquoi elle refuse tout ce qu'elle ne sait
    /// pas transcrire SANS RIEN TRANSFORMER : rendre au client un nom qui n'est
    /// pas celui qu'il a demandé lui ferait chercher longtemps.
    fn create<'b>(&mut self, arguments: &[u8], out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        if self.etat == State::NotAuthenticated {
            return self.faute(b"Command is not allowed before authentication", out);
        }
        let mut place = [0_u8; MAILBOX_NAME_MAX];
        let Some(nom) = self.un_nom(arguments, &mut place) else {
            return self.faute(b"CREATE expects a mailbox name", out);
        };
        // §6.3.4 : un `/` final ne change pas la boîte désignée.
        let nom = ams_proto_imap::mailbox_name_trimmed(nom);
        // §6.3.4 : `INBOX` existe toujours, et ne se crée donc pas.
        if nom.eq_ignore_ascii_case(b"INBOX") {
            return self.termine(
                Status::No,
                b"[ALREADYEXISTS] INBOX always exists",
                Action::Continue,
                out,
            );
        }
        if !ams_proto_imap::mailbox_name_is_safe(nom) {
            return self.termine(
                Status::No,
                b"[CANNOT] This mailbox name is not served",
                Action::Continue,
                out,
            );
        }
        match self.boites.create(self.user(), nom) {
            Creation::Faite => self.termine(Status::Ok, b"CREATE completed", Action::Continue, out),
            Creation::DejaLa => self.termine(
                Status::No,
                b"[ALREADYEXISTS] Mailbox already exists",
                Action::Continue,
                out,
            ),
            Creation::Refusee => {
                self.termine(Status::No, b"Cannot create mailbox", Action::Continue, out)
            }
        }
    }

    /// `DELETE` (§6.3.5).
    ///
    /// # UNE BOÎTE QUI A DES FILLES NE DISPARAÎT PAS
    ///
    /// §6.3.5 : son courrier s'en va, son NOM demeure, et il se marque
    /// `\Noselect`. Effacer le nom romprait la hiérarchie, et ses filles
    /// n'auraient plus de chemin par où être nommées — elles existeraient sans
    /// que personne puisse les atteindre.
    fn delete<'b>(&mut self, arguments: &[u8], out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        if self.etat == State::NotAuthenticated {
            return self.faute(b"Command is not allowed before authentication", out);
        }
        let mut place = [0_u8; MAILBOX_NAME_MAX];
        let Some(nom) = self.un_nom(arguments, &mut place) else {
            return self.faute(b"DELETE expects a mailbox name", out);
        };
        let nom = ams_proto_imap::mailbox_name_trimmed(nom);
        // §6.3.5 : `INBOX` ne s'efface pas. Elle est le seul endroit où le
        // courrier arrive, et un client qui la perdrait ne recevrait plus rien.
        if nom.eq_ignore_ascii_case(b"INBOX") {
            return self.termine(
                Status::No,
                b"[CANNOT] INBOX cannot be deleted",
                Action::Continue,
                out,
            );
        }
        if !ams_proto_imap::mailbox_name_is_safe(nom) {
            return self.termine(
                Status::No,
                b"[NONEXISTENT] Mailbox does not exist",
                Action::Continue,
                out,
            );
        }
        let issue = self.boites.delete(self.user(), nom);
        // ON NE GARDE PAS OUVERTE UNE BOÎTE QU'ON VIENT D'EFFACER. La session
        // en tient un instantané, des chemins, un état — tout cela désigne
        // désormais ce qui n'est plus. Le client se retrouve authentifié sans
        // sélection, et il doit le savoir.
        if matches!(issue, Deletion::Faite | Deletion::Videe) && nom == self.selected() {
            self.ouverte = None;
            self.emission = None;
            self.nom_ouvert_len = 0;
            self.etat = State::Authenticated;
        }
        match issue {
            Deletion::Faite | Deletion::Videe => {
                self.termine(Status::Ok, b"DELETE completed", Action::Continue, out)
            }
            Deletion::Absente => self.termine(
                Status::No,
                b"[NONEXISTENT] Mailbox does not exist",
                Action::Continue,
                out,
            ),
            Deletion::Refusee => {
                self.termine(Status::No, b"Cannot delete mailbox", Action::Continue, out)
            }
        }
    }

    /// `RENAME` (§6.3.6).
    ///
    /// # LES FILLES SUIVENT, ET `INBOX` NE PART PAS
    ///
    /// Deux règles qu'on manque facilement. Renommer `Archives` renomme aussi
    /// `Archives/2026` : les laisser derrière ferait des boîtes dont le chemin
    /// ne mène plus nulle part. Et renommer `INBOX` déplace son courrier sans la
    /// faire disparaître — c'est le seul endroit où le courrier arrive, et un
    /// compte qui la perdrait ne recevrait plus rien.
    fn rename<'b>(&mut self, arguments: &[u8], out: &'b mut [u8]) -> Result<Turn<'b>, Error> {
        if self.etat == State::NotAuthenticated {
            return self.faute(b"Command is not allowed before authentication", out);
        }
        let mut lus = Args::new(arguments);
        let mut avant = [0_u8; MAILBOX_NAME_MAX];
        let mut apres = [0_u8; MAILBOX_NAME_MAX];
        let (Some(Ok(premier)), Some(Ok(second)), None) = (lus.next(), lus.next(), lus.next())
        else {
            return self.faute(b"RENAME expects two mailbox names", out);
        };
        let (Ok(avant), Ok(apres)) = (premier.value(&mut avant), second.value(&mut apres)) else {
            return self.faute(b"RENAME arguments are too long", out);
        };
        let avant = ams_proto_imap::mailbox_name_trimmed(avant);
        let apres = ams_proto_imap::mailbox_name_trimmed(apres);
        if avant.is_empty() || apres.is_empty() {
            return self.faute(b"RENAME expects two mailbox names", out);
        }

        // §6.3.6 : `INBOX` peut être renommée — cela la vide —, mais rien ne
        // peut être renommé EN `INBOX` : elle existe déjà, de tout temps.
        if apres.eq_ignore_ascii_case(b"INBOX") {
            return self.termine(
                Status::No,
                b"[ALREADYEXISTS] INBOX always exists",
                Action::Continue,
                out,
            );
        }
        if !ams_proto_imap::mailbox_name_is_safe(apres) {
            return self.termine(
                Status::No,
                b"[CANNOT] This mailbox name is not served",
                Action::Continue,
                out,
            );
        }
        let source_valide =
            avant.eq_ignore_ascii_case(b"INBOX") || ams_proto_imap::mailbox_name_is_safe(avant);
        if !source_valide {
            return self.termine(
                Status::No,
                b"[NONEXISTENT] Mailbox does not exist",
                Action::Continue,
                out,
            );
        }
        // UNE BOÎTE NE SE RANGE PAS SOUS ELLE-MÊME. `Archives` vers
        // `Archives/2026` ferait descendre la mère sous sa propre fille, et le
        // renommage des filles n'aurait plus de fin qui ait un sens.
        if apres.len() > avant.len()
            && apres.starts_with(avant)
            && apres.get(avant.len()) == Some(&b'/')
        {
            return self.termine(
                Status::No,
                b"[CANNOT] A mailbox cannot be renamed under itself",
                Action::Continue,
                out,
            );
        }

        let issue = self.boites.rename(self.user(), avant, apres);
        // ON NE GARDE PAS OUVERTE UNE BOÎTE QUI A CHANGÉ DE NOM — ni une de ses
        // filles : la session en tient un instantané et des chemins, et tout
        // cela désigne désormais autre chose.
        let ouverte_touchee = self.selected() == avant
            || (self.selected().len() > avant.len()
                && self.selected().starts_with(avant)
                && self.selected().get(avant.len()) == Some(&b'/'));
        if issue == Renaming::Faite && ouverte_touchee {
            self.ouverte = None;
            self.emission = None;
            self.nom_ouvert_len = 0;
            self.etat = State::Authenticated;
        }
        match issue {
            Renaming::Faite => self.termine(Status::Ok, b"RENAME completed", Action::Continue, out),
            Renaming::Absente => self.termine(
                Status::No,
                b"[NONEXISTENT] Mailbox does not exist",
                Action::Continue,
                out,
            ),
            Renaming::DejaLa => self.termine(
                Status::No,
                b"[ALREADYEXISTS] Mailbox already exists",
                Action::Continue,
                out,
            ),
            Renaming::Refusee => {
                self.termine(Status::No, b"Cannot rename mailbox", Action::Continue, out)
            }
        }
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
        plume.nom_de_boite(b"* STATUS ", nom, b" (MESSAGES ")?;
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
        if verbe.eq_ignore_ascii_case(b"STORE") {
            return self.store(reste, true, out);
        }
        if verbe.eq_ignore_ascii_case(b"EXPUNGE") {
            return self.expunge(reste, true, out);
        }
        if verbe.eq_ignore_ascii_case(b"SEARCH") {
            return self.search(reste, true, out);
        }
        if verbe.eq_ignore_ascii_case(b"COPY") {
            return self.copy(reste, true, out);
        }
        if verbe.eq_ignore_ascii_case(b"MOVE") {
            return self.deplacer(reste, true, out);
        }
        self.termine(
            Status::No,
            b"[CANNOT] This UID command is not served yet",
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
            cles_uid: par_uid,
            exige_la_marque: true,
            star,
            star_uid: dernier_uid,
            courant: 1,
            exists,
            ecriture: None,
            silencieux: false,
            genre: Genre::Fetch,
            plage: None,
            a_ecrire: None,
            entame: false,
            trouve: false,
            effaces: 0,
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
                    emission.genre.conclusion(emission.par_uid),
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

        // ── UNE RECHERCHE REND UN ENSEMBLE, PAS UNE SUITE DE RÉPONSES ───────
        //
        // §7.3.4 : `* ESEARCH (TAG "a001") ALL 2,4:7`. UNE seule ligne, dont les
        // résultats sont comprimés en plages — et une ligne peut être longue,
        // donc elle traverse plusieurs morceaux. C'est la seule réponse du
        // serveur qui ne tienne pas dans un morceau, et l'appelant n'a rien à en
        // savoir : il écrit ce qu'on lui donne, dans l'ordre.
        if emission.genre == Genre::Search {
            // Le tag est recopié AVANT d'emprunter la boîte : il vit dans la
            // session, et l'emprunter en lecture pendant qu'on écrit dans la
            // boîte fâcherait le compilateur — à juste titre.
            let mut tag = [0_u8; TAG_MAX_OCTETS];
            let tag_len = self.tag_len.min(tag.len());
            for (place, octet) in tag.iter_mut().zip(self.tag.iter()) {
                *place = *octet;
            }
            let tag = tag.get(..tag_len).unwrap_or_default();
            let bornes = self.limits;

            // CHAQUE MORCEAU S'ÉCRIT D'UN SEUL GESTE.
            //
            // Une plage s'écrit en plusieurs bouts — le séparateur, un nombre,
            // deux-points, un nombre — et découvrir le manque de place au
            // troisième laisserait une plage à moitié écrite, que le client
            // lirait comme un résultat faux. On compose donc dans un tampon de
            // taille fixe, par des routines qui ne peuvent pas échouer, et l'on
            // ne pousse qu'une fois. Ce qui rend le manque de place ORDINAIRE :
            // on rend la main, et l'on reprendra au même endroit.
            let mut petit = [0_u8; ESEARCH_MORCEAU_MAX];
            let mut plume = Plume::neuve(out);
            if !emission.entame {
                let ecrits = entete_esearch(&mut petit, tag, emission.par_uid);
                plume.pousser(petit.get(..ecrits).unwrap_or_default())?;
                emission.entame = true;
            }
            loop {
                // 1. Une plage close attend-elle d'être écrite ?
                if let Some((debut, fin)) = emission.a_ecrire {
                    let ecrits = plage_esearch(&mut petit, emission.trouve, debut, fin);
                    if plume
                        .pousser(petit.get(..ecrits).unwrap_or_default())
                        .is_err()
                    {
                        break;
                    }
                    emission.trouve = true;
                    emission.a_ecrire = None;
                    continue;
                }
                // 2. Sinon, on avance d'un résultat.
                let Some(clef) = emission.trouvaille(boite, &bornes) else {
                    // La boîte est parcourue : la plage ouverte se ferme, puis
                    // la ligne.
                    if let Some(plage) = emission.plage.take() {
                        emission.a_ecrire = Some(plage);
                        continue;
                    }
                    if plume.pousser(b"\r\n").is_ok() {
                        emission.etape = Etape::Conclure;
                    }
                    break;
                };
                match emission.plage {
                    // Le résultat prolonge la plage ouverte.
                    Some((debut, fin)) if clef == fin.saturating_add(1) => {
                        emission.plage = Some((debut, clef));
                    }
                    // Il ouvre une plage, et ferme la précédente.
                    Some(plage) => {
                        emission.a_ecrire = Some(plage);
                        emission.plage = Some((clef, clef));
                    }
                    None => emission.plage = Some((clef, clef)),
                }
            }
            let ecrits = plume.ecrits();
            // UN MORCEAU VIDE QUI NE CONCLUT RIEN EST UNE BOUCLE SANS FIN. Si le
            // tampon est trop court pour qu'on avance d'un seul octet, le dire
            // vaut mieux que de rendre indéfiniment du vide à un appelant qui
            // l'écrira indéfiniment.
            if ecrits == 0 && emission.etape != Etape::Conclure {
                return Err(Error::Reply(ImapError::BufferTooSmall {
                    needed: ESEARCH_MORCEAU_MAX,
                }));
            }
            self.emission = Some(emission);
            return Ok(Some(FetchChunk::Bytes(
                out.get(..ecrits).unwrap_or_default(),
            )));
        }

        // ── L'EFFACEMENT SUIT UN AUTRE CHEMIN QUE LA LECTURE ────────────────
        //
        // §7.5.1 : chaque `* n EXPUNGE` RENUMÉROTE ce qui suit. La réponse n'a
        // donc pas la forme d'un `FETCH`, et le parcours non plus : il ne
        // s'arrête pas au rang courant mais à ce qu'il reste de la boîte.
        if matches!(emission.genre, Genre::Expunge | Genre::Move) {
            loop {
                let Some(rang) = emission.a_effacer(boite, &self.limits) else {
                    emission.etape = Etape::Conclure;
                    self.emission = Some(emission);
                    return self.next_fetch(out);
                };
                // `EXPUNGE` relit la marque avant d'effacer, `MOVE` non : voir
                // `Mailbox::remove`. Les confondre ferait ou bien un `MOVE` qui
                // ne déplace rien, ou bien un `EXPUNGE` qui efface ce qu'on ne
                // lui a pas demandé.
                let parti = if emission.genre == Genre::Move {
                    boite.remove(rang)
                } else {
                    boite.expunge(rang)
                };
                if !parti {
                    // Toujours là — la marque a dû être retirée entre-temps. On
                    // passe, et l'on n'annonce rien : annoncer un effacement qui
                    // n'a pas eu lieu ferait perdre au client le fil des numéros.
                    emission.courant = rang.saturating_add(1);
                    continue;
                }
                emission.effaces = emission.effaces.saturating_add(1);
                self.emission = Some(emission);
                let mut plume = Plume::neuve(out);
                plume.pousser(b"* ")?;
                plume.nombre(u64::from(rang))?;
                plume.pousser(b" EXPUNGE\r\n")?;
                let ecrits = plume.ecrits();
                return Ok(Some(FetchChunk::Bytes(
                    out.get(..ecrits).unwrap_or_default(),
                )));
            }
        }

        // ON BOUCLE PLUTÔT QUE DE SE RAPPELER SOI-MÊME. Un `STORE .SILENT` sur
        // dix mille messages n'écrit rien pour chacun : une récursion par
        // message userait la pile à la demande du client.
        let (rang, info) = loop {
            let Some((rang, info)) = emission.suivant(boite, &self.limits) else {
                emission.etape = Etape::Conclure;
                self.emission = Some(emission);
                return self.next_fetch(out);
            };
            if let Some((mode, drapeaux)) = emission.ecriture {
                // Le message a pu disparaître entre l'instantané et l'écriture ;
                // §6.4.6 veut qu'on n'en fasse pas une erreur, et le client
                // l'apprend en ne recevant rien pour lui.
                let Some(nouveaux) = boite.store_flags(rang, mode, drapeaux) else {
                    continue;
                };
                if !emission.silencieux {
                    break (
                        rang,
                        MessageInfo {
                            flags: nouveaux,
                            ..info
                        },
                    );
                }
                continue;
            }
            break (rang, info);
        };
        // §6.4.5 : un corps rendu SANS `PEEK` marque le message comme lu. On le
        // marque AVANT de composer, pour que les `FLAGS` de la même réponse
        // disent la vérité plutôt que l'état d'avant.
        let items = emission.items.get(..emission.items_len).unwrap_or_default();
        let info = if items
            .iter()
            .any(|item| matches!(item, FetchItem::Body { peek: false, .. }))
        {
            boite
                .store_flags(rang, StoreMode::Add, Flags::SEEN)
                .map_or(info, |flags| MessageInfo { flags, ..info })
        } else {
            info
        };

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
        // de l'ASCII imprimable — espace compris, parce que « Sent Messages »
        // est un nom de dossier des plus ordinaires, et que la réponse le CITE
        // entre guillemets. Ce qui est exclu, ce sont les octets qui feraient
        // écrire au client une réponse de notre part.
        if ecrit.is_empty()
            || !ecrit
                .iter()
                .all(|octet| octet.is_ascii_graphic() || *octet == b' ')
            || ecrit.iter().any(|octet| matches!(*octet, b'"' | b'\\'))
        {
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

/// Ce qu'on accepte d'écrire pour l'ensemble SOURCE d'un `COPYUID`.
///
/// Au-delà, on omet `COPYUID` : un ensemble tronqué désignerait d'autres
/// messages que ceux qu'on a copiés, ce qui est pire que de ne rien dire.
const COPYUID_SOURCE_MAX: usize = 192;

/// La place que prend le texte complet d'une conclusion de `COPY`.
const COPYUID_MAX: usize = COPYUID_SOURCE_MAX + 64;

/// Vingt-deux octets majorent une plage : `4294967295:4294967295`.
const PLAGE_MAX_OCTETS: usize = 22;

/// Un ensemble de numéros qu'on construit en avançant, et qui se comprime.
///
/// # POURQUOI IL PEUT DÉBORDER, ET POURQUOI IL LE DIT
///
/// L'ensemble source d'un `COPYUID` est ce que le CLIENT a désigné, trous
/// compris : `1,3,5,7,…` ne se comprime pas. Sa longueur est donc choisie par le
/// client, et la retenir sans borne lui donnerait le droit de choisir combien de
/// mémoire le serveur consomme. On borne, et l'on constate le débordement au
/// lieu de tronquer.
struct Plage {
    texte: [u8; COPYUID_SOURCE_MAX],
    len: usize,
    ouverte: Option<(u32, u32)>,
    deborde: bool,
}

impl Plage {
    fn neuve() -> Self {
        Self {
            texte: [0; COPYUID_SOURCE_MAX],
            len: 0,
            ouverte: None,
            deborde: false,
        }
    }

    /// Ajoute un numéro. Contigu au précédent, il prolonge la plage ouverte.
    fn pousser(&mut self, clef: u32) {
        match self.ouverte {
            Some((debut, fin)) if clef == fin.saturating_add(1) => {
                self.ouverte = Some((debut, clef));
            }
            Some(plage) => {
                self.ecrire(plage);
                self.ouverte = Some((clef, clef));
            }
            None => self.ouverte = Some((clef, clef)),
        }
    }

    /// Écrit une plage close, ou constate qu'elle ne tient pas.
    fn ecrire(&mut self, (debut, fin): (u32, u32)) {
        if self.texte.len().saturating_sub(self.len) < PLAGE_MAX_OCTETS {
            self.deborde = true;
            return;
        }
        if self.len != 0 {
            self.len = recopier(&mut self.texte, self.len, b",");
        }
        self.len = self.len.saturating_add(nombre_en_octets(
            self.texte.get_mut(self.len..).unwrap_or_default(),
            debut,
        ));
        if fin != debut {
            self.len = recopier(&mut self.texte, self.len, b":");
            self.len = self.len.saturating_add(nombre_en_octets(
                self.texte.get_mut(self.len..).unwrap_or_default(),
                fin,
            ));
        }
    }

    /// Ferme la plage en cours : après cela, le texte est complet.
    ///
    /// **On parcourt une tranche plutôt que de tester une option** : une plage
    /// ouverte n'est pas une condition, c'est un élément qu'on a ou qu'on n'a
    /// pas. Un `if let` porterait un « et sinon » qui ne dit rien, et une
    /// tranche d'au plus un élément se parcourt sans rien affirmer.
    fn fermer(&mut self) {
        let a_fermer = self.ouverte.take();
        for plage in a_fermer.as_slice() {
            self.ecrire(*plage);
        }
    }

    /// L'ensemble a-t-il débordé ?
    fn a_deborde(&self) -> bool {
        self.deborde
    }

    /// Le texte de l'ensemble, ou `None` s'il a débordé.
    fn texte(&self) -> Option<&[u8]> {
        if self.deborde {
            return None;
        }
        self.texte.get(..self.len)
    }
}

/// Pourquoi une phase de copie n'a rien laissé derrière elle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Echec {
    /// Une copie a échoué.
    Copie,
    /// Les sources ne tiennent pas dans ce qu'on sait nommer.
    TropMorcele,
}

/// Ce qu'une phase de copie a produit.
struct Copies {
    /// Les UID des messages copiés, comprimés en ensemble.
    source: Plage,
    /// Le premier UID attribué dans la destination.
    premier_copie: u32,
    /// Le dernier.
    dernier_copie: u32,
    /// Combien de messages ont été copiés.
    copies: u32,
}

/// Compose le texte d'un `* OK [COPYUID …]` non sollicité (§6.4.8).
fn copyuid_non_sollicite(
    out: &mut [u8],
    uid_validity: u32,
    source: &[u8],
    premier: u32,
    dernier: u32,
) -> usize {
    let mut ecrits = recopier(out, 0, b"OK [COPYUID ");
    ecrits = ecrits.saturating_add(nombre_en_octets(
        out.get_mut(ecrits..).unwrap_or_default(),
        uid_validity,
    ));
    ecrits = recopier(out, ecrits, b" ");
    ecrits = recopier(out, ecrits, source);
    ecrits = recopier(out, ecrits, b" ");
    ecrits = ecrits.saturating_add(nombre_en_octets(
        out.get_mut(ecrits..).unwrap_or_default(),
        premier,
    ));
    if dernier != premier {
        ecrits = recopier(out, ecrits, b":");
        ecrits = ecrits.saturating_add(nombre_en_octets(
            out.get_mut(ecrits..).unwrap_or_default(),
            dernier,
        ));
    }
    recopier(out, ecrits, b"] Moved")
}

/// Compose la conclusion d'un `COPY`, `COPYUID` compris s'il tient.
fn copyuid(
    out: &mut [u8],
    uid_validity: u32,
    source: &Plage,
    premier: u32,
    dernier: u32,
    par_uid: bool,
) -> usize {
    let fin: &[u8] = if par_uid {
        b"] UID COPY completed"
    } else {
        b"] COPY completed"
    };
    let Some(source) = source.texte() else {
        // Débordé : on conclut sans rien affirmer sur les UID.
        return recopier(
            out,
            0,
            if par_uid {
                b"UID COPY completed"
            } else {
                b"COPY completed"
            },
        );
    };
    let mut ecrits = recopier(out, 0, b"[COPYUID ");
    ecrits = ecrits.saturating_add(nombre_en_octets(
        out.get_mut(ecrits..).unwrap_or_default(),
        uid_validity,
    ));
    ecrits = recopier(out, ecrits, b" ");
    ecrits = recopier(out, ecrits, source);
    ecrits = recopier(out, ecrits, b" ");
    ecrits = ecrits.saturating_add(nombre_en_octets(
        out.get_mut(ecrits..).unwrap_or_default(),
        premier,
    ));
    if dernier != premier {
        ecrits = recopier(out, ecrits, b":");
        ecrits = ecrits.saturating_add(nombre_en_octets(
            out.get_mut(ecrits..).unwrap_or_default(),
            dernier,
        ));
    }
    recopier(out, ecrits, fin)
}

/// La plus grande taille d'un morceau d'`ESEARCH` composé d'un seul geste.
///
/// L'en-tête est le plus long : `* ESEARCH (TAG "` plus un tag, plus `") UID`.
const ESEARCH_MORCEAU_MAX: usize = TAG_MAX_OCTETS + 32;

/// Écrit un entier décimal dans `out`, et rend le nombre d'octets écrits.
///
/// **Rien ne peut échouer** : dix chiffres majorent tout `u32`, et l'appelant
/// donne toujours au moins cela. Ce qui déborderait n'est pas écrit, ce qui ne
/// peut pas arriver.
fn nombre_en_octets(out: &mut [u8], valeur: u32) -> usize {
    let mut chiffres = [b'0'; 10];
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
    let mut ecrits = 0_usize;
    for (place, chiffre) in out
        .iter_mut()
        .zip(chiffres.get(debut..).unwrap_or_default())
    {
        *place = *chiffre;
        ecrits = ecrits.saturating_add(1);
    }
    ecrits
}

/// Recopie `morceau` à partir de `ecrits`, et rend la nouvelle position.
fn recopier(out: &mut [u8], ecrits: usize, morceau: &[u8]) -> usize {
    let mut ecrits = ecrits;
    for (place, octet) in out.iter_mut().skip(ecrits).zip(morceau) {
        *place = *octet;
        ecrits = ecrits.saturating_add(1);
    }
    ecrits
}

/// Compose `* ESEARCH (TAG "…")` et, si la recherche porte sur des UID, ` UID`.
fn entete_esearch(out: &mut [u8], tag: &[u8], par_uid: bool) -> usize {
    let mut ecrits = recopier(out, 0, b"* ESEARCH (TAG \"");
    ecrits = recopier(out, ecrits, tag);
    ecrits = recopier(out, ecrits, b"\")");
    if par_uid {
        ecrits = recopier(out, ecrits, b" UID");
    }
    ecrits
}

/// Compose une plage de résultats : ` ALL 1:3` la première, `,7` les suivantes.
fn plage_esearch(out: &mut [u8], deja: bool, debut: u32, fin: u32) -> usize {
    let mut ecrits = recopier(out, 0, if deja { b"," } else { b" ALL " });
    ecrits = ecrits.saturating_add(nombre_en_octets(
        out.get_mut(ecrits..).unwrap_or_default(),
        debut,
    ));
    if fin != debut {
        ecrits = recopier(out, ecrits, b":");
        ecrits = ecrits.saturating_add(nombre_en_octets(
            out.get_mut(ecrits..).unwrap_or_default(),
            fin,
        ));
    }
    ecrits
}

/// Rend ce qui suit `tete`, si le texte commence par elle — sans égard à la
/// casse, ce que `strip_prefix` ne sait pas faire.
fn tete_sans_casse<'a>(texte: &'a [u8], tete: &[u8]) -> Option<&'a [u8]> {
    let (debut, reste) = texte.split_at_checked(tete.len())?;
    debut.eq_ignore_ascii_case(tete).then_some(reste)
}

/// Rend `nom` privé de `suffixe`
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

    /// Écrit un nom de boîte, ENTRE GUILLEMETS, entouré de ce qu'on lui donne.
    ///
    /// # POURQUOI TOUJOURS LES GUILLEMETS
    ///
    /// Un nom peut porter un espace — « Sent Messages » — et l'écrire nu ferait
    /// lire au client deux mots là où il y en a un. Ne citer que les noms qui en
    /// ont besoin demanderait une condition de plus, qu'il faudrait avoir juste
    /// à chaque endroit ; citer toujours n'en demande aucune, et la grammaire
    /// admet la forme citée partout où un nom paraît.
    fn nom_de_boite(&mut self, avant: &[u8], nom: &[u8], apres: &[u8]) -> Result<(), Error> {
        self.pousser(avant)?;
        self.pousser(b"\"")?;
        self.pousser(nom)?;
        self.pousser(b"\"")?;
        self.pousser(apres)
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
