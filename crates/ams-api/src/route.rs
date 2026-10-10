// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La table de routage : ce que cette API met à disposition.
//!
//! # UNE RESSOURCE, PUIS UNE MÉTHODE — ET NON L'INVERSE
//!
//! Le chemin dit CE QU'ON DÉSIGNE ; la méthode dit CE QU'ON EN FAIT. Les
//! confondre en une seule table donnerait autant d'entrées que de couples, et
//! rendrait impossible la distinction que §15.5.6 de RFC 9110 exige : un 404
//! quand la ressource n'existe pas, un 405 avec un `Allow` quand elle existe
//! mais pas avec cette méthode.
//!
//! Cette distinction n'est pas de la politesse. Un client qui reçoit 404 sur un
//! `PATCH` ne sait pas s'il s'est trompé de chemin ou de verbe, et réessaiera
//! les deux — ce qui double le trafic pour rien.
//!
//! # CHAQUE RESSOURCE PORTE SA PORTÉE, DANS LE MÊME `match`
//!
//! [`Resource::scope`] est un `match` exhaustif sur le même type que la table.
//! Ajouter une ressource sans lui donner de portée **ne compile pas**.
//!
//! C'est l'inverse d'une liste de contrôle tenue à part, qui se désynchronise au
//! premier ajout — et dont le premier symptôme est une ressource servie sans
//! droit.
//!
//! # LA VERSION EST DANS LE CHEMIN, ET ELLE EST OBLIGATOIRE
//!
//! `/v1/…`. Sans elle, la première rupture de compatibilité n'aurait nulle part
//! où se dire, et se dirait donc en silence — chez le client, à l'exécution.

use ams_proto_http::Method;

use crate::error::{Error, Reason};
use crate::path::{Segments, decode};
use crate::query::Query;
use crate::scope::{Area, Rights, Scope};

/// La version d'API que porte le chemin.
pub const VERSION: &str = "v1";

/// De quoi écrire la valeur d'`Allow` la plus longue, avec de la marge.
///
/// `GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS` fait quarante-quatre octets.
/// Aucune ressource ne sert les sept, mais la borne ne se calcule pas sur ce
/// qu'on sert aujourd'hui — elle se calcule sur ce que le type peut produire.
pub const ALLOW_OCTETS_MAX: usize = 64;

/// Ce qu'un chemin désigne.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource<'o> {
    /// `/v1/tokens` — l'échange d'identifiants contre un jeton.
    ///
    /// **LA SEULE RESSOURCE QUI N'EXIGE AUCUNE PORTÉE**, puisque c'est celle où
    /// l'on n'en a pas encore.
    Tokens,
    /// `/v1/tokens/current` — le jeton qu'on présente, pour le révoquer.
    CurrentToken,

    /// `/v1/mailboxes` — les boîtes du compte.
    Mailboxes,
    /// `/v1/mailboxes/{boite}` — une boîte, et son état.
    Mailbox {
        /// Le nom de la boîte.
        boite: &'o str,
    },
    /// `/v1/mailboxes/{boite}/messages` — les messages qu'elle porte.
    Messages {
        /// Le nom de la boîte.
        boite: &'o str,
    },
    /// `/v1/mailboxes/{boite}/messages/{uid}` — un message, enveloppe et
    /// structure.
    Message {
        /// Le nom de la boîte.
        boite: &'o str,
        /// L'identifiant unique du message dans cette boîte.
        uid: u64,
    },
    /// `/v1/mailboxes/{boite}/messages/{uid}/raw` — le message tel qu'il est
    /// arrivé.
    ///
    /// **UNE RESSOURCE À PART, ET NON UNE NÉGOCIATION DE CONTENU** : le message
    /// brut et son enveloppe décodée ne sont pas deux représentations d'une même
    /// chose — l'un est ce qui a été reçu, l'autre notre lecture. Les confondre
    /// ferait dépendre d'un en-tête `Accept` la question « qu'est-ce que le
    /// serveur a vraiment reçu ? », qui doit avoir une réponse stable.
    MessageRaw {
        /// Le nom de la boîte.
        boite: &'o str,
        /// L'identifiant unique.
        uid: u64,
    },
    /// `/v1/mailboxes/{boite}/messages/{uid}/parts/{partie}` — une partie MIME.
    MessagePart {
        /// Le nom de la boîte.
        boite: &'o str,
        /// L'identifiant unique.
        uid: u64,
        /// Le chemin de la partie, tel que §6.4.5 de RFC 9051 le numérote.
        partie: &'o str,
    },
    /// `/v1/mailboxes/{boite}/changes` — **ce qui a changé depuis un point**.
    ///
    /// `?since=<modseq>` est exigé : c'est la synchronisation incrémentale, et
    /// elle n'a de sens que depuis quelque part. Un curseur que le journal ne
    /// sert plus rend `410` — le client relit la boîte entière.
    Changes {
        /// Le nom de la boîte.
        boite: &'o str,
    },
    /// `/v1/mailboxes/{boite}/search` — une recherche dans une boîte.
    Search {
        /// Le nom de la boîte.
        boite: &'o str,
    },
    /// `/v1/drafts` — **un message se soumet corps d'abord.**
    ///
    /// Décision de l'exploitant : le corps — texte, HTML — part seul, dans la
    /// borne d'un message ; les pièces jointes suivent, par morceaux écrits sur
    /// disque, et le serveur compose le message entier au moment d'envoyer ou
    /// de ranger. Un `POST` crée le brouillon à partir du corps.
    Drafts,
    /// `/v1/drafts/{id}` — un brouillon : son état, ou son abandon.
    Draft {
        /// L'identifiant du brouillon.
        id: &'o str,
    },
    /// `/v1/drafts/{id}/attachments` — déclarer une pièce jointe.
    DraftAttachments {
        /// L'identifiant du brouillon.
        id: &'o str,
    },
    /// `/v1/drafts/{id}/attachments/{n}` — un morceau d'une pièce jointe
    /// (`PUT` avec `Content-Range`), ou son retrait.
    DraftAttachment {
        /// L'identifiant du brouillon.
        id: &'o str,
        /// Le numéro de la pièce jointe dans le brouillon.
        piece: u64,
    },
    /// `/v1/drafts/{id}/send` — composer le message et l'envoyer.
    DraftSend {
        /// L'identifiant du brouillon.
        id: &'o str,
    },
    /// `/v1/drafts/{id}/store` — composer le message et le ranger dans une
    /// boîte, sans l'envoyer.
    DraftStore {
        /// L'identifiant du brouillon.
        id: &'o str,
    },
    /// `/v1/mailboxes/{boite}/copy` — copier des messages vers une autre boîte.
    ///
    /// **GROUPÉ, COMME `COPY` D'IMAP** : ranger cinquante messages ne doit pas
    /// coûter cinquante allers-retours sur un réseau mobile. Le corps nomme la
    /// destination et les UID ; la réponse dit l'UID de chaque copie.
    Copy {
        /// La boîte d'où l'on copie.
        boite: &'o str,
    },
    /// `/v1/mailboxes/{boite}/move` — déplacer des messages vers une autre
    /// boîte : copier, puis retirer l'original, comme `MOVE` d'IMAP (RFC 6851).
    Move {
        /// La boîte d'où l'on déplace.
        boite: &'o str,
    },

    /// `/v1/me/password` — **le secret de qui appelle**, et de personne d'autre.
    ///
    /// # POURQUOI `/v1/me/…` ET NON `/v1/accounts/me/password`
    ///
    /// Le second aurait rendu INATTEIGNABLE, par la route d'administration, un
    /// compte réellement nommé `me` : `check_login` l'accepte, et rien
    /// n'interdit à quelqu'un de le choisir. Réserver un nom de compte pour
    /// faire tenir une route est un prix qu'on ne paie pas quand un segment de
    /// tête libre existe.
    ///
    /// # ELLE N'EXIGE AUCUNE PORTÉE, ET CE N'EST PAS UN OUBLI
    ///
    /// Comme `/v1/tokens/current`, elle agit sur SOI et non sur une ressource
    /// du serveur : le jeton présenté dit déjà de qui il s'agit. Exiger `Admin`
    /// en ferait une route que seul un administrateur peut emprunter, ce qui
    /// est très exactement ce qu'elle existe pour éviter.
    ///
    /// **LE MOT DE PASSE ACTUEL EST EXIGÉ DANS LE CORPS**, lui. Sans cela, un
    /// jeton volé permettrait de verrouiller le propriétaire légitime hors de
    /// sa boîte, définitivement — un vol de jeton deviendrait un vol de compte.
    OwnPassword,

    /// `/v1/me/devices` — **les appareils de qui appelle**, et de personne
    /// d'autre.
    ///
    /// # POURQUOI SOUS `/v1/me/…` ET NON SOUS `/v1/accounts/…`
    ///
    /// Pour la même raison que le mot de passe : elle agit sur SOI, et le jeton
    /// présenté dit déjà de qui il s'agit. La ranger sous l'administration en
    /// ferait une route que seul un administrateur peut emprunter — or c'est
    /// l'utilisateur qui doit pouvoir voir ses propres appareils, et surtout en
    /// révoquer un, sans demander à personne.
    ///
    /// **C'EST LA RÉVOCATION QUI PRESSE** : un téléphone perdu se retire dans la
    /// minute, pas au prochain jour ouvré.
    ///
    /// # ELLE S'ÉCRIT AUSSI, ET C'EST L'APPAIRAGE CROISÉ
    ///
    /// Un `POST` y enrôle un SECOND appareil, approuvé par un premier. Sans
    /// cela, ajouter une tablette exigerait une invitation de l'exploitant, et
    /// donc de révoquer le téléphone d'abord.
    ///
    /// **LE JETON NE SUFFIT PAS À CE `POST`** : il faut un défi signé par un
    /// appareil DÉJÀ enrôlé. Un jeton vaut quinze minutes, une clef vaut jusqu'à
    /// sa révocation — laisser un porteur créer une clef ferait d'un vol de
    /// quinze minutes un accès permanent, que fermer la session ne retirerait
    /// pas.
    OwnDevices,
    /// `/v1/me/devices/{id}` — un appareil à soi, pour le révoquer.
    ///
    /// **L'IDENTIFIANT NE SUFFIT PAS À DÉSIGNER** : le compte de qui appelle
    /// entre dans la recherche. Sans cela, deviner un identifiant permettrait de
    /// révoquer l'appareil d'un autre, et un déni de service tiendrait en une
    /// boucle.
    OwnDevice {
        /// L'identifiant de l'appareil, tel que le serveur l'a tiré.
        id: &'o str,
    },
    /// `/v1/me/push` — l'abonnement aux notifications de l'APPAREIL qui
    /// appelle.
    ///
    /// **L'APPAREIL, ET NON LE COMPTE** : c'est la session qui le désigne,
    /// ouverte par sa clef. Une session ouverte par mot de passe n'a pas
    /// d'appareil, donc pas d'abonnement — la réponse le dit (`409`). Un
    /// identifiant dans le chemin laisserait abonner l'appareil d'un autre.
    OwnPush,
    /// `/v1/me/app-passwords` — les mots de passe applicatifs de qui appelle.
    ///
    /// Un `GET` les liste — noms et dates, **jamais le secret** ; un `POST` en
    /// crée un, dont le secret est rendu UNE FOIS, dans la réponse.
    ///
    /// **ILS N'OUVRENT PAS CETTE API**, seulement IMAP, SMTP et POP3 : sans
    /// cela, le client de courrier d'un poste perdu pourrait en créer d'autres,
    /// et le révoquer ne suffirait plus.
    OwnAppPasswords,
    /// `/v1/accounts/{compte}/delegates` — qui atteint la boîte de ce compte, et
    /// avec quels droits. **ADMINISTRATION SEULE** : les boîtes partagées n'ont
    /// pas de titulaire humain pour en décider.
    Delegates {
        /// Le titulaire.
        compte: &'o str,
    },
    /// `/v1/accounts/{compte}/delegates/{delegue}` — une délégation : `PUT` la
    /// pose ou la remplace, `DELETE` la retire.
    Delegate {
        /// Le titulaire.
        compte: &'o str,
        /// Le compte qui reçoit l'accès.
        delegue: &'o str,
    },
    /// `/v1/me/audit` — le journal d'audit de qui appelle : ce qui a touché à
    /// la sécurité de son compte, du plus récent au plus ancien (phase 6).
    ///
    /// **N'IMPORTE QUEL JETON DE SON TITULAIRE Y SUFFIT**, comme pour ses
    /// appareils : « qui s'est connecté à mon compte ? » ne s'adresse pas à
    /// l'exploitant. Il ne s'écrit pas : un journal qu'on peut retoucher ne
    /// prouve rien.
    OwnAudit,
    /// `/v1/accounts/{compte}/devices` — les appareils d'un compte : `GET` les
    /// liste, `DELETE` les révoque TOUS (0.2.41). **ADMINISTRATION SEULE.**
    ///
    /// **C'EST LA VOIE DE SECOURS** : une invitation ne vaut que pour un compte
    /// sans appareil, et un utilisateur qui a perdu son seul téléphone ne peut
    /// pas en approuver un autre. Sans cette ressource, le réinviter demandait
    /// de supprimer son compte.
    AccountDevices {
        /// Le compte.
        compte: &'o str,
    },
    /// `/v1/accounts/{compte}/devices/{id}` — un appareil d'un compte, pour le
    /// révoquer. **ADMINISTRATION SEULE.**
    AccountDevice {
        /// Le compte.
        compte: &'o str,
        /// L'identifiant de l'appareil.
        id: &'o str,
    },
    /// `/v1/accounts/{compte}/audit` — le journal d'audit d'un compte.
    /// **ADMINISTRATION SEULE.**
    AccountAudit {
        /// Le compte.
        compte: &'o str,
    },
    /// `/v1/me/delegations` — les boîtes d'autrui que qui appelle peut
    /// atteindre, et ses droits sur chacune. C'est ce qu'une application lit
    /// pour afficher « support@ » à côté de sa propre boîte.
    OwnDelegations,
    /// `/v1/me/app-passwords/{id}` — un mot de passe applicatif à soi, pour le
    /// révoquer. Le compte de qui appelle entre dans la recherche, comme pour
    /// un appareil.
    OwnAppPassword {
        /// L'identifiant du mot de passe applicatif.
        id: &'o str,
    },

    /// `/v1/devices` — **enrôler un appareil, sans jeton.**
    ///
    /// # LA SEULE AUTRE RESSOURCE QUI N'EXIGE AUCUN JETON
    ///
    /// Comme `/v1/tokens`, et pour la même raison : c'est une porte d'entrée.
    /// Celui qui s'enrôle n'a encore rien — ni mot de passe qu'il veuille
    /// donner, ni appareil déjà connu. **C'est l'invitation, dans le corps, qui
    /// l'autorise**, et elle se vérifie avec la même clé qu'un jeton.
    ///
    /// Elle n'est PAS sous `/v1/me` : « moi » n'a pas de sens sans jeton, et
    /// c'est l'invitation qui dit de quel compte il s'agit.
    Devices,

    /// `/v1/sessions/challenge` — **obtenir un défi à signer.**
    ///
    /// # ELLE N'EXIGE AUCUN JETON, ET N'APPREND RIEN
    ///
    /// C'est la troisième porte d'entrée. Un défi est émis pour **n'importe
    /// quel** couple compte-appareil, connu ou non : refuser d'en émettre pour
    /// un inconnu ferait de cette route un oracle d'énumération des appareils.
    ///
    /// Ce qu'elle rend est scellé, borné à soixante secondes, et ne vaut que
    /// pour l'appareil qui tient la clef correspondante.
    SessionChallenge,

    /// `/v1/sessions` — **ouvrir une session avec la clef d'un appareil.**
    ///
    /// Le pendant de `/v1/tokens` pour l'authentification par clef : on y
    /// présente un défi signé au lieu d'un mot de passe, et l'on en ressort avec
    /// le même jeton.
    Sessions,

    /// `/v1/invitations` — frapper une invitation.
    ///
    /// **CELLE-CI EXIGE `admin`**, et c'est toute la dissymétrie : inviter est
    /// un geste d'exploitant, s'enrôler est un geste d'utilisateur.
    Invitations,

    /// `/v1/accounts` — les comptes.
    Accounts,
    /// `/v1/accounts/{compte}` — un compte.
    Account {
        /// Le nom du compte.
        compte: &'o str,
    },
    /// `/v1/accounts/{compte}/password` — son secret.
    ///
    /// **UNE RESSOURCE À PART, QUI NE SE LIT PAS.** La séparer du compte est ce
    /// qui permet à `GET /v1/accounts/{compte}` d'exister sans jamais rendre une
    /// empreinte : il n'y a pas de représentation du compte qui la contienne.
    AccountPassword {
        /// Le nom du compte.
        compte: &'o str,
    },
    /// `/v1/accounts/{compte}/addresses` — les adresses qu'il déclare.
    AccountAddresses {
        /// Le nom du compte.
        compte: &'o str,
    },
    /// `/v1/domains` — les domaines qu'on héberge.
    Domains,
    /// `/v1/bans` — les sources bannies (C8).
    Bans,
    /// `/v1/bans/{source}` — un bannissement, pour le lever.
    Ban {
        /// La source, telle qu'`ams-guard` la nomme.
        source: &'o str,
    },

    /// `/v1/submissions` — déposer un message.
    Submissions,

    /// `/v1/health` — le serveur répond-il ?
    Health,
    /// `/v1/openapi.json` — **ce que cette API fait**, et non ce qu'elle a.
    ///
    /// # DÉCOUVRIR N'EST PAS UTILISER, ET CELLE-CI N'EXIGE DONC RIEN
    ///
    /// Un document OpenAPI décrit l'API comme un PRODUIT : les mêmes chemins
    /// pour tout appelant, à toute heure, quelle que soit l'installation. Il ne
    /// nomme aucun compte, aucune boîte, aucun domaine, aucun réglage — il est à
    /// cette API ce qu'une page de manuel est à une commande.
    ///
    /// **ET CE QU'IL PUBLIE EST DÉJÀ PUBLIC.** Mesuré : sans jeton, un chemin
    /// qui existe rend `401` et un chemin inventé rend `404`. La surface des
    /// routes s'énumère donc en une boucle, par n'importe qui. Exiger un jeton
    /// ici n'aurait caché que la commodité.
    ///
    /// # CE QU'ELLE COÛTE, ET CE QUI LE BORNE
    ///
    /// Deux cent dix kibioctets rendus sans vérifier de jeton, ce serait un
    /// robinet. Deux choses le ferment : le garde (C8) compte cette requête
    /// comme toute autre — les seuils par source s'y appliquent —, et un `ETag`
    /// fait qu'une relecture coûte un `304` de quelques octets.
    ///
    /// **L'`ETag` EST LA VERSION DU SERVEUR**, et c'est exact plutôt que
    /// commode : le document porte `info.version`, donc deux versions égales
    /// décrivent le même document, et `check-compile` exige déjà que les pages
    /// de manuel et le code annoncent la même.
    OpenApi,

    /// `/v1/metrics` — les compteurs.
    Metrics,
}

impl Resource<'_> {
    /// La portée qu'il faut pour l'atteindre avec cette méthode.
    ///
    /// `None` pour ce qui ne demande aucune portée. **Cinq ressources, pas une** —
    /// cette ligne disait « l'échange de jeton, et lui seul » alors que quatre
    /// autres étaient déjà dans ce cas : les quatre portes d'entrée (`Tokens`,
    /// `Devices`, `Sessions`, `SessionChallenge`), dont le corps porte ce qui
    /// autorise, et `OpenApi`, qui n'est pas une porte mais une description. Le
    /// compte exact est tenu dans les deux sens par la propriété 5 de
    /// `fuzz_ams_api_route` ; c'est elle qui a refusé `OpenApi` tant que personne
    /// ne l'avait déclarée.
    ///
    /// # LA MÉTHODE DÉCIDE DU DROIT, LA RESSOURCE DU DOMAINE
    ///
    /// C'est ce qui évite d'écrire quatre-vingts lignes de table : le domaine ne
    /// dépend que du chemin, et le droit ne dépend que du verbe. Une ressource
    /// qui aurait besoin d'échapper à cette règle serait le signe qu'elle en
    /// mélange deux.
    #[must_use]
    pub const fn scope(self, method: Method) -> Option<Scope> {
        let domaine = match self {
            // **CELLE-CI N'EXIGE RIEN** : c'est là qu'on obtient de quoi exiger.
            // **NI L'UNE NI L'AUTRE N'EXIGE DE JETON** : ce sont les deux
            // portes d'entrée. Ce qui autorise est dans le corps — des
            // identifiants pour l'une, une invitation scellée pour l'autre.
            Self::Tokens | Self::Devices | Self::SessionChallenge | Self::Sessions => {
                return None;
            }
            // **NI CELLE-CI**, pour une autre raison : ce n'est pas une porte,
            // c'est une description. Découvrir n'est pas utiliser, et ce qu'elle
            // publie est déjà énumérable sans jeton.
            Self::OpenApi => return None,
            // Révoquer son propre jeton ne demande que de l'avoir.
            Self::CurrentToken
            | Self::OwnPassword
            | Self::OwnDevices
            | Self::OwnDevice { .. }
            | Self::OwnPush
            | Self::OwnAppPasswords
            | Self::OwnAppPassword { .. }
            | Self::OwnDelegations
            | Self::OwnAudit => {
                return Some(Scope::none());
            }
            Self::Mailboxes
            | Self::Mailbox { .. }
            | Self::Messages { .. }
            | Self::Message { .. }
            | Self::MessageRaw { .. }
            | Self::MessagePart { .. }
            | Self::Search { .. }
            | Self::Copy { .. }
            | Self::Move { .. }
            | Self::Changes { .. }
            // Ranger dans une boîte est un geste sur le courrier.
            | Self::DraftStore { .. } => Area::Mail,
            Self::Invitations
            | Self::Accounts
            | Self::Account { .. }
            | Self::AccountPassword { .. }
            | Self::AccountAddresses { .. }
            | Self::Domains
            | Self::Bans
            | Self::Ban { .. }
            | Self::Delegates { .. }
            | Self::Delegate { .. }
            | Self::AccountAudit { .. }
            | Self::AccountDevices { .. }
            | Self::AccountDevice { .. } => Area::Admin,
            // **UN BROUILLON EST UNE SOUMISSION EN COURS** : il vit sous la même
            // portée qu'elle, et un jeton qui ne peut pas soumettre ne peut pas
            // non plus préparer ce qu'il ne pourra pas envoyer.
            Self::Submissions
            | Self::Drafts
            | Self::Draft { .. }
            | Self::DraftAttachments { .. }
            | Self::DraftAttachment { .. }
            | Self::DraftSend { .. } => Area::Submit,
            Self::Health | Self::Metrics => Area::Observe,
        };
        Some(Scope::one(domaine, droit(method)))
    }

    /// Les méthodes que cette ressource sert.
    ///
    /// **C'EST CE QU'ON ÉCRIT DANS `Allow`**, et §15.5.6 de RFC 9110 en fait une
    /// obligation sur un 405 : sans lui, le client sait qu'il s'est trompé mais
    /// pas de quoi.
    #[must_use]
    pub const fn allowed(self) -> &'static [Method] {
        match self {
            Self::Tokens
            | Self::Submissions
            | Self::Devices
            | Self::Invitations
            | Self::SessionChallenge
            | Self::Sessions => &[Method::Post],
            Self::CurrentToken => &[Method::Delete],
            // La recherche est un `POST` : ses critères ne tiennent pas dans une
            // chaîne de requête sans ambiguïté, et les y mettre les ferait
            // journaliser par tout intermédiaire.
            Self::Search { .. } => &[Method::Post],
            // Ni l'une ni l'autre ne se lit : ce sont des gestes, pas des états.
            Self::Copy { .. } | Self::Move { .. } => &[Method::Post],
            Self::Drafts
            | Self::DraftAttachments { .. }
            | Self::DraftSend { .. }
            | Self::DraftStore { .. } => &[Method::Post],
            Self::Draft { .. } => &[Method::Get, Method::Head, Method::Delete],
            // **UN MORCEAU SE POSE, IL NE SE LIT PAS** : l'état de la pièce
            // jointe — ce qui est reçu — se lit dans le brouillon.
            Self::DraftAttachment { .. } => &[Method::Put, Method::Delete],
            // **ELLE NE S'ÉCRIT PAS** : le journal se déduit de la boîte, il ne
            // se pose pas.
            Self::Changes { .. } => &[Method::Get, Method::Head],
            Self::Mailboxes
            | Self::Domains
            | Self::Bans
            | Self::Health
            | Self::Metrics
            | Self::OpenApi => &[Method::Get, Method::Head],
            Self::Mailbox { .. } => &[Method::Get, Method::Head, Method::Put, Method::Delete],
            Self::Messages { .. } => &[Method::Get, Method::Head, Method::Post],
            Self::Message { .. } => &[Method::Get, Method::Head, Method::Patch, Method::Delete],
            Self::MessageRaw { .. } | Self::MessagePart { .. } => &[Method::Get, Method::Head],
            Self::Accounts => &[Method::Get, Method::Head, Method::Post],
            Self::Account { .. } => &[Method::Get, Method::Head, Method::Put, Method::Delete],
            // **CELLE-CI NE SE LIT PAS** : il n'existe aucune méthode qui rende
            // une empreinte, et c'est la raison d'être de cette ressource.
            Self::AccountPassword { .. } | Self::OwnPassword => &[Method::Put],
            Self::AccountAddresses { .. } => &[Method::Get, Method::Head, Method::Put],
            Self::Delegates { .. } | Self::OwnDelegations => &[Method::Get, Method::Head],
            // **UN JOURNAL D'AUDIT SE LIT, ET C'EST TOUT.**
            Self::OwnAudit | Self::AccountAudit { .. } => &[Method::Get, Method::Head],
            Self::AccountDevices { .. } => &[Method::Get, Method::Head, Method::Delete],
            Self::AccountDevice { .. } => &[Method::Delete],
            Self::Delegate { .. } => &[Method::Put, Method::Delete],
            Self::Ban { .. } | Self::OwnDevice { .. } | Self::OwnAppPassword { .. } => {
                &[Method::Delete]
            }
            Self::OwnPush => &[Method::Get, Method::Head, Method::Put, Method::Delete],
            // **UN MOT DE PASSE APPLICATIF NE SE LIT PAS SEUL** : son secret
            // n'est rendu qu'à sa création, et le reste figure dans la liste.
            Self::OwnAppPasswords => &[Method::Get, Method::Head, Method::Post],
            // **ELLE NE S'ÉCRIT PAS ICI** : un appareil s'enrôle par le
            // chemin d'enrôlement, qui prouve la possession de la clef. Un
            // `POST` de liste laisserait déclarer une clef sans rien prouver.
            Self::OwnDevices => &[Method::Get, Method::Head, Method::Post],
        }
    }

    /// Cette ressource sert-elle cette méthode ?
    #[must_use]
    pub fn serves(self, method: Method) -> bool {
        // `OPTIONS` s'applique à toute ressource qui existe (§9.3.7) : c'est le
        // moyen normalisé de demander ce que `allowed` rend.
        matches!(method, Method::Options) || self.allowed().contains(&method)
    }

    /// Cette ressource accepte-t-elle ces paramètres, sous ce verbe ?
    ///
    /// # ELLE VIVAIT DANS `ams-session`, ET C'ÉTAIT UNE TABLE DE TROP
    ///
    /// Une fonction libre, à côté de la boucle HTTP, qui disait d'une ressource
    /// ce que cette énumération dit déjà de toutes les autres — portée, méthodes.
    /// Elle a été déplacée ici SANS CHANGER UNE LIGNE de sa logique, pour la même
    /// raison que `scope` y vit : **ce qu'une ressource accepte se lit sur la
    /// ressource**, d'un seul endroit.
    ///
    /// Et cela rend la règle ÉNUMÉRABLE : le document OpenAPI la sonde — un
    /// paramètre à la fois — au lieu de la recopier. Une API documentée qui
    /// mentirait sur ses paramètres de requête est redevenue impossible.
    ///
    /// **TROIS RESSOURCES EN PRENNENT, EN LECTURE SEULEMENT** : la liste des
    /// messages (`before`, `limit`), le journal des changements (`since`,
    /// EXIGÉ, et `limit`) et le journal d'audit (`limit`). Ailleurs, un paramètre est refusé plutôt qu'ignoré : un
    /// client qui croit filtrer ce qui ne l'est pas ne s'en apercevrait jamais.
    pub const fn requete_permise(self, verbe: Method, requete: &Query) -> bool {
        let lecture = matches!(verbe, Method::Get | Method::Head);
        match self {
            Self::Messages { .. } => requete.is_empty() || (lecture && requete.since.is_none()),
            // **`since` EST EXIGÉ** : une synchronisation incrémentale part de
            // quelque part. Sans lui, la réponse serait « tout » — ce que la liste
            // des messages rend déjà, et mieux.
            Self::Changes { .. } => requete.since.is_some() && requete.before.is_none(),
            // Le journal d'audit ne se lit que par la fin : `limit`, et rien d'autre.
            Self::OwnAudit | Self::AccountAudit { .. } => {
                requete.before.is_none() && requete.since.is_none()
            }
            _ => requete.is_empty(),
        }
    }

    /// Écrit la valeur de l'en-tête `Allow` de cette ressource dans `place`.
    ///
    /// # §15.5.6 DE RFC 9110 EN FAIT UNE OBLIGATION SUR UN 405
    ///
    /// « The origin server MUST generate an Allow header field in a 405
    /// response ». Sans lui, un client qui reçoit 405 sait qu'il s'est trompé
    /// mais pas de quoi — et réessaiera le chemin ET le verbe, ce qui double le
    /// trafic pour rien.
    ///
    /// Le commentaire d'[`Self::allowed`] annonçait « c'est ce qu'on écrit dans
    /// `Allow` » depuis l'origine. **RIEN NE L'ÉCRIVAIT** : `champs_ordinaires`
    /// d'`ams-session` énumère ce que toute réponse porte, et `allow` n'y était
    /// pas, pour aucun statut. L'intention était juste, et tenue par personne.
    ///
    /// # `OPTIONS` Y FIGURE, ET [`Self::allowed`] NE LA LISTE PAS
    ///
    /// Les deux sont vrais en même temps, et ce n'est pas une incohérence.
    /// `allowed` dit les droits qu'on a SUR la ressource ; `OPTIONS` n'en est
    /// pas un, c'est le moyen de demander lesquels le sont (§9.3.7). Mais
    /// `Allow` énumère ce qu'on peut ENVOYER, et `OPTIONS` en fait partie
    /// puisqu'elle est servie : l'omettre dirait à un client de ne pas poser la
    /// question à laquelle on vient de répondre.
    ///
    /// # ELLE N'ALLOUE PAS, ET ELLE NE TRONQUE PAS EN SILENCE
    ///
    /// La valeur la plus longue que cette API puisse produire fait
    /// quarante-quatre octets ; [`ALLOW_OCTETS_MAX`] en réserve davantage. Si
    /// `place` ne suffisait pourtant pas, ce qui est écrit s'arrête sur une
    /// méthode entière — jamais au milieu d'un nom, qui donnerait un en-tête
    /// qu'un client lirait de travers.
    #[must_use]
    pub fn allow(self, place: &mut [u8]) -> &[u8] {
        let mut ecrit = 0_usize;
        for method in self
            .allowed()
            .iter()
            .copied()
            .chain(core::iter::once(Method::Options))
        {
            let nom = method.as_bytes();
            // **UNE SEULE VÉRIFICATION DE BORNES, ET C'EST LA GARDE.** Deux
            // `if let Some(…)` successifs en faisaient trois, dont deux que la
            // première rendait inatteignables : du code défensif que rien ne
            // pouvait éprouver, et que C2 compte comme non couvert à juste
            // titre — une branche qu'aucun essai n'atteint est une branche dont
            // personne ne sait ce qu'elle fait.
            let separe: &[u8] = match ecrit {
                0 => b"",
                _ => b", ",
            };
            let fin = ecrit.saturating_add(separe.len()).saturating_add(nom.len());
            let Some(cible) = place.get_mut(ecrit..fin) else {
                break;
            };
            let (devant, derriere) = cible.split_at_mut(separe.len().min(cible.len()));
            devant.copy_from_slice(separe);
            derriere.copy_from_slice(nom);
            ecrit = fin;
        }
        place.get(..ecrit).unwrap_or_default()
    }

    /// Son rang dans [`crate::catalogue::CATALOGUE`].
    ///
    /// # CE `match` EST LA GARDE DU CATALOGUE
    ///
    /// Il est exhaustif : **ajouter une ressource sans lui donner de rang ne
    /// compile pas**. Et l'essai qui exige que les rangs du catalogue soient
    /// exactement `0..len`, chacun une fois, échoue si la nouvelle ressource n'y
    /// est pas décrite.
    ///
    /// C'est ce qui rend impossible la panne ordinaire d'une documentation
    /// d'API : une route servie que le document ne mentionne pas. Ici, elle ne
    /// se compile pas, puis elle ne passe pas les essais.
    ///
    /// **CE RANG N'A AUCUN SENS AU-DEHORS.** Ce n'est ni un identifiant stable,
    /// ni un ordre de tri : c'est une place dans un tableau, et elle change
    /// quand le tableau change.
    #[must_use]
    pub const fn rang(self) -> usize {
        match self {
            Self::Tokens => 0,
            Self::CurrentToken => 1,
            Self::SessionChallenge => 2,
            Self::Sessions => 3,
            Self::Devices => 4,
            Self::Invitations => 5,
            Self::OwnPassword => 6,
            Self::OwnDevices => 7,
            Self::OwnDevice { .. } => 8,
            Self::OwnPush => 9,
            Self::OwnAppPasswords => 10,
            Self::OwnAppPassword { .. } => 11,
            Self::OwnDelegations => 12,
            Self::OwnAudit => 13,
            Self::Mailboxes => 14,
            Self::Mailbox { .. } => 15,
            Self::Messages { .. } => 16,
            Self::Message { .. } => 17,
            Self::MessageRaw { .. } => 18,
            Self::MessagePart { .. } => 19,
            Self::Changes { .. } => 20,
            Self::Search { .. } => 21,
            Self::Copy { .. } => 22,
            Self::Move { .. } => 23,
            Self::Drafts => 24,
            Self::Draft { .. } => 25,
            Self::DraftAttachments { .. } => 26,
            Self::DraftAttachment { .. } => 27,
            Self::DraftSend { .. } => 28,
            Self::DraftStore { .. } => 29,
            Self::Submissions => 30,
            Self::Accounts => 31,
            Self::Account { .. } => 32,
            Self::AccountPassword { .. } => 33,
            Self::AccountAddresses { .. } => 34,
            Self::Delegates { .. } => 35,
            Self::Delegate { .. } => 36,
            Self::AccountDevices { .. } => 37,
            Self::AccountDevice { .. } => 38,
            Self::AccountAudit { .. } => 39,
            Self::Domains => 40,
            Self::Bans => 41,
            Self::Ban { .. } => 42,
            Self::Health => 43,
            Self::Metrics => 44,
            Self::OpenApi => 45,
        }
    }
}

/// Le droit qu'une méthode demande.
///
/// **`HEAD` DEMANDE LE MÊME DROIT QUE `GET`** (§9.3.2) : il rend les mêmes
/// en-têtes, et le laisser passer plus facilement rendrait lisible par sa
/// longueur ce qu'on refusait de rendre.
const fn droit(method: Method) -> Rights {
    match method {
        Method::Get | Method::Head | Method::Options => Rights::Read,
        Method::Post | Method::Put | Method::Delete | Method::Patch => Rights::Write,
    }
}

/// Une requête résolue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolved<'o> {
    /// Ce qu'elle désigne.
    pub resource: Resource<'o>,
    /// Ce qu'elle en fait.
    pub method: Method,
    /// Ce qu'il faut pour y avoir droit, ou `None` si rien n'est exigé.
    ///
    /// **QUAND LA MÉTHODE N'EST PAS SERVIE, C'EST LA PORTÉE DE LECTURE.** Un
    /// `405` nomme la ressource et énumère ses méthodes dans `Allow` : c'est une
    /// confidence sur la ressource, et le droit d'y avoir part est celui de la
    /// lire. Exiger la portée de la méthode DEMANDÉE — écrire, pour un `PATCH` —
    /// rendrait `404` à un lecteur légitime qui s'est trompé de verbe, alors
    /// qu'il peut déjà lire la ressource.
    pub scope: Option<Scope>,
    /// Cette ressource sert-elle cette méthode ?
    ///
    /// **C'EST L'APPELANT QUI EN TIRE LE `405`, ET APRÈS L'AUTORISATION.** Voir
    /// [`resolve`] : le rendre ici le rendait avant, et c'était une fuite.
    pub serves: bool,
    /// **LE TITULAIRE DE LA BOÎTE VISÉE**, quand le chemin en nomme un autre :
    /// `/v1/accounts/{compte}/mailboxes/…`. `None` : la boîte de qui appelle.
    ///
    /// La ressource est la MÊME que sous `/v1/mailboxes/…` — c'est ce qui rend
    /// toutes les routes d'une boîte déléguables d'un coup. Le droit d'y
    /// toucher ne se décide PAS ici : il vient de la table des délégations,
    /// consultée par le serveur à chaque requête.
    pub owner: Option<&'o str>,
}

/// Résout une requête.
///
/// `chemin` est la partie du chemin, sans la chaîne de requête — voir
/// [`split_query`]. `sortie` reçoit les segments décodés, et les emprunts du
/// résultat y pointent.
///
/// [`split_query`]: crate::split_query
///
/// # LE VERBE NE SE JUGE PAS ICI, ET C'EST UN CORRECTIF
///
/// Cette fonction rendait `MethodNotAllowed` — donc un `405` — avant que
/// personne n'ait vérifié le moindre jeton. [`Reason::status`] déclare pourtant,
/// onze lignes plus bas dans le même `match`, que « cela n'existe pas » et
/// « vous n'avez pas le droit de savoir » se répondent PAREIL, « la différence
/// entre les deux serait l'information elle-même ».
///
/// Le `405` rendait cette différence, et à qui n'avait rien présenté :
/// `PATCH /v1/bans` répondait `405` avec un `Allow`, `PATCH /v1/inconnu`
/// répondait `404`. L'arbre entier des ressources s'énumérait ainsi, verbe par
/// verbe, sans jeton — et un jeton de courrier y lisait la surface
/// d'administration qu'il n'ouvre pas.
///
/// On rend donc [`Resolved::serves`], et **c'est l'appelant qui en tire le `405`
/// une fois l'autorisation acquise**.
///
/// # Errors
///
/// [`Reason::BadPath`] et [`Reason::PathTooLong`] pour ce que le chemin ne peut
/// pas être ; [`Reason::NoSuchResource`] pour un chemin bien formé qui ne
/// désigne rien.
pub fn resolve<'o>(
    method: Method,
    chemin: &[u8],
    sortie: &'o mut [u8],
) -> Result<Resolved<'o>, Error> {
    let segments = decode(chemin, sortie)?;
    // **LA VERSION D'ABORD** : sans elle, la première rupture de compatibilité
    // n'aurait nulle part où se dire.
    if segments.get(0) != VERSION {
        return Err(Error::new(Reason::NoSuchResource));
    }
    // **UNE BOÎTE D'AUTRUI SE DÉSIGNE PAR SON TITULAIRE, PUIS COMME LA SIENNE**
    // : `/v1/accounts/{compte}/mailboxes/…` mène aux mêmes ressources que
    // `/v1/mailboxes/…`, à partir du quatrième segment.
    let (resource, owner) = if segments.get(1) == "accounts" && segments.get(3) == "mailboxes" {
        (boites(&segments, 3)?, Some(segments.get(2)))
    } else {
        (designer(&segments)?, None)
    };
    let serves = resource.serves(method);
    Ok(Resolved {
        resource,
        method,
        // Voir [`Resolved::scope`] : ce qu'il faut pour APPRENDRE qu'un verbe
        // n'est pas servi, c'est ce qu'il faut pour lire la ressource.
        scope: resource.scope(if serves { method } else { Method::Get }),
        serves,
        owner,
    })
}

/// Ce que ces segments désignent, la version déjà vérifiée.
///
/// **AUCUNE GARDE SUR L'ABSENCE D'UN SEGMENT** : [`Segments::get`] rend la
/// chaîne vide hors des bornes, et aucun segment valide n'est vide. La longueur
/// suffit donc à discriminer, et une garde de plus serait une branche qu'aucun
/// chemin ne peut emprunter.
fn designer<'o>(segments: &Segments<'o>) -> Result<Resource<'o>, Error> {
    let manque = Error::new(Reason::NoSuchResource);
    match (segments.get(1), segments.len()) {
        ("tokens", 2) => Ok(Resource::Tokens),
        ("devices", 2) => Ok(Resource::Devices),
        ("invitations", 2) => Ok(Resource::Invitations),
        ("sessions", 2) => Ok(Resource::Sessions),
        ("sessions", 3) if segments.get(2) == "challenge" => Ok(Resource::SessionChallenge),
        ("tokens", 3) if segments.get(2) == "current" => Ok(Resource::CurrentToken),
        ("mailboxes", _) => boites(segments, 1),
        ("accounts", 2) => Ok(Resource::Accounts),
        ("accounts", 3) => Ok(Resource::Account {
            compte: segments.get(2),
        }),
        ("accounts", 4) => {
            let compte = segments.get(2);
            match segments.get(3) {
                "password" => Ok(Resource::AccountPassword { compte }),
                "addresses" => Ok(Resource::AccountAddresses { compte }),
                "delegates" => Ok(Resource::Delegates { compte }),
                "audit" => Ok(Resource::AccountAudit { compte }),
                "devices" => Ok(Resource::AccountDevices { compte }),
                _ => Err(manque),
            }
        }
        ("accounts", 5) if segments.get(3) == "delegates" => Ok(Resource::Delegate {
            compte: segments.get(2),
            delegue: segments.get(4),
        }),
        ("accounts", 5) if segments.get(3) == "devices" => Ok(Resource::AccountDevice {
            compte: segments.get(2),
            id: segments.get(4),
        }),
        ("me", 3) if segments.get(2) == "delegations" => Ok(Resource::OwnDelegations),
        ("me", 3) if segments.get(2) == "audit" => Ok(Resource::OwnAudit),
        ("me", 3) if segments.get(2) == "password" => Ok(Resource::OwnPassword),
        ("me", 3) if segments.get(2) == "devices" => Ok(Resource::OwnDevices),
        ("me", 4) if segments.get(2) == "devices" => Ok(Resource::OwnDevice {
            id: segments.get(3),
        }),
        ("me", 3) if segments.get(2) == "push" => Ok(Resource::OwnPush),
        ("me", 3) if segments.get(2) == "app-passwords" => Ok(Resource::OwnAppPasswords),
        ("me", 4) if segments.get(2) == "app-passwords" => Ok(Resource::OwnAppPassword {
            id: segments.get(3),
        }),
        ("domains", 2) => Ok(Resource::Domains),
        ("bans", 2) => Ok(Resource::Bans),
        ("bans", 3) => Ok(Resource::Ban {
            source: segments.get(2),
        }),
        ("submissions", 2) => Ok(Resource::Submissions),
        ("drafts", 2) => Ok(Resource::Drafts),
        ("drafts", 3) => Ok(Resource::Draft {
            id: segments.get(2),
        }),
        ("drafts", 4) => {
            let id = segments.get(2);
            match segments.get(3) {
                "attachments" => Ok(Resource::DraftAttachments { id }),
                "send" => Ok(Resource::DraftSend { id }),
                "store" => Ok(Resource::DraftStore { id }),
                _ => Err(manque),
            }
        }
        ("drafts", 5) if segments.get(3) == "attachments" => Ok(Resource::DraftAttachment {
            id: segments.get(2),
            piece: uid(segments.get(4))?,
        }),
        ("health", 2) => Ok(Resource::Health),
        ("metrics", 2) => Ok(Resource::Metrics),
        ("openapi.json", 2) => Ok(Resource::OpenApi),
        _ => Err(manque),
    }
}

/// Ce que désigne un chemin sous `/v1/mailboxes`.
/// Ce qu'un chemin de boîte désigne, à partir du segment `mailboxes` qui porte
/// le rang `base` : un pour sa propre boîte, trois pour celle d'autrui.
fn boites<'o>(segments: &Segments<'o>, base: usize) -> Result<Resource<'o>, Error> {
    let manque = Error::new(Reason::NoSuchResource);
    let rang = |decalage: usize| segments.get(base.saturating_add(decalage));
    let combien = segments.len().saturating_sub(base.saturating_sub(1));
    if combien == 2 {
        return Ok(Resource::Mailboxes);
    }
    let boite = rang(1);
    match (combien, rang(2)) {
        (3, _) => Ok(Resource::Mailbox { boite }),
        (4, "search") => Ok(Resource::Search { boite }),
        (4, "changes") => Ok(Resource::Changes { boite }),
        (4, "copy") => Ok(Resource::Copy { boite }),
        (4, "move") => Ok(Resource::Move { boite }),
        (4, "messages") => Ok(Resource::Messages { boite }),
        (5, "messages") => Ok(Resource::Message {
            boite,
            uid: uid(rang(3))?,
        }),
        (6, "messages") if rang(4) == "raw" => Ok(Resource::MessageRaw {
            boite,
            uid: uid(rang(3))?,
        }),
        (7, "messages") if rang(4) == "parts" => Ok(Resource::MessagePart {
            boite,
            uid: uid(rang(3))?,
            partie: rang(5),
        }),
        _ => Err(manque),
    }
}

/// L'identifiant unique que porte ce segment.
///
/// # UN SEUL FORMAT, ET PAS DE SIGNE
///
/// « 12 », et ni « +12 », ni « 012 », ni « 0x0c ». Chacune de ces écritures
/// désigne le même message, et chacune est une seconde clé pour un cache ou pour
/// un journal. Refuser coûte moins cher que de garantir que tout le monde
/// normalise pareil.
///
/// # ET ZÉRO NE PEUT PAS SORTIR D'ICI
///
/// §2.3.1.1 de RFC 9051 : un identifiant vaut au moins un. Il n'y a pourtant
/// aucune garde pour l'écarter, parce qu'aucune n'est atteignable : un zéro de
/// tête est refusé, et un segment vide l'a été au décodage. Toute valeur qui
/// sort d'ici commence donc par un chiffre non nul.
fn uid(segment: &str) -> Result<u64, Error> {
    let mauvais = Error::new(Reason::NoSuchResource);
    let octets = segment.as_bytes();
    // Un zéro de tête est une seconde écriture — et ici, la seule façon d'écrire
    // zéro.
    if octets.first() == Some(&b'0') {
        return Err(mauvais);
    }
    let mut valeur = 0_u64;
    for octet in octets {
        let chiffre = octet.checked_sub(b'0').filter(|c| *c <= 9).ok_or(mauvais)?;
        valeur = valeur
            .checked_mul(10)
            .and_then(|dix| dix.checked_add(u64::from(chiffre)))
            .ok_or(mauvais)?;
    }
    Ok(valeur)
}

#[cfg(test)]
mod tests;
