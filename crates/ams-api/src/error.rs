// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qui peut mal tourner, et ce que le client en lira.
//!
//! # LE CODE D'ÉTAT EST UNE RÉPONSE, ET IL EN DIT PLUS QU'ON NE CROIT
//!
//! Répondre 404 à une ressource existante qu'on n'a pas le droit de voir, ou 403
//! à une ressource qui n'existe pas : le choix n'est pas cosmétique. La
//! différence entre les deux réponses **est** l'information « cette ressource
//! existe », et un client qui n'a aucun droit peut la collecter en balayant.
//!
//! Cette API répond donc 404 dans les deux cas dès que la portée manque, et
//! réserve 403 à ce qui est visible mais interdit.

use ams_proto_http::StatusCode;

/// Ce qui a mal tourné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Un chemin qu'on refuse d'interpréter (segment vide, `.`, `..`, octet de
    /// contrôle, pourcentage mal écrit, UTF-8 invalide).
    BadPath,
    /// Un chemin qui porte plus de segments qu'on n'en retient.
    PathTooLong,
    /// Aucune ressource de cette API ne porte ce chemin.
    NoSuchResource,
    /// La ressource existe, mais pas avec cette méthode (§15.5.6 de RFC 9110).
    ///
    /// **CELLE-CI SE RÉPOND AVEC UN `Allow`**, et §15.5.6 en fait une
    /// obligation : sans lui, le client sait qu'il s'est trompé mais pas de quoi.
    MethodNotAllowed,
    /// Le jeton présenté n'ouvre pas cette portée.
    Forbidden,
    /// **Le mot de passe actuel présenté ne correspond pas.**
    ///
    /// # POURQUOI CE N'EST PAS `Forbidden`, ET POURQUOI CE N'EST PAS 404
    ///
    /// `Forbidden` dit « votre jeton n'ouvre pas cette portée », et répond 404
    /// pour que l'existence de la ressource ne se lise pas dans la réponse. Ici,
    /// rien de tel à cacher : le porteur agit sur SA PROPRE ressource, dont il
    /// connaît évidemment l'existence. Répondre 404 lui dirait que sa route a
    /// disparu, ce qui est faux et le ferait chercher au mauvais endroit.
    ///
    /// Ce n'est pas 401 non plus : le jeton, lui, est bon — c'est ce qui a
    /// permis d'arriver ici. Un 401 ferait recommencer une authentification qui
    /// a réussi. §15.5.4 de RFC 9110 nomme exactement ce cas : « the server
    /// understood the request but refuses to fulfill it ».
    BadPassword,
    /// Le jeton présenté ne se vérifie pas — sceau, structure, ou écriture.
    ///
    /// **UNE SEULE RAISON POUR TOUTES CES FAUTES** : dire laquelle apprendrait à
    /// qui forge jusqu'où il est allé.
    BadToken,
    /// Le jeton est authentique, et son heure est passée.
    ///
    /// **LE DISTINGUER N'APPREND RIEN À QUI FORGE** : on ne l'atteint qu'après
    /// un sceau valide. Et cela apprend au client honnête qu'il doit se
    /// réauthentifier plutôt que de croire son jeton refusé.
    TokenExpired,
    /// Le jeton est authentique, et **sa session a été fermée**.
    ///
    /// # POURQUOI LA DISTINGUER DE L'EXPIRATION
    ///
    /// Les deux disent au client « réauthentifie-toi », et les deux répondent
    /// 401. Mais elles ne se réparent pas pareil : une expiration est la marche
    /// normale du temps, une fermeture est une DÉCISION — un appareil révoqué,
    /// une déconnexion ailleurs. Un exploitant qui lit « session fermée » dans
    /// un journal sait que quelqu'un a agi ; « jeton expiré » le laisserait
    /// chercher une horloge qui dérive.
    ///
    /// **ET CELA N'APPREND RIEN À QUI FORGE** : on ne l'atteint qu'après un
    /// sceau valide, c'est-à-dire en tenant déjà un jeton de ce compte.
    SessionClosed,
    /// La clé de scellement n'est pas acceptable. **Notre faute** : c'est la
    /// configuration du serveur qui la fournit.
    BadKey,
    /// Le compte demandé n'est pas acceptable.
    ///
    /// **CELLE-CI SE DIT, ET C'EST L'INVERSE DE [`Self::BadMessage`]** : qui la
    /// lit tient un jeton d'administration, donc l'autorité qui peut déjà lire la
    /// liste des comptes. Lui cacher pourquoi son nom est refusé ne protégerait
    /// rien et l'enverrait chercher au hasard.
    BadAccount,
    /// Le message déposé n'est pas recevable.
    ///
    /// **UNE SEULE RAISON POUR TOUT** : un en-tête illisible, un `From:` qui
    /// n'appartient pas au compte, un destinataire qu'on ne sait pas lire, un
    /// destinataire qui n'est pas d'ici. Les distinguer ferait de la soumission
    /// un moyen d'ÉNUMÉRER les comptes locaux — « celui-ci passe, celui-là
    /// non » —, et un compte ouvert suffirait alors à dresser la liste de tous
    /// les autres.
    BadMessage,
    /// Le corps reçu n'est pas un JSON que ce serveur accepte.
    ///
    /// **UNE SEULE RAISON POUR TOUT** : profondeur, clé répétée, virgule finale,
    /// nombre à virgule, moitié de paire d'indirection. Dire laquelle
    /// apprendrait à qui sonde quelle règle il a touchée.
    BadJsonBody,
    /// L'écrivain JSON a reçu une suite impossible. **Notre faute.**
    BadJson,
    /// Une représentation plus profonde que ce qu'on écrit. **Notre faute.**
    JsonTooDeep,
    /// Le tampon de sortie ne suffit pas. **Notre faute, pas celle du client.**
    BufferTooSmall,
    /// La ressource existe dans cette API, et **ce serveur-ci ne la sert pas**.
    ///
    /// # POURQUOI CE N'EST PAS 404, POUR UNE FOIS
    ///
    /// La règle de ce module est que « cela n'existe pas » et « vous n'avez pas
    /// le droit de savoir » se répondent pareil. Elle ne s'applique pas ici :
    /// ce qui manque n'est pas une ressource d'un AUTRE, c'est une capacité que
    /// l'exploitant n'a pas configurée. Le porteur agit sur SA propre ressource,
    /// et répondre 404 lui dirait que sa route a disparu — il chercherait le
    /// défaut dans son client, alors qu'il est dans la configuration du serveur.
    ///
    /// **ET CELA N'APPREND RIEN QU'UN BALAYAGE PUISSE EXPLOITER** : la réponse
    /// ne dépend d'aucun compte, seulement de ce que ce serveur sert. Deux
    /// comptes obtiennent la même.
    NotImplemented,
    /// **Ce compte a déjà un appareil**, et l'invitation ne vaut que pour le
    /// premier.
    ///
    /// # POURQUOI ELLE SE DIT, ET NE SE CACHE PAS
    ///
    /// Qui la reçoit a présenté une invitation que NOTRE clé a scellée : il est
    /// autorisé, et lui répondre « aucune ressource ici » l'enverrait chercher
    /// un défaut dans son application. Ce qu'il doit savoir est précis — il faut
    /// révoquer l'appareil existant avant d'en enrôler un autre —, et lui seul
    /// peut le demander à son exploitant.
    ///
    /// §15.5.10 de RFC 9110 nomme exactement ce cas : « the request could not be
    /// completed due to a conflict with the current state of the target
    /// resource ».
    AlreadyEnrolled,
    /// **La limite est atteinte** : ce compte a déjà autant de mots de passe
    /// applicatifs qu'il en peut avoir.
    ///
    /// Un `409`, comme un appareil déjà enrôlé : la demande est bien formée, et
    /// c'est l'état du compte qui l'empêche. Ce que le client doit en faire est
    /// précis — révoquer celui dont il ne se sert plus.
    LimitReached,
    /// **La chaîne de requête est refusée** : un paramètre inconnu, en double,
    /// ou dont la valeur n'est pas un entier écrit d'une seule façon.
    ///
    /// Refusée plutôt qu'ignorée : un paramètre ignoré ferait croire au client
    /// qu'il a été entendu.
    BadQuery,
    /// **Le curseur de synchronisation n'est plus servi** : le journal de la
    /// boîte a oublié ce qui s'est passé avant lui, ou a été recréé.
    ///
    /// `410` (§15.5.11 de RFC 9110), et non `404` : la ressource existe, c'est
    /// le passé qu'elle ne sait plus rendre. Le client relit la boîte entière,
    /// prend le nouveau `highestModseq`, et reprend les deltas depuis lui.
    SyncExpired,
    /// **Le corps de la requête dépasse ce que cette ressource reçoit** :
    /// 64 Kio pour un document JSON, 1 Mio pour un message.
    ///
    /// `413` (§15.5.14 de RFC 9110), et non `400` : la requête est bien formée,
    /// c'est sa TAILLE qui gêne. Un message qui porte des pièces jointes ne se
    /// soumet pas d'un seul tenant — il passe par un brouillon.
    BodyTooLarge,
    /// **Le message porte plus que son corps** : une pièce jointe, une image
    /// en ligne. Il ne se soumet pas — ni ne se dépose — d'un seul tenant : il
    /// passe par un brouillon (`/v1/drafts`), corps d'abord, pièces jointes
    /// ensuite.
    ///
    /// `422` (§15.5.21 de RFC 9110) : le message est bien formé et compris, et
    /// c'est sa FORME qui demande un autre chemin.
    AttachmentsNeedDraft,
    /// **L'état du brouillon empêche ce geste** : une pièce jointe encore
    /// incomplète au moment d'envoyer, un morceau qui en chevauche un autre
    /// sans l'égaler, une pièce déjà entière, ou trop de pièces.
    ///
    /// `409`, comme un appareil déjà enrôlé : la demande est bien formée, et
    /// c'est l'état de la ressource qui l'empêche. Le client relit le brouillon
    /// (`GET /v1/drafts/{id}`) pour savoir ce qui manque.
    DraftConflict,
    /// **Le champ `Idempotency-Key` est mal formé** : ce doit être une chaîne
    /// structurée (§3.3.3 de RFC 8941) — `"…"`, de l'ASCII imprimable, au plus
    /// deux cent cinquante-cinq caractères.
    BadIdempotencyKey,
    /// **Cette clé d'idempotence a déjà servi, pour une AUTRE requête** : même
    /// clé, autre chemin ou autre corps. `422`, comme le prévoit le brouillon
    /// IETF `httpapi-idempotency-key-header` : rejouer la première réponse
    /// ferait croire au client que sa seconde demande a eu lieu.
    IdempotencyKeyReused,
    /// **La requête qui porte cette clé est encore en cours.** `409` : le client
    /// réessaie un peu plus tard, et obtiendra la réponse de la première.
    IdempotencyInFlight,
    /// **Cette partie porte un `Content-Transfer-Encoding` que ce serveur ne
    /// sait pas défaire** (§6.4.5 de RFC 9051 dit `UNKNOWN-CTE`). `422` : la
    /// demande est bien formée, c'est le message qui ne se lit pas. Rendre les
    /// octets encodés en les faisant passer pour le contenu tromperait le
    /// client sans qu'il puisse s'en apercevoir ; le message brut, lui, reste
    /// servi.
    UnknownEncoding,
    /// **Cette session n'a pas été ouverte par un appareil** : par mot de
    /// passe, elle n'a pas d'appareil à abonner. `409` : la demande est bien
    /// formée, c'est l'état de la session qui l'empêche — une session ouverte
    /// par la clef de l'appareil le pourra.
    NotADevice,
    /// **Cet appareil demande plus vite que son débit.** `429` (§4 de
    /// RFC 6585), avec `Retry-After: 1` : un seau vide retrouve toujours un
    /// jeton dans la seconde. Le débit se compte PAR APPAREIL, et non par
    /// adresse — voir `ams_guard::Rate`.
    TooManyRequests,
}

impl Reason {
    /// Le code d'état qui va avec.
    #[must_use]
    pub const fn status(self) -> StatusCode {
        match self {
            Self::BadPath
            | Self::BadQuery
            | Self::BadJsonBody
            | Self::BadMessage
            | Self::BadAccount
            | Self::BadIdempotencyKey => StatusCode::BAD_REQUEST,
            // §15.5.15 : celui-ci existe exactement pour un chemin trop long, et
            // le distinguer d'un 400 dit au client que c'est la LONGUEUR qui
            // gêne — donc qu'il peut réessayer plus court.
            Self::PathTooLong => StatusCode::URI_TOO_LONG,
            // **LA MÊME RÉPONSE POUR « CELA N'EXISTE PAS » ET « VOUS N'AVEZ PAS
            // LE DROIT DE SAVOIR »** : la différence entre les deux serait
            // l'information elle-même.
            Self::NoSuchResource | Self::Forbidden => StatusCode::NOT_FOUND,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::BadPassword => StatusCode::FORBIDDEN,
            // §11.6.1 de RFC 9110 : « the request has not been applied because
            // it lacks valid authentication credentials ». Un jeton qui ne se
            // vérifie pas et un jeton périmé sont tous deux cela.
            Self::BadToken | Self::TokenExpired | Self::SessionClosed => StatusCode::UNAUTHORIZED,
            Self::BadKey | Self::BadJson | Self::JsonTooDeep | Self::BufferTooSmall => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            // §15.6.2 de RFC 9110 : « the server does not support the
            // functionality required to fulfill the request ».
            Self::NotImplemented => StatusCode::NOT_IMPLEMENTED,
            Self::AlreadyEnrolled
            | Self::LimitReached
            | Self::DraftConflict
            | Self::IdempotencyInFlight
            | Self::NotADevice => StatusCode::CONFLICT,
            Self::SyncExpired => StatusCode::GONE,
            Self::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            Self::BodyTooLarge => StatusCode::CONTENT_TOO_LARGE,
            Self::AttachmentsNeedDraft | Self::IdempotencyKeyReused | Self::UnknownEncoding => {
                StatusCode::UNPROCESSABLE_CONTENT
            }
        }
    }

    /// Ce qu'on dit au client.
    ///
    /// # ON NE DIT JAMAIS CE QU'ON A REFUSÉ, NI POURQUOI PRÉCISÉMENT
    ///
    /// « le chemin est refusé » et non « le segment 3 contient un `..` » : la
    /// seconde formulation apprend à qui sonde exactement quelle règle il a
    /// touchée, et donc laquelle contourner. Le journal du serveur, lui, a le
    /// droit d'être précis — il ne va pas au client.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::BadPath => "le chemin est refusé",
            Self::BadJsonBody => "le corps de la requête est refusé",
            Self::BadMessage => "le message déposé est refusé",
            Self::BadAccount => "ce compte n'est pas acceptable",
            Self::PathTooLong => "le chemin est trop long",
            Self::NoSuchResource | Self::Forbidden => "aucune ressource ici",
            Self::MethodNotAllowed => "cette méthode n'est pas servie ici",
            Self::BadPassword => "le mot de passe actuel ne correspond pas",
            Self::BadToken => "l'authentification n'est pas recevable",
            Self::TokenExpired => "l'authentification a expiré",
            Self::SessionClosed => "la session a été fermée",
            Self::NotImplemented => "ce serveur ne sert pas cette ressource",
            Self::AlreadyEnrolled => "ce compte a déjà un appareil enrôlé",
            Self::LimitReached => "ce compte a atteint sa limite ; révoquez-en un d'abord",
            Self::BadQuery => "la chaîne de requête est refusée",
            Self::SyncExpired => "ce curseur n'est plus servi ; relisez la boîte entière",
            Self::BodyTooLarge => "le corps de la requête est trop long pour cette ressource",
            Self::BadIdempotencyKey => "le champ Idempotency-Key est refusé",
            Self::IdempotencyKeyReused => {
                "cette clé d'idempotence a déjà servi pour une autre requête"
            }
            Self::IdempotencyInFlight => {
                "la requête qui porte cette clé est encore en cours ; réessayez plus tard"
            }
            Self::DraftConflict => {
                "l'état du brouillon l'empêche ; relisez-le pour savoir ce qui manque"
            }
            Self::AttachmentsNeedDraft => {
                "ce message porte des pièces jointes : envoyez-le par un brouillon (/v1/drafts)"
            }
            Self::NotADevice => {
                "cette session n'a pas été ouverte par un appareil ; ouvrez-la avec sa clef"
            }
            Self::TooManyRequests => {
                "trop de requêtes pour cet appareil ; réessayez dans une seconde"
            }
            Self::UnknownEncoding => {
                "cette partie porte un encodage que le serveur ne sait pas défaire ; lisez le message brut"
            }
            // **CE QUI EST NÔTRE SE DIT D'UNE SEULE FAÇON.** Distinguer nos
            // fautes internes apprendrait au client ce que notre code a fait de
            // travers, et ne lui servirait à rien : il n'y peut rien. Le journal
            // du serveur, lui, garde la raison exacte.
            Self::BadKey | Self::BadJson | Self::JsonTooDeep | Self::BufferTooSmall => {
                "le serveur n'a pas pu produire la réponse"
            }
        }
    }
}

/// Une faute, avec ce que le client en lira.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    /// Ce qui a mal tourné.
    reason: Reason,
}

impl Error {
    /// La faute qui va avec cette raison.
    #[must_use]
    pub const fn new(reason: Reason) -> Self {
        Self { reason }
    }

    /// Ce qui a mal tourné.
    #[must_use]
    pub const fn reason(self) -> Reason {
        self.reason
    }

    /// Le code d'état qui va avec.
    #[must_use]
    pub const fn status(self) -> StatusCode {
        self.reason.status()
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} ({})",
            self.reason.message(),
            self.reason.status().value()
        )
    }
}

#[cfg(test)]
mod tests;
