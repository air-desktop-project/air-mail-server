// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La session HTTP : **qui parle, et ce qu'il a le droit de toucher**.
//!
//! # ÉCRITE UNE FOIS, SERVIE PAR DEUX PROTOCOLES
//!
//! HTTP/2 et HTTP/3 ne partagent aucun octet de cadrage, mais ils produisent
//! tous deux un [`RequestHead`] : une méthode, une cible, des champs. Tout ce qui
//! suit — router, authentifier, autoriser, refuser — ne dépend que de cela.
//!
//! L'écrire deux fois, ce serait se donner deux occasions de l'écrire
//! différemment, et une différence entre les deux moitiés d'un même serveur est
//! exactement ce qu'un attaquant cherche : il lui suffirait alors de choisir le
//! protocole où la règle manque.
//!
//! # ELLE NE TOUCHE À RIEN, ET C'EST TOUT SON OBJET
//!
//! Cette session ne lit aucune boîte, ne vérifie aucun mot de passe, n'écrit
//! aucun message. Elle DÉCIDE, et rend à l'appelant ce qu'il reste à faire
//! ([`Next`]). C'est la même forme que les sessions SMTP, POP3 et IMAP de cette
//! crate, et pour la même raison : une machine qui n'attend jamais n'a besoin ni
//! d'horloge, ni de disque, ni de réseau (C1).
//!
//! # CE QU'ELLE REFUSE AVANT MÊME DE ROUTER
//!
//! Trois vérifications précèdent le routage, parce qu'aucune ressource ne doit
//! pouvoir les contourner :
//!
//! 1. **Le schéma doit être `https`.** Ce serveur ne sert rien en clair (C4), et
//!    une requête qui prétend l'inverse s'est trompée d'adresse — ou cherche à
//!    voir ce qu'on répond quand on croit être en clair.
//! 2. **Un corps n'est permis que là où il a un sens.** §9.3.1 de RFC 9110 :
//!    « content received in a GET request has no generally defined semantics ».
//!    Ce qui n'a pas de sens défini se lit différemment d'un logiciel à l'autre,
//!    et c'est de là que vient toute la famille de la contrebande de requête.
//! 3. **Le type d'un corps doit être celui qu'on lit.** Accepter un corps sans
//!    savoir ce qu'il prétend être, c'est laisser un intermédiaire et nous en
//!    faire deux lectures.
//!
//! # ET AUCUNE RÉPONSE NE REDIT CE QUE LE CLIENT A ÉCRIT
//!
//! Pas de chemin repris, pas d'en-tête cité, pas de détail d'analyse. C'est la
//! même règle que pour les sessions SMTP et IMAP : l'injection de réponse devient
//! inexprimable, et pas seulement refusée par l'encodeur.

use ams_api::{
    Error as ApiError, JSON_MEDIA_TYPE, Json, Key, PROBLEM_MEDIA_TYPE, Query, Reason, Resource,
    Scope, Token, authorize, bearer, parse_query, problem, resolve, split_query, verify,
    verify_invitation,
};
use ams_proto_http::{Method, RequestHead, StatusCode};

/// Cette ressource accepte-t-elle ces paramètres, sous ce verbe ?
///
/// **DEUX RESSOURCES EN PRENNENT, EN LECTURE SEULEMENT** : la liste des
/// messages (`before`, `limit`) et le journal des changements (`since`,
/// EXIGÉ, et `limit`). Ailleurs, un paramètre est refusé plutôt qu'ignoré : un
/// client qui croit filtrer ce qui ne l'est pas ne s'en apercevrait jamais.
fn requete_permise(ressource: Resource<'_>, verbe: Method, requete: &Query) -> bool {
    let lecture = matches!(verbe, Method::Get | Method::Head);
    match ressource {
        Resource::Messages { .. } => requete.is_empty() || (lecture && requete.since.is_none()),
        // **`since` EST EXIGÉ** : une synchronisation incrémentale part de
        // quelque part. Sans lui, la réponse serait « tout » — ce que la liste
        // des messages rend déjà, et mieux.
        Resource::Changes { .. } => requete.since.is_some() && requete.before.is_none(),
        _ => requete.is_empty(),
    }
}

/// Ce qu'un corps de requête peut faire de long.
///
/// Soixante-quatre kibioctets. Aucune requête de cette API n'a besoin de
/// davantage : ce sont des drapeaux, des noms, des critères. **Un dépôt de
/// message, lui, ne passe pas par un corps JSON** — il passe par
/// `/v1/submissions`, dont le corps est le message lui-même et que la boucle
/// écoule sans le retenir.
pub const BODY_OCTETS_MAX: usize = 64 * 1024;

/// Combien de champs une réponse porte au plus.
pub const FIELDS_MAX: usize = 8;

/// Combien de champs [`champs_de_toute_reponse`] peut rendre.
pub const COMMUNS_MAX: usize = 4;

/// Ce qui ouvre une valeur d'`Alt-Svc` (RFC 7838 §3).
const ALT_SVC_PREFIXE: &[u8] = b"h3=\":";

/// Ce qui sépare le port de sa durée de validité.
const ALT_SVC_MILIEU: &[u8] = b"\"; ma=";
/// Ce qu'un nom de domaine peut faire de long (§3.1 de RFC 1035).
pub const DOMAINE_MAX: usize = 255;

/// La plus longue valeur d'`Alt-Svc` que ce serveur écrive.
///
/// **LA SOMME EXACTE DES QUATRE MORCEAUX**, port le plus long compris —
/// `h3=":65535"; ma=86400` — et non un arrondi généreux. C'est ce qui permet à
/// [`Http::with_h3_port`] de n'avoir aucune garde de troncature : une borne
/// approximative aurait laissé une branche que rien n'atteint, c'est-à-dire une
/// garde qui n'en est pas une.
pub const ALT_SVC_MAX: usize = ALT_SVC_PREFIXE.len() + 5 + ALT_SVC_MILIEU.len() + ALT_SVC_MA.len();

/// Combien de temps un client peut se fier à l'alternative annoncée (RFC 7838
/// §3, `ma`), en secondes.
///
/// # POURQUOI CE N'EST PAS UN RÉGLAGE
///
/// Les durées de la file se règlent parce qu'un exploitant décide combien de
/// temps il garde du courrier. Celle-ci ne gouverne rien de tel : c'est le
/// défaut de la RFC, et un client qui garde l'alternative trop longtemps ne perd
/// qu'une connexion, qu'il rejoue aussitôt sur le port TCP.
const ALT_SVC_MA: &[u8] = b"86400";

/// Ce que TOUTE réponse de cette API porte, quelle que soit la version d'HTTP.
///
/// # UN SEUL ENDROIT LE DIT, ET CE N'EST PAS DE L'ÉLÉGANCE
///
/// Cette API se sert en HTTP/2 ET en HTTP/3, par deux composeurs qui n'ont pas
/// une ligne en commun. Chacun écrivait sa propre liste — et **celle d'HTTP/3
/// avait divergé** : elle ne portait ni `no-store`, ni `nosniff`, ni le
/// `www-authenticate` d'un refus. La même API, les mêmes données par compte, et
/// deux niveaux de protection selon le transport que le client avait choisi.
///
/// Personne ne l'aurait vu en lisant l'un des deux : chacun paraissait complet.
///
/// # CE QUE CHAQUE CHAMP EMPÊCHE
///
/// - `no-store` (§5.2.2.5 de RFC 9111) : ce qu'on rend dépend du jeton présenté,
///   et un intermédiaire qui garderait la réponse la servirait au compte
///   suivant.
/// - `nosniff` : un JSON servi à un navigateur qui devine le type peut se faire
///   lire comme du HTML, et ce qu'il porte vient d'ailleurs.
/// - `www-authenticate` sur un 401 (§3 de RFC 6750) : il dit COMMENT
///   s'authentifier, sans quoi un client honnête ne peut que deviner.
/// - `alt-svc` (RFC 7838, §3.1 de RFC 9114) : **la seule chose qui rende le port
///   HTTP/3 trouvable.** Sans elle, ce serveur ouvre un port UDP qu'aucun client
///   conforme ne cherchera jamais.
///
/// `alt_svc` vide n'écrit rien : on n'annonce pas une alternative qu'on ne sert
/// pas, comme `DSN` ne s'annonce pas sans file.
#[must_use]
pub fn champs_de_toute_reponse(
    status: StatusCode,
    alt_svc: &[u8],
) -> [Option<(&'static [u8], &[u8])>; COMMUNS_MAX] {
    // **UN TABLEAU LITTÉRAL, ET NON UN `zip` SUR DES PLACES.** L'idiome employé
    // ailleurs dans ce fichier — `places.by_ref().zip(une_option)` — CONSOMME UNE
    // PLACE quand l'option est vide : `zip` tire d'abord du premier itérateur,
    // puis découvre que le second est épuisé, et ce qu'il a tiré est perdu. Le
    // champ suivant tombe alors dans le vide. C'est arrivé ici même, et cela n'a
    // été vu que parce qu'un essai comptait les champs d'un refus.
    [
        Some((&b"cache-control"[..], &b"no-store"[..])),
        Some((&b"x-content-type-options"[..], &b"nosniff"[..])),
        (status == StatusCode::UNAUTHORIZED).then_some((&b"www-authenticate"[..], &b"Bearer"[..])),
        (!alt_svc.is_empty()).then_some((&b"alt-svc"[..], alt_svc)),
    ]
}

/// Ce que la session demande à l'appelant de faire ensuite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next<'o> {
    /// Rien de plus : la réponse est écrite, il n'y a qu'à l'émettre.
    Respond,
    /// Vérifier ces identifiants, puis appeler [`Http::on_credentials`].
    ///
    /// **LA SESSION N'AUTHENTIFIE PERSONNE.** Elle conduit l'échange, lit le
    /// corps, et demande — comme les sessions SMTP et POP3 de cette crate. Les
    /// empreintes Argon2id vivent ailleurs, et c'est ce qui permet à cette
    /// machine de n'avoir ni fichier ni horloge.
    CheckCredentials {
        /// Le compte annoncé.
        login: &'o str,
        /// Le secret présenté.
        password: &'o [u8],
    },
    /// Enrôler cet appareil, **sur la foi d'une invitation et non d'un jeton**.
    ///
    /// # POURQUOI CE N'EST PAS UN `Serve`
    ///
    /// Un `Serve` désigne une SESSION : l'appelant consulte son registre des
    /// sessions vivantes pour savoir si celle-ci a été fermée. Un enrôlement
    /// n'est pas une session — il n'y en a pas encore —, et le faire passer pour
    /// tel avec un identifiant nul ferait chercher dans le registre une entrée
    /// qui ne peut pas s'y trouver, donc refuser chaque enrôlement.
    ///
    /// **LA SESSION A DÉJÀ VÉRIFIÉ L'INVITATION** : si l'appelant reçoit ceci,
    /// le sceau était bon, la version était celle d'une invitation et non d'un
    /// jeton, et l'heure n'était pas passée. Ce qu'il lui reste à faire est ce
    /// que cette crate ne peut pas faire : lire le magasin.
    Enrol {
        /// Le compte que l'invitation désigne.
        account: &'o str,
        /// La clef publique annoncée, **telle qu'elle a été écrite**.
        ///
        /// Elle n'est pas décodée ici : la décoder demanderait un tampon de plus
        /// à une machine qui n'alloue pas, et l'appelant doit de toute façon la
        /// valider comme point de la courbe avant de la ranger.
        public_key: &'o str,
        /// Le nom que son propriétaire lui donne. Peut être vide.
        name: &'o str,
    },
    /// Vérifier cette signature d'appareil, puis appeler [`Http::on_credentials`].
    ///
    /// **LE MÊME CHEMIN DE FRAPPE QUE LE MOT DE PASSE**, et c'est voulu : une
    /// session ouverte par clef EST une session, et lui donner un second
    /// chemin donnerait deux jetons qui finiraient par différer.
    ///
    /// **LA SESSION A DÉJÀ VÉRIFIÉ LE DÉFI** : si l'appelant reçoit ceci, le
    /// sceau était bon, la version était celle d'un défi et non d'un jeton ni
    /// d'une invitation, et les soixante secondes n'étaient pas passées.
    ///
    /// Ce qu'il reste à faire est ce que cette crate ne peut pas faire : lire la
    /// clef publique dans le magasin, vérifier la signature, et refuser le
    /// REJEU — un défi émis avant la dernière session de cet appareil ne vaut
    /// plus, et c'est le magasin qui porte cette date.
    CheckDevice {
        /// Le compte que le défi désigne.
        account: &'o str,
        /// L'appareil que le défi désigne.
        device: &'o str,
        /// Quand le défi a été émis, **en millisecondes** — l'unité du magasin.
        issued_at_ms: u64,
        /// Le défi, **tel qu'il a été rendu** : c'est lui qui entre dans le
        /// condensat signé, et le redécouper ici ferait deux écritures d'une
        /// seule chose.
        challenge: &'o str,
        /// La signature annoncée, en base64url.
        signature: &'o str,
    },
    /// Servir cette ressource, pour ce compte.
    ///
    /// L'autorisation est déjà faite : si l'appelant reçoit ceci, le jeton
    /// existait, se vérifiait, n'avait pas expiré, et ouvrait la portée que la
    /// route exige.
    Serve {
        /// Ce que le chemin désigne.
        resource: Resource<'o>,
        /// Ce qu'on en fait.
        method: Method,
        /// Pour qui.
        account: &'o str,
        /// **CE QUI DISTINGUE CETTE SESSION DES AUTRES DU MÊME COMPTE.**
        ///
        /// Il sort d'ici parce qu'il ne sert qu'à l'appelant : c'est la clef du
        /// registre des sessions vivantes, que cette crate ne tient pas — elle
        /// n'a ni état partagé ni horloge (C1). Sans lui, l'appelant ne
        /// pourrait vérifier que le compte, et fermer une session reviendrait à
        /// fermer le compte.
        nonce: u64,
        /// Ce que le jeton ouvre.
        ///
        /// **L'APPELANT EN A BESOIN POUR SAVOIR SI C'EST UNE SESSION.** Cette
        /// API n'émet jamais de portée `admin` : un jeton qui la porte a été
        /// frappé hors d'ici, par quelqu'un qui lit le secret de scellement —
        /// c'est-à-dire depuis la machine. Il n'y a alors aucune session à
        /// consulter, et exiger qu'il y en ait une refuserait à l'exploitant
        /// l'outil qu'on lui a donné.
        scope: Scope,
        /// Le corps de la requête, s'il y en avait un.
        body: &'o [u8],
        /// Les paramètres de la chaîne de requête, déjà lus et déjà jugés
        /// recevables pour CETTE ressource et CE verbe.
        query: Query,
    },
}

/// Une réponse, et ce qu'il reste à faire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Turn<'o> {
    /// Le code d'état.
    status: StatusCode,
    /// Les champs à écrire.
    fields: [Option<(&'static [u8], &'o [u8])>; FIELDS_MAX],
    /// Le corps.
    body: &'o [u8],
    /// La suite.
    next: Next<'o>,
}

impl<'o> Turn<'o> {
    /// Le code d'état.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// Les champs à écrire, dans l'ordre.
    pub fn fields(&self) -> impl Iterator<Item = (&'static [u8], &'o [u8])> + '_ {
        self.fields.iter().flatten().copied()
    }

    /// Le corps.
    #[must_use]
    pub const fn body(&self) -> &'o [u8] {
        self.body
    }

    /// Ce qu'il reste à faire.
    #[must_use]
    pub const fn next(&self) -> Next<'o> {
        self.next
    }
}

/// La session HTTP.
#[derive(Debug, Clone)]
pub struct Http {
    /// La clé qui scelle les jetons.
    clef: Key,
    /// Combien de temps un jeton vaut, en microsecondes.
    duree: u64,
    /// La valeur d'`Alt-Svc`, et sa longueur. Zéro : HTTP/3 n'est pas servi.
    ///
    /// **UN SEUL PROPRIÉTAIRE.** Les deux conducteurs — HTTP/2 et HTTP/3 —
    /// tiennent déjà cette session ; la leur faire lire ici évite de porter la
    /// même chaîne à deux endroits, c'est-à-dire d'en avoir deux le jour où l'un
    /// change.
    alt_svc: [u8; ALT_SVC_MAX],
    alt_svc_len: usize,
    /// Le domaine de ce serveur, et sa longueur. Zéro : les sessions par clef
    /// ne sont pas servies.
    ///
    /// **IL ENTRE DANS CE QU'UN APPAREIL SIGNE**, et c'est ce qui empêche une
    /// signature obtenue ici de valoir ailleurs. Une session qui ne le connaît
    /// pas ne peut donc pas émettre de défi — et répondre `501` vaut mieux
    /// qu'émettre un défi lié à un domaine vide, que deux serveurs
    /// partageraient.
    domaine: [u8; DOMAINE_MAX],
    domaine_len: usize,
}

impl Http {
    /// Une session, avec la clé de scellement et la durée de vie des jetons.
    ///
    /// # UNE DURÉE IMPOSSIBLE SE REFUSE ICI, ET UNE SEULE FOIS
    ///
    /// Au-delà de ce qu'un jeton peut vivre, chaque échange d'identifiants
    /// répondrait 500 — une faute de configuration qui ne se verrait qu'en
    /// production, requête après requête. La refuser au montage la fait voir au
    /// démarrage, une fois pour toutes.
    ///
    /// # Errors
    ///
    /// [`Reason::BadKey`] pour une durée nulle ou plus longue que
    /// [`ams_api::LIFETIME_MAX_US`]. **C'est notre configuration, donc notre
    /// faute.**
    pub const fn new(clef: Key, duree: u64) -> Result<Self, Reason> {
        if duree == 0 || duree > ams_api::LIFETIME_MAX_US {
            return Err(Reason::BadKey);
        }
        Ok(Self {
            clef,
            duree,
            alt_svc: [0; ALT_SVC_MAX],
            alt_svc_len: 0,
            domaine: [0; DOMAINE_MAX],
            domaine_len: 0,
        })
    }

    /// Lui dit quel domaine ce serveur sert.
    ///
    /// **C'est la seule façon d'ouvrir les sessions par clef** : le domaine
    /// entre dans le condensat qu'un appareil signe, et sans lui une signature
    /// obtenue ici vaudrait contre un autre serveur.
    ///
    /// Un domaine plus long que [`DOMAINE_MAX`] est **ignoré** plutôt que
    /// tronqué : un domaine tronqué donnerait un condensat qu'aucun client ne
    /// saurait reproduire, et les sessions par clef échoueraient sans que rien
    /// ne dise pourquoi. §3.1 de RFC 1035 borne un nom à 255 octets, et ce
    /// serveur refuse déjà de démarrer sur un domaine qui n'en est pas un.
    #[must_use]
    pub fn avec_domaine(mut self, domaine: &[u8]) -> Self {
        if domaine.is_empty() || domaine.len() > DOMAINE_MAX {
            return self;
        }
        for (place, lu) in self.domaine.iter_mut().zip(domaine) {
            *place = *lu;
        }
        self.domaine_len = domaine.len();
        self
    }

    /// Le domaine de ce serveur, ou une tranche vide s'il n'est pas connu.
    fn domaine(&self) -> &[u8] {
        self.domaine.get(..self.domaine_len).unwrap_or_default()
    }

    /// Annonce qu'HTTP/3 s'écoute sur ce port UDP (RFC 7838, §3.1 de RFC 9114).
    ///
    /// # LE PORT VIENT DU SOCKET LIÉ, PAS DU TEXTE DE CONFIGURATION
    ///
    /// `listenH3` peut dire `:0`, et le noyau choisit alors. Annoncer ce qui est
    /// écrit dans le fichier ferait envoyer les clients sur un port que personne
    /// n'écoute — et un client qui essaie une alternative morte perd une
    /// connexion avant de se rabattre.
    ///
    /// **Sans cet appel, rien n'est annoncé**, ce qui est exactement ce qu'il
    /// faut quand HTTP/3 n'est pas servi.
    #[must_use]
    pub fn with_h3_port(mut self, port: u16) -> Self {
        let mut chiffres = [0_u8; 5];
        let combien = decimales(port, &mut chiffres);
        // **AUCUNE GARDE DE TRONCATURE**, parce qu'il n'y a rien à garder :
        // `ALT_SVC_MAX` est la somme EXACTE des quatre morceaux, port le plus
        // long compris, et une assertion de compilation le dit. Un `if` sur la
        // place restante serait une branche que rien ne peut atteindre — donc
        // pas une garde.
        let voulu = ALT_SVC_PREFIXE
            .iter()
            .chain(chiffres.get(..combien).unwrap_or_default())
            .chain(ALT_SVC_MILIEU)
            .chain(ALT_SVC_MA);
        let mut ecrits = 0_usize;
        for (place, octet) in self.alt_svc.iter_mut().zip(voulu) {
            *place = *octet;
            ecrits = ecrits.saturating_add(1);
        }
        self.alt_svc_len = ecrits;
        self
    }

    /// Ce qu'on annonce dans `Alt-Svc`, ou rien.
    #[must_use]
    pub fn alt_svc(&self) -> &[u8] {
        self.alt_svc.get(..self.alt_svc_len).unwrap_or_default()
    }

    /// Décide ce qu'il advient d'une requête.
    ///
    /// `sortie` reçoit ce que la réponse doit porter — segments de chemin,
    /// document d'erreur, jeton. Les emprunts rendus y pointent.
    ///
    /// # L'ORDRE DES REFUS N'EST PAS ARBITRAIRE
    ///
    /// Ce qui vaut pour toute ressource se vérifie avant de savoir laquelle est
    /// visée : sinon, il existerait une ressource dont le chemin, à lui seul,
    /// ferait sauter une règle générale.
    pub fn request<'o>(
        &'o self,
        tete: &RequestHead<'_>,
        corps: &'o [u8],
        maintenant: u64,
        sortie: &'o mut [u8],
    ) -> Turn<'o> {
        match self.decider(tete, corps, maintenant, sortie) {
            Ok(tour) => tour,
            Err((raison, place)) => refus(self.alt_svc(), raison, place),
        }
    }

    /// Le corps de la décision, dont chaque refus remonte en faute.
    fn decider<'o>(
        &'o self,
        tete: &RequestHead<'_>,
        corps: &'o [u8],
        maintenant: u64,
        sortie: &'o mut [u8],
    ) -> Result<Turn<'o>, (Reason, &'o mut [u8])> {
        // 1. Le schéma. **CE SERVEUR NE SERT RIEN EN CLAIR** (C4).
        if tete.scheme() != b"https" {
            return Err((Reason::BadPath, sortie));
        }
        // 2. Le corps n'est permis que là où il a un sens (§9.3.1).
        if let Err(raison) = verifier_le_corps(tete, corps) {
            return Err((raison, sortie));
        }

        // 3. Le tampon se partage EN TROIS, et les trois parts sont disjointes :
        //    le chemin décodé, le jeton déchiffré, et la réponse. C'est ce qui
        //    permet au nom de compte de vivre aussi longtemps que la réponse
        //    sans qu'aucune part n'écrase l'autre.
        let (place_du_chemin, reste) = couper(sortie, CHEMIN_OCTETS);
        let (place_du_sceau, place_de_la_reponse) = couper(reste, PLACE_DU_SCEAU);

        // 4. Le routage. La chaîne de requête ne participe pas : elle n'est pas
        //    dans le chemin (§3.4 de RFC 3986).
        let (chemin, brute) = split_query(tete.path());
        let resolu = match resolve(tete.method(), chemin, place_du_chemin) {
            Ok(resolu) => resolu,
            Err(faute) => return Err((faute.reason(), place_de_la_reponse)),
        };
        // 4 bis. **SA GRAMMAIRE SE JUGE ICI, SON SENS PLUS LOIN.** Une chaîne
        //    mal écrite l'est sur toute ressource, et le dire n'apprend rien ;
        //    qu'une ressource accepte tel paramètre, en revanche, se dit après
        //    le jeton — comme tout ce qui dépend de la ressource.
        let requete = match parse_query(brute) {
            Ok(requete) => requete,
            Err(faute) => return Err((faute.reason(), place_de_la_reponse)),
        };

        // 5. L'AUTORISATION, ET ELLE PASSE AVANT TOUT CE QUI DÉPEND DE LA
        //    RESSOURCE. Un `405` nomme la ressource et énumère ses méthodes ; un
        //    `400` sur le type d'un corps dit qu'on a reconnu le chemin. Les
        //    rendre avant le jeton donnait à n'importe qui de quoi énumérer
        //    l'arbre entier, verbe par verbe — alors que `Reason::status`
        //    répond exprès la MÊME chose à « cela n'existe pas » et à « vous
        //    n'avez pas le droit de savoir ». Tout ce qui distingue les deux
        //    attend donc ici.
        let Some(voulue) = resolu.scope else {
            // **LA SEULE RESSOURCE QUI N'EXIGE AUCUNE PORTÉE** est celle où l'on
            // en obtient une. Son verbe se juge quand même : sans cela, un
            // `GET /v1/tokens` entrerait dans l'échange de jeton.
            if !resolu.serves {
                return Err((Reason::MethodNotAllowed, place_de_la_reponse));
            }
            // **LE TYPE DU CORPS SE VÉRIFIE ICI AUSSI**, et il n'y a rien à
            // cacher en le faisant : cette ressource-ci est la porte publique,
            // celle qu'on atteint sans rien présenter. Son existence n'est pas
            // le secret que le reste de cette fonction protège.
            if let Err(raison) = verifier_le_type(tete, corps, resolu.resource) {
                return Err((raison, place_de_la_reponse));
            }
            // **AUCUNE PORTE D'ENTRÉE NE PREND DE PARAMÈTRE** : ce qui autorise
            // est dans le corps, et une chaîne ignorée ferait croire au client
            // qu'elle a servi.
            if !requete.is_empty() {
                return Err((Reason::BadQuery, place_de_la_reponse));
            }
            // **DEUX PORTES, ET ELLES NE FONT PAS LA MÊME CHOSE.** L'une
            // échange des identifiants contre un jeton ; l'autre enrôle une
            // clef sur la foi d'une invitation. Les distinguer ici plutôt que
            // dans l'appelant garde la vérification du sceau là où la clé vit.
            if matches!(resolu.resource, Resource::SessionChallenge) {
                return self.emettre_un_defi(corps, maintenant, place_de_la_reponse);
            }
            if matches!(resolu.resource, Resource::Sessions) {
                return self.repondre_a_un_defi(
                    corps,
                    maintenant,
                    place_du_sceau,
                    place_de_la_reponse,
                );
            }
            if matches!(resolu.resource, Resource::Devices) {
                return enroler_un_appareil(
                    self.alt_svc(),
                    &self.clef,
                    corps,
                    maintenant,
                    place_du_sceau,
                    place_de_la_reponse,
                );
            }
            return echanger_un_jeton(self.alt_svc(), corps, place_de_la_reponse);
        };
        let jeton = match self.authentifier(tete, maintenant, voulue, place_du_sceau) {
            Ok(jeton) => jeton,
            Err(raison) => return Err((raison, place_de_la_reponse)),
        };

        // 6. Le verbe, maintenant qu'on a le droit d'apprendre qu'il ne va pas.
        if !resolu.serves {
            return Err((Reason::MethodNotAllowed, place_de_la_reponse));
        }

        // 7. Le type du corps, maintenant qu'on sait ce qu'il alimente.
        if let Err(raison) = verifier_le_type(tete, corps, resolu.resource) {
            return Err((raison, place_de_la_reponse));
        }

        // 8. Les paramètres, maintenant qu'on sait ce qu'ils visent.
        if !requete_permise(resolu.resource, resolu.method, &requete) {
            return Err((Reason::BadQuery, place_de_la_reponse));
        }

        Ok(Turn {
            status: StatusCode::OK,
            fields: champs_ordinaires(StatusCode::OK, self.alt_svc(), &[]),
            body: &[],
            next: Next::Serve {
                resource: resolu.resource,
                method: resolu.method,
                account: jeton.login,
                nonce: jeton.nonce,
                scope: jeton.scope,
                body: corps,
                query: requete,
            },
        })
    }

    /// Émet un défi pour ce couple compte-appareil.
    ///
    /// # ON N'A RIEN À CONSULTER, ET C'EST TOUT L'INTÉRÊT
    ///
    /// Un défi est émis pour **n'importe quel** couple, connu ou non : cette
    /// session n'a pas le magasin, et c'est ce qui rend l'énumération
    /// impossible par construction — il n'y a rien ici qui puisse dire qu'un
    /// appareil existe.
    ///
    /// **SANS DOMAINE, ON N'ÉMET PAS.** Il entre dans ce que l'appareil signe ;
    /// un défi lié à un domaine vide serait un défi que deux serveurs
    /// partageraient.
    fn emettre_un_defi<'o>(
        &'o self,
        corps: &[u8],
        maintenant: u64,
        sortie: &'o mut [u8],
    ) -> Result<Turn<'o>, (Reason, &'o mut [u8])> {
        if self.domaine().is_empty() {
            return Err((Reason::NotImplemented, sortie));
        }
        let Ok(demande) = render::read_challenge_request(corps) else {
            return Err((Reason::BadJsonBody, sortie));
        };
        let mut texte = [0_u8; ams_api::CHALLENGE_ENCODED_OCTETS_MAX];
        // **LE DÉFI COMPTE EN MILLISECONDES**, et l'appelant nous donne des
        // microsecondes : la conversion a lieu ICI, une fois, et le nom du champ
        // porte son unité. Voir l'en-tête de `ams_api::challenge`.
        let defi = match ams_api::issue_challenge(
            &self.clef,
            &ams_api::Challenge {
                login: demande.login,
                device: demande.device,
                issued_at_ms: maintenant / 1_000,
            },
            &mut texte,
        ) {
            Ok(defi) => defi,
            // Un compte ou un appareil hors bornes : c'est le corps qui cloche.
            Err(_) => return Err((Reason::BadJsonBody, sortie)),
        };
        match render::write_challenge(
            defi,
            // **L'ALPHABET DE §5 DE RFC 4648 EST DE L'ASCII**, et le rôle est une
            // constante de ce dépôt : les deux sont de l'UTF-8 par construction.
            // **LE RÔLE SUIT L'USAGE DEMANDÉ**, et le serveur le rend au client
            // pour qu'il n'ait pas à le deviner — ni à le deviner
            // différemment d'une application à l'autre.
            core::str::from_utf8(match demande.appairage {
                true => ams_api::CHALLENGE_ROLE_APPAIRAGE,
                false => ams_api::CHALLENGE_ROLE,
            })
            .unwrap_or_default(),
            core::str::from_utf8(self.domaine()).unwrap_or_default(),
            ams_api::CHALLENGE_VIE_SECONDES,
            sortie,
        ) {
            Ok(ecrit) => Ok(Turn {
                status: StatusCode::CREATED,
                fields: champs_ordinaires(StatusCode::CREATED, self.alt_svc(), &[]),
                body: ecrit,
                next: Next::Respond,
            }),
            // **LE MÊME TRAITEMENT QUE POUR UN JETON QU'ON NE SAIT PAS ÉCRIRE** :
            // le tampon ne suffit pas, c'est notre faute, et l'on ne peut même
            // plus écrire dans ce tampon le document qui le dirait.
            Err(_) => Ok(Turn {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                fields: champs_ordinaires(StatusCode::INTERNAL_SERVER_ERROR, self.alt_svc(), &[]),
                body: &[],
                next: Next::Respond,
            }),
        }
    }

    /// Lit une réponse à un défi, et demande à l'appelant de vérifier la
    /// signature.
    ///
    /// # LE MÊME REFUS POUR TOUT CE QUI N'EST PAS UN DÉFI DE CE SERVEUR
    ///
    /// Un corps mal formé, un défi forgé, un jeton présenté à sa place : tout
    /// rend `401`. **L'EXPIRATION, ELLE, SE DIT** — on ne l'atteint qu'après un
    /// sceau valide, elle n'apprend donc rien à qui forge, et une horloge de
    /// client qui dérive produirait sinon des échecs incompréhensibles.
    fn repondre_a_un_defi<'o>(
        &'o self,
        corps: &'o [u8],
        maintenant: u64,
        place_du_defi: &'o mut [u8],
        sortie: &'o mut [u8],
    ) -> Result<Turn<'o>, (Reason, &'o mut [u8])> {
        if self.domaine().is_empty() {
            return Err((Reason::NotImplemented, sortie));
        }
        let Ok(demande) = render::read_session_request(corps) else {
            return Err((Reason::BadJsonBody, sortie));
        };
        let lu = match ams_api::verify_challenge(
            &self.clef,
            demande.challenge.as_bytes(),
            maintenant / 1_000,
            place_du_defi,
        ) {
            Ok(lu) => lu,
            Err(faute) => return Err((faute.reason(), sortie)),
        };
        Ok(Turn {
            status: StatusCode::OK,
            fields: champs_ordinaires(StatusCode::OK, self.alt_svc(), &[]),
            body: &[],
            next: Next::CheckDevice {
                account: lu.login,
                device: lu.device,
                issued_at_ms: lu.issued_at_ms,
                challenge: demande.challenge,
                signature: demande.signature,
            },
        })
    }

    /// Combien de temps un jeton qu'on émet vaudra, en microsecondes.
    ///
    /// **L'APPELANT EN A BESOIN POUR INSCRIRE LA SESSION** : l'expiration
    /// qu'il retient doit être CELLE DU JETON, et non une qu'il recalculerait.
    /// Deux calculs de la même durée finissent par différer, et une session qui
    /// meurt avant son jeton refuse un porteur légitime.
    #[must_use]
    pub const fn duree(&self) -> u64 {
        self.duree
    }

    /// Vérifie le jeton porteur et la portée qu'il ouvre.
    ///
    /// `place` reçoit le jeton déchiffré : le nom de compte y pointe, et vit donc
    /// aussi longtemps que la réponse. Le déchiffrer dans un tampon local
    /// obligerait à le retrouver ailleurs — et il n'est nulle part ailleurs,
    /// puisque l'écriture du jeton est encodée.
    fn authentifier<'o>(
        &self,
        tete: &RequestHead<'_>,
        maintenant: u64,
        voulue: Scope,
        place: &'o mut [u8],
    ) -> Result<Token<'o>, Reason> {
        let porte = tete
            .field(b"authorization")
            .ok_or(Reason::BadToken)
            .and_then(|valeur| bearer(valeur).map_err(ApiError::reason))?;
        let jeton = verify(&self.clef, porte, maintenant, place).map_err(ApiError::reason)?;
        authorize(&jeton, Some(voulue)).map_err(ApiError::reason)?;
        Ok(jeton)
    }

    /// Écrit le jeton d'un échange réussi, ou le refus.
    ///
    /// `accorde` est ce que la vérification des identifiants a rendu ;
    /// `identifiant` distingue ce jeton des autres du même compte.
    ///
    /// # UN REFUS D'IDENTIFIANTS NE DIT PAS CE QUI CLOCHE
    ///
    /// Ni « ce compte n'existe pas », ni « ce mot de passe est faux » : la
    /// différence entre les deux réponses rendrait le fichier de comptes
    /// énumérable sans en connaître un seul mot de passe. C'est la même règle
    /// que pour `AUTH` en SMTP, et elle vaut ici pour la même raison.
    pub fn on_credentials<'o>(
        &'o self,
        accorde: bool,
        login: &str,
        scope: Scope,
        identifiant: u64,
        maintenant: u64,
        sortie: &'o mut [u8],
    ) -> Turn<'o> {
        if !accorde {
            return refus(self.alt_svc(), Reason::BadToken, sortie);
        }
        let jeton = Token {
            login,
            scope,
            expiry: maintenant.saturating_add(self.duree),
            nonce: identifiant,
        };
        let mut place = [0_u8; ams_api::ENCODED_OCTETS_MAX];
        // **LA SEULE FAÇON D'ÉCHOUER ICI EST UN NOM DE COMPTE IMPOSSIBLE** —
        // vide, ou plus long que ce qu'un jeton porte. La durée, elle, a été
        // vérifiée au montage.
        let Ok(texte) = ams_api::issue(&self.clef, &jeton, maintenant, &mut place) else {
            return refus(self.alt_svc(), Reason::BadKey, sortie);
        };
        let mut json = Json::new(sortie);
        let ecrit = (|| {
            json.begin_object()?;
            json.field_str("token", texte)?;
            json.field_u64("expires", jeton.expiry)?;
            json.end_object()?;
            json.finish()
        })();
        match ecrit {
            Ok(corps) => Turn {
                status: StatusCode::CREATED,
                fields: champs_ordinaires(
                    StatusCode::CREATED,
                    self.alt_svc(),
                    &[(EN_TETE_TYPE, JSON_MEDIA_TYPE.as_bytes())],
                ),
                body: corps,
                next: Next::Respond,
            },
            // Le tampon ne suffit pas : c'est notre faute, et l'on ne peut même
            // plus écrire le document qui le dirait dans le même tampon.
            Err(_) => Turn {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                fields: champs_ordinaires(StatusCode::INTERNAL_SERVER_ERROR, self.alt_svc(), &[]),
                body: &[],
                next: Next::Respond,
            },
        }
    }
}

/// Ce que le chemin décodé occupe dans le tampon de sortie.
///
/// Le chemin le plus long qu'on serve fait quelques dizaines d'octets ; deux
/// kibioctets laissent la place à des noms de boîte entiers sans jamais mordre
/// sur ce que la réponse a besoin d'écrire.
const CHEMIN_OCTETS: usize = 2 * 1024;

/// Écrit `valeur` en chiffres décimaux, et rend combien.
///
/// **AUCUNE GARDE DE BORNE.** Un `u16` fait au plus cinq chiffres, et `out` en
/// tient cinq : `zip` porte cette impossibilité dans la bibliothèque standard
/// plutôt que dans un `if` que rien ne déclencherait.
fn decimales(valeur: u16, out: &mut [u8; 5]) -> usize {
    let mut envers = [0_u8; 5];
    let mut combien = 0_usize;
    let mut reste = valeur;
    // **UNE FOIS AU MOINS**, pour que zéro s'écrive `0` plutôt que rien.
    loop {
        for (place, chiffre) in envers
            .iter_mut()
            .skip(combien)
            .take(1)
            .zip([b'0'.saturating_add(u8::try_from(reste % 10).unwrap_or(0))])
        {
            *place = chiffre;
        }
        combien = combien.saturating_add(1);
        reste /= 10;
        if reste == 0 {
            break;
        }
    }
    for (place, chiffre) in out
        .iter_mut()
        .zip(envers.iter().take(combien).rev().copied())
    {
        *place = chiffre;
    }
    combien
}

/// Le nom du champ qui porte le type d'un contenu.
const EN_TETE_TYPE: &[u8] = b"content-type";

/// Ce qu'un nom d'appareil peut faire de long, une fois déséchappé.
///
/// **LA MÊME BORNE QUE `ams_config::NOM_OCTETS_MAX`**, et cette crate ne peut
/// pas la lire : elle ne dépend pas du magasin, et ne doit pas en dépendre. Un
/// essai d'`ams-server` — qui voit les deux — vérifie qu'elles coïncident, parce
/// qu'une borne recopiée finit par diverger.
pub const NOM_D_APPAREIL_MAX: usize = 128;

/// La place où l'on déchiffre ce qu'un pair présente : un jeton, ou un défi.
///
/// # ELLE EST DIMENSIONNÉE SUR LE PLUS GRAND DES DEUX, ET C'EST UN DÉFAUT RÉEL
///
/// Elle valait la taille d'un JETON. Un défi est plus gros — il porte DEUX noms,
/// le compte et l'appareil, là où un jeton n'en porte qu'un — et son déchiffrage
/// échouait donc par manque de place, rendant `500` à toute ouverture de session
/// par clef.
///
/// **L'ESSAI DE BOUT EN BOUT NE L'A PAS VU** : son compte s'appelle `marie`, et
/// le total tombait à trois octets sous la borne. En production, avec
/// `thierry.delhaise`, il la dépassait de huit. Un essai qui passe par la
/// longueur de ses données d'épreuve ne prouve rien, et c'est la production qui
/// l'a dit.
const PLACE_DU_SCEAU: usize = if ams_api::CHALLENGE_OCTETS_MAX > ams_api::TOKEN_OCTETS_MAX {
    ams_api::CHALLENGE_OCTETS_MAX
} else {
    ams_api::TOKEN_OCTETS_MAX
};

/// Ce que le tampon de travail doit faire au minimum.
///
/// Le chemin décodé, le plus grand des deux sceaux déchiffrés, et de quoi écrire
/// une réponse. En dessous, tout se refuse par manque de place — ce qui est
/// notre faute, et se dit comme telle.
pub const SCRATCH_OCTETS_MIN: usize = CHEMIN_OCTETS + PLACE_DU_SCEAU + 1024;

/// Coupe un tampon en deux, sans jamais déborder.
///
/// **UNE COUPE QUI DÉPASSE REND LA SECONDE PART VIDE**, et tout ce qui s'y
/// écrirait se refusera de soi-même. Un `split_at_mut` nu paniquerait, et une
/// garde séparée serait une branche de plus à couvrir pour dire la même chose.
fn couper(tampon: &mut [u8], combien: usize) -> (&mut [u8], &mut [u8]) {
    tampon.split_at_mut(combien.min(tampon.len()))
}

/// Vérifie qu'un corps a sa place ici, et qu'il dit ce qu'il est.
fn verifier_le_corps(tete: &RequestHead<'_>, corps: &[u8]) -> Result<(), Reason> {
    let attendu = matches!(tete.method(), Method::Post | Method::Put | Method::Patch);
    if corps.is_empty() {
        return Ok(());
    }
    // **§9.3.1 : UN CORPS SUR UN `GET` N'A PAS DE SENS DÉFINI.** Ce qui n'a pas
    // de sens défini se lit différemment d'un logiciel à l'autre, et c'est de là
    // que vient toute la famille de la contrebande de requête.
    if !attendu {
        return Err(Reason::BadPath);
    }
    if corps.len() > BODY_OCTETS_MAX {
        return Err(Reason::BadJsonBody);
    }
    Ok(())
}

/// Ce corps dit-il ce qu'il est, et le sait-on lire ICI ?
///
/// # POURQUOI CE CONTRÔLE VIENT APRÈS LE ROUTAGE, ET L'AUTRE AVANT
///
/// Ce qu'un corps a le droit d'être dépend de la RESSOURCE, et la ressource n'est
/// connue qu'une fois le chemin résolu. Ce qui ne dépend pas d'elle — un corps
/// sur un `GET`, un corps trop long — se refuse **avant** : c'est de là que vient
/// toute la famille de la contrebande de requête, et on ne la laisse pas entrer
/// le temps de savoir où elle allait.
///
/// # UN CORPS DIT CE QU'IL EST, OU ON NE LE LIT PAS
///
/// Le deviner, c'est se donner une lecture que l'intermédiaire d'à côté n'aura
/// pas. Une soumission porte un message (§5.2.1 de RFC 2046) ; tout le reste
/// porte du JSON. **Et pas l'inverse** : accepter un message là où l'on attend du
/// JSON ferait lire un message comme une représentation.
fn verifier_le_type(
    tete: &RequestHead<'_>,
    corps: &[u8],
    resource: Resource<'_>,
) -> Result<(), Reason> {
    // **PAS DE CORPS, PAS DE TYPE À VÉRIFIER.** Une ressource qui exige un corps
    // le dira elle-même, en refusant ce qu'elle n'a pas reçu ; c'est elle qui
    // sait ce qu'elle attend, et non ce contrôle-ci.
    if corps.is_empty() {
        return Ok(());
    }
    let attendu = match resource {
        Resource::Submissions => ams_api::MESSAGE_MEDIA_TYPE,
        _ => JSON_MEDIA_TYPE,
    };
    match tete.field(EN_TETE_TYPE) {
        Some(dit) if est_le_type(dit, attendu) => Ok(()),
        _ => Err(Reason::BadJsonBody),
    }
}

/// Ce type de média est-il celui qu'on lit ?
///
/// **LES PARAMÈTRES SONT ADMIS, LE TYPE NE L'EST PAS À MOITIÉ** : §8.3 de
/// RFC 9110 permet `; charset=utf-8`, et le refuser écarterait des clients
/// conformes. Ce qui précède le point-virgule, en revanche, doit être exactement
/// le type qu'on sait lire — et sans égard à la casse, que §8.3.1 impose.
fn est_le_type(dit: &[u8], attendu: &str) -> bool {
    let nu = dit
        .iter()
        .position(|octet| *octet == b';')
        .map_or(dit, |rang| dit.get(..rang).unwrap_or_default());
    let nu = rogner(nu);
    nu.eq_ignore_ascii_case(attendu.as_bytes())
}

/// Ôte les blancs de tête et de queue.
fn rogner(octets: &[u8]) -> &[u8] {
    let debut = octets
        .iter()
        .position(|octet| !octet.is_ascii_whitespace())
        .unwrap_or(octets.len());
    let reste = octets.get(debut..).unwrap_or_default();
    let fin = reste
        .iter()
        .rposition(|octet| !octet.is_ascii_whitespace())
        .map_or(0, |rang| rang.saturating_add(1));
    reste.get(..fin).unwrap_or_default()
}

/// L'enrôlement d'un appareil, sur la foi d'une invitation.
///
/// `place_de_l_invitation` reçoit l'invitation déchiffrée : le nom de compte y
/// pointe, et vit donc aussi longtemps que la réponse.
///
/// # LE MÊME REFUS POUR TOUT, ET C'EST DÉLIBÉRÉ
///
/// Un corps mal formé, une invitation forgée, un jeton porteur présenté à sa
/// place, une invitation expirée : tout rend le même refus. Les distinguer
/// dirait à qui essaie jusqu'où il est allé — et surtout, une invitation
/// EXPIRÉE distinguée apprendrait qu'elle a existé, donc que ce compte a été
/// invité.
fn enroler_un_appareil<'o>(
    alt_svc: &'o [u8],
    clef: &Key,
    corps: &'o [u8],
    maintenant: u64,
    place_de_l_invitation: &'o mut [u8],
    sortie: &'o mut [u8],
) -> Result<Turn<'o>, (Reason, &'o mut [u8])> {
    // **LE NOM A SA PLACE À PART**, et le reste sert aux refus : un nom
    // déséchappé doit vivre aussi longtemps que la réponse, et le corps de la
    // requête ne peut pas le porter — il est en lecture seule.
    let (place_du_nom, sortie) = couper(sortie, NOM_D_APPAREIL_MAX);
    let Some((invitation, public_key, name)) = lire_un_enrolement(corps) else {
        return Err((Reason::BadToken, sortie));
    };
    // **UN NOM QUI NE TIENT PAS DANS LA BORNE SE REFUSE ICI**, et non au
    // magasin : le refuser plus loin ferait écrire une invitation consommée
    // pour rien.
    let name = match name {
        None => "",
        Some(texte) => match texte.unescape(place_du_nom) {
            Ok(clair) => clair,
            Err(_) => return Err((Reason::BadJsonBody, sortie)),
        },
    };
    let lue = match verify_invitation(
        clef,
        invitation.as_bytes(),
        maintenant,
        place_de_l_invitation,
    ) {
        Ok(lue) => lue,
        Err(_) => return Err((Reason::BadToken, sortie)),
    };
    Ok(Turn {
        status: StatusCode::OK,
        fields: champs_ordinaires(StatusCode::OK, alt_svc, &[]),
        body: &[],
        next: Next::Enrol {
            account: lue.login,
            public_key,
            name,
        },
    })
}

/// Lit un corps d'enrôlement.
///
/// # AUCUN ÉCHAPPEMENT, ET CE QUE CELA COÛTE EST DIT
///
/// Les trois champs se lisent tels quels. Pour l'invitation et la clef, c'est
/// sans conséquence : leur alphabet est celui de §5 de RFC 4648, qui ne contient
/// rien qu'on échappe. Pour le NOM, cela exclut `"` et `\` et les caractères de
/// contrôle — un nom d'appareil n'en a pas besoin, et l'UTF-8 littéral passe
/// entier. Décoder les échappements demanderait un tampon que cette machine
/// n'a pas.
fn lire_un_enrolement(corps: &[u8]) -> Option<(&str, &str, Option<ams_api::Str<'_>>)> {
    use ams_api::{Event, Reader};

    let mut lecteur = Reader::new(corps);
    let mut invitation = None;
    let mut public_key = None;
    // **LE NOM EST FACULTATIF** : un appareil qu'on n'a pas nommé reste un
    // appareil, et refuser l'enrôlement pour cela serait une pédanterie.
    let mut name = None;
    let mut attendu = 0_u8;
    loop {
        match lecteur.read() {
            Err(_) => return None,
            Ok(None) => break,
            Ok(Some(Event::Key(clef))) => {
                attendu = match (clef.is("invitation"), clef.is("publicKey"), clef.is("name")) {
                    (true, _, _) => 1,
                    (_, true, _) => 2,
                    (_, _, true) => 3,
                    _ => 0,
                };
            }
            Ok(Some(Event::Text(texte))) => match attendu {
                // **L'INVITATION ET LA CLEF NE S'ÉCHAPPENT JAMAIS** : leur
                // alphabet est celui de §5 de RFC 4648, qui ne contient rien
                // qu'on échappe. Les accepter échappées n'ouvrirait aucun usage
                // et ajouterait un chemin de plus.
                1 => invitation = Some(texte.as_plain()?),
                2 => public_key = Some(texte.as_plain()?),
                // **LE NOM, LUI, SE DÉSÉCHAPPE**, et l'appelant s'en charge :
                // c'est lui qui tient le tampon. Voir `enroler_un_appareil`.
                3 => name = Some(texte),
                _ => {}
            },
            Ok(Some(_)) => {}
        }
    }
    match (invitation, public_key) {
        (Some(invitation), Some(public_key)) => Some((invitation, public_key, name)),
        _ => None,
    }
}

/// L'échange d'identifiants contre un jeton.
fn echanger_un_jeton<'o>(
    alt_svc: &'o [u8],
    corps: &'o [u8],
    sortie: &'o mut [u8],
) -> Result<Turn<'o>, (Reason, &'o mut [u8])> {
    match lire_des_identifiants(corps) {
        Some((login, password)) => Ok(Turn {
            status: StatusCode::OK,
            fields: champs_ordinaires(StatusCode::OK, alt_svc, &[]),
            body: &[],
            next: Next::CheckCredentials { login, password },
        }),
        // **LE MÊME REFUS QU'UN MAUVAIS MOT DE PASSE** : un corps mal formé et un
        // compte inconnu se répondent pareil, sans quoi la forme de la réponse
        // dirait laquelle des deux choses on a réussie.
        None => Err((Reason::BadToken, sortie)),
    }
}

/// Lit un corps d'échange d'identifiants.
fn lire_des_identifiants(corps: &[u8]) -> Option<(&str, &[u8])> {
    use ams_api::{Event, Reader};

    let mut lecteur = Reader::new(corps);
    let mut login = None;
    let mut password = None;
    let mut attendu = None;
    loop {
        match lecteur.read() {
            Err(_) => return None,
            Ok(None) => break,
            Ok(Some(Event::Key(clef))) => {
                attendu = match (clef.is("login"), clef.is("password")) {
                    (true, _) => Some(true),
                    (_, true) => Some(false),
                    _ => None,
                };
            }
            Ok(Some(Event::Text(texte))) => {
                // **AUCUN ÉCHAPPEMENT DANS UN IDENTIFIANT.** Le décoder
                // demanderait un tampon que cette machine n'a pas, et un nom de
                // compte n'en a jamais besoin : `check_login` les refuse déjà.
                let clair = texte.as_plain()?;
                match attendu {
                    Some(true) => login = Some(clair),
                    Some(false) => password = Some(clair.as_bytes()),
                    None => {}
                }
            }
            Ok(Some(_)) => {}
        }
    }
    match (login, password) {
        (Some(login), Some(password)) => Some((login, password)),
        _ => None,
    }
}

/// Les champs que porte toute réponse, plus ceux qu'on ajoute.
///
/// # CE QU'ON N'ÉCRIT PAS COMPTE AUTANT
///
/// Pas de `server` : nommer le logiciel et sa version à qui demande, c'est
/// répondre à la première question de tout balayage.
fn champs_ordinaires<'o>(
    status: StatusCode,
    alt_svc: &'o [u8],
    ajouts: &[(&'static [u8], &'o [u8])],
) -> [Option<(&'static [u8], &'o [u8])>; FIELDS_MAX] {
    let mut champs = [None; FIELDS_MAX];
    // **CE QUE TOUTE RÉPONSE PORTE VIENT D'UN SEUL ENDROIT**, que les deux
    // conducteurs lisent aussi : c'est ce qui empêche HTTP/2 et HTTP/3 de
    // diverger une seconde fois.
    //
    // **UN SEUL `zip`, ET LES DEUX SOURCES ENCHAÎNÉES** : deux `zip` successifs
    // sur `by_ref` perdent une place chaque fois que le premier s'épuise, et le
    // champ suivant tombe dans le trou.
    let voulus = champs_de_toute_reponse(status, alt_svc)
        .into_iter()
        .flatten()
        .chain(ajouts.iter().copied());
    for (place, champ) in champs.iter_mut().zip(voulus) {
        *place = Some(champ);
    }
    champs
}

/// La réponse qui va avec une faute.
fn refus<'o>(alt_svc: &'o [u8], raison: Reason, sortie: &'o mut [u8]) -> Turn<'o> {
    let status = raison.status();
    // **LE `www-authenticate` D'UN 401 N'EST PLUS ÉCRIT ICI** : il fait partie de
    // ce que toute réponse porte, et l'ajouter une seconde fois donnerait deux
    // fois le même champ à un client qui n'en attend qu'un.
    match problem(raison, sortie) {
        Ok(corps) => Turn {
            status,
            fields: champs_ordinaires(
                status,
                alt_svc,
                &[(EN_TETE_TYPE, PROBLEM_MEDIA_TYPE.as_bytes())],
            ),
            body: corps,
            next: Next::Respond,
        },
        // Le tampon ne suffit même pas pour dire la faute : on rend le code seul,
        // ce qui reste vrai.
        Err(_) => Turn {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            fields: champs_ordinaires(StatusCode::INTERNAL_SERVER_ERROR, alt_svc, &[]),
            body: &[],
            next: Next::Respond,
        },
    }
}

pub mod render;

#[cfg(test)]
mod tests;
