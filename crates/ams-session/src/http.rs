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
    Error as ApiError, JSON_MEDIA_TYPE, Json, Key, PROBLEM_MEDIA_TYPE, Reason, Resource, Scope,
    Token, authorize, bearer, problem, resolve, split_query, verify,
};
use ams_proto_http::{Method, RequestHead, StatusCode};

/// Ce qu'un corps de requête peut faire de long.
///
/// Soixante-quatre kibioctets. Aucune requête de cette API n'a besoin de
/// davantage : ce sont des drapeaux, des noms, des critères. **Un dépôt de
/// message, lui, ne passe pas par un corps JSON** — il passe par
/// `/v1/submissions`, dont le corps est le message lui-même et que la boucle
/// écoule sans le retenir.
pub const BODY_OCTETS_MAX: usize = 64 * 1024;

/// Combien de champs une réponse porte au plus.
pub const FIELDS_MAX: usize = 6;

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
        /// Le corps de la requête, s'il y en avait un.
        body: &'o [u8],
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
        Ok(Self { clef, duree })
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
        &self,
        tete: &RequestHead<'_>,
        corps: &'o [u8],
        maintenant: u64,
        sortie: &'o mut [u8],
    ) -> Turn<'o> {
        match self.decider(tete, corps, maintenant, sortie) {
            Ok(tour) => tour,
            Err((raison, place)) => refus(raison, place),
        }
    }

    /// Le corps de la décision, dont chaque refus remonte en faute.
    fn decider<'o>(
        &self,
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
        let (place_du_jeton, place_de_la_reponse) = couper(reste, ams_api::TOKEN_OCTETS_MAX);

        // 4. Le routage. La chaîne de requête ne participe pas : elle n'est pas
        //    dans le chemin (§3.4 de RFC 3986).
        let (chemin, _requete) = split_query(tete.path());
        let resolu = match resolve(tete.method(), chemin, place_du_chemin) {
            Ok(resolu) => resolu,
            Err(faute) => return Err((faute.reason(), place_de_la_reponse)),
        };

        // 5. L'autorisation.
        let Some(voulue) = resolu.scope else {
            // **LA SEULE RESSOURCE QUI N'EXIGE AUCUNE PORTÉE** est celle où l'on
            // en obtient une.
            return echanger_un_jeton(corps, place_de_la_reponse);
        };
        let jeton = match self.authentifier(tete, maintenant, voulue, place_du_jeton) {
            Ok(jeton) => jeton,
            Err(raison) => return Err((raison, place_de_la_reponse)),
        };

        Ok(Turn {
            status: StatusCode::OK,
            fields: champs_ordinaires(&[]),
            body: &[],
            next: Next::Serve {
                resource: resolu.resource,
                method: resolu.method,
                account: jeton.login,
                body: corps,
            },
        })
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
        &self,
        accorde: bool,
        login: &str,
        scope: Scope,
        identifiant: u64,
        maintenant: u64,
        sortie: &'o mut [u8],
    ) -> Turn<'o> {
        if !accorde {
            return refus(Reason::BadToken, sortie);
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
            return refus(Reason::BadKey, sortie);
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
                fields: champs_ordinaires(&[(EN_TETE_TYPE, JSON_MEDIA_TYPE.as_bytes())]),
                body: corps,
                next: Next::Respond,
            },
            // Le tampon ne suffit pas : c'est notre faute, et l'on ne peut même
            // plus écrire le document qui le dirait dans le même tampon.
            Err(_) => Turn {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                fields: champs_ordinaires(&[]),
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

/// Le nom du champ qui porte le type d'un contenu.
const EN_TETE_TYPE: &[u8] = b"content-type";

/// Ce que le tampon de travail doit faire au minimum.
///
/// Le chemin décodé, le jeton déchiffré, et de quoi écrire une réponse. En
/// dessous, tout se refuse par manque de place — ce qui est notre faute, et se
/// dit comme telle.
pub const SCRATCH_OCTETS_MIN: usize = CHEMIN_OCTETS + ams_api::TOKEN_OCTETS_MAX + 1024;

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
    // **UN CORPS DIT CE QU'IL EST, OU ON NE LE LIT PAS.** Le deviner, c'est se
    // donner une lecture que l'intermédiaire d'à côté n'aura pas.
    match tete.field(EN_TETE_TYPE) {
        Some(dit) if est_du_json(dit) => Ok(()),
        _ => Err(Reason::BadJsonBody),
    }
}

/// Ce type de média est-il celui qu'on lit ?
///
/// **LES PARAMÈTRES SONT ADMIS, LE TYPE NE L'EST PAS À MOITIÉ** : §8.3 de
/// RFC 9110 permet `; charset=utf-8`, et le refuser écarterait des clients
/// conformes. Ce qui précède le point-virgule, en revanche, doit être exactement
/// le type qu'on sait lire — et sans égard à la casse, que §8.3.1 impose.
fn est_du_json(dit: &[u8]) -> bool {
    let nu = dit
        .iter()
        .position(|octet| *octet == b';')
        .map_or(dit, |rang| dit.get(..rang).unwrap_or_default());
    let nu = rogner(nu);
    nu.eq_ignore_ascii_case(JSON_MEDIA_TYPE.as_bytes())
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

/// L'échange d'identifiants contre un jeton.
fn echanger_un_jeton<'o>(
    corps: &'o [u8],
    sortie: &'o mut [u8],
) -> Result<Turn<'o>, (Reason, &'o mut [u8])> {
    match lire_des_identifiants(corps) {
        Some((login, password)) => Ok(Turn {
            status: StatusCode::OK,
            fields: champs_ordinaires(&[]),
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
    ajouts: &[(&'static [u8], &'o [u8])],
) -> [Option<(&'static [u8], &'o [u8])>; FIELDS_MAX] {
    let mut champs = [None; FIELDS_MAX];
    let mut places = champs.iter_mut();
    // **`no-store`, ET SUR TOUTE RÉPONSE** : ce qu'on rend dépend du jeton
    // présenté, et un intermédiaire qui garderait une réponse la servirait au
    // compte suivant. §5.2.2.5 de RFC 9111 : « the response MUST NOT be stored ».
    for (place, champ) in places
        .by_ref()
        .zip([(&b"cache-control"[..], &b"no-store"[..])])
    {
        *place = Some(champ);
    }
    // **`nosniff`** : un JSON servi à un navigateur qui devine le type peut se
    // faire lire comme du HTML, et ce qu'il porte vient d'ailleurs.
    for (place, champ) in places
        .by_ref()
        .zip([(&b"x-content-type-options"[..], &b"nosniff"[..])])
    {
        *place = Some(champ);
    }
    for (place, champ) in places.zip(ajouts.iter().copied()) {
        *place = Some(champ);
    }
    champs
}

/// La réponse qui va avec une faute.
fn refus(raison: Reason, sortie: &mut [u8]) -> Turn<'_> {
    let status = raison.status();
    // §15.5.6 de RFC 9110 : un 405 DOIT porter un `Allow`. Sans lui, le client
    // sait qu'il s'est trompé, mais pas de quoi.
    //
    // §3 de RFC 6750 : un 401 porte un `WWW-Authenticate`, qui dit COMMENT
    // s'authentifier — sans quoi un client honnête ne peut que deviner.
    let ajouts: &[(&'static [u8], &[u8])] = match status.value() {
        401 => &[(b"www-authenticate", b"Bearer")],
        _ => &[],
    };
    match problem(raison, sortie) {
        Ok(corps) => {
            let mut tous = [None; FIELDS_MAX];
            let mut places = tous.iter_mut();
            for (place, champ) in places
                .by_ref()
                .zip(champs_ordinaires(ajouts).iter().flatten())
            {
                *place = Some(*champ);
            }
            for (place, champ) in places.zip([(EN_TETE_TYPE, PROBLEM_MEDIA_TYPE.as_bytes())]) {
                *place = Some(champ);
            }
            Turn {
                status,
                fields: tous,
                body: corps,
                next: Next::Respond,
            }
        }
        // Le tampon ne suffit même pas pour dire la faute : on rend le code seul,
        // ce qui reste vrai.
        Err(_) => Turn {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            fields: champs_ordinaires(&[]),
            body: &[],
            next: Next::Respond,
        },
    }
}

pub mod render;

#[cfg(test)]
mod tests;
