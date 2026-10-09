// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Le document OpenAPI 3.1, **engendré depuis la table de routage**.
//!
//! # POURQUOI ENGENDRÉ, ET NON ÉCRIT
//!
//! Un document d'API écrit à la main est faux le jour où une route bouge, et
//! personne ne s'en aperçoit : rien ne le relit. C'est la panne ordinaire de
//! toutes les API documentées, et elle est pire que l'absence de document — un
//! client code contre ce qui est écrit, pas contre ce qui est servi.
//!
//! Ici, chaque chemin, chaque méthode et chaque portée sont LUS sur les mêmes
//! fonctions que le serveur interroge pour router et pour autoriser :
//! `ams_api::CATALOGUE` pour les chemins, `Resource::allowed` pour les méthodes,
//! `Resource::scope` pour le droit. **Il n'y a rien à tenir à jour**, et
//! `scripts/check-openapi.sh` vérifie que le document commité est bien celui que
//! ce code engendre.
//!
//! # POURQUOI ICI, ET NON DANS `ams-api`
//!
//! C'est là qu'il a commencé, et l'écrivain `Json` de cette crate l'a refusé —
//! pour une bonne raison. Il porte `DEPTH_MAX = 8` et `FIELDS_MAX = 16`, et son
//! commentaire dit pourquoi : « c'est celle du lecteur, et ce n'est pas une
//! coïncidence ». Ces bornes protègent les réponses de l'API contre un document
//! qui l'épuiserait ; or `paths` compte quarante-cinq clés et ce document
//! descend à neuf niveaux.
//!
//! **LES RELEVER AURAIT ÉCHANGÉ UNE BORNE DE SÉCURITÉ CONTRE UNE COMMODITÉ DE
//! DOCUMENTATION.** Le document s'écrit donc ici, où allouer est permis, et la
//! table qu'il décrit reste là-bas, où elle sert à router.
//!
//! # CE QU'IL DIT, ET CE QU'IL NE DIT PAS
//!
//! Il dit, et il ne peut pas se tromper : les chemins, leurs paramètres, les
//! méthodes servies, le schéma d'authentification, la portée exigée par
//! opération, et le document d'erreur de RFC 9457 avec les motifs que `Reason`
//! énumère.
//!
//! **IL NE DIT PAS LES SCHÉMAS DE CORPS, NI LES CODES DE SUCCÈS EXACTS.** Ceux-là
//! vivent dans les gestionnaires — sept mille lignes d'`ams-server::api` — et non
//! dans cette table ; les deviner ici produirait très exactement le mensonge que
//! ce module existe pour éviter. Les succès sont déclarés par plage (`2XX`), et
//! le document le dit de lui-même.

use ams_api::{CATALOGUE, Entree, Query, Reason};
use ams_proto_http::Method;

/// La version d'OpenAPI que ce document suit.
const OPENAPI: &str = "3.1.0";

/// Les sept méthodes, pour les parcourir.
const VERBES: [Method; 7] = [
    Method::Get,
    Method::Head,
    Method::Post,
    Method::Put,
    Method::Delete,
    Method::Patch,
    Method::Options,
];

/// Les codes de refus que le document référence sur chaque opération.
const REFUS: [&str; 10] = [
    "400", "401", "403", "404", "405", "409", "410", "413", "429", "500",
];

/// Le document, en entier.
///
/// **IL EST INDENTÉ, ET C'EST POUR LE `diff`** : il est commité, et une barrière
/// le compare. Un document sur une seule ligne rendrait illisible le changement
/// qu'une route de plus y produit.
#[must_use]
pub fn document() -> String {
    let mut out = Objet::racine();
    out.texte("openapi", OPENAPI);
    out.brut("info", &info());
    out.brut("servers", &serveurs());
    out.brut("security", "[\n    {\n      \"bearerAuth\": []\n    }\n  ]");
    out.brut("paths", &chemins());
    out.brut("components", &composants());
    let mut document = out.fermer();
    document.push('\n');
    document
}

/// Le bloc `info`.
fn info() -> String {
    let mut out = Objet::new(2);
    out.texte("title", "air-mail-server — API REST");
    out.texte("version", env!("CARGO_PKG_VERSION"));
    out.texte(
        "summary",
        "Lire et envoyer du courrier, et administrer ce serveur.",
    );
    out.texte("description", DESCRIPTION);
    out.brut(
        "license",
        "{\n      \"name\": \"MPL-2.0\",\n      \"identifier\": \"MPL-2.0\"\n    }",
    );
    out.fermer()
}

/// Ce que ce document est, et ce qu'il n'est pas.
const DESCRIPTION: &str = concat!(
    "Ce document est ENGENDRÉ depuis la table de routage du serveur ",
    "(`ams-api::catalogue`) : les chemins, les méthodes servies et la portée exigée ",
    "par opération ne peuvent donc pas s'écarter de ce qui est servi, et une barrière ",
    "de CI le vérifie à chaque changement.\n\n",
    "CE QU'IL NE DÉCRIT PAS : les schémas de corps de requête et de réponse, et les ",
    "codes de succès exacts. Ceux-là vivent dans les gestionnaires et non dans la ",
    "table ; les déclarer ici sans les y lire serait les inventer. Les succès sont ",
    "donc donnés par plage (2XX).\n\n",
    "Les refus, eux, sont exacts : `application/problem+json` (RFC 9457), et les types ",
    "énumérés sont ceux de l'énumération `Reason`.\n\n",
    "La version est dans le chemin, et elle est obligatoire : `/v1/…`."
);

/// Le bloc `servers`.
///
/// **UNE URL RELATIVE, ET C'EST VOULU** : ce serveur ne connaît pas le nom par
/// lequel on l'atteint. L'écrire en dur donnerait un document juste sur une
/// installation et faux sur toutes les autres.
fn serveurs() -> String {
    let mut out = Objet::new(3);
    out.texte("url", "/");
    out.texte(
        "description",
        "La racine de l'API, sur l'écoute que `--listen-http` déclare.",
    );
    format!("[\n    {}\n  ]", out.fermer())
}

/// Le bloc `paths` : une entrée par ressource du catalogue.
fn chemins() -> String {
    let mut out = Objet::new(2);
    for entree in CATALOGUE {
        out.brut(entree.gabarit, &chemin(entree));
    }
    out.fermer()
}

/// Ce qu'un chemin porte : son résumé, ses paramètres, ses opérations.
fn chemin(entree: &Entree) -> String {
    let mut out = Objet::new(3);
    out.texte("description", entree.resume);
    if let Some(parametres) = parametres_de_chemin(entree.gabarit) {
        out.brut("parameters", &parametres);
    }
    for method in VERBES {
        // `OPTIONS` s'applique à toute ressource qui existe (§9.3.7), et
        // `allowed` ne la liste jamais : ce n'est pas un droit sur la ressource,
        // c'est le moyen de demander lesquels le sont.
        if entree.exemplaire.allowed().contains(&method) || matches!(method, Method::Options) {
            out.brut(verbe(method), &operation(entree, method));
        }
    }
    out.fermer()
}

/// Les paramètres de chemin, LUS SUR LE GABARIT.
///
/// Rien n'est déclaré à côté : ce qui est entre accolades est un paramètre, et un
/// gabarit qui en gagnerait un le déclarerait du même coup.
fn parametres_de_chemin(gabarit: &str) -> Option<String> {
    let noms: Vec<&str> = gabarit
        .split('{')
        .skip(1)
        .filter_map(|apres| apres.split('}').next())
        .collect();
    if noms.is_empty() {
        return None;
    }
    let mut pieces = Vec::new();
    for nom in noms {
        let mut out = Objet::new(5);
        out.texte("name", nom);
        out.texte("in", "path");
        out.brut("required", "true");
        out.texte("description", decrire_le_parametre(nom));
        out.brut("schema", &schema_de_parametre(nom));
        pieces.push(format!("      {}", out.fermer()));
    }
    Some(format!("[\n{}\n    ]", pieces.join(",\n")))
}

/// Le schéma d'un paramètre de chemin.
///
/// **C'EST LE ROUTAGE QUI DÉCIDE DU TYPE, PAS CE MODULE** : `uid` et `n` sont les
/// deux segments que `resolve` passe par sa lecture d'entier, qui refuse un zéro
/// de tête et toute autre écriture.
fn schema_de_parametre(nom: &str) -> String {
    let mut out = Objet::new(6);
    match nom {
        "uid" | "n" => {
            out.texte("type", "integer");
            out.brut("minimum", "1");
        }
        _ => {
            out.texte("type", "string");
            out.brut("minLength", "1");
            out.brut("maxLength", &ams_api::SEGMENT_OCTETS_MAX.to_string());
        }
    }
    out.fermer()
}

/// Ce que ce paramètre désigne.
const fn decrire_le_parametre(nom: &str) -> &'static str {
    match nom.as_bytes() {
        b"boite" => "Le nom de la boîte, tel qu'IMAP le nomme.",
        b"uid" => {
            "L'identifiant unique du message dans cette boîte (§2.3.1.1 de RFC 9051) : au moins 1, sans zéro de tête."
        }
        b"partie" => "Le chemin de la partie MIME, numéroté comme §6.4.5 de RFC 9051.",
        b"id" => "L'identifiant de l'objet désigné.",
        b"n" => "Le rang de la pièce jointe dans le brouillon.",
        b"compte" => "L'identifiant du compte.",
        b"delegue" => "Le compte à qui l'accès est accordé.",
        b"source" => "La source bannie, telle que `/v1/bans` la rend.",
        _ => "",
    }
}

/// Les paramètres de requête que cette ressource accepte, **SONDÉS**.
///
/// # ON NE RECOPIE PAS LA RÈGLE, ON LA QUESTIONNE
///
/// `Resource::requete_permise` est la seule autorité sur ce qu'un chemin accepte
/// — c'est elle que le serveur interroge pour refuser un paramètre de trop. La
/// redire ici en ferait une seconde table, qui divergerait au premier
/// changement.
///
/// # ET ON LA QUESTIONNE EN DEUX TEMPS
///
/// Un paramètre essayé SEUL ne suffit pas : sur le journal des changements,
/// `since` est exigé, donc `limit` essayé seul est refusé — alors qu'il est bel
/// et bien accepté, à côté de `since`. Une sonde naïve l'aurait tu.
///
/// On cherche donc d'abord ce qui est EXIGÉ — ce sans quoi une requête vide est
/// refusée —, puis on essaie chaque autre paramètre EN PLUS de cette base.
fn parametres_acceptes(entree: &Entree) -> Vec<(&'static str, bool)> {
    let ressource = entree.exemplaire;
    let noms = ["since", "before", "limit"];

    // Le premier temps : ce qui est exigé.
    let vide_passe = ressource.requete_permise(Method::Get, &Query::default());
    let mut base = Query::default();
    let mut exiges: Vec<&'static str> = Vec::new();
    if !vide_passe {
        for nom in noms {
            let essai = poser(&Query::default(), nom);
            if ressource.requete_permise(Method::Get, &essai) {
                base = essai;
                exiges.push(nom);
            }
        }
    }

    // Le second temps : ce qui s'ajoute à cette base.
    let mut out: Vec<(&'static str, bool)> = exiges.iter().map(|nom| (*nom, true)).collect();
    for nom in noms {
        if exiges.contains(&nom) {
            continue;
        }
        let essai = poser(&base, nom);
        if ressource.requete_permise(Method::Get, &essai) {
            out.push((nom, false));
        }
    }
    out
}

/// La même requête, ce paramètre en plus.
fn poser(requete: &Query, nom: &str) -> Query {
    let mut out = *requete;
    match nom {
        "since" => out.since = Some(1),
        "before" => out.before = Some(1),
        "limit" => out.limit = Some(1),
        _ => {}
    }
    out
}

/// Les paramètres de requête d'une opération de lecture.
///
/// **SEULEMENT EN LECTURE** : `requete_permise` ne les admet que sous `GET` et
/// `HEAD`, et les déclarer au niveau du chemin laisserait croire qu'un `POST`
/// les prend aussi.
fn parametres_de_lecture(entree: &Entree, method: Method) -> Option<String> {
    if !matches!(method, Method::Get | Method::Head) {
        return None;
    }
    let acceptes = parametres_acceptes(entree);
    if acceptes.is_empty() {
        return None;
    }
    let pieces: Vec<String> = acceptes
        .iter()
        .map(|(nom, exige)| match exige {
            // **UN PARAMÈTRE EXIGÉ S'ÉCRIT EN ENTIER** : un `$ref` remplace tout
            // l'objet dans OpenAPI 3.1, et le composant partagé le déclare
            // facultatif. Le référencer ici tairait qu'il ne l'est pas.
            true => format!("        {}", parametre_exige(nom)),
            false => format!(
                "        {{\n          \"$ref\": \"#/components/parameters/{nom}\"\n        }}"
            ),
        })
        .collect();
    Some(format!("[\n{}\n      ]", pieces.join(",\n")))
}

/// Un paramètre de requête exigé, écrit en entier.
fn parametre_exige(nom: &str) -> String {
    let mut schema = Objet::new(6);
    schema.texte("type", "integer");
    schema.brut("minimum", "1");
    let mut out = Objet::new(5);
    out.texte("name", nom);
    out.texte("in", "query");
    out.brut("required", "true");
    out.texte(
        "description",
        &format!("EXIGÉ ici. {}", decrire_la_requete(nom)),
    );
    out.brut("schema", &schema.fermer());
    out.fermer()
}

/// Une opération : une méthode sur une ressource.
fn operation(entree: &Entree, method: Method) -> String {
    let mut out = Objet::new(4);
    out.texte("summary", entree.resume);
    out.texte("operationId", &identifiant(entree.gabarit, method));
    out.brut(
        "tags",
        &format!("[\n        \"{}\"\n      ]", etiquette(entree)),
    );
    out.texte("description", &exigence(entree, method));
    if let Some(parametres) = parametres_de_lecture(entree, method) {
        out.brut("parameters", &parametres);
    }
    // Une liste vide remplace la `security` du document (§4.8.5 d'OpenAPI) :
    // sans elle, un explorateur exigerait un jeton pour aller en chercher un.
    if entree.exemplaire.scope(method).is_none() {
        out.brut("security", "[]");
    }
    out.brut("responses", &reponses(method));
    out.fermer()
}

/// `operationId`, déduit du gabarit et du verbe.
///
/// **IL NE FIGURE DANS AUCUNE TABLE** : le déduire interdit qu'il diverge du
/// chemin qu'il nomme, et les générateurs de clients en ont besoin pour nommer
/// leurs fonctions.
fn identifiant(gabarit: &str, method: Method) -> String {
    let mut out = String::from(verbe(method));
    // **FAUX AU DÉPART, ET C'EST LE POINT** : le gabarit commence par `/`, et le
    // tenir pour « déjà séparé » collait le verbe à la version — `getv1_…` au
    // lieu de `get_v1_…`. Un essai l'a dit.
    let mut separe = false;
    for caractere in gabarit.chars() {
        match caractere {
            '/' | '{' | '}' | '-' | '.' => {
                if !separe {
                    out.push('_');
                    separe = true;
                }
            }
            autre => {
                out.push(autre);
                separe = false;
            }
        }
    }
    String::from(out.trim_end_matches('_'))
}

/// L'étiquette qui groupe cette ressource, tirée de son domaine de portée.
///
/// **ELLE SUIT LA PORTÉE, ET NON UNE CLASSIFICATION DE PLUS** : deux ressources
/// groupées ensemble sont deux ressources qu'un même jeton ouvre, et c'est le
/// groupement qu'un client cherche.
fn etiquette(entree: &Entree) -> &'static str {
    let Some(scope) = entree.exemplaire.scope(Method::Get) else {
        return "portes d'entrée";
    };
    for area in ams_api::Area::TOUS {
        if scope.allows(area, ams_api::Rights::Read) {
            return area.name();
        }
    }
    "soi-même"
}

/// Ce que cette opération exige, en une phrase.
fn exigence(entree: &Entree, method: Method) -> String {
    let Some(scope) = entree.exemplaire.scope(method) else {
        return String::from(
            "N'EXIGE AUCUN JETON : c'est une porte d'entrée. Ce qui autorise est dans le corps.",
        );
    };
    for area in ams_api::Area::TOUS {
        for (rights, suffixe) in [
            (ams_api::Rights::Write, ":write"),
            (ams_api::Rights::Read, ":read"),
        ] {
            if scope.allows(area, rights) {
                return format!(
                    "Exige un jeton dont la portée ouvre `{}{suffixe}`.",
                    area.name()
                );
            }
        }
    }
    String::from("Exige un jeton valide, sans portée particulière.")
}

/// Les réponses : le succès par plage, les refus par référence.
fn reponses(method: Method) -> String {
    let mut out = Objet::new(5);
    match method {
        Method::Options => {
            let mut succes = Objet::new(6);
            succes.texte(
                "description",
                "Les méthodes servies, dans l'en-tête `Allow` (§9.3.7 de RFC 9110).",
            );
            succes.brut("headers", &entetes_allow(7));
            out.brut("204", &succes.fermer());
        }
        _ => {
            let mut succes = Objet::new(6);
            succes.texte(
                "description",
                "Succès. Le code exact et le schéma du corps ne sont pas encore décrits — voir la description du document.",
            );
            out.brut("2XX", &succes.fermer());
        }
    }
    for code in REFUS {
        out.brut(
            code,
            "{\n          \"$ref\": \"#/components/responses/Probleme\"\n        }",
        );
    }
    out.brut(
        "default",
        "{\n          \"$ref\": \"#/components/responses/Probleme\"\n        }",
    );
    out.fermer()
}

/// L'en-tête `Allow`, que `OPTIONS` et `405` portent tous deux.
fn entetes_allow(niveau: usize) -> String {
    let mut schema = Objet::new(niveau.saturating_add(2));
    schema.texte("type", "string");
    let mut allow = Objet::new(niveau.saturating_add(1));
    allow.texte("description", "Les méthodes que cette ressource sert.");
    allow.brut("schema", &schema.fermer());
    let mut out = Objet::new(niveau);
    out.brut("Allow", &allow.fermer());
    out.fermer()
}

/// Le verbe, tel qu'OpenAPI le nomme : en minuscules.
const fn verbe(method: Method) -> &'static str {
    match method {
        Method::Get => "get",
        Method::Head => "head",
        Method::Post => "post",
        Method::Put => "put",
        Method::Delete => "delete",
        Method::Patch => "patch",
        Method::Options => "options",
    }
}

/// Le bloc `components`.
fn composants() -> String {
    let mut out = Objet::new(2);
    out.brut("securitySchemes", &schemas_de_securite());
    out.brut("parameters", &parametres_de_requete());
    out.brut("schemas", &schemas());
    out.brut("responses", &reponses_communes());
    out.fermer()
}

/// Le schéma d'authentification : un jeton porteur, et rien d'autre.
fn schemas_de_securite() -> String {
    let mut bearer = Objet::new(4);
    bearer.texte("type", "http");
    bearer.texte("scheme", "bearer");
    bearer.texte(
        "description",
        concat!(
            "Le jeton que `POST /v1/tokens` ou `POST /v1/sessions` rend, dans ",
            "`Authorization: Bearer …`. Un refus porte `WWW-Authenticate: Bearer`. ",
            "Le jeton est scellé par le serveur et porte sa propre portée : ce que la ",
            "description d'une opération nomme est ce que le jeton doit ouvrir."
        ),
    );
    let mut out = Objet::new(3);
    out.brut("bearerAuth", &bearer.fermer());
    out.fermer()
}

/// Ce paramètre est-il référencé par au moins une opération ?
///
/// Déduit du catalogue, comme le reste : un paramètre accepté SANS être exigé est
/// référencé ; exigé, il est écrit en entier là où il l'est.
fn reference_quelque_part(nom: &str) -> bool {
    CATALOGUE.iter().any(|entree| {
        parametres_acceptes(entree)
            .iter()
            .any(|(candidat, exige)| *candidat == nom && !exige)
    })
}

/// Ce que ce paramètre de requête demande.
///
/// **D'UN SEUL ENDROIT** : le composant partagé et le paramètre exigé écrit en
/// entier y puisent tous deux, et une phrase corrigée se corrige une fois.
const fn decrire_la_requete(nom: &str) -> &'static str {
    match nom.as_bytes() {
        b"since" => {
            "Les changements postérieurs à ce point du journal. Un curseur que le journal ne sert plus rend 410."
        }
        b"before" => {
            "Les messages d'UID strictement inférieur : le curseur pour remonter dans le temps."
        }
        b"limit" => "Combien au plus. Zéro est refusé : ne rien demander n'est pas une requête.",
        _ => "",
    }
}

/// Les trois paramètres de requête, et il n'y en a pas d'autres.
///
/// `ams_api::parse_query` refuse tout nom qu'elle ne connaît pas : cette liste
/// est donc exhaustive par construction, et non par relecture.
fn parametres_de_requete() -> String {
    let mut out = Objet::new(3);
    for (nom, format_) in [("since", "int64"), ("before", "int32"), ("limit", "int32")] {
        // **ON NE DÉCLARE QUE CE QUI EST RÉFÉRENCÉ** : un paramètre exigé
        // s'écrit en entier dans son opération, et son composant ne servirait
        // donc à personne. OpenAPI tolère un composant orphelin ; les valideurs
        // le signalent, et ils ont raison — c'est du document mort.
        if !reference_quelque_part(nom) {
            continue;
        }
        let description = decrire_la_requete(nom);
        let mut schema = Objet::new(6);
        schema.texte("type", "integer");
        schema.texte("format", format_);
        schema.brut("minimum", "1");
        let mut parametre = Objet::new(5);
        parametre.texte("name", nom);
        parametre.texte("in", "query");
        parametre.brut("required", "false");
        parametre.texte("description", description);
        parametre.brut("schema", &schema.fermer());
        out.brut(nom, &parametre.fermer());
    }
    out.fermer()
}

/// Le schéma du document de refus, et l'énumération de ses types.
fn schemas() -> String {
    let mut types = Objet::new(6);
    types.texte("type", "string");
    types.texte("description", "L'identifiant stable du motif de refus.");
    types.brut("enum", &liste(&kinds()));

    let mut titre = Objet::new(6);
    titre.texte("type", "string");
    titre.texte("description", "Ce que le refus dit, en une phrase.");

    let mut statut = Objet::new(6);
    statut.texte("type", "integer");
    statut.texte("description", "Le code de statut, répété dans le corps.");
    statut.brut("enum", &nombres(&statuts()));

    let mut proprietes = Objet::new(5);
    proprietes.brut("type", &types.fermer());
    proprietes.brut("title", &titre.fermer());
    proprietes.brut("status", &statut.fermer());

    let mut probleme = Objet::new(4);
    probleme.texte("type", "object");
    probleme.texte("title", "Un refus, selon RFC 9457");
    probleme.texte(
        "description",
        "Servi en `application/problem+json`. `type` identifie le motif et ne change pas ; `title` est une phrase pour un humain et peut changer.",
    );
    probleme.brut("required", &liste(&["type", "title", "status"]));
    probleme.brut("properties", &proprietes.fermer());

    let mut out = Objet::new(3);
    out.brut("Probleme", &probleme.fermer());
    out.fermer()
}

/// La réponse de refus, référencée par toutes les opérations.
fn reponses_communes() -> String {
    let mut media = Objet::new(7);
    media.brut(
        "schema",
        "{\n              \"$ref\": \"#/components/schemas/Probleme\"\n            }",
    );
    let mut contenu = Objet::new(6);
    contenu.brut(ams_api::PROBLEM_MEDIA_TYPE, &media.fermer());
    let mut probleme = Objet::new(5);
    probleme.texte(
        "description",
        "Un refus, décrit comme RFC 9457 le demande. Le code exact dépend du motif.",
    );
    probleme.brut("content", &contenu.fermer());
    probleme.brut("headers", &entetes_allow(6));
    let mut out = Objet::new(3);
    out.brut("Probleme", &probleme.fermer());
    out.fermer()
}

/// Les types de refus, chacun une fois.
///
/// **PLUSIEURS MOTIFS PARTAGENT UN TYPE** : `Reason::kind` se replie sur le code
/// d'état quand le motif n'a pas de type propre, et un `enum` qui répéterait une
/// valeur serait refusé par les valideurs de schéma (§6.1.2 de JSON Schema).
fn kinds() -> Vec<&'static str> {
    let mut vus: Vec<&'static str> = Vec::new();
    for reason in Reason::TOUS {
        let kind = reason.kind();
        if !vus.contains(&kind) {
            vus.push(kind);
        }
    }
    vus
}

/// Les codes de refus, chacun une fois, dans l'ordre croissant.
fn statuts() -> Vec<u16> {
    let mut vus: Vec<u16> = Vec::new();
    for reason in Reason::TOUS {
        let code = reason.status().value();
        if !vus.contains(&code) {
            vus.push(code);
        }
    }
    vus.sort_unstable();
    vus
}

/// Un tableau de chaînes, indenté.
fn liste(valeurs: &[&str]) -> String {
    let pieces: Vec<String> = valeurs
        .iter()
        .map(|valeur| format!("          \"{valeur}\""))
        .collect();
    format!("[\n{}\n        ]", pieces.join(",\n"))
}

/// Un tableau de nombres, indenté.
fn nombres(valeurs: &[u16]) -> String {
    let pieces: Vec<String> = valeurs
        .iter()
        .map(|valeur| format!("          {valeur}"))
        .collect();
    format!("[\n{}\n        ]", pieces.join(",\n"))
}

/// Un objet JSON qu'on remplit champ par champ, en tenant l'indentation.
///
/// **IL N'ÉCHAPPE QUE CE QUI DOIT L'ÊTRE, ET IL LE FAIT TOUJOURS** : tout ce qui
/// entre par [`Objet::texte`] passe par [`echapper`]. Rien de ce document ne vient
/// d'un client — ce sont des constantes de ce dépôt —, mais un document JSON
/// produit par concaténation est précisément ce qu'on ne sait pas relire plus
/// tard, et un guillemet oublié casserait la barrière de CI sans dire pourquoi.
struct Objet {
    /// Les champs, déjà rendus.
    champs: Vec<String>,
    /// La profondeur, en niveaux de deux espaces.
    niveau: usize,
}

impl Objet {
    /// Un objet à la racine du document.
    fn racine() -> Self {
        Self::new(1)
    }

    /// Un objet à ce niveau d'indentation.
    fn new(niveau: usize) -> Self {
        Self {
            champs: Vec::new(),
            niveau,
        }
    }

    /// Ajoute un champ dont la valeur est une chaîne.
    fn texte(&mut self, nom: &str, valeur: &str) {
        self.brut(nom, &format!("\"{}\"", echapper(valeur)));
    }

    /// Ajoute un champ dont la valeur est déjà rendue.
    fn brut(&mut self, nom: &str, valeur: &str) {
        let marge = "  ".repeat(self.niveau);
        self.champs
            .push(format!("{marge}\"{}\": {valeur}", echapper(nom)));
    }

    /// Rend l'objet. Vide, il rend `{}`.
    fn fermer(self) -> String {
        if self.champs.is_empty() {
            return String::from("{}");
        }
        let marge = "  ".repeat(self.niveau.saturating_sub(1));
        format!("{{\n{}\n{marge}}}", self.champs.join(",\n"))
    }
}

/// Échappe ce que §7 de RFC 8259 exige d'échapper.
///
/// Rien de ce document ne vient d'un client : ce sont des constantes de ce
/// dépôt. L'échappement n'en est pas moins systématique — un document JSON
/// produit par concaténation est précisément celui qu'on ne sait pas relire plus
/// tard, et un guillemet oublié casserait la barrière de CI sans dire pourquoi.
fn echapper(valeur: &str) -> String {
    let mut out = String::with_capacity(valeur.len());
    for caractere in valeur.chars() {
        match caractere {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            autre if (autre as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", autre as u32));
            }
            autre => out.push(autre),
        }
    }
    out
}

#[cfg(test)]
mod tests;
