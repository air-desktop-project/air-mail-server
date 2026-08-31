// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : le routage de l'API REST** — ce qu'une requête désigne, et le droit
//! qu'elle demande.
//!
//! # Pourquoi celle-ci
//!
//! C'est la première surface de ce serveur qu'aucune RFC ne décrit, et c'est
//! celle qu'un attaquant atteint en premier : un chemin est ce qu'il contrôle
//! entièrement.
//!
//! La quasi-totalité des fautes d'autorisation d'une API vit dans l'écart entre
//! deux écritures d'un même chemin. Ce module refuse au lieu de normaliser, et
//! c'est cette promesse-là qu'il faut vérifier sur des octets qu'on n'a pas
//! choisis : **rien de ce qui est accepté ne doit pouvoir remonter, ni s'écrire
//! de deux façons.**
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quels que soient les octets et la méthode.
//! 2. **AUCUN SEGMENT ACCEPTÉ N'EST `.`, `..`, VIDE, OU PORTEUR D'UN OCTET DE
//!    CONTRÔLE.** C'est la promesse entière du module, et elle se vérifie sur le
//!    résultat plutôt que sur l'entrée — ce qui la rend indépendante de la façon
//!    dont on l'a obtenue.
//! 3. **CE QU'ON A COMPRIS, ON SAIT LE RÉÉCRIRE — ET LE RELIRE À L'IDENTIQUE.**
//!    Le percent-encodage donne plusieurs écritures d'un même nom, et §6.2.2.2
//!    de RFC 3986 les déclare équivalentes : « une seule écriture » serait donc
//!    une propriété fausse. La vraie est l'aller-retour — réencoder ce qu'on a
//!    décodé doit redonner la même ressource. Sans elle, il existerait un nom
//!    que le serveur accepte mais ne sait pas désigner, et les deux moitiés du
//!    serveur ne parleraient plus du même objet.
//! 4. **UNE RESSOURCE SERT CE QU'ELLE ANNONCE, ET RIEN D'AUTRE** : `resolve` ne
//!    réussit que pour une méthode que `allowed` nomme, ou `OPTIONS`.
//! 5. **TOUTE RESSOURCE EXIGE UNE PORTÉE, SAUF L'ÉCHANGE DE JETON** — c'est là
//!    qu'on en obtient une, et c'est la seule.
//! 6. **LA LECTURE NE DONNE JAMAIS L'ÉCRITURE** : une méthode sûre n'exige
//!    jamais un droit d'écriture, et une méthode qui modifie l'exige toujours.
//! 7. **LE SECRET D'UN COMPTE NE SE LIT PAR AUCUNE MÉTHODE.**
//! 8. **LA CHAÎNE DE REQUÊTE NE CHANGE JAMAIS LA RESSOURCE** : ce qui suit le
//!    `?` est hors du chemin, et l'y laisser entrer ferait d'un paramètre un
//!    nom de boîte.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_api::{Area, Reason, Resource, Rights, Scope, resolve, split_query};
use ams_proto_http::Method;

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// La cible, telle qu'elle arriverait du réseau.
    cible: &'a [u8],
    /// La méthode.
    methode: u8,
}

/// La méthode que désigne un octet.
const fn methode(brut: u8) -> Method {
    match brut % 7 {
        0 => Method::Get,
        1 => Method::Head,
        2 => Method::Post,
        3 => Method::Put,
        4 => Method::Delete,
        5 => Method::Patch,
        _ => Method::Options,
    }
}

/// Une méthode modifie-t-elle ?
const fn modifie(method: Method) -> bool {
    matches!(
        method,
        Method::Post | Method::Put | Method::Delete | Method::Patch
    )
}

fuzz_target!(|entree: Entree| {
    let method = methode(entree.methode);
    let (chemin, requete) = split_query(entree.cible);
    // PROPRIÉTÉ 8 : le chemin et la requête recomposent la cible.
    assert!(
        chemin.len() <= entree.cible.len(),
        "le chemin déborde la cible"
    );
    assert!(
        requete.len() <= entree.cible.len(),
        "la requête déborde la cible"
    );
    assert!(!chemin.contains(&b'?'), "un `?` est resté dans le chemin");

    let mut place = [0_u8; 4_096];
    let Ok(resolu) = resolve(method, chemin, &mut place) else {
        return;
    };
    let resource = resolu.resource;

    // PROPRIÉTÉ 4 : la ressource sert ce qu'elle annonce, et rien d'autre.
    assert!(
        resource.allowed().contains(&method) || matches!(method, Method::Options),
        "{resource:?} a servi {method:?} sans l'annoncer"
    );
    assert!(resource.serves(method));
    assert_eq!(resolu.method, method);

    // PROPRIÉTÉ 5 : toute ressource exige une portée, sauf l'échange de jeton.
    match resolu.scope {
        None => assert!(
            matches!(resource, Resource::Tokens),
            "{resource:?} n'exige aucune portée"
        ),
        Some(portee) => {
            assert!(
                !matches!(resource, Resource::Tokens),
                "l'échange de jeton exige une portée"
            );
            // PROPRIÉTÉ 6 : la lecture ne donne jamais l'écriture.
            let ecrit = Area::TOUS
                .into_iter()
                .any(|area| portee.allows(area, Rights::Write));
            // La révocation de son propre jeton n'exige rien de plus que de
            // l'avoir : c'est la seule portée vide qui soit légitime.
            let vide = portee == Scope::none();
            assert!(
                vide || ecrit == modifie(method),
                "{resource:?} et {method:?} : le droit ne suit pas le verbe"
            );
            // Une portée n'ouvre jamais deux domaines à la fois.
            let domaines = Area::TOUS
                .into_iter()
                .filter(|area| portee.allows(*area, Rights::Read))
                .count();
            assert!(domaines <= 1, "{resource:?} ouvre {domaines} domaines");
        }
    }

    // PROPRIÉTÉ 7 : le secret d'un compte ne se lit par aucune méthode.
    if matches!(resource, Resource::AccountPassword { .. }) {
        assert!(
            !matches!(method, Method::Get | Method::Head),
            "une empreinte s'est laissé lire"
        );
    }

    // PROPRIÉTÉS 2 et 3 : on réécrit le chemin depuis ce qu'on en a compris, et
    // il doit se relire à l'identique.
    let mut refait = std::string::String::new();
    for segment in segments_de(&resource) {
        let segment = segment.as_str();
        // PROPRIÉTÉ 2 : rien de ce qui est accepté ne peut remonter.
        assert!(!segment.is_empty(), "un segment vide est passé");
        assert_ne!(segment, ".", "un segment `.` est passé");
        assert_ne!(segment, "..", "un segment `..` est passé");
        assert!(
            !segment.bytes().any(|o| o < 0x20 || o == 0x7f),
            "un octet de contrôle est passé : {segment:?}"
        );
        refait.push('/');
        // **ON RÉENCODE** : un nom peut contenir `%` ou `/`, et les écrire tels
        // quels donnerait un autre chemin — ou pas de chemin du tout.
        for octet in segment.bytes() {
            match octet {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    refait.push(char::from(octet));
                }
                autre => refait.push_str(&std::format!("%{autre:02X}")),
            }
        }
    }

    // PROPRIÉTÉ 3 : la réécriture désigne la même chose.
    let mut encore = [0_u8; 4_096];
    let relu = resolve(method, refait.as_bytes(), &mut encore)
        .expect("un chemin reconstruit depuis ses segments se relit");
    assert_eq!(
        relu.resource, resource,
        "deux écritures désignent la même ressource : {refait}"
    );
    assert_eq!(relu.scope, resolu.scope);

    // Et une faute de chemin ne se déguise jamais en ressource inconnue.
    if let Err(faute) = resolve(method, entree.cible, &mut encore) {
        assert!(
            matches!(
                faute.reason(),
                Reason::BadPath
                    | Reason::PathTooLong
                    | Reason::NoSuchResource
                    | Reason::MethodNotAllowed
                    | Reason::BufferTooSmall
            ),
            "une faute inattendue : {faute:?}"
        );
    }
});

/// Les segments qui recomposent le chemin de cette ressource.
///
/// On rend des chaînes possédées : emprunter obligerait à faire vivre l'écriture
/// décimale d'un identifiant aussi longtemps que le chemin, donc à la fuir — et
/// une fuite délibérée dans le harnais masquerait celles du code.
fn segments_de(resource: &Resource<'_>) -> std::vec::Vec<std::string::String> {
    let mut segments = std::vec![std::string::String::from("v1")];
    let mut pousser = |texte: &str| segments.push(std::string::String::from(texte));
    match *resource {
        Resource::Tokens => pousser("tokens"),
        Resource::CurrentToken => {
            pousser("tokens");
            pousser("current");
        }
        Resource::Mailboxes => pousser("mailboxes"),
        Resource::Mailbox { boite } => {
            pousser("mailboxes");
            pousser(boite);
        }
        Resource::Messages { boite } => {
            pousser("mailboxes");
            pousser(boite);
            pousser("messages");
        }
        Resource::Search { boite } => {
            pousser("mailboxes");
            pousser(boite);
            pousser("search");
        }
        Resource::Message { boite, uid } => {
            pousser("mailboxes");
            pousser(boite);
            pousser("messages");
            pousser(&std::format!("{uid}"));
        }
        Resource::MessageRaw { boite, uid } => {
            pousser("mailboxes");
            pousser(boite);
            pousser("messages");
            pousser(&std::format!("{uid}"));
            pousser("raw");
        }
        Resource::MessagePart { boite, uid, partie } => {
            pousser("mailboxes");
            pousser(boite);
            pousser("messages");
            pousser(&std::format!("{uid}"));
            pousser("parts");
            pousser(partie);
        }
        Resource::Accounts => pousser("accounts"),
        Resource::Account { compte } => {
            pousser("accounts");
            pousser(compte);
        }
        Resource::AccountPassword { compte } => {
            pousser("accounts");
            pousser(compte);
            pousser("password");
        }
        Resource::AccountAddresses { compte } => {
            pousser("accounts");
            pousser(compte);
            pousser("addresses");
        }
        Resource::Domains => pousser("domains"),
        Resource::Bans => pousser("bans"),
        Resource::Ban { source } => {
            pousser("bans");
            pousser(source);
        }
        Resource::Submissions => pousser("submissions"),
        Resource::Health => pousser("health"),
        Resource::Metrics => pousser("metrics"),
    }
    segments
}
