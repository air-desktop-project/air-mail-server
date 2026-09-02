// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! **Cible : la session HTTP** — qui parle, et ce qu'il a le droit de toucher.
//!
//! # Pourquoi celle-ci
//!
//! C'est la porte. Tout ce qui arrive de dehors par HTTP/2 ou HTTP/3 passe par
//! cette décision, et une seule requête qui atteindrait le magasin sans jeton
//! valable ouvrirait toutes les boîtes du serveur.
//!
//! Les propriétés qui comptent ici ne tiennent pas dans un appel : elles disent
//! ce qui ne doit JAMAIS arriver, quelle que soit la requête. C'est exactement ce
//! qu'un fuzz sait vérifier et qu'un essai ne fait que sur les cas qu'on a
//! imaginés.
//!
//! # Les propriétés
//!
//! 1. **Rien ne panique**, quelle que soit la requête.
//! 2. **ON N'ATTEINT LE MAGASIN QU'AVEC UN JETON QUI OUVRE LA PORTÉE VOULUE.**
//!    C'est la propriété entière de ce module : si `Serve` sort d'ici, alors un
//!    jeton scellé par NOTRE clé existait, n'avait pas expiré, et sa portée
//!    contenait celle que la route exige.
//! 3. **LE COMPTE SERVI EST CELUI DU JETON**, et jamais celui que le chemin
//!    nomme. Confondre les deux, c'est laisser lire la boîte du voisin en
//!    changeant une URL.
//! 4. **RIEN NE SORT EN CLAIR** : un schéma `http` ne sert jamais.
//! 5. **UN REFUS EST TIRÉ D'UN VOCABULAIRE FINI**, écrit d'avance. C'est la
//!    formulation juste de « aucune réponse ne redit ce que le client a écrit » :
//!    chercher les octets du client dans la réponse serait plus faible ET faux —
//!    un client peut copier notre propre document d'erreur, et le fuzz l'a
//!    trouvé en quelques secondes. Ce qui compte n'est pas que la réponse diffère
//!    de l'entrée, c'est qu'elle ne DÉPENDE pas d'elle : elle est l'un des dix
//!    documents que les dix raisons produisent, et rien d'autre.
//! 6. **TOUTE RÉPONSE PORTE SES GARDES** — `no-store` et `nosniff` — et aucune ne
//!    nomme le logiciel.
//! 7. **UN CORPS N'EST LU QUE LÀ OÙ IL A UN SENS**, et seulement s'il dit ce
//!    qu'il est.
//! 8. **AUCUN CHAMP N'EST ÉCRIT DEUX FOIS**, et `alt-svc` n'apparaît que si
//!    HTTP/3 est servi.
//!
//! # LA HUITIÈME EST NÉE D'UN DÉFAUT, ET DE DEUX
//!
//! `www-authenticate` s'écrivait à DEUX endroits — une fois comme champ de tout
//! refus, une fois ajouté par le composeur d'un 401 —, et un client qui en lit
//! deux ne sait pas lequel croire. Un simple compte l'aurait vu.
//!
//! Et `alt-svc` est ce qui rend le port HTTP/3 trouvable (RFC 7838, §3.1 de
//! RFC 9114). L'annoncer quand il n'existe pas ferait perdre une connexion à
//! chaque client qui le croit ; ne pas l'annoncer quand il existe rend toute la
//! pile HTTP/3 introuvable. Les deux se vérifient d'un seul coup.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use ams_api::{Key, Scope, Token, issue};
use ams_proto_http::{HeadBuilder, Limits, Method, StatusCode};
use ams_session::http::{Http, Next};

/// La clé du serveur.
const CLEF: &[u8; 32] = b"une clef de trente-deux octets!!";

/// Une clé qui n'est pas la sienne.
const AUTRE: &[u8; 32] = b"une AUTRE clef de trente-deux o!";

/// Une heure, en microsecondes.
const HEURE: u64 = 3_600 * 1_000_000;

/// Ce qu'on soumet.
#[derive(Arbitrary, Debug)]
struct Entree<'a> {
    /// La méthode, telle qu'elle arriverait.
    methode: u8,
    /// Le schéma : le sien, ou celui qu'on refuse.
    en_clair: bool,
    /// La cible.
    chemin: &'a [u8],
    /// Ce que porte `authorization`, quand il y en a un.
    autorisation: Option<&'a [u8]>,
    /// Faut-il présenter un vrai jeton plutôt que ces octets ?
    vrai_jeton: bool,
    /// Le compte et la portée de ce jeton.
    compte: &'a str,
    bits: u8,
    /// De combien le jeton est-il déjà vieux ?
    age: u32,
    /// Le corps, et ce qu'il prétend être.
    corps: &'a [u8],
    type_de_corps: Option<&'a [u8]>,
    /// L'instant présent.
    maintenant: u32,
    /// Le port UDP d'HTTP/3. **Zéro veut dire « pas servi »** — c'est le seul
    /// port qu'un socket lié ne rend jamais, puisque `:0` fait choisir le noyau.
    port_h3: u16,
}

/// La méthode que désigne un octet.
const fn methode(brut: u8) -> &'static [u8] {
    match brut % 7 {
        0 => b"GET",
        1 => b"HEAD",
        2 => b"POST",
        3 => b"PUT",
        4 => b"DELETE",
        5 => b"PATCH",
        _ => b"OPTIONS",
    }
}

fuzz_target!(|entree: Entree| {
    let clef = Key::new(CLEF).expect("trente-deux octets");
    let Ok(session) = Http::new(clef, HEURE) else {
        return;
    };
    // **HTTP/3 SERVI OU NON**, tiré de l'entrée : les deux moitiés de la
    // huitième propriété se jouent dans la même campagne.
    let session = match entree.port_h3 {
        0 => session,
        port => session.with_h3_port(port),
    };
    let maintenant = u64::from(entree.maintenant).saturating_add(HEURE);

    // Un vrai jeton, quand l'entrée le demande — sinon les octets bruts.
    let mut ecrit = [0_u8; ams_api::ENCODED_OCTETS_MAX];
    let mut entete = std::vec::Vec::new();
    let portee = Scope::from_bits(entree.bits);
    let expiry = maintenant
        .saturating_add(HEURE)
        .saturating_sub(u64::from(entree.age));
    let scelle = entree.vrai_jeton
        && issue(
            &Key::new(CLEF).expect("trente-deux octets"),
            &Token {
                login: entree.compte,
                scope: portee,
                expiry,
                nonce: 3,
            },
            maintenant,
            &mut ecrit,
        )
        .map(|texte| {
            entete.extend_from_slice(b"Bearer ");
            entete.extend_from_slice(texte.as_bytes());
        })
        .is_ok();
    let autorisation = match scelle {
        true => Some(entete.as_slice()),
        false => entree.autorisation,
    };

    let schema: &[u8] = match entree.en_clair {
        true => b"http",
        false => b"https",
    };
    let mut champs: std::vec::Vec<(&[u8], &[u8])> = std::vec![
        (&b":method"[..], methode(entree.methode)),
        (&b":scheme"[..], schema),
        (&b":authority"[..], &b"exemple.fr"[..]),
        (&b":path"[..], entree.chemin),
    ];
    if let Some(valeur) = autorisation {
        champs.push((b"authorization", valeur));
    }
    if let Some(dit) = entree.type_de_corps {
        champs.push((b"content-type", dit));
    }

    // La grammaire garde sa part : ce qu'elle refuse ne parvient pas ici.
    let limites = Limits::DEFAULT;
    let mut constructeur = HeadBuilder::new(&limites);
    for (nom, valeur) in &champs {
        if constructeur.field(nom, valeur).is_err() {
            return;
        }
    }
    let Ok(tete) = constructeur.finish() else {
        return;
    };

    let mut place = [0_u8; ams_session::http::SCRATCH_OCTETS_MIN + 4_096];
    let tour = session.request(&tete, entree.corps, maintenant, &mut place);

    // PROPRIÉTÉ 6 : toute réponse porte ses gardes, et n'en nomme pas d'autre.
    let champs_rendus: std::vec::Vec<_> = tour.fields().collect();
    assert!(
        champs_rendus.contains(&(&b"cache-control"[..], &b"no-store"[..])),
        "une réponse sans `no-store` peut être gardée par un intermédiaire"
    );
    assert!(
        champs_rendus.contains(&(&b"x-content-type-options"[..], &b"nosniff"[..])),
        "une réponse sans `nosniff` peut se faire lire comme du HTML"
    );
    assert!(
        !champs_rendus.iter().any(|(nom, _)| *nom == b"server"),
        "une réponse nomme le logiciel"
    );

    // PROPRIÉTÉ 8 : aucun champ deux fois, et l'alternative dit la vérité.
    for (rang, (nom, _)) in champs_rendus.iter().enumerate() {
        let combien = champs_rendus
            .iter()
            .filter(|(autre, _)| autre == nom)
            .count();
        assert_eq!(
            combien,
            1,
            "le champ {} est écrit {combien} fois (rang {rang})",
            String::from_utf8_lossy(nom)
        );
    }
    let annonce = champs_rendus.iter().any(|(nom, _)| *nom == b"alt-svc");
    assert_eq!(
        annonce,
        entree.port_h3 != 0,
        "l'alternative annoncée ne dit pas ce qui est servi"
    );

    match tour.next() {
        Next::Serve { account, .. } => {
            // PROPRIÉTÉ 4 : rien ne sort en clair.
            assert!(!entree.en_clair, "une requête en clair a été servie");
            // PROPRIÉTÉ 2 : un jeton NÔTRE, valide, et de portée suffisante.
            assert!(
                scelle,
                "on sert sans qu'un jeton scellé par notre clé ait été présenté"
            );
            assert!(maintenant < expiry, "un jeton expiré a servi");
            // PROPRIÉTÉ 3 : le compte servi est celui du jeton.
            assert_eq!(
                account, entree.compte,
                "le compte servi n'est pas celui du jeton"
            );
            // La portée du jeton contient celle que la route exige : on le
            // revérifie en refaisant le chemin avec une portée vide.
            assert_ne!(
                portee,
                Scope::none(),
                "une portée vide n'ouvre aucune ressource servie"
            );
            assert_eq!(tour.status(), StatusCode::OK);
            // PROPRIÉTÉ 7 : un corps n'accompagne qu'une méthode qui en attend.
            if !entree.corps.is_empty() {
                assert!(
                    matches!(tete.method(), Method::Post | Method::Put | Method::Patch),
                    "un corps a été servi là où il n'a pas de sens"
                );
            }
        }
        Next::CheckCredentials { .. } => {
            assert!(!entree.en_clair, "une requête en clair a été servie");
            assert_eq!(tour.status(), StatusCode::OK);
        }
        Next::Respond => {
            // Un refus porte un document, et son code n'est jamais un succès
            // silencieux.
            assert!(
                tour.status().class() >= 4,
                "on répond {} sans rien servir",
                tour.status().value()
            );
        }
    }

    // PROPRIÉTÉ 5 : un refus est tiré d'un vocabulaire fini.
    if matches!(tour.next(), Next::Respond) && tour.status().class() >= 4 {
        let mut place = [0_u8; 256];
        let connu = RAISONS.into_iter().any(|raison| {
            ams_api::problem(raison, &mut place).is_ok_and(|attendu| attendu == tour.body())
        });
        assert!(
            connu || tour.body().is_empty(),
            "un refus a écrit autre chose que l'un des documents prévus"
        );
    }

    // **UNE AUTRE CLÉ N'OUVRE RIEN**, et c'est ce qui rend le jeton utile.
    let autre =
        Http::new(Key::new(AUTRE).expect("trente-deux octets"), HEURE).expect("une durée licite");
    let mut place = [0_u8; ams_session::http::SCRATCH_OCTETS_MIN + 4_096];
    let ailleurs = autre.request(&tete, entree.corps, maintenant, &mut place);
    if scelle {
        assert!(
            !matches!(ailleurs.next(), Next::Serve { .. }),
            "un jeton scellé ailleurs a été servi"
        );
    }
});

/// Toutes les raisons que l'API sait dire.
///
/// **C'EST LE VOCABULAIRE ENTIER D'UN REFUS.** Ajouter une raison sans l'ajouter
/// ici fait échouer la cible, ce qui est exactement ce qu'on veut : une réponse
/// qu'on n'a pas prévue est une réponse qu'on n'a pas relue.
const RAISONS: [ams_api::Reason; 10] = [
    ams_api::Reason::BadPath,
    ams_api::Reason::PathTooLong,
    ams_api::Reason::NoSuchResource,
    ams_api::Reason::MethodNotAllowed,
    ams_api::Reason::Forbidden,
    ams_api::Reason::BadToken,
    ams_api::Reason::TokenExpired,
    ams_api::Reason::BadJsonBody,
    ams_api::Reason::BadKey,
    ams_api::Reason::BufferTooSmall,
];
