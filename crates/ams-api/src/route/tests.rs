// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce que cette API met à disposition, et ce qu'il faut pour y accéder.

use ams_proto_http::Method;

use super::{Resource, resolve};
use crate::error::Reason;
use crate::scope::{Area, Rights, Scope};

/// Un tampon confortable.
const PLACE: usize = 1_024;

/// Résout, et rend tout ce que le routage a décidé.
fn resolu(method: Method, chemin: &[u8]) -> Result<super::Resolved<'static>, Reason> {
    // La sortie survit à l'appel : on la fuit exprès, pour que les emprunts
    // rendus vivent aussi longtemps que le test.
    let place = std::boxed::Box::leak(std::boxed::Box::new([0_u8; PLACE]));
    resolve(method, chemin, place).map_err(|e| e.reason())
}

/// Résout, et rend la ressource.
fn ou(method: Method, chemin: &[u8]) -> Result<Resource<'static>, Reason> {
    resolu(method, chemin).map(|resolu| resolu.resource)
}

/// Chaque ressource se désigne par son chemin.
#[test]
fn chaque_ressource_se_designe() {
    let cas: [(Method, &[u8], Resource<'_>); 20] = [
        (Method::Post, b"/v1/tokens", Resource::Tokens),
        (
            Method::Delete,
            b"/v1/tokens/current",
            Resource::CurrentToken,
        ),
        (Method::Get, b"/v1/mailboxes", Resource::Mailboxes),
        (
            Method::Get,
            b"/v1/mailboxes/INBOX",
            Resource::Mailbox { boite: "INBOX" },
        ),
        (
            Method::Get,
            b"/v1/mailboxes/INBOX/messages",
            Resource::Messages { boite: "INBOX" },
        ),
        (
            Method::Post,
            b"/v1/mailboxes/INBOX/messages",
            Resource::Messages { boite: "INBOX" },
        ),
        (
            Method::Get,
            b"/v1/mailboxes/INBOX/messages/12",
            Resource::Message {
                boite: "INBOX",
                uid: 12,
            },
        ),
        (
            Method::Patch,
            b"/v1/mailboxes/INBOX/messages/12",
            Resource::Message {
                boite: "INBOX",
                uid: 12,
            },
        ),
        (
            Method::Get,
            b"/v1/mailboxes/INBOX/messages/12/raw",
            Resource::MessageRaw {
                boite: "INBOX",
                uid: 12,
            },
        ),
        (
            Method::Get,
            b"/v1/mailboxes/INBOX/messages/12/parts/1.2",
            Resource::MessagePart {
                boite: "INBOX",
                uid: 12,
                partie: "1.2",
            },
        ),
        (
            Method::Post,
            b"/v1/mailboxes/INBOX/search",
            Resource::Search { boite: "INBOX" },
        ),
        (Method::Get, b"/v1/accounts", Resource::Accounts),
        (Method::Post, b"/v1/accounts", Resource::Accounts),
        (
            Method::Get,
            b"/v1/accounts/marc",
            Resource::Account { compte: "marc" },
        ),
        (
            Method::Put,
            b"/v1/accounts/marc/password",
            Resource::AccountPassword { compte: "marc" },
        ),
        (
            Method::Get,
            b"/v1/accounts/marc/addresses",
            Resource::AccountAddresses { compte: "marc" },
        ),
        (Method::Get, b"/v1/domains", Resource::Domains),
        (Method::Get, b"/v1/bans", Resource::Bans),
        (
            Method::Delete,
            b"/v1/bans/198.51.100.4",
            Resource::Ban {
                source: "198.51.100.4",
            },
        ),
        (Method::Post, b"/v1/submissions", Resource::Submissions),
    ];
    for (method, chemin, attendue) in cas {
        assert_eq!(ou(method, chemin), Ok(attendue), "{chemin:?}");
    }
    assert_eq!(ou(Method::Get, b"/v1/health"), Ok(Resource::Health));
    assert_eq!(ou(Method::Get, b"/v1/metrics"), Ok(Resource::Metrics));
}

/// **LA VERSION EST OBLIGATOIRE** : sans elle, la première rupture de
/// compatibilité n'aurait nulle part où se dire.
#[test]
fn la_version_est_obligatoire() {
    for sans in [&b"/health"[..], b"/v2/health", b"/V1/health", b"/"] {
        assert_eq!(
            ou(Method::Get, sans),
            Err(Reason::NoSuchResource),
            "{sans:?}"
        );
    }
}

/// **LE MAUVAIS VERBE SE DIT, MAIS CE N'EST PLUS ICI QU'ON LE DIT.**
///
/// §15.5.6 veut qu'une ressource qui existe sans servir ce verbe rende 405 et
/// non 404 — sinon le client réessaie les deux et double le trafic pour rien.
/// Mais rendre ce 405 DEPUIS LE ROUTAGE le rendait avant toute autorisation, et
/// `Reason::status` déclare que « cela n'existe pas » et « vous n'avez pas le
/// droit de savoir » se répondent PAREIL. Le 405 rendait cette différence à qui
/// n'avait rien présenté.
///
/// Le routage rend donc `serves`, et la session en tire le 405 UNE FOIS LE JETON
/// VÉRIFIÉ — c'est éprouvé dans `ams-session`, sur le fil.
#[test]
fn le_mauvais_verbe_se_dit_sans_faire_echouer_le_routage() {
    for (verbe, chemin) in [
        (Method::Delete, &b"/v1/health"[..]),
        (Method::Get, b"/v1/submissions"),
    ] {
        let resolu = resolu(verbe, chemin).expect("le chemin désigne une ressource");
        assert!(!resolu.serves, "{chemin:?} ne sert pas {verbe:?}");
        // **ET LA PORTÉE EXIGÉE EST CELLE DE LA LECTURE** : apprendre qu'un
        // verbe n'est pas servi, c'est apprendre quelque chose de la ressource.
        assert_eq!(
            resolu.scope,
            resolu.resource.scope(Method::Get),
            "{chemin:?} n'exige pas la portée de lecture"
        );
    }
    // Et un chemin qui ne désigne rien reste un 404, quel que soit le verbe.
    assert_eq!(
        ou(Method::Delete, b"/v1/inconnu"),
        Err(Reason::NoSuchResource)
    );
}

/// **CELLE-CI NE SE LIT PAS** : il n'existe aucune méthode qui rende une
/// empreinte, et c'est la raison d'être de cette ressource.
#[test]
fn un_secret_ne_se_lit_jamais() {
    for lecture in [Method::Get, Method::Head] {
        let resolu = resolu(lecture, b"/v1/accounts/marc/password").expect("désignée");
        assert!(!resolu.serves, "{lecture:?} ne rend jamais une empreinte");
    }
    let pose = resolu(Method::Put, b"/v1/accounts/marc/password").expect("désignée");
    assert!(pose.serves, "`PUT` pose le secret");
}

/// **`OPTIONS` S'APPLIQUE À TOUTE RESSOURCE QUI EXISTE** (§9.3.7) : c'est le
/// moyen normalisé de demander ce qu'elle sert.
#[test]
fn options_s_applique_partout() {
    for chemin in [
        &b"/v1/health"[..],
        b"/v1/accounts/marc/password",
        b"/v1/submissions",
        b"/v1/mailboxes/INBOX/messages/12",
    ] {
        assert!(ou(Method::Options, chemin).is_ok(), "{chemin:?}");
    }
    // Mais pas à ce qui n'existe pas.
    assert_eq!(
        ou(Method::Options, b"/v1/inconnu"),
        Err(Reason::NoSuchResource)
    );
}

/// **CHAQUE RESSOURCE PORTE SA PORTÉE**, et la méthode décide du droit.
#[test]
fn chaque_ressource_porte_sa_portee() {
    let mut place = [0_u8; PLACE];
    let lecture = resolve(Method::Get, b"/v1/mailboxes", &mut place).expect("licite");
    assert_eq!(
        lecture.scope,
        Some(Scope::one(Area::Mail, Rights::Read)),
        "lire du courrier ne demande que de lire"
    );

    let mut place = [0_u8; PLACE];
    let ecriture = resolve(Method::Post, b"/v1/accounts", &mut place).expect("licite");
    assert_eq!(ecriture.scope, Some(Scope::one(Area::Admin, Rights::Write)));
    assert_eq!(ecriture.method, Method::Post);

    let mut place = [0_u8; PLACE];
    let depot = resolve(Method::Post, b"/v1/submissions", &mut place).expect("licite");
    assert_eq!(depot.scope, Some(Scope::one(Area::Submit, Rights::Write)));

    let mut place = [0_u8; PLACE];
    let compteurs = resolve(Method::Get, b"/v1/metrics", &mut place).expect("licite");
    assert_eq!(
        compteurs.scope,
        Some(Scope::one(Area::Observe, Rights::Read))
    );
}

/// **`HEAD` DEMANDE LE MÊME DROIT QUE `GET`** (§9.3.2) : le laisser passer plus
/// facilement rendrait lisible par sa longueur ce qu'on refusait de rendre.
#[test]
fn head_demande_autant_que_get() {
    let mut un = [0_u8; PLACE];
    let mut deux = [0_u8; PLACE];
    let par_get = resolve(Method::Get, b"/v1/accounts/marc", &mut un).expect("licite");
    let par_head = resolve(Method::Head, b"/v1/accounts/marc", &mut deux).expect("licite");
    assert_eq!(par_get.scope, par_head.scope);
}

/// **L'ÉCHANGE DE JETON EST LA SEULE RESSOURCE QUI N'EXIGE AUCUNE PORTÉE**,
/// puisque c'est là qu'on en obtient une.
#[test]
fn seul_l_echange_de_jeton_n_exige_rien() {
    let mut place = [0_u8; PLACE];
    let echange = resolve(Method::Post, b"/v1/tokens", &mut place).expect("licite");
    assert_eq!(echange.scope, None);

    // Révoquer le sien demande de l'avoir, et rien de plus.
    let mut place = [0_u8; PLACE];
    let revoque = resolve(Method::Delete, b"/v1/tokens/current", &mut place).expect("licite");
    assert_eq!(revoque.scope, Some(Scope::none()));

    // Et toutes les autres exigent quelque chose.
    for (method, chemin) in [
        (Method::Get, &b"/v1/health"[..]),
        (Method::Get, b"/v1/mailboxes"),
        (Method::Get, b"/v1/accounts"),
        (Method::Post, b"/v1/submissions"),
    ] {
        let mut place = [0_u8; PLACE];
        let resolu = resolve(method, chemin, &mut place).expect("licite");
        let portee = resolu.scope.expect("une portée");
        assert_ne!(portee, Scope::none(), "{chemin:?} n'exige rien");
    }
}

/// **UN SEUL FORMAT D'IDENTIFIANT, ET PAS DE SIGNE** : chaque autre écriture est
/// une seconde clé pour un cache ou pour un journal.
#[test]
fn un_identifiant_n_a_qu_une_ecriture() {
    for mauvais in [
        &b"/v1/mailboxes/INBOX/messages/012"[..],
        b"/v1/mailboxes/INBOX/messages/+12",
        b"/v1/mailboxes/INBOX/messages/-12",
        b"/v1/mailboxes/INBOX/messages/0x0c",
        b"/v1/mailboxes/INBOX/messages/12abc",
        b"/v1/mailboxes/INBOX/messages/1 2",
        // Zéro n'est pas un identifiant (§2.3.1.1 de RFC 9051).
        b"/v1/mailboxes/INBOX/messages/0",
        // Et ce qui déborde n'en est pas un non plus.
        b"/v1/mailboxes/INBOX/messages/99999999999999999999999",
    ] {
        assert_eq!(
            ou(Method::Get, mauvais),
            Err(Reason::NoSuchResource),
            "{mauvais:?}"
        );
    }
    // La plus grande valeur qui tient, elle, passe.
    let grand = std::format!("/v1/mailboxes/INBOX/messages/{}", u64::MAX);
    assert_eq!(
        ou(Method::Get, grand.as_bytes()),
        Ok(Resource::Message {
            boite: "INBOX",
            uid: u64::MAX,
        })
    );
}

/// **UNE FAUTE DE CHEMIN REMONTE TELLE QUELLE** : le routage ne la traduit pas
/// en « ressource inconnue », sans quoi un client qui a mal écrit son chemin
/// chercherait la ressource au lieu de relire son URL.
#[test]
fn une_faute_de_chemin_remonte_telle_quelle() {
    assert_eq!(ou(Method::Get, b"/v1/.."), Err(Reason::BadPath));
    assert_eq!(ou(Method::Get, b"/v1//health"), Err(Reason::BadPath));
    assert_eq!(ou(Method::Get, b"v1/health"), Err(Reason::BadPath));
    assert_eq!(
        ou(Method::Get, b"/a/b/c/d/e/f/g/h/i"),
        Err(Reason::PathTooLong)
    );
}

/// **L'IDENTIFIANT SE VÉRIFIE SUR TOUTES LES ROUTES QUI EN PORTENT UN**, et non
/// seulement sur la plus courte : chacune est une porte, et une porte oubliée
/// suffit.
#[test]
fn l_identifiant_se_verifie_sur_chaque_route() {
    for mauvais in [
        &b"/v1/mailboxes/INBOX/messages/0/raw"[..],
        b"/v1/mailboxes/INBOX/messages/012/raw",
        b"/v1/mailboxes/INBOX/messages/abc/raw",
        b"/v1/mailboxes/INBOX/messages/0/parts/1",
        b"/v1/mailboxes/INBOX/messages/012/parts/1",
        b"/v1/mailboxes/INBOX/messages/abc/parts/1",
    ] {
        assert_eq!(
            ou(Method::Get, mauvais),
            Err(Reason::NoSuchResource),
            "{mauvais:?}"
        );
    }
}

/// Les chemins qui ressemblent à une ressource sans en être une se refusent.
#[test]
fn les_presque_ressources_se_refusent() {
    for mauvais in [
        &b"/v1"[..],
        b"/v1/tokens/autre",
        b"/v1/tokens/current/encore",
        b"/v1/mailboxes/INBOX/autre",
        b"/v1/mailboxes/INBOX/messages/12/autre",
        b"/v1/mailboxes/INBOX/messages/12/parts",
        b"/v1/mailboxes/INBOX/messages/12/raw/encore",
        b"/v1/mailboxes/INBOX/messages/12/parts/1/encore",
        b"/v1/accounts/marc/autre",
        b"/v1/accounts/marc/password/encore",
        b"/v1/domains/exemple.fr",
        b"/v1/bans/1.2.3.4/encore",
        b"/v1/submissions/1",
        b"/v1/health/detail",
        b"/v1/metrics/detail",
    ] {
        assert_eq!(
            ou(Method::Get, mauvais),
            Err(Reason::NoSuchResource),
            "{mauvais:?}"
        );
    }
}

/// **CE QUE `Allow` DIRA** : §15.5.6 en fait une obligation sur un 405.
#[test]
fn chaque_ressource_dit_ce_qu_elle_sert() {
    let toutes = [
        Resource::Tokens,
        Resource::CurrentToken,
        Resource::Mailboxes,
        Resource::Mailbox { boite: "b" },
        Resource::Messages { boite: "b" },
        Resource::Message { boite: "b", uid: 1 },
        Resource::MessageRaw { boite: "b", uid: 1 },
        Resource::MessagePart {
            boite: "b",
            uid: 1,
            partie: "1",
        },
        Resource::Search { boite: "b" },
        Resource::Accounts,
        Resource::Account { compte: "c" },
        Resource::AccountPassword { compte: "c" },
        Resource::AccountAddresses { compte: "c" },
        Resource::Domains,
        Resource::Bans,
        Resource::Ban { source: "s" },
        Resource::Submissions,
        Resource::Health,
        Resource::Metrics,
    ];
    for resource in toutes {
        let servies = resource.allowed();
        assert!(!servies.is_empty(), "{resource:?} ne sert rien");
        // Ce qu'elle annonce, elle le sert.
        for method in servies {
            assert!(resource.serves(*method), "{resource:?} ment sur {method:?}");
            // **SEUL L'ÉCHANGE DE JETON N'A PAS DE PORTÉE** : l'assertion le
            // dit dans les deux sens, plutôt que de tolérer l'absence.
            assert_eq!(
                resource.scope(*method).is_some(),
                !matches!(resource, Resource::Tokens),
                "{resource:?} et {method:?}"
            );
        }
        // **UN `GET` VA TOUJOURS AVEC UN `HEAD`** (§9.3.2).
        assert_eq!(
            servies.contains(&Method::Get),
            servies.contains(&Method::Head),
            "{resource:?} sépare `GET` et `HEAD`"
        );
    }
}
