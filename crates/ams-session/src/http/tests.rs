// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une session HTTP a le droit de décider.

use std::string::{String, ToString};
use std::vec::Vec;

use ams_api::{Area, Key, Resource, Rights, Scope, Token, issue};
use ams_proto_http::{HeadBuilder, Limits, Method, RequestHead, StatusCode};

use super::{BODY_OCTETS_MAX, Http, Next, SCRATCH_OCTETS_MIN};

/// Une clé de scellement d'essai.
const CLEF: &[u8; 32] = b"une clef de trente-deux octets!!";

/// Un instant commode.
const MAINTENANT: u64 = 1_700_000_000_000_000;

/// Une heure, en microsecondes.
const HEURE: u64 = 3_600 * 1_000_000;

/// Le tampon de travail.
const PLACE: usize = SCRATCH_OCTETS_MIN + 4_096;

/// La session d'essai.
fn session() -> Http {
    Http::new(Key::new(CLEF).expect("trente-deux octets"), HEURE).expect("une durée licite")
}

/// Un jeton scellé pour ce compte et cette portée.
fn jeton(login: &str, scope: Scope) -> String {
    let mut place = [0_u8; ams_api::ENCODED_OCTETS_MAX];
    let ecrit = issue(
        &Key::new(CLEF).expect("trente-deux octets"),
        &Token {
            login,
            scope,
            expiry: MAINTENANT + HEURE,
            nonce: 7,
        },
        MAINTENANT,
        &mut place,
    )
    .expect("émissible");
    let mut valeur = String::from("Bearer ");
    valeur.push_str(ecrit);
    valeur
}

/// Construit une requête à partir de ses champs.
fn entete<'a>(champs: &[(&'a [u8], &'a [u8])]) -> RequestHead<'a> {
    let limites = Limits::DEFAULT;
    let mut constructeur = HeadBuilder::new(&limites);
    for (nom, valeur) in champs {
        constructeur.field(nom, valeur).expect("un champ licite");
    }
    constructeur.finish().expect("une requête complète")
}

/// Les champs d'une requête ordinaire, avec ce jeton.
fn requete<'a>(method: &'a [u8], chemin: &'a [u8], porte: &'a [u8]) -> Vec<(&'a [u8], &'a [u8])> {
    std::vec![
        (&b":method"[..], method),
        (&b":scheme"[..], &b"https"[..]),
        (&b":authority"[..], &b"exemple.fr"[..]),
        (&b":path"[..], chemin),
        (&b"authorization"[..], porte),
    ]
}

/// La ressource qu'une suite désigne, si elle en désigne une.
fn en_ressource<'o>(next: Next<'o>) -> Option<(Resource<'o>, Method, &'o str)> {
    match next {
        Next::Serve {
            resource,
            method,
            account,
            ..
        } => Some((resource, method, account)),
        _ => None,
    }
}

/// **L'EXTRACTEUR REND `None` SUR AUTRE CHOSE**, et c'est ce qui permet aux
/// essais de dire `expect` plutôt que d'ouvrir un arc qu'ils n'empruntent jamais.
#[test]
fn l_extracteur_refuse_ce_qui_n_est_pas_un_service() {
    assert!(en_ressource(Next::Respond).is_none());
    assert!(
        en_ressource(Next::CheckCredentials {
            login: "marc",
            password: b"x",
        })
        .is_none()
    );
}

/// Le corps d'une réponse, en texte.
fn texte(corps: &[u8]) -> String {
    core::str::from_utf8(corps).expect("de l'UTF-8").to_string()
}

/// **UNE REQUÊTE AUTORISÉE ARRIVE JUSQU'AU MAGASIN**, et pas plus loin.
#[test]
fn une_requete_autorisee_demande_a_servir() {
    let porte = jeton("marc", Scope::one(Area::Mail, Rights::Read));
    let champs = requete(b"GET", b"/v1/mailboxes", porte.as_bytes());
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let tour = session().request(&tete, &[], MAINTENANT, &mut place);
    assert_eq!(tour.status(), StatusCode::OK);
    let (resource, method, account) = en_ressource(tour.next()).expect("on sert");
    assert_eq!(resource, Resource::Mailboxes);
    assert_eq!(method, Method::Get);
    assert_eq!(account, "marc");
    assert_eq!(
        tour.next(),
        Next::Serve {
            resource,
            method,
            account,
            body: &[],
        }
    );
}

/// **CE SERVEUR NE SERT RIEN EN CLAIR** (C4) : une requête qui prétend l'inverse
/// s'est trompée d'adresse.
#[test]
fn le_schema_doit_etre_https() {
    let porte = jeton("marc", Scope::one(Area::Mail, Rights::Read));
    // La grammaire accepte `http` et `https` — elle dit elle-même que « que
    // `http` soit recevable est une question de POLITIQUE ». C'est ici qu'on la
    // tranche, et le reste ne franchit même pas la grammaire.
    let champs = std::vec![
        (&b":method"[..], &b"GET"[..]),
        (&b":scheme"[..], &b"http"[..]),
        (&b":authority"[..], &b"exemple.fr"[..]),
        (&b":path"[..], &b"/v1/mailboxes"[..]),
        (&b"authorization"[..], porte.as_bytes()),
    ];
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let tour = session().request(&tete, &[], MAINTENANT, &mut place);
    assert_eq!(tour.status(), StatusCode::BAD_REQUEST);
    assert_eq!(tour.next(), Next::Respond);

    // Et `https` passe, sans quoi cet essai ne dirait rien.
    let champs = requete(b"GET", b"/v1/mailboxes", porte.as_bytes());
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    assert_eq!(
        session()
            .request(&tete, &[], MAINTENANT, &mut place)
            .status(),
        StatusCode::OK
    );
}

/// **SANS JETON, RIEN** — et la réponse dit COMMENT s'authentifier (§3 de
/// RFC 6750).
#[test]
fn sans_jeton_on_refuse_et_l_on_dit_comment() {
    let champs = std::vec![
        (&b":method"[..], &b"GET"[..]),
        (&b":scheme"[..], &b"https"[..]),
        (&b":authority"[..], &b"exemple.fr"[..]),
        (&b":path"[..], &b"/v1/mailboxes"[..]),
    ];
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let tour = session().request(&tete, &[], MAINTENANT, &mut place);
    assert_eq!(tour.status(), StatusCode::UNAUTHORIZED);
    let champs: Vec<_> = tour.fields().collect();
    assert!(
        champs.contains(&(&b"www-authenticate"[..], &b"Bearer"[..])),
        "un 401 sans `WWW-Authenticate` laisse le client deviner"
    );
    assert!(texte(tour.body()).contains("/problems/unauthorized"));
}

/// **UN JETON QUI N'OUVRE PAS LA PORTÉE NE PASSE PAS**, et la réponse ne dit pas
/// que la ressource existe.
#[test]
fn une_portee_insuffisante_repond_comme_une_absence() {
    // Un jeton de courrier ne touche pas à l'administration.
    let porte = jeton("marc", Scope::one(Area::Mail, Rights::Write));
    let champs = requete(b"GET", b"/v1/accounts", porte.as_bytes());
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let tour = session().request(&tete, &[], MAINTENANT, &mut place);
    assert_eq!(tour.status(), StatusCode::NOT_FOUND);
    assert!(texte(tour.body()).contains("/problems/not-found"));

    // Et un chemin qui n'existe pas répond exactement pareil.
    let champs = requete(b"GET", b"/v1/inconnu", porte.as_bytes());
    let tete = entete(&champs);
    let mut autre = [0_u8; PLACE];
    let absent = session().request(&tete, &[], MAINTENANT, &mut autre);
    assert_eq!(absent.status(), tour.status());
    assert_eq!(texte(absent.body()), texte(tour.body()));
}

/// **LA LECTURE NE DONNE PAS L'ÉCRITURE.**
#[test]
fn un_jeton_de_lecture_n_ecrit_pas() {
    let porte = jeton("marc", Scope::one(Area::Mail, Rights::Read));
    let champs = requete(b"POST", b"/v1/mailboxes/INBOX/messages", porte.as_bytes());
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let tour = session().request(&tete, &[], MAINTENANT, &mut place);
    assert_eq!(tour.status(), StatusCode::NOT_FOUND);
}

/// **UN JETON EXPIRÉ SE DIT**, et le client sait qu'il doit se réauthentifier.
#[test]
fn un_jeton_expire_se_dit() {
    let porte = jeton("marc", Scope::one(Area::Mail, Rights::Read));
    let champs = requete(b"GET", b"/v1/mailboxes", porte.as_bytes());
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let tour = session().request(&tete, &[], MAINTENANT + HEURE, &mut place);
    assert_eq!(tour.status(), StatusCode::UNAUTHORIZED);
}

/// **UN 405 PORTE CE QU'IL FAUT POUR SE CORRIGER** (§15.5.6).
#[test]
fn un_mauvais_verbe_se_distingue_d_un_mauvais_chemin() {
    let porte = jeton("marc", Scope::one(Area::Observe, Rights::Read));
    let champs = requete(b"DELETE", b"/v1/health", porte.as_bytes());
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let tour = session().request(&tete, &[], MAINTENANT, &mut place);
    assert_eq!(tour.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(texte(tour.body()).contains("/problems/method-not-allowed"));
}

/// **§9.3.1 : UN CORPS SUR UN `GET` N'A PAS DE SENS DÉFINI**, et ce qui n'a pas
/// de sens défini se lit différemment d'un logiciel à l'autre.
#[test]
fn un_corps_la_ou_il_n_a_pas_de_sens_se_refuse() {
    let porte = jeton("marc", Scope::one(Area::Mail, Rights::Read));
    for methode in [&b"GET"[..], b"HEAD", b"DELETE"] {
        let champs = requete(methode, b"/v1/mailboxes", porte.as_bytes());
        let tete = entete(&champs);
        let mut place = [0_u8; PLACE];
        let tour = session().request(&tete, b"{}", MAINTENANT, &mut place);
        assert_eq!(tour.status(), StatusCode::BAD_REQUEST, "{methode:?}");
    }
}

/// **UN CORPS DIT CE QU'IL EST, OU ON NE LE LIT PAS.**
#[test]
fn un_corps_sans_type_se_refuse() {
    let porte = jeton("marc", Scope::one(Area::Mail, Rights::Write));
    // Sans `content-type`.
    let champs = requete(b"POST", b"/v1/mailboxes/INBOX/messages", porte.as_bytes());
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let tour = session().request(&tete, b"{}", MAINTENANT, &mut place);
    assert_eq!(tour.status(), StatusCode::BAD_REQUEST);

    // Avec un type qu'on ne lit pas.
    for dit in [
        &b"text/plain"[..],
        b"application/xml",
        b"application/json-patch+json",
        b"",
    ] {
        let mut champs = requete(b"POST", b"/v1/mailboxes/INBOX/messages", porte.as_bytes());
        champs.push((b"content-type", dit));
        let tete = entete(&champs);
        let mut place = [0_u8; PLACE];
        let tour = session().request(&tete, b"{}", MAINTENANT, &mut place);
        assert_eq!(tour.status(), StatusCode::BAD_REQUEST, "{dit:?}");
    }
}

/// **LES PARAMÈTRES SONT ADMIS, ET LA CASSE NE COMPTE PAS** (§8.3 de RFC 9110) :
/// les refuser écarterait des clients conformes.
#[test]
fn le_type_se_lit_avec_ses_parametres() {
    let porte = jeton("marc", Scope::one(Area::Mail, Rights::Write));
    for dit in [
        &b"application/json"[..],
        b"application/json; charset=utf-8",
        b"APPLICATION/JSON",
        b"application/json ;charset=utf-8",
        b"application/json; charset=UTF-8",
    ] {
        let mut champs = requete(b"POST", b"/v1/mailboxes/INBOX/messages", porte.as_bytes());
        champs.push((b"content-type", dit));
        let tete = entete(&champs);
        let mut place = [0_u8; PLACE];
        let tour = session().request(&tete, b"{}", MAINTENANT, &mut place);
        assert_eq!(tour.status(), StatusCode::OK, "{dit:?}");
        assert!(en_ressource(tour.next()).is_some(), "{dit:?}");
    }
}

/// **UNE SOUMISSION PORTE UN MESSAGE, ET LE RESTE PORTE DU JSON.**
///
/// §5.2.1 de RFC 2046 nomme le type d'un message de courrier. L'emballer dans une
/// chaîne JSON doublerait sa taille pour ne rien dire de plus.
///
/// **ET PAS L'INVERSE** : accepter un message là où l'on attend du JSON ferait
/// lire un message comme une représentation, et du JSON là où l'on attend un
/// message ferait remettre une accolade à quelqu'un.
#[test]
fn une_soumission_porte_un_message_et_rien_d_autre() {
    let porte = jeton("marc", Scope::one(Area::Submit, Rights::Write));
    let message = b"From: marc@exemple.test\r\nTo: marc@exemple.test\r\n\r\nbonjour";

    let mut champs = requete(b"POST", b"/v1/submissions", porte.as_bytes());
    champs.push((b"content-type", b"message/rfc822"));
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let tour = session().request(&tete, message, MAINTENANT, &mut place);
    assert_eq!(tour.status(), StatusCode::OK);
    assert!(
        en_ressource(tour.next()).is_some(),
        "et le message va jusqu'à la ressource"
    );

    // Du JSON sur une soumission : refusé.
    let mut champs = requete(b"POST", b"/v1/submissions", porte.as_bytes());
    champs.push((b"content-type", b"application/json"));
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let tour = session().request(&tete, b"{}", MAINTENANT, &mut place);
    assert_eq!(tour.status(), StatusCode::BAD_REQUEST);

    // Un message là où l'on attend du JSON : refusé de même.
    let porte = jeton("marc", Scope::one(Area::Mail, Rights::Write));
    let mut champs = requete(b"POST", b"/v1/mailboxes/INBOX/messages", porte.as_bytes());
    champs.push((b"content-type", b"message/rfc822"));
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let tour = session().request(&tete, message, MAINTENANT, &mut place);
    assert_eq!(tour.status(), StatusCode::BAD_REQUEST);
}

/// **PAS DE CORPS, PAS DE TYPE À VÉRIFIER.**
///
/// Une ressource qui exige un corps le dira elle-même, en refusant ce qu'elle n'a
/// pas reçu : c'est elle qui sait ce qu'elle attend.
#[test]
fn un_corps_vide_ne_demande_aucun_type() {
    let porte = jeton("marc", Scope::one(Area::Submit, Rights::Write));
    let champs = requete(b"POST", b"/v1/submissions", porte.as_bytes());
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let tour = session().request(&tete, b"", MAINTENANT, &mut place);
    assert_eq!(tour.status(), StatusCode::OK);
}

/// Un corps plus gros que ce qu'on lit se refuse.
#[test]
fn un_corps_trop_gros_se_refuse() {
    let porte = jeton("marc", Scope::one(Area::Mail, Rights::Write));
    let mut champs = requete(b"POST", b"/v1/mailboxes/INBOX/messages", porte.as_bytes());
    champs.push((b"content-type", b"application/json"));
    let tete = entete(&champs);
    let gros = std::vec![b'x'; BODY_OCTETS_MAX + 1];
    let mut place = [0_u8; PLACE];
    let tour = session().request(&tete, &gros, MAINTENANT, &mut place);
    assert_eq!(tour.status(), StatusCode::BAD_REQUEST);
}

/// **`no-store` ET `nosniff` SUR TOUTE RÉPONSE**, quelle qu'elle soit.
#[test]
fn toute_reponse_porte_ses_gardes() {
    let porte = jeton("marc", Scope::one(Area::Mail, Rights::Read));
    let cas: [(&[u8], &[u8]); 3] = [
        (b"GET", b"/v1/mailboxes"),
        (b"GET", b"/v1/inconnu"),
        (b"DELETE", b"/v1/health"),
    ];
    for (methode, chemin) in cas {
        let champs = requete(methode, chemin, porte.as_bytes());
        let tete = entete(&champs);
        let mut place = [0_u8; PLACE];
        let tour = session().request(&tete, &[], MAINTENANT, &mut place);
        let champs: Vec<_> = tour.fields().collect();
        assert!(
            champs.contains(&(&b"cache-control"[..], &b"no-store"[..])),
            "{chemin:?} : un intermédiaire pourrait garder cette réponse"
        );
        assert!(
            champs.contains(&(&b"x-content-type-options"[..], &b"nosniff"[..])),
            "{chemin:?}"
        );
        // **PAS DE `server`** : nommer le logiciel et sa version répond à la
        // première question de tout balayage.
        assert!(
            !champs.iter().any(|(nom, _)| *nom == b"server"),
            "{chemin:?} nomme le logiciel"
        );
    }
}

/// **L'ÉCHANGE D'IDENTIFIANTS N'EXIGE AUCUN JETON**, puisque c'est là qu'on en
/// obtient un.
#[test]
fn l_echange_d_identifiants_n_exige_pas_de_jeton() {
    let champs = std::vec![
        (&b":method"[..], &b"POST"[..]),
        (&b":scheme"[..], &b"https"[..]),
        (&b":authority"[..], &b"exemple.fr"[..]),
        (&b":path"[..], &b"/v1/tokens"[..]),
        (&b"content-type"[..], &b"application/json"[..]),
    ];
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let tour = session().request(
        &tete,
        br#"{"login":"marc","password":"secret"}"#,
        MAINTENANT,
        &mut place,
    );
    assert_eq!(
        tour.next(),
        Next::CheckCredentials {
            login: "marc",
            password: b"secret",
        }
    );
}

/// Un corps d'échange mal formé se refuse comme un mauvais mot de passe.
#[test]
fn un_corps_d_echange_mal_forme_se_refuse_pareil() {
    let attendu = {
        let mut place = [0_u8; PLACE];
        let tour =
            session().on_credentials(false, "marc", Scope::none(), 1, MAINTENANT, &mut place);
        (tour.status(), texte(tour.body()))
    };
    for corps in [
        &b"{}"[..],
        br#"{"login":"marc"}"#,
        br#"{"password":"x"}"#,
        b"pas du json",
        br#"{"login":1,"password":"x"}"#,
        // Un identifiant échappé : on ne le décode pas ici.
        br#"{"login":"\u006darc","password":"x"}"#,
    ] {
        let champs = std::vec![
            (&b":method"[..], &b"POST"[..]),
            (&b":scheme"[..], &b"https"[..]),
            (&b":authority"[..], &b"exemple.fr"[..]),
            (&b":path"[..], &b"/v1/tokens"[..]),
            (&b"content-type"[..], &b"application/json"[..]),
        ];
        let tete = entete(&champs);
        let mut place = [0_u8; PLACE];
        let tour = session().request(&tete, corps, MAINTENANT, &mut place);
        assert_eq!(tour.status(), attendu.0, "{corps:?}");
        assert_eq!(texte(tour.body()), attendu.1, "{corps:?}");
    }
}

/// **UNE DURÉE IMPOSSIBLE SE REFUSE AU MONTAGE**, et non requête après requête.
#[test]
fn une_duree_impossible_se_refuse_au_montage() {
    let clef = || Key::new(CLEF).expect("trente-deux octets");
    assert!(Http::new(clef(), 0).is_err(), "une durée nulle");
    assert!(
        Http::new(clef(), ams_api::LIFETIME_MAX_US + 1).is_err(),
        "au-delà de ce qu'un jeton peut vivre"
    );
    assert!(Http::new(clef(), ams_api::LIFETIME_MAX_US).is_ok(), "pile");
    assert!(Http::new(clef(), 1).is_ok());
}

/// **UN NOM DE COMPTE IMPOSSIBLE NE FAIT PAS DE JETON**, et c'est notre faute :
/// c'est le magasin qui nous l'a rendu.
#[test]
fn un_nom_de_compte_impossible_ne_fait_pas_de_jeton() {
    let long = "x".repeat(ams_api::LOGIN_OCTETS_MAX + 1);
    for login in ["", long.as_str()] {
        let mut place = [0_u8; PLACE];
        let tour = session().on_credentials(
            true,
            login,
            Scope::one(Area::Mail, Rights::Read),
            1,
            MAINTENANT,
            &mut place,
        );
        assert_eq!(tour.status().class(), 5, "« {login} »");
    }
}

/// Un corps d'échange qui porte autre chose que des chaînes ne trouble rien.
#[test]
fn un_corps_d_echange_bavard_se_lit_quand_meme() {
    let champs = std::vec![
        (&b":method"[..], &b"POST"[..]),
        (&b":scheme"[..], &b"https"[..]),
        (&b":authority"[..], &b"exemple.fr"[..]),
        (&b":path"[..], &b"/v1/tokens"[..]),
        (&b"content-type"[..], &b"application/json"[..]),
    ];
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    // Des champs qu'on ne connaît pas, des valeurs qui ne sont pas des chaînes,
    // et un tableau : rien de tout cela ne change les deux qu'on cherche.
    let tour = session().request(
        &tete,
        br#"{"autre":"x","login":"marc","liste":[1,true,null],"password":"secret"}"#,
        MAINTENANT,
        &mut place,
    );
    assert_eq!(
        tour.next(),
        Next::CheckCredentials {
            login: "marc",
            password: b"secret",
        }
    );
}

/// **NOTRE TAMPON, NOTRE FAUTE**, même quand l'échange a réussi : on rend le
/// code seul plutôt qu'un jeton coupé en deux.
#[test]
fn un_tampon_trop_court_pour_le_jeton_est_notre_faute() {
    // Toutes les tailles jusqu'à la bonne : c'est ce qui met en jeu chacune des
    // écritures du chemin, plutôt que la première qui échoue.
    let entier = {
        let mut place = [0_u8; PLACE];
        session()
            .on_credentials(
                true,
                "marc",
                Scope::one(Area::Mail, Rights::Read),
                1,
                MAINTENANT,
                &mut place,
            )
            .body()
            .len()
    };
    assert!(entier > 0, "l'échange doit écrire quelque chose");
    for taille in 0..entier {
        let mut petit = std::vec![0_u8; taille];
        let tour = session().on_credentials(
            true,
            "marc",
            Scope::one(Area::Mail, Rights::Read),
            1,
            MAINTENANT,
            &mut petit,
        );
        assert_eq!(tour.status().class(), 5, "{taille}");
        assert!(tour.body().is_empty(), "{taille}");
    }
}

/// **UN ÉCHANGE RÉUSSI REND UN JETON QUI OUVRE CE QU'ON LUI A DONNÉ.**
#[test]
fn un_echange_reussi_rend_un_jeton_utilisable() {
    let portee = Scope::one(Area::Mail, Rights::Write);
    let mut place = [0_u8; PLACE];
    let tour = session().on_credentials(true, "marc", portee, 42, MAINTENANT, &mut place);
    assert_eq!(tour.status(), StatusCode::CREATED);
    assert_eq!(tour.next(), Next::Respond);
    let corps = texte(tour.body());
    assert!(corps.starts_with(r#"{"token":""#), "{corps}");
    assert!(corps.contains(r#""expires":"#), "{corps}");

    // Le jeton rendu ouvre bien ce qu'on lui a donné.
    let debut = corps.find(':').expect("un premier champ") + 2;
    let fin = corps[debut..].find('"').expect("une fin de chaîne") + debut;
    let mut valeur = String::from("Bearer ");
    valeur.push_str(&corps[debut..fin]);
    let champs = requete(b"POST", b"/v1/mailboxes/INBOX/search", valeur.as_bytes());
    let tete = entete(&champs);
    let mut autre = [0_u8; PLACE];
    let suite = session().request(&tete, &[], MAINTENANT, &mut autre);
    assert_eq!(suite.status(), StatusCode::OK);
    assert!(matches!(
        suite.next(),
        Next::Serve {
            account: "marc",
            ..
        }
    ));
}

/// **UN REFUS D'IDENTIFIANTS NE DIT PAS CE QUI CLOCHE.**
#[test]
fn un_refus_d_identifiants_ne_dit_rien() {
    let mut place = [0_u8; PLACE];
    let tour = session().on_credentials(false, "marc", Scope::none(), 1, MAINTENANT, &mut place);
    assert_eq!(tour.status(), StatusCode::UNAUTHORIZED);
    let dit = texte(tour.body());
    for indice in ["marc", "compte", "mot de passe", "inconnu"] {
        assert!(!dit.contains(indice), "« {dit} » nomme « {indice} »");
    }
}

/// **AUCUNE RÉPONSE NE REDIT CE QUE LE CLIENT A ÉCRIT.**
#[test]
fn aucune_reponse_ne_redit_la_requete() {
    let porte = jeton("marc", Scope::one(Area::Mail, Rights::Read));
    let chemin = b"/v1/mailboxes/%3Cscript%3E/messages/0";
    let champs = requete(b"GET", chemin, porte.as_bytes());
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let tour = session().request(&tete, &[], MAINTENANT, &mut place);
    let dit = texte(tour.body());
    assert!(!dit.contains("script"), "{dit}");
    assert!(!dit.contains("mailboxes"), "{dit}");
    assert!(!dit.contains('<'), "{dit}");
}

/// **NOTRE TAMPON, NOTRE FAUTE** : sous la place qu'il faut, on rend le code seul
/// plutôt que d'écrire à moitié.
#[test]
fn un_tampon_trop_court_est_notre_faute() {
    let porte = jeton("marc", Scope::one(Area::Mail, Rights::Read));
    let champs = requete(b"GET", b"/v1/mailboxes", porte.as_bytes());
    let tete = entete(&champs);
    for taille in [0_usize, 16, 256, 1_024] {
        let mut petit = std::vec![0_u8; taille];
        let tour = session().request(&tete, &[], MAINTENANT, &mut petit);
        assert_eq!(tour.status().class(), 5, "{taille}");
        assert_eq!(tour.next(), Next::Respond);
    }
}

/// La chaîne de requête ne participe pas au routage (§3.4 de RFC 3986).
#[test]
fn la_chaine_de_requete_ne_change_pas_la_ressource() {
    let porte = jeton("marc", Scope::one(Area::Mail, Rights::Read));
    for chemin in [
        &b"/v1/mailboxes"[..],
        b"/v1/mailboxes?",
        b"/v1/mailboxes?depuis=10",
        b"/v1/mailboxes?a=1&b=2",
    ] {
        let champs = requete(b"GET", chemin, porte.as_bytes());
        let tete = entete(&champs);
        let mut place = [0_u8; PLACE];
        let tour = session().request(&tete, &[], MAINTENANT, &mut place);
        let (resource, _, _) = en_ressource(tour.next()).expect("on sert");
        assert_eq!(resource, Resource::Mailboxes, "{chemin:?}");
    }
}
