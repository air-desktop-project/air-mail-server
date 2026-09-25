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
fn une_session() -> Http {
    Http::new(Key::new(CLEF).expect("trente-deux octets"), HEURE).expect("une durée licite")
}

/// L'identifiant que portent les jetons de ce banc.
const IDENTIFIANT: u64 = 7;

/// Un jeton scellé pour ce compte et cette portée.
fn jeton(login: &str, scope: Scope) -> String {
    let mut place = [0_u8; ams_api::ENCODED_OCTETS_MAX];
    let ecrit = issue(
        &Key::new(CLEF).expect("trente-deux octets"),
        &Token {
            login,
            scope,
            expiry: MAINTENANT + HEURE,
            nonce: IDENTIFIANT,
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
fn en_ressource<'o>(next: Next<'o>) -> Option<(Resource<'o>, Method, &'o str, u64, Scope)> {
    match next {
        Next::Serve {
            resource,
            method,
            account,
            nonce,
            scope,
            ..
        } => Some((resource, method, account, nonce, scope)),
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
    let session = une_session();
    let tour = session.request(&tete, &[], MAINTENANT, &mut place);
    assert_eq!(tour.status(), StatusCode::OK);
    let (resource, method, account, nonce, portee) = en_ressource(tour.next()).expect("on sert");
    assert_eq!(resource, Resource::Mailboxes);
    assert_eq!(method, Method::Get);
    assert_eq!(account, "marc");
    // **L'IDENTIFIANT DE SESSION REMONTE JUSQU'À L'APPELANT**, et c'est ce qui
    // lui permet de fermer CETTE session-là plutôt que le compte entier.
    assert_eq!(nonce, IDENTIFIANT);
    assert_eq!(
        tour.next(),
        Next::Serve {
            resource,
            method,
            account,
            nonce,
            scope: portee,
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
    let session = une_session();
    let tour = session.request(&tete, &[], MAINTENANT, &mut place);
    assert_eq!(tour.status(), StatusCode::BAD_REQUEST);
    assert_eq!(tour.next(), Next::Respond);

    // Et `https` passe, sans quoi cet essai ne dirait rien.
    let champs = requete(b"GET", b"/v1/mailboxes", porte.as_bytes());
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    assert_eq!(
        session.request(&tete, &[], MAINTENANT, &mut place).status(),
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
    let session = une_session();
    let tour = session.request(&tete, &[], MAINTENANT, &mut place);
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
    let session = une_session();
    let tour = session.request(&tete, &[], MAINTENANT, &mut place);
    assert_eq!(tour.status(), StatusCode::NOT_FOUND);
    assert!(texte(tour.body()).contains("/problems/not-found"));

    // Et un chemin qui n'existe pas répond exactement pareil.
    let champs = requete(b"GET", b"/v1/inconnu", porte.as_bytes());
    let tete = entete(&champs);
    let mut autre = [0_u8; PLACE];
    let absent = session.request(&tete, &[], MAINTENANT, &mut autre);
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
    let session = une_session();
    let tour = session.request(&tete, &[], MAINTENANT, &mut place);
    assert_eq!(tour.status(), StatusCode::NOT_FOUND);
}

/// **UN JETON EXPIRÉ SE DIT**, et le client sait qu'il doit se réauthentifier.
#[test]
fn un_jeton_expire_se_dit() {
    let porte = jeton("marc", Scope::one(Area::Mail, Rights::Read));
    let champs = requete(b"GET", b"/v1/mailboxes", porte.as_bytes());
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let session = une_session();
    let tour = session.request(&tete, &[], MAINTENANT + HEURE, &mut place);
    assert_eq!(tour.status(), StatusCode::UNAUTHORIZED);
}

/// **UN 405 PORTE CE QU'IL FAUT POUR SE CORRIGER** (§15.5.6).
#[test]
fn un_mauvais_verbe_se_distingue_d_un_mauvais_chemin() {
    let porte = jeton("marc", Scope::one(Area::Observe, Rights::Read));
    let champs = requete(b"DELETE", b"/v1/health", porte.as_bytes());
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let session = une_session();
    let tour = session.request(&tete, &[], MAINTENANT, &mut place);
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
        let session = une_session();
        let tour = session.request(&tete, b"{}", MAINTENANT, &mut place);
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
    let session = une_session();
    let tour = session.request(&tete, b"{}", MAINTENANT, &mut place);
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
        let tour = session.request(&tete, b"{}", MAINTENANT, &mut place);
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
        let session = une_session();
        let tour = session.request(&tete, b"{}", MAINTENANT, &mut place);
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
    let session = une_session();
    let tour = session.request(&tete, message, MAINTENANT, &mut place);
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
    let tour = session.request(&tete, b"{}", MAINTENANT, &mut place);
    assert_eq!(tour.status(), StatusCode::BAD_REQUEST);

    // Un message là où l'on attend du JSON : refusé de même.
    let porte = jeton("marc", Scope::one(Area::Mail, Rights::Write));
    let mut champs = requete(b"POST", b"/v1/mailboxes/INBOX/messages", porte.as_bytes());
    champs.push((b"content-type", b"message/rfc822"));
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let tour = session.request(&tete, message, MAINTENANT, &mut place);
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
    let session = une_session();
    let tour = session.request(&tete, b"", MAINTENANT, &mut place);
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
    let session = une_session();
    let tour = session.request(&tete, &gros, MAINTENANT, &mut place);
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
        let session = une_session();
        let tour = session.request(&tete, &[], MAINTENANT, &mut place);
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
    let session = une_session();
    let tour = session.request(
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

/// **LA PORTE PUBLIQUE GARDE SON VERBE ET SON TYPE**, bien qu'elle n'exige
/// aucune portée.
///
/// `/v1/tokens` est la seule ressource que l'on atteigne sans rien présenter :
/// son autorisation ne peut donc rien retarder. Les deux contrôles que les
/// autres ressources font APRÈS le jeton — le verbe, puis le type du corps —
/// doivent y être faits quand même, et sans rien divulguer : l'existence de
/// cette porte-là n'est pas un secret.
///
/// **SANS LE PREMIER, UN `GET /v1/tokens` ENTRERAIT DANS L'ÉCHANGE** au lieu
/// d'être refusé.
#[test]
fn la_porte_publique_garde_son_verbe_et_son_type() {
    let session = une_session();

    // Un verbe que cette ressource ne sert pas.
    let champs = std::vec![
        (&b":method"[..], &b"GET"[..]),
        (&b":scheme"[..], &b"https"[..]),
        (&b":authority"[..], &b"exemple.fr"[..]),
        (&b":path"[..], &b"/v1/tokens"[..]),
    ];
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let tour = session.request(&tete, &[], MAINTENANT, &mut place);
    assert_eq!(tour.status(), StatusCode::METHOD_NOT_ALLOWED);

    // Un corps qui ne dit pas ce que cette ressource sait lire.
    let champs = std::vec![
        (&b":method"[..], &b"POST"[..]),
        (&b":scheme"[..], &b"https"[..]),
        (&b":authority"[..], &b"exemple.fr"[..]),
        (&b":path"[..], &b"/v1/tokens"[..]),
        (&b"content-type"[..], &b"message/rfc822"[..]),
    ];
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let tour = session.request(
        &tete,
        br#"{"login":"marc","password":"secret"}"#,
        MAINTENANT,
        &mut place,
    );
    assert_eq!(tour.status(), StatusCode::BAD_REQUEST);
}

/// Un corps d'échange mal formé se refuse comme un mauvais mot de passe.
#[test]
fn un_corps_d_echange_mal_forme_se_refuse_pareil() {
    let session = une_session();
    let attendu = {
        let mut place = [0_u8; PLACE];
        let tour = session.on_credentials(false, "marc", Scope::none(), 1, MAINTENANT, &mut place);
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
        let tour = session.request(&tete, corps, MAINTENANT, &mut place);
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
        let session = une_session();
        let tour = session.on_credentials(
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
    let session = une_session();
    let tour = session.request(
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
    let session = une_session();
    let entier = {
        let mut place = [0_u8; PLACE];
        session
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
        let tour = session.on_credentials(
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
    let session = une_session();
    let tour = session.on_credentials(true, "marc", portee, 42, MAINTENANT, &mut place);
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
    let suite = session.request(&tete, &[], MAINTENANT, &mut autre);
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
    let session = une_session();
    let tour = session.on_credentials(false, "marc", Scope::none(), 1, MAINTENANT, &mut place);
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
    let session = une_session();
    let tour = session.request(&tete, &[], MAINTENANT, &mut place);
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
        let session = une_session();
        let tour = session.request(&tete, &[], MAINTENANT, &mut petit);
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
        let session = une_session();
        let tour = session.request(&tete, &[], MAINTENANT, &mut place);
        let (resource, _, _, _, _) = en_ressource(tour.next()).expect("on sert");
        assert_eq!(resource, Resource::Mailboxes, "{chemin:?}");
    }
}

// ── CE QUE TOUTE RÉPONSE PORTE (un seul endroit le dit) ─────────────────────

/// Les noms de champ d'un tour, dans l'ordre.
fn noms(tour: &super::Turn<'_>) -> std::vec::Vec<std::string::String> {
    tour.fields()
        .map(|(nom, _)| std::string::String::from_utf8_lossy(nom).into_owned())
        .collect()
}

/// **DEUX PROTECTIONS SUR TOUTE RÉPONSE**, quelle qu'elle soit.
///
/// `no-store` parce que ce qu'on rend dépend du jeton présenté (§5.2.2.5 de
/// RFC 9111), et `nosniff` parce qu'un JSON deviné comme du HTML se lit comme du
/// HTML. Elles ne dépendent ni du code, ni de la ressource, ni de la version
/// d'HTTP — et c'est précisément ce qui avait cessé d'être vrai.
#[test]
fn toute_reponse_porte_les_memes_protections() {
    let alt = &b"h3=\":443\"; ma=86400"[..];
    for status in [
        StatusCode::OK,
        StatusCode::CREATED,
        StatusCode::BAD_REQUEST,
        StatusCode::UNAUTHORIZED,
        StatusCode::INTERNAL_SERVER_ERROR,
    ] {
        let champs = super::champs_de_toute_reponse(status, alt);
        let vus: std::vec::Vec<&[u8]> = champs.iter().flatten().map(|(nom, _)| *nom).collect();
        assert!(vus.contains(&&b"cache-control"[..]), "{}", status.value());
        assert!(
            vus.contains(&&b"x-content-type-options"[..]),
            "{}",
            status.value()
        );
        // **`www-authenticate` NE SORT QUE SUR UN 401** (§3 de RFC 6750) :
        // l'écrire ailleurs inviterait à s'authentifier là où ce n'est pas la
        // question.
        assert_eq!(
            vus.contains(&&b"www-authenticate"[..]),
            status == StatusCode::UNAUTHORIZED,
            "{}",
            status.value()
        );
    }
}

/// **ON N'ANNONCE PAS UNE ALTERNATIVE QU'ON NE SERT PAS.**
///
/// Sans HTTP/3, aucun `alt-svc` : un client qui croirait l'annonce perdrait une
/// connexion sur un port muet avant de se rabattre. C'est la même règle que pour
/// `DSN`, qui ne s'annonce pas sans file.
#[test]
fn sans_http3_aucune_alternative_n_est_annoncee() {
    let champs = super::champs_de_toute_reponse(StatusCode::OK, &[]);
    let vus: std::vec::Vec<&[u8]> = champs.iter().flatten().map(|(nom, _)| *nom).collect();
    assert!(!vus.contains(&&b"alt-svc"[..]), "{vus:?}");

    // Et une session qu'on n'a pas renseignée n'annonce rien non plus.
    let session = une_session();
    assert!(session.alt_svc().is_empty());
    let champs = requete(b"GET", b"/v1/mailboxes", b"");
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let tour = session.request(&tete, &[], MAINTENANT, &mut place);
    assert!(!noms(&tour).iter().any(|nom| nom == "alt-svc"));
}

/// **AVEC HTTP/3, `Alt-Svc` PART SUR TOUTE RÉPONSE** (RFC 7838).
///
/// C'est la seule chose qui rende le port UDP trouvable (§3.1 de RFC 9114) : un
/// port qu'aucun client ne cherche est du code qui ne sert jamais.
#[test]
fn le_port_http3_se_fait_annoncer() {
    let session = une_session().with_h3_port(443);
    assert_eq!(session.alt_svc(), b"h3=\":443\"; ma=86400");

    // Sur un refus AUSSI : c'est souvent la première réponse qu'un client voit.
    let champs = requete(b"GET", b"/v1/mailboxes", b"");
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let tour = session.request(&tete, &[], MAINTENANT, &mut place);
    assert_eq!(tour.status(), StatusCode::UNAUTHORIZED);
    let vus = noms(&tour);
    assert!(vus.iter().any(|nom| nom == "alt-svc"), "{vus:?}");
    assert!(vus.iter().any(|nom| nom == "www-authenticate"), "{vus:?}");
    assert!(vus.iter().any(|nom| nom == "cache-control"), "{vus:?}");
    // **UNE SEULE FOIS** : `www-authenticate` était écrit à deux endroits, et un
    // client qui en lit deux ne sait pas lequel croire.
    assert_eq!(
        vus.iter().filter(|nom| *nom == "www-authenticate").count(),
        1,
        "{vus:?}"
    );
}

/// **UN PORT QUELCONQUE S'ÉCRIT JUSTE**, y compris aux bornes.
///
/// Le port vient du socket LIÉ, et `:0` fait choisir le noyau : la valeur
/// annoncée peut donc être n'importe laquelle.
#[test]
fn tout_port_s_annonce_sans_se_tronquer() {
    for (port, attendu) in [
        (0_u16, &b"h3=\":0\"; ma=86400"[..]),
        (443, b"h3=\":443\"; ma=86400"),
        (8_443, b"h3=\":8443\"; ma=86400"),
        (u16::MAX, b"h3=\":65535\"; ma=86400"),
    ] {
        let session = une_session().with_h3_port(port);
        assert_eq!(session.alt_svc(), attendu, "port {port}");
        // La borne annoncée couvre le pire cas.
        assert!(session.alt_svc().len() <= super::ALT_SVC_MAX, "port {port}");
    }
}

/// **LA DURÉE QU'ON ANNONCE EST CELLE QU'ON ÉMET.**
///
/// L'appelant s'en sert pour inscrire la session : si elle différait de celle
/// que le jeton porte, la session mourrait avant lui — et un porteur parfaitement
/// légitime serait refusé sans que rien ne l'explique.
#[test]
fn la_duree_annoncee_est_celle_des_jetons_emis() {
    let session = Http::new(Key::new(CLEF).expect("trente-deux octets"), HEURE).expect("montable");
    assert_eq!(session.duree(), HEURE);

    // Et elle se retrouve dans ce qu'un échange rend.
    let mut place = [0_u8; 4096];
    let tour = session.on_credentials(
        true,
        "marc",
        Scope::one(Area::Mail, Rights::Read),
        IDENTIFIANT,
        MAINTENANT,
        &mut place,
    );
    let dit = String::from_utf8_lossy(tour.body()).into_owned();
    let attendu = std::format!("\"expires\":{}", MAINTENANT + HEURE);
    assert!(dit.contains(&attendu), "{dit}");
}

/// Frappe une invitation d'épreuve pour ce compte.
fn une_invitation(login: &str, expiry: u64) -> std::string::String {
    use std::string::ToString as _;
    let mut place = [0_u8; ams_api::INVITATION_ENCODED_OCTETS_MAX];
    ams_api::issue_invitation(
        &Key::new(CLEF).expect("trente-deux octets"),
        &ams_api::Invitation { login, expiry },
        MAINTENANT,
        &mut place,
    )
    .expect("écrivable")
    .to_string()
}

/// Les champs d'une requête d'enrôlement bien formée.
fn champs_d_enrolement<'a>() -> std::vec::Vec<(&'a [u8], &'a [u8])> {
    std::vec![
        (&b":method"[..], &b"POST"[..]),
        (&b":scheme"[..], &b"https"[..]),
        (&b":authority"[..], &b"exemple.fr"[..]),
        (&b":path"[..], &b"/v1/devices"[..]),
        (&b"content-type"[..], &b"application/json"[..]),
    ]
}

/// **L'ENRÔLEMENT N'EXIGE AUCUN JETON, ET L'INVITATION DIT QUI C'EST.**
///
/// C'est tout l'amorçage : celui qui s'enrôle n'a rien à présenter — ni mot de
/// passe qu'il veuille donner, ni appareil déjà connu. Ce qui l'autorise est le
/// sceau, et la session en tire le compte.
#[test]
fn un_enrolement_tire_son_compte_de_l_invitation() {
    let invitation = une_invitation("marc", MAINTENANT + HEURE);
    let corps = std::format!(
        r#"{{"invitation":"{invitation}","publicKey":"BAECAwQ","name":"iPhone de Marc"}}"#
    );
    let champs = champs_d_enrolement();
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let session = une_session();
    let tour = session.request(&tete, corps.as_bytes(), MAINTENANT, &mut place);
    assert_eq!(
        tour.next(),
        Next::Enrol {
            account: "marc",
            public_key: "BAECAwQ",
            name: "iPhone de Marc",
        }
    );
}

/// **LE NOM EST FACULTATIF** : un appareil qu'on n'a pas nommé reste un
/// appareil, et refuser l'enrôlement pour cela serait une pédanterie.
#[test]
fn un_enrolement_sans_nom_passe() {
    let invitation = une_invitation("marc", MAINTENANT + HEURE);
    let corps = std::format!(r#"{{"invitation":"{invitation}","publicKey":"BAECAwQ"}}"#);
    let champs = champs_d_enrolement();
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    assert_eq!(
        une_session()
            .request(&tete, corps.as_bytes(), MAINTENANT, &mut place)
            .next(),
        Next::Enrol {
            account: "marc",
            public_key: "BAECAwQ",
            name: "",
        }
    );
}

/// **UN JETON PORTEUR NE S'ENRÔLE PAS.**
///
/// Il est scellé par la MÊME clé ; seule sa version le sépare d'une invitation.
/// Sans cette séparation, le jeton de courrier de n'importe qui — ou le sien —
/// s'échangerait contre une clef d'appareil permanente sur le compte.
#[test]
fn un_jeton_ne_s_enrole_pas() {
    use std::string::ToString as _;
    let mut ecrit = [0_u8; ams_api::ENCODED_OCTETS_MAX];
    let jeton = ams_api::issue(
        &Key::new(CLEF).expect("trente-deux octets"),
        &ams_api::Token {
            login: "marc",
            scope: Scope::one(Area::Mail, Rights::Read),
            expiry: MAINTENANT + HEURE,
            nonce: 7,
        },
        MAINTENANT,
        &mut ecrit,
    )
    .expect("écrivable")
    .to_string();

    let corps = std::format!(r#"{{"invitation":"{jeton}","publicKey":"BAECAwQ"}}"#);
    let champs = champs_d_enrolement();
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let session = une_session();
    let tour = session.request(&tete, corps.as_bytes(), MAINTENANT, &mut place);
    assert_eq!(tour.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(tour.next(), Next::Respond);
}

/// **TOUT CE QUI NE S'ENRÔLE PAS SE REFUSE PAREIL.**
///
/// Une invitation forgée, une invitation expirée, un corps sans invitation, un
/// corps sans clef : les distinguer dirait à qui essaie jusqu'où il est allé —
/// et une invitation EXPIRÉE distinguée apprendrait qu'elle a existé, donc que
/// ce compte a été invité.
#[test]
fn tout_ce_qui_ne_s_enrole_pas_se_refuse_pareil() {
    // **DÉJÀ MORTE À L'INSTANT OÙ ON LA LIT** : `maintenant >= expiry` refuse.
    let expiree = une_invitation("marc", MAINTENANT);
    let bonne = une_invitation("marc", MAINTENANT + HEURE);
    let cas: std::vec::Vec<std::string::String> = std::vec![
        // Forgée : un sceau qui n'est pas le nôtre.
        std::string::String::from(
            r#"{"invitation":"AAAAAAAAAAAAAAAAAAAAAA","publicKey":"BAECAwQ"}"#
        ),
        // Authentique, et son heure est passée.
        std::format!(r#"{{"invitation":"{expiree}","publicKey":"BAECAwQ"}}"#),
        // Pas d'invitation du tout.
        std::string::String::from(r#"{"publicKey":"BAECAwQ"}"#),
        // Pas de clef.
        std::format!(r#"{{"invitation":"{bonne}"}}"#),
        // Un corps qui n'est pas du JSON.
        std::string::String::from("pas du json"),
    ];
    for corps in &cas {
        let champs = champs_d_enrolement();
        let tete = entete(&champs);
        let mut place = [0_u8; PLACE];
        let session = une_session();
        let tour = session.request(&tete, corps.as_bytes(), MAINTENANT, &mut place);
        assert_eq!(
            tour.status(),
            StatusCode::UNAUTHORIZED,
            "« {corps} » n'a pas été refusé pareil"
        );
    }
}

/// **UNE INVITATION AUTHENTIQUE CESSE DE VALOIR À SON HEURE**, et pas avant.
#[test]
fn une_invitation_vaut_jusqu_a_son_heure() {
    let invitation = une_invitation("marc", MAINTENANT + HEURE);
    let corps = std::format!(r#"{{"invitation":"{invitation}","publicKey":"BAECAwQ"}}"#);

    let champs = champs_d_enrolement();
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    assert!(
        matches!(
            une_session()
                .request(&tete, corps.as_bytes(), MAINTENANT + HEURE - 1, &mut place)
                .next(),
            Next::Enrol { .. }
        ),
        "une microseconde avant, elle vaut encore"
    );

    let champs = champs_d_enrolement();
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    assert_eq!(
        une_session()
            .request(&tete, corps.as_bytes(), MAINTENANT + HEURE, &mut place)
            .status(),
        StatusCode::UNAUTHORIZED,
        "à l'heure exacte, elle ne vaut DÉJÀ plus"
    );
}

/// **L'ENRÔLEMENT GARDE SON VERBE ET SON TYPE**, comme l'autre porte publique.
#[test]
fn l_enrolement_garde_son_verbe_et_son_type() {
    let champs = std::vec![
        (&b":method"[..], &b"GET"[..]),
        (&b":scheme"[..], &b"https"[..]),
        (&b":authority"[..], &b"exemple.fr"[..]),
        (&b":path"[..], &b"/v1/devices"[..]),
    ];
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    assert_eq!(
        une_session()
            .request(&tete, &[], MAINTENANT, &mut place)
            .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );

    let invitation = une_invitation("marc", MAINTENANT + HEURE);
    let corps = std::format!(r#"{{"invitation":"{invitation}","publicKey":"BAECAwQ"}}"#);
    let champs = std::vec![
        (&b":method"[..], &b"POST"[..]),
        (&b":scheme"[..], &b"https"[..]),
        (&b":authority"[..], &b"exemple.fr"[..]),
        (&b":path"[..], &b"/v1/devices"[..]),
        (&b"content-type"[..], &b"message/rfc822"[..]),
    ];
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    assert_eq!(
        une_session()
            .request(&tete, corps.as_bytes(), MAINTENANT, &mut place)
            .status(),
        StatusCode::BAD_REQUEST
    );
}

/// **UN CHAMP INCONNU DANS UN CORPS D'ENRÔLEMENT EST IGNORÉ**, et n'empêche pas
/// l'enrôlement.
///
/// # POURQUOI ICI ON TOLÈRE, ET DANS LA DEMANDE D'INVITATION ON REFUSE
///
/// Ce ne sont pas les mêmes appelants. La demande d'invitation vient de
/// l'exploitant, d'un seul outil : y refuser `minute` pour `minutes` lui dit
/// qu'on ne l'a pas écouté, ce qu'il doit savoir.
///
/// **CE CORPS-CI VIENT DE CINQ APPLICATIONS NATIVES**, qui ne se mettent pas à
/// jour le même jour que le serveur. Un champ qu'une version plus récente
/// ajouterait ferait refuser tout enrôlement par un serveur plus ancien — alors
/// que les champs dont il a besoin sont là. Ce qui manque se voit autrement :
/// une invitation ou une clef absente refuse, puisqu'on les exige.
#[test]
fn un_champ_inconnu_n_empeche_pas_un_enrolement() {
    let invitation = une_invitation("marc", MAINTENANT + HEURE);
    let corps = std::format!(
        r#"{{"attestation":"d'une version future","invitation":"{invitation}","publicKey":"BAECAwQ"}}"#
    );
    let champs = champs_d_enrolement();
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let session = une_session();
    assert_eq!(
        session
            .request(&tete, corps.as_bytes(), MAINTENANT, &mut place)
            .next(),
        Next::Enrol {
            account: "marc",
            public_key: "BAECAwQ",
            name: "",
        }
    );
}

/// **UN NOM ÉCHAPPÉ S'ENRÔLE, ET C'EST UN PIÈGE RÉEL QUI L'A IMPOSÉ.**
///
/// # CE QUI A CHANGÉ, ET POURQUOI
///
/// La première écriture refusait toute chaîne échappée : déséchapper demandait
/// un tampon que cette session n'avait pas. C'était juste pour l'invitation et
/// la clef — leur alphabet est celui de §5 de RFC 4648, qui ne contient rien
/// qu'on échappe.
///
/// **POUR LE NOM, C'ÉTAIT UN PIÈGE D'INTEROPÉRABILITÉ.** Beaucoup d'encodeurs
/// JSON échappent le non-ASCII PAR DÉFAUT — celui de Python le premier — et un
/// appareil nommé « Téléphone de Renée » partait alors en
/// `T\u00e9l\u00e9phone`. L'enrôlement échouait avec un `401` qui n'expliquait
/// rien, et les cinq applications natives l'auraient rencontré.
///
/// Le nom a donc sa place à part dans le tampon de sortie, et se déséchappe.
#[test]
fn un_nom_echappe_s_enrole() {
    let invitation = une_invitation("marc", MAINTENANT + HEURE);
    let corps = std::format!(
        r#"{{"invitation":"{invitation}","publicKey":"BAECAwQ","name":"T\u00e9l\u00e9phone de Ren\u00e9e"}}"#
    );
    let champs = champs_d_enrolement();
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let session = une_session();
    assert_eq!(
        session
            .request(&tete, corps.as_bytes(), MAINTENANT, &mut place)
            .next(),
        Next::Enrol {
            account: "marc",
            public_key: "BAECAwQ",
            name: "Téléphone de Renée",
        },
        "un nom échappé doit arriver DÉSÉCHAPPÉ"
    );
}

/// **UN NOM PLUS LONG QUE LA BORNE SE REFUSE ICI**, et non au magasin.
///
/// Le refuser plus loin ferait consommer l'invitation pour rien : le magasin
/// n'est atteint qu'après, et une invitation ne vaut qu'une fois.
#[test]
fn un_nom_trop_long_ne_s_enrole_pas() {
    let invitation = une_invitation("marc", MAINTENANT + HEURE);
    let trop: std::string::String =
        core::iter::repeat_n('x', super::NOM_D_APPAREIL_MAX + 1).collect();
    let corps =
        std::format!(r#"{{"invitation":"{invitation}","publicKey":"BAECAwQ","name":"{trop}"}}"#);
    let champs = champs_d_enrolement();
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let session = une_session();
    assert_eq!(
        session
            .request(&tete, corps.as_bytes(), MAINTENANT, &mut place)
            .status(),
        StatusCode::BAD_REQUEST
    );

    // **ET À LA BORNE EXACTE, CELA PASSE.**
    let juste: std::string::String = core::iter::repeat_n('x', super::NOM_D_APPAREIL_MAX).collect();
    let corps =
        std::format!(r#"{{"invitation":"{invitation}","publicKey":"BAECAwQ","name":"{juste}"}}"#);
    let champs = champs_d_enrolement();
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let session = une_session();
    assert!(matches!(
        session
            .request(&tete, corps.as_bytes(), MAINTENANT, &mut place)
            .next(),
        Next::Enrol { .. }
    ));
}

/// **UN NOM EN UTF-8 LITTÉRAL PASSE**, lui : c'est la moitié de la règle
/// ci-dessus, et sans elle un appareil nommé « Téléphone de Renée » serait
/// refusé.
#[test]
fn un_nom_accentue_s_enrole() {
    let invitation = une_invitation("marc", MAINTENANT + HEURE);
    let corps = std::format!(
        r#"{{"invitation":"{invitation}","publicKey":"BAECAwQ","name":"Téléphone de Renée"}}"#
    );
    let champs = champs_d_enrolement();
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let session = une_session();
    assert_eq!(
        session
            .request(&tete, corps.as_bytes(), MAINTENANT, &mut place)
            .next(),
        Next::Enrol {
            account: "marc",
            public_key: "BAECAwQ",
            name: "Téléphone de Renée",
        }
    );
}

/// Une session qui connaît son domaine — sans lui, les sessions par clef ne
/// sont pas servies.
fn une_session_avec_domaine() -> Http {
    une_session().avec_domaine(b"mail.exemple.fr")
}

/// Les champs d'une requête vers cette route.
fn champs_vers(chemin: &[u8]) -> std::vec::Vec<(&[u8], &[u8])> {
    std::vec![
        (&b":method"[..], &b"POST"[..]),
        (&b":scheme"[..], &b"https"[..]),
        (&b":authority"[..], &b"exemple.fr"[..]),
        (&b":path"[..], chemin),
        (&b"content-type"[..], &b"application/json"[..]),
    ]
}

/// **UN DÉFI S'ÉMET SANS RIEN CONSULTER, ET POUR N'IMPORTE QUI.**
///
/// Cette session n'a pas le magasin : elle ne peut pas savoir si cet appareil
/// existe, et c'est précisément ce qui rend l'énumération impossible par
/// construction.
#[test]
fn un_defi_s_emet_pour_n_importe_quel_appareil() {
    let champs = champs_vers(b"/v1/sessions/challenge");
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let session = une_session_avec_domaine();
    let tour = session.request(
        &tete,
        br#"{"login":"marc","deviceId":"appareil-inconnu"}"#,
        MAINTENANT,
        &mut place,
    );
    assert_eq!(tour.status(), StatusCode::CREATED);
    assert_eq!(tour.next(), Next::Respond);

    let dit = std::str::from_utf8(tour.body()).expect("utf8");
    assert!(dit.contains("\"challenge\":\""), "{dit}");
    assert!(dit.contains("\"role\":\"ams-session\""), "{dit}");
    assert!(
        dit.contains("\"serverIdentity\":\"mail.exemple.fr\""),
        "le client ne doit pas avoir à deviner le domaine : {dit}"
    );
    assert!(dit.contains("\"expiresInSeconds\":60"), "{dit}");
}

/// **SANS DOMAINE, LES SESSIONS PAR CLEF NE SONT PAS SERVIES.**
///
/// Un défi lié à un domaine vide serait un défi que deux serveurs partageraient,
/// et une signature obtenue chez l'un vaudrait chez l'autre. Mieux vaut `501`.
#[test]
fn sans_domaine_les_sessions_par_clef_ne_se_servent_pas() {
    let session = une_session();
    for (chemin, corps) in [
        (
            &b"/v1/sessions/challenge"[..],
            &br#"{"login":"marc","deviceId":"a1"}"#[..],
        ),
        (
            &b"/v1/sessions"[..],
            &br#"{"challenge":"AAAA","signature":"AAAA"}"#[..],
        ),
    ] {
        let champs = champs_vers(chemin);
        let tete = entete(&champs);
        let mut place = [0_u8; PLACE];
        let tour = session.request(&tete, corps, MAINTENANT, &mut place);
        assert_eq!(
            tour.status(),
            StatusCode::NOT_IMPLEMENTED,
            "{}",
            std::str::from_utf8(chemin).expect("utf8")
        );

        // **LE DOCUMENT EST CELUI DU VOCABULAIRE, ET CET ESSAI LE LIE.**
        //
        // Le banc de fuzz vérifie qu'un refus écrit l'un des documents connus,
        // et sa liste est tenue à la main. Un motif devenu joignable sans y
        // figurer ne se voit qu'en campagne, au hasard d'une entrée — et
        // l'intégration continue l'a trouvé là où la machine de développement
        // ne l'avait pas. Cet essai-ci le dit à chaque `cargo test`.
        let mut attendu = [0_u8; 256];
        assert_eq!(
            tour.body(),
            ams_api::problem(ams_api::Reason::NotImplemented, &mut attendu).expect("écrivable"),
            "le 501 doit écrire le document de `NotImplemented`"
        );
    }
}

/// **UN DÉFI VÉRIFIÉ DEMANDE À L'APPELANT DE JUGER LA SIGNATURE.**
///
/// La session ne peut pas la juger : elle n'a ni le magasin, ni la clef
/// publique. Elle vérifie le SCEAU, en tire le compte et l'appareil, et passe.
#[test]
fn un_defi_verifie_demande_la_signature_a_l_appelant() {
    let session = une_session_avec_domaine();

    // On obtient d'abord un vrai défi de cette session.
    let champs = champs_vers(b"/v1/sessions/challenge");
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let tour = session.request(
        &tete,
        br#"{"login":"marc","deviceId":"a1b2"}"#,
        MAINTENANT,
        &mut place,
    );
    let dit = std::string::String::from(std::str::from_utf8(tour.body()).expect("utf8"));
    let defi = dit
        .split_once("\"challenge\":\"")
        .and_then(|(_, reste)| reste.split_once('"'))
        .map(|(texte, _)| std::string::String::from(texte))
        .expect("un défi");

    let corps = std::format!(r#"{{"challenge":"{defi}","signature":"AQID"}}"#);
    let champs = champs_vers(b"/v1/sessions");
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let session = une_session_avec_domaine();
    let tour = session.request(&tete, corps.as_bytes(), MAINTENANT, &mut place);
    assert_eq!(
        tour.next(),
        Next::CheckDevice {
            account: "marc",
            device: "a1b2",
            issued_at_ms: MAINTENANT / 1_000,
            challenge: &defi,
            signature: "AQID",
        }
    );
}

/// **UN DÉFI EXPIRÉ SE DIT DISTINCTEMENT D'UN DÉFI FORGÉ.**
///
/// Le tableau des risques l'exige : une horloge de client qui dérive produirait
/// sinon des échecs que personne ne sait expliquer. Et cela n'apprend rien à qui
/// forge — on n'atteint cette réponse qu'après un sceau valide.
#[test]
fn un_defi_expire_se_distingue_d_un_defi_forge() {
    let session = une_session_avec_domaine();
    let champs = champs_vers(b"/v1/sessions/challenge");
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let tour = session.request(
        &tete,
        br#"{"login":"marc","deviceId":"a1"}"#,
        MAINTENANT,
        &mut place,
    );
    let dit = std::string::String::from(std::str::from_utf8(tour.body()).expect("utf8"));
    let defi = dit
        .split_once("\"challenge\":\"")
        .and_then(|(_, reste)| reste.split_once('"'))
        .map(|(texte, _)| std::string::String::from(texte))
        .expect("un défi");

    // Soixante secondes plus tard, à la seconde exacte.
    let corps = std::format!(r#"{{"challenge":"{defi}","signature":"AQID"}}"#);
    let champs = champs_vers(b"/v1/sessions");
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let session = une_session_avec_domaine();
    let tour = session.request(
        &tete,
        corps.as_bytes(),
        MAINTENANT + 60 * 1_000_000,
        &mut place,
    );
    assert_eq!(tour.status(), StatusCode::UNAUTHORIZED);
    let document = std::str::from_utf8(tour.body()).expect("utf8");
    assert!(
        document.contains("l'authentification a expiré"),
        "un défi expiré doit se dire : {document}"
    );

    // Un défi forgé, lui, ne dit rien de plus que « irrecevable ».
    let champs = champs_vers(b"/v1/sessions");
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let session = une_session_avec_domaine();
    let tour = session.request(
        &tete,
        br#"{"challenge":"AAAAAAAAAAAAAAAAAAAAAA","signature":"AQID"}"#,
        MAINTENANT,
        &mut place,
    );
    assert_eq!(tour.status(), StatusCode::UNAUTHORIZED);
    let document = std::str::from_utf8(tour.body()).expect("utf8");
    assert!(
        document.contains("n'est pas recevable"),
        "un défi forgé ne doit rien dire de plus : {document}"
    );
}

/// **TOUT CE QUI N'EST PAS UNE DEMANDE SE REFUSE.**
#[test]
fn les_corps_irrecevables_des_sessions_se_refusent() {
    let session = une_session_avec_domaine();
    for (chemin, corps) in [
        (&b"/v1/sessions/challenge"[..], &b"{}"[..]),
        (&b"/v1/sessions/challenge"[..], br#"{"login":"marc"}"#),
        (&b"/v1/sessions/challenge"[..], br#"{"deviceId":"a1"}"#),
        (
            &b"/v1/sessions/challenge"[..],
            br#"{"login":"","deviceId":"a1"}"#,
        ),
        (
            &b"/v1/sessions/challenge"[..],
            br#"{"login":"marc","inconnu":1}"#,
        ),
        (&b"/v1/sessions/challenge"[..], b"pas du json"),
        (&b"/v1/sessions"[..], &b"{}"[..]),
        (&b"/v1/sessions"[..], br#"{"challenge":"AAAA"}"#),
        (&b"/v1/sessions"[..], br#"{"signature":"AAAA"}"#),
        (&b"/v1/sessions"[..], b"pas du json"),
    ] {
        let champs = champs_vers(chemin);
        let tete = entete(&champs);
        let mut place = [0_u8; PLACE];
        let tour = session.request(&tete, corps, MAINTENANT, &mut place);
        assert!(
            tour.status().class() >= 4,
            "« {} » sur {} a été accepté",
            std::string::String::from_utf8_lossy(corps),
            std::str::from_utf8(chemin).expect("utf8")
        );
    }
}

/// **UN DOMAINE IRRECEVABLE EST IGNORÉ, ET NON TRONQUÉ.**
///
/// Un domaine tronqué donnerait un condensat qu'aucun client ne saurait
/// reproduire : toutes les sessions par clef échoueraient, et rien ne dirait
/// pourquoi. L'ignorer laisse la route répondre `501`, ce qui se comprend.
#[test]
fn un_domaine_irrecevable_est_ignore() {
    let trop_long: std::vec::Vec<u8> = std::vec![b'x'; super::DOMAINE_MAX + 1];
    for domaine in [&b""[..], &trop_long] {
        let session = une_session().avec_domaine(domaine);
        let champs = champs_vers(b"/v1/sessions/challenge");
        let tete = entete(&champs);
        let mut place = [0_u8; PLACE];
        assert_eq!(
            session
                .request(
                    &tete,
                    br#"{"login":"marc","deviceId":"a1"}"#,
                    MAINTENANT,
                    &mut place
                )
                .status(),
            StatusCode::NOT_IMPLEMENTED,
            "domaine de {} octets",
            domaine.len()
        );
    }

    // **ET À LA BORNE EXACTE, CELA PASSE** : une borne inatteignable est mal
    // écrite.
    let juste: std::vec::Vec<u8> = std::vec![b'x'; super::DOMAINE_MAX];
    let session = une_session().avec_domaine(&juste);
    let champs = champs_vers(b"/v1/sessions/challenge");
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    assert_eq!(
        session
            .request(
                &tete,
                br#"{"login":"marc","deviceId":"a1"}"#,
                MAINTENANT,
                &mut place
            )
            .status(),
        StatusCode::CREATED
    );
}

/// **UN TAMPON TROP COURT POUR UN DÉFI EST NOTRE FAUTE**, et se dit `500`.
///
/// Toutes les tailles jusqu'à la bonne : c'est ce qui met en jeu chacune des
/// écritures du chemin, plutôt que la première qui échoue. Et rien ne doit
/// paniquer — un tampon trop court est une faute de configuration, pas un
/// effondrement.
#[test]
fn un_tampon_trop_court_pour_un_defi_est_notre_faute() {
    let session = une_session_avec_domaine();
    let champs = champs_vers(b"/v1/sessions/challenge");

    let entier = {
        let tete = entete(&champs);
        let mut place = [0_u8; PLACE];
        session
            .request(
                &tete,
                br#"{"login":"marc","deviceId":"a1"}"#,
                MAINTENANT,
                &mut place,
            )
            .body()
            .len()
    };
    assert!(entier > 0, "un défi doit écrire quelque chose");

    let mut vu_un_cinq_cents = false;
    for taille in 0..PLACE {
        let tete = entete(&champs);
        let mut petit = std::vec![0_u8; taille];
        let tour = session.request(
            &tete,
            br#"{"login":"marc","deviceId":"a1"}"#,
            MAINTENANT,
            &mut petit,
        );
        if tour.status() == StatusCode::INTERNAL_SERVER_ERROR {
            vu_un_cinq_cents = true;
            assert!(
                tour.body().is_empty(),
                "on ne peut plus écrire dans le tampon qui manque"
            );
        }
    }
    assert!(
        vu_un_cinq_cents,
        "aucune taille n'a mis le chemin d'écriture en défaut"
    );
}

/// **UN DÉFI AUX BORNES SE DÉCHIFFRE**, et c'est un défaut réel qui impose cet
/// essai.
///
/// # CE QUE LA PRODUCTION A TROUVÉ ET QUE LES ESSAIS AVAIENT MANQUÉ
///
/// La place où la session déchiffre ce qu'on lui présente valait la taille d'un
/// JETON. Un défi est plus gros — il porte DEUX noms, le compte et l'appareil —
/// et son déchiffrage échouait donc par manque de place : `500` à toute
/// ouverture de session par clef.
///
/// **L'ESSAI DE BOUT EN BOUT NE L'A PAS VU** parce que son compte s'appelle
/// `marie` : le total tombait à trois octets sous la borne. En production, avec
/// un compte de seize caractères, il la dépassait de huit. Un essai qui passe
/// par la longueur de ses données d'épreuve ne prouve rien.
///
/// Celui-ci emploie donc les noms les plus longs que les bornes admettent.
#[test]
fn un_defi_aux_bornes_se_dechiffre() {
    let compte: std::string::String =
        core::iter::repeat_n('c', ams_api::LOGIN_OCTETS_MAX).collect();
    let appareil: std::string::String =
        core::iter::repeat_n('a', ams_api::CHALLENGE_ID_OCTETS_MAX).collect();

    let session = une_session_avec_domaine();
    let corps = std::format!(r#"{{"login":"{compte}","deviceId":"{appareil}"}}"#);
    let champs = champs_vers(b"/v1/sessions/challenge");
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let tour = session.request(&tete, corps.as_bytes(), MAINTENANT, &mut place);
    assert_eq!(tour.status(), StatusCode::CREATED, "le défi doit s'émettre");
    let dit = std::string::String::from(std::str::from_utf8(tour.body()).expect("utf8"));
    let defi = dit
        .split_once("\"challenge\":\"")
        .and_then(|(_, reste)| reste.split_once('"'))
        .map(|(texte, _)| std::string::String::from(texte))
        .expect("un défi");

    // **ET IL SE RELIT** : c'est ici que la place manquait.
    let reponse = std::format!(r#"{{"challenge":"{defi}","signature":"AQID"}}"#);
    let champs = champs_vers(b"/v1/sessions");
    let tete = entete(&champs);
    let mut place = [0_u8; PLACE];
    let session = une_session_avec_domaine();
    let tour = session.request(&tete, reponse.as_bytes(), MAINTENANT, &mut place);
    assert_eq!(
        tour.next(),
        Next::CheckDevice {
            account: &compte,
            device: &appareil,
            issued_at_ms: MAINTENANT / 1_000,
            challenge: &defi,
            signature: "AQID",
        },
        "un défi aux bornes doit se déchiffrer, et non rendre 500"
    );
}

/// **L'INVITATION ET LA CLEF NE S'ACCEPTENT JAMAIS ÉCHAPPÉES**, contrairement au
/// nom.
///
/// # POURQUOI LA RÈGLE DIFFÈRE D'UN CHAMP À L'AUTRE
///
/// Leur alphabet est celui de §5 de RFC 4648 — lettres, chiffres, tiret et
/// souligné — et **aucun encodeur JSON n'échappe rien de cela**. Une invitation
/// échappée n'est donc jamais l'œuvre d'un client honnête : c'est une écriture
/// de plus pour désigner la même chose, et ce dépôt refuse partout qu'une chose
/// ait deux écritures.
///
/// Le NOM est l'inverse : il porte du texte humain, et beaucoup d'encodeurs y
/// échappent le non-ASCII par défaut. Le refuser aurait fait échouer tout
/// appareil au nom accentué.
#[test]
fn ni_l_invitation_ni_la_clef_ne_s_acceptent_echappees() {
    let invitation = une_invitation("marc", MAINTENANT + HEURE);
    // La MÊME chaîne, écrite deux fois : dans l'invitation chaque `A`
    // devient `\u0041`, et la clef `BAECAwQ` s'écrit `BAECAw\u0051`.
    let cas = [
        std::format!(
            r#"{{"invitation":"{}","publicKey":"BAECAwQ"}}"#,
            invitation.replace('A', "\\u0041")
        ),
        std::format!(r#"{{"invitation":"{invitation}","publicKey":"BAECAw\u0051"}}"#),
    ];
    for corps in &cas {
        let champs = champs_d_enrolement();
        let tete = entete(&champs);
        let mut place = [0_u8; PLACE];
        let session = une_session();
        let tour = session.request(&tete, corps.as_bytes(), MAINTENANT, &mut place);
        assert_eq!(
            tour.status(),
            StatusCode::UNAUTHORIZED,
            "une écriture échappée est passée : {corps}"
        );
        assert_eq!(tour.next(), Next::Respond);
    }
}

/// **L'USAGE DEMANDÉ CHOISIT LE RÔLE QUE LE SERVEUR ANNONCE.**
///
/// Le défi, lui, ne change pas : le rôle n'est pas dans le sceau, il entre dans
/// le CONDENSAT que l'appareil signera. C'est ce qui sépare « ouvrir une boîte »
/// de « approuver un appairage » sans qu'il existe deux sortes de défis.
#[test]
fn l_usage_demande_choisit_le_role_annonce() {
    let session = une_session_avec_domaine();
    for (usage, attendu) in [("session", "ams-session"), ("pairing", "ams-pairing")] {
        let corps = std::format!(r#"{{"login":"marc","deviceId":"a1","purpose":"{usage}"}}"#);
        let champs = champs_vers(b"/v1/sessions/challenge");
        let tete = entete(&champs);
        let mut place = [0_u8; PLACE];
        let tour = session.request(&tete, corps.as_bytes(), MAINTENANT, &mut place);
        assert_eq!(tour.status(), StatusCode::CREATED, "{usage}");
        let dit = std::str::from_utf8(tour.body()).expect("utf8");
        assert!(
            dit.contains(&std::format!("\"role\":\"{attendu}\"")),
            "usage `{usage}` : {dit}"
        );
    }

    // **LE DÉFI EST LE MÊME DANS LES DEUX CAS**, et c'est voulu : ce qui
    // distingue les deux gestes est la signature, pas le scellé.
    let lire_le_defi = |usage: &str| -> std::string::String {
        let corps = std::format!(r#"{{"login":"marc","deviceId":"a1","purpose":"{usage}"}}"#);
        let champs = champs_vers(b"/v1/sessions/challenge");
        let tete = entete(&champs);
        let mut place = [0_u8; PLACE];
        let tour = session.request(&tete, corps.as_bytes(), MAINTENANT, &mut place);
        let dit = std::string::String::from(std::str::from_utf8(tour.body()).expect("utf8"));
        dit.split_once("\"challenge\":\"")
            .and_then(|(_, reste)| reste.split_once('"'))
            .map(|(texte, _)| std::string::String::from(texte))
            .expect("un défi")
    };
    assert_eq!(lire_le_defi("session"), lire_le_defi("pairing"));
}
