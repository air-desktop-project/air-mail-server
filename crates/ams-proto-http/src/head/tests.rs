// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une liste de champs a le droit d'être.

use super::{FIELDS_MAX, HeadBuilder, RequestHead};
use crate::{Error, Limits, Method};

const BORNES: Limits = Limits::DEFAULT;

/// Une requête bien formée, la plus simple.
const MINIMALE: [(&[u8], &[u8]); 4] = [
    (b":method", b"GET"),
    (b":scheme", b"https"),
    (b":authority", b"mail.example.com"),
    (b":path", b"/etat"),
];

/// Monte une requête depuis une liste de paires.
fn lire<'a>(champs: &[(&'a [u8], &'a [u8])]) -> Result<RequestHead<'a>, Error> {
    let mut accumule = HeadBuilder::new(&BORNES);
    for (nom, valeur) in champs {
        accumule.field(nom, valeur)?;
    }
    accumule.finish()
}

/// La même, avec des champs ordinaires en plus.
fn avec<'a>(suite: &[(&'a [u8], &'a [u8])]) -> Result<RequestHead<'a>, Error> {
    let mut champs = std::vec::Vec::from(&MINIMALE[..]);
    champs.extend_from_slice(suite);
    lire(&champs)
}

/// Ce qu'une liste refuse. **UNE REQUÊTE NE SE COMPARE PAS** — elle porte des
/// tranches empruntées, et l'égalité qu'on en tirerait n'aurait pas de sens.
fn faute(champs: &[(&[u8], &[u8])]) -> Option<Error> {
    lire(champs).err()
}

/// Ce que la liste minimale refuse, une fois augmentée.
fn faute_avec(suite: &[(&[u8], &[u8])]) -> Option<Error> {
    avec(suite).err()
}

/// Une requête bien formée se lit, et rend ce qu'elle porte.
#[test]
fn une_requete_bien_formee_se_lit() {
    let lue = avec(&[
        (b"accept", b"application/json"),
        (b"authorization", b"Bearer jeton"),
    ])
    .expect("recevable");
    assert_eq!(lue.method(), Method::Get);
    assert_eq!(lue.scheme(), b"https");
    assert_eq!(lue.authority(), b"mail.example.com");
    assert_eq!(lue.path(), b"/etat");
    assert_eq!(lue.fields().len(), 2);
    assert_eq!(lue.field(b"accept"), Some(&b"application/json"[..]));
    assert_eq!(lue.field(b"absent"), None);
    assert_eq!(lue.content_length(), None);
}

/// **LA PREMIÈRE VALEUR, ET NON LA DERNIÈRE** : prendre la dernière laisserait
/// un client remplacer ce qu'un intermédiaire a posé devant.
#[test]
fn un_champ_repete_rend_sa_premiere_valeur() {
    let lue = avec(&[(b"accept", b"un"), (b"accept", b"deux")]).expect("recevable");
    assert_eq!(lue.field(b"accept"), Some(&b"un"[..]));
    assert_eq!(lue.fields().len(), 2, "les deux sont retenus");
}

/// **LES PSEUDO-EN-TÊTES VIENNENT TOUS EN TÊTE** (§8.3). L'ordre n'est pas une
/// convention de présentation : c'est ce qui permet de décider qu'une liste est
/// complète sans l'avoir lue en entier.
#[test]
fn un_pseudo_apres_un_champ_est_une_faute() {
    let champs: [(&[u8], &[u8]); 5] = [
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", b"x.test"),
        (b"accept", b"*/*"),
        (b":path", b"/"),
    ];
    assert_eq!(faute(&champs), Some(Error::PseudoAfterField));
}

/// Chaque pseudo-en-tête ne paraît qu'une fois.
#[test]
fn un_pseudo_repete_est_une_faute() {
    for suite in [
        (&b":method"[..], &b"POST"[..]),
        (b":scheme", b"http"),
        (b":authority", b"y.test"),
        (b":path", b"/autre"),
    ] {
        let mut champs = std::vec::Vec::from(&MINIMALE[..]);
        champs.insert(0, suite);
        assert_eq!(faute(&champs), Some(Error::DuplicatePseudo), "{suite:?}");
    }
}

/// **LA LISTE DES PSEUDO-EN-TÊTES DE REQUÊTE EST FERMÉE** : un intermédiaire qui
/// ignorerait un nom inventé et un serveur qui l'honorerait ne verraient pas la
/// même requête.
#[test]
fn un_pseudo_inconnu_est_une_faute() {
    for nom in [&b":status"[..], b":protocol", b":chose", b":a"] {
        let mut champs = std::vec::Vec::from(&MINIMALE[..]);
        champs.insert(0, (nom, b"x"));
        assert_eq!(faute(&champs), Some(Error::UnknownPseudo), "{nom:?}");
    }
}

/// Il faut `:method`, `:scheme`, `:path` — et une autorité.
#[test]
fn un_pseudo_obligatoire_qui_manque_est_une_faute() {
    for retire in 0..MINIMALE.len() {
        let champs: std::vec::Vec<_> = MINIMALE
            .iter()
            .enumerate()
            .filter(|(rang, _)| *rang != retire)
            .map(|(_, paire)| *paire)
            .collect();
        assert_eq!(faute(&champs), Some(Error::MissingPseudo), "sans {retire}");
    }
    // Une autorité VIDE n'en est pas une.
    let champs: [(&[u8], &[u8]); 4] = [
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", b""),
        (b":path", b"/"),
    ];
    assert_eq!(faute(&champs), Some(Error::MissingPseudo));
}

/// **`host` REMPLACE `:authority` QUAND IL MANQUE** (§8.3.1), et les deux
/// ensemble doivent dire la même chose : deux autorités, c'est deux serveurs
/// d'origine possibles.
#[test]
fn host_supplee_l_autorite_mais_ne_la_contredit_pas() {
    let sans_pseudo: [(&[u8], &[u8]); 4] = [
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":path", b"/"),
        (b"host", b"mail.example.com"),
    ];
    let lue = lire(&sans_pseudo).expect("recevable");
    assert_eq!(lue.authority(), b"mail.example.com");

    let accord = avec(&[(b"host", b"mail.example.com")]).expect("recevable");
    assert_eq!(accord.authority(), b"mail.example.com");

    assert_eq!(
        faute_avec(&[(b"host", b"ailleurs.test")]),
        Some(Error::AuthorityMismatch)
    );
}

/// **`:path` NE PEUT PAS ÊTRE VIDE**, et `*` n'est licite que pour `OPTIONS` :
/// une cible en forme absolue serait une requête de mandataire.
#[test]
fn un_chemin_qu_on_ne_saurait_pas_router_est_une_faute() {
    for chemin in [
        &b""[..],
        b"*",
        b"etat",
        b"https://ailleurs.test/etat",
        b"//ailleurs.test/etat".get(..1).unwrap_or_default(),
    ] {
        let champs: [(&[u8], &[u8]); 4] = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"x.test"),
            (b":path", chemin),
        ];
        if chemin == b"/" {
            continue;
        }
        assert_eq!(faute(&champs), Some(Error::MalformedPath), "{chemin:?}");
    }
    // `*` passe pour `OPTIONS`, et pour elle seule.
    let etoile: [(&[u8], &[u8]); 4] = [
        (b":method", b"OPTIONS"),
        (b":scheme", b"https"),
        (b":authority", b"x.test"),
        (b":path", b"*"),
    ];
    assert_eq!(lire(&etoile).expect("recevable").path(), b"*");
}

/// **`CONNECT` ET `TRACE` SE REFUSENT DÈS LE PSEUDO-EN-TÊTE.**
#[test]
fn une_methode_qu_on_ne_sert_pas_est_une_faute() {
    for methode in [&b"CONNECT"[..], b"TRACE", b"get", b"BREW"] {
        let champs: [(&[u8], &[u8]); 4] = [
            (b":method", methode),
            (b":scheme", b"https"),
            (b":authority", b"x.test"),
            (b":path", b"/"),
        ];
        assert_eq!(
            faute(&champs),
            Some(Error::UnsupportedMethod),
            "{methode:?}"
        );
    }
}

/// Le schéma est un vocabulaire fermé ; que `http` soit acceptable sur une
/// connexion chiffrée est une question de POLITIQUE, tranchée plus haut.
#[test]
fn un_schema_qu_on_ne_sert_pas_est_une_faute() {
    for schema in [&b"ftp"[..], b"HTTPS", b"", b"https "] {
        let champs: [(&[u8], &[u8]); 4] = [
            (b":method", b"GET"),
            (b":scheme", schema),
            (b":authority", b"x.test"),
            (b":path", b"/"),
        ];
        assert!(
            matches!(
                lire(&champs),
                Err(Error::UnsupportedScheme | Error::MalformedFieldValue)
            ),
            "{schema:?}"
        );
    }
    let clair: [(&[u8], &[u8]); 4] = [
        (b":method", b"GET"),
        (b":scheme", b"http"),
        (b":authority", b"x.test"),
        (b":path", b"/"),
    ];
    assert_eq!(lire(&clair).expect("recevable").scheme(), b"http");
}

/// **LES CHAMPS PROPRES À LA CONNEXION SONT INTERDITS** (§8.2.2), et `te` ne
/// survit qu'avec `trailers`.
#[test]
fn un_champ_propre_a_la_connexion_est_une_faute() {
    for (nom, valeur) in [
        (&b"connection"[..], &b"close"[..]),
        (b"proxy-connection", b"keep-alive"),
        (b"keep-alive", b"timeout=5"),
        (b"transfer-encoding", b"chunked"),
        (b"upgrade", b"websocket"),
        (b"te", b"gzip"),
        (b"te", b"chunked"),
        (b"te", b""),
    ] {
        assert_eq!(
            faute_avec(&[(nom, valeur)]),
            Some(Error::ConnectionSpecificField),
            "{nom:?}: {valeur:?}"
        );
    }
    assert!(avec(&[(b"te", b"trailers")]).is_ok());
}

/// **DEUX `content-length` QUI SE CONTREDISENT, C'EST LA CONTREBANDE** ; deux
/// qui s'accordent sont licites.
#[test]
fn content_length_se_lit_et_ne_se_contredit_pas() {
    let lue = avec(&[(b"content-length", b"42")]).expect("recevable");
    assert_eq!(lue.content_length(), Some(42));

    let deux = avec(&[(b"content-length", b"42"), (b"content-length", b"42")])
        .expect("deux qui s'accordent");
    assert_eq!(deux.content_length(), Some(42));

    assert_eq!(
        faute_avec(&[(b"content-length", b"42"), (b"content-length", b"43")]),
        Some(Error::MalformedContentLength)
    );
}

/// **QUE DES CHIFFRES, ET AU MOINS UN.** Un analyseur indulgent lirait `+10`
/// comme dix là où le suivant y verrait une faute, et l'écart entre les deux est
/// la longueur d'une requête clandestine.
#[test]
fn une_longueur_qui_n_en_est_pas_une_se_refuse() {
    for valeur in [
        &b""[..],
        b"+10",
        b"-1",
        b"0x10",
        b"10 ",
        b" 10",
        b"1_0",
        b"dix",
        b"1,2",
        // Ce qui déborde un `u64` n'est pas un grand nombre.
        b"18446744073709551616",
        b"99999999999999999999999999",
    ] {
        assert!(
            matches!(
                avec(&[(b"content-length", valeur)]),
                Err(Error::MalformedContentLength | Error::MalformedFieldValue)
            ),
            "{valeur:?}"
        );
    }
    // La borne exacte passe.
    let max = avec(&[(b"content-length", b"18446744073709551615")]).expect("recevable");
    assert_eq!(max.content_length(), Some(u64::MAX));
    // Les zéros en tête aussi : §8.6 ne les interdit pas.
    assert_eq!(
        avec(&[(b"content-length", b"007")])
            .expect("recevable")
            .content_length(),
        Some(7)
    );
}

/// Un nom ou une valeur mal formés se refusent, et disent lequel.
#[test]
fn un_champ_mal_forme_se_refuse() {
    assert_eq!(
        faute_avec(&[(b"Accept", b"*/*")]),
        Some(Error::MalformedFieldName)
    );
    assert_eq!(faute_avec(&[(b"", b"x")]), Some(Error::MalformedFieldName));
    assert_eq!(
        faute_avec(&[(b"accept", b"a\r\nb")]),
        Some(Error::MalformedFieldValue)
    );
    assert_eq!(
        faute_avec(&[(b"accept", b" x")]),
        Some(Error::MalformedFieldValue)
    );
}

/// **LA BOMBE DE DÉCOMPRESSION S'ARRÊTE AU POIDS TOTAL**, pas au poids d'un
/// champ : mille champs vides tiennent en quelques octets sur le fil, et aucune
/// borne PAR CHAMP ne les arrête.
#[test]
fn le_poids_total_borne_la_liste() {
    let mut serrees = BORNES;
    // De quoi tenir trois champs vides — trente-trois octets chacun — et pas le
    // quatrième.
    serrees.max_header_list = 100;
    let mut accumule = HeadBuilder::new(&serrees);
    for rang in 0..3_usize {
        accumule
            .field(b"x", b"")
            .unwrap_or_else(|_| panic!("{rang}"));
    }
    assert_eq!(accumule.field(b"x", b""), Err(Error::FieldTooLong));

    // **LE POIDS SE COMPTE AVANT L'EXAMEN** : un champ fautif coûte ce qu'il
    // pèse, sans quoi une bombe faite de champs invalides passerait entre les
    // gouttes.
    let mut autre = HeadBuilder::new(&serrees);
    assert_eq!(
        autre.field(b"Majuscule", b""),
        Err(Error::MalformedFieldName)
    );
    let reste = std::vec![b'y'; 60];
    assert_eq!(autre.field(&reste, b""), Err(Error::FieldTooLong));
}

/// Les bornes par champ se disent aussi.
#[test]
fn un_champ_demesure_se_refuse() {
    let long = std::vec![b'a'; BORNES.max_field_name.saturating_add(1)];
    assert_eq!(faute_avec(&[(&long, b"x")]), Some(Error::FieldTooLong));

    let grosse = std::vec![b'a'; BORNES.max_field_value.saturating_add(1)];
    assert_eq!(
        faute_avec(&[(b"accept", &grosse)]),
        Some(Error::FieldTooLong)
    );

    let chemin = std::vec![b'/'; BORNES.max_path.saturating_add(1)];
    let champs: [(&[u8], &[u8]); 4] = [
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", b"x.test"),
        (b":path", &chemin),
    ];
    assert_eq!(faute(&champs), Some(Error::FieldTooLong));

    let hote = std::vec![b'a'; BORNES.max_authority.saturating_add(1)];
    let autre: [(&[u8], &[u8]); 4] = [
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", &hote),
        (b":path", b"/"),
    ];
    assert_eq!(faute(&autre), Some(Error::FieldTooLong));
}

/// **LA BORNE DE CONFIGURATION RESSERRE, LE TABLEAU A LE DERNIER MOT.**
#[test]
fn le_nombre_de_champs_est_borne_des_deux_cotes() {
    let mut serrees = BORNES;
    serrees.max_fields = 2;
    let mut accumule = HeadBuilder::new(&serrees);
    for (nom, valeur) in MINIMALE {
        accumule.field(nom, valeur).expect("les pseudo passent");
    }
    accumule.field(b"a", b"1").expect("premier");
    accumule.field(b"b", b"2").expect("second");
    assert_eq!(
        accumule.field(b"c", b"3"),
        Err(Error::TooManyFields { limit: 2 })
    );

    // Une borne de configuration plus large que le tableau ne l'élargit pas.
    let mut larges = BORNES;
    larges.max_fields = 10_000;
    larges.max_header_list = usize::MAX;
    let mut autre = HeadBuilder::new(&larges);
    for (nom, valeur) in MINIMALE {
        autre.field(nom, valeur).expect("les pseudo passent");
    }
    for _ in 0..FIELDS_MAX {
        autre.field(b"x", b"1").expect("dans le tableau");
    }
    assert_eq!(
        autre.field(b"x", b"1"),
        Err(Error::TooManyFields { limit: FIELDS_MAX })
    );
}

/// **ON NE MONTRE PAS LES VALEURS DES CHAMPS** : un `authorization` dans un
/// journal est un mot de passe dans un journal.
#[test]
fn le_debug_ne_montre_pas_les_valeurs() {
    let lue = avec(&[(b"authorization", b"Bearer secret")]).expect("recevable");
    let texte = std::format!("{lue:?}");
    assert!(!texte.contains("secret"), "{texte}");
    assert!(texte.contains("/etat"), "{texte}");
    assert!(texte.contains("fields: 1"), "{texte}");

    // Une autorité qui n'est pas de l'UTF-8 se montre par sa longueur.
    let brut: [(&[u8], &[u8]); 4] = [
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", b"\xff\xfe"),
        (b":path", b"/"),
    ];
    let opaque = lire(&brut).expect("recevable");
    assert!(std::format!("{opaque:?}").contains("<2 octets>"));
}

/// Chaque faute se dit, et le texte nomme ce qui cloche.
#[test]
fn chaque_faute_se_dit() {
    for (erreur, extrait) in [
        (Error::MalformedFieldName, "jeton"),
        (Error::MalformedFieldValue, "octet interdit"),
        (Error::ConnectionSpecificField, "connexion"),
        (Error::PseudoAfterField, "pseudo-en-tête après"),
        (Error::UnknownPseudo, "inconnu"),
        (Error::DuplicatePseudo, "répété"),
        (Error::MissingPseudo, "manque"),
        (Error::UnsupportedMethod, "méthode"),
        (Error::MalformedContentLength, "content-length"),
        (Error::UnsupportedScheme, "schéma"),
        (Error::MalformedPath, ":path"),
        (Error::AuthorityMismatch, "authority"),
        (Error::TooManyFields { limit: 3 }, "3 champs"),
        (Error::FieldTooLong, "dépasse"),
        (Error::BufferTooSmall { needed: 7 }, "7 octets"),
    ] {
        let texte = std::format!("{erreur}");
        assert!(texte.contains(extrait), "{erreur:?} : {texte}");
    }
}

/// Les bornes par défaut sont celles du produit, et `Default` les rend.
#[test]
fn les_bornes_par_defaut_sont_celles_du_produit() {
    assert_eq!(Limits::default(), Limits::DEFAULT);
    // LE TABLEAU A LE DERNIER MOT, et la borne par défaut ne prétend pas
    // l'élargir. `const` parce que les deux sont des constantes : l'écrire en
    // assertion ordinaire ferait un test que rien n'exécute.
    const { assert!(Limits::DEFAULT.max_fields <= FIELDS_MAX) };
    assert!(std::format!("{BORNES:?}").contains("max_field_name"));
}
