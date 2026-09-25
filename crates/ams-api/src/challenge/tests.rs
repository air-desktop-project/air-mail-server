// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un défi prouve, ce qu'il refuse, et ce qu'il lie.

use super::{
    CHALLENGE_OCTETS_MAX, Challenge, ENCODED_OCTETS_MAX, ID_OCTETS_MAX, LOGIN_OCTETS_MAX, ROLE,
    ROLE_APPAIRAGE, ROLES, VERSION, VIE_SECONDES, digest, issue, verify,
};
use crate::error::{Error, Reason};
use crate::token::Key;

/// Une clé d'épreuve, tirée d'octets FIXES.
fn clef() -> Key {
    Key::new(&[7_u8; 32]).expect("une clé valide")
}

/// Une heure d'épreuve, **en secondes** — l'unité du défi.
const MAINTENANT: u64 = 1_790_000_000;

/// Le domaine d'épreuve.
const DOMAINE: &[u8] = b"mail.example.com";

/// Écrit un défi, et rend son texte.
fn ecrire(login: &str, device: &str, instant: u64) -> std::string::String {
    use std::string::ToString as _;
    let mut place = [0_u8; ENCODED_OCTETS_MAX];
    issue(
        &clef(),
        &Challenge {
            login,
            device,
            issued_at_seconds: instant,
        },
        &mut place,
    )
    .expect("écrivable")
    .to_string()
}

/// Lit un défi, et rend ce qu'il dit ou la raison du refus.
fn lire(
    texte: &str,
    maintenant: u64,
) -> Result<(std::string::String, std::string::String, u64), Reason> {
    use std::string::ToString as _;
    let mut place = [0_u8; CHALLENGE_OCTETS_MAX];
    verify(&clef(), texte.as_bytes(), maintenant, &mut place)
        .map(|lu| {
            (
                lu.login.to_string(),
                lu.device.to_string(),
                lu.issued_at_seconds,
            )
        })
        .map_err(Error::reason)
}

/// **CE QUI EST SCELLÉ SE RELIT.**
#[test]
fn un_defi_fait_l_aller_retour() {
    let texte = ecrire("marie", "a1b2c3", MAINTENANT);
    assert_eq!(
        lire(&texte, MAINTENANT),
        Ok((
            std::string::String::from("marie"),
            std::string::String::from("a1b2c3"),
            MAINTENANT
        ))
    );
}

/// **LES TROIS VERSIONS DU DÉPÔT SONT DISTINCTES**, et c'est ce qui empêche de
/// présenter l'un des trois objets à la place d'un autre — ils partagent LA
/// MÊME CLÉ.
#[test]
fn les_trois_versions_sont_distinctes() {
    const { assert!(VERSION != crate::token::VERSION) }
    const { assert!(VERSION != crate::invitation::VERSION) }
    const { assert!(crate::token::VERSION != crate::invitation::VERSION) }
}

/// **NI UN JETON NI UNE INVITATION NE PASSENT POUR UN DÉFI.**
#[test]
fn ni_jeton_ni_invitation_ne_passent_pour_un_defi() {
    use std::string::ToString as _;

    let mut place = [0_u8; crate::token::ENCODED_OCTETS_MAX];
    let jeton = crate::token::issue(
        &clef(),
        &crate::token::Token {
            login: "marie",
            scope: crate::scope::Scope::none(),
            expiry: MAINTENANT * 1_000_000 + 3_600_000_000,
            nonce: 1,
        },
        MAINTENANT * 1_000_000,
        &mut place,
    )
    .expect("écrivable")
    .to_string();
    assert_eq!(lire(&jeton, MAINTENANT), Err(Reason::BadToken));

    let mut place = [0_u8; crate::invitation::ENCODED_OCTETS_MAX];
    let invitation = crate::invitation::issue(
        &clef(),
        &crate::invitation::Invitation {
            login: "marie",
            expiry: MAINTENANT * 1_000_000 + 3_600_000_000,
        },
        MAINTENANT * 1_000_000,
        &mut place,
    )
    .expect("écrivable")
    .to_string();
    assert_eq!(lire(&invitation, MAINTENANT), Err(Reason::BadToken));
}

/// **ET LE DÉFI NE PASSE POUR AUCUN DES DEUX.**
#[test]
fn un_defi_n_ouvre_ni_session_ni_enrolement() {
    let texte = ecrire("marie", "a1", MAINTENANT);

    let mut place = [0_u8; crate::token::TOKEN_OCTETS_MAX];
    assert_eq!(
        crate::token::verify(
            &clef(),
            texte.as_bytes(),
            MAINTENANT * 1_000_000,
            &mut place
        )
        .err()
        .map(Error::reason),
        Some(Reason::BadToken)
    );

    let mut place = [0_u8; crate::invitation::INVITATION_OCTETS_MAX];
    assert_eq!(
        crate::invitation::verify(
            &clef(),
            texte.as_bytes(),
            MAINTENANT * 1_000_000,
            &mut place
        )
        .err()
        .map(Error::reason),
        Some(Reason::BadToken)
    );
}

/// **UN DÉFI EXPIRÉ SE DIT COMME TEL, ET C'EST UNE EXIGENCE.**
///
/// Le tableau des risques de la feuille de route le demande nommément : une
/// horloge de client qui dérive produit sinon des échecs que personne ne sait
/// expliquer. Et cela n'apprend rien à qui forge — on n'atteint cette réponse
/// qu'après un sceau valide.
#[test]
fn un_defi_expire_se_dit_distinctement() {
    let texte = ecrire("marie", "a1", MAINTENANT);
    assert!(lire(&texte, MAINTENANT + VIE_SECONDES - 1).is_ok());
    assert_eq!(
        lire(&texte, MAINTENANT + VIE_SECONDES),
        Err(Reason::TokenExpired),
        "à la soixantième seconde exacte, il ne vaut DÉJÀ plus"
    );
    assert_eq!(lire(&texte, MAINTENANT + 3_600), Err(Reason::TokenExpired));
}

/// **UN DÉFI ÉMIS DANS LE FUTUR NE VAUT RIEN.**
///
/// C'est un défi qu'on n'a pas émis, ou une horloge qui a reculé. L'accepter le
/// ferait vivre bien au-delà de ses soixante secondes : il suffirait de le dater
/// d'un an en avant. **Le sceau ne protège pas de cela** — c'est le serveur qui
/// scelle, et un serveur dont l'horloge saute scellerait une date fausse.
#[test]
fn un_defi_venu_du_futur_ne_vaut_rien() {
    let texte = ecrire("marie", "a1", MAINTENANT + 1);
    assert_eq!(lire(&texte, MAINTENANT), Err(Reason::BadToken));
    // À la seconde exacte, il vaut.
    assert!(lire(&texte, MAINTENANT + 1).is_ok());
}

/// **UNE AUTRE CLÉ NE VÉRIFIE RIEN.**
#[test]
fn une_autre_cle_ne_verifie_rien() {
    let texte = ecrire("marie", "a1", MAINTENANT);
    let autre = Key::new(&[9_u8; 32]).expect("valide");
    let mut place = [0_u8; CHALLENGE_OCTETS_MAX];
    assert_eq!(
        verify(&autre, texte.as_bytes(), MAINTENANT, &mut place)
            .err()
            .map(Error::reason),
        Some(Reason::BadToken)
    );
}

/// **UN SEUL OCTET CHANGÉ SUFFIT À LE REFUSER** : le sceau couvre TOUT le clair
/// — version, instant, longueurs, compte et appareil.
#[test]
fn un_octet_change_suffit_a_le_refuser() {
    let texte = ecrire("marie", "a1b2", MAINTENANT);
    let sain = texte.as_bytes();
    let mut eprouves = 0_u32;
    for position in 0..sain.len() {
        for remplacant in *b"Az0-_" {
            let mut corrompu = sain.to_vec();
            let Some(place) = corrompu.get_mut(position) else {
                continue;
            };
            if *place == remplacant {
                continue;
            }
            *place = remplacant;
            let mut lecture = [0_u8; CHALLENGE_OCTETS_MAX];
            assert!(
                verify(&clef(), &corrompu, MAINTENANT, &mut lecture).is_err(),
                "la position {position} changée en `{}` est passée",
                char::from(remplacant)
            );
            eprouves = eprouves.saturating_add(1);
        }
    }
    assert!(eprouves > 0, "aucune corruption n'a été éprouvée");
}

/// **UN COMPTE OU UN APPAREIL IRRECEVABLE NE S'ÉMET PAS.**
#[test]
fn un_nom_irrecevable_ne_s_emet_pas() {
    let mut place = [0_u8; ENCODED_OCTETS_MAX];
    let long_login: std::string::String = core::iter::repeat_n('x', LOGIN_OCTETS_MAX + 1).collect();
    let long_device: std::string::String = core::iter::repeat_n('y', ID_OCTETS_MAX + 1).collect();
    for (login, device) in [
        ("", "a1"),
        ("marie", ""),
        (long_login.as_str(), "a1"),
        ("marie", long_device.as_str()),
    ] {
        assert_eq!(
            issue(
                &clef(),
                &Challenge {
                    login,
                    device,
                    issued_at_seconds: MAINTENANT,
                },
                &mut place,
            )
            .err()
            .map(Error::reason),
            Some(Reason::BadToken),
            "compte de {} octets, appareil de {} octets",
            login.len(),
            device.len()
        );
    }

    // **ET AUX BORNES EXACTES, CELA PASSE** : une borne inatteignable est mal
    // écrite.
    let juste_login: std::string::String = core::iter::repeat_n('x', LOGIN_OCTETS_MAX).collect();
    let juste_device: std::string::String = core::iter::repeat_n('y', ID_OCTETS_MAX).collect();
    let texte = {
        use std::string::ToString as _;
        issue(
            &clef(),
            &Challenge {
                login: &juste_login,
                device: &juste_device,
                issued_at_seconds: MAINTENANT,
            },
            &mut place,
        )
        .expect("écrivable")
        .to_string()
    };
    assert_eq!(
        lire(&texte, MAINTENANT),
        Ok((juste_login, juste_device, MAINTENANT))
    );
}

/// **DES LONGUEURS QUI MENTENT SE REFUSENT**, bien qu'elles soient scellées.
#[test]
fn des_longueurs_qui_mentent_se_refusent() {
    use ams_sasl::hmac_sha256;

    // On fabrique le clair à la main, puis on le scelle POUR DE VRAI : c'est le
    // seul moyen d'atteindre la lecture avec ce que l'émission refuserait.
    for (taille_login, taille_device) in [(9_u8, 2_u8), (5, 9), (0, 7), (5, 0), (255, 255)] {
        let mut clair = std::vec![VERSION];
        clair.extend_from_slice(&MAINTENANT.to_be_bytes());
        clair.push(taille_login);
        clair.push(taille_device);
        clair.extend_from_slice(b"mariea1");
        let sceau = hmac_sha256(&[7_u8; 32], &clair);
        let mut brut = clair.clone();
        brut.extend_from_slice(&sceau);

        let mut ecrit = [0_u8; ENCODED_OCTETS_MAX];
        let texte = crate::base64url::encode(&brut, &mut ecrit).expect("écrivable");
        let mut place = [0_u8; CHALLENGE_OCTETS_MAX];
        assert_eq!(
            verify(&clef(), texte, MAINTENANT, &mut place)
                .err()
                .map(Error::reason),
            Some(Reason::BadToken),
            "longueurs {taille_login} et {taille_device}"
        );
    }
}

/// **UN NOM HORS UTF-8 SE REFUSE**, même scellé.
#[test]
fn un_nom_hors_utf8_se_refuse() {
    use ams_sasl::hmac_sha256;

    // Le compte hors UTF-8, puis l'appareil hors UTF-8 — cinq octets de
    // compte suivis de deux d'appareil dans les deux cas.
    for noms in [&b"\xffariea1"[..], &b"marie\xff1"[..]] {
        let mut clair = std::vec![VERSION];
        clair.extend_from_slice(&MAINTENANT.to_be_bytes());
        clair.push(5);
        clair.push(2);
        clair.extend_from_slice(noms);
        let sceau = hmac_sha256(&[7_u8; 32], &clair);
        let mut brut = clair.clone();
        brut.extend_from_slice(&sceau);

        let mut ecrit = [0_u8; ENCODED_OCTETS_MAX];
        let texte = crate::base64url::encode(&brut, &mut ecrit).expect("écrivable");
        let mut place = [0_u8; CHALLENGE_OCTETS_MAX];
        assert_eq!(
            verify(&clef(), texte, MAINTENANT, &mut place)
                .err()
                .map(Error::reason),
            Some(Reason::BadToken)
        );
    }
}

/// **CE QUI EST TROP LONG OU TROP COURT SE REFUSE.**
#[test]
fn ce_qui_ne_peut_pas_etre_un_defi_se_refuse() {
    let mut place = [0_u8; CHALLENGE_OCTETS_MAX];
    let trop = std::vec![b'A'; ENCODED_OCTETS_MAX + 1];
    assert_eq!(
        verify(&clef(), &trop, MAINTENANT, &mut place)
            .err()
            .map(Error::reason),
        Some(Reason::BadToken)
    );
    for court in [&b""[..], b"A", b"AAAA", b"AAAAAAAAAAAAAAAA"] {
        assert!(verify(&clef(), court, MAINTENANT, &mut place).is_err());
    }
}

/// **UN TAMPON TROP COURT EST NOTRE FAUTE.**
#[test]
fn un_tampon_trop_court_est_notre_faute() {
    let mut minuscule = [0_u8; 4];
    assert_eq!(
        issue(
            &clef(),
            &Challenge {
                login: "marie",
                device: "a1",
                issued_at_seconds: MAINTENANT,
            },
            &mut minuscule,
        )
        .err()
        .map(Error::reason),
        Some(Reason::BufferTooSmall)
    );
    let texte = ecrire("marie", "a1", MAINTENANT);
    assert_eq!(
        verify(&clef(), texte.as_bytes(), MAINTENANT, &mut minuscule)
            .err()
            .map(Error::reason),
        Some(Reason::BufferTooSmall)
    );
}

// ── CE QUE LE CLIENT SIGNE ──────────────────────────────────────────────────

/// **LE CONDENSAT LIE LA SIGNATURE AU SERVEUR ET À L'USAGE.**
///
/// Sans cette liaison, une signature obtenue pour ouvrir une session ici
/// vaudrait pour en ouvrir une ailleurs.
#[test]
fn le_condensat_lie_au_serveur_et_a_l_usage() {
    let defi = ecrire("marie", "a1", MAINTENANT);

    let ici = digest(ROLE, DOMAINE, defi.as_bytes());
    let ailleurs = digest(ROLE, b"mail.autre.test", defi.as_bytes());
    assert_ne!(ici, ailleurs, "deux serveurs, deux condensats");

    let autre_defi = ecrire("marie", "a1", MAINTENANT + 1);
    assert_ne!(
        ici,
        digest(ROLE, DOMAINE, autre_defi.as_bytes()),
        "deux défis, deux condensats"
    );
}

/// **LE CONDENSAT EST STABLE** : deux appels sur les mêmes entrées rendent la
/// même chose, sans quoi le client ne pourrait jamais le reproduire.
#[test]
fn le_condensat_est_stable() {
    let defi = ecrire("marie", "a1", MAINTENANT);
    assert_eq!(
        digest(ROLE, DOMAINE, defi.as_bytes()),
        digest(ROLE, DOMAINE, defi.as_bytes())
    );
}

/// **LES SÉPARATEURS NULS EMPÊCHENT DEUX ENTRÉES DE SE RECOLLER EN UNE.**
///
/// Sans eux, un domaine `ab` avec un défi `c` et un domaine `a` avec un défi
/// `bc` donneraient la même suite d'octets, donc le même condensat — et une
/// signature obtenue pour l'un vaudrait pour l'autre.
#[test]
fn les_separateurs_empechent_le_recollement() {
    assert_ne!(digest(ROLE, b"ab", b"c"), digest(ROLE, b"a", b"bc"));
}

/// **LE RÔLE EST DANS LE CONDENSAT**, et l'essai le constate plutôt que de le
/// supposer : c'est lui qui séparera cette signature de la prochaine qu'une
/// clef d'appareil devra produire.
#[test]
fn le_role_est_dans_le_condensat() {
    assert_eq!(ROLE, b"ams-session");
    // Le condensat de ce qu'on prétend écrire, calculé à la main.
    let mut attendu = std::vec::Vec::new();
    attendu.extend_from_slice(ROLE);
    attendu.push(0);
    attendu.extend_from_slice(DOMAINE);
    attendu.push(0);
    attendu.extend_from_slice(b"un-defi");
    assert_eq!(
        digest(ROLE, DOMAINE, b"un-defi"),
        ams_sasl::sha256(&attendu)
    );
}

/// **UN DOMAINE DÉMESURÉ NE FAIT PAS COLLISIONNER LE CONDENSAT.**
///
/// # CET ESSAI A TROUVÉ UN DÉFAUT RÉEL, ET IL LE GARDE FERMÉ
///
/// La première écriture recopiait les trois morceaux dans un tampon borné.
/// §3.1 de RFC 1035 borne un nom de domaine à 255 octets, et la borne était
/// dimensionnée pour cela — mais rien ne l'imposait. Un domaine plus long
/// chassait le défi hors du tampon, et **deux défis distincts donnaient le MÊME
/// condensat** : une signature aurait valu pour n'importe lequel.
///
/// Il ne paniquait pas. Il collisionnait, en silence. Le tampon a été supprimé —
/// le condensat se calcule maintenant par morceaux, et il n'y a plus rien à
/// tronquer.
#[test]
fn un_domaine_demesure_ne_fait_pas_collisionner() {
    let enorme = std::vec![b'x'; 4_096];
    assert_ne!(
        digest(ROLE, &enorme, b"defi"),
        digest(ROLE, &enorme, b"autre"),
        "le défi doit encore compter, quelle que soit la taille du domaine"
    );
    // Et le domaine aussi, quelle que soit sa taille.
    let autre_enorme = std::vec![b'y'; 4_096];
    assert_ne!(
        digest(ROLE, &enorme, b"defi"),
        digest(ROLE, &autre_enorme, b"defi")
    );
}

/// **DEUX RÔLES DONNENT DEUX CONDENSATS**, et c'est ce qui empêche une signature
/// obtenue pour un geste de valoir pour l'autre.
///
/// # POURQUOI CETTE PROPRIÉTÉ EST LE CŒUR DE L'APPAIRAGE
///
/// Ouvrir une session donne un jeton de quinze minutes ; approuver un appairage
/// crée une clef qui vaut jusqu'à sa révocation. Sans cette séparation, une
/// application qui demande « ouvre ma boîte » à son propriétaire obtiendrait de
/// quoi lui ajouter un appareil permanent — et le propriétaire n'aurait vu
/// qu'une invite biométrique ordinaire.
#[test]
fn deux_roles_donnent_deux_condensats() {
    let defi = ecrire("marie", "a1", MAINTENANT);
    assert_ne!(
        digest(ROLE, DOMAINE, defi.as_bytes()),
        digest(ROLE_APPAIRAGE, DOMAINE, defi.as_bytes()),
        "une signature de session ne doit pas valoir pour un appairage"
    );
}

/// **LES DEUX RÔLES SONT DISTINCTS, ET LA LISTE LES PORTE TOUS LES DEUX.**
#[test]
fn les_roles_sont_distincts_et_enumeres() {
    assert_ne!(ROLE, ROLE_APPAIRAGE);
    assert_eq!(ROLES, [ROLE, ROLE_APPAIRAGE]);
    // **AUCUN RÔLE NE PORTE D'OCTET NUL** : c'est ce qui rend les séparateurs du
    // condensat non ambigus.
    for role in ROLES {
        assert!(!role.contains(&0), "{role:?} porte un octet nul");
        assert!(!role.is_empty());
    }
}
