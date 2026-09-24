// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'une invitation prouve, et tout ce qu'elle refuse de prouver.

use super::{
    ENCODED_OCTETS_MAX, INVITATION_OCTETS_MAX, Invitation, LIFETIME_MAX_US, LOGIN_OCTETS_MAX,
    VERSION, issue, verify,
};
use crate::error::Reason;
use crate::scope::{Area, Rights, Scope};
use crate::token::{Key, Token};

/// Une clé d'épreuve, tirée d'octets FIXES.
fn clef() -> Key {
    Key::new(&[7_u8; 32]).expect("une clé valide")
}

/// Une seconde clé, différente.
fn autre_clef() -> Key {
    Key::new(&[9_u8; 32]).expect("une clé valide")
}

/// Un instant d'épreuve, et une expiration une heure plus tard.
const MAINTENANT: u64 = 1_790_000_000_000_000;
const DANS_UNE_HEURE: u64 = MAINTENANT + 3_600_000_000;

/// Écrit une invitation, et rend son texte.
fn ecrire(login: &str, expiry: u64) -> std::string::String {
    use std::string::ToString as _;
    let mut place = [0_u8; ENCODED_OCTETS_MAX];
    issue(
        &clef(),
        &Invitation { login, expiry },
        MAINTENANT,
        &mut place,
    )
    .expect("écrivable")
    .to_string()
}

/// **CE QUI EST SCELLÉ SE RELIT.** L'aller-retour, d'abord.
#[test]
fn une_invitation_fait_l_aller_retour() {
    let texte = ecrire("marie", DANS_UNE_HEURE);
    let mut place = [0_u8; INVITATION_OCTETS_MAX];
    let lue = verify(&clef(), texte.as_bytes(), MAINTENANT, &mut place).expect("vérifiable");
    assert_eq!(lue.login, "marie");
    assert_eq!(lue.expiry, DANS_UNE_HEURE);
}

/// **UN JETON PORTEUR N'EST PAS UNE INVITATION**, bien qu'il porte le MÊME
/// SCEAU, produit par la MÊME CLÉ.
///
/// # C'EST L'ESSAI LE PLUS IMPORTANT DE CE FICHIER
///
/// Les deux objets sont scellés par la même clé : si la version ne les séparait
/// pas, un jeton de courrier volé — ou simplement le sien — s'échangerait contre
/// l'enrôlement d'une clef d'appareil sur le compte. L'octet de version est dans
/// le clair, donc COUVERT PAR LE SCEAU : on ne peut pas le retoucher.
#[test]
fn un_jeton_ne_passe_pas_pour_une_invitation() {
    use std::string::ToString as _;
    let mut place = [0_u8; crate::token::ENCODED_OCTETS_MAX];
    let jeton = crate::token::issue(
        &clef(),
        &Token {
            login: "marie",
            scope: Scope::one(Area::Mail, Rights::Read),
            expiry: DANS_UNE_HEURE,
            nonce: 42,
        },
        MAINTENANT,
        &mut place,
    )
    .expect("écrivable")
    .to_string();

    let mut lecture = [0_u8; INVITATION_OCTETS_MAX];
    assert_eq!(
        verify(&clef(), jeton.as_bytes(), MAINTENANT, &mut lecture)
            .err()
            .map(crate::error::Error::reason),
        Some(Reason::BadToken),
        "un jeton authentique ne doit pas s'enrôler"
    );
}

/// **ET L'INVERSE NON PLUS** : une invitation n'ouvre aucune session.
#[test]
fn une_invitation_ne_passe_pas_pour_un_jeton() {
    let texte = ecrire("marie", DANS_UNE_HEURE);
    let mut place = [0_u8; crate::token::TOKEN_OCTETS_MAX];
    assert_eq!(
        crate::token::verify(&clef(), texte.as_bytes(), MAINTENANT, &mut place)
            .err()
            .map(crate::error::Error::reason),
        Some(Reason::BadToken)
    );
}

/// **LES DEUX VERSIONS DIFFÈRENT**, et cet essai le fige : les égaliser
/// rouvrirait la confusion que les deux essais ci-dessus ferment.
#[test]
fn les_deux_versions_ne_se_confondent_pas() {
    assert_ne!(VERSION, crate::token::VERSION);
}

/// **UNE AUTRE CLÉ NE VÉRIFIE RIEN.**
#[test]
fn une_autre_cle_ne_verifie_rien() {
    let texte = ecrire("marie", DANS_UNE_HEURE);
    let mut place = [0_u8; INVITATION_OCTETS_MAX];
    assert_eq!(
        verify(&autre_clef(), texte.as_bytes(), MAINTENANT, &mut place)
            .err()
            .map(crate::error::Error::reason),
        Some(Reason::BadToken)
    );
}

/// **UN SEUL OCTET CHANGÉ SUFFIT À LA REFUSER.**
///
/// Chaque position, et chaque octet de l'alphabet : c'est le sceau qu'on
/// éprouve, et il doit couvrir TOUT le clair — version comprise, expiration
/// comprise, nom compris.
#[test]
fn un_octet_change_suffit_a_la_refuser() {
    let texte = ecrire("marie", DANS_UNE_HEURE);
    let sain = texte.as_bytes();
    let mut refusees = 0_u32;
    for position in 0..sain.len() {
        for remplacant in *b"Az0-_" {
            let mut corrompue = sain.to_vec();
            let Some(place) = corrompue.get_mut(position) else {
                continue;
            };
            if *place == remplacant {
                continue;
            }
            *place = remplacant;
            let mut lecture = [0_u8; INVITATION_OCTETS_MAX];
            assert!(
                verify(&clef(), &corrompue, MAINTENANT, &mut lecture).is_err(),
                "la position {position} changée en `{}` est passée",
                char::from(remplacant)
            );
            refusees = refusees.saturating_add(1);
        }
    }
    assert!(refusees > 0, "aucune corruption n'a été éprouvée");
}

/// **UNE INVITATION EXPIRÉE SE DIT COMME TELLE**, et non « irrecevable ».
///
/// Elle n'est atteinte qu'après un sceau valide : la distinguer n'apprend donc
/// rien à qui forge, et apprend à qui la porte qu'il faut en redemander une.
#[test]
fn une_invitation_expiree_se_dit() {
    let texte = ecrire("marie", DANS_UNE_HEURE);
    let mut place = [0_u8; INVITATION_OCTETS_MAX];
    assert_eq!(
        verify(&clef(), texte.as_bytes(), DANS_UNE_HEURE, &mut place)
            .err()
            .map(crate::error::Error::reason),
        Some(Reason::TokenExpired),
        "à l'instant exact de l'expiration, elle ne vaut DÉJÀ plus"
    );
    assert!(verify(&clef(), texte.as_bytes(), DANS_UNE_HEURE - 1, &mut place).is_ok());
}

/// **UNE VIE PLUS LONGUE QUE LA BORNE SE REFUSE À L'ÉMISSION.**
#[test]
fn une_vie_trop_longue_ne_s_emet_pas() {
    let mut place = [0_u8; ENCODED_OCTETS_MAX];
    assert_eq!(
        issue(
            &clef(),
            &Invitation {
                login: "marie",
                expiry: MAINTENANT + LIFETIME_MAX_US + 1,
            },
            MAINTENANT,
            &mut place,
        )
        .err()
        .map(crate::error::Error::reason),
        Some(Reason::BadToken)
    );
    // Et à la borne exacte, elle s'émet : une borne inatteignable est mal écrite.
    assert!(
        issue(
            &clef(),
            &Invitation {
                login: "marie",
                expiry: MAINTENANT + LIFETIME_MAX_US,
            },
            MAINTENANT,
            &mut place,
        )
        .is_ok()
    );
}

/// **ELLE VIT PLUS LONGTEMPS QU'UN JETON, ET C'EST VOULU** : elle voyage par un
/// canal humain, son porteur doit avoir le temps d'installer une application.
///
/// **VÉRIFIÉ À LA COMPILATION**, et non à l'exécution : les deux bornes sont des
/// constantes, et un essai qui les compare ne pourrait échouer qu'après avoir
/// été compilé — c'est-à-dire trop tard pour empêcher quoi que ce soit.
#[test]
fn elle_vit_plus_longtemps_qu_un_jeton() {
    const { assert!(LIFETIME_MAX_US > crate::token::LIFETIME_MAX_US) }
}

/// **UN NOM VIDE OU TROP LONG NE S'ÉMET PAS.**
#[test]
fn un_nom_irrecevable_ne_s_emet_pas() {
    let mut place = [0_u8; ENCODED_OCTETS_MAX];
    for login in [
        std::string::String::new(),
        core::iter::repeat_n('x', LOGIN_OCTETS_MAX + 1).collect(),
    ] {
        assert_eq!(
            issue(
                &clef(),
                &Invitation {
                    login: &login,
                    expiry: DANS_UNE_HEURE,
                },
                MAINTENANT,
                &mut place,
            )
            .err()
            .map(crate::error::Error::reason),
            Some(Reason::BadToken),
            "nom de {} octets",
            login.len()
        );
    }
    // Et à la borne exacte, cela passe.
    let juste: std::string::String = core::iter::repeat_n('x', LOGIN_OCTETS_MAX).collect();
    let texte = {
        use std::string::ToString as _;
        issue(
            &clef(),
            &Invitation {
                login: &juste,
                expiry: DANS_UNE_HEURE,
            },
            MAINTENANT,
            &mut place,
        )
        .expect("écrivable")
        .to_string()
    };
    let mut lecture = [0_u8; INVITATION_OCTETS_MAX];
    assert_eq!(
        verify(&clef(), texte.as_bytes(), MAINTENANT, &mut lecture)
            .expect("vérifiable")
            .login,
        juste
    );
}

/// **UN TAMPON TROP COURT EST NOTRE FAUTE**, et se dit comme telle.
#[test]
fn un_tampon_trop_court_est_notre_faute() {
    let mut minuscule = [0_u8; 4];
    assert_eq!(
        issue(
            &clef(),
            &Invitation {
                login: "marie",
                expiry: DANS_UNE_HEURE,
            },
            MAINTENANT,
            &mut minuscule,
        )
        .err()
        .map(crate::error::Error::reason),
        Some(Reason::BufferTooSmall)
    );

    let texte = ecrire("marie", DANS_UNE_HEURE);
    assert_eq!(
        verify(&clef(), texte.as_bytes(), MAINTENANT, &mut minuscule)
            .err()
            .map(crate::error::Error::reason),
        Some(Reason::BufferTooSmall)
    );
}

/// **CE QUI EST PLUS LONG QUE LA PLUS GRANDE INVITATION SE REFUSE D'EMBLÉE.**
///
/// Sans cette garde, un corps de cent mébioctets ferait travailler le décodeur
/// avant qu'on ne sache qu'il ne peut rien contenir.
#[test]
fn ce_qui_est_trop_long_se_refuse_d_emblee() {
    let trop = std::vec![b'A'; ENCODED_OCTETS_MAX + 1];
    let mut place = [0_u8; INVITATION_OCTETS_MAX];
    assert_eq!(
        verify(&clef(), &trop, MAINTENANT, &mut place)
            .err()
            .map(crate::error::Error::reason),
        Some(Reason::BadToken)
    );
}

/// **CE QUI EST TROP COURT POUR PORTER UN EN-TÊTE ET UN SCEAU SE REFUSE.**
#[test]
fn ce_qui_est_trop_court_se_refuse() {
    let mut place = [0_u8; INVITATION_OCTETS_MAX];
    for texte in [&b""[..], b"A", b"AAAA", b"AAAAAAAAAAAAAAAA"] {
        assert!(
            verify(&clef(), texte, MAINTENANT, &mut place).is_err(),
            "{texte:?} est passé"
        );
    }
}

/// **UN NOM QUI N'EST PAS DE L'UTF-8 SE REFUSE**, même scellé.
///
/// On ne l'atteint qu'en tenant la clé — c'est donc l'émetteur qui se serait
/// trompé, et le refuser ici vaut mieux que de rendre une chaîne de
/// remplacement que personne n'a écrite.
#[test]
fn un_nom_hors_utf8_se_refuse() {
    use ams_sasl::hmac_sha256;

    // On fabrique le clair à la main, puis on le scelle POUR DE VRAI : c'est le
    // seul moyen d'atteindre la lecture avec un nom que l'émission refuserait.
    let mut clair = std::vec![VERSION];
    clair.extend_from_slice(&DANS_UNE_HEURE.to_be_bytes());
    clair.push(3);
    clair.extend_from_slice(b"a\xffb");
    let sceau = hmac_sha256(&[7_u8; 32], &clair);
    let mut brut = clair.clone();
    brut.extend_from_slice(&sceau);

    let mut ecrit = [0_u8; ENCODED_OCTETS_MAX];
    let texte = crate::base64url::encode(&brut, &mut ecrit).expect("écrivable");

    let mut place = [0_u8; INVITATION_OCTETS_MAX];
    assert_eq!(
        verify(&clef(), texte, MAINTENANT, &mut place)
            .err()
            .map(crate::error::Error::reason),
        Some(Reason::BadToken)
    );
}

/// **UNE LONGUEUR ANNONCÉE QUI MENT SE REFUSE**, bien qu'elle soit scellée.
///
/// Elle est authentique — le sceau la couvre — mais un émetteur qui se
/// tromperait produirait deux invitations désignant le même compte de deux
/// façons.
#[test]
fn une_longueur_qui_ment_se_refuse() {
    use ams_sasl::hmac_sha256;

    let mut clair = std::vec![VERSION];
    clair.extend_from_slice(&DANS_UNE_HEURE.to_be_bytes());
    clair.push(9); // le nom fait cinq octets, pas neuf.
    clair.extend_from_slice(b"marie");
    let sceau = hmac_sha256(&[7_u8; 32], &clair);
    let mut brut = clair.clone();
    brut.extend_from_slice(&sceau);

    let mut ecrit = [0_u8; ENCODED_OCTETS_MAX];
    let texte = crate::base64url::encode(&brut, &mut ecrit).expect("écrivable");

    let mut place = [0_u8; INVITATION_OCTETS_MAX];
    assert_eq!(
        verify(&clef(), texte, MAINTENANT, &mut place)
            .err()
            .map(crate::error::Error::reason),
        Some(Reason::BadToken)
    );
}

/// L'invitation se débogue et se compare — l'appelant en a besoin pour ses
/// essais et sa trace.
#[test]
fn une_invitation_se_debogue() {
    let lue = Invitation {
        login: "marie",
        expiry: DANS_UNE_HEURE,
    };
    assert_eq!(lue, lue);
    let rendu = std::format!("{lue:?}");
    assert!(rendu.contains("marie"), "{rendu}");
}
