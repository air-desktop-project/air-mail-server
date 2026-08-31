// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'un jeton porteur a le droit d'être.

use super::{
    ENCODED_OCTETS_MAX, Key, LIFETIME_MAX_US, LOGIN_OCTETS_MAX, TOKEN_OCTETS_MAX, Token, VERSION,
    authorize, bearer, issue, verify,
};
use crate::error::Reason;
use crate::scope::{Area, Rights, Scope};

/// Une clé d'essai.
const CLEF: &[u8; 32] = b"une clef de trente-deux octets!!";

/// Une autre, qui ne doit rien ouvrir de ce que la première a scellé.
const AUTRE: &[u8; 32] = b"une AUTRE clef de trente-deux o!";

/// Un instant commode, et une expiration une heure plus tard.
const MAINTENANT: u64 = 1_700_000_000_000_000;

/// Une heure, en microsecondes.
const HEURE: u64 = 3_600 * 1_000_000;

/// La clé d'essai.
fn clef() -> Key {
    Key::new(CLEF).expect("trente-deux octets")
}

/// Un jeton ordinaire.
fn jeton() -> Token<'static> {
    Token {
        login: "marc",
        scope: Scope::one(Area::Mail, Rights::Write),
        expiry: MAINTENANT + HEURE,
        nonce: 0x0123_4567_89ab_cdef,
    }
}

/// Émet le jeton, et rend son écriture.
fn emettre(token: &Token<'_>) -> std::vec::Vec<u8> {
    let mut place = [0_u8; ENCODED_OCTETS_MAX];
    issue(&clef(), token, MAINTENANT, &mut place)
        .expect("émissible")
        .as_bytes()
        .to_vec()
}

/// **CE QU'ON SCELLE SE RELIT À L'IDENTIQUE.**
#[test]
fn ce_qu_on_scelle_se_relit() {
    let attendu = jeton();
    let ecrit = emettre(&attendu);
    let mut place = [0_u8; TOKEN_OCTETS_MAX];
    let lu = verify(&clef(), &ecrit, MAINTENANT, &mut place).expect("vérifiable");
    assert_eq!(lu, attendu);
}

/// Tous les noms de compte et toutes les portées font l'aller-retour.
#[test]
fn tous_les_champs_font_l_aller_retour() {
    for login in ["a", "marc", &"x".repeat(LOGIN_OCTETS_MAX)] {
        for bits in [0_u8, 0x01, 0x55, 0xaa, u8::MAX] {
            let attendu = Token {
                login,
                scope: Scope::from_bits(bits),
                expiry: MAINTENANT + 1,
                nonce: u64::from(bits),
            };
            let ecrit = emettre(&attendu);
            let mut place = [0_u8; TOKEN_OCTETS_MAX];
            let lu = verify(&clef(), &ecrit, MAINTENANT, &mut place).expect("vérifiable");
            assert_eq!(lu, attendu, "{login} et {bits:#04x}");
        }
    }
}

/// **UNE AUTRE CLÉ N'OUVRE RIEN**, et c'est toute la raison d'être du sceau.
#[test]
fn une_autre_clef_n_ouvre_rien() {
    let ecrit = emettre(&jeton());
    let autre = Key::new(AUTRE).expect("trente-deux octets");
    let mut place = [0_u8; TOKEN_OCTETS_MAX];
    let issue = verify(&autre, &ecrit, MAINTENANT, &mut place).expect_err("scellé ailleurs");
    assert_eq!(issue.reason(), Reason::BadToken);
}

/// **UN SEUL OCTET CHANGÉ SUFFIT À LE REFUSER**, où qu'il soit.
#[test]
fn un_octet_change_suffit_a_le_refuser() {
    let ecrit = emettre(&jeton());
    for rang in 0..ecrit.len() {
        let mut abime = ecrit.clone();
        // On remplace par un autre caractère de l'alphabet, pour que ce ne soit
        // pas le décodage qui refuse.
        abime[rang] = match abime[rang] {
            b'A' => b'B',
            _ => b'A',
        };
        let mut sortie = [0_u8; TOKEN_OCTETS_MAX];
        assert!(
            verify(&clef(), &abime, MAINTENANT, &mut sortie).is_err(),
            "l'octet {rang} a été changé et le jeton passe encore"
        );
    }
}

/// **UN JETON EXPIRÉ SE DIT, ET LE DIRE N'APPREND RIEN À QUI FORGE** : on ne
/// l'atteint qu'après un sceau valide.
#[test]
fn un_jeton_expire_se_dit() {
    let token = jeton();
    let ecrit = emettre(&token);
    let mut place = [0_u8; TOKEN_OCTETS_MAX];
    // Une microseconde avant : il vaut encore.
    assert!(verify(&clef(), &ecrit, token.expiry - 1, &mut place).is_ok());
    // À l'instant même : il ne vaut plus.
    let issue = verify(&clef(), &ecrit, token.expiry, &mut place).expect_err("expiré");
    assert_eq!(issue.reason(), Reason::TokenExpired);
    let issue = verify(&clef(), &ecrit, u64::MAX, &mut place).expect_err("expiré");
    assert_eq!(issue.reason(), Reason::TokenExpired);
}

/// **UN JETON NE SE RÉVOQUE PAS TOUT SEUL** : sa seule fin garantie est son
/// expiration, et l'émission la borne.
#[test]
fn la_vie_d_un_jeton_est_bornee_a_l_emission() {
    let mut trop = jeton();
    trop.expiry = MAINTENANT + LIFETIME_MAX_US + 1;
    let mut place = [0_u8; ENCODED_OCTETS_MAX];
    let faute = issue(&clef(), &trop, MAINTENANT, &mut place).expect_err("trop long");
    assert_eq!(faute.reason(), Reason::BadToken);

    // Pile la borne passe.
    let mut pile = jeton();
    pile.expiry = MAINTENANT + LIFETIME_MAX_US;
    assert!(issue(&clef(), &pile, MAINTENANT, &mut place).is_ok());
}

/// Un nom de compte vide ou trop long ne fait pas un jeton.
#[test]
fn un_nom_de_compte_impossible_se_refuse() {
    let long = "x".repeat(LOGIN_OCTETS_MAX + 1);
    for login in ["", long.as_str()] {
        let mut token = jeton();
        token.login = login;
        let mut place = [0_u8; ENCODED_OCTETS_MAX];
        let faute = issue(&clef(), &token, MAINTENANT, &mut place).expect_err("impossible");
        assert_eq!(faute.reason(), Reason::BadToken, "« {login} »");
    }
}

/// **UNE CLÉ TROP COURTE SE REFUSE**, et c'est notre faute : c'est la
/// configuration du serveur qui la fournit.
#[test]
fn une_clef_trop_courte_se_refuse() {
    for taille in 0..32_usize {
        let courte = std::vec![0x41_u8; taille];
        let issue = Key::new(&courte).expect_err("trop courte");
        assert_eq!(issue.reason(), Reason::BadKey, "{taille} octets");
    }
    // Trente-deux passent, et davantage aussi — on prend les trente-deux
    // premiers.
    assert!(Key::new(&[0x41_u8; 32]).is_ok());
    assert!(Key::new(&[0x41_u8; 64]).is_ok());
}

/// **UNE CLÉ NE S'AFFICHE PAS**, même en débogage.
#[test]
fn une_clef_ne_s_affiche_pas() {
    let dit = std::format!("{:?}", clef());
    assert!(!dit.contains("clef de trente"), "la clé a fui : {dit}");
    assert!(dit.contains("secret"));
    // Et le clonage n'y change rien.
    let copie = clef().clone();
    assert!(!std::format!("{copie:?}").contains("clef de trente"));
}

/// Ce qui ne se décode pas, ou ne fait pas la taille d'un jeton, se refuse.
#[test]
fn ce_qui_n_est_pas_un_jeton_se_refuse() {
    let mut place = [0_u8; TOKEN_OCTETS_MAX];
    for mauvais in [
        &b""[..],
        b"A",
        b"AAAA",
        // Hors de l'alphabet.
        b"AAA+",
        b"AAA/",
        b"AAA=",
        // Une longueur impossible en base64url.
        b"AAAAA",
        // Trop long pour un jeton.
        &[b'A'; ENCODED_OCTETS_MAX + 4],
    ] {
        let issue = verify(&clef(), mauvais, MAINTENANT, &mut place).expect_err("pas un jeton");
        assert_eq!(issue.reason(), Reason::BadToken, "{mauvais:?}");
    }
}

/// **UN JETON D'UNE AUTRE VERSION SE REFUSE** : la version fixe l'algorithme, et
/// il n'y en a qu'un.
#[test]
fn une_autre_version_se_refuse() {
    // On fabrique un jeton scellé dont le premier octet n'est pas la version.
    // Il faut sceller nous-mêmes, sinon c'est le sceau qui refuserait.
    let token = jeton();
    let ecrit = emettre(&token);
    let mut brut = [0_u8; TOKEN_OCTETS_MAX];
    let decode = crate::base64url::decode(&ecrit, &mut brut).expect("décodable");
    assert_eq!(decode.first(), Some(&VERSION));

    // Le même jeton avec une autre version, rescellé pour que seul le numéro de
    // version puisse le faire refuser.
    let mut modifie = decode.to_vec();
    modifie[0] = VERSION.wrapping_add(1);
    let coupe = modifie.len() - super::MAC_OCTETS;
    let sceau = crate::mac::hmac_sha256(CLEF, modifie.get(..coupe).unwrap_or_default());
    modifie.truncate(coupe);
    modifie.extend_from_slice(&sceau);

    let mut ecrit = [0_u8; ENCODED_OCTETS_MAX];
    let refait = crate::base64url::encode(&modifie, &mut ecrit).expect("écrivable");
    let mut place = [0_u8; TOKEN_OCTETS_MAX];
    let issue = verify(&clef(), refait, MAINTENANT, &mut place).expect_err("autre version");
    assert_eq!(issue.reason(), Reason::BadToken);
}

/// **UNE LONGUEUR DE NOM QUI MENT SE REFUSE**, même scellée : deux jetons
/// authentiques désigneraient le même compte de deux façons.
#[test]
fn une_longueur_de_nom_qui_ment_se_refuse() {
    let ecrit = emettre(&jeton());
    let mut brut = [0_u8; TOKEN_OCTETS_MAX];
    let decode = crate::base64url::decode(&ecrit, &mut brut).expect("décodable");
    let mut modifie = decode.to_vec();
    // L'octet 18 porte la longueur du nom.
    modifie[18] = modifie[18].wrapping_add(1);
    let coupe = modifie.len() - super::MAC_OCTETS;
    let sceau = crate::mac::hmac_sha256(CLEF, modifie.get(..coupe).unwrap_or_default());
    modifie.truncate(coupe);
    modifie.extend_from_slice(&sceau);

    let mut ecrit = [0_u8; ENCODED_OCTETS_MAX];
    let refait = crate::base64url::encode(&modifie, &mut ecrit).expect("écrivable");
    let mut place = [0_u8; TOKEN_OCTETS_MAX];
    let issue = verify(&clef(), refait, MAINTENANT, &mut place).expect_err("longueur menteuse");
    assert_eq!(issue.reason(), Reason::BadToken);
}

/// Un jeton sans nom de compte n'en est pas un.
#[test]
fn un_jeton_sans_nom_se_refuse() {
    // Dix-neuf octets d'en-tête et trente-deux de sceau, sans un octet de nom.
    let mut brut = std::vec![0_u8; 19];
    brut[0] = VERSION;
    let sceau = crate::mac::hmac_sha256(CLEF, &brut);
    brut.extend_from_slice(&sceau);
    let mut ecrit = [0_u8; ENCODED_OCTETS_MAX];
    let refait = crate::base64url::encode(&brut, &mut ecrit).expect("écrivable");
    let mut place = [0_u8; TOKEN_OCTETS_MAX];
    let issue = verify(&clef(), refait, MAINTENANT, &mut place).expect_err("sans nom");
    assert_eq!(issue.reason(), Reason::BadToken);
}

/// Un nom de compte qui n'est pas de l'UTF-8 se refuse, même scellé.
#[test]
fn un_nom_qui_n_est_pas_de_l_utf8_se_refuse() {
    let mut brut = std::vec![0_u8; 19];
    brut[0] = VERSION;
    // Une expiration lointaine, pour que ce ne soit pas elle qui refuse.
    for (rang, octet) in u64::MAX.to_be_bytes().into_iter().enumerate() {
        brut[rang.saturating_add(2)] = octet;
    }
    brut[18] = 2;
    brut.extend_from_slice(&[0xff, 0xfe]);
    let sceau = crate::mac::hmac_sha256(CLEF, &brut);
    brut.extend_from_slice(&sceau);
    let mut ecrit = [0_u8; ENCODED_OCTETS_MAX];
    let refait = crate::base64url::encode(&brut, &mut ecrit).expect("écrivable");
    let mut place = [0_u8; TOKEN_OCTETS_MAX];
    let issue = verify(&clef(), refait, MAINTENANT, &mut place).expect_err("pas de l'UTF-8");
    assert_eq!(issue.reason(), Reason::BadToken);
}

/// **NOTRE TAMPON, NOTRE FAUTE.**
#[test]
fn un_tampon_trop_court_est_notre_faute() {
    let token = jeton();
    let mut minuscule = [0_u8; 4];
    let faute = issue(&clef(), &token, MAINTENANT, &mut minuscule).expect_err("trop court");
    assert_eq!(faute.reason(), Reason::BufferTooSmall);

    let ecrit = emettre(&token);
    let mut minuscule = [0_u8; 4];
    let faute = verify(&clef(), &ecrit, MAINTENANT, &mut minuscule).expect_err("trop court");
    assert_eq!(faute.reason(), Reason::BufferTooSmall);
}

/// **LA PORTÉE DU JETON DOIT CONTENIR CELLE DE LA ROUTE.**
#[test]
fn l_autorisation_compare_les_portees() {
    let token = Token {
        login: "marc",
        scope: Scope::one(Area::Mail, Rights::Read),
        expiry: MAINTENANT + HEURE,
        nonce: 1,
    };
    // Ce qui n'exige rien passe toujours.
    assert!(authorize(&token, None).is_ok());
    // Ce qu'il ouvre passe.
    assert!(authorize(&token, Some(Scope::one(Area::Mail, Rights::Read))).is_ok());
    assert!(authorize(&token, Some(Scope::none())).is_ok());
    // Ce qu'il n'ouvre pas ne passe pas.
    let issue = authorize(&token, Some(Scope::one(Area::Mail, Rights::Write)))
        .expect_err("il ne peut que lire");
    assert_eq!(issue.reason(), Reason::Forbidden);
    assert!(authorize(&token, Some(Scope::one(Area::Admin, Rights::Read))).is_err());
}

/// **LE NOM DU SCHÉMA EST INSENSIBLE À LA CASSE** (§11.1 de RFC 9110), et le
/// jeton ne l'est pas.
#[test]
fn le_schema_se_lit_sans_egard_a_la_casse() {
    for ecriture in [
        &b"Bearer abc"[..],
        b"bearer abc",
        b"BEARER abc",
        b"BeArEr abc",
    ] {
        assert_eq!(bearer(ecriture), Ok(&b"abc"[..]), "{ecriture:?}");
    }
}

/// Ce qui n'est pas un jeton porteur se refuse.
#[test]
fn ce_qui_n_est_pas_porteur_se_refuse() {
    for mauvais in [
        &b""[..],
        b"Bearer",
        b"Bearer ",
        b"Basic abc",
        b"Bear abc",
        b"Bearerabc",
        // **UN SEUL ESPACE** : deux écritures d'un même en-tête sont une de
        // trop, puisque c'est la valeur entière qu'un journal retient.
        b"Bearer  abc",
        b"Bearer abc def",
    ] {
        let faute = bearer(mauvais).expect_err("pas un jeton porteur");
        assert_eq!(faute.reason(), Reason::BadToken, "{mauvais:?}");
    }
}
