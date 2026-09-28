// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::{
    ATTESTATION, Algorithme, CLE_EC, CLE_RSA, COURBE_P256, COURBE_P384, Certificat, Cle,
    ECDSA_SHA256, RSA_SHA512, lire, signe_par,
};
use crate::Refusal;
use crate::tests::fabrique::{octets, seq, tlv};
use std::vec::Vec;

fn oid(contenu: &[u8]) -> Vec<u8> {
    tlv(&[0x06], contenu)
}

fn bits(contenu: &[u8]) -> Vec<u8> {
    let mut avec = std::vec![0_u8];
    avec.extend_from_slice(contenu);
    tlv(&[0x03], &avec)
}

fn utc(texte: &str) -> Vec<u8> {
    tlv(&[0x17], texte.as_bytes())
}

fn generalise(texte: &str) -> Vec<u8> {
    tlv(&[0x18], texte.as_bytes())
}

/// Une clef P-256 quelconque : un point qu'on ne vérifiera pas.
fn spki_ec(courbe: &[u8]) -> Vec<u8> {
    seq(&[&seq(&[&oid(CLE_EC), &oid(courbe)]), &bits(&[4; 65])])
}

fn validite() -> Vec<u8> {
    seq(&[&utc("250101000000Z"), &generalise("20350101000000Z")])
}

fn extension(oid_: &[u8], valeur: &[u8]) -> Vec<u8> {
    seq(&[&oid(oid_), &octets(valeur)])
}

/// Un `TBSCertificate` : version, série, algorithme, émetteur, validité,
/// sujet, clef, puis ce qu'on ajoute.
fn tbs(validite: &[u8], spki: &[u8], suite: &[&[u8]]) -> Vec<u8> {
    let mut champs: Vec<&[u8]> = Vec::new();
    let version = tlv(&[0xA0], &crate::tests::fabrique::entier(2));
    let serie = crate::tests::fabrique::entier(1);
    let algorithme = seq(&[&oid(ECDSA_SHA256)]);
    let nom = seq(&[]);
    champs.extend([
        &version[..],
        &serie,
        &algorithme,
        &nom,
        validite,
        &nom,
        spki,
    ]);
    champs.extend_from_slice(suite);
    seq(&champs)
}

fn certificat(tbs: &[u8], algorithme: &[u8], signature: &[u8]) -> Vec<u8> {
    seq(&[tbs, &seq(&[&oid(algorithme)]), signature])
}

/// Un certificat ordinaire, dont on fait varier une partie.
fn ordinaire(suite: &[&[u8]]) -> Vec<u8> {
    certificat(
        &tbs(&validite(), &spki_ec(COURBE_P256), suite),
        ECDSA_SHA256,
        &bits(&[1, 2]),
    )
}

#[test]
fn un_certificat_se_lit() {
    let attestation = extension(ATTESTATION, b"lue");
    let extensions = tlv(
        &[0xA3],
        &seq(&[&extension(&[0x55, 0x1D, 0x13], b""), &attestation]),
    );
    let brut = ordinaire(&[&extensions]);
    let lu = lire(&brut).expect("lisible");
    assert_eq!(lu.algorithme, Algorithme::EcdsaSha256);
    assert_eq!(lu.cle, Cle::P256(&[4; 65]));
    assert_eq!(lu.attestation, Some(&b"lue"[..]));
    assert_eq!(lu.signature, &[1, 2]);
    // 2025-01-01 et 2035-01-01.
    assert_eq!((lu.debut, lu.fin), (1_735_689_600, 2_051_222_400));
    // Sans extensions, sans attestation ; les identifiants uniques [1] et [2]
    // se sautent.
    let brut = ordinaire(&[&tlv(&[0x81], &[0]), &tlv(&[0x82], &[0])]);
    let sans = lire(&brut).expect("lisible");
    assert_eq!(sans.attestation, None);
    // Une extension critique se lit comme une autre.
    let critique = seq(&[&oid(ATTESTATION), &tlv(&[0x01], &[0xFF]), &octets(b"c")]);
    let brut = ordinaire(&[&tlv(&[0xA3], &seq(&[&critique]))]);
    let lu = lire(&brut).expect("lisible");
    assert_eq!(lu.attestation, Some(&b"c"[..]));
}

#[test]
fn ce_qui_n_a_pas_la_forme_d_un_certificat_est_refuse() {
    let bon = ordinaire(&[]);
    let mut apres = bon.clone();
    apres.push(0);
    let bon_tbs = tbs(&validite(), &spki_ec(COURBE_P256), &[]);
    let quatre = seq(&[
        &bon_tbs,
        &seq(&[&oid(ECDSA_SHA256)]),
        &bits(&[1]),
        &bits(&[1]),
    ]);
    let trois_dates = seq(&[
        &utc("250101000000Z"),
        &utc("250101000000Z"),
        &utc("250101000000Z"),
    ]);
    let spki_long = seq(&[
        &seq(&[&oid(CLE_EC), &oid(COURBE_P256)]),
        &bits(&[4]),
        &bits(&[4]),
    ]);
    let deux_listes = tlv(&[0xA3], &[&seq(&[])[..], &seq(&[])].concat());
    let pas_octets = tlv(&[0xA3], &seq(&[&seq(&[&oid(ATTESTATION), &bits(&[1])])]));
    let reste = tlv(
        &[0xA3],
        &seq(&[&seq(&[&oid(ATTESTATION), &octets(b"a"), &octets(b"b")])]),
    );
    let deux = tlv(
        &[0xA3],
        &seq(&[&extension(ATTESTATION, b"a"), &extension(ATTESTATION, b"b")]),
    );
    let bits_inutilises = certificat(&bon_tbs, ECDSA_SHA256, &tlv(&[0x03], &[1, 0xFF]));
    // Un identifiant unique [1] suivi d'un élément illisible, puis [1] et [2]
    // suivis d'un élément illisible.
    let illisible: &[u8] = &[0x83, 0x05];
    let apres_un = ordinaire(&[&tlv(&[0x81], &[0]), illisible]);
    let apres_deux = ordinaire(&[&tlv(&[0x81], &[0]), &tlv(&[0x82], &[0]), illisible]);
    for faux in [
        apres,
        quatre,
        apres_un,
        apres_deux,
        certificat(
            &tbs(&trois_dates, &spki_ec(COURBE_P256), &[]),
            ECDSA_SHA256,
            &bits(&[1]),
        ),
        certificat(
            &tbs(&validite(), &spki_long, &[]),
            ECDSA_SHA256,
            &bits(&[1]),
        ),
        ordinaire(&[&tlv(&[0xA3], &seq(&[])), &crate::tests::fabrique::entier(0)]),
        ordinaire(&[&deux_listes]),
        ordinaire(&[&pas_octets]),
        ordinaire(&[&reste]),
        ordinaire(&[&deux]),
        bits_inutilises,
        certificat(&bon_tbs, ECDSA_SHA256, &tlv(&[0x03], &[])),
    ] {
        assert_eq!(lire(&faux), Err(Refusal::Malformed), "{faux:02x?}");
    }
}

#[test]
fn ce_qu_on_ne_sait_pas_employer_est_dit_tel() {
    let inconnu = [0x2A, 0x03];
    let bon_tbs = tbs(&validite(), &spki_ec(COURBE_P256), &[]);
    let rsa = seq(&[
        &seq(&[&oid(CLE_RSA), &tlv(&[0x05], &[])]),
        &bits(&[0x30, 0x00]),
    ]);
    for faux in [
        certificat(&bon_tbs, &inconnu, &bits(&[1])),
        certificat(
            &tbs(&validite(), &spki_ec(&inconnu), &[]),
            ECDSA_SHA256,
            &bits(&[1]),
        ),
        certificat(
            &tbs(
                &validite(),
                &seq(&[&seq(&[&oid(&inconnu)]), &bits(&[1])]),
                &[],
            ),
            ECDSA_SHA256,
            &bits(&[1]),
        ),
    ] {
        assert_eq!(lire(&faux), Err(Refusal::Unsupported));
    }
    // Les formes connues se lisent — y compris SHA-512 et une clef RSA, rendue
    // sous sa `SubjectPublicKeyInfo` entière.
    let brut = certificat(&tbs(&validite(), &rsa, &[]), RSA_SHA512, &bits(&[1]));
    let lu = lire(&brut).expect("lisible");
    assert_eq!(lu.algorithme, Algorithme::RsaSha512);
    assert_eq!(lu.cle, Cle::Rsa(&rsa));
    let brut = certificat(
        &tbs(&validite(), &spki_ec(COURBE_P384), &[]),
        ECDSA_SHA256,
        &bits(&[1]),
    );
    let lu = lire(&brut).expect("lisible");
    assert!(matches!(lu.cle, Cle::P384(_)));
}

/// **LES DATES DE RFC 5280** : `UTCTime` jusqu'en 2049, `GeneralizedTime`
/// au-delà — et rien d'autre.
#[test]
fn les_dates_se_lisent_et_les_fausses_se_refusent() {
    let date = |debut: &[u8]| {
        let validite = seq(&[debut, &generalise("21060207062815Z")]);
        lire(&certificat(
            &tbs(&validite, &spki_ec(COURBE_P256), &[]),
            ECDSA_SHA256,
            &bits(&[1]),
        ))
        .map(|lu| (lu.debut, lu.fin))
    };
    // L'époque, un siècle qui bascule, un 29 février.
    assert_eq!(date(&utc("700101000000Z")), Ok((0, 4_294_967_295)));
    assert_eq!(date(&utc("491231235959Z")).map(|d| d.0), Ok(2_524_607_999));
    assert_eq!(date(&utc("000301000000Z")).map(|d| d.0), Ok(951_868_800));
    assert_eq!(
        date(&generalise("20240229120000Z")).map(|d| d.0),
        Ok(1_709_208_000)
    );
    for fausse in [
        utc("7001010000Z"),
        utc("700101000000+"),
        utc("701301000000Z"),
        utc("700100000000Z"),
        utc("700132000000Z"),
        utc("700101240000Z"),
        utc("700101006000Z"),
        utc("700101000060Z"),
        utc("7a0101000000Z"),
        generalise("2a240101000000Z"),
        octets(b"700101000000Z"),
    ] {
        assert_eq!(date(&fausse), Err(Refusal::Malformed), "{fausse:02x?}");
    }
}

fn signe(algorithme: Algorithme, signature: &'static [u8]) -> Certificat<'static> {
    Certificat {
        signe: b"message",
        algorithme,
        signature,
        spki: &[],
        cle: Cle::P256(&[]),
        debut: 0,
        fin: 0,
        attestation: None,
    }
}

/// **TOUT CE QUI NE VA PAS EST « NON »** — clef illisible, signature mal
/// formée, algorithme qui ne va pas avec la clef.
#[test]
fn une_signature_qui_ne_se_verifie_pas_rend_faux() {
    let point = [4_u8; 65];
    let point_384 = [4_u8; 97];
    // Une signature DER bien formée, sur une clef qui n'est pas un point.
    let rs: &'static [u8] = &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
    for (algorithme, cle) in [
        (Algorithme::EcdsaSha256, Cle::P256(&point)),
        (Algorithme::EcdsaSha384, Cle::P256(&point)),
        (Algorithme::EcdsaSha256, Cle::P384(&point_384)),
        (Algorithme::EcdsaSha384, Cle::P384(&point_384)),
        (Algorithme::RsaSha256, Cle::Rsa(b"pas une clef")),
        (Algorithme::RsaSha384, Cle::Rsa(b"pas une clef")),
        (Algorithme::RsaSha512, Cle::Rsa(b"pas une clef")),
        (Algorithme::RsaSha256, Cle::P256(&point)),
        (Algorithme::EcdsaSha256, Cle::Rsa(b"")),
    ] {
        assert!(!signe_par(&signe(algorithme, rs), cle), "{algorithme:?}");
    }
}

/// Une vraie clef, pour atteindre la signature elle-même.
#[test]
fn une_signature_ecdsa_mal_formee_rend_faux() {
    let chaine: &[u8] = include_bytes!("../vecteurs/synthese/tee.der");
    let mut lecteur = crate::der::Lecteur::new(chaine);
    let feuille = lire(lecteur.lire().expect("feuille").brut).expect("lisible");
    let intermediaire = lire(lecteur.lire().expect("intermédiaire").brut).expect("lisible");
    let racine = lire(lecteur.lire().expect("racine").brut).expect("lisible");
    assert!(signe_par(&feuille, intermediaire.cle));
    assert!(signe_par(&intermediaire, racine.cle));
    for fausse in [
        // Pas une SEQUENCE ; un troisième entier ; un octet après ; un r trop
        // long pour sa moitié ; des zéros, qui ne sont pas une signature.
        &[0x04, 0x00][..],
        &[
            0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
        ],
        &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00],
        &[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00],
    ] {
        let mut altere = feuille;
        altere.signature = fausse;
        assert!(!signe_par(&altere, intermediaire.cle), "{fausse:02x?}");
    }
    let mut long = std::vec![0x30, 0x27, 0x02, 0x21, 0x01];
    long.extend_from_slice(&[1; 32]);
    long.extend_from_slice(&[0x02, 0x01, 0x01]);
    let mut altere = feuille;
    altere.signature = &long;
    assert!(!signe_par(&altere, intermediaire.cle));
    let mut p384 = intermediaire;
    p384.signature = &[0x04, 0x00];
    assert!(!signe_par(&p384, racine.cle));
}
