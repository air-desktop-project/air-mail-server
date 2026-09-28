// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Ce qu'on lit d'un certificat X.509 (RFC 5280) — et ce qu'on vérifie de sa
//! signature.
//!
//! # CE N'EST PAS UN VÉRIFICATEUR X.509 GÉNÉRAL
//!
//! Une chaîne d'attestation n'est pas une chaîne TLS : pas de nom d'hôte, pas
//! d'usage étendu, pas de contraintes de nom. Ce qu'elle prouve tient en trois
//! choses — chaque certificat est signé par le suivant, le dernier porte une
//! clef que l'on connaît, et le premier porte l'attestation. On ne lit donc que
//! ce qu'il faut pour cela : les octets signés, l'algorithme, la signature, la
//! clef publique, les dates, et l'extension d'attestation.

use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
use rsa::pkcs8::DecodePublicKey as _;
use rsa::traits::SignatureScheme as _;
use sha2::Digest as _;

use crate::Refusal;
use crate::der::{
    BITS, BOOLEEN, ENTIER, Lecteur, OCTETS, OID, SEQUENCE, TEMPS_GENERALISE, TEMPS_UTC,
};

/// `ecdsa-with-SHA256` (1.2.840.10045.4.3.2).
const ECDSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
/// `ecdsa-with-SHA384` (1.2.840.10045.4.3.3).
const ECDSA_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];
/// `sha256WithRSAEncryption` (1.2.840.113549.1.1.11).
const RSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
/// `sha384WithRSAEncryption` (1.2.840.113549.1.1.12).
const RSA_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C];
/// `sha512WithRSAEncryption` (1.2.840.113549.1.1.13).
const RSA_SHA512: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D];

/// `id-ecPublicKey` (1.2.840.10045.2.1).
const CLE_EC: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
/// `prime256v1` (1.2.840.10045.3.1.7).
const COURBE_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
/// `secp384r1` (1.3.132.0.34).
const COURBE_P384: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
/// `rsaEncryption` (1.2.840.113549.1.1.1).
const CLE_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];

/// L'extension d'attestation d'Android (1.3.6.1.4.1.11129.2.1.17).
const ATTESTATION: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x01, 0x11];
/// L'extension d'App Attest d'Apple (1.2.840.113635.100.8.2), qui porte le
/// nonce.
const APPLE: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x63, 0x64, 0x08, 0x02];

/// Un algorithme de signature qu'on sait vérifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Algorithme {
    /// ECDSA sur SHA-256.
    EcdsaSha256,
    /// ECDSA sur SHA-384.
    EcdsaSha384,
    /// RSA PKCS#1 v1.5 sur SHA-256.
    RsaSha256,
    /// RSA PKCS#1 v1.5 sur SHA-384.
    RsaSha384,
    /// RSA PKCS#1 v1.5 sur SHA-512.
    RsaSha512,
}

/// Une clef publique qu'on sait employer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cle<'a> {
    /// Un point P-256 (SEC1).
    P256(&'a [u8]),
    /// Un point P-384 (SEC1).
    P384(&'a [u8]),
    /// Une clef RSA, sous la forme de sa `SubjectPublicKeyInfo` entière.
    Rsa(&'a [u8]),
}

/// Ce qu'on retient d'un certificat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Certificat<'a> {
    /// Les octets signés : le `TBSCertificate` entier.
    pub(crate) signe: &'a [u8],
    /// L'algorithme de la signature.
    pub(crate) algorithme: Algorithme,
    /// La signature.
    pub(crate) signature: &'a [u8],
    /// La `SubjectPublicKeyInfo` entière, telle qu'écrite : c'est ce qu'on
    /// compare aux racines épinglées.
    pub(crate) spki: &'a [u8],
    /// La clef publique.
    pub(crate) cle: Cle<'a>,
    /// Le début de validité, en secondes depuis l'époque.
    pub(crate) debut: i64,
    /// La fin de validité, en secondes depuis l'époque.
    pub(crate) fin: i64,
    /// Le contenu de l'extension d'attestation d'Android, s'il y en a une.
    pub(crate) attestation: Option<&'a [u8]>,
    /// Le contenu de l'extension d'App Attest d'Apple, s'il y en a une.
    pub(crate) apple: Option<&'a [u8]>,
    /// Le numéro de série, s'il tient sur seize octets — ce que la liste de
    /// révocation nomme. Au-delà, aucune entrée ne peut le désigner.
    pub(crate) serie: Option<u128>,
}

/// Lit un certificat.
///
/// # Errors
///
/// [`Refusal::Malformed`] sur ce qui n'a pas la forme d'un certificat ;
/// [`Refusal::Unsupported`] sur un algorithme ou une clef qu'on ne sait pas
/// employer.
pub(crate) fn lire(certificat: &[u8]) -> Result<Certificat<'_>, Refusal> {
    let mut exterieur = Lecteur::new(certificat);
    let cert = exterieur.attendre(SEQUENCE)?;
    if !exterieur.fini() {
        return Err(Refusal::Malformed);
    }
    let mut champs = Lecteur::new(cert.contenu);
    let tbs = champs.attendre(SEQUENCE)?;
    let algorithme = algorithme(champs.attendre(SEQUENCE)?.contenu)?;
    let signature = bits(champs.attendre(BITS)?.contenu)?;
    if !champs.fini() {
        return Err(Refusal::Malformed);
    }

    let mut tbs_champs = Lecteur::new(tbs.contenu);
    // [0] version, facultative ; le numéro de série ; l'algorithme (redit) ;
    // l'émetteur.
    let _ = tbs_champs.optionnel(0)?;
    let serie = serie(tbs_champs.attendre(ENTIER)?.contenu);
    let _ = tbs_champs.attendre(SEQUENCE)?;
    let _ = tbs_champs.attendre(SEQUENCE)?;
    let mut validite = Lecteur::new(tbs_champs.attendre(SEQUENCE)?.contenu);
    let debut = temps(&mut validite)?;
    let fin = temps(&mut validite)?;
    if !validite.fini() {
        return Err(Refusal::Malformed);
    }
    // Le sujet, puis la clef.
    let _ = tbs_champs.attendre(SEQUENCE)?;
    let spki = tbs_champs.attendre(SEQUENCE)?;
    let cle = cle(spki.contenu, spki.brut)?;
    // [1] et [2], les identifiants uniques, facultatifs et sans intérêt ici.
    let _ = tbs_champs.optionnel(1)?;
    let _ = tbs_champs.optionnel(2)?;
    let (attestation, apple) = match tbs_champs.optionnel(3)? {
        Some(extensions) => attestations(extensions.contenu)?,
        None => (None, None),
    };
    if !tbs_champs.fini() {
        return Err(Refusal::Malformed);
    }
    Ok(Certificat {
        signe: tbs.brut,
        algorithme,
        signature,
        spki: spki.brut,
        cle,
        debut,
        fin,
        attestation,
        apple,
        serie,
    })
}

/// Un numéro de série en nombre, s'il tient sur seize octets une fois son
/// zéro de signe ôté. Un numéro négatif — que RFC 5280 interdit, et que des
/// fabricants ont écrit — n'est pas un de ceux que la liste nomme : elle les
/// écrit en hexadécimal positif.
fn serie(contenu: &[u8]) -> Option<u128> {
    let chiffres = match contenu {
        [0, reste @ ..] => reste,
        [premier, ..] if premier & 0x80 != 0 => return None,
        tout => tout,
    };
    (chiffres.len() <= 16).then(|| {
        chiffres
            .iter()
            .fold(0_u128, |acc, &octet| (acc << 8) | u128::from(octet))
    })
}

/// L'algorithme d'un `AlgorithmIdentifier`.
fn algorithme(contenu: &[u8]) -> Result<Algorithme, Refusal> {
    let mut lecteur = Lecteur::new(contenu);
    let oid = lecteur.attendre(OID)?.contenu;
    match oid {
        ECDSA_SHA256 => Ok(Algorithme::EcdsaSha256),
        ECDSA_SHA384 => Ok(Algorithme::EcdsaSha384),
        RSA_SHA256 => Ok(Algorithme::RsaSha256),
        RSA_SHA384 => Ok(Algorithme::RsaSha384),
        RSA_SHA512 => Ok(Algorithme::RsaSha512),
        _ => Err(Refusal::Unsupported),
    }
}

/// Le contenu d'une `BIT STRING` qui ne laisse aucun bit inutilisé.
fn bits(contenu: &[u8]) -> Result<&[u8], Refusal> {
    match contenu.split_first() {
        Some((0, octets)) => Ok(octets),
        _ => Err(Refusal::Malformed),
    }
}

/// La clef d'une `SubjectPublicKeyInfo`.
fn cle<'a>(contenu: &'a [u8], brut: &'a [u8]) -> Result<Cle<'a>, Refusal> {
    let mut lecteur = Lecteur::new(contenu);
    let mut algorithme = Lecteur::new(lecteur.attendre(SEQUENCE)?.contenu);
    let point = bits(lecteur.attendre(BITS)?.contenu)?;
    if !lecteur.fini() {
        return Err(Refusal::Malformed);
    }
    let sorte = algorithme.attendre(OID)?.contenu;
    match sorte {
        CLE_EC => match algorithme.attendre(OID)?.contenu {
            COURBE_P256 => Ok(Cle::P256(point)),
            COURBE_P384 => Ok(Cle::P384(point)),
            _ => Err(Refusal::Unsupported),
        },
        CLE_RSA => Ok(Cle::Rsa(brut)),
        _ => Err(Refusal::Unsupported),
    }
}

/// Les deux extensions d'attestation : celle d'Android, celle d'App Attest.
type Extensions<'a> = (Option<&'a [u8]>, Option<&'a [u8]>);

/// Cherche les extensions d'attestation parmi les extensions : celle d'Android,
/// et celle d'App Attest.
///
/// **UNE SEULE DE CHAQUE**, et c'est vérifié : deux extensions d'attestation
/// dans un même certificat laisseraient choisir celle qu'on lit.
fn attestations(contenu: &[u8]) -> Result<Extensions<'_>, Refusal> {
    let mut exterieur = Lecteur::new(contenu);
    let mut liste = Lecteur::new(exterieur.attendre(SEQUENCE)?.contenu);
    if !exterieur.fini() {
        return Err(Refusal::Malformed);
    }
    let mut trouvee = None;
    let mut apple = None;
    while !liste.fini() {
        let mut extension = Lecteur::new(liste.attendre(SEQUENCE)?.contenu);
        let oid = extension.attendre(OID)?.contenu;
        let mut valeur = extension.lire()?;
        if valeur.est(BOOLEEN) {
            valeur = extension.lire()?;
        }
        if !valeur.est(OCTETS) || !extension.fini() {
            return Err(Refusal::Malformed);
        }
        let place = match oid {
            ATTESTATION => &mut trouvee,
            APPLE => &mut apple,
            _ => continue,
        };
        if place.is_some() {
            return Err(Refusal::Malformed);
        }
        *place = Some(valeur.contenu);
    }
    Ok((trouvee, apple))
}

/// La clef d'une `SubjectPublicKeyInfo` entière — une racine épinglée.
///
/// # Errors
///
/// Comme la lecture d'une clef de certificat.
pub(crate) fn cle_de_spki(spki: &[u8]) -> Result<Cle<'_>, Refusal> {
    let mut exterieur = Lecteur::new(spki);
    let lu = exterieur.attendre(SEQUENCE)?;
    if !exterieur.fini() {
        return Err(Refusal::Malformed);
    }
    cle(lu.contenu, lu.brut)
}

/// Un instant `UTCTime` ou `GeneralizedTime`, en secondes depuis l'époque.
///
/// RFC 5280 §4.1.2.5 : en UTC (`Z`), aux secondes, sans fraction ; une année
/// `UTCTime` de 50 à 99 est au XXᵉ siècle.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "chaque terme vient de deux ou quatre chiffres décimaux déjà bornés : \
              l'instant tient dans un i64 avec une marge de dix ordres de grandeur"
)]
fn temps(lecteur: &mut Lecteur<'_>) -> Result<i64, Refusal> {
    let lu = lecteur.lire()?;
    // La longueur est vérifiée par le motif : tous les découpages qui suivent
    // tombent dedans.
    let (siecle, annee_ecrite, reste) = match (lu.classe, lu.numero, lu.contenu.len()) {
        (0, TEMPS_UTC, 13) => {
            let (annee, reste) = lu.contenu.split_at(2);
            (None, annee, reste)
        }
        (0, TEMPS_GENERALISE, 15) => {
            let (annee, reste) = lu.contenu.split_at(4);
            (Some(0), annee, reste)
        }
        _ => return Err(Refusal::Malformed),
    };
    let (champs, fin) = reste.split_at(10);
    if fin != b"Z" {
        return Err(Refusal::Malformed);
    }
    let mut valeurs = [0_i64; 6];
    for (valeur, texte) in valeurs
        .iter_mut()
        .zip(core::iter::once(annee_ecrite).chain(champs.chunks(2)))
    {
        *valeur = chiffres(texte)?;
    }
    let [annee, mois, jour, heure, minute, seconde] = valeurs;
    let annee = match siecle {
        Some(_) => annee,
        None if annee >= 50 => 1900 + annee,
        None => 2000 + annee,
    };
    if !(1..=12).contains(&mois)
        || !(1..=31).contains(&jour)
        || heure > 23
        || minute > 59
        || seconde > 59
    {
        return Err(Refusal::Malformed);
    }
    let jours = jours_depuis_l_epoque(annee, mois, jour);
    Ok(jours * 86_400 + heure * 3_600 + minute * 60 + seconde)
}

/// Des chiffres décimaux, en nombre. Les appelants n'en donnent jamais plus
/// de quatre, et c'est ce qui borne l'arithmétique.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "quatre chiffres décimaux au plus : la valeur ne dépasse pas 9 999"
)]
fn chiffres(octets: &[u8]) -> Result<i64, Refusal> {
    let mut valeur = 0_i64;
    for &octet in octets {
        if !octet.is_ascii_digit() {
            return Err(Refusal::Malformed);
        }
        valeur = valeur * 10 + i64::from(octet - b'0');
    }
    Ok(valeur)
}

/// Le nombre de jours du 1970-01-01 à cette date (algorithme de Howard
/// Hinnant, « days from civil »). Les bornes sont celles de [`temps`] : une
/// année de quatre chiffres, un mois et un jour déjà vérifiés.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "l'année tient en quatre chiffres, le mois et le jour sont bornés : aucune \
              de ces opérations ne peut déborder un i64"
)]
fn jours_depuis_l_epoque(annee: i64, mois: i64, jour: i64) -> i64 {
    let annee = if mois <= 2 { annee - 1 } else { annee };
    let ere = annee.div_euclid(400);
    let dans_l_ere = annee - ere * 400;
    let mois_decale = if mois > 2 { mois - 3 } else { mois + 9 };
    let dans_l_annee = (153 * mois_decale + 2) / 5 + jour - 1;
    let dans_le_cycle = dans_l_ere * 365 + dans_l_ere / 4 - dans_l_ere / 100 + dans_l_annee;
    ere * 146_097 + dans_le_cycle - 719_468
}

/// Ce certificat est-il signé par cette clef ?
///
/// **FAUX SUR TOUT CE QUI NE VA PAS** — clef illisible, signature mal formée,
/// algorithme qui ne va pas avec la clef : la seule réponse qui compte est
/// « cette signature se vérifie », et tout le reste est « non ».
pub(crate) fn signe_par(certificat: &Certificat<'_>, cle: Cle<'_>) -> bool {
    let message = certificat.signe;
    let signature = certificat.signature;
    match (certificat.algorithme, cle) {
        (Algorithme::EcdsaSha256, Cle::P256(point)) => {
            ecdsa_p256(point, &sha2::Sha256::digest(message), signature)
        }
        (Algorithme::EcdsaSha384, Cle::P256(point)) => {
            ecdsa_p256(point, &sha2::Sha384::digest(message), signature)
        }
        (Algorithme::EcdsaSha256, Cle::P384(point)) => {
            ecdsa_p384(point, &sha2::Sha256::digest(message), signature)
        }
        (Algorithme::EcdsaSha384, Cle::P384(point)) => {
            ecdsa_p384(point, &sha2::Sha384::digest(message), signature)
        }
        (Algorithme::RsaSha256, Cle::Rsa(spki)) => rsa_pkcs1(
            spki,
            rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha256>(),
            &sha2::Sha256::digest(message),
            signature,
        ),
        (Algorithme::RsaSha384, Cle::Rsa(spki)) => rsa_pkcs1(
            spki,
            rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha384>(),
            &sha2::Sha384::digest(message),
            signature,
        ),
        (Algorithme::RsaSha512, Cle::Rsa(spki)) => rsa_pkcs1(
            spki,
            rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha512>(),
            &sha2::Sha512::digest(message),
            signature,
        ),
        _ => false,
    }
}

fn ecdsa_p256(point: &[u8], condensat: &[u8], signature: &[u8]) -> bool {
    let mut brute = [0_u8; 64];
    let (Ok(cle), Some(())) = (
        p256::ecdsa::VerifyingKey::from_sec1_bytes(point),
        r_et_s(signature, &mut brute),
    ) else {
        return false;
    };
    p256::ecdsa::Signature::from_slice(&brute)
        .is_ok_and(|lue| cle.verify_prehash(condensat, &lue).is_ok())
}

fn ecdsa_p384(point: &[u8], condensat: &[u8], signature: &[u8]) -> bool {
    let mut brute = [0_u8; 96];
    let (Ok(cle), Some(())) = (
        p384::ecdsa::VerifyingKey::from_sec1_bytes(point),
        r_et_s(signature, &mut brute),
    ) else {
        return false;
    };
    p384::ecdsa::Signature::from_slice(&brute)
        .is_ok_and(|lue| cle.verify_prehash(condensat, &lue).is_ok())
}

fn rsa_pkcs1(
    spki: &[u8],
    schema: rsa::pkcs1v15::Pkcs1v15Sign,
    condensat: &[u8],
    signature: &[u8],
) -> bool {
    rsa::RsaPublicKey::from_public_key_der(spki)
        .is_ok_and(|cle| schema.verify(&cle, condensat, signature).is_ok())
}

/// Une signature ECDSA DER (`SEQUENCE { r INTEGER, s INTEGER }`), récrite en
/// `r ‖ s` de largeur fixe dans `sortie` — la moitié pour chacun.
fn r_et_s(signature: &[u8], sortie: &mut [u8]) -> Option<()> {
    let mut exterieur = Lecteur::new(signature);
    let mut paire = Lecteur::new(exterieur.attendre(SEQUENCE).ok()?.contenu);
    let r = paire.attendre(ENTIER).ok()?.contenu;
    let s = paire.attendre(ENTIER).ok()?.contenu;
    if !paire.fini() || !exterieur.fini() {
        return None;
    }
    let moitie = sortie.len() / 2;
    let (gauche, droite) = sortie.split_at_mut(moitie);
    aligner(r, gauche)?;
    aligner(s, droite)
}

/// Un entier positif, aligné à droite dans `place` — sans le zéro de signe
/// qu'ajoute DER.
fn aligner(entier: &[u8], place: &mut [u8]) -> Option<()> {
    let sans_zero = match entier {
        [0, reste @ ..] if !reste.is_empty() => reste,
        tout => tout,
    };
    let debut = place.len().checked_sub(sans_zero.len())?;
    // `debut` ne dépasse pas la longueur, et ce qui reste fait exactement
    // la longueur de l'entier : ni l'un ni l'autre ne peut paniquer.
    let (_, droite) = place.split_at_mut(debut);
    droite.copy_from_slice(sans_zero);
    Some(())
}

#[cfg(test)]
mod tests;
