// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! App Attest d'Apple : ce que prouve l'objet d'attestation qu'une application
//! iOS obtient de `DCAppAttestService.attestKey` (0.2.43).
//!
//! # CE QU'IL PROUVE
//!
//! Qu'une clef a été créée dans la Secure Enclave d'un appareil Apple
//! authentique, **par l'application `TeamID.bundleID`** telle qu'Apple l'a
//! signée, et qu'elle a attesté CE `clientDataHash` — que le serveur choisit.
//!
//! # CE QU'IL NE PROUVE PAS, ET POURQUOI IL FAUT UNE LIAISON
//!
//! La clef d'App Attest n'est PAS notre clef d'appareil : elle ne sait signer
//! que des « assertions » d'App Attest. C'est le `clientDataHash` qui lie les
//! deux — l'application y met le condensat de l'invitation ET de sa clef
//! d'appareil ; voir le serveur. Une attestation obtenue pour une autre clef
//! d'appareil ne vaut donc pas pour celle-ci.
//!
//! # LES ÉTAPES, TELLES QU'APPLE LES DÉCRIT
//!
//! (« Validating apps that connect to your server ».) La chaîne `x5c` remonte à
//! la racine d'Apple ; le nonce `SHA-256(authData ‖ clientDataHash)` est celui
//! que porte l'extension `1.2.840.113635.100.8.2` du certificat de la clef ;
//! l'identifiant de la clef est le condensat de sa clef publique ; `authData`
//! désigne l'application, porte un compteur à zéro et l'environnement voulu.

use sha2::Digest as _;

use crate::Refusal;
use crate::cbor::Cbor;
use crate::der::{Lecteur, OCTETS, SEQUENCE};
use crate::x509;

/// La clef racine d'App Attest, « Apple App Attestation Root CA » (P-384,
/// 2020–2045), en `SubjectPublicKeyInfo` DER. Empreinte SHA-256 `1ae751fd…` —
/// l'essai `la_racine_d_apple_est_celle_qu_apple_publie` la tient.
pub const APPLE_ROOTS: [&[u8]; 1] = [include_bytes!("racines/apple-app-attest.spki")];

/// L'environnement dans lequel la clef a été attestée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppleEnvironment {
    /// Une application distribuée — App Store, TestFlight, entreprise.
    Production,
    /// Une application signée pour le développement.
    Development,
}

impl AppleEnvironment {
    /// L'`aaguid` que porte `authData` dans cet environnement.
    const fn aaguid(self) -> &'static [u8; 16] {
        match self {
            Self::Production => b"appattest\0\0\0\0\0\0\0",
            Self::Development => b"appattestdevelop",
        }
    }
}

/// Ce que la configuration exige d'une attestation App Attest.
#[derive(Debug, Clone, Copy)]
pub struct ApplePolicy<'a> {
    /// Les racines admises, en `SubjectPublicKeyInfo` DER : d'ordinaire
    /// [`APPLE_ROOTS`].
    pub roots: &'a [&'a [u8]],
    /// L'identifiant d'application : `TeamID.bundleID`.
    pub app_id: &'a [u8],
    /// L'environnement admis.
    pub environment: AppleEnvironment,
}

/// Ce qu'une attestation acceptée établit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppAttestation {
    /// L'identifiant de la clef d'App Attest — le condensat de sa clef
    /// publique.
    pub key_id: [u8; 32],
}

/// Vérifie un objet d'attestation d'App Attest.
///
/// - `object` : l'objet CBOR que rend `attestKey` ;
/// - `client_data_hash` : ce que l'application a passé à `attestKey` ;
/// - `now` : l'instant, en secondes depuis l'époque.
///
/// # Errors
///
/// Le premier [`Refusal`] rencontré — la cryptographie d'abord.
pub fn verify_app_attest(
    object: &[u8],
    client_data_hash: &[u8],
    policy: &ApplePolicy<'_>,
    now: i64,
) -> Result<AppAttestation, Refusal> {
    // ── L'OBJET : { fmt, attStmt: { x5c, receipt }, authData } ──────────────
    let mut lecteur = Cbor::new(object);
    let mut format = None;
    let mut chaine: [Option<&[u8]>; 2] = [None; 2];
    let mut certificats = None;
    let mut auth_data = None;
    for _ in 0..lecteur.table()? {
        match lecteur.texte()? {
            b"fmt" => format = Some(lecteur.texte()?),
            b"authData" => auth_data = Some(lecteur.octets()?),
            b"attStmt" => {
                for _ in 0..lecteur.table()? {
                    match lecteur.texte()? {
                        b"x5c" => {
                            let combien = lecteur.tableau()?;
                            if combien != 2 {
                                return Err(Refusal::ChainLength);
                            }
                            for place in &mut chaine {
                                *place = Some(lecteur.octets()?);
                            }
                            certificats = Some(());
                        }
                        _ => lecteur.sauter(0)?,
                    }
                }
            }
            _ => lecteur.sauter(0)?,
        }
    }
    if !lecteur.fini() || format != Some(&b"apple-appattest"[..]) {
        return Err(Refusal::Malformed);
    }
    let (Some(()), [Some(feuille), Some(intermediaire)], Some(auth_data)) =
        (certificats, chaine, auth_data)
    else {
        return Err(Refusal::Malformed);
    };

    // ── LA CHAÎNE, JUSQU'À UNE RACINE ÉPINGLÉE ──────────────────────────────
    //
    // La racine n'est pas dans `x5c` : c'est sa CLEF qu'on épingle, et c'est
    // elle qui doit avoir signé l'intermédiaire.
    let feuille = x509::lire(feuille)?;
    let intermediaire = x509::lire(intermediaire)?;
    if !x509::signe_par(&feuille, intermediaire.cle) {
        return Err(Refusal::BadSignature);
    }
    let mut racine_admise = false;
    for racine in policy.roots {
        racine_admise |=
            x509::cle_de_spki(racine).is_ok_and(|cle| x509::signe_par(&intermediaire, cle));
    }
    if !racine_admise {
        return Err(Refusal::UnknownRoot);
    }
    for certificat in [&feuille, &intermediaire] {
        if now < certificat.debut || now > certificat.fin {
            return Err(Refusal::Expired);
        }
    }

    // ── LE NONCE : SHA-256(authData ‖ clientDataHash) ───────────────────────
    let extension = feuille.apple.ok_or(Refusal::NoAttestation)?;
    let nonce = sha2::Sha256::new()
        .chain_update(auth_data)
        .chain_update(client_data_hash)
        .finalize();
    if nonce_de(extension)? != nonce.as_slice() {
        return Err(Refusal::OtherChallenge);
    }

    // ── LA CLEF, ET SON IDENTIFIANT ─────────────────────────────────────────
    let x509::Cle::P256(point) = feuille.cle else {
        return Err(Refusal::OtherKey);
    };
    let key_id: [u8; 32] = sha2::Sha256::digest(point).into();

    // ── authData : rpIdHash ‖ drapeaux ‖ compteur ‖ aaguid ‖ credId ───────────
    let (rp_id_hash, reste) = auth_data.split_at_checked(32).ok_or(Refusal::Malformed)?;
    let (_drapeaux, reste) = reste.split_at_checked(1).ok_or(Refusal::Malformed)?;
    let (compteur, reste) = reste.split_at_checked(4).ok_or(Refusal::Malformed)?;
    let (aaguid, reste) = reste.split_at_checked(16).ok_or(Refusal::Malformed)?;
    let (longueur, reste) = reste.split_at_checked(2).ok_or(Refusal::Malformed)?;
    let longueur = usize::from(u16::from_be_bytes([
        longueur.first().copied().unwrap_or(0),
        longueur.get(1).copied().unwrap_or(0),
    ]));
    let identifiant = reste.get(..longueur).ok_or(Refusal::Malformed)?;
    if rp_id_hash != sha2::Sha256::digest(policy.app_id).as_slice() {
        return Err(Refusal::OtherApplication);
    }
    // **UN COMPTEUR À ZÉRO** : une attestation est le PREMIER usage de la
    // clef ; un compteur plus haut dirait une assertion déguisée.
    if compteur != [0, 0, 0, 0] {
        return Err(Refusal::Malformed);
    }
    if aaguid != policy.environment.aaguid() {
        return Err(Refusal::OtherEnvironment);
    }
    if identifiant != key_id {
        return Err(Refusal::OtherKey);
    }
    Ok(AppAttestation { key_id })
}

/// Le nonce que porte l'extension d'App Attest : `SEQUENCE { [1] EXPLICIT
/// OCTET STRING }`.
fn nonce_de(extension: &[u8]) -> Result<&[u8], Refusal> {
    let mut exterieur = Lecteur::new(extension);
    let mut sequence = Lecteur::new(exterieur.attendre(SEQUENCE)?.contenu);
    let etiquette = sequence.optionnel(1)?.ok_or(Refusal::Malformed)?;
    let mut dedans = Lecteur::new(etiquette.contenu);
    let nonce = dedans.attendre(OCTETS)?.contenu;
    if !exterieur.fini() || !sequence.fini() || !dedans.fini() {
        return Err(Refusal::Malformed);
    }
    Ok(nonce)
}

#[cfg(test)]
mod tests;
