// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! L'attestation de clef d'Android (« Key Attestation ») — **sans Google Play,
//! sans appel réseau, sans entrée-sortie** (C1).
//!
//! # CE QU'UNE ATTESTATION PROUVE
//!
//! Quand une application crée sa clef d'appareil dans le Keystore matériel, le
//! téléphone la décrit dans un certificat, signé par une clef que le
//! constructeur a gravée dans l'appareil à l'usine, elle-même certifiée
//! jusqu'à une racine de Google. Le certificat dit :
//!
//! - que la clef a été **créée dans le matériel** — TEE ou StrongBox — et n'en
//!   sortira pas ;
//! - **quelle application** l'a demandée : son nom de paquet et l'empreinte du
//!   certificat qui la SIGNE — celui d'air-desktop.org, et non celui d'un
//!   magasin ;
//! - l'état du téléphone : **chargeur verrouillé, système vérifié** ;
//! - le **défi** que l'application a reçu du serveur, ce qui rend l'attestation
//!   fraîche.
//!
//! # POURQUOI PAS PLAY INTEGRITY
//!
//! Play Integrity demande que l'application soit enregistrée chez Google Play,
//! reconnaît surtout ce qui en vient, et se vérifie en interrogeant Google.
//! L'attestation de clef se vérifie ICI, contre deux clefs racines épinglées :
//! l'application peut être signée par air-desktop.org et téléchargée depuis ses
//! serveurs.
//!
//! # CE QU'ELLE NE PROUVE PAS
//!
//! Ni que l'utilisateur est honnête, ni que l'application n'a pas de faille.
//! Elle prouve que la clef enrôlée vit dans un téléphone intègre, sous notre
//! application. La révocation des clefs d'usine compromises — la liste que
//! Google publie — n'est pas vérifiée ici : c'est une donnée qui change, et
//! elle viendra de l'appelant.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
extern crate std;

mod der;
mod description;
mod status;
mod x509;

pub use status::{SERIAL_HEX_MAX, read_status_list};

use description::{Demarrage, Niveau};

/// Les deux clefs racines de Google, telles que la documentation d'Android les
/// publie, sous forme de `SubjectPublicKeyInfo` DER.
///
/// - la clef **RSA-4096** d'origine (2016), réémise quatre fois sous des dates
///   différentes — c'est pourquoi on épingle la CLEF et non un certificat : le
///   certificat de 2016 a expiré en mai 2026, la clef non ;
/// - la clef **ECDSA P-384** « Key Attestation CA1 » (2025), qui certifie les
///   clefs d'attestation provisionnées à distance.
///
/// Empreintes SHA-256 : `feb2ea75…` et `3ee44512…` — l'essai
/// `les_racines_de_google_sont_celles_de_la_documentation` les tient.
pub const GOOGLE_ROOTS: [&[u8]; 2] = [
    include_bytes!("racines/google-rsa.spki"),
    include_bytes!("racines/google-ec.spki"),
];

/// Combien de certificats une chaîne porte au plus.
///
/// Une chaîne réelle en a trois ou quatre ; huit laissent de la marge sans
/// laisser un inconnu faire vérifier autant de signatures qu'il veut.
pub const CHAIN_MAX: usize = 8;

/// Une clef publique P-256 non compressée — celle d'un appareil.
pub const DEVICE_KEY_OCTETS: usize = 65;

/// Ce que la configuration exige.
#[derive(Debug, Clone, Copy)]
pub struct Policy<'a> {
    /// Les racines admises, en `SubjectPublicKeyInfo` DER : d'ordinaire
    /// [`GOOGLE_ROOTS`].
    pub roots: &'a [&'a [u8]],
    /// Le nom de paquet de l'application — `org.airdesktop.mail`, par exemple.
    pub package: &'a [u8],
    /// Les empreintes SHA-256 admises du certificat qui SIGNE l'application.
    pub signers: &'a [[u8; 32]],
    /// Les numéros de série que la liste de révocation de Google nomme,
    /// **TRIÉS** — voir [`read_status_list`]. Un certificat de la chaîne qui
    /// y figure la fait refuser.
    pub revoked: &'a [u128],
}

/// Où vit la clef attestée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// Dans l'environnement d'exécution sécurisé du processeur.
    TrustedEnvironment,
    /// Dans une puce de sécurité à part.
    StrongBox,
}

impl SecurityLevel {
    /// Son nom, tel que l'API le rend.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::TrustedEnvironment => "tee",
            Self::StrongBox => "strongbox",
        }
    }
}

/// Ce qu'une attestation acceptée établit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attestation {
    /// Où vit la clef.
    pub level: SecurityLevel,
    /// La version de KeyMint (ou de Keymaster) de l'appareil.
    pub keymint_version: u32,
    /// Le niveau de correctifs du système, en `AAAAMM`, s'il est dit.
    pub os_patch_level: Option<u32>,
}

/// Pourquoi une attestation est refusée.
///
/// **POUR LE JOURNAL DU SERVEUR, PAS POUR LE CLIENT** : dire à qui présente une
/// attestation laquelle des règles il a touchée l'aiderait à la contourner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Les octets n'ont pas la forme attendue.
    Malformed,
    /// Un algorithme ou une clef qu'on ne sait pas employer.
    Unsupported,
    /// Moins de deux certificats, ou plus de [`CHAIN_MAX`].
    ChainLength,
    /// Un certificat n'est pas signé par le suivant.
    BadSignature,
    /// Un certificat n'est pas valide à cet instant.
    Expired,
    /// La chaîne ne remonte à aucune racine admise.
    UnknownRoot,
    /// La clef attestée n'est pas celle de l'appareil.
    OtherKey,
    /// Le premier certificat ne porte pas d'attestation.
    NoAttestation,
    /// Le défi n'est pas celui du serveur.
    OtherChallenge,
    /// La clef, ou l'attestation, vit en logiciel.
    Software,
    /// La clef a été importée, et non créée dans le matériel.
    Imported,
    /// Le chargeur de démarrage n'est pas verrouillé, ou le système n'est pas
    /// vérifié.
    UnverifiedBoot,
    /// Le matériel ne dit rien de l'état du démarrage.
    NoRootOfTrust,
    /// L'application n'est pas la nôtre.
    OtherApplication,
    /// L'application n'est pas signée par un certificat admis.
    OtherSigner,
    /// Un certificat de la chaîne est révoqué, ou suspendu, par Google.
    Revoked,
}

impl Refusal {
    /// Ce que le journal du serveur en dit.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Malformed => "attestation illisible",
            Self::Unsupported => "algorithme ou clef non pris en charge",
            Self::ChainLength => "chaîne trop courte ou trop longue",
            Self::BadSignature => "un certificat n'est pas signé par le suivant",
            Self::Expired => "un certificat n'est pas valide à cette date",
            Self::UnknownRoot => "racine inconnue",
            Self::OtherKey => "la clef attestée n'est pas celle de l'appareil",
            Self::NoAttestation => "aucune extension d'attestation",
            Self::OtherChallenge => "défi différent",
            Self::Software => "clef en logiciel",
            Self::Imported => "clef importée",
            Self::UnverifiedBoot => "démarrage non vérifié ou chargeur déverrouillé",
            Self::NoRootOfTrust => "racine de confiance absente",
            Self::OtherApplication => "autre application",
            Self::OtherSigner => "application signée par un autre certificat",
            Self::Revoked => "une clef de la chaîne est révoquée par Google",
        }
    }
}

/// Vérifie une attestation.
///
/// - `chain` : les certificats DER **mis bout à bout**, la feuille d'abord et
///   la racine en dernier — DER se délimite lui-même ;
/// - `device_key` : la clef publique que l'appareil enrôle ;
/// - `challenge` : le défi que le serveur attendait ;
/// - `now` : l'instant, en secondes depuis l'époque.
///
/// # L'ORDRE DES CONTRÔLES
///
/// La cryptographie d'abord : tant que la chaîne ne remonte pas à une racine
/// admise, rien de ce qu'elle dit ne vaut, et le lire serait croire un inconnu.
///
/// # Errors
///
/// Le premier [`Refusal`] rencontré.
pub fn verify(
    chain: &[u8],
    device_key: &[u8; DEVICE_KEY_OCTETS],
    challenge: &[u8],
    policy: &Policy<'_>,
    now: i64,
) -> Result<Attestation, Refusal> {
    let mut certificats: [Option<x509::Certificat<'_>>; CHAIN_MAX] = [None; CHAIN_MAX];
    let mut combien = 0_usize;
    let mut lecteur = der::Lecteur::new(chain);
    while !lecteur.fini() {
        let brut = lecteur.lire()?.brut;
        let place = certificats.get_mut(combien).ok_or(Refusal::ChainLength)?;
        *place = Some(x509::lire(brut)?);
        combien = combien.saturating_add(1);
    }
    let lus = certificats.get(..combien).unwrap_or_default();
    let (Some(Some(feuille)), Some(Some(racine))) = (lus.first(), lus.last()) else {
        return Err(Refusal::ChainLength);
    };
    if combien < 2 {
        return Err(Refusal::ChainLength);
    }

    // ── LA CHAÎNE ───────────────────────────────────────────────────────────
    let enfants = lus.iter().flatten();
    let parents = lus.iter().flatten().skip(1);
    for (enfant, parent) in enfants.zip(parents) {
        if !x509::signe_par(enfant, parent.cle) {
            return Err(Refusal::BadSignature);
        }
    }
    if !policy.roots.contains(&racine.spki) {
        return Err(Refusal::UnknownRoot);
    }
    // **CHAQUE CERTIFICAT SE CHERCHE DANS LA LISTE** (§« Certificate
    // revocation status list » de la documentation d'Android) : c'est une clef
    // d'usine qui fuit, et elle peut être à n'importe quel étage.
    for certificat in lus.iter().flatten() {
        if certificat
            .serie
            .is_some_and(|serie| policy.revoked.binary_search(&serie).is_ok())
        {
            return Err(Refusal::Revoked);
        }
    }
    // **LA RACINE EST ÉPINGLÉE PAR SA CLEF, PAS PAR SES DATES** : Google a
    // réémis la même clef sous d'autres certificats. Les autres le sont par
    // leurs dates.
    let sans_racine = lus.get(..combien.saturating_sub(1)).unwrap_or_default();
    for certificat in sans_racine.iter().flatten() {
        if now < certificat.debut || now > certificat.fin {
            return Err(Refusal::Expired);
        }
    }

    // ── LA CLEF ET SON ATTESTATION ──────────────────────────────────────────
    if feuille.cle != x509::Cle::P256(device_key) {
        return Err(Refusal::OtherKey);
    }
    let extension = feuille.attestation.ok_or(Refusal::NoAttestation)?;
    let lue = description::lire(extension)?;
    if lue.defi != challenge {
        return Err(Refusal::OtherChallenge);
    }
    let level = match (lue.niveau_attestation, lue.niveau) {
        (Niveau::Logiciel, _) | (_, Niveau::Logiciel) => return Err(Refusal::Software),
        (_, Niveau::Tee) => SecurityLevel::TrustedEnvironment,
        (_, Niveau::StrongBox) => SecurityLevel::StrongBox,
    };
    if !lue.generee {
        return Err(Refusal::Imported);
    }
    let racine_de_confiance = lue.racine.ok_or(Refusal::NoRootOfTrust)?;
    if !racine_de_confiance.verrouille || racine_de_confiance.demarrage != Demarrage::Verifie {
        return Err(Refusal::UnverifiedBoot);
    }

    // ── L'APPLICATION ───────────────────────────────────────────────────────
    let application = lue.application.ok_or(Refusal::OtherApplication)?;
    let mut paquets = 0_usize;
    let mut notre_paquet = false;
    let mut empreintes = 0_usize;
    let mut toutes_admises = true;
    description::application(
        application,
        &mut |nom| {
            paquets = paquets.saturating_add(1);
            notre_paquet |= nom == policy.package;
        },
        &mut |empreinte| {
            empreintes = empreintes.saturating_add(1);
            toutes_admises &= policy
                .signers
                .iter()
                .any(|admise| admise.as_slice() == empreinte);
        },
    )?;
    // **UN SEUL PAQUET, LE NÔTRE** : plusieurs paquets partagent un même
    // identifiant d'utilisateur Linux quand ils le demandent, et la clef est
    // alors à tous. Une application qui partage sa clef n'est pas la nôtre.
    if paquets != 1 || !notre_paquet {
        return Err(Refusal::OtherApplication);
    }
    // **TOUTES LES EMPREINTES, ET AU MOINS UNE** : une application signée par
    // deux certificats l'est aussi par celui qu'on n'a pas admis.
    if empreintes == 0 || !toutes_admises {
        return Err(Refusal::OtherSigner);
    }
    Ok(Attestation {
        level,
        keymint_version: lue.version,
        os_patch_level: lue.correctifs,
    })
}

#[cfg(test)]
mod tests;
