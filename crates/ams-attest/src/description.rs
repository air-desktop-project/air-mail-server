// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La `KeyDescription` d'Android : ce que le Keystore dit de la clef qu'il
//! atteste.
//!
//! ```text
//! KeyDescription ::= SEQUENCE {
//!     attestationVersion         INTEGER,
//!     attestationSecurityLevel   SecurityLevel,
//!     keyMintVersion             INTEGER,
//!     keyMintSecurityLevel       SecurityLevel,
//!     attestationChallenge       OCTET STRING,
//!     uniqueId                   OCTET STRING,
//!     softwareEnforced           AuthorizationList,
//!     hardwareEnforced           AuthorizationList,
//! }
//! ```
//!
//! # CE QUI VIENT DE LA LISTE MATÉRIELLE, ET D'ELLE SEULE
//!
//! Une `AuthorizationList` dit ce qu'une clef a le droit de faire, et la même
//! étiquette peut paraître dans les deux listes. **L'origine de la clef et la
//! racine de confiance ne se lisent que dans la liste MATÉRIELLE** : la liste
//! logicielle est écrite par Android lui-même, et un système trafiqué y écrit ce
//! qu'il veut. L'identité de l'application, elle, n'est connue que d'Android —
//! c'est le gestionnaire de paquets qui la fournit —, et elle vit donc dans la
//! liste logicielle ; c'est la signature du matériel sur l'ensemble qui lui
//! donne sa valeur.

use crate::Refusal;
use crate::der::{BOOLEEN, CONTEXTE, ENSEMBLE, ENTIER, ENUMERE, Lecteur, OCTETS, SEQUENCE};

/// `origin` : d'où vient la clef.
const ORIGINE: u32 = 702;
/// `rootOfTrust` : l'état du démarrage vérifié.
const RACINE_DE_CONFIANCE: u32 = 704;
/// `osPatchLevel` : le niveau de correctifs du système, en `AAAAMM`.
const CORRECTIFS: u32 = 706;
/// `attestationApplicationId` : l'application qui a demandé la clef.
const APPLICATION: u32 = 709;

/// Où vit la clef.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Niveau {
    /// En logiciel : rien ne la protège d'un système compromis.
    Logiciel,
    /// Dans l'environnement d'exécution sécurisé (TEE) du processeur.
    Tee,
    /// Dans une puce de sécurité à part (StrongBox).
    StrongBox,
}

/// L'état du démarrage vérifié (`VerifiedBootState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Demarrage {
    /// Le système est celui du constructeur, vérifié jusqu'au bout.
    Verifie,
    /// Un système signé par une autre clef, que l'utilisateur a installée.
    AutoSigne,
    /// Aucune vérification : le chargeur est déverrouillé.
    NonVerifie,
    /// La vérification a échoué.
    Echoue,
}

/// Ce qu'on retient de la racine de confiance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RacineDeConfiance {
    /// Le chargeur de démarrage est-il verrouillé ?
    pub(crate) verrouille: bool,
    /// L'état du démarrage vérifié.
    pub(crate) demarrage: Demarrage,
}

/// Ce qu'on retient d'une `KeyDescription`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Description<'a> {
    /// Où vit la clef de l'attestation.
    pub(crate) niveau_attestation: Niveau,
    /// La version de KeyMint (ou de Keymaster).
    pub(crate) version: u32,
    /// Où vit la clef attestée.
    pub(crate) niveau: Niveau,
    /// Le défi que l'application a donné en créant la clef.
    pub(crate) defi: &'a [u8],
    /// La clef a-t-elle été CRÉÉE dans le matériel (et non importée) ?
    pub(crate) generee: bool,
    /// La racine de confiance, si le matériel la dit.
    pub(crate) racine: Option<RacineDeConfiance>,
    /// Le niveau de correctifs, s'il est dit.
    pub(crate) correctifs: Option<u32>,
    /// L'`AttestationApplicationId`, encore encodé.
    pub(crate) application: Option<&'a [u8]>,
}

/// Lit une `KeyDescription`.
///
/// # Errors
///
/// [`Refusal::Malformed`] sur ce qui n'en a pas la forme.
pub(crate) fn lire(extension: &[u8]) -> Result<Description<'_>, Refusal> {
    let mut exterieur = Lecteur::new(extension);
    let mut champs = Lecteur::new(exterieur.attendre(SEQUENCE)?.contenu);
    if !exterieur.fini() {
        return Err(Refusal::Malformed);
    }
    let _ = champs.attendre(ENTIER)?;
    let niveau_attestation = niveau(champs.attendre(ENUMERE)?.contenu)?;
    let version = crate::der::petit_entier(champs.attendre(ENTIER)?.contenu)?;
    let niveau = niveau(champs.attendre(ENUMERE)?.contenu)?;
    let defi = champs.attendre(OCTETS)?.contenu;
    let _ = champs.attendre(OCTETS)?;
    let logiciel = champs.attendre(SEQUENCE)?.contenu;
    let materiel = champs.attendre(SEQUENCE)?.contenu;
    if !champs.fini() {
        return Err(Refusal::Malformed);
    }

    let mut generee = false;
    let mut racine = None;
    let mut correctifs = None;
    let mut application = None;
    for_each_autorisation(materiel, &mut |numero, contenu| {
        match numero {
            ORIGINE => generee = crate::der::petit_entier(une_valeur(contenu, ENTIER)?)? == 0,
            RACINE_DE_CONFIANCE => racine = Some(racine_de_confiance(contenu)?),
            CORRECTIFS => {
                correctifs = Some(crate::der::petit_entier(une_valeur(contenu, ENTIER)?)?);
            }
            APPLICATION => application = Some(une_valeur(contenu, OCTETS)?),
            _ => {}
        }
        Ok(())
    })?;
    // L'identité de l'application vit d'ordinaire dans la liste logicielle —
    // voir l'en-tête du module. Elle ne s'y lit que si le matériel ne l'a pas
    // dite, et elle ne peut pas y être deux fois.
    for_each_autorisation(logiciel, &mut |numero, contenu| {
        if numero == APPLICATION {
            if application.is_some() {
                return Err(Refusal::Malformed);
            }
            application = Some(une_valeur(contenu, OCTETS)?);
        }
        Ok(())
    })?;
    Ok(Description {
        niveau_attestation,
        version,
        niveau,
        defi,
        generee,
        racine,
        correctifs,
        application,
    })
}

/// Un `SecurityLevel`.
fn niveau(contenu: &[u8]) -> Result<Niveau, Refusal> {
    match contenu {
        [0] => Ok(Niveau::Logiciel),
        [1] => Ok(Niveau::Tee),
        [2] => Ok(Niveau::StrongBox),
        _ => Err(Refusal::Malformed),
    }
}

/// Parcourt une `AuthorizationList` : une suite d'éléments de contexte, chacun
/// enveloppant sa valeur.
///
/// **UNE FERMETURE DYNAMIQUE, ET NON GÉNÉRIQUE** : une fonction générique
/// s'instancie une fois par appelant, et une branche qu'un seul appelant
/// emprunte compterait comme non couverte dans l'autre.
///
/// **UNE ÉTIQUETTE NE PARAÎT QU'UNE FOIS, ET DANS L'ORDRE** : DER range les
/// champs d'une `SEQUENCE` par numéro croissant. Deux fois la même, ou dans le
/// désordre, et ce n'est plus une liste qu'Android a écrite.
fn for_each_autorisation<'a>(
    liste: &'a [u8],
    chacune: &mut dyn FnMut(u32, &'a [u8]) -> Result<(), Refusal>,
) -> Result<(), Refusal> {
    let mut lecteur = Lecteur::new(liste);
    let mut precedente = None;
    while !lecteur.fini() {
        let lu = lecteur.lire()?;
        if lu.classe != CONTEXTE || !lu.construit {
            return Err(Refusal::Malformed);
        }
        if precedente.is_some_and(|avant| lu.numero <= avant) {
            return Err(Refusal::Malformed);
        }
        precedente = Some(lu.numero);
        chacune(lu.numero, lu.contenu)?;
    }
    Ok(())
}

/// La valeur unique qu'enveloppe un élément de contexte, de ce type.
fn une_valeur(contenu: &[u8], numero: u32) -> Result<&[u8], Refusal> {
    let mut lecteur = Lecteur::new(contenu);
    let valeur = lecteur.attendre(numero)?;
    if lecteur.fini() {
        Ok(valeur.contenu)
    } else {
        Err(Refusal::Malformed)
    }
}

/// `RootOfTrust ::= SEQUENCE { verifiedBootKey OCTET STRING, deviceLocked
/// BOOLEAN, verifiedBootState VerifiedBootState, verifiedBootHash OCTET STRING
/// }` — le dernier champ n'existe qu'à partir de la version 3.
fn racine_de_confiance(contenu: &[u8]) -> Result<RacineDeConfiance, Refusal> {
    let mut exterieur = Lecteur::new(contenu);
    let mut champs = Lecteur::new(exterieur.attendre(SEQUENCE)?.contenu);
    if !exterieur.fini() {
        return Err(Refusal::Malformed);
    }
    let _ = champs.attendre(OCTETS)?;
    let verrouille = match champs.attendre(BOOLEEN)?.contenu {
        [0x00] => false,
        [0xFF] => true,
        _ => return Err(Refusal::Malformed),
    };
    let demarrage = match champs.attendre(ENUMERE)?.contenu {
        [0] => Demarrage::Verifie,
        [1] => Demarrage::AutoSigne,
        [2] => Demarrage::NonVerifie,
        [3] => Demarrage::Echoue,
        _ => return Err(Refusal::Malformed),
    };
    if !champs.fini() {
        let _ = champs.attendre(OCTETS)?;
    }
    if !champs.fini() {
        return Err(Refusal::Malformed);
    }
    Ok(RacineDeConfiance {
        verrouille,
        demarrage,
    })
}

/// Ce que dit un `AttestationApplicationId` : les paquets, et les empreintes
/// de leurs certificats de signature.
///
/// ```text
/// AttestationApplicationId ::= SEQUENCE {
///     package_infos      SET OF AttestationPackageInfo,
///     signature_digests  SET OF OCTET_STRING,
/// }
/// AttestationPackageInfo ::= SEQUENCE {
///     package_name  OCTET_STRING,
///     version       INTEGER,
/// }
/// ```
///
/// `chaque_paquet` et `chaque_empreinte` sont appelées pour chacun, dans
/// l'ordre ; la première faute arrête tout.
pub(crate) fn application<'a>(
    encode: &'a [u8],
    chaque_paquet: &mut dyn FnMut(&'a [u8]),
    chaque_empreinte: &mut dyn FnMut(&'a [u8]),
) -> Result<(), Refusal> {
    let mut exterieur = Lecteur::new(encode);
    let mut champs = Lecteur::new(exterieur.attendre(SEQUENCE)?.contenu);
    if !exterieur.fini() {
        return Err(Refusal::Malformed);
    }
    let mut paquets = Lecteur::new(champs.attendre(ENSEMBLE)?.contenu);
    let mut empreintes = Lecteur::new(champs.attendre(ENSEMBLE)?.contenu);
    if !champs.fini() {
        return Err(Refusal::Malformed);
    }
    while !paquets.fini() {
        let mut paquet = Lecteur::new(paquets.attendre(SEQUENCE)?.contenu);
        let nom = paquet.attendre(OCTETS)?.contenu;
        let _ = paquet.attendre(ENTIER)?;
        if !paquet.fini() {
            return Err(Refusal::Malformed);
        }
        chaque_paquet(nom);
    }
    while !empreintes.fini() {
        chaque_empreinte(empreintes.attendre(OCTETS)?.contenu);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
