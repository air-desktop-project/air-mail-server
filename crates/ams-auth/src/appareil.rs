// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! La signature d'un appareil : **ce qu'on accepte, et ce qu'on refuse**.
//!
//! # UNE COURBE, UN CONDENSAT, UNE FORME
//!
//! ECDSA sur P-256, SHA-256, et rien d'autre. Ce n'est pas un choix de goût :
//! **la Secure Enclave d'Apple ne génère que des clefs P-256** et ne sait pas
//! faire d'Ed25519 ; le Keystore Android suit la même réalité dès qu'on exige
//! StrongBox. Une clef qui ne peut pas naître dans l'enclave ne peut pas être
//! protégée par la biométrie, et c'est tout l'objet de l'exercice.
//!
//! # LA FORME DE LA SIGNATURE SE FIXE, ELLE NE SE DEVINE PAS
//!
//! ECDSA se sérialise de deux façons : en DER, ou en paire fixe de soixante-
//! quatre octets. **Les plateformes ne s'accordent pas** — CryptoKit rend du
//! DER, WebCrypto rend du fixe, Android rend du DER. Accepter les deux
//! reviendrait à lire deux grammaires sur les mêmes octets, et c'est la faute
//! que ce dépôt refuse partout ailleurs.
//!
//! **On n'accepte que la forme fixe**, `r ‖ s`, soixante-quatre octets exactement.
//! Un client qui tient du DER le convertit : c'est trois lignes chez lui, et une
//! ambiguïté en moins ici.
//!
//! # LES DEUX FORMES DE `s` SONT ACCEPTÉES, ET C'EST UN CHOIX MESURÉ
//!
//! Toute signature ECDSA `(r, s)` a une jumelle valide `(r, n − s)` : qui
//! intercepte l'une peut fabriquer l'autre **sans connaître la clef privée**.
//! On appelle cela la malléabilité, et l'on pourrait être tenté de n'accepter
//! que la forme « basse » pour l'écarter.
//!
//! **CE SERAIT UNE FAUTE, ET ELLE A FAILLI ÊTRE COMMISE ICI.** La forme basse
//! est une convention du Bitcoin (BIP 62), et non une règle d'ECDSA : la norme
//! NIST n'en dit rien, et **la Secure Enclave comme le Keystore Android
//! produisent l'une ou l'autre au hasard**. Mesuré sur ce dépôt : dix-neuf
//! signatures hautes sur quarante.
//!
//! Exiger la forme basse aurait donc refusé **une signature légitime sur deux**,
//! sur les cinq plateformes à la fois — et se serait manifesté par « l'ouverture
//! de session échoue une fois sur deux, sans raison apparente ».
//!
//! # CE QUI PROTÈGE DU REJEU N'EST PAS LA SIGNATURE, C'EST LE DÉFI
//!
//! La malléabilité ne gêne que qui compte les signatures pour empêcher un
//! rejeu. Ici, ce rôle revient au **défi** : scellé, lié au compte et à
//! l'appareil, et valable soixante secondes. Une jumelle fabriquée sur le même
//! défi ne vaut pas plus longtemps que l'originale, et n'ouvre rien de plus.
//!
//! # CE QU'ON NE FAIT PAS ICI
//!
//! On ne condense pas. L'appelant donne le condensat, parce que c'est lui qui
//! sait ce qui a été signé et avec quelle chaîne de domaine — et qu'une crate
//! qui condenserait « ce qu'on lui donne » finirait par condenser la mauvaise
//! chose.

use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
use p256::ecdsa::{Signature, VerifyingKey};

/// Ce qu'une clef publique P-256 occupe, en forme non compressée (§2.3.3 de
/// SEC 1) : l'octet `0x04`, puis `x` et `y` sur trente-deux octets chacun.
pub const CLE_OCTETS: usize = 65;

/// Ce qu'une signature occupe, en paire fixe : `r` et `s`, trente-deux octets
/// chacun.
pub const SIGNATURE_OCTETS: usize = 64;

/// Ce qu'un condensat SHA-256 occupe.
pub const CONDENSAT_OCTETS: usize = 32;

/// Pourquoi une signature d'appareil est refusée.
///
/// # ELLES NE SE DISENT PAS AU PAIR
///
/// L'appelant les distingue pour son journal — un exploitant qui voit
/// « signature malléable » sait que le client est mal écrit, là où « refusée »
/// l'enverrait soupçonner un vol. **Ce qui part sur le fil, lui, reste un refus
/// unique** : dire laquelle des quatre a joué apprendrait à qui forge jusqu'où il
/// est allé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refus {
    /// La clef publique ne fait pas [`CLE_OCTETS`], ou n'est pas un point.
    CleIrrecevable,
    /// La signature ne fait pas [`SIGNATURE_OCTETS`].
    TailleDeSignature,
    /// `r` ou `s` vaut zéro, ou dépasse l'ordre du groupe.
    ValeurHorsDomaine,
    /// La signature ne correspond pas au condensat.
    NeCorrespondPas,
}

/// Une clef publique d'appareil, déjà validée comme point de la courbe.
///
/// **ELLE NE SE CONSTRUIT QUE PAR [`Cle::lire`]**, qui refuse tout ce qui n'est
/// pas un point valide : le type porte donc sa garantie, et aucun appelant n'a
/// à la revérifier.
#[derive(Clone)]
pub struct Cle {
    verificateur: VerifyingKey,
}

impl core::fmt::Debug for Cle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Une clef PUBLIQUE peut s'afficher sans dommage, mais l'afficher
        // encombrerait un journal de soixante-cinq octets sans rien apprendre.
        f.write_str("Cle(<P-256>)")
    }
}

impl Cle {
    /// Lit une clef publique en forme non compressée.
    ///
    /// # Errors
    ///
    /// [`Refus::CleIrrecevable`] si les octets ne font pas [`CLE_OCTETS`], ou
    /// ne désignent pas un point de la courbe. **Un point qui n'est pas sur la
    /// courbe n'est pas une clef faible : c'est une clef qui n'existe pas**, et
    /// l'accepter ouvrirait des attaques par courbe invalide.
    pub fn lire(octets: &[u8]) -> Result<Self, Refus> {
        if octets.len() != CLE_OCTETS {
            return Err(Refus::CleIrrecevable);
        }
        VerifyingKey::from_sec1_bytes(octets)
            .map(|verificateur| Self { verificateur })
            .map_err(|_| Refus::CleIrrecevable)
    }

    /// Les octets de cette clef, en forme non compressée.
    #[must_use]
    pub fn octets(&self) -> [u8; CLE_OCTETS] {
        let point = self.verificateur.to_sec1_point(false);
        let mut sortie = [0_u8; CLE_OCTETS];
        for (place, lu) in sortie.iter_mut().zip(point.as_bytes()) {
            *place = *lu;
        }
        sortie
    }
}

/// Cette signature couvre-t-elle ce condensat, sous cette clef ?
///
/// `condensat` est un SHA-256 **déjà calculé par l'appelant** — voir l'en-tête
/// du module.
///
/// # Errors
///
/// [`Refus`] dit lequel des quatre contrôles a cédé. **À ne pas répéter au
/// pair** : l'appelant en fait une trace, pas une réponse.
pub fn verifier(cle: &Cle, condensat: &[u8], signature: &[u8]) -> Result<(), Refus> {
    if condensat.len() != CONDENSAT_OCTETS {
        return Err(Refus::NeCorrespondPas);
    }
    if signature.len() != SIGNATURE_OCTETS {
        return Err(Refus::TailleDeSignature);
    }
    // `from_slice` refuse `r` ou `s` nul, et toute valeur au-delà de l'ordre du
    // groupe : deux contrôles que la structure du type porte, plutôt que des
    // gardes qu'on écrirait ici et qu'on oublierait ailleurs.
    let lue = Signature::from_slice(signature).map_err(|_| Refus::ValeurHorsDomaine)?;

    cle.verificateur
        .verify_prehash(condensat, &lue)
        .map_err(|_| Refus::NeCorrespondPas)
}

#[cfg(test)]
mod tests;
